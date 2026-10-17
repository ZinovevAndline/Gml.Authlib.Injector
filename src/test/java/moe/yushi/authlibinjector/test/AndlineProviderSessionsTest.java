/*
 * ANDLINE extensions to authlib-injector.
 * Copyright (C) 2026 ANDLINE contributors.
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package moe.yushi.authlibinjector.test;

import static org.junit.jupiter.api.Assertions.*;
import java.util.UUID;
import moe.yushi.authlibinjector.andline.AndlineProviderSessions;
import moe.yushi.authlibinjector.andline.AndlineSessionRouteRegistry.Provider;
import org.junit.jupiter.api.Test;

public class AndlineProviderSessionsTest {
    public static class FakePendingConnection {
        private final String name;
        public FakePendingConnection(String name) { this.name = name; }
        public String getName() { return name; }
    }

    @Test
    public void onlyMarkedEncryptedConnectionCanCreateAnAuthenticationRoute() {
        String hash = "a8899ffe6c3";
        FakePendingConnection conn = new FakePendingConnection("TestPremium");
        AndlineProviderSessions.registerEncryptedHash(conn, hash);
        assertFalse(AndlineProviderSessions.consume(hash, "TestPremium").isPresent());

        UUID owner = UUID.randomUUID();
        AndlineProviderSessions.markConnection(conn, Provider.MOJANG, owner);
        AndlineProviderSessions.registerEncryptedHash(conn, hash);
        assertEquals(Provider.MOJANG,
                AndlineProviderSessions.consume(hash, "TestPremium").get().provider());
        assertFalse(AndlineProviderSessions.consume(hash, "TestPremium").isPresent());
    }

    @Test
    public void cancelledHandshakeNeverRegistersEvenWithTheSameNickname() {
        String hash = "123abc44fa";
        FakePendingConnection old = new FakePendingConnection("Steve");
        FakePendingConnection current = new FakePendingConnection("Steve");
        AndlineProviderSessions.markConnection(old, Provider.GML, UUID.randomUUID());
        AndlineProviderSessions.clearConnection(old);
        AndlineProviderSessions.registerEncryptedHash(old, hash);
        assertFalse(AndlineProviderSessions.consume(hash, "Steve").isPresent());

        AndlineProviderSessions.markConnection(current, Provider.MOJANG, UUID.randomUUID());
        AndlineProviderSessions.registerEncryptedHash(current, hash);
        assertEquals(Provider.MOJANG, AndlineProviderSessions.consume(hash, "Steve").get().provider());
    }

    @Test
    public void markCannotBeReplayedAfterHashRegistration() {
        String hash = "42c0ffee";
        FakePendingConnection conn = new FakePendingConnection("Steve");
        AndlineProviderSessions.markConnection(conn, Provider.GML, UUID.randomUUID());
        AndlineProviderSessions.registerEncryptedHash(conn, hash);
        AndlineProviderSessions.registerEncryptedHash(conn, hash);
        assertEquals(Provider.GML, AndlineProviderSessions.consume(hash, "Steve").get().provider());
        assertFalse(AndlineProviderSessions.consume(hash, "Steve").isPresent());
    }
    @Test
    public void disconnectAfterEncryptionRevokesTheExactUnconsumedRoute() {
        String hash = "9ba771f0d0";
        FakePendingConnection conn = new FakePendingConnection("CloseBeforeJoined");
        AndlineProviderSessions.markConnection(conn, Provider.MOJANG, UUID.randomUUID());
        AndlineProviderSessions.registerEncryptedHash(conn, hash);
        AndlineProviderSessions.clearConnection(conn);
        assertFalse(AndlineProviderSessions.consume(hash, "CloseBeforeJoined").isPresent(),
                "A disconnected player must never leave a usable Mojang reservation");
    }

    @Test
    public void oneDisconnectedPlayerCannotRevokeAnotherPlayersVerification() {
        String hash = "bf881ac3";
        FakePendingConnection first = new FakePendingConnection("FirstPlayer");
        FakePendingConnection second = new FakePendingConnection("OtherPlayer");
        AndlineProviderSessions.markConnection(first, Provider.GML, UUID.randomUUID());
        AndlineProviderSessions.markConnection(second, Provider.MOJANG, UUID.randomUUID());
        AndlineProviderSessions.registerEncryptedHash(first, hash);
        AndlineProviderSessions.registerEncryptedHash(second, hash);
        AndlineProviderSessions.clearConnection(first);
        assertFalse(AndlineProviderSessions.consume(hash, "FirstPlayer").isPresent());
        assertEquals(Provider.MOJANG,
                AndlineProviderSessions.consume(hash, "OtherPlayer").orElseThrow().provider());
    }

    @Test
    public void aPendingConnectionCannotRegisterMultipleEncryptedProviders() {
        FakePendingConnection conn = new FakePendingConnection("NoSwitch");
        String first = "012345abcde";
        AndlineProviderSessions.markConnection(conn, Provider.GML, UUID.randomUUID());
        AndlineProviderSessions.registerEncryptedHash(conn, first);
        assertThrows(IllegalStateException.class,
                () -> AndlineProviderSessions.markConnection(conn, Provider.MOJANG, UUID.randomUUID()));
        AndlineProviderSessions.registerEncryptedHash(conn, "012345abcdef");
        assertFalse(AndlineProviderSessions.consume("012345abcdef", "NoSwitch").isPresent());
        assertEquals(Provider.GML,
                AndlineProviderSessions.consume(first, "NoSwitch").orElseThrow().provider());
        AndlineProviderSessions.clearConnection(conn);
    }

    @Test
    public void cannotFlipPinnedGmlToMojangBeforeEncryption() {
        FakePendingConnection conn = new FakePendingConnection("Steve");
        UUID owner = UUID.randomUUID();
        AndlineProviderSessions.markConnection(conn, Provider.GML, owner);
        assertThrows(IllegalStateException.class,
                () -> AndlineProviderSessions.markConnection(conn, Provider.MOJANG, owner));
        assertThrows(IllegalStateException.class,
                () -> AndlineProviderSessions.markConnection(conn, Provider.GML, UUID.randomUUID()));
        String hash = "a03f19";
        AndlineProviderSessions.registerEncryptedHash(conn, hash);
        assertEquals(Provider.GML, AndlineProviderSessions.consume(hash, "Steve").get().provider());
    }

}
