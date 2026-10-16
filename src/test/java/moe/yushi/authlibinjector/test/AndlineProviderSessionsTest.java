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
}
