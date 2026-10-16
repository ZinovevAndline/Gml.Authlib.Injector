/*
 * ANDLINE extensions to authlib-injector.
 * Copyright (C) 2026 ANDLINE contributors.
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package moe.yushi.authlibinjector.test;

import static org.junit.jupiter.api.Assertions.*;

import java.io.IOException;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;
import moe.yushi.authlibinjector.andline.AndlineHasJoinedFilter;
import moe.yushi.authlibinjector.andline.AndlineSessionRouteRegistry;
import moe.yushi.authlibinjector.andline.AndlineSessionRouteRegistry.Provider;
import org.junit.jupiter.api.Test;

public class AndlineHasJoinedFilterTest {
    private static final String HASH = "c03441e6cbbbeefa00";
    private static final String NAME = "Steve";
    private static final UUID OWNER = UUID.fromString("9247f52e-2f6b-4914-804b-18b84b1c48b7");
    private static final String PROFILE = "{\"id\":\"8667ba71b85a4004af54457a9734eed7\",\"name\":\"Steve\"}";

    @Test
    public void withoutEncryptionReservationNoAuthorityIsQueried() throws IOException {
        AndlineSessionRouteRegistry registry = new AndlineSessionRouteRegistry();
        AtomicInteger requests = new AtomicInteger();
        AndlineHasJoinedFilter handler = new AndlineHasJoinedFilter(registry, (provider, name, hash, ip) -> {
            requests.incrementAndGet();
            return Optional.of(PROFILE);
        });

        assertFalse(handler.verify(NAME, HASH, null).isPresent());
        assertEquals(0, requests.get());
    }

    @Test
    public void providerIsImmutableAndProofCanBeUsedOnce() throws IOException {
        AndlineSessionRouteRegistry registry = new AndlineSessionRouteRegistry();
        registry.reserve(HASH, NAME, Provider.MOJANG, OWNER, 15_000);
        assertFalse(registry.reserve(HASH, NAME, Provider.GML, UUID.randomUUID(), 15_000));

        AtomicInteger requests = new AtomicInteger();
        AndlineHasJoinedFilter handler = new AndlineHasJoinedFilter(registry, (provider, name, hash, ip) -> {
            assertEquals(Provider.MOJANG, provider);
            assertEquals(NAME, name);
            assertEquals(HASH, hash);
            requests.incrementAndGet();
            return Optional.of(PROFILE);
        });
        assertTrue(handler.verify(NAME, HASH, null).isPresent());
        assertFalse(handler.verify(NAME, HASH, null).isPresent());
        assertEquals(1, requests.get());
    }

    @Test
    public void gmlSessionUsesOnlyItsRegisteredProvider() throws IOException {
        AndlineSessionRouteRegistry registry = new AndlineSessionRouteRegistry();
        registry.reserve(HASH, NAME, Provider.GML, OWNER, 15_000);
        AndlineHasJoinedFilter handler = new AndlineHasJoinedFilter(registry, (provider, name, hash, ip) -> {
            assertEquals(Provider.GML, provider);
            return Optional.of(PROFILE);
        });
        assertEquals(PROFILE, handler.verify(NAME, HASH, null).get());
    }

    @Test
    public void authorityCannotAuthenticateADifferentNameOrInvalidUuid() throws IOException {
        for (String response : new String[] {
                "{\"id\":\"8667ba71b85a4004af54457a9734eed7\",\"name\":\"SomeoneElse\"}",
                "{\"id\":\"fake-uuid\",\"name\":\"Steve\"}",
                "{\"id\":\"00000000000000000000000000000000\",\"name\":\"Steve\"}",
                "{\"id\":\"8667ba71b85a4004af54457a9734eed7\"}",
                "not-json"
        }) {
            AndlineSessionRouteRegistry registry = new AndlineSessionRouteRegistry();
            registry.reserve(HASH, NAME, Provider.MOJANG, OWNER, 15_000);
            AndlineHasJoinedFilter handler = new AndlineHasJoinedFilter(registry,
                    (provider, name, hash, ip) -> Optional.of(response));
            assertFalse(handler.verify(NAME, HASH, null).isPresent(), response);
        }
    }

    @Test
    public void mismatchingHashAndNetworkFailureNeverFallBack() throws IOException {
        AndlineSessionRouteRegistry registry = new AndlineSessionRouteRegistry();
        registry.reserve(HASH, NAME, Provider.GML, OWNER, 15_000);
        AndlineHasJoinedFilter handler = new AndlineHasJoinedFilter(registry, (provider, name, hash, ip) -> {
            throw new IOException("server unavailable");
        });
        assertFalse(handler.verify(NAME, "abccbad", null).isPresent());
        assertThrows(IOException.class, () -> handler.verify(NAME, HASH, null));
        assertFalse(handler.verify(NAME, HASH, null).isPresent());
    }

    @Test
    public void invalidInputsDoNotConsumeRealRoute() throws IOException {
        AndlineSessionRouteRegistry registry = new AndlineSessionRouteRegistry();
        registry.reserve(HASH, NAME, Provider.MOJANG, OWNER, 15_000);
        AndlineHasJoinedFilter handler = new AndlineHasJoinedFilter(registry,
                (provider, name, hash, ip) -> Optional.of(PROFILE));
        assertFalse(handler.verify(NAME, HASH, "some.fake.ip").isPresent());
        assertFalse(handler.verify(NAME, HASH + "x", null).isPresent());
        assertFalse(handler.verify("Bad Player", HASH, null).isPresent());
        assertTrue(handler.verify(NAME, HASH, null).isPresent());
    }
}
