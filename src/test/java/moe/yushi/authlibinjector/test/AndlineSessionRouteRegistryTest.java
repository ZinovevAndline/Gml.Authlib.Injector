/*
 * ANDLINE extensions to authlib-injector.
 * Copyright (C) 2026 ANDLINE contributors.
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package moe.yushi.authlibinjector.test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import moe.yushi.authlibinjector.andline.AndlineSessionRouteRegistry;
import moe.yushi.authlibinjector.andline.AndlineSessionRouteRegistry.Provider;
import org.junit.jupiter.api.Test;

public class AndlineSessionRouteRegistryTest {
    private static final String HASH = "-7fedcba987654321";
    private static final String NAME = "AndlineTest";
    private static final UUID CONNECTION_1 = UUID.fromString("fe3892d5-7670-49ad-ac58-988723f16456");
    private static final UUID CONNECTION_2 = UUID.fromString("d2968758-fd9f-4bb1-a946-2c82dca6417f");

    @Test
    public void onlyTheRegisteredProviderCanBeClaimedExactlyOnce() {
        AndlineSessionRouteRegistry routes = new AndlineSessionRouteRegistry();
        assertTrue(routes.reserve(HASH, NAME, Provider.MOJANG, CONNECTION_1, 15_000));
        assertFalse(routes.reserve(HASH, NAME, Provider.GML, CONNECTION_2, 15_000));
        assertFalse(routes.consume(HASH, "OtherPlayer").isPresent());
        assertTrue(routes.consume(HASH, NAME).isPresent());
        assertFalse(routes.consume(HASH, NAME).isPresent());
    }

    @Test
    public void nameAndHashMustMatchExactly() {
        AndlineSessionRouteRegistry routes = new AndlineSessionRouteRegistry();
        assertTrue(routes.reserve(HASH, NAME, Provider.GML, CONNECTION_1, 15_000));
        assertFalse(routes.consume(HASH, "andlinetest").isPresent());
        assertFalse(routes.consume("7fedcba987654321", NAME).isPresent());
        Optional<AndlineSessionRouteRegistry.Route> accepted = routes.consume(HASH, NAME);
        assertTrue(accepted.isPresent());
        assertEquals(Provider.GML, accepted.get().provider());
        assertEquals(CONNECTION_1, accepted.get().connectionId());
    }

    @Test
    public void disconnectCanOnlyCancelItsOwnReservation() {
        AndlineSessionRouteRegistry routes = new AndlineSessionRouteRegistry();
        routes.reserve(HASH, NAME, Provider.MOJANG, CONNECTION_1, 15_000);
        assertFalse(routes.cancel(HASH, NAME, CONNECTION_2));
        assertTrue(routes.cancel(HASH, NAME, CONNECTION_1));
        assertFalse(routes.consume(HASH, NAME).isPresent());
    }

    @Test
    public void expiredReservationCannotBeConsumedAndCanBeReplaced() {
        AtomicLong time = new AtomicLong(1_000);
        AndlineSessionRouteRegistry routes = new AndlineSessionRouteRegistry(time::get);
        assertTrue(routes.reserve(HASH, NAME, Provider.GML, CONNECTION_1, 1_000));
        time.set(2_000);
        assertFalse(routes.consume(HASH, NAME).isPresent());
        assertTrue(routes.reserve(HASH, NAME, Provider.MOJANG, CONNECTION_2, 1_000));
        assertEquals(Provider.MOJANG, routes.consume(HASH, NAME).get().provider());
    }

    @Test
    public void malformedIdsAndOverlongTtlFailClosed() {
        AndlineSessionRouteRegistry routes = new AndlineSessionRouteRegistry();
        assertThrows(IllegalArgumentException.class,
                () -> routes.reserve("handshakeFromClient", NAME, Provider.GML, CONNECTION_1, 1000));
        assertThrows(IllegalArgumentException.class,
                () -> routes.reserve(HASH, "Bad Name", Provider.GML, CONNECTION_1, 1000));
        assertThrows(IllegalArgumentException.class,
                () -> routes.reserve(HASH, NAME, Provider.GML, CONNECTION_1, 31_000));
        assertThrows(NullPointerException.class,
                () -> routes.reserve(HASH, NAME, null, CONNECTION_1, 1000));
        assertThrows(IllegalArgumentException.class,
                () -> routes.consume("not-a-server-hash", NAME));
    }

    @Test
    public void racingCallbacksCanNeverConsumeTheSameProofTwice() throws InterruptedException {
        AndlineSessionRouteRegistry routes = new AndlineSessionRouteRegistry();
        routes.reserve(HASH, NAME, Provider.MOJANG, CONNECTION_1, 15_000);
        int threads = 12;
        CountDownLatch ready = new CountDownLatch(threads);
        CountDownLatch start = new CountDownLatch(1);
        CountDownLatch finished = new CountDownLatch(threads);
        AtomicInteger accepted = new AtomicInteger();
        for (int i = 0; i < threads; i++) {
            Thread thread = new Thread(() -> {
                ready.countDown();
                try {
                    start.await();
                    if (routes.consume(HASH, NAME).isPresent()) accepted.incrementAndGet();
                } catch (InterruptedException ex) {
                    Thread.currentThread().interrupt();
                } finally {
                    finished.countDown();
                }
            });
            thread.setDaemon(true);
            thread.start();
        }
        ready.await();
        start.countDown();
        finished.await();
        assertEquals(1, accepted.get());
    }
}
