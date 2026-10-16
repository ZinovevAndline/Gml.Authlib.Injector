/*
 * ANDLINE extensions to authlib-injector.
 * Copyright (C) 2026 ANDLINE contributors.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * This file is distributed under the GNU Affero General Public License v3.0
 * or later, consistent with the upstream authlib-injector license.
 */
package moe.yushi.authlibinjector.andline;

import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import java.util.function.LongSupplier;
import java.util.regex.Pattern;

/**
 * Reservation of the chosen Yggdrasil verification authority for one
 * cryptographic Minecraft login handshake.
 *
 * The server hash MUST be calculated by the trusted proxy after its encryption
 * exchange, never supplied by the player, their nickname, or their virtual host.
 * No reservation means no verification and NO offline or other-provider fallback.
 *
 * This registry is intentionally not wired into global URL redirects yet:
 * the Bungee/NullCordX handshake adapter must register the *actual* server hash
 * before the Authlib hasJoined request is made. Doing it at PreLogin by nickname
 * is race-prone and insecure.
 */
public final class AndlineSessionRouteRegistry {
    private static final Pattern SERVER_HASH = Pattern.compile("-?[0-9a-fA-F]{1,40}");
    private static final Pattern USERNAME = Pattern.compile("[A-Za-z0-9_]{3,16}");
    public static final long MAX_TTL_MILLIS = 30_000L;
    private static final int MAX_ENTRIES = 4096;

    public enum Provider {
        MOJANG, GML
    }

    /** Immutable routing decision. No client-controlled provider strings. */
    public static final class Route {
        private final Provider provider;
        private final UUID connectionId;
        private final long expiresAt;

        private Route(Provider provider, UUID connectionId, long expiresAt) {
            this.provider = provider;
            this.connectionId = connectionId;
            this.expiresAt = expiresAt;
        }

        public Provider provider() { return provider; }
        public UUID connectionId() { return connectionId; }
        public long expiresAt() { return expiresAt; }
    }

    private static final class Key {
        private final String hash;
        private final String username;

        private Key(String hash, String username) {
            this.hash = hash;
            this.username = username;
        }

        @Override
        public boolean equals(Object other) {
            if (!(other instanceof Key)) return false;
            Key key = (Key) other;
            return hash.equals(key.hash) && username.equals(key.username);
        }

        @Override
        public int hashCode() {
            return 31 * hash.hashCode() + username.hashCode();
        }
    }

    private final LongSupplier clock;
    private final Map<Key, Route> pending = new HashMap<>();

    public AndlineSessionRouteRegistry() {
        this(System::currentTimeMillis);
    }

    public AndlineSessionRouteRegistry(LongSupplier clock) {
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    /**
     * Only the trusted proxy code with a real encryption exchange may call
     * this method. Never expose it through an unsigned or unauthenticated API.
     * Duplicate reservations, including attempts to change GML to MOJANG,
     * are rejected rather than replaced.
     */
    public synchronized boolean reserve(String serverHash, String username,
            Provider provider, UUID connectionId, long ttlMillis) {
        Key key = checkedKey(serverHash, username);
        Objects.requireNonNull(provider, "provider");
        Objects.requireNonNull(connectionId, "connectionId");
        if (ttlMillis < 1 || ttlMillis > MAX_TTL_MILLIS) {
            throw new IllegalArgumentException("Invalid session reservation TTL");
        }

        long now = clock.getAsLong();
        Route current = pending.get(key);
        if (current != null && current.expiresAt > now) return false;
        if (current != null) pending.remove(key);
        if (pending.size() >= MAX_ENTRIES) purgeExpired(now);
        if (pending.size() >= MAX_ENTRIES) return false;
        pending.put(key, new Route(provider, connectionId, now + ttlMillis));
        return true;
    }

    /**
     * A hasJoined request consumes exactly one registered route. A missing,
     * expired or replayed request has no provider: the caller MUST reject.
     */
    public synchronized Optional<Route> consume(String serverHash, String username) {
        Key key = checkedKey(serverHash, username);
        Route route = pending.remove(key);
        return route != null && route.expiresAt > clock.getAsLong()
                ? Optional.of(route) : Optional.empty();
    }

    /** A stale disconnect cannot invalidate a newer connection's reservation. */
    public synchronized boolean cancel(String serverHash, String username, UUID connectionId) {
        Key key = checkedKey(serverHash, username);
        Objects.requireNonNull(connectionId, "connectionId");
        Route route = pending.get(key);
        return route != null && connectionId.equals(route.connectionId)
                && pending.remove(key) != null;
    }

    private void purgeExpired(long now) {
        for (Iterator<Map.Entry<Key, Route>> it = pending.entrySet().iterator(); it.hasNext();) {
            if (it.next().getValue().expiresAt <= now) it.remove();
        }
    }

    private static Key checkedKey(String hash, String name) {
        if (hash == null || !SERVER_HASH.matcher(hash).matches()
                || name == null || !USERNAME.matcher(name).matches()) {
            throw new IllegalArgumentException("Invalid encrypted handshake identity");
        }
        return new Key(hash, name);
    }
}
