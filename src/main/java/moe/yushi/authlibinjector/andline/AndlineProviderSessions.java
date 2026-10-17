/*
 * ANDLINE extensions to authlib-injector.
 * Copyright (C) 2026 ANDLINE contributors.
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package moe.yushi.authlibinjector.andline;

import java.lang.reflect.Method;
import java.util.Collections;
import java.util.Map;
import java.util.UUID;
import java.util.WeakHashMap;
import moe.yushi.authlibinjector.transform.CallbackMethod;

/**
 * One JVM-local rendezvous between trusted TiAuth PreLogin provider choice,
 * encrypted Bungee handshake and the hasJoined filter.
 *
 * Must only be called from trusted proxy code. Client-supplied hostnames or
 * claimed UUIDs do not constitute an authenticated provider selection.
 */
public final class AndlineProviderSessions {
    private static final AndlineSessionRouteRegistry ROUTES = new AndlineSessionRouteRegistry();
    private static final Map<Object, Selection> selections =
            Collections.synchronizedMap(new WeakHashMap<>());

    // Protected by selections' monitor together with the pending choices.
    // Retain only a weak reference to each connection: the route registry
    // itself has a bounded 30-second expiry.
    private static final Map<Object, RegisteredRoute> registered = new WeakHashMap<>();

    private static final class RegisteredRoute {
        final String hash;
        final String name;
        final UUID connectionId;

        RegisteredRoute(String hash, String name, UUID connectionId) {
            this.hash = hash;
            this.name = name;
            this.connectionId = connectionId;
        }
    }

    private static final class Selection {
        final AndlineSessionRouteRegistry.Provider provider;
        final UUID connectionId;

        Selection(AndlineSessionRouteRegistry.Provider provider, UUID connectionId) {
            this.provider = provider;
            this.connectionId = connectionId;
        }
    }

    private AndlineProviderSessions() {}

    /**
     * Pin selected provider to the actual PendingConnection before encryption.
     * A callback from a different connection never inherits this choice.
     */
    public static void markConnection(Object pendingConnection,
            AndlineSessionRouteRegistry.Provider provider, UUID connectionId) {
        if (pendingConnection == null || provider == null || connectionId == null) {
            throw new IllegalArgumentException("Missing authenticated provider selection");
        }
        synchronized (selections) {
            if (registered.containsKey(pendingConnection)) {
                throw new IllegalStateException("Encrypted handshake already registered for this connection");
            }
            Selection existing = selections.get(pendingConnection);
            if (existing != null) {
                if (existing.provider != provider || !existing.connectionId.equals(connectionId)) {
                    throw new IllegalStateException("Provider already pinned for this connection");
                }
                return;
            }
            selections.put(pendingConnection, new Selection(provider, connectionId));
        }
    }

    /** Explicitly drop a connection that cancelled during PreLogin. */
    public static void clearConnection(Object pendingConnection) {
        if (pendingConnection == null) return;
        synchronized (selections) {
            selections.remove(pendingConnection);
            RegisteredRoute route = registered.remove(pendingConnection);
            if (route != null) {
                // This route is revoked ONLY if its original connection ID
                // still owns it; reconnects cannot erase a newer admission.
                ROUTES.cancel(route.hash, route.name, route.connectionId);
            }
        }
    }

    /**
     * Called ONLY by the instrumented InitialHandler after Bungee calculated
     * SHA-1(serverId + negotiated secret + proxy key) during EncryptionResponse.
     * The server hash itself is NOT learned from user input.
     */
    @CallbackMethod
    public static void registerEncryptedHash(Object pendingConnection, String serverHash) {
        if (pendingConnection == null || serverHash == null) return;
        synchronized (selections) {
            // Only the first valid encrypted hash may represent a connection.
            if (registered.containsKey(pendingConnection)) return;
            Selection selected = selections.remove(pendingConnection);
            if (selected == null) return; // No verified routing decision.
            try {
                Method getName = pendingConnection.getClass().getMethod("getName");
                Object value = getName.invoke(pendingConnection);
                if (!(value instanceof String)) return;
                String name = (String) value;
                if (ROUTES.reserve(serverHash, name,
                        selected.provider, selected.connectionId, 30_000L)) {
                    registered.put(pendingConnection,
                            new RegisteredRoute(serverHash, name, selected.connectionId));
                }
            } catch (ReflectiveOperationException | IllegalArgumentException | SecurityException ignored) {
                // Unsupported proxy build: never silently guess a provider.
            }
        }
    }

    /** For JVM-local tests and the opt-in HTTP filter. */
    public static AndlineSessionRouteRegistry registry() {
        return ROUTES;
    }

    public static boolean cancel(String hash, String name, UUID connectionId) {
        return ROUTES.cancel(hash, name, connectionId);
    }

    public static java.util.Optional<AndlineSessionRouteRegistry.Route> consume(String hash, String name) {
        return ROUTES.consume(hash, name);
    }
}
