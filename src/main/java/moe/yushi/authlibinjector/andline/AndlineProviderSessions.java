package moe.yushi.authlibinjector.andline;

import java.util.UUID;

public final class AndlineProviderSessions {
    private static final AndlineSessionRouteRegistry ROUTES = new AndlineSessionRouteRegistry();
    private AndlineProviderSessions() {}

    public static boolean reserve(String hash, String name, AndlineSessionRouteRegistry.Provider provider, UUID connectionId) {
        return ROUTES.reserve(hash, name, provider, connectionId, 30_000L);
    }

    public static boolean cancel(String hash, String name, UUID connectionId) {
        return ROUTES.cancel(hash, name, connectionId);
    }

    public static java.util.Optional<AndlineSessionRouteRegistry.Route> consume(String hash, String name) {
        return ROUTES.consume(hash, name);
    }
}
