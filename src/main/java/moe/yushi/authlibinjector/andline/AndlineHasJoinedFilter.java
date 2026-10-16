/*
 * ANDLINE extensions to authlib-injector.
 * Copyright (C) 2026 ANDLINE contributors.
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package moe.yushi.authlibinjector.andline;

import static moe.yushi.authlibinjector.util.IOUtils.CONTENT_TYPE_JSON;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.regex.Pattern;

import moe.yushi.authlibinjector.httpd.URLFilter;
import moe.yushi.authlibinjector.internal.fi.iki.elonen.IHTTPSession;
import moe.yushi.authlibinjector.internal.fi.iki.elonen.Response;
import moe.yushi.authlibinjector.internal.fi.iki.elonen.Status;
import moe.yushi.authlibinjector.internal.org.json.simple.JSONObject;
import moe.yushi.authlibinjector.internal.org.json.simple.JSONValue;

/**
 * Opt-in server-side hasJoined routing. This filter NEVER detects Premium from a
 * client nickname/host; the trusted encryption adapter must first reserve the
 * server hash + username in the provider registry.
 *
 * Once the reservation is consumed, HTTPS goes ONLY to the selected authority.
 * Failed or missing proof returns no authenticated profile, never a fallback.
 */
public final class AndlineHasJoinedFilter implements URLFilter {
    private static final String DOMAIN = "sessionserver.mojang.com";
    private static final String PATH = "/session/minecraft/hasJoined";
    private static final String MOJANG = "https://sessionserver.mojang.com/session/minecraft/hasJoined";
    private static final int MAX_PROFILE_BYTES = 65_536;
    private static final Pattern NAME = Pattern.compile("[A-Za-z0-9_]{3,16}");
    private static final Pattern HASH = Pattern.compile("-?[0-9a-fA-F]{1,40}");
    private static final Pattern UUID_HEX = Pattern.compile("[0-9a-fA-F]{32}");

    public interface Upstream {
        Optional<String> fetch(AndlineSessionRouteRegistry.Provider provider,
                String name, String serverHash, String ip) throws IOException;
    }

    private final AndlineSessionRouteRegistry registry;
    private final Upstream upstream;

    public AndlineHasJoinedFilter(String gmlRoot, AndlineSessionRouteRegistry registry) {
        this(registry, new SecureHttpsUpstream(gmlRoot));
    }

    /** Public for isolated tests; production uses only SecureHttpsUpstream. */
    public AndlineHasJoinedFilter(AndlineSessionRouteRegistry registry, Upstream upstream) {
        if (registry == null || upstream == null) throw new IllegalArgumentException("Missing routing dependencies");
        this.registry = registry;
        this.upstream = upstream;
    }

    @Override
    public boolean canHandle(String domain) {
        return DOMAIN.equals(domain);
    }

    @Override
    public Optional<Response> handle(String domain, String path, IHTTPSession session) throws IOException {
        if (!DOMAIN.equals(domain) || !PATH.equals(path)) return Optional.empty();
        if (!"GET".equals(session.getMethod())) {
            return Optional.of(Response.newFixedLength(Status.METHOD_NOT_ALLOWED, null, ""));
        }

        String name = single(session, "username");
        String hash = single(session, "serverId");
        String ip = single(session, "ip");
        Optional<String> approved = verify(name, hash, ip);
        return Optional.of(approved.isPresent()
                ? Response.newFixedLength(Status.OK, CONTENT_TYPE_JSON, approved.get())
                : Response.newFixedLength(Status.NO_CONTENT, null, ""));
    }

    /**
     * A positive result requires BOTH a one-time registered authority and the
     * corresponding HTTPS authority's actual response. Unmatched requests fail.
     */
    public Optional<String> verify(String name, String hash, String ip) throws IOException {
        if (name == null || !NAME.matcher(name).matches()
                || hash == null || !HASH.matcher(hash).matches()) return Optional.empty();
        if (ip != null && (ip.length() > 45 || !ip.matches("[0-9a-fA-F:.]+"))) {
            return Optional.empty();
        }

        // Consume BEFORE the remote call. Retries cannot switch provider.
        Optional<AndlineSessionRouteRegistry.Route> choice = registry.consume(hash, name);
        if (!choice.isPresent()) return Optional.empty();

        Optional<String> response = upstream.fetch(choice.get().provider(), name, hash, ip);
        if (!response.isPresent()) return Optional.empty();
        String body = response.get();
        if (body.length() > MAX_PROFILE_BYTES) return Optional.empty();

        Object parsed = JSONValue.parse(body);
        if (!(parsed instanceof JSONObject)) return Optional.empty();
        JSONObject profile = (JSONObject) parsed;
        Object returnedName = profile.get("name");
        Object returnedId = profile.get("id");
        if (!(returnedName instanceof String) || !(returnedId instanceof String)) return Optional.empty();
        String profileName = (String) returnedName;
        String profileId = (String) returnedId;
        if (!NAME.matcher(profileName).matches() || !profileName.equalsIgnoreCase(name)
                || !UUID_HEX.matcher(profileId).matches()
                || profileId.equals("00000000000000000000000000000000")) return Optional.empty();
        return Optional.of(body);
    }

    private static String single(IHTTPSession session, String field) {
        List<String> values = session.getParameters().get(field);
        return values != null && values.size() == 1 ? values.get(0) : null;
    }

    private static final class SecureHttpsUpstream implements Upstream {
        private final String gml;

        SecureHttpsUpstream(String gmlRoot) {
            this.gml = requireGmlHttpsRoot(gmlRoot);
        }

        @Override
        public Optional<String> fetch(AndlineSessionRouteRegistry.Provider provider,
                String name, String serverHash, String ip) throws IOException {
            String endpoint = provider == AndlineSessionRouteRegistry.Provider.MOJANG
                    ? MOJANG : gml + "sessionserver/session/minecraft/hasJoined";
            String query = "username=" + encode(name) + "&serverId=" + encode(serverHash);
            if (ip != null) query += "&ip=" + encode(ip);
            URL url = new URL(endpoint + "?" + query);
            HttpURLConnection connection = (HttpURLConnection) url.openConnection();
            try {
                connection.setInstanceFollowRedirects(false);
                connection.setConnectTimeout(3_000);
                connection.setReadTimeout(3_000);
                connection.setRequestMethod("GET");
                connection.setRequestProperty("Accept", "application/json");
                if (connection.getResponseCode() != 200) return Optional.empty();
                try (InputStream input = connection.getInputStream();
                     ByteArrayOutputStream output = new ByteArrayOutputStream()) {
                    byte[] buffer = new byte[4096];
                    int count;
                    while ((count = input.read(buffer)) != -1) {
                        if (output.size() + count > MAX_PROFILE_BYTES) return Optional.empty();
                        output.write(buffer, 0, count);
                    }
                    return Optional.of(new String(output.toByteArray(), StandardCharsets.UTF_8));
                }
            } finally {
                connection.disconnect();
            }
        }

        private static String requireGmlHttpsRoot(String root) {
            try {
                URL url = new URL(root);
                if (!"https".equals(url.getProtocol().toLowerCase(Locale.ROOT))
                        || url.getHost().isEmpty() || url.getUserInfo() != null
                        || url.getQuery() != null || url.getRef() != null) {
                    throw new IllegalArgumentException("GML URL must be a fixed HTTPS API root");
                }
                return root.endsWith("/") ? root : root + "/";
            } catch (IOException | NullPointerException error) {
                throw new IllegalArgumentException("Invalid GML URL", error);
            }
        }

        private static String encode(String value) throws IOException {
            return URLEncoder.encode(value, "UTF-8");
        }
    }
}
