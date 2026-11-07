package gg.effront.anarcry.apiclient.auth;

import gg.effront.anarcry.apiclient.model.AuthConfig;
import gg.effront.anarcry.apiclient.model.HttpRequestDef;
import gg.effront.anarcry.apiclient.vars.VariableStore;

import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Consumer;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class OAuth2Injector implements AuthInjector {

    private static final Pattern TOKEN_PATTERN = Pattern.compile("\"access_token\"\\s*:\\s*\"([^\"]+)\"");
    private static final Pattern REFRESH_PATTERN = Pattern.compile("\"refresh_token\"\\s*:\\s*\"([^\"]+)\"");
    private static final Pattern EXPIRES_PATTERN = Pattern.compile("\"expires_in\"\\s*:\\s*(\\d+)");

    private final Map<String, CachedToken> tokenCache = new ConcurrentHashMap<>();
    private final HttpClient httpClient;
    private Consumer<String> log = s -> {
    };

    public record CachedToken(String accessToken, String refreshToken, Instant expiresAt) {

        public boolean isExpired() {
            return expiresAt != null && Instant.now().isAfter(expiresAt);
        }
    }

    public OAuth2Injector() {
        this.httpClient = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10))
                .followRedirects(HttpClient.Redirect.NORMAL).build();
    }

    public void setLog(Consumer<String> log) {
        this.log = log;
    }

    @Override
    public String mode() {
        return "oauth2";
    }

    @Override
    public HttpRequestDef inject(HttpRequestDef request, AuthConfig auth, VariableStore vars) {
        if (!(auth instanceof AuthConfig.OAuth2 oauth)) {
            return request;
        }
        String token = resolveToken(oauth);
        if (token == null) {
            return request;
        }
        if ("url".equalsIgnoreCase(oauth.tokenPlacement())) {
            return AuthInjectorRegistry.addQueryParam(request, "access_token", token);
        }
        return AuthInjectorRegistry.addHeader(request, "Authorization", "Bearer " + token);
    }

    public void clearCache() {
        tokenCache.clear();
    }

    private String resolveToken(AuthConfig.OAuth2 oauth) {
        String cacheKey = oauth.accessTokenUrl() + ":" + oauth.clientId();
        CachedToken cached = tokenCache.get(cacheKey);

        if (cached != null && !cached.isExpired()) {
            return cached.accessToken();
        }

        if (cached != null && cached.refreshToken() != null && oauth.refreshTokenUrl() != null
                && !oauth.refreshTokenUrl().isBlank()) {
            CachedToken refreshed = refreshToken(oauth, cached.refreshToken());
            if (refreshed != null) {
                tokenCache.put(cacheKey, refreshed);
                return refreshed.accessToken();
            }
        }

        CachedToken fresh = fetchToken(oauth);
        if (fresh != null) {
            tokenCache.put(cacheKey, fresh);
            return fresh.accessToken();
        }
        return null;
    }

    private CachedToken fetchToken(AuthConfig.OAuth2 oauth) {
        StringBuilder formBody = new StringBuilder();
        formBody.append("grant_type=").append(enc(oauth.grantType()));

        if (oauth.scope() != null && !oauth.scope().isBlank()) {
            formBody.append("&scope=").append(enc(oauth.scope()));
        }

        boolean credsInBody = "body".equalsIgnoreCase(oauth.credPlacement());
        if (credsInBody) {
            formBody.append("&client_id=").append(enc(oauth.clientId()));
            if (oauth.clientSecret() != null) {
                formBody.append("&client_secret=").append(enc(oauth.clientSecret()));
            }
        }

        if ("password".equals(oauth.grantType()) && oauth.additionalParams() != null) {
            String username = oauth.additionalParams().get("username");
            String password = oauth.additionalParams().get("password");
            if (username != null) {
                formBody.append("&username=").append(enc(username));
            }
            if (password != null) {
                formBody.append("&password=").append(enc(password));
            }
        }

        if (oauth.additionalParams() != null) {
            for (var entry : oauth.additionalParams().entrySet()) {
                String k = entry.getKey();
                if (!"username".equals(k) && !"password".equals(k)) {
                    formBody.append("&").append(enc(k)).append("=").append(enc(entry.getValue()));
                }
            }
        }

        HttpRequest.Builder builder = HttpRequest.newBuilder().uri(URI.create(oauth.accessTokenUrl()))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(formBody.toString())).timeout(Duration.ofSeconds(15));

        if (!credsInBody && oauth.clientId() != null) {
            String creds = oauth.clientId() + ":" + (oauth.clientSecret() != null ? oauth.clientSecret() : "");
            builder.header("Authorization",
                    "Basic " + Base64.getEncoder().encodeToString(creds.getBytes(StandardCharsets.UTF_8)));
        }

        return executeTokenRequest(builder.build());
    }

    private CachedToken refreshToken(AuthConfig.OAuth2 oauth, String refreshTokenValue) {
        StringBuilder formBody = new StringBuilder();
        formBody.append("grant_type=refresh_token");
        formBody.append("&refresh_token=").append(enc(refreshTokenValue));
        formBody.append("&client_id=").append(enc(oauth.clientId()));
        if (oauth.clientSecret() != null && !oauth.clientSecret().isBlank()) {
            formBody.append("&client_secret=").append(enc(oauth.clientSecret()));
        }

        HttpRequest req = HttpRequest.newBuilder().uri(URI.create(oauth.refreshTokenUrl()))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(formBody.toString())).timeout(Duration.ofSeconds(15)).build();

        return executeTokenRequest(req);
    }

    private CachedToken executeTokenRequest(HttpRequest req) {
        try {
            HttpResponse<String> resp = httpClient.send(req, HttpResponse.BodyHandlers.ofString());
            if (resp.statusCode() >= 200 && resp.statusCode() < 300) {
                return parseTokenResponse(resp.body());
            }
            log.accept("[!] OAuth2 token request failed: HTTP " + resp.statusCode());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            log.accept("[!] OAuth2 token request interrupted");
        } catch (Exception e) {
            log.accept("[!] OAuth2 token request error: " + e.getMessage());
        }
        return null;
    }

    private CachedToken parseTokenResponse(String body) {
        Matcher tokenMatcher = TOKEN_PATTERN.matcher(body);
        if (!tokenMatcher.find()) {
            return null;
        }
        String accessToken = tokenMatcher.group(1);

        Matcher refreshMatcher = REFRESH_PATTERN.matcher(body);
        String refreshTokenVal = refreshMatcher.find() ? refreshMatcher.group(1) : null;

        Matcher expiresMatcher = EXPIRES_PATTERN.matcher(body);
        long expiresIn = expiresMatcher.find() ? Long.parseLong(expiresMatcher.group(1)) : 3600;

        return new CachedToken(accessToken, refreshTokenVal, Instant.now().plusSeconds(expiresIn));
    }

    private static String enc(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }
}
