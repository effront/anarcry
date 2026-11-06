package gg.effront.anarcry.scanner.auth;

import gg.effront.anarcry.scanner.auth.firebase.FirebaseConfig;
import gg.effront.anarcry.scanner.auth.firebase.FirebaseConfigExtractor;
import gg.effront.anarcry.scanner.auth.harvester.FormParser;
import gg.effront.anarcry.scanner.auth.harvester.HarvesterRegistry;
import gg.effront.anarcry.scanner.util.HttpClientFactory;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class ProviderDetector {

    public record DiscoveryResult(AuthProvider provider, String clientId, String apiKey, String authEndpoint,
            String tokenEndpoint, Map<String, String> extra) {
    }

    private ProviderDetector() {
    }

    public static DiscoveryResult detect(String targetUrl) {
        try {
            HttpClient hc = HttpClientFactory.http2();
            HttpRequest req = HttpRequest.newBuilder().uri(URI.create(targetUrl)).timeout(Duration.ofSeconds(15)).GET()
                    .build();
            HttpResponse<String> resp = hc.send(req, HttpResponse.BodyHandlers.ofString());
            String body = resp.body() != null ? resp.body() : "";
            DiscoveryResult result = detectFromPage(targetUrl, body);
            if (result != null && HarvesterRegistry.isSupported(result.provider())) {
                return result;
            }
            FirebaseConfig fbConfig = FirebaseConfigExtractor.extractFromUrl(targetUrl);
            if (fbConfig != null) {
                return buildFirebaseResult(fbConfig);
            }
            return null;
        } catch (Exception e) {
            return null;
        }
    }

    public static DiscoveryResult detectFromPage(String targetUrl, String pageSource) {
        String lower = pageSource.toLowerCase();

        if (lower.contains("firebaseapp.com") || lower.contains("/__/auth/")
                || (lower.contains("firebase") && lower.contains("apikey"))) {
            FirebaseConfig config = FirebaseConfigExtractor.extract(pageSource);
            if (config != null) {
                return buildFirebaseResult(config);
            }
        }

        if (lower.contains(".auth0.com")) {
            String clientId = extractPattern(pageSource, "clientId\\s*[:=]\\s*[\"']([^\"']+)[\"']");
            String domain = extractPattern(pageSource, "([\\w-]+\\.auth0\\.com)");
            return new DiscoveryResult(AuthProvider.AUTH0, clientId, null,
                    domain != null ? "https://" + domain + "/authorize" : null,
                    domain != null ? "https://" + domain + "/oauth/token" : null, Map.of());
        }

        if (lower.contains(".supabase.co")) {
            String anonKey = extractPattern(pageSource,
                    "(?:supabaseKey|anon[_-]?key)\\s*[:=]\\s*[\"']([A-Za-z0-9._-]+)[\"']");
            String projectUrl = extractPattern(pageSource, "(https://[\\w-]+\\.supabase\\.co)");
            return new DiscoveryResult(AuthProvider.SUPABASE, null, anonKey,
                    projectUrl != null ? projectUrl + "/auth/v1/authorize" : null,
                    projectUrl != null ? projectUrl + "/auth/v1/token?grant_type=password" : null, Map.of());
        }

        if (lower.contains("/auth/realms/")) {
            String realm = extractPattern(pageSource, "/auth/realms/([^/\"']+)");
            String baseUrl = extractPattern(pageSource, "(https?://[^/]+)/auth/realms/");
            return new DiscoveryResult(AuthProvider.KEYCLOAK, null, null,
                    baseUrl != null && realm != null
                            ? baseUrl + "/auth/realms/" + realm + "/protocol/openid-connect/auth"
                            : null,
                    baseUrl != null && realm != null
                            ? baseUrl + "/auth/realms/" + realm + "/protocol/openid-connect/token"
                            : null,
                    realm != null ? Map.of("realm", realm) : Map.of());
        }

        DiscoveryResult oidcResult = probeOidc(targetUrl);
        if (oidcResult != null) {
            return oidcResult;
        }

        if (FormParser.looksLikeLoginPage(pageSource)) {
            FormParser.LoginForm form = FormParser.findLoginForm(pageSource, targetUrl);
            if (form != null) {
                Map<String, String> formExtra = new HashMap<>();
                if (form.usernameField() != null) {
                    formExtra.put("usernameField", form.usernameField());
                }
                formExtra.put("passwordField", form.passwordField());
                return new DiscoveryResult(AuthProvider.FORM, null, null, form.action(), null, formExtra);
            }
        }

        return null;
    }

    private static DiscoveryResult probeOidc(String targetUrl) {
        try {
            URI base = URI.create(targetUrl);
            String oidcUrl = base.getScheme() + "://" + base.getHost()
                    + (base.getPort() > 0 ? ":" + base.getPort() : "") + "/.well-known/openid-configuration";
            HttpClient hc = HttpClientFactory.http2();
            HttpRequest req = HttpRequest.newBuilder().uri(URI.create(oidcUrl)).timeout(Duration.ofSeconds(5)).GET()
                    .build();
            HttpResponse<String> resp = hc.send(req, HttpResponse.BodyHandlers.ofString());
            if (resp.statusCode() == 200 && resp.body() != null && resp.body().contains("token_endpoint")) {
                String tokenEndpoint = extractPattern(resp.body(), "\"token_endpoint\"\\s*:\\s*\"([^\"]+)\"");
                String authEndpoint = extractPattern(resp.body(), "\"authorization_endpoint\"\\s*:\\s*\"([^\"]+)\"");
                return new DiscoveryResult(AuthProvider.OIDC, null, null, authEndpoint, tokenEndpoint, Map.of());
            }
        } catch (Exception ignored) {
        }
        return null;
    }

    private static DiscoveryResult buildFirebaseResult(FirebaseConfig config) {
        Map<String, String> extra = new HashMap<>();
        if (config.projectId() != null) {
            extra.put("projectId", config.projectId());
        }
        if (config.authDomain() != null) {
            extra.put("authDomain", config.authDomain());
        }
        return new DiscoveryResult(AuthProvider.FIREBASE, null, config.apiKey(),
                config.identityToolkitUrl() + "/accounts:signInWithPassword?key=" + config.apiKey(),
                config.secureTokenUrl() + "/token?key=" + config.apiKey(), extra);
    }

    private static String extractPattern(String text, String regex) {
        Matcher m = Pattern.compile(regex).matcher(text);
        return m.find() ? m.group(1) : null;
    }
}
