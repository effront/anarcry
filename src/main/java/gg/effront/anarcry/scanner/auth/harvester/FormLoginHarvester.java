package gg.effront.anarcry.scanner.auth.harvester;

import gg.effront.anarcry.scanner.auth.AuthException;
import gg.effront.anarcry.scanner.auth.AuthProvider;
import gg.effront.anarcry.scanner.auth.CredentialStore;
import gg.effront.anarcry.scanner.util.HttpClientFactory;

import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public class FormLoginHarvester implements Harvester {

    private static final int TIMEOUT_SECONDS = 15;
    private static final long SESSION_TTL_SECONDS = 3600;

    @Override
    public AuthProvider provider() {
        return AuthProvider.FORM;
    }

    @Override
    public boolean canHandle(String targetUrl, String pageSource) {
        return FormParser.looksLikeLoginPage(pageSource);
    }

    @Override
    public CredentialStore harvest(String targetUrl, String username, String password, Map<String, String> extra)
            throws AuthException {
        try {
            HttpClient hc = HttpClientFactory.noRedirect();
            String pageSource = extra != null ? extra.get("pageSource") : null;

            String loginUrl = extra != null ? extra.get("loginUrl") : null;
            if (loginUrl == null || loginUrl.isBlank()) {
                loginUrl = findLoginUrl(targetUrl, hc);
            }

            if (pageSource == null || pageSource.isBlank()) {
                HttpResponse<String> pageResp = fetchPage(hc, loginUrl);
                pageSource = pageResp.body();
                capturePreflight(pageResp, extra);
            }

            FormParser.LoginForm form = FormParser.findLoginForm(pageSource, loginUrl);
            if (form == null) {
                throw new AuthException("No login form found at " + loginUrl);
            }

            Map<String, String> postData = new LinkedHashMap<>(form.hiddenFields());
            if (form.usernameField() != null) {
                postData.put(form.usernameField(), username);
            }
            postData.put(form.passwordField(), password);

            String body = encodeForm(postData);
            HttpRequest.Builder reqBuilder = HttpRequest.newBuilder().uri(URI.create(form.action()))
                    .timeout(Duration.ofSeconds(TIMEOUT_SECONDS))
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .header("Origin", extractOrigin(form.action())).header("Referer", loginUrl)
                    .POST(HttpRequest.BodyPublishers.ofString(body));

            String preflightCookies = extra != null ? extra.get("preflightCookies") : null;
            if (preflightCookies != null && !preflightCookies.isBlank()) {
                reqBuilder.header("Cookie", preflightCookies);
            }

            HttpResponse<String> loginResp = hc.send(reqBuilder.build(), HttpResponse.BodyHandlers.ofString());

            Map.Entry<String, String> session = extractSessionCookie(loginResp, targetUrl);
            if (session == null) {
                int status = loginResp.statusCode();
                if (status == 302 || status == 301 || status == 303) {
                    String location = loginResp.headers().firstValue("location").orElse(null);
                    if (location != null) {
                        String redirectUrl = URI.create(form.action()).resolve(location).toString();
                        HttpRequest redirectReq = HttpRequest.newBuilder().uri(URI.create(redirectUrl))
                                .timeout(Duration.ofSeconds(TIMEOUT_SECONDS)).GET().build();
                        String redirectCookies = collectSetCookies(loginResp);
                        if (!redirectCookies.isBlank()) {
                            redirectReq = HttpRequest.newBuilder(redirectReq, (n, v) -> true)
                                    .header("Cookie", redirectCookies).build();
                        }
                        HttpResponse<String> redirectResp = hc.send(redirectReq, HttpResponse.BodyHandlers.ofString());
                        session = extractSessionCookie(redirectResp, targetUrl);
                        if (session == null && !redirectCookies.isBlank()) {
                            session = parseMainCookie(redirectCookies, targetUrl);
                        }
                    }
                }
            }

            if (session == null) {
                String allCookies = collectSetCookies(loginResp);
                if (!allCookies.isBlank()) {
                    session = parseMainCookie(allCookies, targetUrl);
                }
            }

            if (session == null) {
                throw new AuthException("Login succeeded (HTTP " + loginResp.statusCode()
                        + ") but no session cookie found in response");
            }

            String cookieName = session.getKey();
            String cookieValue = session.getValue();
            String finalLoginUrl = loginUrl;

            return new CredentialStore(cookieValue, null, SESSION_TTL_SECONDS, AuthProvider.FORM, cookieName,
                    ignored -> {
                        try {
                            return reLogin(finalLoginUrl, username, password, extra);
                        } catch (AuthException e) {
                            throw new RuntimeException(e);
                        }
                    });
        } catch (AuthException e) {
            throw e;
        } catch (Exception e) {
            throw new AuthException("Form login failed: " + e.getMessage(), e);
        }
    }

    private CredentialStore.RefreshResult reLogin(String loginUrl, String username, String password,
            Map<String, String> extra) throws AuthException {
        CredentialStore store = harvest(loginUrl, username, password, extra);
        return new CredentialStore.RefreshResult(store.activeToken(), store.refreshToken(), store.remainingSeconds());
    }

    private String findLoginUrl(String targetUrl, HttpClient hc) throws AuthException {
        try {
            HttpResponse<String> resp = fetchPage(hc, targetUrl);
            String body = resp.body() != null ? resp.body() : "";
            if (FormParser.looksLikeLoginPage(body)) {
                return targetUrl;
            }
            String[] commonPaths = {"/login", "/signin", "/auth/login", "/account/login", "/users/sign_in",
                    "/api/auth/login", "/entrar"};
            String base = extractOrigin(targetUrl);
            for (String path : commonPaths) {
                String url = base + path;
                HttpResponse<String> probe = fetchPage(hc, url);
                if (probe.statusCode() < 400 && FormParser.looksLikeLoginPage(probe.body())) {
                    return url;
                }
            }
            return targetUrl;
        } catch (Exception e) {
            throw new AuthException("Failed to find login page: " + e.getMessage(), e);
        }
    }

    private HttpResponse<String> fetchPage(HttpClient hc, String url) throws Exception {
        HttpRequest req = HttpRequest.newBuilder().uri(URI.create(url)).timeout(Duration.ofSeconds(TIMEOUT_SECONDS))
                .GET().build();
        return hc.send(req, HttpResponse.BodyHandlers.ofString());
    }

    private void capturePreflight(HttpResponse<String> resp, Map<String, String> extra) {
        if (extra == null) {
            return;
        }
        String cookies = collectSetCookies(resp);
        if (!cookies.isBlank()) {
            extra.put("preflightCookies", cookies);
        }
    }

    private static Map.Entry<String, String> extractSessionCookie(HttpResponse<String> resp, String targetUrl) {
        List<String> setCookies = resp.headers().allValues("set-cookie");
        if (setCookies.isEmpty()) {
            return null;
        }
        String host = URI.create(targetUrl).getHost();
        String domain = host.startsWith("www.") ? host.substring(4) : host;
        String[] sessionPatterns = {"session", "sess", "sid", "token", "auth", "login", "jwt"};
        for (String raw : setCookies) {
            String[] parts = raw.split(";", 2);
            int eq = parts[0].indexOf('=');
            if (eq <= 0) {
                continue;
            }
            String name = parts[0].substring(0, eq).trim();
            String value = parts[0].substring(eq + 1).trim();
            if (value.isBlank() || "deleted".equalsIgnoreCase(value)) {
                continue;
            }
            String lower = name.toLowerCase();
            if (lower.contains(domain.split("\\.")[0])) {
                return Map.entry(name, value);
            }
            for (String pattern : sessionPatterns) {
                if (lower.contains(pattern)) {
                    return Map.entry(name, value);
                }
            }
        }
        for (String raw : setCookies) {
            String[] parts = raw.split(";", 2);
            int eq = parts[0].indexOf('=');
            if (eq <= 0) {
                continue;
            }
            String name = parts[0].substring(0, eq).trim();
            String value = parts[0].substring(eq + 1).trim();
            if (!value.isBlank() && !"deleted".equalsIgnoreCase(value) && value.length() > 32) {
                return Map.entry(name, value);
            }
        }
        return null;
    }

    private static Map.Entry<String, String> parseMainCookie(String cookieString, String targetUrl) {
        String[] pairs = cookieString.split(";\\s*");
        for (String pair : pairs) {
            int eq = pair.indexOf('=');
            if (eq <= 0) {
                continue;
            }
            String name = pair.substring(0, eq).trim();
            String value = pair.substring(eq + 1).trim();
            if (!value.isBlank() && value.length() > 32) {
                return Map.entry(name, value);
            }
        }
        return null;
    }

    private static String collectSetCookies(HttpResponse<String> resp) {
        List<String> setCookies = resp.headers().allValues("set-cookie");
        StringBuilder sb = new StringBuilder();
        for (String raw : setCookies) {
            String[] parts = raw.split(";", 2);
            if (!sb.isEmpty()) {
                sb.append("; ");
            }
            sb.append(parts[0].trim());
        }
        return sb.toString();
    }

    private static String encodeForm(Map<String, String> data) {
        StringBuilder sb = new StringBuilder();
        data.forEach((k, v) -> {
            if (!sb.isEmpty()) {
                sb.append("&");
            }
            sb.append(URLEncoder.encode(k, StandardCharsets.UTF_8)).append("=")
                    .append(URLEncoder.encode(v, StandardCharsets.UTF_8));
        });
        return sb.toString();
    }

    private static String extractOrigin(String url) {
        URI uri = URI.create(url);
        String origin = uri.getScheme() + "://" + uri.getHost();
        if (uri.getPort() > 0 && uri.getPort() != 443 && uri.getPort() != 80) {
            origin += ":" + uri.getPort();
        }
        return origin;
    }
}
