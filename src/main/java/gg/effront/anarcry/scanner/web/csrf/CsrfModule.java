package gg.effront.anarcry.scanner.web.csrf;

import gg.effront.anarcry.model.Finding;
import gg.effront.anarcry.model.Severity;
import gg.effront.anarcry.scanner.ScanContext;
import gg.effront.anarcry.scanner.Scanner;
import gg.effront.anarcry.scanner.util.Http;
import gg.effront.anarcry.scanner.util.HttpClientFactory;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.function.Consumer;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class CsrfModule implements Scanner {

    private static final List<String> PROBE_PATHS = List.of("/", "/login", "/account", "/settings", "/profile",
            "/api/email", "/api/password", "/api/user", "/admin", "/transfer", "/checkout");

    // Matches <form ...> tags with method attribute (POST, PUT, DELETE, PATCH)
    private static final Pattern FORM_TAG = Pattern.compile(
            "<form\\b[^>]*\\bmethod\\s*=\\s*['\"]?(POST|PUT|DELETE|PATCH)['\"]?[^>]*>",
            Pattern.CASE_INSENSITIVE | Pattern.DOTALL);

    // Matches action attribute inside a form tag
    private static final Pattern FORM_ACTION = Pattern.compile("\\baction\\s*=\\s*['\"]([^'\"]*)['\"]",
            Pattern.CASE_INSENSITIVE);

    // Matches the closing form tag to delimit form body
    private static final Pattern FORM_CLOSE = Pattern.compile("</form>", Pattern.CASE_INSENSITIVE);

    // Matches hidden inputs that look like CSRF tokens
    private static final Pattern CSRF_INPUT = Pattern.compile(
            "<input\\b[^>]*\\btype\\s*=\\s*['\"]hidden['\"][^>]*\\bname\\s*=\\s*['\"]("
                    + "csrf|_csrf|token|_token|csrf_token|csrfmiddlewaretoken"
                    + "|authenticity_token|XSRF-TOKEN|__RequestVerificationToken"
                    + "|anti-csrf-token|anticsrf|csrfToken" + ")['\"][^>]*\\bvalue\\s*=\\s*['\"]([^'\"]*)['\"]",
            Pattern.CASE_INSENSITIVE);

    // Alternate order: value before name
    private static final Pattern CSRF_INPUT_ALT = Pattern
            .compile("<input\\b[^>]*\\bvalue\\s*=\\s*['\"]([^'\"]*)['\"][^>]*\\bname\\s*=\\s*['\"]("
                    + "csrf|_csrf|token|_token|csrf_token|csrfmiddlewaretoken"
                    + "|authenticity_token|XSRF-TOKEN|__RequestVerificationToken"
                    + "|anti-csrf-token|anticsrf|csrfToken" + ")['\"]", Pattern.CASE_INSENSITIVE);

    // AJAX patterns that suggest state-changing requests in JS
    private static final Pattern AJAX_POST = Pattern.compile(
            "(fetch\\s*\\([^)]*['\"]POST['\"]" + "|XMLHttpRequest[^;]*\\.open\\s*\\([^)]*['\"]POST['\"]"
                    + "|\\.ajax\\s*\\(\\s*\\{[^}]*type\\s*:\\s*['\"]POST['\"]" + "|\\.post\\s*\\()",
            Pattern.CASE_INSENSITIVE);

    // Meta tag CSRF token (Rails, Laravel, etc.)
    private static final Pattern META_CSRF = Pattern.compile("<meta\\b[^>]*\\bname\\s*=\\s*['\"]("
            + "csrf-token|csrf-param|_csrf_token|_token" + ")['\"][^>]*\\bcontent\\s*=\\s*['\"]([^'\"]+)['\"]",
            Pattern.CASE_INSENSITIVE);

    private record FormInfo(String action, String method, String tokenName, String tokenValue) {
    }

    @Override
    public String id() {
        return "CSRF";
    }

    @Override
    public List<Finding> scan(ScanContext ctx, Consumer<String> log) throws Exception {
        List<Finding> findings = new ArrayList<>();
        HttpClient hc = HttpClientFactory.http2();

        String scheme = ctx.isHttps() ? "https" : "http";
        int defPort = ctx.isHttps() ? 443 : 80;
        String baseUrl = scheme + "://" + ctx.host() + (ctx.port() != defPort ? ":" + ctx.port() : "");

        log.accept("[~] CSRF: iniciando deteccao em " + baseUrl);

        // Collect paths: built-in probes + crawler-discovered paths
        Set<String> allPaths = new LinkedHashSet<>(PROBE_PATHS);
        for (String p : ctx.discoveredPaths().paths()) {
            if (p.startsWith("/")) {
                allPaths.add(p);
            } else if (p.startsWith(baseUrl)) {
                allPaths.add(p.substring(baseUrl.length()));
            }
        }

        log.accept("[~] CSRF: " + allPaths.size() + " paths para analise (" + PROBE_PATHS.size() + " built-in + "
                + (allPaths.size() - PROBE_PATHS.size()) + " discovered)");

        Set<String> checkedEndpoints = new HashSet<>();

        // Phase 1: SameSite cookie check on root
        checkSameSiteCookie(ctx, hc, baseUrl, log, findings);

        // Phase 2: Discover forms and check CSRF protections
        for (String path : allPaths) {
            if (Thread.currentThread().isInterrupted()) {
                log.accept("[!] CSRF: interrupted");
                break;
            }

            String url = baseUrl + path;
            try {
                HttpRequest getReq = HttpRequest.newBuilder().uri(URI.create(url)).timeout(Duration.ofSeconds(6)).GET()
                        .build();
                HttpResponse<String> resp = Http.send(ctx, hc, getReq, HttpResponse.BodyHandlers.ofString(), id());

                if (resp.statusCode() < 200 || resp.statusCode() >= 400) {
                    continue;
                }

                String body = resp.body() != null ? resp.body() : "";
                String contentType = resp.headers().firstValue("content-type").orElse("");

                if (!contentType.contains("text/html")) {
                    continue;
                }

                // Check for meta CSRF tokens (indicates framework-level protection)
                boolean hasMetaCsrf = META_CSRF.matcher(body).find();

                // Check for AJAX POST patterns without visible CSRF headers
                if (AJAX_POST.matcher(body).find() && !hasMetaCsrf) {
                    log.accept("[~] CSRF: AJAX POST detectado sem meta CSRF em " + path);
                }

                // Parse forms
                List<FormInfo> forms = parseForms(body, path);
                if (forms.isEmpty()) {
                    continue;
                }

                log.accept("[~] CSRF: " + forms.size() + " form(s) state-changing em " + path);

                for (FormInfo form : forms) {
                    String endpoint = form.action().isEmpty() ? path : form.action();
                    String dedupKey = form.method() + "|" + endpoint;
                    if (!checkedEndpoints.add(dedupKey)) {
                        continue;
                    }

                    if (form.tokenName().isEmpty()) {
                        // No CSRF token at all -- check if meta tag provides one
                        if (!hasMetaCsrf) {
                            log.accept("[!!] CSRF: form sem token em " + path + " -> " + endpoint);
                            findings.add(buildFinding(endpoint, "No CSRF token on state-changing form", Severity.HIGH,
                                    "Form action: " + endpoint + " | Method: " + form.method() + " | Page: " + path
                                            + " | No hidden CSRF input found" + " | No meta CSRF tag found",
                                    "State-changing endpoint has no CSRF protection."
                                            + " An attacker can forge requests from"
                                            + " a malicious page while the victim" + " is authenticated.",
                                    generatePoc(baseUrl, endpoint, form.method()),
                                    "Implement anti-CSRF tokens (synchronizer token"
                                            + " pattern). Set SameSite=Lax or Strict"
                                            + " on session cookies. Validate Origin" + " and Referer headers."));
                        }
                    } else {
                        // Token found -- run validation tests
                        log.accept("[~] CSRF: token '" + form.tokenName() + "' encontrado em " + path
                                + " -- testando validacao");
                        testTokenValidation(ctx, hc, baseUrl, path, form, log, findings);
                    }
                }

                // Phase 5: Origin/Referer validation on forms found
                for (FormInfo form : forms) {
                    String endpoint = form.action().isEmpty() ? path : form.action();
                    checkOriginValidation(ctx, hc, baseUrl, endpoint, form, log, findings);
                }

            } catch (Exception e) {
                // Connection errors expected for unreachable paths
            }
        }

        if (findings.isEmpty()) {
            log.accept("[+] CSRF: nenhuma vulnerabilidade detectada");
        }
        return findings;
    }

    // ---------------------------------------------------------------------------
    // Phase 1: SameSite cookie check
    // ---------------------------------------------------------------------------

    private void checkSameSiteCookie(ScanContext ctx, HttpClient hc, String baseUrl, Consumer<String> log,
            List<Finding> findings) throws Exception {
        HttpRequest req = HttpRequest.newBuilder().uri(URI.create(baseUrl + "/")).timeout(Duration.ofSeconds(6)).GET()
                .build();
        HttpResponse<Void> resp = Http.send(ctx, hc, req, HttpResponse.BodyHandlers.discarding(), id());

        List<String> setCookies = resp.headers().allValues("set-cookie");
        for (String cookie : setCookies) {
            String lower = cookie.toLowerCase(Locale.ROOT);
            // Only check session-like cookies
            boolean isSession = lower.startsWith("session") || lower.startsWith("sess") || lower.startsWith("sid")
                    || lower.startsWith("jsessionid") || lower.startsWith("phpsessid")
                    || lower.startsWith("connect.sid") || lower.startsWith("_session") || lower.startsWith("token");

            if (!isSession) {
                continue;
            }

            String cookieName = cookie.split("=")[0].trim();

            if (!lower.contains("samesite")) {
                log.accept("[!] CSRF: session cookie '" + cookieName + "' sem SameSite");
                findings.add(buildFinding(baseUrl + "/", "Missing SameSite on session cookie '" + cookieName + "'",
                        Severity.MEDIUM, "Set-Cookie: " + cookie + " | SameSite attribute: absent",
                        "Without SameSite attribute, the browser sends the"
                                + " session cookie on cross-site requests, enabling"
                                + " CSRF attacks on browsers that default to None.",
                        "curl -sI '" + baseUrl + "/' | grep -i set-cookie",
                        "Set SameSite=Lax or SameSite=Strict on all session"
                                + " cookies. Combine with Secure and HttpOnly flags."));
            } else if (lower.contains("samesite=none")) {
                log.accept("[!] CSRF: session cookie '" + cookieName + "' com SameSite=None");
                findings.add(buildFinding(baseUrl + "/", "SameSite=None on session cookie '" + cookieName + "'",
                        Severity.MEDIUM, "Set-Cookie: " + cookie + " | SameSite=None explicitly set",
                        "SameSite=None disables cross-site cookie protection."
                                + " The browser sends the cookie with every cross-site"
                                + " request, enabling CSRF unless other defenses exist.",
                        "curl -sI '" + baseUrl + "/' | grep -i set-cookie",
                        "Change SameSite to Lax or Strict. Only use None when"
                                + " cross-origin embedding is required, and always"
                                + " combined with anti-CSRF tokens."));
            }
        }
    }

    // ---------------------------------------------------------------------------
    // Phase 2: Parse forms from HTML
    // ---------------------------------------------------------------------------

    private List<FormInfo> parseForms(String html, String currentPath) {
        List<FormInfo> forms = new ArrayList<>();
        Matcher formMatcher = FORM_TAG.matcher(html);

        while (formMatcher.find()) {
            String method = formMatcher.group(1).toUpperCase(Locale.ROOT);
            int formStart = formMatcher.start();
            String formTag = formMatcher.group(0);

            // Extract action
            Matcher actionMatcher = FORM_ACTION.matcher(formTag);
            String action = actionMatcher.find() ? actionMatcher.group(1) : "";
            if (action.isEmpty()) {
                action = currentPath;
            }

            // Find form body (between open and close tags)
            Matcher closeMatcher = FORM_CLOSE.matcher(html);
            String formBody;
            if (closeMatcher.find(formStart)) {
                formBody = html.substring(formStart, closeMatcher.end());
            } else {
                formBody = html.substring(formStart);
            }

            // Look for CSRF token in hidden inputs
            String tokenName = "";
            String tokenValue = "";
            Matcher csrfMatcher = CSRF_INPUT.matcher(formBody);
            if (csrfMatcher.find()) {
                tokenName = csrfMatcher.group(1);
                tokenValue = csrfMatcher.group(2);
            } else {
                // Try alternate attribute order
                Matcher altMatcher = CSRF_INPUT_ALT.matcher(formBody);
                if (altMatcher.find()) {
                    tokenValue = altMatcher.group(1);
                    tokenName = altMatcher.group(2);
                }
            }

            forms.add(new FormInfo(action, method, tokenName, tokenValue));
        }

        return forms;
    }

    // ---------------------------------------------------------------------------
    // Phase 3: Token validation tests
    // ---------------------------------------------------------------------------

    private void testTokenValidation(ScanContext ctx, HttpClient hc, String baseUrl, String pagePath, FormInfo form,
            Consumer<String> log, List<Finding> findings) throws Exception {

        String actionUrl = resolveUrl(baseUrl, form.action());

        // Get baseline: submit with valid token
        int baselineStatus = submitForm(ctx, hc, actionUrl, form.tokenName(), form.tokenValue());
        if (baselineStatus < 0) {
            log.accept("[~] CSRF: baseline request falhou para " + actionUrl);
            return;
        }

        // Test A: remove token entirely
        int noTokenStatus = submitForm(ctx, hc, actionUrl, null, null);
        if (noTokenStatus >= 0 && isAccepted(noTokenStatus) && isAccepted(baselineStatus)) {
            log.accept("[!!] CSRF: token removivel em " + actionUrl);
            findings.add(buildFinding(form.action(), "CSRF token accepted when removed", Severity.HIGH,
                    "Endpoint: " + actionUrl + " | Token param: " + form.tokenName() + " | With token: HTTP "
                            + baselineStatus + " | Without token: HTTP " + noTokenStatus,
                    "The server accepts requests without a CSRF token." + " An attacker can submit forged requests"
                            + " without needing to obtain a valid token.",
                    generatePoc(baseUrl, form.action(), form.method()),
                    "Reject requests missing the CSRF token." + " Return HTTP 403 when the token is absent."));
            return; // No need for further tests
        }

        // Test B: submit with random/modified token
        String fakeToken = "anarcry_csrf_probe_" + System.nanoTime();
        int fakeTokenStatus = submitForm(ctx, hc, actionUrl, form.tokenName(), fakeToken);
        if (fakeTokenStatus >= 0 && isAccepted(fakeTokenStatus) && isAccepted(baselineStatus)) {
            log.accept("[!!] CSRF: token nao validado em " + actionUrl);
            findings.add(buildFinding(form.action(), "CSRF token not validated (random token accepted)", Severity.HIGH,
                    "Endpoint: " + actionUrl + " | Token param: " + form.tokenName() + " | Valid token: HTTP "
                            + baselineStatus + " | Random token: HTTP " + fakeTokenStatus + " | Fake value: "
                            + fakeToken,
                    "The server does not validate the CSRF token value."
                            + " Any arbitrary value is accepted, making the" + " protection ineffective.",
                    generatePoc(baseUrl, form.action(), form.method()),
                    "Validate the token against the server-side session." + " Use the synchronizer token pattern or"
                            + " a signed double-submit cookie."));
            return;
        }

        // Test C: submit with empty token
        int emptyTokenStatus = submitForm(ctx, hc, actionUrl, form.tokenName(), "");
        if (emptyTokenStatus >= 0 && isAccepted(emptyTokenStatus) && isAccepted(baselineStatus)) {
            log.accept("[!!] CSRF: token vazio aceito em " + actionUrl);
            findings.add(buildFinding(form.action(), "CSRF token accepted when empty", Severity.HIGH,
                    "Endpoint: " + actionUrl + " | Token param: " + form.tokenName() + " | Valid token: HTTP "
                            + baselineStatus + " | Empty token: HTTP " + emptyTokenStatus,
                    "The server accepts an empty CSRF token value." + " An attacker can forge requests with an"
                            + " empty token parameter.",
                    generatePocWithToken(baseUrl, form.action(), form.method(), form.tokenName(), ""),
                    "Reject empty token values. Validate token length" + " and entropy before comparing."));
        }
    }

    // ---------------------------------------------------------------------------
    // Phase 5: Origin/Referer validation
    // ---------------------------------------------------------------------------

    private void checkOriginValidation(ScanContext ctx, HttpClient hc, String baseUrl, String endpoint, FormInfo form,
            Consumer<String> log, List<Finding> findings) throws Exception {

        String actionUrl = resolveUrl(baseUrl, endpoint);

        // Build a POST with a foreign Origin header
        String body = form.tokenName().isEmpty() ? "test=1" : form.tokenName() + "=" + form.tokenValue();

        try {
            HttpRequest crossOriginReq = HttpRequest.newBuilder().uri(URI.create(actionUrl))
                    .timeout(Duration.ofSeconds(6)).header("Content-Type", "application/x-www-form-urlencoded")
                    .header("Origin", "https://evil.com").header("Referer", "https://evil.com/csrf-poc")
                    .POST(HttpRequest.BodyPublishers.ofString(body)).build();
            HttpResponse<Void> resp = Http.send(ctx, hc, crossOriginReq, HttpResponse.BodyHandlers.discarding(), id());

            // Also send with legitimate origin for baseline
            HttpRequest legitimateReq = HttpRequest.newBuilder().uri(URI.create(actionUrl))
                    .timeout(Duration.ofSeconds(6)).header("Content-Type", "application/x-www-form-urlencoded")
                    .header("Origin", baseUrl).header("Referer", baseUrl + "/")
                    .POST(HttpRequest.BodyPublishers.ofString(body)).build();
            HttpResponse<Void> legResp = Http.send(ctx, hc, legitimateReq, HttpResponse.BodyHandlers.discarding(),
                    id());

            // If cross-origin is accepted the same as legitimate, report
            if (isAccepted(resp.statusCode()) && isAccepted(legResp.statusCode()) && !isRejected(resp.statusCode())) {
                log.accept("[!] CSRF: Origin/Referer nao validados em " + endpoint);
                findings.add(buildFinding(endpoint, "Origin/Referer not validated on state-changing endpoint",
                        Severity.MEDIUM,
                        "Endpoint: " + actionUrl + " | Cross-Origin: HTTP " + resp.statusCode()
                                + " | Legitimate-Origin: HTTP " + legResp.statusCode()
                                + " | Origin sent: https://evil.com" + " | Referer sent: https://evil.com/csrf-poc",
                        "The server does not validate Origin or Referer headers."
                                + " Combined with a missing or weak CSRF token,"
                                + " this allows cross-site request forgery.",
                        "curl -s -X POST '" + actionUrl + "'" + " -H 'Origin: https://evil.com'"
                                + " -H 'Referer: https://evil.com/csrf-poc'" + " -H 'Content-Type:"
                                + " application/x-www-form-urlencoded'" + " -d '" + body + "'",
                        "Validate Origin and Referer headers against an"
                                + " allowlist of trusted domains. Reject requests"
                                + " with missing or untrusted Origin on" + " state-changing endpoints."));
            }
        } catch (Exception e) {
            // Connection errors expected
        }
    }

    // ---------------------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------------------

    private int submitForm(ScanContext ctx, HttpClient hc, String actionUrl, String tokenName, String tokenValue)
            throws Exception {
        try {
            String body;
            if (tokenName == null) {
                body = "anarcry_probe=1";
            } else if (tokenValue == null) {
                body = "anarcry_probe=1";
            } else {
                body = java.net.URLEncoder.encode(tokenName, "UTF-8") + "="
                        + java.net.URLEncoder.encode(tokenValue, "UTF-8");
            }

            HttpRequest req = HttpRequest.newBuilder().uri(URI.create(actionUrl)).timeout(Duration.ofSeconds(6))
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .POST(HttpRequest.BodyPublishers.ofString(body)).build();
            HttpResponse<Void> resp = Http.send(ctx, hc, req, HttpResponse.BodyHandlers.discarding(), id());
            return resp.statusCode();
        } catch (Exception e) {
            return -1;
        }
    }

    private static boolean isAccepted(int status) {
        return status >= 200 && status < 400;
    }

    private static boolean isRejected(int status) {
        return status == 403 || status == 419 || status == 422 || status == 440;
    }

    private String resolveUrl(String baseUrl, String action) {
        if (action.startsWith("http://") || action.startsWith("https://")) {
            return action;
        }
        if (action.startsWith("/")) {
            return baseUrl + action;
        }
        return baseUrl + "/" + action;
    }

    private String generatePoc(String baseUrl, String action, String method) {
        String fullUrl = resolveUrl(baseUrl, action);
        return "<!-- CSRF PoC -->\n" + "<html>\n" + "<body>\n" + "  <form action=\"" + fullUrl + "\" method=\"" + method
                + "\">\n" + "    <input type=\"submit\" value=\"Submit\">\n" + "  </form>\n"
                + "  <script>document.forms[0].submit()</script>\n" + "</body>\n" + "</html>";
    }

    private String generatePocWithToken(String baseUrl, String action, String method, String tokenName,
            String tokenValue) {
        String fullUrl = resolveUrl(baseUrl, action);
        return "<!-- CSRF PoC (with token bypass) -->\n" + "<html>\n" + "<body>\n" + "  <form action=\"" + fullUrl
                + "\" method=\"" + method + "\">\n" + "    <input type=\"hidden\" name=\"" + tokenName + "\" value=\""
                + tokenValue + "\">\n" + "    <input type=\"submit\" value=\"Submit\">\n" + "  </form>\n"
                + "  <script>document.forms[0].submit()</script>\n" + "</body>\n" + "</html>";
    }

    private Finding buildFinding(String endpoint, String title, Severity severity, String evidence, String impact,
            String reproduction, String recommendation) {
        return Finding.of(id(), endpoint, title, severity, evidence, impact, reproduction, recommendation);
    }
}
