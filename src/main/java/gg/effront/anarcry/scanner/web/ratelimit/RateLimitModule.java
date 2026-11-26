package gg.effront.anarcry.scanner.web.ratelimit;

import gg.effront.anarcry.model.CvssCalculator;
import gg.effront.anarcry.model.Finding;
import gg.effront.anarcry.model.Severity;
import gg.effront.anarcry.scanner.ScanContext;
import gg.effront.anarcry.scanner.Scanner;
import gg.effront.anarcry.scanner.util.CircuitBreakerException;
import gg.effront.anarcry.scanner.util.Http;
import gg.effront.anarcry.scanner.util.HttpClientFactory;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.function.Consumer;
import java.util.regex.Pattern;

/**
 * RateLimitModule -- CWE-307 scanner.
 *
 * <p>
 * Detects missing rate limiting on authentication-related endpoints by sending
 * a burst of rapid requests and checking whether the server responds with 429,
 * Retry-After, or X-RateLimit-Remaining headers. Absence of throttling enables
 * brute-force and credential-stuffing attacks.
 */
public class RateLimitModule implements Scanner {

    private static final String CWE_ID = "CWE-307";
    private static final String CWE_TITLE = "Improper Restriction of Excessive Authentication Attempts";
    private static final String CVSS_LOGIN = "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N";
    private static final String CVSS_OTHER = "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N";

    private static final int BURST_SIZE = 10;
    private static final int BASELINE_BODY_TOLERANCE = 15;
    private static final int MAX_FINDINGS_PER_CATEGORY = 1;
    private static final Duration REQUEST_TIMEOUT = Duration.ofSeconds(6);

    private static final String DUMMY_BODY = "{\"email\":\"test@test.com\",\"password\":\"test123\"}";

    private static final List<String> LOGIN_PATHS = List.of("/api/auth/login", "/api/login", "/auth/login",
            "/api/auth/signin", "/login");

    private static final List<String> RESET_PATHS = List.of("/api/auth/reset", "/api/auth/forgot-password",
            "/api/password-reset", "/auth/forgot");

    private static final List<String> MFA_PATHS = List.of("/api/auth/verify", "/api/auth/mfa", "/api/mfa/verify",
            "/api/auth/2fa");

    private static final Pattern AUTH_PATTERN = Pattern
            .compile("(?i)(auth|login|signin|signup|register|reset|forgot|verify|mfa|2fa|otp)");

    private static final Pattern LOGIN_PATTERN = Pattern.compile("(?i)(login|signin)");
    private static final Pattern RESET_PATTERN = Pattern.compile("(?i)(reset|forgot)");

    @Override
    public String id() {
        return "RateLimit";
    }

    @Override
    public List<Finding> scan(ScanContext ctx, Consumer<String> log) throws Exception {
        List<Finding> findings = new ArrayList<>();
        HttpClient hc = HttpClientFactory.http2();

        String baseUrl = buildBaseUrl(ctx);
        log.accept("[~] RateLimit: iniciando deteccao em " + baseUrl);

        // Baseline: POST to a path that cannot exist -- detect middleware catch-all
        BaselineResponse baseline;
        try {
            baseline = fetchBaseline(ctx, hc, baseUrl, log);
        } catch (CircuitBreakerException e) {
            throw e;
        } catch (Exception e) {
            log.accept("[~] RateLimit: baseline probe falhou -- " + e.getMessage());
            baseline = null;
        }

        LinkedHashSet<EndpointCandidate> candidates = new LinkedHashSet<>();
        for (String p : LOGIN_PATHS) {
            candidates.add(new EndpointCandidate(p, true, "login"));
        }
        for (String p : RESET_PATHS) {
            candidates.add(new EndpointCandidate(p, false, "reset"));
        }
        for (String p : MFA_PATHS) {
            candidates.add(new EndpointCandidate(p, false, "mfa"));
        }

        if (!ctx.discoveredPaths().isEmpty()) {
            for (String dp : ctx.discoveredPaths().paths()) {
                if (AUTH_PATTERN.matcher(dp).find()) {
                    boolean isLogin = LOGIN_PATTERN.matcher(dp).find();
                    String category = isLogin ? "login" : RESET_PATTERN.matcher(dp).find() ? "reset" : "mfa";
                    candidates.add(new EndpointCandidate(dp, isLogin, category));
                }
            }
        }

        log.accept("[~] RateLimit: " + candidates.size() + " endpoints candidatos");

        Map<String, Integer> categoryCount = new LinkedHashMap<>();

        for (EndpointCandidate candidate : candidates) {
            String endpoint = candidate.path();
            String url = baseUrl + endpoint;

            int catSoFar = categoryCount.getOrDefault(candidate.category(), 0);
            if (catSoFar >= MAX_FINDINGS_PER_CATEGORY) {
                log.accept(
                        "[~] RateLimit: cap reached for " + candidate.category() + " category -- skipping " + endpoint);
                continue;
            }

            boolean exists;
            try {
                exists = probeEndpoint(ctx, hc, url, baseline, log);
            } catch (CircuitBreakerException e) {
                throw e;
            } catch (Exception ignored) {
                continue;
            }

            if (!exists) {
                continue;
            }

            log.accept("[~] RateLimit: endpoint ativo -- " + endpoint);

            boolean rateLimited;
            try {
                rateLimited = sendBurstAndCheckLimit(ctx, hc, url, log);
            } catch (CircuitBreakerException e) {
                throw e;
            } catch (Exception ignored) {
                continue;
            }

            if (rateLimited) {
                log.accept("[+] RateLimit: rate limiting detectado em " + endpoint);
                continue;
            }

            Severity severity = candidate.isLogin() ? Severity.HIGH : Severity.MEDIUM;
            String cvssVector = candidate.isLogin() ? CVSS_LOGIN : CVSS_OTHER;
            double cvssScore = CvssCalculator.calculate(cvssVector);

            log.accept("[!!] RateLimit: " + severity + " -- sem rate limiting em " + endpoint + " (" + BURST_SIZE
                    + " requests sem throttle)");

            findings.add(Finding.of(id(), endpoint, "Missing rate limiting on " + endpoint, severity,
                    "Sent " + BURST_SIZE + " rapid POST requests to " + url
                            + " -- no 429 status, no Retry-After header," + " no X-RateLimit-Remaining: 0 detected",
                    "Absence of rate limiting allows brute-force and credential-stuffing attacks."
                            + " An attacker can automate login attempts at high speed without being"
                            + " throttled, potentially compromising user accounts.",
                    "curl -s -o /dev/null -w '%{http_code}' -X POST" + " -H 'Content-Type: application/json'" + " -d '"
                            + DUMMY_BODY + "' '" + url + "'\n" + "# Repeat " + BURST_SIZE
                            + " times rapidly -- expect 429 after threshold",
                    "Implement rate limiting on authentication endpoints: return HTTP 429 after"
                            + " threshold; include Retry-After header; apply exponential backoff;"
                            + " consider account lockout after N failures and CAPTCHA challenges.",
                    CWE_ID, CWE_TITLE, cvssVector, cvssScore));
            categoryCount.merge(candidate.category(), 1, Integer::sum);
        }

        if (findings.isEmpty()) {
            log.accept("[+] RateLimit: nenhuma ausencia de rate limiting detectada");
        }
        return findings;
    }

    private BaselineResponse fetchBaseline(ScanContext ctx, HttpClient hc, String baseUrl, Consumer<String> log)
            throws Exception {
        String probePath = "/api/anarcry-ratelimit-probe-" + UUID.randomUUID().toString().substring(0, 8);
        String url = baseUrl + probePath;

        HttpRequest req = HttpRequest.newBuilder().uri(URI.create(url)).timeout(REQUEST_TIMEOUT)
                .header("Content-Type", "application/json").POST(HttpRequest.BodyPublishers.ofString(DUMMY_BODY))
                .build();

        HttpResponse<String> resp = Http.send(ctx, hc, req, HttpResponse.BodyHandlers.ofString(), id());
        int status = resp.statusCode();
        int bodyLen = resp.body() != null ? resp.body().length() : 0;
        log.accept("[~] RateLimit: baseline probe -- status=" + status + " bodyLen=" + bodyLen);
        return new BaselineResponse(status, bodyLen);
    }

    private boolean probeEndpoint(ScanContext ctx, HttpClient hc, String url, BaselineResponse baseline,
            Consumer<String> log) throws Exception {
        HttpRequest req = HttpRequest.newBuilder().uri(URI.create(url)).timeout(REQUEST_TIMEOUT)
                .header("Content-Type", "application/json").POST(HttpRequest.BodyPublishers.ofString(DUMMY_BODY))
                .build();

        HttpResponse<String> resp = Http.send(ctx, hc, req, HttpResponse.BodyHandlers.ofString(), id());
        int sc = resp.statusCode();
        boolean statusOk = sc >= 200 && sc < 300 || sc == 401 || sc == 403;
        if (!statusOk) {
            return false;
        }

        if (baseline != null) {
            int bodyLen = resp.body() != null ? resp.body().length() : 0;
            if (sc == baseline.status() && Math.abs(bodyLen - baseline.bodyLength()) <= BASELINE_BODY_TOLERANCE) {
                String endpoint = URI.create(url).getPath();
                log.accept("[~] RateLimit: " + endpoint + " matches baseline (middleware catch-all) -- skipping");
                return false;
            }
        }

        return true;
    }

    private boolean sendBurstAndCheckLimit(ScanContext ctx, HttpClient hc, String url, Consumer<String> log)
            throws Exception {
        for (int i = 0; i < BURST_SIZE; i++) {
            HttpRequest req = HttpRequest.newBuilder().uri(URI.create(url)).timeout(REQUEST_TIMEOUT)
                    .header("Content-Type", "application/json").POST(HttpRequest.BodyPublishers.ofString(DUMMY_BODY))
                    .build();

            HttpResponse<Void> resp;
            try {
                resp = Http.send(ctx, hc, req, HttpResponse.BodyHandlers.discarding(), id());
            } catch (CircuitBreakerException e) {
                throw e;
            } catch (Exception ignored) {
                continue;
            }

            if (isRateLimited(resp)) {
                log.accept("[~] RateLimit: throttle detectado na request " + (i + 1) + "/" + BURST_SIZE);
                return true;
            }
        }
        return false;
    }

    private boolean isRateLimited(HttpResponse<Void> resp) {
        if (resp.statusCode() == 429) {
            return true;
        }
        if (resp.headers().firstValue("Retry-After").isPresent()) {
            return true;
        }
        String remaining = resp.headers().firstValue("X-RateLimit-Remaining").orElse("").trim();
        return remaining.equals("0");
    }

    private String buildBaseUrl(ScanContext ctx) {
        String scheme = ctx.isHttps() ? "https" : "http";
        int defPort = ctx.isHttps() ? 443 : 80;
        return scheme + "://" + ctx.host() + (ctx.port() != defPort ? ":" + ctx.port() : "");
    }

    private record BaselineResponse(int status, int bodyLength) {
    }

    private record EndpointCandidate(String path, boolean isLogin, String category) {
    }
}
