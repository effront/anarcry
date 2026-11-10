package gg.effront.anarcry.scanner.web.race;

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
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.function.Consumer;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class RaceConditionModule implements Scanner {

    private static final int BURST_SIZE = 10;
    private static final Duration REQUEST_TIMEOUT = Duration.ofSeconds(8);

    private static final Set<String> CANDIDATE_KEYWORDS = Set.of("payment", "transfer", "checkout", "redeem", "coupon",
            "voucher", "vote", "like", "follow", "subscribe", "register", "signup", "apply", "claim", "withdraw",
            "deposit", "order", "purchase", "submit");

    private static final Pattern RATE_LIMIT_REMAINING = Pattern.compile("x-ratelimit-remaining",
            Pattern.CASE_INSENSITIVE);

    private static final Pattern NUMERIC_VALUE = Pattern.compile("-?\\d+");

    @Override
    public String id() {
        return "RaceCondition";
    }

    @Override
    public List<Finding> scan(ScanContext ctx, Consumer<String> log) throws Exception {
        List<Finding> findings = new ArrayList<>();
        HttpClient hc = HttpClientFactory.http2();

        // Phase 1: Identify candidate endpoints from discovered paths
        List<String> candidates = identifyCandidates(ctx, log);
        if (candidates.isEmpty()) {
            log.accept("[~] " + id() + ": nenhum endpoint candidato encontrado -- pulando");
            return findings;
        }

        log.accept("[~] " + id() + ": " + candidates.size() + " endpoint(s) candidato(s) para teste de race condition");

        for (String path : candidates) {
            String url = buildUrl(ctx, path);
            log.accept("[~] " + id() + ": testando " + url);

            try {
                // Phase 2: Baseline request
                BaselineResult baseline = sendBaseline(ctx, hc, url, log);
                if (baseline == null) {
                    log.accept("[~] " + id() + ": baseline falhou para " + url + " -- pulando");
                    continue;
                }

                // Phase 3: Concurrent burst
                List<BurstResponse> burstResponses = sendConcurrentBurst(ctx, hc, url, log);
                if (burstResponses.isEmpty()) {
                    log.accept("[~] " + id() + ": burst sem respostas para " + url + " -- pulando");
                    continue;
                }

                // Phase 4: Inconsistency detection
                analyzeResponses(ctx, url, baseline, burstResponses, findings, log);
            } catch (Exception e) {
                log.accept("[!] " + id() + ": erro testando " + url + " -- " + e.getMessage());
            }
        }

        if (findings.isEmpty()) {
            log.accept("[+] " + id() + ": nenhuma vulnerabilidade detectada");
        }
        return findings;
    }

    // -------------------------------------------------------------------------
    // Phase 1: Candidate identification
    // -------------------------------------------------------------------------

    private List<String> identifyCandidates(ScanContext ctx, Consumer<String> log) {
        List<String> candidates = new ArrayList<>();
        Set<String> discoveredPaths = ctx.discoveredPaths().paths();

        for (String path : discoveredPaths) {
            String lower = path.toLowerCase(Locale.ROOT);
            for (String keyword : CANDIDATE_KEYWORDS) {
                if (lower.contains(keyword)) {
                    candidates.add(path);
                    log.accept("[~] " + id() + ": candidato encontrado -- " + path + " (keyword: " + keyword + ")");
                    break;
                }
            }
        }

        return candidates;
    }

    // -------------------------------------------------------------------------
    // Phase 2: Baseline
    // -------------------------------------------------------------------------

    private record BaselineResult(int statusCode, String body, Map<String, List<String>> headers, long rttMs) {
    }

    private BaselineResult sendBaseline(ScanContext ctx, HttpClient hc, String url, Consumer<String> log)
            throws Exception {
        HttpRequest.Builder reqBuilder = HttpRequest.newBuilder().uri(URI.create(url)).timeout(REQUEST_TIMEOUT)
                .POST(HttpRequest.BodyPublishers.noBody());
        addAuthHeaders(ctx, reqBuilder);

        HttpRequest req = reqBuilder.build();
        long start = System.nanoTime();
        HttpResponse<String> resp = Http.send(ctx, hc, req, HttpResponse.BodyHandlers.ofString(), id());
        long rttMs = (System.nanoTime() - start) / 1_000_000;

        log.accept("[~] " + id() + ": baseline -- HTTP " + resp.statusCode() + " (" + rttMs + "ms, "
                + resp.body().length() + " bytes)");

        return new BaselineResult(resp.statusCode(), resp.body(), resp.headers().map(), rttMs);
    }

    // -------------------------------------------------------------------------
    // Phase 3: Concurrent burst
    // -------------------------------------------------------------------------

    private record BurstResponse(int statusCode, String body, Map<String, List<String>> headers, long rttMs,
            int index) {
    }

    private List<BurstResponse> sendConcurrentBurst(ScanContext ctx, HttpClient hc, String url, Consumer<String> log) {
        List<BurstResponse> responses = new ArrayList<>();

        try (ExecutorService pool = Executors.newVirtualThreadPerTaskExecutor()) {
            List<CompletableFuture<BurstResponse>> futures = new ArrayList<>();

            for (int i = 0; i < BURST_SIZE; i++) {
                final int index = i;
                futures.add(CompletableFuture.supplyAsync(() -> {
                    try {
                        HttpRequest.Builder reqBuilder = HttpRequest.newBuilder().uri(URI.create(url))
                                .timeout(REQUEST_TIMEOUT).POST(HttpRequest.BodyPublishers.noBody());
                        addAuthHeaders(ctx, reqBuilder);
                        HttpRequest req = reqBuilder.build();

                        long start = System.nanoTime();
                        HttpResponse<String> resp = Http.send(ctx, hc, req, HttpResponse.BodyHandlers.ofString(), id());
                        long rttMs = (System.nanoTime() - start) / 1_000_000;

                        return new BurstResponse(resp.statusCode(), resp.body(), resp.headers().map(), rttMs, index);
                    } catch (Exception e) {
                        return null;
                    }
                }, pool));
            }

            // Wait for all futures
            CompletableFuture.allOf(futures.toArray(new CompletableFuture[0])).join();

            for (CompletableFuture<BurstResponse> f : futures) {
                try {
                    BurstResponse br = f.get();
                    if (br != null) {
                        responses.add(br);
                    }
                } catch (Exception ignored) {
                    // Individual request failures are expected
                }
            }
        }

        log.accept("[~] " + id() + ": burst -- " + responses.size() + "/" + BURST_SIZE + " respostas recebidas");
        return responses;
    }

    // -------------------------------------------------------------------------
    // Phase 4: Inconsistency detection
    // -------------------------------------------------------------------------

    private void analyzeResponses(ScanContext ctx, String url, BaselineResult baseline, List<BurstResponse> responses,
            List<Finding> findings, Consumer<String> log) {

        // Check 1: Success duplication -- multiple 2xx when only one should succeed
        checkSuccessDuplication(ctx, url, baseline, responses, findings, log);

        // Check 2: Rate limit bypass
        checkRateLimitBypass(ctx, url, baseline, responses, findings, log);

        // Check 3: State inconsistency
        checkStateInconsistency(ctx, url, baseline, responses, findings, log);
    }

    private void checkSuccessDuplication(ScanContext ctx, String url, BaselineResult baseline,
            List<BurstResponse> responses, List<Finding> findings, Consumer<String> log) {

        long successCount = responses.stream().filter(r -> r.statusCode() >= 200 && r.statusCode() < 300).count();

        // If baseline was not 2xx, but multiple burst requests got 2xx -- suspicious
        // If baseline was 2xx and all burst are 2xx with same body -- normal behavior
        if (successCount > 1 && baseline.statusCode() >= 200 && baseline.statusCode() < 300) {
            // Check if success responses have different bodies -- indicates state mutation
            List<String> successBodies = responses.stream().filter(r -> r.statusCode() >= 200 && r.statusCode() < 300)
                    .map(BurstResponse::body).distinct().toList();

            if (successBodies.size() > 1) {
                String evidence = buildSuccessDupEvidence(baseline, responses, successCount);
                String curlCmd = buildCurlPoC(ctx, url);

                findings.add(Finding.of(id(), url, "Race Condition -- Success Duplication on Transactional Endpoint",
                        Severity.HIGH, evidence,
                        "Concurrent requests to a transactional endpoint returned multiple success "
                                + "responses with divergent bodies. An attacker can exploit this to "
                                + "duplicate transactions, apply coupons multiple times, cast multiple "
                                + "votes, or bypass single-use restrictions.",
                        curlCmd,
                        "Implement server-side locking (database-level locks or distributed locks). "
                                + "Use idempotency keys for financial transactions. Apply atomic "
                                + "operations with proper isolation levels (SERIALIZABLE). "
                                + "Add optimistic concurrency control with version columns."));

                log.accept("[!!] " + id() + ": success duplication detectada em " + url);
            }
        }
    }

    private void checkRateLimitBypass(ScanContext ctx, String url, BaselineResult baseline,
            List<BurstResponse> responses, List<Finding> findings, Consumer<String> log) {

        // Extract rate limit headers from baseline
        int baselineRemaining = extractRateLimitRemaining(baseline.headers());
        if (baselineRemaining < 0) {
            // No rate limit header in baseline -- nothing to compare
            return;
        }

        // Check burst responses for rate limit inconsistencies
        List<Integer> burstRemaining = new ArrayList<>();
        int negativeCount = 0;
        int sameAsBaseline = 0;

        for (BurstResponse r : responses) {
            int remaining = extractRateLimitRemaining(r.headers());
            if (remaining >= 0) {
                burstRemaining.add(remaining);
                if (remaining < 0) {
                    negativeCount++;
                }
                if (remaining == baselineRemaining) {
                    sameAsBaseline++;
                }
            }
        }

        if (burstRemaining.isEmpty()) {
            return;
        }

        boolean bypass = false;
        StringBuilder evidenceBuilder = new StringBuilder();
        evidenceBuilder.append("Baseline X-RateLimit-Remaining: ").append(baselineRemaining).append("\n");
        evidenceBuilder.append("Burst X-RateLimit-Remaining values: ").append(burstRemaining).append("\n");

        // Negative remaining -- counter went below zero
        if (negativeCount > 0) {
            bypass = true;
            evidenceBuilder.append("Anomaly: ").append(negativeCount)
                    .append(" response(s) with negative remaining count\n");
        }

        // All burst responses show same remaining -- counter not synchronized
        if (sameAsBaseline > burstRemaining.size() / 2) {
            bypass = true;
            evidenceBuilder.append("Anomaly: ").append(sameAsBaseline).append("/").append(burstRemaining.size())
                    .append(" responses show same remaining as baseline (counter not decremented)\n");
        }

        if (bypass) {
            String curlCmd = buildCurlPoC(ctx, url);
            findings.add(Finding.of(id(), url, "Race Condition -- Rate Limit Bypass via Concurrent Requests",
                    Severity.HIGH, evidenceBuilder.toString(),
                    "The rate limiting mechanism does not properly synchronize concurrent "
                            + "requests. An attacker can send parallel requests to bypass rate "
                            + "limits, enabling brute force attacks, API abuse, or transaction "
                            + "duplication that the rate limiter was designed to prevent.",
                    curlCmd,
                    "Implement atomic rate limit counters (Redis INCR, database FOR UPDATE). "
                            + "Use distributed locks for rate limit checks. Apply rate limiting "
                            + "at the load balancer level with proper synchronization."));

            log.accept("[!!] " + id() + ": rate limit bypass detectado em " + url);
        }
    }

    private void checkStateInconsistency(ScanContext ctx, String url, BaselineResult baseline,
            List<BurstResponse> responses, List<Finding> findings, Consumer<String> log) {

        // Group responses by status code
        Map<Integer, Integer> statusCounts = new HashMap<>();
        for (BurstResponse r : responses) {
            statusCounts.merge(r.statusCode(), 1, Integer::sum);
        }

        // If all responses have the same status and same body -- no inconsistency
        long distinctBodies = responses.stream().map(BurstResponse::body).distinct().count();
        boolean allSameStatus = statusCounts.size() == 1;

        if (allSameStatus && distinctBodies <= 1) {
            return;
        }

        // Mixed status codes suggest state contention (e.g., some 200, some 409, some
        // 429)
        boolean hasMixedStatus = statusCounts.size() > 1;
        boolean hasSuccess = statusCounts.keySet().stream().anyMatch(s -> s >= 200 && s < 300);
        boolean hasConflict = statusCounts.containsKey(409) || statusCounts.containsKey(429);

        if (hasMixedStatus && hasSuccess && hasConflict) {
            StringBuilder evidence = new StringBuilder();
            evidence.append("Baseline: HTTP ").append(baseline.statusCode()).append("\n");
            evidence.append("Burst status code distribution:\n");
            for (Map.Entry<Integer, Integer> entry : statusCounts.entrySet()) {
                evidence.append("  HTTP ").append(entry.getKey()).append(": ").append(entry.getValue())
                        .append(" response(s)\n");
            }
            evidence.append("Distinct response bodies: ").append(distinctBodies).append("\n");
            evidence.append("Interpretation: mixed success/conflict responses indicate a TOCTOU window -- ")
                    .append("some requests passed the check before others triggered the guard condition.");

            String curlCmd = buildCurlPoC(ctx, url);
            findings.add(Finding.of(id(), url, "Race Condition -- State Inconsistency (TOCTOU Window)", Severity.HIGH,
                    evidence.toString(),
                    "Concurrent requests produce mixed success and conflict responses, "
                            + "indicating a time-of-check-to-time-of-use (TOCTOU) gap. An "
                            + "attacker can repeatedly exploit this window to bypass single-use "
                            + "constraints, duplicate actions, or corrupt shared state.",
                    curlCmd,
                    "Use database transactions with SERIALIZABLE isolation level. "
                            + "Implement SELECT ... FOR UPDATE or advisory locks around "
                            + "check-then-act sequences. Apply idempotency keys for " + "state-mutating operations."));

            log.accept("[!!] " + id() + ": state inconsistency (TOCTOU) detectada em " + url);
        }
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private String buildUrl(ScanContext ctx, String path) {
        String base = ctx.targetUrl();
        if (base.endsWith("/") && path.startsWith("/")) {
            return base + path.substring(1);
        }
        if (!base.endsWith("/") && !path.startsWith("/")) {
            return base + "/" + path;
        }
        return base + path;
    }

    private void addAuthHeaders(ScanContext ctx, HttpRequest.Builder builder) {
        String token = ctx.activeToken();
        if (token != null && !token.isBlank()) {
            builder.header("Authorization", "Bearer " + token);
        }
    }

    private int extractRateLimitRemaining(Map<String, List<String>> headers) {
        for (Map.Entry<String, List<String>> entry : headers.entrySet()) {
            if (RATE_LIMIT_REMAINING.matcher(entry.getKey()).matches()) {
                for (String val : entry.getValue()) {
                    Matcher m = NUMERIC_VALUE.matcher(val);
                    if (m.find()) {
                        try {
                            return Integer.parseInt(m.group());
                        } catch (NumberFormatException ignored) {
                            // skip non-numeric values
                        }
                    }
                }
            }
        }
        return -1;
    }

    private String buildSuccessDupEvidence(BaselineResult baseline, List<BurstResponse> responses, long successCount) {
        StringBuilder sb = new StringBuilder();
        sb.append("Baseline: HTTP ").append(baseline.statusCode()).append(" (").append(baseline.body().length())
                .append(" bytes)\n");
        sb.append("Burst: ").append(successCount).append("/").append(responses.size())
                .append(" requests returned 2xx\n");
        sb.append("Response status distribution:\n");

        Map<Integer, Integer> statusDist = new HashMap<>();
        for (BurstResponse r : responses) {
            statusDist.merge(r.statusCode(), 1, Integer::sum);
        }
        for (Map.Entry<Integer, Integer> entry : statusDist.entrySet()) {
            sb.append("  HTTP ").append(entry.getKey()).append(": ").append(entry.getValue()).append("x\n");
        }

        long distinctBodies = responses.stream().filter(r -> r.statusCode() >= 200 && r.statusCode() < 300)
                .map(BurstResponse::body).distinct().count();
        sb.append("Distinct 2xx response bodies: ").append(distinctBodies).append("\n");
        sb.append("Multiple success responses with different bodies indicate state mutation ");
        sb.append("from concurrent requests (race condition).");
        return sb.toString();
    }

    private String buildCurlPoC(ScanContext ctx, String url) {
        StringBuilder sb = new StringBuilder();
        sb.append("# Race condition PoC -- send ").append(BURST_SIZE).append(" concurrent requests\n");

        String authHeader = "";
        String token = ctx.activeToken();
        if (token != null && !token.isBlank()) {
            authHeader = " -H 'Authorization: Bearer " + token + "'";
        }
        if (!ctx.config().sessionCookie().isBlank()) {
            authHeader += " -H 'Cookie: " + ctx.config().sessionCookie() + "'";
        }

        sb.append("for i in $(seq 1 ").append(BURST_SIZE).append("); do\n");
        sb.append("  curl -s -o /dev/null -w '%{http_code}\\n' -X POST '").append(url).append("'");
        sb.append(authHeader);
        sb.append(" &\n");
        sb.append("done\n");
        sb.append("wait");
        return sb.toString();
    }
}
