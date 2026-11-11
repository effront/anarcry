package gg.effront.anarcry.scanner.web.protopollution;

import gg.effront.anarcry.model.Finding;
import gg.effront.anarcry.model.Severity;
import gg.effront.anarcry.scanner.ScanContext;
import gg.effront.anarcry.scanner.Scanner;
import gg.effront.anarcry.scanner.util.CircuitBreakerException;
import gg.effront.anarcry.scanner.util.Http;
import gg.effront.anarcry.scanner.util.HttpClientFactory;
import gg.effront.anarcry.scanner.util.ProbeExecutor;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.Callable;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Consumer;
import java.util.regex.Pattern;

public class PrototypePollutionModule implements Scanner {

    private static final List<String> FALLBACK_PATHS = List.of("/", "/api/", "/api/v1/", "/search", "/login",
            "/register", "/settings");

    private static final List<String> PARAMS = List.of("q", "query", "search", "name", "data", "input", "config",
            "options", "settings", "user", "filter");

    // Canary value unlikely to appear in normal responses
    private static final String CANARY = "anarcry_pp_7x3k9";

    // Client-side prototype pollution payloads (query param injection)
    private static final List<String> CLIENT_PAYLOADS = List.of("__proto__[ppcanary]=" + CANARY,
            "constructor.prototype.ppcanary=" + CANARY, "__proto__[constructor][prototype][ppcanary]=" + CANARY,
            "__proto__.ppcanary=" + CANARY);

    // Server-side JSON payloads
    private static final List<String> SERVER_JSON_PAYLOADS = List.of(
            "{\"__proto__\": {\"ppcanary\": \"" + CANARY + "\"}}",
            "{\"constructor\": {\"prototype\": {\"ppcanary\": \"" + CANARY + "\"}}}",
            "{\"a\": {\"__proto__\": {\"ppcanary\": \"" + CANARY + "\"}}}");

    // Error patterns that may indicate prototype pollution side effects
    private static final Pattern ERROR_PATTERN = Pattern.compile(
            "Cannot read prop|undefined is not an object|Cannot convert undefined"
                    + "|TypeError.*undefined|Cannot set prop.*of undefined" + "|\\[object Object\\].*ppcanary",
            Pattern.CASE_INSENSITIVE);

    @Override
    public String id() {
        return "ProtoPollution";
    }

    @Override
    public List<Finding> scan(ScanContext ctx, Consumer<String> log) throws Exception {
        List<Finding> findings = new ArrayList<>();
        HttpClient hc = HttpClientFactory.http2();

        String scheme = ctx.isHttps() ? "https" : "http";
        int defPort = ctx.isHttps() ? 443 : 80;
        String base = scheme + "://" + ctx.host() + (ctx.port() != defPort ? ":" + ctx.port() : "");

        Set<String> crawledPaths = ctx.discoveredPaths().paths();
        List<String> paths = crawledPaths.isEmpty() ? FALLBACK_PATHS : new ArrayList<>(crawledPaths);

        log.accept("[~] " + id() + ": testando prototype pollution em " + paths.size() + " paths");

        int concurrency = ctx.config().probeConcurrency();
        AtomicBoolean cancel = new AtomicBoolean(false);
        List<Callable<List<Finding>>> tasks = new ArrayList<>();

        for (int pi = 0; pi < paths.size(); pi++) {
            final String path = paths.get(pi);
            final int pathIdx = pi;
            tasks.add(() -> {
                List<Finding> local = new ArrayList<>();
                if (cancel.get()) {
                    return local;
                }
                log.accept("[~] " + id() + ": [" + (pathIdx + 1) + "/" + paths.size() + "] " + path);

                // Phase 1: Client-side -- inject __proto__ and constructor.prototype in query
                // params
                Finding clientFinding = probeClientSide(ctx, hc, base, path, log);
                if (clientFinding != null) {
                    local.add(clientFinding);
                }

                // Phase 2: Server-side -- POST JSON payloads with polluted prototypes
                Finding serverFinding = probeServerSide(ctx, hc, base, path, log);
                if (serverFinding != null) {
                    local.add(serverFinding);
                }

                // Phase 4: Parameter pollution -- inject __proto__ in GET query params
                Finding paramFinding = probeParamPollution(ctx, hc, base, path, log);
                if (paramFinding != null) {
                    local.add(paramFinding);
                }

                return local;
            });
        }

        findings.addAll(ProbeExecutor.run(tasks, concurrency, cancel));

        if (findings.isEmpty()) {
            log.accept("[+] " + id() + ": nenhuma vulnerabilidade de prototype pollution detectada");
        }
        return findings;
    }

    // -------------------------------------------------------------------------
    // Phase 1: Client-side prototype pollution via query parameters
    // -------------------------------------------------------------------------

    private Finding probeClientSide(ScanContext ctx, HttpClient hc, String base, String path, Consumer<String> log) {
        // Baseline
        String baselineBody = fetchBody(ctx, hc, base + path, log);

        for (String payload : CLIENT_PAYLOADS) {
            try {
                String url = base + path + "?" + payload;
                HttpRequest req = HttpRequest.newBuilder().uri(URI.create(url)).timeout(Duration.ofSeconds(6)).GET()
                        .build();
                HttpResponse<String> resp = Http.send(ctx, hc, req, HttpResponse.BodyHandlers.ofString(), id());
                String body = resp.body() != null ? resp.body() : "";

                // Check if the canary is reflected in the response (server-side processing)
                if (body.contains(CANARY) && !baselineBody.contains(CANARY)) {
                    log.accept("[!!] " + id() + ": client-side pollution reflected -- " + path);
                    return Finding.of(id(), path + "?" + payload,
                            "Client-Side Prototype Pollution -- Property Reflected", Severity.MEDIUM,
                            "Payload: " + payload + " | Canary '" + CANARY + "' found in response | URL: " + url,
                            "Prototype pollution via query parameters can lead to XSS, authentication"
                                    + " bypass, or DOM clobbering when client-side JavaScript merges"
                                    + " attacker-controlled properties into application objects",
                            "curl -s '" + url + "' | grep '" + CANARY + "'",
                            "Sanitize query parameters before merging into objects. Use Object.create(null)"
                                    + " or Map instead of plain objects. Freeze Object.prototype in"
                                    + " client-side code. Validate and reject __proto__ and constructor keys.");
                }

                // Phase 3: Check for error patterns indicating prototype pollution side effects
                if (resp.statusCode() == 500
                        || (ERROR_PATTERN.matcher(body).find() && !ERROR_PATTERN.matcher(baselineBody).find())) {
                    log.accept("[!!] " + id() + ": error pattern detected after injection -- " + path);
                    return Finding.of(id(), path + "?" + payload, "Prototype Pollution -- Error Pattern Detected",
                            Severity.MEDIUM,
                            "Payload: " + payload + " | Server returned error or TypeError pattern" + " | Status: "
                                    + resp.statusCode() + " | URL: " + url,
                            "Error messages after prototype pollution injection suggest the application"
                                    + " processes __proto__ or constructor properties, which may lead to"
                                    + " denial of service or unexpected behavior",
                            "curl -s -o /dev/null -w '%{http_code}' '" + url + "'",
                            "Reject __proto__ and constructor.prototype keys in all input parsing."
                                    + " Use a safe merge function that skips prototype properties.");
                }
            } catch (CircuitBreakerException cbe) {
                throw cbe;
            } catch (Exception ignored) {
                // Connection errors are expected for some paths
            }
        }
        return null;
    }

    // -------------------------------------------------------------------------
    // Phase 2: Server-side prototype pollution via JSON POST
    // -------------------------------------------------------------------------

    private Finding probeServerSide(ScanContext ctx, HttpClient hc, String base, String path, Consumer<String> log) {
        // First send a normal JSON POST to establish baseline behavior
        String normalJson = "{\"test\": \"value\"}";
        String baselineBody = "";
        int baselineStatus = 0;
        try {
            HttpRequest baseReq = HttpRequest.newBuilder().uri(URI.create(base + path)).timeout(Duration.ofSeconds(6))
                    .header("Content-Type", "application/json").POST(HttpRequest.BodyPublishers.ofString(normalJson))
                    .build();
            HttpResponse<String> baseResp = Http.send(ctx, hc, baseReq, HttpResponse.BodyHandlers.ofString(), id());
            baselineBody = baseResp.body() != null ? baseResp.body() : "";
            baselineStatus = baseResp.statusCode();
        } catch (CircuitBreakerException cbe) {
            throw cbe;
        } catch (Exception e) {
            return null;
        }

        // Skip paths that do not accept JSON (405, 404, etc.)
        if (baselineStatus == 404 || baselineStatus == 405) {
            return null;
        }

        for (String jsonPayload : SERVER_JSON_PAYLOADS) {
            try {
                HttpRequest req = HttpRequest.newBuilder().uri(URI.create(base + path)).timeout(Duration.ofSeconds(6))
                        .header("Content-Type", "application/json")
                        .POST(HttpRequest.BodyPublishers.ofString(jsonPayload)).build();
                HttpResponse<String> resp = Http.send(ctx, hc, req, HttpResponse.BodyHandlers.ofString(), id());
                String body = resp.body() != null ? resp.body() : "";

                // Check if canary appears in response
                if (body.contains(CANARY) && !baselineBody.contains(CANARY)) {
                    log.accept("[!!] " + id() + ": server-side prototype pollution confirmed -- " + path);
                    return Finding.of(id(), path, "Server-Side Prototype Pollution -- JSON Injection", Severity.HIGH,
                            "Payload: " + jsonPayload + " | Canary '" + CANARY + "' reflected in response" + " | URL: "
                                    + base + path,
                            "Server-side prototype pollution allows an attacker to modify the behavior"
                                    + " of the application by injecting properties into Object.prototype."
                                    + " This can lead to privilege escalation, authentication bypass,"
                                    + " remote code execution, or denial of service",
                            "curl -s -X POST '" + base + path + "' \\\n  -H 'Content-Type: application/json' \\\n  -d '"
                                    + jsonPayload + "'",
                            "Use safe merge/deep-copy functions that skip __proto__ and constructor"
                                    + " properties. Use Map or Object.create(null) for untrusted data."
                                    + " Validate JSON schema and reject unexpected keys.");
                }

                // Check for error patterns indicating server processed the polluted keys
                if (ERROR_PATTERN.matcher(body).find() && !ERROR_PATTERN.matcher(baselineBody).find()) {
                    log.accept("[!!] " + id() + ": server-side error after JSON pollution -- " + path);
                    return Finding.of(id(), path, "Server-Side Prototype Pollution -- Error Indicator", Severity.MEDIUM,
                            "Payload: " + jsonPayload + " | Error pattern detected in response" + " | Status: "
                                    + resp.statusCode() + " | URL: " + base + path,
                            "The server exhibited error behavior after receiving a JSON payload with"
                                    + " __proto__ or constructor.prototype keys, indicating the application"
                                    + " may be vulnerable to prototype pollution",
                            "curl -s -X POST '" + base + path + "' \\\n  -H 'Content-Type: application/json' \\\n  -d '"
                                    + jsonPayload + "'",
                            "Sanitize incoming JSON by stripping __proto__ and constructor keys before"
                                    + " processing. Use JSON schema validation to reject unexpected properties.");
                }

                // Phase 5: Deep merge detection -- check if subsequent GET reflects pollution
                try {
                    HttpRequest getReq = HttpRequest.newBuilder().uri(URI.create(base + path))
                            .timeout(Duration.ofSeconds(6)).GET().build();
                    HttpResponse<String> getResp = Http.send(ctx, hc, getReq, HttpResponse.BodyHandlers.ofString(),
                            id());
                    String getBody = getResp.body() != null ? getResp.body() : "";
                    if (getBody.contains(CANARY) && !baselineBody.contains(CANARY)) {
                        log.accept("[!!] " + id() + ": deep merge pollution persisted -- " + path);
                        return Finding.of(id(), path, "Server-Side Prototype Pollution -- Deep Merge Persistence",
                                Severity.HIGH,
                                "POST payload: " + jsonPayload + " | Canary '" + CANARY + "' persisted across requests"
                                        + " | URL: " + base + path,
                                "Prototype pollution via deep merge persists across requests, indicating"
                                        + " the polluted property is stored on a shared object. This can"
                                        + " affect all users and lead to privilege escalation or RCE",
                                "curl -s -X POST '" + base + path
                                        + "' \\\n  -H 'Content-Type: application/json' \\\n  -d '" + jsonPayload
                                        + "' && \\\ncurl -s '" + base + path + "' | grep '" + CANARY + "'",
                                "Use immutable objects or Object.freeze(Object.prototype). Implement"
                                        + " safe merge that ignores __proto__ and constructor keys."
                                        + " Use Map for storing untrusted key-value data.");
                    }
                } catch (CircuitBreakerException cbe) {
                    throw cbe;
                } catch (Exception ignored) {
                    // Follow-up GET failure is non-critical
                }
            } catch (CircuitBreakerException cbe) {
                throw cbe;
            } catch (Exception ignored) {
                // Connection errors for individual payloads
            }
        }
        return null;
    }

    // -------------------------------------------------------------------------
    // Phase 4: Parameter pollution via __proto__ in GET query params
    // -------------------------------------------------------------------------

    private Finding probeParamPollution(ScanContext ctx, HttpClient hc, String base, String path,
            Consumer<String> log) {
        String baselineBody = fetchBody(ctx, hc, base + path, log);

        Set<String> discoveredParams = ctx.discoveredPaths().parameters();
        List<String> testParams = discoveredParams.isEmpty() ? PARAMS : new ArrayList<>(discoveredParams);

        for (String param : testParams) {
            try {
                // Inject __proto__ as a parameter alongside the normal param
                String encoded = URLEncoder.encode("test", StandardCharsets.UTF_8);
                String protoPayload = param + "=" + encoded + "&__proto__[ppcanary]=" + CANARY
                        + "&constructor[prototype][ppcanary]=" + CANARY;
                String url = base + path + "?" + protoPayload;
                HttpRequest req = HttpRequest.newBuilder().uri(URI.create(url)).timeout(Duration.ofSeconds(6)).GET()
                        .build();
                HttpResponse<String> resp = Http.send(ctx, hc, req, HttpResponse.BodyHandlers.ofString(), id());
                String body = resp.body() != null ? resp.body() : "";

                if (body.contains(CANARY) && !baselineBody.contains(CANARY)) {
                    log.accept("[!!] " + id() + ": parameter pollution via __proto__ -- " + path + " param=" + param);
                    return Finding.of(id(), path + "?" + protoPayload, "Prototype Pollution via Parameter Injection",
                            Severity.MEDIUM,
                            "Payload injected alongside param '" + param + "' | Canary '" + CANARY
                                    + "' found in response | URL: " + url,
                            "The application processes __proto__ or constructor.prototype from query"
                                    + " parameters, allowing prototype pollution that may cascade into"
                                    + " XSS, privilege escalation, or logic bypass",
                            "curl -s '" + url + "' | grep '" + CANARY + "'",
                            "Use a query parser that ignores __proto__ and constructor keys (e.g., qs"
                                    + " with allowPrototypes: false). Validate parameter names against an"
                                    + " allowlist. Use Object.create(null) for parsed query objects.");
                }

                // Check for error patterns
                if (ERROR_PATTERN.matcher(body).find() && !ERROR_PATTERN.matcher(baselineBody).find()) {
                    log.accept("[!!] " + id() + ": error after param pollution -- " + path + " param=" + param);
                    return Finding.of(id(), path + "?" + protoPayload,
                            "Prototype Pollution -- Parameter Error Indicator", Severity.LOW,
                            "Payload injected alongside param '" + param + "' | Error pattern in response"
                                    + " | Status: " + resp.statusCode() + " | URL: " + url,
                            "Error response after __proto__ parameter injection suggests the"
                                    + " application may be processing prototype chain properties",
                            "curl -s -o /dev/null -w '%{http_code}' '" + url + "'",
                            "Reject __proto__ and constructor keys in query parameter parsing."
                                    + " Use a safe query parser library.");
                }
            } catch (CircuitBreakerException cbe) {
                throw cbe;
            } catch (Exception ignored) {
                // Individual param failures are expected
            }
        }
        return null;
    }

    // -------------------------------------------------------------------------
    // Utility
    // -------------------------------------------------------------------------

    private String fetchBody(ScanContext ctx, HttpClient hc, String url, Consumer<String> log) {
        try {
            HttpRequest req = HttpRequest.newBuilder().uri(URI.create(url)).timeout(Duration.ofSeconds(6)).GET()
                    .build();
            HttpResponse<String> r = Http.send(ctx, hc, req, HttpResponse.BodyHandlers.ofString(), id());
            return r.body() != null ? r.body() : "";
        } catch (Exception e) {
            return "";
        }
    }
}
