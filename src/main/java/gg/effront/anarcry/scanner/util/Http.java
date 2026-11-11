package gg.effront.anarcry.scanner.util;

import gg.effront.anarcry.model.RequestRecord;
import gg.effront.anarcry.scanner.ScanContext;
import gg.effront.anarcry.scanner.auth.CredentialStore;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.function.Consumer;

public class Http {

    private static final String[] ORIGIN_SPOOF_HEADERS = {"X-Forwarded-For", "X-Real-IP", "X-Original-IP",
            "CF-Connecting-IP", "True-Client-IP", "X-Client-IP"};
    private static final String SPOOF_IP = "127.0.0.1";

    @SuppressWarnings("unchecked")
    public static <T> HttpResponse<T> send(ScanContext ctx, HttpClient hc, HttpRequest req,
            HttpResponse.BodyHandler<T> handler, String moduleId) throws Exception {
        CredentialStore creds = ctx.credentialStore();
        if (creds != null && creds.isExpiringSoon()) {
            try {
                String freshToken = creds.refresh();
                req = rebuildWithToken(req, freshToken);
            } catch (Exception e) {
                Consumer<String> log = ctx.wafState().runtimeLog();
                if (log != null) {
                    log.accept("[!] Token refresh failed: " + e.getMessage());
                }
            }
        }

        String cookies = "";
        if (!ctx.config().sessionCookie().isBlank()) {
            cookies = ctx.config().sessionCookie();
        }
        if (creds != null && creds.isCookieBased() && creds.sessionCookieName() != null) {
            String credCookie = creds.sessionCookieName() + "=" + creds.activeToken();
            cookies = cookies.isEmpty() ? credCookie : cookies + "; " + credCookie;
        }
        String challengeCookies = ctx.wafState().challengeCookies();
        if (!challengeCookies.isEmpty()) {
            cookies = cookies.isEmpty() ? challengeCookies : cookies + "; " + challengeCookies;
        }

        // Inject origin-spoof headers when WAF is detected (CF trusts internal IPs)
        if (ctx.wafState().isWafDetected() || !cookies.isEmpty()) {
            HttpRequest.Builder rb = HttpRequest.newBuilder(req, (n, v) -> true);
            if (!cookies.isEmpty()) {
                rb.header("Cookie", cookies);
            }
            if (ctx.wafState().isWafDetected()) {
                for (String h : ORIGIN_SPOOF_HEADERS) {
                    rb.header(h, SPOOF_IP);
                }
            }
            req = rb.build();
        }

        CircuitBreaker cb = ctx.wafState().circuitBreaker(moduleId);
        cb.checkAndThrow();

        long t0 = System.currentTimeMillis();
        HttpResponse<T> resp = dispatch(ctx, hc, req, handler);
        long elapsed = System.currentTimeMillis() - t0;

        if (creds != null && creds.isCookieBased() && creds.sessionCookieName() != null) {
            rotateCookie(resp, creds);
        }

        int totalDelay = ctx.config().delayMs() + ctx.wafState().wafDelayMs();
        if (totalDelay > 0) {
            try {
                Thread.sleep(totalDelay);
            } catch (InterruptedException ie) {
                Thread.currentThread().interrupt();
            }
        }

        int status = resp.statusCode();
        String serverHdr = resp.headers().firstValue("Server").orElse("");
        String bodyStr = "";
        Object rawBody = resp.body();
        if (rawBody instanceof String s) {
            bodyStr = s;
        }

        if (ctx.wafState().isDebugMode()) {
            String cfRay = resp.headers().firstValue("cf-ray").orElse("-");
            String cfCache = resp.headers().firstValue("cf-cache-status").orElse("-");
            String contentType = resp.headers().firstValue("content-type").orElse("-");
            int bodyLen = bodyStr.length();
            ctx.wafState()
                    .debugLog(moduleId + " " + req.method() + " " + req.uri() + " -> HTTP " + status + " (" + elapsed
                            + "ms) Server=" + serverHdr + " CF-Ray=" + cfRay + " CF-Cache=" + cfCache + " CT="
                            + contentType + " body=" + bodyLen + "B");
            if (status == 403 || status == 503) {
                String bodySnippet = bodyStr.length() > 200 ? bodyStr.substring(0, 200) + "..." : bodyStr;
                bodySnippet = bodySnippet.replace("\n", " ").replace("\r", "");
                ctx.wafState().debugLog(moduleId + " response body: " + bodySnippet);
            }
        }

        boolean wafBlock = WafEvasion.isWafBlocked(status, serverHdr, bodyStr);
        boolean challenge = WafEvasion.isJsChallenge(status, resp.headers().map(), bodyStr);

        // Auto-retry chain when WAF blocks a GET with query params:
        // 1. X-Original-URL rewrite (WAF sees clean /, backend reads header)
        // 2. POST JSON body (CF inspects JSON bodies with weaker rules)
        if (wafBlock && "GET".equals(req.method()) && ctx.wafState().isWafDetected()
                && req.uri().getRawQuery() != null) {
            if (ctx.wafState().isDebugMode()) {
                ctx.wafState().debugLog(moduleId + " WAF block detected, trying auto-retry chain");
            }
            // Retry 1: X-Original-URL / X-Rewrite-URL header bypass
            HttpRequest rewriteRetry = buildRewriteRequest(req);
            if (rewriteRetry != null) {
                HttpResponse<T> rResp = dispatch(ctx, hc, rewriteRetry, handler);
                if (isSuccessfulRetry(rResp)) {
                    if (ctx.wafState().isDebugMode()) {
                        ctx.wafState().debugLog(
                                moduleId + " X-Original-URL retry succeeded (HTTP " + rResp.statusCode() + ")");
                    }
                    return recordAndReturn(ctx, cb, rResp, rewriteRetry, moduleId);
                }
            }
            // Retry 2: POST JSON body
            HttpRequest jsonRetry = convertGetToJsonPost(req);
            if (jsonRetry != null) {
                HttpResponse<T> jResp = dispatch(ctx, hc, jsonRetry, handler);
                if (isSuccessfulRetry(jResp)) {
                    if (ctx.wafState().isDebugMode()) {
                        ctx.wafState()
                                .debugLog(moduleId + " POST JSON retry succeeded (HTTP " + jResp.statusCode() + ")");
                    }
                    return recordAndReturn(ctx, cb, jResp, jsonRetry, moduleId);
                }
            }
            if (ctx.wafState().isDebugMode()) {
                ctx.wafState().debugLog(moduleId + " all retry strategies failed");
            }
        }

        if (wafBlock || challenge) {
            if (ctx.wafState().isDebugMode()) {
                ctx.wafState().debugLog(moduleId + " wafBlock=" + wafBlock + " challenge=" + challenge + " blockType="
                        + ctx.wafState().blockType() + " cb.blocks=" + cb.consecutiveBlocks());
            }
            Consumer<String> log = ctx.wafState().runtimeLog();
            if (!ctx.wafState().isWafDetected()) {
                var providers = WafEvasion.detectProviders(status, resp.headers().map(), bodyStr, req.uri().toString());
                if (!providers.isEmpty()) {
                    ctx.wafState().markWafDetected(providers.get(0).name());
                } else {
                    String cdn = ctx.wafState().cdnProduct();
                    String product = !cdn.isEmpty() ? cdn : WafEvasion.detectWafProduct(serverHdr);
                    ctx.wafState().markWafDetected(product.isEmpty() ? serverHdr : product);
                }
                if (log != null) {
                    log.accept("[!] Runtime WAF detectado via " + moduleId + " -- " + ctx.wafState().wafProduct()
                            + " (HTTP " + status + ")");
                }
                BrowserTransport bt2 = ctx.wafState().browserTransport();
                if (!ctx.wafState().isStealthActive() && bt2 == null) {
                    ctx.wafState().markStealthActive();
                    if (log != null) {
                        log.accept("[*] Runtime: ativando StealthHttpClient (Chrome JA3+H2)");
                    }
                }
            }
            BrowserTransport btRef = ctx.wafState().browserTransport();
            if (btRef != null) {
                if (ctx.wafState().blockType() != WafState.WafBlockType.RULE_BLOCK) {
                    ctx.wafState().markBlockType(WafState.WafBlockType.RULE_BLOCK);
                }
            } else if (ctx.wafState().blockType() == WafState.WafBlockType.NONE) {
                String cfType = WafEvasion.parseCfChallengeType(bodyStr, resp.headers().map(), req.uri().toString());
                if ("managed".equals(cfType) || "interactive".equals(cfType)) {
                    ctx.wafState().markBlockType(WafState.WafBlockType.MANAGED_CHALLENGE);
                } else if ("turnstile".equals(cfType)) {
                    ctx.wafState().markBlockType(WafState.WafBlockType.TURNSTILE);
                } else if ("jsd".equals(cfType) || challenge) {
                    ctx.wafState().markBlockType(WafState.WafBlockType.JS_CHALLENGE);
                } else {
                    ctx.wafState().markBlockType(WafState.WafBlockType.RULE_BLOCK);
                }
            }
            cb.adjustThreshold(ctx.wafState().effectiveThreshold());
            cb.recordBlock(log);
            cb.checkAndThrow();
        } else {
            cb.recordSuccess();
        }

        if (!ctx.wafState().isWafDetected() && WafEvasion.isCloudflarePresent(resp.headers().map())) {
            ctx.wafState().markCdnPresent("cloudflare");
        }

        long bodySize = resp.headers().firstValueAsLong("content-length").orElse(0);
        if (bodySize == 0 && !bodyStr.isEmpty()) {
            bodySize = bodyStr.length();
        }
        ctx.requestLog().accept(new RequestRecord(req.method(), req.uri().toString(), status, bodySize,
                System.currentTimeMillis(), moduleId));
        return resp;
    }

    @SuppressWarnings("unchecked")
    private static <T> HttpResponse<T> dispatch(ScanContext ctx, HttpClient hc, HttpRequest req,
            HttpResponse.BodyHandler<T> handler) throws Exception {
        BrowserTransport bt = ctx.wafState().browserTransport();
        if (bt != null && bt.isChallengeResolved() && bt.isTargetHost(req.uri().toString())) {
            return (HttpResponse<T>) bt.fetch(req);
        } else if (ctx.wafState().isStealthActive()) {
            return (HttpResponse<T>) StealthHttpClient.send(req);
        }
        return hc.send(req, handler);
    }

    private static <T> boolean isSuccessfulRetry(HttpResponse<T> resp) {
        String server = resp.headers().firstValue("Server").orElse("");
        String body = "";
        Object raw = resp.body();
        if (raw instanceof String s) {
            body = s;
        }
        return !WafEvasion.isWafBlocked(resp.statusCode(), server, body);
    }

    private static <T> HttpResponse<T> recordAndReturn(ScanContext ctx, CircuitBreaker cb, HttpResponse<T> resp,
            HttpRequest req, String moduleId) {
        cb.recordSuccess();
        String body = "";
        Object raw = resp.body();
        if (raw instanceof String s) {
            body = s;
        }
        long size = resp.headers().firstValueAsLong("content-length").orElse(0);
        if (size == 0 && !body.isEmpty()) {
            size = body.length();
        }
        ctx.requestLog().accept(new RequestRecord(req.method(), req.uri().toString(), resp.statusCode(), size,
                System.currentTimeMillis(), moduleId));
        return resp;
    }

    // Sends a clean GET / with payload path+query in X-Original-URL header.
    // WAF inspects the visible URL (/), backend reads X-Original-URL for routing.
    static HttpRequest buildRewriteRequest(HttpRequest original) {
        URI uri = original.uri();
        String pathAndQuery = uri.getRawPath();
        if (uri.getRawQuery() != null) {
            pathAndQuery += "?" + uri.getRawQuery();
        }
        String baseUrl = uri.getScheme() + "://" + uri.getAuthority() + "/";
        HttpRequest.Builder rb = HttpRequest.newBuilder().uri(URI.create(baseUrl)).GET()
                .header("X-Original-URL", pathAndQuery).header("X-Rewrite-URL", pathAndQuery)
                .timeout(original.timeout().orElse(Duration.ofSeconds(8)));
        original.headers().map().forEach((name, values) -> {
            String lower = name.toLowerCase();
            if (!"host".equals(lower) && !"x-original-url".equals(lower) && !"x-rewrite-url".equals(lower)) {
                for (String v : values) {
                    rb.header(name, v);
                }
            }
        });
        return rb.build();
    }

    // Converts a GET request with query params to a POST with JSON body.
    // ?foo=bar&baz=qux -> {"foo":"bar","baz":"qux"}
    static HttpRequest convertGetToJsonPost(HttpRequest getReq) {
        String query = getReq.uri().getRawQuery();
        if (query == null || query.isEmpty()) {
            return null;
        }
        StringBuilder json = new StringBuilder("{");
        String[] pairs = query.split("&");
        for (int i = 0; i < pairs.length; i++) {
            int eq = pairs[i].indexOf('=');
            String key;
            String val;
            if (eq >= 0) {
                key = java.net.URLDecoder.decode(pairs[i].substring(0, eq), java.nio.charset.StandardCharsets.UTF_8);
                val = java.net.URLDecoder.decode(pairs[i].substring(eq + 1), java.nio.charset.StandardCharsets.UTF_8);
            } else {
                key = java.net.URLDecoder.decode(pairs[i], java.nio.charset.StandardCharsets.UTF_8);
                val = "";
            }
            if (i > 0) {
                json.append(",");
            }
            json.append("\"").append(escapeJsonStr(key)).append("\":\"").append(escapeJsonStr(val)).append("\"");
        }
        json.append("}");

        URI original = getReq.uri();
        String baseUrl = original.getScheme() + "://" + original.getAuthority() + original.getPath();

        HttpRequest.Builder builder = HttpRequest.newBuilder().uri(URI.create(baseUrl))
                .header("Content-Type", "application/json").POST(HttpRequest.BodyPublishers.ofString(json.toString()))
                .timeout(getReq.timeout().orElse(Duration.ofSeconds(8)));
        getReq.headers().map().forEach((name, values) -> {
            for (String v : values) {
                if (!"content-type".equalsIgnoreCase(name) && !"content-length".equalsIgnoreCase(name)) {
                    builder.header(name, v);
                }
            }
        });
        return builder.build();
    }

    private static HttpRequest rebuildWithToken(HttpRequest original, String freshToken) {
        if (freshToken == null || freshToken.isBlank()) {
            return original;
        }
        boolean hasAuth = original.headers().firstValue("Authorization").isPresent();
        if (!hasAuth) {
            return original;
        }
        HttpRequest.Builder rb = HttpRequest.newBuilder(original, (n, v) -> true);
        rb.header("Authorization", "Bearer " + freshToken);
        return rb.build();
    }

    private static <T> void rotateCookie(HttpResponse<T> resp, CredentialStore creds) {
        String cookieName = creds.sessionCookieName();
        String prefix = cookieName + "=";
        resp.headers().allValues("set-cookie").stream().filter(c -> c.startsWith(prefix)).findFirst()
                .ifPresent(cookie -> {
                    String value = cookie.substring(prefix.length());
                    int semi = value.indexOf(';');
                    String attrs = semi > 0 ? cookie.substring(semi) : "";
                    if (semi > 0) {
                        value = value.substring(0, semi);
                    }
                    long expiry = parseMaxAge(attrs);
                    creds.updateToken(value, expiry);
                });
    }

    private static long parseMaxAge(String cookieAttrs) {
        String lower = cookieAttrs.toLowerCase();
        int idx = lower.indexOf("max-age=");
        if (idx >= 0) {
            int start = idx + 8;
            int end = lower.indexOf(';', start);
            String val = (end > 0 ? lower.substring(start, end) : lower.substring(start)).trim();
            try {
                long seconds = Long.parseLong(val);
                if (seconds > 0) {
                    return seconds;
                }
            } catch (NumberFormatException nfe) {
                // non-numeric max-age, fall through to default
            }
        }
        return 3600;
    }

    public static HttpResponse<String> sendSimple(HttpClient hc, HttpRequest req) throws Exception {
        return hc.send(req, HttpResponse.BodyHandlers.ofString());
    }

    private static String escapeJsonStr(String s) {
        return s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n").replace("\r", "\\r").replace("\t",
                "\\t");
    }
}
