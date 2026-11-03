package gg.effront.anarcry.scanner.util;

import gg.effront.anarcry.model.RequestRecord;
import gg.effront.anarcry.scanner.ScanContext;

import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.function.Consumer;

public class Http {

    @SuppressWarnings("unchecked")
    public static <T> HttpResponse<T> send(ScanContext ctx, HttpClient hc, HttpRequest req,
            HttpResponse.BodyHandler<T> handler, String moduleId) throws Exception {
        String cookies = "";
        if (!ctx.config().sessionCookie().isBlank()) {
            cookies = ctx.config().sessionCookie();
        }
        String challengeCookies = ctx.wafState().challengeCookies();
        if (!challengeCookies.isEmpty()) {
            cookies = cookies.isEmpty() ? challengeCookies : cookies + "; " + challengeCookies;
        }
        if (!cookies.isEmpty()) {
            req = HttpRequest.newBuilder(req, (n, v) -> true).header("Cookie", cookies).build();
        }

        CircuitBreaker cb = ctx.wafState().circuitBreaker(moduleId);
        cb.checkAndThrow();

        HttpResponse<T> resp;
        BrowserTransport bt = ctx.wafState().browserTransport();
        if (bt != null && bt.isTargetHost(req.uri().toString())) {
            resp = (HttpResponse<T>) bt.fetch(req);
        } else if (ctx.wafState().isStealthActive()) {
            resp = (HttpResponse<T>) StealthHttpClient.send(req);
        } else {
            resp = hc.send(req, handler);
        }
        if (ctx.config().delayMs() > 0) {
            try {
                Thread.sleep(ctx.config().delayMs());
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

        boolean wafBlock = WafEvasion.isWafBlocked(status, serverHdr, bodyStr);
        boolean challenge = WafEvasion.isJsChallenge(status, resp.headers().map(), bodyStr);

        if (wafBlock || challenge) {
            Consumer<String> log = ctx.wafState().runtimeLog();
            if (!ctx.wafState().isWafDetected()) {
                var providers = WafEvasion.detectProviders(status, resp.headers().map(), bodyStr, req.uri().toString());
                if (!providers.isEmpty()) {
                    ctx.wafState().markWafDetected(providers.get(0).name());
                } else {
                    String product = WafEvasion.detectWafProduct(serverHdr);
                    ctx.wafState().markWafDetected(product.isEmpty() ? serverHdr : product);
                }
                if (log != null) {
                    log.accept("[!] Runtime WAF detectado via " + moduleId + " -- " + ctx.wafState().wafProduct()
                            + " (HTTP " + status + ")");
                }
                if (!ctx.wafState().isStealthActive() && bt == null) {
                    ctx.wafState().markStealthActive();
                    if (log != null) {
                        log.accept("[*] Runtime: ativando StealthHttpClient (Chrome JA3+H2)");
                    }
                }
            }
            // Classify block type at runtime if not already set
            if (ctx.wafState().blockType() == WafState.WafBlockType.NONE) {
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
            cb.lowerThreshold(ctx.wafState().effectiveThreshold());
            cb.recordBlock(log);
            cb.checkAndThrow();
        } else if (status >= 200 && status < 400) {
            cb.recordSuccess();
        }

        if (!ctx.wafState().isWafDetected() && WafEvasion.isCloudflarePresent(resp.headers().map())) {
            ctx.wafState().markWafDetected("cloudflare");
            Consumer<String> log = ctx.wafState().runtimeLog();
            if (log != null) {
                log.accept(
                        "[!] Runtime: Cloudflare detectado via cf-ray/Server em " + moduleId + " -- ativando stealth");
            }
            if (!ctx.wafState().isStealthActive() && bt == null) {
                ctx.wafState().markStealthActive();
            }
        }

        long bodySize = resp.headers().firstValueAsLong("content-length").orElse(0);
        if (bodySize == 0 && !bodyStr.isEmpty()) {
            bodySize = bodyStr.length();
        }
        ctx.requestLog().accept(new RequestRecord(req.method(), req.uri().toString(), status, bodySize,
                System.currentTimeMillis(), moduleId));
        return resp;
    }
}
