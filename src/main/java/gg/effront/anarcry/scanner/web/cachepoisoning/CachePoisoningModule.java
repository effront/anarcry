package gg.effront.anarcry.scanner.web.cachepoisoning;

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
import java.util.List;
import java.util.function.Consumer;
import gg.effront.anarcry.model.CweRegistry;
import gg.effront.anarcry.model.CvssCalculator;

public class CachePoisoningModule implements Scanner {

    private static final String PROBE_VALUE = "evil.anarcry-probe.com";

    // Headers CDNs commonly exclude from the cache key but apps use to build responses
    private static final List<String> UNKEYED_HEADERS = List.of(
            "X-Forwarded-Host",
            "X-Forwarded-Scheme",
            "X-Original-URL",
            "X-Rewrite-URL",
            "X-Forwarded-Prefix"
    );

    private static final List<String> PROBE_PATHS = List.of(
            "/", "/api/", "/api/v1/"
    );

    @Override
    public String id() { return "CachePoisoning"; }

    @Override
    public List<Finding> scan(ScanContext ctx, Consumer<String> log) throws Exception {
        String _cweId     = CweRegistry.cweId(id());
        String _cweTitle  = CweRegistry.cweTitle(id());
        String _cveVector = CweRegistry.cvssVector(id());
        double _score     = CvssCalculator.calculate(_cveVector);
        List<Finding> findings = new ArrayList<>();

        String scheme  = ctx.isHttps() ? "https" : "http";
        int    defPort = ctx.isHttps() ? 443 : 80;
        String baseUrl = scheme + "://" + ctx.host()
                + (ctx.port() != defPort ? ":" + ctx.port() : "");

        HttpClient hc = HttpClientFactory.http2();
        log.accept("[~] CachePoisoning: testando " + UNKEYED_HEADERS.size()
                + " unkeyed headers em " + baseUrl);

        outer:
        for (String path : PROBE_PATHS) {
            String url = baseUrl + path;
            for (String header : UNKEYED_HEADERS) {
                try {
                    HttpRequest req = HttpRequest.newBuilder()
                            .uri(URI.create(url))
                            .timeout(Duration.ofSeconds(5))
                            .header(header, PROBE_VALUE)
                            .GET().build();

                    HttpResponse<String> resp = Http.send(ctx, hc, req,
                            HttpResponse.BodyHandlers.ofString(), id());

                    String body     = resp.body() != null ? resp.body() : "";
                    boolean inBody  = body.contains(PROBE_VALUE);
                    boolean inLoc   = resp.headers().firstValue("location")
                            .orElse("").contains(PROBE_VALUE);

                    if (inBody || inLoc) {
                        boolean cached  = isCacheHit(resp);
                        Severity sev    = cached ? Severity.CRITICAL : Severity.HIGH;
                        String title    = cached
                                ? "Web Cache Poisoning — reflexão confirmada e cacheada"
                                : "Web Cache Poisoning — header unkeyed refletido (cache não confirmado)";
                        log.accept("[!!] CachePoisoning: " + sev + " — " + header
                                + " refletido" + (cached ? " + cacheado" : "") + " em " + url);
                        findings.add(Finding.of("CachePoisoning", path,
                                title, sev,
                                "Header: " + header + "=" + PROBE_VALUE
                                        + " | Refletido em " + (inBody ? "body" : "Location")
                                        + (cached ? " | Cache HIT detectado" : ""),
                                "Header não incluso na cache key é refletido na resposta — "
                                        + "atacante pode envenenar o cache servindo XSS/redirects maliciosos "
                                        + "para todos os usuários que acessam essa URL",
                                "curl -H '" + header + ": " + PROBE_VALUE + "' " + url,
                                "Incluir na cache key todos os headers que afetam o conteúdo da resposta; "
                                        + "ou não refletir headers de request em responses cacheadas",
                                _cweId, _cweTitle, _cveVector, _score));
                        break outer;
                    }
                } catch (Exception e) {
                    // Skip connection errors — continue
                }
            }
        }

        if (findings.isEmpty()) {
            log.accept("[+] CachePoisoning: nenhum unkeyed header refletido detectado");
        }
        return findings;
    }

    private boolean isCacheHit(HttpResponse<?> resp) {
        String xCache  = resp.headers().firstValue("x-cache").orElse("").toLowerCase();
        String cfCache = resp.headers().firstValue("cf-cache-status").orElse("").toLowerCase();
        String age     = resp.headers().firstValue("age").orElse("0").trim();
        boolean varnish = resp.headers().map().containsKey("x-varnish");

        if (xCache.contains("hit"))   return true;
        if (cfCache.contains("hit"))  return true;
        if (varnish)                  return true;
        try { if (Integer.parseInt(age) > 0) return true; } catch (NumberFormatException ignored) {}
        return false;
    }
}
