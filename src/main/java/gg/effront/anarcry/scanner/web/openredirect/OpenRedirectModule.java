package gg.effront.anarcry.scanner.web.openredirect;

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

public class OpenRedirectModule implements Scanner {

    private static final String EVIL_HOST = "evil.anarcry-probe.com";

    private static final List<String> REDIRECT_PARAMS = List.of("url", "next", "redirect", "returnUrl", "redirect_uri",
            "return", "to", "goto", "dest");

    private static final List<String> PROBE_PATHS = List.of("", "/login", "/logout", "/redirect", "/go",
            "/auth/callback", "/oauth/authorize", "/oauth/return", "/sso");

    // Payloads ordered by detection value:
    // 1. Absolute URL — baseline check
    // 2. Protocol-relative — bypasses "must start with https" check
    // 3. Encoded slash — bypasses path-prefix check
    // 4. User-info bypass — browser navigates to evil.com after @
    // 5. Backslash — normalized to / by IIS and some parsers
    // 6. Encoded scheme — bypasses regex on raw string
    private record Payload(String value, String technique) {
    }

    private static final List<Payload> PAYLOADS = List.of(new Payload("https://" + EVIL_HOST, "absolute"),
            new Payload("//" + EVIL_HOST, "protocol-relative"), new Payload("/%2f%2f" + EVIL_HOST, "encoded-slash"),
            new Payload("https://trusted.com@" + EVIL_HOST, "user-info"), new Payload("\\" + EVIL_HOST, "backslash"),
            new Payload("https%3A%2F%2F" + EVIL_HOST, "encoded-scheme"));

    @Override
    public String id() {
        return "OpenRedirect";
    }

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
        log.accept("[~] OpenRedirect: iniciando probes em " + baseUrl);

        outer : for (String path : PROBE_PATHS) {
            for (String param : REDIRECT_PARAMS) {
                for (Payload payload : PAYLOADS) {
                    try {
                        String encoded = URLEncoder.encode(payload.value(), "UTF-8");
                        String url = baseUrl + path + "?" + param + "=" + encoded;
                        HttpRequest req = HttpRequest.newBuilder().uri(URI.create(url)).timeout(Duration.ofSeconds(3))
                                .GET().build();
                        HttpResponse<Void> resp = Http.send(ctx, hc, req, HttpResponse.BodyHandlers.discarding(), id());
                        int status = resp.statusCode();
                        String location = resp.headers().firstValue("location").orElse("").trim();

                        if ((status == 301 || status == 302 || status == 307 || status == 308)
                                && location.contains(EVIL_HOST)) {
                            log.accept("[!!] OpenRedirect: HIGH — " + payload.technique() + " bypass confirmado → "
                                    + location);
                            findings.add(Finding.of("OpenRedirect", path + "?" + param,
                                    "Open Redirect — " + payload.technique() + " bypass", Severity.HIGH,
                                    "URL: " + url + " | Param: " + param + " | Técnica: " + payload.technique()
                                            + " | Location: " + location,
                                    "Parâmetro de redirecionamento aceita URL externa via " + payload.technique()
                                            + " — permite phishing e roubo de tokens OAuth via redirect",
                                    "curl -v '" + baseUrl + path + "?" + param + "=https://" + EVIL_HOST + "'",
                                    "Validar redirect_uri contra whitelist de paths relativos; "
                                            + "rejeitar URLs com host diferente; nunca confiar em redirect_uri do"
                                            + "cliente",
                                    _cweId, _cweTitle, _cveVector, _score));
                            break outer;
                        }
                    } catch (Exception e) {
                        // URI creation may fail for edge-case payloads — skip
                    }
                }
            }
        }

        if (findings.isEmpty()) {
            log.accept("[+] OpenRedirect: nenhum redirect aberto detectado");
        }
        return findings;
    }
}
