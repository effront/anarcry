package gg.effront.anarcry.scanner.web.cors;

import gg.effront.anarcry.model.CvssCalculator;
import gg.effront.anarcry.model.CweRegistry;
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

public class CorsModule implements Scanner {

    private static final List<String> PROBE_PATHS = List.of("/", "/api/", "/api/v1/", "/api/me");

    private record OriginProbe(String origin, String technique) {}

    @Override
    public String id() { return "CORS"; }

    @Override
    public List<Finding> scan(ScanContext ctx, Consumer<String> log) throws Exception {
        List<Finding> findings = new ArrayList<>();

        String _cweId     = CweRegistry.cweId(id());
        String _cweTitle  = CweRegistry.cweTitle(id());
        String _cveVector = CweRegistry.cvssVector(id());
        double _score     = CvssCalculator.calculate(_cveVector);

        String scheme  = ctx.isHttps() ? "https" : "http";
        int    defPort = ctx.isHttps() ? 443 : 80;
        String baseUrl = scheme + "://" + ctx.host()
                + (ctx.port() != defPort ? ":" + ctx.port() : "");

        HttpClient hc = HttpClientFactory.noRedirect();
        log.accept("[~] CORS: iniciando probes em " + baseUrl);

        // Origins ordered by severity — each tests a distinct bypass technique
        List<OriginProbe> origins = List.of(
                new OriginProbe("https://evil.com",                     "reflection"),
                new OriginProbe("null",                                  "null-origin"),
                new OriginProbe("https://" + ctx.host() + ".evil.com",  "prefix-bypass"),
                new OriginProbe("https://evil." + ctx.host(),           "suffix-bypass"),
                new OriginProbe("http://" + ctx.host(),                 "http-downgrade")
        );

        outer:
        for (String path : PROBE_PATHS) {
            String url = baseUrl + path;
            for (OriginProbe probe : origins) {
                // When JWT is present, also probe authenticated requests
                boolean[] authModes = ctx.jwtToken().isBlank()
                        ? new boolean[]{false}
                        : new boolean[]{false, true};

                for (boolean withAuth : authModes) {
                    try {
                        String origin = probe.origin();
                        HttpRequest.Builder builder = HttpRequest.newBuilder()
                                .uri(URI.create(url))
                                .header("Origin", origin)
                                .header("Cookie", "session=anarcry-probe")
                                .timeout(Duration.ofSeconds(5))
                                .GET();
                        if (withAuth) builder.header("Authorization", "Bearer " + ctx.jwtToken());
                        HttpResponse<Void> resp = Http.send(ctx, hc, builder.build(),
                                HttpResponse.BodyHandlers.discarding(), id());

                        String acao = resp.headers().firstValue("access-control-allow-origin").orElse("").trim();
                        String acac = resp.headers().firstValue("access-control-allow-credentials").orElse("").trim();
                        boolean credsAllowed = acac.equalsIgnoreCase("true");

                        if (acao.isBlank()) continue;

                        String authTag = withAuth ? " [autenticado]" : "";
                        log.accept("[~] CORS: " + path + authTag + " Origin=" + origin
                                + " → ACAO=" + acao + " ACAC=" + acac);

                        // CRITICAL: reflected origin with credentials
                        if (acao.equalsIgnoreCase(origin) && credsAllowed) {
                            log.accept("[!!] CORS: CRITICAL — " + probe.technique() + authTag + " origin com credentials em " + url);
                            findings.add(Finding.of("CORS", path,
                                    "CORS " + probe.technique() + " com credentials" + authTag,
                                    Severity.CRITICAL,
                                    "URL: " + url + " | Origin: " + origin + " | ACAO: " + acao + " | ACAC: " + acac,
                                    "Servidor reflete origin via " + probe.technique()
                                            + " e permite cookies/credenciais — atacante pode ler dados autenticados via XHR cross-origin",
                                    "# PoC (hospedar na origem controlada):\nfetch('" + url
                                            + "', {credentials: 'include'})\n  .then(r => r.text())\n  .then(d => exfiltrate(d))",
                                    "Whitelist explícita de origens; nunca refletir a Origin; validar antes de definir ACAO",
                                    _cweId, _cweTitle, _cveVector, _score));
                            break outer;
                        }

                        // HIGH: wildcard without credentials
                        if (acao.equals("*")) {
                            log.accept("[!] CORS: HIGH — wildcard ACAO" + authTag + " em " + url);
                            findings.add(Finding.of("CORS", path,
                                    "CORS wildcard — Access-Control-Allow-Origin: *" + authTag,
                                    Severity.HIGH,
                                    "URL: " + url + " | ACAO: * | ACAC: " + (acac.isBlank() ? "ausente" : acac),
                                    "Qualquer origem pode ler a resposta — vazamento de dados para sites externos",
                                    "fetch('" + url + "').then(r => r.text()).then(console.log)",
                                    "Restringir ACAO a origens confiáveis; usar wildcard apenas para recursos genuinamente públicos",
                                    _cweId, _cweTitle, _cveVector, _score));
                        }

                        // MEDIUM: null origin accepted
                        if (acao.equalsIgnoreCase("null") && origin.equals("null")) {
                            log.accept("[!] CORS: MEDIUM — null origin aceita" + authTag + " em " + url);
                            findings.add(Finding.of("CORS", path,
                                    "CORS aceita null origin" + authTag,
                                    Severity.MEDIUM,
                                    "URL: " + url + " | ACAO: null",
                                    "null origin aceita — bypass via iframe sandbox ou data: URI no navegador da vítima",
                                    "<iframe sandbox='allow-scripts' srcdoc=\"<script>"
                                            + "fetch('" + url + "',{credentials:'include'})"
                                            + ".then(r=>r.text()).then(d=>parent.postMessage(d,'*'))"
                                            + "</script>\">",
                                    "Nunca aceitar null origin em endpoints com dados sensíveis ou autenticados",
                                    _cweId, _cweTitle, _cveVector, _score));
                        }

                        // MEDIUM: suffix or prefix bypass without creds
                        if (acao.equalsIgnoreCase(origin)
                                && !credsAllowed
                                && (probe.technique().equals("suffix-bypass")
                                    || probe.technique().equals("prefix-bypass")
                                    || probe.technique().equals("http-downgrade"))) {
                            log.accept("[!] CORS: MEDIUM — " + probe.technique() + authTag + " origin aceita em " + url);
                            findings.add(Finding.of("CORS", path,
                                    "CORS " + probe.technique() + " origin aceita" + authTag,
                                    Severity.MEDIUM,
                                    "URL: " + url + " | Origin: " + origin + " | ACAO: " + acao,
                                    "CORS mal configurado aceita " + probe.technique()
                                            + " — potencialmente explorável via domínio controlado pelo atacante",
                                    "curl -H 'Origin: " + origin + "' '" + url + "'",
                                    "Validar origin com comparação exata de string contra whitelist; "
                                            + "não usar regex parcial como endsWith ou startsWith",
                                    _cweId, _cweTitle, _cveVector, _score));
                        }

                    } catch (Exception e) {
                        // Connection errors expected for unreachable paths
                    }
                }
            }
        }

        if (findings.isEmpty()) {
            log.accept("[+] CORS: nenhuma misconfiguration detectada");
        }
        return findings;
    }
}
