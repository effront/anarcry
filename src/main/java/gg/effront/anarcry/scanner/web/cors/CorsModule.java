package gg.effront.anarcry.scanner.web.cors;

import gg.effront.anarcry.model.CweRegistry;
import gg.effront.anarcry.model.Finding;
import gg.effront.anarcry.model.KnowledgeBase;
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
import java.util.LinkedHashSet;
import java.util.List;
import java.util.function.Consumer;

public class CorsModule implements Scanner {

    private static final List<String> PROBE_PATHS = List.of("/", "/api/", "/api/v1/", "/api/me");

    private record OriginProbe(String origin, String technique) {
    }

    @Override
    public String id() {
        return "CORS";
    }

    private List<OriginProbe> mergeKbOrigins(List<OriginProbe> base, String targetHost) {
        LinkedHashSet<String> seen = new LinkedHashSet<>();
        List<OriginProbe> merged = new ArrayList<>(base);
        for (OriginProbe p : base) {
            seen.add(p.origin());
        }
        for (String kbp : KnowledgeBase.getInstance().filteredPayloads(id())) {
            String trimmed = kbp.strip();
            // Extract origin from "Origin: VALUE" format
            if (!trimmed.startsWith("Origin:")) {
                continue;
            }
            String origin = trimmed.substring("Origin:".length()).strip();
            // Strip inline comments (preceded by whitespace)
            origin = origin.replaceFirst("\\s+#.*$", "").strip();
            if (origin.isBlank()) {
                continue;
            }
            // Replace generic target host with actual
            origin = origin.replace("alvo.com", targetHost);
            if (seen.add(origin)) {
                merged.add(new OriginProbe(origin, "kb"));
            }
        }
        return merged;
    }

    @Override
    public List<Finding> scan(ScanContext ctx, Consumer<String> log) throws Exception {
        List<Finding> findings = new ArrayList<>();

        String _cweId = CweRegistry.cweId(id());
        String _cweTitle = CweRegistry.cweTitle(id());

        String scheme = ctx.isHttps() ? "https" : "http";
        int defPort = ctx.isHttps() ? 443 : 80;
        String baseUrl = scheme + "://" + ctx.host() + (ctx.port() != defPort ? ":" + ctx.port() : "");

        HttpClient hc = HttpClientFactory.noRedirect();
        log.accept("[~] CORS: iniciando probes em " + baseUrl);

        // Origins ordered by severity -- each tests a distinct bypass technique
        List<OriginProbe> origins = mergeKbOrigins(
                List.of(new OriginProbe("https://evil.com", "reflection"), new OriginProbe("null", "null-origin"),
                        new OriginProbe("https://" + ctx.host() + ".evil.com", "prefix-bypass"),
                        new OriginProbe("https://evil." + ctx.host(), "suffix-bypass"),
                        new OriginProbe("http://" + ctx.host(), "http-downgrade")),
                ctx.host());

        outer : for (String path : PROBE_PATHS) {
            String url = baseUrl + path;
            for (OriginProbe probe : origins) {
                // When JWT is present, also probe authenticated requests
                boolean[] authModes = ctx.jwtToken().isBlank() ? new boolean[]{false} : new boolean[]{false, true};

                for (boolean withAuth : authModes) {
                    try {
                        String origin = probe.origin();
                        HttpRequest.Builder builder = HttpRequest.newBuilder().uri(URI.create(url))
                                .header("Origin", origin).header("Cookie", "session=anarcry-probe")
                                .timeout(Duration.ofSeconds(5)).GET();
                        if (withAuth) {
                            builder.header("Authorization", "Bearer " + ctx.jwtToken());
                        }
                        HttpResponse<Void> resp = Http.send(ctx, hc, builder.build(),
                                HttpResponse.BodyHandlers.discarding(), id());

                        String acao = resp.headers().firstValue("access-control-allow-origin").orElse("").trim();
                        String acac = resp.headers().firstValue("access-control-allow-credentials").orElse("").trim();
                        boolean credsAllowed = acac.equalsIgnoreCase("true");

                        if (acao.isBlank()) {
                            continue;
                        }

                        String authTag = withAuth ? " [autenticado]" : "";
                        log.accept("[~] CORS: " + path + authTag + " Origin=" + origin + " → ACAO=" + acao + " ACAC="
                                + acac);

                        // CRITICAL: reflected origin with credentials
                        if (acao.equalsIgnoreCase(origin) && credsAllowed) {
                            log.accept("[!!] CORS: CRITICAL -- " + probe.technique() + authTag
                                    + " origin com credentials em " + url);
                            findings.add(Finding.of("CORS", path,
                                    "CORS " + probe.technique() + " com credentials" + authTag, Severity.CRITICAL,
                                    "URL: " + url + " | Origin: " + origin + " | ACAO: " + acao + " | ACAC: " + acac,
                                    "Servidor reflete origin via " + probe.technique()
                                            + " e permite cookies/credenciais -- atacante pode ler dados autenticados"
                                            + " via XHR cross-origin",
                                    "# PoC (hospedar na origem controlada):\nfetch('" + url
                                            + "', {credentials: 'include'})\n  .then(r => r.text())\n  .then(d =>"
                                            + "exfiltrate(d))",
                                    "Whitelist explícita de origens; nunca refletir a Origin; validar antes de definir"
                                            + "ACAO",
                                    _cweId, _cweTitle, "AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N", 9.3));
                            break outer;
                        }

                        if (acao.equals("*")) {
                            if (credsAllowed) {
                                // Spec forbids ACAO:* with ACAC:true but broken servers do it
                                log.accept("[!] CORS: HIGH -- wildcard ACAO com credentials" + authTag + " em " + url);
                                findings.add(Finding.of("CORS", path,
                                        "CORS wildcard com Access-Control-Allow-Credentials: true" + authTag,
                                        Severity.HIGH, "URL: " + url + " | ACAO: * | ACAC: true",
                                        "Wildcard ACAO combinado com credentials -- navegadores"
                                                + " modernos bloqueiam, mas proxies intermediarios"
                                                + " ou clientes nao-browser podem permitir leitura"
                                                + " cross-origin de dados autenticados",
                                        "curl -H 'Origin: https://evil.com' -v '" + url + "'",
                                        "Remover wildcard; usar whitelist explicita de origens;"
                                                + " nunca combinar ACAO:* com ACAC:true",
                                        _cweId, _cweTitle, "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5));
                            } else {
                                Severity sev = Severity.MEDIUM;
                                String sevLabel = "MEDIUM";
                                String impactNote = "Qualquer origem pode ler a resposta, porem sem"
                                        + " credentials (ACAC ausente) o impacto se limita"
                                        + " a dados nao autenticados";
                                String cvssVec = "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N";
                                double cvssNum = 5.3;

                                try {
                                    HttpRequest noAuthReq = HttpRequest.newBuilder().uri(URI.create(url))
                                            .timeout(Duration.ofSeconds(5)).GET().build();
                                    HttpResponse<String> noAuthResp = Http.send(ctx, hc, noAuthReq,
                                            HttpResponse.BodyHandlers.ofString(), id());
                                    int sc = noAuthResp.statusCode();
                                    if (sc == 401 || sc == 403) {
                                        sev = Severity.INFO;
                                        sevLabel = "INFO";
                                        impactNote = "Endpoint requer autenticacao (HTTP " + sc
                                                + ") e ACAC ausente -- wildcard ACAO sem" + " impacto exploravel";
                                        cvssVec = "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N";
                                        cvssNum = 0.0;
                                    }
                                } catch (Exception ignored) {
                                    // Probe failure -- keep MEDIUM as conservative default
                                }

                                log.accept("[" + (sev == Severity.INFO ? "~" : "!") + "] CORS: " + sevLabel
                                        + " -- wildcard ACAO" + authTag + " em " + url);
                                findings.add(Finding.of("CORS", path,
                                        "CORS wildcard -- Access-Control-Allow-Origin: *" + authTag, sev,
                                        "URL: " + url + " | ACAO: * | ACAC: " + (acac.isBlank() ? "ausente" : acac),
                                        impactNote, "fetch('" + url + "').then(r => r.text()).then(console.log)",
                                        "Restringir ACAO a origens confiaveis; usar wildcard"
                                                + " apenas para recursos genuinamente publicos",
                                        _cweId, _cweTitle, cvssVec, cvssNum));
                            }
                        }

                        // MEDIUM: null origin accepted
                        if (acao.equalsIgnoreCase("null") && origin.equals("null")) {
                            log.accept("[!] CORS: MEDIUM -- null origin aceita" + authTag + " em " + url);
                            findings.add(Finding.of("CORS", path, "CORS aceita null origin" + authTag, Severity.MEDIUM,
                                    "URL: " + url + " | ACAO: null",
                                    "null origin aceita -- bypass via iframe sandbox ou data: URI no navegador"
                                            + " da vítima",
                                    "<iframe sandbox='allow-scripts' srcdoc=\"<script>" + "fetch('" + url
                                            + "',{credentials:'include'})"
                                            + ".then(r=>r.text()).then(d=>parent.postMessage(d,'*'))" + "</script>\">",
                                    "Nunca aceitar null origin em endpoints com dados sensíveis ou autenticados",
                                    _cweId, _cweTitle, "AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N", 5.4));
                        }

                        // MEDIUM: suffix or prefix bypass without creds
                        if (acao.equalsIgnoreCase(origin) && !credsAllowed
                                && (probe.technique().equals("suffix-bypass")
                                        || probe.technique().equals("prefix-bypass")
                                        || probe.technique().equals("http-downgrade"))) {
                            log.accept(
                                    "[!] CORS: MEDIUM -- " + probe.technique() + authTag + " origin aceita em " + url);
                            findings.add(Finding.of("CORS", path,
                                    "CORS " + probe.technique() + " origin aceita" + authTag, Severity.MEDIUM,
                                    "URL: " + url + " | Origin: " + origin + " | ACAO: " + acao,
                                    "CORS mal configurado aceita " + probe.technique()
                                            + " -- potencialmente explorável via domínio controlado pelo atacante",
                                    "curl -H 'Origin: " + origin + "' '" + url + "'",
                                    "Validar origin com comparação exata de string contra whitelist; "
                                            + "não usar regex parcial como endsWith ou startsWith",
                                    _cweId, _cweTitle, "AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N", 5.4));
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
