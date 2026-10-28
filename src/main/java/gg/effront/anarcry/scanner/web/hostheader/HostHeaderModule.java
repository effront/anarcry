package gg.effront.anarcry.scanner.web.hostheader;

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

public class HostHeaderModule implements Scanner {

    private static final String PROBE_HOST = "evil.anarcry-probe.com";

    private static final List<String> HOST_HEADERS = List.of("Host", "X-Forwarded-Host", "X-Host", "X-Original-Host");

    private record ProbeTarget(String method, String path, String body, boolean isPasswordReset) {
    }

    private static final List<ProbeTarget> TARGETS = List.of(new ProbeTarget("GET", "/", null, false),
            new ProbeTarget("GET", "/api/", null, false),
            new ProbeTarget("POST", "/forgot-password", "email=test@test.com", true),
            new ProbeTarget("POST", "/password/reset", "email=test@test.com", true),
            new ProbeTarget("POST", "/account/recover", "email=test@test.com", true));

    @Override
    public String id() {
        return "HostHeader";
    }

    @Override
    public List<Finding> scan(ScanContext ctx, Consumer<String> log) throws Exception {
        String _cweId = CweRegistry.cweId(id());
        String _cweTitle = CweRegistry.cweTitle(id());
        String _cveVector = CweRegistry.cvssVector(id());
        double _score = CvssCalculator.calculate(_cveVector);
        List<Finding> findings = new ArrayList<>();

        String scheme = ctx.isHttps() ? "https" : "http";
        int defPort = ctx.isHttps() ? 443 : 80;
        String baseUrl = scheme + "://" + ctx.host() + (ctx.port() != defPort ? ":" + ctx.port() : "");

        HttpClient hc = HttpClientFactory.noRedirect();
        log.accept("[~] HostHeader: iniciando probes em " + baseUrl);

        for (ProbeTarget target : TARGETS) {
            for (String headerName : HOST_HEADERS) {
                try {
                    String url = baseUrl + target.path();
                    HttpRequest.Builder builder = HttpRequest.newBuilder().uri(URI.create(url))
                            .timeout(Duration.ofSeconds(5)).header(headerName, PROBE_HOST);

                    if (!ctx.jwtToken().isBlank()) {
                        builder.header("Authorization", "Bearer " + ctx.jwtToken());
                    }

                    if ("POST".equals(target.method()) && target.body() != null) {
                        builder.header("Content-Type", "application/x-www-form-urlencoded");
                        builder.POST(HttpRequest.BodyPublishers.ofString(target.body()));
                    } else {
                        builder.GET();
                    }

                    HttpRequest req = builder.build();
                    HttpResponse<String> resp = Http.send(ctx, hc, req, HttpResponse.BodyHandlers.ofString(), id());
                    String body = resp.body() != null ? resp.body() : "";
                    String location = resp.headers().firstValue("location").orElse("");

                    boolean bodyReflects = body.contains(PROBE_HOST);
                    boolean locationReflects = location.contains(PROBE_HOST);

                    if (bodyReflects || locationReflects) {
                        Severity sev;
                        String title;
                        if (target.isPasswordReset()) {
                            sev = Severity.HIGH;
                            title = "Host Header Injection -- password reset poisoning via " + headerName;
                        } else {
                            sev = Severity.MEDIUM;
                            title = "Host Header Injection -- " + headerName + " refletido em " + target.path();
                        }

                        String evidence = bodyReflects ? "Body contém: " + PROBE_HOST : "Location: " + location;

                        log.accept("[!!] HostHeader: " + sev + " -- " + headerName + " em " + target.path());
                        findings.add(Finding.of("HostHeader", target.path(), title, sev,
                                "URL: " + url + " | Header: " + headerName + ": " + PROBE_HOST + " | Evidência: "
                                        + evidence,
                                target.isPasswordReset()
                                        ? "Servidor usa o header " + headerName + " para gerar link de reset -- "
                                                + "atacante pode enviar link de reset apontando para domínio controlado"
                                        : "Servidor reflete o valor de " + headerName
                                                + " -- possível cache poisoning ou open redirect",
                                "curl -H '" + headerName + ": " + PROBE_HOST + "' '" + url + "'",
                                "Ignorar headers Host customizáveis; usar hostname configurado na aplicação para links"
                                        + "de reset; " + "implementar allowlist de hosts permitidos",
                                _cweId, _cweTitle, _cveVector, _score));

                        // One finding per endpoint is sufficient
                        break;
                    }
                } catch (Exception e) {
                    // Expected for unreachable paths
                }
            }
        }

        if (findings.isEmpty()) {
            log.accept("[+] HostHeader: nenhuma injeção detectada");
        }
        return findings;
    }
}
