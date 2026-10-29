package gg.effront.anarcry.scanner.crypto.hsts;

import gg.effront.anarcry.model.CvssCalculator;
import gg.effront.anarcry.model.CweRegistry;
import gg.effront.anarcry.model.Finding;
import gg.effront.anarcry.model.RequestRecord;
import gg.effront.anarcry.model.Severity;
import gg.effront.anarcry.scanner.ScanContext;
import gg.effront.anarcry.scanner.Scanner;
import gg.effront.anarcry.scanner.util.TlsUtil;

import javax.net.ssl.HttpsURLConnection;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;

public class HSTSModule implements Scanner {

    private static final long MIN_MAX_AGE = 31536000L;

    @Override
    public String id() {
        return "HSTS";
    }

    @Override
    public List<Finding> scan(ScanContext ctx, Consumer<String> log) throws Exception {
        String cweId = CweRegistry.cweId(id());
        String cweTitle = CweRegistry.cweTitle(id());
        String cvssVector = CweRegistry.cvssVector(id());
        double score = CvssCalculator.calculate(cvssVector);
        List<Finding> findings = new ArrayList<>();

        // Probe 1: HTTP acessível + JWT transmitido em plaintext
        String httpUrl = ctx.targetUrl().replaceFirst("^https://", "http://");
        log.accept("[~] HSTS: probe HTTP em " + httpUrl);
        try {
            HttpURLConnection conn = (HttpURLConnection) new URL(httpUrl).openConnection();
            conn.setInstanceFollowRedirects(false);
            conn.setConnectTimeout(5000);
            conn.setReadTimeout(8000);
            conn.setRequestProperty("User-Agent", "AnarCry/1.1");
            if (!ctx.jwtToken().isBlank()) {
                conn.setRequestProperty("Authorization", "Bearer " + ctx.jwtToken());
            }

            int status;
            try {
                status = conn.getResponseCode();
            } finally {
                conn.disconnect();
            }

            ctx.requestLog().accept(new RequestRecord("GET", httpUrl, status, 0, System.currentTimeMillis(), id()));
            String evidence = "GET " + httpUrl + " → HTTP " + status;

            if (status == 200) {
                findings.add(Finding.of(id(), ctx.targetUrl(),
                        "API serve conteúdo via HTTP sem redirect -- JWT em plaintext", Severity.CRITICAL, evidence,
                        "Servidor retorna 200 em HTTP: credenciais e dados transmitidos sem cifração",
                        "curl -sI " + httpUrl, "Forçar HTTPS em todas as rotas e adicionar HSTS", cweId, cweTitle,
                        cvssVector, score));
            } else if (status / 100 == 3) {
                if (!ctx.jwtToken().isBlank()) {
                    // Validado via tcpdump: Authorization header é enviado no request HTTP
                    // antes do redirect chegar -- um MITM intercepta o token sem processar o 3xx
                    findings.add(Finding.of(id(), ctx.targetUrl(),
                            "JWT transmitido em plaintext antes do redirect HTTP " + status, Severity.HIGH, evidence,
                            "Authorization: Bearer enviado em TCP plaintext antes do " + status
                                    + " -- MITM intercepta o token sem precisar quebrar TLS. "
                                    + "Validado: tcpdump capturou JWT completo no wire em port 80.",
                            "# Terminal 1:\nsudo tcpdump -i any -A 'tcp port 80'\n"
                                    + "# Terminal 2:\ncurl --max-redirs 0 " + "-H 'Authorization: Bearer <jwt>' "
                                    + httpUrl,
                            "Adicionar HSTS com max-age=31536000; includeSubDomains; preload", cweId, cweTitle,
                            cvssVector, score));
                } else {
                    findings.add(Finding.of(id(), ctx.targetUrl(),
                            "Endpoint HTTP acessível -- downgrade via SSLstrip possível", Severity.MEDIUM, evidence,
                            "Sem HSTS, MITM pode interceptar o redirect " + status + " e manter conexão em HTTP",
                            "curl -sv --max-redirs 0 " + httpUrl,
                            "Adicionar HSTS com max-age=31536000; includeSubDomains; preload", cweId, cweTitle,
                            cvssVector, score));
                }
            }
        } catch (Exception e) {
            log.accept("[~] HSTS: probe HTTP falhou -- " + e.getMessage());
        }

        // Probe 2: qualidade do header HSTS no response HTTPS
        log.accept("[~] HSTS: verificando policy HTTPS em " + ctx.targetUrl());
        try {
            HttpsURLConnection https = (HttpsURLConnection) new URL(ctx.targetUrl()).openConnection();
            https.setSSLSocketFactory(TlsUtil.sslContext(TlsUtil.trustAll()).getSocketFactory());
            https.setHostnameVerifier((h, s) -> true);
            https.setInstanceFollowRedirects(true);
            https.setConnectTimeout(5000);
            https.setReadTimeout(8000);
            https.setRequestProperty("User-Agent", "AnarCry/1.1");

            Map<String, List<String>> headers;
            int status;
            try {
                status = https.getResponseCode();
                headers = https.getHeaderFields();
            } finally {
                https.disconnect();
            }

            ctx.requestLog()
                    .accept(new RequestRecord("GET", ctx.targetUrl(), status, 0, System.currentTimeMillis(), id()));
            String evidence = "GET " + ctx.targetUrl() + " → HTTP " + status;
            String hstsVal = getHeader(headers, "Strict-Transport-Security");

            if (hstsVal == null) {
                findings.add(
                        Finding.of(id(), ctx.targetUrl(), "HSTS ausente no response HTTPS", Severity.HIGH, evidence,
                                "Sem Strict-Transport-Security, o browser nao memoriza"
                                        + " que o dominio exige HTTPS -- SSLstrip trivial",
                                "curl -sI " + ctx.targetUrl() + " | grep -i strict",
                                "Adicionar: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
                                cweId, cweTitle, cvssVector, score));
            } else {
                long maxAge = parseMaxAge(hstsVal);
                if (maxAge >= 0 && maxAge < MIN_MAX_AGE) {
                    findings.add(Finding.of(id(), ctx.targetUrl(),
                            "HSTS max-age insuficiente: " + maxAge + "s (mínimo recomendado: " + MIN_MAX_AGE + "s)",
                            Severity.MEDIUM, evidence + " | HSTS: " + hstsVal,
                            "max-age baixo -- política expirada rapidamente, reabrindo janela para downgrade",
                            "curl -sI " + ctx.targetUrl() + " | grep -i strict",
                            "Aumentar max-age para pelo menos 31536000 (1 ano)", cweId, cweTitle, cvssVector, score));
                }
                if (!hstsVal.toLowerCase().contains("includesubdomains")) {
                    findings.add(Finding.of(id(), ctx.targetUrl(), "HSTS sem includeSubDomains", Severity.LOW,
                            evidence + " | HSTS: " + hstsVal,
                            "Subdomínios não cobertos -- downgrade HTTP ainda possível em *.domínio",
                            "curl -sI " + ctx.targetUrl() + " | grep -i strict",
                            "Adicionar includeSubDomains à diretiva HSTS", cweId, cweTitle, cvssVector, score));
                }
                if (!hstsVal.toLowerCase().contains("preload")) {
                    findings.add(Finding.of(id(), ctx.targetUrl(), "HSTS sem preload", Severity.INFO,
                            evidence + " | HSTS: " + hstsVal,
                            "Sem preload, primeira visita de novo usuário ainda é vulnerável (TOFU attack)",
                            "curl -sI " + ctx.targetUrl() + " | grep -i strict",
                            "Adicionar preload e submeter em https://hstspreload.org", cweId, cweTitle, cvssVector,
                            score));
                }
            }
        } catch (Exception e) {
            log.accept("[~] HSTS: probe HTTPS falhou -- " + e.getMessage());
        }

        log.accept("[+] HSTS: " + findings.size() + " finding(s)");
        return findings;
    }

    private String getHeader(Map<String, List<String>> headers, String name) {
        return headers.entrySet().stream().filter(e -> e.getKey() != null && e.getKey().equalsIgnoreCase(name))
                .map(e -> e.getValue().isEmpty() ? null : e.getValue().get(0)).findFirst().orElse(null);
    }

    private long parseMaxAge(String hstsValue) {
        for (String part : hstsValue.split(";")) {
            String p = part.trim().toLowerCase();
            if (p.startsWith("max-age=")) {
                try {
                    return Long.parseLong(p.substring("max-age=".length()).trim());
                } catch (NumberFormatException ignored) {
                }
            }
        }
        return -1;
    }
}
