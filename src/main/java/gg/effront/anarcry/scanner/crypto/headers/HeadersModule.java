package gg.effront.anarcry.scanner.crypto.headers;

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

public class HeadersModule implements Scanner {

    @Override
    public String id() {
        return "Headers";
    }

    @Override
    public List<Finding> scan(ScanContext ctx, Consumer<String> log) throws Exception {
        String _cweId = CweRegistry.cweId(id());
        String _cweTitle = CweRegistry.cweTitle(id());
        String _cveVector = CweRegistry.cvssVector(id());
        double _score = CvssCalculator.calculate(_cveVector);
        List<Finding> findings = new ArrayList<>();

        log.accept("[~] HEADERS: conectando em " + ctx.targetUrl());

        HttpURLConnection conn;
        if (ctx.isHttps()) {
            HttpsURLConnection https = (HttpsURLConnection) new URL(ctx.targetUrl()).openConnection();
            https.setSSLSocketFactory(TlsUtil.sslContext(TlsUtil.trustAll()).getSocketFactory());
            https.setHostnameVerifier((h, s) -> true);
            conn = https;
        } else {
            conn = (HttpURLConnection) new URL(ctx.targetUrl()).openConnection();
        }

        conn.setConnectTimeout(5000);
        conn.setReadTimeout(10000);
        conn.setInstanceFollowRedirects(true);
        conn.setRequestProperty("User-Agent", "AnarCry/1.1");

        final Map<String, List<String>> headers;
        final String evidence;
        final int code;
        try {
            conn.connect();
            code = conn.getResponseCode();
            log.accept("[~] HEADERS: HTTP " + code);
            headers = conn.getHeaderFields();
            evidence = "HTTP " + code + " -- " + ctx.targetUrl();
            ctx.requestLog().accept(new RequestRecord("GET", ctx.targetUrl(), code,
                    Math.max(0, conn.getContentLengthLong()), System.currentTimeMillis(), id()));
        } finally {
            conn.disconnect();
        }

        if (code == 403) {
            String server = getHeader(headers, "Server");
            boolean wafLikely = server != null
                    && (server.toLowerCase().contains("cloudflare") || server.toLowerCase().contains("akamai")
                            || server.toLowerCase().contains("awselb") || server.toLowerCase().contains("incapsula")
                            || server.toLowerCase().contains("sucuri") || server.toLowerCase().contains("ddos-guard"));
            if (wafLikely) {
                ctx.wafState().markWafDetected(server);
                log.accept("[!] HEADERS: HTTP 403 com Server: " + server
                        + " -- possivel bloqueio por WAF, headers nao confiaveis");
                findings.add(
                        Finding.of("Headers", ctx.targetUrl(), "Possivel bloqueio por WAF -- headers nao confiaveis",
                                Severity.INFO, evidence + " | Server: " + server,
                                "Response 403 de WAF (" + server
                                        + ") -- headers reportados pertencem ao WAF, nao a aplicacao real."
                                        + " Findings de headers ausentes nao sao confiaveis neste contexto.",
                                "curl -sI " + ctx.targetUrl(),
                                "Testar com IP/dominio interno ou bypass de WAF para obter headers reais"));
                return findings;
            }
        }

        if (!hasHeader(headers, "Content-Security-Policy")) {
            findings.add(Finding.of("Headers", ctx.targetUrl(), "CSP ausente", Severity.MEDIUM, evidence,
                    "Sem CSP, a aplicação é mais vulnerável a XSS e injeção de conteúdo",
                    "curl -sI " + ctx.targetUrl() + " | grep -i content-security-policy",
                    "Implementar Content-Security-Policy com política restritiva", _cweId, _cweTitle, _cveVector,
                    _score));
        }

        String cspVal = getHeader(headers, "Content-Security-Policy");
        if (cspVal != null) {
            boolean scriptUnsafe = directiveHasEffectiveUnsafeInline(cspVal, "script-src", "default-src");
            boolean styleUnsafe = !scriptUnsafe
                    && directiveHasEffectiveUnsafeInline(cspVal, "style-src", "default-src");
            if (scriptUnsafe) {
                findings.add(
                        Finding.of("Headers", ctx.targetUrl(), "CSP script-src contém unsafe-inline sem nonce/hash",
                                Severity.MEDIUM, evidence + " | CSP: " + cspVal,
                                "unsafe-inline em script-src sem nonce/hash anula a proteção contra XSS",
                                "curl -sI " + ctx.targetUrl() + " | grep -i content-security-policy",
                                "Remover 'unsafe-inline' do script-src e usar nonces ou hashes para scripts legítimos",
                                _cweId, _cweTitle, _cveVector, _score));
            } else if (styleUnsafe) {
                boolean scriptStrict = !directiveHasEffectiveUnsafeInline(cspVal, "script-src", "default-src");
                boolean frameAncestorsNone = cspDirectiveContains(cspVal, "frame-ancestors", "'none'");
                boolean imgSrcRestricted = !directiveContainsWildcard(cspVal, "img-src", "default-src");
                boolean fullyMitigated = scriptStrict && frameAncestorsNone && imgSrcRestricted;

                Severity styleSev = fullyMitigated ? Severity.INFO : Severity.LOW;
                String styleImpact = fullyMitigated
                        ? "CSS injection severamente mitigada: script-src estrito impede escalada para JS; "
                                + "frame-ancestors 'none' bloqueia clickjacking; img-src restrita limita exfiltração"
                        : "unsafe-inline em style-src permite CSS injection"
                                + (scriptStrict ? "" : "; script-src não é estrito -- escalada para XSS possível")
                                + (frameAncestorsNone
                                        ? ""
                                        : "; frame-ancestors ausente/permissivo -- clickjacking via iframe")
                                + (imgSrcRestricted
                                        ? ""
                                        : "; img-src tem wildcard -- exfiltração via background:url() possível");
                findings.add(Finding.of("Headers", ctx.targetUrl(), "CSP style-src contém unsafe-inline sem nonce/hash",
                        styleSev, evidence + " | CSP: " + cspVal, styleImpact,
                        "curl -sI " + ctx.targetUrl() + " | grep -i content-security-policy",
                        "Remover 'unsafe-inline' do style-src e usar nonces ou hashes para estilos legítimos", _cweId,
                        _cweTitle, _cveVector, _score));
            }
        }

        if (!hasHeader(headers, "X-Frame-Options")) {
            findings.add(Finding.of("Headers", ctx.targetUrl(), "X-Frame-Options ausente", Severity.MEDIUM, evidence,
                    "Sem X-Frame-Options, a página pode ser embutida em iframes -- risco de clickjacking",
                    "curl -sI " + ctx.targetUrl() + " | grep -i x-frame-options",
                    "Adicionar: X-Frame-Options: DENY (ou SAMEORIGIN se necessário)", _cweId, _cweTitle, _cveVector,
                    _score));
        }

        if (!hasHeader(headers, "X-Content-Type-Options")) {
            findings.add(Finding.of("Headers", ctx.targetUrl(), "X-Content-Type-Options ausente", Severity.LOW,
                    evidence, "Sem X-Content-Type-Options, o browser pode interpretar erroneamente o MIME type",
                    "curl -sI " + ctx.targetUrl() + " | grep -i x-content-type-options",
                    "Adicionar: X-Content-Type-Options: nosniff", _cweId, _cweTitle, _cveVector, _score));
        }

        if (!hasHeader(headers, "Referrer-Policy")) {
            findings.add(Finding.of("Headers", ctx.targetUrl(), "Referrer-Policy ausente", Severity.INFO, evidence,
                    "Sem Referrer-Policy, a URL completa pode ser enviada em requisições cross-origin",
                    "curl -sI " + ctx.targetUrl() + " | grep -i referrer-policy",
                    "Adicionar: Referrer-Policy: strict-origin-when-cross-origin", _cweId, _cweTitle, _cveVector,
                    _score));
        }

        if (!hasHeader(headers, "Permissions-Policy")) {
            findings.add(Finding.of("Headers", ctx.targetUrl(), "Permissions-Policy ausente", Severity.INFO, evidence,
                    "Sem Permissions-Policy, features do browser (câmera, microfone etc.) não estão restritas",
                    "curl -sI " + ctx.targetUrl() + " | grep -i permissions-policy",
                    "Adicionar: Permissions-Policy: camera=(), microphone=(), geolocation=()", _cweId, _cweTitle,
                    _cveVector, _score));
        }

        String serverHeader = getHeader(headers, "Server");
        if (serverHeader != null) {
            findings.add(Finding.of("Headers", ctx.targetUrl(), "Header Server expõe tecnologia: " + serverHeader,
                    Severity.INFO, evidence + " | Server: " + serverHeader,
                    "Divulgação de versão de servidor facilita reconhecimento do atacante",
                    "curl -sI " + ctx.targetUrl() + " | grep -i '^server:'", "Remover ou ofuscar o header Server",
                    _cweId, _cweTitle, _cveVector, _score));
        }

        String poweredBy = getHeader(headers, "X-Powered-By");
        if (poweredBy != null) {
            findings.add(Finding.of("Headers", ctx.targetUrl(), "X-Powered-By expõe tecnologia: " + poweredBy,
                    Severity.LOW, evidence + " | X-Powered-By: " + poweredBy,
                    "Divulgação de stack de tecnologia facilita ataques direcionados",
                    "curl -sI " + ctx.targetUrl() + " | grep -i x-powered-by", "Remover o header X-Powered-By", _cweId,
                    _cweTitle, _cveVector, _score));
        }

        // Flags de segurança nos cookies
        headers.entrySet().stream().filter(e -> e.getKey() != null && e.getKey().equalsIgnoreCase("Set-Cookie"))
                .flatMap(e -> e.getValue().stream()).forEach(cookie -> {
                    String low = cookie.toLowerCase();
                    String cname = cookie.contains("=") ? cookie.substring(0, cookie.indexOf("=")).trim() : cookie;
                    if (!low.contains("secure")) {
                        findings.add(Finding.of("Headers", ctx.targetUrl(), "Cookie sem flag Secure: " + cname,
                                Severity.LOW, evidence + " | Set-Cookie: " + cookie,
                                "Cookie pode ser transmitido por HTTP -- interceptável em rede não cifrada",
                                "curl -sI " + ctx.targetUrl() + " | grep -i 'set-cookie'",
                                "Adicionar a flag Secure em todos os cookies de sessão", _cweId, _cweTitle, _cveVector,
                                _score));
                    }
                    if (!low.contains("httponly")) {
                        findings.add(Finding.of("Headers", ctx.targetUrl(), "Cookie sem flag HttpOnly: " + cname,
                                Severity.LOW, evidence + " | Set-Cookie: " + cookie,
                                "Cookie acessível via JavaScript -- roubo de sessão via XSS",
                                "curl -sI " + ctx.targetUrl() + " | grep -i 'set-cookie'",
                                "Adicionar a flag HttpOnly em todos os cookies de sessão", _cweId, _cweTitle,
                                _cveVector, _score));
                    }
                });

        log.accept("[+] HEADERS: " + findings.size() + " finding(s) de headers");
        return findings;
    }

    private boolean hasHeader(Map<String, List<String>> headers, String name) {
        return headers.keySet().stream().anyMatch(k -> k != null && k.equalsIgnoreCase(name));
    }

    private String getHeader(Map<String, List<String>> headers, String name) {
        return headers.entrySet().stream().filter(e -> e.getKey() != null && e.getKey().equalsIgnoreCase(name))
                .map(e -> e.getValue().isEmpty() ? null : e.getValue().get(0)).findFirst().orElse(null);
    }

    private static boolean directiveHasEffectiveUnsafeInline(String csp, String... candidates) {
        for (String candidate : candidates) {
            for (String directive : csp.split(";")) {
                String d = directive.trim().toLowerCase();
                if (!d.startsWith(candidate)) {
                    continue;
                }
                if (!d.contains("unsafe-inline")) {
                    return false;
                }
                boolean neutralized = d.contains("'nonce-") || d.contains("'sha256-") || d.contains("'sha384-")
                        || d.contains("'sha512-");
                return !neutralized;
            }
        }
        return false;
    }

    private static boolean cspDirectiveContains(String csp, String directive, String token) {
        for (String part : csp.split(";")) {
            String d = part.trim().toLowerCase();
            if (d.startsWith(directive.toLowerCase())) {
                return d.contains(token.toLowerCase());
            }
        }
        return false;
    }

    private static boolean directiveContainsWildcard(String csp, String... candidates) {
        for (String candidate : candidates) {
            for (String part : csp.split(";")) {
                String d = part.trim().toLowerCase();
                if (!d.startsWith(candidate.toLowerCase())) {
                    continue;
                }
                for (String token : d.split("\\s+")) {
                    if (token.equals("*") || token.startsWith("*.")) {
                        return true;
                    }
                }
                return false;
            }
        }
        return true;
    }
}
