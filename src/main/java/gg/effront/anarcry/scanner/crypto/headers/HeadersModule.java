package gg.effront.anarcry.scanner.crypto.headers;

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
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.function.Consumer;

public class HeadersModule implements Scanner {

    private static final Set<String> CDN_WAF_NAMES = Set.of("cloudflare", "akamai", "akamaighost", "awselb",
            "incapsula", "sucuri", "ddos-guard", "cloudfront", "fastly", "varnish");

    private static final Set<String> PAAS_NAMES = Set.of("railway-hikari", "railway", "heroku", "render", "fly",
            "vercel", "netlify");

    private static final List<String> FALLBACK_PATHS = List.of("/health", "/api", "/api/health", "/status",
            "/robots.txt", "/favicon.ico");

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

        HttpClient hc = HttpClientFactory.http2();
        HttpRequest request = HttpRequest.newBuilder().uri(URI.create(ctx.targetUrl())).timeout(Duration.ofSeconds(10))
                .header("User-Agent", gg.effront.anarcry.Version.userAgent()).GET().build();
        HttpResponse<String> response = Http.send(ctx, hc, request, HttpResponse.BodyHandlers.ofString(), id());
        int code = response.statusCode();
        log.accept("[~] HEADERS: HTTP " + code);
        Map<String, List<String>> headers = response.headers().map();
        String checkedUrl = ctx.targetUrl();
        boolean isErrorPage = code >= 400;

        if (code == 403) {
            String server = getHeader(headers, "Server");
            boolean wafLikely = server != null && isCdnOrWaf(server);
            if (wafLikely) {
                ctx.wafState().markWafDetected(server);
                log.accept("[!] HEADERS: HTTP 403 com Server: " + server
                        + " -- possivel bloqueio por WAF, headers nao confiaveis");
                findings.add(
                        Finding.of("Headers", ctx.targetUrl(), "Possivel bloqueio por WAF -- headers nao confiaveis",
                                Severity.INFO, "HTTP " + code + " -- " + ctx.targetUrl() + " | Server: " + server,
                                "Response 403 de WAF (" + server
                                        + ") -- headers reportados pertencem ao WAF, nao a aplicacao real."
                                        + " Findings de headers ausentes nao sao confiaveis neste contexto.",
                                "curl -sI " + ctx.targetUrl(),
                                "Testar com IP/dominio interno ou bypass de WAF para obter headers reais"));
                return findings;
            }
        }

        if (isErrorPage) {
            log.accept("[~] HEADERS: base retornou HTTP " + code + " -- tentando fallback paths");
            String baseUrl = ctx.targetUrl();
            if (baseUrl.endsWith("/")) {
                baseUrl = baseUrl.substring(0, baseUrl.length() - 1);
            }
            for (String path : FALLBACK_PATHS) {
                String probeUrl = baseUrl + path;
                try {
                    HttpRequest probeReq = HttpRequest.newBuilder().uri(URI.create(probeUrl))
                            .timeout(Duration.ofSeconds(6)).header("User-Agent", gg.effront.anarcry.Version.userAgent())
                            .GET().build();
                    HttpResponse<String> probeResp = Http.send(ctx, hc, probeReq, HttpResponse.BodyHandlers.ofString(),
                            id());
                    int probeCode = probeResp.statusCode();
                    if (probeCode >= 200 && probeCode < 300) {
                        log.accept("[+] HEADERS: fallback " + path + " retornou HTTP " + probeCode
                                + " -- usando como fonte primaria");
                        code = probeCode;
                        headers = probeResp.headers().map();
                        checkedUrl = probeUrl;
                        isErrorPage = false;
                        break;
                    }
                } catch (Exception e) {
                    // skip failed probes
                }
            }
            if (isErrorPage) {
                log.accept("[~] HEADERS: nenhum fallback retornou 2xx -- usando response original com nota");
            }
        }

        String evidenceBase = "HTTP " + code + " -- " + checkedUrl;
        if (isErrorPage) {
            evidenceBase += " (error page -- headers may not reflect production routes)";
        }
        final String evidence = evidenceBase;

        if (!hasHeader(headers, "Content-Security-Policy")) {
            Severity cspSev = isErrorPage ? Severity.LOW : Severity.MEDIUM;
            String cspImpact = "Sem CSP, a aplicacao e mais vulneravel a XSS e injecao de conteudo";
            if (isErrorPage) {
                cspImpact += " (severidade reduzida: pagina de erro tem impacto limitado de XSS)";
            }
            findings.add(Finding.of("Headers", ctx.targetUrl(), "CSP ausente", cspSev, evidence, cspImpact,
                    "curl -sI " + checkedUrl + " | grep -i content-security-policy",
                    "Implementar Content-Security-Policy com politica restritiva", _cweId, _cweTitle, _cveVector,
                    _score));
        }

        String cspVal = getHeader(headers, "Content-Security-Policy");
        if (cspVal != null) {
            boolean scriptUnsafe = directiveHasEffectiveUnsafeInline(cspVal, "script-src", "default-src");
            boolean styleUnsafe = !scriptUnsafe
                    && directiveHasEffectiveUnsafeInline(cspVal, "style-src", "default-src");
            if (scriptUnsafe) {
                Severity scriptSev = isErrorPage ? Severity.LOW : Severity.MEDIUM;
                findings.add(Finding.of("Headers", ctx.targetUrl(),
                        "CSP script-src contem unsafe-inline sem nonce/hash", scriptSev, evidence + " | CSP: " + cspVal,
                        "unsafe-inline em script-src sem nonce/hash anula a protecao contra XSS",
                        "curl -sI " + checkedUrl + " | grep -i content-security-policy",
                        "Remover 'unsafe-inline' do script-src e usar nonces ou hashes para scripts legitimos", _cweId,
                        _cweTitle, _cveVector, _score));
            } else if (styleUnsafe) {
                boolean scriptStrict = !directiveHasEffectiveUnsafeInline(cspVal, "script-src", "default-src");
                boolean frameAncestorsNone = cspDirectiveContains(cspVal, "frame-ancestors", "'none'");
                boolean imgSrcRestricted = !directiveContainsWildcard(cspVal, "img-src", "default-src");
                boolean fullyMitigated = scriptStrict && frameAncestorsNone && imgSrcRestricted;

                Severity styleSev;
                if (isErrorPage || fullyMitigated) {
                    styleSev = Severity.INFO;
                } else {
                    styleSev = Severity.LOW;
                }
                String styleImpact = fullyMitigated
                        ? "CSS injection severamente mitigada: script-src estrito impede escalada para JS; "
                                + "frame-ancestors 'none' bloqueia clickjacking; img-src restrita limita exfiltracao"
                        : "unsafe-inline em style-src permite CSS injection"
                                + (scriptStrict ? "" : "; script-src nao e estrito -- escalada para XSS possivel")
                                + (frameAncestorsNone
                                        ? ""
                                        : "; frame-ancestors ausente/permissivo -- clickjacking via iframe")
                                + (imgSrcRestricted
                                        ? ""
                                        : "; img-src tem wildcard -- exfiltracao via background:url() possivel");
                findings.add(Finding.of("Headers", ctx.targetUrl(), "CSP style-src contem unsafe-inline sem nonce/hash",
                        styleSev, evidence + " | CSP: " + cspVal, styleImpact,
                        "curl -sI " + checkedUrl + " | grep -i content-security-policy",
                        "Remover 'unsafe-inline' do style-src e usar nonces ou hashes para estilos legitimos", _cweId,
                        _cweTitle, _cveVector, _score));
            }
        }

        if (!hasHeader(headers, "X-Frame-Options")) {
            Severity xfoSev = isErrorPage ? Severity.LOW : Severity.MEDIUM;
            String xfoImpact = "Sem X-Frame-Options, a pagina pode ser embutida em iframes -- risco de clickjacking";
            if (isErrorPage) {
                xfoImpact += " (severidade reduzida: pagina de erro tem impacto limitado de clickjacking)";
            }
            findings.add(Finding.of("Headers", ctx.targetUrl(), "X-Frame-Options ausente", xfoSev, evidence, xfoImpact,
                    "curl -sI " + checkedUrl + " | grep -i x-frame-options",
                    "Adicionar: X-Frame-Options: DENY (ou SAMEORIGIN se necessario)", _cweId, _cweTitle, _cveVector,
                    _score));
        }

        if (!hasHeader(headers, "X-Content-Type-Options")) {
            Severity xctoSev = isErrorPage ? Severity.INFO : Severity.LOW;
            String xctoImpact = "Sem X-Content-Type-Options, o browser pode interpretar erroneamente o MIME type";
            if (isErrorPage) {
                xctoImpact += " (severidade reduzida: pagina de erro tem impacto limitado)";
            }
            findings.add(Finding.of("Headers", ctx.targetUrl(), "X-Content-Type-Options ausente", xctoSev, evidence,
                    xctoImpact, "curl -sI " + checkedUrl + " | grep -i x-content-type-options",
                    "Adicionar: X-Content-Type-Options: nosniff", _cweId, _cweTitle, _cveVector, _score));
        }

        if (!hasHeader(headers, "Referrer-Policy")) {
            findings.add(Finding.of("Headers", ctx.targetUrl(), "Referrer-Policy ausente", Severity.INFO, evidence,
                    "Sem Referrer-Policy, a URL completa pode ser enviada em requisicoes cross-origin",
                    "curl -sI " + checkedUrl + " | grep -i referrer-policy",
                    "Adicionar: Referrer-Policy: strict-origin-when-cross-origin", _cweId, _cweTitle, _cveVector,
                    _score));
        }

        if (!hasHeader(headers, "Permissions-Policy")) {
            findings.add(Finding.of("Headers", ctx.targetUrl(), "Permissions-Policy ausente", Severity.INFO, evidence,
                    "Sem Permissions-Policy, features do browser (camera, microfone etc.) nao estao restritas",
                    "curl -sI " + checkedUrl + " | grep -i permissions-policy",
                    "Adicionar: Permissions-Policy: camera=(), microphone=(), geolocation=()", _cweId, _cweTitle,
                    _cveVector, _score));
        }

        String serverHeader = getHeader(headers, "Server");
        if (serverHeader != null && !isCdnOrWaf(serverHeader)) {
            if (isPaas(serverHeader)) {
                log.accept("[~] HEADERS: Server header e infraestrutura PaaS (" + serverHeader
                        + ") -- pulando finding de tech disclosure");
            } else {
                findings.add(Finding.of("Headers", ctx.targetUrl(), "Header Server expoe tecnologia: " + serverHeader,
                        Severity.INFO, evidence + " | Server: " + serverHeader,
                        "Divulgacao de versao de servidor facilita reconhecimento do atacante",
                        "curl -sI " + checkedUrl + " | grep -i '^server:'", "Remover ou ofuscar o header Server",
                        _cweId, _cweTitle, _cveVector, _score));
            }
        }

        String poweredBy = getHeader(headers, "X-Powered-By");
        if (poweredBy != null) {
            findings.add(Finding.of("Headers", ctx.targetUrl(), "X-Powered-By expoe tecnologia: " + poweredBy,
                    Severity.LOW, evidence + " | X-Powered-By: " + poweredBy,
                    "Divulgacao de stack de tecnologia facilita ataques direcionados",
                    "curl -sI " + checkedUrl + " | grep -i x-powered-by", "Remover o header X-Powered-By", _cweId,
                    _cweTitle, _cveVector, _score));
        }

        final String curlTarget = checkedUrl;
        headers.entrySet().stream().filter(e -> e.getKey() != null && e.getKey().equalsIgnoreCase("Set-Cookie"))
                .flatMap(e -> e.getValue().stream()).forEach(cookie -> {
                    String low = cookie.toLowerCase();
                    String cname = cookie.contains("=") ? cookie.substring(0, cookie.indexOf("=")).trim() : cookie;
                    if (!low.contains("secure")) {
                        findings.add(Finding.of("Headers", ctx.targetUrl(), "Cookie sem flag Secure: " + cname,
                                Severity.LOW, evidence + " | Set-Cookie: " + cookie,
                                "Cookie pode ser transmitido por HTTP -- interceptavel em rede nao cifrada",
                                "curl -sI " + curlTarget + " | grep -i 'set-cookie'",
                                "Adicionar a flag Secure em todos os cookies de sessao", _cweId, _cweTitle, _cveVector,
                                _score));
                    }
                    if (!low.contains("httponly")) {
                        findings.add(Finding.of("Headers", ctx.targetUrl(), "Cookie sem flag HttpOnly: " + cname,
                                Severity.LOW, evidence + " | Set-Cookie: " + cookie,
                                "Cookie acessivel via JavaScript -- roubo de sessao via XSS",
                                "curl -sI " + curlTarget + " | grep -i 'set-cookie'",
                                "Adicionar a flag HttpOnly em todos os cookies de sessao", _cweId, _cweTitle,
                                _cveVector, _score));
                    }
                });

        log.accept("[+] HEADERS: " + findings.size() + " finding(s) de headers");

        // --- Multi-page consistency check ---
        Set<String> allPaths = ctx.discoveredPaths().paths();
        if (!allPaths.isEmpty()) {
            log.accept("[~] HEADERS: multi-page consistency check");

            List<String> priorityKeywords = List.of("login", "account", "admin", "dashboard", "api", "payment",
                    "referral", "swap", "wallet", "settings", "profile");

            List<String> prioritized = new ArrayList<>();
            List<String> others = new ArrayList<>();
            for (String p : allPaths) {
                String lower = p.toLowerCase(Locale.ROOT);
                boolean isPriority = priorityKeywords.stream().anyMatch(lower::contains);
                if (isPriority) {
                    prioritized.add(p);
                } else {
                    others.add(p);
                }
            }

            List<String> pagesToCheck = new ArrayList<>();
            pagesToCheck.addAll(prioritized);
            pagesToCheck.addAll(others);
            if (pagesToCheck.size() > 15) {
                pagesToCheck = pagesToCheck.subList(0, 15);
            }
            pagesToCheck.add("/anarcry-header-probe-404");

            String[] criticalHeaders = {"Content-Security-Policy", "X-Frame-Options", "X-Content-Type-Options"};
            Map<String, Map<String, Boolean>> pageHeaders = new LinkedHashMap<>();

            Map<String, Boolean> rootResult = new HashMap<>();
            for (String hdr : criticalHeaders) {
                rootResult.put(hdr, hasHeader(headers, hdr));
            }
            pageHeaders.put("/", rootResult);

            String baseUrl = ctx.targetUrl();
            if (baseUrl.endsWith("/")) {
                baseUrl = baseUrl.substring(0, baseUrl.length() - 1);
            }

            for (String path : pagesToCheck) {
                String fullUrl = baseUrl + (path.startsWith("/") ? path : "/" + path);
                try {
                    Thread.sleep(100);
                    HttpRequest pageReq = HttpRequest.newBuilder().uri(URI.create(fullUrl))
                            .timeout(Duration.ofSeconds(10))
                            .header("User-Agent", gg.effront.anarcry.Version.userAgent()).GET().build();
                    HttpResponse<String> pageResp = Http.send(ctx, hc, pageReq, HttpResponse.BodyHandlers.ofString(),
                            id());
                    int pageCode = pageResp.statusCode();

                    if (pageCode == 403) {
                        String body = pageResp.body();
                        if (body != null && (body.contains("challenge-platform")
                                || body.contains("cf-browser-verification") || body.contains("Just a moment"))) {
                            continue;
                        }
                    }

                    Map<String, List<String>> pageHdrs = pageResp.headers().map();
                    Map<String, Boolean> result = new HashMap<>();
                    for (String hdr : criticalHeaders) {
                        result.put(hdr, hasHeader(pageHdrs, hdr));
                    }
                    pageHeaders.put(path, result);
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                    break;
                } catch (Exception e) {
                    // Skip pages that fail (timeout, connection error, circuit breaker, etc.)
                }
            }

            if (pageHeaders.size() > 1) {
                for (String hdr : criticalHeaders) {
                    List<String> presentOn = new ArrayList<>();
                    List<String> absentOn = new ArrayList<>();
                    for (var entry : pageHeaders.entrySet()) {
                        if (Boolean.TRUE.equals(entry.getValue().get(hdr))) {
                            presentOn.add(entry.getKey());
                        } else {
                            absentOn.add(entry.getKey());
                        }
                    }

                    if (!presentOn.isEmpty() && !absentOn.isEmpty()) {
                        String consistencyEvidence = "Present on: " + presentOn + ". Absent on: " + absentOn + ". "
                                + presentOn.size() + " of " + pageHeaders.size() + " pages protected.";
                        String reproUrl = absentOn.get(0).equals("/")
                                ? ctx.targetUrl()
                                : baseUrl + (absentOn.get(0).startsWith("/") ? absentOn.get(0) : "/" + absentOn.get(0));
                        findings.add(Finding.of("Headers", ctx.targetUrl(), "Inconsistent " + hdr + " across routes",
                                Severity.MEDIUM, consistencyEvidence,
                                "Inconsistent security header deployment suggests route-level misconfiguration."
                                        + " Unprotected pages remain vulnerable.",
                                "curl -sI " + ctx.targetUrl() + " && curl -sI " + reproUrl,
                                "Apply " + hdr + " uniformly via server-level configuration"
                                        + " (e.g., vercel.json headers, nuxt.config.ts routeRules,"
                                        + " nginx location blocks)"));
                    }
                }
            }

            log.accept("[+] HEADERS: multi-page check done -- " + pageHeaders.size() + " pages scanned");
        }

        return findings;
    }

    private boolean hasHeader(Map<String, List<String>> headers, String name) {
        return headers.keySet().stream().anyMatch(k -> k != null && k.equalsIgnoreCase(name));
    }

    private String getHeader(Map<String, List<String>> headers, String name) {
        return headers.entrySet().stream().filter(e -> e.getKey() != null && e.getKey().equalsIgnoreCase(name))
                .map(e -> e.getValue().isEmpty() ? null : e.getValue().get(0)).findFirst().orElse(null);
    }

    private static boolean isCdnOrWaf(String serverValue) {
        String low = serverValue.toLowerCase(Locale.ROOT);
        return CDN_WAF_NAMES.stream().anyMatch(low::contains);
    }

    private static boolean isPaas(String serverValue) {
        String low = serverValue.toLowerCase(Locale.ROOT);
        return PAAS_NAMES.stream().anyMatch(low::contains);
    }

    private static boolean directiveHasEffectiveUnsafeInline(String csp, String... candidates) {
        for (String candidate : candidates) {
            String matched = null;
            for (String directive : csp.split(";")) {
                String d = directive.trim().toLowerCase();
                if (d.startsWith(candidate)) {
                    matched = d;
                    break;
                }
            }
            if (matched != null) {
                if (!matched.contains("unsafe-inline")) {
                    return false;
                }
                boolean neutralized = matched.contains("'nonce-") || matched.contains("'sha256-")
                        || matched.contains("'sha384-") || matched.contains("'sha512-");
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
            String matched = null;
            for (String part : csp.split(";")) {
                String d = part.trim().toLowerCase();
                if (d.startsWith(candidate.toLowerCase())) {
                    matched = d;
                    break;
                }
            }
            if (matched != null) {
                for (String token : matched.split("\\s+")) {
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
