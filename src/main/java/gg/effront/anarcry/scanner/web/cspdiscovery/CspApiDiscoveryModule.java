package gg.effront.anarcry.scanner.web.cspdiscovery;

import gg.effront.anarcry.model.CvssCalculator;
import gg.effront.anarcry.model.Finding;
import gg.effront.anarcry.model.Severity;
import gg.effront.anarcry.scanner.ScanContext;
import gg.effront.anarcry.scanner.Scanner;
import gg.effront.anarcry.scanner.util.CircuitBreakerException;
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
import java.util.Set;
import java.util.function.Consumer;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class CspApiDiscoveryModule implements Scanner {

    private static final String CWE_ID = "CWE-200";
    private static final String CWE_TITLE = "Exposure of Sensitive Information";

    private static final String CVSS_INFO = "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N";
    private static final double SCORE_INFO = 0.0;

    private static final String CVSS_MEDIUM = "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N";
    private static final double SCORE_MEDIUM = CvssCalculator.calculate(CVSS_MEDIUM);

    private static final Pattern CSP_DIRECTIVE = Pattern
            .compile("((?:connect|script|img|font|style|media|frame|worker|default)-src)\\s+([^;]+)");
    private static final Pattern URL_PATTERN = Pattern.compile("https?://[\\w.\\-:]+(?:/[\\w.\\-/]*)?");
    private static final Pattern DOMAIN_PATTERN = Pattern.compile("(?:\\*\\.)?([\\w.\\-]+\\.[a-zA-Z]{2,})");

    private static final Set<String> INTERNAL_INDICATORS = Set.of("internal", "staging", "dev", "test", "local",
            "admin", "debug", "private", "corp", "intranet", "api-internal", "graphql-internal", "backend");

    private static final Set<String> KNOWN_CDN_DOMAINS = Set.of("cdn.jsdelivr.net", "cdnjs.cloudflare.com", "unpkg.com",
            "fonts.googleapis.com", "fonts.gstatic.com", "ajax.googleapis.com", "maxcdn.bootstrapcdn.com",
            "stackpath.bootstrapcdn.com", "code.jquery.com", "www.google-analytics.com", "www.googletagmanager.com",
            "connect.facebook.net", "platform.twitter.com", "cdn.segment.com");

    private record CspParseResult(Set<String> discoveredUrls, Set<String> discoveredDomains, Set<String> internalApis,
            Set<String> apiEndpoints) {
    }

    @Override
    public String id() {
        return "CspApiDiscovery";
    }

    @Override
    public List<Finding> scan(ScanContext ctx, Consumer<String> log) throws Exception {
        List<Finding> findings = new ArrayList<>();
        HttpClient hc = HttpClientFactory.http2();
        String base = ctx.baseUrl();

        log.accept("[~] CspApiDiscovery: analisando CSP headers em " + base);

        String cspHeader = fetchCspHeader(ctx, hc, base, log);
        if (cspHeader.isBlank()) {
            log.accept("[~] CspApiDiscovery: nenhum CSP header encontrado");
            return findings;
        }

        log.accept("[~] CspApiDiscovery: CSP encontrado (" + cspHeader.length() + " chars)");

        CspParseResult parsed = parseCspDirectives(cspHeader);
        if (parsed.discoveredUrls().isEmpty() && parsed.discoveredDomains().isEmpty()) {
            log.accept("[+] CspApiDiscovery: CSP presente mas sem URLs/dominios relevantes");
            return findings;
        }

        log.accept(
                "[~] CspApiDiscovery: " + parsed.discoveredUrls().size() + " URLs, " + parsed.discoveredDomains().size()
                        + " dominios, " + parsed.apiEndpoints().size() + " connect-src endpoints");

        buildApiSurfaceFinding(parsed, base, findings);
        probeInternalApis(ctx, hc, parsed.internalApis(), findings, log);
        probeConnectSrcApis(ctx, hc, parsed, log);

        if (findings.isEmpty()) {
            log.accept("[+] CspApiDiscovery: nenhuma API exposta detectada via CSP");
        }
        return findings;
    }

    private String fetchCspHeader(ScanContext ctx, HttpClient hc, String base, Consumer<String> log) {
        try {
            HttpRequest.Builder builder = HttpRequest.newBuilder().uri(URI.create(base + "/"))
                    .timeout(Duration.ofSeconds(6)).GET();
            if (!ctx.jwtToken().isBlank()) {
                builder.header("Authorization", "Bearer " + ctx.jwtToken());
            }
            HttpRequest req = builder.build();
            HttpResponse<String> resp = Http.send(ctx, hc, req, HttpResponse.BodyHandlers.ofString(), id());

            String csp = resp.headers().firstValue("content-security-policy").orElse("");
            if (csp.isBlank()) {
                csp = resp.headers().firstValue("content-security-policy-report-only").orElse("");
            }
            if (csp.isBlank()) {
                csp = extractCspFromMetaTag(resp.body());
                if (!csp.isBlank()) {
                    log.accept("[~] CspApiDiscovery: CSP encontrado via meta tag");
                }
            }
            return csp;
        } catch (CircuitBreakerException cbe) {
            throw cbe;
        } catch (Exception e) {
            log.accept("[!] CspApiDiscovery: falha ao buscar CSP: " + e.getMessage());
            return "";
        }
    }

    private static String extractCspFromMetaTag(String body) {
        if (body == null) {
            return "";
        }
        Pattern metaCsp = Pattern.compile(
                "<meta[^>]+http-equiv=[\"']Content-Security-Policy[\"'][^>]+content=[\"']([^\"']+)[\"']",
                Pattern.CASE_INSENSITIVE);
        Matcher m = metaCsp.matcher(body);
        return m.find() ? m.group(1) : "";
    }

    private static CspParseResult parseCspDirectives(String cspHeader) {
        Set<String> discoveredUrls = new LinkedHashSet<>();
        Set<String> discoveredDomains = new LinkedHashSet<>();
        Set<String> internalApis = new LinkedHashSet<>();
        Set<String> apiEndpoints = new LinkedHashSet<>();

        Matcher dirMatcher = CSP_DIRECTIVE.matcher(cspHeader);
        while (dirMatcher.find()) {
            String directive = dirMatcher.group(1);
            String values = dirMatcher.group(2);
            extractUrlsFromDirective(directive, values, discoveredUrls, apiEndpoints, internalApis);
            extractDomainsFromValues(values, discoveredDomains);
        }

        return new CspParseResult(discoveredUrls, discoveredDomains, internalApis, apiEndpoints);
    }

    private static void extractUrlsFromDirective(String directive, String values, Set<String> discoveredUrls,
            Set<String> apiEndpoints, Set<String> internalApis) {
        Matcher urlMatcher = URL_PATTERN.matcher(values);
        while (urlMatcher.find()) {
            String url = urlMatcher.group();
            discoveredUrls.add(url);
            if ("connect-src".equals(directive)) {
                apiEndpoints.add(url);
            }
            classifyInternalUrl(url, internalApis);
        }
    }

    private static void classifyInternalUrl(String url, Set<String> internalApis) {
        String urlLower = url.toLowerCase();
        for (String indicator : INTERNAL_INDICATORS) {
            if (urlLower.contains(indicator)) {
                internalApis.add(url);
                break;
            }
        }
    }

    private static void extractDomainsFromValues(String values, Set<String> discoveredDomains) {
        Matcher domMatcher = DOMAIN_PATTERN.matcher(values);
        while (domMatcher.find()) {
            String domain = domMatcher.group(1);
            if (!KNOWN_CDN_DOMAINS.contains(domain.toLowerCase())) {
                discoveredDomains.add(domain);
            }
        }
    }

    private void buildApiSurfaceFinding(CspParseResult parsed, String base, List<Finding> findings) {
        if (parsed.apiEndpoints().isEmpty() && parsed.discoveredDomains().isEmpty()) {
            return;
        }
        StringBuilder evidence = new StringBuilder("CSP header analise:");
        if (!parsed.apiEndpoints().isEmpty()) {
            evidence.append(" | connect-src APIs: ").append(String.join(", ", limitSet(parsed.apiEndpoints(), 10)));
        }
        if (!parsed.discoveredDomains().isEmpty()) {
            evidence.append(" | Dominios: ").append(String.join(", ", limitSet(parsed.discoveredDomains(), 10)));
        }
        evidence.append(" | Total URLs: ").append(parsed.discoveredUrls().size());

        findings.add(Finding.of(id(), "/", "CSP API Surface Discovery -- " + parsed.apiEndpoints().size()
                + " API endpoints, " + parsed.discoveredDomains().size() + " dominios", Severity.INFO,
                evidence.toString(),
                "CSP header revela a superficie de API do aplicativo, incluindo endpoints "
                        + "de backend, servicos terceiros e dominios permitidos. "
                        + "Informacao util para reconhecimento e mapeamento de ataque",
                "curl -sI '" + base + "/' | grep -i content-security-policy",
                "Minimizar dominios no CSP para reduzir superficie exposta. "
                        + "Usar nonces em vez de domain allowlists quando possivel. "
                        + "Revisar periodicamente dominios no CSP para remover entradas obsoletas",
                CWE_ID, CWE_TITLE, CVSS_INFO, SCORE_INFO));
    }

    private void probeInternalApis(ScanContext ctx, HttpClient hc, Set<String> internalApis, List<Finding> findings,
            Consumer<String> log) {
        if (internalApis.isEmpty()) {
            return;
        }
        log.accept("[~] CspApiDiscovery: probing " + internalApis.size() + " APIs internas detectadas no CSP");
        for (String internalUrl : internalApis) {
            try {
                HttpRequest probeReq = HttpRequest.newBuilder().uri(URI.create(internalUrl))
                        .timeout(Duration.ofSeconds(5)).GET().build();
                HttpResponse<String> probeResp = Http.send(ctx, hc, probeReq, HttpResponse.BodyHandlers.ofString(),
                        id());

                int status = probeResp.statusCode();
                if (status >= 200 && status < 500 && status != 404) {
                    String body = probeResp.body() != null ? probeResp.body() : "";
                    log.accept("[!] CspApiDiscovery: API interna acessivel: " + internalUrl + " (HTTP " + status + ")");
                    findings.add(Finding.of(id(), internalUrl, "Internal API acessivel externamente: " + internalUrl,
                            Severity.MEDIUM,
                            "URL: " + internalUrl + " | Status: " + status + " | Descoberto via CSP connect-src"
                                    + " | Body preview: " + body.substring(0, Math.min(150, body.length())),
                            "API interna referenciada no CSP e acessivel externamente. "
                                    + "APIs internas geralmente nao implementam autenticacao ou autorizacao "
                                    + "completa, podendo expor dados sensiveis ou funcionalidades administrativas",
                            "curl '" + internalUrl + "'",
                            "Restringir acesso a APIs internas via firewall/VPN. "
                                    + "Nunca expor URLs internas no CSP de paginas publicas. "
                                    + "Implementar autenticacao em todas as APIs independente do ambiente",
                            CWE_ID, CWE_TITLE, CVSS_MEDIUM, SCORE_MEDIUM));
                }
            } catch (CircuitBreakerException cbe) {
                throw cbe;
            } catch (Exception ignored) {
                // Internal API not reachable -- expected
            }
        }
    }

    private void probeConnectSrcApis(ScanContext ctx, HttpClient hc, CspParseResult parsed, Consumer<String> log) {
        Set<String> nonInternalApis = new LinkedHashSet<>(parsed.apiEndpoints());
        nonInternalApis.removeAll(parsed.internalApis());
        if (nonInternalApis.isEmpty()) {
            return;
        }
        log.accept("[~] CspApiDiscovery: probing " + nonInternalApis.size() + " connect-src API endpoints");
        int probed = 0;
        for (String apiUrl : nonInternalApis) {
            if (probed >= 10) {
                break;
            }
            try {
                // Skip same-origin URLs
                URI apiUri = URI.create(apiUrl);
                if (ctx.host().equals(apiUri.getHost())) {
                    continue;
                }

                HttpRequest probeReq = HttpRequest.newBuilder().uri(apiUri).timeout(Duration.ofSeconds(5)).GET()
                        .build();
                HttpResponse<String> probeResp = Http.send(ctx, hc, probeReq, HttpResponse.BodyHandlers.ofString(),
                        id());
                probed++;

                int status = probeResp.statusCode();
                String body = probeResp.body() != null ? probeResp.body() : "";

                // If a third-party API returns JSON data without auth, it may be interesting
                if (status == 200 && body.stripLeading().startsWith("{") && body.length() > 50) {
                    log.accept("[~] CspApiDiscovery: third-party API retorna dados abertos: " + apiUrl);
                }
            } catch (CircuitBreakerException cbe) {
                throw cbe;
            } catch (Exception ignored) {
                // Third party API not reachable or timeout
            }
        }
    }

    private static Set<String> limitSet(Set<String> set, int max) {
        Set<String> limited = new LinkedHashSet<>();
        int count = 0;
        for (String s : set) {
            if (count >= max) {
                limited.add("... +" + (set.size() - max) + " more");
                break;
            }
            limited.add(s);
            count++;
        }
        return limited;
    }
}
