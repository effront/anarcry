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

    @Override
    public String id() {
        return "CspApiDiscovery";
    }

    @Override
    public List<Finding> scan(ScanContext ctx, Consumer<String> log) throws Exception {
        List<Finding> findings = new ArrayList<>();
        HttpClient hc = HttpClientFactory.http2();

        String scheme = ctx.isHttps() ? "https" : "http";
        int defPort = ctx.isHttps() ? 443 : 80;
        String base = scheme + "://" + ctx.host() + (ctx.port() != defPort ? ":" + ctx.port() : "");

        log.accept("[~] CspApiDiscovery: analisando CSP headers em " + base);

        // Fetch the main page to get CSP headers
        String cspHeader = null;
        try {
            HttpRequest.Builder builder = HttpRequest.newBuilder().uri(URI.create(base + "/"))
                    .timeout(Duration.ofSeconds(6)).GET();
            if (!ctx.jwtToken().isBlank()) {
                builder.header("Authorization", "Bearer " + ctx.jwtToken());
            }
            HttpRequest req = builder.build();
            HttpResponse<String> resp = Http.send(ctx, hc, req, HttpResponse.BodyHandlers.ofString(), id());

            cspHeader = resp.headers().firstValue("content-security-policy").orElse("");
            if (cspHeader.isBlank()) {
                cspHeader = resp.headers().firstValue("content-security-policy-report-only").orElse("");
            }

            // Also check meta tag in HTML
            if (cspHeader.isBlank()) {
                String body = resp.body() != null ? resp.body() : "";
                Pattern metaCsp = Pattern.compile(
                        "<meta[^>]+http-equiv=[\"']Content-Security-Policy[\"'][^>]+content=[\"']([^\"']+)[\"']",
                        Pattern.CASE_INSENSITIVE);
                Matcher metaMatcher = metaCsp.matcher(body);
                if (metaMatcher.find()) {
                    cspHeader = metaMatcher.group(1);
                    log.accept("[~] CspApiDiscovery: CSP encontrado via meta tag");
                }
            }
        } catch (CircuitBreakerException cbe) {
            throw cbe;
        } catch (Exception e) {
            log.accept("[!] CspApiDiscovery: falha ao buscar CSP: " + e.getMessage());
            return findings;
        }

        if (cspHeader.isBlank()) {
            log.accept("[~] CspApiDiscovery: nenhum CSP header encontrado");
            return findings;
        }

        log.accept("[~] CspApiDiscovery: CSP encontrado (" + cspHeader.length() + " chars)");

        // Parse all directives
        Set<String> discoveredUrls = new LinkedHashSet<>();
        Set<String> discoveredDomains = new LinkedHashSet<>();
        Set<String> internalApis = new LinkedHashSet<>();
        Set<String> apiEndpoints = new LinkedHashSet<>();

        Matcher dirMatcher = CSP_DIRECTIVE.matcher(cspHeader);
        while (dirMatcher.find()) {
            String directive = dirMatcher.group(1);
            String values = dirMatcher.group(2);

            // Extract full URLs
            Matcher urlMatcher = URL_PATTERN.matcher(values);
            while (urlMatcher.find()) {
                String url = urlMatcher.group();
                discoveredUrls.add(url);

                // Classify as API endpoint (connect-src is most indicative)
                if ("connect-src".equals(directive)) {
                    apiEndpoints.add(url);
                }

                // Check for internal indicators
                String urlLower = url.toLowerCase();
                for (String indicator : INTERNAL_INDICATORS) {
                    if (urlLower.contains(indicator)) {
                        internalApis.add(url);
                        break;
                    }
                }
            }

            // Extract domains
            Matcher domMatcher = DOMAIN_PATTERN.matcher(values);
            while (domMatcher.find()) {
                String domain = domMatcher.group(1);
                if (!KNOWN_CDN_DOMAINS.contains(domain.toLowerCase())) {
                    discoveredDomains.add(domain);
                }
            }
        }

        if (discoveredUrls.isEmpty() && discoveredDomains.isEmpty()) {
            log.accept("[+] CspApiDiscovery: CSP presente mas sem URLs/dominios relevantes");
            return findings;
        }

        log.accept("[~] CspApiDiscovery: " + discoveredUrls.size() + " URLs, " + discoveredDomains.size()
                + " dominios, " + apiEndpoints.size() + " connect-src endpoints");

        // Report API surface discovery (INFO)
        if (!apiEndpoints.isEmpty() || !discoveredDomains.isEmpty()) {
            StringBuilder evidence = new StringBuilder("CSP header analise:");
            if (!apiEndpoints.isEmpty()) {
                evidence.append(" | connect-src APIs: ").append(String.join(", ", limitSet(apiEndpoints, 10)));
            }
            if (!discoveredDomains.isEmpty()) {
                evidence.append(" | Dominios: ").append(String.join(", ", limitSet(discoveredDomains, 10)));
            }
            evidence.append(" | Total URLs: ").append(discoveredUrls.size());

            findings.add(Finding.of(id(), "/",
                    "CSP API Surface Discovery -- "
                            + apiEndpoints.size() + " API endpoints, " + discoveredDomains.size() + " dominios",
                    Severity.INFO, evidence.toString(),
                    "CSP header revela a superficie de API do aplicativo, incluindo endpoints "
                            + "de backend, servicos terceiros e dominios permitidos. "
                            + "Informacao util para reconhecimento e mapeamento de ataque",
                    "curl -sI '" + base + "/' | grep -i content-security-policy",
                    "Minimizar dominios no CSP para reduzir superficie exposta. "
                            + "Usar nonces em vez de domain allowlists quando possivel. "
                            + "Revisar periodicamente dominios no CSP para remover entradas obsoletas",
                    CWE_ID, CWE_TITLE, CVSS_INFO, SCORE_INFO));
        }

        // Probe internal APIs for accessibility (MEDIUM if reachable)
        if (!internalApis.isEmpty()) {
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
                        log.accept("[!] CspApiDiscovery: API interna acessivel: " + internalUrl + " (HTTP " + status
                                + ")");
                        findings.add(Finding.of(id(), internalUrl,
                                "Internal API acessivel externamente: " + internalUrl, Severity.MEDIUM,
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

        // Probe connect-src API endpoints for open access
        Set<String> nonInternalApis = new LinkedHashSet<>(apiEndpoints);
        nonInternalApis.removeAll(internalApis);
        if (!nonInternalApis.isEmpty()) {
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

        if (findings.isEmpty()) {
            log.accept("[+] CspApiDiscovery: nenhuma API exposta detectada via CSP");
        }
        return findings;
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
