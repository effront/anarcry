package gg.effront.anarcry.scanner.web.clerk;

import gg.effront.anarcry.model.CvssCalculator;
import gg.effront.anarcry.model.Finding;
import gg.effront.anarcry.model.Severity;
import gg.effront.anarcry.scanner.ScanContext;
import gg.effront.anarcry.scanner.Scanner;
import gg.effront.anarcry.scanner.util.CircuitBreakerException;
import gg.effront.anarcry.scanner.util.Http;
import gg.effront.anarcry.scanner.util.HttpClientFactory;
import gg.effront.anarcry.scanner.util.JsBundleDiscovery;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.function.Consumer;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Detects Clerk authentication provider misconfigurations: development keys in
 * production, environment config disclosure via /v1/environment, user
 * enumeration via sign-in endpoint, and outdated Clerk JS versions with known
 * vulnerabilities.
 */
public class ClerkModule implements Scanner {

    private static final String CWE_ID = "CWE-200";
    private static final String CWE_TITLE = "Exposure of Sensitive Information to an Unauthorized Actor";
    private static final String CVSS_DEV_KEY = "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N";
    private static final String CVSS_CONFIG = "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N";
    private static final String CVSS_ENUM = "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N";
    private static final String CVSS_VERSION = "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N";

    // Clerk publishable test/dev key pattern
    private static final Pattern PK_TEST = Pattern.compile("(pk_test_[A-Za-z0-9+/=]{10,})");

    // Clerk JS version detection -- matches @clerk/clerk-js@X.Y.Z or clerkjs/X.Y.Z
    private static final Pattern CLERK_VERSION = Pattern
            .compile("(?:@clerk/clerk-js@|clerkjs/)(\\d+)\\.(\\d+)(?:\\.(\\d+))?");

    private static final Duration TIMEOUT = Duration.ofSeconds(6);

    @Override
    public String id() {
        return "Clerk";
    }

    @Override
    public List<Finding> scan(ScanContext ctx, Consumer<String> log) throws Exception {
        List<Finding> findings = new ArrayList<>();
        HttpClient hc = HttpClientFactory.http2();

        String scheme = ctx.isHttps() ? "https" : "http";
        int defPort = ctx.isHttps() ? 443 : 80;
        String baseUrl = scheme + "://" + ctx.host() + (ctx.port() != defPort ? ":" + ctx.port() : "");

        log.accept("[~] Clerk: iniciando verificacao em " + baseUrl);

        // Discover JS bundles from crawled pages
        Set<String> jsUrls = JsBundleDiscovery.discover(ctx, hc, baseUrl, log);

        // Also collect JS paths from discoveredPaths
        Set<String> jsPaths = new LinkedHashSet<>();
        for (String path : ctx.discoveredPaths().paths()) {
            if (path.endsWith(".js") || path.contains(".js?")) {
                jsPaths.add(path.startsWith("http") ? path : baseUrl + path);
            }
        }
        jsUrls.addAll(jsPaths);

        // Check 1: Dev key in production
        String foundDevKey = checkDevKeyInProduction(ctx, hc, baseUrl, jsUrls, findings, log);

        // Check 2: Environment config disclosure
        checkEnvironmentDisclosure(ctx, hc, baseUrl, foundDevKey, findings, log);

        // Check 3: User enumeration via sign-in
        checkUserEnumeration(ctx, hc, baseUrl, findings, log);

        // Check 4: Clerk JS version
        checkClerkVersion(ctx, hc, jsUrls, findings, log);

        if (findings.isEmpty()) {
            log.accept("[+] Clerk: nenhuma misconfiguracao detectada");
        }
        return findings;
    }

    /**
     * Check 1: Scan base URL and JS bundles for pk_test_ keys (development keys in
     * production). Returns the first dev key found (or null) so it can be used in
     * check 2.
     */
    private String checkDevKeyInProduction(ScanContext ctx, HttpClient hc, String baseUrl, Set<String> jsUrls,
            List<Finding> findings, Consumer<String> log) {

        log.accept("[~] Clerk: verificando dev key em paginas e bundles JS");

        // URLs to scan for dev keys: base page + all discovered JS bundles
        Set<String> urlsToScan = new LinkedHashSet<>();
        urlsToScan.add(baseUrl + "/");
        urlsToScan.addAll(jsUrls);

        for (String url : urlsToScan) {
            try {
                HttpRequest req = HttpRequest.newBuilder().uri(URI.create(url)).timeout(TIMEOUT).GET().build();
                HttpResponse<String> resp = Http.send(ctx, hc, req, HttpResponse.BodyHandlers.ofString(), id());

                if (resp.statusCode() >= 400) {
                    continue;
                }

                String body = resp.body();
                if (body == null || body.isBlank()) {
                    continue;
                }

                Matcher m = PK_TEST.matcher(body);
                if (m.find()) {
                    String devKey = m.group(1);
                    // Truncate key for evidence display
                    String keyPreview = devKey.length() > 30 ? devKey.substring(0, 30) + "..." : devKey;

                    log.accept("[!!] Clerk: HIGH -- dev key (pk_test_) encontrada em " + url);
                    findings.add(Finding.of(id(), url, "Clerk Development Key in Production", Severity.HIGH,
                            "URL: " + url + " | Key: " + keyPreview + " | Production keys should start with pk_live_",
                            "Clerk development key (pk_test_) exposta em producao -- atacante pode usar"
                                    + " a chave para interagir com a API Clerk do ambiente de desenvolvimento,"
                                    + " potencialmente acessando dados de teste ou configuracoes inseguras",
                            "curl -s '" + url + "' | grep -oP 'pk_test_[A-Za-z0-9+/=]+'",
                            "Substituir pk_test_ por pk_live_ em producao; usar variaveis de ambiente"
                                    + " para separar chaves de dev e prod; verificar que build de producao"
                                    + " nao inclui .env de desenvolvimento",
                            CWE_ID, CWE_TITLE, CVSS_DEV_KEY, CvssCalculator.calculate(CVSS_DEV_KEY)));
                    return devKey;
                }
            } catch (CircuitBreakerException cbe) {
                throw cbe;
            } catch (Exception ignored) {
                // Connection errors expected for some JS URLs
            }
        }

        log.accept("[~] Clerk: nenhuma dev key encontrada");
        return null;
    }

    /**
     * Check 2: Probe /v1/environment for config disclosure. Tries with discovered
     * dev key (if any) and without auth.
     */
    private void checkEnvironmentDisclosure(ScanContext ctx, HttpClient hc, String baseUrl, String devKey,
            List<Finding> findings, Consumer<String> log) {

        log.accept("[~] Clerk: verificando /v1/environment config disclosure");

        String envUrl = baseUrl + "/v1/environment";

        // Build probe variants: with dev key auth (if found) and without auth
        Set<HttpRequest> probes = new HashSet<>();
        probes.add(HttpRequest.newBuilder().uri(URI.create(envUrl)).timeout(TIMEOUT).GET().build());

        if (devKey != null) {
            probes.add(HttpRequest.newBuilder().uri(URI.create(envUrl)).header("Authorization", "Bearer " + devKey)
                    .timeout(TIMEOUT).GET().build());
        }

        for (HttpRequest probe : probes) {
            try {
                HttpResponse<String> resp = Http.send(ctx, hc, probe, HttpResponse.BodyHandlers.ofString(), id());

                if (resp.statusCode() != 200) {
                    continue;
                }

                String body = resp.body();
                if (body == null || body.isBlank()) {
                    continue;
                }

                boolean hasAuthConfig = body.contains("\"auth_config\"");
                boolean hasDisplayConfig = body.contains("\"display_config\"");

                if (hasAuthConfig || hasDisplayConfig) {
                    List<String> exposedFields = new ArrayList<>();
                    if (hasAuthConfig) {
                        exposedFields.add("auth_config");
                    }
                    if (hasDisplayConfig) {
                        exposedFields.add("display_config");
                    }
                    if (body.contains("\"user_settings\"")) {
                        exposedFields.add("user_settings");
                    }
                    if (body.contains("\"organization_settings\"")) {
                        exposedFields.add("organization_settings");
                    }

                    boolean usedAuth = probe.headers().firstValue("Authorization").isPresent();
                    String authNote = usedAuth ? " (com dev key)" : " (sem autenticacao)";

                    log.accept("[!] Clerk: MEDIUM -- /v1/environment exposto" + authNote);
                    findings.add(Finding.of(id(), "/v1/environment", "Clerk Environment Config Disclosure",
                            Severity.MEDIUM,
                            "URL: " + envUrl + authNote + " | Exposed fields: " + String.join(", ", exposedFields),
                            "Configuracao do ambiente Clerk exposta -- revela auth providers habilitados,"
                                    + " configuracoes de MFA, URLs de callback e detalhes de identidade"
                                    + " visual que facilitam engenharia social e ataques direcionados",
                            "curl -s '" + envUrl + "'" + (usedAuth ? " -H 'Authorization: Bearer <pk_test_key>'" : "")
                                    + " | jq .",
                            "Restringir acesso ao endpoint /v1/environment em producao;"
                                    + " usar middleware ou WAF rules para bloquear acesso externo"
                                    + " a endpoints internos da API Clerk",
                            CWE_ID, CWE_TITLE, CVSS_CONFIG, CvssCalculator.calculate(CVSS_CONFIG)));
                    return; // One finding is enough for this check
                }
            } catch (CircuitBreakerException cbe) {
                throw cbe;
            } catch (Exception ignored) {
                // Expected for targets not running Clerk
            }
        }

        log.accept("[~] Clerk: /v1/environment nao exposto");
    }

    /**
     * Check 3: User enumeration via differential responses to /v1/client/sign_ins.
     * Compares response for a non-existent user vs a likely-existing admin user.
     */
    private void checkUserEnumeration(ScanContext ctx, HttpClient hc, String baseUrl, List<Finding> findings,
            Consumer<String> log) {

        log.accept("[~] Clerk: verificando user enumeration via sign-in");

        String signInUrl = baseUrl + "/v1/client/sign_ins";
        String domain = ctx.host();

        // Probe 1: definitely non-existent user
        String fakePayload = "{\"identifier\":\"definitely-not-a-user@example.com\"}";
        // Probe 2: likely-existing admin user at target domain
        String adminPayload = "{\"identifier\":\"admin@" + domain + "\"}";

        try {
            HttpRequest fakeReq = HttpRequest.newBuilder().uri(URI.create(signInUrl))
                    .header("Content-Type", "application/json").timeout(TIMEOUT)
                    .POST(HttpRequest.BodyPublishers.ofString(fakePayload)).build();
            HttpResponse<String> fakeResp = Http.send(ctx, hc, fakeReq, HttpResponse.BodyHandlers.ofString(), id());

            HttpRequest adminReq = HttpRequest.newBuilder().uri(URI.create(signInUrl))
                    .header("Content-Type", "application/json").timeout(TIMEOUT)
                    .POST(HttpRequest.BodyPublishers.ofString(adminPayload)).build();
            HttpResponse<String> adminResp = Http.send(ctx, hc, adminReq, HttpResponse.BodyHandlers.ofString(), id());

            int fakeStatus = fakeResp.statusCode();
            int adminStatus = adminResp.statusCode();
            String fakeBody = fakeResp.body() != null ? fakeResp.body() : "";
            String adminBody = adminResp.body() != null ? adminResp.body() : "";

            // Skip if both returned non-API responses (likely not a Clerk backend)
            if (fakeStatus == 404 && adminStatus == 404) {
                log.accept("[~] Clerk: /v1/client/sign_ins nao encontrado -- nao e Clerk backend");
                return;
            }

            boolean statusDiffer = fakeStatus != adminStatus;
            boolean errorMsgDiffer = hasDistinctErrorMessages(fakeBody, adminBody);

            if (statusDiffer || errorMsgDiffer) {
                String evidence = "URL: " + signInUrl + " | Fake user status: " + fakeStatus + " | Admin user status: "
                        + adminStatus;
                if (statusDiffer) {
                    evidence += " | Status codes differ";
                }
                if (errorMsgDiffer) {
                    evidence += " | Error messages differ";
                }

                log.accept("[!] Clerk: MEDIUM -- user enumeration detectada via /v1/client/sign_ins");
                findings.add(Finding.of(id(), "/v1/client/sign_ins", "Clerk User Enumeration via Sign-In",
                        Severity.MEDIUM, evidence,
                        "Sign-in endpoint retorna respostas diferentes para usuarios existentes"
                                + " e inexistentes -- atacante pode enumerar contas validas e direcionar"
                                + " ataques de credential stuffing ou phishing",
                        "# Comparar respostas:\n" + "curl -s -o /dev/null -w '%{http_code}' -X POST '" + signInUrl + "'"
                                + " -H 'Content-Type: application/json'"
                                + " -d '{\"identifier\":\"fake@example.com\"}'\n"
                                + "curl -s -o /dev/null -w '%{http_code}' -X POST '" + signInUrl + "'"
                                + " -H 'Content-Type: application/json'" + " -d '{\"identifier\":\"admin@" + domain
                                + "\"}'",
                        "Configurar Clerk para retornar respostas genericas em caso de erro;"
                                + " habilitar rate limiting no sign-in endpoint;"
                                + " considerar CAPTCHA apos tentativas falhas",
                        CWE_ID, CWE_TITLE, CVSS_ENUM, CvssCalculator.calculate(CVSS_ENUM)));
            } else {
                log.accept("[~] Clerk: respostas consistentes -- sem user enumeration detectada");
            }
        } catch (CircuitBreakerException cbe) {
            throw cbe;
        } catch (Exception e) {
            log.accept("[~] Clerk: sign-in probe falhou -- " + e.getMessage());
        }
    }

    /**
     * Check 4: Detect outdated Clerk JS versions in discovered bundles. Versions
     * below 4.0 are flagged as potentially vulnerable.
     */
    private void checkClerkVersion(ScanContext ctx, HttpClient hc, Set<String> jsUrls, List<Finding> findings,
            Consumer<String> log) {

        log.accept("[~] Clerk: verificando versao do Clerk JS em bundles");

        for (String url : jsUrls) {
            try {
                HttpRequest req = HttpRequest.newBuilder().uri(URI.create(url)).timeout(TIMEOUT).GET().build();
                HttpResponse<String> resp = Http.send(ctx, hc, req, HttpResponse.BodyHandlers.ofString(), id());

                if (resp.statusCode() >= 400) {
                    continue;
                }

                String body = resp.body();
                if (body == null || body.isBlank()) {
                    continue;
                }

                Matcher m = CLERK_VERSION.matcher(body);
                if (m.find()) {
                    int major = Integer.parseInt(m.group(1));
                    int minor = Integer.parseInt(m.group(2));
                    String patch = m.group(3);
                    String version = major + "." + minor + (patch != null ? "." + patch : "");

                    if (major < 4) {
                        log.accept("[~] Clerk: INFO -- versao antiga detectada: " + version);
                        findings.add(Finding.of(id(), url, "Clerk JS Outdated Version (" + version + ")", Severity.INFO,
                                "URL: " + url + " | Clerk JS version: " + version
                                        + " | Versions < 4.0 may contain known vulnerabilities",
                                "Versao antiga do Clerk JS detectada -- versoes anteriores a 4.0"
                                        + " podem conter vulnerabilidades conhecidas incluindo XSS"
                                        + " e bypass de autenticacao",
                                "curl -s '" + url + "' | grep -oP '@clerk/clerk-js@[0-9.]+'",
                                "Atualizar @clerk/clerk-js para a versao mais recente (>= 4.0);"
                                        + " verificar changelog do Clerk para security advisories",
                                CWE_ID, CWE_TITLE, CVSS_VERSION, CvssCalculator.calculate(CVSS_VERSION)));
                        return; // One version finding is sufficient
                    }

                    log.accept("[~] Clerk: versao " + version + " detectada (atual)");
                    return;
                }
            } catch (CircuitBreakerException cbe) {
                throw cbe;
            } catch (Exception ignored) {
                // Expected for unreachable URLs
            }
        }

        log.accept("[~] Clerk: nenhuma versao de Clerk JS detectada em bundles");
    }

    /**
     * Compares two error response bodies for signs of user enumeration. Returns
     * true if the responses contain distinct error indicators -- e.g., one says
     * "not found" while the other says "wrong password" or "needs verification".
     */
    private static boolean hasDistinctErrorMessages(String body1, String body2) {
        if (body1.isBlank() || body2.isBlank()) {
            return false;
        }

        // Clerk error patterns that distinguish existing vs non-existing users
        String[] notFoundPatterns = {"not found", "couldn't find", "no account", "identifier_not_found"};
        String[] existsPatterns = {"wrong password", "incorrect password", "needs_identifier", "needs_first_factor",
                "needs_second_factor", "strategy_for_user"};

        boolean body1NotFound = containsAny(body1, notFoundPatterns);
        boolean body2NotFound = containsAny(body2, notFoundPatterns);
        boolean body1Exists = containsAny(body1, existsPatterns);
        boolean body2Exists = containsAny(body2, existsPatterns);

        // User enumeration: one response says "not found", the other implies user
        // exists
        return (body1NotFound && body2Exists) || (body2NotFound && body1Exists);
    }

    private static boolean containsAny(String body, String[] patterns) {
        String lower = body.toLowerCase();
        for (String p : patterns) {
            if (lower.contains(p.toLowerCase())) {
                return true;
            }
        }
        return false;
    }
}
