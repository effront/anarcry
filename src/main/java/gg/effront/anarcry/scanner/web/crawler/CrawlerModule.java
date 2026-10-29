package gg.effront.anarcry.scanner.web.crawler;

import gg.effront.anarcry.model.Finding;
import gg.effront.anarcry.model.KnowledgeBase;
import gg.effront.anarcry.model.KnowledgeEntry;
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
import java.util.Set;
import java.util.function.Consumer;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class CrawlerModule implements Scanner {

    @Override
    public String id() {
        return "Crawler";
    }

    // Wordlist de 80 paths essenciais (API, admin, docs, config)
    private static final List<String> WORDLIST = List.of("/api", "/api/v1", "/api/v2", "/api/v3", "/api/users",
            "/api/user", "/api/me", "/api/profile", "/api/auth", "/api/login", "/api/logout", "/api/register",
            "/api/admin", "/api/config", "/api/settings", "/api/health", "/api/status", "/api/version", "/api/docs",
            "/api/graphql", "/api/upload", "/api/files", "/api/export", "/api/import", "/admin", "/admin/",
            "/admin/login", "/administrator", "/dashboard", "/panel", "/cp", "/control", "/login", "/logout",
            "/register", "/signup", "/health", "/health/", "/healthz", "/ping", "/status", "/metrics", "/actuator",
            "/actuator/health", "/swagger.json", "/swagger.yaml", "/openapi.json", "/openapi.yaml", "/api-docs",
            "/v2/api-docs", "/v3/api-docs", "/swagger-ui.html", "/swagger-ui/index.html",
            "/.well-known/openid-configuration", "/.well-known/oauth-authorization-server", "/graphql", "/graphiql",
            "/playground", "/config", "/config.json", "/settings", "/settings.json", "/env", "/environment", "/.env",
            "/backup", "/backup.sql", "/database.sql", "/dump.sql", "/robots.txt", "/sitemap.xml", "/crossdomain.xml",
            "/.git/config", "/.git/HEAD", "/git/config", "/wp-admin", "/wp-login.php", "/xmlrpc.php", "/phpmyadmin",
            "/phpinfo.php", "/console", "/rails/info/properties", "/rails/mailers", "/debug", "/trace", "/test",
            "/demo", "/upload", "/uploads", "/files", "/static", "/assets", "/public", "/resources", "/internal",
            "/private", "/secret", "/v1", "/v2", "/v3", "/api/v1/users", "/api/v2/users");

    private static final List<String> OPENAPI_PATHS = List.of("/swagger.json", "/openapi.json", "/openapi.yaml",
            "/api-docs", "/v2/api-docs", "/v3/api-docs", "/swagger-ui.html", "/swagger-ui/index.html");

    // Regex para extrair paths de JS
    private static final Pattern PATH_PATTERN = Pattern
            .compile("[\"'](\\/(?:api|v[0-9]|graphql|auth|user|admin)[\\w/.\\-]{0,100})[\"']");

    @Override
    public List<Finding> scan(ScanContext ctx, Consumer<String> log) throws Exception {
        List<Finding> findings = new ArrayList<>();
        Set<String> discovered = new LinkedHashSet<>();
        HttpClient hc = HttpClientFactory.noRedirect();

        String base = (ctx.isHttps() ? "https" : "http") + "://" + ctx.host()
                + (ctx.port() != (ctx.isHttps() ? 443 : 80) ? ":" + ctx.port() : "");

        log.accept("[~] Crawler: analisando " + base);

        // 0. Aggregate crawlerHints from KB for all enabled modules
        Set<String> kbPaths = new LinkedHashSet<>();
        Set<String> kbParameters = new LinkedHashSet<>();
        for (String mod : ctx.enabledModules()) {
            KnowledgeBase.getInstance().byModule(mod).ifPresent(entry -> {
                KnowledgeEntry.CrawlerHints hints = entry.crawlerHints();
                if (hints != null) {
                    if (hints.paths() != null) {
                        kbPaths.addAll(hints.paths());
                    }
                    if (hints.parameters() != null) {
                        kbParameters.addAll(hints.parameters());
                    }
                }
            });
        }
        log.accept("[~] Crawler: " + kbPaths.size() + " KB hint paths merged from " + ctx.enabledModules().size()
                + " modules");

        // 1. GET targetUrl -- extrair paths do HTML
        try {
            var req = HttpRequest.newBuilder().uri(URI.create(ctx.targetUrl())).timeout(Duration.ofSeconds(8)).GET()
                    .build();
            var resp = Http.send(ctx, hc, req, HttpResponse.BodyHandlers.ofString(), id());
            if (resp.statusCode() == 200) {
                extractHtmlPaths(resp.body(), base, discovered);
                log.accept("[~] Crawler: " + discovered.size() + " paths extraídos do HTML");
            }
        } catch (Exception e) {
            log.accept("[!] Crawler: erro ao buscar HTML: " + e.getMessage());
        }

        // 2. Fetch e analisa cada .js encontrado
        Set<String> jsPaths = new LinkedHashSet<>(discovered);
        for (String path : jsPaths) {
            if (!path.endsWith(".js")) {
                continue;
            }
            try {
                var req = HttpRequest.newBuilder().uri(URI.create(base + path)).timeout(Duration.ofSeconds(5)).GET()
                        .build();
                var resp = Http.send(ctx, hc, req, HttpResponse.BodyHandlers.ofString(), id());
                if (resp.statusCode() == 200) {
                    Matcher m = PATH_PATTERN.matcher(resp.body());
                    while (m.find()) {
                        discovered.add(m.group(1));
                    }
                }
            } catch (Exception ignored) {
            }
        }

        // 2b. Merge KB paths into probe set (WORDLIST + KB hints, deduped)
        Set<String> mergedProbeSet = new LinkedHashSet<>(WORDLIST);
        mergedProbeSet.addAll(kbPaths);

        // 3. OpenAPI discovery
        for (String p : OPENAPI_PATHS) {
            try {
                var req = HttpRequest.newBuilder().uri(URI.create(base + p)).timeout(Duration.ofSeconds(5)).GET()
                        .build();
                var resp = Http.send(ctx, hc, req, HttpResponse.BodyHandlers.ofString(), id());
                if (resp.statusCode() == 200) {
                    log.accept("[!!] Crawler: OpenAPI/Swagger exposto em " + p);
                    findings.add(Finding.of("Crawler", p, "OpenAPI/Swagger spec exposta sem autenticação",
                            Severity.MEDIUM, "GET " + base + p + " → HTTP 200 | Size: " + resp.body().length(),
                            "Especificação API exposta publicamente -- revela todos os endpoints, parâmetros e schemas",
                            "curl '" + base + p + "'", "Proteger /api-docs com autenticação ou remover de produção",
                            "CWE-200", "Exposure of Sensitive Information to an Unauthorized Actor",
                            "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", 5.3));
                }
            } catch (Exception ignored) {
            }
        }

        // 4. Wordlist + KB probing
        int found200 = 0;
        long delayMs = ctx.config().delayMs() > 0 ? ctx.config().delayMs() : 100;
        for (String p : mergedProbeSet) {
            if (OPENAPI_PATHS.contains(p)) {
                continue; // já verificado
            }
            try {
                Thread.sleep(delayMs);
            } catch (InterruptedException ie) {
                Thread.currentThread().interrupt();
                break;
            }
            try {
                var req = HttpRequest.newBuilder().uri(URI.create(base + p)).timeout(Duration.ofSeconds(4)).GET()
                        .build();
                var resp = Http.send(ctx, hc, req, HttpResponse.BodyHandlers.ofString(), id());
                int sc = resp.statusCode();
                if (sc == 200 || sc == 301 || sc == 302) {
                    discovered.add(p);
                    found200++;
                    if (p.contains("backup") || p.contains(".sql") || p.contains(".env") || p.contains("/.git")
                            || p.contains("phpinfo")) {
                        log.accept("[!!] Crawler: endpoint sensível acessível: " + p + " → " + sc);
                        findings.add(Finding.of("Crawler", p, "Endpoint sensível acessível: " + p, Severity.HIGH,
                                "GET " + base + p + " → HTTP " + sc,
                                "Endpoint potencialmente sensível acessível sem autenticação",
                                "curl '" + base + p + "'", "Remover ou proteger com autenticação", "CWE-200",
                                "Exposure of Sensitive Information to an Unauthorized Actor",
                                "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5));
                    }
                }
            } catch (Exception ignored) {
            }
        }

        // 5. Cap discovered paths at 500
        if (discovered.size() > 500) {
            Set<String> capped = new LinkedHashSet<>();
            int count = 0;
            for (String path : discovered) {
                if (count >= 500) {
                    break;
                }
                capped.add(path);
                count++;
            }
            discovered = capped;
            log.accept("[~] Crawler: capped discovered paths to 500");
        }

        log.accept(
                "[+] Crawler: " + discovered.size() + " paths descobertos, " + found200 + " da wordlist responderam");

        // 6. Push results to ctx.discoveredPaths()
        ctx.discoveredPaths().addPaths(discovered);
        ctx.discoveredPaths().addParameters(kbParameters);

        if (findings.isEmpty()) {
            log.accept("[+] Crawler: nenhum endpoint sensível ou spec exposta");
        }
        return findings;
    }

    private void extractHtmlPaths(String html, String base, Set<String> out) {
        // href, action, src
        Pattern p = Pattern.compile("(?:href|action|src)=[\"']([^\"'#?]*)[\"']", Pattern.CASE_INSENSITIVE);
        Matcher m = p.matcher(html);
        while (m.find()) {
            String v = m.group(1).trim();
            if (v.isBlank() || v.startsWith("http") || v.startsWith("mailto") || v.startsWith("tel")) {
                continue;
            }
            if (!v.startsWith("/")) {
                v = "/" + v;
            }
            // só caminhos, sem extensões de assets estáticos
            if (v.matches(".*\\.(png|jpg|jpeg|gif|ico|svg|woff|woff2|ttf|eot|css|map).*")) {
                continue;
            }
            out.add(v);
        }
    }
}
