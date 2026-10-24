package gg.effront.anarcry.scanner.web.oauth;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import gg.effront.anarcry.model.CvssCalculator;
import gg.effront.anarcry.model.CweRegistry;
import gg.effront.anarcry.model.Finding;
import gg.effront.anarcry.model.Severity;
import gg.effront.anarcry.scanner.ScanContext;
import gg.effront.anarcry.scanner.Scanner;
import gg.effront.anarcry.scanner.util.Http;
import gg.effront.anarcry.scanner.util.HttpClientFactory;
import gg.effront.anarcry.scanner.util.TlsUtil;

import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.function.Consumer;
import javax.net.ssl.SSLParameters;

public class OAuthModule implements Scanner {

    private static final List<String> WELLKNOWN_PATHS = List.of("/.well-known/openid-configuration",
            "/.well-known/oauth-authorization-server");
    private static final List<String> AUTHORIZE_PATHS = List.of("/oauth/authorize", "/oauth2/authorize", "/authorize",
            "/auth/authorize", "/connect/authorize", "/oauth/auth");
    private static final String EVIL_REDIRECT = "https://evil.anarcry-probe.com/callback";

    @Override
    public String id() {
        return "OAuth";
    }

    @Override
    public List<Finding> scan(ScanContext ctx, Consumer<String> log) throws Exception {
        List<Finding> findings = new ArrayList<>();

        String _cweId = CweRegistry.cweId(id());
        String _cweTitle = CweRegistry.cweTitle(id());
        String _cveVector = CweRegistry.cvssVector(id());
        double _score = CvssCalculator.calculate(_cveVector);

        String scheme = ctx.isHttps() ? "https" : "http";
        int defPort = ctx.isHttps() ? 443 : 80;
        String baseUrl = scheme + "://" + ctx.host() + (ctx.port() != defPort ? ":" + ctx.port() : "");

        HttpClient hcNoRedirect = HttpClientFactory.noRedirect();
        HttpClient hcFollow = HttpClientFactory.http2();
        log.accept("[~] OAuth: descobrindo endpoints em " + baseUrl);

        // ── 1. Discover via well-known ────────────────────────────────
        String authorizeEndpoint = null;
        for (String wk : WELLKNOWN_PATHS) {
            try {
                HttpRequest req = HttpRequest.newBuilder().uri(URI.create(baseUrl + wk)).timeout(Duration.ofSeconds(5))
                        .GET().build();
                HttpResponse<String> resp = Http.send(ctx, hcFollow, req, HttpResponse.BodyHandlers.ofString(), id());
                if (resp.statusCode() == 200 && resp.body() != null && resp.body().contains("authorization_endpoint")) {
                    log.accept("[+] OAuth: well-known encontrado em " + wk);
                    try {
                        JsonObject json = JsonParser.parseString(resp.body()).getAsJsonObject();
                        if (json.has("authorization_endpoint")) {
                            authorizeEndpoint = json.get("authorization_endpoint").getAsString();
                        }
                    } catch (Exception ignored) {
                    }
                    findings.add(Finding.of("OAuth", baseUrl + wk, "OAuth / OpenID Connect endpoint descoberto",
                            Severity.INFO, "Well-known: " + baseUrl + wk + " | authorize: " + authorizeEndpoint,
                            "Endpoint OAuth identificado — verificar state, PKCE e redirect_uri whitelist",
                            "curl " + baseUrl + wk,
                            "Auditar: state obrigatório, PKCE habilitado, redirect_uri em whitelist estrita", _cweId,
                            _cweTitle, _cveVector, _score));
                    break;
                }
            } catch (Exception e) {
                log.accept("[~] OAuth: " + wk + " — " + e.getMessage());
            }
        }

        // ── 2. Fallback: probe common authorize paths ─────────────────
        if (authorizeEndpoint == null) {
            for (String path : AUTHORIZE_PATHS) {
                try {
                    String testUrl = baseUrl + path + "?response_type=code&client_id=anarcry-test";
                    HttpRequest req = HttpRequest.newBuilder().uri(URI.create(testUrl)).timeout(Duration.ofSeconds(5))
                            .GET().build();
                    HttpResponse<Void> resp = Http.send(ctx, hcNoRedirect, req, HttpResponse.BodyHandlers.discarding(),
                            id());
                    if (resp.statusCode() != 404) {
                        log.accept(
                                "[+] OAuth: authorize path encontrado: " + path + " (HTTP " + resp.statusCode() + ")");
                        authorizeEndpoint = baseUrl + path;
                        findings.add(Finding.of("OAuth", authorizeEndpoint, "OAuth authorize endpoint descoberto",
                                Severity.INFO, "URL: " + authorizeEndpoint + " | HTTP " + resp.statusCode(),
                                "Endpoint de autorização OAuth identificado — auditar segurança do fluxo",
                                "curl '" + authorizeEndpoint + "?response_type=code&client_id=test'",
                                "Exigir state e PKCE; validar redirect_uri contra whitelist estrita", _cweId, _cweTitle,
                                _cveVector, _score));
                        break;
                    }
                } catch (Exception e) {
                    log.accept("[~] OAuth: " + path + " — " + e.getMessage());
                }
            }
        }

        if (authorizeEndpoint == null) {
            log.accept("[~] OAuth: nenhum endpoint OAuth encontrado");
            return findings;
        }

        // ── 3. Probe: redirect_uri bypass ─────────────────────────────
        findRedirectUriBypass(ctx, authorizeEndpoint, hcNoRedirect, log).ifPresent(findings::add);

        // ── 4. Probe: state parameter not enforced ────────────────────
        findStateMissing(ctx, authorizeEndpoint, hcNoRedirect, log).ifPresent(findings::add);

        return findings;
    }

    private Optional<Finding> findRedirectUriBypass(ScanContext ctx, String endpoint, HttpClient hc,
            Consumer<String> log) {
        String _cweId = CweRegistry.cweId(id());
        String _cweTitle = CweRegistry.cweTitle(id());
        String _cveVector = CweRegistry.cvssVector(id());
        double _score = CvssCalculator.calculate(_cveVector);
        log.accept("[~] OAuth: probe redirect_uri bypass → " + endpoint);
        String encodedRedirect;
        try {
            encodedRedirect = URLEncoder.encode(EVIL_REDIRECT, "UTF-8");
        } catch (Exception e) {
            encodedRedirect = EVIL_REDIRECT;
        }
        String url = endpoint + "?response_type=code&client_id=anarcry-test" + "&redirect_uri=" + encodedRedirect
                + "&state=anarchtest";
        try {
            HttpRequest req = HttpRequest.newBuilder().uri(URI.create(url)).timeout(Duration.ofSeconds(5)).GET()
                    .build();
            HttpResponse<Void> resp = Http.send(ctx, hc, req, HttpResponse.BodyHandlers.discarding(), id());
            int status = resp.statusCode();
            String location = resp.headers().firstValue("location").orElse("").trim();
            log.accept("[~] OAuth: redirect_uri probe → HTTP " + status + " Location=" + location);

            if ((status == 301 || status == 302 || status == 307 || status == 308)
                    && location.startsWith(EVIL_REDIRECT)) {
                log.accept("[!] OAuth: CRÍTICO — redirect_uri bypass confirmado → " + location);
                return Optional.of(Finding.of("OAuth", endpoint,
                        "OAuth redirect_uri bypass — roubo de código de autorização", Severity.CRITICAL,
                        "Endpoint: " + endpoint + " | redirect_uri injetada: " + EVIL_REDIRECT + " | Location: "
                                + location,
                        "Servidor redireciona o código de autorização para URL controlada pelo atacante — "
                                + "permite roubo de sessão OAuth completo",
                        "# 1. Enviar vítima para:\n" + url + "\n"
                                + "# 2. O código chega em evil.anarcry-probe.com/callback\n"
                                + "# 3. Trocar por access_token no token endpoint",
                        "Validar redirect_uri contra whitelist estrita registrada por cliente;"
                                + " rejeitar qualquer desvio",
                        _cweId, _cweTitle, _cveVector, _score));
            }
        } catch (Exception e) {
            log.accept("[~] OAuth: redirect_uri probe — " + e.getMessage());
        }
        return Optional.empty();
    }

    private Optional<Finding> findStateMissing(ScanContext ctx, String endpoint, HttpClient hc, Consumer<String> log) {
        String _cweId = CweRegistry.cweId(id());
        String _cweTitle = CweRegistry.cweTitle(id());
        String _cveVector = CweRegistry.cvssVector(id());
        double _score = CvssCalculator.calculate(_cveVector);
        log.accept("[~] OAuth: probe state parameter → " + endpoint);
        String encodedCb;
        try {
            encodedCb = URLEncoder.encode("https://callback.example.com", "UTF-8");
        } catch (Exception e) {
            encodedCb = "https%3A%2F%2Fcallback.example.com";
        }
        // Request WITHOUT state — if server redirects back with code and no state error
        // → HIGH
        String url = endpoint + "?response_type=code&client_id=anarcry-test" + "&redirect_uri=" + encodedCb;
        try {
            HttpRequest req = HttpRequest.newBuilder().uri(URI.create(url)).timeout(Duration.ofSeconds(5)).GET()
                    .build();
            HttpResponse<String> resp = Http.send(ctx, hc, req, HttpResponse.BodyHandlers.ofString(), id());
            int status = resp.statusCode();
            String location = resp.headers().firstValue("location").orElse("").trim();
            String body = resp.body() != null ? resp.body().toLowerCase() : "";

            log.accept("[~] OAuth: state probe → HTTP " + status + " Location=" + location);

            // Successful auth redirect with code but no state = state not enforced
            if ((status == 302 || status == 301) && location.contains("code=") && !location.contains("state=")) {
                log.accept("[!] OAuth: HIGH — state param ausente na resposta de autorização");
                return Optional.of(Finding.of("OAuth", endpoint,
                        "OAuth state parameter não exigido — CSRF no fluxo de autorização", Severity.HIGH,
                        "Endpoint: " + endpoint + " | Resposta sem state: HTTP " + status + " Location=" + location,
                        "Fluxo OAuth aceita requisições sem state — atacante pode forçar troca de código "
                                + "via CSRF e assumir a sessão OAuth da vítima",
                        "# CSRF PoC — iframe/link enviado para vítima:\n" + url,
                        "Exigir e validar o parâmetro state em todos os requests de autorização; usar PKCE como"
                                + "complemento",
                        _cweId, _cweTitle, _cveVector, _score));
            }

            // Explicit error about state being required — server is SAFE for this check
            if (body.contains("state") && (body.contains("required") || body.contains("missing")
                    || body.contains("invalid") || status == 400 || status == 422)) {
                log.accept("[+] OAuth: state obrigatório validado pelo servidor");
            }

        } catch (Exception e) {
            log.accept("[~] OAuth: state probe — " + e.getMessage());
        }
        return Optional.empty();
    }

    private HttpClient buildClient(boolean followRedirects) throws Exception {
        SSLParameters params = new SSLParameters();
        params.setEndpointIdentificationAlgorithm("");
        return HttpClient.newBuilder().sslContext(TlsUtil.sslContext(TlsUtil.trustAll())).sslParameters(params)
                .followRedirects(followRedirects ? HttpClient.Redirect.ALWAYS : HttpClient.Redirect.NEVER)
                .version(HttpClient.Version.HTTP_1_1).connectTimeout(Duration.ofSeconds(5)).build();
    }
}
