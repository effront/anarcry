package gg.effront.anarcry.scanner.web.graphql;

import gg.effront.anarcry.model.CvssCalculator;
import gg.effront.anarcry.model.CweRegistry;
import gg.effront.anarcry.model.Finding;
import gg.effront.anarcry.model.Severity;
import gg.effront.anarcry.scanner.ScanContext;
import gg.effront.anarcry.scanner.Scanner;
import gg.effront.anarcry.scanner.util.TlsUtil;
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
import javax.net.ssl.SSLParameters;

public class GraphQLModule implements Scanner {

    private static final List<String> ENDPOINTS = List.of("/graphql", "/__graphql", "/api/graphql", "/graphql/v1",
            "/graphiql", "/query", "/api/query", "/v1/graphql", "/graphql/console");

    private static final String INTROSPECTION = "{\"query\":\"{__schema{types{name}}}\"}";
    private static final String TYPENAME_QUERY = "{\"query\":\"{__typename}\"}";

    @Override
    public String id() {
        return "GraphQL";
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

        HttpClient hc = HttpClientFactory.noRedirect();
        log.accept("[~] GraphQL: descobrindo endpoints em " + baseUrl);

        for (String endpoint : ENDPOINTS) {
            String url = baseUrl + endpoint;
            try {
                HttpRequest req = HttpRequest.newBuilder().uri(URI.create(url))
                        .header("Content-Type", "application/json").timeout(Duration.ofSeconds(5))
                        .POST(HttpRequest.BodyPublishers.ofString(INTROSPECTION)).build();
                HttpResponse<String> resp = Http.send(ctx, hc, req, HttpResponse.BodyHandlers.ofString(), id());
                int status = resp.statusCode();
                String body = resp.body() != null ? resp.body() : "";
                String ct = resp.headers().firstValue("content-type").orElse("");

                if (status == 404) {
                    continue;
                }

                log.accept("[~] GraphQL: " + endpoint + " → HTTP " + status);

                if (body.contains("__schema") && body.contains("types")) {
                    log.accept("[!] GraphQL: HIGH — introspection habilitada em " + url);
                    findings.add(Finding.of("GraphQL", url,
                            "GraphQL introspection habilitada — schema completo exposto", Severity.HIGH,
                            "Endpoint: " + url + " | HTTP " + status + " | __schema presente na resposta",
                            "Introspection habilitada em produção expõe o schema completo da API (queries, mutations, "
                                    + "types, campos, diretivas) — facilita enumeração de superfície de ataque e "
                                    + "descoberta de funcionalidades não documentadas",
                            "curl -sX POST " + url + " \\\n" + "  -H 'Content-Type: application/json' \\\n" + "  -d '"
                                    + INTROSPECTION + "' | python3 -m json.tool",
                            "Desabilitar introspection em produção; considerar persisted queries e "
                                    + "query depth/complexity limits; habilitar introspection apenas em ambientes"
                                    + " de dev controlados",
                            _cweId, _cweTitle, _cveVector, _score));
                    continue;
                }

                // Endpoint exists but introspection disabled — confirm with __typename probe
                // to avoid FP on any REST API that returns JSON errors.
                if ((status == 200 || status == 400 || status == 422) && ct.contains("json")) {
                    try {
                        HttpRequest typenameReq = HttpRequest.newBuilder().uri(URI.create(url))
                                .header("Content-Type", "application/json").timeout(Duration.ofSeconds(5))
                                .POST(HttpRequest.BodyPublishers.ofString(TYPENAME_QUERY)).build();
                        HttpResponse<String> typenameResp = Http.send(ctx, hc, typenameReq,
                                HttpResponse.BodyHandlers.ofString(), id());
                        String typenameBody = typenameResp.body() != null ? typenameResp.body() : "";
                        if (typenameBody.contains("__typename")) {
                            log.accept("[+] GraphQL: endpoint confirmado em " + url + " (introspection desativada)");
                            findings.add(Finding.of("GraphQL", url, "GraphQL endpoint descoberto", Severity.INFO,
                                    "Endpoint: " + url + " | HTTP " + status + " | __typename confirmado na resposta",
                                    "Endpoint GraphQL identificado — auditar queries expostas, depth limiting e rate"
                                            + "limiting",
                                    "curl -sX POST " + url + " \\\n" + "  -H 'Content-Type: application/json' \\\n"
                                            + "  -d '" + TYPENAME_QUERY + "'",
                                    "Habilitar depth limiting, field-level authorization e rate limiting; "
                                            + "considerar persisted queries para reduzir superfície de ataque",
                                    _cweId, _cweTitle, _cveVector, _score));
                        }
                    } catch (Exception ignored) {
                    }
                }

            } catch (Exception e) {
                log.accept("[~] GraphQL: " + url + " — " + e.getMessage());
            }
        }

        if (findings.isEmpty()) {
            log.accept("[+] GraphQL: nenhum endpoint GraphQL encontrado");
        }
        return findings;
    }

    private HttpClient buildClient() throws Exception {
        SSLParameters params = new SSLParameters();
        params.setEndpointIdentificationAlgorithm("");
        return HttpClient.newBuilder().sslContext(TlsUtil.sslContext(TlsUtil.trustAll())).sslParameters(params)
                .followRedirects(HttpClient.Redirect.NEVER).version(HttpClient.Version.HTTP_1_1)
                .connectTimeout(Duration.ofSeconds(5)).build();
    }
}
