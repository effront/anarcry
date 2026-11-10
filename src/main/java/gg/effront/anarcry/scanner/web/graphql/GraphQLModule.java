package gg.effront.anarcry.scanner.web.graphql;

import gg.effront.anarcry.model.CvssCalculator;
import gg.effront.anarcry.model.CweRegistry;
import gg.effront.anarcry.model.Finding;
import gg.effront.anarcry.model.Severity;
import gg.effront.anarcry.scanner.ScanContext;
import gg.effront.anarcry.scanner.Scanner;
import gg.effront.anarcry.scanner.util.CircuitBreakerException;
import gg.effront.anarcry.scanner.util.Http;
import gg.effront.anarcry.scanner.util.HttpClientFactory;
import gg.effront.anarcry.scanner.util.TlsUtil;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;
import java.util.regex.Pattern;
import javax.net.ssl.SSLParameters;

public class GraphQLModule implements Scanner {

    private static final List<String> ENDPOINTS = List.of("/graphql", "/__graphql", "/api/graphql", "/graphql/v1",
            "/graphiql", "/query", "/api/query", "/v1/graphql", "/graphql/console");

    private static final String INTROSPECTION = "{\"query\":\"{__schema{types{name}}}\"}";
    private static final String TYPENAME_QUERY = "{\"query\":\"{__typename}\"}";

    // Full introspection query to enumerate mutations
    private static final String MUTATION_INTROSPECTION = "{\"query\":\"{__schema{mutationType{name,fields{"
            + "name,args{name,type{name,kind,ofType{name}}}}}}}\"}";

    // Pattern to detect field name suggestions in error messages
    private static final Pattern SUGGESTION_PATTERN = Pattern
            .compile("(?i)(did you mean|suggest|similar|maybe you meant)[^\"]*\"([^\"]+)\"");

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

        // Track confirmed GraphQL endpoints for advanced probes
        List<String> confirmedEndpoints = new ArrayList<>();

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

                log.accept("[~] GraphQL: " + endpoint + " -> HTTP " + status);

                if (body.contains("__schema") && body.contains("types")) {
                    log.accept("[!] GraphQL: HIGH -- introspection habilitada em " + url);
                    findings.add(Finding.of("GraphQL", url,
                            "GraphQL introspection habilitada -- schema completo exposto", Severity.HIGH,
                            "Endpoint: " + url + " | HTTP " + status + " | __schema presente na resposta",
                            "Introspection habilitada em producao expoe o schema completo da API (queries, mutations, "
                                    + "types, campos, diretivas) -- facilita enumeracao de superficie de ataque e "
                                    + "descoberta de funcionalidades nao documentadas",
                            "curl -sX POST " + url + " \\\n" + "  -H 'Content-Type: application/json' \\\n" + "  -d '"
                                    + INTROSPECTION + "' | python3 -m json.tool",
                            "Desabilitar introspection em producao; considerar persisted queries e "
                                    + "query depth/complexity limits; habilitar introspection apenas em ambientes"
                                    + " de dev controlados",
                            _cweId, _cweTitle, _cveVector, _score));
                    confirmedEndpoints.add(url);
                    continue;
                }

                // Endpoint exists but introspection disabled -- confirm with __typename probe
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
                                    "Endpoint GraphQL identificado -- auditar queries expostas, depth limiting e rate"
                                            + "limiting",
                                    "curl -sX POST " + url + " \\\n" + "  -H 'Content-Type: application/json' \\\n"
                                            + "  -d '" + TYPENAME_QUERY + "'",
                                    "Habilitar depth limiting, field-level authorization e rate limiting; "
                                            + "considerar persisted queries para reduzir superficie de ataque",
                                    _cweId, _cweTitle, _cveVector, _score));
                            confirmedEndpoints.add(url);
                        }
                    } catch (CircuitBreakerException cbe) {
                        throw cbe;
                    } catch (Exception ignored) {
                    }
                }

            } catch (CircuitBreakerException cbe) {
                throw cbe;
            } catch (Exception e) {
                log.accept("[~] GraphQL: " + url + " -- " + e.getMessage());
            }
        }

        // -- Phase 2: Advanced probes on confirmed endpoints --
        for (String gqlUrl : confirmedEndpoints) {
            probeMutationTesting(ctx, hc, gqlUrl, findings, log, _cweId, _cweTitle, _cveVector, _score);
            probeNestedQueryDoS(ctx, hc, gqlUrl, findings, log, _cweId, _cweTitle, _cveVector, _score);
            probeBatchingBypass(ctx, hc, gqlUrl, findings, log, _cweId, _cweTitle, _cveVector, _score);
            probeFieldSuggestionLeak(ctx, hc, gqlUrl, findings, log, _cweId, _cweTitle, _cveVector, _score);
        }

        if (findings.isEmpty()) {
            log.accept("[+] GraphQL: nenhum endpoint GraphQL encontrado");
        }
        return findings;
    }

    // -- Phase 2a: Mutation testing --
    // Enumerate mutations via introspection and test for unauthenticated access
    private void probeMutationTesting(ScanContext ctx, HttpClient hc, String url, List<Finding> findings,
            Consumer<String> log, String cweId, String cweTitle, String cveVector, double score) {
        log.accept("[~] GraphQL: testando mutations em " + url);
        try {
            // Query for mutation schema
            HttpRequest req = HttpRequest.newBuilder().uri(URI.create(url)).header("Content-Type", "application/json")
                    .timeout(Duration.ofSeconds(6)).POST(HttpRequest.BodyPublishers.ofString(MUTATION_INTROSPECTION))
                    .build();
            HttpResponse<String> resp = Http.send(ctx, hc, req, HttpResponse.BodyHandlers.ofString(), id());
            String body = resp.body() != null ? resp.body() : "";

            if (!body.contains("mutationType") || !body.contains("fields")) {
                log.accept("[~] GraphQL: mutations nao disponiveis via introspection");
                return;
            }

            // Extract mutation names from response (simple pattern extraction)
            List<String> mutations = extractMutationNames(body);
            if (mutations.isEmpty()) {
                return;
            }
            log.accept("[~] GraphQL: " + mutations.size() + " mutations encontradas");

            // Test each mutation without auth header (unauthenticated access)
            for (String mutation : mutations) {
                String testQuery = "{\"query\":\"mutation { " + mutation + "(input: {}) { __typename } }\"}";

                // Send WITHOUT auth -- check if mutation is accessible
                HttpRequest noAuthReq = HttpRequest.newBuilder().uri(URI.create(url))
                        .header("Content-Type", "application/json").timeout(Duration.ofSeconds(6))
                        .POST(HttpRequest.BodyPublishers.ofString(testQuery)).build();
                HttpResponse<String> noAuthResp = Http.send(ctx, hc, noAuthReq, HttpResponse.BodyHandlers.ofString(),
                        id());
                String noAuthBody = noAuthResp.body() != null ? noAuthResp.body() : "";

                // If we get data back (not an auth error), the mutation is accessible without
                // auth
                boolean hasData = noAuthBody.contains("\"data\"") && !noAuthBody.contains("\"data\":null")
                        && !noAuthBody.contains("\"data\": null");
                boolean noAuthError = !noAuthBody.contains("unauthorized") && !noAuthBody.contains("unauthenticated")
                        && !noAuthBody.contains("forbidden") && !noAuthBody.contains("not authenticated")
                        && !noAuthBody.contains("UNAUTHENTICATED");

                if (hasData && noAuthError) {
                    log.accept("[!!] GraphQL: mutation '" + mutation + "' acessivel sem autenticacao");
                    findings.add(Finding.of("GraphQL", url, "GraphQL mutation sem autenticacao -- " + mutation,
                            Severity.HIGH,
                            "Mutation: " + mutation + " | Resposta sem auth: "
                                    + noAuthBody.substring(0, Math.min(200, noAuthBody.length())),
                            "Mutation acessivel sem autenticacao pode permitir alteracao de dados, "
                                    + "criacao de contas, ou escalonamento de privilegios",
                            "curl -sX POST " + url + " \\\n" + "  -H 'Content-Type: application/json' \\\n" + "  -d '"
                                    + testQuery + "'",
                            "Exigir autenticacao em todas as mutations; implementar field-level "
                                    + "authorization; usar middleware de autenticacao no resolver",
                            cweId, cweTitle, cveVector, score));
                    break; // One finding is enough to prove the issue
                }
            }
        } catch (CircuitBreakerException cbe) {
            throw cbe;
        } catch (Exception e) {
            log.accept("[~] GraphQL: erro no teste de mutations -- " + e.getMessage());
        }
    }

    // -- Phase 2b: Nested query DoS (query depth) --
    // Send increasingly deep nested queries to detect missing depth limits
    private void probeNestedQueryDoS(ScanContext ctx, HttpClient hc, String url, List<Finding> findings,
            Consumer<String> log, String cweId, String cweTitle, String cveVector, double score) {
        log.accept("[~] GraphQL: testando nested query depth em " + url);
        try {
            // Measure baseline response time
            long baselineStart = System.currentTimeMillis();
            HttpRequest baseReq = HttpRequest.newBuilder().uri(URI.create(url))
                    .header("Content-Type", "application/json").timeout(Duration.ofSeconds(6))
                    .POST(HttpRequest.BodyPublishers.ofString(TYPENAME_QUERY)).build();
            Http.send(ctx, hc, baseReq, HttpResponse.BodyHandlers.ofString(), id());
            long baselineRtt = System.currentTimeMillis() - baselineStart;

            int[] depths = {5, 10, 20, 50};
            int maxAcceptedDepth = 0;
            long maxRtt = 0;

            for (int depth : depths) {
                String nestedQuery = buildNestedQuery(depth);
                String payload = "{\"query\":\"" + nestedQuery.replace("\"", "\\\"") + "\"}";

                long start = System.currentTimeMillis();
                HttpRequest req = HttpRequest.newBuilder().uri(URI.create(url))
                        .header("Content-Type", "application/json").timeout(Duration.ofSeconds(10))
                        .POST(HttpRequest.BodyPublishers.ofString(payload)).build();
                HttpResponse<String> resp = Http.send(ctx, hc, req, HttpResponse.BodyHandlers.ofString(), id());
                long rtt = System.currentTimeMillis() - start;
                String body = resp.body() != null ? resp.body() : "";
                int status = resp.statusCode();

                // Server rejected (depth limit in place) -- stop escalating
                boolean rejected = body.contains("depth") || body.contains("complexity") || body.contains("too many")
                        || body.contains("maximum") || status == 400 || status == 413 || status == 429;
                if (rejected) {
                    log.accept("[~] GraphQL: depth " + depth + " rejeitado -- limite detectado");
                    break;
                }

                maxAcceptedDepth = depth;
                maxRtt = rtt;
                log.accept("[~] GraphQL: depth " + depth + " aceito (rtt=" + rtt + "ms)");
            }

            // Report if server accepted depth >= 20 without rejection
            if (maxAcceptedDepth >= 20) {
                String rttInfo = "baseline=" + baselineRtt + "ms, depth " + maxAcceptedDepth + "=" + maxRtt + "ms";
                Severity sev = maxAcceptedDepth >= 50 ? Severity.HIGH : Severity.MEDIUM;
                log.accept("[!] GraphQL: " + sev + " -- nested query depth " + maxAcceptedDepth + " aceito");
                findings.add(Finding.of("GraphQL", url,
                        "GraphQL DoS -- nested query depth " + maxAcceptedDepth + " sem limite", sev,
                        "Endpoint: " + url + " | Depth maximo aceito: " + maxAcceptedDepth + " | RTT: " + rttInfo,
                        "Servidor aceita queries com aninhamento profundo sem limites de depth ou "
                                + "complexity -- atacante pode causar DoS com queries exponencialmente "
                                + "custosas (ex: N+1 queries, cartesian product via fragments)",
                        "curl -sX POST " + url + " \\\n" + "  -H 'Content-Type: application/json' \\\n"
                                + "  -d '{\"query\":\"" + buildNestedQuery(maxAcceptedDepth).replace("\"", "\\\"")
                                + "\"}'",
                        "Implementar query depth limiting (max 10-15); habilitar query complexity "
                                + "analysis; usar timeout por query; considerar persisted queries",
                        cweId, cweTitle, cveVector, score));
            }
        } catch (CircuitBreakerException cbe) {
            throw cbe;
        } catch (Exception e) {
            log.accept("[~] GraphQL: erro no teste de depth -- " + e.getMessage());
        }
    }

    // -- Phase 2c: Batching/aliasing bypass --
    // Test if server allows batched queries or aliased queries that bypass rate
    // limits
    private void probeBatchingBypass(ScanContext ctx, HttpClient hc, String url, List<Finding> findings,
            Consumer<String> log, String cweId, String cweTitle, String cveVector, double score) {
        log.accept("[~] GraphQL: testando batching/aliasing bypass em " + url);
        try {
            // Test 1: Array batching
            String batchPayload = "[" + "{\"query\":\"{__typename}\"}," + "{\"query\":\"{__typename}\"},"
                    + "{\"query\":\"{__typename}\"}," + "{\"query\":\"{__typename}\"}," + "{\"query\":\"{__typename}\"}"
                    + "]";

            HttpRequest batchReq = HttpRequest.newBuilder().uri(URI.create(url))
                    .header("Content-Type", "application/json").timeout(Duration.ofSeconds(6))
                    .POST(HttpRequest.BodyPublishers.ofString(batchPayload)).build();
            HttpResponse<String> batchResp = Http.send(ctx, hc, batchReq, HttpResponse.BodyHandlers.ofString(), id());
            String batchBody = batchResp.body() != null ? batchResp.body() : "";
            int batchStatus = batchResp.statusCode();

            boolean batchAccepted = batchStatus == 200 && batchBody.startsWith("[")
                    && countOccurrences(batchBody, "__typename") >= 3;

            // Test 2: Aliased queries
            StringBuilder aliasQuery = new StringBuilder("{ ");
            int aliasCount = 20;
            for (int i = 1; i <= aliasCount; i++) {
                aliasQuery.append("a").append(i).append(": __typename ");
            }
            aliasQuery.append("}");
            String aliasPayload = "{\"query\":\"" + aliasQuery.toString().replace("\"", "\\\"") + "\"}";

            HttpRequest aliasReq = HttpRequest.newBuilder().uri(URI.create(url))
                    .header("Content-Type", "application/json").timeout(Duration.ofSeconds(6))
                    .POST(HttpRequest.BodyPublishers.ofString(aliasPayload)).build();
            HttpResponse<String> aliasResp = Http.send(ctx, hc, aliasReq, HttpResponse.BodyHandlers.ofString(), id());
            String aliasBody = aliasResp.body() != null ? aliasResp.body() : "";
            int aliasStatus = aliasResp.statusCode();

            boolean aliasAccepted = aliasStatus == 200 && aliasBody.contains("\"data\"")
                    && countOccurrences(aliasBody, "\"a") >= aliasCount / 2;

            if (batchAccepted || aliasAccepted) {
                String technique = batchAccepted && aliasAccepted
                        ? "batching + aliasing"
                        : batchAccepted ? "batching" : "aliasing";
                String evidence;
                if (batchAccepted) {
                    evidence = "Batch de 5 queries aceito (HTTP " + batchStatus + "): "
                            + batchBody.substring(0, Math.min(200, batchBody.length()));
                } else {
                    evidence = "Alias de " + aliasCount + " queries aceito (HTTP " + aliasStatus + "): "
                            + aliasBody.substring(0, Math.min(200, aliasBody.length()));
                }

                log.accept("[!] GraphQL: MEDIUM -- " + technique + " bypass detectado");
                findings.add(Finding.of("GraphQL", url, "GraphQL rate limit bypass via " + technique, Severity.MEDIUM,
                        evidence,
                        "Servidor aceita " + technique + " sem rate limiting por operacao -- "
                                + "atacante pode executar multiplas queries em um unico request HTTP, "
                                + "bypassando rate limits baseados em requests/segundo "
                                + "(ex: brute force, enumeracao de dados)",
                        "curl -sX POST " + url + " \\\n" + "  -H 'Content-Type: application/json' \\\n" + "  -d '"
                                + (batchAccepted ? batchPayload : aliasPayload) + "'",
                        "Implementar rate limiting por operacao GraphQL (nao por request HTTP); "
                                + "limitar numero de queries por batch; limitar aliases por query; "
                                + "considerar query cost analysis",
                        cweId, cweTitle, cveVector, score));
            }
        } catch (CircuitBreakerException cbe) {
            throw cbe;
        } catch (Exception e) {
            log.accept("[~] GraphQL: erro no teste de batching -- " + e.getMessage());
        }
    }

    // -- Phase 2d: Field suggestion leak --
    // Send queries with intentional typos to check if error messages reveal valid
    // field names
    private void probeFieldSuggestionLeak(ScanContext ctx, HttpClient hc, String url, List<Finding> findings,
            Consumer<String> log, String cweId, String cweTitle, String cveVector, double score) {
        log.accept("[~] GraphQL: testando field suggestion leak em " + url);
        try {
            // Send queries with intentional typos in common field names
            List<String> typoQueries = List.of("{\"query\":\"{ usr { id } }\"}", "{\"query\":\"{ usrs { email } }\"}",
                    "{\"query\":\"{ me { passwrd } }\"}", "{\"query\":\"{ admi { role } }\"}",
                    "{\"query\":\"{ accont { balance } }\"}");

            for (String typoPayload : typoQueries) {
                HttpRequest req = HttpRequest.newBuilder().uri(URI.create(url))
                        .header("Content-Type", "application/json").timeout(Duration.ofSeconds(6))
                        .POST(HttpRequest.BodyPublishers.ofString(typoPayload)).build();
                HttpResponse<String> resp = Http.send(ctx, hc, req, HttpResponse.BodyHandlers.ofString(), id());
                String body = resp.body() != null ? resp.body() : "";

                var matcher = SUGGESTION_PATTERN.matcher(body);
                if (matcher.find()) {
                    String suggestedField = matcher.group(2);
                    log.accept("[!] GraphQL: field suggestion leak -- sugeriu '" + suggestedField + "'");
                    findings.add(Finding.of("GraphQL", url, "GraphQL field suggestion information disclosure",
                            Severity.MEDIUM,
                            "Endpoint: " + url + " | Query: " + typoPayload + " | Sugestao: '" + suggestedField
                                    + "' | Resposta: " + body.substring(0, Math.min(300, body.length())),
                            "Mensagens de erro sugerem nomes de campos validos quando typos sao "
                                    + "enviados -- atacante pode enumerar o schema completo sem "
                                    + "introspection, descobrindo campos sensiveis (password, token, "
                                    + "secret, admin)",
                            "curl -sX POST " + url + " \\\n" + "  -H 'Content-Type: application/json' \\\n" + "  -d '"
                                    + typoPayload + "'",
                            "Desabilitar field suggestions em producao (ex: Apollo Server -- "
                                    + "NODE_ENV=production desabilita automaticamente); retornar erros "
                                    + "genericos sem sugestoes de campos",
                            cweId, cweTitle, cveVector, score));
                    return; // One finding is enough
                }
            }
        } catch (CircuitBreakerException cbe) {
            throw cbe;
        } catch (Exception e) {
            log.accept("[~] GraphQL: erro no teste de field suggestion -- " + e.getMessage());
        }
    }

    // Build a deeply nested query: { a { a { a { ... { id } ... } } } }
    private static String buildNestedQuery(int depth) {
        StringBuilder sb = new StringBuilder();
        sb.append("{ ");
        for (int i = 0; i < depth; i++) {
            sb.append("a { ");
        }
        sb.append("id");
        for (int i = 0; i < depth; i++) {
            sb.append(" }");
        }
        sb.append(" }");
        return sb.toString();
    }

    // Extract mutation names from introspection response (simple JSON parsing)
    private static List<String> extractMutationNames(String body) {
        List<String> names = new ArrayList<>();
        // Look for "name":"<value>" patterns after "fields" in the response
        int fieldsIdx = body.indexOf("\"fields\"");
        if (fieldsIdx < 0) {
            return names;
        }
        String sub = body.substring(fieldsIdx);
        int idx = 0;
        while ((idx = sub.indexOf("\"name\":\"", idx)) != -1) {
            int start = idx + 8;
            int end = sub.indexOf("\"", start);
            if (end > start) {
                String name = sub.substring(start, end);
                // Skip internal GraphQL names and type names
                if (!name.startsWith("__") && !name.isEmpty()) {
                    names.add(name);
                }
            }
            idx = end > 0 ? end + 1 : idx + 1;
            // Limit to first 10 mutations to avoid excessive requests
            if (names.size() >= 10) {
                break;
            }
        }
        return names;
    }

    private static int countOccurrences(String haystack, String needle) {
        int count = 0;
        int idx = 0;
        while ((idx = haystack.indexOf(needle, idx)) != -1) {
            count++;
            idx += needle.length();
        }
        return count;
    }

    private HttpClient buildClient() throws Exception {
        SSLParameters params = new SSLParameters();
        params.setEndpointIdentificationAlgorithm("");
        return HttpClient.newBuilder().sslContext(TlsUtil.sslContext(TlsUtil.trustAll())).sslParameters(params)
                .followRedirects(HttpClient.Redirect.NEVER).version(HttpClient.Version.HTTP_1_1)
                .connectTimeout(Duration.ofSeconds(5)).build();
    }
}
