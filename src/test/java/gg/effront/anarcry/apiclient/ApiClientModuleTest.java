package gg.effront.anarcry.apiclient;

import com.sun.net.httpserver.HttpServer;
import gg.effront.anarcry.apiclient.auth.ApiKeyInjector;
import gg.effront.anarcry.apiclient.auth.AuthInjectorRegistry;
import gg.effront.anarcry.apiclient.auth.BasicAuthInjector;
import gg.effront.anarcry.apiclient.auth.BearerAuthInjector;
import gg.effront.anarcry.apiclient.io.CurlImporter;
import gg.effront.anarcry.apiclient.model.*;
import gg.effront.anarcry.apiclient.runner.AssertionEngine;
import gg.effront.anarcry.apiclient.runner.CollectionRunner;
import gg.effront.anarcry.apiclient.runner.RequestExecutor;
import gg.effront.anarcry.apiclient.vars.BuiltInFunctions;
import gg.effront.anarcry.apiclient.vars.Interpolator;
import gg.effront.anarcry.apiclient.vars.VariableStore;
import org.junit.jupiter.api.*;

import java.net.InetSocketAddress;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class ApiClientModuleTest {

    // =====================================================
    // 1. Built-in Functions
    // =====================================================

    @Test
    @Order(1)
    void builtInFunctions_timestamp() {
        String result = BuiltInFunctions.resolve("timestamp");
        assertNotNull(result);
        long ts = Long.parseLong(result);
        assertTrue(ts > 1700000000 && ts < 2000000000);
    }

    @Test
    @Order(2)
    void builtInFunctions_guid() {
        String guid = BuiltInFunctions.resolve("guid");
        assertNotNull(guid);
        assertTrue(guid.matches("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"));

        String uuid = BuiltInFunctions.resolve("uuid");
        assertNotNull(uuid);
        assertEquals(36, uuid.length());
    }

    @Test
    @Order(3)
    void builtInFunctions_randomInt() {
        String result = BuiltInFunctions.resolve("randomInt");
        assertNotNull(result);
        int val = Integer.parseInt(result);
        assertTrue(val >= 0 && val < 10000);
    }

    @Test
    @Order(4)
    void builtInFunctions_unknownReturnsNull() {
        assertNull(BuiltInFunctions.resolve("nonexistent"));
    }

    // =====================================================
    // 2. Variable Store
    // =====================================================

    @Test
    @Order(10)
    void variableStore_precedence() {
        VariableStore vars = new VariableStore();

        Environment env = new Environment("e1", "prod", "#CC0000",
                List.of(new EnvVariable("host", "https://prod.api.com", false, true),
                        new EnvVariable("token", "env-token", false, true)),
                null);
        vars.loadEnv(env);

        RootConfig collection = new RootConfig(List.of(), new AuthConfig.None(),
                List.of(new EnvVariable("host", "https://default.api.com", false, true),
                        new EnvVariable("version", "v1", false, true)));
        vars.loadCollection(collection);

        assertEquals("https://prod.api.com", vars.resolve("host"));
        assertEquals("v1", vars.resolve("version"));
        assertEquals("env-token", vars.resolve("token"));

        vars.setRuntime("host", "https://override.api.com");
        assertEquals("https://override.api.com", vars.resolve("host"));
    }

    @Test
    @Order(11)
    void variableStore_disabledVarsSkipped() {
        VariableStore vars = new VariableStore();
        Environment env = new Environment("e1", "test", null,
                List.of(new EnvVariable("active", "yes", false, true), new EnvVariable("disabled", "no", false, false)),
                null);
        vars.loadEnv(env);

        assertEquals("yes", vars.resolve("active"));
        assertNull(vars.resolve("disabled"));
    }

    // =====================================================
    // 3. Interpolator
    // =====================================================

    @Test
    @Order(20)
    void interpolator_simpleVar() {
        Interpolator interpolator = new Interpolator();
        VariableStore vars = new VariableStore();
        vars.setRuntime("host", "https://api.example.com");
        vars.setRuntime("version", "v1");

        assertEquals("https://api.example.com/v1/users", interpolator.interpolate("{{host}}/{{version}}/users", vars));
    }

    @Test
    @Order(21)
    void interpolator_nestedResolution() {
        Interpolator interpolator = new Interpolator();
        VariableStore vars = new VariableStore();
        vars.setRuntime("protocol", "https");
        vars.setRuntime("domain", "api.example.com");
        vars.setRuntime("baseUrl", "{{protocol}}://{{domain}}");

        assertEquals("https://api.example.com/users", interpolator.interpolate("{{baseUrl}}/users", vars));
    }

    @Test
    @Order(22)
    void interpolator_circularDetection() {
        Interpolator interpolator = new Interpolator();
        VariableStore vars = new VariableStore();
        vars.setRuntime("a", "{{b}}");
        vars.setRuntime("b", "{{a}}");

        String result = interpolator.interpolate("{{a}}", vars);
        assertTrue(result.contains("{{"));
    }

    @Test
    @Order(23)
    void interpolator_builtInFunctions() {
        Interpolator interpolator = new Interpolator();
        VariableStore vars = new VariableStore();

        String result = interpolator.interpolate("ts={{$timestamp}}", vars);
        assertTrue(result.startsWith("ts="));
        assertFalse(result.contains("{{"));
    }

    @Test
    @Order(24)
    void interpolator_unresolvedKept() {
        Interpolator interpolator = new Interpolator();
        VariableStore vars = new VariableStore();

        assertEquals("{{unknown}}", interpolator.interpolate("{{unknown}}", vars));
    }

    @Test
    @Order(25)
    void interpolator_jsonEscaping() {
        Interpolator interpolator = new Interpolator();
        VariableStore vars = new VariableStore();
        vars.setRuntime("name", "John \"Doe\"\nNew Line");

        String result = interpolator.interpolateJson("{\"name\": \"{{name}}\"}", vars);
        assertTrue(result.contains("\\\"Doe\\\""));
        assertTrue(result.contains("\\n"));
    }

    // =====================================================
    // 4. Auth Injectors
    // =====================================================

    @Test
    @Order(30)
    void basicAuth_injectsHeader() {
        BasicAuthInjector injector = new BasicAuthInjector();
        HttpRequestDef req = simpleRequest("GET", "https://api.example.com");
        AuthConfig.Basic auth = new AuthConfig.Basic("user", "pass");

        HttpRequestDef result = injector.inject(req, auth, new VariableStore());

        Header authHeader = result.headers().stream().filter(h -> h.name().equals("Authorization")).findFirst()
                .orElse(null);
        assertNotNull(authHeader);
        String expected = "Basic " + Base64.getEncoder().encodeToString("user:pass".getBytes(StandardCharsets.UTF_8));
        assertEquals(expected, authHeader.value());
    }

    @Test
    @Order(31)
    void bearerAuth_injectsHeader() {
        BearerAuthInjector injector = new BearerAuthInjector();
        HttpRequestDef req = simpleRequest("GET", "https://api.example.com");
        AuthConfig.Bearer auth = new AuthConfig.Bearer("my-token-123");

        HttpRequestDef result = injector.inject(req, auth, new VariableStore());

        Header authHeader = result.headers().stream().filter(h -> h.name().equals("Authorization")).findFirst()
                .orElse(null);
        assertNotNull(authHeader);
        assertEquals("Bearer my-token-123", authHeader.value());
    }

    @Test
    @Order(32)
    void apiKeyAuth_header() {
        ApiKeyInjector injector = new ApiKeyInjector();
        HttpRequestDef req = simpleRequest("GET", "https://api.example.com");
        AuthConfig.ApiKey auth = new AuthConfig.ApiKey("X-API-Key", "secret-key", "header");

        HttpRequestDef result = injector.inject(req, auth, new VariableStore());

        assertTrue(result.headers().stream()
                .anyMatch(h -> h.name().equals("X-API-Key") && h.value().equals("secret-key")));
    }

    @Test
    @Order(33)
    void apiKeyAuth_queryParam() {
        ApiKeyInjector injector = new ApiKeyInjector();
        HttpRequestDef req = simpleRequest("GET", "https://api.example.com");
        AuthConfig.ApiKey auth = new AuthConfig.ApiKey("api_key", "secret-key", "queryparams");

        HttpRequestDef result = injector.inject(req, auth, new VariableStore());

        assertTrue(result.params().query().stream()
                .anyMatch(p -> p.name().equals("api_key") && p.value().equals("secret-key")));
    }

    @Test
    @Order(34)
    void authRegistry_routesCorrectly() {
        AuthInjectorRegistry registry = new AuthInjectorRegistry();
        assertTrue(registry.forMode("basic").isPresent());
        assertTrue(registry.forMode("bearer").isPresent());
        assertTrue(registry.forMode("apikey").isPresent());
        assertTrue(registry.forMode("digest").isPresent());
        assertTrue(registry.forMode("oauth2").isPresent());
        assertTrue(registry.forMode("wsse").isPresent());
        assertTrue(registry.forMode("none").isEmpty());
        assertTrue(registry.forMode("inherit").isEmpty());
    }

    // =====================================================
    // 5. Assertion Engine
    // =====================================================

    @Test
    @Order(40)
    void assertions_statusEq() {
        AssertionEngine engine = new AssertionEngine(new Interpolator());
        ResponseData resp = new ResponseData(200, "OK", java.util.Map.of(), "{\"name\":\"John\"}", new byte[0], 100,
                50);
        List<Assertion> assertions = List.of(new Assertion("res.status", AssertOp.EQ, "200", true));

        List<AssertionResult> results = engine.evaluate(assertions, resp, new VariableStore());
        assertEquals(1, results.size());
        assertTrue(results.get(0).passed());
    }

    @Test
    @Order(41)
    void assertions_bodyField() {
        AssertionEngine engine = new AssertionEngine(new Interpolator());
        ResponseData resp = new ResponseData(200, "OK", java.util.Map.of(), "{\"name\":\"John\",\"age\":30}",
                new byte[0], 100, 50);

        List<Assertion> assertions = List.of(new Assertion("res.body.name", AssertOp.EQ, "John", true),
                new Assertion("res.body.age", AssertOp.GT, "18", true),
                new Assertion("res.body.name", AssertOp.CONTAINS, "oh", true));

        List<AssertionResult> results = engine.evaluate(assertions, resp, new VariableStore());
        assertEquals(3, results.size());
        assertTrue(results.stream().allMatch(AssertionResult::passed));
    }

    @Test
    @Order(42)
    void assertions_failCase() {
        AssertionEngine engine = new AssertionEngine(new Interpolator());
        ResponseData resp = new ResponseData(404, "Not Found", java.util.Map.of(), "{}", new byte[0], 100, 2);

        List<Assertion> assertions = List.of(new Assertion("res.status", AssertOp.EQ, "200", true));

        List<AssertionResult> results = engine.evaluate(assertions, resp, new VariableStore());
        assertEquals(1, results.size());
        assertFalse(results.get(0).passed());
    }

    @Test
    @Order(43)
    void assertions_unaryOperators() {
        AssertionEngine engine = new AssertionEngine(new Interpolator());
        ResponseData resp = new ResponseData(200, "OK", java.util.Map.of(),
                "{\"name\":\"John\",\"items\":[1,2,3],\"active\":true}", new byte[0], 100, 50);

        List<Assertion> assertions = List.of(new Assertion("res.body.name", AssertOp.IS_DEFINED, null, true),
                new Assertion("res.body.name", AssertOp.IS_STRING, null, true),
                new Assertion("res.body.items", AssertOp.IS_ARRAY, null, true),
                new Assertion("res.body", AssertOp.IS_JSON, null, true));

        List<AssertionResult> results = engine.evaluate(assertions, resp, new VariableStore());
        assertTrue(results.stream().allMatch(AssertionResult::passed));
    }

    @Test
    @Order(44)
    void assertions_responseTime() {
        AssertionEngine engine = new AssertionEngine(new Interpolator());
        ResponseData resp = new ResponseData(200, "OK", java.util.Map.of(), "{}", new byte[0], 150, 2);

        List<Assertion> assertions = List.of(new Assertion("res.responseTime", AssertOp.LT, "2000", true),
                new Assertion("res.responseTime", AssertOp.GT, "50", true));

        List<AssertionResult> results = engine.evaluate(assertions, resp, new VariableStore());
        assertTrue(results.stream().allMatch(AssertionResult::passed));
    }

    @Test
    @Order(45)
    void assertions_disabledSkipped() {
        AssertionEngine engine = new AssertionEngine(new Interpolator());
        ResponseData resp = new ResponseData(500, "", java.util.Map.of(), "{}", new byte[0], 100, 2);

        List<Assertion> assertions = List.of(new Assertion("res.status", AssertOp.EQ, "200", false));

        List<AssertionResult> results = engine.evaluate(assertions, resp, new VariableStore());
        assertTrue(results.isEmpty());
    }

    // =====================================================
    // 6. Curl Importer
    // =====================================================

    @Test
    @Order(50)
    void curlImporter_simpleGet() {
        CurlImporter importer = new CurlImporter();
        RequestItem item = importer.importCurl("curl https://api.example.com/users");

        assertEquals("GET", item.request().method());
        assertEquals("https://api.example.com/users", item.request().url());
    }

    @Test
    @Order(51)
    void curlImporter_postWithJson() {
        CurlImporter importer = new CurlImporter();
        RequestItem item = importer.importCurl(
                "curl -X POST -H 'Content-Type: application/json' -d '{\"name\":\"John\"}' https://api.example.com/users");

        assertEquals("POST", item.request().method());
        assertInstanceOf(BodyConfig.Json.class, item.request().body());
        assertEquals("{\"name\":\"John\"}", ((BodyConfig.Json) item.request().body()).content());
    }

    @Test
    @Order(52)
    void curlImporter_basicAuth() {
        CurlImporter importer = new CurlImporter();
        RequestItem item = importer.importCurl("curl -u admin:secret https://api.example.com/admin");

        assertInstanceOf(AuthConfig.Basic.class, item.request().auth());
        AuthConfig.Basic basic = (AuthConfig.Basic) item.request().auth();
        assertEquals("admin", basic.username());
        assertEquals("secret", basic.password());
    }

    @Test
    @Order(53)
    void curlImporter_queryParams() {
        CurlImporter importer = new CurlImporter();
        RequestItem item = importer.importCurl("curl 'https://api.example.com/users?page=1&limit=50'");

        assertEquals("https://api.example.com/users", item.request().url());
        assertEquals(2, item.request().params().query().size());
        assertEquals("page", item.request().params().query().get(0).name());
        assertEquals("1", item.request().params().query().get(0).value());
    }

    @Test
    @Order(54)
    void curlImporter_multilineWithBackslash() {
        CurlImporter importer = new CurlImporter();
        RequestItem item = importer.importCurl("""
                curl -X DELETE \
                  -H 'Authorization: Bearer token123' \
                  https://api.example.com/users/me""");

        assertEquals("DELETE", item.request().method());
        assertTrue(item.request().headers().stream()
                .anyMatch(h -> h.name().equals("Authorization") && h.value().equals("Bearer token123")));
    }

    // =====================================================
    // 7. AssertOp
    // =====================================================

    @Test
    @Order(60)
    void assertOp_fromSymbol() {
        assertEquals(AssertOp.EQ, AssertOp.fromSymbol("eq"));
        assertEquals(AssertOp.NEQ, AssertOp.fromSymbol("neq"));
        assertEquals(AssertOp.CONTAINS, AssertOp.fromSymbol("contains"));
        assertEquals(AssertOp.IS_DEFINED, AssertOp.fromSymbol("isDefined"));
        assertThrows(IllegalArgumentException.class, () -> AssertOp.fromSymbol("nonexistent"));
    }

    @Test
    @Order(61)
    void assertOp_unaryCheck() {
        assertTrue(AssertOp.IS_NULL.isUnary());
        assertTrue(AssertOp.IS_DEFINED.isUnary());
        assertFalse(AssertOp.EQ.isUnary());
        assertFalse(AssertOp.CONTAINS.isUnary());
    }

    // =====================================================
    // 8. Model Records
    // =====================================================

    @Test
    @Order(70)
    void authConfig_sealedHierarchy() {
        AuthConfig none = new AuthConfig.None();
        assertEquals("none", none.mode());

        AuthConfig bearer = new AuthConfig.Bearer("token");
        assertEquals("bearer", bearer.mode());

        AuthConfig basic = new AuthConfig.Basic("user", "pass");
        assertEquals("basic", basic.mode());

        AuthConfig inherit = new AuthConfig.Inherit();
        assertEquals("inherit", inherit.mode());
    }

    @Test
    @Order(71)
    void bodyConfig_sealedHierarchy() {
        BodyConfig none = new BodyConfig.None();
        assertEquals("none", none.mode());

        BodyConfig json = new BodyConfig.Json("{\"key\":\"value\"}");
        assertEquals("json", json.mode());

        BodyConfig form = new BodyConfig.FormUrlEncoded(List.of(Param.query("key", "value")));
        assertEquals("formUrlEncoded", form.mode());
    }

    @Test
    @Order(72)
    void collection_structure() {
        RequestItem req = new RequestItem("r1", "get-users", RequestMeta.http("get-users", 1),
                simpleRequest("GET", "{{baseUrl}}/users"), VarsDef.empty(), List.of(), "");

        Folder folder = new Folder("f1", "users", List.of(req), RootConfig.empty());

        Collection collection = new Collection("c1", "test-api", "1", List.of(), List.of(folder), RootConfig.empty(),
                CollectionSettings.defaults());

        assertEquals("test-api", collection.name());
        assertEquals(1, collection.items().size());
        assertInstanceOf(Folder.class, collection.items().get(0));
    }

    // =====================================================
    // 9. E2E: Collection Runner with mock server
    // =====================================================

    @Test
    @Order(80)
    void collectionRunner_e2e() throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/api/login", exchange -> {
            byte[] body = "{\"token\":\"jwt-abc-123\",\"userId\":\"u1\"}".getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, body.length);
            exchange.getResponseBody().write(body);
            exchange.close();
        });
        server.createContext("/api/me", exchange -> {
            String auth = exchange.getRequestHeaders().getFirst("Authorization");
            if (auth != null && auth.contains("jwt-abc-123")) {
                byte[] body = "{\"name\":\"John\",\"email\":\"john@test.com\"}".getBytes(StandardCharsets.UTF_8);
                exchange.getResponseHeaders().add("Content-Type", "application/json");
                exchange.sendResponseHeaders(200, body.length);
                exchange.getResponseBody().write(body);
            } else {
                byte[] body = "{\"error\":\"unauthorized\"}".getBytes(StandardCharsets.UTF_8);
                exchange.sendResponseHeaders(401, body.length);
                exchange.getResponseBody().write(body);
            }
            exchange.close();
        });
        server.start();
        int port = server.getAddress().getPort();

        try {
            String baseUrl = "http://127.0.0.1:" + port;

            RequestItem loginReq = new RequestItem("r1", "login", RequestMeta.http("login", 1),
                    new HttpRequestDef("POST", baseUrl + "/api/login", ParamsDef.empty(),
                            List.of(Header.of("Content-Type", "application/json")), new AuthConfig.None(),
                            new BodyConfig.Json("{\"email\":\"test@test.com\",\"password\":\"pass\"}"),
                            RequestSettings.defaults()),
                    new VarsDef(List.of(), List.of(new VarsDef.VarEntry("token", "res.body.token"))),
                    List.of(new Assertion("res.status", AssertOp.EQ, "200", true),
                            new Assertion("res.body.token", AssertOp.IS_DEFINED, null, true)),
                    "Login and extract token");

            RequestItem meReq = new RequestItem("r2", "get-me", RequestMeta.http("get-me", 2),
                    new HttpRequestDef("GET", baseUrl + "/api/me", ParamsDef.empty(),
                            List.of(Header.of("Authorization", "Bearer {{token}}")), new AuthConfig.None(),
                            new BodyConfig.None(), RequestSettings.defaults()),
                    VarsDef.empty(),
                    List.of(new Assertion("res.status", AssertOp.EQ, "200", true),
                            new Assertion("res.body.name", AssertOp.EQ, "John", true)),
                    "Get profile with extracted token");

            Folder authFolder = new Folder("f1", "auth", List.of(loginReq), RootConfig.empty());
            Folder usersFolder = new Folder("f2", "users", List.of(meReq), RootConfig.empty());

            Collection collection = new Collection("c1", "E2E Test", "1", List.of(), List.of(authFolder, usersFolder),
                    RootConfig.empty(), CollectionSettings.defaults());

            Interpolator interpolator = new Interpolator();
            AuthInjectorRegistry authRegistry = new AuthInjectorRegistry();
            AssertionEngine assertionEngine = new AssertionEngine(interpolator);
            RequestExecutor executor = new RequestExecutor(HttpClient.newHttpClient(), interpolator, authRegistry,
                    assertionEngine);
            CollectionRunner runner = new CollectionRunner(executor);

            List<String> logs = new ArrayList<>();
            RunResult result = runner.run(collection, null, logs::add);

            assertEquals(2, result.results().size());

            RequestResult loginResult = result.results().get(0);
            assertTrue(loginResult.passed(), "Login should pass: " + logs);
            assertEquals(200, loginResult.response().status());

            RequestResult meResult = result.results().get(1);
            assertTrue(meResult.passed(), "Get-me should pass (token chained): " + logs);
            assertEquals(200, meResult.response().status());
            assertTrue(meResult.response().body().contains("John"));

            assertEquals(2, result.summary().passed());
            assertEquals(0, result.summary().failed());
        } finally {
            server.stop(0);
        }
    }

    // =====================================================
    // Helpers
    // =====================================================

    private HttpRequestDef simpleRequest(String method, String url) {
        return new HttpRequestDef(method, url, ParamsDef.empty(), new ArrayList<>(), new AuthConfig.None(),
                new BodyConfig.None(), RequestSettings.defaults());
    }
}
