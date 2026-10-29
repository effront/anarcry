package gg.effront.anarcry.harness;

import static org.junit.jupiter.api.Assertions.*;

import com.sun.net.httpserver.HttpServer;
import gg.effront.anarcry.model.Finding;
import gg.effront.anarcry.model.Severity;
import gg.effront.anarcry.scanner.ScanContext;
import gg.effront.anarcry.scanner.crypto.headers.HeadersModule;
import gg.effront.anarcry.scanner.util.HttpClientFactory;
import gg.effront.anarcry.scanner.util.WafEvasion;
import gg.effront.anarcry.scanner.util.WafState;
import gg.effront.anarcry.scanner.web.sqli.SqlInjectionModule;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;

/**
 * Integration tests for WAF evasion using a mock WAF server. Tests verify that
 * evasion strategies bypass basic WAF string-matching rules.
 */
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class WafHarnessTest {

    /**
     * Creates a mock WAF HTTP server that blocks requests containing known attack
     * patterns in query string or body. Unblocked requests get the decoded query or
     * body echoed back.
     */
    private static HttpServer createMockWafServer() throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", exchange -> {
            String query = exchange.getRequestURI().getRawQuery();
            String body = new String(exchange.getRequestBody().readAllBytes());
            String serverHeader = "cloudflare";

            // Decode query once (real WAFs inspect decoded params)
            String decodedQuery = "";
            if (query != null) {
                try {
                    decodedQuery = java.net.URLDecoder.decode(query, "UTF-8");
                } catch (Exception e) {
                    decodedQuery = query;
                }
            }

            // WAF logic: block if decoded query or body contains known attack patterns
            boolean blocked = false;
            String combined = decodedQuery + body;
            if (combined.contains("<script>") || combined.contains("SELECT") || combined.contains("../etc/passwd")
                    || combined.contains("{{7*7")) {
                blocked = true;
            }

            if (blocked) {
                exchange.getResponseHeaders().set("Server", serverHeader);
                byte[] resp = "Access Denied".getBytes();
                exchange.sendResponseHeaders(403, resp.length);
                exchange.getResponseBody().write(resp);
            } else {
                // Echo back decoded params (simulates vulnerable app behind WAF)
                String echoSource = !decodedQuery.isEmpty() ? decodedQuery : body;
                byte[] resp = echoSource.getBytes();
                exchange.getResponseHeaders().set("Server", serverHeader);
                exchange.sendResponseHeaders(200, resp.length);
                exchange.getResponseBody().write(resp);
            }
            exchange.getResponseBody().close();
        });
        return server;
    }

    // -------------------------------------------------
    // 1. Mock WAF blocks raw attack payload
    // -------------------------------------------------

    @Test
    @Order(1)
    void wafBlocksNormalPayload() throws Exception {
        HttpServer server = createMockWafServer();
        server.start();
        int port = server.getAddress().getPort();
        try {
            HttpClient hc = HttpClientFactory.http2();
            HttpRequest req = HttpRequest.newBuilder()
                    .uri(URI.create("http://127.0.0.1:" + port + "/?q=%3Cscript%3Ealert(1)%3C/script%3E")).GET()
                    .build();
            HttpResponse<String> resp = hc.send(req, HttpResponse.BodyHandlers.ofString());
            assertEquals(403, resp.statusCode(), "WAF deve bloquear payload <script> com 403");
            assertTrue(resp.body().contains("Access Denied"), "Body deve conter 'Access Denied' quando bloqueado");
        } finally {
            server.stop(0);
        }
    }

    // -------------------------------------------------
    // 2. WAF passes double-encoded payload
    // -------------------------------------------------

    @Test
    @Order(2)
    void wafPassesDoubleEncodedPayload() throws Exception {
        HttpServer server = createMockWafServer();
        server.start();
        int port = server.getAddress().getPort();
        try {
            HttpClient hc = HttpClientFactory.http2();
            String encoded = WafEvasion.doubleEncode("<script>alert(1)</script>");
            HttpRequest req = HttpRequest.newBuilder().uri(URI.create("http://127.0.0.1:" + port + "/?q=" + encoded))
                    .GET().build();
            HttpResponse<String> resp = hc.send(req, HttpResponse.BodyHandlers.ofString());
            assertEquals(200, resp.statusCode(),
                    "WAF nao deve bloquear payload double-encoded, got " + resp.statusCode());
        } finally {
            server.stop(0);
        }
    }

    // -------------------------------------------------
    // 3. WAF passes case-mutated payload
    // -------------------------------------------------

    @Test
    @Order(3)
    void wafPassesCaseMutatedPayload() throws Exception {
        HttpServer server = createMockWafServer();
        server.start();
        int port = server.getAddress().getPort();
        try {
            HttpClient hc = HttpClientFactory.http2();
            String mutated = WafEvasion.mutateCase("SELECT * FROM users");
            // The mock WAF checks for exact "SELECT" -- case mutation should bypass it
            HttpRequest req = HttpRequest.newBuilder()
                    .uri(URI.create("http://127.0.0.1:" + port + "/?q=" + java.net.URLEncoder.encode(mutated, "UTF-8")))
                    .GET().build();
            HttpResponse<String> resp = hc.send(req, HttpResponse.BodyHandlers.ofString());
            assertEquals(200, resp.statusCode(),
                    "WAF nao deve bloquear payload case-mutated '" + mutated + "', got " + resp.statusCode());
        } finally {
            server.stop(0);
        }
    }

    // -------------------------------------------------
    // 4. WafState is shared and visible across threads
    // -------------------------------------------------

    @Test
    @Order(4)
    void wafStateSharedAcrossModules() throws Exception {
        WafState state = new WafState();
        CountDownLatch latch = new CountDownLatch(1);
        AtomicReference<Boolean> visibleFromOtherThread = new AtomicReference<>(false);
        AtomicReference<String> productFromOtherThread = new AtomicReference<>("");

        // Mark WAF detected from main thread
        state.markWafDetected("cloudflare");

        // Read from another thread
        Thread reader = new Thread(() -> {
            visibleFromOtherThread.set(state.isWafDetected());
            productFromOtherThread.set(state.wafProduct());
            latch.countDown();
        });
        reader.start();
        assertTrue(latch.await(5, TimeUnit.SECONDS), "Thread deve completar em 5s");

        assertTrue(visibleFromOtherThread.get(), "WafState.isWafDetected() deve ser visivel de outra thread");
        assertEquals("cloudflare", productFromOtherThread.get(),
                "WafState.wafProduct() deve ser visivel de outra thread");
    }

    // -------------------------------------------------
    // 5. probeStrategies finds an effective strategy
    // -------------------------------------------------

    @Test
    @Order(5)
    void probeStrategiesFindsEffective() throws Exception {
        HttpServer server = createMockWafServer();
        server.start();
        int port = server.getAddress().getPort();
        try {
            ScanContext ctx = new ScanContext("http://127.0.0.1:" + port, "", Set.of());
            HttpClient hc = HttpClientFactory.http2();
            WafEvasion.Strategy strategy = WafEvasion.probeStrategies(ctx, hc, "http://127.0.0.1:" + port, "test",
                    msg -> {
                    });
            assertNotNull(strategy, "probeStrategies deve encontrar uma estrategia efetiva contra o mock WAF");
            // DOUBLE_ENCODE should be found first since mock WAF only does exact string
            // matching
            assertEquals(WafEvasion.Strategy.DOUBLE_ENCODE, strategy,
                    "DOUBLE_ENCODE deve ser a primeira estrategia efetiva encontrada");
        } finally {
            server.stop(0);
        }
    }

    // -------------------------------------------------
    // 6. Full evasion flow integration
    // -------------------------------------------------

    @Test
    @Order(6)
    void evasionPayloadIntegration() throws Exception {
        HttpServer server = createMockWafServer();
        server.start();
        int port = server.getAddress().getPort();
        try {
            // Step 1: verify WAF blocks raw payload
            HttpClient hc = HttpClientFactory.http2();
            HttpRequest rawReq = HttpRequest.newBuilder()
                    .uri(URI.create("http://127.0.0.1:" + port + "/?q=%3Cscript%3Ealert(1)%3C/script%3E")).GET()
                    .build();
            HttpResponse<String> rawResp = hc.send(rawReq, HttpResponse.BodyHandlers.ofString());
            assertEquals(403, rawResp.statusCode(), "Raw payload deve ser bloqueado");

            // Step 2: detect WAF from the response
            String serverHdr = rawResp.headers().firstValue("Server").orElse(null);
            assertTrue(WafEvasion.isWafBlocked(rawResp.statusCode(), serverHdr, rawResp.body()),
                    "isWafBlocked deve retornar true para resposta do mock WAF");
            String product = WafEvasion.detectWafProduct(serverHdr);
            assertFalse(product.isEmpty(), "Deve detectar produto WAF do header Server");

            // Step 3: probe strategies
            ScanContext ctx = new ScanContext("http://127.0.0.1:" + port, "", Set.of());
            ctx.wafState().markWafDetected(product);
            WafEvasion.Strategy strategy = WafEvasion.probeStrategies(ctx, hc, "http://127.0.0.1:" + port, "test",
                    msg -> {
                    });
            assertNotNull(strategy, "Deve encontrar estrategia efetiva");
            ctx.wafState().markEffectiveStrategy(strategy);

            // Step 4: use evasionPayload to transform and verify bypass
            String payload = "<script>alert(1)</script>";
            String evaded = WafEvasion.evasionPayload(ctx, payload);
            assertNotEquals(payload, evaded, "Payload deve ser transformado");

            HttpRequest evadedReq = HttpRequest.newBuilder()
                    .uri(URI.create("http://127.0.0.1:" + port + "/?q=" + evaded)).GET().build();
            HttpResponse<String> evadedResp = hc.send(evadedReq, HttpResponse.BodyHandlers.ofString());
            assertEquals(200, evadedResp.statusCode(),
                    "Payload transformado deve passar pelo WAF, got " + evadedResp.statusCode());
        } finally {
            server.stop(0);
        }
    }

    // -------------------------------------------------
    // 7. HeadersModule detects WAF and sets wafState
    // -------------------------------------------------

    @Test
    @Order(7)
    void headersModuleDetectsWafAndSetsState() throws Exception {
        // Server that returns 403 + Server: cloudflare (simulates WAF blocking)
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", exchange -> {
            exchange.getResponseHeaders().set("Server", "cloudflare");
            byte[] body = "Access Denied".getBytes();
            exchange.sendResponseHeaders(403, body.length);
            exchange.getResponseBody().write(body);
            exchange.getResponseBody().close();
        });
        server.start();
        int port = server.getAddress().getPort();
        try {
            ScanContext ctx = new ScanContext("http://127.0.0.1:" + port, "", Set.of("Headers"));
            List<Finding> findings = new HeadersModule().scan(ctx, msg -> System.out.println("[Headers-WAF] " + msg));

            // HeadersModule should produce findings (missing security headers)
            // NOTE: this test assumes HeadersModule will be updated to call
            // ctx.wafState().markWafDetected() when it sees a WAF server header.
            // If that integration is not done yet, the wafState assertion will fail --
            // expected.
            assertTrue(ctx.wafState().isWafDetected(),
                    "HeadersModule deve marcar wafState como WAF detectado ao ver Server: cloudflare");
            assertEquals("cloudflare", ctx.wafState().wafProduct(), "wafProduct deve ser 'cloudflare'");
        } finally {
            server.stop(0);
        }
    }

    // -------------------------------------------------
    // 8. SQLi module bypasses WAF with evasion
    // -------------------------------------------------

    @Test
    @Order(8)
    void sqliModuleBypassesWafWithEvasion() throws Exception {
        // Mock WAF server that blocks raw SQL keywords but returns SQL error
        // on double-encoded payloads (simulates a vulnerable app behind a WAF)
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", exchange -> {
            String query = exchange.getRequestURI().getRawQuery();
            String combined = query != null ? query : "";
            String serverHeader = "cloudflare";

            // WAF: block raw SQL keywords
            if (combined.contains("'") || combined.contains("SELECT") || combined.contains("UNION")
                    || combined.contains("OR+1")) {
                exchange.getResponseHeaders().set("Server", serverHeader);
                byte[] resp = "Access Denied".getBytes();
                exchange.sendResponseHeaders(403, resp.length);
                exchange.getResponseBody().write(resp);
                exchange.getResponseBody().close();
                return;
            }

            // If double-encoded single-quote (%2527) is present, simulate SQL error
            // (the app decodes once, WAF already passed it)
            if (combined.contains("%2527") || combined.contains("%25")) {
                byte[] resp = "You have an error in your SQL syntax; check the manual near '' at line 1".getBytes();
                exchange.getResponseHeaders().set("Server", serverHeader);
                exchange.sendResponseHeaders(200, resp.length);
                exchange.getResponseBody().write(resp);
                exchange.getResponseBody().close();
                return;
            }

            // Normal response
            byte[] resp = "ok".getBytes();
            exchange.getResponseHeaders().set("Server", serverHeader);
            exchange.sendResponseHeaders(200, resp.length);
            exchange.getResponseBody().write(resp);
            exchange.getResponseBody().close();
        });
        server.start();
        int port = server.getAddress().getPort();
        try {
            ScanContext ctx = new ScanContext("http://127.0.0.1:" + port, "", Set.of("SQLi"));
            // Pre-configure WAF state (as if HeadersModule or probe already ran)
            ctx.wafState().markWafDetected("cloudflare");
            ctx.wafState().markEffectiveStrategy(WafEvasion.Strategy.DOUBLE_ENCODE);

            // NOTE: this test assumes SqlInjectionModule will be updated to use
            // WafEvasion.evasionPayload() for payload transformation.
            // If that integration is not done yet, this test will fail -- expected
            // (test-first).
            List<Finding> findings = new SqlInjectionModule().scan(ctx, msg -> System.out.println("[SQLi-WAF] " + msg));

            assertFalse(findings.isEmpty(),
                    "SQLi module deve detectar SQL injection mesmo atras de WAF usando evasion");
            assertTrue(
                    findings.stream().anyMatch(
                            f -> f.severity() == Severity.CRITICAL && f.title().toLowerCase().contains("sql")),
                    "Error-based SQLi com evasion deve gerar CRITICAL");
            assertTrue(findings.stream().anyMatch(f -> "CWE-89".equals(f.cweId())),
                    "CWE-89 deve estar presente no finding");
        } finally {
            server.stop(0);
        }
    }
}
