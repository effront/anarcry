package gg.effront.anarcry.harness;

import com.sun.net.httpserver.HttpServer;
import gg.effront.anarcry.model.Finding;
import gg.effront.anarcry.model.Severity;
import gg.effront.anarcry.scanner.ScanContext;
import gg.effront.anarcry.scanner.util.BrowserTransport;
import gg.effront.anarcry.scanner.web.sqli.SqlInjectionModule;
import org.junit.jupiter.api.*;

import java.lang.reflect.Constructor;
import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

/**
 * End-to-end tests for SqlInjectionModule using local mock HTTP servers.
 */
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class SqlInjectionModuleTest {

    // ─────────────────────────────────────────
    // Error-based detection
    // ─────────────────────────────────────────

    @Test
    @Order(1)
    void sqliErrorBasedDetectedCritical() throws Exception {
        // Vulnerable server: when query contains a single-quote, returns a MySQL error
        // message
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", exchange -> {
            String raw = exchange.getRequestURI().getRawQuery();
            byte[] body;
            if (raw != null && (raw.contains("%27") || raw.contains("'"))) {
                // Simulates MySQL error exposure
                body = "You have an error in your SQL syntax; check the manual near '' at line 1".getBytes();
            } else {
                body = "ok".getBytes();
            }
            exchange.sendResponseHeaders(200, body.length);
            exchange.getResponseBody().write(body);
            exchange.getResponseBody().close();
        });
        server.start();
        int port = server.getAddress().getPort();
        try {
            ScanContext ctx = new ScanContext("http://127.0.0.1:" + port, "", Set.of("SQLi"));
            List<Finding> findings = new SqlInjectionModule().scan(ctx, msg -> System.out.println("[SQLi] " + msg));
            assertFalse(findings.isEmpty(), "Servidor com erro SQL deve gerar finding");
            assertTrue(
                    findings.stream().anyMatch(
                            f -> f.severity() == Severity.CRITICAL && f.title().toLowerCase().contains("sql")),
                    "Error-based SQLi deve gerar CRITICAL");
            // CWE-89 must be set
            assertTrue(findings.stream().anyMatch(f -> "CWE-89".equals(f.cweId())),
                    "CWE-89 deve estar presente no finding");
        } finally {
            server.stop(0);
        }
    }

    @Test
    @Order(2)
    void sqliCleanServerNoFinding() throws Exception {
        // Safe server: always returns "ok" with status 200, no SQL errors
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", exchange -> {
            byte[] body = "ok".getBytes();
            exchange.sendResponseHeaders(200, body.length);
            exchange.getResponseBody().write(body);
            exchange.getResponseBody().close();
        });
        server.start();
        int port = server.getAddress().getPort();
        try {
            ScanContext ctx = new ScanContext("http://127.0.0.1:" + port, "", Set.of("SQLi"));
            List<Finding> findings = new SqlInjectionModule().scan(ctx, msg -> {
            });
            assertTrue(findings.isEmpty(), "Servidor limpo NÃO deve gerar SQLi findings, gerou: "
                    + findings.stream().map(f -> f.module() + ":" + f.title()).reduce("", (a, b) -> a + ", " + b));
        } finally {
            server.stop(0);
        }
    }

    @Test
    @Order(3)
    void sqliErrorBaselineSqlSkipsParam() throws Exception {
        // Anti-FP: server always returns SQL-looking text even on benign request
        // → module must skip params where baseline itself matches the error pattern
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", exchange -> {
            // Always returns SQL error-like text — this is the baseline too
            byte[] body = "You have an error in your SQL syntax near 'test'".getBytes();
            exchange.sendResponseHeaders(200, body.length);
            exchange.getResponseBody().write(body);
            exchange.getResponseBody().close();
        });
        server.start();
        int port = server.getAddress().getPort();
        try {
            ScanContext ctx = new ScanContext("http://127.0.0.1:" + port, "", Set.of("SQLi"));
            List<Finding> findings = new SqlInjectionModule().scan(ctx, msg -> {
            });
            // Because baseline matches, the module should NOT generate error-based findings
            // (time-based could still run but will not trigger since server is instant)
            assertTrue(findings.stream().noneMatch(f -> f.title().contains("Error-Based")),
                    "Baseline com SQL error NÃO deve gerar error-based finding (anti-FP)");
        } finally {
            server.stop(0);
        }
    }

    @Test
    @Order(4)
    void sqli400ResponseNotFlagged() throws Exception {
        // Anti-FP: server returns 400 on single-quote (input validation), not a real
        // SQLi
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", exchange -> {
            String raw = exchange.getRequestURI().getRawQuery();
            if (raw != null && (raw.contains("%27") || raw.contains("'"))) {
                byte[] body = "Invalid input".getBytes();
                exchange.sendResponseHeaders(400, body.length);
                exchange.getResponseBody().write(body);
            } else {
                byte[] body = "ok".getBytes();
                exchange.sendResponseHeaders(200, body.length);
                exchange.getResponseBody().write(body);
            }
            exchange.getResponseBody().close();
        });
        server.start();
        int port = server.getAddress().getPort();
        try {
            ScanContext ctx = new ScanContext("http://127.0.0.1:" + port, "", Set.of("SQLi"));
            List<Finding> findings = new SqlInjectionModule().scan(ctx, msg -> {
            });
            assertTrue(findings.stream().noneMatch(f -> f.title().contains("Error-Based")),
                    "400 Bad Request sem SQL error NÃO deve gerar finding error-based");
        } finally {
            server.stop(0);
        }
    }

    @Test
    @Order(5)
    void sqliModuleId() {
        assertEquals("SQLi", new SqlInjectionModule().id(), "id() deve retornar 'SQLi'");
    }

    @Test
    @Order(6)
    void sqliCweRegistryEntry() {
        // Verify the CWE registry has the SQLi entry
        assertEquals("CWE-89", gg.effront.anarcry.model.CweRegistry.cweId("SQLi"),
                "CweRegistry deve ter CWE-89 para SQLi");
        assertTrue(gg.effront.anarcry.model.CweRegistry.cvssVector("SQLi").startsWith("AV:N"),
                "CVSS vector para SQLi deve ser network-based");
    }

    // -------------------------------------------------
    // BrowserTransport interaction: Phase 2 skip
    // -------------------------------------------------

    private static BrowserTransport stubBrowserTransport() throws Exception {
        Constructor<?> ctor = BrowserTransport.class.getDeclaredConstructors()[0];
        ctor.setAccessible(true);
        return (BrowserTransport) ctor.newInstance(null, null, null, "stub.local");
    }

    @Test
    @Order(7)
    void sqliPhase2SkippedWhenBrowserTransportActive() throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", exchange -> {
            byte[] body = "ok".getBytes();
            exchange.sendResponseHeaders(200, body.length);
            exchange.getResponseBody().write(body);
            exchange.getResponseBody().close();
        });
        server.start();
        int port = server.getAddress().getPort();
        try {
            ScanContext ctx = new ScanContext("http://127.0.0.1:" + port, "", Set.of("SQLi"));
            ctx.wafState().setBrowserTransport(stubBrowserTransport());

            List<String> logs = new ArrayList<>();
            List<Finding> findings = new SqlInjectionModule().scan(ctx, logs::add);

            assertTrue(logs.stream().anyMatch(l -> l.contains("BrowserTransport") && l.contains("time-based")),
                    "Deve logar que phase 2 (time-based) esta desabilitada com BrowserTransport");
            assertTrue(findings.isEmpty(), "Clean server com BT ativo nao deve gerar findings");
        } finally {
            server.stop(0);
        }
    }

    @Test
    @Order(8)
    void sqliPhase1WorksWithBrowserTransportActive() throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", exchange -> {
            String raw = exchange.getRequestURI().getRawQuery();
            byte[] body;
            if (raw != null && (raw.contains("%27") || raw.contains("'"))) {
                body = "You have an error in your SQL syntax; check the manual near '' at line 1".getBytes();
            } else {
                body = "ok".getBytes();
            }
            exchange.sendResponseHeaders(200, body.length);
            exchange.getResponseBody().write(body);
            exchange.getResponseBody().close();
        });
        server.start();
        int port = server.getAddress().getPort();
        try {
            ScanContext ctx = new ScanContext("http://127.0.0.1:" + port, "", Set.of("SQLi"));
            ctx.wafState().setBrowserTransport(stubBrowserTransport());

            List<String> logs = new ArrayList<>();
            List<Finding> findings = new SqlInjectionModule().scan(ctx, logs::add);

            assertTrue(logs.stream().anyMatch(l -> l.contains("BrowserTransport")), "Phase 2 deve estar desabilitada");
            assertFalse(findings.isEmpty(), "Phase 1 (error-based) deve funcionar mesmo com BT ativo");
            assertTrue(
                    findings.stream().anyMatch(
                            f -> f.severity() == Severity.CRITICAL && f.title().toLowerCase().contains("sql")),
                    "Error-based SQLi deve gerar CRITICAL mesmo com BT");
        } finally {
            server.stop(0);
        }
    }
}
