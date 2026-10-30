package gg.effront.anarcry.harness;

import static org.junit.jupiter.api.Assertions.*;

import com.sun.net.httpserver.HttpServer;
import gg.effront.anarcry.model.Finding;
import gg.effront.anarcry.model.Severity;
import gg.effront.anarcry.scanner.ScanContext;
import gg.effront.anarcry.scanner.util.BrowserTransport;
import gg.effront.anarcry.scanner.web.cmdinject.CommandInjectionModule;

import java.lang.reflect.Constructor;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.function.Consumer;

import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;

@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class CommandInjectionModuleTest {

    private static BrowserTransport stubBrowserTransport() throws Exception {
        Constructor<?> ctor = BrowserTransport.class.getDeclaredConstructors()[0];
        ctor.setAccessible(true);
        return (BrowserTransport) ctor.newInstance(null, null, null, "stub.local");
    }

    private static HttpServer vulnerableServer() throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", exchange -> {
            String query = exchange.getRequestURI().getRawQuery();
            byte[] body;
            if (query != null) {
                String decoded = URLDecoder.decode(query, StandardCharsets.UTF_8);
                if (decoded.contains("; id") || decoded.contains("| id") || decoded.contains("|| id")
                        || decoded.contains("&& id") || decoded.contains("$(id)")) {
                    body = "uid=0(root) gid=0(root) groups=0(root)".getBytes();
                } else {
                    body = "ok".getBytes();
                }
            } else {
                body = "ok".getBytes();
            }
            exchange.sendResponseHeaders(200, body.length);
            exchange.getResponseBody().write(body);
            exchange.getResponseBody().close();
        });
        return server;
    }

    private static HttpServer cleanServer() throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", exchange -> {
            byte[] body = "ok".getBytes();
            exchange.sendResponseHeaders(200, body.length);
            exchange.getResponseBody().write(body);
            exchange.getResponseBody().close();
        });
        return server;
    }

    // -------------------------------------------------
    // Phase 1: active output-based detection
    // -------------------------------------------------

    @Test
    @Order(1)
    void cmdiActiveDetectedCritical() throws Exception {
        HttpServer server = vulnerableServer();
        server.start();
        int port = server.getAddress().getPort();
        try {
            ScanContext ctx = new ScanContext("http://127.0.0.1:" + port, "", Set.of("CmdInjection"));
            List<Finding> findings = new CommandInjectionModule().scan(ctx, msg -> System.out.println("[CmdI] " + msg));
            assertFalse(findings.isEmpty(), "Servidor com saida RCE deve gerar finding");
            assertTrue(
                    findings.stream().anyMatch(
                            f -> f.severity() == Severity.CRITICAL && f.title().toLowerCase().contains("command")),
                    "Active command injection deve gerar CRITICAL");
            assertTrue(findings.stream().anyMatch(f -> "CWE-78".equals(f.cweId())),
                    "CWE-78 deve estar presente no finding");
        } finally {
            server.stop(0);
        }
    }

    @Test
    @Order(2)
    void cmdiCleanServerNoFinding() throws Exception {
        HttpServer server = cleanServer();
        server.start();
        int port = server.getAddress().getPort();
        try {
            ScanContext ctx = new ScanContext("http://127.0.0.1:" + port, "", Set.of("CmdInjection"));
            List<Finding> findings = new CommandInjectionModule().scan(ctx, msg -> {
            });
            assertTrue(findings.isEmpty(), "Servidor limpo NAO deve gerar CmdInjection findings");
        } finally {
            server.stop(0);
        }
    }

    // -------------------------------------------------
    // Anti-false-positive
    // -------------------------------------------------

    @Test
    @Order(3)
    void cmdiBaselineRceSkipsParam() throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", exchange -> {
            byte[] body = "uid=1000(user) gid=1000(user)".getBytes();
            exchange.sendResponseHeaders(200, body.length);
            exchange.getResponseBody().write(body);
            exchange.getResponseBody().close();
        });
        server.start();
        int port = server.getAddress().getPort();
        try {
            ScanContext ctx = new ScanContext("http://127.0.0.1:" + port, "", Set.of("CmdInjection"));
            List<String> logs = new ArrayList<>();
            List<Finding> findings = new CommandInjectionModule().scan(ctx, logs::add);
            assertTrue(findings.stream().noneMatch(f -> f.title().contains("confirmada")),
                    "Baseline com padrao RCE NAO deve gerar active finding (anti-FP)");
            assertTrue(logs.stream().anyMatch(l -> l.contains("baseline") && l.contains("RCE")),
                    "Deve logar que baseline contem padrao RCE");
        } finally {
            server.stop(0);
        }
    }

    @Test
    @Order(4)
    void cmdi500ResponseNotFlagged() throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", exchange -> {
            String query = exchange.getRequestURI().getRawQuery();
            byte[] body;
            int status;
            if (query != null && (query.contains("%3B") || query.contains("%7C"))) {
                body = "uid=0(root)".getBytes();
                status = 500;
            } else {
                body = "ok".getBytes();
                status = 200;
            }
            exchange.sendResponseHeaders(status, body.length);
            exchange.getResponseBody().write(body);
            exchange.getResponseBody().close();
        });
        server.start();
        int port = server.getAddress().getPort();
        try {
            ScanContext ctx = new ScanContext("http://127.0.0.1:" + port, "", Set.of("CmdInjection"));
            List<Finding> findings = new CommandInjectionModule().scan(ctx, msg -> {
            });
            assertTrue(findings.stream().noneMatch(f -> f.title().contains("confirmada")),
                    "500 com saida RCE NAO deve gerar active finding (status >= 500 filtrado)");
        } finally {
            server.stop(0);
        }
    }

    // -------------------------------------------------
    // BrowserTransport interaction: Phase 2 skip
    // -------------------------------------------------

    @Test
    @Order(5)
    void cmdiPhase2SkippedWhenBrowserTransportActive() throws Exception {
        HttpServer server = cleanServer();
        server.start();
        int port = server.getAddress().getPort();
        try {
            ScanContext ctx = new ScanContext("http://127.0.0.1:" + port, "", Set.of("CmdInjection"));
            ctx.wafState().setBrowserTransport(stubBrowserTransport());

            List<String> logs = new ArrayList<>();
            List<Finding> findings = new CommandInjectionModule().scan(ctx, logs::add);

            assertTrue(logs.stream().anyMatch(l -> l.contains("phase 2") && l.contains("desabilitada")),
                    "Deve logar que phase 2 (time-based) esta desabilitada com BrowserTransport");
            assertTrue(findings.isEmpty(), "Clean server com BT ativo nao deve gerar findings");
        } finally {
            server.stop(0);
        }
    }

    @Test
    @Order(6)
    void cmdiPhase1WorksWithBrowserTransportActive() throws Exception {
        HttpServer server = vulnerableServer();
        server.start();
        int port = server.getAddress().getPort();
        try {
            ScanContext ctx = new ScanContext("http://127.0.0.1:" + port, "", Set.of("CmdInjection"));
            ctx.wafState().setBrowserTransport(stubBrowserTransport());

            List<String> logs = new ArrayList<>();
            List<Finding> findings = new CommandInjectionModule().scan(ctx, logs::add);

            assertTrue(logs.stream().anyMatch(l -> l.contains("phase 2") && l.contains("desabilitada")),
                    "Phase 2 deve estar desabilitada");
            assertFalse(findings.isEmpty(), "Phase 1 (active) deve funcionar mesmo com BT ativo");
            assertTrue(findings.stream().anyMatch(f -> f.severity() == Severity.CRITICAL),
                    "Active injection deve gerar CRITICAL mesmo com BT");
        } finally {
            server.stop(0);
        }
    }

    @Test
    @Order(7)
    void cmdiPhase2SkipDoesNotAffectPhase1Accuracy() throws Exception {
        HttpServer server = vulnerableServer();
        server.start();
        int port = server.getAddress().getPort();
        try {
            // Without BrowserTransport
            ScanContext ctx1 = new ScanContext("http://127.0.0.1:" + port, "", Set.of("CmdInjection"));
            List<Finding> without = new CommandInjectionModule().scan(ctx1, msg -> {
            });

            // With BrowserTransport
            ScanContext ctx2 = new ScanContext("http://127.0.0.1:" + port, "", Set.of("CmdInjection"));
            ctx2.wafState().setBrowserTransport(stubBrowserTransport());
            List<Finding> with = new CommandInjectionModule().scan(ctx2, msg -> {
            });

            assertFalse(without.isEmpty(), "Sem BT deve detectar injection");
            assertFalse(with.isEmpty(), "Com BT deve detectar injection");
            assertTrue(without.stream().anyMatch(f -> f.severity() == Severity.CRITICAL), "Sem BT deve gerar CRITICAL");
            assertTrue(with.stream().anyMatch(f -> f.severity() == Severity.CRITICAL), "Com BT deve gerar CRITICAL");
        } finally {
            server.stop(0);
        }
    }

    // -------------------------------------------------
    // Module metadata
    // -------------------------------------------------

    @Test
    @Order(8)
    void cmdiModuleId() {
        assertEquals("CmdInjection", new CommandInjectionModule().id(), "id() deve retornar 'CmdInjection'");
    }

    @Test
    @Order(9)
    void cmdiCweRegistryEntry() {
        assertEquals("CWE-78", gg.effront.anarcry.model.CweRegistry.cweId("CmdInjection"),
                "CweRegistry deve ter CWE-78 para CmdInjection");
        assertTrue(gg.effront.anarcry.model.CweRegistry.cvssVector("CmdInjection").startsWith("AV:N"),
                "CVSS vector para CmdInjection deve ser network-based");
    }
}
