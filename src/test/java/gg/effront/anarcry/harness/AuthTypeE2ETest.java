package gg.effront.anarcry.harness;

import static org.junit.jupiter.api.Assertions.*;

import com.sun.net.httpserver.HttpServer;
import gg.effront.anarcry.model.AuthType;
import gg.effront.anarcry.model.Finding;
import gg.effront.anarcry.model.Severity;
import gg.effront.anarcry.scanner.ScanContext;
import gg.effront.anarcry.scanner.crypto.headers.HeadersModule;
import gg.effront.anarcry.scanner.crypto.jwt.JwtModule;
import gg.effront.anarcry.scanner.web.cors.CorsModule;
import gg.effront.anarcry.scanner.web.hostheader.HostHeaderModule;
import gg.effront.anarcry.scanner.web.idor.IdorModule;
import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class AuthTypeE2ETest {

    private static final Base64.Encoder B64 = Base64.getUrlEncoder().withoutPadding();

    private static String buildJwt(String headerJson, String payloadJson) {
        return B64.encodeToString(headerJson.getBytes()) + "." + B64.encodeToString(payloadJson.getBytes()) + ".";
    }

    private static final String SAMPLE_JWT = buildJwt("{\"alg\":\"none\"}", "{\"sub\":\"test\"}");
    private static final String SAMPLE_JWT2 = buildJwt("{\"alg\":\"none\"}", "{\"sub\":\"user2\"}");
    private static final String SAMPLE_COOKIE = "sid=abc123; token=xyz";
    private static final String SAMPLE_BEARER = "opaque-oauth2-access-token";

    // -- helpers --

    private static ScanContext contextFor(AuthType type, String target, Set<String> modules) {
        return contextFor(type, target, modules, null, null);
    }

    private static ScanContext contextFor(AuthType type, String target, Set<String> modules, String credential,
            String credential2) {
        String cred = credential != null ? credential : defaultCredential(type);
        String cred2 = credential2 != null ? credential2 : "";
        return type.buildContext(target, modules, cred, cred2);
    }

    private static String defaultCredential(AuthType type) {
        return switch (type) {
            case NONE -> "";
            case JWT -> SAMPLE_JWT;
            case COOKIE -> SAMPLE_COOKIE;
            case BEARER -> SAMPLE_BEARER;
        };
    }

    private record CapturedRequest(String authorization, String cookie, String method, String path) {
    }

    private static HttpServer headerCapturingServer(List<CapturedRequest> captured) throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", exchange -> {
            String auth = exchange.getRequestHeaders().getFirst("Authorization");
            String cookieHdr = exchange.getRequestHeaders().getFirst("Cookie");
            captured.add(new CapturedRequest(auth != null ? auth : "", cookieHdr != null ? cookieHdr : "",
                    exchange.getRequestMethod(), exchange.getRequestURI().getPath()));
            byte[] body = "ok".getBytes();
            exchange.sendResponseHeaders(200, body.length);
            exchange.getResponseBody().write(body);
            exchange.getResponseBody().close();
        });
        return server;
    }

    // -----------------------------------------------
    // Section 1: AuthType enum contract
    // -----------------------------------------------

    @Test
    @Order(1)
    void authTypeHasFourValues() {
        assertEquals(4, AuthType.values().length);
        assertNotNull(AuthType.NONE);
        assertNotNull(AuthType.JWT);
        assertNotNull(AuthType.COOKIE);
        assertNotNull(AuthType.BEARER);
    }

    @Test
    @Order(2)
    void authTypeUsesBearer() {
        assertFalse(AuthType.NONE.usesBearer());
        assertTrue(AuthType.JWT.usesBearer());
        assertFalse(AuthType.COOKIE.usesBearer());
        assertTrue(AuthType.BEARER.usesBearer());
    }

    @Test
    @Order(3)
    void authTypeUsesCookie() {
        assertFalse(AuthType.NONE.usesCookie());
        assertFalse(AuthType.JWT.usesCookie());
        assertTrue(AuthType.COOKIE.usesCookie());
        assertFalse(AuthType.BEARER.usesCookie());
    }

    @Test
    @Order(4)
    void authTypeRequiresJwtParsing() {
        assertFalse(AuthType.NONE.requiresJwtParsing());
        assertTrue(AuthType.JWT.requiresJwtParsing());
        assertFalse(AuthType.COOKIE.requiresJwtParsing());
        assertFalse(AuthType.BEARER.requiresJwtParsing());
    }

    @Test
    @Order(5)
    void authTypeHasAuth() {
        assertFalse(AuthType.NONE.hasAuth());
        assertTrue(AuthType.JWT.hasAuth());
        assertTrue(AuthType.COOKIE.hasAuth());
        assertTrue(AuthType.BEARER.hasAuth());
    }

    // -----------------------------------------------
    // Section 2: ScanContext wiring per AuthType
    // -----------------------------------------------

    @Test
    @Order(10)
    void noneAuthClearsAllCredentials() {
        ScanContext ctx = contextFor(AuthType.NONE, "https://example.com", Set.of("Headers"));
        assertTrue(ctx.jwtToken().isBlank());
        assertTrue(ctx.jwtToken2().isBlank());
        assertTrue(ctx.config().sessionCookie().isBlank());
    }

    @Test
    @Order(11)
    void jwtAuthSetsTokens() {
        ScanContext ctx = contextFor(AuthType.JWT, "https://example.com", Set.of("JWT"), SAMPLE_JWT, SAMPLE_JWT2);
        assertEquals(SAMPLE_JWT, ctx.jwtToken());
        assertEquals(SAMPLE_JWT2, ctx.jwtToken2());
        assertTrue(ctx.config().sessionCookie().isBlank());
    }

    @Test
    @Order(12)
    void cookieAuthSetsSessionCookie() {
        ScanContext ctx = contextFor(AuthType.COOKIE, "https://example.com", Set.of("Headers"), SAMPLE_COOKIE, null);
        assertTrue(ctx.jwtToken().isBlank());
        assertTrue(ctx.jwtToken2().isBlank());
        assertEquals(SAMPLE_COOKIE, ctx.config().sessionCookie());
    }

    @Test
    @Order(13)
    void bearerAuthSetsJwtTokenField() {
        ScanContext ctx = contextFor(AuthType.BEARER, "https://example.com", Set.of("Headers"), SAMPLE_BEARER, null);
        assertEquals(SAMPLE_BEARER, ctx.jwtToken());
        assertTrue(ctx.config().sessionCookie().isBlank());
    }

    @ParameterizedTest
    @EnumSource(AuthType.class)
    @Order(14)
    void noAuthFieldIsNull(AuthType type) {
        ScanContext ctx = contextFor(type, "https://example.com", Set.of("Headers"));
        assertNotNull(ctx.jwtToken());
        assertNotNull(ctx.jwtToken2());
        assertNotNull(ctx.config().sessionCookie());
    }

    @Test
    @Order(15)
    void authTypeDoesNotAffectEnabledModules() {
        Set<String> modules = Set.of("Headers", "CORS", "SQLi");
        for (AuthType type : AuthType.values()) {
            ScanContext ctx = contextFor(type, "https://example.com", modules);
            assertTrue(ctx.has("Headers"), type + " must preserve enabled modules");
            assertTrue(ctx.has("CORS"), type + " must preserve enabled modules");
            assertTrue(ctx.has("SQLi"), type + " must preserve enabled modules");
        }
    }

    // -----------------------------------------------
    // Section 3: Module skip logic per AuthType
    // -----------------------------------------------

    @Test
    @Order(20)
    void jwtModuleSkipsOnNoneAuth() throws Exception {
        ScanContext ctx = contextFor(AuthType.NONE, "https://example.com", Set.of("JWT"));
        List<Finding> findings = new JwtModule().scan(ctx, msg -> {
        });
        assertTrue(findings.isEmpty(), "JwtModule must skip when no JWT token");
    }

    @Test
    @Order(21)
    void jwtModuleSkipsOnCookieAuth() throws Exception {
        ScanContext ctx = contextFor(AuthType.COOKIE, "https://example.com", Set.of("JWT"), SAMPLE_COOKIE, null);
        List<Finding> findings = new JwtModule().scan(ctx, msg -> {
        });
        assertTrue(findings.isEmpty(), "JwtModule must skip when auth is cookie-based");
    }

    @Test
    @Order(22)
    void jwtModuleRunsOnJwtAuth() throws Exception {
        ScanContext ctx = contextFor(AuthType.JWT, "https://example.com", Set.of("JWT"), SAMPLE_JWT, null);
        List<Finding> findings = new JwtModule().scan(ctx, msg -> {
        });
        assertTrue(
                findings.stream()
                        .anyMatch(f -> f.severity() == Severity.CRITICAL && f.title().toLowerCase().contains("none")),
                "JwtModule must detect alg:none on JWT auth");
    }

    @Test
    @Order(23)
    void jwtModuleGracefullyHandlesOpaqueBearer() throws Exception {
        ScanContext ctx = contextFor(AuthType.BEARER, "https://example.com", Set.of("JWT"), SAMPLE_BEARER, null);
        List<Finding> findings = new JwtModule().scan(ctx, msg -> {
        });
        assertTrue(findings.stream().noneMatch(f -> f.severity() == Severity.CRITICAL),
                "JwtModule must not report CRITICAL for unparseable opaque tokens");
    }

    @Test
    @Order(24)
    void idorModuleSkipsOnNoneAuth() throws Exception {
        ScanContext ctx = contextFor(AuthType.NONE, "https://example.com", Set.of("IDOR"));
        List<Finding> findings = new IdorModule().scan(ctx, msg -> {
        });
        assertTrue(findings.isEmpty(), "IdorModule must skip when no auth");
    }

    @Test
    @Order(25)
    void idorModuleSkipsOnCookieAuth() throws Exception {
        ScanContext ctx = contextFor(AuthType.COOKIE, "https://example.com", Set.of("IDOR"), SAMPLE_COOKIE, null);
        List<Finding> findings = new IdorModule().scan(ctx, msg -> {
        });
        assertTrue(findings.isEmpty(), "IdorModule skips on cookie auth (jwtToken is blank) -- known gap");
    }

    // -----------------------------------------------
    // Section 4: HTTP header verification (mock server)
    // -----------------------------------------------

    @Test
    @Order(30)
    void cookieAuthInjectsCookieViaHttpSend() throws Exception {
        CopyOnWriteArrayList<CapturedRequest> captured = new CopyOnWriteArrayList<>();
        HttpServer server = headerCapturingServer(captured);
        server.start();
        int port = server.getAddress().getPort();
        try {
            // HostHeaderModule uses Http.send() (HeadersModule uses HttpURLConnection
            // directly)
            ScanContext ctx = contextFor(AuthType.COOKIE, "http://127.0.0.1:" + port, Set.of("HostHeader"),
                    "sid=testcookie123", null);
            new HostHeaderModule().scan(ctx, msg -> {
            });
            assertFalse(captured.isEmpty(), "HostHeaderModule must send at least one request");
            assertTrue(captured.stream().anyMatch(r -> r.cookie().contains("sid=testcookie123")),
                    "Http.send() must inject session cookie on COOKIE auth");
        } finally {
            server.stop(0);
        }
    }

    @Test
    @Order(31)
    void noneAuthSendsNoAuthHeaders() throws Exception {
        CopyOnWriteArrayList<CapturedRequest> captured = new CopyOnWriteArrayList<>();
        HttpServer server = headerCapturingServer(captured);
        server.start();
        int port = server.getAddress().getPort();
        try {
            ScanContext ctx = contextFor(AuthType.NONE, "http://127.0.0.1:" + port, Set.of("Headers"));
            new HeadersModule().scan(ctx, msg -> {
            });
            assertFalse(captured.isEmpty(), "HeadersModule must send at least one request");
            assertTrue(captured.stream().allMatch(r -> r.authorization().isEmpty()),
                    "NONE auth must not send Authorization header");
            assertTrue(captured.stream().allMatch(r -> r.cookie().isEmpty()), "NONE auth must not send Cookie header");
        } finally {
            server.stop(0);
        }
    }

    @Test
    @Order(32)
    void jwtAuthSendsBearerOnAuthAwareModule() throws Exception {
        CopyOnWriteArrayList<CapturedRequest> captured = new CopyOnWriteArrayList<>();
        HttpServer server = headerCapturingServer(captured);
        server.start();
        int port = server.getAddress().getPort();
        try {
            ScanContext ctx = contextFor(AuthType.JWT, "http://127.0.0.1:" + port, Set.of("HostHeader"), SAMPLE_JWT,
                    null);
            new HostHeaderModule().scan(ctx, msg -> {
            });
            assertFalse(captured.isEmpty(), "HostHeaderModule must send at least one request");
            assertTrue(captured.stream().anyMatch(r -> r.authorization().contains("Bearer ")),
                    "JWT auth must produce Authorization: Bearer on auth-aware modules");
        } finally {
            server.stop(0);
        }
    }

    @Test
    @Order(33)
    void cookieAuthNoBearerOnAuthAwareModule() throws Exception {
        CopyOnWriteArrayList<CapturedRequest> captured = new CopyOnWriteArrayList<>();
        HttpServer server = headerCapturingServer(captured);
        server.start();
        int port = server.getAddress().getPort();
        try {
            ScanContext ctx = contextFor(AuthType.COOKIE, "http://127.0.0.1:" + port, Set.of("HostHeader"),
                    "sid=testcookie", null);
            new HostHeaderModule().scan(ctx, msg -> {
            });
            assertFalse(captured.isEmpty(), "HostHeaderModule must send at least one request");
            assertTrue(captured.stream().allMatch(r -> r.authorization().isEmpty()),
                    "COOKIE auth must not produce Bearer header on modules checking jwtToken");
            assertTrue(captured.stream().anyMatch(r -> r.cookie().contains("sid=testcookie")),
                    "COOKIE auth must inject session cookie via Http.send()");
        } finally {
            server.stop(0);
        }
    }

    @Test
    @Order(34)
    void bearerAuthSendsBearerHeader() throws Exception {
        CopyOnWriteArrayList<CapturedRequest> captured = new CopyOnWriteArrayList<>();
        HttpServer server = headerCapturingServer(captured);
        server.start();
        int port = server.getAddress().getPort();
        try {
            ScanContext ctx = contextFor(AuthType.BEARER, "http://127.0.0.1:" + port, Set.of("HostHeader"),
                    SAMPLE_BEARER, null);
            new HostHeaderModule().scan(ctx, msg -> {
            });
            assertFalse(captured.isEmpty(), "HostHeaderModule must send at least one request");
            assertTrue(captured.stream().anyMatch(r -> r.authorization().contains(SAMPLE_BEARER)),
                    "BEARER auth must produce Authorization: Bearer with opaque token");
        } finally {
            server.stop(0);
        }
    }

    // -----------------------------------------------
    // Section 5: Integration -- module execution with auth
    // -----------------------------------------------

    @Test
    @Order(40)
    void headersModuleProducesFindingsWithCookieAuth() throws Exception {
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
            ScanContext ctx = contextFor(AuthType.COOKIE, "http://127.0.0.1:" + port, Set.of("Headers"),
                    "sid=integrationtest", null);
            List<Finding> findings = new HeadersModule().scan(ctx, msg -> {
            });
            assertTrue(findings.stream().anyMatch(f -> f.title().contains("CSP")),
                    "HeadersModule must detect missing CSP with cookie auth");
        } finally {
            server.stop(0);
        }
    }

    @Test
    @Order(41)
    void corsAnonymousProbeOnNoneAuth() throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", exchange -> {
            String origin = exchange.getRequestHeaders().getFirst("Origin");
            if (origin != null) {
                exchange.getResponseHeaders().add("Access-Control-Allow-Origin", origin);
                exchange.getResponseHeaders().add("Access-Control-Allow-Credentials", "true");
            }
            byte[] body = "ok".getBytes();
            exchange.sendResponseHeaders(200, body.length);
            exchange.getResponseBody().write(body);
            exchange.getResponseBody().close();
        });
        server.start();
        int port = server.getAddress().getPort();
        try {
            ScanContext ctx = contextFor(AuthType.NONE, "http://127.0.0.1:" + port, Set.of("CORS"));
            List<Finding> findings = new CorsModule().scan(ctx, msg -> {
            });
            assertTrue(findings.stream().anyMatch(f -> f.module().equals("CORS")),
                    "CorsModule must detect reflective CORS with NONE auth");
        } finally {
            server.stop(0);
        }
    }

    @Test
    @Order(42)
    void corsJwtAuthProbesAuthenticatedAndAnonymous() throws Exception {
        // Server must NOT reflect Origin -- a reflected CORS triggers `break outer`
        // before the authenticated probe runs. Plain 200 ensures all auth modes
        // execute.
        CopyOnWriteArrayList<CapturedRequest> captured = new CopyOnWriteArrayList<>();
        HttpServer server = headerCapturingServer(captured);
        server.start();
        int port = server.getAddress().getPort();
        try {
            ScanContext ctx = contextFor(AuthType.JWT, "http://127.0.0.1:" + port, Set.of("CORS"), SAMPLE_JWT, null);
            new CorsModule().scan(ctx, msg -> {
            });
            assertTrue(captured.stream().anyMatch(r -> r.authorization().contains("Bearer ")),
                    "CorsModule must send authenticated probes with JWT auth");
            assertTrue(captured.stream().anyMatch(r -> r.authorization().isEmpty()),
                    "CorsModule must also send unauthenticated probes");
        } finally {
            server.stop(0);
        }
    }
}
