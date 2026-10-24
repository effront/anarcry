package gg.effront.anarcry.harness;

import com.google.gson.JsonArray;
import com.google.gson.JsonParser;
import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsServer;
import com.sun.net.httpserver.HttpServer;
import gg.effront.anarcry.model.Finding;
import gg.effront.anarcry.model.Severity;
import gg.effront.anarcry.report.ReportEngine;
import gg.effront.anarcry.scanner.ScanContext;
import gg.effront.anarcry.scanner.crypto.headers.HeadersModule;
import gg.effront.anarcry.scanner.web.cors.CorsModule;
import gg.effront.anarcry.scanner.web.crlf.CrlfModule;
import gg.effront.anarcry.scanner.web.graphql.GraphQLModule;
import gg.effront.anarcry.scanner.crypto.jwt.JwtModule;
import gg.effront.anarcry.scanner.web.oauth.OAuthModule;
import gg.effront.anarcry.scanner.web.openredirect.OpenRedirectModule;
import gg.effront.anarcry.scanner.web.ssrf.SsrfModule;
import gg.effront.anarcry.scanner.web.xxe.XxeModule;
import gg.effront.anarcry.scanner.web.ssti.SstiModule;
import gg.effront.anarcry.scanner.web.idor.IdorModule;
import gg.effront.anarcry.model.CvssCalculator;
import gg.effront.anarcry.model.CweRegistry;
import gg.effront.anarcry.scanner.Scanner;
import gg.effront.anarcry.scanner.ScanRunner;
import gg.effront.anarcry.scanner.crypto.pqc.PqcModule;
import gg.effront.anarcry.scanner.crypto.tls.CipherSuiteProbe;
import gg.effront.anarcry.scanner.crypto.tls.TlsModule;
import java.util.Collections;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.*;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Set;
import gg.effront.anarcry.scanner.web.cachepoisoning.CachePoisoningModule;
import gg.effront.anarcry.scanner.web.smuggling.RequestSmugglingModule;
import gg.effront.anarcry.scanner.web.crawler.CrawlerModule;
import gg.effront.anarcry.scanner.ScanConfig;
import gg.effront.anarcry.scanner.web.xss.XssModule;
import gg.effront.anarcry.scanner.web.sqli.SqlInjectionModule;
import gg.effront.anarcry.scanner.web.lfi.LfiModule;
import gg.effront.anarcry.scanner.web.cmdinject.CommandInjectionModule;
import gg.effront.anarcry.scanner.web.massassign.MassAssignmentModule;
import gg.effront.anarcry.scanner.util.HttpClientFactory;

import java.lang.reflect.Field;

import static org.junit.jupiter.api.Assertions.*;

@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class ScanHarnessTest {

    // ─────────────────────────────────────────
    // Fast tests (pure logic, no network)
    // ─────────────────────────────────────────

    @Test
    @Order(1)
    void jwtAlgNoneDetected() throws Exception {
        // eyJhbGciOiJub25lIn0 = {"alg":"none"}
        // eyJzdWIiOiJ0ZXN0In0 = {"sub":"test"}
        String token = "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ0ZXN0In0.";
        ScanContext ctx = new ScanContext("https://example.com", token, Set.of("JWT"));
        List<Finding> findings = new JwtModule().scan(ctx, msg -> {
        });
        assertTrue(
                findings.stream()
                        .anyMatch(f -> f.severity() == Severity.CRITICAL && f.title().toLowerCase().contains("none")),
                "Deve detectar alg:none como CRITICAL");
    }

    @Test
    @Order(2)
    void jwtWeakSecretDetected() throws Exception {
        String secret = "secret";
        String headerB64 = Base64.getUrlEncoder().withoutPadding()
                .encodeToString("{\"alg\":\"HS256\",\"typ\":\"JWT\"}".getBytes());
        String payloadB64 = Base64.getUrlEncoder().withoutPadding().encodeToString("{\"sub\":\"test\"}".getBytes());
        String sigInput = headerB64 + "." + payloadB64;

        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(secret.getBytes("UTF-8"), "HmacSHA256"));
        byte[] sig = mac.doFinal(sigInput.getBytes("UTF-8"));
        String sigB64 = Base64.getUrlEncoder().withoutPadding().encodeToString(sig);

        String token = sigInput + "." + sigB64;
        ScanContext ctx = new ScanContext("https://example.com", token, Set.of("JWT"));
        List<Finding> findings = new JwtModule().scan(ctx, msg -> {
        });

        assertTrue(
                findings.stream()
                        .anyMatch(f -> f.severity() == Severity.CRITICAL && f.title().toLowerCase().contains("fraco")),
                "Deve detectar segredo 'secret' como CRITICAL");
    }

    @Test
    @Order(3)
    void jwtNoExpDetected() throws Exception {
        String headerB64 = Base64.getUrlEncoder().withoutPadding()
                .encodeToString("{\"alg\":\"HS256\",\"typ\":\"JWT\"}".getBytes());
        String payloadB64 = Base64.getUrlEncoder().withoutPadding().encodeToString("{\"sub\":\"test\"}".getBytes());
        // Signature doesn't matter for this check
        String token = headerB64 + "." + payloadB64 + ".fakesig";
        ScanContext ctx = new ScanContext("https://example.com", token, Set.of("JWT"));
        List<Finding> findings = new JwtModule().scan(ctx, msg -> {
        });

        assertTrue(
                findings.stream()
                        .anyMatch(f -> f.severity() == Severity.LOW && f.title().toLowerCase().contains("exp")),
                "Deve detectar ausência de claim exp como LOW");
    }

    @Test
    @Order(4)
    void jwtKidDetected() throws Exception {
        String headerB64 = Base64.getUrlEncoder().withoutPadding()
                .encodeToString("{\"alg\":\"HS256\",\"typ\":\"JWT\",\"kid\":\"key1\"}".getBytes());
        String payloadB64 = Base64.getUrlEncoder().withoutPadding()
                .encodeToString("{\"sub\":\"test\",\"exp\":9999999999}".getBytes());
        String token = headerB64 + "." + payloadB64 + ".fakesig";
        ScanContext ctx = new ScanContext("https://example.com", token, Set.of("JWT"));
        List<Finding> findings = new JwtModule().scan(ctx, msg -> {
        });

        assertTrue(
                findings.stream()
                        .anyMatch(f -> f.severity() == Severity.LOW && f.title().toLowerCase().contains("kid")),
                "Deve detectar parâmetro kid como LOW");
    }

    @Test
    @Order(5)
    void reportExportWritesDisk() throws Exception {
        List<Finding> findings = List.of(
                new Finding("TLS", "/", "Disco 1", Severity.HIGH, "ev1", "imp1", "rep1", "rec1", "CWE-200",
                        "Exposure of Sensitive Information", "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", 5.3),
                new Finding("JWT", "/", "Disco 2", Severity.CRITICAL, "ev2", "imp2", "rep2", "rec2", "CWE-200",
                        "Exposure of Sensitive Information", "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", 5.3));
        Path cwd = Path.of(System.getProperty("user.dir"));
        String mdFile = new ReportEngine().export(findings, "https://test.example.com");
        Path md = cwd.resolve(mdFile);
        Path json = cwd.resolve(mdFile.replace(".md", ".json"));
        try {
            assertTrue(Files.exists(md), "Arquivo .md deve existir em disco");
            assertTrue(Files.exists(json), "Arquivo .json deve existir em disco");
            String mdContent = Files.readString(md);
            assertTrue(mdContent.contains("https://test.example.com"), "Markdown deve conter o target");
            assertTrue(mdContent.contains("CRITICAL"), "Markdown deve conter severity CRITICAL");
            String jsonContent = Files.readString(json);
            assertTrue(jsonContent.contains("CRITICAL"), "JSON deve conter severity CRITICAL");
        } finally {
            Files.deleteIfExists(md);
            Files.deleteIfExists(json);
        }
    }

    @Test
    @Order(6)
    void reportExportJson() throws Exception {
        List<Finding> findings = List.of(
                new Finding("TLS", "/", "Teste 1", Severity.HIGH, "ev1", "imp1", "rep1", "rec1", "CWE-200",
                        "Exposure of Sensitive Information", "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", 5.3),
                new Finding("JWT", "/", "Teste 2", Severity.CRITICAL, "ev2", "imp2", "rep2", "rec2", "CWE-200",
                        "Exposure of Sensitive Information", "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", 5.3));
        String json = new ReportEngine().toJson(findings);
        JsonArray arr = JsonParser.parseString(json).getAsJsonArray();
        assertEquals(2, arr.size(), "JSON deve conter 2 findings");
        // CRITICAL vem primeiro
        assertEquals("CRITICAL", arr.get(0).getAsJsonObject().get("severity").getAsString());
    }

    // ─────────────────────────────────────────
    // Integration tests (network required)
    // ─────────────────────────────────────────

    @Test
    @Order(6)
    @Tag("integration")
    void tlsCertExpiredBadSsl() throws Exception {
        ScanContext ctx = new ScanContext("https://expired.badssl.com", "", Set.of("TLS"));
        List<Finding> findings = new TlsModule().scan(ctx, msg -> System.out.println("[CERT] " + msg));
        assertTrue(
                findings.stream().anyMatch(
                        f -> f.severity() == Severity.CRITICAL && f.title().toLowerCase().contains("expirado")),
                "Deve detectar certificado expirado em expired.badssl.com");
    }

    @Test
    @Order(7)
    @Tag("integration")
    void tlsCertSelfSignedBadSsl() throws Exception {
        ScanContext ctx = new ScanContext("https://self-signed.badssl.com", "", Set.of("TLS"));
        List<Finding> findings = new TlsModule().scan(ctx, msg -> System.out.println("[CERT] " + msg));
        assertTrue(
                findings.stream().anyMatch(
                        f -> f.severity() == Severity.MEDIUM && f.title().toLowerCase().contains("auto-assinado")),
                "Deve detectar certificado auto-assinado em self-signed.badssl.com");
    }

    @Test
    @Order(8)
    @Tag("integration")
    void headersMissingOnLocalServer() throws Exception {
        // Sobe servidor HTTP local sem headers de segurança
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
            ScanContext ctx = new ScanContext("http://127.0.0.1:" + port, "", Set.of("Headers"));
            List<Finding> findings = new HeadersModule().scan(ctx, msg -> {
            });

            assertTrue(findings.stream().anyMatch(f -> f.title().contains("CSP")), "Deve reportar CSP ausente");
            assertTrue(findings.stream().anyMatch(f -> f.title().contains("X-Frame-Options")),
                    "Deve reportar X-Frame-Options ausente");
        } finally {
            server.stop(0);
        }
    }

    @Test
    @Order(9)
    void headersCookieFlags() throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", exchange -> {
            exchange.getResponseHeaders().add("Set-Cookie", "session=abc");
            byte[] body = "ok".getBytes();
            exchange.sendResponseHeaders(200, body.length);
            exchange.getResponseBody().write(body);
            exchange.getResponseBody().close();
        });
        server.start();
        int port = server.getAddress().getPort();
        try {
            ScanContext ctx = new ScanContext("http://127.0.0.1:" + port, "", Set.of("Headers"));
            List<Finding> findings = new HeadersModule().scan(ctx, msg -> {
            });
            assertTrue(findings.stream().anyMatch(f -> f.title().toLowerCase().contains("secure")),
                    "Deve reportar cookie sem Secure");
            assertTrue(findings.stream().anyMatch(f -> f.title().toLowerCase().contains("httponly")),
                    "Deve reportar cookie sem HttpOnly");
        } finally {
            server.stop(0);
        }
    }

    @Test
    @Order(10)
    void headersHstsSubdomains() throws Exception {
        Map<String, String> hdrs = Map.of("Strict-Transport-Security", "max-age=31536000", "Content-Security-Policy",
                "default-src 'self'");
        HttpsServer server = createTestHttpsServer(hdrs);
        int port = server.getAddress().getPort();
        try {
            ScanContext ctx = new ScanContext("https://127.0.0.1:" + port, "", Set.of("Headers"));
            List<Finding> findings = new HeadersModule().scan(ctx, msg -> {
            });
            assertTrue(findings.stream().anyMatch(f -> f.title().toLowerCase().contains("includesubdomains")),
                    "Deve reportar HSTS sem includeSubDomains");
        } finally {
            server.stop(0);
        }
    }

    @Test
    @Order(11)
    void headersUnsafeCsp() throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", exchange -> {
            exchange.getResponseHeaders().add("Content-Security-Policy",
                    "default-src 'self'; script-src 'unsafe-inline'");
            byte[] body = "ok".getBytes();
            exchange.sendResponseHeaders(200, body.length);
            exchange.getResponseBody().write(body);
            exchange.getResponseBody().close();
        });
        server.start();
        int port = server.getAddress().getPort();
        try {
            ScanContext ctx = new ScanContext("http://127.0.0.1:" + port, "", Set.of("Headers"));
            List<Finding> findings = new HeadersModule().scan(ctx, msg -> {
            });
            assertTrue(findings.stream().anyMatch(f -> f.title().toLowerCase().contains("unsafe-inline")),
                    "Deve reportar CSP com unsafe-inline");
        } finally {
            server.stop(0);
        }
    }

    @Test
    @Order(12)
    void jwtAlgNoneActiveFails() throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", exchange -> {
            exchange.sendResponseHeaders(401, -1);
            exchange.getResponseBody().close();
        });
        server.start();
        int port = server.getAddress().getPort();
        try {
            String h = Base64.getUrlEncoder().withoutPadding()
                    .encodeToString("{\"alg\":\"HS256\",\"typ\":\"JWT\"}".getBytes());
            String p = Base64.getUrlEncoder().withoutPadding().encodeToString("{\"sub\":\"test\"}".getBytes());
            String token = h + "." + p + ".fakesig";
            ScanContext ctx = new ScanContext("http://127.0.0.1:" + port, token, Set.of("JWT"));
            List<Finding> findings = new JwtModule().scan(ctx, msg -> {
            });
            assertTrue(findings.stream().noneMatch(f -> f.title().toLowerCase().contains("ativamente")),
                    "Probe ativa NÃO deve gerar finding quando servidor retorna 401");
        } finally {
            server.stop(0);
        }
    }

    @Test
    @Order(13)
    void jwtAlgNoneActiveDetected() throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", exchange -> {
            String auth = exchange.getRequestHeaders().getFirst("Authorization");
            int status = (auth != null && auth.startsWith("Bearer ")) ? 200 : 401;
            exchange.sendResponseHeaders(status, -1);
            exchange.getResponseBody().close();
        });
        server.start();
        int port = server.getAddress().getPort();
        try {
            String h = Base64.getUrlEncoder().withoutPadding()
                    .encodeToString("{\"alg\":\"HS256\",\"typ\":\"JWT\"}".getBytes());
            String p = Base64.getUrlEncoder().withoutPadding().encodeToString("{\"sub\":\"test\"}".getBytes());
            String token = h + "." + p + ".fakesig";
            ScanContext ctx = new ScanContext("http://127.0.0.1:" + port, token, Set.of("JWT"));
            List<Finding> findings = new JwtModule().scan(ctx, msg -> System.out.println("[JWT] " + msg));
            assertTrue(
                    findings.stream().anyMatch(
                            f -> f.severity() == Severity.CRITICAL && f.title().toLowerCase().contains("ativamente")),
                    "Probe ativa DEVE gerar CRITICAL quando servidor aceita alg:none");
        } finally {
            server.stop(0);
        }
    }

    @Test
    @Order(14)
    void cipherSuiteGroupsRegistered() throws Exception {
        // Java 27 removeu 3DES/EXPORT do JSSE completamente — probe responde
        // "nenhum cipher disponível localmente" (comportamento correto).
        // Este teste verifica estruturalmente que os grupos estão registrados.
        java.lang.reflect.Field f = CipherSuiteProbe.class.getDeclaredField("GROUPS");
        f.setAccessible(true);
        @SuppressWarnings("unchecked")
        List<?> groups = (List<?>) f.get(null);

        List<String> names = groups.stream().map(g -> {
            try {
                var m = g.getClass().getDeclaredMethod("name");
                m.setAccessible(true);
                return (String) m.invoke(g);
            } catch (Exception e) {
                return "";
            }
        }).collect(java.util.stream.Collectors.toList());

        assertEquals(5, groups.size(), "GROUPS deve ter 5 entradas: RC4/NULL/ANON/3DES/EXPORT");
        assertTrue(names.contains("3DES"), "GROUPS deve conter grupo 3DES");
        assertTrue(names.contains("EXPORT"), "GROUPS deve conter grupo EXPORT");
    }

    // ─────────────────────────────────────────
    // JWT v2 — Sprint 1 (novos probes)
    // ─────────────────────────────────────────

    @Test
    @Order(15)
    void jwtJkuHeaderDetected() throws Exception {
        // Token com jku apontando para HTTPS externo → MEDIUM
        String hdr = Base64.getUrlEncoder().withoutPadding().encodeToString(
                "{\"alg\":\"RS256\",\"typ\":\"JWT\",\"jku\":\"https://example.com/jwks.json\"}".getBytes());
        String pld = Base64.getUrlEncoder().withoutPadding()
                .encodeToString("{\"sub\":\"test\",\"exp\":9999999999}".getBytes());
        String token = hdr + "." + pld + ".fakesig";
        ScanContext ctx = new ScanContext("https://example.com", token, Set.of("JWT"));
        List<Finding> findings = new JwtModule().scan(ctx, msg -> {
        });
        assertTrue(findings.stream().anyMatch(f -> f.title().toLowerCase().contains("jku")),
                "Deve detectar jku header como finding");
    }

    @Test
    @Order(16)
    void jwtJkuHttpSchemeIsHigh() throws Exception {
        // jku com http:// → HIGH (inseguro)
        String hdr = Base64.getUrlEncoder().withoutPadding()
                .encodeToString("{\"alg\":\"RS256\",\"typ\":\"JWT\",\"jku\":\"http://evil.com/jwks.json\"}".getBytes());
        String pld = Base64.getUrlEncoder().withoutPadding()
                .encodeToString("{\"sub\":\"test\",\"exp\":9999999999}".getBytes());
        String token = hdr + "." + pld + ".fakesig";
        ScanContext ctx = new ScanContext("https://example.com", token, Set.of("JWT"));
        List<Finding> findings = new JwtModule().scan(ctx, msg -> {
        });
        assertTrue(
                findings.stream()
                        .anyMatch(f -> f.title().toLowerCase().contains("jku") && f.severity() == Severity.HIGH),
                "jku com http:// deve ser HIGH");
    }

    @Test
    @Order(17)
    void jwtNullSignatureDetected() throws Exception {
        // Servidor aceita qualquer Bearer → NullSignatureProbe deve reportar CRITICAL
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", exchange -> {
            String auth = exchange.getRequestHeaders().getFirst("Authorization");
            int status = (auth != null && auth.startsWith("Bearer ")) ? 200 : 401;
            exchange.sendResponseHeaders(status, -1);
            exchange.getResponseBody().close();
        });
        server.start();
        int port = server.getAddress().getPort();
        try {
            String hdr = Base64.getUrlEncoder().withoutPadding()
                    .encodeToString("{\"alg\":\"HS256\",\"typ\":\"JWT\"}".getBytes());
            String pld = Base64.getUrlEncoder().withoutPadding()
                    .encodeToString("{\"sub\":\"test\",\"exp\":9999999999}".getBytes());
            String token = hdr + "." + pld + ".fakesig";
            ScanContext ctx = new ScanContext("http://127.0.0.1:" + port, token, Set.of("JWT"));
            List<Finding> findings = new JwtModule().scan(ctx, msg -> System.out.println("[NULL_SIG] " + msg));
            assertTrue(
                    findings.stream()
                            .anyMatch(f -> f.severity() == Severity.CRITICAL
                                    && f.title().toLowerCase().contains("null signature")),
                    "Null signature aceita pelo servidor deve gerar CRITICAL");
        } finally {
            server.stop(0);
        }
    }

    @Test
    @Order(18)
    void jwtNullSignatureActiveFails() throws Exception {
        // Servidor retorna 401 para tudo → sem finding de null signature
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", exchange -> {
            exchange.sendResponseHeaders(401, -1);
            exchange.getResponseBody().close();
        });
        server.start();
        int port = server.getAddress().getPort();
        try {
            String hdr = Base64.getUrlEncoder().withoutPadding()
                    .encodeToString("{\"alg\":\"HS256\",\"typ\":\"JWT\"}".getBytes());
            String pld = Base64.getUrlEncoder().withoutPadding()
                    .encodeToString("{\"sub\":\"test\",\"exp\":9999999999}".getBytes());
            String token = hdr + "." + pld + ".fakesig";
            ScanContext ctx = new ScanContext("http://127.0.0.1:" + port, token, Set.of("JWT"));
            List<Finding> findings = new JwtModule().scan(ctx, msg -> {
            });
            assertTrue(findings.stream().noneMatch(f -> f.title().toLowerCase().contains("null signature")),
                    "Servidor 401 não deve gerar finding de null signature");
        } finally {
            server.stop(0);
        }
    }

    @Test
    @Order(19)
    void jwtSignatureDisclosureDetected() throws Exception {
        // Servidor retorna body com "Expected <sig> got <sig>" → MEDIUM
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", exchange -> {
            byte[] body = "Invalid token. Expected abc123XYZ got xyz789ABC".getBytes();
            exchange.sendResponseHeaders(401, body.length);
            exchange.getResponseBody().write(body);
            exchange.getResponseBody().close();
        });
        server.start();
        int port = server.getAddress().getPort();
        try {
            // Precisamos de uma signature real para poder flip o último byte
            String secret = "secret";
            String hdr = Base64.getUrlEncoder().withoutPadding()
                    .encodeToString("{\"alg\":\"HS256\",\"typ\":\"JWT\"}".getBytes());
            String pld = Base64.getUrlEncoder().withoutPadding()
                    .encodeToString("{\"sub\":\"test\",\"exp\":9999999999}".getBytes());
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(secret.getBytes("UTF-8"), "HmacSHA256"));
            String sigInput = hdr + "." + pld;
            byte[] sig = mac.doFinal(sigInput.getBytes("UTF-8"));
            String token = sigInput + "." + Base64.getUrlEncoder().withoutPadding().encodeToString(sig);

            ScanContext ctx = new ScanContext("http://127.0.0.1:" + port, token, Set.of("JWT"));
            List<Finding> findings = new JwtModule().scan(ctx, msg -> System.out.println("[SIG_DISC] " + msg));
            assertTrue(
                    findings.stream().anyMatch(
                            f -> f.severity() == Severity.MEDIUM && f.title().toLowerCase().contains("signature")),
                    "Response body com 'Expected X got Y' deve gerar finding MEDIUM");
        } finally {
            server.stop(0);
        }
    }

    @Test
    @Order(20)
    void jwtRs256Hs256Detected() throws Exception {
        // Servidor HTTPS que aceita qualquer Bearer → RS256→HS256 probe deve reportar
        // CRITICAL
        HttpsServer httpsServer = createTestHttpsServer(Map.of());
        int port = httpsServer.getAddress().getPort();
        try {
            String hdr = Base64.getUrlEncoder().withoutPadding()
                    .encodeToString("{\"alg\":\"RS256\",\"typ\":\"JWT\"}".getBytes());
            String pld = Base64.getUrlEncoder().withoutPadding()
                    .encodeToString("{\"sub\":\"test\",\"exp\":9999999999}".getBytes());
            String token = hdr + "." + pld + ".fakesig";
            ScanContext ctx = new ScanContext("https://127.0.0.1:" + port, token, Set.of("JWT"));
            List<Finding> findings = new JwtModule().scan(ctx, msg -> System.out.println("[RS256] " + msg));
            assertTrue(
                    findings.stream().anyMatch(
                            f -> f.severity() == Severity.CRITICAL && f.title().toLowerCase().contains("rs256")),
                    "RS256→HS256 confusion aceita pelo servidor deve gerar CRITICAL");
        } finally {
            httpsServer.stop(0);
        }
    }

    // ─────────────────────────────────────────
    // CORS — Sprint 2
    // ─────────────────────────────────────────

    @Test
    @Order(21)
    void corsCriticalOriginReflectionWithCredentials() throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", exchange -> {
            String origin = exchange.getRequestHeaders().getFirst("Origin");
            if (origin != null && !origin.isBlank()) {
                exchange.getResponseHeaders().set("Access-Control-Allow-Origin", origin);
                exchange.getResponseHeaders().set("Access-Control-Allow-Credentials", "true");
            }
            byte[] body = "ok".getBytes();
            exchange.sendResponseHeaders(200, body.length);
            exchange.getResponseBody().write(body);
            exchange.getResponseBody().close();
        });
        server.start();
        int port = server.getAddress().getPort();
        try {
            ScanContext ctx = new ScanContext("http://127.0.0.1:" + port, "", Set.of("CORS"));
            List<Finding> findings = new CorsModule().scan(ctx, msg -> {
            });
            assertTrue(
                    findings.stream().anyMatch(
                            f -> f.severity() == Severity.CRITICAL && f.title().toLowerCase().contains("cors")),
                    "Origin reflection + credentials deve gerar CRITICAL");
        } finally {
            server.stop(0);
        }
    }

    @Test
    @Order(22)
    void corsHighWildcard() throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", exchange -> {
            exchange.getResponseHeaders().set("Access-Control-Allow-Origin", "*");
            byte[] body = "ok".getBytes();
            exchange.sendResponseHeaders(200, body.length);
            exchange.getResponseBody().write(body);
            exchange.getResponseBody().close();
        });
        server.start();
        int port = server.getAddress().getPort();
        try {
            ScanContext ctx = new ScanContext("http://127.0.0.1:" + port, "", Set.of("CORS"));
            List<Finding> findings = new CorsModule().scan(ctx, msg -> {
            });
            assertTrue(
                    findings.stream().anyMatch(
                            f -> f.severity() == Severity.HIGH && f.title().toLowerCase().contains("wildcard")),
                    "ACAO: * deve gerar HIGH");
        } finally {
            server.stop(0);
        }
    }

    @Test
    @Order(23)
    void corsMediumNullOrigin() throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", exchange -> {
            String origin = exchange.getRequestHeaders().getFirst("Origin");
            if ("null".equals(origin)) {
                exchange.getResponseHeaders().set("Access-Control-Allow-Origin", "null");
            }
            byte[] body = "ok".getBytes();
            exchange.sendResponseHeaders(200, body.length);
            exchange.getResponseBody().write(body);
            exchange.getResponseBody().close();
        });
        server.start();
        int port = server.getAddress().getPort();
        try {
            ScanContext ctx = new ScanContext("http://127.0.0.1:" + port, "", Set.of("CORS"));
            List<Finding> findings = new CorsModule().scan(ctx, msg -> {
            });
            assertTrue(
                    findings.stream()
                            .anyMatch(f -> f.severity() == Severity.MEDIUM && f.title().toLowerCase().contains("null")),
                    "ACAO: null deve gerar MEDIUM");
        } finally {
            server.stop(0);
        }
    }

    @Test
    @Order(24)
    void corsCleanNoFinding() throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", exchange -> {
            // No CORS headers
            byte[] body = "ok".getBytes();
            exchange.sendResponseHeaders(200, body.length);
            exchange.getResponseBody().write(body);
            exchange.getResponseBody().close();
        });
        server.start();
        int port = server.getAddress().getPort();
        try {
            ScanContext ctx = new ScanContext("http://127.0.0.1:" + port, "", Set.of("CORS"));
            List<Finding> findings = new CorsModule().scan(ctx, msg -> {
            });
            assertTrue(findings.isEmpty(), "Sem CORS headers → sem findings");
        } finally {
            server.stop(0);
        }
    }

    // ─────────────────────────────────────────
    // OAuth — Sprint 2
    // ─────────────────────────────────────────

    @Test
    @Order(25)
    void oauthEndpointDiscoveredViaWellKnown() throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", exchange -> {
            String path = exchange.getRequestURI().getPath();
            byte[] body;
            if (path.contains("openid-configuration")) {
                String json = "{\"issuer\":\"http://test\"," + "\"authorization_endpoint\":\"http://127.0.0.1:"
                        + server.getAddress().getPort() + "/authorize\"}";
                body = json.getBytes();
            } else {
                body = "not found".getBytes();
                exchange.sendResponseHeaders(404, body.length);
                exchange.getResponseBody().write(body);
                exchange.getResponseBody().close();
                return;
            }
            exchange.getResponseHeaders().set("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, body.length);
            exchange.getResponseBody().write(body);
            exchange.getResponseBody().close();
        });
        server.start();
        int port = server.getAddress().getPort();
        try {
            ScanContext ctx = new ScanContext("http://127.0.0.1:" + port, "", Set.of("OAuth"));
            List<Finding> findings = new OAuthModule().scan(ctx, msg -> {
            });
            assertTrue(
                    findings.stream()
                            .anyMatch(f -> f.title().toLowerCase().contains("oauth")
                                    || f.title().toLowerCase().contains("openid")),
                    "Well-known endpoint deve gerar finding OAuth");
        } finally {
            server.stop(0);
        }
    }

    @Test
    @Order(26)
    void oauthRedirectUriBypassDetected() throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", exchange -> {
            String path = exchange.getRequestURI().getPath();
            String query = exchange.getRequestURI().getRawQuery();
            if (path.endsWith("/authorize")) {
                if (query != null && query.contains("redirect_uri=")) {
                    // Naive server — redirect to whatever redirect_uri was sent
                    String redirectUri = java.util.Arrays.stream(query.split("&"))
                            .filter(p -> p.startsWith("redirect_uri=")).map(p -> p.substring("redirect_uri=".length()))
                            .findFirst().orElse("https://callback.example.com");
                    try {
                        redirectUri = java.net.URLDecoder.decode(redirectUri, "UTF-8");
                    } catch (Exception ignored) {
                    }
                    exchange.getResponseHeaders().set("Location", redirectUri + "?code=auth123");
                    exchange.sendResponseHeaders(302, -1);
                } else {
                    // Discovery probe (no redirect_uri) — return 200 to signal endpoint exists
                    byte[] body = "Login required".getBytes();
                    exchange.sendResponseHeaders(200, body.length);
                    exchange.getResponseBody().write(body);
                }
            } else {
                exchange.sendResponseHeaders(404, -1);
            }
            exchange.getResponseBody().close();
        });
        server.start();
        int port = server.getAddress().getPort();
        try {
            ScanContext ctx = new ScanContext("http://127.0.0.1:" + port, "", Set.of("OAuth"));
            List<Finding> findings = new OAuthModule().scan(ctx, msg -> System.out.println("[OAUTH] " + msg));
            assertTrue(
                    findings.stream().anyMatch(
                            f -> f.severity() == Severity.CRITICAL && f.title().toLowerCase().contains("redirect")),
                    "redirect_uri bypass deve gerar CRITICAL");
        } finally {
            server.stop(0);
        }
    }

    @Test
    @Order(27)
    void oauthEndpointNotFoundNoOauthFinding() throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", exchange -> {
            exchange.sendResponseHeaders(404, -1);
            exchange.getResponseBody().close();
        });
        server.start();
        int port = server.getAddress().getPort();
        try {
            ScanContext ctx = new ScanContext("http://127.0.0.1:" + port, "", Set.of("OAuth"));
            List<Finding> findings = new OAuthModule().scan(ctx, msg -> {
            });
            assertTrue(findings.isEmpty(), "Servidor sem endpoints OAuth → nenhum finding");
        } finally {
            server.stop(0);
        }
    }

    // ─────────────────────────────────────────
    // Open Redirect — Sprint 3
    // ─────────────────────────────────────────

    @Test
    @Order(28)
    void openRedirectHighDetected() throws Exception {
        // Naive server: echoes back any redirect param value as Location (vulnerable)
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", exchange -> {
            String query = exchange.getRequestURI().getRawQuery();
            if (query != null) {
                for (String param : java.util.List.of("url", "next", "redirect", "redir", "return", "returnUrl",
                        "returnTo", "goto", "to", "dest")) {
                    java.util.Optional<String> match = java.util.Arrays.stream(query.split("&"))
                            .filter(p -> p.startsWith(param + "=")).map(p -> p.substring(param.length() + 1))
                            .findFirst();
                    if (match.isPresent()) {
                        String location;
                        try {
                            location = java.net.URLDecoder.decode(match.get(), "UTF-8");
                        } catch (Exception e) {
                            location = match.get();
                        }
                        exchange.getResponseHeaders().set("Location", location);
                        exchange.sendResponseHeaders(302, -1);
                        exchange.getResponseBody().close();
                        return;
                    }
                }
            }
            byte[] body = "ok".getBytes();
            exchange.sendResponseHeaders(200, body.length);
            exchange.getResponseBody().write(body);
            exchange.getResponseBody().close();
        });
        server.start();
        int port = server.getAddress().getPort();
        try {
            ScanContext ctx = new ScanContext("http://127.0.0.1:" + port, "", Set.of("OpenRedirect"));
            List<Finding> findings = new OpenRedirectModule().scan(ctx, msg -> {
            });
            assertTrue(findings.stream().anyMatch(f -> f.severity() == Severity.HIGH),
                    "Servidor que reflete redirect param deve gerar HIGH");
        } finally {
            server.stop(0);
        }
    }

    @Test
    @Order(29)
    void openRedirectCleanNoFinding() throws Exception {
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
            ScanContext ctx = new ScanContext("http://127.0.0.1:" + port, "", Set.of("OpenRedirect"));
            List<Finding> findings = new OpenRedirectModule().scan(ctx, msg -> {
            });
            assertTrue(findings.isEmpty(), "Servidor que não redireciona → nenhum finding");
        } finally {
            server.stop(0);
        }
    }

    // ─────────────────────────────────────────
    // SSRF — Sprint 3
    // ─────────────────────────────────────────

    @Test
    @Order(30)
    void ssrfLocalHostDetected() throws Exception {
        // Vulnerable server: if url param contains known SSRF targets, returns
        // metadata-like body
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", exchange -> {
            String query = exchange.getRequestURI().getRawQuery();
            byte[] body;
            if (query != null && (query.contains("127.0.0.1") || query.contains("localhost")
                    || query.contains("169.254") || query.contains("0.0.0.0"))) {
                body = "ami-id: ami-12345678\ninstance-id: i-abc123456\n".getBytes();
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
            ScanContext ctx = new ScanContext("http://127.0.0.1:" + port, "", Set.of("SSRF"));
            List<Finding> findings = new SsrfModule().scan(ctx, msg -> {
            });
            assertFalse(findings.isEmpty(), "Servidor vulnerável a SSRF deve gerar finding");
            assertTrue(findings.stream().anyMatch(f -> f.title().toLowerCase().contains("ssrf")),
                    "Finding deve mencionar SSRF");
        } finally {
            server.stop(0);
        }
    }

    @Test
    @Order(31)
    void ssrfCleanNoFinding() throws Exception {
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
            ScanContext ctx = new ScanContext("http://127.0.0.1:" + port, "", Set.of("SSRF"));
            List<Finding> findings = new SsrfModule().scan(ctx, msg -> {
            });
            assertTrue(findings.isEmpty(), "Servidor sem SSRF → nenhum finding");
        } finally {
            server.stop(0);
        }
    }

    // ─────────────────────────────────────────
    // GraphQL — Sprint 3
    // ─────────────────────────────────────────

    @Test
    @Order(32)
    void graphqlIntrospectionEnabled() throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/graphql", exchange -> {
            String body = "{\"data\":{\"__schema\":{\"types\":[{\"name\":\"Query\"},{\"name\":\"String\"}]}}}";
            exchange.getResponseHeaders().set("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, body.length());
            exchange.getResponseBody().write(body.getBytes());
            exchange.getResponseBody().close();
        });
        server.createContext("/", exchange -> {
            exchange.sendResponseHeaders(404, -1);
            exchange.getResponseBody().close();
        });
        server.start();
        int port = server.getAddress().getPort();
        try {
            ScanContext ctx = new ScanContext("http://127.0.0.1:" + port, "", Set.of("GraphQL"));
            List<Finding> findings = new GraphQLModule().scan(ctx, msg -> {
            });
            assertTrue(
                    findings.stream().anyMatch(
                            f -> f.severity() == Severity.HIGH && f.title().toLowerCase().contains("introspection")),
                    "GraphQL com introspection deve gerar HIGH");
        } finally {
            server.stop(0);
        }
    }

    @Test
    @Order(33)
    void graphqlNoEndpoint() throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", exchange -> {
            exchange.sendResponseHeaders(404, -1);
            exchange.getResponseBody().close();
        });
        server.start();
        int port = server.getAddress().getPort();
        try {
            ScanContext ctx = new ScanContext("http://127.0.0.1:" + port, "", Set.of("GraphQL"));
            List<Finding> findings = new GraphQLModule().scan(ctx, msg -> {
            });
            assertTrue(findings.isEmpty(), "Servidor sem GraphQL → nenhum finding");
        } finally {
            server.stop(0);
        }
    }

    // ─────────────────────────────────────────
    // CRLF Injection — Sprint 3
    // ─────────────────────────────────────────

    @Test
    @Order(34)
    void crlfInjectionDetected() throws Exception {
        // Vulnerable server: if path contains %0a or %0d, echoes Set-Cookie:
        // crlf=injection
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", exchange -> {
            String rawPath = exchange.getRequestURI().getRawPath();
            if (rawPath != null && (rawPath.contains("%0a") || rawPath.contains("%0d") || rawPath.contains("%0A")
                    || rawPath.contains("%0D"))) {
                exchange.getResponseHeaders().add("Set-Cookie", "crlf=injection; Path=/; HttpOnly");
            }
            byte[] body = "ok".getBytes();
            exchange.sendResponseHeaders(200, body.length);
            exchange.getResponseBody().write(body);
            exchange.getResponseBody().close();
        });
        server.start();
        int port = server.getAddress().getPort();
        try {
            ScanContext ctx = new ScanContext("http://127.0.0.1:" + port, "", Set.of("CRLF"));
            List<Finding> findings = new CrlfModule().scan(ctx, msg -> {
            });
            assertTrue(
                    findings.stream().anyMatch(
                            f -> f.severity() == Severity.CRITICAL && f.title().toLowerCase().contains("crlf")),
                    "Servidor vulnerável a CRLF deve gerar CRITICAL");
        } finally {
            server.stop(0);
        }
    }

    @Test
    @Order(35)
    void crlfCleanNoFinding() throws Exception {
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
            ScanContext ctx = new ScanContext("http://127.0.0.1:" + port, "", Set.of("CRLF"));
            List<Finding> findings = new CrlfModule().scan(ctx, msg -> {
            });
            assertTrue(findings.isEmpty(), "Servidor sem CRLF → nenhum finding");
        } finally {
            server.stop(0);
        }
    }

    // ─────────────────────────────────────────
    // ScanContext — E2E Sprint
    // ─────────────────────────────────────────

    @Test
    @Order(36)
    void scanContextHttpsDefaultPort() {
        ScanContext ctx = new ScanContext("https://example.com", "", Set.of());
        assertTrue(ctx.isHttps(), "HTTPS deve marcar isHttps=true");
        assertEquals("example.com", ctx.host(), "host() deve extrair o hostname");
        assertEquals(443, ctx.port(), "Porta padrão HTTPS deve ser 443");
    }

    @Test
    @Order(37)
    void scanContextHttpCustomPort() {
        ScanContext ctx = new ScanContext("http://target.local:8080", "", Set.of());
        assertFalse(ctx.isHttps(), "HTTP deve marcar isHttps=false");
        assertEquals("target.local", ctx.host(), "host() deve excluir a porta");
        assertEquals(8080, ctx.port(), "Porta explícita deve ser respeitada");
    }

    @Test
    @Order(38)
    void scanContextHasModule() {
        ScanContext ctx = new ScanContext("https://x.com", "", Set.of("TLS", "JWT", "CORS"));
        assertTrue(ctx.has("TLS"), "TLS deve estar habilitado");
        assertTrue(ctx.has("JWT"), "JWT deve estar habilitado");
        assertTrue(ctx.has("CORS"), "CORS deve estar habilitado");
        assertFalse(ctx.has("SSRF"), "SSRF NÃO deve estar habilitado");
        assertFalse(ctx.has("GraphQL"), "GraphQL NÃO deve estar habilitado");
    }

    // ─────────────────────────────────────────
    // PQC — E2E Sprint
    // ─────────────────────────────────────────

    @Test
    @Order(39)
    void pqcSkipsNonHttps() throws Exception {
        List<String> logs = new java.util.ArrayList<>();
        List<Finding> findings = new PqcModule().scan(new ScanContext("http://example.com", "", Set.of("PQC")),
                logs::add);
        assertTrue(findings.isEmpty(), "PQC deve ignorar alvo HTTP");
        assertTrue(logs.stream().anyMatch(l -> l.contains("ignorado")), "PQC deve logar que foi ignorado em HTTP");
    }

    @Test
    @Order(40)
    void pqcHttpsLocalServerReturnsInfo() throws Exception {
        HttpsServer server = createTestHttpsServer(Map.of());
        int port = server.getAddress().getPort();
        try {
            ScanContext ctx = new ScanContext("https://127.0.0.1:" + port, "", Set.of("PQC"));
            List<Finding> findings = new PqcModule().scan(ctx, msg -> System.out.println("[PQC] " + msg));
            assertFalse(findings.isEmpty(), "PQC deve retornar ao menos um finding em servidor HTTPS local");
            assertTrue(findings.stream().anyMatch(f -> f.severity() == Severity.INFO || f.severity() == Severity.LOW),
                    "PQC deve reportar INFO ou LOW sobre suporte TLS 1.3");
        } finally {
            server.stop(0);
        }
    }

    // ─────────────────────────────────────────
    // ScanRunner — callbacks e isolamento
    // ─────────────────────────────────────────

    @Test
    @Order(41)
    void scanRunnerCallbacksFireInOrder() throws Exception {
        AtomicInteger startSeq = new AtomicInteger(0);
        AtomicInteger firstFindingSeq = new AtomicInteger(0);
        AtomicInteger finishSeq = new AtomicInteger(0);
        AtomicInteger counter = new AtomicInteger(0);
        CountDownLatch latch = new CountDownLatch(1);

        ScanRunner runner = new ScanRunner(msg -> {
        }, f -> {
            int seq = counter.incrementAndGet();
            firstFindingSeq.compareAndSet(0, seq);
        });
        runner.setOnScanStart(() -> startSeq.set(counter.incrementAndGet()));
        runner.setOnScanFinish(() -> {
            finishSeq.set(counter.incrementAndGet());
            latch.countDown();
        });

        // alg:none → CRITICAL finding sem rede; probes ativas são puladas
        String token = "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ0ZXN0In0.";
        runner.run(new ScanContext("https://example.com", token, Set.of("JWT")));
        assertTrue(latch.await(10, TimeUnit.SECONDS), "Scan deve completar em 10s");
        runner.shutdown();

        assertEquals(1, startSeq.get(), "onScanStart deve ser o primeiro evento");
        assertTrue(firstFindingSeq.get() > startSeq.get(), "findings devem chegar após onScanStart");
        assertTrue(finishSeq.get() > firstFindingSeq.get(), "onScanFinish deve chegar após os findings");
    }

    @Test
    @Order(42)
    void scanRunnerDisabledModuleDoesNotRun() throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", exchange -> {
            byte[] body = "ok".getBytes();
            exchange.sendResponseHeaders(200, body.length);
            exchange.getResponseBody().write(body);
            exchange.getResponseBody().close();
        });
        server.start();
        int port = server.getAddress().getPort();

        List<Finding> found = Collections.synchronizedList(new java.util.ArrayList<>());
        List<String> logs = Collections.synchronizedList(new java.util.ArrayList<>());
        CountDownLatch latch = new CountDownLatch(1);
        ScanRunner runner = new ScanRunner(logs::add, found::add);
        runner.setOnScanFinish(latch::countDown);

        try {
            runner.run(new ScanContext("http://127.0.0.1:" + port, "", Set.of("Headers")));
            assertTrue(latch.await(15, TimeUnit.SECONDS), "Scan deve completar em 15s");
            runner.shutdown();

            assertTrue(found.stream().anyMatch(f -> "Headers".equals(f.module())), "Headers deve gerar findings");
            assertTrue(found.stream().noneMatch(f -> "CORS".equals(f.module())), "CORS NÃO deve rodar se desabilitado");
            assertTrue(found.stream().noneMatch(f -> "SSRF".equals(f.module())), "SSRF NÃO deve rodar se desabilitado");
            assertTrue(logs.stream().noneMatch(l -> l.contains("Modulo CORS")),
                    "Log NÃO deve conter 'Modulo CORS' quando desabilitado");
        } finally {
            server.stop(0);
        }
    }

    @Test
    @Order(43)
    void scanRunnerAllModulesDisabledZeroFindings() throws Exception {
        List<Finding> found = Collections.synchronizedList(new java.util.ArrayList<>());
        CountDownLatch latch = new CountDownLatch(1);
        ScanRunner runner = new ScanRunner(msg -> {
        }, found::add);
        runner.setOnScanFinish(latch::countDown);
        runner.run(new ScanContext("https://example.com", "", Set.of()));
        assertTrue(latch.await(5, TimeUnit.SECONDS), "Scan vazio deve completar em 5s");
        runner.shutdown();
        assertTrue(found.isEmpty(), "Sem módulos habilitados → zero findings");
    }

    // ─────────────────────────────────────────
    // E2E Omnibus — servidor vulnerável completo
    // ─────────────────────────────────────────

    @Test
    @Order(44)
    void scanRunnerOmnibusVulnerableAllModules() throws Exception {
        HttpServer omnibus = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        int omPort = omnibus.getAddress().getPort();
        String omBase = "http://127.0.0.1:" + omPort;

        omnibus.createContext("/", exchange -> {
            String rawPath = exchange.getRequestURI().getRawPath();
            String path = exchange.getRequestURI().getPath();
            String query = exchange.getRequestURI().getRawQuery();
            String origin = exchange.getRequestHeaders().getFirst("Origin");

            // CORS: reflete origin com credentials em todos os requests
            if (origin != null && !origin.isBlank()) {
                exchange.getResponseHeaders().set("Access-Control-Allow-Origin", origin);
                exchange.getResponseHeaders().set("Access-Control-Allow-Credentials", "true");
            }

            // CRLF: injeta Set-Cookie quando path contém CRLF percent-encoded
            if (rawPath != null && (rawPath.toLowerCase().contains("%0a") || rawPath.toLowerCase().contains("%0d"))) {
                exchange.getResponseHeaders().add("Set-Cookie", "crlf=injection; Path=/; HttpOnly");
            }

            // GraphQL: retorna introspection no endpoint correto
            if ("/graphql".equals(path)) {
                byte[] b = ("{\"data\":{\"__schema\":{\"types\":[{\"name\":\"Query\"}]}}}").getBytes();
                exchange.getResponseHeaders().set("Content-Type", "application/json");
                exchange.sendResponseHeaders(200, b.length);
                exchange.getResponseBody().write(b);
                exchange.getResponseBody().close();
                return;
            }

            // OAuth: well-known discovery
            if (path.contains("openid-configuration") || path.contains("oauth-authorization-server")) {
                String disc = "{\"issuer\":\"" + omBase + "\"," + "\"authorization_endpoint\":\"" + omBase
                        + "/authorize\"}";
                byte[] b = disc.getBytes();
                exchange.getResponseHeaders().set("Content-Type", "application/json");
                exchange.sendResponseHeaders(200, b.length);
                exchange.getResponseBody().write(b);
                exchange.getResponseBody().close();
                return;
            }

            // OAuth: authorize com redirect_uri bypass
            if (path.endsWith("/authorize") && query != null && query.contains("redirect_uri=")) {
                String redir = java.util.Arrays.stream(query.split("&")).filter(p -> p.startsWith("redirect_uri="))
                        .map(p -> p.substring("redirect_uri=".length())).findFirst().orElse("");
                try {
                    redir = java.net.URLDecoder.decode(redir, "UTF-8");
                } catch (Exception ignored) {
                }
                exchange.getResponseHeaders().set("Location", redir + "?code=z");
                exchange.sendResponseHeaders(302, -1);
                exchange.getResponseBody().close();
                return;
            }
            if (path.endsWith("/authorize")) {
                byte[] b = "Login".getBytes();
                exchange.sendResponseHeaders(200, b.length);
                exchange.getResponseBody().write(b);
                exchange.getResponseBody().close();
                return;
            }

            // SSRF: metadata body quando query contém IPs de probe
            if (query != null && (query.contains("127.0.0.1") || query.contains("169.254")
                    || query.contains("localhost") || query.contains("0.0.0.0"))) {
                byte[] b = "ami-id: ami-12345678\ninstance-id: i-abc123456\n".getBytes();
                exchange.sendResponseHeaders(200, b.length);
                exchange.getResponseBody().write(b);
                exchange.getResponseBody().close();
                return;
            }

            // OpenRedirect: reflete valor do param se contiver evil host
            if (query != null) {
                for (String part : query.split("&")) {
                    int eq = part.indexOf('=');
                    if (eq > 0) {
                        String val = part.substring(eq + 1);
                        try {
                            val = java.net.URLDecoder.decode(val, "UTF-8");
                        } catch (Exception ignored) {
                        }
                        if (val.contains("evil.anarcry-probe.com")) {
                            exchange.getResponseHeaders().set("Location", val);
                            exchange.sendResponseHeaders(302, -1);
                            exchange.getResponseBody().close();
                            return;
                        }
                    }
                }
            }

            // Default: 200 OK, sem security headers (Headers module detecta ausências)
            byte[] b = "ok".getBytes();
            exchange.sendResponseHeaders(200, b.length);
            exchange.getResponseBody().write(b);
            exchange.getResponseBody().close();
        });
        omnibus.start();

        // JWT HS256 assinado com segredo fraco "secret", sem claim exp
        String jwtHdr = Base64.getUrlEncoder().withoutPadding()
                .encodeToString("{\"alg\":\"HS256\",\"typ\":\"JWT\"}".getBytes());
        String jwtPld = Base64.getUrlEncoder().withoutPadding().encodeToString("{\"sub\":\"admin\"}".getBytes());
        Mac jwtMac = Mac.getInstance("HmacSHA256");
        jwtMac.init(new SecretKeySpec("secret".getBytes("UTF-8"), "HmacSHA256"));
        String jwtSig = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(jwtMac.doFinal((jwtHdr + "." + jwtPld).getBytes("UTF-8")));
        String jwtToken = jwtHdr + "." + jwtPld + "." + jwtSig;

        List<Finding> collected = Collections.synchronizedList(new java.util.ArrayList<>());
        List<String> logLines = Collections.synchronizedList(new java.util.ArrayList<>());
        CountDownLatch latch = new CountDownLatch(1);
        ScanRunner runner = new ScanRunner(logLines::add, collected::add);
        runner.setOnScanFinish(latch::countDown);

        ScanContext ctx = new ScanContext(omBase, jwtToken,
                Set.of("TLS", "Headers", "JWT", "PQC", "CORS", "OAuth", "OpenRedirect", "SSRF", "GraphQL", "CRLF"));
        runner.run(ctx);

        try {
            assertTrue(latch.await(90, TimeUnit.SECONDS), "Omnibus scan deve completar em 90s");
            runner.shutdown();

            assertTrue(collected.size() >= 5, "Omnibus deve gerar ≥5 findings, gerou: " + collected.size());

            long crits = collected.stream().filter(f -> f.severity() == Severity.CRITICAL).count();
            assertTrue(crits >= 2, "Omnibus deve gerar ≥2 CRITICAL, gerou: " + crits);

            Set<String> mods = collected.stream().map(Finding::module).collect(java.util.stream.Collectors.toSet());
            assertTrue(mods.contains("Headers"), "Headers deve gerar findings");
            assertTrue(mods.contains("CORS"), "CORS deve detectar origin reflection");
            assertTrue(mods.contains("CRLF"), "CRLF deve detectar injeção");
            assertTrue(mods.contains("SSRF"), "SSRF deve detectar metadata exposure");
            assertTrue(mods.contains("GraphQL"), "GraphQL deve detectar introspection");
            assertTrue(mods.contains("OpenRedirect"), "OpenRedirect deve detectar redirect aberto");

            assertTrue(logLines.stream().anyMatch(l -> l.contains("TLS") && l.contains("ignorado")),
                    "TLS deve ser ignorado em alvo HTTP");
            assertTrue(logLines.stream().anyMatch(l -> l.contains("PQC") && l.contains("ignorado")),
                    "PQC deve ser ignorado em alvo HTTP");
        } finally {
            omnibus.stop(0);
        }
    }

    @Test
    @Order(45)
    void scanRunnerCleanServerNoFalsePositives() throws Exception {
        HttpServer clean = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        clean.createContext("/", exchange -> {
            byte[] b = "ok".getBytes();
            exchange.sendResponseHeaders(200, b.length);
            exchange.getResponseBody().write(b);
            exchange.getResponseBody().close();
        });
        clean.start();
        int cleanPort = clean.getAddress().getPort();

        List<Finding> found = Collections.synchronizedList(new java.util.ArrayList<>());
        CountDownLatch latch = new CountDownLatch(1);
        ScanRunner runner = new ScanRunner(msg -> {
        }, found::add);
        runner.setOnScanFinish(latch::countDown);

        // Módulos de probe: nenhum deve gerar false-positive em servidor limpo
        ScanContext ctx = new ScanContext("http://127.0.0.1:" + cleanPort, "",
                Set.of("CORS", "SSRF", "OpenRedirect", "CRLF", "GraphQL"));
        runner.run(ctx);

        try {
            assertTrue(latch.await(90, TimeUnit.SECONDS), "Clean scan deve completar em 90s");
            runner.shutdown();
            assertTrue(found.isEmpty(), "Servidor limpo NÃO deve gerar findings, gerou: " + found.stream()
                    .map(f -> f.module() + ": " + f.title()).collect(java.util.stream.Collectors.joining(", ")));
        } finally {
            clean.stop(0);
        }
    }

    @Test
    @Order(46)
    void e2eReportPipelineFromScanRunner() throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", exchange -> {
            String origin = exchange.getRequestHeaders().getFirst("Origin");
            if (origin != null) {
                exchange.getResponseHeaders().set("Access-Control-Allow-Origin", origin);
                exchange.getResponseHeaders().set("Access-Control-Allow-Credentials", "true");
            }
            byte[] b = "ok".getBytes();
            exchange.sendResponseHeaders(200, b.length);
            exchange.getResponseBody().write(b);
            exchange.getResponseBody().close();
        });
        server.start();
        int port = server.getAddress().getPort();

        List<Finding> collected = Collections.synchronizedList(new java.util.ArrayList<>());
        CountDownLatch latch = new CountDownLatch(1);
        ScanRunner runner = new ScanRunner(msg -> {
        }, collected::add);
        runner.setOnScanFinish(latch::countDown);
        runner.run(new ScanContext("http://127.0.0.1:" + port, "", Set.of("Headers", "CORS")));

        try {
            assertTrue(latch.await(20, TimeUnit.SECONDS), "Pipeline scan deve completar em 20s");
            runner.shutdown();

            assertFalse(collected.isEmpty(), "Pipeline deve gerar findings para exportar");
            assertTrue(collected.stream().anyMatch(f -> f.severity() == Severity.CRITICAL),
                    "CORS deve gerar CRITICAL na pipeline E2E");

            String mdFile = new ReportEngine().export(new java.util.ArrayList<>(collected), "http://127.0.0.1:" + port);
            Path md = Path.of(System.getProperty("user.dir")).resolve(mdFile);
            Path json = Path.of(System.getProperty("user.dir")).resolve(mdFile.replace(".md", ".json"));
            try {
                assertTrue(Files.exists(md), "Arquivo .md deve existir após export");
                assertTrue(Files.exists(json), "Arquivo .json deve existir após export");
                String mdContent = Files.readString(md);
                assertTrue(mdContent.contains("127.0.0.1"), "MD deve conter o target URL");
                assertTrue(mdContent.contains("CRITICAL"), "MD deve conter finding CRITICAL");
            } finally {
                Files.deleteIfExists(md);
                Files.deleteIfExists(json);
            }
        } finally {
            server.stop(0);
        }
    }

    // ─────────────────────────────────────────
    // Web Cache Poisoning — Sprint 25
    // ─────────────────────────────────────────

    @Test
    @Order(56)
    void cachePoisoningReflectedCachedCritical() throws Exception {
        // Simulates a real poisoned cache: first request with X-Forwarded-Host stores
        // the value,
        // subsequent requests (even without the header) keep returning the poisoned
        // body.
        java.util.concurrent.atomic.AtomicReference<String> cachedValue = new java.util.concurrent.atomic.AtomicReference<>(
                "ok");
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", exchange -> {
            String xfh = exchange.getRequestHeaders().getFirst("X-Forwarded-Host");
            if (xfh != null)
                cachedValue.set(xfh);
            byte[] body = cachedValue.get().getBytes();
            exchange.getResponseHeaders().set("X-Cache", "HIT from proxy");
            exchange.sendResponseHeaders(200, body.length);
            exchange.getResponseBody().write(body);
            exchange.getResponseBody().close();
        });
        server.start();
        int port = server.getAddress().getPort();
        try {
            ScanContext ctx = new ScanContext("http://127.0.0.1:" + port, "", Set.of("CachePoisoning"));
            List<Finding> findings = new CachePoisoningModule().scan(ctx, msg -> {
            });
            assertTrue(
                    findings.stream().anyMatch(
                            f -> f.severity() == Severity.CRITICAL && f.title().toLowerCase().contains("cache")),
                    "X-Forwarded-Host refletido + X-Cache:HIT deve gerar CRITICAL");
        } finally {
            server.stop(0);
        }
    }

    @Test
    @Order(57)
    void cachePoisoningReflectedNoCacheHigh() throws Exception {
        // Potentially vulnerable: reflects X-Forwarded-Host in body but no cache
        // indicators
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", exchange -> {
            String xfh = exchange.getRequestHeaders().getFirst("X-Forwarded-Host");
            byte[] body = (xfh != null ? xfh : "ok").getBytes();
            exchange.sendResponseHeaders(200, body.length);
            exchange.getResponseBody().write(body);
            exchange.getResponseBody().close();
        });
        server.start();
        int port = server.getAddress().getPort();
        try {
            ScanContext ctx = new ScanContext("http://127.0.0.1:" + port, "", Set.of("CachePoisoning"));
            List<Finding> findings = new CachePoisoningModule().scan(ctx, msg -> {
            });
            assertTrue(
                    findings.stream()
                            .anyMatch(f -> f.severity() == Severity.HIGH && f.title().toLowerCase().contains("cache")),
                    "X-Forwarded-Host refletido sem cache deve gerar HIGH");
        } finally {
            server.stop(0);
        }
    }

    @Test
    @Order(58)
    void cachePoisoningCleanNoFinding() throws Exception {
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
            ScanContext ctx = new ScanContext("http://127.0.0.1:" + port, "", Set.of("CachePoisoning"));
            List<Finding> findings = new CachePoisoningModule().scan(ctx, msg -> {
            });
            assertTrue(findings.isEmpty(), "Servidor que não reflete headers → sem finding");
        } finally {
            server.stop(0);
        }
    }

    // ─────────────────────────────────────────
    // HTTP Request Smuggling — Sprint 26
    // ─────────────────────────────────────────

    @Test
    @Order(59)
    void reqSmugglingClTeDetected() throws Exception {
        // Raw TCP server: hangs 5s when it receives both CL and TE headers (simulates
        // CL.TE vulnerable backend)
        java.net.ServerSocket rawServer = new java.net.ServerSocket(0);
        int rawPort = rawServer.getLocalPort();
        Thread serverThread = new Thread(() -> {
            try (java.net.Socket conn = rawServer.accept()) {
                conn.setSoTimeout(10_000);
                java.io.InputStream in = conn.getInputStream();
                byte[] buf = new byte[4096];
                int read = in.read(buf);
                String req = read > 0 ? new String(buf, 0, read, java.nio.charset.StandardCharsets.US_ASCII) : "";
                // Simulate CL.TE vulnerable: hang when both CL and TE are present
                if (req.contains("Content-Length") && req.contains("Transfer-Encoding")) {
                    Thread.sleep(5_000); // hang — module's 3s probe timeout will fire
                }
                String resp = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK";
                conn.getOutputStream().write(resp.getBytes(java.nio.charset.StandardCharsets.US_ASCII));
            } catch (Exception ignored) {
            }
        });
        serverThread.setDaemon(true);
        serverThread.start();
        try {
            ScanContext ctx = new ScanContext("http://127.0.0.1:" + rawPort, "", Set.of("ReqSmuggling"));
            List<Finding> findings = new RequestSmugglingModule().scan(ctx, msg -> System.out.println("[SMUG] " + msg));
            assertTrue(
                    findings.stream().anyMatch(
                            f -> f.severity() == Severity.CRITICAL && f.title().toLowerCase().contains("cl.te")),
                    "Servidor CL.TE deve gerar CRITICAL");
        } finally {
            rawServer.close();
        }
    }

    @Test
    @Order(60)
    void reqSmugglingCleanNoFinding() throws Exception {
        // Fast server: always responds quickly → no timing differential detected
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
            ScanContext ctx = new ScanContext("http://127.0.0.1:" + port, "", Set.of("ReqSmuggling"));
            List<Finding> findings = new RequestSmugglingModule().scan(ctx, msg -> {
            });
            assertTrue(findings.isEmpty(), "Servidor rápido não deve gerar finding de request smuggling");
        } finally {
            server.stop(0);
        }
    }

    // ─────────────────────────────────────────
    // CRLF Sprint 28 — injeção via request headers
    // ─────────────────────────────────────────

    @Test
    @Order(61)
    void crlfHeaderInjectionDetected() throws Exception {
        // Multi-connection raw TCP server: accepts all connections, reflects raw
        // User-Agent in response headers.
        // Path probes (via HttpClient) get a normal 200. Header probe (raw socket) gets
        // CRLF echoed back.
        java.net.ServerSocket rawServer = new java.net.ServerSocket(0);
        rawServer.setReuseAddress(true);
        int rawPort = rawServer.getLocalPort();
        Thread acceptLoop = new Thread(() -> {
            while (!rawServer.isClosed()) {
                try {
                    java.net.Socket conn = rawServer.accept();
                    new Thread(() -> {
                        try (java.net.Socket c = conn) {
                            c.setSoTimeout(5_000);
                            byte[] buf = new byte[4096];
                            int read = c.getInputStream().read(buf);
                            String req = read > 0
                                    ? new String(buf, 0, read, java.nio.charset.StandardCharsets.ISO_8859_1)
                                    : "";
                            StringBuilder resp = new StringBuilder("HTTP/1.1 200 OK\r\n");
                            // Vulnerable server: extracts User-Agent value without splitting on CRLF,
                            // then reflects it raw — CRLF in the value injects our marker as a new header
                            int uaIdx = req.indexOf("User-Agent: ");
                            if (uaIdx >= 0) {
                                int valStart = uaIdx + "User-Agent: ".length();
                                int valEnd = req.indexOf("\r\nConnection:", valStart);
                                if (valEnd < 0)
                                    valEnd = req.indexOf("\r\n\r\n", valStart);
                                if (valEnd > valStart) {
                                    String uaRaw = req.substring(valStart, valEnd);
                                    // Reflecting raw bytes — CRLF in value breaks out into a new header
                                    resp.append("X-Debug-UA: ").append(uaRaw).append("\r\n");
                                }
                            }
                            resp.append("Content-Length: 2\r\n\r\nOK");
                            c.getOutputStream()
                                    .write(resp.toString().getBytes(java.nio.charset.StandardCharsets.ISO_8859_1));
                        } catch (Exception ignored) {
                        }
                    }).start();
                } catch (Exception ignored) {
                    break;
                }
            }
        });
        acceptLoop.setDaemon(true);
        acceptLoop.start();
        try {
            ScanContext ctx = new ScanContext("http://127.0.0.1:" + rawPort, "", Set.of("CRLF"));
            List<Finding> findings = new CrlfModule().scan(ctx, msg -> System.out.println("[CRLF] " + msg));
            assertTrue(
                    findings.stream().anyMatch(
                            f -> f.severity() == Severity.CRITICAL && f.title().toLowerCase().contains("user-agent")),
                    "Servidor que reflete User-Agent com CRLF deve gerar CRITICAL");
        } finally {
            rawServer.close();
        }
    }

    @Test
    @Order(62)
    void crlfHeaderInjectionCleanNoFinding() throws Exception {
        // Safe server: responds normally, never injects our marker into response
        // headers
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
            ScanContext ctx = new ScanContext("http://127.0.0.1:" + port, "", Set.of("CRLF"));
            List<Finding> findings = new CrlfModule().scan(ctx, msg -> {
            });
            assertTrue(findings.isEmpty(), "Servidor que não reflete CRLF não deve gerar finding");
        } finally {
            server.stop(0);
        }
    }

    // ─────────────────────────────────────────
    // Utilitário: servidor HTTPS local com cert autoassinado
    // ─────────────────────────────────────────

    private static HttpsServer createTestHttpsServer(Map<String, String> extraHeaders) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(1024);
        KeyPair kp = kpg.generateKeyPair();

        long now = System.currentTimeMillis();
        X500Name subject = new X500Name("CN=localhost");
        ContentSigner signer = new JcaContentSignerBuilder("SHA256WithRSA").build(kp.getPrivate());
        GeneralNames sans = new GeneralNames(new GeneralName[]{new GeneralName(GeneralName.dNSName, "localhost"),
                new GeneralName(GeneralName.iPAddress, "127.0.0.1")});
        X509Certificate cert = new JcaX509CertificateConverter().getCertificate(new JcaX509v3CertificateBuilder(subject,
                BigInteger.ONE, new Date(now), new Date(now + 365L * 86400_000L), subject, kp.getPublic())
                .addExtension(Extension.subjectAlternativeName, false, sans).build(signer));

        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(null, null);
        ks.setKeyEntry("test", kp.getPrivate(), "x".toCharArray(), new java.security.cert.Certificate[]{cert});

        KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
        kmf.init(ks, "x".toCharArray());
        SSLContext ssl = SSLContext.getInstance("TLS");
        ssl.init(kmf.getKeyManagers(), null, null);

        HttpsServer server = HttpsServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.setHttpsConfigurator(new HttpsConfigurator(ssl));
        server.createContext("/", exchange -> {
            extraHeaders.forEach((k, v) -> exchange.getResponseHeaders().set(k, v));
            byte[] body = "ok".getBytes();
            exchange.sendResponseHeaders(200, body.length);
            exchange.getResponseBody().write(body);
            exchange.getResponseBody().close();
        });
        server.start();
        return server;
    }

    // ─────────────────────────────────────────
    // ScanEvent — Sprint 7
    // ─────────────────────────────────────────

    @Test
    @Order(47)
    void scanEventModuleDoneFiresPerModule() throws Exception {
        List<gg.effront.anarcry.scanner.ScanEvent> events = Collections.synchronizedList(new java.util.ArrayList<>());
        CountDownLatch latch = new CountDownLatch(1);

        // Two stub modules: JWT (alg:none — no network) + Headers (minimal server)
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
            String token = "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ0ZXN0In0.";
            ScanRunner runner = new ScanRunner(msg -> {
            }, f -> {
            });
            runner.setOnScanEvent(events::add);
            runner.setOnScanFinish(latch::countDown);
            runner.run(new ScanContext("http://127.0.0.1:" + port, token, Set.of("JWT", "Headers")));

            assertTrue(latch.await(20, TimeUnit.SECONDS), "Scan deve completar em 20s");
            runner.shutdown();

            long moduleDoneCount = events.stream()
                    .filter(e -> e.type() == gg.effront.anarcry.scanner.ScanEvent.Type.MODULE_DONE).count();
            assertEquals(2, moduleDoneCount, "Deve disparar exatamente 2 MODULE_DONE para 2 módulos");
        } finally {
            server.stop(0);
        }
    }

    @Test
    @Order(48)
    void scanEventIndexProgression() throws Exception {
        List<gg.effront.anarcry.scanner.ScanEvent> doneEvents = Collections
                .synchronizedList(new java.util.ArrayList<>());
        CountDownLatch latch = new CountDownLatch(1);

        // Three stub modules: JWT + CORS + CRLF (all HTTP, no TLS needed)
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
            String token = "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ0ZXN0In0.";
            ScanRunner runner = new ScanRunner(msg -> {
            }, f -> {
            });
            runner.setOnScanEvent(e -> {
                if (e.type() == gg.effront.anarcry.scanner.ScanEvent.Type.MODULE_DONE)
                    doneEvents.add(e);
            });
            runner.setOnScanFinish(latch::countDown);
            runner.run(new ScanContext("http://127.0.0.1:" + port, token, Set.of("JWT", "CORS", "CRLF")));

            assertTrue(latch.await(30, TimeUnit.SECONDS), "Scan deve completar em 30s");
            runner.shutdown();

            assertEquals(3, doneEvents.size(), "Deve ter 3 MODULE_DONE events");
            // Com execução paralela a ordem de conclusão é não-determinística;
            // verifica apenas que os índices 1-3 estão todos presentes.
            Set<Integer> indices = doneEvents.stream().map(gg.effront.anarcry.scanner.ScanEvent::index)
                    .collect(java.util.stream.Collectors.toSet());
            assertEquals(Set.of(1, 2, 3), indices, "MODULE_DONE deve conter os índices 1, 2 e 3");
            doneEvents.forEach(e -> assertEquals(3, e.total(), "Total deve ser 3 em todos os events"));
        } finally {
            server.stop(0);
        }
    }

    // ─────────────────────────────────────────
    // XXE — Sprint 11
    // ─────────────────────────────────────────

    @Test
    @Order(49)
    void xxeFileReadDetected() throws Exception {
        // Server accepts XML and echoes entity expansion (file read simulation)
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/api/", exchange -> {
            String body = exchange.getRequestBody().readAllBytes().length > 0
                    ? "myserver\n" // simulates /etc/hostname being returned
                    : "error";
            exchange.sendResponseHeaders(200, body.getBytes().length);
            exchange.getResponseBody().write(body.getBytes());
            exchange.getResponseBody().close();
        });
        server.start();
        int port = server.getAddress().getPort();
        try {
            ScanContext ctx = new ScanContext("http://127.0.0.1:" + port, "", Set.of("XXE"));
            List<Finding> findings = new XxeModule().scan(ctx, msg -> {
            });
            assertTrue(findings.stream().anyMatch(f -> f.severity() == Severity.CRITICAL && f.module().equals("XXE")),
                    "Servidor vulnerável a XXE deve gerar CRITICAL");
        } finally {
            server.stop(0);
        }
    }

    @Test
    @Order(50)
    void xxeCleanNoFinding() throws Exception {
        // Server returns 415 for XML (rejects it)
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", exchange -> {
            exchange.sendResponseHeaders(415, -1);
            exchange.getResponseBody().close();
        });
        server.start();
        int port = server.getAddress().getPort();
        try {
            ScanContext ctx = new ScanContext("http://127.0.0.1:" + port, "", Set.of("XXE"));
            List<Finding> findings = new XxeModule().scan(ctx, msg -> {
            });
            assertTrue(findings.isEmpty(), "Servidor rejeitando XML não deve gerar finding");
        } finally {
            server.stop(0);
        }
    }

    // ─────────────────────────────────────────
    // SSTI — Sprint 12
    // ─────────────────────────────────────────

    @Test
    @Order(51)
    void sstiFreemarkerDetected() throws Exception {
        // Server echoes "2401" when query param contains ${7*7*7*7} (7^4)
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", exchange -> {
            String query = exchange.getRequestURI().getQuery();
            String body;
            if (query != null && query.contains("7*7")) {
                body = "Result: 2401";
            } else {
                body = "Hello";
            }
            exchange.sendResponseHeaders(200, body.getBytes().length);
            exchange.getResponseBody().write(body.getBytes());
            exchange.getResponseBody().close();
        });
        server.start();
        int port = server.getAddress().getPort();
        try {
            ScanContext ctx = new ScanContext("http://127.0.0.1:" + port, "", Set.of("SSTI"));
            List<Finding> findings = new SstiModule().scan(ctx, msg -> {
            });
            assertTrue(findings.stream().anyMatch(f -> f.severity() == Severity.CRITICAL && f.module().equals("SSTI")),
                    "Servidor que retorna 2401 deve gerar SSTI CRITICAL");
        } finally {
            server.stop(0);
        }
    }

    @Test
    @Order(52)
    void sstiCleanNoFinding() throws Exception {
        // Server always returns the same text, never "49"
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", exchange -> {
            byte[] body = "Hello World".getBytes();
            exchange.sendResponseHeaders(200, body.length);
            exchange.getResponseBody().write(body);
            exchange.getResponseBody().close();
        });
        server.start();
        int port = server.getAddress().getPort();
        try {
            ScanContext ctx = new ScanContext("http://127.0.0.1:" + port, "", Set.of("SSTI"));
            List<Finding> findings = new SstiModule().scan(ctx, msg -> {
            });
            assertTrue(findings.isEmpty(), "Servidor sem SSTI não deve gerar finding");
        } finally {
            server.stop(0);
        }
    }

    // ─────────────────────────────────────────
    // IDOR — Sprint 13
    // ─────────────────────────────────────────

    @Test
    @Order(53)
    void idorDetectedCrossUser() throws Exception {
        // Server returns the same body regardless of which Bearer token is used
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/api/user/1", exchange -> {
            byte[] body = "{\"id\":1,\"name\":\"Alice\",\"email\":\"alice@example.com\"}".getBytes();
            exchange.sendResponseHeaders(200, body.length);
            exchange.getResponseBody().write(body);
            exchange.getResponseBody().close();
        });
        server.start();
        int port = server.getAddress().getPort();
        try {
            ScanContext ctx = new ScanContext("http://127.0.0.1:" + port, "token1", Set.of("IDOR"), "token2");
            List<Finding> findings = new IdorModule().scan(ctx, msg -> {
            });
            assertTrue(findings.stream().anyMatch(f -> f.severity() == Severity.HIGH && f.module().equals("IDOR")),
                    "Servidor que retorna o mesmo recurso para tokens diferentes deve gerar IDOR HIGH");
        } finally {
            server.stop(0);
        }
    }

    @Test
    @Order(54)
    void idorBlockedNoFinding() throws Exception {
        // Server returns 403 for token2 (correct authorization)
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/api/user/1", exchange -> {
            String auth = exchange.getRequestHeaders().getFirst("Authorization");
            if (auth != null && auth.contains("token2")) {
                exchange.sendResponseHeaders(403, -1);
            } else {
                byte[] body = "{\"id\":1,\"name\":\"Alice\"}".getBytes();
                exchange.sendResponseHeaders(200, body.length);
                exchange.getResponseBody().write(body);
            }
            exchange.getResponseBody().close();
        });
        server.start();
        int port = server.getAddress().getPort();
        try {
            ScanContext ctx = new ScanContext("http://127.0.0.1:" + port, "token1", Set.of("IDOR"), "token2");
            List<Finding> findings = new IdorModule().scan(ctx, msg -> {
            });
            assertTrue(findings.isEmpty(), "Servidor com autorização correta não deve gerar IDOR");
        } finally {
            server.stop(0);
        }
    }

    // ─────────────────────────────────────────
    // Sprint 16 — CVSS, CWE Registry, Dedup
    // ─────────────────────────────────────────

    @Test
    @Order(63)
    void cvssCalculatorKnownVectors() {
        assertEquals(10.0, CvssCalculator.calculate("AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N"), 0.1,
                "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N deve ser 10.0");
        assertEquals(7.5, CvssCalculator.calculate("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"), 0.1,
                "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N deve ser 7.5");
        assertEquals(0.0, CvssCalculator.calculate("AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"), 0.1,
                "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N deve ser 0.0");
    }

    @Test
    @Order(64)
    void cweRegistryMappedForAllModules() {
        List<String> moduleIds = List.of("TLS", "Headers", "JWT", "PQC", "CORS", "OAuth", "OpenRedirect", "SSRF",
                "GraphQL", "CRLF", "XXE", "SSTI", "IDOR", "HostHeader", "Actuator", "MassAssign", "CachePoisoning",
                "ReqSmuggling");
        for (String moduleId : moduleIds) {
            String[] entry = CweRegistry.forModule(moduleId);
            assertNotNull(entry, "forModule(" + moduleId + ") não deve retornar null");
            assertEquals(3, entry.length, "forModule(" + moduleId + ") deve ter 3 elementos");
        }
    }

    @Test
    @Order(65)
    void scanRunnerDeduplicatesDuplicateFindings() throws Exception {
        Finding dup = new Finding("Mock", "/dup", "Dup Title", Severity.HIGH, "ev", "imp", "rep", "rec", "CWE-200",
                "Exposure of Sensitive Information", "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", 5.3);

        Scanner mockScanner = new Scanner() {
            @Override
            public String id() {
                return "Mock";
            }
            @Override
            public List<Finding> scan(ScanContext ctx, java.util.function.Consumer<String> log) {
                return List.of(dup, dup);
            }
        };

        AtomicInteger counter = new AtomicInteger(0);
        CountDownLatch latch = new CountDownLatch(1);
        ScanRunner runner = new ScanRunner(msg -> {
        }, f -> counter.incrementAndGet());
        runner.addModule(mockScanner);
        runner.setOnScanFinish(latch::countDown);
        runner.run(new ScanContext("https://example.com", "", Set.of()));

        assertTrue(latch.await(5, TimeUnit.SECONDS), "Scan deve completar em 5s");
        runner.shutdown();
        assertEquals(1, counter.get(), "findingCb deve ser chamado apenas 1 vez para findings duplicados");
    }

    // ─────────────────────────────────────────
    // Crawler — Sprints 18-21
    // ─────────────────────────────────────────

    @Test
    @Order(66)
    void crawlerDiscoverOpenApi() throws Exception {
        // Server returns a minimal swagger.json at /swagger.json
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/swagger.json", exchange -> {
            byte[] body = ("{\"swagger\":\"2.0\",\"info\":{\"title\":\"Test\",\"version\":\"1.0\"}," + "\"paths\":{}}")
                    .getBytes();
            exchange.getResponseHeaders().set("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, body.length);
            exchange.getResponseBody().write(body);
            exchange.getResponseBody().close();
        });
        server.createContext("/", exchange -> {
            exchange.sendResponseHeaders(404, -1);
            exchange.getResponseBody().close();
        });
        server.start();
        int port = server.getAddress().getPort();
        try {
            ScanContext ctx = new ScanContext("http://127.0.0.1:" + port, "", Set.of("Crawler"));
            List<Finding> findings = new CrawlerModule().scan(ctx, msg -> {
            });
            assertTrue(
                    findings.stream()
                            .anyMatch(f -> f.title().toLowerCase().contains("openapi")
                                    || f.title().toLowerCase().contains("swagger")),
                    "CrawlerModule deve detectar OpenAPI/Swagger spec exposta");
        } finally {
            server.stop(0);
        }
    }

    @Test
    @Order(67)
    void crawlerWordlistSensitivePath() throws Exception {
        // Server returns 200 at /.env (sensitive path)
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/.env", exchange -> {
            byte[] body = "DB_PASSWORD=secret\nAPI_KEY=abc123\n".getBytes();
            exchange.sendResponseHeaders(200, body.length);
            exchange.getResponseBody().write(body);
            exchange.getResponseBody().close();
        });
        server.createContext("/", exchange -> {
            exchange.sendResponseHeaders(404, -1);
            exchange.getResponseBody().close();
        });
        server.start();
        int port = server.getAddress().getPort();
        try {
            ScanContext ctx = new ScanContext("http://127.0.0.1:" + port, "", Set.of("Crawler"));
            List<Finding> findings = new CrawlerModule().scan(ctx, msg -> {
            });
            assertTrue(findings.stream().anyMatch(f -> f.severity() == Severity.HIGH),
                    "CrawlerModule deve emitir finding HIGH para /.env acessível");
        } finally {
            server.stop(0);
        }
    }

    @Test
    @Order(68)
    void scanConfigDelayIsRespected() {
        ScanConfig config = new ScanConfig(0, "", Set.of(), List.of(), "");
        ScanContext ctx = new ScanContext("https://example.com", "", "", Set.of(), config, r -> {
        });
        assertEquals(config, ctx.config(), "ScanContext.config() deve retornar o ScanConfig fornecido");
        assertEquals(0, ctx.config().delayMs(), "ScanConfig.delayMs deve ser 0");
    }

    @Test
    @Order(69)
    void scanConfigInScopeCheck() {
        ScanConfig config = new ScanConfig(0, "", Set.of("allowed.com"), List.of(), "");
        assertTrue(config.isInScope("allowed.com"), "isInScope(\"allowed.com\") deve ser true");
        assertFalse(config.isInScope("blocked.com"), "isInScope(\"blocked.com\") deve ser false");
    }

    // ─────────────────────────────────────────
    // XSS / SQLi / LFI / CmdInjection — Sprint 30
    // ─────────────────────────────────────────

    @Test
    @Order(70)
    void xssReflectedDetected() throws Exception {
        // Vulnerable server: /search reflects q param literally in HTML body
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", exchange -> {
            String query = exchange.getRequestURI().getRawQuery();
            String reflected = "";
            if (query != null) {
                for (String part : query.split("&")) {
                    if (part.startsWith("q=") || part.startsWith("search=") || part.startsWith("query=")
                            || part.startsWith("s=") || part.startsWith("input=") || part.startsWith("term=")
                            || part.startsWith("keyword=")) {
                        try {
                            reflected = java.net.URLDecoder.decode(part.substring(part.indexOf('=') + 1), "UTF-8");
                        } catch (Exception ignored) {}
                        break;
                    }
                }
            }
            byte[] body = ("<html><body>" + reflected + "</body></html>").getBytes(java.nio.charset.StandardCharsets.UTF_8);
            exchange.getResponseHeaders().set("Content-Type", "text/html");
            exchange.sendResponseHeaders(200, body.length);
            exchange.getResponseBody().write(body);
            exchange.getResponseBody().close();
        });
        server.start();
        int port = server.getAddress().getPort();
        try {
            ScanContext ctx = new ScanContext("http://127.0.0.1:" + port, "", Set.of("XSS"));
            List<Finding> findings = new XssModule().scan(ctx, msg -> {});
            assertFalse(findings.isEmpty(), "XSS refletido deve gerar pelo menos um finding");
            assertTrue(findings.stream().anyMatch(f ->
                    f.severity() == Severity.HIGH || f.severity() == Severity.MEDIUM),
                    "XSS refletido deve gerar HIGH ou MEDIUM");
        } finally {
            server.stop(0);
        }
    }

    @Test
    @Order(71)
    void xssCleanNoFinding() throws Exception {
        // Safe server: HTML-encodes all output (< -> &lt; > -> &gt;)
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", exchange -> {
            String query = exchange.getRequestURI().getRawQuery();
            String reflected = "";
            if (query != null) {
                for (String part : query.split("&")) {
                    if (part.contains("=")) {
                        try {
                            reflected = java.net.URLDecoder.decode(part.substring(part.indexOf('=') + 1), "UTF-8");
                        } catch (Exception ignored) {}
                        break;
                    }
                }
            }
            // HTML-encode: replace < and > and " and '
            String safe = reflected
                    .replace("&", "&amp;")
                    .replace("<", "&lt;")
                    .replace(">", "&gt;")
                    .replace("\"", "&quot;")
                    .replace("'", "&#x27;");
            byte[] body = ("<html><body>" + safe + "</body></html>").getBytes(java.nio.charset.StandardCharsets.UTF_8);
            exchange.getResponseHeaders().set("Content-Type", "text/html");
            exchange.sendResponseHeaders(200, body.length);
            exchange.getResponseBody().write(body);
            exchange.getResponseBody().close();
        });
        server.start();
        int port = server.getAddress().getPort();
        try {
            ScanContext ctx = new ScanContext("http://127.0.0.1:" + port, "", Set.of("XSS"));
            List<Finding> findings = new XssModule().scan(ctx, msg -> {});
            assertTrue(findings.isEmpty(), "Servidor com HTML-encoding correto não deve gerar findings de XSS");
        } finally {
            server.stop(0);
        }
    }

    @Test
    @Order(72)
    void sqliErrorDetected() throws Exception {
        // Vulnerable server: returns SQL error message when URI contains single-quote
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", exchange -> {
            String rawQuery = exchange.getRequestURI().getRawQuery();
            String decoded = "";
            if (rawQuery != null) {
                try {
                    decoded = java.net.URLDecoder.decode(rawQuery, "UTF-8");
                } catch (Exception ignored) {}
            }
            byte[] body;
            if (decoded.contains("'")) {
                body = "You have an error in your SQL syntax near \"'\" at line 1".getBytes();
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
            List<Finding> findings = new SqlInjectionModule().scan(ctx, msg -> {});
            assertFalse(findings.isEmpty(), "SQLi com mensagem de erro SQL deve gerar finding");
            assertTrue(findings.stream().anyMatch(f -> f.severity() == Severity.CRITICAL),
                    "SQLi por erro de sintaxe deve gerar CRITICAL");
        } finally {
            server.stop(0);
        }
    }

    @Test
    @Order(73)
    void sqliCleanNoFinding() throws Exception {
        // Safe server: always returns "ok" without SQL error messages
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
            List<Finding> findings = new SqlInjectionModule().scan(ctx, msg -> {});
            assertTrue(findings.isEmpty(), "Servidor sem SQL errors não deve gerar findings de SQLi");
        } finally {
            server.stop(0);
        }
    }

    @Test
    @Order(74)
    void lfiPasswdDetected() throws Exception {
        // Vulnerable server: if URI contains "passwd", return /etc/passwd content
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", exchange -> {
            String rawQuery = exchange.getRequestURI().getRawQuery();
            String decoded = "";
            if (rawQuery != null) {
                try {
                    decoded = java.net.URLDecoder.decode(rawQuery, "UTF-8");
                } catch (Exception ignored) {}
            }
            byte[] body;
            if (decoded.contains("passwd") || decoded.contains("etc")) {
                body = "root:x:0:0:/root:/bin/bash\ndaemon:x:1:1:/usr/sbin:/usr/sbin/nologin\n".getBytes();
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
            ScanContext ctx = new ScanContext("http://127.0.0.1:" + port, "", Set.of("LFI"));
            List<Finding> findings = new LfiModule().scan(ctx, msg -> {});
            assertFalse(findings.isEmpty(), "LFI retornando /etc/passwd deve gerar finding");
            assertTrue(findings.stream().anyMatch(f ->
                    f.severity() == Severity.CRITICAL || f.severity() == Severity.HIGH),
                    "LFI com /etc/passwd deve gerar CRITICAL ou HIGH");
        } finally {
            server.stop(0);
        }
    }

    @Test
    @Order(75)
    void lfiCleanNoFinding() throws Exception {
        // Safe server: always returns "ok" 200
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
            ScanContext ctx = new ScanContext("http://127.0.0.1:" + port, "", Set.of("LFI"));
            List<Finding> findings = new LfiModule().scan(ctx, msg -> {});
            assertTrue(findings.isEmpty(), "Servidor limpo não deve gerar findings de LFI");
        } finally {
            server.stop(0);
        }
    }

    @Test
    @Order(76)
    void cmdInjectionActiveDetected() throws Exception {
        // Vulnerable server: /ping?host=... if body contains "; id" or "$(id)" returns uid output
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/ping", exchange -> {
            String rawQuery = exchange.getRequestURI().getRawQuery();
            String decoded = "";
            if (rawQuery != null) {
                try {
                    decoded = java.net.URLDecoder.decode(rawQuery, "UTF-8");
                } catch (Exception ignored) {}
            }
            byte[] body;
            if (decoded.contains("; id") || decoded.contains("$(id)") || decoded.contains("`id`")
                    || decoded.contains("| id") || decoded.contains("& id")
                    || decoded.contains("127.0.0.1; id")) {
                body = "PING 127.0.0.1: uid=33(www-data) gid=33(www-data) groups=33(www-data)\n".getBytes();
            } else {
                body = "PING 127.0.0.1: 56 data bytes\n".getBytes();
            }
            exchange.sendResponseHeaders(200, body.length);
            exchange.getResponseBody().write(body);
            exchange.getResponseBody().close();
        });
        server.createContext("/", exchange -> {
            byte[] body = "ok".getBytes();
            exchange.sendResponseHeaders(200, body.length);
            exchange.getResponseBody().write(body);
            exchange.getResponseBody().close();
        });
        server.start();
        int port = server.getAddress().getPort();
        try {
            ScanContext ctx = new ScanContext("http://127.0.0.1:" + port, "", Set.of("CmdInjection"));
            List<Finding> findings = new CommandInjectionModule().scan(ctx, msg -> {});
            assertFalse(findings.isEmpty(), "CmdInjection: servidor vulnerável deve gerar finding");
            assertTrue(findings.stream().anyMatch(f -> f.severity() == Severity.CRITICAL),
                    "OS Command Injection confirmado deve gerar CRITICAL");
        } finally {
            server.stop(0);
        }
    }

    @Test
    @Order(77)
    void cmdInjectionCleanNoFinding() throws Exception {
        // Safe server: /ping always returns clean output without uid strings
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", exchange -> {
            byte[] body = "PING 127.0.0.1: 56 data bytes\n64 bytes from 127.0.0.1: icmp_seq=0 ttl=64\n".getBytes();
            exchange.sendResponseHeaders(200, body.length);
            exchange.getResponseBody().write(body);
            exchange.getResponseBody().close();
        });
        server.start();
        int port = server.getAddress().getPort();
        try {
            ScanContext ctx = new ScanContext("http://127.0.0.1:" + port, "", Set.of("CmdInjection"));
            List<Finding> findings = new CommandInjectionModule().scan(ctx, msg -> {});
            assertTrue(findings.isEmpty(), "Servidor limpo não deve gerar findings de CmdInjection");
        } finally {
            server.stop(0);
        }
    }

    @Test
    @Order(55)
    void idorSkipsWhenNoToken2() throws Exception {
        // Server returns 403 for DELETE (no IDOR via deletion) and non-JSON for GraphQL
        // Phase 1 is skipped (no token2); phases 2+3 should not generate findings on
        // this server.
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", exchange -> {
            if ("DELETE".equals(exchange.getRequestMethod())) {
                exchange.sendResponseHeaders(403, -1);
            } else if (exchange.getRequestURI().getPath().contains("graphql")) {
                byte[] body = "not found".getBytes();
                exchange.sendResponseHeaders(404, body.length);
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
            // No jwtToken2 provided — phase 1 skipped; phases 2+3 find no IDOR on this
            // server
            ScanContext ctx = new ScanContext("http://127.0.0.1:" + port, "token1", Set.of("IDOR"));
            List<Finding> findings = new IdorModule().scan(ctx, msg -> {
            });
            assertTrue(findings.isEmpty(), "IDOR sem jwtToken2 e server seguro deve retornar lista vazia");
        } finally {
            server.stop(0);
        }
    }

    // ─────────────────────────────────────────
    // Sprint 19 — ScanConfig
    // ─────────────────────────────────────────

    @Test
    @Order(78)
    void scanConfigSessionCookieReturnsSetValue() {
        ScanConfig cfg = new ScanConfig(0, "session=abc123", Set.of(), List.of(), "");
        assertEquals("session=abc123", cfg.sessionCookie(),
                "sessionCookie() deve retornar o valor definido no construtor");
        assertTrue(cfg.isInScope("any.host.com"),
                "Config com inScopeHosts vazio deve permitir qualquer host");
    }

    @Test
    @Order(79)
    void scanConfigScopeBlocksOutOfScopeHost() {
        ScanConfig cfg = new ScanConfig(0, "", Set.of("api.target.com"), List.of(), "");
        assertTrue(cfg.isInScope("api.target.com"), "host em escopo deve retornar true");
        assertFalse(cfg.isInScope("evil.com"), "host fora do escopo deve retornar false");
        assertFalse(cfg.isInScope(""), "string vazia não deve estar em escopo específico");
    }

    @Test
    @Order(80)
    void scanConfigDefaultsAllowAllHosts() {
        ScanConfig defaults = ScanConfig.defaults();
        assertTrue(defaults.isInScope("anything.com"),
                "defaults() com inScopeHosts vazio deve permitir qualquer host");
        assertTrue(defaults.isInScope("other.com"),
                "defaults() não deve restringir nenhum host");
    }

    // ─────────────────────────────────────────
    // Sprint 20 — MassAssignment + IDOR
    // ─────────────────────────────────────────

    @Test
    @Order(81)
    void massAssignNoFindingOnPlain200() throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", exchange -> {
            byte[] body = "{\"status\":\"ok\"}".getBytes();
            exchange.sendResponseHeaders(200, body.length);
            exchange.getResponseBody().write(body);
            exchange.getResponseBody().close();
        });
        server.start();
        int port = server.getAddress().getPort();
        try {
            ScanContext ctx = new ScanContext("http://127.0.0.1:" + port, "", Set.of("MassAssign"));
            List<Finding> findings = new MassAssignmentModule().scan(ctx, msg -> {});
            assertTrue(findings.stream().noneMatch(f ->
                    f.severity() == Severity.CRITICAL || f.severity() == Severity.HIGH),
                    "Servidor com resposta simples não deve gerar CRITICAL ou HIGH em MassAssign");
        } finally {
            server.stop(0);
        }
    }

    @Test
    @Order(82)
    void massAssignMediumWhenAdminReflectedButNotPersisted() throws Exception {
        // Mutation returns admin-like but not exact ADMIN_PATTERN match; GET returns plain role
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", exchange -> {
            byte[] body = "GET".equals(exchange.getRequestMethod())
                    ? "{\"role\":\"user\",\"id\":\"1\"}".getBytes()
                    : "{\"admin\":\"yes\",\"role\":\"elevated\",\"message\":\"updated\"}".getBytes();
            exchange.sendResponseHeaders(200, body.length);
            exchange.getResponseBody().write(body);
            exchange.getResponseBody().close();
        });
        server.start();
        int port = server.getAddress().getPort();
        try {
            ScanContext ctx = new ScanContext("http://127.0.0.1:" + port, "", Set.of("MassAssign"));
            List<Finding> findings = new MassAssignmentModule().scan(ctx, msg -> {});
            assertTrue(findings.isEmpty() ||
                    findings.stream().noneMatch(f -> f.severity() == Severity.CRITICAL),
                    "MassAssign: campos admin-like sem match exato não devem gerar CRITICAL");
        } finally {
            server.stop(0);
        }
    }

    @Test
    @Order(83)
    void idorModuleSkipsSmallErrorResponses() throws Exception {
        // Both tokens receive short error body (< 50 chars) — isSimilar returns false
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", exchange -> {
            if ("DELETE".equals(exchange.getRequestMethod())) {
                exchange.sendResponseHeaders(403, -1);
                exchange.getResponseBody().close();
                return;
            }
            byte[] body = "{\"error\":\"unauthorized\"}".getBytes(); // 24 chars < 50
            exchange.sendResponseHeaders(200, body.length);
            exchange.getResponseBody().write(body);
            exchange.getResponseBody().close();
        });
        server.start();
        int port = server.getAddress().getPort();
        try {
            ScanContext ctx = new ScanContext("http://127.0.0.1:" + port, "token1", "token2",
                    Set.of("IDOR"));
            List<Finding> findings = new IdorModule().scan(ctx, msg -> {});
            assertTrue(findings.isEmpty(),
                    "IDOR não deve ser reportado quando respostas são erros curtos (< 50 chars)");
        } finally {
            server.stop(0);
        }
    }

    @Test
    @Order(84)
    void idorCrossUserConfirmed() throws Exception {
        // Both tokens receive identical large body — same resource accessible by different users
        String userData = "{\"id\":\"1\",\"name\":\"Alice\",\"email\":\"alice@example.com\","
                + "\"role\":\"user\",\"balance\":1000}";
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", exchange -> {
            if ("DELETE".equals(exchange.getRequestMethod())) {
                exchange.sendResponseHeaders(403, -1);
                exchange.getResponseBody().close();
                return;
            }
            byte[] body = userData.getBytes();
            exchange.sendResponseHeaders(200, body.length);
            exchange.getResponseBody().write(body);
            exchange.getResponseBody().close();
        });
        server.start();
        int port = server.getAddress().getPort();
        try {
            ScanContext ctx = new ScanContext("http://127.0.0.1:" + port, "token1", "token2",
                    Set.of("IDOR"));
            List<Finding> findings = new IdorModule().scan(ctx, msg -> {});
            assertTrue(findings.stream().anyMatch(f ->
                    f.severity() == Severity.HIGH || f.severity() == Severity.CRITICAL),
                    "IDOR deve ser detectado quando token2 acessa recurso de token1 (respostas idênticas)");
        } finally {
            server.stop(0);
        }
    }

    @AfterAll
    static void tearDownHttpClients() throws Exception {
        for (String fieldName : new String[]{"http2Instance", "noRedirectInstance"}) {
            Field f = HttpClientFactory.class.getDeclaredField(fieldName);
            f.setAccessible(true);
            java.net.http.HttpClient hc = (java.net.http.HttpClient) f.get(null);
            if (hc != null) {
                hc.close();
                f.set(null, null);
            }
        }
    }
}
