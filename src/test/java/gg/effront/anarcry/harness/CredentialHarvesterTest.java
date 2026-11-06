package gg.effront.anarcry.harness;

import com.sun.net.httpserver.HttpServer;
import gg.effront.anarcry.model.AuthType;
import gg.effront.anarcry.scanner.auth.AuthProvider;
import gg.effront.anarcry.scanner.auth.CredentialStore;
import gg.effront.anarcry.scanner.auth.ProviderDetector;
import gg.effront.anarcry.scanner.auth.firebase.FirebaseAuthClient;
import gg.effront.anarcry.scanner.auth.firebase.FirebaseConfig;
import gg.effront.anarcry.scanner.auth.firebase.FirebaseConfigExtractor;
import gg.effront.anarcry.scanner.auth.harvester.FirebaseHarvester;
import gg.effront.anarcry.scanner.auth.harvester.HarvesterRegistry;
import org.junit.jupiter.api.*;

import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class CredentialHarvesterTest {

    private static final String FIREBASE_PAGE = """
            <!DOCTYPE html>
            <html>
            <head><title>Test App</title></head>
            <body>
            <script>
            const firebaseConfig = {
                apiKey: "AIzaSyARDbQi_AWPlzwKQXbALXqAvtO13BoyeEw",
                authDomain: "test-project.firebaseapp.com",
                projectId: "test-project",
                storageBucket: "test-project.appspot.com",
                messagingSenderId: "573040944768",
                appId: "1:573040944768:web:464ea7a10ffd0fdbdb2865"
            };
            </script>
            </body>
            </html>
            """;

    private static final String PLAIN_PAGE = """
            <!DOCTYPE html>
            <html><head><title>Plain</title></head><body>No auth here</body></html>
            """;

    @Test
    @Order(1)
    void firebaseConfigExtractor_extractsFromHtml() {
        FirebaseConfig config = FirebaseConfigExtractor.extract(FIREBASE_PAGE);
        assertNotNull(config);
        assertEquals("AIzaSyARDbQi_AWPlzwKQXbALXqAvtO13BoyeEw", config.apiKey());
        assertEquals("test-project.firebaseapp.com", config.authDomain());
        assertEquals("test-project", config.projectId());
        assertEquals("test-project.appspot.com", config.storageBucket());
        assertEquals("573040944768", config.messagingSenderId());
    }

    @Test
    @Order(2)
    void firebaseConfigExtractor_returnsNullForPlainPage() {
        FirebaseConfig config = FirebaseConfigExtractor.extract(PLAIN_PAGE);
        assertNull(config);
    }

    @Test
    @Order(3)
    void firebaseConfigExtractor_looksLikeFirebase() {
        assertTrue(FirebaseConfigExtractor.looksLikeFirebase(FIREBASE_PAGE));
        assertFalse(FirebaseConfigExtractor.looksLikeFirebase(PLAIN_PAGE));
    }

    @Test
    @Order(10)
    void providerDetector_detectsFirebaseFromPage() {
        ProviderDetector.DiscoveryResult result = ProviderDetector.detectFromPage("https://example.com", FIREBASE_PAGE);
        assertNotNull(result);
        assertEquals(AuthProvider.FIREBASE, result.provider());
        assertEquals("AIzaSyARDbQi_AWPlzwKQXbALXqAvtO13BoyeEw", result.apiKey());
        assertTrue(result.authEndpoint().contains("signInWithPassword"));
        assertTrue(result.extra().containsKey("projectId"));
    }

    @Test
    @Order(11)
    void providerDetector_returnsNullForPlainPage() {
        ProviderDetector.DiscoveryResult result = ProviderDetector.detectFromPage("https://example.com", PLAIN_PAGE);
        assertNull(result);
    }

    @Test
    @Order(12)
    void providerDetector_detectsAuth0() {
        String page = "<script>const config = {domain: 'myapp.auth0.com', clientId: 'abc123'};</script>";
        ProviderDetector.DiscoveryResult result = ProviderDetector.detectFromPage("https://example.com", page);
        assertNotNull(result);
        assertEquals(AuthProvider.AUTH0, result.provider());
        assertEquals("abc123", result.clientId());
    }

    @Test
    @Order(13)
    void providerDetector_detectsSupabase() {
        String page = "<script>const url = 'https://abc.supabase.co'; const supabaseKey = 'eyJhbGci.test';</script>";
        ProviderDetector.DiscoveryResult result = ProviderDetector.detectFromPage("https://example.com", page);
        assertNotNull(result);
        assertEquals(AuthProvider.SUPABASE, result.provider());
    }

    @Test
    @Order(14)
    void providerDetector_detectsKeycloak() {
        String page = "<script>const kcUrl = 'https://sso.example.com/auth/realms/myapp';</script>";
        ProviderDetector.DiscoveryResult result = ProviderDetector.detectFromPage("https://example.com", page);
        assertNotNull(result);
        assertEquals(AuthProvider.KEYCLOAK, result.provider());
        assertEquals("myapp", result.extra().get("realm"));
    }

    @Test
    @Order(15)
    void providerDetector_detectsFirebaseViaLiveServer() throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", exchange -> {
            byte[] body = FIREBASE_PAGE.getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(200, body.length);
            exchange.getResponseBody().write(body);
            exchange.close();
        });
        server.start();
        int port = server.getAddress().getPort();
        try {
            ProviderDetector.DiscoveryResult result = ProviderDetector.detect("http://127.0.0.1:" + port + "/");
            assertNotNull(result);
            assertEquals(AuthProvider.FIREBASE, result.provider());
        } finally {
            server.stop(0);
        }
    }

    @Test
    @Order(20)
    void firebaseHarvester_canHandle() {
        FirebaseHarvester harvester = new FirebaseHarvester();
        assertEquals(AuthProvider.FIREBASE, harvester.provider());
        assertTrue(harvester.canHandle("https://example.com", FIREBASE_PAGE));
        assertFalse(harvester.canHandle("https://example.com", PLAIN_PAGE));
    }

    @Test
    @Order(21)
    void harvesterRegistry_detectsFirebase() {
        assertTrue(HarvesterRegistry.detect("https://example.com", FIREBASE_PAGE).isPresent());
        assertTrue(HarvesterRegistry.detect("https://example.com", PLAIN_PAGE).isEmpty());
        assertTrue(HarvesterRegistry.forProvider(AuthProvider.FIREBASE).isPresent());
        assertTrue(HarvesterRegistry.forProvider(AuthProvider.AUTH0).isEmpty());
    }

    @Test
    @Order(30)
    void firebaseHarvester_harvestWithMockServer() throws Exception {
        String authResponse = """
                {"idToken":"mock-id-token-xyz","refreshToken":"mock-refresh-token-abc","expiresIn":"3600","localId":"uid123","email":"test@test.com"}
                """;
        HttpServer authServer = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        authServer.createContext("/v1/accounts:signInWithPassword", exchange -> {
            byte[] body = authResponse.getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(200, body.length);
            exchange.getResponseBody().write(body);
            exchange.close();
        });
        authServer.start();
        int authPort = authServer.getAddress().getPort();

        HttpServer pageServer = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        String pageWithLocalApi = FIREBASE_PAGE.replace(
                "AIzaSyARDbQi_AWPlzwKQXbALXqAvtO13BoyeEw",
                "AIzaSyARDbQi_AWPlzwKQXbALXqAvtO13BoyeEw");
        pageServer.createContext("/", exchange -> {
            byte[] body = pageWithLocalApi.getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(200, body.length);
            exchange.getResponseBody().write(body);
            exchange.close();
        });
        pageServer.start();

        try {
            FirebaseConfig config = new FirebaseConfig("AIzaSyARDbQi_AWPlzwKQXbALXqAvtO13BoyeEw",
                    "test-project.firebaseapp.com", "test-project", "test-project.appspot.com",
                    "573040944768", "1:573040944768:web:464ea7a10ffd0fdbdb2865",
                    "http://127.0.0.1:" + authPort + "/v1",
                    "http://127.0.0.1:" + authPort + "/v1");

            FirebaseAuthClient.AuthResult result = FirebaseAuthClient.signInWithPassword(config, "test@test.com",
                    "password123");
            assertEquals("mock-id-token-xyz", result.idToken());
            assertEquals("mock-refresh-token-abc", result.refreshToken());
            assertEquals(3600, result.expiresIn());
            assertEquals("uid123", result.localId());
        } finally {
            authServer.stop(0);
            pageServer.stop(0);
        }
    }

    @Test
    @Order(40)
    void credentialStore_lifecycle() {
        CredentialStore store = new CredentialStore("token-1", "refresh-1", 3600, AuthProvider.FIREBASE,
                rt -> new CredentialStore.RefreshResult("token-2", "refresh-2", 3600));

        assertEquals("token-1", store.activeToken());
        assertEquals("refresh-1", store.refreshToken());
        assertEquals(AuthProvider.FIREBASE, store.provider());
        assertFalse(store.isExpiringSoon());
        assertFalse(store.isExpired());
        assertTrue(store.remainingSeconds() > 3500);
    }

    @Test
    @Order(41)
    void credentialStore_refresh() throws Exception {
        CredentialStore store = new CredentialStore("token-1", "refresh-1", 1, AuthProvider.FIREBASE,
                rt -> {
                    assertEquals("refresh-1", rt);
                    return new CredentialStore.RefreshResult("token-2", "refresh-2", 3600);
                });

        Thread.sleep(1100);
        assertTrue(store.isExpired());
        assertTrue(store.isExpiringSoon());

        String newToken = store.refresh();
        assertEquals("token-2", newToken);
        assertEquals("token-2", store.activeToken());
        assertEquals("refresh-2", store.refreshToken());
        assertFalse(store.isExpired());
    }

    @Test
    @Order(42)
    void credentialStore_destroy() {
        CredentialStore store = new CredentialStore("token", "refresh", 3600, AuthProvider.FIREBASE, rt -> null);
        store.destroy();
        assertNull(store.activeToken());
        assertNull(store.refreshToken());
    }

    @Test
    @Order(50)
    void authType_autoFlags() {
        assertEquals(5, AuthType.values().length);
        assertTrue(AuthType.AUTO.usesBearer());
        assertFalse(AuthType.AUTO.usesCookie());
        assertTrue(AuthType.AUTO.requiresJwtParsing());
        assertTrue(AuthType.AUTO.hasAuth());
        assertTrue(AuthType.AUTO.requiresHarvest());
        assertFalse(AuthType.JWT.requiresHarvest());
        assertFalse(AuthType.NONE.requiresHarvest());
    }

    @Test
    @Order(51)
    void authType_autoBuildContext() {
        var ctx = AuthType.AUTO.buildContext("https://example.com", java.util.Set.of("Headers"), null, null);
        assertNotNull(ctx);
        assertEquals("https://example.com", ctx.targetUrl());
        assertEquals("", ctx.jwtToken());
    }
}
