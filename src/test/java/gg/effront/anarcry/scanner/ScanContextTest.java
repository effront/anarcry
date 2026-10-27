package gg.effront.anarcry.scanner;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Set;

import org.junit.jupiter.api.Test;

class ScanContextTest {

    @Test
    void discoveredPathsStartsEmptyOnMinimalConstructor() {
        ScanContext ctx = new ScanContext("https://example.com", "", Set.of("TLS"));
        assertNotNull(ctx.discoveredPaths());
        assertTrue(ctx.discoveredPaths().isEmpty());
    }

    @Test
    void discoveredPathsStartsEmptyOn4ArgConstructor() {
        ScanContext ctx = new ScanContext("https://example.com", "", "", Set.of("TLS"));
        assertNotNull(ctx.discoveredPaths());
        assertTrue(ctx.discoveredPaths().isEmpty());
    }

    @Test
    void discoveredPathsStartsEmptyOnFullConvenienceConstructor() {
        ScanContext ctx = new ScanContext("https://example.com", "", Set.of("TLS"), "", ScanConfig.defaults(), r -> {
        });
        assertNotNull(ctx.discoveredPaths());
        assertTrue(ctx.discoveredPaths().isEmpty());
    }

    @Test
    void addPathsPopulatesDiscoveredPaths() {
        ScanContext ctx = new ScanContext("https://example.com", "", Set.of("SSRF"));
        ctx.discoveredPaths().addPath("/api/users");
        ctx.discoveredPaths().addParameter("url");
        assertEquals(1, ctx.discoveredPaths().pathCount());
        assertEquals(1, ctx.discoveredPaths().parameterCount());
        assertFalse(ctx.discoveredPaths().isEmpty());
    }

    @Test
    void existingAccessorsStillWork() {
        ScanContext ctx = new ScanContext("https://example.com:8443", "jwt", Set.of("TLS", "SSRF"));
        assertEquals("example.com", ctx.host());
        assertEquals(8443, ctx.port());
        assertTrue(ctx.isHttps());
        assertTrue(ctx.has("TLS"));
        assertTrue(ctx.has("SSRF"));
        assertFalse(ctx.has("XSS"));
    }

    @Test
    void defaultPortInference() {
        ScanContext http = new ScanContext("http://example.com", "", Set.of());
        assertEquals(80, http.port());
        assertFalse(http.isHttps());

        ScanContext https = new ScanContext("https://example.com", "", Set.of());
        assertEquals(443, https.port());
        assertTrue(https.isHttps());
    }
}
