package gg.effront.anarcry.scanner.oast;

import static org.junit.jupiter.api.Assertions.*;

import java.util.List;
import org.junit.jupiter.api.Test;

class OastCorrelatorTest {

    @Test
    void generatePayloadIdReturns12HexChars() {
        String id = OastCorrelator.generatePayloadId();
        assertNotNull(id);
        assertEquals(12, id.length());
        assertTrue(id.matches("[0-9a-f]+"), "payload ID must be lowercase hex");
    }

    @Test
    void generatePayloadIdIsUnique() {
        String id1 = OastCorrelator.generatePayloadId();
        String id2 = OastCorrelator.generatePayloadId();
        assertNotEquals(id1, id2);
    }

    @Test
    void registerAndCorrelateWithMatchingCallback() {
        OastCorrelator correlator = new OastCorrelator();
        String pid = "abcdef012345";

        OastPayload payload = new OastPayload(pid, "SSRF", "/api/?url", "url", "http://callback/" + pid, 1000L);
        correlator.registerPayload(payload);
        assertEquals(1, correlator.pendingCount());

        OastCallback callback = new OastCallback(pid, "http", "10.0.0.1", "GET /abcdef012345", 2000L);
        correlator.recordCallback(callback);
        assertEquals(1, correlator.callbackCount());

        List<OastCorrelator.CorrelatedHit> hits = correlator.correlate();
        assertEquals(1, hits.size());
        assertEquals(pid, hits.get(0).payload().payloadId());
        assertEquals("SSRF", hits.get(0).payload().moduleId());
        assertEquals("10.0.0.1", hits.get(0).callback().sourceIp());
    }

    @Test
    void correlateReturnsEmptyWhenNoMatch() {
        OastCorrelator correlator = new OastCorrelator();

        OastPayload payload = new OastPayload("aaa111bbb222", "XXE", "/xml", "body", "<xml>...</xml>", 1000L);
        correlator.registerPayload(payload);

        OastCallback callback = new OastCallback("zzz999yyy888", "http", "10.0.0.1", "GET /zzz999yyy888", 2000L);
        correlator.recordCallback(callback);

        List<OastCorrelator.CorrelatedHit> hits = correlator.correlate();
        assertTrue(hits.isEmpty());
    }

    @Test
    void correlateReturnsEmptyWhenNoCallbacks() {
        OastCorrelator correlator = new OastCorrelator();
        OastPayload payload = new OastPayload("abc123def456", "SSRF", "/api", "url", "payload", 1000L);
        correlator.registerPayload(payload);

        List<OastCorrelator.CorrelatedHit> hits = correlator.correlate();
        assertTrue(hits.isEmpty());
    }

    @Test
    void callbackBaseUrlSetAndGet() {
        OastCorrelator correlator = new OastCorrelator();
        assertEquals("", correlator.callbackBaseUrl());

        correlator.setCallbackBaseUrl("http://192.168.1.10:54321");
        assertEquals("http://192.168.1.10:54321", correlator.callbackBaseUrl());
    }

    @Test
    void callbackUrlGeneratesCorrectUrl() {
        OastCorrelator correlator = new OastCorrelator();
        correlator.setCallbackBaseUrl("http://10.0.0.1:9999");
        assertEquals("http://10.0.0.1:9999/abc123def456", correlator.callbackUrl("abc123def456"));
    }

    @Test
    void callbackUrlReturnsEmptyWhenNoBaseUrl() {
        OastCorrelator correlator = new OastCorrelator();
        assertEquals("", correlator.callbackUrl("abc123def456"));
    }
}
