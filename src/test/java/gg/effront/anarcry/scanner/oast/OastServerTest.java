package gg.effront.anarcry.scanner.oast;

import static org.junit.jupiter.api.Assertions.*;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.List;
import org.junit.jupiter.api.Test;

class OastServerTest {

    @Test
    void extractPayloadIdFromValidPath() {
        assertEquals("abcdef012345", OastServer.extractPayloadId("/abcdef012345"));
        assertEquals("abcdef012345", OastServer.extractPayloadId("/abcdef012345/extra/path"));
    }

    @Test
    void extractPayloadIdReturnsEmptyForInvalid() {
        assertEquals("", OastServer.extractPayloadId("/"));
        assertEquals("", OastServer.extractPayloadId(""));
        assertEquals("", OastServer.extractPayloadId(null));
        assertEquals("", OastServer.extractPayloadId("/too-short"));
        assertEquals("", OastServer.extractPayloadId("/ABCDEF012345")); // uppercase not valid
        assertEquals("", OastServer.extractPayloadId("/abcdefghijklmnop")); // too long
    }

    @Test
    void serverStartsAndAcceptsCallbacks() throws Exception {
        OastCorrelator correlator = new OastCorrelator();
        String payloadId = OastCorrelator.generatePayloadId();

        OastPayload payload = new OastPayload(payloadId, "TestModule", "/test", "param", "test-payload", 1000L);
        correlator.registerPayload(payload);

        try (OastServer server = new OastServer(correlator, "", msg -> {
        })) {
            assertTrue(server.port() > 0, "Server should bind to a valid port");
            assertFalse(server.callbackBaseUrl().isEmpty(), "Base URL should not be empty");

            // Send a callback request to the server
            HttpClient hc = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build();
            String callbackUrl = "http://127.0.0.1:" + server.port() + "/" + payloadId;
            HttpRequest req = HttpRequest.newBuilder().uri(URI.create(callbackUrl)).timeout(Duration.ofSeconds(5)).GET()
                    .build();
            HttpResponse<String> resp = hc.send(req, HttpResponse.BodyHandlers.ofString());

            assertEquals(200, resp.statusCode());

            // Verify callback was recorded and correlates
            assertEquals(1, correlator.callbackCount());
            List<OastCorrelator.CorrelatedHit> hits = correlator.correlate();
            assertEquals(1, hits.size());
            assertEquals(payloadId, hits.get(0).payload().payloadId());
            assertEquals("TestModule", hits.get(0).payload().moduleId());
            assertEquals("http", hits.get(0).callback().protocol());
        }
    }

    @Test
    void serverSetsCallbackBaseUrlOnCorrelator() throws Exception {
        OastCorrelator correlator = new OastCorrelator();
        assertEquals("", correlator.callbackBaseUrl());

        try (OastServer server = new OastServer(correlator, "", msg -> {
        })) {
            assertFalse(correlator.callbackBaseUrl().isEmpty());
            assertTrue(correlator.callbackBaseUrl().startsWith("http://"), "Callback URL should start with http://");
        }
    }

    @Test
    void serverUsesExternalUrlWhenProvided() throws Exception {
        OastCorrelator correlator = new OastCorrelator();
        String customUrl = "http://my-oast-server.example.com:8080";

        try (OastServer server = new OastServer(correlator, customUrl, msg -> {
        })) {
            assertEquals(customUrl, server.callbackBaseUrl());
            assertEquals(customUrl, correlator.callbackBaseUrl());
        }
    }

    @Test
    void serverStripsTrailingSlashFromExternalUrl() throws Exception {
        OastCorrelator correlator = new OastCorrelator();
        String customUrl = "http://my-oast-server.example.com:8080/";

        try (OastServer server = new OastServer(correlator, customUrl, msg -> {
        })) {
            assertEquals("http://my-oast-server.example.com:8080", server.callbackBaseUrl());
        }
    }

    @Test
    void nonMatchingCallbackDoesNotCorrelate() throws Exception {
        OastCorrelator correlator = new OastCorrelator();
        String payloadId = OastCorrelator.generatePayloadId();

        OastPayload payload = new OastPayload(payloadId, "TestModule", "/test", "param", "test-payload", 1000L);
        correlator.registerPayload(payload);

        try (OastServer server = new OastServer(correlator, "", msg -> {
        })) {
            // Send a request with a DIFFERENT payload ID
            HttpClient hc = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build();
            String otherUrl = "http://127.0.0.1:" + server.port() + "/999999999999";
            HttpRequest req = HttpRequest.newBuilder().uri(URI.create(otherUrl)).timeout(Duration.ofSeconds(5)).GET()
                    .build();
            HttpResponse<String> resp = hc.send(req, HttpResponse.BodyHandlers.ofString());

            assertEquals(200, resp.statusCode());
            // The callback was recorded but should not correlate
            List<OastCorrelator.CorrelatedHit> hits = correlator.correlate();
            assertTrue(hits.isEmpty());
        }
    }
}
