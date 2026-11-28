package gg.effront.anarcry.mcp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;

/**
 * Tests for the MCP server -- JSON-RPC 2.0 protocol, tool registry, and session
 * management. These tests start a real HTTP server on a random high port and
 * send actual HTTP requests.
 */
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class McpServerTest {

    private static final int TEST_PORT = 19900;
    private static McpServer server;
    private static HttpClient client;
    private static String baseUrl;

    @BeforeAll
    static void startServer() throws Exception {
        server = new McpServer(TEST_PORT, 2, 30, msg -> {
        });
        server.start();
        client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build();
        baseUrl = "http://localhost:" + TEST_PORT + "/mcp";
    }

    @AfterAll
    static void stopServer() {
        if (server != null) {
            server.close();
        }
        if (client != null) {
            client.close();
        }
    }

    @Test
    @Order(1)
    void initializeReturnsServerInfo() throws Exception {
        JsonObject req = rpcRequest("initialize", new JsonObject(), 1);
        JsonObject resp = sendRpc(req);

        assertEquals("2.0", resp.get("jsonrpc").getAsString());
        assertEquals(1, resp.get("id").getAsInt());
        assertTrue(resp.has("result"));

        JsonObject result = resp.getAsJsonObject("result");
        assertEquals("2025-06-18", result.get("protocolVersion").getAsString());

        JsonObject serverInfo = result.getAsJsonObject("serverInfo");
        assertEquals("anarcry-mcp", serverInfo.get("name").getAsString());

        JsonObject capabilities = result.getAsJsonObject("capabilities");
        JsonObject tools = capabilities.getAsJsonObject("tools");
        assertFalse(tools.get("listChanged").getAsBoolean());
    }

    @Test
    @Order(2)
    void toolsListReturns15Tools() throws Exception {
        JsonObject req = rpcRequest("tools/list", new JsonObject(), 2);
        JsonObject resp = sendRpc(req);

        assertEquals("2.0", resp.get("jsonrpc").getAsString());
        assertTrue(resp.has("result"));

        JsonObject result = resp.getAsJsonObject("result");
        JsonArray tools = result.getAsJsonArray("tools");
        assertEquals(15, tools.size());

        // Verify first tool has expected structure
        JsonObject first = tools.get(0).getAsJsonObject();
        assertTrue(first.has("name"));
        assertTrue(first.has("description"));
        assertTrue(first.has("inputSchema"));

        JsonObject schema = first.getAsJsonObject("inputSchema");
        assertEquals("object", schema.get("type").getAsString());
        assertTrue(schema.has("properties"));
        assertTrue(schema.has("required"));
    }

    @Test
    @Order(3)
    void toolsListContainsExpectedTools() throws Exception {
        JsonObject req = rpcRequest("tools/list", new JsonObject(), 3);
        JsonObject resp = sendRpc(req);

        JsonArray tools = resp.getAsJsonObject("result").getAsJsonArray("tools");
        String[] expected = {"scan_sqli", "scan_xss", "scan_ssrf", "scan_ssti", "scan_lfi", "scan_xxe", "scan_cors",
                "scan_headers", "scan_cmdinject", "scan_openredirect", "scan_graphql", "scan_jwt", "scan_tls",
                "scan_idor", "scan_csrf"};

        for (String toolName : expected) {
            boolean found = false;
            for (JsonElement el : tools) {
                if (toolName.equals(el.getAsJsonObject().get("name").getAsString())) {
                    found = true;
                    break;
                }
            }
            assertTrue(found, "Missing tool: " + toolName);
        }
    }

    @Test
    @Order(4)
    void unknownMethodReturnsError() throws Exception {
        JsonObject req = rpcRequest("nonexistent/method", new JsonObject(), 4);
        JsonObject resp = sendRpc(req);

        assertTrue(resp.has("error"));
        assertEquals(-32601, resp.getAsJsonObject("error").get("code").getAsInt());
    }

    @Test
    @Order(5)
    void invalidJsonReturnsParseError() throws Exception {
        HttpRequest httpReq = HttpRequest.newBuilder().uri(URI.create(baseUrl))
                .header("Content-Type", "application/json").POST(HttpRequest.BodyPublishers.ofString("{not valid json"))
                .timeout(Duration.ofSeconds(5)).build();
        HttpResponse<String> httpResp = client.send(httpReq, HttpResponse.BodyHandlers.ofString());

        JsonObject resp = JsonParser.parseString(httpResp.body()).getAsJsonObject();
        assertTrue(resp.has("error"));
        assertEquals(-32700, resp.getAsJsonObject("error").get("code").getAsInt());
    }

    @Test
    @Order(6)
    void missingJsonrpcVersionReturnsInvalidRequest() throws Exception {
        JsonObject req = new JsonObject();
        req.addProperty("method", "initialize");
        req.addProperty("id", 6);

        HttpRequest httpReq = HttpRequest.newBuilder().uri(URI.create(baseUrl))
                .header("Content-Type", "application/json").POST(HttpRequest.BodyPublishers.ofString(req.toString()))
                .timeout(Duration.ofSeconds(5)).build();
        HttpResponse<String> httpResp = client.send(httpReq, HttpResponse.BodyHandlers.ofString());

        JsonObject resp = JsonParser.parseString(httpResp.body()).getAsJsonObject();
        assertTrue(resp.has("error"));
        assertEquals(-32600, resp.getAsJsonObject("error").get("code").getAsInt());
    }

    @Test
    @Order(7)
    void toolsCallMissingTargetUrlReturnsError() throws Exception {
        JsonObject params = new JsonObject();
        params.addProperty("name", "scan_headers");
        params.add("arguments", new JsonObject());

        JsonObject req = rpcRequest("tools/call", params, 7);
        JsonObject resp = sendRpc(req);

        assertTrue(resp.has("error"));
        assertEquals(-32602, resp.getAsJsonObject("error").get("code").getAsInt());
    }

    @Test
    @Order(8)
    void toolsCallUnknownToolReturnsError() throws Exception {
        JsonObject params = new JsonObject();
        params.addProperty("name", "scan_nonexistent");

        JsonObject req = rpcRequest("tools/call", params, 8);
        JsonObject resp = sendRpc(req);

        assertTrue(resp.has("error"));
        assertEquals(-32602, resp.getAsJsonObject("error").get("code").getAsInt());
    }

    @Test
    @Order(9)
    void getMethodReturns405() throws Exception {
        HttpRequest httpReq = HttpRequest.newBuilder().uri(URI.create(baseUrl)).GET().timeout(Duration.ofSeconds(5))
                .build();
        HttpResponse<String> httpResp = client.send(httpReq, HttpResponse.BodyHandlers.ofString());
        assertEquals(405, httpResp.statusCode());
    }

    @Test
    @Order(10)
    void sessionIdHeaderIsPropagated() throws Exception {
        String customSessionId = "test-session-123";
        JsonObject req = rpcRequest("initialize", new JsonObject(), 10);

        HttpRequest httpReq = HttpRequest.newBuilder().uri(URI.create(baseUrl))
                .header("Content-Type", "application/json").header("Mcp-Session-Id", customSessionId)
                .POST(HttpRequest.BodyPublishers.ofString(req.toString())).timeout(Duration.ofSeconds(5)).build();
        HttpResponse<String> httpResp = client.send(httpReq, HttpResponse.BodyHandlers.ofString());

        assertEquals(200, httpResp.statusCode());
        String returnedSession = httpResp.headers().firstValue("Mcp-Session-Id").orElse("");
        assertEquals(customSessionId, returnedSession);
    }

    @Test
    @Order(11)
    void toolRegistryModuleIdMapping() {
        McpToolRegistry registry = new McpToolRegistry();
        assertEquals("SQLi", registry.moduleIdFor("scan_sqli"));
        assertEquals("XSS", registry.moduleIdFor("scan_xss"));
        assertEquals("SSRF", registry.moduleIdFor("scan_ssrf"));
        assertEquals("Headers", registry.moduleIdFor("scan_headers"));
        assertEquals("TLS", registry.moduleIdFor("scan_tls"));
        assertEquals("JWT", registry.moduleIdFor("scan_jwt"));
        assertEquals("IDOR", registry.moduleIdFor("scan_idor"));
        assertEquals("CSRF", registry.moduleIdFor("scan_csrf"));
        assertNotNull(registry.moduleIdFor("scan_cmdinject"));
        assertTrue(registry.has("scan_lfi"));
        assertFalse(registry.has("scan_nonexistent"));
    }

    @Test
    @Order(12)
    void sessionManagerConcurrency() {
        McpSessionManager mgr = new McpSessionManager(2);
        assertTrue(mgr.acquire());
        assertTrue(mgr.acquire());
        assertEquals(0, mgr.availablePermits());
        mgr.release();
        assertEquals(1, mgr.availablePermits());
        mgr.release();
        mgr.shutdown();
    }

    // -- helpers --

    private static JsonObject rpcRequest(String method, JsonObject params, int id) {
        JsonObject req = new JsonObject();
        req.addProperty("jsonrpc", "2.0");
        req.addProperty("method", method);
        req.add("params", params);
        req.addProperty("id", id);
        return req;
    }

    private static JsonObject sendRpc(JsonObject rpcReq) throws Exception {
        HttpRequest httpReq = HttpRequest.newBuilder().uri(URI.create(baseUrl))
                .header("Content-Type", "application/json").POST(HttpRequest.BodyPublishers.ofString(rpcReq.toString()))
                .timeout(Duration.ofSeconds(5)).build();
        HttpResponse<String> httpResp = client.send(httpReq, HttpResponse.BodyHandlers.ofString());
        assertEquals(200, httpResp.statusCode());
        return JsonParser.parseString(httpResp.body()).getAsJsonObject();
    }
}
