package gg.effront.anarcry.mcp;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import java.util.function.Consumer;

/**
 * Parses JSON-RPC 2.0 requests and routes them to the appropriate MCP handler.
 * Supports: initialize, tools/list, tools/call.
 */
public final class JsonRpcHandler {

    private static final String JSONRPC_VERSION = "2.0";
    private static final String MCP_PROTOCOL_VERSION = "2025-06-18";
    private static final String SERVER_NAME = "anarcry-mcp";
    private static final String SERVER_VERSION = "1.0.0";

    // JSON-RPC error codes
    private static final int PARSE_ERROR = -32700;
    private static final int INVALID_REQUEST = -32600;
    private static final int METHOD_NOT_FOUND = -32601;
    private static final int INVALID_PARAMS = -32602;
    private static final int INTERNAL_ERROR = -32603;

    private final McpToolRegistry registry;
    private final McpToolExecutor executor;
    private final McpSessionManager sessionManager;
    private final Consumer<String> log;

    public JsonRpcHandler(McpToolRegistry registry, McpToolExecutor executor, McpSessionManager sessionManager,
            Consumer<String> log) {
        this.registry = registry;
        this.executor = executor;
        this.sessionManager = sessionManager;
        this.log = log;
    }

    /**
     * Handles a raw JSON-RPC request body and returns the JSON-RPC response string.
     * The sessionId is extracted from the HTTP header by the caller and passed here
     * for session tracking.
     */
    public String handle(String requestBody, String sessionId) {
        JsonObject req;
        try {
            req = JsonParser.parseString(requestBody).getAsJsonObject();
        } catch (Exception e) {
            return errorResponse(null, PARSE_ERROR, "Parse error: invalid JSON");
        }

        if (!req.has("jsonrpc") || !JSONRPC_VERSION.equals(req.get("jsonrpc").getAsString())) {
            return errorResponse(extractId(req), INVALID_REQUEST, "Invalid JSON-RPC version");
        }

        if (!req.has("method")) {
            return errorResponse(extractId(req), INVALID_REQUEST, "Missing method field");
        }

        String method = req.get("method").getAsString();
        JsonObject params = req.has("params") ? req.getAsJsonObject("params") : new JsonObject();
        JsonElement id = extractId(req);

        return switch (method) {
            case "initialize" -> handleInitialize(id, sessionId);
            case "tools/list" -> handleToolsList(id);
            case "tools/call" -> handleToolsCall(id, params, sessionId);
            default -> errorResponse(id, METHOD_NOT_FOUND, "Unknown method: " + method);
        };
    }

    private String handleInitialize(JsonElement id, String sessionId) {
        sessionManager.getOrCreate(sessionId);
        log.accept("[~] MCP initialize: session=" + sessionId);

        JsonObject result = new JsonObject();
        result.addProperty("protocolVersion", MCP_PROTOCOL_VERSION);

        JsonObject serverInfo = new JsonObject();
        serverInfo.addProperty("name", SERVER_NAME);
        serverInfo.addProperty("version", SERVER_VERSION);
        result.add("serverInfo", serverInfo);

        JsonObject capabilities = new JsonObject();
        JsonObject tools = new JsonObject();
        tools.addProperty("listChanged", false);
        capabilities.add("tools", tools);
        result.add("capabilities", capabilities);

        return successResponse(id, result);
    }

    private String handleToolsList(JsonElement id) {
        log.accept("[~] MCP tools/list: " + registry.all().size() + " tools");

        JsonObject result = new JsonObject();
        result.add("tools", registry.toJsonArray());
        return successResponse(id, result);
    }

    private String handleToolsCall(JsonElement id, JsonObject params, String sessionId) {
        if (!params.has("name")) {
            return errorResponse(id, INVALID_PARAMS, "Missing tool name in params");
        }

        String toolName = params.get("name").getAsString();
        if (!registry.has(toolName)) {
            return errorResponse(id, INVALID_PARAMS, "Unknown tool: " + toolName);
        }

        JsonObject arguments = params.has("arguments") ? params.getAsJsonObject("arguments") : new JsonObject();

        if (!arguments.has("target_url")) {
            return errorResponse(id, INVALID_PARAMS, "Missing required argument: target_url");
        }

        String targetUrl = arguments.get("target_url").getAsString();
        if (!targetUrl.startsWith("http://") && !targetUrl.startsWith("https://")) {
            targetUrl = "https://" + targetUrl;
        }

        String authToken = arguments.has("auth_token") ? arguments.get("auth_token").getAsString() : "";

        log.accept("[~] MCP tools/call: " + toolName + " -> " + targetUrl);

        if (!sessionManager.acquire()) {
            return errorResponse(id, INTERNAL_ERROR, "Concurrency limit reached, try again later");
        }

        try {
            JsonArray content = executor.execute(toolName, targetUrl, authToken);

            JsonObject result = new JsonObject();
            result.add("content", content);
            result.addProperty("isError", false);

            log.accept("[+] MCP tools/call completed: " + toolName);
            return successResponse(id, result);
        } catch (Exception e) {
            log.accept("[!] MCP tools/call failed: " + toolName + " -- " + e.getMessage());

            JsonObject result = new JsonObject();
            JsonArray content = new JsonArray();
            JsonObject errorText = new JsonObject();
            errorText.addProperty("type", "text");
            errorText.addProperty("text", "Scan error: " + e.getMessage());
            content.add(errorText);
            result.add("content", content);
            result.addProperty("isError", true);

            return successResponse(id, result);
        } finally {
            sessionManager.release();
        }
    }

    private static String successResponse(JsonElement id, JsonObject result) {
        JsonObject resp = new JsonObject();
        resp.addProperty("jsonrpc", JSONRPC_VERSION);
        resp.add("result", result);
        if (id != null) {
            resp.add("id", id);
        }
        return resp.toString();
    }

    private static String errorResponse(JsonElement id, int code, String message) {
        JsonObject resp = new JsonObject();
        resp.addProperty("jsonrpc", JSONRPC_VERSION);

        JsonObject error = new JsonObject();
        error.addProperty("code", code);
        error.addProperty("message", message);
        resp.add("error", error);

        if (id != null) {
            resp.add("id", id);
        }
        return resp.toString();
    }

    private static JsonElement extractId(JsonObject req) {
        return req.has("id") ? req.get("id") : null;
    }
}
