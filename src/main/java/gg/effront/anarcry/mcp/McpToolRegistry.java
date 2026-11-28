package gg.effront.anarcry.mcp;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Registry of MCP tools exposed to ARTEX workers. Each tool maps to an AnarCry
 * scanner module. The registry produces JSON tool definitions for tools/list
 * and resolves tool names to their internal module IDs for tools/call dispatch.
 */
public final class McpToolRegistry {

    private final Map<String, ToolDef> tools = new LinkedHashMap<>();

    public McpToolRegistry() {
        register("scan_sqli", "SQLi", "Run SQL injection detection against a target endpoint");
        register("scan_xss", "XSS", "Run cross-site scripting detection against a target endpoint");
        register("scan_ssrf", "SSRF", "Run server-side request forgery detection against a target endpoint");
        register("scan_ssti", "SSTI", "Run server-side template injection detection against a target endpoint");
        register("scan_lfi", "LFI", "Run local file inclusion detection against a target endpoint");
        register("scan_xxe", "XXE", "Run XML external entity injection detection against a target endpoint");
        register("scan_cors", "CORS", "Run CORS misconfiguration detection against a target endpoint");
        register("scan_headers", "Headers", "Run security headers analysis against a target endpoint");
        register("scan_cmdinject", "CmdInjection", "Run OS command injection detection against a target endpoint");
        register("scan_openredirect", "OpenRedirect", "Run open redirect detection against a target endpoint");
        register("scan_graphql", "GraphQL",
                "Run GraphQL introspection and misconfiguration detection against a target endpoint");
        register("scan_jwt", "JWT", "Run JWT attack suite (alg:none, key confusion, JKU) against a target endpoint");
        register("scan_tls", "TLS", "Run TLS version, cipher suite and certificate analysis against a target endpoint");
        register("scan_idor", "IDOR", "Run insecure direct object reference detection against a target endpoint");
        register("scan_csrf", "CSRF", "Run cross-site request forgery detection against a target endpoint");
    }

    private void register(String toolName, String moduleId, String description) {
        tools.put(toolName, new ToolDef(toolName, moduleId, description));
    }

    /** Returns the internal module ID for a tool name, or null if unknown. */
    public String moduleIdFor(String toolName) {
        ToolDef def = tools.get(toolName);
        return def != null ? def.moduleId : null;
    }

    /** Returns true if the given tool name is registered. */
    public boolean has(String toolName) {
        return tools.containsKey(toolName);
    }

    /** Returns an unmodifiable view of all registered tool definitions. */
    public Map<String, ToolDef> all() {
        return Collections.unmodifiableMap(tools);
    }

    /**
     * Builds the JSON array for tools/list response. Each entry follows the MCP
     * tool schema: name, description, inputSchema.
     */
    public JsonArray toJsonArray() {
        JsonArray arr = new JsonArray();
        for (ToolDef def : tools.values()) {
            arr.add(def.toJson());
        }
        return arr;
    }

    /** Immutable definition of a single MCP tool. */
    public record ToolDef(String name, String moduleId, String description) {

        JsonObject toJson() {
            JsonObject tool = new JsonObject();
            tool.addProperty("name", name);
            tool.addProperty("description", description);
            tool.add("inputSchema", buildInputSchema());
            return tool;
        }

        private JsonObject buildInputSchema() {
            JsonObject schema = new JsonObject();
            schema.addProperty("type", "object");

            JsonObject props = new JsonObject();

            JsonObject targetUrl = new JsonObject();
            targetUrl.addProperty("type", "string");
            targetUrl.addProperty("description", "Target URL to scan");
            props.add("target_url", targetUrl);

            JsonObject params = new JsonObject();
            params.addProperty("type", "array");
            JsonObject paramItems = new JsonObject();
            paramItems.addProperty("type", "string");
            params.add("items", paramItems);
            params.addProperty("description", "Query parameters to test");
            props.add("parameters", params);

            JsonObject authToken = new JsonObject();
            authToken.addProperty("type", "string");
            authToken.addProperty("description", "Bearer token for authenticated scanning");
            props.add("auth_token", authToken);

            schema.add("properties", props);

            JsonArray required = new JsonArray();
            required.add("target_url");
            schema.add("required", required);

            return schema;
        }
    }
}
