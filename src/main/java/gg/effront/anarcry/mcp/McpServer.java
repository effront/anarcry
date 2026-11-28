package gg.effront.anarcry.mcp;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.function.Consumer;

/**
 * Embedded MCP (Model Context Protocol) server for AnarCry. Exposes scanner
 * modules as tools callable by ARTEX workers via Streamable HTTP transport.
 *
 * <p>
 * Single endpoint: POST /mcp -- JSON-RPC 2.0 (initialize, tools/list,
 * tools/call).
 *
 * <p>
 * Uses com.sun.net.httpserver with virtual threads for request handling.
 * Default port 9900, configurable via constructor.
 */
public final class McpServer implements AutoCloseable {

    public static final int DEFAULT_PORT = 9900;
    private static final String MCP_PATH = "/mcp";
    private static final String CONTENT_TYPE_JSON = "application/json";

    private final int port;
    private final HttpServer server;
    private final ExecutorService requestPool;
    private final JsonRpcHandler rpcHandler;
    private final McpToolExecutor toolExecutor;
    private final McpSessionManager sessionManager;
    private final Consumer<String> log;

    /**
     * Creates an MCP server on the default port (9900).
     */
    public McpServer(Consumer<String> log) throws IOException {
        this(DEFAULT_PORT, log);
    }

    /**
     * Creates an MCP server on the specified port.
     */
    public McpServer(int port, Consumer<String> log) throws IOException {
        this(port, 4, 120, log);
    }

    /**
     * Creates an MCP server with full configuration.
     *
     * @param port
     *            TCP port to bind
     * @param maxConcurrent
     *            maximum concurrent tool executions
     * @param timeoutSeconds
     *            timeout per tool execution in seconds
     * @param log
     *            log callback for server events
     */
    public McpServer(int port, int maxConcurrent, int timeoutSeconds, Consumer<String> log) throws IOException {
        this.port = port;
        this.log = log;

        McpToolRegistry registry = new McpToolRegistry();
        this.sessionManager = new McpSessionManager(maxConcurrent);
        this.toolExecutor = new McpToolExecutor(registry, timeoutSeconds);
        this.rpcHandler = new JsonRpcHandler(registry, toolExecutor, sessionManager, log);

        this.requestPool = Executors.newThreadPerTaskExecutor(Thread.ofVirtual().name("mcp-http-", 0).factory());

        this.server = HttpServer.create(new InetSocketAddress(port), 0);
        this.server.createContext(MCP_PATH, new McpHttpHandler());
        this.server.setExecutor(requestPool);
    }

    /** Starts the HTTP server. Non-blocking. */
    public void start() {
        server.start();
        log.accept("[+] MCP server started on port " + port + " -- POST " + MCP_PATH);
        log.accept("[~] MCP protocol version: 2025-06-18");
        log.accept("[~] MCP tools registered: " + new McpToolRegistry().all().size());
    }

    /** Returns the port this server is bound to. */
    public int port() {
        return port;
    }

    /** Returns true if the server has active sessions. */
    public boolean hasActiveSessions() {
        return sessionManager.sessionCount() > 0;
    }

    /** Returns the number of active tool executions. */
    public int activeExecutions() {
        return sessionManager.activeExecutionCount();
    }

    /** Graceful shutdown: stops accepting requests, cancels active executions. */
    @Override
    public void close() {
        log.accept("[~] MCP server shutting down...");
        server.stop(2);
        toolExecutor.shutdown();
        sessionManager.shutdown();
        requestPool.shutdownNow();
        log.accept("[+] MCP server stopped");
    }

    /**
     * HTTP handler for the /mcp endpoint. Accepts only POST with JSON body. Routes
     * to JsonRpcHandler for JSON-RPC 2.0 dispatch.
     */
    private final class McpHttpHandler implements HttpHandler {

        @Override
        public void handle(HttpExchange exchange) throws IOException {
            // Only accept POST
            if (!"POST".equalsIgnoreCase(exchange.getRequestMethod())) {
                sendResponse(exchange, 405, "{\"error\":\"Method not allowed. Use POST.\"}");
                return;
            }

            // Read request body
            String requestBody;
            try (InputStream is = exchange.getRequestBody()) {
                requestBody = new String(is.readAllBytes(), StandardCharsets.UTF_8);
            }

            if (requestBody.isBlank()) {
                sendResponse(exchange, 400, "{\"error\":\"Empty request body\"}");
                return;
            }

            // Extract or generate session ID from header
            String sessionId = exchange.getRequestHeaders().getFirst("Mcp-Session-Id");
            if (sessionId == null || sessionId.isBlank()) {
                sessionId = sessionManager.newSessionId();
            }

            // Dispatch to JSON-RPC handler
            String responseBody;
            try {
                responseBody = rpcHandler.handle(requestBody, sessionId);
            } catch (Exception e) {
                log.accept("[!] MCP handler error: " + e.getMessage());
                responseBody = "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32603,"
                        + "\"message\":\"Internal server error\"},\"id\":null}";
            }

            // Set session ID header on response
            exchange.getResponseHeaders().set("Mcp-Session-Id", sessionId);
            sendResponse(exchange, 200, responseBody);
        }

        private void sendResponse(HttpExchange exchange, int statusCode, String body) throws IOException {
            byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().set("Content-Type", CONTENT_TYPE_JSON);
            exchange.getResponseHeaders().set("Access-Control-Allow-Origin", "*");
            exchange.getResponseHeaders().set("Access-Control-Allow-Headers", "Content-Type, Mcp-Session-Id");
            exchange.sendResponseHeaders(statusCode, bytes.length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(bytes);
            }
        }
    }
}
