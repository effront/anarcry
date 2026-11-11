package gg.effront.anarcry.scanner.oast;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.io.OutputStream;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.NetworkInterface;
import java.nio.charset.StandardCharsets;
import java.util.Enumeration;
import java.util.function.Consumer;

/**
 * Lightweight HTTP callback listener for OAST (Out-of-Band Application Security
 * Testing).
 *
 * <p>
 * Uses the JDK built-in {@link com.sun.net.httpserver.HttpServer} to listen on
 * a random available port. Every incoming request is recorded as an
 * {@link OastCallback} via the {@link OastCorrelator}. The payload ID is
 * extracted from the first segment of the URL path.
 */
public class OastServer implements AutoCloseable {

    private final HttpServer server;
    private final OastCorrelator correlator;
    private final int port;
    private final String externalBaseUrl;

    /**
     * Start the OAST callback listener.
     *
     * @param correlator
     *            shared correlator instance for recording callbacks
     * @param externalUrl
     *            user-provided external URL (empty for auto-detect)
     * @param log
     *            callback for status messages
     * @throws IOException
     *             if the server cannot bind
     */
    public OastServer(OastCorrelator correlator, String externalUrl, Consumer<String> log) throws IOException {
        this.correlator = correlator;
        this.server = HttpServer.create(new InetSocketAddress(0), 0);
        this.port = server.getAddress().getPort();

        if (externalUrl != null && !externalUrl.isBlank()) {
            // Strip trailing slash for consistency
            this.externalBaseUrl = externalUrl.endsWith("/")
                    ? externalUrl.substring(0, externalUrl.length() - 1)
                    : externalUrl;
        } else {
            String detectedIp = detectExternalIp();
            this.externalBaseUrl = "http://" + detectedIp + ":" + port;
        }

        server.createContext("/", this::handleCallback);
        server.setExecutor(null);
        server.start();
        correlator.setCallbackBaseUrl(externalBaseUrl);
        log.accept("[+] OAST: callback server listening on port " + port + " (" + externalBaseUrl + ")");
    }

    /** Get the base callback URL (e.g. http://192.168.1.10:12345). */
    public String callbackBaseUrl() {
        return externalBaseUrl;
    }

    /** Generate a full callback URL for a specific payload ID. */
    public String callbackUrl(String payloadId) {
        return externalBaseUrl + "/" + payloadId;
    }

    /** The port the server is listening on. */
    public int port() {
        return port;
    }

    @Override
    public void close() {
        server.stop(0);
    }

    private void handleCallback(HttpExchange exchange) throws IOException {
        try {
            String path = exchange.getRequestURI().getPath();
            // Extract payload ID from first path segment: /abc123def456/... -> abc123def456
            String payloadId = extractPayloadId(path);

            String sourceIp = exchange.getRemoteAddress() != null
                    ? exchange.getRemoteAddress().getAddress().getHostAddress()
                    : "unknown";

            String method = exchange.getRequestMethod();
            String requestData = method + " " + exchange.getRequestURI() + " from " + sourceIp + " headers="
                    + exchange.getRequestHeaders().entrySet();

            if (!payloadId.isEmpty()) {
                OastCallback callback = new OastCallback(payloadId, "http", sourceIp, requestData,
                        System.currentTimeMillis());
                correlator.recordCallback(callback);
            }

            // Always respond 200 OK -- we want the target to consider the request
            // successful
            byte[] response = "ok".getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(200, response.length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(response);
            }
        } catch (Exception e) {
            // Best-effort: respond 200 even on internal errors to avoid leaking info
            try {
                exchange.sendResponseHeaders(200, 0);
                exchange.getResponseBody().close();
            } catch (Exception ignored) {
                // Connection may already be closed
            }
        }
    }

    /**
     * Extract payload ID from URL path. Expects format: /{payloadId} or
     * /{payloadId}/anything The payload ID is a 12-char hex string.
     */
    static String extractPayloadId(String path) {
        if (path == null || path.length() < 2) {
            return "";
        }
        // Remove leading slash
        String trimmed = path.startsWith("/") ? path.substring(1) : path;
        // Take first segment
        int slash = trimmed.indexOf('/');
        String segment = slash > 0 ? trimmed.substring(0, slash) : trimmed;
        // Validate: payload IDs are 12 hex chars
        if (segment.length() == 12 && segment.matches("[0-9a-f]+")) {
            return segment;
        }
        return "";
    }

    /**
     * Detect a non-loopback IPv4 address for this host. Falls back to 127.0.0.1 if
     * no external interface is found.
     */
    private static String detectExternalIp() {
        try {
            Enumeration<NetworkInterface> interfaces = NetworkInterface.getNetworkInterfaces();
            while (interfaces.hasMoreElements()) {
                NetworkInterface iface = interfaces.nextElement();
                if (iface.isLoopback() || !iface.isUp()) {
                    continue;
                }
                Enumeration<InetAddress> addresses = iface.getInetAddresses();
                while (addresses.hasMoreElements()) {
                    InetAddress addr = addresses.nextElement();
                    if (addr instanceof Inet4Address && !addr.isLoopbackAddress()) {
                        return addr.getHostAddress();
                    }
                }
            }
        } catch (Exception e) {
            // Fall through to default
        }
        return "127.0.0.1";
    }
}
