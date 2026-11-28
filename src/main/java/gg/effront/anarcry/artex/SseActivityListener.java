package gg.effront.anarcry.artex;

import com.google.gson.Gson;
import com.google.gson.JsonObject;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Consumer;
import java.util.stream.Stream;

/**
 * SSE client that listens to the ARTEX real-time activity stream for a given
 * task. Connects to GET /api/tasks/{taskId}/exploration/activity and dispatches
 * parsed events to an {@link ActivityCallback}.
 *
 * <p>
 * The listener runs in a virtual thread and auto-reconnects with exponential
 * backoff on disconnects. Use {@link #stop()} to terminate gracefully.
 */
public class SseActivityListener {

    private static final long INITIAL_BACKOFF_MS = 1_000;
    private static final long MAX_BACKOFF_MS = 30_000;
    private static final Duration CONNECT_TIMEOUT = Duration.ofSeconds(10);
    private static final Gson GSON = new Gson();

    private final String baseUrl;
    private final String taskId;
    private final String bearerToken;
    private final ActivityCallback callback;
    private final Consumer<String> log;
    private final AtomicBoolean running = new AtomicBoolean(false);
    private volatile Thread listenerThread;
    private volatile String lastEventId = "";

    /**
     * Creates a new SSE activity listener.
     *
     * @param baseUrl
     *            ARTEX API base URL (e.g. "https://artex.example.com")
     * @param taskId
     *            the task ID to listen to
     * @param bearerToken
     *            Bearer token for Authorization header
     * @param callback
     *            event callback handler
     * @param log
     *            logging consumer -- uses [~] info, [+] success, [!] error format
     */
    public SseActivityListener(String baseUrl, String taskId, String bearerToken, ActivityCallback callback,
            Consumer<String> log) {
        this.baseUrl = baseUrl.endsWith("/") ? baseUrl.substring(0, baseUrl.length() - 1) : baseUrl;
        this.taskId = taskId;
        this.bearerToken = bearerToken;
        this.callback = callback;
        this.log = log;
    }

    /** Starts the SSE listener in a virtual thread. No-op if already running. */
    public void start() {
        if (running.compareAndSet(false, true)) {
            listenerThread = Thread.ofVirtual().name("artex-sse-" + taskId).start(this::listenLoop);
            log.accept("[~] SSE: listener started for task " + taskId);
        }
    }

    /**
     * Stops the listener gracefully. Thread-safe -- can be called from any thread.
     */
    public void stop() {
        if (running.compareAndSet(true, false)) {
            Thread t = listenerThread;
            if (t != null) {
                t.interrupt();
            }
            log.accept("[~] SSE: listener stopped for task " + taskId);
        }
    }

    /** Returns true if the listener is currently running. */
    public boolean isRunning() {
        return running.get();
    }

    /** Returns the last event ID received, for resume tracking. */
    public String lastEventId() {
        return lastEventId;
    }

    private void listenLoop() {
        long backoffMs = INITIAL_BACKOFF_MS;
        int attempt = 0;

        while (running.get()) {
            try {
                connectAndConsume();
                // If connectAndConsume returns normally (stream ended), reset backoff
                backoffMs = INITIAL_BACKOFF_MS;
                attempt = 0;
            } catch (InterruptedException ie) {
                Thread.currentThread().interrupt();
                break;
            } catch (Exception e) {
                if (!running.get()) {
                    break;
                }
                attempt++;
                callback.onError(e);
                callback.onReconnect(attempt);
                log.accept("[!] SSE: connection lost (attempt " + attempt + "): " + e.getMessage());

                try {
                    Thread.sleep(backoffMs);
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                    break;
                }

                backoffMs = Math.min(backoffMs * 2, MAX_BACKOFF_MS);
                log.accept("[~] SSE: reconnecting (backoff " + backoffMs + "ms)");
            }
        }

        running.set(false);
    }

    private void connectAndConsume() throws Exception {
        HttpClient hc = HttpClient.newBuilder().connectTimeout(CONNECT_TIMEOUT)
                .followRedirects(HttpClient.Redirect.NORMAL).version(HttpClient.Version.HTTP_2).build();

        String url = baseUrl + "/api/tasks/" + taskId + "/exploration/activity";
        HttpRequest.Builder reqBuilder = HttpRequest.newBuilder().uri(URI.create(url))
                .header("Accept", "text/event-stream").header("Authorization", "Bearer " + bearerToken)
                .header("Cache-Control", "no-cache").GET();

        if (!lastEventId.isEmpty()) {
            reqBuilder.header("Last-Event-ID", lastEventId);
        }

        HttpRequest req = reqBuilder.build();
        log.accept("[~] SSE: connecting to " + url);

        HttpResponse<Stream<String>> resp = hc.send(req, HttpResponse.BodyHandlers.ofLines());

        int status = resp.statusCode();
        if (status != 200) {
            throw new SseConnectionException("SSE endpoint returned HTTP " + status);
        }

        log.accept("[+] SSE: connected (HTTP " + status + ")");

        // Reset backoff on successful connection
        StringBuilder blockBuilder = new StringBuilder();

        try (Stream<String> lines = resp.body()) {
            lines.takeWhile(line -> running.get()).forEach(line -> {
                if (line.isEmpty()) {
                    // Blank line marks the end of an SSE event block
                    String block = blockBuilder.toString();
                    blockBuilder.setLength(0);

                    if (!block.isBlank()) {
                        long retryMs = SseEvent.parseRetry(block);
                        if (retryMs > 0) {
                            log.accept("[~] SSE: server requested retry interval " + retryMs + "ms");
                        }

                        SseEvent event = SseEvent.parse(block);
                        if (event != null) {
                            if (!event.id().isEmpty()) {
                                lastEventId = event.id();
                            }
                            dispatchEvent(event);
                        }
                    }
                } else {
                    blockBuilder.append(line).append('\n');
                }
            });
        }
    }

    private void dispatchEvent(SseEvent event) {
        try {
            switch (event.eventType()) {
                case "intent.created", "intent.completed", "intent.failed" -> dispatchIntent(event);
                case "finding.created", "finding.updated" -> dispatchFinding(event);
                case "asset.created" -> dispatchAsset(event);
                default -> log.accept("[~] SSE: unhandled event type '" + event.eventType() + "'");
            }
        } catch (Exception e) {
            log.accept("[!] SSE: error dispatching event '" + event.eventType() + "': " + e.getMessage());
            callback.onError(e);
        }
    }

    private void dispatchIntent(SseEvent event) {
        JsonObject json = GSON.fromJson(event.data(), JsonObject.class);
        String intentId = getStringOrEmpty(json, "id");
        String status = extractStatus(event.eventType());
        String summary = getStringOrEmpty(json, "summary");
        if (summary.isEmpty()) {
            summary = getStringOrEmpty(json, "description");
        }
        log.accept("[~] SSE: intent " + status + " -- " + intentId);
        callback.onIntent(intentId, status, summary);
    }

    private void dispatchFinding(SseEvent event) {
        JsonObject json = GSON.fromJson(event.data(), JsonObject.class);
        String findingId = getStringOrEmpty(json, "id");
        String title = getStringOrEmpty(json, "title");
        String severity = getStringOrEmpty(json, "severity");
        String action = event.eventType().equals("finding.created") ? "created" : "updated";
        log.accept("[!!] SSE: finding " + action + " -- " + title + " [" + severity + "]");
        callback.onFinding(findingId, title, severity);
    }

    private void dispatchAsset(SseEvent event) {
        JsonObject json = GSON.fromJson(event.data(), JsonObject.class);
        String assetType = getStringOrEmpty(json, "type");
        String value = getStringOrEmpty(json, "value");
        if (value.isEmpty()) {
            value = getStringOrEmpty(json, "address");
        }
        log.accept("[+] SSE: asset discovered -- " + assetType + ": " + value);
        callback.onAsset(assetType, value);
    }

    /**
     * Extracts the status suffix from a dotted event type (e.g. "intent.failed" ->
     * "failed").
     */
    private static String extractStatus(String eventType) {
        int dot = eventType.lastIndexOf('.');
        return dot >= 0 ? eventType.substring(dot + 1) : eventType;
    }

    private static String getStringOrEmpty(JsonObject json, String key) {
        if (json == null || !json.has(key) || json.get(key).isJsonNull()) {
            return "";
        }
        return json.get(key).getAsString();
    }

    /**
     * Exception for SSE connection-level errors (non-200 status, unexpected
     * disconnect).
     */
    public static class SseConnectionException extends Exception {

        public SseConnectionException(String message) {
            super(message);
        }
    }
}
