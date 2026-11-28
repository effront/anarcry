package gg.effront.anarcry.artex;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import java.util.List;
import java.util.concurrent.CompletableFuture;

/**
 * Minimal contract for communicating with an ARTEX middleware gateway. The
 * concrete ArtexClient implementation is being built in parallel -- this
 * interface defines the methods TaskOrchestrator depends on.
 *
 * <p>
 * All methods that hit the network return CompletableFuture so the caller never
 * blocks the scan thread. Implementations must be thread-safe.
 */
public interface ArtexClientApi {

    // -- Task lifecycle ----------------------------------------------------------

    /**
     * Creates a new ARTEX task for the given target.
     *
     * @param targetUrl
     *            the base URL being scanned
     * @param taskName
     *            human-readable label (e.g. "anarcry-<host>-<timestamp>")
     * @return future resolving to the ARTEX task ID
     */
    CompletableFuture<String> createTask(String targetUrl, String taskName);

    /**
     * Starts (or resumes) a previously created task.
     *
     * @param taskId
     *            the ARTEX task ID
     * @return future completing when the command is acknowledged
     */
    CompletableFuture<Void> startTask(String taskId);

    /**
     * Pauses a running task. The task can be resumed later via {@link #startTask}.
     *
     * @param taskId
     *            the ARTEX task ID
     * @return future completing when the command is acknowledged
     */
    CompletableFuture<Void> pauseTask(String taskId);

    /**
     * Stops a task permanently. No further work will be scheduled.
     *
     * @param taskId
     *            the ARTEX task ID
     * @return future completing when the command is acknowledged
     */
    CompletableFuture<Void> stopTask(String taskId);

    // -- Assets ------------------------------------------------------------------

    /**
     * Pushes discovered assets (URLs, paths, parameters) to an ARTEX task so the
     * remote engine can use them as seeds.
     *
     * @param taskId
     *            the ARTEX task ID
     * @param assets
     *            JSON array of asset objects ({@code [{"url":"...","type":"path"},
     *            ...]})
     * @return future completing when assets are accepted
     */
    CompletableFuture<Void> pushAssets(String taskId, JsonArray assets);

    // -- Findings ----------------------------------------------------------------

    /**
     * Pushes a batch of AnarCry findings to the ARTEX task.
     *
     * @param taskId
     *            the ARTEX task ID
     * @param findings
     *            JSON array of finding objects
     * @return future completing when findings are accepted
     */
    CompletableFuture<Void> pushFindings(String taskId, JsonArray findings);

    /**
     * Pulls all findings discovered by the ARTEX remote engine for the given task.
     *
     * @param taskId
     *            the ARTEX task ID
     * @return future resolving to a JSON array of ARTEX finding objects
     */
    CompletableFuture<JsonArray> pullFindings(String taskId);

    // -- Status ------------------------------------------------------------------

    /**
     * Retrieves the current status/summary of an ARTEX task.
     *
     * @param taskId
     *            the ARTEX task ID
     * @return future resolving to a status JSON object with at minimum:
     *         {@code status} (string), {@code findingCount} (int),
     *         {@code assetCount} (int)
     */
    CompletableFuture<JsonObject> getTaskStatus(String taskId);

    // -- Health ------------------------------------------------------------------

    /**
     * Pings the ARTEX gateway to verify connectivity.
     *
     * @return future resolving to true if the gateway is reachable
     */
    CompletableFuture<Boolean> ping();

    /**
     * Returns the list of vulnerability classes supported by the remote ARTEX
     * engine.
     *
     * @return future resolving to a list of vulnclass identifiers
     */
    CompletableFuture<List<String>> supportedVulnClasses();
}
