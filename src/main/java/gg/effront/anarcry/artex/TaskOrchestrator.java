package gg.effront.anarcry.artex;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import gg.effront.anarcry.model.Finding;
import gg.effront.anarcry.scanner.ScanContext;
import gg.effront.anarcry.scanner.ScanRunner;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Consumer;

/**
 * Coordinates local AnarCry scans with remote ARTEX tasks. Thread-safe and
 * virtual-thread compatible -- all ARTEX network calls happen off the scan
 * thread via CompletableFuture.
 *
 * <p>
 * Lifecycle:
 *
 * <ol>
 * <li>{@link #startScan} creates an ARTEX task, wires a finding listener,
 * starts the local scan, seeds assets from crawler results, and starts the
 * ARTEX task.
 * <li>{@link #stopScan} stops both local and remote sides.
 * <li>{@link #pullArtexFindings} fetches findings from ARTEX and converts them
 * to AnarCry format.
 * <li>{@link #getSummary} returns combined local + remote statistics.
 * </ol>
 */
public class TaskOrchestrator {

    private static final int BATCH_SIZE = 20;
    private static final long FLUSH_INTERVAL_MS = 5_000;
    private final ArtexClientApi client;
    private final Consumer<String> log;

    /** Active tasks keyed by ARTEX taskId. */
    private final ConcurrentHashMap<String, TaskState> tasks = new ConcurrentHashMap<>();

    /**
     * Shared scheduler for periodic batch flushes. Daemon threads, single thread.
     */
    private final ScheduledExecutorService scheduler;

    /** Virtual-thread executor for async ARTEX calls. */
    private final ExecutorService asyncPool;

    public TaskOrchestrator(ArtexClientApi client, Consumer<String> log) {
        this.client = client;
        this.log = log;
        this.scheduler = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "artex-flush");
            t.setDaemon(true);
            return t;
        });
        this.asyncPool = Executors.newThreadPerTaskExecutor(Thread.ofVirtual().name("artex-async-", 0).factory());
    }

    /**
     * Creates an ARTEX task, starts the local scan, wires up real-time finding
     * push, seeds assets from crawler/infra discovery, and starts the ARTEX task.
     *
     * @param ctx
     *            the scan context (target, modules, config)
     * @return the ARTEX task ID for monitoring
     * @throws Exception
     *             if ARTEX task creation fails
     */
    public String startScan(ScanContext ctx) throws Exception {
        // 1. Create ARTEX task (blocking -- must have taskId before proceeding)
        String taskName = "anarcry-" + ctx.host() + "-" + Instant.now().getEpochSecond();
        log.accept("[~] ARTEX: creating task for " + ctx.targetUrl());

        String taskId;
        try {
            taskId = client.createTask(ctx.targetUrl(), taskName).get(15, TimeUnit.SECONDS);
        } catch (Exception e) {
            log.accept("[!] ARTEX: failed to create task -- " + unwrapMessage(e));
            throw e;
        }
        log.accept("[+] ARTEX: task created -- " + taskId);

        // 2. Initialize task state
        TaskState state = new TaskState(taskId, ctx, Instant.now());
        tasks.put(taskId, state);

        // 3. Wire ScanRunner with finding listener that batches pushes to ARTEX
        ScanRunner runner = new ScanRunner(log, finding -> onLocalFinding(taskId, finding));
        state.runner = runner;

        // 4. Schedule periodic batch flush
        state.flushHandle = scheduler.scheduleWithFixedDelay(() -> flushBatch(taskId), FLUSH_INTERVAL_MS,
                FLUSH_INTERVAL_MS, TimeUnit.MILLISECONDS);

        // 5. Start local scan (non-blocking -- ScanRunner.run() submits to its own
        // executor)
        log.accept("[~] ARTEX: starting local scan for task " + taskId);
        runner.setOnScanFinish(() -> {
            // Final flush when scan completes
            flushBatch(taskId);
            seedAssets(taskId, ctx);
            log.accept("[+] ARTEX: local scan finished for task " + taskId);
        });
        runner.run(ctx);

        // 6. Start ARTEX task (async -- don't block scan thread)
        CompletableFuture.runAsync(() -> {
            try {
                client.startTask(taskId).get(10, TimeUnit.SECONDS);
                log.accept("[+] ARTEX: remote task started -- " + taskId);
            } catch (Exception e) {
                log.accept("[!] ARTEX: failed to start remote task -- " + unwrapMessage(e));
            }
        }, asyncPool);

        return taskId;
    }

    /**
     * Stops both the local scan and the remote ARTEX task.
     *
     * @param taskId
     *            the ARTEX task ID
     */
    public void stopScan(String taskId) {
        TaskState state = tasks.get(taskId);
        if (state == null) {
            log.accept("[!] ARTEX: unknown task " + taskId);
            return;
        }

        // Stop local scan
        if (state.runner != null) {
            state.runner.shutdown();
            log.accept("[+] ARTEX: local scan stopped for task " + taskId);
        }

        // Cancel flush scheduler
        if (state.flushHandle != null) {
            state.flushHandle.cancel(false);
        }

        // Final flush before stopping
        flushBatch(taskId);

        // Stop ARTEX task (async)
        CompletableFuture.runAsync(() -> {
            try {
                client.stopTask(taskId).get(10, TimeUnit.SECONDS);
                log.accept("[+] ARTEX: remote task stopped -- " + taskId);
            } catch (Exception e) {
                log.accept("[!] ARTEX: failed to stop remote task -- " + unwrapMessage(e));
            }
        }, asyncPool);

        state.stopped.set(true);
    }

    /**
     * Pauses only the ARTEX remote side. Local scan continues running.
     *
     * @param taskId
     *            the ARTEX task ID
     */
    public void pauseArtex(String taskId) {
        CompletableFuture.runAsync(() -> {
            try {
                client.pauseTask(taskId).get(10, TimeUnit.SECONDS);
                log.accept("[+] ARTEX: remote task paused -- " + taskId);
            } catch (Exception e) {
                log.accept("[!] ARTEX: failed to pause remote task -- " + unwrapMessage(e));
            }
        }, asyncPool);
    }

    /**
     * Resumes a paused ARTEX remote task. Local scan is unaffected.
     *
     * @param taskId
     *            the ARTEX task ID
     */
    public void resumeArtex(String taskId) {
        CompletableFuture.runAsync(() -> {
            try {
                client.startTask(taskId).get(10, TimeUnit.SECONDS);
                log.accept("[+] ARTEX: remote task resumed -- " + taskId);
            } catch (Exception e) {
                log.accept("[!] ARTEX: failed to resume remote task -- " + unwrapMessage(e));
            }
        }, asyncPool);
    }

    /**
     * Pulls findings from the ARTEX remote engine and converts them to AnarCry
     * Finding format (reverse sync).
     *
     * @param taskId
     *            the ARTEX task ID
     * @return list of AnarCry Findings from the remote engine
     */
    public List<Finding> pullArtexFindings(String taskId) {
        try {
            JsonArray remote = client.pullFindings(taskId).get(30, TimeUnit.SECONDS);
            List<Finding> converted = ArtexFindingConverter.convert(remote);
            log.accept("[+] ARTEX: pulled " + converted.size() + " finding(s) from task " + taskId);

            TaskState state = tasks.get(taskId);
            if (state != null) {
                state.artexFindingCount.set(converted.size());
            }
            return converted;
        } catch (Exception e) {
            log.accept("[!] ARTEX: failed to pull findings -- " + unwrapMessage(e));
            return List.of();
        }
    }

    /**
     * Returns combined local + remote scan statistics.
     *
     * @param taskId
     *            the ARTEX task ID
     * @return a ScanSummary with merged stats, or a zeroed summary if the task is
     *         unknown
     */
    public ScanSummary getSummary(String taskId) {
        TaskState state = tasks.get(taskId);
        if (state == null) {
            return new ScanSummary(0, 0, 0, "unknown", Duration.ZERO);
        }

        int localCount = state.localFindingCount.get();
        int artexCount = state.artexFindingCount.get();
        Duration elapsed = Duration.between(state.startTime, Instant.now());

        // Fetch remote status (best-effort, don't block forever)
        String status = "running";
        int assetCount = 0;
        try {
            JsonObject remoteStatus = client.getTaskStatus(taskId).get(5, TimeUnit.SECONDS);
            if (remoteStatus.has("status")) {
                status = remoteStatus.get("status").getAsString();
            }
            if (remoteStatus.has("assetCount")) {
                assetCount = remoteStatus.get("assetCount").getAsInt();
            }
            if (remoteStatus.has("findingCount")) {
                artexCount = Math.max(artexCount, remoteStatus.get("findingCount").getAsInt());
            }
        } catch (Exception e) {
            log.accept("[~] ARTEX: could not fetch remote status -- " + unwrapMessage(e));
            if (state.stopped.get()) {
                status = "stopped";
            }
        }

        return new ScanSummary(localCount, artexCount, assetCount, status, elapsed);
    }

    /**
     * Shuts down the orchestrator, cancelling all flush schedulers and stopping the
     * async pool. Active scans are NOT stopped -- call {@link #stopScan} first if
     * needed.
     */
    public void shutdown() {
        scheduler.shutdownNow();
        asyncPool.shutdownNow();
    }

    // -- Internal: finding batch push ------------------------------------------

    /** Called by ScanRunner's findingCb for each local finding. */
    private void onLocalFinding(String taskId, Finding finding) {
        TaskState state = tasks.get(taskId);
        if (state == null || state.stopped.get()) {
            return;
        }
        state.localFindingCount.incrementAndGet();
        state.pendingFindings.add(finding);

        // Flush immediately if batch is full
        if (state.pendingFindings.size() >= BATCH_SIZE) {
            flushBatch(taskId);
        }
    }

    /** Drains pending findings and pushes them to ARTEX as a batch. */
    private void flushBatch(String taskId) {
        TaskState state = tasks.get(taskId);
        if (state == null) {
            return;
        }

        List<Finding> batch = new ArrayList<>();
        Finding f;
        while ((f = state.pendingFindings.poll()) != null) {
            batch.add(f);
        }
        if (batch.isEmpty()) {
            return;
        }

        JsonArray arr = new JsonArray();
        for (Finding finding : batch) {
            arr.add(FindingDto.toJsonObject(finding));
        }

        // Push async -- don't block scan thread
        CompletableFuture.runAsync(() -> {
            try {
                client.pushFindings(taskId, arr).get(15, TimeUnit.SECONDS);
                log.accept("[~] ARTEX: pushed " + batch.size() + " finding(s) to task " + taskId);
            } catch (Exception e) {
                log.accept("[!] ARTEX: failed to push findings -- " + unwrapMessage(e));
                // Re-queue for retry on next flush
                state.pendingFindings.addAll(batch);
            }
        }, asyncPool);
    }

    /**
     * Seeds ARTEX task with discovered paths and parameters from the local scan.
     */
    private void seedAssets(String taskId, ScanContext ctx) {
        JsonArray assets = new JsonArray();

        for (String path : ctx.discoveredPaths().paths()) {
            JsonObject asset = new JsonObject();
            asset.addProperty("url", path);
            asset.addProperty("type", "path");
            assets.add(asset);
        }
        for (String param : ctx.discoveredPaths().parameters()) {
            JsonObject asset = new JsonObject();
            asset.addProperty("name", param);
            asset.addProperty("type", "parameter");
            assets.add(asset);
        }

        if (assets.isEmpty()) {
            return;
        }

        CompletableFuture.runAsync(() -> {
            try {
                client.pushAssets(taskId, assets).get(15, TimeUnit.SECONDS);
                log.accept("[+] ARTEX: seeded " + assets.size() + " asset(s) to task " + taskId);
            } catch (Exception e) {
                log.accept("[!] ARTEX: failed to push assets -- " + unwrapMessage(e));
            }
        }, asyncPool);
    }

    /** Unwraps nested exception messages for cleaner logging. */
    private static String unwrapMessage(Exception e) {
        Throwable cause = e.getCause();
        if (cause != null && cause.getMessage() != null) {
            return cause.getMessage();
        }
        return e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName();
    }

    // -- Internal state per task -----------------------------------------------

    private static class TaskState {
        final String taskId;
        final ScanContext ctx;
        final Instant startTime;
        final AtomicInteger localFindingCount = new AtomicInteger(0);
        final AtomicInteger artexFindingCount = new AtomicInteger(0);
        final AtomicBoolean stopped = new AtomicBoolean(false);
        final ConcurrentLinkedQueue<Finding> pendingFindings = new ConcurrentLinkedQueue<>();
        volatile ScanRunner runner;
        volatile java.util.concurrent.ScheduledFuture<?> flushHandle;

        TaskState(String taskId, ScanContext ctx, Instant startTime) {
            this.taskId = taskId;
            this.ctx = ctx;
            this.startTime = startTime;
        }
    }
}
