package gg.effront.anarcry.scanner;

import gg.effront.anarcry.model.Finding;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;

/**
 * A FindingListener that buffers findings and flushes them in batches. Flush
 * triggers when either the buffer reaches {@code batchSize} findings or
 * {@code flushIntervalMs} milliseconds have elapsed since the first unbatched
 * finding -- whichever comes first.
 *
 * <p>
 * Thread-safe: multiple scanner modules may call {@link #onFinding}
 * concurrently.
 */
public class BatchFindingListener implements FindingListener, AutoCloseable {

    private static final int DEFAULT_BATCH_SIZE = 10;
    private static final long DEFAULT_FLUSH_INTERVAL_MS = 2000;

    private final Consumer<List<Finding>> flushCallback;
    private final int batchSize;
    private final long flushIntervalMs;

    private final Object lock = new Object();
    private final List<Finding> buffer = new ArrayList<>();
    private final ScheduledExecutorService scheduler;
    private ScheduledFuture<?> timerTask;
    private boolean closed;

    public BatchFindingListener(Consumer<List<Finding>> flushCallback) {
        this(flushCallback, DEFAULT_BATCH_SIZE, DEFAULT_FLUSH_INTERVAL_MS);
    }

    public BatchFindingListener(Consumer<List<Finding>> flushCallback, int batchSize, long flushIntervalMs) {
        this.flushCallback = flushCallback;
        this.batchSize = batchSize;
        this.flushIntervalMs = flushIntervalMs;
        this.scheduler = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "anarcry-finding-flush");
            t.setDaemon(true);
            return t;
        });
    }

    @Override
    public void onFinding(Finding finding) {
        synchronized (lock) {
            if (closed) {
                return;
            }
            buffer.add(finding);
            if (buffer.size() >= batchSize) {
                doFlush();
            } else if (timerTask == null || timerTask.isDone()) {
                // Schedule a timer flush for the first finding in a new batch window
                timerTask = scheduler.schedule(() -> {
                    synchronized (lock) {
                        if (!buffer.isEmpty()) {
                            doFlush();
                        }
                    }
                }, flushIntervalMs, TimeUnit.MILLISECONDS);
            }
        }
    }

    /**
     * Flushes the current buffer immediately. Safe to call from any thread.
     */
    public void flush() {
        synchronized (lock) {
            if (!buffer.isEmpty()) {
                doFlush();
            }
        }
    }

    /** Must be called under {@code lock}. */
    private void doFlush() {
        List<Finding> batch = new ArrayList<>(buffer);
        buffer.clear();
        if (timerTask != null) {
            timerTask.cancel(false);
            timerTask = null;
        }
        flushCallback.accept(batch);
    }

    /**
     * Flushes any remaining findings and shuts down the timer executor. After
     * close, subsequent calls to {@link #onFinding} are silently ignored.
     */
    @Override
    public void close() {
        synchronized (lock) {
            if (closed) {
                return;
            }
            closed = true;
            if (!buffer.isEmpty()) {
                doFlush();
            }
        }
        scheduler.shutdown();
        try {
            if (!scheduler.awaitTermination(5, TimeUnit.SECONDS)) {
                scheduler.shutdownNow();
            }
        } catch (InterruptedException e) {
            scheduler.shutdownNow();
            Thread.currentThread().interrupt();
        }
    }
}
