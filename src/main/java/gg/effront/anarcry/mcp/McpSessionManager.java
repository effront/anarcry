package gg.effront.anarcry.mcp;

import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Future;
import java.util.concurrent.Semaphore;

/**
 * Manages MCP sessions and controls concurrent tool execution. Each session is
 * identified by a session-id header. The manager enforces a global concurrency
 * limit via semaphore (matching FuzzEngine pattern) and tracks active
 * executions for cancellation.
 */
public final class McpSessionManager {

    private static final int DEFAULT_MAX_CONCURRENT = 4;

    private final Semaphore concurrencyLimit;
    private final Map<String, SessionState> sessions = new ConcurrentHashMap<>();
    private final Map<String, Future<?>> activeExecutions = new ConcurrentHashMap<>();

    public McpSessionManager() {
        this(DEFAULT_MAX_CONCURRENT);
    }

    public McpSessionManager(int maxConcurrent) {
        this.concurrencyLimit = new Semaphore(maxConcurrent);
    }

    /** Creates or retrieves a session for the given session ID. */
    public SessionState getOrCreate(String sessionId) {
        if (sessionId == null || sessionId.isBlank()) {
            sessionId = UUID.randomUUID().toString();
        }
        return sessions.computeIfAbsent(sessionId, id -> new SessionState(id));
    }

    /** Generates a fresh session ID. */
    public String newSessionId() {
        String id = UUID.randomUUID().toString();
        sessions.put(id, new SessionState(id));
        return id;
    }

    /**
     * Acquires a concurrency permit. Blocks until one is available. Returns true if
     * acquired, false if interrupted.
     */
    public boolean acquire() {
        try {
            concurrencyLimit.acquire();
            return true;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return false;
        }
    }

    /** Releases a concurrency permit. */
    public void release() {
        concurrencyLimit.release();
    }

    /** Returns available permit count. */
    public int availablePermits() {
        return concurrencyLimit.availablePermits();
    }

    /**
     * Tracks an active execution by request ID so it can be cancelled.
     */
    public void trackExecution(String requestId, Future<?> future) {
        if (requestId != null) {
            activeExecutions.put(requestId, future);
        }
    }

    /** Removes a tracked execution after completion. */
    public void untrackExecution(String requestId) {
        if (requestId != null) {
            activeExecutions.remove(requestId);
        }
    }

    /**
     * Cancels an active execution by request ID. Returns true if found and
     * cancelled.
     */
    public boolean cancelExecution(String requestId) {
        Future<?> future = activeExecutions.remove(requestId);
        if (future != null) {
            return future.cancel(true);
        }
        return false;
    }

    /** Cancels all active executions and clears session state. */
    public void shutdown() {
        for (Future<?> f : activeExecutions.values()) {
            f.cancel(true);
        }
        activeExecutions.clear();
        sessions.clear();
    }

    /** Returns the number of active sessions. */
    public int sessionCount() {
        return sessions.size();
    }

    /** Returns the number of active executions. */
    public int activeExecutionCount() {
        return activeExecutions.size();
    }

    /** Per-session state tracking. */
    public static final class SessionState {
        private final String sessionId;
        private final long createdAt;

        SessionState(String sessionId) {
            this.sessionId = sessionId;
            this.createdAt = System.currentTimeMillis();
        }

        public String sessionId() {
            return sessionId;
        }

        public long createdAt() {
            return createdAt;
        }
    }
}
