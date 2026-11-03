package gg.effront.anarcry.assistant;

import java.util.concurrent.atomic.AtomicInteger;

public final class UsageTracker {

    private final AtomicInteger totalInputTokens = new AtomicInteger();
    private final AtomicInteger totalOutputTokens = new AtomicInteger();
    private final AtomicInteger requestCount = new AtomicInteger();
    private volatile double accumulatedCost;

    public void record(UsageInfo info) {
        totalInputTokens.addAndGet(info.inputTokens());
        totalOutputTokens.addAndGet(info.outputTokens());
        requestCount.incrementAndGet();
        synchronized (this) {
            accumulatedCost += info.estimatedCost();
        }
    }

    public int totalTokens() {
        return totalInputTokens.get() + totalOutputTokens.get();
    }

    public double totalCost() {
        synchronized (this) {
            return accumulatedCost;
        }
    }

    public String summary() {
        int tokens = totalTokens();
        double cost = totalCost();
        String tokenStr;
        if (tokens >= 1_000_000) {
            tokenStr = String.format("%.1fM", tokens / 1_000_000.0);
        } else if (tokens >= 1_000) {
            tokenStr = String.format("%.1fK", tokens / 1_000.0);
        } else {
            tokenStr = String.valueOf(tokens);
        }
        return String.format("AI: %s tokens (~$%.2f)", tokenStr, cost);
    }
}
