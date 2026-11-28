package gg.effront.anarcry.artex;

import java.time.Duration;

/**
 * Combined summary of a local AnarCry scan and its paired ARTEX remote task.
 * Returned by {@link TaskOrchestrator#getSummary(String)}.
 */
public record ScanSummary(int localFindings, int artexFindings, int totalAssets, String taskStatus, Duration duration) {

    /** Total findings across both local and remote engines. */
    public int totalFindings() {
        return localFindings + artexFindings;
    }

    @Override
    public String toString() {
        long secs = duration.toSeconds();
        return "ScanSummary[local=" + localFindings + ", artex=" + artexFindings + ", assets=" + totalAssets
                + ", status=" + taskStatus + ", duration=" + secs + "s]";
    }
}
