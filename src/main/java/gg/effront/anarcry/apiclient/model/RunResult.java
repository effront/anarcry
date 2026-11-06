package gg.effront.anarcry.apiclient.model;

import java.util.List;

public record RunResult(List<RequestResult> results, RunSummary summary, long durationMs) {
}
