package gg.effront.anarcry.apiclient.model;

import java.util.List;

public record RequestResult(RequestItem item, HttpRequestDef interpolatedRequest, ResponseData response,
        List<AssertionResult> assertions, long durationMs, boolean passed) {
}
