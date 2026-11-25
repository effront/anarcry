package gg.effront.anarcry.fuzzer;

public record FuzzResult(int requestNum, String[] payloads, int statusCode, long length, long timeMs,
        String responseBody, String responseHeaders, String error, int[] grepMatchCounts, String[] grepExtracts) {

    public boolean hasError() {
        return error != null && !error.isEmpty();
    }

    public String payloadSummary() {
        if (payloads == null || payloads.length == 0) {
            return "";
        }
        if (payloads.length == 1) {
            return payloads[0];
        }
        return String.join(" | ", payloads);
    }
}
