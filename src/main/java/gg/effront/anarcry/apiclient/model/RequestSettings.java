package gg.effront.anarcry.apiclient.model;

public record RequestSettings(boolean followRedirects, int timeoutMs, boolean encodeUrl) {

    public static final int DEFAULT_TIMEOUT_MS = 30_000;

    public RequestSettings {
        if (timeoutMs <= 0) {
            timeoutMs = DEFAULT_TIMEOUT_MS;
        }
    }

    public static RequestSettings defaults() {
        return new RequestSettings(true, DEFAULT_TIMEOUT_MS, true);
    }
}
