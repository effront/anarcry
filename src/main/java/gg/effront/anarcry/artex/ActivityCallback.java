package gg.effront.anarcry.artex;

/**
 * Callback interface for ARTEX SSE activity stream events. Implementations
 * receive parsed events dispatched by {@link SseActivityListener}.
 */
public interface ActivityCallback {

    /** Worker intent created, completed, or failed. */
    void onIntent(String intentId, String status, String summary);

    /** ARTEX finding created or updated. */
    void onFinding(String findingId, String title, String severity);

    /** New asset discovered during exploration. */
    void onAsset(String assetType, String value);

    /** Connection or parse error on the SSE stream. */
    void onError(Exception e);

    /** Reconnection attempt after stream disconnect. */
    void onReconnect(int attempt);
}
