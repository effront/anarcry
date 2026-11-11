package gg.effront.anarcry.scanner.oast;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Thread-safe correlator that matches incoming OOB callbacks to previously
 * registered payloads.
 *
 * <p>
 * Scanner modules register payloads via {@link #registerPayload(OastPayload)}
 * before injection. The {@link OastServer} records callbacks via
 * {@link #recordCallback(OastCallback)}. After the callback wait period,
 * {@link #correlate()} returns all matched hits.
 *
 * <p>
 * The correlator also holds the callback base URL so scanner modules can
 * generate full callback URLs without direct access to the {@link OastServer}.
 */
public class OastCorrelator {

    private final Map<String, OastPayload> pendingPayloads = new ConcurrentHashMap<>();
    private final List<OastCallback> receivedCallbacks = Collections.synchronizedList(new ArrayList<>());
    private volatile String callbackBaseUrl = "";

    /** Set the callback base URL (called by OastServer after binding). */
    public void setCallbackBaseUrl(String url) {
        this.callbackBaseUrl = url != null ? url : "";
    }

    /** Get the callback base URL (e.g. http://192.168.1.10:12345). */
    public String callbackBaseUrl() {
        return callbackBaseUrl;
    }

    /**
     * Generate a full callback URL for a specific payload ID.
     *
     * @return the callback URL, or empty string if no base URL is configured
     */
    public String callbackUrl(String payloadId) {
        if (callbackBaseUrl.isEmpty()) {
            return "";
        }
        return callbackBaseUrl + "/" + payloadId;
    }

    /** Register a payload before injecting it into the target. */
    public void registerPayload(OastPayload payload) {
        pendingPayloads.put(payload.payloadId(), payload);
    }

    /** Record an incoming callback from the OAST server. */
    public void recordCallback(OastCallback callback) {
        receivedCallbacks.add(callback);
    }

    /**
     * Correlate all received callbacks against registered payloads.
     *
     * @return list of correlated hits where a callback matched a registered payload
     */
    public List<CorrelatedHit> correlate() {
        List<CorrelatedHit> hits = new ArrayList<>();
        synchronized (receivedCallbacks) {
            for (OastCallback cb : receivedCallbacks) {
                OastPayload payload = pendingPayloads.get(cb.payloadId());
                if (payload != null) {
                    hits.add(new CorrelatedHit(payload, cb));
                }
            }
        }
        return hits;
    }

    /** Number of registered (pending) payloads. */
    public int pendingCount() {
        return pendingPayloads.size();
    }

    /** Number of received callbacks. */
    public int callbackCount() {
        return receivedCallbacks.size();
    }

    /**
     * Generate a unique payload ID suitable for embedding in URLs and DNS labels.
     * Uses a truncated UUID (first 12 hex chars) to stay within DNS label length
     * limits while remaining practically unique within a single scan session.
     */
    public static String generatePayloadId() {
        return UUID.randomUUID().toString().replace("-", "").substring(0, 12);
    }

    /**
     * A correlated hit linking the original payload to the callback that confirmed
     * it.
     */
    public record CorrelatedHit(OastPayload payload, OastCallback callback) {
    }
}
