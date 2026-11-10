package gg.effront.anarcry.scanner.oast;

/**
 * Represents an incoming callback received by the OAST server. The
 * {@code payloadId} is extracted from the callback URL path and used for
 * correlation against registered payloads.
 */
public record OastCallback(String payloadId, String protocol, String sourceIp, String requestData, long receivedAt) {
}
