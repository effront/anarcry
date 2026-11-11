package gg.effront.anarcry.scanner.oast;

/**
 * Links a generated OAST payload to its originating scan context -- the module
 * that injected it, the target endpoint, and the parameter used.
 */
public record OastPayload(String payloadId, String moduleId, String targetEndpoint, String parameterName,
        String fullPayload, long createdAt) {
}
