package gg.effront.anarcry.apiclient.model;

import java.util.List;

public record CollectionSettings(ProxyConfig proxy, List<ClientCert> clientCerts, int defaultTimeoutMs) {

    public static final int DEFAULT_TIMEOUT_MS = 30_000;

    public record ProxyConfig(String protocol, String hostname, int port, String username, String password,
            boolean enabled) {
    }

    public record ClientCert(String domain, String certFilePath, String keyFilePath, String passphrase) {
    }

    public CollectionSettings {
        if (clientCerts == null) {
            clientCerts = List.of();
        }
        if (defaultTimeoutMs <= 0) {
            defaultTimeoutMs = DEFAULT_TIMEOUT_MS;
        }
    }

    public static CollectionSettings defaults() {
        return new CollectionSettings(null, List.of(), DEFAULT_TIMEOUT_MS);
    }
}
