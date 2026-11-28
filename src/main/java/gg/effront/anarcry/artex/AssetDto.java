package gg.effront.anarcry.artex;

import java.util.Map;

/**
 * DTO for ARTEX asset upsert. Assets are deduped server-side by type+value.
 *
 * @param type
 *            asset type: root_domain, subdomain, ip, service, endpoint, app
 * @param value
 *            asset value (domain name, IP address, URL, etc.)
 * @param metadata
 *            additional key-value metadata for the asset
 */
public record AssetDto(String type, String value, Map<String, String> metadata) {

    /** Root domain asset (e.g. "example.com"). */
    public static AssetDto rootDomain(String domain) {
        return new AssetDto("root_domain", domain, Map.of());
    }

    /** Root domain asset with metadata. */
    public static AssetDto rootDomain(String domain, Map<String, String> metadata) {
        return new AssetDto("root_domain", domain, metadata);
    }

    /** Subdomain asset (e.g. "api.example.com"). */
    public static AssetDto subdomain(String subdomain) {
        return new AssetDto("subdomain", subdomain, Map.of());
    }

    /** Subdomain asset with metadata. */
    public static AssetDto subdomain(String subdomain, Map<String, String> metadata) {
        return new AssetDto("subdomain", subdomain, metadata);
    }

    /** IP address asset. */
    public static AssetDto ip(String address) {
        return new AssetDto("ip", address, Map.of());
    }

    /** IP address asset with metadata. */
    public static AssetDto ip(String address, Map<String, String> metadata) {
        return new AssetDto("ip", address, metadata);
    }

    /** Service asset (e.g. "https", "ssh"). */
    public static AssetDto service(String service, Map<String, String> metadata) {
        return new AssetDto("service", service, metadata);
    }

    /** Endpoint asset (e.g. "/api/users"). */
    public static AssetDto endpoint(String url) {
        return new AssetDto("endpoint", url, Map.of());
    }

    /** Endpoint asset with metadata. */
    public static AssetDto endpoint(String url, Map<String, String> metadata) {
        return new AssetDto("endpoint", url, metadata);
    }

    /** Application asset (e.g. "WordPress 6.4"). */
    public static AssetDto app(String name, Map<String, String> metadata) {
        return new AssetDto("app", name, metadata);
    }
}
