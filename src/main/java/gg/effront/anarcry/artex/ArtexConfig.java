package gg.effront.anarcry.artex;

/**
 * Configuration for the ARTEX platform API client.
 *
 * @param baseUrl
 *            ARTEX server URL (e.g. "https://artex.example.com")
 * @param username
 *            API username (default "ARTEX")
 * @param password
 *            API password
 * @param connectTimeoutSeconds
 *            connect timeout in seconds (default 10)
 * @param readTimeoutSeconds
 *            per-request read timeout in seconds (default 30)
 */
public record ArtexConfig(String baseUrl, String username, String password, int connectTimeoutSeconds,
        int readTimeoutSeconds) {

    public ArtexConfig {
        if (baseUrl == null || baseUrl.isBlank()) {
            throw new IllegalArgumentException("baseUrl must not be blank");
        }
        if (password == null || password.isBlank()) {
            throw new IllegalArgumentException("password must not be blank");
        }
        if (username == null || username.isBlank()) {
            username = "ARTEX";
        }
        if (connectTimeoutSeconds <= 0) {
            connectTimeoutSeconds = 10;
        }
        if (readTimeoutSeconds <= 0) {
            readTimeoutSeconds = 30;
        }
        // Strip trailing slash for consistent URL building
        if (baseUrl.endsWith("/")) {
            baseUrl = baseUrl.substring(0, baseUrl.length() - 1);
        }
    }

    /** Convenience constructor with defaults for username and timeouts. */
    public ArtexConfig(String baseUrl, String password) {
        this(baseUrl, "ARTEX", password, 10, 30);
    }

    /** Convenience constructor with custom username. */
    public ArtexConfig(String baseUrl, String username, String password) {
        this(baseUrl, username, password, 10, 30);
    }
}
