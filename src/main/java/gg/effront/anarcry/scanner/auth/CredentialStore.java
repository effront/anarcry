package gg.effront.anarcry.scanner.auth;

import java.time.Duration;
import java.time.Instant;
import java.util.function.Function;

public class CredentialStore {

    private volatile String activeToken;
    private volatile String refreshToken;
    private volatile Instant expiresAt;
    private volatile AuthProvider provider;
    private volatile String sessionCookieName;
    private final Duration refreshThreshold;
    private Function<String, RefreshResult> refreshFn;

    public record RefreshResult(String token, String refreshToken, long expiresInSeconds) {
    }

    public CredentialStore(String token, String refreshToken, long expiresInSeconds, AuthProvider provider,
            Function<String, RefreshResult> refreshFn) {
        this.activeToken = token;
        this.refreshToken = refreshToken;
        this.expiresAt = Instant.now().plusSeconds(expiresInSeconds);
        this.provider = provider;
        this.refreshThreshold = Duration.ofSeconds(60);
        this.refreshFn = refreshFn;
    }

    public CredentialStore(String token, String refreshToken, long expiresInSeconds, AuthProvider provider,
            String sessionCookieName, Function<String, RefreshResult> refreshFn) {
        this(token, refreshToken, expiresInSeconds, provider, refreshFn);
        this.sessionCookieName = sessionCookieName;
    }

    public String activeToken() {
        return activeToken;
    }

    public String refreshToken() {
        return refreshToken;
    }

    public AuthProvider provider() {
        return provider;
    }

    public Instant expiresAt() {
        return expiresAt;
    }

    public boolean isExpiringSoon() {
        return expiresAt != null && Instant.now().plus(refreshThreshold).isAfter(expiresAt);
    }

    public boolean isExpired() {
        return expiresAt != null && Instant.now().isAfter(expiresAt);
    }

    public boolean isCookieBased() {
        return provider == AuthProvider.COOKIE || provider == AuthProvider.FORM;
    }

    public String sessionCookieName() {
        return sessionCookieName;
    }

    public void updateToken(String newToken) {
        if (newToken != null && !newToken.isBlank()) {
            this.activeToken = newToken;
            this.expiresAt = Instant.now().plusSeconds(3600);
        }
    }

    public long remainingSeconds() {
        if (expiresAt == null) {
            return Long.MAX_VALUE;
        }
        return Duration.between(Instant.now(), expiresAt).toSeconds();
    }

    public synchronized String refresh() throws AuthException {
        if (refreshFn == null || refreshToken == null || refreshToken.isBlank()) {
            throw new AuthException("No refresh mechanism available for provider " + provider);
        }
        try {
            RefreshResult result = refreshFn.apply(refreshToken);
            this.activeToken = result.token();
            if (result.refreshToken() != null && !result.refreshToken().isBlank()) {
                this.refreshToken = result.refreshToken();
            }
            this.expiresAt = Instant.now().plusSeconds(result.expiresInSeconds());
            return this.activeToken;
        } catch (Exception e) {
            throw new AuthException("Token refresh failed for " + provider + ": " + e.getMessage(), e);
        }
    }

    public void destroy() {
        this.activeToken = null;
        this.refreshToken = null;
        this.expiresAt = null;
        this.refreshFn = null;
    }
}
