package gg.effront.anarcry.scanner.auth.harvester;

import gg.effront.anarcry.scanner.auth.AuthException;
import gg.effront.anarcry.scanner.auth.AuthProvider;
import gg.effront.anarcry.scanner.auth.CredentialStore;
import gg.effront.anarcry.scanner.auth.firebase.FirebaseAuthClient;
import gg.effront.anarcry.scanner.auth.firebase.FirebaseConfig;
import gg.effront.anarcry.scanner.auth.firebase.FirebaseConfigExtractor;

import java.util.Map;

public class FirebaseHarvester implements Harvester {

    @Override
    public AuthProvider provider() {
        return AuthProvider.FIREBASE;
    }

    @Override
    public boolean canHandle(String targetUrl, String pageSource) {
        return FirebaseConfigExtractor.looksLikeFirebase(pageSource);
    }

    @Override
    public CredentialStore harvest(String targetUrl, String username, String password, Map<String, String> extra)
            throws AuthException {
        FirebaseConfig config;
        String pageSource = extra != null ? extra.get("pageSource") : null;
        if (pageSource != null) {
            config = FirebaseConfigExtractor.extract(pageSource);
        } else {
            config = FirebaseConfigExtractor.extractFromUrl(targetUrl);
        }
        if (config == null) {
            throw new AuthException("Firebase config not found at " + targetUrl);
        }

        String refreshTokenInput = extra != null ? extra.get("refreshToken") : null;
        if (refreshTokenInput == null || refreshTokenInput.isBlank()) {
            if (looksLikeRefreshToken(username)) {
                refreshTokenInput = username;
            } else if (looksLikeRefreshToken(password)) {
                refreshTokenInput = password;
            }
        }

        FirebaseConfig cfg = config;

        if (refreshTokenInput != null && !refreshTokenInput.isBlank()) {
            FirebaseAuthClient.AuthResult result = FirebaseAuthClient.refreshToken(cfg, refreshTokenInput);
            return buildStore(cfg, result);
        }

        try {
            FirebaseAuthClient.AuthResult result = FirebaseAuthClient.signInWithPassword(config, username, password);
            return buildStore(cfg, result);
        } catch (AuthException e) {
            String msg = e.getMessage().toLowerCase();
            if (msg.contains("invalid_email") || msg.contains("operation_not_allowed")
                    || msg.contains("email_not_found")) {
                throw new AuthException("Email/password sign-in not enabled on this Firebase project. "
                        + "Use a refresh token instead (paste it in the Email field). "
                        + "Extract from browser: DevTools > Application > IndexedDB > firebaseLocalStorageDb "
                        + "> firebaseLocalStorage > spiTokens.refreshToken", e);
            }
            throw e;
        }
    }

    private static CredentialStore buildStore(FirebaseConfig cfg, FirebaseAuthClient.AuthResult result) {
        return new CredentialStore(result.idToken(), result.refreshToken(), result.expiresIn(), AuthProvider.FIREBASE,
                refreshToken -> {
                    try {
                        FirebaseAuthClient.AuthResult refreshed = FirebaseAuthClient.refreshToken(cfg, refreshToken);
                        return new CredentialStore.RefreshResult(refreshed.idToken(), refreshed.refreshToken(),
                                refreshed.expiresIn());
                    } catch (AuthException e) {
                        throw new RuntimeException(e);
                    }
                });
    }

    private static boolean looksLikeRefreshToken(String value) {
        return value != null && value.length() > 100 && value.startsWith("AMf-");
    }
}
