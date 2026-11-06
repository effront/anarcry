package gg.effront.anarcry.scanner.auth.firebase;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import gg.effront.anarcry.scanner.auth.AuthException;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;

public final class FirebaseAuthClient {

    private static final Gson GSON = new Gson();
    private static final HttpClient HC = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).build();

    public record AuthResult(String idToken, String refreshToken, long expiresIn, String localId, String email) {
    }

    private FirebaseAuthClient() {
    }

    public static AuthResult signInWithPassword(FirebaseConfig config, String email, String password)
            throws AuthException {
        String url = config.identityToolkitUrl() + "/accounts:signInWithPassword?key=" + config.apiKey();
        JsonObject body = new JsonObject();
        body.addProperty("email", email);
        body.addProperty("password", password);
        body.addProperty("returnSecureToken", true);
        return executeAuth(url, body);
    }

    public static AuthResult signUp(FirebaseConfig config, String email, String password) throws AuthException {
        String url = config.identityToolkitUrl() + "/accounts:signUp?key=" + config.apiKey();
        JsonObject body = new JsonObject();
        body.addProperty("email", email);
        body.addProperty("password", password);
        body.addProperty("returnSecureToken", true);
        return executeAuth(url, body);
    }

    public static AuthResult signUpAnonymous(FirebaseConfig config) throws AuthException {
        String url = config.identityToolkitUrl() + "/accounts:signUp?key=" + config.apiKey();
        JsonObject body = new JsonObject();
        body.addProperty("returnSecureToken", true);
        return executeAuth(url, body);
    }

    public static AuthResult refreshToken(FirebaseConfig config, String refreshToken) throws AuthException {
        String url = config.secureTokenUrl() + "/token?key=" + config.apiKey();
        String formBody = "grant_type=refresh_token&refresh_token=" + refreshToken;
        try {
            HttpRequest req = HttpRequest.newBuilder().uri(URI.create(url)).timeout(Duration.ofSeconds(10))
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .POST(HttpRequest.BodyPublishers.ofString(formBody)).build();
            HttpResponse<String> resp = HC.send(req, HttpResponse.BodyHandlers.ofString());
            if (resp.statusCode() != 200) {
                throw new AuthException(
                        "Firebase token refresh failed (HTTP " + resp.statusCode() + "): " + resp.body());
            }
            JsonObject json = GSON.fromJson(resp.body(), JsonObject.class);
            return new AuthResult(json.get("id_token").getAsString(), json.get("refresh_token").getAsString(),
                    json.get("expires_in").getAsLong(), json.has("user_id") ? json.get("user_id").getAsString() : "",
                    "");
        } catch (AuthException e) {
            throw e;
        } catch (Exception e) {
            throw new AuthException("Firebase token refresh error: " + e.getMessage(), e);
        }
    }

    public static void sendPasswordReset(FirebaseConfig config, String email) throws AuthException {
        String url = config.identityToolkitUrl() + "/accounts:sendOobCode?key=" + config.apiKey();
        JsonObject body = new JsonObject();
        body.addProperty("requestType", "PASSWORD_RESET");
        body.addProperty("email", email);
        executeRaw(url, body);
    }

    public static void deleteAccount(FirebaseConfig config, String idToken) throws AuthException {
        String url = config.identityToolkitUrl() + "/accounts:delete?key=" + config.apiKey();
        JsonObject body = new JsonObject();
        body.addProperty("idToken", idToken);
        executeRaw(url, body);
    }

    public static boolean isEmailPasswordEnabled(FirebaseConfig config) {
        try {
            AuthResult result = signUp(config, "anarcry-probe-" + System.currentTimeMillis() + "@test.invalid",
                    "AnarCryPr0be!" + System.currentTimeMillis());
            try {
                deleteAccount(config, result.idToken());
            } catch (AuthException ignored) {
            }
            return true;
        } catch (AuthException e) {
            String msg = e.getMessage().toLowerCase();
            return !msg.contains("email_not_found") && !msg.contains("operation_not_allowed")
                    && !msg.contains("admin_only_operation");
        }
    }

    private static AuthResult executeAuth(String url, JsonObject body) throws AuthException {
        try {
            HttpResponse<String> resp = sendJson(url, body);
            if (resp.statusCode() != 200) {
                throw new AuthException("Firebase auth failed (HTTP " + resp.statusCode() + "): " + resp.body());
            }
            JsonObject json = GSON.fromJson(resp.body(), JsonObject.class);
            return new AuthResult(json.has("idToken") ? json.get("idToken").getAsString() : "",
                    json.has("refreshToken") ? json.get("refreshToken").getAsString() : "",
                    json.has("expiresIn") ? json.get("expiresIn").getAsLong() : 3600,
                    json.has("localId") ? json.get("localId").getAsString() : "",
                    json.has("email") ? json.get("email").getAsString() : "");
        } catch (AuthException e) {
            throw e;
        } catch (Exception e) {
            throw new AuthException("Firebase auth error: " + e.getMessage(), e);
        }
    }

    private static void executeRaw(String url, JsonObject body) throws AuthException {
        try {
            HttpResponse<String> resp = sendJson(url, body);
            if (resp.statusCode() != 200) {
                throw new AuthException("Firebase API failed (HTTP " + resp.statusCode() + "): " + resp.body());
            }
        } catch (AuthException e) {
            throw e;
        } catch (Exception e) {
            throw new AuthException("Firebase API error: " + e.getMessage(), e);
        }
    }

    private static HttpResponse<String> sendJson(String url, JsonObject body) throws Exception {
        HttpRequest req = HttpRequest.newBuilder().uri(URI.create(url)).timeout(Duration.ofSeconds(10))
                .header("Content-Type", "application/json").POST(HttpRequest.BodyPublishers.ofString(GSON.toJson(body)))
                .build();
        return HC.send(req, HttpResponse.BodyHandlers.ofString());
    }
}
