package gg.effront.anarcry.artex;

import com.google.gson.Gson;
import com.google.gson.JsonObject;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.locks.ReentrantLock;

/**
 * Java HTTP client for the ARTEX pentest platform REST API.
 *
 * <p>
 * Thread-safe -- a single instance can be shared across virtual threads. Uses
 * JWT bearer auth with automatic re-login on 401.
 */
public class ArtexClient {

    private final ArtexConfig config;
    private final HttpClient httpClient;
    private final Gson gson;
    private final Duration readTimeout;

    // JWT state -- guarded by tokenLock for thread safety
    private final ReentrantLock tokenLock = new ReentrantLock();
    private volatile String token;

    public ArtexClient(ArtexConfig config) {
        this.config = config;
        this.gson = new Gson();
        this.readTimeout = Duration.ofSeconds(config.readTimeoutSeconds());
        this.httpClient = HttpClient.newBuilder().version(HttpClient.Version.HTTP_2)
                .connectTimeout(Duration.ofSeconds(config.connectTimeoutSeconds()))
                .followRedirects(HttpClient.Redirect.NORMAL).build();
    }

    // -- Authentication -----------------------------------------------------------

    /** Authenticate against ARTEX and store the JWT token. */
    public void login() {
        tokenLock.lock();
        try {
            JsonObject body = new JsonObject();
            body.addProperty("username", config.username());
            body.addProperty("password", config.password());

            HttpResponse<String> resp = sendRaw("POST", "/api/auth/login",
                    HttpRequest.BodyPublishers.ofString(gson.toJson(body)), false);

            if (resp.statusCode() != 200) {
                throw new ArtexException("Login failed (HTTP " + resp.statusCode() + ")", resp.statusCode(),
                        resp.body());
            }

            JsonObject json = gson.fromJson(resp.body(), JsonObject.class);
            if (json == null || !json.has("token")) {
                throw new ArtexException("Login response missing 'token' field", resp.statusCode(), resp.body());
            }
            this.token = json.get("token").getAsString();
        } catch (ArtexException e) {
            throw e;
        } catch (Exception e) {
            throw new ArtexException("Login failed: " + e.getMessage(), e);
        } finally {
            tokenLock.unlock();
        }
    }

    /** Returns true if the client currently holds a JWT token. */
    public boolean isAuthenticated() {
        return token != null && !token.isBlank();
    }

    // -- Tasks --------------------------------------------------------------------

    /**
     * Create a new task.
     *
     * @param name
     *            task name
     * @param scope
     *            target scope description
     * @return task id from ARTEX
     */
    public String createTask(String name, String scope) {
        JsonObject body = new JsonObject();
        body.addProperty("name", name);
        body.addProperty("scope", scope);

        HttpResponse<String> resp = execute("POST", "/api/tasks",
                HttpRequest.BodyPublishers.ofString(gson.toJson(body)));

        JsonObject json = gson.fromJson(resp.body(), JsonObject.class);
        if (json != null && json.has("id")) {
            return json.get("id").getAsString();
        }
        throw new ArtexException("createTask response missing 'id' field", resp.statusCode(), resp.body());
    }

    /**
     * Get task details.
     *
     * @param taskId
     *            ARTEX task id
     * @return raw JSON response as a JsonObject
     */
    public JsonObject getTask(String taskId) {
        HttpResponse<String> resp = execute("GET", "/api/tasks/" + taskId, null);
        return gson.fromJson(resp.body(), JsonObject.class);
    }

    /** Transition task to running state. */
    public void startTask(String taskId) {
        execute("POST", "/api/tasks/" + taskId + "/start", HttpRequest.BodyPublishers.noBody());
    }

    /** Pause a running task. */
    public void pauseTask(String taskId) {
        execute("POST", "/api/tasks/" + taskId + "/pause", HttpRequest.BodyPublishers.noBody());
    }

    /** Stop a task. */
    public void stopTask(String taskId) {
        execute("POST", "/api/tasks/" + taskId + "/stop", HttpRequest.BodyPublishers.noBody());
    }

    // -- Findings -----------------------------------------------------------------

    /**
     * Push findings to an ARTEX task.
     *
     * @param taskId
     *            ARTEX task id
     * @param findings
     *            list of findings to push
     */
    public void pushFindings(String taskId, List<FindingDto> findings) {
        String json = gson.toJson(findings);
        execute("POST", "/api/tasks/" + taskId + "/findings", HttpRequest.BodyPublishers.ofString(json));
    }

    // -- Assets -------------------------------------------------------------------

    /**
     * Push assets to an ARTEX task (upsert -- deduped by type+value server-side).
     *
     * @param taskId
     *            ARTEX task id
     * @param assets
     *            list of assets to upsert
     */
    public void pushAssets(String taskId, List<AssetDto> assets) {
        String json = gson.toJson(assets);
        execute("POST", "/api/tasks/" + taskId + "/assets", HttpRequest.BodyPublishers.ofString(json));
    }

    // -- Internal HTTP layer ------------------------------------------------------

    /**
     * Execute an authenticated API call with automatic 401 re-login retry. On first
     * 401, login() is called and the request is retried exactly once.
     */
    private HttpResponse<String> execute(String method, String path, HttpRequest.BodyPublisher bodyPublisher) {
        ensureAuthenticated();
        try {
            HttpResponse<String> resp = sendRaw(method, path, bodyPublisher, true);

            // Auto re-login on 401 and retry once
            if (resp.statusCode() == 401) {
                login();
                resp = sendRaw(method, path, bodyPublisher, true);
                if (resp.statusCode() == 401) {
                    throw new ArtexException("Authentication failed after re-login", 401, resp.body());
                }
            }

            if (resp.statusCode() >= 400) {
                throw new ArtexException(method + " " + path + " failed (HTTP " + resp.statusCode() + ")",
                        resp.statusCode(), resp.body());
            }
            return resp;
        } catch (ArtexException e) {
            throw e;
        } catch (Exception e) {
            throw new ArtexException(method + " " + path + " failed: " + e.getMessage(), e);
        }
    }

    private void ensureAuthenticated() {
        if (!isAuthenticated()) {
            login();
        }
    }

    /**
     * Send a raw HTTP request to the ARTEX API.
     *
     * @param method
     *            HTTP method
     * @param path
     *            API path (e.g. "/api/tasks")
     * @param bodyPublisher
     *            request body (null for GET)
     * @param withAuth
     *            true to include Authorization header
     */
    private HttpResponse<String> sendRaw(String method, String path, HttpRequest.BodyPublisher bodyPublisher,
            boolean withAuth) throws Exception {

        HttpRequest.Builder builder = HttpRequest.newBuilder().uri(URI.create(config.baseUrl() + path))
                .timeout(readTimeout).header("Content-Type", "application/json").header("Accept", "application/json");

        if (withAuth && token != null) {
            builder.header("Authorization", "Bearer " + token);
        }

        if (bodyPublisher == null) {
            builder.GET();
        } else {
            builder.method(method, bodyPublisher);
        }

        return httpClient.send(builder.build(), HttpResponse.BodyHandlers.ofString());
    }

    /** Close the underlying HTTP client. */
    public void close() {
        httpClient.close();
    }
}
