package gg.effront.anarcry.assistant;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.reflect.TypeToken;

import java.io.IOException;
import java.lang.reflect.Type;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Persistent provider key storage at ~/.anarcry/providers.json and
 * auto-detection of credentials from installed CLI tools and system environment
 * variables.
 */
public final class ProviderConfigStore {

    private static final Path CONFIG_DIR = Path.of(System.getProperty("user.home"), ".anarcry");
    private static final Path CONFIG_FILE = CONFIG_DIR.resolve("providers.json");
    private static final Gson GSON = new GsonBuilder().setPrettyPrinting().create();
    private static final Type MAP_TYPE = new TypeToken<LinkedHashMap<String, String>>() {
    }.getType();

    private ProviderConfigStore() {
    }

    /** Loads saved keys from ~/.anarcry/providers.json. */
    public static Map<String, String> loadSaved() {
        if (!Files.exists(CONFIG_FILE)) {
            return Map.of();
        }
        try {
            String json = Files.readString(CONFIG_FILE);
            LinkedHashMap<String, String> map = GSON.fromJson(json, MAP_TYPE);
            return map != null ? map : Map.of();
        } catch (Exception e) {
            return Map.of();
        }
    }

    /** Saves provider keys to ~/.anarcry/providers.json. */
    public static void save(Map<String, String> keys) throws IOException {
        Files.createDirectories(CONFIG_DIR);
        Files.writeString(CONFIG_FILE, GSON.toJson(keys));
    }

    /**
     * Auto-detects API keys from system env vars and installed CLI tools. Returns a
     * map of env-key-name to value (same keys as .env.local).
     */
    public static Map<String, String> autoDetect() {
        Map<String, String> detected = new LinkedHashMap<>();

        // System environment variables
        envIfSet(detected, "ANTHROPIC_API_KEY", "anthropic_api_key");
        envIfSet(detected, "OPENAI_API_KEY", "openai_api_key");
        envIfSet(detected, "GEMINI_API_KEY", "gemini_api_key");
        envIfSet(detected, "DEEPSEEK_API_KEY", "deepseek_api_key");
        envIfSet(detected, "OPENROUTER_API_KEY", "openrouter_api_key");
        envIfSet(detected, "NOTHOLY_API_KEY", "notholy_api_key");

        // NotHoly CLI: ~/.notholy/credentials
        detectNotHoly(detected);

        return detected;
    }

    /**
     * Merges env.local map with auto-detected and saved keys. Priority: env.local >
     * saved > auto-detected.
     */
    public static Map<String, String> mergeAll(Map<String, String> envLocal) {
        Map<String, String> merged = new LinkedHashMap<>();

        // Lowest priority: auto-detected
        merged.putAll(autoDetect());

        // Middle priority: saved config
        for (var entry : loadSaved().entrySet()) {
            if (!entry.getValue().isBlank()) {
                merged.put(entry.getKey(), entry.getValue());
            }
        }

        // Highest priority: env.local
        for (var entry : envLocal.entrySet()) {
            if (!entry.getValue().isBlank()) {
                merged.put(entry.getKey(), entry.getValue());
            }
        }

        return merged;
    }

    private static void envIfSet(Map<String, String> map, String envVar, String key) {
        String val = System.getenv(envVar);
        if (val != null && !val.isBlank()) {
            map.put(key, val);
        }
    }

    private static void detectNotHoly(Map<String, String> map) {
        Path creds = Path.of(System.getProperty("user.home"), ".notholy", "credentials");
        if (!Files.exists(creds)) {
            return;
        }
        try {
            String key = Files.readString(creds).strip();
            if (!key.isBlank()) {
                map.put("notholy_api_key", key);
            }
        } catch (IOException ignored) {
            // Best-effort
        }
    }
}
