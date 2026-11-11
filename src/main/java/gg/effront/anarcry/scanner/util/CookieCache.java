package gg.effront.anarcry.scanner.util;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.reflect.TypeToken;

import java.io.IOException;
import java.lang.reflect.Type;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public final class CookieCache {

    private static final long TTL_SECONDS = 7200;
    private static final Path CACHE_FILE = Path.of(System.getProperty("user.home"), ".anarcry", "cookies.json");
    private static final Gson GSON = new GsonBuilder().setPrettyPrinting().create();
    private static final Type MAP_TYPE = new TypeToken<ConcurrentHashMap<String, Entry>>() {
    }.getType();

    private record Entry(String cookies, long savedAt) {
    }

    private CookieCache() {
    }

    public static String load(String host) {
        try {
            if (!Files.exists(CACHE_FILE)) {
                return null;
            }
            String json = Files.readString(CACHE_FILE);
            Map<String, Entry> cache = GSON.fromJson(json, MAP_TYPE);
            if (cache == null) {
                return null;
            }
            Entry entry = cache.get(host);
            if (entry == null) {
                return null;
            }
            if (Instant.now().getEpochSecond() - entry.savedAt > TTL_SECONDS) {
                cache.remove(host);
                write(cache);
                return null;
            }
            return entry.cookies;
        } catch (Exception e) {
            return null;
        }
    }

    public static void save(String host, String cookies) {
        if (host == null || host.isBlank() || cookies == null || cookies.isBlank()) {
            return;
        }
        try {
            Map<String, Entry> cache;
            if (Files.exists(CACHE_FILE)) {
                String json = Files.readString(CACHE_FILE);
                cache = GSON.fromJson(json, MAP_TYPE);
                if (cache == null) {
                    cache = new ConcurrentHashMap<>();
                }
            } else {
                cache = new ConcurrentHashMap<>();
            }
            cache.put(host, new Entry(cookies, Instant.now().getEpochSecond()));
            write(cache);
        } catch (Exception ignored) {
            // best effort
        }
    }

    public static void evict(String host) {
        try {
            if (!Files.exists(CACHE_FILE)) {
                return;
            }
            String json = Files.readString(CACHE_FILE);
            Map<String, Entry> cache = GSON.fromJson(json, MAP_TYPE);
            if (cache != null && cache.remove(host) != null) {
                write(cache);
            }
        } catch (Exception ignored) {
            // best effort
        }
    }

    private static void write(Map<String, Entry> cache) throws IOException {
        Files.createDirectories(CACHE_FILE.getParent());
        Files.writeString(CACHE_FILE, GSON.toJson(cache));
    }
}
