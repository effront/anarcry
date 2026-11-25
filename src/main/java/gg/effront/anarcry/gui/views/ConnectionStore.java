package gg.effront.anarcry.gui.views;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/**
 * Persists DB and FTP explorer connections to
 * {@code ~/.anarcry/connections.json} so they survive app restarts. Passwords
 * are NEVER stored -- only connection metadata (host, port, type, username, SSH
 * key paths, etc.).
 */
public final class ConnectionStore {

    private static final Path STORE_PATH = Path.of(System.getProperty("user.home"), ".anarcry", "connections.json");
    private static final Gson GSON = new GsonBuilder().setPrettyPrinting().create();

    public record DbConnectionEntry(String name, String dbType, String host, int port, String database, String username,
            boolean useSsl, boolean sshEnabled, String sshHost, int sshPort, String sshUsername, String sshKeyPath,
            String group) {
    }

    public record FtpConnectionEntry(String name, String protocol, String host, int port, String username,
            String keyPath, boolean passive) {
    }

    private static class StoreData {
        List<DbConnectionEntry> dbConnections = new ArrayList<>();
        List<FtpConnectionEntry> ftpConnections = new ArrayList<>();
    }

    private ConnectionStore() {
    }

    public static List<DbConnectionEntry> loadDbConnections() {
        StoreData data = readStore();
        return data.dbConnections != null ? new ArrayList<>(data.dbConnections) : new ArrayList<>();
    }

    public static List<FtpConnectionEntry> loadFtpConnections() {
        StoreData data = readStore();
        return data.ftpConnections != null ? new ArrayList<>(data.ftpConnections) : new ArrayList<>();
    }

    public static void saveDbConnections(List<DbConnectionEntry> entries) {
        StoreData data = readStore();
        data.dbConnections = entries != null ? new ArrayList<>(entries) : new ArrayList<>();
        writeStore(data);
    }

    public static void saveFtpConnections(List<FtpConnectionEntry> entries) {
        StoreData data = readStore();
        data.ftpConnections = entries != null ? new ArrayList<>(entries) : new ArrayList<>();
        writeStore(data);
    }

    private static StoreData readStore() {
        try {
            if (Files.exists(STORE_PATH)) {
                String json = Files.readString(STORE_PATH);
                StoreData data = GSON.fromJson(json, StoreData.class);
                if (data != null) {
                    return data;
                }
            }
        } catch (Exception ignored) {
            // Corrupt or unreadable file -- return empty
        }
        return new StoreData();
    }

    private static synchronized void writeStore(StoreData data) {
        try {
            Files.createDirectories(STORE_PATH.getParent());
            Files.writeString(STORE_PATH, GSON.toJson(data));
        } catch (Exception ignored) {
            // Best effort -- don't crash on write failure
        }
    }
}
