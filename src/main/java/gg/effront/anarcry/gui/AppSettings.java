package gg.effront.anarcry.gui;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

public final class AppSettings {

    private static final Path SETTINGS_DIR = Path.of(System.getProperty("user.home"), ".anarcry");
    private static final Path SETTINGS_FILE = SETTINGS_DIR.resolve("settings.json");
    private static final Gson GSON = new GsonBuilder().setPrettyPrinting().create();

    private static AppSettings instance;

    // -- General --
    public boolean sslVerification;
    public boolean storeCookies = true;
    public boolean sendCookies = true;
    public int requestTimeoutMs = 30000;
    public int parallelism = 4;
    public int scanTimeoutMinutes = 10;
    public String collectionsDir = System.getProperty("user.home");
    public boolean autoSave;

    // -- Themes --
    public String theme = "Dark";

    // -- Display --
    public int fontSize = 13;
    public String resolution = "1920x1080";

    // -- Proxy --
    public boolean proxyEnabled;
    public String proxyProtocol = "http";
    public String proxyHost = "";
    public int proxyPort = 8080;
    public String proxyUser = "";
    public String proxyPass = "";

    // -- Certificates --
    public boolean keepDefaultCa = true;
    public String caCertPath = "";
    public List<CertData> clientCerts = new ArrayList<>();

    // -- Notifications --
    public boolean notifyScanComplete = true;
    public boolean notifyCriticalFinding = true;

    public static final class CertData {

        public boolean enabled = true;
        public String domain = "";
        public String type = "PEM";
        public String certFile = "";
        public String keyFile = "";
        public String passphrase = "";
    }

    private AppSettings() {
    }

    public static synchronized AppSettings get() {
        if (instance == null) {
            instance = load();
        }
        return instance;
    }

    public synchronized void save() {
        try {
            Files.createDirectories(SETTINGS_DIR);
            Files.writeString(SETTINGS_FILE, GSON.toJson(this));
        } catch (IOException e) {
            System.err.println("Failed to save settings: " + e.getMessage());
        }
    }

    private static AppSettings load() {
        if (Files.exists(SETTINGS_FILE)) {
            try {
                String json = Files.readString(SETTINGS_FILE);
                AppSettings loaded = GSON.fromJson(json, AppSettings.class);
                if (loaded != null) {
                    return loaded;
                }
            } catch (Exception e) {
                System.err.println("Failed to load settings, using defaults: " + e.getMessage());
            }
        }
        return new AppSettings();
    }
}
