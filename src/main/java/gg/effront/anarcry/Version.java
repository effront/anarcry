package gg.effront.anarcry;

import java.io.InputStream;
import java.util.Properties;

public final class Version {

    private static final String VERSION;

    static {
        String v = "dev";
        try (InputStream is = Version.class.getResourceAsStream("/version.properties")) {
            if (is != null) {
                Properties p = new Properties();
                p.load(is);
                v = p.getProperty("version", "dev");
            }
        } catch (Exception ignored) {
        }
        VERSION = v;
    }

    private Version() {
    }

    public static String get() {
        return VERSION;
    }

    public static String label() {
        return "AnarCry v" + VERSION;
    }

    public static String userAgent() {
        return "AnarCry/" + VERSION;
    }
}
