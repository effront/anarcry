package gg.effront.anarcry.gui;

import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.regex.Pattern;

/**
 * Global privacy filter that redacts sensitive information (hostnames, JWTs,
 * IPs) from displayed text. Toggle-able at runtime; listeners are notified on
 * state change.
 */
public final class PrivacyFilter {

    private static volatile boolean enabled;
    private static final List<Runnable> LISTENERS = new CopyOnWriteArrayList<>();

    private static final Pattern URL_HOST = Pattern.compile("(https?://)([^/\\s:]+)(:[0-9]+)?");
    private static final Pattern BARE_HOST = Pattern
            .compile("\\b((?:[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?\\.)+[a-zA-Z]{2,})(:[0-9]{1,5})?\\b");
    private static final Pattern JWT = Pattern.compile("eyJ[A-Za-z0-9_-]{10,}(\\.[A-Za-z0-9_-]+)*");
    private static final Pattern IPV4 = Pattern.compile("\\b(\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3})\\b");

    private PrivacyFilter() {
    }

    public static boolean isEnabled() {
        return enabled;
    }

    public static void toggle() {
        enabled = !enabled;
        LISTENERS.forEach(Runnable::run);
    }

    public static void addListener(Runnable r) {
        LISTENERS.add(r);
    }

    /**
     * Redact hostnames, JWTs, and IPs from text. Returns original if privacy is
     * off.
     */
    public static String apply(String text) {
        if (!enabled || text == null || text.isEmpty()) {
            return text;
        }
        String result = URL_HOST.matcher(text).replaceAll("$1*****$3");
        result = BARE_HOST.matcher(result).replaceAll("*****$2");
        result = JWT.matcher(result).replaceAll("eyJ***");
        result = IPV4.matcher(result).replaceAll("*.*.*.*");
        return result;
    }
}
