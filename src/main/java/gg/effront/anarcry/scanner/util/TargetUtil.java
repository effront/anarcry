package gg.effront.anarcry.scanner.util;

public final class TargetUtil {

    private TargetUtil() {
    }

    public static String sanitizeTarget(String raw) {
        String t = raw.trim();
        t = t.replaceFirst("^(https?://)\\1+", "$1");
        t = t.replaceAll("/+$", "");
        if (!t.startsWith("http://") && !t.startsWith("https://")) {
            t = "https://" + t;
        }
        return t;
    }
}
