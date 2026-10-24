package gg.effront.anarcry;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.Map;

public record EnvLoader(String target, String jwt1, String jwt2) {

    public static EnvLoader load(String path) throws IOException {
        Map<String, String> map = new HashMap<>();
        for (String rawLine : Files.readAllLines(Paths.get(path))) {
            String line = rawLine.strip();
            if (line.isBlank() || line.startsWith("#")) {
                continue;
            }
            int sep = line.indexOf(':');
            if (sep < 1) {
                continue;
            }
            String key = line.substring(0, sep).strip().toLowerCase();
            String val = line.substring(sep + 1).strip();
            map.put(key, val);
        }
        String target = normalize(map.getOrDefault("target", ""));
        String jwt1 = map.getOrDefault("jwt1", "");
        String jwt2 = map.getOrDefault("jwt2", "");
        return new EnvLoader(target, jwt1, jwt2);
    }

    public boolean hasTarget() {
        return target != null && !target.isBlank();
    }

    private static String normalize(String t) {
        if (t.isBlank()) {
            return t;
        }
        if (!t.startsWith("http://") && !t.startsWith("https://")) {
            return "https://" + t;
        }
        return t;
    }
}
