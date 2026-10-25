package gg.effront.anarcry.scanner;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import gg.effront.anarcry.model.Suppression;

import java.io.IOException;
import java.lang.reflect.Type;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Collections;
import java.util.List;

public final class SuppressionLoader {

    private static final String DEFAULT_FILE = ".anarcry-ignore.json";

    private SuppressionLoader() {
    }

    public static List<Suppression> loadFromCwd() {
        return load(DEFAULT_FILE);
    }

    public static List<Suppression> load(String path) {
        try {
            String json = Files.readString(Paths.get(path));
            Type listType = new TypeToken<List<Suppression>>() {
            }.getType();
            List<Suppression> result = new Gson().fromJson(json, listType);
            return result != null ? Collections.unmodifiableList(result) : Collections.emptyList();
        } catch (IOException e) {
            return Collections.emptyList();
        }
    }
}
