package gg.effront.anarcry.apiclient.io;

import com.google.gson.Gson;
import gg.effront.anarcry.apiclient.model.Collection;
import gg.effront.anarcry.apiclient.model.Environment;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

public class CollectionWriter {

    private final Gson gson;

    public CollectionWriter() {
        this.gson = GsonFactory.create();
    }

    public void save(Collection collection, Path collectionDir) throws IOException {
        Files.createDirectories(collectionDir);
        Path collectionFile = collectionDir.resolve("collection.json");
        Files.writeString(collectionFile, gson.toJson(collection));

        if (!collection.environments().isEmpty()) {
            Path envDir = collectionDir.resolve("environments");
            Files.createDirectories(envDir);
            for (Environment env : collection.environments()) {
                String filename = sanitizeFilename(env.name()) + ".json";
                Files.writeString(envDir.resolve(filename), gson.toJson(env));
            }
        }
    }

    public void saveEnvironment(Environment env, Path envFile) throws IOException {
        Files.createDirectories(envFile.getParent());
        Files.writeString(envFile, gson.toJson(env));
    }

    private static String sanitizeFilename(String name) {
        return name.toLowerCase().replaceAll("[^a-z0-9_-]", "-");
    }
}
