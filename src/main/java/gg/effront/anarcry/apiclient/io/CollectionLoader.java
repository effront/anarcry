package gg.effront.anarcry.apiclient.io;

import com.google.gson.Gson;
import gg.effront.anarcry.apiclient.model.Collection;
import gg.effront.anarcry.apiclient.model.Environment;

import java.io.IOException;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

public class CollectionLoader {

    private final Gson gson;

    public CollectionLoader() {
        this.gson = GsonFactory.create();
    }

    public Collection load(Path collectionDir) throws IOException {
        Path collectionFile = collectionDir.resolve("collection.json");
        if (!Files.exists(collectionFile)) {
            throw new IOException("collection.json not found in " + collectionDir);
        }
        String json = Files.readString(collectionFile);
        Collection base = gson.fromJson(json, Collection.class);

        List<Environment> environments = loadEnvironments(collectionDir);
        if (!environments.isEmpty()) {
            base = new Collection(base.uid(), base.name(), base.version(), environments, base.items(), base.root(),
                    base.settings());
        }
        return base;
    }

    public Environment loadEnvironment(Path envFile) throws IOException {
        String json = Files.readString(envFile);
        return gson.fromJson(json, Environment.class);
    }

    private List<Environment> loadEnvironments(Path collectionDir) throws IOException {
        Path envDir = collectionDir.resolve("environments");
        if (!Files.isDirectory(envDir)) {
            return List.of();
        }
        List<Environment> envs = new ArrayList<>();
        try (DirectoryStream<Path> stream = Files.newDirectoryStream(envDir, "*.json")) {
            for (Path file : stream) {
                envs.add(loadEnvironment(file));
            }
        }
        return envs;
    }
}
