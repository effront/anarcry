package gg.effront.anarcry.model;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;

import java.io.InputStreamReader;
import java.io.Reader;
import java.lang.reflect.Type;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

public final class KnowledgeBase {

    private static final String RESOURCE = "/knowledge_base.json";

    private final Map<String, KnowledgeEntry> byId;
    private final Map<String, KnowledgeEntry> byModule;

    private KnowledgeBase(Map<String, KnowledgeEntry> entries) {
        Map<String, KnowledgeEntry> idMap = new LinkedHashMap<>();
        Map<String, KnowledgeEntry> modMap = new LinkedHashMap<>();
        for (var entry : entries.entrySet()) {
            idMap.put(entry.getKey().toLowerCase(), entry.getValue());
            modMap.put(entry.getValue().module().toLowerCase(), entry.getValue());
        }
        this.byId = Collections.unmodifiableMap(idMap);
        this.byModule = Collections.unmodifiableMap(modMap);
    }

    public static KnowledgeBase getInstance() {
        return Holder.INSTANCE;
    }

    public Optional<KnowledgeEntry> byId(String id) {
        if (id == null) {
            return Optional.empty();
        }
        return Optional.ofNullable(byId.get(id.toLowerCase()));
    }

    public Optional<KnowledgeEntry> byModule(String moduleName) {
        if (moduleName == null) {
            return Optional.empty();
        }
        return Optional.ofNullable(byModule.get(moduleName.toLowerCase()));
    }

    public Map<String, KnowledgeEntry> all() {
        return byId;
    }

    public int size() {
        return byId.size();
    }

    public List<String> filteredPayloads(String moduleId) {
        return byModule(moduleId).map(e -> e.payloads().stream().filter(p -> !isComment(p)).toList()).orElse(List.of());
    }

    private static boolean isComment(String line) {
        String s = line.strip();
        return s.startsWith("# ") || s.equals("#") || s.startsWith("-- ") || s.equals("--") || s.startsWith("<!--");
    }

    private static final class Holder {
        static final KnowledgeBase INSTANCE = load();

        private static KnowledgeBase load() {
            try (Reader reader = new InputStreamReader(KnowledgeBase.class.getResourceAsStream(RESOURCE),
                    StandardCharsets.UTF_8)) {
                Type type = new TypeToken<LinkedHashMap<String, KnowledgeEntry>>() {
                }.getType();
                Map<String, KnowledgeEntry> entries = new Gson().fromJson(reader, type);
                return new KnowledgeBase(entries);
            } catch (Exception e) {
                throw new ExceptionInInitializerError("Failed to load " + RESOURCE + ": " + e.getMessage());
            }
        }
    }
}
