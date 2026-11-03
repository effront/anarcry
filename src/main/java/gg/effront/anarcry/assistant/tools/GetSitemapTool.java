package gg.effront.anarcry.assistant.tools;

import com.google.gson.Gson;
import gg.effront.anarcry.scanner.DiscoveredPaths;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.function.Supplier;
import java.util.stream.Collectors;

public final class GetSitemapTool implements AssistantTool {

    private static final int MAX_PATHS = 100;
    private static final Gson GSON = new Gson();

    private final Supplier<DiscoveredPaths> pathsSupplier;

    public GetSitemapTool(Supplier<DiscoveredPaths> pathsSupplier) {
        this.pathsSupplier = pathsSupplier;
    }

    @Override
    public String name() {
        return "get_sitemap";
    }

    @Override
    public String description() {
        return "Returns the sitemap of discovered paths and parameters from the crawler";
    }

    @Override
    public String paramsSchema() {
        return """
                {
                  "type": "object",
                  "properties": {}
                }""";
    }

    @Override
    public String call(String paramsJson) {
        DiscoveredPaths discovered = pathsSupplier.get();

        Set<String> allPaths = discovered.paths();
        Set<String> allParams = discovered.parameters();

        Map<String, List<String>> grouped = groupByPrefix(allPaths);

        Map<String, Object> response = new LinkedHashMap<>();
        response.put("totalPaths", allPaths.size());
        response.put("totalParameters", allParams.size());
        response.put("pathsByPrefix", grouped);
        response.put("parameters", allParams.stream().sorted().limit(MAX_PATHS).collect(Collectors.toList()));
        return GSON.toJson(response);
    }

    private static Map<String, List<String>> groupByPrefix(Set<String> paths) {
        Map<String, List<String>> grouped = paths.stream().sorted().limit(MAX_PATHS)
                .collect(Collectors.groupingBy(GetSitemapTool::extractPrefix, TreeMap::new, Collectors.toList()));
        return grouped;
    }

    private static String extractPrefix(String path) {
        if (path == null || path.isEmpty()) {
            return "/";
        }
        int secondSlash = path.indexOf('/', 1);
        if (secondSlash > 0) {
            return path.substring(0, secondSlash);
        }
        return path;
    }
}
