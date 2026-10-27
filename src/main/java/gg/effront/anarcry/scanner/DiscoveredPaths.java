package gg.effront.anarcry.scanner;

import java.util.Collection;
import java.util.Collections;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

public final class DiscoveredPaths {

    private final Set<String> paths = ConcurrentHashMap.newKeySet();
    private final Set<String> parameters = ConcurrentHashMap.newKeySet();

    public void addPath(String path) {
        if (path != null && !path.isBlank()) {
            paths.add(path);
        }
    }

    public void addPaths(Collection<String> p) {
        p.forEach(this::addPath);
    }

    public void addParameter(String param) {
        if (param != null && !param.isBlank()) {
            parameters.add(param);
        }
    }

    public void addParameters(Collection<String> p) {
        p.forEach(this::addParameter);
    }

    public Set<String> paths() {
        return Collections.unmodifiableSet(paths);
    }

    public Set<String> parameters() {
        return Collections.unmodifiableSet(parameters);
    }

    public boolean isEmpty() {
        return paths.isEmpty() && parameters.isEmpty();
    }

    public int pathCount() {
        return paths.size();
    }

    public int parameterCount() {
        return parameters.size();
    }
}
