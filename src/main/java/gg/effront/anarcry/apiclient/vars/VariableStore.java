package gg.effront.anarcry.apiclient.vars;

import gg.effront.anarcry.apiclient.model.EnvVariable;
import gg.effront.anarcry.apiclient.model.Environment;
import gg.effront.anarcry.apiclient.model.RootConfig;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

public class VariableStore {

    private final Map<String, String> runtime = new LinkedHashMap<>();
    private final Map<String, String> request = new LinkedHashMap<>();
    private final Map<String, String> folder = new LinkedHashMap<>();
    private final Map<String, String> env = new LinkedHashMap<>();
    private final Map<String, String> collection = new LinkedHashMap<>();
    private volatile Map<String, String> processEnvCache;

    public String resolve(String key) {
        String v = runtime.get(key);
        if (v != null) {
            return v;
        }
        v = request.get(key);
        if (v != null) {
            return v;
        }
        v = folder.get(key);
        if (v != null) {
            return v;
        }
        v = env.get(key);
        if (v != null) {
            return v;
        }
        v = collection.get(key);
        if (v != null) {
            return v;
        }
        return processEnv().get(key);
    }

    public Map<String, String> resolveAll() {
        Map<String, String> merged = new LinkedHashMap<>(processEnv());
        merged.putAll(collection);
        merged.putAll(env);
        merged.putAll(folder);
        merged.putAll(request);
        merged.putAll(runtime);
        return merged;
    }

    public void setRuntime(String key, String value) {
        runtime.put(key, value);
    }

    public void setRequest(String key, String value) {
        request.put(key, value);
    }

    public void setFolder(String key, String value) {
        folder.put(key, value);
    }

    private final java.util.Set<String> secretKeys = new java.util.LinkedHashSet<>();

    public void loadEnv(Environment environment) {
        env.clear();
        secretKeys.clear();
        if (environment == null || environment.variables() == null) {
            return;
        }
        for (EnvVariable v : environment.variables()) {
            if (v.enabled()) {
                env.put(v.name(), v.value());
                if (v.secret()) {
                    secretKeys.add(v.name());
                }
            }
        }
    }

    public boolean isSecret(String key) {
        return secretKeys.contains(key);
    }

    public void loadCollection(RootConfig root) {
        collection.clear();
        if (root == null || root.vars() == null) {
            return;
        }
        for (EnvVariable v : root.vars()) {
            if (v.enabled()) {
                collection.put(v.name(), v.value());
            }
        }
    }

    public void loadFolder(RootConfig root) {
        folder.clear();
        if (root == null || root.vars() == null) {
            return;
        }
        for (EnvVariable v : root.vars()) {
            if (v.enabled()) {
                folder.put(v.name(), v.value());
            }
        }
    }

    public void clear() {
        runtime.clear();
        request.clear();
        folder.clear();
        env.clear();
        collection.clear();
    }

    public Map<String, String> snapshot() {
        return Collections.unmodifiableMap(resolveAll());
    }

    public Map<String, String> runtimeVars() {
        return Collections.unmodifiableMap(runtime);
    }

    public Map<String, String> requestVars() {
        return Collections.unmodifiableMap(request);
    }

    public Map<String, String> folderVars() {
        return Collections.unmodifiableMap(folder);
    }

    public Map<String, String> envVars() {
        return Collections.unmodifiableMap(env);
    }

    public Map<String, String> collectionVars() {
        return Collections.unmodifiableMap(collection);
    }

    private Map<String, String> processEnv() {
        if (processEnvCache == null) {
            processEnvCache = System.getenv();
        }
        return processEnvCache;
    }
}
