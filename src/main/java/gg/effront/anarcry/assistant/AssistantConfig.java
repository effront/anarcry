package gg.effront.anarcry.assistant;

import java.util.Map;

public record AssistantConfig(String provider, String apiKey, String model, int maxTokens) {

    private static final int DEFAULT_MAX_TOKENS = 4096;

    public static AssistantConfig fromEnv(Map<String, String> env) {
        var providers = ProviderRegistry.detect(env);
        String legacyProvider = env.getOrDefault("assistant_provider", "").toLowerCase();
        String resolvedId = "anthropic".equals(legacyProvider) ? "claude" : legacyProvider;
        for (var info : providers) {
            if (info.id().equals(resolvedId)) {
                String model = env.getOrDefault("assistant_model", info.defaultModel());
                return forProvider(info, model, parseMaxTokens(env));
            }
        }
        if (!providers.isEmpty()) {
            var first = providers.get(0);
            return forProvider(first, first.defaultModel(), parseMaxTokens(env));
        }
        return new AssistantConfig("", "", "", DEFAULT_MAX_TOKENS);
    }

    public static AssistantConfig forProvider(ProviderRegistry.ProviderInfo info, String model, int maxTokens) {
        String m = (model == null || model.isEmpty()) ? info.defaultModel() : model;
        return new AssistantConfig(info.id(), info.apiKey(), m, maxTokens);
    }

    public boolean isConfigured() {
        return !provider.isEmpty() && (!apiKey.isEmpty() || "ollama".equals(provider));
    }

    public static int parseMaxTokens(Map<String, String> env) {
        String maxStr = env.getOrDefault("assistant_max_tokens", "");
        if (!maxStr.isEmpty()) {
            try {
                return Integer.parseInt(maxStr);
            } catch (NumberFormatException ignored) {
                // keep default
            }
        }
        return DEFAULT_MAX_TOKENS;
    }
}
