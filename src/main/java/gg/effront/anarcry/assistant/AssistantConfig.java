package gg.effront.anarcry.assistant;

import java.util.Map;

public record AssistantConfig(String provider, String apiKey, String model, int maxTokens) {

    private static final int DEFAULT_MAX_TOKENS = 4096;

    public static AssistantConfig fromEnv(Map<String, String> env) {
        String provider = env.getOrDefault("assistant_provider", "").toLowerCase();
        String apiKey = env.getOrDefault("assistant_api_key", "");
        String model = env.getOrDefault("assistant_model", defaultModel(provider));
        int maxTokens = DEFAULT_MAX_TOKENS;
        String maxStr = env.getOrDefault("assistant_max_tokens", "");
        if (!maxStr.isEmpty()) {
            try {
                maxTokens = Integer.parseInt(maxStr);
            } catch (NumberFormatException ignored) {
                // keep default
            }
        }
        return new AssistantConfig(provider, apiKey, model, maxTokens);
    }

    public boolean isConfigured() {
        return !provider.isEmpty() && (!apiKey.isEmpty() || "ollama".equals(provider));
    }

    private static String defaultModel(String provider) {
        return switch (provider) {
            case "gemini" -> "gemini-2.5-flash";
            case "claude" -> "claude-sonnet-4-20250514";
            case "openai" -> "gpt-4.1-mini";
            case "ollama" -> "llama3.1";
            default -> "";
        };
    }
}
