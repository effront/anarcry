package gg.effront.anarcry.assistant;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

public final class ProviderRegistry {

    public record ProviderInfo(String id, String label, String apiKey, List<String> models, String defaultModel) {
    }

    private static final List<String> GEMINI_MODELS = List.of("gemini-2.5-flash", "gemini-2.5-pro", "gemini-2.0-flash");
    private static final List<String> CLAUDE_MODELS = List.of("claude-sonnet-4-6", "claude-haiku-4-5-20251001",
            "claude-opus-4-6", "claude-sonnet-5-5", "claude-haiku-5-5", "claude-opus-5-5");
    private static final List<String> OPENAI_MODELS = List.of("gpt-4.1-mini", "gpt-4.1", "gpt-4o-mini", "o4-mini");
    private static final List<String> DEEPSEEK_MODELS = List.of("deepseek-chat", "deepseek-reasoner");
    private static final List<String> OPENROUTER_MODELS = List.of("deepseek/deepseek-chat-v3-0324:free",
            "deepseek/deepseek-r1:free", "qwen/qwen3-235b-a22b:free", "meta-llama/llama-4-maverick:free",
            "google/gemini-2.5-flash-preview:thinking", "anthracite-org/magnum-v4-72b",
            "sophosympatheia/rogue-rose-103b-v0.2:free");
    private static final List<String> NOTHOLY_MODELS = List.of("notholy-specter", "notholy-pulse", "notholy-vector",
            "notholy-wisp");
    private static final List<String> OLLAMA_MODELS = List.of("llama3.1", "llama3.2", "mistral", "codellama",
            "deepseek-coder-v2", "qwen2.5-coder");

    private ProviderRegistry() {
    }

    public static List<ProviderInfo> detect(Map<String, String> env) {
        List<ProviderInfo> providers = new ArrayList<>();

        String geminiKey = firstNonEmpty(env, "gemini_api_key");
        if (!geminiKey.isEmpty()) {
            providers.add(new ProviderInfo("gemini", "Gemini", geminiKey, GEMINI_MODELS, "gemini-2.5-flash"));
        }

        String anthropicKey = firstNonEmpty(env, "anthropic_api_key");
        if (!anthropicKey.isEmpty()) {
            providers.add(new ProviderInfo("claude", "Claude", anthropicKey, CLAUDE_MODELS, "claude-sonnet-4-6"));
        }

        String openaiKey = firstNonEmpty(env, "openai_api_key");
        if (!openaiKey.isEmpty()) {
            providers.add(new ProviderInfo("openai", "OpenAI", openaiKey, OPENAI_MODELS, "gpt-4.1-mini"));
        }

        String deepseekKey = firstNonEmpty(env, "deepseek_api_key");
        if (!deepseekKey.isEmpty()) {
            providers.add(new ProviderInfo("deepseek", "DeepSeek", deepseekKey, DEEPSEEK_MODELS, "deepseek-chat"));
        }

        String openrouterKey = firstNonEmpty(env, "openrouter_api_key");
        if (!openrouterKey.isEmpty()) {
            providers.add(new ProviderInfo("openrouter", "OpenRouter", openrouterKey, OPENROUTER_MODELS,
                    "deepseek/deepseek-chat-v3-0324:free"));
        }

        String notholyKey = firstNonEmpty(env, "notholy_api_key");
        if (!notholyKey.isEmpty()) {
            providers.add(new ProviderInfo("notholy", "NotHoly", notholyKey, NOTHOLY_MODELS, "notholy-pulse"));
        }

        addLegacyIfMissing(env, providers);

        String ollamaUrl = env.getOrDefault("ollama_url", "");
        if (!ollamaUrl.isEmpty()) {
            providers.add(new ProviderInfo("ollama", "Ollama", ollamaUrl, OLLAMA_MODELS, "llama3.1"));
        }

        return Collections.unmodifiableList(providers);
    }

    private static void addLegacyIfMissing(Map<String, String> env, List<ProviderInfo> providers) {
        String legacyProvider = env.getOrDefault("assistant_provider", "").toLowerCase();
        String legacyKey = env.getOrDefault("assistant_api_key", "");
        if (legacyKey.isEmpty()) {
            return;
        }
        if (legacyProvider.isEmpty()) {
            legacyProvider = inferProvider(legacyKey);
        }
        String resolvedId = "anthropic".equals(legacyProvider) ? "claude" : legacyProvider;
        boolean alreadyPresent = providers.stream().anyMatch(p -> p.id().equals(resolvedId));
        if (alreadyPresent) {
            return;
        }
        switch (resolvedId) {
            case "gemini" ->
                providers.add(new ProviderInfo("gemini", "Gemini", legacyKey, GEMINI_MODELS, "gemini-2.5-flash"));
            case "claude" ->
                providers.add(new ProviderInfo("claude", "Claude", legacyKey, CLAUDE_MODELS, "claude-sonnet-4-6"));
            case "openai" ->
                providers.add(new ProviderInfo("openai", "OpenAI", legacyKey, OPENAI_MODELS, "gpt-4.1-mini"));
            case "deepseek" ->
                providers.add(new ProviderInfo("deepseek", "DeepSeek", legacyKey, DEEPSEEK_MODELS, "deepseek-chat"));
            case "openrouter" -> providers.add(new ProviderInfo("openrouter", "OpenRouter", legacyKey,
                    OPENROUTER_MODELS, "deepseek/deepseek-chat-v3-0324:free"));
            case "notholy" ->
                providers.add(new ProviderInfo("notholy", "NotHoly", legacyKey, NOTHOLY_MODELS, "notholy-pulse"));
            default -> {
            }
        }
    }

    private static String inferProvider(String apiKey) {
        if (apiKey.startsWith("sk-ant-")) {
            return "claude";
        }
        if (apiKey.startsWith("sk-or-")) {
            return "openrouter";
        }
        if (apiKey.startsWith("sk-")) {
            return "openai";
        }
        if (apiKey.startsWith("AI")) {
            return "gemini";
        }
        return "";
    }

    private static String firstNonEmpty(Map<String, String> env, String... keys) {
        for (String key : keys) {
            String val = env.getOrDefault(key, "");
            if (!val.isEmpty()) {
                return val;
            }
        }
        return "";
    }
}
