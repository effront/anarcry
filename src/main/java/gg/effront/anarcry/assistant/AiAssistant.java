package gg.effront.anarcry.assistant;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import gg.effront.anarcry.assistant.providers.AnthropicProvider;
import gg.effront.anarcry.assistant.providers.GeminiProvider;
import gg.effront.anarcry.assistant.providers.OllamaProvider;
import gg.effront.anarcry.assistant.providers.OpenAiProvider;
import gg.effront.anarcry.assistant.providers.ProviderAdapter;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Consumer;
import java.util.function.Function;

public final class AiAssistant {

    private static final Gson GSON = new Gson();

    private final AssistantConfig config;
    private final ProviderAdapter provider;
    private final HttpClient httpClient;
    private final List<ChatMessage> conversationHistory = Collections.synchronizedList(new ArrayList<>());
    private final Map<String, Function<String, String>> tools = new ConcurrentHashMap<>();
    private final UsageTracker usageTracker = new UsageTracker();

    public AiAssistant(AssistantConfig config) {
        this.config = config;
        this.provider = resolveProvider(config.provider());
        this.httpClient = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(30))
                .followRedirects(HttpClient.Redirect.NORMAL).build();
    }

    public void registerTool(String name, Function<String, String> executor) {
        tools.put(name, executor);
    }

    public String send(String userMessage, String systemPrompt, String toolsJson) throws Exception {
        conversationHistory.add(ChatMessage.user(userMessage));

        List<ChatMessage> snapshot;
        synchronized (conversationHistory) {
            snapshot = new ArrayList<>(conversationHistory);
        }

        HttpRequest request = provider.formatRequest(config, snapshot, systemPrompt, toolsJson);
        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

        String body = response.body();
        if (response.statusCode() >= 400) {
            String error = "API error " + response.statusCode() + ": " + truncate(body, 200);
            conversationHistory.add(ChatMessage.assistant(error));
            return error;
        }

        UsageInfo usage = provider.extractUsage(body, config.model());
        usageTracker.record(usage);

        String toolCallJson = provider.extractToolCallJson(body);
        if (toolCallJson != null && !tools.isEmpty()) {
            String toolResult = dispatchToolCall(toolCallJson);
            if (toolResult != null) {
                String toolCallId = provider.extractToolCallId(body);
                conversationHistory.add(ChatMessage.assistantToolCall(toolCallJson));
                conversationHistory.add(ChatMessage.toolResult(toolResult, toolCallId));
                return sendFollowUp(systemPrompt, toolsJson);
            }
        }

        ChatMessage reply = provider.parseResponse(body);
        conversationHistory.add(reply);
        return reply.content();
    }

    public void sendStreaming(String userMessage, String systemPrompt, String toolsJson, Consumer<String> tokenCallback)
            throws Exception {
        conversationHistory.add(ChatMessage.user(userMessage));

        List<ChatMessage> snapshot;
        synchronized (conversationHistory) {
            snapshot = new ArrayList<>(conversationHistory);
        }

        HttpRequest request = provider.formatStreamRequest(config, snapshot, systemPrompt, toolsJson);
        HttpResponse<java.io.InputStream> response = httpClient.send(request,
                HttpResponse.BodyHandlers.ofInputStream());

        if (response.statusCode() >= 400) {
            String errorBody = new String(response.body().readAllBytes(), StandardCharsets.UTF_8);
            String error = "API error " + response.statusCode() + ": " + truncate(errorBody, 200);
            tokenCallback.accept(error);
            conversationHistory.add(ChatMessage.assistant(error));
            return;
        }

        StringBuilder fullResponse = new StringBuilder();
        String lastFullBody = null;

        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(response.body(), StandardCharsets.UTF_8))) {
            String line;
            while ((line = reader.readLine()) != null) {
                if (line.startsWith("data: ")) {
                    String data = line.substring(6).trim();
                    if ("[DONE]".equals(data)) {
                        break;
                    }
                    lastFullBody = data;
                    String token = provider.parseStreamChunk(data);
                    if (token != null) {
                        fullResponse.append(token);
                        tokenCallback.accept(token);
                    }
                }
            }
        }

        if (lastFullBody != null) {
            UsageInfo usage = provider.extractUsage(lastFullBody, config.model());
            usageTracker.record(usage);
        }

        conversationHistory.add(ChatMessage.assistant(fullResponse.toString()));
    }

    public void clearHistory() {
        conversationHistory.clear();
    }

    public List<ChatMessage> getHistory() {
        synchronized (conversationHistory) {
            return new ArrayList<>(conversationHistory);
        }
    }

    public UsageTracker getUsageTracker() {
        return usageTracker;
    }

    public AssistantConfig getConfig() {
        return config;
    }

    private String sendFollowUp(String systemPrompt, String toolsJson) throws Exception {
        List<ChatMessage> snapshot;
        synchronized (conversationHistory) {
            snapshot = new ArrayList<>(conversationHistory);
        }

        HttpRequest request = provider.formatRequest(config, snapshot, systemPrompt, toolsJson);
        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

        String body = response.body();
        if (response.statusCode() >= 400) {
            String error = "API error " + response.statusCode() + ": " + truncate(body, 200);
            conversationHistory.add(ChatMessage.assistant(error));
            return error;
        }

        UsageInfo usage = provider.extractUsage(body, config.model());
        usageTracker.record(usage);

        ChatMessage reply = provider.parseResponse(body);
        conversationHistory.add(reply);
        return reply.content();
    }

    private String dispatchToolCall(String toolCallJson) {
        try {
            JsonObject call = GSON.fromJson(toolCallJson, JsonObject.class);

            String name = null;
            String args = "{}";

            // Gemini format: {"name": "...", "args": {...}}
            if (call.has("name") && call.has("args")) {
                name = call.get("name").getAsString();
                args = GSON.toJson(call.get("args"));
            } else if (call.has("function")) {
                JsonObject func = call.getAsJsonObject("function");
                name = func.get("name").getAsString();
                args = func.has("arguments") ? func.get("arguments").getAsString() : "{}";
            } else if (call.has("name") && call.has("input")) {
                name = call.get("name").getAsString();
                args = GSON.toJson(call.get("input"));
            }

            if (name == null) {
                return null;
            }

            Function<String, String> executor = tools.get(name);
            if (executor == null) {
                return "Unknown tool: " + name;
            }

            return executor.apply(args);
        } catch (Exception e) {
            return "Tool execution error: " + e.getMessage();
        }
    }

    static ProviderAdapter resolveProvider(String providerId) {
        return switch (providerId.toLowerCase()) {
            case "gemini" -> new GeminiProvider();
            case "claude", "anthropic" -> new AnthropicProvider();
            case "openai" -> new OpenAiProvider();
            case "ollama" -> new OllamaProvider();
            default -> throw new IllegalArgumentException("Unknown AI provider: " + providerId);
        };
    }

    private static String truncate(String s, int max) {
        return s.length() <= max ? s : s.substring(0, max) + "...";
    }
}
