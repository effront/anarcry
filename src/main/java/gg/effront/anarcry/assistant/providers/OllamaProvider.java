package gg.effront.anarcry.assistant.providers;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import gg.effront.anarcry.assistant.AssistantConfig;
import gg.effront.anarcry.assistant.ChatMessage;
import gg.effront.anarcry.assistant.UsageInfo;

import java.net.URI;
import java.net.http.HttpRequest;
import java.util.List;

public final class OllamaProvider implements ProviderAdapter {

    private static final String DEFAULT_URL = "http://localhost:11434/v1/chat/completions";
    private static final Gson GSON = new Gson();

    @Override
    public String id() {
        return "ollama";
    }

    @Override
    public HttpRequest formatRequest(AssistantConfig config, List<ChatMessage> messages, String systemPrompt,
            String toolsJson) {
        return buildRequest(config, messages, systemPrompt, false);
    }

    @Override
    public HttpRequest formatStreamRequest(AssistantConfig config, List<ChatMessage> messages, String systemPrompt,
            String toolsJson) {
        return buildRequest(config, messages, systemPrompt, true);
    }

    private HttpRequest buildRequest(AssistantConfig config, List<ChatMessage> messages, String systemPrompt,
            boolean stream) {
        JsonObject body = new JsonObject();
        body.addProperty("model", config.model());
        body.addProperty("max_tokens", config.maxTokens());

        JsonArray msgs = new JsonArray();
        if (systemPrompt != null && !systemPrompt.isEmpty()) {
            JsonObject sysMsg = new JsonObject();
            sysMsg.addProperty("role", "system");
            sysMsg.addProperty("content", systemPrompt);
            msgs.add(sysMsg);
        }
        for (ChatMessage msg : messages) {
            if ("system".equals(msg.role())) {
                continue;
            }
            if ("tool".equals(msg.role())) {
                JsonObject m = new JsonObject();
                m.addProperty("role", "user");
                m.addProperty("content", "[Tool result] " + msg.content());
                msgs.add(m);
                continue;
            }
            if ("assistant".equals(msg.role()) && msg.toolCallPayload() != null) {
                continue;
            }
            JsonObject m = new JsonObject();
            m.addProperty("role", msg.role());
            m.addProperty("content", msg.content());
            msgs.add(m);
        }
        body.add("messages", msgs);

        if (stream) {
            body.addProperty("stream", true);
        }

        String url = resolveUrl(config);
        return HttpRequest.newBuilder().uri(URI.create(url)).header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(GSON.toJson(body))).build();
    }

    @Override
    public ChatMessage parseResponse(String body) {
        try {
            JsonObject json = GSON.fromJson(body, JsonObject.class);
            JsonArray choices = json.getAsJsonArray("choices");
            if (choices != null && !choices.isEmpty()) {
                JsonObject message = choices.get(0).getAsJsonObject().getAsJsonObject("message");
                if (message != null && message.has("content") && !message.get("content").isJsonNull()) {
                    return ChatMessage.assistant(message.get("content").getAsString());
                }
            }
        } catch (Exception e) {
            // malformed
        }
        return ChatMessage.assistant("");
    }

    @Override
    public String parseStreamChunk(String line) {
        if (line == null || line.isEmpty() || "[DONE]".equals(line)) {
            return null;
        }
        try {
            JsonObject json = GSON.fromJson(line, JsonObject.class);
            JsonArray choices = json.getAsJsonArray("choices");
            if (choices == null || choices.isEmpty()) {
                return null;
            }
            JsonObject delta = choices.get(0).getAsJsonObject().getAsJsonObject("delta");
            if (delta != null && delta.has("content") && !delta.get("content").isJsonNull()) {
                return delta.get("content").getAsString();
            }
        } catch (Exception e) {
            // malformed
        }
        return null;
    }

    @Override
    public String extractToolCallJson(String body) {
        return null;
    }

    private static String resolveUrl(AssistantConfig config) {
        String key = config.apiKey();
        if (key != null && key.startsWith("http")) {
            return key.endsWith("/v1/chat/completions") ? key : key + "/v1/chat/completions";
        }
        return DEFAULT_URL;
    }

    @Override
    public UsageInfo extractUsage(String body, String model) {
        try {
            JsonObject json = GSON.fromJson(body, JsonObject.class);
            JsonObject usage = json.getAsJsonObject("usage");
            if (usage != null) {
                int input = usage.has("prompt_tokens") ? usage.get("prompt_tokens").getAsInt() : 0;
                int output = usage.has("completion_tokens") ? usage.get("completion_tokens").getAsInt() : 0;
                return new UsageInfo(input, output, model);
            }
        } catch (Exception e) {
            // malformed
        }
        return new UsageInfo(0, 0, model);
    }
}
