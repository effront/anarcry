package gg.effront.anarcry.assistant.providers;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import gg.effront.anarcry.assistant.AssistantConfig;
import gg.effront.anarcry.assistant.ChatMessage;
import gg.effront.anarcry.assistant.UsageInfo;

import java.net.URI;
import java.net.http.HttpRequest;
import java.util.List;

public final class AnthropicProvider implements ProviderAdapter {

    private static final String API_URL = "https://api.anthropic.com/v1/messages";
    private static final String API_VERSION = "2023-06-01";
    private static final Gson GSON = new Gson();

    @Override
    public String id() {
        return "claude";
    }

    @Override
    public HttpRequest formatRequest(AssistantConfig config, List<ChatMessage> messages, String systemPrompt,
            String toolsJson) {
        return buildRequest(config, messages, systemPrompt, toolsJson, false);
    }

    @Override
    public HttpRequest formatStreamRequest(AssistantConfig config, List<ChatMessage> messages, String systemPrompt,
            String toolsJson) {
        return buildRequest(config, messages, systemPrompt, toolsJson, true);
    }

    private HttpRequest buildRequest(AssistantConfig config, List<ChatMessage> messages, String systemPrompt,
            String toolsJson, boolean stream) {
        JsonObject body = new JsonObject();
        body.addProperty("model", config.model());
        body.addProperty("max_tokens", config.maxTokens());

        if (systemPrompt != null && !systemPrompt.isEmpty()) {
            body.addProperty("system", systemPrompt);
        }

        JsonArray msgs = new JsonArray();
        for (ChatMessage msg : messages) {
            if ("system".equals(msg.role())) {
                continue;
            }
            JsonObject m = new JsonObject();
            m.addProperty("role", "tool".equals(msg.role()) ? "user" : msg.role());
            m.addProperty("content", msg.content());
            msgs.add(m);
        }
        body.add("messages", msgs);

        if (toolsJson != null && !toolsJson.isEmpty()) {
            JsonArray tools = GSON.fromJson(toolsJson, JsonArray.class);
            if (tools != null && !tools.isEmpty()) {
                body.add("tools", tools);
            }
        }

        if (stream) {
            body.addProperty("stream", true);
        }

        return HttpRequest.newBuilder().uri(URI.create(API_URL)).header("Content-Type", "application/json")
                .header("x-api-key", config.apiKey()).header("anthropic-version", API_VERSION)
                .POST(HttpRequest.BodyPublishers.ofString(GSON.toJson(body))).build();
    }

    @Override
    public ChatMessage parseResponse(String body) {
        JsonObject json = GSON.fromJson(body, JsonObject.class);
        String text = extractText(json);
        return ChatMessage.assistant(text != null ? text : "");
    }

    @Override
    public String parseStreamChunk(String line) {
        if (line == null || line.isEmpty()) {
            return null;
        }
        try {
            JsonObject json = GSON.fromJson(line, JsonObject.class);
            String type = json.has("type") ? json.get("type").getAsString() : "";
            if ("content_block_delta".equals(type)) {
                JsonObject delta = json.getAsJsonObject("delta");
                if (delta != null && delta.has("text")) {
                    return delta.get("text").getAsString();
                }
            }
        } catch (Exception e) {
            // malformed chunk
        }
        return null;
    }

    @Override
    public String extractToolCallJson(String body) {
        try {
            JsonObject json = GSON.fromJson(body, JsonObject.class);
            JsonArray content = json.getAsJsonArray("content");
            if (content == null) {
                return null;
            }
            for (JsonElement block : content) {
                JsonObject b = block.getAsJsonObject();
                if ("tool_use".equals(b.has("type") ? b.get("type").getAsString() : "")) {
                    JsonObject toolCall = new JsonObject();
                    toolCall.addProperty("id", b.get("id").getAsString());
                    toolCall.addProperty("name", b.get("name").getAsString());
                    toolCall.add("input", b.get("input"));
                    return GSON.toJson(toolCall);
                }
            }
        } catch (Exception e) {
            // malformed
        }
        return null;
    }

    @Override
    public UsageInfo extractUsage(String body, String model) {
        try {
            JsonObject json = GSON.fromJson(body, JsonObject.class);
            JsonObject usage = json.getAsJsonObject("usage");
            if (usage == null) {
                return new UsageInfo(0, 0, model);
            }
            int input = usage.has("input_tokens") ? usage.get("input_tokens").getAsInt() : 0;
            int output = usage.has("output_tokens") ? usage.get("output_tokens").getAsInt() : 0;
            return new UsageInfo(input, output, model);
        } catch (Exception e) {
            return new UsageInfo(0, 0, model);
        }
    }

    private static String extractText(JsonObject json) {
        try {
            JsonArray content = json.getAsJsonArray("content");
            if (content == null) {
                return null;
            }
            for (JsonElement block : content) {
                JsonObject b = block.getAsJsonObject();
                if ("text".equals(b.has("type") ? b.get("type").getAsString() : "")) {
                    return b.get("text").getAsString();
                }
            }
        } catch (Exception e) {
            // malformed
        }
        return null;
    }
}
