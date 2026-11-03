package gg.effront.anarcry.assistant.providers;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import gg.effront.anarcry.assistant.AssistantConfig;
import gg.effront.anarcry.assistant.ChatMessage;
import gg.effront.anarcry.assistant.UsageInfo;

import java.net.URI;
import java.net.http.HttpRequest;
import java.util.List;

public final class OpenAiProvider implements ProviderAdapter {

    private static final String API_URL = "https://api.openai.com/v1/chat/completions";
    private static final Gson GSON = new Gson();

    @Override
    public String id() {
        return "openai";
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

    protected HttpRequest buildRequest(AssistantConfig config, List<ChatMessage> messages, String systemPrompt,
            String toolsJson, boolean stream) {
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
            msgs.add(formatMessage(msg));
        }
        body.add("messages", msgs);

        if (toolsJson != null && !toolsJson.isEmpty()) {
            JsonArray rawTools = GSON.fromJson(toolsJson, JsonArray.class);
            if (rawTools != null && !rawTools.isEmpty()) {
                body.add("tools", wrapToolSchemas(rawTools));
            }
        }

        if (stream) {
            body.addProperty("stream", true);
        }

        return HttpRequest.newBuilder().uri(URI.create(apiUrl())).header("Content-Type", "application/json")
                .header("Authorization", "Bearer " + config.apiKey())
                .POST(HttpRequest.BodyPublishers.ofString(GSON.toJson(body))).build();
    }

    protected String apiUrl() {
        return API_URL;
    }

    @Override
    public ChatMessage parseResponse(String body) {
        JsonObject json = GSON.fromJson(body, JsonObject.class);
        String text = extractContent(json);
        return ChatMessage.assistant(text != null ? text : "");
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
            // malformed chunk
        }
        return null;
    }

    @Override
    public StreamToolFragment parseStreamToolFragment(String line) {
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
            if (delta == null || !delta.has("tool_calls")) {
                return null;
            }
            JsonArray toolCalls = delta.getAsJsonArray("tool_calls");
            if (toolCalls == null || toolCalls.isEmpty()) {
                return null;
            }
            JsonObject tc = toolCalls.get(0).getAsJsonObject();
            String id = tc.has("id") && !tc.get("id").isJsonNull() ? tc.get("id").getAsString() : null;
            JsonObject fn = tc.has("function") ? tc.getAsJsonObject("function") : null;
            String name = fn != null && fn.has("name") && !fn.get("name").isJsonNull()
                    ? fn.get("name").getAsString()
                    : null;
            String argsDelta = fn != null && fn.has("arguments") ? fn.get("arguments").getAsString() : null;
            if (id != null || name != null || argsDelta != null) {
                return new StreamToolFragment(id, name, argsDelta);
            }
        } catch (Exception e) {
            // malformed
        }
        return null;
    }

    @Override
    public String extractToolCallJson(String body) {
        try {
            JsonObject json = GSON.fromJson(body, JsonObject.class);
            JsonArray choices = json.getAsJsonArray("choices");
            if (choices == null || choices.isEmpty()) {
                return null;
            }
            JsonObject message = choices.get(0).getAsJsonObject().getAsJsonObject("message");
            if (message == null || !message.has("tool_calls")) {
                return null;
            }
            JsonArray toolCalls = message.getAsJsonArray("tool_calls");
            if (toolCalls == null || toolCalls.isEmpty()) {
                return null;
            }
            return GSON.toJson(toolCalls.get(0));
        } catch (Exception e) {
            // malformed
        }
        return null;
    }

    @Override
    public String extractToolCallId(String body) {
        try {
            JsonObject json = GSON.fromJson(body, JsonObject.class);
            JsonArray choices = json.getAsJsonArray("choices");
            if (choices == null || choices.isEmpty()) {
                return null;
            }
            JsonObject message = choices.get(0).getAsJsonObject().getAsJsonObject("message");
            if (message == null || !message.has("tool_calls")) {
                return null;
            }
            JsonArray toolCalls = message.getAsJsonArray("tool_calls");
            if (toolCalls == null || toolCalls.isEmpty()) {
                return null;
            }
            JsonObject call = toolCalls.get(0).getAsJsonObject();
            return call.has("id") ? call.get("id").getAsString() : null;
        } catch (Exception e) {
            return null;
        }
    }

    @Override
    public UsageInfo extractUsage(String body, String model) {
        try {
            JsonObject json = GSON.fromJson(body, JsonObject.class);
            JsonObject usage = json.getAsJsonObject("usage");
            if (usage == null) {
                return new UsageInfo(0, 0, model);
            }
            int input = usage.has("prompt_tokens") ? usage.get("prompt_tokens").getAsInt() : 0;
            int output = usage.has("completion_tokens") ? usage.get("completion_tokens").getAsInt() : 0;
            return new UsageInfo(input, output, model);
        } catch (Exception e) {
            return new UsageInfo(0, 0, model);
        }
    }

    private static JsonObject formatMessage(ChatMessage msg) {
        JsonObject m = new JsonObject();
        if ("assistant".equals(msg.role()) && msg.toolCallPayload() != null) {
            m.addProperty("role", "assistant");
            JsonArray toolCalls = new JsonArray();
            toolCalls.add(JsonParser.parseString(msg.toolCallPayload()));
            m.add("tool_calls", toolCalls);
            return m;
        }
        if ("tool".equals(msg.role()) && msg.toolCallId() != null) {
            m.addProperty("role", "tool");
            m.addProperty("tool_call_id", msg.toolCallId());
            m.addProperty("content", msg.content());
            return m;
        }
        m.addProperty("role", msg.role());
        m.addProperty("content", msg.content());
        return m;
    }

    private static JsonArray wrapToolSchemas(JsonArray rawTools) {
        JsonArray wrapped = new JsonArray();
        for (JsonElement el : rawTools) {
            JsonObject tool = el.getAsJsonObject();
            if (tool.has("type") && "function".equals(tool.get("type").getAsString())) {
                wrapped.add(tool);
            } else {
                JsonObject wrapper = new JsonObject();
                wrapper.addProperty("type", "function");
                wrapper.add("function", tool);
                wrapped.add(wrapper);
            }
        }
        return wrapped;
    }

    private static String extractContent(JsonObject json) {
        try {
            JsonArray choices = json.getAsJsonArray("choices");
            if (choices == null || choices.isEmpty()) {
                return null;
            }
            JsonObject message = choices.get(0).getAsJsonObject().getAsJsonObject("message");
            if (message != null && message.has("content") && !message.get("content").isJsonNull()) {
                return message.get("content").getAsString();
            }
        } catch (Exception e) {
            // malformed
        }
        return null;
    }
}
