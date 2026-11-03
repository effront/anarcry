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

public final class GeminiProvider implements ProviderAdapter {

    private static final String BASE_URL = "https://generativelanguage.googleapis.com/v1beta/models/";
    private static final Gson GSON = new Gson();

    @Override
    public String id() {
        return "gemini";
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

        JsonArray contents = new JsonArray();
        String lastFunctionName = null;
        for (ChatMessage msg : messages) {
            if ("system".equals(msg.role())) {
                continue;
            }
            if ("assistant".equals(msg.role()) && msg.toolCallPayload() != null) {
                lastFunctionName = parseFunctionName(msg.toolCallPayload());
            }
            contents.add(formatMessage(msg, lastFunctionName));
            if ("tool".equals(msg.role())) {
                lastFunctionName = null;
            }
        }
        body.add("contents", contents);

        if (systemPrompt != null && !systemPrompt.isEmpty()) {
            JsonObject sysInstr = new JsonObject();
            JsonArray sysParts = new JsonArray();
            JsonObject sysText = new JsonObject();
            sysText.addProperty("text", systemPrompt);
            sysParts.add(sysText);
            sysInstr.add("parts", sysParts);
            body.add("systemInstruction", sysInstr);
        }

        if (toolsJson != null && !toolsJson.isEmpty()) {
            JsonArray tools = GSON.fromJson(toolsJson, JsonArray.class);
            if (tools != null && !tools.isEmpty()) {
                JsonArray toolsWrapper = new JsonArray();
                JsonObject funcDecls = new JsonObject();
                funcDecls.add("functionDeclarations", stripToolWrappers(tools));
                toolsWrapper.add(funcDecls);
                body.add("tools", toolsWrapper);
            }
        }

        JsonObject genConfig = new JsonObject();
        genConfig.addProperty("maxOutputTokens", config.maxTokens());
        body.add("generationConfig", genConfig);

        String action = stream ? "streamGenerateContent?alt=sse" : "generateContent";
        String url = BASE_URL + config.model() + ":" + action;

        return HttpRequest.newBuilder().uri(URI.create(url)).header("Content-Type", "application/json")
                .header("x-goog-api-key", config.apiKey()).POST(HttpRequest.BodyPublishers.ofString(GSON.toJson(body)))
                .build();
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
            return extractText(json);
        } catch (Exception e) {
            return null;
        }
    }

    @Override
    public String extractToolCallJson(String body) {
        try {
            JsonObject json = GSON.fromJson(body, JsonObject.class);
            JsonArray candidates = json.getAsJsonArray("candidates");
            if (candidates == null || candidates.isEmpty()) {
                return null;
            }
            JsonObject content = candidates.get(0).getAsJsonObject().getAsJsonObject("content");
            if (content == null) {
                return null;
            }
            JsonArray parts = content.getAsJsonArray("parts");
            if (parts == null) {
                return null;
            }
            for (JsonElement part : parts) {
                JsonObject partObj = part.getAsJsonObject();
                if (partObj.has("functionCall")) {
                    return GSON.toJson(partObj.get("functionCall"));
                }
            }
        } catch (Exception e) {
            // malformed response
        }
        return null;
    }

    @Override
    public UsageInfo extractUsage(String body, String model) {
        try {
            JsonObject json = GSON.fromJson(body, JsonObject.class);
            JsonObject usage = json.getAsJsonObject("usageMetadata");
            if (usage == null) {
                return new UsageInfo(0, 0, model);
            }
            int input = usage.has("promptTokenCount") ? usage.get("promptTokenCount").getAsInt() : 0;
            int output = usage.has("candidatesTokenCount") ? usage.get("candidatesTokenCount").getAsInt() : 0;
            return new UsageInfo(input, output, model);
        } catch (Exception e) {
            return new UsageInfo(0, 0, model);
        }
    }

    private static JsonObject formatMessage(ChatMessage msg, String functionName) {
        JsonObject content = new JsonObject();
        JsonArray parts = new JsonArray();

        if ("assistant".equals(msg.role()) && msg.toolCallPayload() != null) {
            content.addProperty("role", "model");
            JsonObject fcPart = new JsonObject();
            fcPart.add("functionCall", JsonParser.parseString(msg.toolCallPayload()));
            parts.add(fcPart);
            content.add("parts", parts);
            return content;
        }

        if ("tool".equals(msg.role())) {
            content.addProperty("role", "function");
            JsonObject frPart = new JsonObject();
            JsonObject funcResponse = new JsonObject();
            funcResponse.addProperty("name", functionName != null ? functionName : "tool");
            JsonObject responseObj = new JsonObject();
            responseObj.addProperty("result", msg.content());
            funcResponse.add("response", responseObj);
            frPart.add("functionResponse", funcResponse);
            parts.add(frPart);
            content.add("parts", parts);
            return content;
        }

        content.addProperty("role", mapRole(msg.role()));
        JsonObject textPart = new JsonObject();
        textPart.addProperty("text", msg.content());
        parts.add(textPart);
        content.add("parts", parts);
        return content;
    }

    private static String parseFunctionName(String toolCallPayload) {
        try {
            JsonObject call = GSON.fromJson(toolCallPayload, JsonObject.class);
            if (call.has("name")) {
                return call.get("name").getAsString();
            }
        } catch (Exception e) {
            // malformed payload
        }
        return "tool";
    }

    private static JsonArray stripToolWrappers(JsonArray rawTools) {
        JsonArray stripped = new JsonArray();
        for (JsonElement el : rawTools) {
            JsonObject tool = el.getAsJsonObject();
            if (tool.has("type") && "function".equals(tool.get("type").getAsString()) && tool.has("function")) {
                stripped.add(tool.getAsJsonObject("function"));
            } else {
                stripped.add(tool);
            }
        }
        return stripped;
    }

    private static String extractText(JsonObject json) {
        try {
            JsonArray candidates = json.getAsJsonArray("candidates");
            if (candidates == null || candidates.isEmpty()) {
                return null;
            }
            JsonObject content = candidates.get(0).getAsJsonObject().getAsJsonObject("content");
            if (content == null) {
                return null;
            }
            JsonArray parts = content.getAsJsonArray("parts");
            if (parts == null || parts.isEmpty()) {
                return null;
            }
            for (JsonElement part : parts) {
                JsonObject partObj = part.getAsJsonObject();
                if (partObj.has("text")) {
                    return partObj.get("text").getAsString();
                }
            }
        } catch (Exception e) {
            // malformed
        }
        return null;
    }

    private static String mapRole(String role) {
        return switch (role) {
            case "assistant" -> "model";
            case "tool" -> "function";
            default -> "user";
        };
    }
}
