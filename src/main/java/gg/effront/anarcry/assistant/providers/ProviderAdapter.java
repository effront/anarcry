package gg.effront.anarcry.assistant.providers;

import gg.effront.anarcry.assistant.AssistantConfig;
import gg.effront.anarcry.assistant.ChatMessage;
import gg.effront.anarcry.assistant.UsageInfo;

import java.net.http.HttpRequest;
import java.util.List;

public interface ProviderAdapter {

    String id();

    HttpRequest formatRequest(AssistantConfig config, List<ChatMessage> messages, String systemPrompt,
            String toolsJson);

    HttpRequest formatStreamRequest(AssistantConfig config, List<ChatMessage> messages, String systemPrompt,
            String toolsJson);

    ChatMessage parseResponse(String body);

    String parseStreamChunk(String line);

    String extractToolCallJson(String body);

    UsageInfo extractUsage(String body, String model);
}
