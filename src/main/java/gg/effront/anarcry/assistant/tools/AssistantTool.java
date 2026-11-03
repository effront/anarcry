package gg.effront.anarcry.assistant.tools;

public interface AssistantTool {

    String name();

    String description();

    String paramsSchema();

    String call(String paramsJson);
}
