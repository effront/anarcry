package gg.effront.anarcry.assistant.tools;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import java.util.List;

public final class ToolSchemaBuilder {

    private ToolSchemaBuilder() {
    }

    public static String buildJson(List<AssistantTool> toolDefs) {
        JsonArray tools = new JsonArray();
        for (AssistantTool tool : toolDefs) {
            JsonObject fn = new JsonObject();
            fn.addProperty("name", tool.name());
            fn.addProperty("description", tool.description());
            fn.add("parameters", JsonParser.parseString(tool.paramsSchema()));
            tools.add(fn);
        }
        return tools.toString();
    }
}
