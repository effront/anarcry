package gg.effront.anarcry.assistant.tools;

import com.google.gson.Gson;
import com.google.gson.JsonObject;

import gg.effront.anarcry.report.ReportEngine;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

public final class SaveDocTool implements AssistantTool {

    private static final Gson GSON = new Gson();
    private static final DateTimeFormatter FMT = DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss");
    private static final Path DOCS_DIR = ReportEngine.REPORTS_DIR;

    @Override
    public String name() {
        return "save_document";
    }

    @Override
    public String description() {
        return "Saves a markdown document to ~/.anarcry/reports/. Use this to save PoC reports,"
                + " remediation plans, analysis results, or any document the user asks you to generate.";
    }

    @Override
    public String paramsSchema() {
        return """
                {
                  "type": "object",
                  "properties": {
                    "filename": {
                      "type": "string",
                      "description": "Base filename without extension (e.g. poc-xss-target)"
                    },
                    "content": {
                      "type": "string",
                      "description": "Full markdown content of the document"
                    }
                  },
                  "required": ["filename", "content"]
                }
                """;
    }

    @Override
    public String call(String paramsJson) {
        try {
            JsonObject params = GSON.fromJson(paramsJson, JsonObject.class);
            String filename = params.has("filename") ? params.get("filename").getAsString() : "document";
            String content = params.has("content") ? params.get("content").getAsString() : "";

            filename = filename.replaceAll("[^a-zA-Z0-9_\\-]", "_");
            String timestamp = LocalDateTime.now().format(FMT);
            String fullName = filename + "-" + timestamp + ".md";

            Files.createDirectories(DOCS_DIR);
            Path path = DOCS_DIR.resolve(fullName);
            Files.writeString(path, content);

            return "Document saved: " + path;
        } catch (IOException e) {
            return "Error saving document: " + e.getMessage();
        }
    }
}
