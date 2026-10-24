package gg.effront.anarcry.report;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import gg.effront.anarcry.model.Finding;
import gg.effront.anarcry.model.Severity;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Comparator;
import java.util.List;

public class ReportEngine {

    private static final DateTimeFormatter FMT = DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss");
    private static final Gson GSON = new GsonBuilder().setPrettyPrinting().create();
    private static final List<Severity> ORDER = List.of(
        Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO
    );

    public String export(List<Finding> findings, String targetUrl) throws IOException {
        String timestamp = LocalDateTime.now().format(FMT);
        String base = "anarcry-report-" + timestamp;

        List<Finding> sorted = findings.stream()
            .sorted(Comparator.comparingInt(f -> ORDER.indexOf(f.severity())))
            .toList();

        Path mdPath   = Path.of(base + ".md");
        Path jsonPath = Path.of(base + ".json");

        Files.writeString(mdPath, buildMarkdown(sorted, targetUrl, timestamp));
        Files.writeString(jsonPath, toJson(sorted));

        return mdPath.toString();
    }

    public String toJson(List<Finding> findings) {
        List<Finding> sorted = findings.stream()
            .sorted(Comparator.comparingInt(f -> ORDER.indexOf(f.severity())))
            .toList();
        return GSON.toJson(sorted);
    }

    private String buildMarkdown(List<Finding> findings, String targetUrl, String timestamp) {
        StringBuilder sb = new StringBuilder();
        sb.append("# AnarCry Report\n\n");
        sb.append("**Target:** ").append(targetUrl).append("  \n");
        sb.append("**Data:** ").append(timestamp).append("  \n");
        sb.append("**Total findings:** ").append(findings.size()).append("\n\n");

        sb.append("## Resumo\n\n");
        for (Severity s : ORDER) {
            long count = findings.stream().filter(f -> f.severity() == s).count();
            if (count > 0) sb.append("- **").append(s).append("**: ").append(count).append("\n");
        }
        sb.append("\n");

        sb.append("## Findings\n\n");
        sb.append("| Severity | Module | Endpoint | Title | Evidence | Recommendation |\n");
        sb.append("|----------|--------|----------|-------|----------|----------------|\n");
        for (Finding f : findings) {
            sb.append("| ").append(f.severity())
              .append(" | ").append(escape(f.module()))
              .append(" | ").append(escape(f.endpoint()))
              .append(" | ").append(escape(f.title()))
              .append(" | ").append(escape(f.evidence()))
              .append(" | ").append(escape(f.recommendation()))
              .append(" |\n");
        }
        sb.append("\n");

        sb.append("## Detalhes\n\n");
        for (Finding f : findings) {
            sb.append("### [").append(f.severity()).append("] ").append(f.title()).append("\n\n");
            sb.append("**Módulo:** ").append(f.module()).append("  \n");
            sb.append("**Endpoint:** ").append(f.endpoint()).append("  \n");
            sb.append("**Evidência:** ").append(f.evidence()).append("  \n");
            sb.append("**Impacto:** ").append(f.impact()).append("  \n");
            sb.append("**Reprodução:**\n```\n").append(f.reproduction()).append("\n```\n");
            sb.append("**Recomendação:** ").append(f.recommendation()).append("  \n");
            sb.append("\n---\n\n");
        }
        return sb.toString();
    }

    private String escape(String s) {
        return s == null ? "" : s.replace("|", "\\|").replace("\n", " ");
    }
}
