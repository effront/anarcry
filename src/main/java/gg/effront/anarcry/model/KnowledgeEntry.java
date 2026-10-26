package gg.effront.anarcry.model;

import java.util.List;

public record KnowledgeEntry(String title, String module, String severity, String cweId, String cweTitle,
        String cvssVector, String vrtId, String summary, String description, String impact, List<String> payloads,
        CrawlerHints crawlerHints, String recommendation) {

    public record CrawlerHints(List<String> parameters, List<String> paths) {
    }
}
