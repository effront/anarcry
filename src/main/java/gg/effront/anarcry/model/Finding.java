package gg.effront.anarcry.model;

public record Finding(
    String module,
    String endpoint,
    String title,
    Severity severity,
    String evidence,
    String impact,
    String reproduction,
    String recommendation
) {}
