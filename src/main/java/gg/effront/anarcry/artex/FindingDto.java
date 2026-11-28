package gg.effront.anarcry.artex;

import com.google.gson.JsonObject;
import gg.effront.anarcry.model.Finding;

/**
 * DTO that maps an AnarCry {@link Finding} to the ARTEX findings API format.
 *
 * @param module
 *            vulnerability class / scanner module id
 * @param endpoint
 *            affected endpoint URL
 * @param title
 *            finding title
 * @param severity
 *            severity string (CRITICAL, HIGH, MEDIUM, LOW, INFO)
 * @param evidence
 *            concrete evidence from the scan
 * @param impact
 *            description of potential impact
 * @param reproduction
 *            steps to reproduce (typically a curl command)
 * @param recommendation
 *            remediation advice
 * @param cweId
 *            CWE identifier (e.g. "CWE-89")
 * @param cvssScore
 *            CVSS v3.1 base score
 * @param cvssVector
 *            CVSS v3.1 vector string
 */
public record FindingDto(String module, String endpoint, String title, String severity, String evidence, String impact,
        String reproduction, String recommendation, String cweId, double cvssScore, String cvssVector) {

    /** Convert an AnarCry Finding to the ARTEX DTO format. */
    public static FindingDto from(Finding f) {
        return new FindingDto(f.module(), f.endpoint(), f.title(), f.severity().name(), f.evidence(), f.impact(),
                f.reproduction(), f.recommendation(), f.cweId(), f.cvssScore(), f.cvssVector());
    }

    /** Serializes an AnarCry Finding to a JSON object for ARTEX consumption. */
    public static JsonObject toJsonObject(Finding f) {
        JsonObject obj = new JsonObject();
        obj.addProperty("module", f.module());
        obj.addProperty("endpoint", f.endpoint());
        obj.addProperty("title", f.title());
        obj.addProperty("severity", f.severity().name().toLowerCase());
        obj.addProperty("evidence", f.evidence());
        obj.addProperty("impact", f.impact());
        obj.addProperty("reproduction", f.reproduction());
        obj.addProperty("recommendation", f.recommendation());
        obj.addProperty("cwe_id", f.cweId());
        obj.addProperty("cwe_title", f.cweTitle());
        obj.addProperty("cvss_vector", f.cvssVector());
        obj.addProperty("cvss_score", f.cvssScore());
        return obj;
    }
}
