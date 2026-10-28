package gg.effront.anarcry.gui.views;

import gg.effront.anarcry.gui.PrivacyFilter;
import gg.effront.anarcry.model.Finding;
import gg.effront.anarcry.model.Severity;

import java.awt.BorderLayout;
import java.awt.FlowLayout;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

import javax.swing.JButton;
import javax.swing.JEditorPane;
import javax.swing.JFrame;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.SwingUtilities;

/**
 * Report preview panel with HTML rendering and export trigger.
 */
public class ReportView extends JPanel {

    private static final List<Severity> ORDER = List.of(Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW,
            Severity.INFO);

    private final JEditorPane preview;
    private List<Finding> currentFindings = List.of();
    private String currentTarget = "";

    public ReportView() {
        super(new BorderLayout());

        JPanel toolbar = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 4));

        JButton generateBtn = new JButton("Generate Preview");
        generateBtn.addActionListener(e -> refreshPreview());
        toolbar.add(generateBtn);

        JButton exportBtn = new JButton("Export...");
        exportBtn.addActionListener(e -> {
            JFrame frame = (JFrame) SwingUtilities.getWindowAncestor(this);
            new ExportDialog(frame, new ArrayList<>(currentFindings), currentTarget).setVisible(true);
        });
        toolbar.add(exportBtn);

        add(toolbar, BorderLayout.NORTH);

        preview = new JEditorPane();
        preview.setContentType("text/html");
        preview.setEditable(false);
        preview.setText(emptyHtml());
        add(new JScrollPane(preview), BorderLayout.CENTER);

        PrivacyFilter.addListener(() -> SwingUtilities.invokeLater(this::refreshPreview));
    }

    public void update(List<Finding> findings, String targetUrl) {
        this.currentFindings = new ArrayList<>(findings);
        this.currentTarget = targetUrl != null ? targetUrl : "";
        SwingUtilities.invokeLater(this::refreshPreview);
    }

    public void clear() {
        this.currentFindings = List.of();
        this.currentTarget = "";
        SwingUtilities.invokeLater(() -> preview.setText(emptyHtml()));
    }

    private void refreshPreview() {
        if (currentFindings.isEmpty()) {
            preview.setText(emptyHtml());
            return;
        }
        preview.setText(buildHtml(currentFindings, currentTarget));
        preview.setCaretPosition(0);
    }

    private static String emptyHtml() {
        return "<html><body style='font-family:sans-serif;color:#cdd6f4;background:#1e1e2e;padding:16px'>"
                + "<h2>No findings to preview</h2>" + "<p>Run a scan first, then click Generate Preview.</p>"
                + "</body></html>";
    }

    private static String buildHtml(List<Finding> findings, String target) {
        List<Finding> sorted = findings.stream().sorted(Comparator.comparingInt(f -> ORDER.indexOf(f.severity())))
                .toList();

        StringBuilder sb = new StringBuilder();
        sb.append("<html><head><style>");
        sb.append("body{font-family:sans-serif;color:#cdd6f4;background:#1e1e2e;padding:16px}");
        sb.append("h1,h2,h3{color:#89b4fa}");
        sb.append("table{border-collapse:collapse;width:100%;margin:8px 0}");
        sb.append("th,td{border:1px solid #45475a;padding:6px 8px;text-align:left}");
        sb.append("th{background:#313244}");
        sb.append(".crit{color:#f85149} .high{color:#d29922} .med{color:#e3b341}");
        sb.append(" .low{color:#58a6ff} .info{color:#8b949e}");
        sb.append("code{background:#313244;padding:2px 4px;border-radius:3px}");
        sb.append("pre{background:#313244;padding:8px;border-radius:4px;overflow-x:auto}");
        sb.append("</style></head><body>");

        sb.append("<h1>AnarCry Report</h1>");
        sb.append("<p><b>Target:</b> ").append(esc(target)).append("</p>");
        sb.append("<p><b>Total findings:</b> ").append(sorted.size()).append("</p>");

        sb.append("<h2>Summary</h2><ul>");
        for (Severity s : ORDER) {
            long count = sorted.stream().filter(f -> f.severity() == s).count();
            if (count > 0) {
                sb.append("<li><span class='").append(cssClass(s)).append("'><b>").append(s).append("</b></span>: ")
                        .append(count).append("</li>");
            }
        }
        sb.append("</ul>");

        sb.append("<h2>Findings</h2>");
        sb.append("<table><tr><th>Severity</th><th>CVSS</th><th>CWE</th>")
                .append("<th>Module</th><th>Endpoint</th><th>Title</th></tr>");
        for (Finding f : sorted) {
            sb.append("<tr>");
            sb.append("<td class='").append(cssClass(f.severity())).append("'>").append(f.severity()).append("</td>");
            sb.append("<td>").append(String.format("%.1f", f.cvssScore())).append("</td>");
            sb.append("<td>").append(esc(f.cweId())).append("</td>");
            sb.append("<td>").append(esc(f.module())).append("</td>");
            sb.append("<td>").append(esc(f.endpoint())).append("</td>");
            sb.append("<td>").append(esc(f.title())).append("</td>");
            sb.append("</tr>");
        }
        sb.append("</table>");

        sb.append("<h2>Details</h2>");
        for (Finding f : sorted) {
            sb.append("<h3><span class='").append(cssClass(f.severity())).append("'>[").append(f.severity())
                    .append("]</span> ").append(esc(f.title())).append("</h3>");
            sb.append("<p><b>Module:</b> ").append(esc(f.module())).append("</p>");
            sb.append("<p><b>Endpoint:</b> <code>").append(esc(f.endpoint())).append("</code></p>");
            sb.append("<p><b>Evidence:</b></p><pre>").append(esc(f.evidence())).append("</pre>");
            sb.append("<p><b>Impact:</b> ").append(esc(f.impact())).append("</p>");
            sb.append("<p><b>Reproduction:</b></p><pre>").append(esc(f.reproduction())).append("</pre>");
            sb.append("<p><b>Recommendation:</b> ").append(esc(f.recommendation())).append("</p>");
            sb.append("<p><b>CWE:</b> ").append(esc(f.cweId())).append(" — ").append(esc(f.cweTitle())).append("</p>");
            sb.append("<p><b>CVSS:</b> ").append(String.format("%.1f", f.cvssScore())).append(" (")
                    .append(esc(f.cvssVector())).append(")</p>");
            sb.append("<hr>");
        }

        sb.append("</body></html>");
        return sb.toString();
    }

    private static String cssClass(Severity s) {
        return switch (s) {
            case CRITICAL -> "crit";
            case HIGH -> "high";
            case MEDIUM -> "med";
            case LOW -> "low";
            case INFO -> "info";
        };
    }

    private static String esc(String s) {
        if (s == null) {
            return "";
        }
        String text = PrivacyFilter.apply(s);
        return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;");
    }
}
