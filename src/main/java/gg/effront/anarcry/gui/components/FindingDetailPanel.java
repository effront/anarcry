package gg.effront.anarcry.gui.components;

import gg.effront.anarcry.gui.PrivacyFilter;
import gg.effront.anarcry.model.Finding;
import gg.effront.anarcry.model.Severity;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Font;

import javax.swing.BorderFactory;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTabbedPane;
import javax.swing.JTextArea;
import javax.swing.SwingUtilities;

/**
 * Inline panel that displays finding details when a row is selected. Updates
 * via {@link #show(Finding)}.
 */
public class FindingDetailPanel extends JPanel {

    private static final Color COLOR_CRITICAL = new Color(0xF8, 0x51, 0x49);
    private static final Color COLOR_HIGH = new Color(0xD2, 0x99, 0x22);
    private static final Color COLOR_MEDIUM = new Color(0xE3, 0xB3, 0x41);
    private static final Color COLOR_LOW = new Color(0x58, 0xA6, 0xFF);
    private static final Color COLOR_INFO = new Color(0x8B, 0x94, 0x9E);

    private final JLabel headerLabel;
    private final JTextArea impactArea;
    private final JTextArea evidenceArea;
    private final JTextArea reproArea;
    private final JTextArea recommendArea;
    private final JLabel metaLabel;

    public FindingDetailPanel() {
        super(new BorderLayout(0, 4));
        setBorder(BorderFactory.createEmptyBorder(6, 8, 6, 8));

        headerLabel = new JLabel("Select a finding to view details");
        headerLabel.setFont(headerLabel.getFont().deriveFont(Font.BOLD, 14f));
        add(headerLabel, BorderLayout.NORTH);

        impactArea = monoArea();
        evidenceArea = monoArea();
        reproArea = monoArea();
        recommendArea = monoArea();

        JTabbedPane tabs = new JTabbedPane(JTabbedPane.BOTTOM);
        tabs.setFont(tabs.getFont().deriveFont(11f));
        tabs.addTab("Impact", scroll(impactArea));
        tabs.addTab("Evidence", scroll(evidenceArea));
        tabs.addTab("Reproduction", scroll(reproArea));
        tabs.addTab("Recommendation", scroll(recommendArea));
        add(tabs, BorderLayout.CENTER);

        metaLabel = new JLabel(" ");
        metaLabel.setForeground(new Color(0x8B, 0x94, 0x9E));
        metaLabel.setFont(metaLabel.getFont().deriveFont(11f));
        add(metaLabel, BorderLayout.SOUTH);
    }

    /** Display the given finding's details. Thread-safe. */
    public void show(Finding f) {
        SwingUtilities.invokeLater(() -> {
            if (f == null) {
                clear();
                return;
            }
            headerLabel.setText(f.severity().name() + " -- " + safe(f.title()));
            headerLabel.setForeground(colorFor(f.severity()));

            impactArea.setText(safe(PrivacyFilter.apply(f.impact())));
            impactArea.setCaretPosition(0);

            evidenceArea.setText(safe(PrivacyFilter.apply(f.evidence())));
            evidenceArea.setCaretPosition(0);

            reproArea.setText(safe(PrivacyFilter.apply(f.reproduction())));
            reproArea.setCaretPosition(0);

            recommendArea.setText(safe(PrivacyFilter.apply(f.recommendation())));
            recommendArea.setCaretPosition(0);

            String endpoint = PrivacyFilter.apply(f.endpoint());
            metaLabel.setText(String.format("[%s] %s | CVSS %.1f | %s -- %s | %s", f.module(), safe(endpoint),
                    f.cvssScore(), f.cweId(), safe(f.cweTitle()), safe(f.cvssVector())));
        });
    }

    /** Clear all fields. */
    public void clear() {
        SwingUtilities.invokeLater(() -> {
            headerLabel.setText("Select a finding to view details");
            headerLabel.setForeground(null);
            impactArea.setText("");
            evidenceArea.setText("");
            reproArea.setText("");
            recommendArea.setText("");
            metaLabel.setText(" ");
        });
    }

    private static String safe(String s) {
        return s != null && !s.isBlank() ? s : "(no data)";
    }

    private static JTextArea monoArea() {
        JTextArea area = new JTextArea();
        area.setEditable(false);
        area.setLineWrap(true);
        area.setWrapStyleWord(true);
        area.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        area.setBorder(BorderFactory.createEmptyBorder(4, 6, 4, 6));
        return area;
    }

    private static JScrollPane scroll(JTextArea area) {
        JScrollPane sp = new JScrollPane(area);
        sp.setBorder(BorderFactory.createEmptyBorder());
        return sp;
    }

    private static Color colorFor(Severity sev) {
        return switch (sev) {
            case CRITICAL -> COLOR_CRITICAL;
            case HIGH -> COLOR_HIGH;
            case MEDIUM -> COLOR_MEDIUM;
            case LOW -> COLOR_LOW;
            case INFO -> COLOR_INFO;
        };
    }
}
