package gg.effront.anarcry.gui.views;

import gg.effront.anarcry.model.Finding;
import gg.effront.anarcry.model.Severity;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.Toolkit;
import java.awt.datatransfer.StringSelection;

import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JDialog;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTabbedPane;
import javax.swing.JTextArea;

public class FindingDetailDialog extends JDialog {

    private static final int DIALOG_WIDTH = 880;
    private static final int DIALOG_HEIGHT = 640;

    private static final Color COLOR_CRITICAL = new Color(0xF3, 0x2A, 0x4C);
    private static final Color COLOR_HIGH = new Color(0xFF, 0x66, 0x33);
    private static final Color COLOR_MEDIUM = new Color(0xDB, 0xA0, 0x2F);
    private static final Color COLOR_LOW = new Color(0x00, 0x94, 0xFF);
    private static final Color COLOR_INFO = new Color(0x7E, 0x89, 0x93);

    public FindingDetailDialog(JFrame parent, Finding finding) {
        super(parent, finding.severity().name() + " -- " + finding.title(), true);
        setMinimumSize(new Dimension(DIALOG_WIDTH, DIALOG_HEIGHT));
        setSize(DIALOG_WIDTH, DIALOG_HEIGHT);
        setLocationRelativeTo(parent);
        setLayout(new BorderLayout());

        JTabbedPane tabs = new JTabbedPane();
        tabs.addTab("Overview", buildOverviewTab(finding));
        tabs.addTab("Evidence", buildMonoTab(finding.evidence()));
        tabs.addTab("Reproduction", buildMonoTab(finding.reproduction()));
        add(tabs, BorderLayout.CENTER);

        add(buildButtonPanel(finding), BorderLayout.SOUTH);
    }

    private JScrollPane buildOverviewTab(Finding f) {
        JPanel panel = new JPanel();
        panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));
        panel.setBorder(BorderFactory.createEmptyBorder(16, 20, 16, 20));

        JPanel headerRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 12, 0));
        headerRow.setAlignmentX(JPanel.LEFT_ALIGNMENT);
        headerRow.setMaximumSize(new Dimension(Integer.MAX_VALUE, 36));

        JLabel sevLabel = new JLabel(f.severity().name());
        sevLabel.setForeground(colorFor(f.severity()));
        sevLabel.setFont(sevLabel.getFont().deriveFont(Font.BOLD, 20f));
        headerRow.add(sevLabel);

        JLabel cvssLabel = new JLabel("CVSS " + String.format("%.1f", f.cvssScore()));
        cvssLabel.setFont(cvssLabel.getFont().deriveFont(Font.BOLD, 16f));
        headerRow.add(cvssLabel);

        JLabel vectorLabel = new JLabel("(" + safe(f.cvssVector()) + ")");
        vectorLabel.setForeground(new Color(0x8B, 0x94, 0x9E));
        headerRow.add(vectorLabel);

        panel.add(headerRow);
        panel.add(Box.createVerticalStrut(12));

        JPanel formPanel = new JPanel(new GridBagLayout());
        formPanel.setAlignmentX(JPanel.LEFT_ALIGNMENT);
        GridBagConstraints lc = new GridBagConstraints();
        lc.anchor = GridBagConstraints.NORTHWEST;
        lc.insets = new Insets(4, 0, 4, 12);
        lc.gridx = 0;
        lc.fill = GridBagConstraints.NONE;
        lc.weightx = 0;

        GridBagConstraints vc = new GridBagConstraints();
        vc.anchor = GridBagConstraints.NORTHWEST;
        vc.insets = new Insets(4, 0, 4, 0);
        vc.gridx = 1;
        vc.fill = GridBagConstraints.HORIZONTAL;
        vc.weightx = 1.0;

        int row = 0;
        addField(formPanel, lc, vc, row++, "Title", f.title(), false);
        addField(formPanel, lc, vc, row++, "Module", f.module(), false);
        addField(formPanel, lc, vc, row++, "Endpoint", f.endpoint(), false);
        addField(formPanel, lc, vc, row++, "CWE", f.cweId() + " -- " + f.cweTitle(), false);
        addField(formPanel, lc, vc, row++, "Impact", f.impact(), true);
        addField(formPanel, lc, vc, row++, "Recommendation", f.recommendation(), true);

        GridBagConstraints filler = new GridBagConstraints();
        filler.gridx = 0;
        filler.gridy = row;
        filler.weighty = 1.0;
        filler.fill = GridBagConstraints.VERTICAL;
        formPanel.add(Box.createGlue(), filler);

        panel.add(formPanel);

        JScrollPane scroll = new JScrollPane(panel);
        scroll.setBorder(BorderFactory.createEmptyBorder());
        scroll.getVerticalScrollBar().setUnitIncrement(16);
        return scroll;
    }

    private void addField(JPanel form, GridBagConstraints lc, GridBagConstraints vc, int row, String label,
            String value, boolean multiLine) {
        lc.gridy = row;
        JLabel keyLabel = new JLabel(label + ":");
        keyLabel.setFont(keyLabel.getFont().deriveFont(Font.BOLD, 13f));
        form.add(keyLabel, lc);

        vc.gridy = row;
        if (multiLine) {
            JTextArea area = new JTextArea(safe(value));
            area.setEditable(false);
            area.setLineWrap(true);
            area.setWrapStyleWord(true);
            area.setOpaque(false);
            area.setFont(area.getFont().deriveFont(13f));
            area.setBorder(BorderFactory.createEmptyBorder());
            area.setRows(3);
            form.add(area, vc);
        } else {
            JLabel valLabel = new JLabel(safe(value));
            valLabel.setFont(valLabel.getFont().deriveFont(13f));
            form.add(valLabel, vc);
        }
    }

    private JScrollPane buildMonoTab(String text) {
        JTextArea area = new JTextArea(text != null ? text : "(no data)");
        area.setEditable(false);
        area.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 13));
        area.setLineWrap(true);
        area.setWrapStyleWord(true);
        area.setCaretPosition(0);
        area.setBorder(BorderFactory.createEmptyBorder(12, 12, 12, 12));
        JScrollPane sp = new JScrollPane(area);
        sp.setBorder(BorderFactory.createEmptyBorder());
        return sp;
    }

    private JPanel buildButtonPanel(Finding f) {
        JPanel panel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 8));

        JButton copyCurl = new JButton("Copy cURL");
        copyCurl.addActionListener(e -> {
            String curl = buildCurl(f);
            Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(curl), null);
            copyCurl.setText("Copied!");
            javax.swing.Timer t = new javax.swing.Timer(1500, ev -> copyCurl.setText("Copy cURL"));
            t.setRepeats(false);
            t.start();
        });
        panel.add(copyCurl);

        JButton close = new JButton("Close");
        close.addActionListener(e -> dispose());
        panel.add(close);

        return panel;
    }

    private static String buildCurl(Finding f) {
        String endpoint = f.endpoint();
        if (endpoint == null || endpoint.isBlank() || "/".equals(endpoint)) {
            return "curl -v '<target-url>'";
        }
        return "curl -v '" + endpoint.replace("'", "'\\''") + "'";
    }

    private static String safe(String s) {
        return s != null && !s.isBlank() ? s : "(no data)";
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
