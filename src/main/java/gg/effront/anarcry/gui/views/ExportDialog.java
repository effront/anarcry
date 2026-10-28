package gg.effront.anarcry.gui.views;

import gg.effront.anarcry.model.Finding;
import gg.effront.anarcry.report.ReportEngine;

import java.awt.BorderLayout;
import java.awt.FlowLayout;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.util.List;

import javax.swing.BorderFactory;
import javax.swing.ButtonGroup;
import javax.swing.JButton;
import javax.swing.JDialog;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JRadioButton;
import javax.swing.JTextField;

/**
 * Modal export dialog supporting Markdown+JSON, HackerOne, and Bugcrowd
 * formats. Delegates to {@link ReportEngine} for file generation.
 */
public class ExportDialog extends JDialog {

    private final List<Finding> findings;
    private final String targetUrl;

    private final JRadioButton mdRadio;
    private final JRadioButton h1Radio;
    private final JRadioButton bugcrowdRadio;
    private final JTextField programField;
    private final JLabel programLabel;

    public ExportDialog(JFrame parent, List<Finding> findings, String targetUrl) {
        super(parent, "Export Report", true);
        this.findings = findings;
        this.targetUrl = targetUrl;

        setSize(500, 320);
        setLocationRelativeTo(parent);
        setLayout(new BorderLayout(8, 8));

        JPanel formPanel = new JPanel(new GridBagLayout());
        formPanel.setBorder(BorderFactory.createEmptyBorder(12, 12, 4, 12));
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.anchor = GridBagConstraints.WEST;
        gbc.insets = new Insets(4, 4, 4, 4);
        gbc.gridx = 0;
        gbc.gridy = 0;

        formPanel.add(new JLabel("Format:"), gbc);

        gbc.gridy++;
        mdRadio = new JRadioButton("Markdown + JSON", true);
        formPanel.add(mdRadio, gbc);

        gbc.gridy++;
        h1Radio = new JRadioButton("HackerOne");
        formPanel.add(h1Radio, gbc);

        gbc.gridy++;
        bugcrowdRadio = new JRadioButton("Bugcrowd");
        formPanel.add(bugcrowdRadio, gbc);

        ButtonGroup group = new ButtonGroup();
        group.add(mdRadio);
        group.add(h1Radio);
        group.add(bugcrowdRadio);

        gbc.gridy++;
        gbc.insets = new Insets(12, 4, 4, 4);
        programLabel = new JLabel("Program name (H1):");
        programLabel.setEnabled(false);
        formPanel.add(programLabel, gbc);

        gbc.gridy++;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.weightx = 1.0;
        gbc.insets = new Insets(2, 4, 4, 4);
        programField = new JTextField(30);
        programField.setEnabled(false);
        formPanel.add(programField, gbc);

        h1Radio.addActionListener(e -> toggleProgramField());
        mdRadio.addActionListener(e -> toggleProgramField());
        bugcrowdRadio.addActionListener(e -> toggleProgramField());

        add(formPanel, BorderLayout.CENTER);

        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 8));
        JButton exportBtn = new JButton("Export");
        exportBtn.addActionListener(e -> doExport());
        buttonPanel.add(exportBtn);

        JButton cancelBtn = new JButton("Cancel");
        cancelBtn.addActionListener(e -> dispose());
        buttonPanel.add(cancelBtn);

        add(buttonPanel, BorderLayout.SOUTH);
    }

    private void toggleProgramField() {
        boolean h1 = h1Radio.isSelected();
        programLabel.setEnabled(h1);
        programField.setEnabled(h1);
    }

    private void doExport() {
        if (findings.isEmpty()) {
            JOptionPane.showMessageDialog(this, "No findings to export.", "Export", JOptionPane.WARNING_MESSAGE);
            return;
        }

        try {
            ReportEngine engine = new ReportEngine();
            String path;

            if (h1Radio.isSelected()) {
                String program = programField.getText().trim();
                if (program.isEmpty()) {
                    program = "AnarCry Scan";
                }
                path = engine.exportH1(findings, targetUrl, program);
            } else if (bugcrowdRadio.isSelected()) {
                path = engine.exportBugcrowd(findings, targetUrl);
            } else {
                path = engine.export(findings, targetUrl);
            }

            JOptionPane.showMessageDialog(this, "Report exported to:\n" + path, "Export Successful",
                    JOptionPane.INFORMATION_MESSAGE);
            dispose();
        } catch (Exception ex) {
            JOptionPane.showMessageDialog(this, "Export failed:\n" + ex.getMessage(), "Export Error",
                    JOptionPane.ERROR_MESSAGE);
        }
    }
}
