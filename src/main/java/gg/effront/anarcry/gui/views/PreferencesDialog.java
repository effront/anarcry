package gg.effront.anarcry.gui.views;

import gg.effront.anarcry.gui.theme.AnarCryLaf;

import java.awt.BorderLayout;
import java.awt.FlowLayout;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JDialog;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JSpinner;
import javax.swing.SpinnerNumberModel;
import javax.swing.SwingUtilities;

/**
 * Preferences dialog for theme, scan parallelism, and timeout settings.
 */
public class PreferencesDialog extends JDialog {

    private final JComboBox<String> themeCombo;
    private final JSpinner parallelismSpinner;
    private final JSpinner timeoutSpinner;

    private int parallelism = 4;
    private int timeoutMinutes = 10;

    public PreferencesDialog(JFrame parent) {
        super(parent, "Preferences", true);
        setSize(400, 280);
        setLocationRelativeTo(parent);
        setLayout(new BorderLayout(8, 8));

        JPanel formPanel = new JPanel(new GridBagLayout());
        formPanel.setBorder(BorderFactory.createEmptyBorder(16, 16, 8, 16));
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.anchor = GridBagConstraints.WEST;
        gbc.insets = new Insets(6, 4, 6, 8);

        gbc.gridx = 0;
        gbc.gridy = 0;
        formPanel.add(new JLabel("Theme:"), gbc);

        gbc.gridx = 1;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.weightx = 1.0;
        themeCombo = new JComboBox<>(new String[]{"Dark", "Light"});
        themeCombo.setSelectedItem(AnarCryLaf.isDark() ? "Dark" : "Light");
        formPanel.add(themeCombo, gbc);

        gbc.gridx = 0;
        gbc.gridy = 1;
        gbc.fill = GridBagConstraints.NONE;
        gbc.weightx = 0;
        formPanel.add(new JLabel("Scan parallelism:"), gbc);

        gbc.gridx = 1;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.weightx = 1.0;
        parallelismSpinner = new JSpinner(new SpinnerNumberModel(parallelism, 1, 16, 1));
        formPanel.add(parallelismSpinner, gbc);

        gbc.gridx = 0;
        gbc.gridy = 2;
        gbc.fill = GridBagConstraints.NONE;
        gbc.weightx = 0;
        formPanel.add(new JLabel("Scan timeout (min):"), gbc);

        gbc.gridx = 1;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.weightx = 1.0;
        timeoutSpinner = new JSpinner(new SpinnerNumberModel(timeoutMinutes, 1, 60, 1));
        formPanel.add(timeoutSpinner, gbc);

        add(formPanel, BorderLayout.CENTER);

        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 8));
        JButton applyBtn = new JButton("Apply");
        applyBtn.addActionListener(e -> applySettings());
        buttonPanel.add(applyBtn);

        JButton cancelBtn = new JButton("Cancel");
        cancelBtn.addActionListener(e -> dispose());
        buttonPanel.add(cancelBtn);

        add(buttonPanel, BorderLayout.SOUTH);
    }

    public int getParallelism() {
        return parallelism;
    }

    public int getTimeoutMinutes() {
        return timeoutMinutes;
    }

    private void applySettings() {
        parallelism = (Integer) parallelismSpinner.getValue();
        timeoutMinutes = (Integer) timeoutSpinner.getValue();

        boolean wantDark = "Dark".equals(themeCombo.getSelectedItem());
        if (wantDark != AnarCryLaf.isDark()) {
            if (wantDark) {
                AnarCryLaf.install();
            } else {
                AnarCryLaf.installLight();
            }
            SwingUtilities.updateComponentTreeUI(getOwner());
            SwingUtilities.updateComponentTreeUI(this);
        }

        dispose();
    }
}
