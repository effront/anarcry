package gg.effront.anarcry.gui.components;

import gg.effront.anarcry.gui.PrivacyFilter;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Cursor;
import java.awt.FlowLayout;

import javax.swing.BorderFactory;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JProgressBar;
import javax.swing.JToggleButton;
import javax.swing.SwingUtilities;

/**
 * Bottom status bar displaying severity counts, module progress, current
 * target, and a privacy mode toggle on the right.
 */
public class GuiStatusBar extends JPanel {

    private static final Color COLOR_CRITICAL = new Color(0xF8, 0x51, 0x49);
    private static final Color COLOR_HIGH = new Color(0xD2, 0x99, 0x22);
    private static final Color COLOR_MEDIUM = new Color(0xE3, 0xB3, 0x41);
    private static final Color COLOR_LOW = new Color(0x58, 0xA6, 0xFF);
    private static final Color COLOR_SEPARATOR = new Color(0x8B, 0x94, 0x9E);
    private static final Color COLOR_PRIVACY_ON = new Color(0x3F, 0xB9, 0x50);

    private final JLabel criticalLabel;
    private final JLabel highLabel;
    private final JLabel mediumLabel;
    private final JLabel lowLabel;
    private final JLabel modulesLabel;
    private final JLabel targetLabel;
    private final JProgressBar progressBar;
    private final JToggleButton privacyToggle;

    private String rawTarget = "";

    public GuiStatusBar() {
        super(new BorderLayout());
        setBorder(BorderFactory.createEmptyBorder(2, 4, 2, 4));

        // -- Left panel: severity + modules + target + progress --
        JPanel left = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 2));
        left.setOpaque(false);

        criticalLabel = coloredLabel("C:0", COLOR_CRITICAL);
        highLabel = coloredLabel("H:0", COLOR_HIGH);
        mediumLabel = coloredLabel("M:0", COLOR_MEDIUM);
        lowLabel = coloredLabel("L:0", COLOR_LOW);

        JLabel sep1 = new JLabel("|");
        sep1.setForeground(COLOR_SEPARATOR);

        modulesLabel = new JLabel("Modules: 0/0");

        JLabel sep2 = new JLabel("|");
        sep2.setForeground(COLOR_SEPARATOR);

        targetLabel = new JLabel("");

        progressBar = new JProgressBar();
        progressBar.setIndeterminate(true);
        progressBar.setVisible(false);

        left.add(criticalLabel);
        left.add(highLabel);
        left.add(mediumLabel);
        left.add(lowLabel);
        left.add(sep1);
        left.add(modulesLabel);
        left.add(sep2);
        left.add(targetLabel);
        left.add(progressBar);

        // -- Right panel: privacy toggle --
        JPanel right = new JPanel(new FlowLayout(FlowLayout.RIGHT, 6, 2));
        right.setOpaque(false);

        privacyToggle = new JToggleButton("Privacy: OFF");
        privacyToggle.setFocusable(false);
        privacyToggle.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
        privacyToggle.addActionListener(e -> {
            PrivacyFilter.toggle();
            updatePrivacyLabel();
        });
        right.add(privacyToggle);

        add(left, BorderLayout.CENTER);
        add(right, BorderLayout.EAST);

        PrivacyFilter.addListener(() -> SwingUtilities.invokeLater(this::onPrivacyChanged));
    }

    /** Update severity count labels. Safe to call from any thread. */
    public void setSeverityCounts(int c, int h, int m, int l) {
        SwingUtilities.invokeLater(() -> {
            criticalLabel.setText("C:" + c);
            highLabel.setText("H:" + h);
            mediumLabel.setText("M:" + m);
            lowLabel.setText("L:" + l);
        });
    }

    /** Update module progress label. Safe to call from any thread. */
    public void setModuleProgress(int done, int total) {
        SwingUtilities.invokeLater(() -> modulesLabel.setText("Modules: " + done + "/" + total));
    }

    /** Update target label. Safe to call from any thread. */
    public void setTarget(String t) {
        rawTarget = t != null ? t : "";
        SwingUtilities.invokeLater(() -> targetLabel.setText(PrivacyFilter.apply(rawTarget)));
    }

    /**
     * Show or hide the indeterminate progress bar. Safe to call from any thread.
     */
    public void setScanning(boolean scanning) {
        SwingUtilities.invokeLater(() -> progressBar.setVisible(scanning));
    }

    /** Returns the privacy toggle button for external shortcut wiring. */
    public JToggleButton getPrivacyToggle() {
        return privacyToggle;
    }

    private void onPrivacyChanged() {
        updatePrivacyLabel();
        targetLabel.setText(PrivacyFilter.apply(rawTarget));
    }

    private void updatePrivacyLabel() {
        boolean on = PrivacyFilter.isEnabled();
        privacyToggle.setSelected(on);
        privacyToggle.setText(on ? "Privacy: ON" : "Privacy: OFF");
        if (on) {
            privacyToggle.setForeground(COLOR_PRIVACY_ON);
        } else {
            privacyToggle.setForeground(null);
        }
    }

    private static JLabel coloredLabel(String text, Color fg) {
        JLabel label = new JLabel(text);
        label.setForeground(fg);
        return label;
    }
}
