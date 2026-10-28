package gg.effront.anarcry.gui.components;

import gg.effront.anarcry.gui.PrivacyFilter;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Cursor;
import java.awt.Dimension;
import java.awt.Font;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSeparator;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.SwingConstants;
import javax.swing.SwingUtilities;

public class GuiModulesPanel extends JPanel {

    private static final int PREFERRED_WIDTH = 260;

    private static final Color COLOR_RECON = new Color(0x56, 0xD6, 0xD6);
    private static final Color COLOR_CRYPTO = new Color(0x53, 0x84, 0xB2);
    private static final Color COLOR_WEB = new Color(0xFF, 0x9E, 0x7A);
    private static final Color ACCENT = new Color(0xD8, 0x66, 0x33);
    private static final Color SECTION_LINE = new Color(0x49, 0x49, 0x49);

    private final Map<String, JCheckBox> moduleChecks = new LinkedHashMap<>();

    private final JTextField targetField;
    private final JTextArea jwtField;
    private final JTextArea jwt2Field;

    private final JButton startButton;
    private final JButton stopButton;

    private String rawTarget = "https://";
    private String rawJwt = "";
    private String rawJwt2 = "";

    private Runnable onStart = () -> {
    };
    private Runnable onStop = () -> {
    };

    public GuiModulesPanel() {
        super(new BorderLayout());
        setPreferredSize(new Dimension(PREFERRED_WIDTH, 0));
        setMinimumSize(new Dimension(PREFERRED_WIDTH, 0));
        setBorder(BorderFactory.createMatteBorder(0, 0, 0, 1, SECTION_LINE));

        // -- Scrollable module checkboxes (CENTER) --
        JPanel checksPanel = new JPanel();
        checksPanel.setLayout(new BoxLayout(checksPanel, BoxLayout.Y_AXIS));
        checksPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 6, 10));

        addSection(checksPanel, "RECON", COLOR_RECON);
        checksPanel.add(moduleCheck("Crawler", true));
        checksPanel.add(moduleCheck("Infra", false));

        checksPanel.add(Box.createVerticalStrut(12));

        addSection(checksPanel, "CRYPTO", COLOR_CRYPTO);
        checksPanel.add(moduleCheck("TLS", true));
        checksPanel.add(moduleCheck("Headers", true));
        checksPanel.add(moduleCheck("HSTS", true));
        checksPanel.add(moduleCheck("JWT", true));
        checksPanel.add(moduleCheck("PQC", true));

        checksPanel.add(Box.createVerticalStrut(12));

        addSection(checksPanel, "WEB", COLOR_WEB);
        checksPanel.add(moduleCheck("CORS", true));
        checksPanel.add(moduleCheck("OAuth", true));
        checksPanel.add(moduleCheck("OpenRedirect", true));
        checksPanel.add(moduleCheck("SSRF", true));
        checksPanel.add(moduleCheck("GraphQL", true));
        checksPanel.add(moduleCheck("CRLF", true));
        checksPanel.add(moduleCheck("XXE", true));
        checksPanel.add(moduleCheck("SSTI", true));
        checksPanel.add(moduleCheck("HostHeader", true));
        checksPanel.add(moduleCheck("Actuator", true));
        checksPanel.add(moduleCheck("MassAssign", true));
        checksPanel.add(moduleCheck("CachePoisoning", true));
        checksPanel.add(moduleCheck("ReqSmuggling", true));
        checksPanel.add(moduleCheck("IDOR", false));

        JScrollPane checksScroll = new JScrollPane(checksPanel);
        checksScroll.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
        checksScroll.setBorder(BorderFactory.createEmptyBorder());
        checksScroll.getVerticalScrollBar().setUnitIncrement(16);
        add(checksScroll, BorderLayout.CENTER);

        // -- Fixed bottom: Target, JWT, buttons (SOUTH) --
        JPanel bottom = new JPanel();
        bottom.setLayout(new BoxLayout(bottom, BoxLayout.Y_AXIS));
        bottom.setBorder(BorderFactory.createEmptyBorder(6, 10, 10, 10));

        bottom.add(separator());
        bottom.add(Box.createVerticalStrut(6));

        bottom.add(fieldLabel("Target:"));
        targetField = new JTextField("https://");
        targetField.setMaximumSize(new Dimension(Integer.MAX_VALUE, 28));
        targetField.setAlignmentX(Component.LEFT_ALIGNMENT);
        bottom.add(targetField);

        bottom.add(Box.createVerticalStrut(6));

        bottom.add(fieldLabel("JWT 1:"));
        jwtField = new JTextArea(2, 20);
        jwtField.setLineWrap(true);
        jwtField.setAlignmentX(Component.LEFT_ALIGNMENT);
        JScrollPane jwtScroll = new JScrollPane(jwtField);
        jwtScroll.setMaximumSize(new Dimension(Integer.MAX_VALUE, 44));
        jwtScroll.setAlignmentX(Component.LEFT_ALIGNMENT);
        bottom.add(jwtScroll);

        bottom.add(Box.createVerticalStrut(6));

        bottom.add(fieldLabel("JWT 2:"));
        jwt2Field = new JTextArea(2, 20);
        jwt2Field.setLineWrap(true);
        jwt2Field.setAlignmentX(Component.LEFT_ALIGNMENT);
        JScrollPane jwt2Scroll = new JScrollPane(jwt2Field);
        jwt2Scroll.setMaximumSize(new Dimension(Integer.MAX_VALUE, 44));
        jwt2Scroll.setAlignmentX(Component.LEFT_ALIGNMENT);
        bottom.add(jwt2Scroll);

        bottom.add(Box.createVerticalStrut(8));

        JPanel buttonPanel = new JPanel();
        buttonPanel.setLayout(new BoxLayout(buttonPanel, BoxLayout.X_AXIS));
        buttonPanel.setAlignmentX(Component.LEFT_ALIGNMENT);

        startButton = new JButton("Iniciar");
        startButton.setBackground(ACCENT);
        startButton.setForeground(Color.WHITE);
        startButton.setFont(startButton.getFont().deriveFont(Font.BOLD, 13f));
        startButton.setFocusPainted(false);
        startButton.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
        startButton.setPreferredSize(new Dimension(100, 32));
        startButton.addActionListener(e -> onStart.run());

        stopButton = new JButton("Parar");
        stopButton.setEnabled(false);
        stopButton.setPreferredSize(new Dimension(80, 32));
        stopButton.addActionListener(e -> onStop.run());

        buttonPanel.add(startButton);
        buttonPanel.add(Box.createHorizontalStrut(8));
        buttonPanel.add(stopButton);
        bottom.add(buttonPanel);

        add(bottom, BorderLayout.SOUTH);

        PrivacyFilter.addListener(() -> SwingUtilities.invokeLater(this::onPrivacyChanged));
    }

    // ---------------------------------------------------------------------------
    // Public API
    // ---------------------------------------------------------------------------

    public String getTarget() {
        if (!PrivacyFilter.isEnabled()) {
            rawTarget = targetField.getText();
        }
        return rawTarget.trim();
    }

    public String getJwt() {
        if (!PrivacyFilter.isEnabled()) {
            rawJwt = jwtField.getText();
        }
        return rawJwt.trim();
    }

    public String getJwt2() {
        if (!PrivacyFilter.isEnabled()) {
            rawJwt2 = jwt2Field.getText();
        }
        return rawJwt2.trim();
    }

    public Set<String> getEnabledModules() {
        Set<String> enabled = new LinkedHashSet<>();
        for (Map.Entry<String, JCheckBox> entry : moduleChecks.entrySet()) {
            if (entry.getValue().isSelected()) {
                enabled.add(entry.getKey());
            }
        }
        return enabled;
    }

    public void setTarget(String t) {
        rawTarget = t != null ? t : "";
        targetField.setText(PrivacyFilter.isEnabled() ? PrivacyFilter.apply(rawTarget) : rawTarget);
    }

    public void setJwt(String j) {
        rawJwt = j != null ? j : "";
        jwtField.setText(PrivacyFilter.isEnabled() ? PrivacyFilter.apply(rawJwt) : rawJwt);
    }

    public void setJwt2(String j) {
        rawJwt2 = j != null ? j : "";
        jwt2Field.setText(PrivacyFilter.isEnabled() ? PrivacyFilter.apply(rawJwt2) : rawJwt2);
    }

    public void setOnStart(Runnable r) {
        this.onStart = r != null ? r : () -> {
        };
    }

    public void setOnStop(Runnable r) {
        this.onStop = r != null ? r : () -> {
        };
    }

    public void setScanning(boolean scanning) {
        startButton.setEnabled(!scanning);
        stopButton.setEnabled(scanning);
    }

    private void onPrivacyChanged() {
        if (PrivacyFilter.isEnabled()) {
            rawTarget = targetField.getText();
            rawJwt = jwtField.getText();
            rawJwt2 = jwt2Field.getText();
            targetField.setText(PrivacyFilter.apply(rawTarget));
            jwtField.setText(PrivacyFilter.apply(rawJwt));
            jwt2Field.setText(PrivacyFilter.apply(rawJwt2));
            targetField.setEditable(false);
            jwtField.setEditable(false);
            jwt2Field.setEditable(false);
        } else {
            targetField.setText(rawTarget);
            jwtField.setText(rawJwt);
            jwt2Field.setText(rawJwt2);
            targetField.setEditable(true);
            jwtField.setEditable(true);
            jwt2Field.setEditable(true);
        }
    }

    // ---------------------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------------------

    private void addSection(JPanel parent, String text, Color color) {
        JLabel label = new JLabel(text);
        label.setForeground(color);
        label.setFont(label.getFont().deriveFont(Font.BOLD, 12f));
        label.setAlignmentX(Component.LEFT_ALIGNMENT);
        label.setBorder(BorderFactory.createEmptyBorder(0, 0, 2, 0));
        parent.add(label);

        JSeparator line = new JSeparator(SwingConstants.HORIZONTAL);
        line.setForeground(color.darker());
        line.setMaximumSize(new Dimension(Integer.MAX_VALUE, 1));
        line.setAlignmentX(Component.LEFT_ALIGNMENT);
        parent.add(line);

        parent.add(Box.createVerticalStrut(4));
    }

    private JCheckBox moduleCheck(String moduleId, boolean checked) {
        JCheckBox cb = new JCheckBox(moduleId, checked);
        cb.setAlignmentX(Component.LEFT_ALIGNMENT);
        cb.setBorder(BorderFactory.createEmptyBorder(1, 12, 1, 0));
        moduleChecks.put(moduleId, cb);
        return cb;
    }

    private static JLabel fieldLabel(String text) {
        JLabel label = new JLabel(text);
        label.setAlignmentX(Component.LEFT_ALIGNMENT);
        label.setFont(label.getFont().deriveFont(Font.BOLD, 12f));
        label.setBorder(BorderFactory.createEmptyBorder(0, 0, 2, 0));
        return label;
    }

    private static JSeparator separator() {
        JSeparator sep = new JSeparator(SwingConstants.HORIZONTAL);
        sep.setForeground(SECTION_LINE);
        sep.setMaximumSize(new Dimension(Integer.MAX_VALUE, 1));
        sep.setAlignmentX(Component.LEFT_ALIGNMENT);
        return sep;
    }
}
