package gg.effront.anarcry.gui.components;

import gg.effront.anarcry.gui.PrivacyFilter;
import gg.effront.anarcry.model.AuthType;
import gg.effront.anarcry.scanner.util.TargetUtil;

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
import javax.swing.JComponent;
import javax.swing.JComboBox;
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
    private static Color sectionLine() {
        return gg.effront.anarcry.gui.theme.AnarCryLaf.sectionLine();
    }

    private final Map<String, JCheckBox> moduleChecks = new LinkedHashMap<>();

    private final JTextField targetField;
    private final JComboBox<AuthType> authTypeCombo;
    private final JLabel cred1Label;
    private final JLabel cred2Label;
    private final JTextArea jwtField;
    private final JTextArea jwt2Field;
    private final JScrollPane cred1Scroll;
    private final JScrollPane cred2Scroll;
    private final Component cred1Strut;
    private final Component cred2Strut;

    private final JCheckBox exploitationCheck;
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
        setBorder(BorderFactory.createMatteBorder(0, 0, 0, 1, sectionLine()));

        // -- Scrollable module checkboxes (CENTER) --
        JPanel checksPanel = new JPanel();
        checksPanel.setLayout(new BoxLayout(checksPanel, BoxLayout.Y_AXIS));
        checksPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 6, 10));

        JLabel selectLabel = new JLabel("Select modules:");
        selectLabel.setFont(selectLabel.getFont().deriveFont(Font.BOLD, 11f));
        selectLabel.setAlignmentX(Component.LEFT_ALIGNMENT);
        selectLabel.setBorder(BorderFactory.createEmptyBorder(0, 0, 4, 0));
        checksPanel.add(selectLabel);

        JPanel togglePanel = new JPanel();
        togglePanel.setLayout(new BoxLayout(togglePanel, BoxLayout.X_AXIS));
        togglePanel.setAlignmentX(Component.LEFT_ALIGNMENT);
        togglePanel.setOpaque(false);
        JButton allBtn = smallToggle("all");
        allBtn.addActionListener(e -> moduleChecks.values().forEach(cb -> cb.setSelected(true)));
        JButton noneBtn = smallToggle("none");
        noneBtn.addActionListener(e -> moduleChecks.values().forEach(cb -> cb.setSelected(false)));
        JButton passiveBtn = smallToggle("passive");
        passiveBtn.addActionListener(e -> {
            Set<String> passive = Set.of("Crawler", "TLS", "Headers", "HSTS", "CORS");
            moduleChecks.forEach((id, cb) -> cb.setSelected(passive.contains(id)));
        });
        JButton reconBtn = smallToggle("recon");
        reconBtn.addActionListener(e -> {
            Set<String> recon = Set.of("Crawler", "TLS", "Headers", "HSTS", "CORS", "Secrets", "FrameworkConfig",
                    "JsAnalyzer", "DomSinks", "BackendLiveness", "Clickjacking", "SubTakeover");
            moduleChecks.forEach((id, cb) -> cb.setSelected(recon.contains(id)));
        });
        togglePanel.add(allBtn);
        togglePanel.add(smallSep());
        togglePanel.add(noneBtn);
        togglePanel.add(smallSep());
        togglePanel.add(passiveBtn);
        togglePanel.add(smallSep());
        togglePanel.add(reconBtn);
        checksPanel.add(togglePanel);
        checksPanel.add(Box.createVerticalStrut(8));

        addSection(checksPanel, "RECON", COLOR_RECON);
        checksPanel.add(moduleCheck("Crawler", true));
        checksPanel.add(moduleCheck("Infra", false, "Port scan -- slow and noisy, enable manually"));
        checksPanel.add(moduleCheck("BackendLiveness", false, "Detects dangling/dead backend URLs"));
        checksPanel.add(moduleCheck("Clickjacking", false, "Checks frame protection headers across pages"));

        checksPanel.add(Box.createVerticalStrut(12));

        addSection(checksPanel, "CRYPTO", COLOR_CRYPTO);
        checksPanel.add(moduleCheck("TLS", true));
        checksPanel.add(moduleCheck("Headers", true));
        checksPanel.add(moduleCheck("HSTS", true));
        checksPanel.add(moduleCheck("JWT", false));
        checksPanel.add(moduleCheck("PQC", false));

        checksPanel.add(Box.createVerticalStrut(12));

        addSection(checksPanel, "WEB", COLOR_WEB);
        checksPanel.add(moduleCheck("CORS", true));
        checksPanel.add(moduleCheck("OAuth", false));
        checksPanel.add(moduleCheck("OpenRedirect", false));
        checksPanel.add(moduleCheck("SSRF", false));
        checksPanel.add(moduleCheck("GraphQL", false));
        checksPanel.add(moduleCheck("CRLF", false));
        checksPanel.add(moduleCheck("XXE", false));
        checksPanel.add(moduleCheck("SSTI", false));
        checksPanel.add(moduleCheck("HostHeader", false));
        checksPanel.add(moduleCheck("Actuator", false));
        checksPanel.add(moduleCheck("MassAssign", false));
        checksPanel.add(moduleCheck("CachePoisoning", false));
        checksPanel.add(moduleCheck("ReqSmuggling", false));
        checksPanel.add(moduleCheck("SQLi", false));
        checksPanel.add(moduleCheck("XSS", false));
        checksPanel.add(moduleCheck("LFI", false));
        checksPanel.add(moduleCheck("CmdInjection", false));
        checksPanel.add(moduleCheck("CSRF", false));
        checksPanel.add(moduleCheck("Secrets", false));
        checksPanel.add(moduleCheck("RaceCondition", false,
                "Sends concurrent requests that may alter target state (payments, coupons)"));
        checksPanel.add(moduleCheck("NoSQLi", false));
        checksPanel.add(moduleCheck("Deserialization", false));
        checksPanel
                .add(moduleCheck("FileUpload", false, "Uploads test files to the target -- potentially destructive"));
        checksPanel.add(moduleCheck("SubTakeover", false));
        checksPanel.add(moduleCheck("WebSocket", false));
        checksPanel.add(moduleCheck("ProtoPollution", false));
        checksPanel.add(moduleCheck("CloudMisconfig", false));
        checksPanel.add(moduleCheck("FrameworkConfig", false, "Extracts framework config (Nuxt/Next) from JS bundles"));
        checksPanel.add(moduleCheck("JsAnalyzer", false, "Extracts API endpoints from JS fetch/axios calls"));
        checksPanel
                .add(moduleCheck("DomSinks", false, "Detects dangerous DOM sinks (innerHTML, eval, document.write)"));
        checksPanel.add(moduleCheck("IDOR", false, "Requires two auth tokens (JWT Token 2) for cross-user testing"));
        moduleChecks.get("IDOR").addActionListener(e -> updateCredentialFields());

        checksPanel.add(Box.createVerticalStrut(12));

        addSection(checksPanel, "POST-SCAN", new Color(0xBB, 0x6B, 0xD9));
        exploitationCheck = new JCheckBox("<html>Exploitation<br>(validate findings)</html>", false);
        exploitationCheck.setAlignmentX(Component.LEFT_ALIGNMENT);
        exploitationCheck.setBorder(BorderFactory.createEmptyBorder(1, 12, 1, 0));
        checksPanel.add(exploitationCheck);

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

        bottom.add(fieldLabel("Auth Type:"));
        authTypeCombo = new JComboBox<>(AuthType.values());
        authTypeCombo.setSelectedItem(AuthType.NONE);
        authTypeCombo.setMaximumSize(new Dimension(Integer.MAX_VALUE, 28));
        authTypeCombo.setAlignmentX(Component.LEFT_ALIGNMENT);
        bottom.add(authTypeCombo);

        cred1Strut = Box.createVerticalStrut(6);
        bottom.add(cred1Strut);

        cred1Label = fieldLabel("Credential 1:");
        bottom.add(cred1Label);
        jwtField = new JTextArea(2, 20);
        jwtField.setLineWrap(true);
        jwtField.setAlignmentX(Component.LEFT_ALIGNMENT);
        cred1Scroll = new JScrollPane(jwtField);
        cred1Scroll.setMaximumSize(new Dimension(Integer.MAX_VALUE, 44));
        cred1Scroll.setAlignmentX(Component.LEFT_ALIGNMENT);
        bottom.add(cred1Scroll);

        cred2Strut = Box.createVerticalStrut(6);
        bottom.add(cred2Strut);

        cred2Label = fieldLabel("Credential 2:");
        bottom.add(cred2Label);
        jwt2Field = new JTextArea(2, 20);
        jwt2Field.setLineWrap(true);
        jwt2Field.setAlignmentX(Component.LEFT_ALIGNMENT);
        cred2Scroll = new JScrollPane(jwt2Field);
        cred2Scroll.setMaximumSize(new Dimension(Integer.MAX_VALUE, 44));
        cred2Scroll.setAlignmentX(Component.LEFT_ALIGNMENT);
        bottom.add(cred2Scroll);

        authTypeCombo.addActionListener(e -> updateCredentialFields());
        updateCredentialFields();

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
        stopButton.setFont(stopButton.getFont().deriveFont(Font.BOLD, 13f));
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
        return TargetUtil.sanitizeTarget(rawTarget);
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

    public AuthType getAuthType() {
        return (AuthType) authTypeCombo.getSelectedItem();
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
        if (!rawJwt.isEmpty() && getAuthType() == AuthType.NONE) {
            authTypeCombo.setSelectedItem(AuthType.JWT);
        }
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

    public boolean isExploitationEnabled() {
        return exploitationCheck.isSelected();
    }

    private void updateCredentialFields() {
        AuthType selected = getAuthType();
        boolean showCred1 = selected.hasAuth();

        boolean idorAllowed = selected == AuthType.JWT || selected == AuthType.AUTO;
        JCheckBox idorCb = moduleChecks.get("IDOR");
        if (idorCb != null) {
            idorCb.setEnabled(idorAllowed);
            if (!idorAllowed && idorCb.isSelected()) {
                idorCb.setSelected(false);
            }
        }

        boolean idorEnabled = idorCb != null && idorCb.isSelected();
        boolean showCred2 = (selected == AuthType.JWT && idorEnabled) || selected == AuthType.AUTO;

        cred1Label.setVisible(showCred1);
        cred1Scroll.setVisible(showCred1);
        cred1Strut.setVisible(showCred1);
        cred2Label.setVisible(showCred2);
        cred2Scroll.setVisible(showCred2);
        cred2Strut.setVisible(showCred2);

        switch (selected) {
            case NONE -> {
                cred1Label.setText("Credential 1:");
                cred2Label.setText("Credential 2:");
            }
            case JWT -> {
                cred1Label.setText("JWT Token:");
                cred2Label.setText("JWT Token 2 (IDOR):");
            }
            case COOKIE -> {
                cred1Label.setText("Session Cookie:");
                cred2Label.setText("Credential 2:");
            }
            case BEARER -> {
                cred1Label.setText("Bearer Token:");
                cred2Label.setText("Credential 2:");
            }
            case AUTO -> {
                cred1Label.setText("Email (or Refresh Token):");
                cred2Label.setText("Password (blank if token):");
            }
        }

        revalidate();
        repaint();
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

    private JComponent moduleCheck(String moduleId, boolean checked) {
        return moduleCheck(moduleId, checked, null);
    }

    private JComponent moduleCheck(String moduleId, boolean checked, String tooltip) {
        JCheckBox cb = new JCheckBox(moduleId, checked);
        cb.setBorder(BorderFactory.createEmptyBorder(1, 12, 1, 0));
        moduleChecks.put(moduleId, cb);
        if (tooltip == null) {
            cb.setAlignmentX(Component.LEFT_ALIGNMENT);
            return cb;
        }
        JPanel row = new JPanel();
        row.setLayout(new BoxLayout(row, BoxLayout.X_AXIS));
        row.setAlignmentX(Component.LEFT_ALIGNMENT);
        row.setOpaque(false);
        row.add(cb);
        row.add(Box.createHorizontalStrut(2));
        JLabel info = new JLabel("i");
        info.setFont(info.getFont().deriveFont(Font.BOLD | Font.ITALIC, 9f));
        info.setForeground(new Color(0x77, 0x99, 0xBB));
        info.setBorder(
                BorderFactory.createCompoundBorder(BorderFactory.createLineBorder(new Color(0x77, 0x99, 0xBB), 1),
                        BorderFactory.createEmptyBorder(0, 3, 0, 3)));
        info.setToolTipText(tooltip);
        info.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
        row.add(info);
        return row;
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
        sep.setForeground(sectionLine());
        sep.setMaximumSize(new Dimension(Integer.MAX_VALUE, 1));
        sep.setAlignmentX(Component.LEFT_ALIGNMENT);
        return sep;
    }

    private static JButton smallToggle(String text) {
        JButton btn = new JButton(text);
        btn.setFont(btn.getFont().deriveFont(Font.PLAIN, 10f));
        btn.setMargin(new java.awt.Insets(1, 4, 1, 4));
        btn.setFocusPainted(false);
        btn.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
        return btn;
    }

    private static JLabel smallSep() {
        JLabel sep = new JLabel("|");
        sep.setForeground(new Color(0x66, 0x66, 0x66));
        sep.setFont(sep.getFont().deriveFont(9f));
        sep.setBorder(BorderFactory.createEmptyBorder(0, 2, 0, 2));
        return sep;
    }
}
