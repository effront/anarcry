package gg.effront.anarcry.gui.components;

import gg.effront.anarcry.gui.PrivacyFilter;
import gg.effront.anarcry.gui.theme.AnarCryLaf;
import gg.effront.anarcry.model.AuthType;
import gg.effront.anarcry.scanner.util.TargetUtil;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Cursor;
import java.awt.Dimension;
import java.awt.Font;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
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

    private record ColoredComponent(JComponent component, Color color) {
    }

    private final List<ColoredComponent> coloredComponents = new ArrayList<>();
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
        JButton allBtn = smallToggle("all", "Select all modules");
        allBtn.addActionListener(e -> moduleChecks.values().forEach(cb -> cb.setSelected(true)));
        JButton noneBtn = smallToggle("none", "Deselect all modules");
        noneBtn.addActionListener(e -> moduleChecks.values().forEach(cb -> cb.setSelected(false)));
        JButton passiveBtn = smallToggle("passive", "Safe checks only -- no active probing (Headers, TLS, HSTS, CORS)");
        passiveBtn.addActionListener(e -> {
            Set<String> passive = Set.of("Crawler", "TLS", "Headers", "HSTS", "CORS");
            moduleChecks.forEach((id, cb) -> cb.setSelected(passive.contains(id)));
        });
        JButton reconBtn = smallToggle("recon",
                "Reconnaissance -- discovery and fingerprinting without active exploitation");
        reconBtn.addActionListener(e -> {
            Set<String> recon = Set.of("Crawler", "TLS", "Headers", "HSTS", "CORS", "Secrets", "FrameworkConfig",
                    "JsAnalyzer", "DomSinks", "BackendLiveness", "Clickjacking", "SubTakeover");
            moduleChecks.forEach((id, cb) -> cb.setSelected(recon.contains(id)));
        });
        JButton injectBtn = smallToggle("inject",
                "Injection attacks -- SQLi, XSS, SSTI, LFI, command injection, XXE, deserialization");
        injectBtn.addActionListener(e -> {
            Set<String> inject = Set.of("Crawler", "SQLi", "NoSQLi", "XSS", "SSTI", "LFI", "CmdInjection", "XXE",
                    "CRLF", "Deserialization", "ProtoPollution");
            moduleChecks.forEach((id, cb) -> cb.setSelected(inject.contains(id)));
        });
        JButton apiBtn = smallToggle("api",
                "API security -- auth bypass, GraphQL, OAuth, IDOR, mass assignment, rate limiting");
        apiBtn.addActionListener(e -> {
            Set<String> api = Set.of("Crawler", "GraphQL", "CORS", "JWT", "OAuth", "IDOR", "MassAssign", "RateLimit",
                    "SSRF", "Secrets", "ErrorDisclosure", "Clerk");
            moduleChecks.forEach((id, cb) -> cb.setSelected(api.contains(id)));
        });
        JButton infraBtn = smallToggle("infra",
                "Infrastructure -- TLS, headers, cloud misconfig, exposed services, subdomain takeover");
        infraBtn.addActionListener(e -> {
            Set<String> infra = Set.of("Crawler", "TLS", "Headers", "HSTS", "PQC", "Actuator", "HostHeader",
                    "CloudMisconfig", "FrameworkConfig", "EmailSec", "SubTakeover", "Infra");
            moduleChecks.forEach((id, cb) -> cb.setSelected(infra.contains(id)));
        });
        JButton owaspBtn = smallToggle("owasp", "OWASP Top 10 -- A01 to A10 coverage for compliance reports");
        owaspBtn.addActionListener(e -> {
            Set<String> owasp = Set.of("Crawler", "SQLi", "XSS", "SSRF", "XXE", "CmdInjection", "SSTI", "CORS", "JWT",
                    "OAuth", "IDOR", "CSRF", "Headers", "HSTS", "Actuator", "MassAssign", "Deserialization");
            moduleChecks.forEach((id, cb) -> cb.setSelected(owasp.contains(id)));
        });
        togglePanel.add(allBtn);
        togglePanel.add(smallSep());
        togglePanel.add(noneBtn);
        togglePanel.add(smallSep());
        togglePanel.add(passiveBtn);
        togglePanel.add(smallSep());
        togglePanel.add(reconBtn);
        checksPanel.add(togglePanel);

        JPanel togglePanel2 = new JPanel();
        togglePanel2.setLayout(new BoxLayout(togglePanel2, BoxLayout.X_AXIS));
        togglePanel2.setAlignmentX(Component.LEFT_ALIGNMENT);
        togglePanel2.setOpaque(false);
        togglePanel2.add(injectBtn);
        togglePanel2.add(smallSep());
        togglePanel2.add(apiBtn);
        togglePanel2.add(smallSep());
        togglePanel2.add(infraBtn);
        togglePanel2.add(smallSep());
        togglePanel2.add(owaspBtn);
        checksPanel.add(togglePanel2);
        checksPanel.add(Box.createVerticalStrut(8));

        addSection(checksPanel, "RECON", COLOR_RECON);
        checksPanel.add(moduleCheck("Crawler", true, "Crawls the target discovering pages, forms, and endpoints"));
        checksPanel.add(moduleCheck("Infra", false, "Port scan for open services (DB, FTP, SSH, Redis)",
                "Slow and noisy -- enable manually"));
        checksPanel.add(moduleCheck("BackendLiveness", false, "Detects dangling or dead backend URLs"));
        checksPanel.add(moduleCheck("Clickjacking", false, "Checks frame protection headers across pages"));

        checksPanel.add(Box.createVerticalStrut(12));

        addSection(checksPanel, "CRYPTO", COLOR_CRYPTO);
        checksPanel.add(moduleCheck("TLS", true, "Checks TLS version, cipher suites, and certificate validity"));
        checksPanel.add(moduleCheck("Headers", true, "Checks for missing security headers (CSP, X-Frame-Options)"));
        checksPanel.add(moduleCheck("HSTS", true, "Checks HTTP Strict Transport Security enforcement"));
        checksPanel.add(moduleCheck("JWT", false, "Tests JWT attacks (alg:none, key confusion, JKU injection)"));
        checksPanel.add(moduleCheck("PQC", false, "Assesses post-quantum cryptography readiness"));

        checksPanel.add(Box.createVerticalStrut(12));

        addSection(checksPanel, "INJECTION", COLOR_WEB);
        checksPanel.add(moduleCheck("SQLi", false, "Tests for SQL injection (error-based, blind, time-based)"));
        checksPanel.add(moduleCheck("NoSQLi", false, "Tests for NoSQL injection (MongoDB operators, JSON)"));
        checksPanel.add(moduleCheck("XSS", false, "Tests for cross-site scripting (reflected, stored, DOM)"));
        checksPanel.add(moduleCheck("SSTI", false, "Tests for server-side template injection (Jinja2, Twig)"));
        checksPanel.add(moduleCheck("CmdInjection", false, "Tests for OS command injection via user input"));
        checksPanel.add(moduleCheck("CRLF", false, "Tests for CRLF injection in HTTP headers"));
        checksPanel.add(moduleCheck("XXE", false, "Tests for XML external entity injection"));
        checksPanel.add(moduleCheck("LFI", false, "Tests for local file inclusion and path traversal"));

        checksPanel.add(Box.createVerticalStrut(12));

        addSection(checksPanel, "AUTH & ACCESS", new Color(0xE0, 0x7A, 0xA0));
        checksPanel.add(moduleCheck("OAuth", false, "Tests OAuth/OpenID Connect misconfigurations"));
        checksPanel.add(moduleCheck("IDOR", false, "Tests for insecure direct object reference (access control bypass)",
                "Requires two auth tokens (JWT Token 2) for cross-user testing"));
        moduleChecks.get("IDOR").addActionListener(e -> updateCredentialFields());
        checksPanel.add(moduleCheck("CSRF", false, "Tests for missing cross-site request forgery protections"));
        checksPanel.add(moduleCheck("MassAssign", false, "Tests for mass assignment vulnerabilities in APIs"));
        checksPanel.add(moduleCheck("RateLimit", false, "Tests for missing rate limiting on auth endpoints"));
        checksPanel.add(moduleCheck("Clerk", false, "Detects Clerk auth misconfig (dev keys, user enum)"));

        checksPanel.add(Box.createVerticalStrut(12));

        addSection(checksPanel, "HTTP & TRANSPORT", new Color(0x7A, 0xB8, 0xE0));
        checksPanel.add(moduleCheck("CORS", true, "Tests for permissive cross-origin resource sharing policies"));
        checksPanel.add(moduleCheck("HostHeader", false, "Tests for host header injection attacks"));
        checksPanel.add(moduleCheck("CachePoisoning", false, "Tests for web cache poisoning via unkeyed headers"));
        checksPanel.add(moduleCheck("ReqSmuggling", false, "Tests for HTTP request smuggling (CL.TE, TE.CL)"));
        checksPanel.add(moduleCheck("OpenRedirect", false, "Tests for open redirect vulnerabilities"));
        checksPanel.add(moduleCheck("SSRF", false, "Tests for server-side request forgery"));
        checksPanel.add(moduleCheck("GraphQL", false, "Tests GraphQL introspection and query abuse"));
        checksPanel.add(moduleCheck("WebSocket", false, "Tests WebSocket security (origin, auth, injection)"));

        checksPanel.add(Box.createVerticalStrut(12));

        addSection(checksPanel, "CONFIG & EXPOSURE", new Color(0xA0, 0xD0, 0x80));
        checksPanel.add(moduleCheck("Secrets", false, "Scans for exposed API keys, tokens, and credentials"));
        checksPanel.add(moduleCheck("FrameworkConfig", false, "Extracts framework config (Nuxt/Next) from JS bundles"));
        checksPanel.add(moduleCheck("JsAnalyzer", false, "Extracts API endpoints from JS fetch/axios calls"));
        checksPanel
                .add(moduleCheck("DomSinks", false, "Detects dangerous DOM sinks (innerHTML, eval, document.write)"));
        checksPanel.add(moduleCheck("ProtoPollution", false, "Tests for JavaScript prototype pollution"));
        checksPanel.add(moduleCheck("ErrorDisclosure", false, "Triggers errors to find stack traces and path leaks"));
        checksPanel.add(moduleCheck("EmailSec", false, "Checks SPF/DMARC/DKIM DNS records"));
        checksPanel.add(moduleCheck("Actuator", false, "Checks for exposed Spring Boot Actuator endpoints"));
        checksPanel.add(moduleCheck("CloudMisconfig", false, "Checks for cloud storage and service misconfigurations"));
        checksPanel.add(moduleCheck("SubTakeover", false, "Tests for subdomain takeover via dangling DNS records"));

        checksPanel.add(Box.createVerticalStrut(12));

        addSection(checksPanel, "DESTRUCTIVE", new Color(0xD6, 0x21, 0x3F));
        checksPanel.add(moduleCheck("RaceCondition", false, "Tests for race conditions in state-changing operations",
                "Sends concurrent requests that may alter target state (payments, coupons)"));
        checksPanel
                .add(moduleCheck("Deserialization", false, "Tests for insecure deserialization (Java, PHP, Python)"));
        checksPanel.add(moduleCheck("FileUpload", false, "Tests file upload restrictions and bypass techniques",
                "Uploads test files to the target -- potentially destructive"));

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
        applyStartButtonStyle();
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
        AnarCryLaf.addThemeListener(this::reapplyColors);
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

    private void applyStartButtonStyle() {
        startButton.setBackground(ACCENT);
        startButton.setForeground(Color.WHITE);
        startButton.setFont(startButton.getFont().deriveFont(Font.BOLD, 13f));
        startButton.setFocusPainted(false);
        startButton.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
        startButton.setPreferredSize(new Dimension(100, 32));
    }

    private void reapplyColors() {
        for (ColoredComponent cc : coloredComponents) {
            cc.component.setForeground(cc.color);
            if (cc.component instanceof JLabel lbl && "i".equals(lbl.getText())) {
                lbl.setBorder(BorderFactory.createCompoundBorder(BorderFactory.createLineBorder(cc.color, 1),
                        BorderFactory.createEmptyBorder(0, 3, 0, 3)));
            }
        }
        applyStartButtonStyle();
        setBorder(BorderFactory.createMatteBorder(0, 0, 0, 1, sectionLine()));
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
        coloredComponents.add(new ColoredComponent(label, color));

        JSeparator line = new JSeparator(SwingConstants.HORIZONTAL);
        line.setForeground(color.darker());
        line.setMaximumSize(new Dimension(Integer.MAX_VALUE, 1));
        line.setAlignmentX(Component.LEFT_ALIGNMENT);
        parent.add(line);
        coloredComponents.add(new ColoredComponent(line, color.darker()));

        parent.add(Box.createVerticalStrut(4));
    }

    private JComponent moduleCheck(String moduleId, boolean checked, String tooltip) {
        return moduleCheck(moduleId, checked, tooltip, null);
    }

    private JComponent moduleCheck(String moduleId, boolean checked, String tooltip, String warning) {
        JCheckBox cb = new JCheckBox(moduleId, checked);
        cb.setBorder(BorderFactory.createEmptyBorder(1, 12, 1, 0));
        if (tooltip != null) {
            cb.setToolTipText(tooltip);
        }
        moduleChecks.put(moduleId, cb);
        if (warning == null) {
            cb.setAlignmentX(Component.LEFT_ALIGNMENT);
            return cb;
        }
        JPanel row = new JPanel();
        row.setLayout(new BoxLayout(row, BoxLayout.X_AXIS));
        row.setAlignmentX(Component.LEFT_ALIGNMENT);
        row.setOpaque(false);
        row.add(cb);
        row.add(Box.createHorizontalStrut(2));
        Color badgeColor = new Color(0x77, 0x99, 0xBB);
        JLabel info = new JLabel("i");
        info.setFont(info.getFont().deriveFont(Font.BOLD | Font.ITALIC, 9f));
        info.setForeground(badgeColor);
        info.setBorder(BorderFactory.createCompoundBorder(BorderFactory.createLineBorder(badgeColor, 1),
                BorderFactory.createEmptyBorder(0, 3, 0, 3)));
        info.setToolTipText(warning);
        info.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
        coloredComponents.add(new ColoredComponent(info, badgeColor));
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

    private static JButton smallToggle(String text, String tooltip) {
        JButton btn = new JButton(text);
        btn.setToolTipText(tooltip);
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
