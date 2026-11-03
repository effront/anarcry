package gg.effront.anarcry.gui.views;

import gg.effront.anarcry.gui.PrivacyFilter;

import java.awt.Component;
import java.awt.Dimension;
import java.util.Arrays;
import java.util.Set;
import java.util.stream.Collectors;
import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSpinner;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.SpinnerNumberModel;
import javax.swing.SwingUtilities;

/** Target configuration view: URL, JWT tokens, scope rules, and scan delay. */
public class TargetView extends JPanel {

    private final JTextField targetField;
    private final JTextArea jwtField;
    private final JTextArea jwt2Field;
    private final JTextArea scopeField;
    private final JTextField sessionCookieField;
    private final JSpinner delaySpinner;
    private final JButton applyButton;

    private String rawTarget = "https://";
    private String rawJwt = "";
    private String rawJwt2 = "";
    private String rawScope = "";
    private String rawCookie = "";

    private Runnable onApply = () -> {
    };

    public TargetView() {
        setLayout(new BoxLayout(this, BoxLayout.Y_AXIS));
        setBorder(BorderFactory.createEmptyBorder(12, 16, 12, 16));

        add(fieldLabel("Target URL:"));
        targetField = new JTextField("https://");
        targetField.setMaximumSize(new Dimension(Integer.MAX_VALUE, 28));
        targetField.setAlignmentX(Component.LEFT_ALIGNMENT);
        add(targetField);
        add(Box.createVerticalStrut(10));

        add(fieldLabel("JWT Token 1:"));
        jwtField = new JTextArea(3, 40);
        jwtField.setLineWrap(true);
        JScrollPane jwtScroll = scrollWrap(jwtField, 72);
        add(jwtScroll);
        add(Box.createVerticalStrut(10));

        add(fieldLabel("JWT Token 2 (IDOR):"));
        jwt2Field = new JTextArea(3, 40);
        jwt2Field.setLineWrap(true);
        JScrollPane jwt2Scroll = scrollWrap(jwt2Field, 72);
        add(jwt2Scroll);
        add(Box.createVerticalStrut(10));

        add(fieldLabel("In-Scope Hosts (one per line):"));
        scopeField = new JTextArea(4, 40);
        scopeField.setLineWrap(true);
        JScrollPane scopeScroll = scrollWrap(scopeField, 90);
        add(scopeScroll);
        add(Box.createVerticalStrut(10));

        add(fieldLabel("Session Cookie:"));
        sessionCookieField = new JTextField();
        sessionCookieField.setMaximumSize(new Dimension(Integer.MAX_VALUE, 28));
        sessionCookieField.setAlignmentX(Component.LEFT_ALIGNMENT);
        add(sessionCookieField);
        add(Box.createVerticalStrut(10));

        add(fieldLabel("Scan Delay (ms):"));
        delaySpinner = new JSpinner(new SpinnerNumberModel(0, 0, 5000, 50));
        delaySpinner.setMaximumSize(new Dimension(120, 28));
        delaySpinner.setAlignmentX(Component.LEFT_ALIGNMENT);
        add(delaySpinner);
        add(Box.createVerticalStrut(16));

        applyButton = new JButton("Apply");
        applyButton.setAlignmentX(Component.LEFT_ALIGNMENT);
        applyButton.addActionListener(e -> onApply.run());
        add(applyButton);

        add(Box.createVerticalGlue());

        PrivacyFilter.addListener(() -> SwingUtilities.invokeLater(this::onPrivacyChanged));
    }

    // -------------------------------------------------------------------------
    // Public API
    // -------------------------------------------------------------------------

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

    public Set<String> getScopeHosts() {
        String text = PrivacyFilter.isEnabled() ? rawScope : scopeField.getText();
        return Arrays.stream(text.split("\\n")).map(String::trim).filter(s -> !s.isEmpty()).collect(Collectors.toSet());
    }

    public String getSessionCookie() {
        if (!PrivacyFilter.isEnabled()) {
            rawCookie = sessionCookieField.getText();
        }
        return rawCookie.trim();
    }

    public int getDelayMs() {
        return (int) delaySpinner.getValue();
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

    public void setScopeHosts(String hosts) {
        rawScope = hosts != null ? hosts : "";
        scopeField.setText(PrivacyFilter.isEnabled() ? PrivacyFilter.apply(rawScope) : rawScope);
    }

    public void setSessionCookie(String cookie) {
        rawCookie = cookie != null ? cookie : "";
        sessionCookieField.setText(PrivacyFilter.isEnabled() ? PrivacyFilter.apply(rawCookie) : rawCookie);
    }

    public void setOnApply(Runnable r) {
        this.onApply = r != null ? r : () -> {
        };
    }

    // -------------------------------------------------------------------------
    // Privacy
    // -------------------------------------------------------------------------

    private void onPrivacyChanged() {
        if (PrivacyFilter.isEnabled()) {
            rawTarget = targetField.getText();
            rawJwt = jwtField.getText();
            rawJwt2 = jwt2Field.getText();
            rawScope = scopeField.getText();
            rawCookie = sessionCookieField.getText();
            targetField.setText(PrivacyFilter.apply(rawTarget));
            jwtField.setText(PrivacyFilter.apply(rawJwt));
            jwt2Field.setText(PrivacyFilter.apply(rawJwt2));
            scopeField.setText(PrivacyFilter.apply(rawScope));
            sessionCookieField.setText(PrivacyFilter.apply(rawCookie));
            targetField.setEditable(false);
            jwtField.setEditable(false);
            jwt2Field.setEditable(false);
            scopeField.setEditable(false);
            sessionCookieField.setEditable(false);
        } else {
            targetField.setText(rawTarget);
            jwtField.setText(rawJwt);
            jwt2Field.setText(rawJwt2);
            scopeField.setText(rawScope);
            sessionCookieField.setText(rawCookie);
            targetField.setEditable(true);
            jwtField.setEditable(true);
            jwt2Field.setEditable(true);
            scopeField.setEditable(true);
            sessionCookieField.setEditable(true);
        }
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private static JLabel fieldLabel(String text) {
        JLabel label = new JLabel(text);
        label.setAlignmentX(Component.LEFT_ALIGNMENT);
        return label;
    }

    private static JScrollPane scrollWrap(JTextArea area, int maxHeight) {
        area.setAlignmentX(Component.LEFT_ALIGNMENT);
        JScrollPane scroll = new JScrollPane(area);
        scroll.setMaximumSize(new Dimension(Integer.MAX_VALUE, maxHeight));
        scroll.setAlignmentX(Component.LEFT_ALIGNMENT);
        return scroll;
    }
}
