package gg.effront.anarcry.gui.views;

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

/** Target configuration view: URL, JWT tokens, scope rules, and scan delay. */
public class TargetView extends JPanel {

    private final JTextField targetField;
    private final JTextArea jwtField;
    private final JTextArea jwt2Field;
    private final JTextArea scopeField;
    private final JTextField sessionCookieField;
    private final JSpinner delaySpinner;
    private final JButton applyButton;

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
    }

    // -------------------------------------------------------------------------
    // Public API
    // -------------------------------------------------------------------------

    public String getTarget() {
        return targetField.getText().trim();
    }

    public String getJwt() {
        return jwtField.getText().trim();
    }

    public String getJwt2() {
        return jwt2Field.getText().trim();
    }

    public Set<String> getScopeHosts() {
        return Arrays.stream(scopeField.getText().split("\\n")).map(String::trim).filter(s -> !s.isEmpty())
                .collect(Collectors.toSet());
    }

    public String getSessionCookie() {
        return sessionCookieField.getText().trim();
    }

    public int getDelayMs() {
        return (int) delaySpinner.getValue();
    }

    public void setTarget(String t) {
        targetField.setText(t);
    }

    public void setJwt(String j) {
        jwtField.setText(j);
    }

    public void setJwt2(String j) {
        jwt2Field.setText(j);
    }

    public void setOnApply(Runnable r) {
        this.onApply = r != null ? r : () -> {
        };
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
