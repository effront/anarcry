package gg.effront.anarcry.gui.components;

import gg.effront.anarcry.Version;
import gg.effront.anarcry.gui.PrivacyFilter;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Cursor;
import java.awt.FlowLayout;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;

import javax.swing.BorderFactory;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JProgressBar;
import javax.swing.JToggleButton;
import javax.swing.SwingUtilities;

public class GuiStatusBar extends JPanel {

    private static final Color COLOR_CRITICAL = new Color(0xF8, 0x51, 0x49);
    private static final Color COLOR_HIGH = new Color(0xD2, 0x99, 0x22);
    private static final Color COLOR_MEDIUM = new Color(0xE3, 0xB3, 0x41);
    private static final Color COLOR_LOW = new Color(0x58, 0xA6, 0xFF);
    private static final Color COLOR_INFO = new Color(0x8B, 0x94, 0x9E);
    private static final Color COLOR_SEPARATOR = new Color(0x8B, 0x94, 0x9E);
    private static final Color COLOR_PRIVACY_ON = new Color(0x3F, 0xB9, 0x50);
    private static final Color COLOR_PROXY_ON = new Color(0x3F, 0xB9, 0x50);
    private static final Color COLOR_VERSION = new Color(0x8B, 0x94, 0x9E);

    private final JLabel criticalLabel;
    private final JLabel highLabel;
    private final JLabel mediumLabel;
    private final JLabel lowLabel;
    private final JLabel infoLabel;
    private final JLabel modulesLabel;
    private final JLabel targetLabel;
    private final JProgressBar progressBar;
    private final JToggleButton privacyToggle;

    private final JLabel searchLabel;
    private final JLabel cookiesLabel;
    private final JLabel proxyLabel;
    private final JLabel versionLabel;

    private Runnable onSearchClick;
    private Runnable onCookiesClick;
    private Runnable onProxyClick;
    private Runnable onSettingsClick;
    private Runnable onThemeClick;
    private Runnable onGithubClick;
    private Runnable onLicenseClick;
    private Runnable onKeybindingsClick;

    private String rawTarget = "";
    private int modulesCompleted = 0;
    private int modulesTotal = 0;

    public GuiStatusBar() {
        super(new BorderLayout());
        setBorder(BorderFactory.createEmptyBorder(2, 4, 2, 4));

        JPanel left = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 2));
        left.setOpaque(false);

        criticalLabel = coloredLabel("C:0", COLOR_CRITICAL);
        highLabel = coloredLabel("H:0", COLOR_HIGH);
        mediumLabel = coloredLabel("M:0", COLOR_MEDIUM);
        lowLabel = coloredLabel("L:0", COLOR_LOW);
        infoLabel = coloredLabel("I:0", COLOR_INFO);

        modulesLabel = new JLabel("Modules: 0/0");
        targetLabel = new JLabel("");

        progressBar = new JProgressBar(0, 100);
        progressBar.setStringPainted(true);
        progressBar.setVisible(false);

        JLabel settingsGear = iconButton(StatusBarIcons.settings());
        settingsGear.setToolTipText("Preferences (Ctrl+,)");
        settingsGear.addMouseListener(new MouseAdapter() {

            @Override
            public void mouseClicked(MouseEvent e) {
                if (onSettingsClick != null) {
                    onSettingsClick.run();
                }
            }
        });

        JLabel themeLabel = iconButton(StatusBarIcons.palette());
        themeLabel.setToolTipText("Toggle Theme (Ctrl+Shift+T)");
        themeLabel.addMouseListener(new MouseAdapter() {

            @Override
            public void mouseClicked(MouseEvent e) {
                if (onThemeClick != null) {
                    onThemeClick.run();
                }
            }
        });

        JLabel githubLabel = iconButton(StatusBarIcons.github());
        githubLabel.setToolTipText("Open GitHub Repository");
        githubLabel.addMouseListener(new MouseAdapter() {

            @Override
            public void mouseClicked(MouseEvent e) {
                if (onGithubClick != null) {
                    onGithubClick.run();
                }
            }
        });

        JLabel licenseLabel = iconButton(StatusBarIcons.license());
        licenseLabel.setToolTipText("License Info");
        licenseLabel.addMouseListener(new MouseAdapter() {

            @Override
            public void mouseClicked(MouseEvent e) {
                if (onLicenseClick != null) {
                    onLicenseClick.run();
                }
            }
        });

        left.add(settingsGear);
        left.add(themeLabel);
        left.add(githubLabel);
        left.add(licenseLabel);
        left.add(separator());
        left.add(criticalLabel);
        left.add(highLabel);
        left.add(mediumLabel);
        left.add(lowLabel);
        left.add(infoLabel);
        left.add(separator());
        left.add(modulesLabel);
        left.add(separator());
        left.add(targetLabel);
        left.add(progressBar);

        JPanel right = new JPanel(new FlowLayout(FlowLayout.RIGHT, 6, 2));
        right.setOpaque(false);

        searchLabel = iconButton(StatusBarIcons.search());
        searchLabel.setToolTipText("Global Search (Ctrl+K)");
        searchLabel.addMouseListener(new MouseAdapter() {

            @Override
            public void mouseClicked(MouseEvent e) {
                if (onSearchClick != null) {
                    onSearchClick.run();
                }
            }
        });

        cookiesLabel = new JLabel("Cookies(0)", StatusBarIcons.cookie(), JLabel.LEFT);
        cookiesLabel.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
        cookiesLabel.setIconTextGap(4);
        cookiesLabel.setToolTipText("Cookie Jar");
        cookiesLabel.addMouseListener(new MouseAdapter() {

            @Override
            public void mouseClicked(MouseEvent e) {
                if (onCookiesClick != null) {
                    onCookiesClick.run();
                }
            }
        });
        proxyLabel = new JLabel("Proxy: OFF", StatusBarIcons.proxy(), JLabel.LEFT);
        proxyLabel.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
        proxyLabel.setIconTextGap(4);
        proxyLabel.setToolTipText("Proxy Settings");
        proxyLabel.addMouseListener(new MouseAdapter() {

            @Override
            public void mouseClicked(MouseEvent e) {
                if (onProxyClick != null) {
                    onProxyClick.run();
                }
            }
        });

        privacyToggle = new JToggleButton("Privacy: OFF");
        privacyToggle.setFocusable(false);
        privacyToggle.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
        privacyToggle.addActionListener(e -> {
            PrivacyFilter.toggle();
            updatePrivacyLabel();
        });

        versionLabel = new JLabel("v" + Version.get());
        versionLabel.setForeground(COLOR_VERSION);

        right.add(searchLabel);
        right.add(separator());
        right.add(cookiesLabel);
        right.add(separator());
        right.add(proxyLabel);
        right.add(separator());
        right.add(privacyToggle);
        right.add(separator());
        right.add(versionLabel);

        add(left, BorderLayout.CENTER);
        add(right, BorderLayout.EAST);

        PrivacyFilter.addListener(() -> SwingUtilities.invokeLater(this::onPrivacyChanged));
    }

    public void setOnSearchClick(Runnable action) {
        this.onSearchClick = action;
    }

    public void setOnCookiesClick(Runnable action) {
        this.onCookiesClick = action;
    }

    public void setOnProxyClick(Runnable action) {
        this.onProxyClick = action;
    }

    public void setOnSettingsClick(Runnable action) {
        this.onSettingsClick = action;
    }

    public void setOnThemeClick(Runnable action) {
        this.onThemeClick = action;
    }

    public void setOnGithubClick(Runnable action) {
        this.onGithubClick = action;
    }

    public void setOnLicenseClick(Runnable action) {
        this.onLicenseClick = action;
    }

    public void setOnKeybindingsClick(Runnable action) {
        this.onKeybindingsClick = action;
    }

    public void setProxyEnabled(boolean on) {
        SwingUtilities.invokeLater(() -> {
            proxyLabel.setText(on ? "Proxy: ON" : "Proxy: OFF");
            proxyLabel.setForeground(on ? COLOR_PROXY_ON : null);
        });
    }

    public void setCookieCount(int count) {
        SwingUtilities.invokeLater(() -> cookiesLabel.setText("Cookies(" + count + ")"));
    }

    public void setSeverityCounts(int c, int h, int m, int l, int i) {
        SwingUtilities.invokeLater(() -> {
            criticalLabel.setText("C:" + c);
            highLabel.setText("H:" + h);
            mediumLabel.setText("M:" + m);
            lowLabel.setText("L:" + l);
            infoLabel.setText("I:" + i);
        });
    }

    public void setModuleTotal(int total) {
        SwingUtilities.invokeLater(() -> {
            modulesTotal = total;
            modulesCompleted = 0;
            updateProgress();
        });
    }

    public void moduleCompleted() {
        SwingUtilities.invokeLater(() -> {
            modulesCompleted++;
            updateProgress();
        });
    }

    public void resetProgress() {
        SwingUtilities.invokeLater(() -> {
            modulesCompleted = 0;
            modulesTotal = 0;
            updateProgress();
        });
    }

    private void updateProgress() {
        modulesLabel.setText("Modules: " + modulesCompleted + "/" + modulesTotal);
        if (modulesTotal > 0) {
            int pct = (int) Math.round(100.0 * modulesCompleted / modulesTotal);
            progressBar.setValue(pct);
            progressBar.setString(pct + "%");
        } else {
            progressBar.setValue(0);
            progressBar.setString("");
        }
    }

    @Deprecated
    public void setModuleProgress(int done, int total) {
        SwingUtilities.invokeLater(() -> {
            modulesCompleted = done;
            modulesTotal = total;
            updateProgress();
        });
    }

    public void setTarget(String t) {
        rawTarget = t != null ? t : "";
        SwingUtilities.invokeLater(() -> targetLabel.setText(PrivacyFilter.apply(rawTarget)));
    }

    public void setScanning(boolean scanning) {
        SwingUtilities.invokeLater(() -> progressBar.setVisible(scanning));
    }

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
        privacyToggle.setForeground(on ? COLOR_PRIVACY_ON : null);
    }

    private static JLabel coloredLabel(String text, Color fg) {
        JLabel label = new JLabel(text);
        label.setForeground(fg);
        return label;
    }

    private static JLabel clickableLabel(String text) {
        JLabel label = new JLabel(text);
        label.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
        return label;
    }

    private static JLabel iconButton(javax.swing.Icon icon) {
        JLabel label = new JLabel(icon);
        label.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
        return label;
    }

    private static JLabel separator() {
        JLabel sep = new JLabel("|");
        sep.setForeground(COLOR_SEPARATOR);
        return sep;
    }
}
