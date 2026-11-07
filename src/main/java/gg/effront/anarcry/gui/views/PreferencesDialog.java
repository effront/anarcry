package gg.effront.anarcry.gui.views;

import gg.effront.anarcry.Version;
import gg.effront.anarcry.gui.theme.AnarCryLaf;

import java.awt.BorderLayout;
import java.awt.CardLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;

import javax.swing.BorderFactory;
import javax.swing.DefaultListCellRenderer;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JDialog;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JList;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.JScrollPane;
import javax.swing.JSpinner;
import javax.swing.JTable;
import javax.swing.JTextField;
import javax.swing.SpinnerNumberModel;
import javax.swing.SwingUtilities;
import javax.swing.table.DefaultTableModel;

public class PreferencesDialog extends JDialog {

    private static final String[] CATEGORIES = {"General", "Themes", "Display", "Proxy", "Certificates", "License",
            "Notifications", "Keybindings", "Support", "About"};

    private static final Color[] CATEGORY_COLORS = {new Color(0x8B, 0x94, 0x9E), new Color(0xA8, 0x5C, 0xF0),
            new Color(0x58, 0xA6, 0xFF), new Color(0x3F, 0xB9, 0x50), new Color(0xD2, 0x99, 0x22),
            new Color(0xF8, 0x51, 0x49), new Color(0xE3, 0xB3, 0x41), new Color(0x6C, 0x9E, 0xD6),
            new Color(0xCC, 0x66, 0x99), new Color(0x8B, 0x94, 0x9E)};

    private JList<String> categoryList;
    private CardLayout cards;
    private JPanel cardPanel;

    private final JCheckBox sslVerification = new JCheckBox("SSL/TLS Certificate Verification");
    private final JCheckBox storeCookies = new JCheckBox("Store Cookies automatically", true);
    private final JCheckBox sendCookies = new JCheckBox("Send Cookies automatically", true);
    private final JSpinner requestTimeoutSpinner = new JSpinner(new SpinnerNumberModel(30000, 0, 300000, 1000));
    private final JSpinner parallelismSpinner = new JSpinner(new SpinnerNumberModel(4, 1, 16, 1));
    private final JSpinner scanTimeoutSpinner = new JSpinner(new SpinnerNumberModel(10, 1, 60, 1));
    private final JTextField collectionsDir = new JTextField(System.getProperty("user.home"));
    private final JCheckBox autoSave = new JCheckBox("Enable Auto Save");

    private final JComboBox<String> themeCombo = new JComboBox<>(new String[]{"Dark", "Light"});
    private final JSpinner fontSizeSpinner = new JSpinner(new SpinnerNumberModel(13, 10, 24, 1));

    private final JCheckBox proxyEnabled = new JCheckBox("Enable Proxy");
    private final JComboBox<String> proxyProtocol = new JComboBox<>(new String[]{"HTTP", "HTTPS", "SOCKS5"});
    private final JTextField proxyHost = new JTextField();
    private final JSpinner proxyPort = new JSpinner(new SpinnerNumberModel(8080, 1, 65535, 1));
    private final JTextField proxyUser = new JTextField();
    private final JPasswordField proxyPass = new JPasswordField();

    private final JCheckBox keepDefaultCa = new JCheckBox("Keep Default CA Certificates", true);
    private final DefaultTableModel certTableModel = new DefaultTableModel(
            new String[]{"Domain", "Cert File", "Key File"}, 0);

    private int parallelism = 4;
    private int timeoutMinutes = 10;

    public PreferencesDialog(JFrame parent) {
        this(parent, "General");
    }

    public PreferencesDialog(JFrame parent, String initialCategory) {
        super(parent, "Preferences", true);
        setSize(750, 540);
        setLocationRelativeTo(parent);
        setLayout(new BorderLayout());

        themeCombo.setSelectedItem(AnarCryLaf.isDark() ? "Dark" : "Light");

        cards = new CardLayout();
        cardPanel = new JPanel(cards);
        cardPanel.setBorder(BorderFactory.createEmptyBorder(12, 16, 8, 16));

        cardPanel.add(buildGeneralPanel(), "General");
        cardPanel.add(buildThemesPanel(), "Themes");
        cardPanel.add(buildDisplayPanel(), "Display");
        cardPanel.add(buildProxyPanel(), "Proxy");
        cardPanel.add(buildCertificatesPanel(), "Certificates");
        cardPanel.add(buildLicensePanel(), "License");
        cardPanel.add(buildNotificationsPanel(), "Notifications");
        cardPanel.add(buildKeybindingsPanel(), "Keybindings");
        cardPanel.add(buildSupportPanel(), "Support");
        cardPanel.add(buildAboutPanel(), "About");

        int initialIdx = 0;
        for (int i = 0; i < CATEGORIES.length; i++) {
            if (CATEGORIES[i].equals(initialCategory)) {
                initialIdx = i;
                break;
            }
        }

        categoryList = new JList<>(CATEGORIES);
        categoryList.setSelectedIndex(initialIdx);
        categoryList.setFixedCellHeight(36);
        categoryList.setCellRenderer(new DefaultListCellRenderer() {

            @Override
            public Component getListCellRendererComponent(JList<?> list, Object value, int index, boolean isSelected,
                    boolean cellHasFocus) {
                super.getListCellRendererComponent(list, value, index, isSelected, cellHasFocus);
                setBorder(BorderFactory.createEmptyBorder(6, 12, 6, 8));
                if (index >= 0 && index < CATEGORY_COLORS.length) {
                    setIcon(new DotIcon(CATEGORY_COLORS[index]));
                }
                setIconTextGap(8);
                return this;
            }
        });
        categoryList.addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                cards.show(cardPanel, categoryList.getSelectedValue());
            }
        });

        JScrollPane listScroll = new JScrollPane(categoryList);
        listScroll.setPreferredSize(new Dimension(190, 0));
        listScroll.setBorder(BorderFactory.createMatteBorder(0, 0, 0, 1, getBackground().darker()));

        add(listScroll, BorderLayout.WEST);
        add(cardPanel, BorderLayout.CENTER);

        if (initialIdx > 0) {
            cards.show(cardPanel, initialCategory);
        }

        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 8));
        JButton applyBtn = new JButton("Apply");
        applyBtn.addActionListener(e -> applySettings());
        buttonPanel.add(applyBtn);
        JButton cancelBtn = new JButton("Cancel");
        cancelBtn.addActionListener(e -> dispose());
        buttonPanel.add(cancelBtn);
        add(buttonPanel, BorderLayout.SOUTH);
    }

    private JPanel buildGeneralPanel() {
        JPanel p = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = gbc();

        addSection(p, gbc, "GENERAL SETTINGS");

        gbc.gridy++;
        gbc.gridwidth = 2;
        p.add(sslVerification, gbc);

        gbc.gridy++;
        p.add(storeCookies, gbc);

        gbc.gridy++;
        p.add(sendCookies, gbc);

        gbc.gridy++;
        gbc.gridwidth = 1;
        p.add(new JLabel("Request Timeout (ms):"), gbc);
        gbc.gridx = 1;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.weightx = 1.0;
        p.add(requestTimeoutSpinner, gbc);

        gbc.gridx = 0;
        gbc.gridy++;
        gbc.fill = GridBagConstraints.NONE;
        gbc.weightx = 0;
        p.add(new JLabel("Scan parallelism:"), gbc);
        gbc.gridx = 1;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.weightx = 1.0;
        p.add(parallelismSpinner, gbc);

        gbc.gridx = 0;
        gbc.gridy++;
        gbc.fill = GridBagConstraints.NONE;
        gbc.weightx = 0;
        p.add(new JLabel("Scan timeout (min):"), gbc);
        gbc.gridx = 1;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.weightx = 1.0;
        p.add(scanTimeoutSpinner, gbc);

        gbc.gridx = 0;
        gbc.gridy++;
        gbc.fill = GridBagConstraints.NONE;
        gbc.weightx = 0;
        p.add(new JLabel("Collections directory:"), gbc);
        gbc.gridx = 1;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.weightx = 1.0;
        JPanel dirPanel = new JPanel(new BorderLayout(4, 0));
        dirPanel.add(collectionsDir, BorderLayout.CENTER);
        JButton browseBtn = new JButton("Browse");
        browseBtn.addActionListener(e -> browseCollectionsDir());
        dirPanel.add(browseBtn, BorderLayout.EAST);
        p.add(dirPanel, gbc);

        gbc.gridx = 0;
        gbc.gridy++;
        gbc.gridwidth = 2;
        gbc.fill = GridBagConstraints.NONE;
        gbc.weightx = 0;
        p.add(autoSave, gbc);

        addFiller(p, gbc);
        return p;
    }

    private JPanel buildThemesPanel() {
        JPanel p = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = gbc();

        addSection(p, gbc, "THEMES");

        gbc.gridy++;
        gbc.gridwidth = 1;
        p.add(new JLabel("Theme:"), gbc);
        gbc.gridx = 1;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.weightx = 1.0;
        p.add(themeCombo, gbc);

        addFiller(p, gbc);
        return p;
    }

    private JPanel buildDisplayPanel() {
        JPanel p = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = gbc();

        addSection(p, gbc, "DISPLAY");

        gbc.gridy++;
        gbc.gridwidth = 1;
        p.add(new JLabel("Font size:"), gbc);
        gbc.gridx = 1;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.weightx = 1.0;
        p.add(fontSizeSpinner, gbc);

        addFiller(p, gbc);
        return p;
    }

    private JPanel buildProxyPanel() {
        JPanel p = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = gbc();

        addSection(p, gbc, "PROXY");

        gbc.gridy++;
        gbc.gridwidth = 2;
        p.add(proxyEnabled, gbc);

        gbc.gridy++;
        gbc.gridwidth = 1;
        p.add(new JLabel("Protocol:"), gbc);
        gbc.gridx = 1;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.weightx = 1.0;
        p.add(proxyProtocol, gbc);

        gbc.gridx = 0;
        gbc.gridy++;
        gbc.fill = GridBagConstraints.NONE;
        gbc.weightx = 0;
        p.add(new JLabel("Hostname:"), gbc);
        gbc.gridx = 1;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.weightx = 1.0;
        p.add(proxyHost, gbc);

        gbc.gridx = 0;
        gbc.gridy++;
        gbc.fill = GridBagConstraints.NONE;
        gbc.weightx = 0;
        p.add(new JLabel("Port:"), gbc);
        gbc.gridx = 1;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.weightx = 1.0;
        p.add(proxyPort, gbc);

        gbc.gridx = 0;
        gbc.gridy++;
        gbc.fill = GridBagConstraints.NONE;
        gbc.weightx = 0;
        p.add(new JLabel("Username:"), gbc);
        gbc.gridx = 1;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.weightx = 1.0;
        p.add(proxyUser, gbc);

        gbc.gridx = 0;
        gbc.gridy++;
        gbc.fill = GridBagConstraints.NONE;
        gbc.weightx = 0;
        p.add(new JLabel("Password:"), gbc);
        gbc.gridx = 1;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.weightx = 1.0;
        p.add(proxyPass, gbc);

        gbc.gridx = 0;
        gbc.gridy++;
        gbc.gridwidth = 2;
        gbc.fill = GridBagConstraints.NONE;
        gbc.weightx = 0;
        JLabel hint = new JLabel("Route requests through Burp Suite / ZAP / mitmproxy");
        hint.setForeground(hint.getForeground().darker());
        p.add(hint, gbc);

        addFiller(p, gbc);
        return p;
    }

    private JPanel buildCertificatesPanel() {
        JPanel p = new JPanel(new BorderLayout(0, 8));
        p.setBorder(BorderFactory.createEmptyBorder(4, 0, 0, 0));

        JLabel title = new JLabel("CLIENT CERTIFICATES");
        title.setBorder(BorderFactory.createEmptyBorder(0, 0, 8, 0));
        p.add(title, BorderLayout.NORTH);

        JTable table = new JTable(certTableModel);
        table.setFillsViewportHeight(true);
        p.add(new JScrollPane(table), BorderLayout.CENTER);

        JPanel bottom = new JPanel(new BorderLayout(0, 6));
        JPanel btns = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 0));
        JButton addBtn = new JButton("Add");
        addBtn.addActionListener(e -> certTableModel.addRow(new String[]{"", "", ""}));
        btns.add(addBtn);
        JButton removeBtn = new JButton("Remove");
        removeBtn.addActionListener(e -> {
            int row = table.getSelectedRow();
            if (row >= 0) {
                certTableModel.removeRow(row);
            }
        });
        btns.add(removeBtn);
        bottom.add(btns, BorderLayout.NORTH);
        bottom.add(keepDefaultCa, BorderLayout.SOUTH);

        p.add(bottom, BorderLayout.SOUTH);
        return p;
    }

    private JPanel buildKeybindingsPanel() {
        JPanel p = new JPanel(new BorderLayout(0, 8));
        p.setBorder(BorderFactory.createEmptyBorder(4, 0, 0, 0));

        JLabel title = new JLabel("KEYBINDINGS");
        title.setBorder(BorderFactory.createEmptyBorder(0, 0, 8, 0));
        p.add(title, BorderLayout.NORTH);

        String[][] bindings = {{"F1", "Dashboard"}, {"F2", "Scan"}, {"F3", "Target"}, {"F4", "Findings"},
                {"F5", "Repeater"}, {"F6", "Report"}, {"F7", "SiteMap"}, {"F8", "API Client"}, {"F9", "Assistant"},
                {"Ctrl+Enter", "Send / Start Scan"}, {"Ctrl+Q", "Quit"}, {"Ctrl+Shift+P", "Toggle Privacy"},
                {"Ctrl+Shift+T", "Toggle Theme"}, {"E", "Export"}, {"?", "Action Palette"},};

        DefaultTableModel model = new DefaultTableModel(new String[]{"Shortcut", "Action"}, 0) {

            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }
        };
        for (String[] b : bindings) {
            model.addRow(b);
        }
        JTable table = new JTable(model);
        table.getColumnModel().getColumn(0).setPreferredWidth(120);
        table.getColumnModel().getColumn(1).setPreferredWidth(280);
        table.setFillsViewportHeight(true);
        p.add(new JScrollPane(table), BorderLayout.CENTER);

        return p;
    }

    private JPanel buildAboutPanel() {
        JPanel p = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.gridx = 0;
        gbc.gridy = 0;
        gbc.anchor = GridBagConstraints.CENTER;
        gbc.insets = new Insets(12, 0, 6, 0);

        JLabel version = new JLabel(Version.label());
        version.setFont(version.getFont().deriveFont(18f));
        p.add(version, gbc);

        gbc.gridy++;
        gbc.insets = new Insets(4, 0, 4, 0);
        p.add(new JLabel("Security Scanner - Authorized testing only"), gbc);

        gbc.gridy++;
        JLabel author = new JLabel("AnarCry by Effront");
        author.setForeground(author.getForeground().darker());
        p.add(author, gbc);

        return p;
    }

    private JPanel buildLicensePanel() {
        JPanel p = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.gridx = 0;
        gbc.gridy = 0;
        gbc.anchor = GridBagConstraints.CENTER;
        gbc.insets = new Insets(12, 0, 6, 0);

        JLabel title = new JLabel("LICENSE");
        title.setFont(title.getFont().deriveFont(11f));
        title.setForeground(title.getForeground().darker());
        p.add(title, gbc);

        gbc.gridy++;
        gbc.insets = new Insets(16, 0, 4, 0);
        p.add(new JLabel("AnarCry - Proprietary License"), gbc);

        gbc.gridy++;
        gbc.insets = new Insets(4, 0, 4, 0);
        JLabel notice = new JLabel("Authorized security testing use only");
        notice.setForeground(notice.getForeground().darker());
        p.add(notice, gbc);

        gbc.gridy++;
        gbc.insets = new Insets(16, 0, 4, 0);
        p.add(new JLabel("Effront - All rights reserved"), gbc);

        return p;
    }

    private JPanel buildNotificationsPanel() {
        JPanel p = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = gbc();

        addSection(p, gbc, "NOTIFICATIONS");

        gbc.gridy++;
        gbc.gridwidth = 2;
        JCheckBox scanComplete = new JCheckBox("Notify on scan complete", true);
        p.add(scanComplete, gbc);

        gbc.gridy++;
        JCheckBox criticalFinding = new JCheckBox("Notify on critical finding", true);
        p.add(criticalFinding, gbc);

        gbc.gridy++;
        JCheckBox updateAvailable = new JCheckBox("Check for updates");
        p.add(updateAvailable, gbc);

        addFiller(p, gbc);
        return p;
    }

    private JPanel buildSupportPanel() {
        JPanel p = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.gridx = 0;
        gbc.gridy = 0;
        gbc.anchor = GridBagConstraints.CENTER;
        gbc.insets = new Insets(12, 0, 6, 0);

        JLabel title = new JLabel("SUPPORT");
        title.setFont(title.getFont().deriveFont(11f));
        title.setForeground(title.getForeground().darker());
        p.add(title, gbc);

        gbc.gridy++;
        gbc.insets = new Insets(16, 0, 4, 0);
        p.add(new JLabel("Report issues or request features"), gbc);

        gbc.gridy++;
        gbc.insets = new Insets(12, 0, 4, 0);
        JLabel docs = new JLabel("Documentation: docs.effront.gg/anarcry");
        docs.setForeground(new Color(0x58, 0xA6, 0xFF));
        p.add(docs, gbc);

        gbc.gridy++;
        gbc.insets = new Insets(4, 0, 4, 0);
        JLabel repo = new JLabel("Repository: github.com/effront/anarcry");
        repo.setForeground(new Color(0x58, 0xA6, 0xFF));
        p.add(repo, gbc);

        return p;
    }

    public int getParallelism() {
        return parallelism;
    }

    public int getTimeoutMinutes() {
        return timeoutMinutes;
    }

    public boolean isSslVerificationEnabled() {
        return sslVerification.isSelected();
    }

    public boolean isStoreCookies() {
        return storeCookies.isSelected();
    }

    public boolean isSendCookies() {
        return sendCookies.isSelected();
    }

    public int getRequestTimeoutMs() {
        return (Integer) requestTimeoutSpinner.getValue();
    }

    public String getCollectionsDirectory() {
        return collectionsDir.getText();
    }

    public boolean isAutoSaveEnabled() {
        return autoSave.isSelected();
    }

    public int getFontSize() {
        return (Integer) fontSizeSpinner.getValue();
    }

    public boolean isProxyEnabled() {
        return proxyEnabled.isSelected();
    }

    public String getProxyProtocol() {
        return (String) proxyProtocol.getSelectedItem();
    }

    public String getProxyHost() {
        return proxyHost.getText();
    }

    public int getProxyPort() {
        return (Integer) proxyPort.getValue();
    }

    public String getProxyUsername() {
        return proxyUser.getText();
    }

    public char[] getProxyPassword() {
        return proxyPass.getPassword();
    }

    public boolean isKeepDefaultCa() {
        return keepDefaultCa.isSelected();
    }

    private void applySettings() {
        parallelism = (Integer) parallelismSpinner.getValue();
        timeoutMinutes = (Integer) scanTimeoutSpinner.getValue();

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

    private void browseCollectionsDir() {
        JFileChooser chooser = new JFileChooser(collectionsDir.getText());
        chooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
        if (chooser.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
            collectionsDir.setText(chooser.getSelectedFile().getAbsolutePath());
        }
    }

    private static GridBagConstraints gbc() {
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.gridx = 0;
        gbc.gridy = 0;
        gbc.anchor = GridBagConstraints.WEST;
        gbc.insets = new Insets(4, 0, 4, 8);
        return gbc;
    }

    private static void addSection(JPanel p, GridBagConstraints gbc, String title) {
        gbc.gridwidth = 2;
        JLabel label = new JLabel(title);
        label.setFont(label.getFont().deriveFont(11f));
        label.setForeground(label.getForeground().darker());
        label.setBorder(BorderFactory.createEmptyBorder(0, 0, 8, 0));
        p.add(label, gbc);
    }

    private static void addFiller(JPanel p, GridBagConstraints gbc) {
        gbc.gridx = 0;
        gbc.gridy++;
        gbc.weighty = 1.0;
        gbc.fill = GridBagConstraints.VERTICAL;
        p.add(new JLabel(), gbc);
    }

    private static class DotIcon implements javax.swing.Icon {

        private final Color color;

        DotIcon(Color color) {
            this.color = color;
        }

        @Override
        public void paintIcon(Component c, java.awt.Graphics g, int x, int y) {
            java.awt.Graphics2D g2 = (java.awt.Graphics2D) g.create();
            g2.setRenderingHint(java.awt.RenderingHints.KEY_ANTIALIASING, java.awt.RenderingHints.VALUE_ANTIALIAS_ON);
            g2.setColor(color);
            g2.fillOval(x, y, 10, 10);
            g2.dispose();
        }

        @Override
        public int getIconWidth() {
            return 10;
        }

        @Override
        public int getIconHeight() {
            return 10;
        }
    }
}
