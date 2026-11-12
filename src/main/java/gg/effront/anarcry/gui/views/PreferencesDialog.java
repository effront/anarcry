package gg.effront.anarcry.gui.views;

import gg.effront.anarcry.Version;
import gg.effront.anarcry.gui.AppSettings;
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

    public record CertEntry(boolean enabled, String domain, String type, String certFile, String keyFile,
            String passphrase) {
    }

    private static final String[] CATEGORIES = {"General", "Themes", "Display", "Proxy", "Certificates",
            "Notifications", "Keybindings", "License", "Support", "About"};

    private static final Color[] CATEGORY_COLORS = {new Color(0x8B, 0x94, 0x9E), new Color(0xA8, 0x5C, 0xF0),
            new Color(0x58, 0xA6, 0xFF), new Color(0x3F, 0xB9, 0x50), new Color(0xD2, 0x99, 0x22),
            new Color(0xE3, 0xB3, 0x41), new Color(0x6C, 0x9E, 0xD6), new Color(0xF8, 0x51, 0x49),
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

    private static int currentFontSize = 13;

    private final JComboBox<String> themeCombo = new JComboBox<>(new String[]{"Dark", "Light"});
    private final JSpinner fontSizeSpinner = new JSpinner(new SpinnerNumberModel(currentFontSize, 10, 24, 1));
    private final JComboBox<String> resolutionCombo = new JComboBox<>(
            new String[]{"1920x1080", "1280x720", "1400x950", "1600x1000", "Maximized"});

    private final JCheckBox proxyEnabled = new JCheckBox("Enable Proxy");
    private final JComboBox<String> proxyProtocol = new JComboBox<>(new String[]{"http", "https", "socks5"});
    private final JTextField proxyHost = new JTextField();
    private final JSpinner proxyPort = new JSpinner(new SpinnerNumberModel(8080, 1, 65535, 1));
    private final JTextField proxyUser = new JTextField();
    private final JPasswordField proxyPass = new JPasswordField();

    private final JCheckBox keepDefaultCa = new JCheckBox("Keep Default CA Certificates", true);
    private final DefaultTableModel certTableModel = new DefaultTableModel(
            new String[]{"", "Domain", "Type", "Cert/PFX File", "Key File", "Passphrase"}, 0) {

        @Override
        public Class<?> getColumnClass(int column) {
            return column == 0 ? Boolean.class : String.class;
        }

        @Override
        public boolean isCellEditable(int row, int column) {
            if (column == 4) {
                Object type = getValueAt(row, 2);
                return !"PKCS12".equals(type);
            }
            return true;
        }
    };
    private final JTextField caCertPath = new JTextField();

    private final JCheckBox notifyScanComplete = new JCheckBox("Notify on scan complete", true);
    private final JCheckBox notifyCriticalFinding = new JCheckBox("Notify on critical finding", true);

    private int parallelism = 4;
    private int timeoutMinutes = 10;
    private Runnable onApply;

    public PreferencesDialog(JFrame parent) {
        this(parent, "General");
    }

    public PreferencesDialog(JFrame parent, String initialCategory) {
        super(parent, "Preferences", true);
        setSize(900, 680);
        setLocationRelativeTo(parent);
        setLayout(new BorderLayout());

        loadFromSettings();

        cards = new CardLayout();
        cardPanel = new JPanel(cards);
        cardPanel.setBorder(BorderFactory.createEmptyBorder(12, 16, 8, 16));

        cardPanel.add(buildGeneralPanel(), "General");
        cardPanel.add(buildThemesPanel(), "Themes");
        cardPanel.add(buildDisplayPanel(), "Display");
        cardPanel.add(buildProxyPanel(), "Proxy");
        cardPanel.add(buildCertificatesPanel(), "Certificates");
        cardPanel.add(buildNotificationsPanel(), "Notifications");
        cardPanel.add(buildKeybindingsPanel(), "Keybindings");
        cardPanel.add(buildLicensePanel(), "License");
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
        listScroll.setBorder(BorderFactory.createEmptyBorder());

        JButton checkUpdatesBtn = new JButton("Check for Updates");
        checkUpdatesBtn.addActionListener(e -> doCheckForUpdates());
        JPanel updatePanel = new JPanel(new BorderLayout());
        updatePanel.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createMatteBorder(1, 0, 0, 0, getBackground().darker()),
                BorderFactory.createEmptyBorder(8, 12, 8, 12)));
        updatePanel.add(checkUpdatesBtn, BorderLayout.CENTER);

        JPanel sidebar = new JPanel(new BorderLayout());
        sidebar.setPreferredSize(new Dimension(190, 0));
        sidebar.setBorder(BorderFactory.createMatteBorder(0, 0, 0, 1, getBackground().darker()));
        sidebar.add(listScroll, BorderLayout.CENTER);
        sidebar.add(updatePanel, BorderLayout.SOUTH);

        add(sidebar, BorderLayout.WEST);
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

        gbc.gridx = 0;
        gbc.gridy++;
        gbc.fill = GridBagConstraints.NONE;
        gbc.weightx = 0;
        p.add(new JLabel("Window resolution:"), gbc);
        gbc.gridx = 1;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.weightx = 1.0;
        java.awt.Window owner = getOwner();
        if (owner != null) {
            int w = owner.getWidth();
            int h = owner.getHeight();
            boolean maximized = owner instanceof JFrame
                    && (((JFrame) owner).getExtendedState() & JFrame.MAXIMIZED_BOTH) != 0;
            if (maximized) {
                resolutionCombo.setSelectedItem("Maximized");
            } else {
                String current = w + "x" + h;
                boolean found = false;
                for (int i = 0; i < resolutionCombo.getItemCount(); i++) {
                    if (resolutionCombo.getItemAt(i).equals(current)) {
                        found = true;
                        break;
                    }
                }
                if (!found) {
                    resolutionCombo.insertItemAt(current, 0);
                }
                resolutionCombo.setSelectedItem(current);
            }
        }
        p.add(resolutionCombo, gbc);

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
        title.setFont(title.getFont().deriveFont(11f));
        title.setForeground(title.getForeground().darker());
        title.setBorder(BorderFactory.createEmptyBorder(0, 0, 8, 0));
        p.add(title, BorderLayout.NORTH);

        JTable table = new JTable(certTableModel);
        table.setFillsViewportHeight(true);
        table.setRowHeight(24);
        table.getColumnModel().getColumn(0).setMaxWidth(40);
        table.getColumnModel().getColumn(0).setMinWidth(40);
        table.getColumnModel().getColumn(1).setPreferredWidth(120);
        table.getColumnModel().getColumn(2).setPreferredWidth(70);
        table.getColumnModel().getColumn(2).setMaxWidth(80);
        table.getColumnModel().getColumn(3).setPreferredWidth(150);
        table.getColumnModel().getColumn(4).setPreferredWidth(150);
        table.getColumnModel().getColumn(5).setPreferredWidth(100);
        table.getColumnModel().getColumn(2)
                .setCellEditor(new javax.swing.DefaultCellEditor(new JComboBox<>(new String[]{"PEM", "PKCS12"})));
        p.add(new JScrollPane(table), BorderLayout.CENTER);

        JPanel bottom = new JPanel(new BorderLayout(0, 8));

        JPanel btns = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 0));
        JButton addBtn = new JButton("Add");
        addBtn.addActionListener(e -> certTableModel.addRow(new Object[]{Boolean.TRUE, "", "PEM", "", "", ""}));
        btns.add(addBtn);
        JButton removeBtn = new JButton("Remove");
        removeBtn.addActionListener(e -> {
            int row = table.getSelectedRow();
            if (row >= 0) {
                certTableModel.removeRow(row);
            }
        });
        btns.add(removeBtn);
        JButton browseCert = new JButton("Browse Cert/PFX...");
        browseCert.addActionListener(e -> browseFileToColumn(table, 3, "pem", "crt", "p12", "pfx"));
        btns.add(browseCert);
        JButton browseKey = new JButton("Browse Key...");
        browseKey.addActionListener(e -> browseFileToColumn(table, 4, "pem", "key"));
        btns.add(browseKey);
        bottom.add(btns, BorderLayout.NORTH);

        JPanel caPanel = new JPanel(new BorderLayout(0, 4));
        JLabel caTitle = new JLabel("CUSTOM CA CERTIFICATE");
        caTitle.setFont(caTitle.getFont().deriveFont(11f));
        caTitle.setForeground(caTitle.getForeground().darker());
        caPanel.add(caTitle, BorderLayout.NORTH);
        JPanel caRow = new JPanel(new BorderLayout(4, 0));
        caRow.add(caCertPath, BorderLayout.CENTER);
        JButton browseCa = new JButton("Browse");
        browseCa.addActionListener(e -> {
            JFileChooser fc = new JFileChooser();
            fc.setFileFilter(new javax.swing.filechooser.FileNameExtensionFilter(
                    "CA Certificates (*.pem, *.crt, *.der)", "pem", "crt", "der"));
            if (fc.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
                caCertPath.setText(fc.getSelectedFile().getAbsolutePath());
            }
        });
        caRow.add(browseCa, BorderLayout.EAST);
        caPanel.add(caRow, BorderLayout.CENTER);
        caPanel.add(keepDefaultCa, BorderLayout.SOUTH);

        bottom.add(caPanel, BorderLayout.SOUTH);

        p.add(bottom, BorderLayout.SOUTH);
        return p;
    }

    private void browseFileToColumn(JTable table, int column, String... extensions) {
        int row = table.getSelectedRow();
        if (row < 0) {
            return;
        }
        JFileChooser fc = new JFileChooser();
        fc.setFileFilter(
                new javax.swing.filechooser.FileNameExtensionFilter(String.join(", ", extensions), extensions));
        if (fc.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
            certTableModel.setValueAt(fc.getSelectedFile().getAbsolutePath(), row, column);
        }
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
        gbc.insets = new Insets(8, 0, 4, 0);

        java.net.URL logoUrl = getClass().getResource("/icons/logo-about.png");
        if (logoUrl != null) {
            JLabel logoLabel = new JLabel(new javax.swing.ImageIcon(logoUrl));
            p.add(logoLabel, gbc);
            gbc.gridy++;
        }

        gbc.insets = new Insets(8, 0, 4, 0);
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
        gbc.insets = new Insets(8, 0, 4, 0);

        java.net.URL artUrl = getClass().getResource("/icons/license-art.png");
        if (artUrl != null) {
            JLabel artLabel = new JLabel(new javax.swing.ImageIcon(artUrl));
            p.add(artLabel, gbc);
            gbc.gridy++;
        }

        gbc.insets = new Insets(12, 0, 4, 0);
        p.add(new JLabel("AnarCry - Proprietary License"), gbc);

        gbc.gridy++;
        gbc.insets = new Insets(4, 0, 4, 0);
        JLabel notice = new JLabel("Authorized security testing use only");
        notice.setForeground(notice.getForeground().darker());
        p.add(notice, gbc);

        gbc.gridy++;
        gbc.insets = new Insets(12, 0, 4, 0);
        p.add(new JLabel("Effront - All rights reserved"), gbc);

        return p;
    }

    private JPanel buildNotificationsPanel() {
        JPanel p = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = gbc();

        addSection(p, gbc, "NOTIFICATIONS");

        gbc.gridy++;
        gbc.gridwidth = 2;
        p.add(notifyScanComplete, gbc);

        gbc.gridy++;
        p.add(notifyCriticalFinding, gbc);

        addFiller(p, gbc);
        return p;
    }

    private JPanel buildSupportPanel() {
        JPanel p = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.gridx = 0;
        gbc.gridy = 0;
        gbc.anchor = GridBagConstraints.CENTER;
        gbc.insets = new Insets(8, 0, 6, 0);

        java.net.URL supportUrl = getClass().getResource("/icons/support-art.png");
        if (supportUrl != null) {
            JLabel artLabel = new JLabel(new javax.swing.ImageIcon(supportUrl));
            p.add(artLabel, gbc);
            gbc.gridy++;
        }

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
        JLabel docs = hyperlink("Documentation: docs.effront.gg/anarcry", "https://docs.effront.gg/anarcry");
        p.add(docs, gbc);

        gbc.gridy++;
        gbc.insets = new Insets(4, 0, 4, 0);
        JLabel repo = hyperlink("Repository: github.com/effront/anarcry", "https://github.com/effront/anarcry");
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

    public String getCustomCaCertPath() {
        return caCertPath.getText().trim();
    }

    public java.util.List<CertEntry> getCertEntries() {
        java.util.List<CertEntry> entries = new java.util.ArrayList<>();
        for (int i = 0; i < certTableModel.getRowCount(); i++) {
            boolean enabled = Boolean.TRUE.equals(certTableModel.getValueAt(i, 0));
            String domain = stringVal(certTableModel.getValueAt(i, 1));
            String type = stringVal(certTableModel.getValueAt(i, 2));
            String certFile = stringVal(certTableModel.getValueAt(i, 3));
            String keyFile = stringVal(certTableModel.getValueAt(i, 4));
            String passphrase = stringVal(certTableModel.getValueAt(i, 5));
            if (!domain.isEmpty() && !certFile.isEmpty()) {
                entries.add(new CertEntry(enabled, domain, type, certFile, keyFile, passphrase));
            }
        }
        return entries;
    }

    private static String stringVal(Object obj) {
        return obj == null ? "" : obj.toString().trim();
    }

    public void setOnApply(Runnable callback) {
        this.onApply = callback;
    }

    private void applySettings() {
        saveToSettings();
        parallelism = (Integer) parallelismSpinner.getValue();
        timeoutMinutes = (Integer) scanTimeoutSpinner.getValue();

        boolean wantDark = "Dark".equals(themeCombo.getSelectedItem());
        if (wantDark != AnarCryLaf.isDark()) {
            if (wantDark) {
                AnarCryLaf.install();
            } else {
                AnarCryLaf.installLight();
            }
        }

        String resolution = (String) resolutionCombo.getSelectedItem();
        java.awt.Window owner = getOwner();
        if (owner instanceof JFrame ownerFrame) {
            if ("Maximized".equals(resolution)) {
                ownerFrame.setExtendedState(ownerFrame.getExtendedState() | JFrame.MAXIMIZED_BOTH);
            } else if (resolution != null && resolution.contains("x")) {
                ownerFrame.setExtendedState(JFrame.NORMAL);
                String[] parts = resolution.split("x");
                int w = Integer.parseInt(parts[0].trim());
                int h = Integer.parseInt(parts[1].trim());
                ownerFrame.setSize(w, h);
                ownerFrame.setLocationRelativeTo(null);
            }
        }

        SwingUtilities.updateComponentTreeUI(getOwner());

        currentFontSize = (Integer) fontSizeSpinner.getValue();
        applyGlobalFontSize(currentFontSize);
        SwingUtilities.updateComponentTreeUI(getOwner());

        if (onApply != null) {
            onApply.run();
        }
        dispose();
    }

    private void loadFromSettings() {
        AppSettings s = AppSettings.get();
        sslVerification.setSelected(s.sslVerification);
        storeCookies.setSelected(s.storeCookies);
        sendCookies.setSelected(s.sendCookies);
        requestTimeoutSpinner.setValue(s.requestTimeoutMs);
        parallelismSpinner.setValue(s.parallelism);
        scanTimeoutSpinner.setValue(s.scanTimeoutMinutes);
        collectionsDir.setText(s.collectionsDir);
        autoSave.setSelected(s.autoSave);
        themeCombo.setSelectedItem(s.theme);
        fontSizeSpinner.setValue(s.fontSize);
        resolutionCombo.setSelectedItem(s.resolution);
        proxyEnabled.setSelected(s.proxyEnabled);
        proxyProtocol.setSelectedItem(s.proxyProtocol);
        proxyHost.setText(s.proxyHost);
        proxyPort.setValue(s.proxyPort);
        proxyUser.setText(s.proxyUser);
        proxyPass.setText(s.proxyPass);
        keepDefaultCa.setSelected(s.keepDefaultCa);
        caCertPath.setText(s.caCertPath);
        notifyScanComplete.setSelected(s.notifyScanComplete);
        notifyCriticalFinding.setSelected(s.notifyCriticalFinding);
        parallelism = s.parallelism;
        timeoutMinutes = s.scanTimeoutMinutes;

        certTableModel.setRowCount(0);
        for (AppSettings.CertData cd : s.clientCerts) {
            certTableModel.addRow(new Object[]{cd.enabled, cd.domain, cd.type, cd.certFile, cd.keyFile, cd.passphrase});
        }
    }

    private void saveToSettings() {
        AppSettings s = AppSettings.get();
        s.sslVerification = sslVerification.isSelected();
        s.storeCookies = storeCookies.isSelected();
        s.sendCookies = sendCookies.isSelected();
        s.requestTimeoutMs = (Integer) requestTimeoutSpinner.getValue();
        s.parallelism = (Integer) parallelismSpinner.getValue();
        s.scanTimeoutMinutes = (Integer) scanTimeoutSpinner.getValue();
        s.collectionsDir = collectionsDir.getText();
        s.autoSave = autoSave.isSelected();
        s.theme = (String) themeCombo.getSelectedItem();
        s.fontSize = (Integer) fontSizeSpinner.getValue();
        s.resolution = (String) resolutionCombo.getSelectedItem();
        s.proxyEnabled = proxyEnabled.isSelected();
        s.proxyProtocol = (String) proxyProtocol.getSelectedItem();
        s.proxyHost = proxyHost.getText();
        s.proxyPort = (Integer) proxyPort.getValue();
        s.proxyUser = proxyUser.getText();
        s.proxyPass = new String(proxyPass.getPassword());
        s.keepDefaultCa = keepDefaultCa.isSelected();
        s.caCertPath = caCertPath.getText().trim();
        s.notifyScanComplete = notifyScanComplete.isSelected();
        s.notifyCriticalFinding = notifyCriticalFinding.isSelected();

        s.clientCerts.clear();
        for (int i = 0; i < certTableModel.getRowCount(); i++) {
            AppSettings.CertData cd = new AppSettings.CertData();
            cd.enabled = Boolean.TRUE.equals(certTableModel.getValueAt(i, 0));
            cd.domain = stringVal(certTableModel.getValueAt(i, 1));
            cd.type = stringVal(certTableModel.getValueAt(i, 2));
            cd.certFile = stringVal(certTableModel.getValueAt(i, 3));
            cd.keyFile = stringVal(certTableModel.getValueAt(i, 4));
            cd.passphrase = stringVal(certTableModel.getValueAt(i, 5));
            s.clientCerts.add(cd);
        }

        s.save();
    }

    private void browseCollectionsDir() {
        JFileChooser chooser = new JFileChooser(collectionsDir.getText());
        chooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
        if (chooser.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
            collectionsDir.setText(chooser.getSelectedFile().getAbsolutePath());
        }
    }

    private void doCheckForUpdates() {
        JButton src = findCheckButton();
        if (src != null) {
            src.setEnabled(false);
            src.setText("Checking...");
        }
        new Thread(() -> {
            try {
                java.net.http.HttpClient client = java.net.http.HttpClient.newBuilder()
                        .connectTimeout(java.time.Duration.ofSeconds(10)).build();
                java.net.http.HttpRequest req = java.net.http.HttpRequest.newBuilder()
                        .uri(java.net.URI.create("https://api.github.com/repos/effront/anarcry/releases/latest"))
                        .header("Accept", "application/vnd.github.v3+json")
                        .header("User-Agent", "AnarCry/" + Version.get()).GET().build();
                java.net.http.HttpResponse<String> resp = client.send(req,
                        java.net.http.HttpResponse.BodyHandlers.ofString());
                String body = resp.body();
                String latest = extractJsonField(body, "tag_name").replaceFirst("^v", "");
                String url = extractJsonField(body, "html_url");
                if (url.isEmpty()) {
                    url = "https://github.com/effront/anarcry/releases";
                }
                String current = Version.get();
                boolean hasUpdate = !latest.isEmpty() && !latest.equals(current);
                String releaseUrl = url;
                SwingUtilities.invokeLater(() -> {
                    if (src != null) {
                        src.setEnabled(true);
                        src.setText("Check for Updates");
                    }
                    if (hasUpdate) {
                        int choice = javax.swing.JOptionPane.showOptionDialog(this,
                                "Update available: v" + latest + " (current: v" + current + ")\n"
                                        + "Open release page?",
                                "Update Available", javax.swing.JOptionPane.YES_NO_OPTION,
                                javax.swing.JOptionPane.INFORMATION_MESSAGE, null, new String[]{"Open", "Later"},
                                "Open");
                        if (choice == 0) {
                            try {
                                java.awt.Desktop.getDesktop().browse(java.net.URI.create(releaseUrl));
                            } catch (Exception ignored) {
                            }
                        }
                    } else if (latest.isEmpty()) {
                        javax.swing.JOptionPane.showMessageDialog(this, "Could not determine latest version.",
                                "Update Check", javax.swing.JOptionPane.WARNING_MESSAGE);
                    } else {
                        javax.swing.JOptionPane.showMessageDialog(this,
                                "You are running the latest version (v" + current + ").", "Up to Date",
                                javax.swing.JOptionPane.INFORMATION_MESSAGE);
                    }
                });
            } catch (Exception ex) {
                SwingUtilities.invokeLater(() -> {
                    if (src != null) {
                        src.setEnabled(true);
                        src.setText("Check for Updates");
                    }
                    javax.swing.JOptionPane.showMessageDialog(this, "Failed to check for updates:\n" + ex.getMessage(),
                            "Update Error", javax.swing.JOptionPane.ERROR_MESSAGE);
                });
            }
        }, "update-check").start();
    }

    private JButton findCheckButton() {
        java.awt.Container parent = getContentPane();
        return findButtonRecursive(parent, "Checking...", "Check for Updates");
    }

    private static JButton findButtonRecursive(java.awt.Container c, String... texts) {
        for (java.awt.Component comp : c.getComponents()) {
            if (comp instanceof JButton btn) {
                for (String t : texts) {
                    if (t.equals(btn.getText())) {
                        return btn;
                    }
                }
            }
            if (comp instanceof java.awt.Container sub) {
                JButton found = findButtonRecursive(sub, texts);
                if (found != null) {
                    return found;
                }
            }
        }
        return null;
    }

    private static String extractJsonField(String json, String field) {
        String key = "\"" + field + "\"";
        int idx = json.indexOf(key);
        if (idx < 0) {
            return "";
        }
        int colon = json.indexOf(':', idx + key.length());
        if (colon < 0) {
            return "";
        }
        int start = json.indexOf('"', colon + 1);
        if (start < 0) {
            return "";
        }
        int end = json.indexOf('"', start + 1);
        if (end < 0) {
            return "";
        }
        return json.substring(start + 1, end);
    }

    private static void applyGlobalFontSize(int size) {
        java.util.Enumeration<Object> keys = javax.swing.UIManager.getDefaults().keys();
        while (keys.hasMoreElements()) {
            Object key = keys.nextElement();
            Object val = javax.swing.UIManager.get(key);
            if (val instanceof javax.swing.plaf.FontUIResource orig) {
                javax.swing.UIManager.put(key, new javax.swing.plaf.FontUIResource(orig.deriveFont((float) size)));
            }
        }
    }

    private static JLabel hyperlink(String text, String url) {
        JLabel label = new JLabel("<html><u>" + text + "</u></html>");
        label.setForeground(new Color(0x58, 0xA6, 0xFF));
        label.setCursor(java.awt.Cursor.getPredefinedCursor(java.awt.Cursor.HAND_CURSOR));
        label.addMouseListener(new java.awt.event.MouseAdapter() {

            @Override
            public void mouseClicked(java.awt.event.MouseEvent e) {
                try {
                    java.awt.Desktop.getDesktop().browse(java.net.URI.create(url));
                } catch (Exception ignored) {
                }
            }
        });
        return label;
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
