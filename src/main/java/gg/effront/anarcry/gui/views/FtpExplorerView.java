package gg.effront.anarcry.gui.views;

import gg.effront.anarcry.gui.theme.AnarCryLaf;
import gg.effront.anarcry.postexploit.ftpexplorer.AnonDetector;
import gg.effront.anarcry.postexploit.ftpexplorer.AnonDetector.AnonResult;
import gg.effront.anarcry.postexploit.ftpexplorer.BannerFingerprinter;
import gg.effront.anarcry.postexploit.ftpexplorer.BannerFingerprinter.FingerprintResult;
import gg.effront.anarcry.postexploit.ftpexplorer.BannerFingerprinter.KnownVuln;
import gg.effront.anarcry.postexploit.ftpexplorer.FtpClient;
import gg.effront.anarcry.postexploit.ftpexplorer.FtpClient.FileEntry;
import gg.effront.anarcry.postexploit.ftpexplorer.FtpClient.FtpConfig;
import gg.effront.anarcry.postexploit.ftpexplorer.PasvAnalyzer;
import gg.effront.anarcry.postexploit.ftpexplorer.PasvAnalyzer.PasvResult;
import gg.effront.anarcry.postexploit.ftpexplorer.SensitiveFileScanner;
import gg.effront.anarcry.postexploit.ftpexplorer.SensitiveFileScanner.SensitiveFile;
import gg.effront.anarcry.postexploit.ftpexplorer.SftpClient;
import gg.effront.anarcry.postexploit.ftpexplorer.SftpClient.SftpConfig;
import gg.effront.anarcry.postexploit.ftpexplorer.TlsAuditor;
import gg.effront.anarcry.postexploit.ftpexplorer.TlsAuditor.SftpAuditResult;
import gg.effront.anarcry.postexploit.ftpexplorer.TlsAuditor.TlsAuditResult;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Dialog;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.Toolkit;
import java.awt.Window;
import java.awt.datatransfer.StringSelection;
import java.awt.event.ActionEvent;
import java.awt.event.InputEvent;
import java.awt.event.KeyEvent;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.nio.file.Path;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.function.Consumer;

import javax.swing.AbstractAction;
import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JComponent;
import javax.swing.JDialog;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JMenuItem;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.JPopupMenu;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTabbedPane;
import javax.swing.JTable;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.JToolBar;
import javax.swing.JTree;
import javax.swing.KeyStroke;
import javax.swing.SwingUtilities;
import javax.swing.UIManager;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.event.TreeExpansionEvent;
import javax.swing.event.TreeWillExpandListener;
import javax.swing.table.DefaultTableModel;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.DefaultTreeCellRenderer;
import javax.swing.tree.DefaultTreeModel;
import javax.swing.tree.TreeNode;
import javax.swing.tree.TreePath;

/**
 * Swing GUI view for the AnarCry FTP/SFTP Explorer. Supports multiple
 * simultaneous connections with per-session file browsing, sensitive file
 * scanning, banner fingerprinting, TLS/SSH auditing, and raw command execution.
 * Inspired by FileZilla's Site Manager and multi-tab pattern.
 */
public class FtpExplorerView extends JPanel {

    private static final int DEFAULT_FTP_PORT = 21;
    private static final int DEFAULT_SFTP_PORT = 22;
    private static final int LEFT_PANEL_WIDTH = 280;
    private static final int TIMEOUT_MS = 10_000;
    private static final DateTimeFormatter TS_FMT = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")
            .withZone(ZoneId.systemDefault());

    // -------------------------------------------------------------------------
    // Per-session state
    // -------------------------------------------------------------------------

    private static class FtpSession {
        String name;
        String protocol; // "FTP", "FTPS", "SFTP"
        String host;
        int port;
        String username;
        String password;
        String keyPath = "";
        boolean passive = true;
        boolean discovered;
        volatile boolean connected;

        FtpClient ftpClient;
        SftpClient sftpClient;

        DefaultMutableTreeNode treeNode;
        String currentPath = "/";

        // Per-session content buffers
        final StringBuilder logBuffer = new StringBuilder();
        String fingerprintText = "";
        final List<Object[]> cvesData = new ArrayList<>();
        String tlsAuditText = "";
        final List<Object[]> sensitiveData = new ArrayList<>();
        final StringBuilder rawOutputBuffer = new StringBuilder();

        String displayName() {
            return name != null && !name.isBlank() ? name : protocol + " @ " + host + ":" + port;
        }

        @Override
        public String toString() {
            return displayName();
        }
    }

    // -------------------------------------------------------------------------
    // UI components
    // -------------------------------------------------------------------------

    // Session tree (left panel)
    private DefaultMutableTreeNode rootNode;
    private DefaultTreeModel treeModel;
    private JTree mainTree;

    // Session toolbar
    private JButton removeButton;
    private JButton connectToggleButton;
    private JButton quickScanButton;

    // Path bar and status
    private JTextField pathField;
    private JLabel statusLabel;

    // Right tabs
    private JTabbedPane rightTabs;
    private JTextArea fileInfoArea;
    private JTextArea logArea;
    private DefaultTableModel sensitiveTableModel;
    private JTextArea fingerprintArea;
    private DefaultTableModel cvesTableModel;
    private JTextArea tlsAuditArea;
    private JTextField rawCommandField;
    private JTextArea rawCommandOutput;

    // Session management
    private final List<FtpSession> sessions = new ArrayList<>();
    private FtpSession activeSession;

    // -------------------------------------------------------------------------
    // Constructor
    // -------------------------------------------------------------------------

    public FtpExplorerView() {
        super(new BorderLayout());
        JSplitPane split = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, buildLeftPanel(), buildRightPanel());
        split.setDividerLocation(LEFT_PANEL_WIDTH);
        split.setResizeWeight(0.25);
        add(split, BorderLayout.CENTER);
        AnarCryLaf.addThemeListener(this::onThemeChanged);
        loadSavedConnections();
    }

    // -------------------------------------------------------------------------
    // Left panel -- session tree with toolbar
    // -------------------------------------------------------------------------

    private JPanel buildLeftPanel() {
        JPanel panel = new JPanel(new BorderLayout());

        JToolBar toolbar = new JToolBar();
        toolbar.setFloatable(false);
        toolbar.setBorder(BorderFactory.createEmptyBorder(2, 4, 2, 4));

        JButton addButton = new JButton("+");
        addButton.setToolTipText("New Connection");
        addButton.addActionListener(e -> showConnectionDialog(null));

        removeButton = new JButton("-");
        removeButton.setToolTipText("Remove Session");
        removeButton.setEnabled(false);
        removeButton.addActionListener(e -> removeActiveSession());

        connectToggleButton = new JButton("Connect");
        connectToggleButton.setEnabled(false);
        connectToggleButton.addActionListener(e -> toggleConnection());

        quickScanButton = new JButton("Quick Scan");
        quickScanButton.setEnabled(false);
        quickScanButton.addActionListener(e -> runQuickScan());

        toolbar.add(addButton);
        toolbar.add(removeButton);
        toolbar.addSeparator();
        toolbar.add(connectToggleButton);
        toolbar.add(quickScanButton);

        panel.add(toolbar, BorderLayout.NORTH);

        rootNode = new DefaultMutableTreeNode("Connections");
        treeModel = new DefaultTreeModel(rootNode);
        mainTree = new JTree(treeModel);
        mainTree.setRootVisible(false);
        mainTree.setShowsRootHandles(true);
        mainTree.setCellRenderer(new SessionFileTreeCellRenderer());
        mainTree.addTreeSelectionListener(e -> onTreeSelectionChanged());
        mainTree.addTreeWillExpandListener(new LazyExpandListener());
        installTreeMouseListeners();

        panel.add(new JScrollPane(mainTree), BorderLayout.CENTER);
        return panel;
    }

    // -------------------------------------------------------------------------
    // Right panel -- path bar + status + tabbed pane
    // -------------------------------------------------------------------------

    private JPanel buildRightPanel() {
        JPanel panel = new JPanel(new BorderLayout());

        JPanel topBar = new JPanel(new BorderLayout(4, 0));
        topBar.setBorder(BorderFactory.createEmptyBorder(4, 4, 4, 4));

        pathField = new JTextField("/");
        pathField.addActionListener(e -> navigateToPath(pathField.getText().trim()));

        JPanel navButtons = new JPanel(new FlowLayout(FlowLayout.LEFT, 2, 0));
        JButton upButton = new JButton("Up");
        upButton.addActionListener(e -> navigateUp());
        JButton refreshButton = new JButton("Refresh");
        refreshButton.addActionListener(e -> refreshCurrentPath());
        JButton downloadButton = new JButton("Download");
        downloadButton.addActionListener(e -> downloadSelected());
        navButtons.add(upButton);
        navButtons.add(refreshButton);
        navButtons.add(downloadButton);

        statusLabel = new JLabel("No session selected");
        statusLabel.setBorder(BorderFactory.createEmptyBorder(2, 0, 0, 0));

        JPanel pathRow = new JPanel(new BorderLayout(4, 0));
        pathRow.add(pathField, BorderLayout.CENTER);
        pathRow.add(navButtons, BorderLayout.EAST);

        topBar.add(pathRow, BorderLayout.CENTER);
        topBar.add(statusLabel, BorderLayout.SOUTH);
        panel.add(topBar, BorderLayout.NORTH);
        panel.add(buildRightTabs(), BorderLayout.CENTER);

        return panel;
    }

    private JTabbedPane buildRightTabs() {
        rightTabs = new JTabbedPane();

        fileInfoArea = createReadOnlyTextArea();
        rightTabs.addTab("File Info", new JScrollPane(fileInfoArea));

        logArea = createReadOnlyTextArea();
        rightTabs.addTab("Log", new JScrollPane(logArea));

        rightTabs.addTab("Sensitive Files", buildSensitiveFilesTab());
        rightTabs.addTab("Fingerprint", buildFingerprintTab());

        tlsAuditArea = createReadOnlyTextArea();
        rightTabs.addTab("TLS Audit", new JScrollPane(tlsAuditArea));

        rightTabs.addTab("Raw Command", buildRawCommandTab());

        return rightTabs;
    }

    private JPanel buildSensitiveFilesTab() {
        JPanel panel = new JPanel(new BorderLayout());
        sensitiveTableModel = new DefaultTableModel(new String[]{"Path", "Category", "Size", "Match Reason"}, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }
        };
        JTable sensitiveTable = new JTable(sensitiveTableModel);
        sensitiveTable.setAutoCreateRowSorter(true);
        panel.add(new JScrollPane(sensitiveTable), BorderLayout.CENTER);

        JPanel bottomBar = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JButton scanButton = new JButton("Scan Sensitive Files");
        scanButton.addActionListener(e -> runSensitiveScan("/"));
        bottomBar.add(scanButton);
        panel.add(bottomBar, BorderLayout.SOUTH);

        return panel;
    }

    private JPanel buildFingerprintTab() {
        JPanel panel = new JPanel(new BorderLayout());

        fingerprintArea = createReadOnlyTextArea();
        JScrollPane infoScroll = new JScrollPane(fingerprintArea);
        infoScroll.setPreferredSize(new Dimension(0, 120));

        cvesTableModel = new DefaultTableModel(new String[]{"CVE", "Title", "Severity", "Description"}, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }
        };
        JTable cvesTable = new JTable(cvesTableModel);
        cvesTable.setAutoCreateRowSorter(true);

        JPanel pasvPanel = new JPanel(new BorderLayout());
        JButton runPasvButton = new JButton("Run PASV Analysis");
        runPasvButton.addActionListener(e -> runPasvAnalysis());
        pasvPanel.add(runPasvButton, BorderLayout.NORTH);

        JSplitPane fpSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT, infoScroll, new JScrollPane(cvesTable));
        fpSplit.setResizeWeight(0.3);
        panel.add(fpSplit, BorderLayout.CENTER);
        panel.add(pasvPanel, BorderLayout.SOUTH);

        return panel;
    }

    private JPanel buildRawCommandTab() {
        JPanel panel = new JPanel(new BorderLayout());

        JPanel inputBar = new JPanel(new BorderLayout(4, 0));
        inputBar.setBorder(BorderFactory.createEmptyBorder(4, 4, 4, 4));
        rawCommandField = new JTextField();
        JButton sendButton = new JButton("Send");
        sendButton.addActionListener(e -> sendRawCommand());
        inputBar.add(rawCommandField, BorderLayout.CENTER);
        inputBar.add(sendButton, BorderLayout.EAST);

        rawCommandField.getInputMap(JComponent.WHEN_FOCUSED).put(KeyStroke.getKeyStroke(KeyEvent.VK_ENTER, 0),
                "sendCmd");
        rawCommandField.getActionMap().put("sendCmd", new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                sendRawCommand();
            }
        });

        rawCommandField.getInputMap(JComponent.WHEN_FOCUSED)
                .put(KeyStroke.getKeyStroke(KeyEvent.VK_L, InputEvent.CTRL_DOWN_MASK), "clearCmd");
        rawCommandField.getActionMap().put("clearCmd", new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                rawCommandOutput.setText("");
                if (activeSession != null) {
                    activeSession.rawOutputBuffer.setLength(0);
                }
            }
        });

        rawCommandOutput = createReadOnlyTextArea();
        panel.add(inputBar, BorderLayout.NORTH);
        panel.add(new JScrollPane(rawCommandOutput), BorderLayout.CENTER);

        return panel;
    }

    // -------------------------------------------------------------------------
    // Connection dialog -- new and edit
    // -------------------------------------------------------------------------

    @SuppressWarnings("methodlength")
    private void showConnectionDialog(FtpSession existing) {
        Window owner = SwingUtilities.getWindowAncestor(this);
        String title = existing == null ? "New Connection" : "Edit Connection";
        JDialog dialog = new JDialog(owner, title, Dialog.ModalityType.APPLICATION_MODAL);
        dialog.setLayout(new BorderLayout(8, 8));

        JPanel form = new JPanel(new GridBagLayout());
        form.setBorder(BorderFactory.createEmptyBorder(8, 12, 4, 12));
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(3, 4, 3, 4);
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.anchor = GridBagConstraints.WEST;

        int row = 0;

        // Name
        gbc.gridx = 0;
        gbc.gridy = row;
        form.add(new JLabel("Name:"), gbc);
        gbc.gridx = 1;
        gbc.gridwidth = 3;
        gbc.weightx = 1.0;
        JTextField nameField = new JTextField(existing != null ? existing.name : "", 24);
        form.add(nameField, gbc);
        gbc.gridwidth = 1;
        gbc.weightx = 0;

        // Protocol
        row++;
        gbc.gridx = 0;
        gbc.gridy = row;
        form.add(new JLabel("Protocol:"), gbc);
        gbc.gridx = 1;
        JComboBox<String> protocolCombo = new JComboBox<>(new String[]{"FTP", "FTPS", "SFTP"});
        if (existing != null) {
            protocolCombo.setSelectedItem(existing.protocol);
        }
        form.add(protocolCombo, gbc);

        // Host
        gbc.gridx = 2;
        form.add(new JLabel("Host:"), gbc);
        gbc.gridx = 3;
        gbc.weightx = 1.0;
        JTextField hostField = new JTextField(existing != null ? existing.host : "", 16);
        form.add(hostField, gbc);
        gbc.weightx = 0;

        // Port + Username
        row++;
        gbc.gridx = 0;
        gbc.gridy = row;
        form.add(new JLabel("Port:"), gbc);
        gbc.gridx = 1;
        int defPort = existing != null ? existing.port : DEFAULT_FTP_PORT;
        JTextField portField = new JTextField(String.valueOf(defPort), 5);
        form.add(portField, gbc);

        gbc.gridx = 2;
        form.add(new JLabel("Username:"), gbc);
        gbc.gridx = 3;
        gbc.weightx = 1.0;
        JTextField usernameField = new JTextField(existing != null ? existing.username : "", 12);
        form.add(usernameField, gbc);
        gbc.weightx = 0;

        // Password
        row++;
        gbc.gridx = 0;
        gbc.gridy = row;
        form.add(new JLabel("Password:"), gbc);
        gbc.gridx = 1;
        gbc.gridwidth = 3;
        gbc.weightx = 1.0;
        JPasswordField passwordField = new JPasswordField(20);
        if (existing != null && existing.password != null && !existing.password.isEmpty()) {
            passwordField.setText(existing.password);
        }
        form.add(passwordField, gbc);
        gbc.gridwidth = 1;
        gbc.weightx = 0;

        // SSH key path
        row++;
        gbc.gridx = 0;
        gbc.gridy = row;
        form.add(new JLabel("SSH Key:"), gbc);
        gbc.gridx = 1;
        gbc.gridwidth = 2;
        gbc.weightx = 1.0;
        JTextField keyPathField = new JTextField(existing != null ? existing.keyPath : "", 20);
        form.add(keyPathField, gbc);
        gbc.gridwidth = 1;
        gbc.weightx = 0;
        gbc.gridx = 3;
        JButton browseBtn = new JButton("Browse");
        browseBtn.addActionListener(e -> {
            JFileChooser fc = new JFileChooser();
            fc.setDialogTitle("Select SSH Private Key");
            if (fc.showOpenDialog(dialog) == JFileChooser.APPROVE_OPTION) {
                keyPathField.setText(fc.getSelectedFile().getAbsolutePath());
            }
        });
        form.add(browseBtn, gbc);

        // Passive mode
        row++;
        gbc.gridx = 1;
        gbc.gridy = row;
        gbc.gridwidth = 2;
        JCheckBox passiveCheck = new JCheckBox("Passive mode", existing == null || existing.passive);
        form.add(passiveCheck, gbc);
        gbc.gridwidth = 1;

        // Initial SFTP field state
        boolean initSftp = "SFTP".equals(protocolCombo.getSelectedItem());
        keyPathField.setEnabled(initSftp);
        browseBtn.setEnabled(initSftp);
        passiveCheck.setEnabled(!initSftp);

        // Protocol change -- toggle fields and auto-name
        protocolCombo.addActionListener(e -> {
            String sel = (String) protocolCombo.getSelectedItem();
            boolean sftp = "SFTP".equals(sel);
            keyPathField.setEnabled(sftp);
            browseBtn.setEnabled(sftp);
            passiveCheck.setEnabled(!sftp);
            portField.setText(String.valueOf(sftp ? DEFAULT_SFTP_PORT : DEFAULT_FTP_PORT));
            autoFillName(nameField, hostField, portField, protocolCombo);
        });

        // Auto-fill name on host/port change
        DocumentListener autoName = new DocumentListener() {
            @Override
            public void insertUpdate(DocumentEvent e) {
                autoFillName(nameField, hostField, portField, protocolCombo);
            }

            @Override
            public void removeUpdate(DocumentEvent e) {
                autoFillName(nameField, hostField, portField, protocolCombo);
            }

            @Override
            public void changedUpdate(DocumentEvent e) {
                autoFillName(nameField, hostField, portField, protocolCombo);
            }
        };
        hostField.getDocument().addDocumentListener(autoName);
        portField.getDocument().addDocumentListener(autoName);

        dialog.add(form, BorderLayout.CENTER);

        // Buttons
        JPanel buttonBar = new JPanel(new FlowLayout(FlowLayout.RIGHT, 6, 6));

        JButton testButton = new JButton("Test Connection");
        testButton.addActionListener(e -> onTestConnection(dialog, testButton, protocolCombo, hostField, portField,
                usernameField, passwordField, keyPathField, passiveCheck));

        JButton saveButton = new JButton("Save");
        saveButton.addActionListener(e -> onDialogSave(dialog, existing, nameField, protocolCombo, hostField, portField,
                usernameField, keyPathField, passiveCheck));

        JButton connectButton = new JButton("Connect");
        connectButton.addActionListener(e -> onDialogConnect(dialog, existing, nameField, protocolCombo, hostField,
                portField, usernameField, passwordField, keyPathField, passiveCheck));

        JButton cancelButton = new JButton("Cancel");
        cancelButton.addActionListener(e -> dialog.dispose());

        buttonBar.add(testButton);
        buttonBar.add(saveButton);
        buttonBar.add(connectButton);
        buttonBar.add(cancelButton);
        dialog.add(buttonBar, BorderLayout.SOUTH);

        dialog.pack();
        dialog.setMinimumSize(new Dimension(620, 440));
        dialog.setSize(Math.max(dialog.getWidth(), 620), Math.max(dialog.getHeight(), 440));
        dialog.setLocationRelativeTo(this);
        dialog.setVisible(true);
    }

    private static void autoFillName(JTextField nameField, JTextField hostField, JTextField portField,
            JComboBox<String> protocolCombo) {
        String h = hostField.getText().trim();
        if (h.isEmpty()) {
            return;
        }
        String current = nameField.getText().trim();
        String proto = (String) protocolCombo.getSelectedItem();
        String p = portField.getText().trim();
        String generated = proto + " @ " + h + ":" + p;
        if (current.isEmpty() || current.startsWith("FTP @ ") || current.startsWith("FTPS @ ")
                || current.startsWith("SFTP @ ")) {
            nameField.setText(generated);
        }
    }

    // -------------------------------------------------------------------------
    // Dialog button actions
    // -------------------------------------------------------------------------

    private void onTestConnection(JDialog dialog, JButton testButton, JComboBox<String> protocolCombo,
            JTextField hostField, JTextField portField, JTextField usernameField, JPasswordField passwordField,
            JTextField keyPathField, JCheckBox passiveCheck) {
        String host = hostField.getText().trim();
        if (host.isBlank()) {
            JOptionPane.showMessageDialog(dialog, "Host is required.", "Validation", JOptionPane.WARNING_MESSAGE);
            return;
        }
        int port;
        try {
            port = Integer.parseInt(portField.getText().trim());
        } catch (NumberFormatException ex) {
            JOptionPane.showMessageDialog(dialog, "Invalid port.", "Validation", JOptionPane.WARNING_MESSAGE);
            return;
        }
        testButton.setEnabled(false);
        testButton.setText("Testing...");
        String proto = (String) protocolCombo.getSelectedItem();
        String user = usernameField.getText().trim();
        String pass = new String(passwordField.getPassword());
        String key = keyPathField.getText().trim();
        boolean passive = passiveCheck.isSelected();

        Thread.ofVirtual().name("ftp-test-conn").start(() -> {
            try {
                testConnection(proto, host, port, user, pass, key, passive);
                SwingUtilities.invokeLater(() -> {
                    JOptionPane.showMessageDialog(dialog, "Connection successful!", "Test",
                            JOptionPane.INFORMATION_MESSAGE);
                    testButton.setEnabled(true);
                    testButton.setText("Test Connection");
                });
            } catch (Exception ex) {
                SwingUtilities.invokeLater(() -> {
                    JOptionPane.showMessageDialog(dialog, "Connection failed: " + ex.getMessage(), "Test",
                            JOptionPane.ERROR_MESSAGE);
                    testButton.setEnabled(true);
                    testButton.setText("Test Connection");
                });
            }
        });
    }

    private void onDialogSave(JDialog dialog, FtpSession existing, JTextField nameField,
            JComboBox<String> protocolCombo, JTextField hostField, JTextField portField, JTextField usernameField,
            JTextField keyPathField, JCheckBox passiveCheck) {
        String host = hostField.getText().trim();
        if (host.isBlank()) {
            JOptionPane.showMessageDialog(dialog, "Host is required.", "Validation", JOptionPane.WARNING_MESSAGE);
            return;
        }
        int port;
        try {
            port = Integer.parseInt(portField.getText().trim());
        } catch (NumberFormatException ex) {
            JOptionPane.showMessageDialog(dialog, "Invalid port.", "Validation", JOptionPane.WARNING_MESSAGE);
            return;
        }
        String proto = (String) protocolCombo.getSelectedItem();
        String user = usernameField.getText().trim();
        String key = keyPathField.getText().trim();
        boolean passive = passiveCheck.isSelected();
        String name = nameField.getText().trim();

        dialog.dispose();

        if (existing != null) {
            existing.name = name;
            existing.protocol = proto;
            existing.host = host;
            existing.port = port;
            existing.username = user;
            existing.keyPath = key;
            existing.passive = passive;
            existing.discovered = false;
            treeModel.nodeChanged(existing.treeNode);
        } else {
            FtpSession session = createSession(name, proto, host, port, user, key, passive);
            setActiveSession(session);
        }
        persistConnections();
    }

    private void onDialogConnect(JDialog dialog, FtpSession existing, JTextField nameField,
            JComboBox<String> protocolCombo, JTextField hostField, JTextField portField, JTextField usernameField,
            JPasswordField passwordField, JTextField keyPathField, JCheckBox passiveCheck) {
        String host = hostField.getText().trim();
        if (host.isBlank()) {
            JOptionPane.showMessageDialog(dialog, "Host is required.", "Validation", JOptionPane.WARNING_MESSAGE);
            return;
        }
        int port;
        try {
            port = Integer.parseInt(portField.getText().trim());
        } catch (NumberFormatException ex) {
            JOptionPane.showMessageDialog(dialog, "Invalid port.", "Validation", JOptionPane.WARNING_MESSAGE);
            return;
        }
        String proto = (String) protocolCombo.getSelectedItem();
        String user = usernameField.getText().trim();
        String pass = new String(passwordField.getPassword());
        String key = keyPathField.getText().trim();
        boolean passive = passiveCheck.isSelected();
        String name = nameField.getText().trim();

        dialog.dispose();

        if (existing != null) {
            existing.name = name;
            existing.protocol = proto;
            existing.host = host;
            existing.port = port;
            existing.username = user;
            existing.keyPath = key;
            existing.passive = passive;
            existing.discovered = false;
            treeModel.nodeChanged(existing.treeNode);
            if (existing.connected) {
                doDisconnect(existing);
            }
            doConnect(existing, pass);
        } else {
            FtpSession session = createSession(name, proto, host, port, user, key, passive);
            setActiveSession(session);
            doConnect(session, pass);
        }
        persistConnections();
    }

    // -------------------------------------------------------------------------
    // Session management
    // -------------------------------------------------------------------------

    private FtpSession createSession(String name, String protocol, String host, int port, String username,
            String keyPath, boolean passive) {
        FtpSession session = new FtpSession();
        session.name = name.isBlank() ? protocol + " @ " + host + ":" + port : name;
        session.protocol = protocol;
        session.host = host;
        session.port = port;
        session.username = username;
        session.keyPath = keyPath;
        session.passive = passive;

        session.treeNode = new DefaultMutableTreeNode(session);
        session.treeNode.add(new DefaultMutableTreeNode("(not connected)"));

        sessions.add(session);
        rootNode.add(session.treeNode);
        treeModel.reload(rootNode);

        TreePath treePath = new TreePath(session.treeNode.getPath());
        mainTree.expandPath(treePath);
        mainTree.setSelectionPath(treePath);

        return session;
    }

    private void removeActiveSession() {
        if (activeSession == null) {
            return;
        }
        FtpSession session = activeSession;
        String msg = session.connected
                ? "Session \"" + session.name + "\" is connected. Disconnect and remove?"
                : "Remove session \"" + session.name + "\"?";
        int choice = javax.swing.JOptionPane.showConfirmDialog(this, msg, "Remove Session",
                javax.swing.JOptionPane.YES_NO_OPTION);
        if (choice != javax.swing.JOptionPane.YES_OPTION) {
            return;
        }
        if (session.connected) {
            doDisconnect(session);
        }
        sessions.remove(session);
        rootNode.remove(session.treeNode);
        treeModel.reload(rootNode);

        activeSession = null;
        if (!sessions.isEmpty()) {
            setActiveSession(sessions.getLast());
        } else {
            clearAllContent();
            updateToolbarState();
        }
        persistConnections();
    }

    private void setActiveSession(FtpSession session) {
        if (session == activeSession) {
            return;
        }
        activeSession = session;
        if (session != null) {
            loadSessionContent(session);
            TreePath treePath = new TreePath(session.treeNode.getPath());
            mainTree.setSelectionPath(treePath);
        } else {
            clearAllContent();
        }
        updateToolbarState();
    }

    private void loadSessionContent(FtpSession session) {
        logArea.setText(session.logBuffer.toString());
        if (logArea.getDocument().getLength() > 0) {
            logArea.setCaretPosition(logArea.getDocument().getLength());
        }

        fingerprintArea.setText(session.fingerprintText);
        if (!session.fingerprintText.isEmpty()) {
            fingerprintArea.setCaretPosition(0);
        }

        cvesTableModel.setRowCount(0);
        for (Object[] r : session.cvesData) {
            cvesTableModel.addRow(r);
        }

        tlsAuditArea.setText(session.tlsAuditText);
        if (!session.tlsAuditText.isEmpty()) {
            tlsAuditArea.setCaretPosition(0);
        }

        sensitiveTableModel.setRowCount(0);
        for (Object[] r : session.sensitiveData) {
            sensitiveTableModel.addRow(r);
        }

        rawCommandOutput.setText(session.rawOutputBuffer.toString());
        if (rawCommandOutput.getDocument().getLength() > 0) {
            rawCommandOutput.setCaretPosition(rawCommandOutput.getDocument().getLength());
        }

        pathField.setText(session.currentPath);
        fileInfoArea.setText("");
        statusLabel.setText(session.connected
                ? "Connected to " + session.host + ":" + session.port
                : "Disconnected -- " + session.displayName());
    }

    private void clearAllContent() {
        logArea.setText("");
        fingerprintArea.setText("");
        cvesTableModel.setRowCount(0);
        tlsAuditArea.setText("");
        sensitiveTableModel.setRowCount(0);
        rawCommandOutput.setText("");
        pathField.setText("/");
        fileInfoArea.setText("");
        statusLabel.setText("No session selected");
    }

    private void updateToolbarState() {
        boolean hasSession = activeSession != null;
        boolean isConnected = hasSession && activeSession.connected;
        removeButton.setEnabled(hasSession);
        connectToggleButton.setEnabled(hasSession);
        connectToggleButton.setText(isConnected ? "Disconnect" : "Connect");
        quickScanButton.setEnabled(isConnected);
    }

    // -------------------------------------------------------------------------
    // Connect / Disconnect
    // -------------------------------------------------------------------------

    private void toggleConnection() {
        if (activeSession == null) {
            return;
        }
        if (activeSession.connected) {
            doDisconnect(activeSession);
        } else {
            promptAndConnect(activeSession);
        }
    }

    private void promptAndConnect(FtpSession session) {
        if ("SFTP".equals(session.protocol) && !session.keyPath.isEmpty()) {
            doConnect(session, "");
            return;
        }
        JPasswordField passField = new JPasswordField(20);
        JPanel panel = new JPanel(new BorderLayout(4, 4));
        String userLabel = session.username.isEmpty() ? session.host : session.username + "@" + session.host;
        panel.add(new JLabel("Password for " + userLabel + ":"), BorderLayout.NORTH);
        panel.add(passField, BorderLayout.CENTER);

        int result = JOptionPane.showConfirmDialog(this, panel, "Connect -- " + session.displayName(),
                JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);
        if (result == JOptionPane.OK_OPTION) {
            doConnect(session, new String(passField.getPassword()));
        }
    }

    private void doConnect(FtpSession session, String password) {
        session.password = password;
        connectToggleButton.setEnabled(false);
        statusLabel.setText("Connecting...");

        Thread.ofVirtual().name("ftp-connect-" + session.host).start(() -> {
            Consumer<String> log = msg -> appendLog(session, msg);
            try {
                if ("SFTP".equals(session.protocol)) {
                    SftpConfig cfg = new SftpConfig(session.host, session.port, session.username, password,
                            session.keyPath, TIMEOUT_MS);
                    SftpClient client = new SftpClient(cfg);
                    client.connect(log);
                    session.sftpClient = client;
                } else {
                    boolean useFtps = "FTPS".equals(session.protocol);
                    FtpConfig cfg = new FtpConfig(session.host, session.port, session.username, password, useFtps,
                            session.passive, TIMEOUT_MS);
                    FtpClient client = new FtpClient(cfg);
                    client.connect(log);
                    session.ftpClient = client;
                }

                session.connected = true;

                SwingUtilities.invokeLater(() -> {
                    session.treeNode.removeAllChildren();
                    treeModel.reload(session.treeNode);
                    populateSessionRoot(session);
                    treeModel.nodeChanged(session.treeNode);
                    if (session == activeSession) {
                        statusLabel.setText("Connected to " + session.host + ":" + session.port);
                        updateToolbarState();
                    }
                });

                runFingerprint(session);
                runTlsAudit();

            } catch (Exception ex) {
                SwingUtilities.invokeLater(() -> {
                    if (session == activeSession) {
                        statusLabel.setText("Error: " + ex.getMessage());
                        updateToolbarState();
                    }
                });
                appendLog(session, "[!] Connection failed -- " + ex.getMessage());
            }
        });
    }

    private void doDisconnect(FtpSession session) {
        Thread.ofVirtual().name("ftp-disconnect-" + session.host).start(() -> {
            if (session.ftpClient != null) {
                session.ftpClient.disconnect();
                session.ftpClient = null;
            }
            if (session.sftpClient != null) {
                session.sftpClient.disconnect();
                session.sftpClient = null;
            }
            session.connected = false;
            session.password = "";

            SwingUtilities.invokeLater(() -> {
                session.treeNode.removeAllChildren();
                session.treeNode.add(new DefaultMutableTreeNode("(not connected)"));
                treeModel.reload(session.treeNode);
                treeModel.nodeChanged(session.treeNode);
                if (session == activeSession) {
                    statusLabel.setText("Disconnected");
                    updateToolbarState();
                }
            });
            appendLog(session, "[+] Disconnected");
        });
    }

    private void testConnection(String protocol, String host, int port, String username, String password,
            String keyPath, boolean passive) throws Exception {
        if ("SFTP".equals(protocol)) {
            SftpConfig cfg = new SftpConfig(host, port, username, password, keyPath, TIMEOUT_MS);
            try (SftpClient client = new SftpClient(cfg)) {
                client.connect(msg -> {
                });
            }
        } else {
            boolean useFtps = "FTPS".equals(protocol);
            FtpConfig cfg = new FtpConfig(host, port, username, password, useFtps, passive, TIMEOUT_MS);
            try (FtpClient client = new FtpClient(cfg)) {
                client.connect(msg -> {
                });
            }
        }
    }

    // -------------------------------------------------------------------------
    // File tree operations
    // -------------------------------------------------------------------------

    private void populateSessionRoot(FtpSession session) {
        session.currentPath = "/";
        loadChildren(session, session.treeNode, "/");
    }

    private void loadChildren(FtpSession session, DefaultMutableTreeNode parentNode, String remotePath) {
        Thread.ofVirtual().name("ftp-list-" + session.host).start(() -> {
            try {
                List<FileEntry> entries = listRemote(session, remotePath);
                SwingUtilities.invokeLater(() -> {
                    parentNode.removeAllChildren();
                    for (FileEntry entry : entries) {
                        DefaultMutableTreeNode child = new DefaultMutableTreeNode(entry);
                        parentNode.add(child);
                        if (entry.isDirectory()) {
                            child.add(new DefaultMutableTreeNode("Loading..."));
                        }
                    }
                    treeModel.reload(parentNode);
                    mainTree.expandPath(new TreePath(parentNode.getPath()));
                });
            } catch (Exception ex) {
                appendLog(session, "[!] Failed to list " + remotePath + " -- " + ex.getMessage());
            }
        });
    }

    private List<FileEntry> listRemote(FtpSession session, String path) throws Exception {
        Consumer<String> log = msg -> appendLog(session, msg);
        if (session.sftpClient != null) {
            return session.sftpClient.list(path, log);
        } else if (session.ftpClient != null) {
            return session.ftpClient.list(path, log);
        }
        return List.of();
    }

    private void navigateToPath(String path) {
        if (activeSession == null || !activeSession.connected || path.isBlank()) {
            return;
        }
        activeSession.currentPath = path;
        activeSession.treeNode.removeAllChildren();
        treeModel.reload(activeSession.treeNode);
        loadChildren(activeSession, activeSession.treeNode, path);
    }

    private void navigateUp() {
        if (activeSession == null) {
            return;
        }
        String current = pathField.getText().trim();
        if (current.equals("/") || current.isBlank()) {
            return;
        }
        int lastSlash = current.lastIndexOf('/');
        String parent = lastSlash <= 0 ? "/" : current.substring(0, lastSlash);
        pathField.setText(parent);
        navigateToPath(parent);
    }

    private void refreshCurrentPath() {
        if (activeSession == null) {
            return;
        }
        String current = pathField.getText().trim();
        if (current.isBlank()) {
            current = "/";
        }
        navigateToPath(current);
    }

    private void downloadSelected() {
        TreePath sel = mainTree.getSelectionPath();
        if (sel == null || activeSession == null || !activeSession.connected) {
            return;
        }
        DefaultMutableTreeNode node = (DefaultMutableTreeNode) sel.getLastPathComponent();
        Object userObj = node.getUserObject();
        if (!(userObj instanceof FileEntry entry) || entry.isDirectory()) {
            if (activeSession != null) {
                appendLog(activeSession, "[~] Select a file to download");
            }
            return;
        }

        JFileChooser chooser = new JFileChooser();
        chooser.setSelectedFile(new java.io.File(entry.name()));
        if (chooser.showSaveDialog(this) != JFileChooser.APPROVE_OPTION) {
            return;
        }

        Path localPath = chooser.getSelectedFile().toPath();
        String remotePath = buildRemotePath(sel);
        FtpSession session = activeSession;

        Thread.ofVirtual().name("ftp-download-" + session.host).start(() -> {
            try {
                Consumer<String> log = msg -> appendLog(session, msg);
                if (session.sftpClient != null) {
                    session.sftpClient.download(remotePath, localPath, log);
                } else if (session.ftpClient != null) {
                    session.ftpClient.download(remotePath, localPath, log);
                }
                appendLog(session, "[+] Download complete: " + localPath);
            } catch (Exception ex) {
                appendLog(session, "[!] Download failed -- " + ex.getMessage());
            }
        });
    }

    // -------------------------------------------------------------------------
    // Tree selection handling
    // -------------------------------------------------------------------------

    private void onTreeSelectionChanged() {
        TreePath sel = mainTree.getSelectionPath();
        if (sel == null) {
            return;
        }
        DefaultMutableTreeNode node = (DefaultMutableTreeNode) sel.getLastPathComponent();
        Object userObj = node.getUserObject();

        if (userObj instanceof FtpSession session) {
            if (session != activeSession) {
                setActiveSession(session);
            }
        } else if (userObj instanceof FileEntry entry) {
            FtpSession session = findSessionForNode(node);
            if (session != null && session != activeSession) {
                activeSession = session;
                loadSessionContent(session);
                updateToolbarState();
            }
            if (session != null) {
                String remotePath = buildRemotePath(sel);
                session.currentPath = entry.isDirectory() ? remotePath : parentPath(remotePath);
                pathField.setText(session.currentPath);
                showFileInfo(entry, remotePath);
            }
        }
    }

    private void showFileInfo(FileEntry entry, String fullPath) {
        StringBuilder sb = new StringBuilder();
        sb.append("Name:         ").append(entry.name()).append('\n');
        sb.append("Full Path:    ").append(fullPath).append('\n');
        sb.append("Type:         ").append(entry.isDirectory() ? "Directory" : "File").append('\n');
        sb.append("Size:         ").append(formatSize(entry.size())).append('\n');
        sb.append("Permissions:  ").append(entry.permissions()).append('\n');
        if (!Instant.EPOCH.equals(entry.lastModified())) {
            sb.append("Last Modified: ").append(TS_FMT.format(entry.lastModified())).append('\n');
        }
        fileInfoArea.setText(sb.toString());
        fileInfoArea.setCaretPosition(0);
    }

    // -------------------------------------------------------------------------
    // Lazy tree expansion
    // -------------------------------------------------------------------------

    private class LazyExpandListener implements TreeWillExpandListener {
        @Override
        public void treeWillExpand(TreeExpansionEvent event) {
            TreePath path = event.getPath();
            DefaultMutableTreeNode node = (DefaultMutableTreeNode) path.getLastPathComponent();
            Object userObj = node.getUserObject();

            if (userObj instanceof FtpSession session && session.connected) {
                if (hasPlaceholderChild(node)) {
                    loadChildren(session, node, "/");
                }
            } else if (userObj instanceof FileEntry entry && entry.isDirectory()) {
                FtpSession session = findSessionForNode(node);
                if (session != null && session.connected && hasPlaceholderChild(node)) {
                    String remotePath = buildRemotePath(path);
                    loadChildren(session, node, remotePath);
                }
            }
        }

        @Override
        public void treeWillCollapse(TreeExpansionEvent event) {
            // no-op
        }

        private boolean hasPlaceholderChild(DefaultMutableTreeNode node) {
            return node.getChildCount() == 1
                    && ((DefaultMutableTreeNode) node.getChildAt(0)).getUserObject() instanceof String;
        }
    }

    // -------------------------------------------------------------------------
    // Mouse listeners -- context menus and double-click
    // -------------------------------------------------------------------------

    private void installTreeMouseListeners() {
        JPopupMenu sessionMenu = buildSessionContextMenu();
        JPopupMenu fileMenu = buildFileContextMenu();

        mainTree.addMouseListener(new MouseAdapter() {
            @Override
            public void mousePressed(MouseEvent e) {
                handlePopup(e);
                handleDoubleClick(e);
            }

            @Override
            public void mouseReleased(MouseEvent e) {
                handlePopup(e);
            }

            private void handlePopup(MouseEvent e) {
                if (!e.isPopupTrigger()) {
                    return;
                }
                int row = mainTree.getClosestRowForLocation(e.getX(), e.getY());
                if (row < 0) {
                    return;
                }
                mainTree.setSelectionRow(row);
                TreePath path = mainTree.getPathForRow(row);
                if (path == null) {
                    return;
                }
                DefaultMutableTreeNode node = (DefaultMutableTreeNode) path.getLastPathComponent();
                if (node.getUserObject() instanceof FtpSession) {
                    sessionMenu.show(e.getComponent(), e.getX(), e.getY());
                } else if (node.getUserObject() instanceof FileEntry) {
                    fileMenu.show(e.getComponent(), e.getX(), e.getY());
                }
            }

            private void handleDoubleClick(MouseEvent e) {
                if (e.getClickCount() != 2 || e.isPopupTrigger()) {
                    return;
                }
                TreePath path = mainTree.getPathForLocation(e.getX(), e.getY());
                if (path == null) {
                    return;
                }
                DefaultMutableTreeNode node = (DefaultMutableTreeNode) path.getLastPathComponent();
                if (node.getUserObject() instanceof FtpSession session && !session.connected) {
                    setActiveSession(session);
                    promptAndConnect(session);
                }
            }
        });
    }

    private JPopupMenu buildSessionContextMenu() {
        JPopupMenu menu = new JPopupMenu();

        JMenuItem connectItem = new JMenuItem("Connect");
        connectItem.addActionListener(e -> {
            if (activeSession != null && !activeSession.connected) {
                promptAndConnect(activeSession);
            }
        });

        JMenuItem disconnectItem = new JMenuItem("Disconnect");
        disconnectItem.addActionListener(e -> {
            if (activeSession != null && activeSession.connected) {
                doDisconnect(activeSession);
            }
        });

        JMenuItem editItem = new JMenuItem("Edit");
        editItem.addActionListener(e -> {
            if (activeSession != null) {
                showConnectionDialog(activeSession);
            }
        });

        JMenuItem removeItem = new JMenuItem("Remove");
        removeItem.addActionListener(e -> removeActiveSession());

        JMenuItem quickScanItem = new JMenuItem("Quick Scan");
        quickScanItem.addActionListener(e -> runQuickScan());

        menu.add(connectItem);
        menu.add(disconnectItem);
        menu.addSeparator();
        menu.add(editItem);
        menu.add(removeItem);
        menu.addSeparator();
        menu.add(quickScanItem);

        return menu;
    }

    private JPopupMenu buildFileContextMenu() {
        JPopupMenu menu = new JPopupMenu();

        JMenuItem downloadItem = new JMenuItem("Download");
        downloadItem.addActionListener(e -> downloadSelected());

        JMenuItem scanFromHere = new JMenuItem("Scan from here");
        scanFromHere.addActionListener(e -> {
            TreePath sel = mainTree.getSelectionPath();
            if (sel != null) {
                runSensitiveScan(buildRemotePath(sel));
            }
        });

        JMenuItem copyPathItem = new JMenuItem("Copy path");
        copyPathItem.addActionListener(e -> {
            TreePath sel = mainTree.getSelectionPath();
            if (sel != null) {
                Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(buildRemotePath(sel)),
                        null);
            }
        });

        menu.add(downloadItem);
        menu.add(scanFromHere);
        menu.addSeparator();
        menu.add(copyPathItem);

        return menu;
    }

    // -------------------------------------------------------------------------
    // Quick Scan -- AnonDetector + BannerFingerprinter + SensitiveFileScanner
    // -------------------------------------------------------------------------

    private void runQuickScan() {
        if (activeSession == null || !activeSession.connected) {
            return;
        }
        FtpSession session = activeSession;
        quickScanButton.setEnabled(false);
        statusLabel.setText("Quick Scan running...");

        Thread.ofVirtual().name("ftp-quickscan-" + session.host).start(() -> {
            Consumer<String> log = msg -> appendLog(session, msg);
            try {
                if (!"SFTP".equals(session.protocol)) {
                    boolean tryFtps = "FTPS".equals(session.protocol);
                    AnonResult anon = AnonDetector.detect(session.host, session.port, tryFtps, log);
                    if (anon.accessible()) {
                        appendLog(session, "[!!] Anonymous FTP access found: " + anon.usedCredential());
                    }
                }

                runFingerprint(session);
                runTlsAudit();
                runSensitiveScanInternal(session, "/", log);

                SwingUtilities.invokeLater(() -> {
                    if (session == activeSession) {
                        statusLabel.setText("Quick Scan complete");
                    }
                });
            } catch (Exception ex) {
                appendLog(session, "[!] Quick Scan error -- " + ex.getMessage());
                SwingUtilities.invokeLater(() -> {
                    if (session == activeSession) {
                        statusLabel.setText("Quick Scan failed: " + ex.getMessage());
                    }
                });
            } finally {
                SwingUtilities.invokeLater(() -> {
                    if (session == activeSession) {
                        quickScanButton.setEnabled(session.connected);
                    }
                });
            }
        });
    }

    // -------------------------------------------------------------------------
    // Fingerprint
    // -------------------------------------------------------------------------

    private void runFingerprint(FtpSession session) {
        Consumer<String> log = msg -> appendLog(session, msg);
        try {
            if (session.ftpClient != null) {
                String banner = session.ftpClient.getBanner();
                String systType = session.ftpClient.getSystemType();
                Set<String> features = session.ftpClient.getFeatures();
                FingerprintResult fp = BannerFingerprinter.fingerprint(banner, systType, features, log);
                SwingUtilities.invokeLater(() -> displayFingerprint(session, fp, banner));
            } else if (session.sftpClient != null) {
                String version = session.sftpClient.getServerVersion();
                SwingUtilities.invokeLater(() -> {
                    StringBuilder sb = new StringBuilder();
                    sb.append("Protocol:    SFTP/SSH\n");
                    sb.append("Server:      ").append(version).append('\n');
                    sb.append("Host Key:    ").append(session.sftpClient.getHostKeyType()).append('\n');
                    sb.append("KEX:         ").append(session.sftpClient.getKexAlgorithms()).append('\n');
                    sb.append("Ciphers:     ").append(session.sftpClient.getCiphers()).append('\n');
                    sb.append("MACs:        ").append(session.sftpClient.getMacs()).append('\n');

                    session.fingerprintText = sb.toString();
                    session.cvesData.clear();

                    if (session == activeSession) {
                        fingerprintArea.setText(session.fingerprintText);
                        fingerprintArea.setCaretPosition(0);
                        cvesTableModel.setRowCount(0);
                    }
                });
            }
        } catch (Exception ex) {
            appendLog(session, "[!] Fingerprint error -- " + ex.getMessage());
        }
    }

    private void displayFingerprint(FtpSession session, FingerprintResult fp, String banner) {
        StringBuilder sb = new StringBuilder();
        sb.append("Banner:      ").append(banner).append('\n');
        sb.append("Software:    ").append(fp.software()).append('\n');
        sb.append("Version:     ").append(fp.version()).append('\n');
        sb.append("Vulns Found: ").append(fp.vulns().size()).append('\n');

        session.fingerprintText = sb.toString();
        session.cvesData.clear();
        for (KnownVuln v : fp.vulns()) {
            session.cvesData.add(new Object[]{v.cve(), v.title(), v.severity(), v.description()});
        }

        if (session == activeSession) {
            fingerprintArea.setText(session.fingerprintText);
            fingerprintArea.setCaretPosition(0);
            cvesTableModel.setRowCount(0);
            for (Object[] r : session.cvesData) {
                cvesTableModel.addRow(r);
            }
        }
    }

    // -------------------------------------------------------------------------
    // PASV Analysis
    // -------------------------------------------------------------------------

    private void runPasvAnalysis() {
        if (activeSession == null || !activeSession.connected || activeSession.ftpClient == null) {
            if (activeSession != null) {
                appendLog(activeSession, "[~] PASV analysis requires an active FTP/FTPS connection");
            }
            return;
        }
        FtpSession session = activeSession;

        Thread.ofVirtual().name("ftp-pasv-" + session.host).start(() -> {
            try {
                Consumer<String> log = msg -> appendLog(session, msg);
                PasvResult result = PasvAnalyzer.analyze(session.host, session.port, session.username, session.password,
                        log);

                SwingUtilities.invokeLater(() -> {
                    StringBuilder sb = new StringBuilder(session.fingerprintText);
                    sb.append("\n--- PASV Analysis ---\n");
                    sb.append("PASV IP:   ").append(result.pasvIp()).append('\n');
                    sb.append("PASV Port: ").append(result.pasvPort()).append('\n');
                    if (!result.findings().isEmpty()) {
                        sb.append("Findings:\n");
                        for (String f : result.findings()) {
                            sb.append("  ").append(f).append('\n');
                        }
                    } else {
                        sb.append("No PASV misconfigurations detected.\n");
                    }
                    session.fingerprintText = sb.toString();

                    if (session == activeSession) {
                        fingerprintArea.setText(session.fingerprintText);
                        fingerprintArea.setCaretPosition(0);
                    }
                });
            } catch (Exception ex) {
                appendLog(session, "[!] PASV analysis error -- " + ex.getMessage());
            }
        });
    }

    // -------------------------------------------------------------------------
    // Sensitive File Scan
    // -------------------------------------------------------------------------

    private void runSensitiveScan(String basePath) {
        if (activeSession == null || !activeSession.connected) {
            return;
        }
        FtpSession session = activeSession;
        Thread.ofVirtual().name("ftp-sensitive-" + session.host).start(() -> {
            Consumer<String> log = msg -> appendLog(session, msg);
            runSensitiveScanInternal(session, basePath, log);
        });
    }

    private void runSensitiveScanInternal(FtpSession session, String basePath, Consumer<String> log) {
        try {
            SensitiveFileScanner scanner;
            if (session.sftpClient != null) {
                scanner = SensitiveFileScanner.forSftp(session.sftpClient);
            } else if (session.ftpClient != null) {
                scanner = SensitiveFileScanner.forFtp(session.ftpClient);
            } else {
                return;
            }

            List<SensitiveFile> results = scanner.scan(basePath, log);
            SwingUtilities.invokeLater(() -> {
                session.sensitiveData.clear();
                for (SensitiveFile sf : results) {
                    session.sensitiveData
                            .add(new Object[]{sf.path(), sf.category(), formatSize(sf.size()), sf.matchReason()});
                }

                if (session == activeSession) {
                    sensitiveTableModel.setRowCount(0);
                    for (Object[] r : session.sensitiveData) {
                        sensitiveTableModel.addRow(r);
                    }
                    if (!results.isEmpty()) {
                        rightTabs.setSelectedIndex(2);
                    }
                }
            });
        } catch (Exception ex) {
            appendLog(session, "[!] Sensitive scan error -- " + ex.getMessage());
        }
    }

    // -------------------------------------------------------------------------
    // TLS / SSH Audit
    // -------------------------------------------------------------------------

    /**
     * Runs TLS audit for FTPS or SSH audit for SFTP on the active session,
     * populating the TLS Audit tab.
     */
    public void runTlsAudit() {
        if (activeSession == null || !activeSession.connected) {
            return;
        }
        FtpSession session = activeSession;

        Thread.ofVirtual().name("ftp-tls-audit-" + session.host).start(() -> {
            Consumer<String> log = msg -> appendLog(session, msg);
            TlsAuditor auditor = new TlsAuditor();

            if ("SFTP".equals(session.protocol)) {
                SftpAuditResult result = auditor.auditSftp(session.host, session.port, log);
                SwingUtilities.invokeLater(() -> displaySftpAudit(session, result));
            } else {
                TlsAuditResult result = auditor.auditFtps(session.host, session.port, log);
                SwingUtilities.invokeLater(() -> displayFtpsAudit(session, result));
            }
        });
    }

    private void displayFtpsAudit(FtpSession session, TlsAuditResult r) {
        StringBuilder sb = new StringBuilder();
        sb.append("--- FTPS TLS Audit ---\n\n");
        sb.append("TLS Version:        ").append(r.tlsVersion()).append('\n');
        sb.append("Cipher Suite:       ").append(r.cipherSuite()).append('\n');
        sb.append("PROT P Enabled:     ").append(r.protPEnabled()).append('\n');
        sb.append("Session Resume:     ").append(r.supportsSessionResume()).append('\n');
        sb.append("Downgrade Vuln:     ").append(r.downgradeVulnerable()).append('\n');
        if (!r.findings().isEmpty()) {
            sb.append("\nFindings:\n");
            for (String f : r.findings()) {
                sb.append("  ").append(f).append('\n');
            }
        }

        session.tlsAuditText = sb.toString();
        if (session == activeSession) {
            tlsAuditArea.setText(session.tlsAuditText);
            tlsAuditArea.setCaretPosition(0);
            rightTabs.setSelectedIndex(4);
        }
    }

    private void displaySftpAudit(FtpSession session, SftpAuditResult r) {
        StringBuilder sb = new StringBuilder();
        sb.append("--- SFTP/SSH Audit ---\n\n");
        sb.append("KEX Algorithms:     ").append(r.kexAlgorithms()).append('\n');
        sb.append("Ciphers:            ").append(r.ciphers()).append('\n');
        sb.append("MACs:               ").append(r.macs()).append('\n');
        sb.append("Host Key Type:      ").append(r.hostKeyType()).append('\n');
        if (!r.findings().isEmpty()) {
            sb.append("\nFindings:\n");
            for (String f : r.findings()) {
                sb.append("  ").append(f).append('\n');
            }
        }

        session.tlsAuditText = sb.toString();
        if (session == activeSession) {
            tlsAuditArea.setText(session.tlsAuditText);
            tlsAuditArea.setCaretPosition(0);
            rightTabs.setSelectedIndex(4);
        }
    }

    // -------------------------------------------------------------------------
    // Raw Command
    // -------------------------------------------------------------------------

    private void sendRawCommand() {
        String cmd = rawCommandField.getText().trim();
        if (cmd.isBlank() || activeSession == null || !activeSession.connected) {
            return;
        }
        rawCommandField.setText("");
        FtpSession session = activeSession;

        Thread.ofVirtual().name("ftp-raw-cmd-" + session.host).start(() -> {
            try {
                Consumer<String> log = msg -> appendLog(session, msg);

                if (session.ftpClient != null) {
                    String reply = session.ftpClient.sendCommand(cmd, log);
                    SwingUtilities.invokeLater(() -> appendRawOutput(session, ">> " + cmd + "\n<< " + reply + "\n"));
                } else if (session.sftpClient != null) {
                    String output = session.sftpClient.exec(cmd, log);
                    SwingUtilities.invokeLater(() -> appendRawOutput(session, ">> " + cmd + "\n" + output + "\n"));
                }
            } catch (Exception ex) {
                SwingUtilities.invokeLater(
                        () -> appendRawOutput(session, ">> " + cmd + "\n<< ERROR: " + ex.getMessage() + "\n"));
                appendLog(session, "[!] Raw command error -- " + ex.getMessage());
            }
        });
    }

    private void appendRawOutput(FtpSession session, String text) {
        session.rawOutputBuffer.append(text);
        if (session == activeSession) {
            rawCommandOutput.append(text);
            rawCommandOutput.setCaretPosition(rawCommandOutput.getDocument().getLength());
        }
    }

    // -------------------------------------------------------------------------
    // Logging (per-session)
    // -------------------------------------------------------------------------

    private void appendLog(FtpSession session, String message) {
        SwingUtilities.invokeLater(() -> {
            if (session.logBuffer.length() > 0) {
                session.logBuffer.append('\n');
            }
            session.logBuffer.append(message);

            if (session == activeSession) {
                if (logArea.getDocument().getLength() > 0) {
                    logArea.append("\n");
                }
                logArea.append(message);
                logArea.setCaretPosition(logArea.getDocument().getLength());
            }
        });
    }

    // -------------------------------------------------------------------------
    // Public API -- discovered service integration
    // -------------------------------------------------------------------------

    /**
     * Adds a pre-filled disconnected session for a service discovered by a scanner
     * module. The session is NOT connected automatically.
     *
     * @param host
     *            the target hostname or IP
     * @param port
     *            the target port
     * @param serviceType
     *            "FTP", "FTPS", or "SFTP"
     */
    public void addDiscoveredService(String host, int port, String serviceType) {
        SwingUtilities.invokeLater(() -> {
            String name = serviceType + " @ " + host + ":" + port + " (discovered)";
            FtpSession session = createSession(name, serviceType, host, port, "", "", true);
            session.discovered = true;
        });
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private FtpSession findSessionForNode(DefaultMutableTreeNode node) {
        TreeNode current = node;
        while (current != null) {
            if (current instanceof DefaultMutableTreeNode dmtn && dmtn.getUserObject() instanceof FtpSession session) {
                return session;
            }
            current = current.getParent();
        }
        return null;
    }

    private String buildRemotePath(TreePath treePath) {
        Object[] nodes = treePath.getPath();
        // nodes[0] = invisible root, nodes[1] = session node, nodes[2+] = file entries
        if (nodes.length <= 2) {
            return "/";
        }
        // Prepend the session's current navigation prefix so that paths remain
        // correct after the user navigates into a subdirectory via the path bar.
        FtpSession session = null;
        if (nodes[1] instanceof DefaultMutableTreeNode dmtn && dmtn.getUserObject() instanceof FtpSession s) {
            session = s;
        }
        String base = session != null ? session.currentPath : "/";

        StringBuilder sb = new StringBuilder();
        if (!"/".equals(base)) {
            sb.append(base);
        }
        for (int i = 2; i < nodes.length; i++) {
            sb.append('/');
            DefaultMutableTreeNode node = (DefaultMutableTreeNode) nodes[i];
            Object obj = node.getUserObject();
            if (obj instanceof FileEntry entry) {
                sb.append(entry.name());
            } else {
                sb.append(obj);
            }
        }
        return sb.length() == 0 ? "/" : sb.toString();
    }

    private static String parentPath(String path) {
        if (path == null || path.equals("/") || path.isBlank()) {
            return "/";
        }
        int idx = path.lastIndexOf('/');
        return idx <= 0 ? "/" : path.substring(0, idx);
    }

    static String formatSize(long bytes) {
        if (bytes < 1024) {
            return bytes + " B";
        }
        if (bytes < 1024 * 1024) {
            return String.format("%.1f KB", bytes / 1024.0);
        }
        if (bytes < 1024L * 1024 * 1024) {
            return String.format("%.1f MB", bytes / (1024.0 * 1024));
        }
        return String.format("%.1f GB", bytes / (1024.0 * 1024 * 1024));
    }

    private static JTextArea createReadOnlyTextArea() {
        JTextArea area = new JTextArea();
        area.setEditable(false);
        area.setFont(monoFont());
        area.setLineWrap(false);
        return area;
    }

    private static Font monoFont() {
        return new Font(Font.MONOSPACED, Font.PLAIN, 12);
    }

    private void onThemeChanged() {
        // Let FlatLaf handle the theme propagation
    }

    // -------------------------------------------------------------------------
    // Tree cell renderer -- sessions + files
    // -------------------------------------------------------------------------

    private static class SessionFileTreeCellRenderer extends DefaultTreeCellRenderer {

        private static final Color CONNECTED_DARK = new Color(0x66, 0xCC, 0x66);
        private static final Color CONNECTED_LIGHT = new Color(0x22, 0x88, 0x22);

        @Override
        public Component getTreeCellRendererComponent(JTree tree, Object value, boolean sel, boolean expanded,
                boolean leaf, int row, boolean hasFocus) {

            super.getTreeCellRendererComponent(tree, value, sel, expanded, leaf, row, hasFocus);

            if (!(value instanceof DefaultMutableTreeNode node)) {
                return this;
            }
            Object userObj = node.getUserObject();

            if (userObj instanceof FtpSession session) {
                setText(session.displayName());
                if (session.connected) {
                    setIcon(UIManager.getIcon("FileView.computerIcon"));
                    if (!sel) {
                        setForeground(AnarCryLaf.isDark() ? CONNECTED_DARK : CONNECTED_LIGHT);
                    }
                } else {
                    setIcon(UIManager.getIcon("FileView.hardDriveIcon"));
                }
            } else if (userObj instanceof FileEntry entry) {
                String label = entry.name();
                if (!entry.isDirectory() && entry.size() >= 0) {
                    label += "  (" + formatSize(entry.size()) + ")";
                }
                if (!entry.permissions().isBlank()) {
                    label += "  " + entry.permissions();
                }
                setText(label);
                if (entry.isDirectory()) {
                    setIcon(UIManager.getIcon("FileView.directoryIcon"));
                } else {
                    setIcon(UIManager.getIcon("FileView.fileIcon"));
                }
            } else if (userObj instanceof String) {
                setFont(getFont().deriveFont(Font.ITALIC));
            }

            return this;
        }
    }

    // -------------------------------------------------------------------------
    // Connection persistence
    // -------------------------------------------------------------------------

    private void loadSavedConnections() {
        List<ConnectionStore.FtpConnectionEntry> entries = ConnectionStore.loadFtpConnections();
        for (ConnectionStore.FtpConnectionEntry e : entries) {
            FtpSession session = createSession(e.name(), e.protocol(), e.host(), e.port(), e.username(), e.keyPath(),
                    e.passive());
            session.discovered = false;
        }
    }

    private void persistConnections() {
        Thread.ofVirtual().name("ftp-persist").start(() -> {
            List<ConnectionStore.FtpConnectionEntry> entries = new ArrayList<>();
            for (FtpSession s : sessions) {
                if (s.discovered) {
                    continue;
                }
                entries.add(new ConnectionStore.FtpConnectionEntry(s.name, s.protocol, s.host, s.port, s.username,
                        s.keyPath, s.passive));
            }
            ConnectionStore.saveFtpConnections(entries);
        });
    }
}
