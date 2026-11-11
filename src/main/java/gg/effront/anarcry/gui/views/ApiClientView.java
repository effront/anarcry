package gg.effront.anarcry.gui.views;

import gg.effront.anarcry.apiclient.auth.AuthInjectorRegistry;
import gg.effront.anarcry.apiclient.io.BruImporter;
import gg.effront.anarcry.apiclient.io.CollectionLoader;
import gg.effront.anarcry.apiclient.io.CollectionWriter;
import gg.effront.anarcry.apiclient.io.CurlImporter;
import gg.effront.anarcry.apiclient.io.OpenApiImporter;
import gg.effront.anarcry.apiclient.io.PostmanImporter;
import gg.effront.anarcry.apiclient.model.AssertOp;
import gg.effront.anarcry.apiclient.model.Assertion;
import gg.effront.anarcry.apiclient.model.AssertionResult;
import gg.effront.anarcry.apiclient.model.AuthConfig;
import gg.effront.anarcry.apiclient.model.BodyConfig;
import gg.effront.anarcry.apiclient.model.Collection;
import gg.effront.anarcry.apiclient.model.CollectionItem;
import gg.effront.anarcry.apiclient.model.Environment;
import gg.effront.anarcry.apiclient.model.Folder;
import gg.effront.anarcry.apiclient.model.Header;
import gg.effront.anarcry.apiclient.model.HttpRequestDef;
import gg.effront.anarcry.apiclient.model.Param;
import gg.effront.anarcry.apiclient.model.ParamsDef;
import gg.effront.anarcry.apiclient.model.RequestItem;
import gg.effront.anarcry.apiclient.model.RequestMeta;
import gg.effront.anarcry.apiclient.model.RequestResult;
import gg.effront.anarcry.apiclient.model.RequestSettings;
import gg.effront.anarcry.apiclient.model.RunResult;
import gg.effront.anarcry.apiclient.model.VarsDef;
import gg.effront.anarcry.apiclient.runner.AssertionEngine;
import gg.effront.anarcry.apiclient.runner.CollectionRunner;
import gg.effront.anarcry.apiclient.runner.RequestExecutor;
import gg.effront.anarcry.apiclient.runner.RunContext;
import gg.effront.anarcry.apiclient.vars.Interpolator;
import gg.effront.anarcry.apiclient.vars.VariableStore;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Cursor;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.datatransfer.DataFlavor;
import java.awt.datatransfer.Transferable;
import java.awt.datatransfer.UnsupportedFlavorException;
import java.awt.event.InputEvent;
import java.awt.event.KeyEvent;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.net.http.HttpClient;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

import javax.swing.BorderFactory;
import javax.swing.DropMode;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JComponent;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JMenuItem;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPopupMenu;
import javax.swing.JScrollPane;
import javax.swing.JSpinner;
import javax.swing.JSplitPane;
import javax.swing.JTabbedPane;
import javax.swing.JTable;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.JTree;
import javax.swing.KeyStroke;
import javax.swing.SpinnerNumberModel;
import javax.swing.SwingUtilities;
import javax.swing.TransferHandler;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.table.DefaultTableModel;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.DefaultTreeCellRenderer;
import javax.swing.tree.DefaultTreeModel;
import javax.swing.tree.TreePath;

import org.fife.ui.rsyntaxtextarea.RSyntaxTextArea;
import org.fife.ui.rsyntaxtextarea.SyntaxConstants;
import org.fife.ui.rsyntaxtextarea.Theme;
import org.fife.ui.rtextarea.RTextScrollPane;

public class ApiClientView extends JPanel {

    private static final int SIDEBAR_WIDTH = 250;
    private static final int REQUEST_TIMEOUT_SECONDS = 30;
    private static final int MAX_OPEN_TABS = 10;

    private static final Color METHOD_GET = new Color(0x3F, 0xB9, 0x50);
    private static final Color METHOD_POST = new Color(0xD2, 0x99, 0x22);
    private static final Color METHOD_PUT = new Color(0x58, 0xA6, 0xFF);
    private static final Color METHOD_DELETE = new Color(0xF8, 0x51, 0x49);
    private static final Color METHOD_PATCH = new Color(0xBB, 0x6B, 0xD9);
    private static final Color TAB_ACTIVE_BG = new Color(0x3A, 0x3A, 0x4E);
    private static final Color TAB_INACTIVE_BG = new Color(0x24, 0x24, 0x34);

    private JTree collectionTree;
    private DefaultMutableTreeNode treeRoot;
    private DefaultTreeModel treeModel;
    private JTextField sidebarSearchField;
    private JComboBox<String> methodCombo;
    private JTextField urlField;
    private JButton sendButton;
    private JComboBox<String> envCombo;
    private JComboBox<String> bodyTypeCombo;
    private JTextArea headersArea;
    private RSyntaxTextArea bodyArea;
    private JTextArea paramsArea;
    private JComboBox<String> authTypeCombo;
    private JTextArea authFieldsArea;
    private JTextArea varsPreArea;
    private JTextArea varsPostArea;
    private DefaultTableModel assertTableModel;
    private JTextArea docsArea;
    private JCheckBox settingsFollowRedirects;
    private JSpinner settingsTimeout;
    private JCheckBox settingsEncodeUrl;
    private JLabel responseStatus;
    private RSyntaxTextArea responseBody;
    private JTabbedPane responseTabPane;
    private JTextArea responseHeaders;
    private JTextArea assertionsResultArea;
    private JPanel requestTabsPanel;
    private JButton overflowButton;

    private Collection currentCollection;
    private Path collectionPath;
    private RequestItem activeRequest;
    private final List<RequestItem> openRequests = new ArrayList<>();
    private final java.net.CookieManager cookieManager;
    private final HttpClient httpClient;
    private final List<String> runLog = new ArrayList<>();
    private RunContext sessionContext;

    public ApiClientView() {
        super(new BorderLayout());
        cookieManager = new java.net.CookieManager(null, java.net.CookiePolicy.ACCEPT_ALL);
        httpClient = HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NORMAL).cookieHandler(cookieManager)
                .connectTimeout(Duration.ofSeconds(REQUEST_TIMEOUT_SECONDS)).build();

        JSplitPane mainSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, buildSidebar(), buildRightPanel());
        mainSplit.setDividerLocation(SIDEBAR_WIDTH);
        add(mainSplit, BorderLayout.CENTER);
    }

    // ==================== SIDEBAR ====================

    private JPanel buildSidebar() {
        JPanel sidebar = new JPanel(new BorderLayout());
        sidebar.setPreferredSize(new Dimension(SIDEBAR_WIDTH, 0));

        sidebarSearchField = new JTextField();
        sidebarSearchField.putClientProperty("JTextField.placeholderText", "Filter requests...");
        sidebarSearchField.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createMatteBorder(0, 0, 1, 0, new Color(0x55, 0x55, 0x55)),
                BorderFactory.createEmptyBorder(4, 6, 4, 6)));
        sidebarSearchField.getDocument().addDocumentListener(new DocumentListener() {

            @Override
            public void insertUpdate(DocumentEvent e) {
                filterTree();
            }

            @Override
            public void removeUpdate(DocumentEvent e) {
                filterTree();
            }

            @Override
            public void changedUpdate(DocumentEvent e) {
                filterTree();
            }
        });
        JPanel topBar = new JPanel(new BorderLayout());
        topBar.add(sidebarSearchField, BorderLayout.CENTER);

        JPanel sortBar = new JPanel(new FlowLayout(FlowLayout.LEFT, 2, 1));
        sortBar.setBorder(BorderFactory.createMatteBorder(0, 0, 1, 0, new Color(0x44, 0x44, 0x44)));
        JButton sortAz = new JButton("A-Z");
        sortAz.setFont(sortAz.getFont().deriveFont(10f));
        sortAz.setMargin(new java.awt.Insets(1, 4, 1, 4));
        sortAz.setToolTipText("Sort by name");
        sortAz.addActionListener(e -> sortCollection(SortMode.NAME));
        sortBar.add(sortAz);
        JButton sortMethod = new JButton("MTD");
        sortMethod.setFont(sortMethod.getFont().deriveFont(10f));
        sortMethod.setMargin(new java.awt.Insets(1, 4, 1, 4));
        sortMethod.setToolTipText("Sort by method");
        sortMethod.addActionListener(e -> sortCollection(SortMode.METHOD));
        sortBar.add(sortMethod);
        JButton sortType = new JButton("TYP");
        sortType.setFont(sortType.getFont().deriveFont(10f));
        sortType.setMargin(new java.awt.Insets(1, 4, 1, 4));
        sortType.setToolTipText("Sort by type (folders first)");
        sortType.addActionListener(e -> sortCollection(SortMode.TYPE));
        sortBar.add(sortType);
        JButton expandAll = new JButton("+");
        expandAll.setFont(expandAll.getFont().deriveFont(10f));
        expandAll.setMargin(new java.awt.Insets(1, 6, 1, 6));
        expandAll.setToolTipText("Expand all");
        expandAll.addActionListener(e -> expandAllNodes());
        sortBar.add(expandAll);
        JButton collapseAll = new JButton("-");
        collapseAll.setFont(collapseAll.getFont().deriveFont(10f));
        collapseAll.setMargin(new java.awt.Insets(1, 6, 1, 6));
        collapseAll.setToolTipText("Collapse all");
        collapseAll.addActionListener(e -> collapseAllNodes());
        sortBar.add(collapseAll);
        topBar.add(sortBar, BorderLayout.SOUTH);

        sidebar.add(topBar, BorderLayout.NORTH);

        treeRoot = new DefaultMutableTreeNode("No collection loaded");
        treeModel = new DefaultTreeModel(treeRoot);
        collectionTree = new JTree(treeModel);
        collectionTree.setRootVisible(true);
        collectionTree.addTreeSelectionListener(e -> onTreeSelection());
        collectionTree.setDragEnabled(true);
        collectionTree.setDropMode(DropMode.ON_OR_INSERT);
        collectionTree.setTransferHandler(new TreeDragHandler());
        installTreeContextMenu();
        javax.swing.ToolTipManager.sharedInstance().registerComponent(collectionTree);

        collectionTree.setCellRenderer(new javax.swing.tree.TreeCellRenderer() {

            private final JPanel panel = new JPanel(new BorderLayout(4, 0));
            private final JLabel methodLabel = new JLabel();
            private final JLabel nameLabel = new JLabel();
            private final DefaultTreeCellRenderer fallback = new DefaultTreeCellRenderer();

            {
                methodLabel.setFont(new Font(Font.MONOSPACED, Font.BOLD, 12));
                nameLabel.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 12));
                panel.setOpaque(true);
                panel.add(methodLabel, BorderLayout.WEST);
                panel.add(nameLabel, BorderLayout.CENTER);
            }

            @Override
            public Component getTreeCellRendererComponent(JTree tree, Object value, boolean sel, boolean expanded,
                    boolean leaf, int row, boolean hasFocus) {
                if (value instanceof DefaultMutableTreeNode node && node.getUserObject() instanceof RequestItem ri) {
                    String method = ri.request().method();
                    methodLabel.setText(method);
                    methodLabel.setForeground(methodColor(method));
                    nameLabel.setText(ri.name());
                    Color bg = sel ? new Color(0x3A, 0x3A, 0x4E) : tree.getBackground();
                    Color fg = sel ? Color.WHITE : tree.getForeground();
                    panel.setBackground(bg);
                    nameLabel.setForeground(fg);
                    panel.setToolTipText(method + " " + ri.name() + " - " + ri.request().url());
                    return panel;
                }
                Component c = fallback.getTreeCellRendererComponent(tree, value, sel, expanded, leaf, row, hasFocus);
                if (value instanceof DefaultMutableTreeNode node) {
                    fallback.setToolTipText(node.getUserObject().toString());
                }
                return c;
            }
        });

        sidebar.add(new JScrollPane(collectionTree), BorderLayout.CENTER);

        JPanel buttons = new JPanel(new java.awt.GridLayout(5, 1, 2, 2));
        buttons.setBorder(BorderFactory.createEmptyBorder(4, 4, 4, 4));

        JButton loadBtn = new JButton("Load Collection");
        loadBtn.addActionListener(e -> chooseAndLoadCollection());
        buttons.add(loadBtn);

        JButton importBtn = new JButton("Import...");
        importBtn.addActionListener(e -> showImportMenu(importBtn));
        buttons.add(importBtn);

        JButton newReqBtn = new JButton("New Request");
        newReqBtn.addActionListener(e -> addNewRequest());
        buttons.add(newReqBtn);

        JButton saveBtn = new JButton("Save");
        saveBtn.addActionListener(e -> saveCollection());
        buttons.add(saveBtn);

        JButton runBtn = new JButton("Run All");
        runBtn.addActionListener(e -> runCollection());
        buttons.add(runBtn);

        sidebar.add(buttons, BorderLayout.SOUTH);
        return sidebar;
    }

    private void filterTree() {
        if (currentCollection == null) {
            return;
        }
        String query = sidebarSearchField.getText().trim().toLowerCase();
        if (query.isEmpty()) {
            populateTree();
            return;
        }
        treeRoot = new DefaultMutableTreeNode(currentCollection.name());
        addFilteredItems(treeRoot, currentCollection.items(), query);
        treeModel.setRoot(treeRoot);
        for (int i = 0; i < collectionTree.getRowCount(); i++) {
            collectionTree.expandRow(i);
        }
    }

    private void addFilteredItems(DefaultMutableTreeNode parent, List<CollectionItem> items, String query) {
        for (CollectionItem item : items) {
            switch (item) {
                case Folder folder -> {
                    DefaultMutableTreeNode folderNode = new DefaultMutableTreeNode(folder.name());
                    addFilteredItems(folderNode, folder.items(), query);
                    if (folderNode.getChildCount() > 0 || folder.name().toLowerCase().contains(query)) {
                        parent.add(folderNode);
                    }
                }
                case RequestItem req -> {
                    String text = req.request().method() + " " + req.name() + " " + req.request().url();
                    if (text.toLowerCase().contains(query)) {
                        parent.add(new DefaultMutableTreeNode(req));
                    }
                }
            }
        }
    }

    private enum SortMode {
        NAME, METHOD, TYPE
    }

    private void sortCollection(SortMode mode) {
        if (currentCollection == null) {
            return;
        }
        List<CollectionItem> sorted = sortItems(currentCollection.items(), mode);
        currentCollection = new Collection(currentCollection.uid(), currentCollection.name(),
                currentCollection.version(), currentCollection.environments(), sorted, currentCollection.root(),
                currentCollection.settings());
        populateTree();
    }

    private List<CollectionItem> sortItems(List<CollectionItem> items, SortMode mode) {
        List<CollectionItem> result = new ArrayList<>(items);
        java.util.Comparator<CollectionItem> cmp = switch (mode) {
            case NAME -> java.util.Comparator.comparing(i -> itemName(i).toLowerCase());
            case METHOD -> java.util.Comparator.comparing(this::itemMethodKey);
            case TYPE -> java.util.Comparator.<CollectionItem, Integer>comparing(i -> i instanceof Folder ? 0 : 1)
                    .thenComparing(i -> itemName(i).toLowerCase());
        };
        result.sort(cmp);
        for (int i = 0; i < result.size(); i++) {
            if (result.get(i) instanceof Folder f) {
                result.set(i, new Folder(f.uid(), f.name(), sortItems(f.items(), mode), f.root()));
            }
        }
        return result;
    }

    private static String itemName(CollectionItem item) {
        return switch (item) {
            case Folder f -> f.name();
            case RequestItem r -> r.name();
        };
    }

    private String itemMethodKey(CollectionItem item) {
        return switch (item) {
            case Folder f -> "0_" + f.name().toLowerCase();
            case RequestItem r -> r.request().method() + "_" + r.name().toLowerCase();
        };
    }

    private void expandAllNodes() {
        for (int i = 0; i < collectionTree.getRowCount(); i++) {
            collectionTree.expandRow(i);
        }
    }

    private void collapseAllNodes() {
        for (int i = collectionTree.getRowCount() - 1; i > 0; i--) {
            collectionTree.collapseRow(i);
        }
    }

    // ==================== RIGHT PANEL ====================

    private JPanel buildRightPanel() {
        JPanel right = new JPanel(new BorderLayout());

        JPanel topSection = new JPanel(new BorderLayout());
        topSection.add(buildTopBar(), BorderLayout.NORTH);

        requestTabsPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 2, 2));
        requestTabsPanel.setBorder(BorderFactory.createEmptyBorder(0, 4, 2, 4));

        overflowButton = new JButton(">>");
        overflowButton.setFont(overflowButton.getFont().deriveFont(11f));
        overflowButton.setMargin(new java.awt.Insets(2, 6, 2, 6));
        overflowButton.setFocusPainted(false);
        overflowButton.setVisible(false);
        overflowButton.setToolTipText("More tabs");

        JPanel tabsRow = new JPanel(new BorderLayout());
        tabsRow.add(requestTabsPanel, BorderLayout.CENTER);
        tabsRow.add(overflowButton, BorderLayout.EAST);
        tabsRow.setPreferredSize(new Dimension(0, 30));
        topSection.add(tabsRow, BorderLayout.SOUTH);

        right.add(topSection, BorderLayout.NORTH);

        JSplitPane split = new JSplitPane(JSplitPane.VERTICAL_SPLIT, buildRequestEditor(), buildResponseViewer());
        split.setResizeWeight(0.45);
        right.add(split, BorderLayout.CENTER);

        KeyStroke ctrlEnter = KeyStroke.getKeyStroke(KeyEvent.VK_ENTER, InputEvent.CTRL_DOWN_MASK);
        right.registerKeyboardAction(e -> sendRequest(), ctrlEnter, JComponent.WHEN_ANCESTOR_OF_FOCUSED_COMPONENT);

        return right;
    }

    private JPanel buildTopBar() {
        JPanel bar = new JPanel(new BorderLayout(4, 0));
        bar.setBorder(BorderFactory.createEmptyBorder(4, 4, 4, 4));

        methodCombo = new JComboBox<>(new String[]{"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"});
        urlField = new JTextField("https://");
        sendButton = new JButton("Send");
        sendButton.addActionListener(e -> sendRequest());

        envCombo = new JComboBox<>();
        envCombo.addItem("(no env)");
        envCombo.setPreferredSize(new Dimension(140, 28));

        JButton envConfigBtn = new JButton("...");
        envConfigBtn.setPreferredSize(new Dimension(36, 28));
        envConfigBtn.setToolTipText("Configure environments");
        envConfigBtn.addActionListener(e -> openEnvEditor());

        JPanel left = new JPanel(new BorderLayout(4, 0));
        left.add(methodCombo, BorderLayout.WEST);
        left.add(urlField, BorderLayout.CENTER);

        JPanel envPanel = new JPanel(new BorderLayout(2, 0));
        envPanel.add(envCombo, BorderLayout.CENTER);
        envPanel.add(envConfigBtn, BorderLayout.EAST);

        JPanel rightBar = new JPanel(new BorderLayout(4, 0));
        rightBar.add(envPanel, BorderLayout.CENTER);
        rightBar.add(sendButton, BorderLayout.EAST);

        bar.add(left, BorderLayout.CENTER);
        bar.add(rightBar, BorderLayout.EAST);
        return bar;
    }

    // ==================== REQUEST EDITOR ====================

    private JTabbedPane buildRequestEditor() {
        JTabbedPane tabs = new JTabbedPane();

        headersArea = new JTextArea(8, 40);
        headersArea.setFont(monoFont());
        headersArea.setText("User-Agent: " + gg.effront.anarcry.Version.userAgent() + "\nAccept: */*");
        tabs.addTab("Headers", new JScrollPane(headersArea));

        JPanel bodyPanel = new JPanel(new BorderLayout());
        bodyTypeCombo = new JComboBox<>(new String[]{"JSON", "Text", "XML", "FormUrlEncoded", "GraphQL", "None"});
        bodyTypeCombo.addActionListener(e -> updateBodySyntax());
        JPanel bodyTopBar = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 2));
        bodyTopBar.add(new JLabel("Type:"));
        bodyTopBar.add(bodyTypeCombo);
        bodyPanel.add(bodyTopBar, BorderLayout.NORTH);
        bodyArea = createSyntaxArea(false);
        bodyArea.setSyntaxEditingStyle(SyntaxConstants.SYNTAX_STYLE_JSON);
        bodyPanel.add(new RTextScrollPane(bodyArea), BorderLayout.CENTER);
        tabs.addTab("Body", bodyPanel);

        paramsArea = new JTextArea(8, 40);
        paramsArea.setFont(monoFont());
        tabs.addTab("Params", new JScrollPane(paramsArea));

        JPanel authPanel = new JPanel(new BorderLayout(4, 4));
        authPanel.setBorder(BorderFactory.createEmptyBorder(4, 4, 4, 4));
        authTypeCombo = new JComboBox<>(new String[]{"none", "bearer", "basic", "apikey", "digest", "oauth2", "wsse"});
        authFieldsArea = new JTextArea(6, 40);
        authFieldsArea.setFont(monoFont());
        authPanel.add(authTypeCombo, BorderLayout.NORTH);
        authPanel.add(new JScrollPane(authFieldsArea), BorderLayout.CENTER);
        tabs.addTab("Auth", authPanel);

        JPanel varsPanel = new JPanel(new BorderLayout(0, 4));
        varsPanel.setBorder(BorderFactory.createEmptyBorder(4, 4, 4, 4));
        JPanel varsTop = new JPanel(new BorderLayout());
        varsTop.add(new JLabel("Pre-request variables:"), BorderLayout.NORTH);
        varsPreArea = new JTextArea(3, 40);
        varsPreArea.setFont(monoFont());
        varsTop.add(new JScrollPane(varsPreArea), BorderLayout.CENTER);
        JPanel varsBottom = new JPanel(new BorderLayout());
        varsBottom.add(new JLabel("Post-response variables:"), BorderLayout.NORTH);
        varsPostArea = new JTextArea(3, 40);
        varsPostArea.setFont(monoFont());
        varsBottom.add(new JScrollPane(varsPostArea), BorderLayout.CENTER);
        varsPanel.add(varsTop, BorderLayout.NORTH);
        varsPanel.add(varsBottom, BorderLayout.CENTER);
        tabs.addTab("Vars", varsPanel);

        JPanel assertPanel = new JPanel(new BorderLayout(0, 4));
        assertPanel.setBorder(BorderFactory.createEmptyBorder(4, 4, 4, 4));
        assertTableModel = new DefaultTableModel(new String[]{"Expression", "Operator", "Expected", "Enabled"}, 0) {

            @Override
            public Class<?> getColumnClass(int col) {
                return col == 3 ? Boolean.class : String.class;
            }

            @Override
            public boolean isCellEditable(int row, int col) {
                return true;
            }
        };
        JTable assertTable = new JTable(assertTableModel);
        assertTable.getColumnModel().getColumn(1).setPreferredWidth(60);
        assertTable.getColumnModel().getColumn(3).setPreferredWidth(50);
        assertPanel.add(new JScrollPane(assertTable), BorderLayout.CENTER);
        JPanel assertBtns = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 2));
        JButton addAssert = new JButton("Add");
        addAssert.addActionListener(e -> assertTableModel.addRow(new Object[]{"res.status", "eq", "200", true}));
        assertBtns.add(addAssert);
        JButton removeAssert = new JButton("Remove");
        removeAssert.addActionListener(e -> {
            int row = assertTable.getSelectedRow();
            if (row >= 0) {
                assertTableModel.removeRow(row);
            }
        });
        assertBtns.add(removeAssert);
        assertPanel.add(assertBtns, BorderLayout.SOUTH);
        tabs.addTab("Assert", assertPanel);

        docsArea = new JTextArea(8, 40);
        docsArea.setFont(monoFont());
        docsArea.setLineWrap(true);
        docsArea.setWrapStyleWord(true);
        tabs.addTab("Docs", new JScrollPane(docsArea));

        JPanel settingsPanel = new JPanel(new java.awt.GridBagLayout());
        settingsPanel.setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8));
        java.awt.GridBagConstraints gbc = new java.awt.GridBagConstraints();
        gbc.gridx = 0;
        gbc.gridy = 0;
        gbc.anchor = java.awt.GridBagConstraints.WEST;
        gbc.insets = new java.awt.Insets(4, 0, 4, 8);
        settingsFollowRedirects = new JCheckBox("Follow Redirects", true);
        settingsPanel.add(settingsFollowRedirects, gbc);
        gbc.gridy++;
        settingsEncodeUrl = new JCheckBox("Encode URL", true);
        settingsPanel.add(settingsEncodeUrl, gbc);
        gbc.gridy++;
        JPanel timeoutRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 0));
        timeoutRow.add(new JLabel("Timeout (ms):"));
        settingsTimeout = new JSpinner(new SpinnerNumberModel(30000, 0, 300000, 1000));
        timeoutRow.add(settingsTimeout);
        settingsPanel.add(timeoutRow, gbc);
        gbc.gridy++;
        gbc.weighty = 1.0;
        settingsPanel.add(new JLabel(), gbc);
        tabs.addTab("Settings", settingsPanel);

        return tabs;
    }

    private void updateBodySyntax() {
        String type = (String) bodyTypeCombo.getSelectedItem();
        bodyArea.setSyntaxEditingStyle(switch (type) {
            case "JSON" -> SyntaxConstants.SYNTAX_STYLE_JSON;
            case "XML" -> SyntaxConstants.SYNTAX_STYLE_XML;
            case "GraphQL" -> SyntaxConstants.SYNTAX_STYLE_JAVASCRIPT;
            default -> SyntaxConstants.SYNTAX_STYLE_NONE;
        });
    }

    // ==================== RESPONSE VIEWER ====================

    private JPanel buildResponseViewer() {
        JPanel panel = new JPanel(new BorderLayout());

        JPanel statusBar = new JPanel(new BorderLayout());
        responseStatus = new JLabel("");
        JPanel respButtons = new JPanel(new FlowLayout(FlowLayout.RIGHT, 4, 0));
        JButton copyBtn = new JButton("Copy");
        copyBtn.setFont(copyBtn.getFont().deriveFont(11f));
        copyBtn.addActionListener(e -> {
            String text = responseBody.getText();
            if (!text.isEmpty()) {
                java.awt.Toolkit.getDefaultToolkit().getSystemClipboard()
                        .setContents(new java.awt.datatransfer.StringSelection(text), null);
            }
        });
        JButton prettifyBtn = new JButton("Prettify");
        prettifyBtn.setFont(prettifyBtn.getFont().deriveFont(11f));
        prettifyBtn.addActionListener(e -> prettifyResponse());
        respButtons.add(copyBtn);
        respButtons.add(prettifyBtn);
        statusBar.add(responseStatus, BorderLayout.CENTER);
        statusBar.add(respButtons, BorderLayout.EAST);
        panel.add(statusBar, BorderLayout.NORTH);

        responseTabPane = new JTabbedPane();

        responseBody = createSyntaxArea(true);
        responseTabPane.addTab("Body", new RTextScrollPane(responseBody));

        responseHeaders = new JTextArea(6, 40);
        responseHeaders.setEditable(false);
        responseHeaders.setFont(monoFont());
        responseTabPane.addTab("Headers", new JScrollPane(responseHeaders));

        assertionsResultArea = new JTextArea(6, 40);
        assertionsResultArea.setEditable(false);
        assertionsResultArea.setFont(monoFont());
        responseTabPane.addTab("Assertions", new JScrollPane(assertionsResultArea));

        panel.add(responseTabPane, BorderLayout.CENTER);
        return panel;
    }

    private void prettifyResponse() {
        String text = responseBody.getText();
        if (text.isBlank()) {
            return;
        }
        try {
            com.google.gson.JsonElement el = com.google.gson.JsonParser.parseString(text);
            responseBody.setText(new com.google.gson.GsonBuilder().setPrettyPrinting().create().toJson(el));
            responseBody.setCaretPosition(0);
        } catch (Exception ex) {
            // not JSON, ignore
        }
    }

    // ==================== REQUEST TABS ====================

    private void openRequestTab(RequestItem item) {
        if (!openRequests.contains(item)) {
            if (openRequests.size() >= MAX_OPEN_TABS) {
                openRequests.removeFirst();
            }
            openRequests.add(item);
        }
        activeRequest = item;
        refreshRequestTabs();
    }

    private void closeRequestTab(RequestItem item) {
        openRequests.remove(item);
        if (activeRequest == item) {
            activeRequest = openRequests.isEmpty() ? null : openRequests.getLast();
        }
        refreshRequestTabs();
        if (activeRequest != null) {
            loadRequestIntoEditor(activeRequest);
        }
    }

    private void refreshRequestTabs() {
        requestTabsPanel.removeAll();

        List<JPanel> allTabs = new ArrayList<>();
        for (RequestItem req : openRequests) {
            allTabs.add(createRequestTabButton(req));
        }

        // Measure available width and decide which tabs fit.
        // Active tab is always visible -- if it would overflow, swap with the last
        // visible tab.
        int availableWidth = requestTabsPanel.getParent() != null
                ? requestTabsPanel.getParent().getWidth() - 50
                : Integer.MAX_VALUE;
        int usedWidth = 8;
        List<Integer> visibleIndices = new ArrayList<>();
        List<RequestItem> overflowItems = new ArrayList<>();
        for (int i = 0; i < allTabs.size(); i++) {
            int tabWidth = allTabs.get(i).getPreferredSize().width + 4;
            if (usedWidth + tabWidth <= availableWidth || visibleIndices.isEmpty()) {
                visibleIndices.add(i);
                usedWidth += tabWidth;
            } else {
                overflowItems.add(openRequests.get(i));
            }
        }
        // Ensure active tab is visible
        int activeIdx = openRequests.indexOf(activeRequest);
        if (activeIdx >= 0 && !visibleIndices.contains(activeIdx) && !visibleIndices.isEmpty()) {
            int lastVisible = visibleIndices.getLast();
            overflowItems.remove(openRequests.get(activeIdx));
            overflowItems.add(openRequests.get(lastVisible));
            visibleIndices.set(visibleIndices.size() - 1, activeIdx);
        }
        for (int idx : visibleIndices) {
            requestTabsPanel.add(allTabs.get(idx));
        }

        if (!overflowItems.isEmpty()) {
            overflowButton.setVisible(true);
            for (var al : overflowButton.getActionListeners()) {
                overflowButton.removeActionListener(al);
            }
            overflowButton.addActionListener(e -> {
                JPopupMenu popup = new JPopupMenu();
                for (RequestItem oi : overflowItems) {
                    String method = oi.request().method();
                    JMenuItem mi = new JMenuItem(method + " " + oi.name());
                    mi.setForeground(methodColor(method));
                    mi.addActionListener(ev -> {
                        activeRequest = oi;
                        loadRequestIntoEditor(oi);
                        refreshRequestTabs();
                    });
                    popup.add(mi);
                }
                popup.show(overflowButton, 0, overflowButton.getHeight());
            });
        } else {
            overflowButton.setVisible(false);
        }

        requestTabsPanel.revalidate();
        requestTabsPanel.repaint();
    }

    private JPanel createRequestTabButton(RequestItem item) {
        String method = item.request().method();
        String label = method + " " + item.name();
        if (label.length() > 25) {
            label = label.substring(0, 22) + "...";
        }

        JPanel tab = new JPanel(new BorderLayout(4, 0));
        tab.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
        tab.setBackground(item == activeRequest ? TAB_ACTIVE_BG : TAB_INACTIVE_BG);
        tab.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(item == activeRequest ? methodColor(method) : TAB_INACTIVE_BG, 1),
                BorderFactory.createEmptyBorder(2, 6, 2, 2)));

        JLabel textLabel = new JLabel(label);
        textLabel.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 11));
        textLabel.setForeground(methodColor(method));
        tab.add(textLabel, BorderLayout.CENTER);

        JLabel closeLabel = new JLabel("×");
        closeLabel.setFont(closeLabel.getFont().deriveFont(14f));
        closeLabel.setForeground(Color.GRAY);
        closeLabel.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
        closeLabel.setBorder(BorderFactory.createEmptyBorder(0, 4, 0, 4));
        closeLabel.addMouseListener(new MouseAdapter() {

            @Override
            public void mouseClicked(MouseEvent e) {
                closeRequestTab(item);
            }

            @Override
            public void mouseEntered(MouseEvent e) {
                closeLabel.setForeground(Color.WHITE);
            }

            @Override
            public void mouseExited(MouseEvent e) {
                closeLabel.setForeground(Color.GRAY);
            }
        });
        tab.add(closeLabel, BorderLayout.EAST);

        tab.addMouseListener(new MouseAdapter() {

            @Override
            public void mouseClicked(MouseEvent e) {
                if (e.getSource() == closeLabel) {
                    return;
                }
                if (SwingUtilities.isMiddleMouseButton(e)) {
                    closeRequestTab(item);
                } else {
                    activeRequest = item;
                    loadRequestIntoEditor(item);
                    refreshRequestTabs();
                }
            }
        });
        return tab;
    }

    private static Color methodColor(String method) {
        return switch (method) {
            case "GET" -> METHOD_GET;
            case "POST" -> METHOD_POST;
            case "PUT" -> METHOD_PUT;
            case "DELETE" -> METHOD_DELETE;
            case "PATCH" -> METHOD_PATCH;
            default -> Color.LIGHT_GRAY;
        };
    }

    // ==================== TREE CONTEXT MENU ====================

    private void installTreeContextMenu() {
        collectionTree.addMouseListener(new MouseAdapter() {

            @Override
            public void mousePressed(MouseEvent e) {
                if (e.isPopupTrigger()) {
                    showTreePopup(e);
                }
            }

            @Override
            public void mouseReleased(MouseEvent e) {
                if (e.isPopupTrigger()) {
                    showTreePopup(e);
                }
            }
        });
    }

    private void showTreePopup(MouseEvent e) {
        TreePath path = collectionTree.getPathForLocation(e.getX(), e.getY());
        if (path != null) {
            collectionTree.setSelectionPath(path);
        }
        DefaultMutableTreeNode node = path != null ? (DefaultMutableTreeNode) path.getLastPathComponent() : treeRoot;

        JPopupMenu menu = new JPopupMenu();

        JMenuItem newReq = new JMenuItem("New Request");
        newReq.addActionListener(ev -> addNewRequestToNode(node));
        menu.add(newReq);

        JMenuItem newFolder = new JMenuItem("New Folder");
        newFolder.addActionListener(ev -> addNewFolderToNode(node));
        menu.add(newFolder);

        if (node != treeRoot && node.getParent() != null) {
            menu.addSeparator();

            DefaultMutableTreeNode parent = (DefaultMutableTreeNode) node.getParent();
            int idx = parent.getIndex(node);

            JMenuItem moveUp = new JMenuItem("Move Up");
            moveUp.setEnabled(idx > 0);
            moveUp.addActionListener(ev -> moveNode(node, -1));
            menu.add(moveUp);

            JMenuItem moveDown = new JMenuItem("Move Down");
            moveDown.setEnabled(idx < parent.getChildCount() - 1);
            moveDown.addActionListener(ev -> moveNode(node, 1));
            menu.add(moveDown);
        }

        if (node.getUserObject() instanceof RequestItem) {
            menu.addSeparator();

            JMenuItem duplicate = new JMenuItem("Duplicate");
            duplicate.addActionListener(ev -> duplicateRequest(node));
            menu.add(duplicate);

            JMenuItem delete = new JMenuItem("Delete");
            delete.addActionListener(ev -> deleteNode(node));
            menu.add(delete);
        } else if (node != treeRoot) {
            menu.addSeparator();
            JMenuItem delete = new JMenuItem("Delete Folder");
            delete.addActionListener(ev -> deleteNode(node));
            menu.add(delete);
        }

        JMenuItem rename = new JMenuItem("Rename");
        rename.addActionListener(ev -> renameNode(node));
        menu.add(rename);

        menu.show(collectionTree, e.getX(), e.getY());
    }

    private void moveNode(DefaultMutableTreeNode node, int direction) {
        DefaultMutableTreeNode parent = (DefaultMutableTreeNode) node.getParent();
        int idx = parent.getIndex(node);
        int newIdx = idx + direction;
        if (newIdx < 0 || newIdx >= parent.getChildCount()) {
            return;
        }
        treeModel.removeNodeFromParent(node);
        treeModel.insertNodeInto(node, parent, newIdx);
        collectionTree.setSelectionPath(new TreePath(node.getPath()));
        rebuildCollectionFromTree();
    }

    private void addNewRequestToNode(DefaultMutableTreeNode parentNode) {
        HttpRequestDef req = HttpRequestDef.get("https://");
        RequestItem item = new RequestItem(null, "New Request", null, req, null, List.of(), null);

        DefaultMutableTreeNode newNode = new DefaultMutableTreeNode(item);
        DefaultMutableTreeNode target = parentNode.getUserObject() instanceof RequestItem
                ? (DefaultMutableTreeNode) parentNode.getParent()
                : parentNode;
        treeModel.insertNodeInto(newNode, target, target.getChildCount());
        collectionTree.scrollPathToVisible(new TreePath(newNode.getPath()));
        collectionTree.setSelectionPath(new TreePath(newNode.getPath()));
        rebuildCollectionFromTree();
    }

    private void addNewFolderToNode(DefaultMutableTreeNode parentNode) {
        String name = JOptionPane.showInputDialog(this, "Folder name:", "New Folder", JOptionPane.PLAIN_MESSAGE);
        if (name == null || name.isBlank()) {
            return;
        }
        DefaultMutableTreeNode folderNode = new DefaultMutableTreeNode(name);
        DefaultMutableTreeNode target = parentNode.getUserObject() instanceof RequestItem
                ? (DefaultMutableTreeNode) parentNode.getParent()
                : parentNode;
        treeModel.insertNodeInto(folderNode, target, target.getChildCount());
        collectionTree.scrollPathToVisible(new TreePath(folderNode.getPath()));
        rebuildCollectionFromTree();
    }

    private void duplicateRequest(DefaultMutableTreeNode node) {
        if (!(node.getUserObject() instanceof RequestItem original)) {
            return;
        }
        RequestItem copy = new RequestItem(null, original.name() + " (copy)", null, original.request(), original.vars(),
                original.assertions(), original.docs());
        DefaultMutableTreeNode newNode = new DefaultMutableTreeNode(copy);
        DefaultMutableTreeNode parent = (DefaultMutableTreeNode) node.getParent();
        int idx = parent.getIndex(node) + 1;
        treeModel.insertNodeInto(newNode, parent, idx);
        collectionTree.setSelectionPath(new TreePath(newNode.getPath()));
        rebuildCollectionFromTree();
    }

    private void deleteNode(DefaultMutableTreeNode node) {
        if (node == treeRoot) {
            return;
        }
        int confirm = JOptionPane.showConfirmDialog(this, "Delete '" + node.getUserObject() + "'?", "Delete",
                JOptionPane.YES_NO_OPTION);
        if (confirm == JOptionPane.YES_OPTION) {
            treeModel.removeNodeFromParent(node);
            rebuildCollectionFromTree();
        }
    }

    private void renameNode(DefaultMutableTreeNode node) {
        String current = node.getUserObject() instanceof RequestItem ri ? ri.name() : node.getUserObject().toString();
        String newName = JOptionPane.showInputDialog(this, "New name:", current);
        if (newName == null || newName.isBlank()) {
            return;
        }
        if (node.getUserObject() instanceof RequestItem ri) {
            node.setUserObject(
                    new RequestItem(ri.uid(), newName, ri.meta(), ri.request(), ri.vars(), ri.assertions(), ri.docs()));
        } else {
            node.setUserObject(newName);
        }
        treeModel.nodeChanged(node);
        rebuildCollectionFromTree();
    }

    private void rebuildCollectionFromTree() {
        if (currentCollection == null) {
            String name = treeRoot.getUserObject().toString();
            currentCollection = new Collection(null, name, null, List.of(), collectItemsFromNode(treeRoot), null, null);
        } else {
            currentCollection = new Collection(currentCollection.uid(), currentCollection.name(),
                    currentCollection.version(), currentCollection.environments(), collectItemsFromNode(treeRoot),
                    currentCollection.root(), currentCollection.settings());
        }
    }

    private List<CollectionItem> collectItemsFromNode(DefaultMutableTreeNode node) {
        List<CollectionItem> items = new ArrayList<>();
        for (int i = 0; i < node.getChildCount(); i++) {
            DefaultMutableTreeNode child = (DefaultMutableTreeNode) node.getChildAt(i);
            if (child.getUserObject() instanceof RequestItem ri) {
                items.add(ri);
            } else {
                items.add(new Folder(null, child.getUserObject().toString(), collectItemsFromNode(child), null));
            }
        }
        return items;
    }

    // ==================== DRAG AND DROP ====================

    private static final DataFlavor TREE_NODE_FLAVOR = new DataFlavor(DefaultMutableTreeNode.class, "TreeNode");

    private class TreeDragHandler extends TransferHandler {

        @Override
        public int getSourceActions(JComponent c) {
            return MOVE;
        }

        @Override
        protected Transferable createTransferable(JComponent c) {
            TreePath path = collectionTree.getSelectionPath();
            if (path == null) {
                return null;
            }
            DefaultMutableTreeNode node = (DefaultMutableTreeNode) path.getLastPathComponent();
            if (node == treeRoot) {
                return null;
            }
            return new NodeTransferable(node);
        }

        @Override
        public boolean canImport(TransferSupport support) {
            if (!support.isDrop() || !support.isDataFlavorSupported(TREE_NODE_FLAVOR)) {
                return false;
            }
            JTree.DropLocation dl = (JTree.DropLocation) support.getDropLocation();
            return dl.getPath() != null;
        }

        @Override
        public boolean importData(TransferSupport support) {
            if (!canImport(support)) {
                return false;
            }
            try {
                DefaultMutableTreeNode draggedNode = (DefaultMutableTreeNode) support.getTransferable()
                        .getTransferData(TREE_NODE_FLAVOR);
                JTree.DropLocation dl = (JTree.DropLocation) support.getDropLocation();
                TreePath destPath = dl.getPath();
                DefaultMutableTreeNode destParent = (DefaultMutableTreeNode) destPath.getLastPathComponent();
                int childIndex = dl.getChildIndex();

                if (destParent.getUserObject() instanceof RequestItem) {
                    DefaultMutableTreeNode realParent = (DefaultMutableTreeNode) destParent.getParent();
                    childIndex = realParent.getIndex(destParent);
                    destParent = realParent;
                }

                if (isAncestor(draggedNode, destParent)) {
                    return false;
                }

                treeModel.removeNodeFromParent(draggedNode);
                if (childIndex < 0 || childIndex > destParent.getChildCount()) {
                    childIndex = destParent.getChildCount();
                }
                treeModel.insertNodeInto(draggedNode, destParent, childIndex);
                collectionTree.setSelectionPath(new TreePath(draggedNode.getPath()));
                rebuildCollectionFromTree();
                return true;
            } catch (Exception e) {
                return false;
            }
        }

        private boolean isAncestor(DefaultMutableTreeNode ancestor, DefaultMutableTreeNode node) {
            javax.swing.tree.TreeNode current = node;
            while (current != null) {
                if (current == ancestor) {
                    return true;
                }
                current = current.getParent();
            }
            return false;
        }
    }

    private record NodeTransferable(DefaultMutableTreeNode node) implements Transferable {

        @Override
        public DataFlavor[] getTransferDataFlavors() {
            return new DataFlavor[]{TREE_NODE_FLAVOR};
        }

        @Override
        public boolean isDataFlavorSupported(DataFlavor flavor) {
            return TREE_NODE_FLAVOR.equals(flavor);
        }

        @Override
        public Object getTransferData(DataFlavor flavor) throws UnsupportedFlavorException {
            if (!isDataFlavorSupported(flavor)) {
                throw new UnsupportedFlavorException(flavor);
            }
            return node;
        }
    }

    // ==================== TREE SELECTION ====================

    private void onTreeSelection() {
        DefaultMutableTreeNode node = (DefaultMutableTreeNode) collectionTree.getLastSelectedPathComponent();
        if (node == null || !(node.getUserObject() instanceof RequestItem item)) {
            return;
        }
        openRequestTab(item);
        loadRequestIntoEditor(item);
    }

    private void loadRequestIntoEditor(RequestItem item) {
        HttpRequestDef req = item.request();
        methodCombo.setSelectedItem(req.method());
        urlField.setText(req.url());

        StringBuilder hdr = new StringBuilder();
        for (Header h : req.headers()) {
            if (h.enabled()) {
                hdr.append(h.name()).append(": ").append(h.value()).append("\n");
            }
        }
        headersArea.setText(hdr.toString());

        StringBuilder params = new StringBuilder();
        if (req.params() != null) {
            for (Param p : req.params().query()) {
                if (p.enabled()) {
                    params.append(p.name()).append("=").append(p.value()).append("\n");
                }
            }
            for (Param p : req.params().path()) {
                if (p.enabled()) {
                    params.append(":").append(p.name()).append("=").append(p.value()).append("\n");
                }
            }
        }
        paramsArea.setText(params.toString());

        bodyArea.setText(extractBodyText(req.body()));
        selectBodyType(req.body());
        populateAuth(req.auth());

        if (item.vars() != null) {
            StringBuilder pre = new StringBuilder();
            for (VarsDef.VarEntry v : item.vars().pre()) {
                pre.append(v.name()).append("=").append(v.value()).append("\n");
            }
            varsPreArea.setText(pre.toString());
            StringBuilder post = new StringBuilder();
            for (VarsDef.VarEntry v : item.vars().post()) {
                post.append(v.name()).append("=").append(v.value()).append("\n");
            }
            varsPostArea.setText(post.toString());
        } else {
            varsPreArea.setText("");
            varsPostArea.setText("");
        }

        assertTableModel.setRowCount(0);
        if (item.assertions() != null) {
            for (Assertion a : item.assertions()) {
                assertTableModel.addRow(new Object[]{a.lhs(), a.op().symbol(), a.rhs(), a.enabled()});
            }
        }

        docsArea.setText(item.docs() != null ? item.docs() : "");

        RequestSettings settings = req.settings() != null ? req.settings() : RequestSettings.defaults();
        settingsFollowRedirects.setSelected(settings.followRedirects());
        settingsTimeout.setValue(settings.timeoutMs());
        settingsEncodeUrl.setSelected(settings.encodeUrl());
    }

    private String extractBodyText(BodyConfig body) {
        return switch (body) {
            case BodyConfig.Json j -> j.content();
            case BodyConfig.Text t -> t.content();
            case BodyConfig.Xml x -> x.content();
            case BodyConfig.GraphQL g -> g.query();
            default -> "";
        };
    }

    private void selectBodyType(BodyConfig body) {
        String type = switch (body) {
            case BodyConfig.Json ignored -> "JSON";
            case BodyConfig.Xml ignored -> "XML";
            case BodyConfig.Text ignored -> "Text";
            case BodyConfig.FormUrlEncoded ignored -> "FormUrlEncoded";
            case BodyConfig.GraphQL ignored -> "GraphQL";
            default -> "None";
        };
        bodyTypeCombo.setSelectedItem(type);
    }

    private void populateAuth(AuthConfig auth) {
        authTypeCombo.setSelectedItem(auth.mode());
        String fields = switch (auth) {
            case AuthConfig.Bearer b -> "token=" + b.token();
            case AuthConfig.Basic b -> "username=" + b.username() + "\npassword=" + b.password();
            case AuthConfig.ApiKey a -> "key=" + a.key() + "\nvalue=" + a.value() + "\nplacement=" + a.placement();
            case AuthConfig.Digest d -> "username=" + d.username() + "\npassword=" + d.password();
            default -> "";
        };
        authFieldsArea.setText(fields);
    }

    // ==================== ENV EDITOR ====================

    private void openEnvEditor() {
        if (currentCollection == null) {
            currentCollection = new Collection(null, "New Collection", null, List.of(), List.of(), null, null);
            treeRoot.setUserObject(currentCollection.name());
            treeModel.nodeChanged(treeRoot);
        }
        JFrame frame = (JFrame) SwingUtilities.getWindowAncestor(this);
        EnvironmentEditorDialog dialog = new EnvironmentEditorDialog(frame, currentCollection);
        dialog.setVisible(true);
        if (dialog.isSaved()) {
            currentCollection = dialog.getUpdatedCollection();
            populateEnvCombo();
        }
    }

    // ==================== NEW REQUEST ====================

    private void addNewRequest() {
        HttpRequestDef req = HttpRequestDef.get("https://");
        RequestItem item = new RequestItem(null, "New Request", null, req, null, List.of(), null);

        if (currentCollection == null) {
            currentCollection = new Collection(null, "New Collection", null, List.of(), List.of(item), null, null);
            populateTree();
        } else {
            List<CollectionItem> items = new ArrayList<>(currentCollection.items());
            items.add(item);
            currentCollection = new Collection(currentCollection.uid(), currentCollection.name(),
                    currentCollection.version(), currentCollection.environments(), items, currentCollection.root(),
                    currentCollection.settings());
            populateTree();
        }

        int lastRow = collectionTree.getRowCount() - 1;
        if (lastRow >= 0) {
            collectionTree.setSelectionRow(lastRow);
        }
    }

    // ==================== SAVE ====================

    private void saveCollection() {
        if (currentCollection == null) {
            JOptionPane.showMessageDialog(this, "No collection to save.", "Save", JOptionPane.WARNING_MESSAGE);
            return;
        }
        Path savePath = collectionPath;
        if (savePath == null) {
            JFileChooser chooser = new JFileChooser();
            chooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
            chooser.setDialogTitle("Save Collection To");
            if (chooser.showSaveDialog(this) == JFileChooser.APPROVE_OPTION) {
                savePath = chooser.getSelectedFile().toPath();
            } else {
                return;
            }
        }
        try {
            new CollectionWriter().save(currentCollection, savePath);
            collectionPath = savePath;
            JOptionPane.showMessageDialog(this, "Collection saved to " + savePath, "Saved",
                    JOptionPane.INFORMATION_MESSAGE);
        } catch (Exception ex) {
            JOptionPane.showMessageDialog(this, "Save failed: " + ex.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
        }
    }

    // ==================== SEND / RUN ====================

    private void sendRequest() {
        String method = (String) methodCombo.getSelectedItem();
        String url = urlField.getText().trim();
        if (url.isBlank() || "https://".equals(url)) {
            responseStatus.setText("  URL required");
            return;
        }

        sendButton.setEnabled(false);
        responseStatus.setText("  Sending...");
        responseBody.setText("");
        responseHeaders.setText("");
        assertionsResultArea.setText("");

        Thread.ofVirtual().name("apiclient-send").start(() -> {
            try {
                RequestItem item = buildCurrentRequestItem();
                Collection coll = currentCollection != null
                        ? currentCollection
                        : new Collection(null, "adhoc", null, null, List.of(item), null, null);
                Environment env = getSelectedEnvironment();

                ensureSessionContext(coll, env);
                Interpolator interpolator = new Interpolator();
                RequestExecutor executor = new RequestExecutor(httpClient, interpolator, new AuthInjectorRegistry(),
                        new AssertionEngine(interpolator));
                RequestResult result = executor.execute(item, sessionContext, coll, msg -> {
                });

                autoExtractToken(result);

                SwingUtilities.invokeLater(() -> displayResult(result));
            } catch (Exception ex) {
                SwingUtilities.invokeLater(() -> responseStatus.setText("  Error: " + ex.getMessage()));
            } finally {
                SwingUtilities.invokeLater(() -> sendButton.setEnabled(true));
            }
        });
    }

    private RequestItem buildCurrentRequestItem() {
        String method = (String) methodCombo.getSelectedItem();
        String url = urlField.getText().trim();

        List<Header> headers = new ArrayList<>();
        for (String line : headersArea.getText().split("\n")) {
            int sep = line.indexOf(':');
            if (sep > 0) {
                headers.add(Header.of(line.substring(0, sep).trim(), line.substring(sep + 1).trim()));
            }
        }

        List<Param> queryParams = new ArrayList<>();
        List<Param> pathParams = new ArrayList<>();
        for (String line : paramsArea.getText().split("\n")) {
            int sep = line.indexOf('=');
            if (sep > 0) {
                String key = line.substring(0, sep).trim();
                String val = line.substring(sep + 1).trim();
                if (key.startsWith(":")) {
                    pathParams.add(new Param(key.substring(1), val, Param.ParamType.PATH, true));
                } else {
                    queryParams.add(new Param(key, val, Param.ParamType.QUERY, true));
                }
            }
        }
        ParamsDef params = new ParamsDef(queryParams, pathParams);

        List<VarsDef.VarEntry> preVars = new ArrayList<>();
        for (String line : varsPreArea.getText().split("\n")) {
            int sep = line.indexOf('=');
            if (sep > 0) {
                preVars.add(new VarsDef.VarEntry(line.substring(0, sep).trim(), line.substring(sep + 1).trim()));
            }
        }
        List<VarsDef.VarEntry> postVars = new ArrayList<>();
        for (String line : varsPostArea.getText().split("\n")) {
            int sep = line.indexOf('=');
            if (sep > 0) {
                postVars.add(new VarsDef.VarEntry(line.substring(0, sep).trim(), line.substring(sep + 1).trim()));
            }
        }
        VarsDef vars = new VarsDef(preVars, postVars);

        List<Assertion> assertions = new ArrayList<>();
        for (int i = 0; i < assertTableModel.getRowCount(); i++) {
            String expr = String.valueOf(assertTableModel.getValueAt(i, 0));
            String op = String.valueOf(assertTableModel.getValueAt(i, 1));
            String expected = String.valueOf(assertTableModel.getValueAt(i, 2));
            boolean enabled = Boolean.TRUE.equals(assertTableModel.getValueAt(i, 3));
            try {
                assertions.add(new Assertion(expr, AssertOp.fromSymbol(op), expected, enabled));
            } catch (IllegalArgumentException ignored) {
            }
        }

        BodyConfig body = buildBody();
        AuthConfig auth = buildAuth();

        HttpRequestDef req = new HttpRequestDef(method, url, params, headers, auth, body, null);
        String name = activeRequest != null ? activeRequest.name() : "Manual Request";
        int seq = activeRequest != null && activeRequest.meta() != null ? activeRequest.meta().seq() : 0;
        RequestMeta meta = RequestMeta.http(name, seq);
        return new RequestItem(null, name, meta, req, vars, assertions, null);
    }

    private BodyConfig buildBody() {
        String text = bodyArea.getText();
        String type = (String) bodyTypeCombo.getSelectedItem();
        if (text.isBlank() || "None".equals(type)) {
            return new BodyConfig.None();
        }
        return switch (type) {
            case "XML" -> new BodyConfig.Xml(text);
            case "Text" -> new BodyConfig.Text(text);
            case "GraphQL" -> new BodyConfig.GraphQL(text, null);
            case "FormUrlEncoded" -> {
                List<Param> formParams = new ArrayList<>();
                for (String line : text.split("\n")) {
                    int sep = line.indexOf('=');
                    if (sep > 0) {
                        formParams.add(new Param(line.substring(0, sep).trim(), line.substring(sep + 1).trim(),
                                Param.ParamType.QUERY, true));
                    }
                }
                yield new BodyConfig.FormUrlEncoded(formParams);
            }
            default -> new BodyConfig.Json(text);
        };
    }

    private AuthConfig buildAuth() {
        String mode = (String) authTypeCombo.getSelectedItem();
        String fields = authFieldsArea.getText();
        java.util.Map<String, String> map = new java.util.LinkedHashMap<>();
        for (String line : fields.split("\n")) {
            int sep = line.indexOf('=');
            if (sep > 0) {
                map.put(line.substring(0, sep).trim(), line.substring(sep + 1).trim());
            }
        }
        return switch (mode) {
            case "bearer" -> new AuthConfig.Bearer(map.getOrDefault("token", ""));
            case "basic" -> new AuthConfig.Basic(map.getOrDefault("username", ""), map.getOrDefault("password", ""));
            case "apikey" -> new AuthConfig.ApiKey(map.getOrDefault("key", ""), map.getOrDefault("value", ""),
                    map.getOrDefault("placement", "header"));
            case "digest" -> new AuthConfig.Digest(map.getOrDefault("username", ""), map.getOrDefault("password", ""));
            default -> new AuthConfig.None();
        };
    }

    private void ensureSessionContext(Collection coll, Environment env) {
        if (sessionContext == null) {
            VariableStore vars = new VariableStore();
            vars.loadCollection(coll.root());
            if (env != null) {
                vars.loadEnv(env);
            }
            sessionContext = new RunContext(vars);
        } else if (env != null) {
            sessionContext.vars().loadEnv(env);
        }
    }

    private void resetSessionContext() {
        sessionContext = null;
    }

    private static final String[] TOKEN_FIELDS = {"token", "accessToken", "access_token", "jwt"};

    private void autoExtractToken(RequestResult result) {
        if (result.response() == null || result.response().status() >= 300) {
            return;
        }
        String body = result.response().body();
        if (body == null || body.isBlank() || !body.trim().startsWith("{")) {
            return;
        }
        try {
            com.google.gson.JsonObject obj = com.google.gson.JsonParser.parseString(body).getAsJsonObject();
            for (String field : TOKEN_FIELDS) {
                if (obj.has(field) && obj.get(field).isJsonPrimitive()) {
                    String value = obj.get(field).getAsString();
                    if (value != null && !value.isBlank()) {
                        sessionContext.vars().setRuntime("token", value);
                        return;
                    }
                }
            }
        } catch (Exception ignored) {
        }
    }

    private void displayResult(RequestResult result) {
        if (result.response() != null) {
            var resp = result.response();
            String statusText = resp.statusText() != null && !resp.statusText().isEmpty()
                    ? resp.statusText()
                    : String.valueOf(resp.status());
            responseStatus.setText(String.format("  %d %s  %dms  %s", resp.status(), statusText, resp.responseTimeMs(),
                    formatBytes(resp.body().length())));

            responseBody.setText(resp.body());
            responseBody.setCaretPosition(0);

            String ct = resp.header("content-type");
            responseBody.setSyntaxEditingStyle(detectSyntax(ct != null ? ct : ""));

            StringBuilder hdr = new StringBuilder();
            int headerCount = 0;
            for (var entry : resp.headers().entrySet()) {
                for (String v : entry.getValue()) {
                    hdr.append(entry.getKey()).append(": ").append(v).append("\n");
                    headerCount++;
                }
            }
            responseHeaders.setText(hdr.toString());
            responseTabPane.setTitleAt(1, "Headers " + headerCount);
        } else {
            responseStatus.setText("  No response");
        }

        if (result.assertions() != null && !result.assertions().isEmpty()) {
            StringBuilder sb = new StringBuilder();
            for (AssertionResult ar : result.assertions()) {
                String status = ar.passed() ? "PASS" : "FAIL";
                sb.append("[").append(status).append("] ").append(ar.assertion().lhs()).append(" ")
                        .append(ar.assertion().op()).append(" ").append(ar.assertion().rhs());
                if (!ar.passed()) {
                    sb.append(" (actual: ").append(ar.actual()).append(")");
                }
                sb.append("\n");
            }
            assertionsResultArea.setText(sb.toString());
        }
    }

    private static String formatBytes(int bytes) {
        if (bytes < 1024) {
            return bytes + "B";
        }
        return String.format("%.1fKB", bytes / 1024.0);
    }

    // ==================== LOAD / IMPORT ====================

    private void chooseAndLoadCollection() {
        JFileChooser chooser = new JFileChooser();
        chooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
        chooser.setDialogTitle("Select Collection Directory");
        if (chooser.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
            loadCollection(chooser.getSelectedFile().toPath());
        }
    }

    public void loadCollection(Path dir) {
        try {
            if (java.nio.file.Files.exists(dir.resolve("collection.json"))) {
                CollectionLoader loader = new CollectionLoader();
                currentCollection = loader.load(dir);
            } else if (hasBruFiles(dir)) {
                currentCollection = new BruImporter().importDirectory(dir);
            } else {
                JOptionPane.showMessageDialog(this,
                        "No collection.json or .bru files found in:\n" + dir
                                + "\n\nUse 'Import...' for Postman/OpenAPI files.",
                        "Not a collection", JOptionPane.WARNING_MESSAGE);
                return;
            }
            collectionPath = dir;
            openRequests.clear();
            activeRequest = null;
            resetSessionContext();
            populateTree();
            populateEnvCombo();
            refreshRequestTabs();
        } catch (Exception ex) {
            JOptionPane.showMessageDialog(this, "Failed to load collection: " + ex.getMessage(), "Error",
                    JOptionPane.ERROR_MESSAGE);
        }
    }

    private boolean hasBruFiles(Path dir) {
        try (var stream = java.nio.file.Files.walk(dir, 3)) {
            return stream.anyMatch(p -> p.toString().endsWith(".bru"));
        } catch (Exception e) {
            return false;
        }
    }

    private void populateTree() {
        treeRoot = new DefaultMutableTreeNode(currentCollection.name());
        addItemsToNode(treeRoot, currentCollection.items());
        treeModel.setRoot(treeRoot);
        for (int i = 0; i < collectionTree.getRowCount(); i++) {
            collectionTree.expandRow(i);
        }
    }

    private void addItemsToNode(DefaultMutableTreeNode parent, List<CollectionItem> items) {
        for (CollectionItem item : items) {
            switch (item) {
                case Folder folder -> {
                    DefaultMutableTreeNode folderNode = new DefaultMutableTreeNode(folder.name());
                    addItemsToNode(folderNode, folder.items());
                    parent.add(folderNode);
                }
                case RequestItem req -> {
                    DefaultMutableTreeNode reqNode = new DefaultMutableTreeNode(req);
                    parent.add(reqNode);
                }
            }
        }
    }

    private void populateEnvCombo() {
        envCombo.removeAllItems();
        envCombo.addItem("(no env)");
        if (currentCollection != null) {
            for (Environment env : currentCollection.environments()) {
                envCombo.addItem(env.name());
            }
        }
    }

    private Environment getSelectedEnvironment() {
        if (currentCollection == null || envCombo.getSelectedIndex() <= 0) {
            return null;
        }
        String name = (String) envCombo.getSelectedItem();
        return currentCollection.environments().stream().filter(e -> e.name().equals(name)).findFirst().orElse(null);
    }

    private void showImportMenu(JButton anchor) {
        JPopupMenu menu = new JPopupMenu();

        JMenuItem postman = new JMenuItem("Postman Collection...");
        postman.addActionListener(e -> importPostman());
        menu.add(postman);

        JMenuItem openapi = new JMenuItem("OpenAPI Spec...");
        openapi.addActionListener(e -> importOpenApi());
        menu.add(openapi);

        JMenuItem bruno = new JMenuItem("Bruno Directory...");
        bruno.addActionListener(e -> importBruno());
        menu.add(bruno);

        JMenuItem curl = new JMenuItem("cURL Command...");
        curl.addActionListener(e -> importCurl());
        menu.add(curl);

        menu.show(anchor, 0, anchor.getHeight());
    }

    private void importPostman() {
        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Select Postman Collection JSON");
        if (chooser.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
            try {
                currentCollection = new PostmanImporter().importFile(chooser.getSelectedFile().toPath());
                collectionPath = null;
                resetSessionContext();
                populateTree();
                populateEnvCombo();
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(this, "Import failed: " + ex.getMessage(), "Error",
                        JOptionPane.ERROR_MESSAGE);
            }
        }
    }

    private void importOpenApi() {
        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Select OpenAPI Spec (JSON/YAML)");
        if (chooser.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
            try {
                currentCollection = new OpenApiImporter().importFile(chooser.getSelectedFile().toPath());
                collectionPath = null;
                resetSessionContext();
                populateTree();
                populateEnvCombo();
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(this, "Import failed: " + ex.getMessage(), "Error",
                        JOptionPane.ERROR_MESSAGE);
            }
        }
    }

    private void importBruno() {
        JFileChooser chooser = new JFileChooser();
        chooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
        chooser.setDialogTitle("Select Bruno Collection Directory");
        if (chooser.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
            try {
                currentCollection = new BruImporter().importDirectory(chooser.getSelectedFile().toPath());
                collectionPath = null;
                resetSessionContext();
                populateTree();
                populateEnvCombo();
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(this, "Import failed: " + ex.getMessage(), "Error",
                        JOptionPane.ERROR_MESSAGE);
            }
        }
    }

    private void importCurl() {
        String cmd = JOptionPane.showInputDialog(this, "Paste cURL command:", "Import cURL", JOptionPane.PLAIN_MESSAGE);
        if (cmd != null && !cmd.isBlank()) {
            try {
                RequestItem item = new CurlImporter().importCurl(cmd);
                currentCollection = new Collection(null, "cURL Import", null, null, List.of(item), null, null);
                collectionPath = null;
                resetSessionContext();
                populateTree();
                populateEnvCombo();
                onTreeSelection();
                methodCombo.setSelectedItem(item.request().method());
                urlField.setText(item.request().url());
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(this, "Import failed: " + ex.getMessage(), "Error",
                        JOptionPane.ERROR_MESSAGE);
            }
        }
    }

    private void runCollection() {
        if (currentCollection == null) {
            JOptionPane.showMessageDialog(this, "No collection loaded.", "Run", JOptionPane.WARNING_MESSAGE);
            return;
        }

        Thread.ofVirtual().name("apiclient-run").start(() -> {
            try {
                Environment env = getSelectedEnvironment();
                Interpolator interpolator = new Interpolator();
                RequestExecutor executor = new RequestExecutor(httpClient, interpolator, new AuthInjectorRegistry(),
                        new AssertionEngine(interpolator));
                CollectionRunner runner = new CollectionRunner(executor);

                runLog.clear();
                RunResult result = runner.run(currentCollection, env, msg -> runLog.add(msg));

                SwingUtilities.invokeLater(() -> showRunResult(result));
            } catch (Exception ex) {
                SwingUtilities.invokeLater(() -> JOptionPane.showMessageDialog(this, "Run failed: " + ex.getMessage(),
                        "Error", JOptionPane.ERROR_MESSAGE));
            }
        });
    }

    private void showRunResult(RunResult result) {
        StringBuilder sb = new StringBuilder();
        sb.append("Collection: ").append(currentCollection.name()).append("\n");
        sb.append("Total: ").append(result.summary().total()).append(" | Passed: ").append(result.summary().passed())
                .append(" | Failed: ").append(result.summary().failed()).append("\n");
        sb.append("Duration: ").append(result.durationMs()).append("ms\n\n");
        runLog.forEach(l -> sb.append(l).append("\n"));

        JTextArea logArea = new JTextArea(sb.toString());
        logArea.setEditable(false);
        logArea.setFont(monoFont());
        JScrollPane scroll = new JScrollPane(logArea);
        scroll.setPreferredSize(new Dimension(600, 400));
        JOptionPane.showMessageDialog(this, scroll, "Collection Run Result", JOptionPane.INFORMATION_MESSAGE);
    }

    // ==================== UTIL ====================

    private RSyntaxTextArea createSyntaxArea(boolean readOnly) {
        RSyntaxTextArea area = new RSyntaxTextArea(12, 60);
        area.setEditable(!readOnly);
        area.setCodeFoldingEnabled(true);
        area.setAntiAliasingEnabled(true);
        area.setTabSize(2);
        try {
            Theme theme = Theme.load(getClass().getResourceAsStream("/org/fife/ui/rsyntaxtextarea/themes/dark.xml"));
            theme.apply(area);
        } catch (Exception e) {
            area.setBackground(new Color(0x1E, 0x1E, 0x2E));
            area.setForeground(Color.WHITE);
            area.setCaretColor(Color.WHITE);
        }
        return area;
    }

    private static String detectSyntax(String contentType) {
        String ct = contentType.toLowerCase();
        if (ct.contains("json")) {
            return SyntaxConstants.SYNTAX_STYLE_JSON;
        }
        if (ct.contains("html")) {
            return SyntaxConstants.SYNTAX_STYLE_HTML;
        }
        if (ct.contains("xml")) {
            return SyntaxConstants.SYNTAX_STYLE_XML;
        }
        if (ct.contains("javascript")) {
            return SyntaxConstants.SYNTAX_STYLE_JAVASCRIPT;
        }
        return SyntaxConstants.SYNTAX_STYLE_NONE;
    }

    private static Font monoFont() {
        return new Font(Font.MONOSPACED, Font.PLAIN, 12);
    }
}
