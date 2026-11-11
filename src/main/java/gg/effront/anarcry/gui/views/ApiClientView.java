package gg.effront.anarcry.gui.views;

import gg.effront.anarcry.apiclient.auth.AuthInjectorRegistry;
import gg.effront.anarcry.apiclient.io.BruImporter;
import gg.effront.anarcry.apiclient.io.CollectionLoader;
import gg.effront.anarcry.apiclient.io.CollectionWriter;
import gg.effront.anarcry.apiclient.io.CurlGenerator;
import gg.effront.anarcry.apiclient.io.CurlImporter;
import gg.effront.anarcry.apiclient.io.InsomniaImporter;
import gg.effront.anarcry.apiclient.io.OpenApiImporter;
import gg.effront.anarcry.apiclient.io.PostmanImporter;
import gg.effront.anarcry.apiclient.model.AssertOp;
import gg.effront.anarcry.apiclient.model.Assertion;
import gg.effront.anarcry.apiclient.model.AssertionResult;
import gg.effront.anarcry.apiclient.model.AuthConfig;
import gg.effront.anarcry.apiclient.model.BodyConfig;
import gg.effront.anarcry.apiclient.model.Collection;
import gg.effront.anarcry.apiclient.model.CollectionItem;
import gg.effront.anarcry.apiclient.model.EnvVariable;
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
import gg.effront.anarcry.apiclient.model.RunSummary;
import gg.effront.anarcry.apiclient.model.ScriptDef;
import gg.effront.anarcry.apiclient.model.VarsDef;
import gg.effront.anarcry.apiclient.script.ScriptResult;
import gg.effront.anarcry.apiclient.runner.AssertionEngine;
import gg.effront.anarcry.apiclient.runner.CollectionRunner;
import gg.effront.anarcry.apiclient.runner.RequestExecutor;
import gg.effront.anarcry.apiclient.runner.RunContext;
import gg.effront.anarcry.apiclient.vars.Interpolator;
import gg.effront.anarcry.apiclient.vars.VariableStore;
import gg.effront.anarcry.gui.components.KvTableEditor;

import java.awt.BorderLayout;
import java.awt.CardLayout;
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
import javax.swing.DefaultListModel;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JComponent;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JList;
import javax.swing.JMenuItem;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
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
    private KvTableEditor headersEditor;
    private RSyntaxTextArea bodyArea;
    private KvTableEditor formBodyEditor;
    private CardLayout bodyCardLayout;
    private JPanel bodyCardPanel;
    private KvTableEditor paramsEditor;
    private JComboBox<String> authTypeCombo;
    private CardLayout authCardLayout;
    private JPanel authCards;
    private JTextField authBearerToken;
    private JTextField authBasicUser;
    private JTextField authBasicPass;
    private JTextField authApiKeyKey;
    private JTextField authApiKeyValue;
    private JComboBox<String> authApiKeyPlacement;
    private JTextField authDigestUser;
    private JTextField authDigestPass;
    private JTextField authWsseUser;
    private JTextField authWssePass;
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
    private DefaultTableModel cookiesTableModel;
    private DefaultTableModel variablesTableModel;
    private JPanel requestTabsPanel;
    private JButton overflowButton;

    private JTextField authOAuth2GrantType;
    private JTextField authOAuth2TokenUrl;
    private JTextField authOAuth2ClientId;
    private JTextField authOAuth2ClientSecret;
    private JTextField authOAuth2Scope;
    private JTextField authOAuth2CallbackUrl;
    private JTextField authOAuth2AuthUrl;
    private JCheckBox authOAuth2Pkce;
    private JTextField authNtlmUser;
    private JTextField authNtlmPass;
    private JTextField authNtlmDomain;
    private JTextField authAwsAccessKey;
    private JTextField authAwsSecretKey;
    private JTextField authAwsSession;
    private JTextField authAwsService;
    private JTextField authAwsRegion;
    private JTextField authOAuth1ConsumerKey;
    private JTextField authOAuth1ConsumerSecret;
    private JTextField authOAuth1AccessToken;
    private JTextField authOAuth1TokenSecret;
    private JTextField authEdgeAccessToken;
    private JTextField authEdgeClientToken;
    private JTextField authEdgeClientSecret;

    private RSyntaxTextArea preRequestScriptArea;
    private RSyntaxTextArea postResponseScriptArea;
    private RSyntaxTextArea testsScriptArea;
    private JTextArea scriptConsoleArea;
    private JCheckBox proxyEnabled;
    private JComboBox<String> proxyProtocolCombo;
    private JTextField proxyHost;
    private JSpinner proxyPort;
    private JTextField proxyUser;
    private JPasswordField proxyPass;

    private Collection currentCollection;
    private Path collectionPath;
    private RequestItem activeRequest;
    private final List<RequestItem> openRequests = new ArrayList<>();
    private final java.net.CookieManager cookieManager;
    private final HttpClient httpClient;
    private final List<String> runLog = new ArrayList<>();
    private RunContext sessionContext;
    private DefaultListModel<RequestResult> historyModel;
    private JList<RequestResult> historyList;

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

        historyModel = new DefaultListModel<>();
        historyList = new JList<>(historyModel);
        historyList.setFont(monoFont());
        historyList.setCellRenderer(new javax.swing.DefaultListCellRenderer() {
            @Override
            public Component getListCellRendererComponent(JList<?> list, Object value, int index, boolean isSelected,
                    boolean cellHasFocus) {
                super.getListCellRendererComponent(list, value, index, isSelected, cellHasFocus);
                if (value instanceof RequestResult rr) {
                    String method = rr.interpolatedRequest() != null ? rr.interpolatedRequest().method() : "?";
                    int status = rr.response() != null ? rr.response().status() : 0;
                    String url = rr.interpolatedRequest() != null ? rr.interpolatedRequest().url() : "";
                    setText(method + " " + status + " " + url);
                    setForeground(statusColor(status));
                }
                return this;
            }
        });
        historyList.addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                RequestResult sel = historyList.getSelectedValue();
                if (sel != null) {
                    displayResult(sel);
                }
            }
        });

        JPanel historyPanel = new JPanel(new BorderLayout());
        JLabel historyLabel = new JLabel(" History");
        historyLabel.setFont(historyLabel.getFont().deriveFont(Font.BOLD, 11f));
        JButton clearHistBtn = new JButton("Clear");
        clearHistBtn.setFont(clearHistBtn.getFont().deriveFont(10f));
        clearHistBtn.setMargin(new java.awt.Insets(1, 4, 1, 4));
        clearHistBtn.addActionListener(e -> historyModel.clear());
        JPanel histTop = new JPanel(new BorderLayout());
        histTop.add(historyLabel, BorderLayout.WEST);
        histTop.add(clearHistBtn, BorderLayout.EAST);
        historyPanel.add(histTop, BorderLayout.NORTH);
        historyPanel.add(new JScrollPane(historyList), BorderLayout.CENTER);

        JSplitPane sidebarSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT, new JScrollPane(collectionTree),
                historyPanel);
        sidebarSplit.setResizeWeight(0.75);
        sidebar.add(sidebarSplit, BorderLayout.CENTER);

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

        JButton copyCurlBtn = new JButton("cURL");
        copyCurlBtn.setToolTipText("Copy as cURL command");
        copyCurlBtn.addActionListener(e -> copyAsCurl());

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

        JPanel sendPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 4, 0));
        sendPanel.add(copyCurlBtn);
        sendPanel.add(sendButton);

        JPanel rightBar = new JPanel(new BorderLayout(4, 0));
        rightBar.add(envPanel, BorderLayout.CENTER);
        rightBar.add(sendPanel, BorderLayout.EAST);

        bar.add(left, BorderLayout.CENTER);
        bar.add(rightBar, BorderLayout.EAST);
        return bar;
    }

    // ==================== REQUEST EDITOR ====================

    private JTabbedPane buildRequestEditor() {
        JTabbedPane tabs = new JTabbedPane();

        headersEditor = new KvTableEditor();
        headersEditor.addRow("User-Agent", gg.effront.anarcry.Version.userAgent(), true);
        headersEditor.addRow("Accept", "*/*", true);
        tabs.addTab("Headers", headersEditor);

        JPanel bodyPanel = new JPanel(new BorderLayout());
        bodyTypeCombo = new JComboBox<>(new String[]{"JSON", "Text", "XML", "FormUrlEncoded", "GraphQL", "None"});
        bodyTypeCombo.addActionListener(e -> updateBodySyntax());
        JPanel bodyTopBar = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 2));
        bodyTopBar.add(new JLabel("Type:"));
        bodyTopBar.add(bodyTypeCombo);
        bodyPanel.add(bodyTopBar, BorderLayout.NORTH);
        bodyCardLayout = new CardLayout();
        bodyCardPanel = new JPanel(bodyCardLayout);
        bodyArea = createSyntaxArea(false);
        bodyArea.setSyntaxEditingStyle(SyntaxConstants.SYNTAX_STYLE_JSON);
        bodyCardPanel.add(new RTextScrollPane(bodyArea), "text");
        formBodyEditor = new KvTableEditor();
        bodyCardPanel.add(formBodyEditor, "form");
        bodyPanel.add(bodyCardPanel, BorderLayout.CENTER);
        tabs.addTab("Body", bodyPanel);

        paramsEditor = new KvTableEditor();
        tabs.addTab("Params", paramsEditor);

        JPanel authPanel = new JPanel(new BorderLayout(4, 4));
        authPanel.setBorder(BorderFactory.createEmptyBorder(4, 4, 4, 4));
        authTypeCombo = new JComboBox<>(new String[]{"none", "inherit", "bearer", "basic", "apikey", "digest", "oauth2",
                "wsse", "ntlm", "awsv4", "oauth1", "akamai-edgegrid"});
        authTypeCombo.addActionListener(e -> {
            String sel = (String) authTypeCombo.getSelectedItem();
            if (sel != null) {
                authCardLayout.show(authCards, sel);
            }
        });

        authCardLayout = new CardLayout();
        authCards = new JPanel(authCardLayout);
        authCards.add(new JLabel("No authentication"), "none");
        authCards.add(new JLabel("Inherits from parent folder / collection"), "inherit");
        authCards.add(buildBearerCard(), "bearer");
        authCards.add(buildBasicCard(), "basic");
        authCards.add(buildApiKeyCard(), "apikey");
        authCards.add(buildDigestCard(), "digest");
        authCards.add(buildOAuth2Card(), "oauth2");
        authCards.add(buildWsseCard(), "wsse");
        authCards.add(buildNtlmCard(), "ntlm");
        authCards.add(buildAwsV4Card(), "awsv4");
        authCards.add(buildOAuth1Card(), "oauth1");
        authCards.add(buildEdgeGridCard(), "akamai-edgegrid");

        authPanel.add(authTypeCombo, BorderLayout.NORTH);
        authPanel.add(authCards, BorderLayout.CENTER);
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

        tabs.addTab("Script", buildScriptPanel());

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
        gbc.gridx = 0;
        gbc.weightx = 0;
        gbc.fill = java.awt.GridBagConstraints.NONE;
        settingsPanel.add(new JLabel("--- Proxy ---"), gbc);
        gbc.gridy++;
        proxyEnabled = new JCheckBox("Enable Proxy");
        settingsPanel.add(proxyEnabled, gbc);
        gbc.gridy++;
        JPanel proxyRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 0));
        proxyProtocolCombo = new JComboBox<>(new String[]{"http", "https", "socks5"});
        proxyHost = new JTextField(15);
        proxyHost.setFont(monoFont());
        proxyPort = new JSpinner(new SpinnerNumberModel(8080, 1, 65535, 1));
        proxyRow.add(proxyProtocolCombo);
        proxyRow.add(new JLabel("://"));
        proxyRow.add(proxyHost);
        proxyRow.add(new JLabel(":"));
        proxyRow.add(proxyPort);
        settingsPanel.add(proxyRow, gbc);
        gbc.gridy++;
        JPanel proxyAuthRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 0));
        proxyAuthRow.add(new JLabel("User:"));
        proxyUser = new JTextField(10);
        proxyUser.setFont(monoFont());
        proxyAuthRow.add(proxyUser);
        proxyAuthRow.add(new JLabel("Pass:"));
        proxyPass = new JPasswordField(10);
        proxyPass.setFont(monoFont());
        proxyAuthRow.add(proxyPass);
        settingsPanel.add(proxyAuthRow, gbc);
        gbc.gridy++;
        gbc.weighty = 1.0;
        settingsPanel.add(new JLabel(), gbc);
        tabs.addTab("Settings", settingsPanel);

        return tabs;
    }

    private JPanel buildScriptPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        JTabbedPane scriptTabs = new JTabbedPane();

        preRequestScriptArea = createSyntaxArea(false);
        preRequestScriptArea.setSyntaxEditingStyle(SyntaxConstants.SYNTAX_STYLE_JAVASCRIPT);
        scriptTabs.addTab("Pre-request", new RTextScrollPane(preRequestScriptArea));

        postResponseScriptArea = createSyntaxArea(false);
        postResponseScriptArea.setSyntaxEditingStyle(SyntaxConstants.SYNTAX_STYLE_JAVASCRIPT);
        scriptTabs.addTab("Post-response", new RTextScrollPane(postResponseScriptArea));

        testsScriptArea = createSyntaxArea(false);
        testsScriptArea.setSyntaxEditingStyle(SyntaxConstants.SYNTAX_STYLE_JAVASCRIPT);
        scriptTabs.addTab("Tests", new RTextScrollPane(testsScriptArea));

        panel.add(scriptTabs, BorderLayout.CENTER);
        return panel;
    }

    private void updateBodySyntax() {
        String type = (String) bodyTypeCombo.getSelectedItem();
        if ("FormUrlEncoded".equals(type)) {
            bodyCardLayout.show(bodyCardPanel, "form");
        } else {
            bodyCardLayout.show(bodyCardPanel, "text");
            bodyArea.setSyntaxEditingStyle(switch (type) {
                case "JSON" -> SyntaxConstants.SYNTAX_STYLE_JSON;
                case "XML" -> SyntaxConstants.SYNTAX_STYLE_XML;
                case "GraphQL" -> SyntaxConstants.SYNTAX_STYLE_JAVASCRIPT;
                default -> SyntaxConstants.SYNTAX_STYLE_NONE;
            });
        }
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
        JButton saveRespBtn = new JButton("Save");
        saveRespBtn.setFont(saveRespBtn.getFont().deriveFont(11f));
        saveRespBtn.addActionListener(e -> saveResponse());
        respButtons.add(copyBtn);
        respButtons.add(prettifyBtn);
        respButtons.add(saveRespBtn);
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

        cookiesTableModel = new DefaultTableModel(
                new String[]{"Name", "Value", "Domain", "Path", "Expires", "HttpOnly", "Secure"}, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }
        };
        JTable cookiesTable = new JTable(cookiesTableModel);
        cookiesTable.setFont(monoFont());
        responseTabPane.addTab("Cookies", new JScrollPane(cookiesTable));

        variablesTableModel = new DefaultTableModel(new String[]{"Scope", "Key", "Value"}, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }
        };
        JTable variablesTable = new JTable(variablesTableModel);
        variablesTable.setFont(monoFont());
        variablesTable.setRowHeight(22);
        variablesTable.getColumnModel().getColumn(0).setPreferredWidth(80);
        variablesTable.getColumnModel().getColumn(0).setMaxWidth(100);
        variablesTable.getColumnModel().getColumn(1).setPreferredWidth(150);
        variablesTable.getColumnModel().getColumn(2).setPreferredWidth(300);
        responseTabPane.addTab("Variables", new JScrollPane(variablesTable));

        scriptConsoleArea = new JTextArea(6, 40);
        scriptConsoleArea.setEditable(false);
        scriptConsoleArea.setFont(monoFont());
        responseTabPane.addTab("Console", new JScrollPane(scriptConsoleArea));

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

    private void saveResponse() {
        String text = responseBody.getText();
        if (text.isBlank()) {
            responseStatus.setText("  No response to save");
            return;
        }
        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Save Response");
        String ext = responseBody.getSyntaxEditingStyle().contains("json")
                ? ".json"
                : responseBody.getSyntaxEditingStyle().contains("html")
                        ? ".html"
                        : responseBody.getSyntaxEditingStyle().contains("xml") ? ".xml" : ".txt";
        chooser.setSelectedFile(new java.io.File("response" + ext));
        if (chooser.showSaveDialog(this) == JFileChooser.APPROVE_OPTION) {
            try {
                java.nio.file.Files.writeString(chooser.getSelectedFile().toPath(), text);
                responseStatus.setText("  Saved to " + chooser.getSelectedFile().getName());
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(this, "Save failed: " + ex.getMessage(), "Error",
                        JOptionPane.ERROR_MESSAGE);
            }
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

        if (node.getUserObject() instanceof RequestItem reqItem) {
            menu.addSeparator();

            JMenuItem copyCurl = new JMenuItem("Copy as cURL");
            copyCurl.addActionListener(ev -> {
                String curl = CurlGenerator.generate(reqItem.request());
                copyToClipboard(curl);
            });
            menu.add(copyCurl);

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

        List<KvTableEditor.Entry> headerEntries = new ArrayList<>();
        for (Header h : req.headers()) {
            headerEntries.add(new KvTableEditor.Entry(h.name(), h.value(), h.enabled()));
        }
        headersEditor.setEntries(headerEntries);

        List<KvTableEditor.Entry> paramEntries = new ArrayList<>();
        if (req.params() != null) {
            for (Param p : req.params().query()) {
                paramEntries.add(new KvTableEditor.Entry(p.name(), p.value(), p.enabled()));
            }
            for (Param p : req.params().path()) {
                paramEntries.add(new KvTableEditor.Entry(":" + p.name(), p.value(), p.enabled()));
            }
        }
        paramsEditor.setEntries(paramEntries);

        if (req.body() instanceof BodyConfig.FormUrlEncoded f) {
            List<KvTableEditor.Entry> formEntries = new ArrayList<>();
            for (Param p : f.params()) {
                formEntries.add(new KvTableEditor.Entry(p.name(), p.value(), p.enabled()));
            }
            formBodyEditor.setEntries(formEntries);
            bodyArea.setText("");
        } else {
            formBodyEditor.clear();
            bodyArea.setText(extractBodyText(req.body()));
        }
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

        if (item.scripts() != null) {
            preRequestScriptArea.setText(item.scripts().preRequest());
            postResponseScriptArea.setText(item.scripts().postResponse());
            testsScriptArea.setText(item.scripts().tests());
        } else {
            preRequestScriptArea.setText("");
            postResponseScriptArea.setText("");
            testsScriptArea.setText("");
        }
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

    private JPanel buildBearerCard() {
        JPanel p = authFormPanel();
        java.awt.GridBagConstraints g = authFormGbc();
        p.add(new JLabel("Token:"), g);
        g.gridx = 1;
        g.fill = java.awt.GridBagConstraints.HORIZONTAL;
        g.weightx = 1.0;
        authBearerToken = new JTextField(30);
        authBearerToken.setFont(monoFont());
        p.add(authBearerToken, g);
        g.gridy++;
        g.weighty = 1.0;
        p.add(new JLabel(), g);
        return p;
    }

    private JPanel buildBasicCard() {
        JPanel p = authFormPanel();
        java.awt.GridBagConstraints g = authFormGbc();
        p.add(new JLabel("Username:"), g);
        g.gridx = 1;
        g.fill = java.awt.GridBagConstraints.HORIZONTAL;
        g.weightx = 1.0;
        authBasicUser = new JTextField(30);
        authBasicUser.setFont(monoFont());
        p.add(authBasicUser, g);
        g.gridx = 0;
        g.gridy = 1;
        g.fill = java.awt.GridBagConstraints.NONE;
        g.weightx = 0;
        p.add(new JLabel("Password:"), g);
        g.gridx = 1;
        g.fill = java.awt.GridBagConstraints.HORIZONTAL;
        g.weightx = 1.0;
        authBasicPass = new JTextField(30);
        authBasicPass.setFont(monoFont());
        p.add(authBasicPass, g);
        g.gridy++;
        g.weighty = 1.0;
        p.add(new JLabel(), g);
        return p;
    }

    private JPanel buildApiKeyCard() {
        JPanel p = authFormPanel();
        java.awt.GridBagConstraints g = authFormGbc();
        p.add(new JLabel("Key:"), g);
        g.gridx = 1;
        g.fill = java.awt.GridBagConstraints.HORIZONTAL;
        g.weightx = 1.0;
        authApiKeyKey = new JTextField(30);
        authApiKeyKey.setFont(monoFont());
        p.add(authApiKeyKey, g);
        g.gridx = 0;
        g.gridy = 1;
        g.fill = java.awt.GridBagConstraints.NONE;
        g.weightx = 0;
        p.add(new JLabel("Value:"), g);
        g.gridx = 1;
        g.fill = java.awt.GridBagConstraints.HORIZONTAL;
        g.weightx = 1.0;
        authApiKeyValue = new JTextField(30);
        authApiKeyValue.setFont(monoFont());
        p.add(authApiKeyValue, g);
        g.gridx = 0;
        g.gridy = 2;
        g.fill = java.awt.GridBagConstraints.NONE;
        g.weightx = 0;
        p.add(new JLabel("Add to:"), g);
        g.gridx = 1;
        g.fill = java.awt.GridBagConstraints.HORIZONTAL;
        g.weightx = 1.0;
        authApiKeyPlacement = new JComboBox<>(new String[]{"header", "queryparams"});
        p.add(authApiKeyPlacement, g);
        g.gridy++;
        g.weighty = 1.0;
        p.add(new JLabel(), g);
        return p;
    }

    private JPanel buildDigestCard() {
        JPanel p = authFormPanel();
        java.awt.GridBagConstraints g = authFormGbc();
        p.add(new JLabel("Username:"), g);
        g.gridx = 1;
        g.fill = java.awt.GridBagConstraints.HORIZONTAL;
        g.weightx = 1.0;
        authDigestUser = new JTextField(30);
        authDigestUser.setFont(monoFont());
        p.add(authDigestUser, g);
        g.gridx = 0;
        g.gridy = 1;
        g.fill = java.awt.GridBagConstraints.NONE;
        g.weightx = 0;
        p.add(new JLabel("Password:"), g);
        g.gridx = 1;
        g.fill = java.awt.GridBagConstraints.HORIZONTAL;
        g.weightx = 1.0;
        authDigestPass = new JTextField(30);
        authDigestPass.setFont(monoFont());
        p.add(authDigestPass, g);
        g.gridy++;
        g.weighty = 1.0;
        p.add(new JLabel(), g);
        return p;
    }

    private JPanel buildWsseCard() {
        JPanel p = authFormPanel();
        java.awt.GridBagConstraints g = authFormGbc();
        p.add(new JLabel("Username:"), g);
        g.gridx = 1;
        g.fill = java.awt.GridBagConstraints.HORIZONTAL;
        g.weightx = 1.0;
        authWsseUser = new JTextField(30);
        authWsseUser.setFont(monoFont());
        p.add(authWsseUser, g);
        g.gridx = 0;
        g.gridy = 1;
        g.fill = java.awt.GridBagConstraints.NONE;
        g.weightx = 0;
        p.add(new JLabel("Password:"), g);
        g.gridx = 1;
        g.fill = java.awt.GridBagConstraints.HORIZONTAL;
        g.weightx = 1.0;
        authWssePass = new JTextField(30);
        authWssePass.setFont(monoFont());
        p.add(authWssePass, g);
        g.gridy++;
        g.weighty = 1.0;
        p.add(new JLabel(), g);
        return p;
    }

    private JPanel buildOAuth2Card() {
        JPanel p = authFormPanel();
        java.awt.GridBagConstraints g = authFormGbc();
        p.add(new JLabel("Grant Type:"), g);
        g.gridx = 1;
        g.fill = java.awt.GridBagConstraints.HORIZONTAL;
        g.weightx = 1.0;
        authOAuth2GrantType = new JTextField("client_credentials", 30);
        authOAuth2GrantType.setFont(monoFont());
        p.add(authOAuth2GrantType, g);
        g.gridx = 0;
        g.gridy++;
        g.fill = java.awt.GridBagConstraints.NONE;
        g.weightx = 0;
        p.add(new JLabel("Access Token URL:"), g);
        g.gridx = 1;
        g.fill = java.awt.GridBagConstraints.HORIZONTAL;
        g.weightx = 1.0;
        authOAuth2TokenUrl = new JTextField(30);
        authOAuth2TokenUrl.setFont(monoFont());
        p.add(authOAuth2TokenUrl, g);
        g.gridx = 0;
        g.gridy++;
        g.fill = java.awt.GridBagConstraints.NONE;
        g.weightx = 0;
        p.add(new JLabel("Client ID:"), g);
        g.gridx = 1;
        g.fill = java.awt.GridBagConstraints.HORIZONTAL;
        g.weightx = 1.0;
        authOAuth2ClientId = new JTextField(30);
        authOAuth2ClientId.setFont(monoFont());
        p.add(authOAuth2ClientId, g);
        g.gridx = 0;
        g.gridy++;
        g.fill = java.awt.GridBagConstraints.NONE;
        g.weightx = 0;
        p.add(new JLabel("Client Secret:"), g);
        g.gridx = 1;
        g.fill = java.awt.GridBagConstraints.HORIZONTAL;
        g.weightx = 1.0;
        authOAuth2ClientSecret = new JTextField(30);
        authOAuth2ClientSecret.setFont(monoFont());
        p.add(authOAuth2ClientSecret, g);
        g.gridx = 0;
        g.gridy++;
        g.fill = java.awt.GridBagConstraints.NONE;
        g.weightx = 0;
        p.add(new JLabel("Scope:"), g);
        g.gridx = 1;
        g.fill = java.awt.GridBagConstraints.HORIZONTAL;
        g.weightx = 1.0;
        authOAuth2Scope = new JTextField(30);
        authOAuth2Scope.setFont(monoFont());
        p.add(authOAuth2Scope, g);
        g.gridx = 0;
        g.gridy++;
        g.fill = java.awt.GridBagConstraints.NONE;
        g.weightx = 0;
        p.add(new JLabel("Authorization URL:"), g);
        g.gridx = 1;
        g.fill = java.awt.GridBagConstraints.HORIZONTAL;
        g.weightx = 1.0;
        authOAuth2AuthUrl = new JTextField(30);
        authOAuth2AuthUrl.setFont(monoFont());
        p.add(authOAuth2AuthUrl, g);
        g.gridx = 0;
        g.gridy++;
        g.fill = java.awt.GridBagConstraints.NONE;
        g.weightx = 0;
        p.add(new JLabel("Callback URL:"), g);
        g.gridx = 1;
        g.fill = java.awt.GridBagConstraints.HORIZONTAL;
        g.weightx = 1.0;
        authOAuth2CallbackUrl = new JTextField(30);
        authOAuth2CallbackUrl.setFont(monoFont());
        p.add(authOAuth2CallbackUrl, g);
        g.gridx = 0;
        g.gridy++;
        g.fill = java.awt.GridBagConstraints.NONE;
        g.weightx = 0;
        authOAuth2Pkce = new JCheckBox("PKCE");
        p.add(authOAuth2Pkce, g);
        g.gridy++;
        g.gridx = 1;
        g.weighty = 1.0;
        p.add(new JLabel(""), g);
        return p;
    }

    private JPanel buildNtlmCard() {
        JPanel p = authFormPanel();
        java.awt.GridBagConstraints g = authFormGbc();
        p.add(new JLabel("Username:"), g);
        g.gridx = 1;
        g.fill = java.awt.GridBagConstraints.HORIZONTAL;
        g.weightx = 1.0;
        authNtlmUser = new JTextField(30);
        authNtlmUser.setFont(monoFont());
        p.add(authNtlmUser, g);
        g.gridx = 0;
        g.gridy++;
        g.fill = java.awt.GridBagConstraints.NONE;
        g.weightx = 0;
        p.add(new JLabel("Password:"), g);
        g.gridx = 1;
        g.fill = java.awt.GridBagConstraints.HORIZONTAL;
        g.weightx = 1.0;
        authNtlmPass = new JTextField(30);
        authNtlmPass.setFont(monoFont());
        p.add(authNtlmPass, g);
        g.gridx = 0;
        g.gridy++;
        g.fill = java.awt.GridBagConstraints.NONE;
        g.weightx = 0;
        p.add(new JLabel("Domain:"), g);
        g.gridx = 1;
        g.fill = java.awt.GridBagConstraints.HORIZONTAL;
        g.weightx = 1.0;
        authNtlmDomain = new JTextField(30);
        authNtlmDomain.setFont(monoFont());
        p.add(authNtlmDomain, g);
        g.gridy++;
        g.weighty = 1.0;
        p.add(new JLabel(""), g);
        return p;
    }

    private JPanel buildAwsV4Card() {
        JPanel p = authFormPanel();
        java.awt.GridBagConstraints g = authFormGbc();
        p.add(new JLabel("Access Key ID:"), g);
        g.gridx = 1;
        g.fill = java.awt.GridBagConstraints.HORIZONTAL;
        g.weightx = 1.0;
        authAwsAccessKey = new JTextField(30);
        authAwsAccessKey.setFont(monoFont());
        p.add(authAwsAccessKey, g);
        g.gridx = 0;
        g.gridy++;
        g.fill = java.awt.GridBagConstraints.NONE;
        g.weightx = 0;
        p.add(new JLabel("Secret Access Key:"), g);
        g.gridx = 1;
        g.fill = java.awt.GridBagConstraints.HORIZONTAL;
        g.weightx = 1.0;
        authAwsSecretKey = new JTextField(30);
        authAwsSecretKey.setFont(monoFont());
        p.add(authAwsSecretKey, g);
        g.gridx = 0;
        g.gridy++;
        g.fill = java.awt.GridBagConstraints.NONE;
        g.weightx = 0;
        p.add(new JLabel("Session Token:"), g);
        g.gridx = 1;
        g.fill = java.awt.GridBagConstraints.HORIZONTAL;
        g.weightx = 1.0;
        authAwsSession = new JTextField(30);
        authAwsSession.setFont(monoFont());
        p.add(authAwsSession, g);
        g.gridx = 0;
        g.gridy++;
        g.fill = java.awt.GridBagConstraints.NONE;
        g.weightx = 0;
        p.add(new JLabel("Service:"), g);
        g.gridx = 1;
        g.fill = java.awt.GridBagConstraints.HORIZONTAL;
        g.weightx = 1.0;
        authAwsService = new JTextField(30);
        authAwsService.setFont(monoFont());
        p.add(authAwsService, g);
        g.gridx = 0;
        g.gridy++;
        g.fill = java.awt.GridBagConstraints.NONE;
        g.weightx = 0;
        p.add(new JLabel("Region:"), g);
        g.gridx = 1;
        g.fill = java.awt.GridBagConstraints.HORIZONTAL;
        g.weightx = 1.0;
        authAwsRegion = new JTextField(30);
        authAwsRegion.setFont(monoFont());
        p.add(authAwsRegion, g);
        g.gridy++;
        g.weighty = 1.0;
        p.add(new JLabel(""), g);
        return p;
    }

    private JPanel buildOAuth1Card() {
        JPanel p = authFormPanel();
        java.awt.GridBagConstraints g = authFormGbc();
        p.add(new JLabel("Consumer Key:"), g);
        g.gridx = 1;
        g.fill = java.awt.GridBagConstraints.HORIZONTAL;
        g.weightx = 1.0;
        authOAuth1ConsumerKey = new JTextField(30);
        authOAuth1ConsumerKey.setFont(monoFont());
        p.add(authOAuth1ConsumerKey, g);
        g.gridx = 0;
        g.gridy++;
        g.fill = java.awt.GridBagConstraints.NONE;
        g.weightx = 0;
        p.add(new JLabel("Consumer Secret:"), g);
        g.gridx = 1;
        g.fill = java.awt.GridBagConstraints.HORIZONTAL;
        g.weightx = 1.0;
        authOAuth1ConsumerSecret = new JTextField(30);
        authOAuth1ConsumerSecret.setFont(monoFont());
        p.add(authOAuth1ConsumerSecret, g);
        g.gridx = 0;
        g.gridy++;
        g.fill = java.awt.GridBagConstraints.NONE;
        g.weightx = 0;
        p.add(new JLabel("Access Token:"), g);
        g.gridx = 1;
        g.fill = java.awt.GridBagConstraints.HORIZONTAL;
        g.weightx = 1.0;
        authOAuth1AccessToken = new JTextField(30);
        authOAuth1AccessToken.setFont(monoFont());
        p.add(authOAuth1AccessToken, g);
        g.gridx = 0;
        g.gridy++;
        g.fill = java.awt.GridBagConstraints.NONE;
        g.weightx = 0;
        p.add(new JLabel("Token Secret:"), g);
        g.gridx = 1;
        g.fill = java.awt.GridBagConstraints.HORIZONTAL;
        g.weightx = 1.0;
        authOAuth1TokenSecret = new JTextField(30);
        authOAuth1TokenSecret.setFont(monoFont());
        p.add(authOAuth1TokenSecret, g);
        g.gridy++;
        g.weighty = 1.0;
        p.add(new JLabel(""), g);
        return p;
    }

    private JPanel buildEdgeGridCard() {
        JPanel p = authFormPanel();
        java.awt.GridBagConstraints g = authFormGbc();
        p.add(new JLabel("Access Token:"), g);
        g.gridx = 1;
        g.fill = java.awt.GridBagConstraints.HORIZONTAL;
        g.weightx = 1.0;
        authEdgeAccessToken = new JTextField(30);
        authEdgeAccessToken.setFont(monoFont());
        p.add(authEdgeAccessToken, g);
        g.gridx = 0;
        g.gridy++;
        g.fill = java.awt.GridBagConstraints.NONE;
        g.weightx = 0;
        p.add(new JLabel("Client Token:"), g);
        g.gridx = 1;
        g.fill = java.awt.GridBagConstraints.HORIZONTAL;
        g.weightx = 1.0;
        authEdgeClientToken = new JTextField(30);
        authEdgeClientToken.setFont(monoFont());
        p.add(authEdgeClientToken, g);
        g.gridx = 0;
        g.gridy++;
        g.fill = java.awt.GridBagConstraints.NONE;
        g.weightx = 0;
        p.add(new JLabel("Client Secret:"), g);
        g.gridx = 1;
        g.fill = java.awt.GridBagConstraints.HORIZONTAL;
        g.weightx = 1.0;
        authEdgeClientSecret = new JTextField(30);
        authEdgeClientSecret.setFont(monoFont());
        p.add(authEdgeClientSecret, g);
        g.gridy++;
        g.weighty = 1.0;
        p.add(new JLabel(""), g);
        return p;
    }

    private static JPanel authFormPanel() {
        JPanel p = new JPanel(new java.awt.GridBagLayout());
        p.setBorder(BorderFactory.createEmptyBorder(4, 0, 4, 0));
        return p;
    }

    private static java.awt.GridBagConstraints authFormGbc() {
        java.awt.GridBagConstraints g = new java.awt.GridBagConstraints();
        g.insets = new java.awt.Insets(2, 4, 2, 4);
        g.anchor = java.awt.GridBagConstraints.WEST;
        g.gridx = 0;
        g.gridy = 0;
        return g;
    }

    private void populateAuth(AuthConfig auth) {
        authTypeCombo.setSelectedItem(auth.mode());
        clearAuthCards();
        switch (auth) {
            case AuthConfig.Bearer b -> authBearerToken.setText(b.token());
            case AuthConfig.Basic b -> {
                authBasicUser.setText(b.username());
                authBasicPass.setText(b.password());
            }
            case AuthConfig.ApiKey a -> {
                authApiKeyKey.setText(a.key());
                authApiKeyValue.setText(a.value());
                authApiKeyPlacement.setSelectedItem(a.placement());
            }
            case AuthConfig.Digest d -> {
                authDigestUser.setText(d.username());
                authDigestPass.setText(d.password());
            }
            case AuthConfig.Wsse w -> {
                authWsseUser.setText(w.username());
                authWssePass.setText(w.password());
            }
            case AuthConfig.OAuth2 o -> {
                authOAuth2GrantType.setText(o.grantType());
                authOAuth2TokenUrl.setText(o.accessTokenUrl());
                authOAuth2ClientId.setText(o.clientId());
                authOAuth2ClientSecret.setText(o.clientSecret());
                authOAuth2Scope.setText(o.scope());
                authOAuth2AuthUrl.setText(o.authorizationUrl() != null ? o.authorizationUrl() : "");
                authOAuth2CallbackUrl.setText(o.callbackUrl() != null ? o.callbackUrl() : "");
                authOAuth2Pkce.setSelected(o.pkce());
            }
            case AuthConfig.Ntlm n -> {
                authNtlmUser.setText(n.username());
                authNtlmPass.setText(n.password());
                authNtlmDomain.setText(n.domain());
            }
            case AuthConfig.AwsV4 a -> {
                authAwsAccessKey.setText(a.accessKeyId());
                authAwsSecretKey.setText(a.secretAccessKey());
                authAwsSession.setText(a.sessionToken() != null ? a.sessionToken() : "");
                authAwsService.setText(a.service());
                authAwsRegion.setText(a.region());
            }
            case AuthConfig.OAuth1 o -> {
                authOAuth1ConsumerKey.setText(o.consumerKey());
                authOAuth1ConsumerSecret.setText(o.consumerSecret());
                authOAuth1AccessToken.setText(o.accessToken());
                authOAuth1TokenSecret.setText(o.tokenSecret());
            }
            case AuthConfig.EdgeGrid eg -> {
                authEdgeAccessToken.setText(eg.accessToken());
                authEdgeClientToken.setText(eg.clientToken());
                authEdgeClientSecret.setText(eg.clientSecret());
            }
            default -> {
            }
        }
        authCardLayout.show(authCards, auth.mode());
    }

    private void clearAuthCards() {
        authBearerToken.setText("");
        authBasicUser.setText("");
        authBasicPass.setText("");
        authApiKeyKey.setText("");
        authApiKeyValue.setText("");
        authApiKeyPlacement.setSelectedIndex(0);
        authDigestUser.setText("");
        authDigestPass.setText("");
        authWsseUser.setText("");
        authWssePass.setText("");
        authOAuth2GrantType.setText("client_credentials");
        authOAuth2TokenUrl.setText("");
        authOAuth2ClientId.setText("");
        authOAuth2ClientSecret.setText("");
        authOAuth2Scope.setText("");
        authOAuth2AuthUrl.setText("");
        authOAuth2CallbackUrl.setText("");
        authOAuth2Pkce.setSelected(false);
        authNtlmUser.setText("");
        authNtlmPass.setText("");
        authNtlmDomain.setText("");
        authAwsAccessKey.setText("");
        authAwsSecretKey.setText("");
        authAwsSession.setText("");
        authAwsService.setText("");
        authAwsRegion.setText("");
        authOAuth1ConsumerKey.setText("");
        authOAuth1ConsumerSecret.setText("");
        authOAuth1AccessToken.setText("");
        authOAuth1TokenSecret.setText("");
        authEdgeAccessToken.setText("");
        authEdgeClientToken.setText("");
        authEdgeClientSecret.setText("");
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

    private void copyAsCurl() {
        RequestItem item = buildCurrentRequestItem();
        String curl = CurlGenerator.generate(item.request());
        copyToClipboard(curl);
        responseStatus.setText("  cURL copied to clipboard");
    }

    private void copyToClipboard(String text) {
        java.awt.Toolkit.getDefaultToolkit().getSystemClipboard()
                .setContents(new java.awt.datatransfer.StringSelection(text), null);
    }

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

                SwingUtilities.invokeLater(() -> {
                    displayResult(result);
                    addToHistory(result);
                });
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
        for (KvTableEditor.Entry e : headersEditor.getEntries()) {
            headers.add(new Header(e.key(), e.value(), e.enabled()));
        }

        List<Param> queryParams = new ArrayList<>();
        List<Param> pathParams = new ArrayList<>();
        for (KvTableEditor.Entry e : paramsEditor.getEntries()) {
            if (e.key().startsWith(":")) {
                pathParams.add(new Param(e.key().substring(1), e.value(), Param.ParamType.PATH, e.enabled()));
            } else {
                queryParams.add(new Param(e.key(), e.value(), Param.ParamType.QUERY, e.enabled()));
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
        ScriptDef scripts = new ScriptDef(preRequestScriptArea.getText(), postResponseScriptArea.getText(),
                testsScriptArea.getText());
        return new RequestItem(null, name, meta, req, vars, assertions, null, scripts);
    }

    private BodyConfig buildBody() {
        String type = (String) bodyTypeCombo.getSelectedItem();
        if ("None".equals(type)) {
            return new BodyConfig.None();
        }
        if ("FormUrlEncoded".equals(type)) {
            List<Param> formParams = new ArrayList<>();
            for (KvTableEditor.Entry e : formBodyEditor.getEntries()) {
                formParams.add(new Param(e.key(), e.value(), Param.ParamType.QUERY, e.enabled()));
            }
            return new BodyConfig.FormUrlEncoded(formParams);
        }
        String text = bodyArea.getText();
        if (text.isBlank()) {
            return new BodyConfig.None();
        }
        return switch (type) {
            case "XML" -> new BodyConfig.Xml(text);
            case "Text" -> new BodyConfig.Text(text);
            case "GraphQL" -> new BodyConfig.GraphQL(text, null);
            default -> new BodyConfig.Json(text);
        };
    }

    private AuthConfig buildAuth() {
        String mode = (String) authTypeCombo.getSelectedItem();
        return switch (mode) {
            case "inherit" -> new AuthConfig.Inherit();
            case "bearer" -> new AuthConfig.Bearer(authBearerToken.getText());
            case "basic" -> new AuthConfig.Basic(authBasicUser.getText(), authBasicPass.getText());
            case "apikey" -> new AuthConfig.ApiKey(authApiKeyKey.getText(), authApiKeyValue.getText(),
                    (String) authApiKeyPlacement.getSelectedItem());
            case "digest" -> new AuthConfig.Digest(authDigestUser.getText(), authDigestPass.getText());
            case "wsse" -> new AuthConfig.Wsse(authWsseUser.getText(), authWssePass.getText());
            case "oauth2" -> new AuthConfig.OAuth2(authOAuth2GrantType.getText(), authOAuth2TokenUrl.getText(), "",
                    authOAuth2ClientId.getText(), authOAuth2ClientSecret.getText(), authOAuth2Scope.getText(),
                    authOAuth2CallbackUrl.getText(), authOAuth2AuthUrl.getText(), authOAuth2Pkce.isSelected(), "body",
                    "header", false, false, java.util.Map.of());
            case "ntlm" ->
                new AuthConfig.Ntlm(authNtlmUser.getText(), authNtlmPass.getText(), authNtlmDomain.getText());
            case "awsv4" -> new AuthConfig.AwsV4(authAwsAccessKey.getText(), authAwsSecretKey.getText(),
                    authAwsSession.getText(), authAwsService.getText(), authAwsRegion.getText());
            case "oauth1" -> new AuthConfig.OAuth1(authOAuth1ConsumerKey.getText(), authOAuth1ConsumerSecret.getText(),
                    authOAuth1AccessToken.getText(), authOAuth1TokenSecret.getText(), "HMAC-SHA1", "header");
            case "akamai-edgegrid" -> new AuthConfig.EdgeGrid(authEdgeAccessToken.getText(),
                    authEdgeClientToken.getText(), authEdgeClientSecret.getText());
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

    private static final int MAX_HISTORY = 50;

    private void addToHistory(RequestResult result) {
        historyModel.add(0, result);
        if (historyModel.size() > MAX_HISTORY) {
            historyModel.remove(historyModel.size() - 1);
        }
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
        cookiesTableModel.setRowCount(0);
        if (result.response() != null) {
            var resp = result.response();
            String statusText = resp.statusText() != null && !resp.statusText().isEmpty()
                    ? resp.statusText()
                    : String.valueOf(resp.status());
            responseStatus.setText(String.format("  %d %s  %dms  %s", resp.status(), statusText, resp.responseTimeMs(),
                    formatBytes(resp.body().length())));
            responseStatus.setForeground(statusColor(resp.status()));

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

            parseCookies(resp.headers());
            int cookieCount = cookiesTableModel.getRowCount();
            responseTabPane.setTitleAt(3, cookieCount > 0 ? "Cookies " + cookieCount : "Cookies");
        } else {
            responseStatus.setText("  No response");
            responseStatus.setForeground(Color.GRAY);
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

        populateVariablesTab();
        populateScriptConsole();
    }

    private void populateScriptConsole() {
        scriptConsoleArea.setText("");
        if (sessionContext == null) {
            return;
        }
        ScriptResult sr = sessionContext.lastScriptResult();
        if (sr == null) {
            return;
        }
        StringBuilder sb = new StringBuilder();
        for (String line : sr.consoleLog()) {
            sb.append(line).append("\n");
        }
        if (sr.hasError()) {
            sb.append("[ERROR] ").append(sr.error()).append("\n");
        }
        if (!sr.testResults().isEmpty()) {
            sb.append("\n--- Test Results ---\n");
            int passed = 0;
            int failed = 0;
            for (ScriptResult.TestResult t : sr.testResults()) {
                String status = t.passed() ? "PASS" : "FAIL";
                sb.append("[").append(status).append("] ").append(t.name());
                if (!t.message().isEmpty()) {
                    sb.append(" -- ").append(t.message());
                }
                sb.append("\n");
                if (t.passed()) {
                    passed++;
                } else {
                    failed++;
                }
            }
            sb.append("\n").append(passed).append(" passed, ").append(failed).append(" failed\n");
        }
        scriptConsoleArea.setText(sb.toString());
        int consoleIdx = responseTabPane.indexOfTab("Console");
        if (consoleIdx >= 0 && !sr.testResults().isEmpty()) {
            int total = sr.testResults().size();
            int failCount = sr.testsFailed();
            String label = failCount > 0 ? "Console (" + failCount + " FAIL)" : "Console (" + total + " PASS)";
            responseTabPane.setTitleAt(consoleIdx, label);
        } else if (consoleIdx >= 0) {
            responseTabPane.setTitleAt(consoleIdx, "Console");
        }
    }

    private void populateVariablesTab() {
        variablesTableModel.setRowCount(0);
        if (sessionContext == null) {
            return;
        }
        VariableStore vars = sessionContext.vars();
        vars.envVars().forEach(
                (k, v) -> variablesTableModel.addRow(new Object[]{"env", k, vars.isSecret(k) ? "********" : v}));
        vars.collectionVars().forEach((k, v) -> variablesTableModel.addRow(new Object[]{"collection", k, v}));
        vars.folderVars().forEach((k, v) -> variablesTableModel.addRow(new Object[]{"folder", k, v}));
        vars.runtimeVars().forEach((k, v) -> variablesTableModel.addRow(new Object[]{"runtime", k, v}));
        vars.requestVars().forEach((k, v) -> variablesTableModel.addRow(new Object[]{"request", k, v}));
    }

    private static String formatBytes(int bytes) {
        if (bytes < 1024) {
            return bytes + "B";
        }
        return String.format("%.1fKB", bytes / 1024.0);
    }

    private static Color statusColor(int code) {
        if (code >= 200 && code < 300) {
            return METHOD_GET;
        }
        if (code >= 300 && code < 400) {
            return METHOD_PUT;
        }
        if (code >= 400 && code < 500) {
            return METHOD_POST;
        }
        if (code >= 500) {
            return METHOD_DELETE;
        }
        return Color.GRAY;
    }

    private void parseCookies(java.util.Map<String, java.util.List<String>> headers) {
        for (var entry : headers.entrySet()) {
            if (!"set-cookie".equalsIgnoreCase(entry.getKey())) {
                continue;
            }
            for (String raw : entry.getValue()) {
                String name = "";
                String value = "";
                String domain = "";
                String path = "";
                String expires = "";
                String httpOnly = "";
                String secure = "";

                String[] parts = raw.split(";");
                for (int i = 0; i < parts.length; i++) {
                    String part = parts[i].trim();
                    if (i == 0) {
                        int eq = part.indexOf('=');
                        if (eq > 0) {
                            name = part.substring(0, eq).trim();
                            value = part.substring(eq + 1).trim();
                        }
                    } else {
                        String lower = part.toLowerCase(java.util.Locale.ROOT);
                        if (lower.startsWith("domain=")) {
                            domain = part.substring(7).trim();
                        } else if (lower.startsWith("path=")) {
                            path = part.substring(5).trim();
                        } else if (lower.startsWith("expires=")) {
                            expires = part.substring(8).trim();
                        } else if (lower.startsWith("max-age=")) {
                            expires = "max-age=" + part.substring(8).trim();
                        } else if ("httponly".equals(lower)) {
                            httpOnly = "Yes";
                        } else if ("secure".equals(lower)) {
                            secure = "Yes";
                        }
                    }
                }
                cookiesTableModel.addRow(new Object[]{name, value, domain, path, expires, httpOnly, secure});
            }
        }
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
            loadDotEnv(dir);
            populateTree();
            populateEnvCombo();
            refreshRequestTabs();
        } catch (Exception ex) {
            JOptionPane.showMessageDialog(this, "Failed to load collection: " + ex.getMessage(), "Error",
                    JOptionPane.ERROR_MESSAGE);
        }
    }

    private void loadDotEnv(Path dir) {
        Path dotEnv = dir.resolve(".env");
        if (!java.nio.file.Files.isRegularFile(dotEnv)) {
            return;
        }
        try {
            List<EnvVariable> vars = new ArrayList<>();
            for (String line : java.nio.file.Files.readAllLines(dotEnv)) {
                String trimmed = line.trim();
                if (trimmed.isEmpty() || trimmed.startsWith("#")) {
                    continue;
                }
                int eq = trimmed.indexOf('=');
                if (eq > 0) {
                    String key = trimmed.substring(0, eq).trim();
                    String value = trimmed.substring(eq + 1).trim();
                    if (value.startsWith("\"") && value.endsWith("\"") && value.length() >= 2) {
                        value = value.substring(1, value.length() - 1);
                    }
                    vars.add(EnvVariable.of(key, value));
                }
            }
            if (!vars.isEmpty()) {
                List<Environment> envs = new ArrayList<>(currentCollection.environments());
                envs.add(0, new Environment(null, ".env", null, vars, null));
                currentCollection = new Collection(currentCollection.uid(), currentCollection.name(),
                        currentCollection.version(), envs, currentCollection.items(), currentCollection.root(),
                        currentCollection.settings());
            }
        } catch (Exception ignored) {
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

        JMenuItem insomnia = new JMenuItem("Insomnia Export...");
        insomnia.addActionListener(e -> importInsomnia());
        menu.add(insomnia);

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

    private void importInsomnia() {
        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Select Insomnia Export JSON");
        if (chooser.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
            try {
                currentCollection = new InsomniaImporter().importFile(chooser.getSelectedFile().toPath());
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
        removeRunResultsTab();

        JPanel panel = new JPanel(new BorderLayout(0, 4));

        RunSummary summary = result.summary();
        JPanel summaryBar = new JPanel(new FlowLayout(FlowLayout.LEFT, 12, 4));
        summaryBar.add(summaryLabel("Total: " + summary.total(), Color.GRAY));
        summaryBar.add(summaryLabel("Passed: " + summary.passed(), METHOD_GET));
        summaryBar.add(summaryLabel("Failed: " + summary.failed(), METHOD_DELETE));
        if (summary.skipped() > 0) {
            summaryBar.add(summaryLabel("Skipped: " + summary.skipped(), METHOD_PUT));
        }
        summaryBar.add(summaryLabel(result.durationMs() + "ms", Color.GRAY));
        JButton closeBtn = new JButton("X");
        closeBtn.setFont(closeBtn.getFont().deriveFont(Font.BOLD, 10f));
        closeBtn.setMargin(new java.awt.Insets(0, 4, 0, 4));
        closeBtn.addActionListener(e -> removeRunResultsTab());
        summaryBar.add(closeBtn);
        panel.add(summaryBar, BorderLayout.NORTH);

        String[] columns = {"#", "Name", "Method", "URL", "Status", "Time", "Asserts", "Result"};
        DefaultTableModel model = new DefaultTableModel(columns, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }
        };

        List<RequestResult> results = result.results();
        for (int i = 0; i < results.size(); i++) {
            RequestResult rr = results.get(i);
            String name = rr.item() != null ? rr.item().name() : "?";
            String method = rr.interpolatedRequest() != null ? rr.interpolatedRequest().method() : "?";
            String url = rr.interpolatedRequest() != null ? rr.interpolatedRequest().url() : "";
            int status = rr.response() != null ? rr.response().status() : 0;
            long time = rr.durationMs();
            int assertCount = rr.assertions() != null ? rr.assertions().size() : 0;
            long assertPassed = rr.assertions() != null
                    ? rr.assertions().stream().filter(AssertionResult::passed).count()
                    : 0;
            String assertText = assertCount > 0 ? assertPassed + "/" + assertCount : "-";
            String passText = rr.passed() ? "PASS" : "FAIL";

            model.addRow(new Object[]{i + 1, name, method, url, status, time + "ms", assertText, passText});
        }

        JTable table = new JTable(model);
        table.setFont(monoFont());
        table.setRowHeight(22);
        table.getColumnModel().getColumn(0).setMaxWidth(35);
        table.getColumnModel().getColumn(2).setMaxWidth(70);
        table.getColumnModel().getColumn(4).setMaxWidth(60);
        table.getColumnModel().getColumn(5).setMaxWidth(70);
        table.getColumnModel().getColumn(6).setMaxWidth(60);
        table.getColumnModel().getColumn(7).setMaxWidth(50);
        table.setDefaultRenderer(Object.class, new javax.swing.table.DefaultTableCellRenderer() {
            @Override
            public java.awt.Component getTableCellRendererComponent(JTable t, Object value, boolean isSelected,
                    boolean hasFocus, int row, int column) {
                super.getTableCellRendererComponent(t, value, isSelected, hasFocus, row, column);
                if (!isSelected) {
                    if (column == 4 && value instanceof Integer code) {
                        setForeground(statusColor(code));
                    } else if (column == 7) {
                        setForeground("PASS".equals(value) ? METHOD_GET : METHOD_DELETE);
                    } else {
                        setForeground(t.getForeground());
                    }
                }
                return this;
            }
        });

        table.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                int row = table.getSelectedRow();
                if (row >= 0 && row < results.size()) {
                    displayResult(results.get(row));
                }
            }
        });

        panel.add(new JScrollPane(table), BorderLayout.CENTER);

        responseTabPane.addTab("Run Results", panel);
        responseTabPane.setSelectedComponent(panel);
    }

    private void removeRunResultsTab() {
        for (int i = responseTabPane.getTabCount() - 1; i >= 0; i--) {
            if ("Run Results".equals(responseTabPane.getTitleAt(i))) {
                responseTabPane.removeTabAt(i);
            }
        }
    }

    private static JLabel summaryLabel(String text, Color color) {
        JLabel label = new JLabel(text);
        label.setForeground(color);
        label.setFont(label.getFont().deriveFont(Font.BOLD, 12f));
        return label;
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
