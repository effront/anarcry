package gg.effront.anarcry.gui.views;

import gg.effront.anarcry.apiclient.auth.AuthInjectorRegistry;
import gg.effront.anarcry.apiclient.io.BruImporter;
import gg.effront.anarcry.apiclient.io.CollectionLoader;
import gg.effront.anarcry.gui.PrivacyFilter;
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
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;

import javax.swing.BorderFactory;
import javax.swing.DropMode;
import javax.swing.JButton;
import javax.swing.DefaultListModel;
import javax.swing.ActionMap;
import javax.swing.InputMap;
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

    private static final int SIDEBAR_WIDTH = 320;
    private static final int REQUEST_TIMEOUT_SECONDS = 30;
    private static final int MAX_OPEN_TABS = 10;

    private static final Color METHOD_GET = new Color(0x3F, 0xB9, 0x50);
    private static final Color METHOD_POST = new Color(0xD2, 0x99, 0x22);
    private static final Color METHOD_PUT = new Color(0x58, 0xA6, 0xFF);
    private static final Color METHOD_DELETE = new Color(0xF8, 0x51, 0x49);
    private static final Color METHOD_PATCH = new Color(0xBB, 0x6B, 0xD9);
    private static Color tabActiveBg() {
        return gg.effront.anarcry.gui.theme.AnarCryLaf.isDark()
                ? new Color(0x3A, 0x3A, 0x4E)
                : new Color(0xDE, 0xDE, 0xE8);
    }

    private static Color tabInactiveBg() {
        return gg.effront.anarcry.gui.theme.AnarCryLaf.isDark()
                ? new Color(0x24, 0x24, 0x34)
                : new Color(0xEA, 0xEA, 0xEA);
    }

    private static Color panelBorder() {
        return gg.effront.anarcry.gui.theme.AnarCryLaf.isDark()
                ? new Color(0x44, 0x44, 0x4F)
                : new Color(0xC0, 0xC0, 0xC0);
    }

    private static Color badgeBg() {
        return gg.effront.anarcry.gui.theme.AnarCryLaf.isDark()
                ? new Color(0x2A, 0x2A, 0x3A)
                : new Color(0xE0, 0xE0, 0xEC);
    }

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
    private KvTableEditor queryParamsEditor;
    private KvTableEditor pathParamsEditor;
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
    private JLabel responseStatusLabel;
    private JLabel responseTimeLabel;
    private JLabel responseSizeLabel;
    private RSyntaxTextArea responseBody;
    private JTabbedPane requestEditorTabs;
    private JTabbedPane responseTabPane;
    private JComboBox<String> responseFormatCombo;
    private CardLayout rightCardLayout;
    private JPanel rightCardPanel;
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
    private Consumer<Boolean> proxyStatusCallback;
    private java.net.ProxySelector currentProxy;
    private javax.net.ssl.SSLContext currentSslContext;

    private Collection currentCollection;
    private Path collectionPath;
    private RequestItem activeRequest;
    private final List<RequestItem> openRequests = new ArrayList<>();
    private final java.util.Map<String, RequestItem> tabStateCache = new java.util.HashMap<>();
    private final java.util.Map<String, RequestResult> tabResponseCache = new java.util.HashMap<>();
    private final java.net.CookieManager cookieManager;
    private HttpClient httpClient;
    private final List<String> runLog = new ArrayList<>();
    private RunContext sessionContext;
    private DefaultListModel<RequestResult> historyModel;
    private JList<RequestResult> historyList;

    private final Map<javax.swing.text.JTextComponent, String> privacyRawValues = new LinkedHashMap<>();
    private final List<javax.swing.text.JTextComponent> privacyManagedFields = new ArrayList<>();

    public void setProxyStatusCallback(Consumer<Boolean> callback) {
        this.proxyStatusCallback = callback;
    }

    public List<String> getRequestNames() {
        if (currentCollection == null) {
            return List.of();
        }
        List<String> names = new ArrayList<>();
        collectRequestNames(currentCollection.items(), names);
        return names;
    }

    private void collectRequestNames(List<CollectionItem> items, List<String> out) {
        for (CollectionItem item : items) {
            if (item instanceof RequestItem ri) {
                out.add(ri.request().method() + " " + ri.name() + " - " + ri.request().url());
            } else if (item instanceof Folder f) {
                collectRequestNames(f.items(), out);
            }
        }
    }

    public ApiClientView() {
        super(new BorderLayout());
        cookieManager = new java.net.CookieManager(null, java.net.CookiePolicy.ACCEPT_ALL);
        httpClient = buildHttpClient();

        JSplitPane mainSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, buildSidebar(), buildRightPanel());
        mainSplit.setDividerLocation(SIDEBAR_WIDTH);
        add(mainSplit, BorderLayout.CENTER);

        registerPrivacyFields();
        PrivacyFilter.addListener(() -> SwingUtilities.invokeLater(this::onPrivacyChanged));
        gg.effront.anarcry.gui.theme.AnarCryLaf.addThemeListener(this::onThemeChanged);
    }

    private void onThemeChanged() {
        applySyntaxTheme(bodyArea);
        applySyntaxTheme(responseBody);
        applySyntaxTheme(preRequestScriptArea);
        applySyntaxTheme(postResponseScriptArea);
        applySyntaxTheme(testsScriptArea);
        refreshRequestTabs();
    }

    private HttpClient buildHttpClient() {
        HttpClient.Builder builder = HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NORMAL)
                .cookieHandler(cookieManager).connectTimeout(Duration.ofSeconds(REQUEST_TIMEOUT_SECONDS));
        if (currentProxy != null) {
            builder.proxy(currentProxy);
        }
        if (currentSslContext != null) {
            builder.sslContext(currentSslContext);
        }
        return builder.build();
    }

    public void setNetworkConfig(java.net.ProxySelector proxy, javax.net.ssl.SSLContext sslCtx, boolean proxyActive) {
        this.currentProxy = proxy;
        this.currentSslContext = sslCtx;
        httpClient = buildHttpClient();
        if (proxyStatusCallback != null) {
            proxyStatusCallback.accept(proxyActive);
        }
    }

    // ==================== SIDEBAR ====================

    private JPanel buildSidebar() {
        JPanel sidebar = new JPanel(new BorderLayout());
        sidebar.setPreferredSize(new Dimension(SIDEBAR_WIDTH, 0));

        sidebarSearchField = new JTextField();
        sidebarSearchField.putClientProperty("JTextField.placeholderText", "Filter requests...");
        sidebarSearchField.setBorder(
                BorderFactory.createCompoundBorder(BorderFactory.createMatteBorder(0, 0, 1, 0, panelBorder()),
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
        sortBar.setBorder(BorderFactory.createMatteBorder(0, 0, 1, 0, panelBorder()));
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

            private final JPanel panel = new JPanel(new BorderLayout(6, 0));
            private final JLabel methodLabel = new JLabel();
            private final JLabel nameLabel = new JLabel();
            private final DefaultTreeCellRenderer fallback = new DefaultTreeCellRenderer();

            {
                methodLabel.setFont(new Font(Font.MONOSPACED, Font.BOLD, 10));
                methodLabel.setHorizontalAlignment(javax.swing.SwingConstants.CENTER);
                methodLabel.setPreferredSize(new Dimension(52, 16));
                methodLabel.setMinimumSize(new Dimension(52, 16));
                methodLabel.setMaximumSize(new Dimension(52, 16));
                methodLabel.setOpaque(true);
                nameLabel.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 12));
                panel.setOpaque(true);
                panel.setBorder(BorderFactory.createEmptyBorder(2, 2, 2, 0));
                panel.add(methodLabel, BorderLayout.WEST);
                panel.add(nameLabel, BorderLayout.CENTER);
            }

            @Override
            public Component getTreeCellRendererComponent(JTree tree, Object value, boolean sel, boolean expanded,
                    boolean leaf, int row, boolean hasFocus) {
                if (value instanceof DefaultMutableTreeNode node && node.getUserObject() instanceof RequestItem ri) {
                    String method = ri.request().method();
                    methodLabel.setText(method);
                    Color mc = methodColor(method);
                    methodLabel.setForeground(mc);
                    methodLabel.setBackground(methodBadgeBg(mc));
                    nameLabel.setText(" " + ri.name());
                    Color bg = sel ? tabActiveBg() : tree.getBackground();
                    Color fg = sel ? gg.effront.anarcry.gui.theme.AnarCryLaf.fg() : tree.getForeground();
                    panel.setBackground(bg);
                    nameLabel.setForeground(fg);
                    panel.setToolTipText(method + " " + ri.name() + " - " + pf(ri.request().url()));
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
                    long timeMs = rr.response() != null ? rr.response().responseTimeMs() : 0;
                    String url = rr.interpolatedRequest() != null ? rr.interpolatedRequest().url() : "";
                    String timeStr = timeMs > 0 ? " " + formatDuration(timeMs) : "";
                    setText(method + " " + status + timeStr + " " + pf(url));
                    setForeground(statusColor(status));
                }
                setBorder(BorderFactory.createEmptyBorder(2, 4, 2, 4));
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

        rightCardLayout = new CardLayout();
        rightCardPanel = new JPanel(rightCardLayout);
        rightCardPanel.add(buildEmptyStatePanel(), "empty");
        rightCardPanel.add(split, "editor");
        rightCardLayout.show(rightCardPanel, "empty");

        right.add(rightCardPanel, BorderLayout.CENTER);

        InputMap im = right.getInputMap(JComponent.WHEN_ANCESTOR_OF_FOCUSED_COMPONENT);
        ActionMap am = right.getActionMap();

        im.put(KeyStroke.getKeyStroke(KeyEvent.VK_ENTER, InputEvent.CTRL_DOWN_MASK), "send");
        am.put("send", new javax.swing.AbstractAction() {
            @Override
            public void actionPerformed(java.awt.event.ActionEvent e) {
                sendRequest();
            }
        });

        im.put(KeyStroke.getKeyStroke(KeyEvent.VK_N, InputEvent.CTRL_DOWN_MASK), "newRequest");
        am.put("newRequest", new javax.swing.AbstractAction() {
            @Override
            public void actionPerformed(java.awt.event.ActionEvent e) {
                addNewRequest();
            }
        });

        im.put(KeyStroke.getKeyStroke(KeyEvent.VK_E, InputEvent.CTRL_DOWN_MASK), "editEnv");
        am.put("editEnv", new javax.swing.AbstractAction() {
            @Override
            public void actionPerformed(java.awt.event.ActionEvent e) {
                openEnvEditor();
            }
        });

        im.put(KeyStroke.getKeyStroke(KeyEvent.VK_L, InputEvent.CTRL_DOWN_MASK), "focusUrl");
        am.put("focusUrl", new javax.swing.AbstractAction() {
            @Override
            public void actionPerformed(java.awt.event.ActionEvent e) {
                urlField.requestFocusInWindow();
                urlField.selectAll();
            }
        });

        im.put(KeyStroke.getKeyStroke(KeyEvent.VK_S, InputEvent.CTRL_DOWN_MASK), "saveRequest");
        am.put("saveRequest", new javax.swing.AbstractAction() {
            @Override
            public void actionPerformed(java.awt.event.ActionEvent e) {
                saveCurrentRequest();
            }
        });

        return right;
    }

    private JPanel buildEmptyStatePanel() {
        JPanel panel = new JPanel(new java.awt.GridBagLayout());
        java.awt.GridBagConstraints gbc = new java.awt.GridBagConstraints();
        gbc.gridx = 0;
        gbc.gridy = java.awt.GridBagConstraints.RELATIVE;
        gbc.anchor = java.awt.GridBagConstraints.CENTER;
        gbc.insets = new java.awt.Insets(4, 0, 4, 0);

        Color hintColor = new Color(0x6B, 0x73, 0x7C);
        Color shortcutColor = new Color(0x8B, 0x94, 0x9E);
        Color accentColor = new Color(0x3F, 0xB9, 0x50, 0x40);

        JLabel titleLabel = new JLabel("Select a request or create a new one");
        titleLabel.setFont(titleLabel.getFont().deriveFont(Font.PLAIN, 16f));
        titleLabel.setForeground(hintColor);
        gbc.insets = new java.awt.Insets(0, 0, 20, 0);
        panel.add(titleLabel, gbc);

        gbc.insets = new java.awt.Insets(4, 0, 4, 0);
        java.util.List<String[]> shortcuts = java.util.List.of(new String[]{"Send Request", "Ctrl+Enter"},
                new String[]{"New Request", "Ctrl+N"}, new String[]{"Edit Environments", "Ctrl+E"},
                new String[]{"Global Search", "Ctrl+Shift+F"});

        for (String[] shortcut : shortcuts) {
            JPanel row = new JPanel(new BorderLayout(0, 0));
            row.setOpaque(false);
            row.setPreferredSize(new Dimension(280, 28));

            JLabel actionLabel = new JLabel(shortcut[0]);
            actionLabel.setForeground(hintColor);
            actionLabel.setFont(actionLabel.getFont().deriveFont(13f));

            JLabel keyLabel = new JLabel(shortcut[1]);
            keyLabel.setForeground(shortcutColor);
            keyLabel.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
            keyLabel.setOpaque(true);
            keyLabel.setBackground(accentColor);
            keyLabel.setBorder(BorderFactory.createCompoundBorder(BorderFactory.createLineBorder(panelBorder(), 1),
                    BorderFactory.createEmptyBorder(2, 6, 2, 6)));
            keyLabel.setHorizontalAlignment(javax.swing.SwingConstants.CENTER);

            row.add(actionLabel, BorderLayout.WEST);
            row.add(keyLabel, BorderLayout.EAST);
            panel.add(row, gbc);
        }
        return panel;
    }

    private void showEditorCard() {
        rightCardLayout.show(rightCardPanel, "editor");
    }

    private void showEmptyCard() {
        rightCardLayout.show(rightCardPanel, "empty");
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
        requestEditorTabs = tabs;

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

        JPanel paramsPanel = new JPanel(new BorderLayout(0, 0));
        JSplitPane paramsSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        paramsSplit.setResizeWeight(0.5);
        paramsSplit.setBorder(BorderFactory.createEmptyBorder());

        JPanel querySection = new JPanel(new BorderLayout());
        JLabel queryLabel = new JLabel("  Query");
        queryLabel.setFont(queryLabel.getFont().deriveFont(java.awt.Font.BOLD));
        queryLabel.setBorder(BorderFactory.createEmptyBorder(4, 0, 2, 0));
        querySection.add(queryLabel, BorderLayout.NORTH);
        queryParamsEditor = new KvTableEditor();
        querySection.add(queryParamsEditor, BorderLayout.CENTER);

        JPanel pathSection = new JPanel(new BorderLayout());
        JLabel pathLabel = new JLabel("  Path");
        pathLabel.setFont(pathLabel.getFont().deriveFont(java.awt.Font.BOLD));
        pathLabel.setBorder(BorderFactory.createEmptyBorder(4, 0, 2, 0));
        pathSection.add(pathLabel, BorderLayout.NORTH);
        pathParamsEditor = new KvTableEditor();
        pathSection.add(pathParamsEditor, BorderLayout.CENTER);

        paramsSplit.setTopComponent(querySection);
        paramsSplit.setBottomComponent(pathSection);
        paramsPanel.add(paramsSplit, BorderLayout.CENTER);
        tabs.addTab("Params", paramsPanel);

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

        JPanel statusBar = new JPanel(new BorderLayout(4, 0));
        statusBar.setBorder(BorderFactory.createEmptyBorder(2, 4, 2, 4));

        JPanel badges = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 1));
        badges.setOpaque(false);

        responseStatusLabel = createBadge("");
        responseTimeLabel = createBadge("");
        responseSizeLabel = createBadge("");
        responseStatusLabel.setVisible(false);
        responseTimeLabel.setVisible(false);
        responseSizeLabel.setVisible(false);
        badges.add(responseStatusLabel);
        badges.add(responseTimeLabel);
        badges.add(responseSizeLabel);

        JPanel respButtons = new JPanel(new FlowLayout(FlowLayout.RIGHT, 4, 0));
        respButtons.setOpaque(false);

        responseFormatCombo = new JComboBox<>(new String[]{"JSON", "HTML", "XML", "Raw"});
        responseFormatCombo.setFont(responseFormatCombo.getFont().deriveFont(11f));
        responseFormatCombo.setPreferredSize(new Dimension(70, 22));
        responseFormatCombo.addActionListener(e -> {
            String fmt = (String) responseFormatCombo.getSelectedItem();
            if (fmt != null) {
                responseBody.setSyntaxEditingStyle(switch (fmt) {
                    case "JSON" -> SyntaxConstants.SYNTAX_STYLE_JSON;
                    case "HTML" -> SyntaxConstants.SYNTAX_STYLE_HTML;
                    case "XML" -> SyntaxConstants.SYNTAX_STYLE_XML;
                    default -> SyntaxConstants.SYNTAX_STYLE_NONE;
                });
            }
        });

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
        JButton clearRespBtn = new JButton("Clear");
        clearRespBtn.setFont(clearRespBtn.getFont().deriveFont(11f));
        clearRespBtn.addActionListener(e -> clearResponsePanel());
        respButtons.add(responseFormatCombo);
        respButtons.add(copyBtn);
        respButtons.add(prettifyBtn);
        respButtons.add(saveRespBtn);
        respButtons.add(clearRespBtn);
        statusBar.add(badges, BorderLayout.CENTER);
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
            String pretty = new com.google.gson.GsonBuilder().setPrettyPrinting().create().toJson(el);
            responseBody.setText(pf(pretty));
            responseBody.setCaretPosition(0);
        } catch (Exception ex) {
            // not JSON, ignore
        }
    }

    private void saveResponse() {
        String text = responseBody.getText();
        if (text.isBlank()) {
            responseStatusLabel.setText("No response to save");
            responseStatusLabel.setForeground(Color.GRAY);
            responseStatusLabel.setVisible(true);
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
                responseStatusLabel.setText("Saved to " + chooser.getSelectedFile().getName());
                responseStatusLabel.setForeground(METHOD_GET);
                responseStatusLabel.setVisible(true);
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
        showEditorCard();
    }

    private void closeRequestTab(RequestItem item) {
        openRequests.remove(item);
        tabStateCache.remove(item.uid());
        tabResponseCache.remove(item.uid());
        if (activeRequest == item) {
            activeRequest = openRequests.isEmpty() ? null : openRequests.getLast();
        }
        refreshRequestTabs();
        if (activeRequest != null) {
            loadRequestIntoEditor(activeRequest);
        } else {
            showEmptyCard();
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
        String name = item.name();
        if (name.length() > 20) {
            name = name.substring(0, 17) + "...";
        }

        JPanel tab = new JPanel(new BorderLayout(4, 0));
        tab.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
        boolean isActive = item == activeRequest;
        tab.setBackground(isActive ? tabActiveBg() : tabInactiveBg());
        Color mc = methodColor(method);
        tab.setBorder(BorderFactory.createCompoundBorder(BorderFactory.createMatteBorder(0, 0, isActive ? 2 : 0, 0, mc),
                BorderFactory.createEmptyBorder(2, 4, 2, 2)));

        String shortMethod = method.length() > 3 ? method.substring(0, 3) : method;
        JLabel methodTag = new JLabel(shortMethod);
        methodTag.setFont(new Font(Font.MONOSPACED, Font.BOLD, 10));
        methodTag.setForeground(mc);
        methodTag.setOpaque(true);
        methodTag.setBackground(methodBadgeBg(mc));
        methodTag.setHorizontalAlignment(javax.swing.SwingConstants.CENTER);
        methodTag.setBorder(BorderFactory.createEmptyBorder(1, 3, 1, 3));

        JLabel nameLabel = new JLabel(name);
        nameLabel.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 11));
        nameLabel.setForeground(isActive ? gg.effront.anarcry.gui.theme.AnarCryLaf.fg() : new Color(0x8B, 0x94, 0x9E));

        JPanel labelPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 0));
        labelPanel.setOpaque(false);
        labelPanel.add(methodTag);
        labelPanel.add(nameLabel);
        tab.add(labelPanel, BorderLayout.CENTER);

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
                closeLabel.setForeground(gg.effront.anarcry.gui.theme.AnarCryLaf.fg());
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
                    saveEditorState();
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

    private static Color methodBadgeBg(Color mc) {
        if (gg.effront.anarcry.gui.theme.AnarCryLaf.isDark()) {
            return new Color(mc.getRed() / 6, mc.getGreen() / 6, mc.getBlue() / 6);
        }
        return new Color(mc.getRed() / 3 + 170, mc.getGreen() / 3 + 170, mc.getBlue() / 3 + 170);
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
                String curl = pf(CurlGenerator.generate(reqItem.request()));
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
        saveEditorState();
        openRequestTab(item);
        loadRequestIntoEditor(item);
    }

    private void saveEditorState() {
        if (activeRequest == null) {
            return;
        }
        RequestItem snapshot = buildCurrentRequestItem();
        tabStateCache.put(activeRequest.uid(), snapshot);
    }

    private RequestItem resolveTabState(RequestItem item) {
        RequestItem cached = tabStateCache.get(item.uid());
        return cached != null ? cached : item;
    }

    private void loadRequestIntoEditor(RequestItem item) {
        item = resolveTabState(item);
        RequestResult cachedResponse = tabResponseCache.get(item.uid());
        if (cachedResponse != null) {
            displayResult(cachedResponse);
        } else {
            clearResponsePanel();
        }
        HttpRequestDef req = item.request();
        methodCombo.setSelectedItem(req.method());
        setFieldWithPrivacy(urlField, req.url());

        List<KvTableEditor.Entry> headerEntries = new ArrayList<>();
        for (Header h : req.headers()) {
            headerEntries.add(new KvTableEditor.Entry(h.name(), h.value(), h.enabled()));
        }
        headersEditor.setEntries(headerEntries);

        List<KvTableEditor.Entry> queryEntries = new ArrayList<>();
        List<KvTableEditor.Entry> pathEntries = new ArrayList<>();
        if (req.params() != null) {
            for (Param p : req.params().query()) {
                queryEntries.add(new KvTableEditor.Entry(p.name(), p.value(), p.enabled()));
            }
            for (Param p : req.params().path()) {
                pathEntries.add(new KvTableEditor.Entry(p.name(), p.value(), p.enabled()));
            }
        }
        queryParamsEditor.setEntries(queryEntries);
        pathParamsEditor.setEntries(pathEntries);

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

        autoSelectEditorTab(req);
        updateTabBadges(req, item);
    }

    private static final int TAB_HEADERS = 0;
    private static final int TAB_BODY = 1;
    private static final int TAB_PARAMS = 2;
    private static final int TAB_AUTH = 3;
    private static final int TAB_VARS = 4;
    private static final int TAB_ASSERT = 5;
    private static final int TAB_DOCS = 6;
    private static final int TAB_SCRIPT = 7;
    private static final int TAB_SETTINGS = 8;

    private void autoSelectEditorTab(HttpRequestDef req) {
        boolean hasBody = !(req.body() instanceof BodyConfig.None);
        boolean hasParams = req.params() != null && (!req.params().query().isEmpty() || !req.params().path().isEmpty());
        boolean hasAuth = req.auth() != null && !(req.auth() instanceof AuthConfig.None)
                && !(req.auth() instanceof AuthConfig.Inherit);
        boolean hasHeaders = !req.headers().isEmpty();

        if (hasBody) {
            requestEditorTabs.setSelectedIndex(TAB_BODY);
        } else if (hasParams) {
            requestEditorTabs.setSelectedIndex(TAB_PARAMS);
        } else if (hasAuth) {
            requestEditorTabs.setSelectedIndex(TAB_AUTH);
        } else if (hasHeaders) {
            requestEditorTabs.setSelectedIndex(TAB_HEADERS);
        } else {
            requestEditorTabs.setSelectedIndex(TAB_PARAMS);
        }
    }

    private void updateTabBadges(HttpRequestDef req, RequestItem item) {
        int headerCount = req.headers().size();
        requestEditorTabs.setTitleAt(TAB_HEADERS, headerCount > 0 ? "Headers " + headerCount : "Headers");

        boolean hasBody = !(req.body() instanceof BodyConfig.None);
        requestEditorTabs.setTitleAt(TAB_BODY, hasBody ? "Body *" : "Body");

        int paramCount = 0;
        if (req.params() != null) {
            paramCount = req.params().query().size() + req.params().path().size();
        }
        requestEditorTabs.setTitleAt(TAB_PARAMS, paramCount > 0 ? "Params " + paramCount : "Params");

        boolean hasAuth = req.auth() != null && !(req.auth() instanceof AuthConfig.None)
                && !(req.auth() instanceof AuthConfig.Inherit);
        requestEditorTabs.setTitleAt(TAB_AUTH, hasAuth ? "Auth *" : "Auth");

        boolean hasVars = item.vars() != null && (!item.vars().pre().isEmpty() || !item.vars().post().isEmpty());
        requestEditorTabs.setTitleAt(TAB_VARS, hasVars ? "Vars *" : "Vars");

        int assertCount = item.assertions() != null ? item.assertions().size() : 0;
        requestEditorTabs.setTitleAt(TAB_ASSERT, assertCount > 0 ? "Assert " + assertCount : "Assert");

        boolean hasDocs = item.docs() != null && !item.docs().isBlank();
        requestEditorTabs.setTitleAt(TAB_DOCS, hasDocs ? "Docs *" : "Docs");

        boolean hasScript = item.scripts() != null && (!item.scripts().preRequest().isBlank()
                || !item.scripts().postResponse().isBlank() || !item.scripts().tests().isBlank());
        requestEditorTabs.setTitleAt(TAB_SCRIPT, hasScript ? "Script *" : "Script");
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
            case AuthConfig.Bearer b -> setFieldWithPrivacy(authBearerToken, b.token());
            case AuthConfig.Basic b -> {
                setFieldWithPrivacy(authBasicUser, b.username());
                setFieldWithPrivacy(authBasicPass, b.password());
            }
            case AuthConfig.ApiKey a -> {
                setFieldWithPrivacy(authApiKeyKey, a.key());
                setFieldWithPrivacy(authApiKeyValue, a.value());
                authApiKeyPlacement.setSelectedItem(a.placement());
            }
            case AuthConfig.Digest d -> {
                setFieldWithPrivacy(authDigestUser, d.username());
                setFieldWithPrivacy(authDigestPass, d.password());
            }
            case AuthConfig.Wsse w -> {
                setFieldWithPrivacy(authWsseUser, w.username());
                setFieldWithPrivacy(authWssePass, w.password());
            }
            case AuthConfig.OAuth2 o -> {
                setFieldWithPrivacy(authOAuth2GrantType, o.grantType());
                setFieldWithPrivacy(authOAuth2TokenUrl, o.accessTokenUrl());
                setFieldWithPrivacy(authOAuth2ClientId, o.clientId());
                setFieldWithPrivacy(authOAuth2ClientSecret, o.clientSecret());
                setFieldWithPrivacy(authOAuth2Scope, o.scope());
                setFieldWithPrivacy(authOAuth2AuthUrl, o.authorizationUrl() != null ? o.authorizationUrl() : "");
                setFieldWithPrivacy(authOAuth2CallbackUrl, o.callbackUrl() != null ? o.callbackUrl() : "");
                authOAuth2Pkce.setSelected(o.pkce());
            }
            case AuthConfig.Ntlm n -> {
                setFieldWithPrivacy(authNtlmUser, n.username());
                setFieldWithPrivacy(authNtlmPass, n.password());
                setFieldWithPrivacy(authNtlmDomain, n.domain());
            }
            case AuthConfig.AwsV4 a -> {
                setFieldWithPrivacy(authAwsAccessKey, a.accessKeyId());
                setFieldWithPrivacy(authAwsSecretKey, a.secretAccessKey());
                setFieldWithPrivacy(authAwsSession, a.sessionToken() != null ? a.sessionToken() : "");
                setFieldWithPrivacy(authAwsService, a.service());
                setFieldWithPrivacy(authAwsRegion, a.region());
            }
            case AuthConfig.OAuth1 o -> {
                setFieldWithPrivacy(authOAuth1ConsumerKey, o.consumerKey());
                setFieldWithPrivacy(authOAuth1ConsumerSecret, o.consumerSecret());
                setFieldWithPrivacy(authOAuth1AccessToken, o.accessToken());
                setFieldWithPrivacy(authOAuth1TokenSecret, o.tokenSecret());
            }
            case AuthConfig.EdgeGrid eg -> {
                setFieldWithPrivacy(authEdgeAccessToken, eg.accessToken());
                setFieldWithPrivacy(authEdgeClientToken, eg.clientToken());
                setFieldWithPrivacy(authEdgeClientSecret, eg.clientSecret());
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

    private void saveCurrentRequest() {
        saveEditorState();
        saveCollection();
    }

    // ==================== SEND / RUN ====================

    private void copyAsCurl() {
        RequestItem item = buildCurrentRequestItem();
        String curl = pf(CurlGenerator.generate(item.request()));
        copyToClipboard(curl);
        responseStatusLabel.setText("cURL copied to clipboard");
        responseStatusLabel.setForeground(METHOD_GET);
        responseStatusLabel.setVisible(true);
    }

    private void copyToClipboard(String text) {
        java.awt.Toolkit.getDefaultToolkit().getSystemClipboard()
                .setContents(new java.awt.datatransfer.StringSelection(text), null);
    }

    private void sendRequest() {
        String method = (String) methodCombo.getSelectedItem();
        String url = urlField.getText().trim();
        if (url.isBlank() || "https://".equals(url)) {
            responseStatusLabel.setText("URL required");
            responseStatusLabel.setForeground(METHOD_DELETE);
            responseStatusLabel.setVisible(true);
            return;
        }

        sendButton.setEnabled(false);
        responseStatusLabel.setText("Sending...");
        responseStatusLabel.setForeground(new Color(0x8B, 0x94, 0x9E));
        responseStatusLabel.setVisible(true);
        responseTimeLabel.setVisible(false);
        responseSizeLabel.setVisible(false);
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
                SwingUtilities.invokeLater(() -> {
                    responseStatusLabel.setText("Error: " + ex.getMessage());
                    responseStatusLabel.setForeground(METHOD_DELETE);
                    responseStatusLabel.setVisible(true);
                });
            } finally {
                SwingUtilities.invokeLater(() -> sendButton.setEnabled(true));
            }
        });
    }

    private RequestItem buildCurrentRequestItem() {
        String method = (String) methodCombo.getSelectedItem();
        String url = rawFieldValue(urlField).trim();

        List<Header> headers = new ArrayList<>();
        for (KvTableEditor.Entry e : headersEditor.getEntries()) {
            headers.add(new Header(e.key(), e.value(), e.enabled()));
        }

        List<Param> queryParams = new ArrayList<>();
        for (KvTableEditor.Entry e : queryParamsEditor.getEntries()) {
            queryParams.add(new Param(e.key(), e.value(), Param.ParamType.QUERY, e.enabled()));
        }
        List<Param> pathParams = new ArrayList<>();
        for (KvTableEditor.Entry e : pathParamsEditor.getEntries()) {
            pathParams.add(new Param(e.key(), e.value(), Param.ParamType.PATH, e.enabled()));
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
            case "bearer" -> new AuthConfig.Bearer(rawFieldValue(authBearerToken));
            case "basic" -> new AuthConfig.Basic(rawFieldValue(authBasicUser), rawFieldValue(authBasicPass));
            case "apikey" -> new AuthConfig.ApiKey(rawFieldValue(authApiKeyKey), rawFieldValue(authApiKeyValue),
                    (String) authApiKeyPlacement.getSelectedItem());
            case "digest" -> new AuthConfig.Digest(rawFieldValue(authDigestUser), rawFieldValue(authDigestPass));
            case "wsse" -> new AuthConfig.Wsse(rawFieldValue(authWsseUser), rawFieldValue(authWssePass));
            case "oauth2" -> new AuthConfig.OAuth2(rawFieldValue(authOAuth2GrantType),
                    rawFieldValue(authOAuth2TokenUrl), "", rawFieldValue(authOAuth2ClientId),
                    rawFieldValue(authOAuth2ClientSecret), rawFieldValue(authOAuth2Scope),
                    rawFieldValue(authOAuth2CallbackUrl), rawFieldValue(authOAuth2AuthUrl), authOAuth2Pkce.isSelected(),
                    "body", "header", false, false, java.util.Map.of());
            case "ntlm" -> new AuthConfig.Ntlm(rawFieldValue(authNtlmUser), rawFieldValue(authNtlmPass),
                    rawFieldValue(authNtlmDomain));
            case "awsv4" -> new AuthConfig.AwsV4(rawFieldValue(authAwsAccessKey), rawFieldValue(authAwsSecretKey),
                    rawFieldValue(authAwsSession), rawFieldValue(authAwsService), rawFieldValue(authAwsRegion));
            case "oauth1" -> new AuthConfig.OAuth1(rawFieldValue(authOAuth1ConsumerKey),
                    rawFieldValue(authOAuth1ConsumerSecret), rawFieldValue(authOAuth1AccessToken),
                    rawFieldValue(authOAuth1TokenSecret), "HMAC-SHA1", "header");
            case "akamai-edgegrid" -> new AuthConfig.EdgeGrid(rawFieldValue(authEdgeAccessToken),
                    rawFieldValue(authEdgeClientToken), rawFieldValue(authEdgeClientSecret));
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
            String token = findTokenField(obj);
            if (token == null && obj.has("data") && obj.get("data").isJsonObject()) {
                token = findTokenField(obj.getAsJsonObject("data"));
            }
            if (token != null) {
                sessionContext.vars().setRuntime("token", token);
            }
        } catch (Exception ignored) {
        }
    }

    private static String findTokenField(com.google.gson.JsonObject obj) {
        for (String field : TOKEN_FIELDS) {
            if (obj.has(field) && obj.get(field).isJsonPrimitive()) {
                String value = obj.get(field).getAsString();
                if (value != null && !value.isBlank()) {
                    return value;
                }
            }
        }
        return null;
    }

    private void clearResponsePanel() {
        responseStatusLabel.setVisible(false);
        responseTimeLabel.setVisible(false);
        responseSizeLabel.setVisible(false);
        responseBody.setText("");
        responseHeaders.setText("");
        assertionsResultArea.setText("");
        cookiesTableModel.setRowCount(0);
        responseTabPane.setTitleAt(1, "Headers");
        responseTabPane.setTitleAt(3, "Cookies");
        scriptConsoleArea.setText("");
    }

    private void displayResult(RequestResult result) {
        if (activeRequest != null) {
            tabResponseCache.put(activeRequest.uid(), result);
        }
        cookiesTableModel.setRowCount(0);
        if (result.response() != null) {
            var resp = result.response();
            String statusText = resp.statusText() != null && !resp.statusText().isEmpty()
                    ? resp.statusText()
                    : httpReasonPhrase(resp.status());

            Color sc = statusColor(resp.status());
            responseStatusLabel.setText(resp.status() + " " + statusText);
            responseStatusLabel.setForeground(sc);
            responseStatusLabel.setBorder(BorderFactory.createCompoundBorder(
                    BorderFactory.createLineBorder(sc.darker(), 1), BorderFactory.createEmptyBorder(1, 6, 1, 6)));
            responseStatusLabel.setVisible(true);

            responseTimeLabel.setText(formatDuration(resp.responseTimeMs()));
            responseTimeLabel.setForeground(new Color(0x8B, 0x94, 0x9E));
            responseTimeLabel.setVisible(true);

            responseSizeLabel.setText(formatBytes(resp.body().length()));
            responseSizeLabel.setForeground(new Color(0x8B, 0x94, 0x9E));
            responseSizeLabel.setVisible(true);

            responseBody.setText(pf(resp.body()));
            responseBody.setCaretPosition(0);

            String ct = resp.header("content-type");
            String syntax = detectSyntax(ct != null ? ct : "");
            responseBody.setSyntaxEditingStyle(syntax);
            selectResponseFormat(syntax);

            StringBuilder hdr = new StringBuilder();
            int headerCount = 0;
            for (var entry : resp.headers().entrySet()) {
                for (String v : entry.getValue()) {
                    hdr.append(entry.getKey()).append(": ").append(v).append("\n");
                    headerCount++;
                }
            }
            responseHeaders.setText(pf(hdr.toString()));
            responseTabPane.setTitleAt(1, "Headers " + headerCount);

            parseCookies(resp.headers());
            int cookieCount = cookiesTableModel.getRowCount();
            responseTabPane.setTitleAt(3, cookieCount > 0 ? "Cookies " + cookieCount : "Cookies");
        } else {
            responseStatusLabel.setText("No response");
            responseStatusLabel.setForeground(Color.GRAY);
            responseStatusLabel.setVisible(true);
            responseTimeLabel.setVisible(false);
            responseSizeLabel.setVisible(false);
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
            assertionsResultArea.setText(pf(sb.toString()));
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
        scriptConsoleArea.setText(pf(sb.toString()));
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
                (k, v) -> variablesTableModel.addRow(new Object[]{"env", k, vars.isSecret(k) ? "********" : pf(v)}));
        vars.collectionVars().forEach((k, v) -> variablesTableModel.addRow(new Object[]{"collection", k, pf(v)}));
        vars.folderVars().forEach((k, v) -> variablesTableModel.addRow(new Object[]{"folder", k, pf(v)}));
        vars.runtimeVars().forEach((k, v) -> variablesTableModel.addRow(new Object[]{"runtime", k, pf(v)}));
        vars.requestVars().forEach((k, v) -> variablesTableModel.addRow(new Object[]{"request", k, pf(v)}));
    }

    private void selectResponseFormat(String syntax) {
        String fmt = switch (syntax) {
            case SyntaxConstants.SYNTAX_STYLE_JSON -> "JSON";
            case SyntaxConstants.SYNTAX_STYLE_HTML -> "HTML";
            case SyntaxConstants.SYNTAX_STYLE_XML -> "XML";
            default -> "Raw";
        };
        responseFormatCombo.setSelectedItem(fmt);
    }

    private static JLabel createBadge(String text) {
        JLabel badge = new JLabel(text);
        badge.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 11));
        badge.setBorder(BorderFactory.createCompoundBorder(BorderFactory.createLineBorder(panelBorder(), 1),
                BorderFactory.createEmptyBorder(1, 6, 1, 6)));
        badge.setOpaque(true);
        badge.setBackground(badgeBg());
        return badge;
    }

    private static String formatDuration(long ms) {
        if (ms < 1000) {
            return ms + "ms";
        }
        return String.format("%.2fs", ms / 1000.0);
    }

    private static String formatBytes(int bytes) {
        if (bytes < 1024) {
            return bytes + " B";
        }
        if (bytes < 1024 * 1024) {
            return String.format("%.1f KB", bytes / 1024.0);
        }
        return String.format("%.1f MB", bytes / (1024.0 * 1024.0));
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

    @SuppressWarnings("checkstyle:MagicNumber")
    private static String httpReasonPhrase(int code) {
        return switch (code) {
            case 200 -> "OK";
            case 201 -> "Created";
            case 202 -> "Accepted";
            case 204 -> "No Content";
            case 301 -> "Moved Permanently";
            case 302 -> "Found";
            case 304 -> "Not Modified";
            case 307 -> "Temporary Redirect";
            case 308 -> "Permanent Redirect";
            case 400 -> "Bad Request";
            case 401 -> "Unauthorized";
            case 403 -> "Forbidden";
            case 404 -> "Not Found";
            case 405 -> "Method Not Allowed";
            case 409 -> "Conflict";
            case 413 -> "Payload Too Large";
            case 415 -> "Unsupported Media Type";
            case 422 -> "Unprocessable Entity";
            case 429 -> "Too Many Requests";
            case 500 -> "Internal Server Error";
            case 502 -> "Bad Gateway";
            case 503 -> "Service Unavailable";
            case 504 -> "Gateway Timeout";
            default -> String.valueOf(code);
        };
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
                cookiesTableModel.addRow(new Object[]{name, pf(value), pf(domain), path, expires, httpOnly, secure});
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
            tabStateCache.clear();
            tabResponseCache.clear();
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
                setFieldWithPrivacy(urlField, item.request().url());
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

            model.addRow(new Object[]{i + 1, name, method, pf(url), status, time + "ms", assertText, passText});
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

    // ==================== PRIVACY ====================

    private void registerPrivacyFields() {
        privacyManagedFields.addAll(List.of(urlField, authBearerToken, authBasicUser, authBasicPass, authApiKeyKey,
                authApiKeyValue, authDigestUser, authDigestPass, authWsseUser, authWssePass, authOAuth2GrantType,
                authOAuth2TokenUrl, authOAuth2ClientId, authOAuth2ClientSecret, authOAuth2Scope, authOAuth2CallbackUrl,
                authOAuth2AuthUrl, authNtlmUser, authNtlmPass, authNtlmDomain, authAwsAccessKey, authAwsSecretKey,
                authAwsSession, authAwsService, authAwsRegion, authOAuth1ConsumerKey, authOAuth1ConsumerSecret,
                authOAuth1AccessToken, authOAuth1TokenSecret, authEdgeAccessToken, authEdgeClientToken,
                authEdgeClientSecret));
    }

    private void onPrivacyChanged() {
        if (PrivacyFilter.isEnabled()) {
            for (javax.swing.text.JTextComponent field : privacyManagedFields) {
                String raw = field.getText();
                privacyRawValues.put(field, raw);
                field.setText(PrivacyFilter.apply(raw));
                field.setEditable(false);
            }
        } else {
            for (javax.swing.text.JTextComponent field : privacyManagedFields) {
                String raw = privacyRawValues.getOrDefault(field, field.getText());
                field.setText(raw);
                field.setEditable(true);
            }
            privacyRawValues.clear();
        }

        refreshResponsePrivacy();
        collectionTree.repaint();
        historyList.repaint();
    }

    private void refreshResponsePrivacy() {
        if (activeRequest != null) {
            RequestResult cached = tabResponseCache.get(activeRequest.uid());
            if (cached != null) {
                displayResult(cached);
                return;
            }
        }
        responseBody.setText(PrivacyFilter.apply(responseBody.getText()));
        responseHeaders.setText(PrivacyFilter.apply(responseHeaders.getText()));
        assertionsResultArea.setText(PrivacyFilter.apply(assertionsResultArea.getText()));
        scriptConsoleArea.setText(PrivacyFilter.apply(scriptConsoleArea.getText()));
    }

    private static String pf(String text) {
        return PrivacyFilter.apply(text);
    }

    private void setFieldWithPrivacy(javax.swing.text.JTextComponent field, String rawValue) {
        if (PrivacyFilter.isEnabled()) {
            privacyRawValues.put(field, rawValue);
            field.setText(PrivacyFilter.apply(rawValue));
            field.setEditable(false);
        } else {
            field.setText(rawValue);
        }
    }

    String rawFieldValue(javax.swing.text.JTextComponent field) {
        if (PrivacyFilter.isEnabled()) {
            return privacyRawValues.getOrDefault(field, field.getText());
        }
        return field.getText();
    }

    // ==================== UTIL ====================

    private RSyntaxTextArea createSyntaxArea(boolean readOnly) {
        RSyntaxTextArea area = new RSyntaxTextArea(12, 60);
        area.setEditable(!readOnly);
        area.setCodeFoldingEnabled(true);
        area.setAntiAliasingEnabled(true);
        area.setTabSize(2);
        applySyntaxTheme(area);
        return area;
    }

    private void applySyntaxTheme(RSyntaxTextArea area) {
        boolean dark = gg.effront.anarcry.gui.theme.AnarCryLaf.isDark();
        String themePath = dark
                ? "/org/fife/ui/rsyntaxtextarea/themes/dark.xml"
                : "/org/fife/ui/rsyntaxtextarea/themes/default.xml";
        try {
            Theme theme = Theme.load(getClass().getResourceAsStream(themePath));
            theme.apply(area);
        } catch (Exception e) {
            if (dark) {
                area.setBackground(new Color(0x1E, 0x1E, 0x2E));
                area.setForeground(Color.WHITE);
                area.setCaretColor(Color.WHITE);
            } else {
                area.setBackground(Color.WHITE);
                area.setForeground(new Color(0x1A, 0x1A, 0x1A));
                area.setCaretColor(new Color(0x1A, 0x1A, 0x1A));
            }
        }
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
