package gg.effront.anarcry.gui.views;

import gg.effront.anarcry.gui.theme.AnarCryLaf;
import gg.effront.anarcry.postexploit.dbexplorer.ConnectionConfig;
import gg.effront.anarcry.postexploit.dbexplorer.ConnectionManager;
import gg.effront.anarcry.postexploit.dbexplorer.DataExporter;
import gg.effront.anarcry.postexploit.dbexplorer.DbType;
import gg.effront.anarcry.postexploit.dbexplorer.MongoExplorer;
import gg.effront.anarcry.postexploit.dbexplorer.RedisExplorer;
import gg.effront.anarcry.postexploit.dbexplorer.SchemaBrowser;
import gg.effront.anarcry.postexploit.dbexplorer.SchemaBrowser.ColumnInfo;
import gg.effront.anarcry.postexploit.dbexplorer.SchemaBrowser.TableInfo;
import gg.effront.anarcry.postexploit.dbexplorer.SqlDialect;
import gg.effront.anarcry.postexploit.dbexplorer.SqlExecutor;
import gg.effront.anarcry.postexploit.dbexplorer.SqlExecutor.QueryResult;
import gg.effront.anarcry.postexploit.dbexplorer.SshTunnel;
import gg.effront.anarcry.postexploit.dbexplorer.SshTunnel.SshTunnelConfig;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.event.InputEvent;
import java.awt.event.ItemEvent;
import java.awt.event.KeyEvent;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.nio.file.Path;
import java.sql.Connection;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.Consumer;

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
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.filechooser.FileNameExtensionFilter;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.DefaultTableModel;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.DefaultTreeCellRenderer;
import javax.swing.tree.DefaultTreeModel;
import javax.swing.tree.TreePath;

import org.fife.ui.autocomplete.AutoCompletion;
import org.fife.ui.autocomplete.BasicCompletion;
import org.fife.ui.autocomplete.DefaultCompletionProvider;
import org.fife.ui.autocomplete.ShorthandCompletion;
import org.fife.ui.rsyntaxtextarea.RSyntaxTextArea;
import org.fife.ui.rsyntaxtextarea.SyntaxConstants;
import org.fife.ui.rsyntaxtextarea.Theme;
import org.fife.ui.rtextarea.RTextScrollPane;

/**
 * Database Explorer panel -- supports multiple simultaneous database
 * connections, each with its own schema tree, query editor state, and execution
 * context. Connects to SQL databases (MySQL, PostgreSQL, MSSQL, SQLite,
 * Oracle), MongoDB, and Redis for authorized post-exploitation analysis.
 *
 * <p>
 * Layout: left panel has a connection tree with per-session schema browsers;
 * center panel has a SQL editor and results tabs bound to the active session.
 * Connections are managed via a modal dialog (New/Edit) and toolbar actions
 * (Connect, Disconnect, Remove).
 */
public class DbExplorerView extends JPanel {

    private static final Color DARK_BG = new Color(0x1E, 0x1E, 0x2E);
    private static final Color CONNECTED_COLOR = new Color(0x00, 0x99, 0x00);
    private static final int DEFAULT_CONN_PANEL_WIDTH = 280;
    private static final int QUERY_RESULT_LIMIT = 100;
    private static final int MAX_HISTORY_ENTRIES = 100;
    private static final java.time.format.DateTimeFormatter HISTORY_TIME_FMT = java.time.format.DateTimeFormatter
            .ofPattern("HH:mm:ss").withZone(java.time.ZoneId.systemDefault());

    // -------------------------------------------------------------------------
    // DbTypeSelection enum
    // -------------------------------------------------------------------------

    /** Extended type selector that includes non-SQL databases. */
    private enum DbTypeSelection {
        MYSQL(3306), POSTGRESQL(5432), MSSQL(1433), SQLITE(0), ORACLE(1521), MONGODB(27017), REDIS(6379);

        private final int defaultPort;

        DbTypeSelection(int defaultPort) {
            this.defaultPort = defaultPort;
        }

        int defaultPort() {
            return defaultPort;
        }

        boolean isSql() {
            return this != MONGODB && this != REDIS;
        }

        DbType toDbType() {
            return switch (this) {
                case MYSQL -> DbType.MYSQL;
                case POSTGRESQL -> DbType.POSTGRESQL;
                case MSSQL -> DbType.MSSQL;
                case SQLITE -> DbType.SQLITE;
                case ORACLE -> DbType.ORACLE;
                default -> throw new IllegalStateException("No DbType mapping for " + this);
            };
        }

        static DbTypeSelection fromServiceType(String serviceType) {
            if (serviceType == null) {
                return MYSQL;
            }
            return switch (serviceType.toUpperCase()) {
                case "MYSQL" -> MYSQL;
                case "POSTGRESQL", "POSTGRES" -> POSTGRESQL;
                case "MSSQL", "SQLSERVER" -> MSSQL;
                case "SQLITE" -> SQLITE;
                case "ORACLE" -> ORACLE;
                case "MONGODB", "MONGO" -> MONGODB;
                case "REDIS" -> REDIS;
                default -> MYSQL;
            };
        }
    }

    private record QueryHistoryEntry(String sql, long timestamp, long durationMs, int rowCount, String error) {
    }

    // -------------------------------------------------------------------------
    // DbSession -- holds all state for one connection
    // -------------------------------------------------------------------------

    private static class DbSession {
        String name;
        DbTypeSelection dbType;
        String host;
        int port;
        String database;
        String username;
        boolean useSsl;
        boolean connected;
        boolean discovered;
        String group;

        // SSH tunnel config (stored for reconnect, passwords NOT stored after connect)
        boolean sshEnabled;
        String sshHost;
        int sshPort;
        String sshUsername;
        String sshKeyPath;

        // SQL state
        Connection sqlConnection;
        SqlDialect sqlDialect;
        SchemaBrowser schemaBrowser;
        SqlExecutor sqlExecutor;

        // NoSQL state
        MongoExplorer mongoExplorer;
        RedisExplorer redisExplorer;

        // SSH tunnel
        SshTunnel.ActiveTunnel activeTunnel;

        // Tree node for this session in the connection tree
        DefaultMutableTreeNode treeNode;

        // Per-session editor state
        String lastQueryText = "";

        // Per-session result state
        List<String> lastResultColumns;
        List<List<String>> lastResultRows;

        String displayName() {
            if (name != null && !name.isBlank()) {
                return name;
            }
            String db = (database != null && !database.isBlank()) ? "/" + database : "";
            String portStr = port > 0 ? ":" + port : "";
            String prefix = discovered ? "(discovered) " : "";
            return prefix + dbType + " @ " + host + portStr + db;
        }
    }

    // -------------------------------------------------------------------------
    // Tree node data records
    // -------------------------------------------------------------------------

    private record SessionNodeData(DbSession session) {
        @Override
        public String toString() {
            return session.displayName();
        }
    }

    private record SchemaNodeData(DbSession session, String name) {
        @Override
        public String toString() {
            return name;
        }
    }

    private record TableNodeData(DbSession session, String schema, TableInfo info) {
        @Override
        public String toString() {
            if (info.approxRowCount() <= 0) {
                return info.name();
            }
            return info.name() + " (" + String.format("%,d", info.approxRowCount()) + " rows)";
        }
    }

    private record MongoCollNodeData(DbSession session, String dbName, MongoExplorer.CollectionInfo info) {
        String collName() {
            return info.name();
        }

        @Override
        public String toString() {
            return info.name() + " (" + info.documentCount() + " docs)";
        }
    }

    private record RedisKeyNodeData(DbSession session, String key) {
        @Override
        public String toString() {
            return key;
        }
    }

    // -------------------------------------------------------------------------
    // State
    // -------------------------------------------------------------------------

    private final List<DbSession> sessions = new CopyOnWriteArrayList<>();
    private volatile DbSession activeSession;

    // -- Connection tree --
    private JTree connectionTree;
    private DefaultMutableTreeNode connectionTreeRoot;
    private DefaultTreeModel connectionTreeModel;
    private JTextField filterField;
    private final Map<DefaultMutableTreeNode, List<DefaultMutableTreeNode>> unfilteredChildren = new HashMap<>();

    // -- Connection toolbar --
    private JButton addButton;
    private JButton removeButton;
    private JButton connectToggleButton;
    private JButton editButton;

    // -- Query editor --
    private RSyntaxTextArea sqlEditor;
    private JButton executeButton;
    private JButton clearButton;
    private JButton exportResultsButton;

    // -- Results area --
    private JTable resultsTable;
    private DefaultTableModel resultsTableModel;
    private JTextArea messagesArea;
    private JTextArea infoArea;
    private JTabbedPane resultsTabs;
    private JScrollPane messagesScroll;
    private JScrollPane infoScroll;
    private JScrollPane historyScroll;
    private final java.util.List<QueryHistoryEntry> queryHistory = new java.util.ArrayList<>();
    private JTable historyTable;
    private DefaultTableModel historyTableModel;

    // -- Value viewer --
    private RSyntaxTextArea valueViewer;
    private JSplitPane resultsSplit;
    private boolean valueViewerVisible;

    // -- Auto-completion --
    private DefaultCompletionProvider completionProvider;
    private AutoCompletion autoCompletion;

    // -- Multiple result tabs (DBX-012) --
    private static final int MAX_RESULT_TABS = 5;
    private static final int FIXED_TAB_COUNT = 3;
    private final java.text.SimpleDateFormat resultTabTimeFmt = new java.text.SimpleDateFormat("HH:mm:ss");

    // -- Status bar --
    private JLabel rowCountLabel;
    private JLabel execTimeLabel;
    private JLabel statusLabel;

    // -------------------------------------------------------------------------
    // Constructor
    // -------------------------------------------------------------------------

    public DbExplorerView() {
        super(new BorderLayout());
        buildUi();
        AnarCryLaf.addThemeListener(this::onThemeChanged);
        loadSavedConnections();
    }

    // -------------------------------------------------------------------------
    // Public API -- scan integration
    // -------------------------------------------------------------------------

    /**
     * Adds a pre-filled disconnected session for a service discovered during
     * scanning. The session is NOT connected automatically -- the user must open
     * the connection dialog to supply credentials.
     *
     * @param host
     *            the discovered host
     * @param port
     *            the discovered port
     * @param serviceType
     *            one of "Redis", "MongoDB", "MySQL", "PostgreSQL", "MSSQL",
     *            "Oracle", "SQLite"
     */
    public void addDiscoveredService(String host, int port, String serviceType) {
        SwingUtilities.invokeLater(() -> {
            DbSession session = new DbSession();
            session.dbType = DbTypeSelection.fromServiceType(serviceType);
            session.host = host;
            session.port = port > 0 ? port : session.dbType.defaultPort();
            session.database = "";
            session.username = "";
            session.useSsl = false;
            session.connected = false;
            session.discovered = true;
            session.name = "(discovered) " + serviceType + " @ " + host + ":" + session.port;
            addSessionToTree(session);
        });
    }

    // -------------------------------------------------------------------------
    // UI construction
    // -------------------------------------------------------------------------

    private void buildUi() {
        JPanel leftPanel = buildConnectionPanel();
        leftPanel.setPreferredSize(new Dimension(DEFAULT_CONN_PANEL_WIDTH, 0));

        JSplitPane mainSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, leftPanel, buildEditorAndResultsPanel());
        mainSplit.setDividerLocation(DEFAULT_CONN_PANEL_WIDTH);

        add(mainSplit, BorderLayout.CENTER);

        // Status bar at bottom
        JPanel statusBar = new JPanel(new BorderLayout());
        statusBar.setBorder(BorderFactory.createMatteBorder(1, 0, 0, 0, new Color(0x80, 0x80, 0x80, 0x40)));
        statusLabel = new JLabel("No connections");
        statusLabel.setFont(statusLabel.getFont().deriveFont(Font.ITALIC));
        statusLabel.setBorder(BorderFactory.createEmptyBorder(2, 6, 2, 6));
        statusBar.add(statusLabel, BorderLayout.WEST);

        JPanel rightStatus = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 1));
        rightStatus.setOpaque(false);
        rowCountLabel = new JLabel("");
        rowCountLabel.setFont(monoFont().deriveFont(11f));
        execTimeLabel = new JLabel("");
        execTimeLabel.setFont(monoFont().deriveFont(11f));
        rightStatus.add(rowCountLabel);
        rightStatus.add(execTimeLabel);
        statusBar.add(rightStatus, BorderLayout.EAST);
        add(statusBar, BorderLayout.SOUTH);
    }

    /** Builds the left panel with connection toolbar and tree. */
    private JPanel buildConnectionPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBorder(BorderFactory.createTitledBorder("Connections"));

        // -- Toolbar --
        JToolBar toolbar = new JToolBar();
        toolbar.setFloatable(false);

        addButton = new JButton("+");
        addButton.setToolTipText("New Connection");
        addButton.addActionListener(e -> showConnectionDialog(null));
        toolbar.add(addButton);

        removeButton = new JButton("-");
        removeButton.setToolTipText("Remove Connection");
        removeButton.setEnabled(false);
        removeButton.addActionListener(e -> onRemoveSession());
        toolbar.add(removeButton);

        toolbar.addSeparator();

        connectToggleButton = new JButton("Connect");
        connectToggleButton.setEnabled(false);
        connectToggleButton.addActionListener(e -> onConnectToggle());
        toolbar.add(connectToggleButton);

        editButton = new JButton("Edit");
        editButton.setToolTipText("Edit Connection");
        editButton.setEnabled(false);
        editButton.addActionListener(e -> onEditSession());
        toolbar.add(editButton);

        filterField = new JTextField();
        filterField.putClientProperty("JTextField.placeholderText", "Filter tables...");
        filterField.getDocument().addDocumentListener(new DocumentListener() {
            @Override
            public void insertUpdate(DocumentEvent e) {
                applyTreeFilter(filterField.getText());
            }

            @Override
            public void removeUpdate(DocumentEvent e) {
                applyTreeFilter(filterField.getText());
            }

            @Override
            public void changedUpdate(DocumentEvent e) {
                applyTreeFilter(filterField.getText());
            }
        });

        JPanel topPanel = new JPanel(new BorderLayout());
        topPanel.add(toolbar, BorderLayout.NORTH);
        topPanel.add(filterField, BorderLayout.SOUTH);
        panel.add(topPanel, BorderLayout.NORTH);

        // -- Connection tree --
        connectionTreeRoot = new DefaultMutableTreeNode("Connections");
        connectionTreeModel = new DefaultTreeModel(connectionTreeRoot);
        connectionTree = new JTree(connectionTreeModel);
        connectionTree.setRootVisible(false);
        connectionTree.setShowsRootHandles(true);
        connectionTree.setRowHeight(22);
        connectionTree.setCellRenderer(new ConnectionTreeCellRenderer());
        javax.swing.ToolTipManager.sharedInstance().registerComponent(connectionTree);

        connectionTree.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                if (e.getClickCount() == 2) {
                    onTreeDoubleClick();
                }
            }

            @Override
            public void mousePressed(MouseEvent e) {
                if (e.isPopupTrigger()) {
                    showTreeContextMenu(e);
                }
            }

            @Override
            public void mouseReleased(MouseEvent e) {
                if (e.isPopupTrigger()) {
                    showTreeContextMenu(e);
                }
            }
        });

        connectionTree.addTreeSelectionListener(e -> {
            TreePath path = connectionTree.getSelectionPath();
            if (path != null) {
                onTreeSelectionChanged(path);
            }
        });

        // Lazy-load children on expand
        connectionTree.addTreeWillExpandListener(new javax.swing.event.TreeWillExpandListener() {
            @Override
            public void treeWillExpand(javax.swing.event.TreeExpansionEvent event) {
                onTreeWillExpand(event.getPath());
            }

            @Override
            public void treeWillCollapse(javax.swing.event.TreeExpansionEvent event) {
                // no-op
            }
        });

        panel.add(new JScrollPane(connectionTree), BorderLayout.CENTER);
        return panel;
    }

    /** Builds the center panel with SQL editor on top and results on bottom. */
    private JPanel buildEditorAndResultsPanel() {
        JPanel panel = new JPanel(new BorderLayout());

        // -- Editor with toolbar --
        JPanel editorPanel = new JPanel(new BorderLayout());
        editorPanel.add(buildEditorToolbar(), BorderLayout.NORTH);

        sqlEditor = new RSyntaxTextArea(12, 80);
        sqlEditor.setSyntaxEditingStyle(SyntaxConstants.SYNTAX_STYLE_SQL);
        sqlEditor.setCodeFoldingEnabled(true);
        sqlEditor.setAntiAliasingEnabled(true);
        sqlEditor.setTabSize(2);
        applySyntaxTheme(sqlEditor);

        completionProvider = new DefaultCompletionProvider();
        completionProvider.setAutoActivationRules(false, null);
        addSqlKeywordCompletions(completionProvider);
        autoCompletion = new AutoCompletion(completionProvider);
        autoCompletion.setAutoActivationEnabled(true);
        autoCompletion.setAutoActivationDelay(300);
        autoCompletion.setShowDescWindow(true);
        autoCompletion.install(sqlEditor);

        // Ctrl+Enter shortcut
        KeyStroke ctrlEnter = KeyStroke.getKeyStroke(KeyEvent.VK_ENTER, InputEvent.CTRL_DOWN_MASK);
        sqlEditor.getInputMap(JComponent.WHEN_FOCUSED).put(ctrlEnter, "execute-query");
        sqlEditor.getActionMap().put("execute-query", new javax.swing.AbstractAction() {
            @Override
            public void actionPerformed(java.awt.event.ActionEvent e) {
                onExecute();
            }
        });

        RTextScrollPane editorScroll = new RTextScrollPane(sqlEditor);
        editorPanel.add(editorScroll, BorderLayout.CENTER);

        // -- Results tabs --
        JPanel resultsPanel = buildResultsPanel();

        JSplitPane vertSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT, editorPanel, resultsPanel);
        vertSplit.setResizeWeight(0.35);

        panel.add(vertSplit, BorderLayout.CENTER);

        // Global shortcuts
        panel.getInputMap(JComponent.WHEN_ANCESTOR_OF_FOCUSED_COMPONENT).put(KeyStroke.getKeyStroke(KeyEvent.VK_F5, 0),
                "re-execute");
        panel.getActionMap().put("re-execute", new javax.swing.AbstractAction() {
            @Override
            public void actionPerformed(java.awt.event.ActionEvent e) {
                onExecute();
            }
        });
        panel.getInputMap(JComponent.WHEN_ANCESTOR_OF_FOCUSED_COMPONENT).put(KeyStroke.getKeyStroke(KeyEvent.VK_F7, 0),
                "toggle-value-viewer");
        panel.getActionMap().put("toggle-value-viewer", new javax.swing.AbstractAction() {
            @Override
            public void actionPerformed(java.awt.event.ActionEvent e) {
                toggleValueViewer();
            }
        });
        panel.getInputMap(JComponent.WHEN_ANCESTOR_OF_FOCUSED_COMPONENT)
                .put(KeyStroke.getKeyStroke(KeyEvent.VK_S, InputEvent.CTRL_DOWN_MASK), "save-query");
        panel.getActionMap().put("save-query", new javax.swing.AbstractAction() {
            @Override
            public void actionPerformed(java.awt.event.ActionEvent e) {
                onSaveQuery();
            }
        });

        // Results table shortcuts
        resultsTable.getInputMap(JComponent.WHEN_FOCUSED)
                .put(KeyStroke.getKeyStroke(KeyEvent.VK_C, InputEvent.CTRL_DOWN_MASK), "copy-cell");
        resultsTable.getActionMap().put("copy-cell", new javax.swing.AbstractAction() {
            @Override
            public void actionPerformed(java.awt.event.ActionEvent e) {
                copyCellToClipboard(false);
            }
        });
        resultsTable.getInputMap(JComponent.WHEN_FOCUSED).put(
                KeyStroke.getKeyStroke(KeyEvent.VK_C, InputEvent.CTRL_DOWN_MASK | InputEvent.SHIFT_DOWN_MASK),
                "copy-with-headers");
        resultsTable.getActionMap().put("copy-with-headers", new javax.swing.AbstractAction() {
            @Override
            public void actionPerformed(java.awt.event.ActionEvent e) {
                copyCellToClipboard(true);
            }
        });
        resultsTable.getInputMap(JComponent.WHEN_FOCUSED).put(KeyStroke.getKeyStroke(KeyEvent.VK_ESCAPE, 0),
                "clear-selection");
        resultsTable.getActionMap().put("clear-selection", new javax.swing.AbstractAction() {
            @Override
            public void actionPerformed(java.awt.event.ActionEvent e) {
                resultsTable.clearSelection();
            }
        });

        return panel;
    }

    private JToolBar buildEditorToolbar() {
        JToolBar bar = new JToolBar();
        bar.setFloatable(false);

        executeButton = new JButton("Execute (Ctrl+Enter)");
        executeButton.addActionListener(e -> onExecute());
        bar.add(executeButton);

        bar.addSeparator();

        clearButton = new JButton("Clear");
        clearButton.addActionListener(e -> {
            sqlEditor.setText("");
            clearResults();
        });
        bar.add(clearButton);

        bar.addSeparator();

        exportResultsButton = new JButton("Export Results");
        exportResultsButton.setEnabled(false);
        exportResultsButton.addActionListener(e -> onExportResults());
        bar.add(exportResultsButton);

        bar.addSeparator();

        JButton explainButton = new JButton("Explain");
        explainButton.setToolTipText("Show query execution plan");
        explainButton.addActionListener(e -> onExplain());
        bar.add(explainButton);

        bar.addSeparator();

        JButton saveQueryButton = new JButton("Save");
        saveQueryButton.setToolTipText("Save current query (Ctrl+S)");
        saveQueryButton.addActionListener(e -> onSaveQuery());
        bar.add(saveQueryButton);

        JButton loadQueryButton = new JButton("Queries");
        loadQueryButton.setToolTipText("Load a saved query");
        loadQueryButton.addActionListener(e -> showLoadQueryMenu(loadQueryButton));
        bar.add(loadQueryButton);

        return bar;
    }

    private JPanel buildResultsPanel() {
        JPanel panel = new JPanel(new BorderLayout());

        resultsTabs = new JTabbedPane();

        // Initial empty results table (will be replaced by dynamic result tabs)
        resultsTable = createResultTable();
        resultsTableModel = (DefaultTableModel) resultsTable.getModel();

        // Messages tab (fixed)
        messagesArea = new JTextArea();
        messagesArea.setEditable(false);
        messagesArea.setFont(monoFont());
        messagesScroll = new JScrollPane(messagesArea);
        resultsTabs.addTab("Messages", messagesScroll);

        // Info tab (fixed)
        infoArea = new JTextArea();
        infoArea.setEditable(false);
        infoArea.setFont(monoFont());
        infoScroll = new JScrollPane(infoArea);
        resultsTabs.addTab("Info", infoScroll);

        // History tab
        historyTableModel = new DefaultTableModel(new String[]{"Time", "Duration", "Rows", "SQL"}, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }
        };
        historyTable = new JTable(historyTableModel);
        historyTable.setFont(monoFont());
        historyTable.getColumnModel().getColumn(0).setPreferredWidth(70);
        historyTable.getColumnModel().getColumn(0).setMaxWidth(90);
        historyTable.getColumnModel().getColumn(1).setPreferredWidth(70);
        historyTable.getColumnModel().getColumn(1).setMaxWidth(90);
        historyTable.getColumnModel().getColumn(2).setPreferredWidth(50);
        historyTable.getColumnModel().getColumn(2).setMaxWidth(70);
        historyTable.getColumnModel().getColumn(3).setPreferredWidth(600);
        historyTable.addMouseListener(new java.awt.event.MouseAdapter() {
            @Override
            public void mouseClicked(java.awt.event.MouseEvent e) {
                if (e.getClickCount() == 2) {
                    onHistoryDoubleClick();
                }
            }

            @Override
            public void mousePressed(java.awt.event.MouseEvent e) {
                if (e.isPopupTrigger()) {
                    showHistoryContextMenu(e);
                }
            }

            @Override
            public void mouseReleased(java.awt.event.MouseEvent e) {
                if (e.isPopupTrigger()) {
                    showHistoryContextMenu(e);
                }
            }
        });
        historyScroll = new JScrollPane(historyTable);
        resultsTabs.addTab("History", historyScroll);

        // Value viewer panel (toggled with F7)
        valueViewer = new RSyntaxTextArea();
        valueViewer.setEditable(false);
        valueViewer.setSyntaxEditingStyle(SyntaxConstants.SYNTAX_STYLE_NONE);
        valueViewer.setFont(monoFont());
        valueViewer.setLineWrap(true);
        valueViewer.setWrapStyleWord(true);
        applySyntaxTheme(valueViewer);

        resultsSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT, resultsTabs, new RTextScrollPane(valueViewer));
        resultsSplit.setResizeWeight(0.7);
        resultsSplit.setDividerLocation(1.0);
        resultsSplit.getBottomComponent().setVisible(false);
        valueViewerVisible = false;

        panel.add(resultsSplit, BorderLayout.CENTER);
        return panel;
    }

    // -------------------------------------------------------------------------
    // Connection dialog (modal)
    // -------------------------------------------------------------------------

    /**
     * Shows the New/Edit connection dialog. If session is null, creates a new
     * session. If session is non-null, edits the existing session.
     */
    private void showConnectionDialog(DbSession existing) {
        boolean isEdit = existing != null;
        JDialog dialog = new JDialog(SwingUtilities.getWindowAncestor(this),
                isEdit ? "Edit Connection" : "New Connection", java.awt.Dialog.ModalityType.APPLICATION_MODAL);
        dialog.setLayout(new BorderLayout());
        dialog.setSize(620, 540);
        dialog.setLocationRelativeTo(this);

        JPanel form = new JPanel(new GridBagLayout());
        form.setBorder(BorderFactory.createEmptyBorder(10, 12, 6, 12));
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(3, 4, 3, 4);
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.anchor = GridBagConstraints.WEST;

        int row = 0;

        // Name
        JTextField nameField = new JTextField(20);
        addDialogField(form, gbc, "Name:", nameField, row++);

        // Group (optional)
        JTextField groupField = new JTextField(20);
        addDialogField(form, gbc, "Group:", groupField, row++);

        // Type
        JComboBox<DbTypeSelection> typeCombo = new JComboBox<>(DbTypeSelection.values());
        addDialogField(form, gbc, "Type:", typeCombo, row++);

        // Host
        JTextField hostField = new JTextField("localhost", 20);
        addDialogField(form, gbc, "Host:", hostField, row++);

        // Port
        JTextField portField = new JTextField(String.valueOf(DbTypeSelection.MYSQL.defaultPort()), 6);
        addDialogField(form, gbc, "Port:", portField, row++);

        // Database
        JTextField databaseField = new JTextField(20);
        addDialogField(form, gbc, "Database:", databaseField, row++);

        // Username
        JTextField usernameField = new JTextField(20);
        addDialogField(form, gbc, "User:", usernameField, row++);

        // Password
        JPasswordField passwordField = new JPasswordField(20);
        addDialogField(form, gbc, "Password:", passwordField, row++);

        // SSL
        JCheckBox sslCheckBox = new JCheckBox("Use SSL/TLS");
        gbc.gridx = 1;
        gbc.gridy = row++;
        gbc.weightx = 1.0;
        form.add(sslCheckBox, gbc);

        // -- SSH Tunnel section --
        JCheckBox sshCheckBox = new JCheckBox("SSH Tunnel");
        gbc.gridx = 0;
        gbc.gridy = row++;
        gbc.gridwidth = 2;
        gbc.weightx = 0;
        form.add(sshCheckBox, gbc);
        gbc.gridwidth = 1;

        JPanel sshPanel = new JPanel(new GridBagLayout());
        sshPanel.setVisible(false);
        GridBagConstraints sgbc = new GridBagConstraints();
        sgbc.insets = new Insets(2, 4, 2, 4);
        sgbc.fill = GridBagConstraints.HORIZONTAL;
        sgbc.anchor = GridBagConstraints.WEST;

        JTextField sshHostField = new JTextField(14);
        addDialogField(sshPanel, sgbc, "SSH Host:", sshHostField, 0);

        JTextField sshPortField = new JTextField("22", 5);
        addDialogField(sshPanel, sgbc, "SSH Port:", sshPortField, 1);

        JTextField sshUserField = new JTextField(14);
        addDialogField(sshPanel, sgbc, "SSH User:", sshUserField, 2);

        JPasswordField sshPassField = new JPasswordField(14);
        addDialogField(sshPanel, sgbc, "SSH Pass:", sshPassField, 3);

        JTextField sshKeyField = new JTextField(14);
        JButton sshKeyBrowse = new JButton("...");
        sshKeyBrowse.setPreferredSize(new Dimension(28, 24));
        sshKeyBrowse.addActionListener(e -> {
            JFileChooser chooser = new JFileChooser();
            chooser.setDialogTitle("Select SSH Private Key");
            if (chooser.showOpenDialog(dialog) == JFileChooser.APPROVE_OPTION) {
                sshKeyField.setText(chooser.getSelectedFile().getAbsolutePath());
            }
        });
        sgbc.gridy = 4;
        sgbc.gridx = 0;
        sgbc.weightx = 0;
        sshPanel.add(new JLabel("SSH Key:"), sgbc);
        sgbc.gridx = 1;
        sgbc.weightx = 1.0;
        JPanel keyRow = new JPanel(new BorderLayout(2, 0));
        keyRow.add(sshKeyField, BorderLayout.CENTER);
        keyRow.add(sshKeyBrowse, BorderLayout.EAST);
        sshPanel.add(keyRow, sgbc);

        gbc.gridx = 0;
        gbc.gridy = row++;
        gbc.gridwidth = 2;
        gbc.weightx = 1.0;
        form.add(sshPanel, gbc);
        gbc.gridwidth = 1;

        sshCheckBox.addItemListener(e -> {
            sshPanel.setVisible(sshCheckBox.isSelected());
            dialog.revalidate();
        });

        // Auto-update port when type changes
        typeCombo.addItemListener(e -> {
            if (e.getStateChange() == ItemEvent.SELECTED) {
                DbTypeSelection sel = (DbTypeSelection) typeCombo.getSelectedItem();
                if (sel != null) {
                    portField.setText(sel.defaultPort() > 0 ? String.valueOf(sel.defaultPort()) : "");
                }
            }
        });

        // Auto-fill name
        Runnable autoName = () -> {
            if (nameField.getText().isBlank() || !isEdit) {
                DbTypeSelection sel = (DbTypeSelection) typeCombo.getSelectedItem();
                String h = hostField.getText().trim();
                String p = portField.getText().trim();
                String d = databaseField.getText().trim();
                String auto = (sel != null ? sel.name() : "DB") + " @ " + h;
                if (!p.isBlank()) {
                    auto += ":" + p;
                }
                if (!d.isBlank()) {
                    auto += "/" + d;
                }
                nameField.setText(auto);
            }
        };

        // Pre-fill from existing session
        if (isEdit) {
            nameField.setText(existing.name != null ? existing.name : "");
            groupField.setText(existing.group != null ? existing.group : "");
            typeCombo.setSelectedItem(existing.dbType);
            hostField.setText(existing.host != null ? existing.host : "");
            portField.setText(existing.port > 0 ? String.valueOf(existing.port) : "");
            databaseField.setText(existing.database != null ? existing.database : "");
            usernameField.setText(existing.username != null ? existing.username : "");
            sslCheckBox.setSelected(existing.useSsl);
            sshCheckBox.setSelected(existing.sshEnabled);
            sshPanel.setVisible(existing.sshEnabled);
            sshHostField.setText(existing.sshHost != null ? existing.sshHost : "");
            sshPortField.setText(existing.sshPort > 0 ? String.valueOf(existing.sshPort) : "22");
            sshUserField.setText(existing.sshUsername != null ? existing.sshUsername : "");
            sshKeyField.setText(existing.sshKeyPath != null ? existing.sshKeyPath : "");
        }

        dialog.add(new JScrollPane(form), BorderLayout.CENTER);

        // -- Button panel --
        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.RIGHT, 6, 6));

        JButton testBtn = new JButton("Test Connection");
        testBtn.addActionListener(e -> {
            DbTypeSelection sel = (DbTypeSelection) typeCombo.getSelectedItem();
            if (sel == null) {
                return;
            }
            testBtn.setEnabled(false);
            testBtn.setText("Testing...");

            // Capture all field values on the EDT before spawning a virtual thread
            String testHost = hostField.getText().trim();
            int testPort = parsePort(portField.getText().trim(), sel.defaultPort());
            String testDatabase = databaseField.getText().trim();
            String testUsername = usernameField.getText().trim();
            String testPassword = new String(passwordField.getPassword());
            boolean testSsl = sslCheckBox.isSelected();
            boolean testSshEnabled = sshCheckBox.isSelected();
            String testSshHost = sshHostField.getText().trim();
            int testSshPort = parsePort(sshPortField.getText().trim(), 22);
            String testSshUser = sshUserField.getText().trim();
            String testSshPass = new String(sshPassField.getPassword());
            String testSshKey = sshKeyField.getText().trim();
            DbTypeSelection testDbType = sel;

            Thread.ofVirtual().name("db-test").start(() -> {
                SshTunnel.ActiveTunnel tempTunnel = null;
                try {
                    String connectHost = testHost;
                    int connectPort = testPort;

                    // Open SSH tunnel if enabled
                    if (testSshEnabled && !testSshHost.isBlank()) {
                        SshTunnelConfig tunnelCfg = new SshTunnelConfig(testSshHost, testSshPort, testSshUser,
                                testSshPass.isEmpty() ? null : testSshPass, testSshKey.isEmpty() ? null : testSshKey,
                                testHost, testPort, 0, 15_000);
                        tempTunnel = SshTunnel.open(tunnelCfg, msg -> {
                        });
                        connectHost = "127.0.0.1";
                        connectPort = tempTunnel.localPort();
                    }

                    long startMs = System.currentTimeMillis();
                    String serverInfo;

                    if (testDbType == DbTypeSelection.MONGODB) {
                        serverInfo = testMongoConnection(connectHost, connectPort, testDatabase, testUsername,
                                testPassword, testSsl);
                    } else if (testDbType == DbTypeSelection.REDIS) {
                        serverInfo = testRedisConnection(connectHost, connectPort, testDatabase, testUsername,
                                testPassword, testSsl);
                    } else {
                        serverInfo = testSqlConnection(testDbType, connectHost, connectPort, testDatabase, testUsername,
                                testPassword, testSsl);
                    }

                    long elapsed = System.currentTimeMillis() - startMs;
                    String resultMsg = "Connection successful!\n\n" + serverInfo + "\nLatency: " + elapsed + " ms";

                    SwingUtilities.invokeLater(() -> {
                        testBtn.setEnabled(true);
                        testBtn.setText("Test Connection");
                        JOptionPane.showMessageDialog(dialog, resultMsg, "Test Connection",
                                JOptionPane.INFORMATION_MESSAGE);
                    });
                } catch (Exception ex) {
                    String errMsg = ex.getMessage() != null ? ex.getMessage() : ex.getClass().getSimpleName();
                    SwingUtilities.invokeLater(() -> {
                        testBtn.setEnabled(true);
                        testBtn.setText("Test Connection");
                        JOptionPane.showMessageDialog(dialog, "Connection failed:\n\n" + errMsg, "Test Connection",
                                JOptionPane.ERROR_MESSAGE);
                    });
                } finally {
                    if (tempTunnel != null) {
                        tempTunnel.close();
                    }
                }
            });
        });
        buttons.add(testBtn);

        JButton saveBtn = new JButton("Save");
        saveBtn.setToolTipText("Save without connecting");
        saveBtn.addActionListener(e -> {
            DbSession session = isEdit ? existing : new DbSession();
            fillSessionFromDialog(session, nameField, groupField, typeCombo, hostField, portField, databaseField,
                    usernameField, sslCheckBox, sshCheckBox, sshHostField, sshPortField, sshUserField, sshKeyField);
            session.discovered = false;
            if (!isEdit) {
                addSessionToTree(session);
            } else {
                updateSessionTreeNode(session);
            }
            dialog.dispose();
            persistConnections();
        });
        buttons.add(saveBtn);

        JButton connectBtn = new JButton("Connect");
        connectBtn.addActionListener(e -> {
            DbSession session = isEdit ? existing : new DbSession();
            fillSessionFromDialog(session, nameField, groupField, typeCombo, hostField, portField, databaseField,
                    usernameField, sslCheckBox, sshCheckBox, sshHostField, sshPortField, sshUserField, sshKeyField);
            String password = new String(passwordField.getPassword());
            String sshPass = new String(sshPassField.getPassword());
            session.discovered = false;
            if (!isEdit) {
                addSessionToTree(session);
            } else {
                updateSessionTreeNode(session);
            }
            dialog.dispose();
            persistConnections();
            doConnect(session, password, sshPass);
        });
        buttons.add(connectBtn);

        JButton cancelBtn = new JButton("Cancel");
        cancelBtn.addActionListener(e -> dialog.dispose());
        buttons.add(cancelBtn);

        dialog.add(buttons, BorderLayout.SOUTH);
        dialog.setVisible(true);
    }

    private void fillSessionFromDialog(DbSession session, JTextField nameField, JTextField groupField,
            JComboBox<DbTypeSelection> typeCombo, JTextField hostField, JTextField portField, JTextField databaseField,
            JTextField usernameField, JCheckBox sslCheckBox, JCheckBox sshCheckBox, JTextField sshHostField,
            JTextField sshPortField, JTextField sshUserField, JTextField sshKeyField) {
        session.dbType = (DbTypeSelection) typeCombo.getSelectedItem();
        session.host = hostField.getText().trim();
        session.port = parsePort(portField.getText().trim(), session.dbType.defaultPort());
        session.database = databaseField.getText().trim();
        session.username = usernameField.getText().trim();
        session.useSsl = sslCheckBox.isSelected();
        session.sshEnabled = sshCheckBox.isSelected();
        session.sshHost = sshHostField.getText().trim();
        session.sshPort = parsePort(sshPortField.getText().trim(), 22);
        session.sshUsername = sshUserField.getText().trim();
        session.sshKeyPath = sshKeyField.getText().trim();
        String nameText = nameField.getText().trim();
        session.name = nameText.isBlank() ? session.displayName() : nameText;
        String groupText = groupField.getText().trim();
        session.group = groupText.isBlank() ? null : groupText;
    }

    // -------------------------------------------------------------------------
    // Session management
    // -------------------------------------------------------------------------

    private void addSessionToTree(DbSession session) {
        sessions.add(session);
        DefaultMutableTreeNode sessionNode = new DefaultMutableTreeNode(new SessionNodeData(session));
        session.treeNode = sessionNode;
        DefaultMutableTreeNode parent = getOrCreateGroupNode(session.group);
        parent.add(sessionNode);
        connectionTreeModel.reload(connectionTreeRoot);
        connectionTree.setSelectionPath(new TreePath(sessionNode.getPath()));
        setActiveSession(session);
    }

    private DefaultMutableTreeNode getOrCreateGroupNode(String group) {
        if (group == null || group.isBlank()) {
            return connectionTreeRoot;
        }
        for (int i = 0; i < connectionTreeRoot.getChildCount(); i++) {
            DefaultMutableTreeNode child = (DefaultMutableTreeNode) connectionTreeRoot.getChildAt(i);
            if (child.getUserObject() instanceof String s && s.equals(group)) {
                return child;
            }
        }
        DefaultMutableTreeNode groupNode = new DefaultMutableTreeNode(group);
        connectionTreeRoot.add(groupNode);
        return groupNode;
    }

    private void updateSessionTreeNode(DbSession session) {
        if (session.treeNode != null) {
            session.treeNode.setUserObject(new SessionNodeData(session));
            connectionTreeModel.nodeChanged(session.treeNode);
        }
    }

    private void onRemoveSession() {
        DbSession session = getSelectedSession();
        if (session == null) {
            return;
        }
        String msg = session.connected
                ? "Session \"" + session.displayName() + "\" is connected. Disconnect and remove?"
                : "Remove connection \"" + session.displayName() + "\"?";
        int choice = JOptionPane.showConfirmDialog(this, msg, "Remove Connection", JOptionPane.YES_NO_OPTION);
        if (choice != JOptionPane.YES_OPTION) {
            return;
        }
        if (session.connected) {
            doDisconnect(session);
        }
        sessions.remove(session);
        if (session.treeNode != null) {
            connectionTreeModel.removeNodeFromParent(session.treeNode);
        }
        if (activeSession == session) {
            activeSession = null;
            clearEditorAndResults();
            updateToolbarState();
            updateStatusBar();
        }
        persistConnections();
    }

    private void onEditSession() {
        DbSession session = getSelectedSession();
        if (session == null) {
            return;
        }
        if (session.connected) {
            JOptionPane.showMessageDialog(this, "Disconnect before editing.", "Edit", JOptionPane.WARNING_MESSAGE);
            return;
        }
        showConnectionDialog(session);
    }

    private void onConnectToggle() {
        DbSession session = getSelectedSession();
        if (session == null) {
            return;
        }
        if (session.connected) {
            doDisconnect(session);
        } else {
            // Need password -- show a quick dialog
            showConnectPasswordDialog(session);
        }
    }

    /**
     * Shows a minimal password prompt to connect an existing saved session. SSH
     * password is also requested if SSH tunnel is enabled.
     */
    private void showConnectPasswordDialog(DbSession session) {
        JPanel panel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(3, 4, 3, 4);
        gbc.fill = GridBagConstraints.HORIZONTAL;

        JPasswordField passField = new JPasswordField(16);
        addDialogField(panel, gbc, "Password:", passField, 0);

        JPasswordField sshPassField = new JPasswordField(16);
        if (session.sshEnabled) {
            addDialogField(panel, gbc, "SSH Password:", sshPassField, 1);
        }

        int result = JOptionPane.showConfirmDialog(this, panel, "Connect to " + session.displayName(),
                JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);
        if (result == JOptionPane.OK_OPTION) {
            String password = new String(passField.getPassword());
            String sshPass = new String(sshPassField.getPassword());
            doConnect(session, password, sshPass);
        }
    }

    private void setActiveSession(DbSession session) {
        // Save current editor text to previous active session
        if (activeSession != null && sqlEditor != null) {
            activeSession.lastQueryText = sqlEditor.getText();
        }

        activeSession = session;

        // Restore editor text from new active session
        if (session != null && sqlEditor != null) {
            sqlEditor.setText(session.lastQueryText != null ? session.lastQueryText : "");
        }

        // Restore results from active session
        restoreSessionResults(session);
        updateToolbarState();
        updateStatusBar();
    }

    private void restoreSessionResults(DbSession session) {
        resultsTableModel.setRowCount(0);
        resultsTableModel.setColumnCount(0);
        messagesArea.setText("");
        infoArea.setText("");

        if (session != null && session.lastResultColumns != null && session.lastResultRows != null) {
            for (String col : session.lastResultColumns) {
                resultsTableModel.addColumn(col);
            }
            for (List<String> row : session.lastResultRows) {
                resultsTableModel.addRow(row.toArray());
            }
            exportResultsButton.setEnabled(true);
        } else {
            exportResultsButton.setEnabled(false);
        }
    }

    // -------------------------------------------------------------------------
    // Connection logic
    // -------------------------------------------------------------------------

    private void doConnect(DbSession session, String password, String sshPassword) {
        setStatus("Connecting to " + session.displayName() + "...", AnarCryLaf.fg());
        connectToggleButton.setEnabled(false);

        Thread.ofVirtual().name("db-connect-" + session.displayName()).start(() -> {
            Consumer<String> log = this::logMessage;
            try {
                // SSH tunnel if enabled
                if (session.sshEnabled) {
                    openSshTunnel(session, sshPassword, log);
                }

                if (session.dbType == DbTypeSelection.MONGODB) {
                    connectMongo(session, password, log);
                } else if (session.dbType == DbTypeSelection.REDIS) {
                    connectRedis(session, password, log);
                } else {
                    connectSql(session, password, log);
                }

                SwingUtilities.invokeLater(() -> {
                    session.connected = true;
                    updateSessionTreeNode(session);
                    updateToolbarState();
                    updateStatusBar();
                    refreshCompletions(session);
                });
            } catch (Exception ex) {
                log.accept("[!] Connection failed -- " + ex.getMessage());
                closeTunnel(session);
                SwingUtilities.invokeLater(() -> {
                    setStatus("Error: " + ex.getMessage(), Color.RED);
                    updateToolbarState();
                });
            }
        });
    }

    private void connectSql(DbSession session, String password, Consumer<String> log) throws Exception {
        String host = session.host;
        int port = session.port;

        if (session.activeTunnel != null) {
            host = "127.0.0.1";
            port = session.activeTunnel.localPort();
        }

        ConnectionConfig config = new ConnectionConfig(session.dbType.toDbType(), host, port, session.database,
                session.username, password, "", ConnectionConfig.DEFAULT_CONNECT_TIMEOUT_MS,
                ConnectionConfig.DEFAULT_QUERY_TIMEOUT_MS, session.useSsl);

        session.sqlConnection = ConnectionManager.connect(config, log);
        session.sqlDialect = SqlDialect.fromDbType(session.dbType.toDbType());
        session.schemaBrowser = new SchemaBrowser(session.sqlConnection, session.sqlDialect);
        session.sqlExecutor = new SqlExecutor(session.sqlConnection, session.sqlDialect);

        String dbProduct = "";
        String dbVersion = "";
        try {
            var meta = session.sqlConnection.getMetaData();
            dbProduct = meta.getDatabaseProductName();
            dbVersion = meta.getDatabaseProductVersion();
            String driverName = meta.getDriverName();
            String driverVersion = meta.getDriverVersion();
            log.accept("[+] Connected to " + session.displayName() + " (" + dbProduct + " " + dbVersion + ")");
            String infoText = "Database: " + dbProduct + " " + dbVersion + "\nDriver: " + driverName + " "
                    + driverVersion + "\nHost: " + host + ":" + port + "\nSchema: " + session.database + "\nUser: "
                    + session.username;
            SwingUtilities.invokeLater(() -> {
                infoArea.setText(infoText);
                selectInfoTab();
            });
        } catch (Exception ex) {
            log.accept("[+] Connected to " + session.displayName());
        }

        SwingUtilities.invokeLater(() -> populateSqlTree(session, log));
    }

    private void connectMongo(DbSession session, String password, Consumer<String> log) {
        String host = session.host;
        int port = session.port;

        if (session.activeTunnel != null) {
            host = "127.0.0.1";
            port = session.activeTunnel.localPort();
        }

        StringBuilder connStr = new StringBuilder("mongodb://");
        if (session.username != null && !session.username.isEmpty()) {
            connStr.append(session.username);
            if (!password.isEmpty()) {
                connStr.append(":").append(password);
            }
            connStr.append("@");
        }
        connStr.append(host).append(":").append(port);
        if (session.database != null && !session.database.isEmpty()) {
            connStr.append("/").append(session.database);
        }
        if (session.useSsl) {
            connStr.append(connStr.toString().contains("?") ? "&" : "?");
            connStr.append("tls=true");
        }

        session.mongoExplorer = new MongoExplorer();
        session.mongoExplorer.connect(new MongoExplorer.MongoConfig(connStr.toString()), log);
        log.accept("[+] Connected to " + session.displayName() + " (MongoDB)");
        String mongoHost = host;
        int mongoPort = port;
        SwingUtilities.invokeLater(() -> {
            infoArea.setText("Database: MongoDB\nHost: " + mongoHost + ":" + mongoPort + "\nDatabase: "
                    + (session.database != null ? session.database : "default"));
            selectInfoTab();
        });

        SwingUtilities.invokeLater(() -> populateMongoTree(session, log));
    }

    private void connectRedis(DbSession session, String password, Consumer<String> log) {
        String host = session.host;
        int port = session.port;
        int db = 0;
        if (session.database != null && !session.database.isBlank()) {
            try {
                db = Integer.parseInt(session.database);
            } catch (NumberFormatException ex) {
                // keep default 0
            }
        }

        if (session.activeTunnel != null) {
            host = "127.0.0.1";
            port = session.activeTunnel.localPort();
        }

        session.redisExplorer = new RedisExplorer();
        RedisExplorer.RedisConfig redisConfig = new RedisExplorer.RedisConfig(host, port,
                password.isEmpty() ? null : password,
                (session.username != null && !session.username.isEmpty()) ? session.username : null, session.useSsl,
                5_000, db);
        session.redisExplorer.connect(redisConfig, log);
        log.accept("[+] Connected to " + session.displayName() + " (Redis)");
        String redisHost = host;
        int redisPort = port;
        int redisDb = db;
        SwingUtilities.invokeLater(() -> {
            infoArea.setText("Database: Redis\nHost: " + redisHost + ":" + redisPort + "\nDB: " + redisDb);
            selectInfoTab();
        });

        SwingUtilities.invokeLater(() -> populateRedisTree(session, log));
    }

    private void openSshTunnel(DbSession session, String sshPassword, Consumer<String> log) throws Exception {
        SshTunnelConfig tunnelConfig = new SshTunnelConfig(session.sshHost, session.sshPort, session.sshUsername,
                sshPassword.isEmpty() ? null : sshPassword, session.sshKeyPath.isEmpty() ? null : session.sshKeyPath,
                session.host, session.port, 0, 15_000);

        session.activeTunnel = SshTunnel.open(tunnelConfig, log);
    }

    private void doDisconnect(DbSession session) {
        Thread.ofVirtual().name("db-disconnect-" + session.displayName()).start(() -> {
            Consumer<String> log = this::logMessage;
            try {
                if (session.sqlConnection != null && !session.sqlConnection.isClosed()) {
                    session.sqlConnection.close();
                    log.accept("[+] SQL connection closed -- " + session.displayName());
                }
            } catch (Exception ex) {
                log.accept("[!] Error closing SQL connection -- " + ex.getMessage());
            }
            session.sqlConnection = null;
            session.schemaBrowser = null;
            session.sqlExecutor = null;
            session.sqlDialect = null;

            if (session.mongoExplorer != null) {
                session.mongoExplorer.disconnect();
                session.mongoExplorer = null;
                log.accept("[+] MongoDB connection closed -- " + session.displayName());
            }
            if (session.redisExplorer != null) {
                session.redisExplorer.disconnect();
                session.redisExplorer = null;
                log.accept("[+] Redis connection closed -- " + session.displayName());
            }

            closeTunnel(session);

            SwingUtilities.invokeLater(() -> {
                session.connected = false;
                clearSessionTreeChildren(session);
                updateSessionTreeNode(session);
                if (activeSession == session) {
                    clearResults();
                }
                updateToolbarState();
                updateStatusBar();
            });
        });
    }

    // -------------------------------------------------------------------------
    // Schema tree population
    // -------------------------------------------------------------------------

    private void populateSqlTree(DbSession session, Consumer<String> log) {
        if (session.treeNode == null) {
            return;
        }
        session.treeNode.removeAllChildren();

        List<String> schemas = session.schemaBrowser.listSchemas(log);
        for (String schema : schemas) {
            DefaultMutableTreeNode schemaNode = new DefaultMutableTreeNode(new SchemaNodeData(session, schema));
            schemaNode.add(new DefaultMutableTreeNode("Loading..."));
            session.treeNode.add(schemaNode);
        }
        connectionTreeModel.reload(session.treeNode);
        connectionTree.expandPath(new TreePath(session.treeNode.getPath()));
    }

    private void populateMongoTree(DbSession session, Consumer<String> log) {
        if (session.treeNode == null) {
            return;
        }
        session.treeNode.removeAllChildren();

        List<String> databases = session.mongoExplorer.listDatabases(log);
        for (String db : databases) {
            DefaultMutableTreeNode dbNode = new DefaultMutableTreeNode(new SchemaNodeData(session, db));
            dbNode.add(new DefaultMutableTreeNode("Loading..."));
            session.treeNode.add(dbNode);
        }
        connectionTreeModel.reload(session.treeNode);
        connectionTree.expandPath(new TreePath(session.treeNode.getPath()));
    }

    private void populateRedisTree(DbSession session, Consumer<String> log) {
        if (session.treeNode == null) {
            return;
        }
        session.treeNode.removeAllChildren();

        long dbSize = session.redisExplorer.dbsize(log);
        DefaultMutableTreeNode infoNode = new DefaultMutableTreeNode("Keys: " + dbSize);
        session.treeNode.add(infoNode);

        List<String> keys = session.redisExplorer.keys("*", 50, log);
        for (String key : keys) {
            session.treeNode.add(new DefaultMutableTreeNode(new RedisKeyNodeData(session, key)));
        }
        connectionTreeModel.reload(session.treeNode);
        connectionTree.expandPath(new TreePath(session.treeNode.getPath()));
    }

    /** Lazy-load child nodes when a tree node is expanded. */
    private void onTreeWillExpand(TreePath path) {
        DefaultMutableTreeNode node = (DefaultMutableTreeNode) path.getLastPathComponent();
        Object data = node.getUserObject();

        if (node.getChildCount() == 1) {
            DefaultMutableTreeNode firstChild = (DefaultMutableTreeNode) node.getChildAt(0);
            if ("Loading...".equals(firstChild.getUserObject())) {
                node.removeAllChildren();
                Thread.ofVirtual().name("tree-expand").start(() -> expandNode(node, data));
            }
        }
    }

    private void expandNode(DefaultMutableTreeNode node, Object data) {
        Consumer<String> log = this::logMessage;

        if (data instanceof SchemaNodeData snd) {
            populateSchemaChildren(snd.session(), node, snd.name());
        } else if (data instanceof TableNodeData tnd && tnd.session().schemaBrowser != null) {
            // SQL: load columns for this table
            List<ColumnInfo> cols = tnd.session().schemaBrowser.listColumns(tnd.schema(), tnd.info().name(), log);
            SwingUtilities.invokeLater(() -> {
                for (ColumnInfo col : cols) {
                    String label = col.name() + " (" + col.typeName() + (col.primaryKey() ? ", PK" : "")
                            + (col.nullable() ? "" : ", NOT NULL") + ")";
                    node.add(new DefaultMutableTreeNode(label));
                }
                connectionTreeModel.reload(node);
            });
        }
    }

    private void populateSchemaChildren(DbSession session, DefaultMutableTreeNode node, String schemaName) {
        Consumer<String> log = this::logMessage;
        if (session.schemaBrowser != null) {
            List<TableInfo> tables = session.schemaBrowser.listTables(schemaName, log);
            SwingUtilities.invokeLater(() -> {
                node.removeAllChildren();
                for (TableInfo t : tables) {
                    DefaultMutableTreeNode tableNode = new DefaultMutableTreeNode(
                            new TableNodeData(session, schemaName, t));
                    tableNode.add(new DefaultMutableTreeNode("Loading..."));
                    node.add(tableNode);
                }
                connectionTreeModel.reload(node);
            });
        } else if (session.mongoExplorer != null) {
            List<MongoExplorer.CollectionInfo> colls = session.mongoExplorer.listCollections(schemaName, log);
            SwingUtilities.invokeLater(() -> {
                node.removeAllChildren();
                for (MongoExplorer.CollectionInfo ci : colls) {
                    node.add(new DefaultMutableTreeNode(new MongoCollNodeData(session, schemaName, ci)));
                }
                connectionTreeModel.reload(node);
            });
        }
    }

    // -------------------------------------------------------------------------
    // Tree interaction
    // -------------------------------------------------------------------------

    private void onTreeSelectionChanged(TreePath path) {
        DbSession session = resolveSessionFromPath(path);
        if (session != null && session != activeSession) {
            setActiveSession(session);
        }
        updateToolbarState();
    }

    private void onTreeDoubleClick() {
        TreePath path = connectionTree.getSelectionPath();
        if (path == null) {
            return;
        }
        DefaultMutableTreeNode node = (DefaultMutableTreeNode) path.getLastPathComponent();
        Object data = node.getUserObject();

        if (data instanceof SessionNodeData snd && !snd.session().connected) {
            // Double-click disconnected session -> open connect dialog
            showConnectPasswordDialog(snd.session());
            return;
        }

        if (data instanceof TableNodeData tnd) {
            DbSession session = tnd.session();
            setActiveSession(session);
            String query = session.sqlDialect
                    .limitQuery("SELECT * FROM " + session.sqlDialect.quoteIdentifier(tnd.schema()) + "."
                            + session.sqlDialect.quoteIdentifier(tnd.info().name()), QUERY_RESULT_LIMIT);
            sqlEditor.setText(query);
            onExecute();
        } else if (data instanceof MongoCollNodeData mc) {
            setActiveSession(mc.session());
            sqlEditor.setText("db." + mc.collName() + ".find({}).limit(" + QUERY_RESULT_LIMIT + ")");
            executeMongoFind(mc.session(), mc.dbName(), mc.collName(), "", log());
        } else if (data instanceof RedisKeyNodeData rk) {
            setActiveSession(rk.session());
            sqlEditor.setText("GET " + rk.key());
            executeRedisGet(rk.session(), rk.key(), log());
        }
    }

    private void showTreeContextMenu(MouseEvent e) {
        TreePath path = connectionTree.getPathForLocation(e.getX(), e.getY());
        if (path == null) {
            return;
        }
        connectionTree.setSelectionPath(path);
        DefaultMutableTreeNode node = (DefaultMutableTreeNode) path.getLastPathComponent();
        Object data = node.getUserObject();

        if (data instanceof SessionNodeData snd) {
            showSessionContextMenu(e, snd.session());
        } else if (data instanceof SchemaNodeData schemaData) {
            showSchemaContextMenu(e, schemaData);
        } else if (data instanceof TableNodeData tnd) {
            showTableContextMenu(e, tnd);
        } else if (data instanceof MongoCollNodeData mcd) {
            showMongoCollContextMenu(e, mcd);
        } else if (data instanceof RedisKeyNodeData rkd) {
            showRedisKeyContextMenu(e, rkd);
        } else if (data instanceof String s) {
            showColumnContextMenu(e, node, s);
        }
    }

    private void showSessionContextMenu(MouseEvent e, DbSession session) {
        JPopupMenu menu = new JPopupMenu();

        if (session.connected) {
            JMenuItem disconnect = new JMenuItem("Disconnect");
            disconnect.addActionListener(a -> doDisconnect(session));
            menu.add(disconnect);
        } else {
            JMenuItem connect = new JMenuItem("Connect");
            connect.addActionListener(a -> showConnectPasswordDialog(session));
            menu.add(connect);
        }

        menu.addSeparator();

        JMenuItem edit = new JMenuItem("Edit");
        edit.setEnabled(!session.connected);
        edit.addActionListener(a -> showConnectionDialog(session));
        menu.add(edit);

        JMenuItem duplicate = new JMenuItem("Duplicate");
        duplicate.addActionListener(a -> onDuplicateSession(session));
        menu.add(duplicate);

        JMenuItem remove = new JMenuItem("Remove");
        remove.addActionListener(a -> {
            setActiveSession(session);
            onRemoveSession();
        });
        menu.add(remove);

        menu.show(connectionTree, e.getX(), e.getY());
    }

    private void showTableContextMenu(MouseEvent e, TableNodeData tnd) {
        DbSession session = tnd.session();
        if (session.sqlDialect == null) {
            return;
        }

        JPopupMenu menu = new JPopupMenu();
        String schema = tnd.schema();
        String table = tnd.info().name();
        String qualified = session.sqlDialect.quoteIdentifier(schema) + "." + session.sqlDialect.quoteIdentifier(table);

        JMenuItem selectAll = new JMenuItem("SELECT *");
        selectAll.addActionListener(a -> {
            setActiveSession(session);
            String q = session.sqlDialect.limitQuery("SELECT * FROM " + qualified, QUERY_RESULT_LIMIT);
            sqlEditor.setText(q);
            onExecute();
        });
        menu.add(selectAll);

        JMenuItem selectCount = new JMenuItem("SELECT COUNT(*)");
        selectCount.addActionListener(a -> {
            setActiveSession(session);
            sqlEditor.setText("SELECT COUNT(*) FROM " + qualified);
            onExecute();
        });
        menu.add(selectCount);

        JMenuItem describe = new JMenuItem("DESCRIBE");
        describe.addActionListener(a -> {
            setActiveSession(session);
            Thread.ofVirtual().name("describe").start(() -> {
                String info = session.schemaBrowser.getTableInfo(schema, table, log());
                SwingUtilities.invokeLater(() -> {
                    infoArea.setText(info);
                    selectInfoTab();
                });
            });
        });
        menu.add(describe);

        menu.addSeparator();

        JMenuItem copyName = new JMenuItem("Copy Name");
        copyName.addActionListener(a -> copyToClipboard(table));
        menu.add(copyName);

        JMenuItem copyQualified = new JMenuItem("Copy Qualified Name");
        copyQualified.addActionListener(a -> copyToClipboard(qualified));
        menu.add(copyQualified);

        menu.addSeparator();

        JMenuItem rowCount = new JMenuItem("Row Count");
        rowCount.addActionListener(a -> {
            setActiveSession(session);
            sqlEditor.setText("SELECT COUNT(*) AS row_count FROM " + qualified);
            onExecute();
        });
        menu.add(rowCount);

        menu.addSeparator();

        JMenuItem exportCsv = new JMenuItem("Export CSV");
        exportCsv.addActionListener(a -> onExportTable(session, schema, table, "csv"));
        menu.add(exportCsv);

        JMenuItem exportJson = new JMenuItem("Export JSON");
        exportJson.addActionListener(a -> onExportTable(session, schema, table, "json"));
        menu.add(exportJson);

        menu.show(connectionTree, e.getX(), e.getY());
    }

    private void showSchemaContextMenu(MouseEvent e, SchemaNodeData schemaData) {
        JPopupMenu menu = new JPopupMenu();

        JMenuItem refresh = new JMenuItem("Refresh");
        refresh.addActionListener(a -> {
            DbSession session = schemaData.session();
            setActiveSession(session);
            DefaultMutableTreeNode schemaNode = (DefaultMutableTreeNode) connectionTree.getLastSelectedPathComponent();
            if (schemaNode != null) {
                schemaNode.removeAllChildren();
                schemaNode.add(new DefaultMutableTreeNode("Loading..."));
                ((DefaultTreeModel) connectionTree.getModel()).reload(schemaNode);
                Thread.ofVirtual().name("refresh-schema").start(() -> {
                    populateSchemaChildren(session, schemaNode, schemaData.name());
                });
            }
        });
        menu.add(refresh);

        JMenuItem cpName = new JMenuItem("Copy Name");
        cpName.addActionListener(a -> copyToClipboard(schemaData.name()));
        menu.add(cpName);

        menu.show(connectionTree, e.getX(), e.getY());
    }

    private void showMongoCollContextMenu(MouseEvent e, MongoCollNodeData mcd) {
        JPopupMenu menu = new JPopupMenu();

        JMenuItem findAll = new JMenuItem("db.coll.find({})");
        findAll.addActionListener(a -> {
            setActiveSession(mcd.session());
            sqlEditor.setText("db." + mcd.info().name() + ".find({}).limit(100)");
            onExecute();
        });
        menu.add(findAll);

        JMenuItem count = new JMenuItem("Count Documents");
        count.addActionListener(a -> {
            setActiveSession(mcd.session());
            sqlEditor.setText("db." + mcd.info().name() + ".find({}).count()");
            onExecute();
        });
        menu.add(count);

        menu.addSeparator();

        JMenuItem cpName = new JMenuItem("Copy Name");
        cpName.addActionListener(a -> copyToClipboard(mcd.info().name()));
        menu.add(cpName);

        menu.show(connectionTree, e.getX(), e.getY());
    }

    private void showRedisKeyContextMenu(MouseEvent e, RedisKeyNodeData rkd) {
        JPopupMenu menu = new JPopupMenu();

        JMenuItem getValue = new JMenuItem("GET");
        getValue.addActionListener(a -> {
            setActiveSession(rkd.session());
            sqlEditor.setText("GET " + rkd.key());
            onExecute();
        });
        menu.add(getValue);

        JMenuItem ttl = new JMenuItem("TTL");
        ttl.addActionListener(a -> {
            setActiveSession(rkd.session());
            sqlEditor.setText("TTL " + rkd.key());
            onExecute();
        });
        menu.add(ttl);

        JMenuItem type = new JMenuItem("TYPE");
        type.addActionListener(a -> {
            setActiveSession(rkd.session());
            sqlEditor.setText("TYPE " + rkd.key());
            onExecute();
        });
        menu.add(type);

        menu.addSeparator();

        JMenuItem cpName = new JMenuItem("Copy Key");
        cpName.addActionListener(a -> copyToClipboard(rkd.key()));
        menu.add(cpName);

        menu.show(connectionTree, e.getX(), e.getY());
    }

    private void showColumnContextMenu(MouseEvent e, DefaultMutableTreeNode node, String colName) {
        JPopupMenu menu = new JPopupMenu();

        String cleanName = colName.replaceAll("\\s*\\[.*?]", "").trim();

        JMenuItem cpName = new JMenuItem("Copy Name");
        cpName.addActionListener(a -> copyToClipboard(cleanName));
        menu.add(cpName);

        JMenuItem cpWhere = new JMenuItem("Copy WHERE Clause");
        cpWhere.addActionListener(a -> copyToClipboard(cleanName + " = ?"));
        menu.add(cpWhere);

        menu.show(connectionTree, e.getX(), e.getY());
    }

    private void onDuplicateSession(DbSession source) {
        DbSession dup = new DbSession();
        dup.name = source.name + " (copy)";
        dup.dbType = source.dbType;
        dup.host = source.host;
        dup.port = source.port;
        dup.database = source.database;
        dup.username = source.username;
        dup.useSsl = source.useSsl;
        dup.sshEnabled = source.sshEnabled;
        dup.sshHost = source.sshHost;
        dup.sshPort = source.sshPort;
        dup.sshUsername = source.sshUsername;
        dup.sshKeyPath = source.sshKeyPath;
        dup.group = source.group;
        dup.connected = false;
        addSessionToTree(dup);
    }

    // -------------------------------------------------------------------------
    // Query execution
    // -------------------------------------------------------------------------

    private void onExecute() {
        DbSession session = activeSession;
        if (session == null || !session.connected) {
            logMessage("[!] No active connected session");
            return;
        }

        String query = sqlEditor.getSelectedText();
        if (query == null || query.isBlank()) {
            query = sqlEditor.getText();
        }
        if (query == null || query.isBlank()) {
            logMessage("[!] Nothing to execute");
            return;
        }

        String finalQuery = query.trim();
        executeButton.setEnabled(false);

        if (session.dbType == DbTypeSelection.MONGODB) {
            Thread.ofVirtual().name("mongo-exec").start(() -> {
                long start = System.nanoTime();
                try {
                    int rows = executeMongoDynamic(session, finalQuery, log());
                    long ms = (System.nanoTime() - start) / 1_000_000;
                    recordHistory(finalQuery, ms, rows, null);
                } catch (Exception ex) {
                    long ms = (System.nanoTime() - start) / 1_000_000;
                    recordHistory(finalQuery, ms, -1, ex.getMessage());
                }
                SwingUtilities.invokeLater(() -> executeButton.setEnabled(true));
            });
        } else if (session.dbType == DbTypeSelection.REDIS) {
            Thread.ofVirtual().name("redis-exec").start(() -> {
                long start = System.nanoTime();
                try {
                    int rows = executeRedisDynamic(session, finalQuery, log());
                    long ms = (System.nanoTime() - start) / 1_000_000;
                    recordHistory(finalQuery, ms, rows, null);
                } catch (Exception ex) {
                    long ms = (System.nanoTime() - start) / 1_000_000;
                    recordHistory(finalQuery, ms, -1, ex.getMessage());
                }
                SwingUtilities.invokeLater(() -> executeButton.setEnabled(true));
            });
        } else {
            Thread.ofVirtual().name("sql-exec").start(() -> {
                long start = System.nanoTime();
                try {
                    int rows = executeSql(session, finalQuery, log());
                    long ms = (System.nanoTime() - start) / 1_000_000;
                    recordHistory(finalQuery, ms, rows, null);
                } catch (Exception ex) {
                    long ms = (System.nanoTime() - start) / 1_000_000;
                    recordHistory(finalQuery, ms, -1, ex.getMessage());
                }
                SwingUtilities.invokeLater(() -> executeButton.setEnabled(true));
            });
        }
    }

    private int executeSql(DbSession session, String sql, Consumer<String> log) {
        if (session.sqlExecutor == null) {
            log.accept("[!] Not connected to a SQL database");
            return -1;
        }
        QueryResult result = session.sqlExecutor.execute(sql, log);
        SwingUtilities.invokeLater(() -> displaySqlResult(session, result));
        return result != null && result.rows() != null ? result.rows().size() : 0;
    }

    private void displaySqlResult(DbSession session, QueryResult result) {
        JTable newTable = createResultTable();
        DefaultTableModel newModel = (DefaultTableModel) newTable.getModel();

        if (result.hasRows()) {
            for (String col : result.columnNames()) {
                newModel.addColumn(col);
            }
            for (List<String> row : result.rows()) {
                newModel.addRow(row.toArray());
            }
            session.lastResultColumns = result.columnNames();
            session.lastResultRows = result.rows();
            exportResultsButton.setEnabled(true);
        } else if (result.isDml()) {
            newModel.addColumn("Result");
            newModel.addRow(new Object[]{result.affectedRows() + " row(s) affected"});
            session.lastResultColumns = null;
            session.lastResultRows = null;
            exportResultsButton.setEnabled(false);
        } else {
            session.lastResultColumns = null;
            session.lastResultRows = null;
            exportResultsButton.setEnabled(false);
        }

        String tabTitle = sqlEditor.getText() != null && sqlEditor.getText().length() > 30
                ? sqlEditor.getText().substring(0, 30).replaceAll("\\s+", " ") + "..."
                : (sqlEditor.getText() != null ? sqlEditor.getText().replaceAll("\\s+", " ") : "Result");
        tabTitle = tabTitle + " " + resultTabTimeFmt.format(new java.util.Date());
        addResultTab(tabTitle, newTable);

        resultsTable = newTable;
        resultsTableModel = newModel;
        autoResizeColumns(resultsTable, 400);
        int rowCount = result.hasRows() && result.rows() != null ? result.rows().size() : 0;
        updateResultStatus(rowCount, result.executionTimeMs(), result.isDml() ? result.affectedRows() : -1);
    }

    private int executeMongoDynamic(DbSession session, String query, Consumer<String> log) {
        if (session.mongoExplorer == null) {
            log.accept("[!] Not connected to MongoDB");
            return -1;
        }
        String dbName = session.database;
        if (dbName == null || dbName.isEmpty()) {
            dbName = "test";
        }

        if (query.contains(".find(")) {
            String coll = extractMongoCollection(query, ".find(");
            String filter = extractMongoArg(query, ".find(");
            return executeMongoFind(session, dbName, coll, filter, log);
        } else if (query.contains(".aggregate(")) {
            String coll = extractMongoCollection(query, ".aggregate(");
            String pipeline = extractMongoArg(query, ".aggregate(");
            return executeMongoAggregate(session, dbName, coll, pipeline, log);
        } else {
            log.accept("[!] Unsupported MongoDB command. " + "Use db.<collection>.find({}) or "
                    + "db.<collection>.aggregate([...])");
            return -1;
        }
    }

    private int executeMongoFind(DbSession session, String dbName, String collection, String filter,
            Consumer<String> log) {
        if (session.mongoExplorer == null) {
            return -1;
        }
        List<String> docs = session.mongoExplorer.find(dbName, collection, filter, QUERY_RESULT_LIMIT, log);
        SwingUtilities.invokeLater(() -> {
            JTable newTable = createResultTable();
            DefaultTableModel newModel = (DefaultTableModel) newTable.getModel();
            newModel.addColumn("Document (JSON)");
            for (String doc : docs) {
                newModel.addRow(new Object[]{doc});
            }
            session.lastResultColumns = null;
            session.lastResultRows = null;
            exportResultsButton.setEnabled(false);
            String title = "find(" + collection + ") " + resultTabTimeFmt.format(new java.util.Date());
            addResultTab(title, newTable);
            resultsTable = newTable;
            resultsTableModel = newModel;
            autoResizeColumns(resultsTable, 400);
            updateResultStatus(docs.size(), -1, -1);
        });
        return docs.size();
    }

    private int executeMongoAggregate(DbSession session, String dbName, String collection, String pipeline,
            Consumer<String> log) {
        if (session.mongoExplorer == null) {
            return -1;
        }
        List<String> docs = session.mongoExplorer.aggregate(dbName, collection, pipeline, log);
        SwingUtilities.invokeLater(() -> {
            JTable newTable = createResultTable();
            DefaultTableModel newModel = (DefaultTableModel) newTable.getModel();
            newModel.addColumn("Result (JSON)");
            for (String doc : docs) {
                newModel.addRow(new Object[]{doc});
            }
            String title = "aggregate(" + collection + ") " + resultTabTimeFmt.format(new java.util.Date());
            addResultTab(title, newTable);
            resultsTable = newTable;
            resultsTableModel = newModel;
            autoResizeColumns(resultsTable, 400);
            updateResultStatus(docs.size(), -1, -1);
        });
        return docs.size();
    }

    private int executeRedisDynamic(DbSession session, String query, Consumer<String> log) {
        if (session.redisExplorer == null) {
            log.accept("[!] Not connected to Redis");
            return -1;
        }
        String upper = query.trim().toUpperCase();
        if (upper.startsWith("GET ")) {
            String key = query.trim().substring(4).trim();
            executeRedisGet(session, key, log);
            return 1;
        } else if (upper.startsWith("KEYS ")) {
            String pattern = query.trim().substring(5).trim();
            List<String> keys = session.redisExplorer.keys(pattern, QUERY_RESULT_LIMIT, log);
            SwingUtilities.invokeLater(() -> {
                JTable newTable = createResultTable();
                DefaultTableModel newModel = (DefaultTableModel) newTable.getModel();
                newModel.addColumn("Key");
                for (String k : keys) {
                    newModel.addRow(new Object[]{k});
                }
                addResultTab("KEYS " + resultTabTimeFmt.format(new java.util.Date()), newTable);
                resultsTable = newTable;
                resultsTableModel = newModel;
                autoResizeColumns(resultsTable, 400);
                updateResultStatus(keys.size(), -1, -1);
            });
            return keys.size();
        } else if (upper.startsWith("INFO")) {
            Map<String, String> info = session.redisExplorer.info(log);
            SwingUtilities.invokeLater(() -> {
                StringBuilder sb = new StringBuilder();
                info.forEach((k, v) -> sb.append(k).append(": ").append(v).append("\n"));
                infoArea.setText(sb.toString());
                selectInfoTab();
            });
            return info.size();
        } else {
            log.accept("[!] Supported Redis commands: GET <key>, KEYS <pattern>, INFO");
            return -1;
        }
    }

    private void executeRedisGet(DbSession session, String key, Consumer<String> log) {
        if (session.redisExplorer == null) {
            return;
        }
        String value = session.redisExplorer.get(key, log);
        SwingUtilities.invokeLater(() -> {
            JTable newTable = createResultTable();
            DefaultTableModel newModel = (DefaultTableModel) newTable.getModel();
            newModel.addColumn("Key");
            newModel.addColumn("Value");
            newModel.addRow(new Object[]{key, value != null ? value : "(nil)"});
            addResultTab("GET " + key + " " + resultTabTimeFmt.format(new java.util.Date()), newTable);
            resultsTable = newTable;
            resultsTableModel = newModel;
            autoResizeColumns(resultsTable, 400);
            updateResultStatus(1, -1, -1);
        });
    }

    // -------------------------------------------------------------------------
    // Schema tree filter
    // -------------------------------------------------------------------------

    private void applyTreeFilter(String filterText) {
        String filter = filterText.trim().toLowerCase();

        for (var entry : unfilteredChildren.entrySet()) {
            DefaultMutableTreeNode sessionNode = entry.getKey();
            sessionNode.removeAllChildren();
            for (DefaultMutableTreeNode child : entry.getValue()) {
                sessionNode.add(child);
            }
        }

        if (filter.isEmpty()) {
            unfilteredChildren.clear();
            connectionTreeModel.reload(connectionTreeRoot);
            for (int i = 0; i < connectionTreeRoot.getChildCount(); i++) {
                DefaultMutableTreeNode sn = (DefaultMutableTreeNode) connectionTreeRoot.getChildAt(i);
                connectionTree.expandPath(new TreePath(sn.getPath()));
            }
            return;
        }

        unfilteredChildren.clear();
        for (int i = 0; i < connectionTreeRoot.getChildCount(); i++) {
            DefaultMutableTreeNode sessionNode = (DefaultMutableTreeNode) connectionTreeRoot.getChildAt(i);
            List<DefaultMutableTreeNode> children = new ArrayList<>();
            for (int j = 0; j < sessionNode.getChildCount(); j++) {
                children.add((DefaultMutableTreeNode) sessionNode.getChildAt(j));
            }
            unfilteredChildren.put(sessionNode, children);
        }

        for (int i = 0; i < connectionTreeRoot.getChildCount(); i++) {
            DefaultMutableTreeNode sessionNode = (DefaultMutableTreeNode) connectionTreeRoot.getChildAt(i);
            List<DefaultMutableTreeNode> originals = unfilteredChildren.get(sessionNode);
            sessionNode.removeAllChildren();
            if (originals != null) {
                for (DefaultMutableTreeNode child : originals) {
                    if (nodeMatchesFilter(child, filter)) {
                        sessionNode.add(child);
                    }
                }
            }
        }

        connectionTreeModel.reload(connectionTreeRoot);

        for (int i = 0; i < connectionTreeRoot.getChildCount(); i++) {
            DefaultMutableTreeNode sessionNode = (DefaultMutableTreeNode) connectionTreeRoot.getChildAt(i);
            if (sessionNode.getChildCount() > 0) {
                connectionTree.expandPath(new TreePath(sessionNode.getPath()));
            }
        }
    }

    private boolean nodeMatchesFilter(DefaultMutableTreeNode node, String filter) {
        if (node.toString().toLowerCase().contains(filter)) {
            return true;
        }
        for (int i = 0; i < node.getChildCount(); i++) {
            if (nodeMatchesFilter((DefaultMutableTreeNode) node.getChildAt(i), filter)) {
                return true;
            }
        }
        return false;
    }

    // -------------------------------------------------------------------------
    // Export
    // -------------------------------------------------------------------------

    private void onExportResults() {
        DbSession session = activeSession;
        if (session == null || session.lastResultColumns == null || session.lastResultRows == null) {
            return;
        }
        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Export Results");
        FileNameExtensionFilter csvFilter = new FileNameExtensionFilter("CSV files (*.csv)", "csv");
        FileNameExtensionFilter jsonFilter = new FileNameExtensionFilter("JSON files (*.json)", "json");
        FileNameExtensionFilter sqlFilter = new FileNameExtensionFilter("SQL INSERT (*.sql)", "sql");
        FileNameExtensionFilter mdFilter = new FileNameExtensionFilter("Markdown (*.md)", "md");
        chooser.addChoosableFileFilter(csvFilter);
        chooser.addChoosableFileFilter(jsonFilter);
        chooser.addChoosableFileFilter(sqlFilter);
        chooser.addChoosableFileFilter(mdFilter);
        chooser.setFileFilter(csvFilter);

        if (chooser.showSaveDialog(this) != JFileChooser.APPROVE_OPTION) {
            return;
        }
        Path outputFile = chooser.getSelectedFile().toPath();
        javax.swing.filechooser.FileFilter selected = chooser.getFileFilter();
        String ext = outputFile.toString();

        List<String> cols = session.lastResultColumns;
        List<List<String>> rows = session.lastResultRows;

        Thread.ofVirtual().name("export-results").start(() -> {
            Consumer<String> log = this::logMessage;
            try {
                if (selected == sqlFilter || ext.endsWith(".sql")) {
                    String tableName = "exported_data";
                    DataExporter.exportSqlInsert(cols, rows, outputFile, tableName, log);
                } else if (selected == mdFilter || ext.endsWith(".md")) {
                    DataExporter.exportMarkdown(cols, rows, outputFile, log);
                } else if (selected == jsonFilter || ext.endsWith(".json")) {
                    DataExporter.exportJson(cols, rows, outputFile, log);
                } else {
                    DataExporter.exportCsv(cols, rows, outputFile, log);
                }
            } catch (Exception ex) {
                log.accept("[!] Export failed -- " + ex.getMessage());
            }
        });
    }

    private void onExportTable(DbSession session, String schema, String table, String format) {
        if (session.sqlConnection == null || session.sqlDialect == null) {
            return;
        }
        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Export " + table + " as " + format);
        chooser.setSelectedFile(new java.io.File(table + "." + format));

        if (chooser.showSaveDialog(this) != JFileChooser.APPROVE_OPTION) {
            return;
        }
        Path outputFile = chooser.getSelectedFile().toPath();

        Thread.ofVirtual().name("export-table").start(() -> {
            Consumer<String> log = this::logMessage;
            try {
                DataExporter.exportTable(session.sqlConnection, session.sqlDialect, schema, table, outputFile, format,
                        log);
            } catch (Exception ex) {
                log.accept("[!] Export failed -- " + ex.getMessage());
            }
        });
    }

    // -------------------------------------------------------------------------
    // Theme support
    // -------------------------------------------------------------------------

    private void onThemeChanged() {
        if (sqlEditor != null) {
            applySyntaxTheme(sqlEditor);
        }
        updateStatusBar();
    }

    private void applySyntaxTheme(RSyntaxTextArea area) {
        boolean dark = AnarCryLaf.isDark();
        String themePath = dark
                ? "/org/fife/ui/rsyntaxtextarea/themes/dark.xml"
                : "/org/fife/ui/rsyntaxtextarea/themes/default.xml";
        try {
            Theme theme = Theme.load(getClass().getResourceAsStream(themePath));
            theme.apply(area);
        } catch (Exception e) {
            if (dark) {
                area.setBackground(DARK_BG);
                area.setForeground(Color.WHITE);
                area.setCaretColor(Color.WHITE);
                area.setCurrentLineHighlightColor(new Color(0x2A, 0x2A, 0x3E));
            } else {
                area.setBackground(Color.WHITE);
                area.setForeground(new Color(0x1A, 0x1A, 0x1A));
                area.setCaretColor(new Color(0x1A, 0x1A, 0x1A));
            }
        }
    }

    // -------------------------------------------------------------------------
    // Connection test helpers (called from virtual thread -- never on EDT)
    // -------------------------------------------------------------------------

    /**
     * Tests a SQL connection and returns a summary string with the server product
     * name and version.
     */
    private static String testSqlConnection(DbTypeSelection dbType, String host, int port, String database,
            String username, String password, boolean useSsl) throws Exception {
        ConnectionConfig cfg = new ConnectionConfig(dbType.toDbType(), host, port, database, username, password, "",
                ConnectionConfig.DEFAULT_CONNECT_TIMEOUT_MS, ConnectionConfig.DEFAULT_QUERY_TIMEOUT_MS, useSsl);
        try (Connection conn = ConnectionManager.connect(cfg, msg -> {
        })) {
            java.sql.DatabaseMetaData meta = conn.getMetaData();
            String product = meta.getDatabaseProductName();
            String version = meta.getDatabaseProductVersion();
            return "Server: " + product + "\nVersion: " + version;
        }
    }

    /**
     * Tests a MongoDB connection and returns a summary with the server version
     * extracted from buildInfo.
     */
    private static String testMongoConnection(String host, int port, String database, String username, String password,
            boolean useSsl) {
        StringBuilder connStr = new StringBuilder("mongodb://");
        if (username != null && !username.isEmpty()) {
            connStr.append(username);
            if (!password.isEmpty()) {
                connStr.append(":").append(password);
            }
            connStr.append("@");
        }
        connStr.append(host).append(":").append(port);
        if (database != null && !database.isEmpty()) {
            connStr.append("/").append(database);
        }
        if (useSsl) {
            connStr.append(connStr.toString().contains("?") ? "&" : "?");
            connStr.append("tls=true");
        }

        MongoExplorer explorer = new MongoExplorer();
        try {
            explorer.connect(new MongoExplorer.MongoConfig(connStr.toString()), msg -> {
            });
            Map<String, String> info = explorer.getServerInfo(msg -> {
            });
            String buildJson = info.getOrDefault("buildInfo", "");
            String version = extractJsonField(buildJson, "version");
            if (version != null && !version.isEmpty()) {
                return "Server: MongoDB\nVersion: " + version;
            }
            return "Server: MongoDB\nVersion: (unknown)";
        } finally {
            explorer.disconnect();
        }
    }

    /**
     * Tests a Redis connection and returns a summary with the server version from
     * INFO.
     */
    private static String testRedisConnection(String host, int port, String database, String username, String password,
            boolean useSsl) {
        int db = 0;
        if (database != null && !database.isBlank()) {
            try {
                db = Integer.parseInt(database);
            } catch (NumberFormatException ignored) {
                // keep default 0
            }
        }

        RedisExplorer explorer = new RedisExplorer();
        try {
            RedisExplorer.RedisConfig config = new RedisExplorer.RedisConfig(host, port,
                    (password != null && !password.isEmpty()) ? password : null,
                    (username != null && !username.isEmpty()) ? username : null, useSsl, 5_000, db);
            explorer.connect(config, msg -> {
            });
            Map<String, String> info = explorer.info(msg -> {
            });
            String version = info.getOrDefault("redis_version", "(unknown)");
            String mode = info.getOrDefault("redis_mode", "");
            String result = "Server: Redis\nVersion: " + version;
            if (!mode.isEmpty()) {
                result += "\nMode: " + mode;
            }
            return result;
        } finally {
            explorer.disconnect();
        }
    }

    /**
     * Extracts a simple string field from a JSON string without a full parser.
     * Looks for "fieldName" : "value" patterns.
     */
    private static String extractJsonField(String json, String fieldName) {
        if (json == null || json.isEmpty()) {
            return null;
        }
        String needle = "\"" + fieldName + "\"";
        int idx = json.indexOf(needle);
        if (idx < 0) {
            return null;
        }
        int colonIdx = json.indexOf(':', idx + needle.length());
        if (colonIdx < 0) {
            return null;
        }
        int quoteStart = json.indexOf('"', colonIdx + 1);
        if (quoteStart < 0) {
            return null;
        }
        int quoteEnd = json.indexOf('"', quoteStart + 1);
        if (quoteEnd < 0) {
            return null;
        }
        return json.substring(quoteStart + 1, quoteEnd);
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private void logMessage(String msg) {
        SwingUtilities.invokeLater(() -> {
            messagesArea.append(msg + "\n");
            messagesArea.setCaretPosition(messagesArea.getDocument().getLength());
        });
    }

    private Consumer<String> log() {
        return this::logMessage;
    }

    private void recordHistory(String sql, long durationMs, int rowCount, String error) {
        QueryHistoryEntry entry = new QueryHistoryEntry(sql, System.currentTimeMillis(), durationMs, rowCount, error);
        SwingUtilities.invokeLater(() -> {
            queryHistory.addFirst(entry);
            while (queryHistory.size() > MAX_HISTORY_ENTRIES) {
                queryHistory.removeLast();
            }
            refreshHistoryTable();
        });
    }

    private void refreshHistoryTable() {
        historyTableModel.setRowCount(0);
        for (QueryHistoryEntry entry : queryHistory) {
            String time = HISTORY_TIME_FMT.format(java.time.Instant.ofEpochMilli(entry.timestamp()));
            String duration = formatDuration(entry.durationMs());
            String rows = entry.error() != null ? "ERR" : String.valueOf(entry.rowCount());
            String sqlPreview = truncateSql(entry.sql(), 120);
            historyTableModel.addRow(new Object[]{time, duration, rows, sqlPreview});
        }
    }

    private static String formatDuration(long ms) {
        if (ms < 1000) {
            return ms + " ms";
        }
        return String.format("%.1f s", ms / 1000.0);
    }

    private static String truncateSql(String sql, int maxLen) {
        String oneLine = sql.replace('\n', ' ').replace('\r', ' ');
        if (oneLine.length() <= maxLen) {
            return oneLine;
        }
        return oneLine.substring(0, maxLen) + "...";
    }

    private void onHistoryDoubleClick() {
        int viewRow = historyTable.getSelectedRow();
        if (viewRow < 0 || viewRow >= queryHistory.size()) {
            return;
        }
        int modelRow = historyTable.convertRowIndexToModel(viewRow);
        if (modelRow >= 0 && modelRow < queryHistory.size()) {
            sqlEditor.setText(queryHistory.get(modelRow).sql());
        }
    }

    private void showHistoryContextMenu(java.awt.event.MouseEvent e) {
        int rowAtPoint = historyTable.rowAtPoint(e.getPoint());
        if (rowAtPoint < 0) {
            return;
        }
        historyTable.setRowSelectionInterval(rowAtPoint, rowAtPoint);
        int modelRow = historyTable.convertRowIndexToModel(rowAtPoint);
        if (modelRow < 0 || modelRow >= queryHistory.size()) {
            return;
        }
        QueryHistoryEntry entry = queryHistory.get(modelRow);
        JPopupMenu menu = new JPopupMenu();
        JMenuItem copyItem = new JMenuItem("Copy SQL");
        copyItem.addActionListener(a -> {
            var sel = new java.awt.datatransfer.StringSelection(entry.sql());
            java.awt.Toolkit.getDefaultToolkit().getSystemClipboard().setContents(sel, null);
        });
        menu.add(copyItem);
        JMenuItem reExecItem = new JMenuItem("Re-execute");
        reExecItem.addActionListener(a -> {
            sqlEditor.setText(entry.sql());
            onExecute();
        });
        menu.add(reExecItem);
        menu.show(historyTable, e.getX(), e.getY());
    }

    /**
     * Resolves the DbSession that owns a given tree path, walking up to the session
     * node.
     */
    private DbSession resolveSessionFromPath(TreePath path) {
        if (path == null) {
            return null;
        }
        Object[] nodes = path.getPath();
        for (Object obj : nodes) {
            if (obj instanceof DefaultMutableTreeNode dmtn) {
                Object data = dmtn.getUserObject();
                if (data instanceof SessionNodeData snd) {
                    return snd.session();
                }
            }
        }
        return null;
    }

    /**
     * Gets the session selected in the connection tree (from the top-level session
     * node).
     */
    private DbSession getSelectedSession() {
        TreePath path = connectionTree.getSelectionPath();
        return resolveSessionFromPath(path);
    }

    private void updateToolbarState() {
        DbSession sel = getSelectedSession();
        removeButton.setEnabled(sel != null);
        editButton.setEnabled(sel != null && !sel.connected);
        connectToggleButton.setEnabled(sel != null);
        connectToggleButton.setText(sel != null && sel.connected ? "Disconnect" : "Connect");
    }

    private void updateStatusBar() {
        if (activeSession == null) {
            setStatus("No active session", AnarCryLaf.fg());
        } else if (activeSession.connected) {
            setStatus("Active: " + activeSession.displayName() + " -- Connected", CONNECTED_COLOR);
        } else {
            setStatus("Active: " + activeSession.displayName() + " -- Disconnected", AnarCryLaf.fg());
        }
    }

    private void setStatus(String text, Color color) {
        String display = text;
        if (display.length() > 120) {
            display = display.substring(0, 117) + "...";
        }
        statusLabel.setText(display);
        statusLabel.setToolTipText(
                text.length() > 120 ? "<html><body style='width:400px'>" + text + "</body></html>" : null);
        statusLabel.setForeground(color);
    }

    private void clearSessionTreeChildren(DbSession session) {
        if (session.treeNode != null) {
            session.treeNode.removeAllChildren();
            connectionTreeModel.reload(session.treeNode);
        }
    }

    private void clearResults() {
        // Remove dynamic result tabs (everything before the fixed tabs)
        while (resultsTabs.getTabCount() > FIXED_TAB_COUNT) {
            resultsTabs.removeTabAt(0);
        }
        resultsTableModel = new DefaultTableModel();
        resultsTable = createResultTable();
        messagesArea.setText("");
        infoArea.setText("");
        exportResultsButton.setEnabled(false);
        rowCountLabel.setText("");
        execTimeLabel.setText("");
    }

    private void clearEditorAndResults() {
        sqlEditor.setText("");
        clearResults();
    }

    private void closeTunnel(DbSession session) {
        if (session.activeTunnel != null) {
            session.activeTunnel.close();
            session.activeTunnel = null;
        }
    }

    private static int parsePort(String text, int defaultPort) {
        if (text == null || text.isBlank()) {
            return defaultPort;
        }
        try {
            return Integer.parseInt(text);
        } catch (NumberFormatException e) {
            return defaultPort;
        }
    }

    private static void addDialogField(JPanel panel, GridBagConstraints gbc, String label, JComponent field, int row) {
        gbc.gridy = row;
        gbc.gridx = 0;
        gbc.weightx = 0;
        panel.add(new JLabel(label), gbc);
        gbc.gridx = 1;
        gbc.weightx = 1.0;
        panel.add(field, gbc);
    }

    private static Font monoFont() {
        return new Font(Font.MONOSPACED, Font.PLAIN, 12);
    }

    private static String extractMongoCollection(String query, String method) {
        int dotIdx = query.indexOf(".");
        if (dotIdx < 0) {
            return "";
        }
        int methodIdx = query.indexOf(method, dotIdx);
        if (methodIdx < 0) {
            return "";
        }
        return query.substring(dotIdx + 1, methodIdx);
    }

    private static String extractMongoArg(String query, String method) {
        int start = query.indexOf(method);
        if (start < 0) {
            return "";
        }
        start += method.length();
        int end = query.lastIndexOf(')');
        if (end <= start) {
            return "";
        }
        return query.substring(start, end).trim();
    }

    // -------------------------------------------------------------------------
    // Custom tree cell renderer for connection/disconnection icons
    // -------------------------------------------------------------------------

    private static class ConnectionTreeCellRenderer extends DefaultTreeCellRenderer {

        private static final Color BLUE = new Color(0x33, 0x87, 0xC5);
        private static final Color GREEN = new Color(0x4D, 0xA5, 0x3C);
        private static final Color RED = new Color(0xDC, 0x38, 0x2D);
        private static final Color ORANGE = new Color(0xED, 0x80, 0x00);
        private static final Color MUTED = new Color(0x88, 0x88, 0x88);

        private static final javax.swing.Icon ICON_DB_ON = cylinderIcon(GREEN);
        private static final javax.swing.Icon ICON_DB_OFF = cylinderIcon(Color.GRAY);
        private static final javax.swing.Icon ICON_MONGO = cylinderIcon(GREEN);
        private static final javax.swing.Icon ICON_REDIS = cylinderIcon(RED);
        private static final javax.swing.Icon ICON_SCHEMA = schemaIcon(BLUE);
        private static final javax.swing.Icon ICON_TABLE = tableIcon(BLUE);
        private static final javax.swing.Icon ICON_COLUMN = columnIcon(BLUE);
        private static final javax.swing.Icon ICON_KEY = keyIcon(BLUE);
        private static final javax.swing.Icon ICON_FOLDER = folderIcon(ORANGE);

        @Override
        public Component getTreeCellRendererComponent(JTree tree, Object value, boolean sel, boolean expanded,
                boolean leaf, int row, boolean hasFocus) {
            Component c = super.getTreeCellRendererComponent(tree, value, sel, expanded, leaf, row, hasFocus);
            if (value instanceof DefaultMutableTreeNode dmtn) {
                Object data = dmtn.getUserObject();
                if (data instanceof SessionNodeData snd) {
                    if (snd.session().connected) {
                        setForeground(new Color(0x00, 0x99, 0x00));
                        if (snd.session().dbType == DbTypeSelection.MONGODB) {
                            setIcon(ICON_MONGO);
                        } else if (snd.session().dbType == DbTypeSelection.REDIS) {
                            setIcon(ICON_REDIS);
                        } else {
                            setIcon(ICON_DB_ON);
                        }
                    } else {
                        setForeground(AnarCryLaf.fg());
                        setIcon(ICON_DB_OFF);
                    }
                } else if (data instanceof SchemaNodeData) {
                    setIcon(ICON_SCHEMA);
                } else if (data instanceof TableNodeData tnd) {
                    setIcon(ICON_TABLE);
                    long cnt = tnd.info().approxRowCount();
                    if (cnt > 0) {
                        String name = escapeHtml(tnd.info().name());
                        String count = String.format("%,d", cnt);
                        setText("<html>" + name + " <font color='#888888'>(" + count + ")</font></html>");
                    }
                } else if (data instanceof MongoCollNodeData mnd) {
                    setIcon(ICON_TABLE);
                    String name = escapeHtml(mnd.collName());
                    long cnt = mnd.info().documentCount();
                    setText("<html>" + name + " <font color='#888888'>(" + cnt + " docs)</font></html>");
                } else if (data instanceof RedisKeyNodeData) {
                    setIcon(ICON_KEY);
                } else if (data instanceof String s && s.contains("PK")) {
                    setIcon(ICON_KEY);
                } else if (data instanceof String s && !s.equals("Loading...") && dmtn.getParent() != null
                        && dmtn.getParent().getParent() == null) {
                    setIcon(ICON_FOLDER);
                    setFont(getFont().deriveFont(Font.BOLD));
                } else if (leaf && !(data instanceof String && "Loading...".equals(data))) {
                    setIcon(ICON_COLUMN);
                }
                setToolTipText(dmtn.getUserObject() != null ? dmtn.getUserObject().toString() : null);
            }
            return c;
        }

        private static String escapeHtml(String s) {
            return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;");
        }

        private static javax.swing.Icon icon16(java.util.function.Consumer<java.awt.Graphics2D> painter) {
            return new javax.swing.Icon() {
                @Override
                public void paintIcon(Component c, java.awt.Graphics g, int x, int y) {
                    java.awt.Graphics2D g2 = (java.awt.Graphics2D) g.create();
                    g2.setRenderingHint(java.awt.RenderingHints.KEY_ANTIALIASING,
                            java.awt.RenderingHints.VALUE_ANTIALIAS_ON);
                    g2.translate(x, y);
                    painter.accept(g2);
                    g2.dispose();
                }

                @Override
                public int getIconWidth() {
                    return 16;
                }

                @Override
                public int getIconHeight() {
                    return 16;
                }
            };
        }

        private static javax.swing.Icon cylinderIcon(Color color) {
            return icon16(g2 -> {
                g2.setColor(color);
                g2.fillRect(3, 4, 10, 7);
                g2.fillOval(3, 2, 10, 4);
                g2.fillArc(3, 9, 10, 4, 180, 180);
                g2.setColor(new Color(0, 0, 0, 50));
                g2.drawArc(3, 5, 10, 3, 180, 180);
                g2.drawArc(3, 7, 10, 3, 180, 180);
            });
        }

        private static javax.swing.Icon schemaIcon(Color color) {
            return icon16(g2 -> {
                g2.setColor(color);
                int[] xp = {2, 10, 14, 14, 2};
                int[] yp = {1, 1, 5, 15, 15};
                g2.fillPolygon(xp, yp, 5);
                g2.setColor(new Color(255, 255, 255, 180));
                g2.fillRect(4, 5, 3, 1);
                g2.fillRect(4, 8, 3, 1);
                g2.fillRect(4, 11, 3, 1);
                g2.fillRect(8, 5, 3, 2);
                g2.fillRect(8, 8, 3, 2);
                g2.fillRect(8, 11, 3, 2);
            });
        }

        private static javax.swing.Icon tableIcon(Color color) {
            return icon16(g2 -> {
                g2.setColor(color);
                g2.drawRect(1, 3, 13, 10);
                g2.fillRect(1, 3, 14, 3);
                g2.drawLine(7, 6, 7, 13);
                g2.drawLine(1, 9, 14, 9);
            });
        }

        private static javax.swing.Icon columnIcon(Color color) {
            return icon16(g2 -> {
                g2.setColor(color);
                g2.drawRect(4, 1, 7, 13);
                g2.drawLine(4, 6, 11, 6);
                g2.drawLine(4, 10, 11, 10);
            });
        }

        private static javax.swing.Icon keyIcon(Color color) {
            return icon16(g2 -> {
                g2.setColor(color);
                g2.setStroke(new java.awt.BasicStroke(1.5f));
                g2.drawOval(1, 5, 6, 6);
                g2.fillRect(7, 7, 8, 2);
                g2.fillRect(12, 9, 1, 2);
                g2.fillRect(10, 9, 1, 2);
            });
        }

        private static javax.swing.Icon folderIcon(Color color) {
            return icon16(g2 -> {
                g2.setColor(color);
                int[] xp = {1, 7, 9, 15, 15, 1};
                int[] yp = {4, 4, 2, 2, 14, 14};
                g2.fillPolygon(xp, yp, 6);
            });
        }
    }

    // -------------------------------------------------------------------------
    // Connection persistence
    // -------------------------------------------------------------------------

    private void loadSavedConnections() {
        List<ConnectionStore.DbConnectionEntry> entries = ConnectionStore.loadDbConnections();
        for (ConnectionStore.DbConnectionEntry e : entries) {
            DbSession session = new DbSession();
            session.name = e.name();
            session.dbType = DbTypeSelection.fromServiceType(e.dbType());
            session.host = e.host();
            session.port = e.port();
            session.database = e.database();
            session.username = e.username();
            session.useSsl = e.useSsl();
            session.discovered = false;
            session.sshEnabled = e.sshEnabled();
            session.sshHost = e.sshHost();
            session.sshPort = e.sshPort();
            session.sshUsername = e.sshUsername();
            session.sshKeyPath = e.sshKeyPath();
            session.group = e.group();
            addSessionToTree(session);
        }
    }

    private void persistConnections() {
        Thread.ofVirtual().name("db-persist").start(() -> {
            List<ConnectionStore.DbConnectionEntry> entries = new ArrayList<>();
            for (DbSession s : sessions) {
                if (s.discovered) {
                    continue;
                }
                entries.add(new ConnectionStore.DbConnectionEntry(s.name, s.dbType != null ? s.dbType.name() : "MYSQL",
                        s.host, s.port, s.database, s.username, s.useSsl, s.sshEnabled, s.sshHost, s.sshPort,
                        s.sshUsername, s.sshKeyPath, s.group));
            }
            ConnectionStore.saveDbConnections(entries);
        });
    }

    // -------------------------------------------------------------------------
    // Read-only accessors for the session list (testing / external use)
    // -------------------------------------------------------------------------

    /** Returns an unmodifiable view of the current sessions. */
    public List<DbSession> getSessions() {
        return Collections.unmodifiableList(new ArrayList<>(sessions));
    }

    // -------------------------------------------------------------------------
    // Grid utilities (auto-resize, NULL renderer, context menu, value viewer)
    // -------------------------------------------------------------------------

    private JTable createResultTable() {
        DefaultTableModel model = new DefaultTableModel();
        JTable table = new JTable(model) {
            @Override
            public Component prepareRenderer(javax.swing.table.TableCellRenderer renderer, int row, int column) {
                Component c = super.prepareRenderer(renderer, row, column);
                if (!isRowSelected(row)) {
                    c.setBackground(row % 2 == 0 ? getBackground() : stripeColor());
                }
                return c;
            }
        };
        table.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);
        table.setAutoCreateRowSorter(true);
        table.setFont(monoFont());
        table.setDefaultRenderer(Object.class, new NullAwareRenderer());
        table.addMouseListener(new MouseAdapter() {
            @Override
            public void mousePressed(MouseEvent e) {
                resultsTable = table;
                resultsTableModel = model;
                showResultsPopup(e);
            }

            @Override
            public void mouseReleased(MouseEvent e) {
                resultsTable = table;
                resultsTableModel = model;
                showResultsPopup(e);
            }
        });
        table.getTableHeader().addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                if (e.getClickCount() == 2) {
                    int col = table.getTableHeader().columnAtPoint(e.getPoint());
                    if (col >= 0) {
                        autoResizeSingleColumn(table, col, 600);
                    }
                }
            }
        });
        table.getSelectionModel().addListSelectionListener(e -> {
            resultsTable = table;
            resultsTableModel = model;
            onResultCellSelected();
        });
        table.getColumnModel().getSelectionModel().addListSelectionListener(e -> {
            resultsTable = table;
            resultsTableModel = model;
            onResultCellSelected();
        });
        table.getInputMap(JComponent.WHEN_FOCUSED).put(KeyStroke.getKeyStroke(KeyEvent.VK_C, InputEvent.CTRL_DOWN_MASK),
                "copy-cell");
        table.getActionMap().put("copy-cell", new javax.swing.AbstractAction() {
            @Override
            public void actionPerformed(java.awt.event.ActionEvent e) {
                copyCellToClipboard(false);
            }
        });
        table.getInputMap(JComponent.WHEN_FOCUSED).put(
                KeyStroke.getKeyStroke(KeyEvent.VK_C, InputEvent.CTRL_DOWN_MASK | InputEvent.SHIFT_DOWN_MASK),
                "copy-with-headers");
        table.getActionMap().put("copy-with-headers", new javax.swing.AbstractAction() {
            @Override
            public void actionPerformed(java.awt.event.ActionEvent e) {
                copyCellToClipboard(true);
            }
        });
        return table;
    }

    private void addResultTab(String title, JTable table) {
        int resultTabCount = resultsTabs.getTabCount() - FIXED_TAB_COUNT;
        while (resultTabCount >= MAX_RESULT_TABS) {
            resultsTabs.removeTabAt(0);
            resultTabCount--;
        }
        int insertIdx = resultsTabs.getTabCount() - FIXED_TAB_COUNT;
        resultsTabs.insertTab(title, null, new JScrollPane(table), null, insertIdx);

        JPanel tabLabel = new JPanel(new FlowLayout(FlowLayout.LEFT, 0, 0));
        tabLabel.setOpaque(false);
        JLabel titleLabel = new JLabel(title.length() > 30 ? title.substring(0, 30) + "..." : title);
        titleLabel.setFont(titleLabel.getFont().deriveFont(11f));
        tabLabel.add(titleLabel);
        JButton closeBtn = new JButton("x");
        closeBtn.setFont(closeBtn.getFont().deriveFont(10f));
        closeBtn.setBorder(BorderFactory.createEmptyBorder(0, 4, 0, 0));
        closeBtn.setContentAreaFilled(false);
        closeBtn.setFocusPainted(false);
        int tabIdx = insertIdx;
        closeBtn.addActionListener(a -> {
            int idx = resultsTabs.indexOfComponent(
                    ((JScrollPane) resultsTabs.getComponentAt(Math.min(tabIdx, resultsTabs.getTabCount() - 1)))
                            .getParent());
            for (int i = 0; i < resultsTabs.getTabCount(); i++) {
                if (resultsTabs.getComponentAt(i) instanceof JScrollPane sp && sp.getViewport().getView() == table) {
                    resultsTabs.removeTabAt(i);
                    break;
                }
            }
        });
        tabLabel.add(closeBtn);
        resultsTabs.setTabComponentAt(insertIdx, tabLabel);
        resultsTabs.setSelectedIndex(insertIdx);
    }

    private static void autoResizeColumns(JTable table, int maxWidth) {
        for (int col = 0; col < table.getColumnCount(); col++) {
            autoResizeSingleColumn(table, col, maxWidth);
        }
    }

    private static void autoResizeSingleColumn(JTable table, int col, int maxWidth) {
        javax.swing.table.TableColumn tc = table.getColumnModel().getColumn(col);
        int width = table.getTableHeader().getDefaultRenderer()
                .getTableCellRendererComponent(table, tc.getHeaderValue(), false, false, -1, col)
                .getPreferredSize().width + 12;
        int sampleRows = Math.min(table.getRowCount(), 100);
        for (int row = 0; row < sampleRows; row++) {
            Component c = table.prepareRenderer(table.getCellRenderer(row, col), row, col);
            width = Math.max(width, c.getPreferredSize().width + 12);
        }
        tc.setPreferredWidth(Math.min(width, maxWidth));
    }

    private static Color stripeColor() {
        Color bg = javax.swing.UIManager.getColor("Table.background");
        if (bg == null) {
            bg = Color.WHITE;
        }
        int r = bg.getRed(), g = bg.getGreen(), b = bg.getBlue();
        boolean dark = (r + g + b) / 3 < 128;
        if (dark) {
            return new Color(Math.min(r + 12, 255), Math.min(g + 12, 255), Math.min(b + 12, 255));
        } else {
            return new Color(Math.max(r - 10, 0), Math.max(g - 10, 0), Math.max(b - 10, 0));
        }
    }

    private static class NullAwareRenderer extends DefaultTableCellRenderer {
        @Override
        public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus,
                int row, int column) {
            super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
            if (value == null) {
                setText("[NULL]");
                setFont(getFont().deriveFont(Font.ITALIC));
                if (!isSelected) {
                    setForeground(Color.GRAY);
                }
            } else {
                setFont(getFont().deriveFont(Font.PLAIN));
                if (!isSelected) {
                    setForeground(table.getForeground());
                }
            }
            return this;
        }
    }

    private void showResultsPopup(MouseEvent e) {
        if (!e.isPopupTrigger()) {
            return;
        }
        int row = resultsTable.rowAtPoint(e.getPoint());
        int col = resultsTable.columnAtPoint(e.getPoint());
        if (row >= 0) {
            resultsTable.setRowSelectionInterval(row, row);
        }
        if (col >= 0) {
            resultsTable.setColumnSelectionInterval(col, col);
        }

        JPopupMenu menu = new JPopupMenu();

        JMenuItem copyCell = new JMenuItem("Copy Cell");
        copyCell.setAccelerator(KeyStroke.getKeyStroke(KeyEvent.VK_C, InputEvent.CTRL_DOWN_MASK));
        copyCell.addActionListener(a -> copyCellToClipboard(false));
        menu.add(copyCell);

        JMenuItem copyWithHeaders = new JMenuItem("Copy with Headers");
        copyWithHeaders.setAccelerator(
                KeyStroke.getKeyStroke(KeyEvent.VK_C, InputEvent.CTRL_DOWN_MASK | InputEvent.SHIFT_DOWN_MASK));
        copyWithHeaders.addActionListener(a -> copyCellToClipboard(true));
        menu.add(copyWithHeaders);

        JMenuItem copyRow = new JMenuItem("Copy Row");
        copyRow.addActionListener(a -> copyRowToClipboard());
        menu.add(copyRow);

        JMenuItem copyColName = new JMenuItem("Copy Column Name");
        copyColName.addActionListener(a -> {
            if (col >= 0) {
                copyToClipboard(resultsTable.getColumnName(col));
            }
        });
        menu.add(copyColName);

        menu.addSeparator();

        JMenuItem copyAsInsert = new JMenuItem("Copy as INSERT");
        copyAsInsert.addActionListener(a -> copyRowAsInsert(row));
        menu.add(copyAsInsert);

        menu.addSeparator();

        JMenuItem sortAsc = new JMenuItem("Sort ASC");
        sortAsc.addActionListener(a -> {
            if (col >= 0 && resultsTable.getRowSorter() != null) {
                resultsTable.getRowSorter()
                        .setSortKeys(List.of(new javax.swing.RowSorter.SortKey(col, javax.swing.SortOrder.ASCENDING)));
            }
        });
        menu.add(sortAsc);

        JMenuItem sortDesc = new JMenuItem("Sort DESC");
        sortDesc.addActionListener(a -> {
            if (col >= 0 && resultsTable.getRowSorter() != null) {
                resultsTable.getRowSorter()
                        .setSortKeys(List.of(new javax.swing.RowSorter.SortKey(col, javax.swing.SortOrder.DESCENDING)));
            }
        });
        menu.add(sortDesc);

        menu.show(resultsTable, e.getX(), e.getY());
    }

    private void copyCellToClipboard(boolean withHeaders) {
        int row = resultsTable.getSelectedRow();
        int col = resultsTable.getSelectedColumn();
        if (row < 0 || col < 0) {
            return;
        }
        Object val = resultsTable.getValueAt(row, col);
        String text = val != null ? val.toString() : "";
        if (withHeaders) {
            text = resultsTable.getColumnName(col) + "\n" + text;
        }
        copyToClipboard(text);
    }

    private void copyRowToClipboard() {
        int row = resultsTable.getSelectedRow();
        if (row < 0) {
            return;
        }
        StringBuilder sb = new StringBuilder();
        for (int c = 0; c < resultsTable.getColumnCount(); c++) {
            if (c > 0) {
                sb.append('\t');
            }
            Object val = resultsTable.getValueAt(row, c);
            sb.append(val != null ? val.toString() : "");
        }
        copyToClipboard(sb.toString());
    }

    private void copyRowAsInsert(int row) {
        if (row < 0) {
            return;
        }
        StringBuilder cols = new StringBuilder("INSERT INTO table_name (");
        StringBuilder vals = new StringBuilder("VALUES (");
        for (int c = 0; c < resultsTable.getColumnCount(); c++) {
            if (c > 0) {
                cols.append(", ");
                vals.append(", ");
            }
            cols.append(resultsTable.getColumnName(c));
            Object val = resultsTable.getValueAt(row, c);
            if (val == null) {
                vals.append("NULL");
            } else {
                String s = val.toString();
                if (s.matches("-?\\d+(\\.\\d+)?")) {
                    vals.append(s);
                } else {
                    vals.append("'").append(s.replace("'", "''")).append("'");
                }
            }
        }
        cols.append(") ");
        vals.append(");");
        copyToClipboard(cols.toString() + vals.toString());
    }

    private static void copyToClipboard(String text) {
        java.awt.Toolkit.getDefaultToolkit().getSystemClipboard()
                .setContents(new java.awt.datatransfer.StringSelection(text), null);
    }

    private void toggleValueViewer() {
        valueViewerVisible = !valueViewerVisible;
        resultsSplit.getBottomComponent().setVisible(valueViewerVisible);
        if (valueViewerVisible) {
            resultsSplit.setDividerLocation(0.7);
            onResultCellSelected();
        }
        resultsSplit.revalidate();
    }

    private void onResultCellSelected() {
        if (!valueViewerVisible) {
            return;
        }
        int row = resultsTable.getSelectedRow();
        int col = resultsTable.getSelectedColumn();
        if (row < 0 || col < 0) {
            return;
        }
        Object val = resultsTable.getValueAt(row, col);
        if (val == null) {
            valueViewer.setSyntaxEditingStyle(SyntaxConstants.SYNTAX_STYLE_NONE);
            valueViewer.setText("[NULL]");
        } else {
            String text = val.toString();
            String trimmed = text.trim();
            if (trimmed.startsWith("{") || trimmed.startsWith("[")) {
                valueViewer.setSyntaxEditingStyle(SyntaxConstants.SYNTAX_STYLE_JSON);
            } else if (trimmed.startsWith("<")) {
                valueViewer.setSyntaxEditingStyle(SyntaxConstants.SYNTAX_STYLE_XML);
            } else {
                valueViewer.setSyntaxEditingStyle(SyntaxConstants.SYNTAX_STYLE_NONE);
            }
            valueViewer.setText(text);
            valueViewer.setCaretPosition(0);
        }
    }

    private void selectInfoTab() {
        int idx = resultsTabs.indexOfComponent(infoScroll);
        if (idx >= 0) {
            resultsTabs.setSelectedIndex(idx);
        }
    }

    private void selectHistoryTab() {
        int idx = resultsTabs.indexOfComponent(historyScroll);
        if (idx >= 0) {
            resultsTabs.setSelectedIndex(idx);
        }
    }

    private void updateResultStatus(int rowCount, long execTimeMs, int affectedRows) {
        if (rowCount >= 0) {
            rowCountLabel.setText(rowCount + " row" + (rowCount != 1 ? "s" : ""));
        } else if (affectedRows >= 0) {
            rowCountLabel.setText(affectedRows + " affected");
        } else {
            rowCountLabel.setText("");
        }
        execTimeLabel.setText(execTimeMs >= 0 ? execTimeMs + "ms" : "");
    }

    // -------------------------------------------------------------------------
    // SQL auto-completion (DBX-011)
    // -------------------------------------------------------------------------

    private static final String[] SQL_KEYWORDS = {"SELECT", "FROM", "WHERE", "INSERT", "INTO", "VALUES", "UPDATE",
            "SET", "DELETE", "DROP", "CREATE", "ALTER", "TABLE", "INDEX", "JOIN", "LEFT", "RIGHT", "INNER", "OUTER",
            "CROSS", "ON", "AND", "OR", "NOT", "IN", "LIKE", "BETWEEN", "IS", "NULL", "AS", "ORDER", "BY", "ASC",
            "DESC", "GROUP", "HAVING", "LIMIT", "OFFSET", "UNION", "ALL", "DISTINCT", "EXISTS", "CASE", "WHEN", "THEN",
            "ELSE", "END", "COUNT", "SUM", "AVG", "MIN", "MAX", "COALESCE", "CAST", "CONCAT", "SUBSTRING", "TRIM",
            "UPPER", "LOWER", "EXPLAIN", "ANALYZE", "WITH", "RECURSIVE", "FETCH", "FIRST", "NEXT", "ROWS", "ONLY",
            "RETURNING", "TRUNCATE"};

    private static void addSqlKeywordCompletions(DefaultCompletionProvider provider) {
        for (String kw : SQL_KEYWORDS) {
            provider.addCompletion(new BasicCompletion(provider, kw, "SQL keyword"));
            provider.addCompletion(new BasicCompletion(provider, kw.toLowerCase(), "SQL keyword"));
        }
    }

    private void refreshCompletions(DbSession session) {
        completionProvider.clear();
        addSqlKeywordCompletions(completionProvider);

        if (session.schemaBrowser != null) {
            Thread.ofVirtual().name("autocomplete-refresh").start(() -> {
                Consumer<String> log = msg -> {
                };
                try {
                    List<String> schemas = session.schemaBrowser.listSchemas(log);
                    for (String schema : schemas) {
                        completionProvider.addCompletion(new BasicCompletion(completionProvider, schema, "schema"));
                        List<TableInfo> tables = session.schemaBrowser.listTables(schema, log);
                        for (TableInfo t : tables) {
                            completionProvider
                                    .addCompletion(new BasicCompletion(completionProvider, t.name(), "table"));
                            List<ColumnInfo> cols = session.schemaBrowser.listColumns(schema, t.name(), log);
                            for (ColumnInfo col : cols) {
                                completionProvider.addCompletion(new BasicCompletion(completionProvider, col.name(),
                                        "column (" + t.name() + "." + col.name() + " " + col.typeName() + ")"));
                                completionProvider.addCompletion(new ShorthandCompletion(completionProvider,
                                        t.name() + "." + col.name(), col.name(), "column (" + col.typeName() + ")"));
                            }
                        }
                    }
                } catch (Exception ignored) {
                    // best-effort
                }
            });
        }
    }

    // -------------------------------------------------------------------------
    // EXPLAIN viewer (DBX-015)
    // -------------------------------------------------------------------------

    private void onExplain() {
        if (activeSession == null || !activeSession.connected) {
            return;
        }
        String query = sqlEditor.getSelectedText();
        if (query == null || query.isBlank()) {
            query = sqlEditor.getText();
        }
        if (query == null || query.isBlank()) {
            return;
        }

        String explainQuery = buildExplainQuery(activeSession, query.trim());
        if (explainQuery == null) {
            logMessage("[!] EXPLAIN not supported for this database type");
            return;
        }

        DbSession session = activeSession;
        String finalQuery = explainQuery;
        Thread.ofVirtual().name("explain-exec").start(() -> {
            if (session.sqlExecutor != null) {
                QueryResult result = session.sqlExecutor.execute(finalQuery, log());
                SwingUtilities.invokeLater(() -> displayExplainResult(result));
            }
        });
    }

    private static String buildExplainQuery(DbSession session, String query) {
        if (session.sqlDialect == null) {
            return null;
        }
        return switch (session.dbType) {
            case POSTGRESQL -> "EXPLAIN (ANALYZE, COSTS, BUFFERS, FORMAT TEXT) " + query;
            case MYSQL -> "EXPLAIN " + query;
            case MSSQL -> "SET SHOWPLAN_TEXT ON;\n" + query + ";\nSET SHOWPLAN_TEXT OFF";
            case SQLITE -> "EXPLAIN QUERY PLAN " + query;
            case ORACLE -> "EXPLAIN PLAN FOR " + query;
            default -> "EXPLAIN " + query;
        };
    }

    private void displayExplainResult(QueryResult result) {
        if (result == null) {
            return;
        }
        StringBuilder sb = new StringBuilder();
        if (result.hasRows()) {
            for (List<String> row : result.rows()) {
                sb.append(String.join(" | ", row)).append("\n");
            }
        }
        infoArea.setText(sb.toString());
        selectInfoTab();
    }

    // -------------------------------------------------------------------------
    // Saved Queries (DBX-016)
    // -------------------------------------------------------------------------

    private static final int MAX_SAVED_QUERIES = 100;
    private static final Path SAVED_QUERIES_PATH = Path.of(System.getProperty("user.home"), ".anarcry",
            "saved-queries.json");

    private void onSaveQuery() {
        String sql = sqlEditor.getText();
        if (sql == null || sql.isBlank()) {
            return;
        }
        String name = JOptionPane.showInputDialog(this, "Query name:", "Save Query", JOptionPane.PLAIN_MESSAGE);
        if (name == null || name.isBlank()) {
            return;
        }
        Map<String, String> queries = loadSavedQueries();
        if (queries.containsKey(name)) {
            int confirm = JOptionPane.showConfirmDialog(this, "\"" + name + "\" already exists. Overwrite?",
                    "Save Query", JOptionPane.YES_NO_OPTION);
            if (confirm != JOptionPane.YES_OPTION) {
                return;
            }
        }
        if (queries.size() >= MAX_SAVED_QUERIES && !queries.containsKey(name)) {
            logMessage("[!] Maximum saved queries (" + MAX_SAVED_QUERIES + ") reached. Delete some first.");
            return;
        }
        queries.put(name, sql.trim());
        writeSavedQueries(queries);
        logMessage("[+] Query saved: " + name);
    }

    private void showLoadQueryMenu(JButton anchor) {
        Map<String, String> queries = loadSavedQueries();
        if (queries.isEmpty()) {
            logMessage("[*] No saved queries");
            return;
        }
        JPopupMenu menu = new JPopupMenu();
        queries.entrySet().stream().sorted(Map.Entry.comparingByKey()).forEach(entry -> {
            JMenuItem item = new JMenuItem(entry.getKey());
            item.setToolTipText(
                    entry.getValue().length() > 80 ? entry.getValue().substring(0, 80) + "..." : entry.getValue());
            item.addActionListener(a -> sqlEditor.setText(entry.getValue()));

            JPopupMenu sub = new JPopupMenu();
            JMenuItem load = new JMenuItem("Load");
            load.addActionListener(a -> sqlEditor.setText(entry.getValue()));
            sub.add(load);
            JMenuItem del = new JMenuItem("Delete");
            del.addActionListener(a -> {
                queries.remove(entry.getKey());
                writeSavedQueries(queries);
                logMessage("[+] Deleted: " + entry.getKey());
            });
            sub.add(del);

            menu.add(item);
        });
        menu.show(anchor, 0, anchor.getHeight());
    }

    @SuppressWarnings("unchecked")
    private Map<String, String> loadSavedQueries() {
        try {
            if (java.nio.file.Files.exists(SAVED_QUERIES_PATH)) {
                String json = java.nio.file.Files.readString(SAVED_QUERIES_PATH);
                Map<String, String> map = new com.google.gson.Gson().fromJson(json,
                        new com.google.gson.reflect.TypeToken<java.util.LinkedHashMap<String, String>>() {
                        }.getType());
                return map != null ? map : new java.util.LinkedHashMap<>();
            }
        } catch (Exception ignored) {
            // best-effort
        }
        return new java.util.LinkedHashMap<>();
    }

    private void writeSavedQueries(Map<String, String> queries) {
        try {
            java.nio.file.Files.createDirectories(SAVED_QUERIES_PATH.getParent());
            String json = new com.google.gson.GsonBuilder().setPrettyPrinting().create().toJson(queries);
            java.nio.file.Files.writeString(SAVED_QUERIES_PATH, json);
        } catch (Exception ex) {
            logMessage("[!] Failed to save queries: " + ex.getMessage());
        }
    }
}
