package gg.effront.anarcry.gui.views;

import gg.effront.anarcry.apiclient.auth.AuthInjectorRegistry;
import gg.effront.anarcry.apiclient.io.BruImporter;
import gg.effront.anarcry.apiclient.io.CollectionLoader;
import gg.effront.anarcry.apiclient.io.CurlImporter;
import gg.effront.anarcry.apiclient.io.OpenApiImporter;
import gg.effront.anarcry.apiclient.io.PostmanImporter;
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
import gg.effront.anarcry.apiclient.model.RequestItem;
import gg.effront.anarcry.apiclient.model.RequestResult;
import gg.effront.anarcry.apiclient.model.RunResult;
import gg.effront.anarcry.apiclient.runner.AssertionEngine;
import gg.effront.anarcry.apiclient.runner.CollectionRunner;
import gg.effront.anarcry.apiclient.runner.RequestExecutor;
import gg.effront.anarcry.apiclient.vars.Interpolator;
import gg.effront.anarcry.apiclient.vars.VariableStore;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.event.InputEvent;
import java.awt.event.KeyEvent;
import java.net.http.HttpClient;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JComponent;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JMenuItem;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPopupMenu;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTabbedPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.JTree;
import javax.swing.KeyStroke;
import javax.swing.SwingUtilities;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.DefaultTreeCellRenderer;
import javax.swing.tree.DefaultTreeModel;

import org.fife.ui.rsyntaxtextarea.RSyntaxTextArea;
import org.fife.ui.rsyntaxtextarea.SyntaxConstants;
import org.fife.ui.rsyntaxtextarea.Theme;
import org.fife.ui.rtextarea.RTextScrollPane;

public class ApiClientView extends JPanel {

    private static final int SIDEBAR_WIDTH = 250;
    private static final int REQUEST_TIMEOUT_SECONDS = 30;

    private JTree collectionTree;
    private DefaultMutableTreeNode treeRoot;
    private DefaultTreeModel treeModel;
    private JComboBox<String> methodCombo;
    private JTextField urlField;
    private JButton sendButton;
    private JComboBox<String> envCombo;
    private JTextArea headersArea;
    private RSyntaxTextArea bodyArea;
    private JTextArea paramsArea;
    private JComboBox<String> authTypeCombo;
    private JTextArea authFieldsArea;
    private JLabel responseStatus;
    private RSyntaxTextArea responseBody;
    private JTextArea responseHeaders;
    private JTextArea assertionsArea;

    private Collection currentCollection;
    private final HttpClient httpClient;
    private final List<String> runLog = new ArrayList<>();

    public ApiClientView() {
        super(new BorderLayout());
        httpClient = HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NORMAL)
                .connectTimeout(Duration.ofSeconds(REQUEST_TIMEOUT_SECONDS)).build();

        JSplitPane mainSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, buildSidebar(), buildRightPanel());
        mainSplit.setDividerLocation(SIDEBAR_WIDTH);
        add(mainSplit, BorderLayout.CENTER);
    }

    private JPanel buildSidebar() {
        JPanel sidebar = new JPanel(new BorderLayout());
        sidebar.setPreferredSize(new Dimension(SIDEBAR_WIDTH, 0));

        treeRoot = new DefaultMutableTreeNode("No collection loaded");
        treeModel = new DefaultTreeModel(treeRoot);
        collectionTree = new JTree(treeModel);
        collectionTree.setRootVisible(true);
        collectionTree.addTreeSelectionListener(e -> onTreeSelection());

        DefaultTreeCellRenderer renderer = new DefaultTreeCellRenderer();
        renderer.setLeafIcon(null);
        renderer.setOpenIcon(null);
        renderer.setClosedIcon(null);
        collectionTree.setCellRenderer(renderer);

        sidebar.add(new JScrollPane(collectionTree), BorderLayout.CENTER);

        JPanel buttons = new JPanel(new java.awt.GridLayout(3, 1, 2, 2));
        buttons.setBorder(BorderFactory.createEmptyBorder(4, 4, 4, 4));

        JButton loadBtn = new JButton("Load Collection");
        loadBtn.addActionListener(e -> chooseAndLoadCollection());
        buttons.add(loadBtn);

        JButton importBtn = new JButton("Import...");
        importBtn.addActionListener(e -> showImportMenu(importBtn));
        buttons.add(importBtn);

        JButton runBtn = new JButton("Run All");
        runBtn.addActionListener(e -> runCollection());
        buttons.add(runBtn);

        sidebar.add(buttons, BorderLayout.SOUTH);
        return sidebar;
    }

    private JPanel buildRightPanel() {
        JPanel right = new JPanel(new BorderLayout());
        right.add(buildTopBar(), BorderLayout.NORTH);

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

        JPanel left = new JPanel(new BorderLayout(4, 0));
        left.add(methodCombo, BorderLayout.WEST);
        left.add(urlField, BorderLayout.CENTER);

        JPanel rightBar = new JPanel(new BorderLayout(4, 0));
        rightBar.add(envCombo, BorderLayout.WEST);
        rightBar.add(sendButton, BorderLayout.EAST);

        bar.add(left, BorderLayout.CENTER);
        bar.add(rightBar, BorderLayout.EAST);
        return bar;
    }

    private JTabbedPane buildRequestEditor() {
        JTabbedPane tabs = new JTabbedPane();

        headersArea = new JTextArea(8, 40);
        headersArea.setFont(monoFont());
        headersArea.setText("User-Agent: " + gg.effront.anarcry.Version.userAgent() + "\nAccept: */*");
        tabs.addTab("Headers", new JScrollPane(headersArea));

        bodyArea = createSyntaxArea(false);
        bodyArea.setSyntaxEditingStyle(SyntaxConstants.SYNTAX_STYLE_JSON);
        tabs.addTab("Body", new RTextScrollPane(bodyArea));

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

        return tabs;
    }

    private JPanel buildResponseViewer() {
        JPanel panel = new JPanel(new BorderLayout());

        responseStatus = new JLabel("  No response yet");
        panel.add(responseStatus, BorderLayout.NORTH);

        JTabbedPane tabs = new JTabbedPane();

        responseBody = createSyntaxArea(true);
        tabs.addTab("Body", new RTextScrollPane(responseBody));

        responseHeaders = new JTextArea(6, 40);
        responseHeaders.setEditable(false);
        responseHeaders.setFont(monoFont());
        tabs.addTab("Headers", new JScrollPane(responseHeaders));

        assertionsArea = new JTextArea(6, 40);
        assertionsArea.setEditable(false);
        assertionsArea.setFont(monoFont());
        tabs.addTab("Assertions", new JScrollPane(assertionsArea));

        panel.add(tabs, BorderLayout.CENTER);
        return panel;
    }

    private void onTreeSelection() {
        DefaultMutableTreeNode node = (DefaultMutableTreeNode) collectionTree.getLastSelectedPathComponent();
        if (node == null || !(node.getUserObject() instanceof RequestItem item)) {
            return;
        }
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
        populateAuth(req.auth());
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
        assertionsArea.setText("");

        Thread.ofVirtual().name("apiclient-send").start(() -> {
            try {
                RequestItem item = buildCurrentRequestItem();
                Collection coll = currentCollection != null
                        ? currentCollection
                        : new Collection(null, "adhoc", null, null, List.of(item), null, null);
                Environment env = getSelectedEnvironment();

                VariableStore vars = new VariableStore();
                vars.loadCollection(coll.root());
                if (env != null) {
                    vars.loadEnv(env);
                }

                Interpolator interpolator = new Interpolator();
                RequestExecutor executor = new RequestExecutor(httpClient, interpolator, new AuthInjectorRegistry(),
                        new AssertionEngine(interpolator));
                CollectionRunner runner = new CollectionRunner(executor);
                RequestResult result = runner.runSingle(item, coll, env, msg -> {
                });

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

        BodyConfig body = buildBody();
        AuthConfig auth = buildAuth();

        HttpRequestDef req = new HttpRequestDef(method, url, null, headers, auth, body, null);
        return new RequestItem(null, "Manual Request", null, req, null, List.of(), null);
    }

    private BodyConfig buildBody() {
        String text = bodyArea.getText();
        if (text.isBlank()) {
            return new BodyConfig.None();
        }
        return new BodyConfig.Json(text);
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

    private void displayResult(RequestResult result) {
        if (result.response() != null) {
            var resp = result.response();
            responseStatus.setText(String.format("  %d - %dms - %d bytes", resp.status(), resp.responseTimeMs(),
                    resp.body().length()));

            responseBody.setText(resp.body());
            responseBody.setCaretPosition(0);

            String ct = resp.header("content-type");
            responseBody.setSyntaxEditingStyle(detectSyntax(ct != null ? ct : ""));

            StringBuilder hdr = new StringBuilder();
            resp.headers()
                    .forEach((k, values) -> values.forEach(v -> hdr.append(k).append(": ").append(v).append("\n")));
            responseHeaders.setText(hdr.toString());
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
            assertionsArea.setText(sb.toString());
        }
    }

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
            CollectionLoader loader = new CollectionLoader();
            currentCollection = loader.load(dir);
            populateTree();
            populateEnvCombo();
        } catch (Exception ex) {
            JOptionPane.showMessageDialog(this, "Failed to load collection: " + ex.getMessage(), "Error",
                    JOptionPane.ERROR_MESSAGE);
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
                VariableStore vars = new VariableStore();
                vars.loadCollection(currentCollection.root());
                if (env != null) {
                    vars.loadEnv(env);
                }

                Interpolator interpolator = new Interpolator();
                RequestExecutor executor = new RequestExecutor(httpClient, interpolator, new AuthInjectorRegistry(),
                        new AssertionEngine(interpolator));
                CollectionRunner runner = new CollectionRunner(executor);

                runLog.clear();
                RunResult result = runner.run(currentCollection, env, msg -> {
                    runLog.add(msg);
                });

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
