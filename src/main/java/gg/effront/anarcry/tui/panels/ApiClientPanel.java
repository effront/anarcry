package gg.effront.anarcry.tui.panels;

import com.googlecode.lanterna.TerminalSize;
import com.googlecode.lanterna.TextColor;
import com.googlecode.lanterna.gui2.ActionListBox;
import com.googlecode.lanterna.gui2.BorderLayout;
import com.googlecode.lanterna.gui2.Borders;
import com.googlecode.lanterna.gui2.Button;
import com.googlecode.lanterna.gui2.ComboBox;
import com.googlecode.lanterna.gui2.Direction;
import com.googlecode.lanterna.gui2.EmptySpace;
import com.googlecode.lanterna.gui2.Label;
import com.googlecode.lanterna.gui2.LinearLayout;
import com.googlecode.lanterna.gui2.Panel;
import com.googlecode.lanterna.gui2.TextBox;
import gg.effront.anarcry.apiclient.auth.AuthInjectorRegistry;
import gg.effront.anarcry.apiclient.io.CollectionLoader;
import gg.effront.anarcry.apiclient.model.Collection;
import gg.effront.anarcry.apiclient.model.CollectionItem;
import gg.effront.anarcry.apiclient.model.Environment;
import gg.effront.anarcry.apiclient.model.Folder;
import gg.effront.anarcry.apiclient.model.RequestItem;
import gg.effront.anarcry.apiclient.model.RequestResult;
import gg.effront.anarcry.apiclient.model.ResponseData;
import gg.effront.anarcry.apiclient.model.RunResult;
import gg.effront.anarcry.apiclient.runner.AssertionEngine;
import gg.effront.anarcry.apiclient.runner.CollectionRunner;
import gg.effront.anarcry.apiclient.runner.RequestExecutor;
import gg.effront.anarcry.apiclient.vars.Interpolator;
import gg.effront.anarcry.tui.PasteableTextBox;

import java.net.http.HttpClient;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;

public class ApiClientPanel extends Panel {

    private final ActionListBox collectionList;
    private final ComboBox<String> methodCombo;
    private final PasteableTextBox urlBox;
    private final PasteableTextBox headersBox;
    private final PasteableTextBox bodyBox;
    private final TextBox responseBox;
    private final Label statusLabel;
    private final ComboBox<String> envCombo;
    private final Consumer<String> log;

    private Collection collection;
    private final List<RequestItem> flatRequests = new ArrayList<>();
    private RequestItem selectedRequest;
    private final CollectionLoader loader = new CollectionLoader();

    public ApiClientPanel(int height, Consumer<String> log) {
        super(new BorderLayout());
        this.log = log;

        int leftW = 24;
        int listH = Math.max(6, height - 6);

        var leftPanel = new Panel(new LinearLayout(Direction.VERTICAL));
        collectionList = new ActionListBox(new TerminalSize(leftW, listH));
        leftPanel.addComponent(collectionList);

        var leftButtons = new Panel(new LinearLayout(Direction.HORIZONTAL));
        leftButtons.addComponent(new Button("Load", this::promptLoadCollection));
        leftButtons.addComponent(new Button("Run All", this::runCollection));
        leftPanel.addComponent(leftButtons);

        var rightPanel = new Panel(new BorderLayout());

        var requestPanel = new Panel(new LinearLayout(Direction.VERTICAL));

        var urlRow = new Panel(new LinearLayout(Direction.HORIZONTAL));
        methodCombo = new ComboBox<>("GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS");
        urlBox = new PasteableTextBox(new TerminalSize(40, 1));
        urlBox.setText("https://");
        urlRow.addComponent(methodCombo);
        urlRow.addComponent(urlBox);
        requestPanel.addComponent(urlRow);

        var envRow = new Panel(new LinearLayout(Direction.HORIZONTAL));
        Label envLabel = new Label(" Env:");
        envLabel.setForegroundColor(TextColor.ANSI.BLUE);
        envRow.addComponent(envLabel);
        envCombo = new ComboBox<>("(none)");
        envRow.addComponent(envCombo);
        requestPanel.addComponent(envRow);

        requestPanel.addComponent(new EmptySpace(new TerminalSize(1, 1)));
        Label hLabel = new Label(" Headers:");
        hLabel.setForegroundColor(TextColor.ANSI.BLUE);
        requestPanel.addComponent(hLabel);
        headersBox = new PasteableTextBox(new TerminalSize(40, 3));
        headersBox.setText("Accept: */*");
        requestPanel.addComponent(headersBox);

        requestPanel.addComponent(new EmptySpace(new TerminalSize(1, 1)));
        Label bLabel = new Label(" Body:");
        bLabel.setForegroundColor(TextColor.ANSI.BLUE);
        requestPanel.addComponent(bLabel);
        bodyBox = new PasteableTextBox(new TerminalSize(40, 4));
        requestPanel.addComponent(bodyBox);

        requestPanel.addComponent(new EmptySpace(new TerminalSize(1, 1)));
        var sendRow = new Panel(new LinearLayout(Direction.HORIZONTAL));
        sendRow.addComponent(new Button("Send", this::sendSelected));
        requestPanel.addComponent(sendRow);

        var responsePanel = new Panel(new LinearLayout(Direction.VERTICAL));
        statusLabel = new Label(" No response yet");
        statusLabel.setForegroundColor(TextColor.ANSI.WHITE);
        responsePanel.addComponent(statusLabel);
        int respH = Math.max(6, height - 18);
        responseBox = new TextBox(new TerminalSize(40, respH), TextBox.Style.MULTI_LINE);
        responseBox.setReadOnly(true);
        responsePanel.addComponent(responseBox, LinearLayout.createLayoutData(LinearLayout.Alignment.Fill));

        rightPanel.addComponent(requestPanel.withBorder(Borders.singleLine("Request")), BorderLayout.Location.TOP);
        rightPanel.addComponent(responsePanel.withBorder(Borders.singleLine("Response")), BorderLayout.Location.CENTER);

        addComponent(leftPanel.withBorder(Borders.singleLine("Collections")), BorderLayout.Location.LEFT);
        addComponent(rightPanel, BorderLayout.Location.CENTER);
    }

    private void promptLoadCollection() {
        Path collectionsDir = Path.of("collections");
        if (!Files.isDirectory(collectionsDir)) {
            log.accept("[!] No collections/ directory found");
            return;
        }
        try (var dirs = Files.newDirectoryStream(collectionsDir, Files::isDirectory)) {
            List<Path> found = new ArrayList<>();
            for (Path d : dirs) {
                if (Files.exists(d.resolve("collection.json"))) {
                    found.add(d);
                }
            }
            if (found.isEmpty()) {
                log.accept("[!] No collections found in collections/");
                return;
            }
            loadCollection(found.getFirst());
        } catch (Exception e) {
            log.accept("[!] Error scanning collections: " + e.getMessage());
        }
    }

    public void loadCollection(Path dir) {
        try {
            if (Files.exists(dir.resolve("collection.json"))) {
                collection = loader.load(dir);
            } else if (hasBruFiles(dir)) {
                collection = new gg.effront.anarcry.apiclient.io.BruImporter().importDirectory(dir);
            } else {
                log.accept("[!] No collection.json or .bru files in: " + dir);
                return;
            }
            flatRequests.clear();
            flatten(collection.items(), flatRequests);
            refreshCollectionList();
            refreshEnvCombo();
            log.accept("[+] Loaded collection: " + collection.name() + " (" + flatRequests.size() + " requests)");
        } catch (Exception e) {
            log.accept("[!] Failed to load collection: " + e.getMessage());
        }
    }

    private boolean hasBruFiles(Path dir) {
        try (var stream = Files.walk(dir, 3)) {
            return stream.anyMatch(p -> p.toString().endsWith(".bru"));
        } catch (Exception e) {
            return false;
        }
    }

    private void refreshCollectionList() {
        collectionList.clearItems();
        addItems(collection.items(), 0);
    }

    private void addItems(List<CollectionItem> items, int depth) {
        String indent = "  ".repeat(depth);
        for (CollectionItem item : items) {
            switch (item) {
                case Folder folder -> {
                    collectionList.addItem(indent + "> " + folder.name(), () -> {
                    });
                    addItems(folder.items(), depth + 1);
                }
                case RequestItem req -> collectionList.addItem(indent + req.request().method() + " " + req.name(),
                        () -> selectRequest(req));
            }
        }
    }

    private void refreshEnvCombo() {
        envCombo.clearItems();
        envCombo.addItem("(none)");
        if (collection != null) {
            for (Environment env : collection.environments()) {
                envCombo.addItem(env.name());
            }
        }
    }

    private void selectRequest(RequestItem req) {
        this.selectedRequest = req;
        methodCombo.setSelectedItem(req.request().method());
        urlBox.setText(req.request().url());

        StringBuilder headers = new StringBuilder();
        req.request().headers().forEach(h -> headers.append(h.name()).append(": ").append(h.value()).append("\n"));
        if (headers.isEmpty()) {
            headers.append("Accept: */*");
        }
        headersBox.setText(headers.toString().stripTrailing());

        String body = switch (req.request().body()) {
            case gg.effront.anarcry.apiclient.model.BodyConfig.Json j -> j.content();
            case gg.effront.anarcry.apiclient.model.BodyConfig.Text t -> t.content();
            case gg.effront.anarcry.apiclient.model.BodyConfig.Xml x -> x.content();
            default -> "";
        };
        bodyBox.setText(body != null ? body : "");
        statusLabel.setText(" Selected: " + req.name());
    }

    private void sendSelected() {
        if (selectedRequest == null) {
            statusLabel.setText(" No request selected");
            return;
        }

        statusLabel.setText(" Sending...");
        responseBox.setText("");

        try {
            Interpolator interpolator = new Interpolator();
            AuthInjectorRegistry authRegistry = new AuthInjectorRegistry();
            AssertionEngine assertionEngine = new AssertionEngine(interpolator);
            HttpClient httpClient = HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NORMAL)
                    .connectTimeout(Duration.ofSeconds(10)).build();
            RequestExecutor executor = new RequestExecutor(httpClient, interpolator, authRegistry, assertionEngine);
            CollectionRunner runner = new CollectionRunner(executor);

            Environment env = getSelectedEnv();
            RequestResult result = runner.runSingle(selectedRequest, collection, env, log);
            displayResult(result);
        } catch (Exception e) {
            statusLabel.setText(" Error: " + e.getMessage());
            responseBox.setText(e.toString());
        }
    }

    private void runCollection() {
        if (collection == null) {
            statusLabel.setText(" No collection loaded");
            return;
        }

        statusLabel.setText(" Running collection...");
        responseBox.setText("");

        try {
            Interpolator interpolator = new Interpolator();
            AuthInjectorRegistry authRegistry = new AuthInjectorRegistry();
            AssertionEngine assertionEngine = new AssertionEngine(interpolator);
            HttpClient httpClient = HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NORMAL)
                    .connectTimeout(Duration.ofSeconds(10)).build();
            RequestExecutor executor = new RequestExecutor(httpClient, interpolator, authRegistry, assertionEngine);
            CollectionRunner runner = new CollectionRunner(executor);

            Environment env = getSelectedEnv();
            RunResult result = runner.run(collection, env, log);

            StringBuilder sb = new StringBuilder();
            sb.append("Collection: ").append(collection.name()).append("\n");
            sb.append("Total: ").append(result.summary().total());
            sb.append("  Passed: ").append(result.summary().passed());
            sb.append("  Failed: ").append(result.summary().failed()).append("\n");
            sb.append("Duration: ").append(result.durationMs()).append("ms\n\n");

            for (RequestResult rr : result.results()) {
                String mark = rr.passed() ? "PASS" : "FAIL";
                sb.append("[").append(mark).append("] ").append(rr.item().name());
                if (rr.response() != null) {
                    sb.append(" - ").append(rr.response().status());
                }
                sb.append(" (").append(rr.durationMs()).append("ms)\n");
            }

            statusLabel.setText(" Done: " + result.summary().passed() + "/" + result.summary().total() + " passed");
            responseBox.setText(sb.toString());
        } catch (Exception e) {
            statusLabel.setText(" Run error: " + e.getMessage());
            responseBox.setText(e.toString());
        }
    }

    private void displayResult(RequestResult result) {
        ResponseData resp = result.response();
        if (resp == null) {
            statusLabel.setText(" No response");
            return;
        }

        statusLabel.setText(String.format(" %d - %dms - %d bytes", resp.status(), resp.responseTimeMs(), resp.size()));

        StringBuilder sb = new StringBuilder();
        sb.append("HTTP ").append(resp.status()).append(" ").append(resp.statusText()).append("\n");
        resp.headers().forEach((k, vals) -> vals.forEach(v -> sb.append(k).append(": ").append(v).append("\n")));
        sb.append("\n");
        sb.append(resp.body());

        if (!result.assertions().isEmpty()) {
            sb.append("\n\n--- Assertions ---\n");
            for (var a : result.assertions()) {
                String mark = a.passed() ? "PASS" : "FAIL";
                sb.append("[").append(mark).append("] ").append(a.message()).append("\n");
            }
        }
        responseBox.setText(sb.toString());
    }

    private Environment getSelectedEnv() {
        if (collection == null || envCombo.getSelectedIndex() <= 0) {
            return null;
        }
        String envName = envCombo.getSelectedItem();
        return collection.environments().stream().filter(e -> e.name().equals(envName)).findFirst().orElse(null);
    }

    private static void flatten(List<CollectionItem> items, List<RequestItem> out) {
        for (CollectionItem item : items) {
            switch (item) {
                case RequestItem ri -> out.add(ri);
                case Folder folder -> flatten(folder.items(), out);
            }
        }
    }
}
