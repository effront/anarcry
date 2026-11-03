package gg.effront.anarcry.tui;

import gg.effront.anarcry.Version;

import com.googlecode.lanterna.TerminalSize;
import com.googlecode.lanterna.TextColor;
import com.googlecode.lanterna.gui2.BasicWindow;
import com.googlecode.lanterna.gui2.BorderLayout;
import com.googlecode.lanterna.gui2.Borders;
import com.googlecode.lanterna.gui2.Button;
import com.googlecode.lanterna.gui2.Component;
import com.googlecode.lanterna.gui2.DefaultWindowManager;
import com.googlecode.lanterna.gui2.Direction;
import com.googlecode.lanterna.gui2.EmptySpace;
import com.googlecode.lanterna.gui2.Label;
import com.googlecode.lanterna.gui2.LinearLayout;
import com.googlecode.lanterna.gui2.MultiWindowTextGUI;
import com.googlecode.lanterna.gui2.Panel;
import com.googlecode.lanterna.gui2.TextBox;
import com.googlecode.lanterna.gui2.Window;
import com.googlecode.lanterna.gui2.WindowListenerAdapter;
import com.googlecode.lanterna.input.KeyStroke;
import com.googlecode.lanterna.input.KeyType;
import com.googlecode.lanterna.input.MouseAction;
import com.googlecode.lanterna.input.MouseActionType;
import com.googlecode.lanterna.screen.TerminalScreen;
import com.googlecode.lanterna.terminal.DefaultTerminalFactory;
import com.googlecode.lanterna.terminal.MouseCaptureMode;
import gg.effront.anarcry.model.Finding;
import gg.effront.anarcry.model.RequestRecord;
import gg.effront.anarcry.model.Severity;
import gg.effront.anarcry.report.ReportEngine;
import gg.effront.anarcry.scanner.ScanEvent;
import gg.effront.anarcry.scanner.ScanRunner;
import gg.effront.anarcry.tui.chrome.EventLogDrawer;
import gg.effront.anarcry.tui.chrome.ModeBar;
import gg.effront.anarcry.tui.chrome.StatusBar;
import gg.effront.anarcry.tui.modes.Mode;
import gg.effront.anarcry.tui.modes.RepeaterMode;
import gg.effront.anarcry.tui.modes.TargetMode;
import gg.effront.anarcry.tui.panels.AssistantPanel;
import gg.effront.anarcry.tui.panels.FindingsPanel;
import gg.effront.anarcry.tui.panels.LogPanel;
import gg.effront.anarcry.tui.panels.ModulesPanel;
import gg.effront.anarcry.tui.panels.SiteMapPanel;

import gg.effront.anarcry.EnvLoader;
import gg.effront.anarcry.assistant.AiAssistant;
import gg.effront.anarcry.assistant.AssistantConfig;
import gg.effront.anarcry.assistant.ContextBuilder;
import gg.effront.anarcry.assistant.ProviderRegistry;
import gg.effront.anarcry.assistant.tools.ExplainCweTool;
import gg.effront.anarcry.assistant.tools.GetFindingsTool;
import gg.effront.anarcry.assistant.tools.GetScanConfigTool;
import gg.effront.anarcry.assistant.tools.GetSitemapTool;
import gg.effront.anarcry.assistant.tools.QueryKbTool;
import gg.effront.anarcry.model.KnowledgeBase;
import gg.effront.anarcry.scanner.DiscoveredPaths;
import gg.effront.anarcry.scanner.ScanContext;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;

public class AnarCryTui {

    private final List<String> logHistory = Collections.synchronizedList(new ArrayList<>());
    private final List<Finding> findingHistory = Collections.synchronizedList(new ArrayList<>());
    private final List<RequestRecord> requestHistory = Collections.synchronizedList(new ArrayList<>());
    private final AtomicReference<LogPanel> currentLog = new AtomicReference<>();
    private final AtomicReference<FindingsPanel> currentFindings = new AtomicReference<>();
    private final AtomicReference<SiteMapPanel> currentSiteMap = new AtomicReference<>();

    private MultiWindowTextGUI gui;
    private ScanRunner scanRunner;
    private LogPanel logPanel;
    private FindingsPanel findingsPanel;
    private SiteMapPanel siteMapPanel;
    private ModulesPanel modulesPanel;
    private AssistantPanel assistantPanel;
    private Consumer<RequestRecord> requestCb;
    private BasicWindow window;
    private ModeBar modeBar;
    private StatusBar statusBar;
    private volatile Mode currentMode = Mode.SCAN;
    private volatile boolean scanning = false;
    private EnvLoader envPreload = null;
    private AiAssistant aiAssistant;
    private ContextBuilder contextBuilder;
    private List<ProviderRegistry.ProviderInfo> availableProviders = List.of();
    private ProviderRegistry.ProviderInfo currentProvider;
    private String currentModel;
    private int maxTokens = 4096;
    private final DiscoveredPaths discoveredPaths = new DiscoveredPaths();
    private final ExecutorService assistantExecutor = Executors.newSingleThreadExecutor(r -> {
        Thread t = new Thread(r, "assistant-worker");
        t.setDaemon(true);
        return t;
    });

    public void start() throws IOException {
        start(null);
    }

    public void start(EnvLoader env) throws IOException {
        this.envPreload = env;
        var factory = new DefaultTerminalFactory();
        factory.setMouseCaptureMode(MouseCaptureMode.CLICK_RELEASE);
        factory.setPreferTerminalEmulator(false);
        TerminalScreen screen = (TerminalScreen) factory.createScreen();
        screen.startScreen();

        gui = new MultiWindowTextGUI(screen, new DefaultWindowManager(), new EmptySpace(TextColor.ANSI.BLACK));

        modeBar = new ModeBar();
        statusBar = new StatusBar();

        Consumer<String> logCb = msg -> gui.getGUIThread().invokeLater(() -> {
            logHistory.add(msg);
            LogPanel lp = currentLog.get();
            if (lp != null) {
                lp.log(msg);
            }
        });
        Consumer<Finding> findingCb = f -> gui.getGUIThread().invokeLater(() -> {
            findingHistory.add(f);
            FindingsPanel fp = currentFindings.get();
            if (fp != null) {
                fp.addFinding(f);
            }
            modeBar.setFindingsCount(findingHistory.size());
            updateStatusBarCounts();
        });

        requestCb = r -> gui.getGUIThread().invokeLater(() -> {
            requestHistory.add(r);
            SiteMapPanel sm = currentSiteMap.get();
            if (sm != null) {
                sm.addRecord(r);
            }
        });

        scanRunner = new ScanRunner(logCb, findingCb);
        statusBar.setGuiInvoker(r -> gui.getGUIThread().invokeLater(r));
        statusBar.setOnExpandRequest(() -> {
            addToLog("[*] --- Status dos módulos ---");
            statusBar.dumpModuleStatus(this::addToLog);
        });

        scanRunner.setOnScanStart(() -> gui.getGUIThread().invokeLater(() -> {
            scanning = true;
            modeBar.setScanning(true);
            statusBar.setTarget(modulesPanel.getTarget());
        }));
        scanRunner.setOnScanFinish(() -> gui.getGUIThread().invokeLater(() -> {
            scanning = false;
            modeBar.setScanning(false);
            statusBar.scanDone();
        }));
        scanRunner.setOnScanEvent(e -> gui.getGUIThread().invokeLater(() -> {
            if (e.type() == ScanEvent.Type.MODULE_START) {
                statusBar.moduleStarted(e.moduleId());
            } else if (e.type() == ScanEvent.Type.MODULE_DONE) {
                statusBar.moduleDone(e.moduleId());
                statusBar.setModuleProgress(e.index(), e.total());
            } else if (e.type() == ScanEvent.Type.SCAN_DONE) {
                statusBar.setModuleProgress(e.index(), e.total());
            }
        }));

        logHistory.add("[*] " + Version.label() + " -- pronto");
        logHistory.add("[*] Configure o alvo e pressione Iniciar para começar");

        buildPanels(screen.getTerminalSize());

        window = new BasicWindow();
        window.setHints(List.of(Window.Hint.FULL_SCREEN, Window.Hint.NO_DECORATIONS));
        window.setComponent(buildRootPanel());

        AtomicReference<TerminalSize> lastSize = new AtomicReference<>(screen.getTerminalSize());
        screen.getTerminal().addResizeListener((terminal, newSize) -> {
            if (!newSize.equals(lastSize.getAndSet(newSize))) {
                gui.getGUIThread().invokeLater(() -> {
                    buildPanels(newSize);
                    window.setComponent(buildRootPanel());
                });
            }
        });

        window.addWindowListener(new WindowListenerAdapter() {
            // Character shortcuts (q/e/?) -- blocked when a TextBox has focus so typing
            // isn't hijacked
            @Override
            public void onInput(Window basePane, KeyStroke keyStroke, AtomicBoolean deliverEvent) {
                if (keyStroke.getKeyType() != KeyType.Character) {
                    return;
                }
                if (window.getFocusedInteractable() instanceof TextBox) {
                    return;
                }
                char ch = keyStroke.getCharacter();
                if (ch == 'q' || ch == 'Q') {
                    scanRunner.shutdown();
                    window.close();
                    deliverEvent.set(false);
                } else if (ch == 'e' || ch == 'E') {
                    showExportMenu();
                    deliverEvent.set(false);
                } else if (ch == '?') {
                    showActionPalette();
                    deliverEvent.set(false);
                } else if ((ch == 's' || ch == 'S') && scanning) {
                    statusBar.expandProgress();
                    deliverEvent.set(false);
                } else if (currentMode == Mode.FINDINGS && ch >= '1' && ch <= '6') {
                    String filter = switch (ch) {
                        case '1' -> null;
                        case '2' -> "CRITICAL";
                        case '3' -> "HIGH";
                        case '4' -> "MEDIUM";
                        case '5' -> "LOW";
                        default -> "INFO";
                    };
                    findingsPanel.setFilter(filter);
                    deliverEvent.set(false);
                }
            }

            // F-key navigation -- placed in onUnhandledInput so it fires after the focused
            // component (TextBox) has already returned UNHANDLED, guaranteeing delivery
            // regardless of which component currently holds focus.
            @Override
            public void onUnhandledInput(Window basePane, KeyStroke keyStroke, AtomicBoolean hasBeenHandled) {
                KeyType kt = keyStroke.getKeyType();
                if (kt == KeyType.F1) {
                    switchMode(Mode.DASHBOARD);
                    hasBeenHandled.set(true);
                } else if (kt == KeyType.F2) {
                    switchMode(Mode.SCAN);
                    hasBeenHandled.set(true);
                } else if (kt == KeyType.F3) {
                    switchMode(Mode.TARGET);
                    hasBeenHandled.set(true);
                } else if (kt == KeyType.F4) {
                    switchMode(Mode.FINDINGS);
                    hasBeenHandled.set(true);
                } else if (kt == KeyType.F5) {
                    switchMode(Mode.REPEATER);
                    hasBeenHandled.set(true);
                } else if (kt == KeyType.F6) {
                    switchMode(Mode.REPORT);
                    hasBeenHandled.set(true);
                } else if (kt == KeyType.F7) {
                    switchMode(Mode.SITEMAP);
                    hasBeenHandled.set(true);
                } else if (kt == KeyType.F8) {
                    switchMode(Mode.ASSISTANT);
                    hasBeenHandled.set(true);
                } else if (kt == KeyType.F9) {
                    EventLogDrawer.show(gui, logHistory);
                    hasBeenHandled.set(true);
                } else if (keyStroke instanceof MouseAction ma && ma.getActionType() == MouseActionType.CLICK_RELEASE
                        && scanning) {
                    TerminalSize ts = gui.getScreen().getTerminalSize();
                    if (ma.getPosition().getRow() >= ts.getRows() - 1) {
                        statusBar.expandProgress();
                        hasBeenHandled.set(true);
                    }
                } else if (currentMode == Mode.SCAN) {
                    if (kt == KeyType.PageUp) {
                        logPanel.scrollUp(8);
                        hasBeenHandled.set(true);
                    } else if (kt == KeyType.PageDown) {
                        logPanel.scrollDown(8);
                        hasBeenHandled.set(true);
                    } else if (keyStroke instanceof MouseAction ma) {
                        if (ma.getActionType() == MouseActionType.SCROLL_UP) {
                            logPanel.scrollUp(3);
                            hasBeenHandled.set(true);
                        } else if (ma.getActionType() == MouseActionType.SCROLL_DOWN) {
                            logPanel.scrollDown(3);
                            hasBeenHandled.set(true);
                        }
                    }
                } else if (currentMode == Mode.ASSISTANT && assistantPanel != null) {
                    if (kt == KeyType.Enter) {
                        assistantPanel.handleEnter();
                        hasBeenHandled.set(true);
                    } else if (kt == KeyType.PageUp) {
                        assistantPanel.scrollUp(8);
                        hasBeenHandled.set(true);
                    } else if (kt == KeyType.PageDown) {
                        assistantPanel.scrollDown(8);
                        hasBeenHandled.set(true);
                    } else if (keyStroke instanceof MouseAction ma) {
                        if (ma.getActionType() == MouseActionType.SCROLL_UP) {
                            assistantPanel.scrollUp(3);
                            hasBeenHandled.set(true);
                        } else if (ma.getActionType() == MouseActionType.SCROLL_DOWN) {
                            assistantPanel.scrollDown(3);
                            hasBeenHandled.set(true);
                        }
                    }
                }
            }
        });

        gui.addWindowAndWait(window);
        scanRunner.shutdown();
        screen.stopScreen();
    }

    private void switchMode(Mode mode) {
        currentMode = mode;
        modeBar.setMode(mode);
        window.setComponent(buildRootPanel());
    }

    private void buildPanels(TerminalSize term) {
        int findingsH = 10;
        int chromeH = 2; // modeBar + statusBar
        int centerH = Math.max(5, term.getRows() - chromeH - findingsH - 4);
        int leftW = 22;
        int siteMapH = Math.max(4, term.getRows() - chromeH - 4); // minus chrome + counter + hint + border

        LogPanel newLog = new LogPanel(centerH);
        FindingsPanel newFindings = new FindingsPanel(findingsH, this::showFindingDetail);
        SiteMapPanel newSiteMap = new SiteMapPanel(siteMapH);

        synchronized (logHistory) {
            logHistory.forEach(newLog::log);
        }
        synchronized (findingHistory) {
            findingHistory.forEach(newFindings::addFinding);
        }
        synchronized (requestHistory) {
            requestHistory.forEach(newSiteMap::addRecord);
        }

        currentLog.set(newLog);
        currentFindings.set(newFindings);
        currentSiteMap.set(newSiteMap);

        logPanel = newLog;
        findingsPanel = newFindings;
        siteMapPanel = newSiteMap;
        if (modulesPanel == null) {
            modulesPanel = new ModulesPanel(leftW, logPanel, findingsPanel, scanRunner);
            modulesPanel.setRequestLogCb(requestCb);
            if (envPreload != null && envPreload.hasTarget()) {
                modulesPanel.setTarget(envPreload.target());
                modulesPanel.setJwt(envPreload.jwt1());
                modulesPanel.setJwt2(envPreload.jwt2());
            }
        } else {
            modulesPanel.updateLogPanel(logPanel);
        }
    }

    private Panel buildRootPanel() {
        var root = new Panel(new BorderLayout());
        root.addComponent(modeBar, BorderLayout.Location.TOP);
        root.addComponent(buildModeContent(currentMode), BorderLayout.Location.CENTER);
        root.addComponent(statusBar, BorderLayout.Location.BOTTOM);
        return root;
    }

    private Component buildModeContent(Mode mode) {
        return switch (mode) {
            case SCAN -> buildScanContent();
            case DASHBOARD -> buildDashboardContent();
            case TARGET -> TargetMode.build(modulesPanel, () -> switchMode(Mode.SCAN));
            case FINDINGS -> buildFindingsContent();
            case REPEATER -> RepeaterMode.build(modulesPanel.getTarget(), modulesPanel.getJwt());
            case REPORT -> buildReportContent();
            case SITEMAP -> buildSiteMapContent();
            case ASSISTANT -> buildAssistantContent();
        };
    }

    private Component buildScanContent() {
        var scanPanel = new Panel(new BorderLayout());
        var innerPanel = new Panel(new BorderLayout());
        innerPanel.addComponent(modulesPanel.withBorder(Borders.singleLine("MODULOS")), BorderLayout.Location.LEFT);
        innerPanel.addComponent(logPanel.withBorder(Borders.singleLine("OUTPUT / LOG  scroll:↑↓ PgUp/Dn")),
                BorderLayout.Location.CENTER);
        scanPanel.addComponent(innerPanel, BorderLayout.Location.CENTER);
        scanPanel.addComponent(findingsPanel.withBorder(Borders.singleLine("FINDINGS")), BorderLayout.Location.BOTTOM);
        return scanPanel;
    }

    private Component buildFindingsContent() {
        var p = new Panel(new BorderLayout());
        p.addComponent(findingsPanel.withBorder(Borders.singleLine("FINDINGS -- Enter: detalhe  F2: voltar ao scan")),
                BorderLayout.Location.CENTER);
        return p;
    }

    private Component buildSiteMapContent() {
        var p = new Panel(new BorderLayout());
        p.addComponent(siteMapPanel.withBorder(Borders.singleLine("SITE MAP -- F7  requisições HTTP interceptadas")),
                BorderLayout.Location.CENTER);
        return p;
    }

    private Component buildAssistantContent() {
        if (assistantPanel == null) {
            TerminalSize ts = gui.getScreen().getTerminalSize();
            int chatHeight = Math.max(8, ts.getRows() - 4);
            assistantPanel = new AssistantPanel(chatHeight, true);

            initAssistant();

            assistantPanel.setOnSend(msg -> {
                if (aiAssistant == null) {
                    assistantPanel.addSystemMessage("Assistant not configured.");
                    return;
                }
                assistantExecutor.submit(() -> {
                    try {
                        String systemPrompt = contextBuilder.build();
                        String toolsJson = buildToolsJson();
                        gui.getGUIThread().invokeLater(() -> assistantPanel.startAssistantMessage());
                        aiAssistant.sendStreaming(msg, systemPrompt, toolsJson, token -> {
                            gui.getGUIThread().invokeLater(() -> assistantPanel.appendToken(token));
                        });
                        gui.getGUIThread().invokeLater(() -> assistantPanel.finishAssistantMessage());
                    } catch (Exception e) {
                        gui.getGUIThread()
                                .invokeLater(() -> assistantPanel.addSystemMessage("Error: " + e.getMessage()));
                    }
                });
            });
            assistantPanel.setOnSlashCommand(cmd -> {
                String[] parts = cmd.split("\\s+", 2);
                String slashCmd = parts[0].toLowerCase();
                String arg = parts.length > 1 ? parts[1] : "";

                if ("/provider".equals(slashCmd)) {
                    handleProviderCommand(arg);
                    return;
                }
                if ("/model".equals(slashCmd)) {
                    handleModelCommand(arg);
                    return;
                }

                if (contextBuilder == null) {
                    assistantPanel.addSystemMessage("Assistant not configured.");
                    return;
                }
                String enriched = contextBuilder.buildWithSlashCommand(slashCmd, arg);
                if (aiAssistant != null) {
                    assistantExecutor.submit(() -> {
                        try {
                            gui.getGUIThread().invokeLater(() -> assistantPanel.startAssistantMessage());
                            aiAssistant.sendStreaming(cmd, enriched, buildToolsJson(), token -> {
                                gui.getGUIThread().invokeLater(() -> assistantPanel.appendToken(token));
                            });
                            gui.getGUIThread().invokeLater(() -> assistantPanel.finishAssistantMessage());
                        } catch (Exception e) {
                            gui.getGUIThread()
                                    .invokeLater(() -> assistantPanel.addSystemMessage("Error: " + e.getMessage()));
                        }
                    });
                }
            });
        }

        var wrapper = new Panel(new BorderLayout());
        wrapper.addComponent(assistantPanel, BorderLayout.Location.CENTER);

        assistantPanel.getInputBox().takeFocus();
        return wrapper;
    }

    private void initAssistant() {
        try {
            Map<String, String> envMap = envPreload != null ? envPreload.asMap() : Map.of();
            availableProviders = ProviderRegistry.detect(envMap);
            maxTokens = AssistantConfig.parseMaxTokens(envMap);

            String legacyProvider = envMap.getOrDefault("assistant_provider", "").toLowerCase();
            String resolvedId = "anthropic".equals(legacyProvider) ? "claude" : legacyProvider;
            currentProvider = null;
            for (var p : availableProviders) {
                if (p.id().equals(resolvedId)) {
                    currentProvider = p;
                    break;
                }
            }
            if (currentProvider == null && !availableProviders.isEmpty()) {
                currentProvider = availableProviders.get(0);
            }
            if (currentProvider == null) {
                assistantPanel.addSystemMessage("No AI providers available.");
                return;
            }

            String envModel = envMap.getOrDefault("assistant_model", "");
            currentModel = envModel.isEmpty() ? currentProvider.defaultModel() : envModel;

            initAssistantForProvider();
            assistantPanel.addSystemMessage("AI Assistant ready (" + currentProvider.label() + " / " + currentModel
                    + "). Use /provider or /model to switch.");
        } catch (Exception e) {
            assistantPanel.addSystemMessage("Error initializing assistant: " + e.getMessage());
        }
    }

    private void initAssistantForProvider() {
        AssistantConfig config = AssistantConfig.forProvider(currentProvider, currentModel, maxTokens);
        aiAssistant = new AiAssistant(config);
        KnowledgeBase kb = KnowledgeBase.getInstance();
        contextBuilder = new ContextBuilder(() -> findingHistory, () -> scanRunner.getLastContext(), kb);

        GetFindingsTool findingsTool = new GetFindingsTool(() -> findingHistory);
        QueryKbTool kbTool = new QueryKbTool(kb);
        ExplainCweTool cweTool = new ExplainCweTool(kb);
        GetSitemapTool sitemapTool = new GetSitemapTool(() -> discoveredPaths);
        GetScanConfigTool configTool = new GetScanConfigTool(() -> scanRunner.getLastContext());

        aiAssistant.registerTool(findingsTool.name(), findingsTool::call);
        aiAssistant.registerTool(kbTool.name(), kbTool::call);
        aiAssistant.registerTool(cweTool.name(), cweTool::call);
        aiAssistant.registerTool(sitemapTool.name(), sitemapTool::call);
        aiAssistant.registerTool(configTool.name(), configTool::call);
    }

    private void handleProviderCommand(String arg) {
        if (arg.isEmpty()) {
            StringBuilder sb = new StringBuilder("Available providers:");
            for (var p : availableProviders) {
                String marker = (currentProvider != null && p.id().equals(currentProvider.id())) ? " [active]" : "";
                sb.append("\n  ").append(p.id()).append(" (").append(p.label()).append(")").append(marker);
            }
            sb.append("\nUsage: /provider <id>");
            assistantPanel.addSystemMessage(sb.toString());
            return;
        }
        for (var p : availableProviders) {
            if (p.id().equalsIgnoreCase(arg) || p.label().equalsIgnoreCase(arg)) {
                currentProvider = p;
                currentModel = p.defaultModel();
                initAssistantForProvider();
                aiAssistant.clearHistory();
                assistantPanel.addSystemMessage("Switched to " + p.label() + " / " + currentModel);
                return;
            }
        }
        assistantPanel.addSystemMessage("Unknown provider: " + arg);
    }

    private void handleModelCommand(String arg) {
        if (currentProvider == null) {
            assistantPanel.addSystemMessage("No provider selected. Use /provider first.");
            return;
        }
        if (arg.isEmpty()) {
            StringBuilder sb = new StringBuilder("Models for " + currentProvider.label() + ":");
            for (String m : currentProvider.models()) {
                String marker = m.equals(currentModel) ? " [active]" : "";
                sb.append("\n  ").append(m).append(marker);
            }
            sb.append("\nUsage: /model <name> (custom names accepted)");
            assistantPanel.addSystemMessage(sb.toString());
            return;
        }
        currentModel = arg;
        initAssistantForProvider();
        aiAssistant.clearHistory();
        assistantPanel.addSystemMessage("Switched to " + currentProvider.label() + " / " + currentModel);
    }

    private String buildToolsJson() {
        if (aiAssistant == null) {
            return "[]";
        }
        KnowledgeBase kb = KnowledgeBase.getInstance();
        var toolDefs = List.of(new GetFindingsTool(() -> findingHistory), new QueryKbTool(kb), new ExplainCweTool(kb),
                new GetSitemapTool(() -> discoveredPaths), new GetScanConfigTool(() -> scanRunner.getLastContext()));
        var tools = new com.google.gson.JsonArray();
        for (var tool : toolDefs) {
            var fn = new com.google.gson.JsonObject();
            fn.addProperty("name", tool.name());
            fn.addProperty("description", tool.description());
            fn.add("parameters", com.google.gson.JsonParser.parseString(tool.paramsSchema()));
            tools.add(fn);
        }
        return tools.toString();
    }

    private Component buildDashboardContent() {
        var p = new Panel(new LinearLayout(Direction.VERTICAL));
        List<Finding> snap;
        synchronized (findingHistory) {
            snap = new ArrayList<>(findingHistory);
        }

        p.addComponent(new EmptySpace(new TerminalSize(1, 1)));

        if (snap.isEmpty()) {
            Label lbl = new Label("  Nenhum scan ainda -- F2 Scan para começar");
            lbl.setForegroundColor(TextColor.ANSI.WHITE);
            p.addComponent(lbl);
            return p.withBorder(Borders.singleLine("Dashboard"));
        }

        String target = modulesPanel != null ? modulesPanel.getTarget() : "";
        if (!target.isBlank()) {
            Label t = new Label("  Alvo:  " + target);
            t.setForegroundColor(TextColor.ANSI.WHITE);
            p.addComponent(t);
            p.addComponent(new EmptySpace(new TerminalSize(1, 1)));
        }

        long c = snap.stream().filter(f -> f.severity() == Severity.CRITICAL).count();
        long h = snap.stream().filter(f -> f.severity() == Severity.HIGH).count();
        long m = snap.stream().filter(f -> f.severity() == Severity.MEDIUM).count();
        long l = snap.stream().filter(f -> f.severity() == Severity.LOW).count();
        long i = snap.stream().filter(f -> f.severity() == Severity.INFO).count();

        p.addComponent(new Label("  Findings: " + snap.size()));
        p.addComponent(new EmptySpace(new TerminalSize(1, 1)));
        p.addComponent(severityBar("  CRITICAL", c, snap.size(), TextColor.ANSI.RED));
        p.addComponent(severityBar("  HIGH    ", h, snap.size(), TextColor.ANSI.YELLOW));
        p.addComponent(severityBar("  MEDIUM  ", m, snap.size(), TextColor.ANSI.WHITE));
        p.addComponent(severityBar("  LOW     ", l, snap.size(), TextColor.ANSI.BLUE));
        p.addComponent(severityBar("  INFO    ", i, snap.size(), TextColor.ANSI.WHITE));
        p.addComponent(new EmptySpace(new TerminalSize(1, 1)));

        if (c > 0 || h > 0) {
            p.addComponent(new Label("  Top findings críticos:"));
            snap.stream().filter(f -> f.severity() == Severity.CRITICAL || f.severity() == Severity.HIGH).limit(5)
                    .forEach(f -> {
                        Label fl = new Label("    [" + f.severity().name() + "] " + f.module() + " -- " + f.title());
                        fl.setForegroundColor(severityColor(f.severity()));
                        p.addComponent(fl);
                    });
        }

        return p.withBorder(Borders.singleLine("Dashboard"));
    }

    private Component buildReportContent() {
        var p = new Panel(new LinearLayout(Direction.VERTICAL));
        List<Finding> snap;
        synchronized (findingHistory) {
            snap = new ArrayList<>(findingHistory);
        }

        if (snap.isEmpty()) {
            Label lbl = new Label("  Nenhum finding. Execute um scan (F2) primeiro.");
            lbl.setForegroundColor(TextColor.ANSI.WHITE);
            p.addComponent(new EmptySpace(new TerminalSize(1, 1)));
            p.addComponent(lbl);
        } else {
            long c = snap.stream().filter(f -> f.severity() == Severity.CRITICAL).count();
            long h = snap.stream().filter(f -> f.severity() == Severity.HIGH).count();
            long m = snap.stream().filter(f -> f.severity() == Severity.MEDIUM).count();
            long l = snap.stream().filter(f -> f.severity() == Severity.LOW).count();
            long i = snap.stream().filter(f -> f.severity() == Severity.INFO).count();
            int total = snap.size();

            p.addComponent(new EmptySpace(new TerminalSize(1, 1)));
            p.addComponent(new Label("  Total: " + total + " findings"));
            p.addComponent(new EmptySpace(new TerminalSize(1, 1)));
            p.addComponent(severityBar("  CRITICAL", c, total, TextColor.ANSI.RED));
            p.addComponent(severityBar("  HIGH    ", h, total, TextColor.ANSI.YELLOW));
            p.addComponent(severityBar("  MEDIUM  ", m, total, TextColor.ANSI.WHITE));
            p.addComponent(severityBar("  LOW     ", l, total, TextColor.ANSI.BLUE));
            p.addComponent(severityBar("  INFO    ", i, total, TextColor.ANSI.WHITE));
            p.addComponent(new EmptySpace(new TerminalSize(1, 1)));
            p.addComponent(new Button("[E] Export Report", this::showExportMenu));
        }
        return p.withBorder(Borders.singleLine("Relatório"));
    }

    private static TextColor severityColor(Severity s) {
        return switch (s) {
            case CRITICAL -> TextColor.ANSI.RED_BRIGHT;
            case HIGH -> TextColor.ANSI.YELLOW_BRIGHT;
            case MEDIUM -> TextColor.ANSI.YELLOW;
            case LOW -> TextColor.ANSI.CYAN;
            case INFO -> TextColor.ANSI.WHITE;
        };
    }

    private static Label severityBar(String prefix, long count, int total, TextColor color) {
        int w = 24;
        int filled = total > 0 ? (int) Math.round((double) count / total * w) : 0;
        String bar = "█".repeat(filled) + "░".repeat(w - filled);
        Label lbl = new Label(prefix + "  [" + bar + "] " + count);
        lbl.setForegroundColor(color);
        return lbl;
    }

    private static Component buildStubContent(String name, String msg) {
        var p = new Panel(new LinearLayout(Direction.VERTICAL));
        p.addComponent(new EmptySpace(new TerminalSize(1, 1)));
        Label lbl = new Label("  " + msg);
        lbl.setForegroundColor(TextColor.ANSI.WHITE);
        p.addComponent(lbl);
        return p.withBorder(Borders.singleLine(name));
    }

    private void updateStatusBarCounts() {
        if (statusBar == null) {
            return;
        }
        long c, h, m, l;
        synchronized (findingHistory) {
            c = findingHistory.stream().filter(f -> f.severity() == Severity.CRITICAL).count();
            h = findingHistory.stream().filter(f -> f.severity() == Severity.HIGH).count();
            m = findingHistory.stream().filter(f -> f.severity() == Severity.MEDIUM).count();
            l = findingHistory.stream().filter(f -> f.severity() == Severity.LOW).count();
        }
        statusBar.setSeverityCounts((int) c, (int) h, (int) m, (int) l);
    }

    private void showActionPalette() {
        gg.effront.anarcry.tui.chrome.ActionPalette.show(gui);
    }

    private void showExportMenu() {
        List<Finding> snapshot;
        synchronized (findingHistory) {
            snapshot = new ArrayList<>(findingHistory);
        }
        if (snapshot.isEmpty()) {
            addToLog("[!] No findings to export");
            return;
        }

        var dialog = new BasicWindow("Export Report");
        dialog.setHints(Set.of(Window.Hint.CENTERED));

        var panel = new Panel(new LinearLayout(Direction.VERTICAL));
        panel.addComponent(new Label(" Select export format:"));
        panel.addComponent(new EmptySpace(new TerminalSize(1, 1)));

        var actions = new com.googlecode.lanterna.gui2.ActionListBox(new TerminalSize(36, 4));
        actions.addItem("[1] AnarCry MD + JSON", () -> {
            dialog.close();
            exportAnarCry(snapshot);
        });
        actions.addItem("[2] HackerOne", () -> {
            dialog.close();
            promptProgramName(snapshot, "h1");
        });
        actions.addItem("[3] Bugcrowd", () -> {
            dialog.close();
            exportBugcrowd(snapshot);
        });
        actions.addItem("[4] JSON only", () -> {
            dialog.close();
            exportJson(snapshot);
        });
        panel.addComponent(actions);

        panel.addComponent(new EmptySpace(new TerminalSize(1, 1)));
        panel.addComponent(new Button("Cancel [Esc]", dialog::close));

        dialog.setComponent(panel.withBorder(Borders.singleLine("Export")));
        dialog.addWindowListener(new WindowListenerAdapter() {
            @Override
            public void onInput(Window w2, KeyStroke ks, AtomicBoolean deliver) {
                if (ks.getKeyType() == KeyType.Escape) {
                    dialog.close();
                    deliver.set(false);
                } else if (ks.getKeyType() == KeyType.Character) {
                    char c = ks.getCharacter();
                    if (c == '1') {
                        dialog.close();
                        exportAnarCry(snapshot);
                        deliver.set(false);
                    } else if (c == '2') {
                        dialog.close();
                        promptProgramName(snapshot, "h1");
                        deliver.set(false);
                    } else if (c == '3') {
                        dialog.close();
                        exportBugcrowd(snapshot);
                        deliver.set(false);
                    } else if (c == '4') {
                        dialog.close();
                        exportJson(snapshot);
                        deliver.set(false);
                    }
                }
            }
        });

        gui.addWindow(dialog);
        gui.setActiveWindow(dialog);
    }

    private void promptProgramName(List<Finding> snapshot, String platform) {
        var dialog = new BasicWindow("Program Name");
        dialog.setHints(Set.of(Window.Hint.CENTERED));

        var panel = new Panel(new LinearLayout(Direction.VERTICAL));
        panel.addComponent(new Label(" Enter the program name:"));
        panel.addComponent(new EmptySpace(new TerminalSize(1, 1)));
        var input = new TextBox(new TerminalSize(36, 1));
        panel.addComponent(input);
        panel.addComponent(new EmptySpace(new TerminalSize(1, 1)));

        var buttons = new Panel(new LinearLayout(Direction.HORIZONTAL));
        buttons.addComponent(new Button("Export", () -> {
            String name = input.getText().isBlank() ? "unknown" : input.getText().trim();
            dialog.close();
            exportH1(snapshot, name);
        }));
        buttons.addComponent(new EmptySpace(new TerminalSize(2, 1)));
        buttons.addComponent(new Button("Cancel", dialog::close));
        panel.addComponent(buttons);

        dialog.setComponent(panel.withBorder(Borders.singleLine("HackerOne")));
        dialog.addWindowListener(new WindowListenerAdapter() {
            @Override
            public void onInput(Window w2, KeyStroke ks, AtomicBoolean deliver) {
                if (ks.getKeyType() == KeyType.Escape) {
                    dialog.close();
                    deliver.set(false);
                }
            }
        });

        gui.addWindow(dialog);
        gui.setActiveWindow(dialog);
    }

    private void exportAnarCry(List<Finding> snapshot) {
        String target = modulesPanel.getTarget();
        try {
            String mdFile = new ReportEngine().export(snapshot, target.isBlank() ? "unknown" : target,
                    scanRunner.testedModules(), scanRunner.testedClean());
            addToLog("[+] Exported: " + mdFile + " (+" + mdFile.replace(".md", ".json") + ")");
        } catch (Throwable t) {
            addToLog("[!] Export error: " + t.getClass().getSimpleName() + ": " + t.getMessage());
        }
    }

    private void exportH1(List<Finding> snapshot, String programName) {
        String target = modulesPanel.getTarget();
        try {
            String file = new ReportEngine().exportH1(snapshot, target.isBlank() ? "unknown" : target, programName,
                    scanRunner.testedModules(), scanRunner.testedClean());
            addToLog("[+] HackerOne report: " + file);
        } catch (Throwable t) {
            addToLog("[!] H1 export error: " + t.getClass().getSimpleName() + ": " + t.getMessage());
        }
    }

    private void exportBugcrowd(List<Finding> snapshot) {
        String target = modulesPanel.getTarget();
        try {
            String file = new ReportEngine().exportBugcrowd(snapshot, target.isBlank() ? "unknown" : target,
                    scanRunner.testedModules(), scanRunner.testedClean());
            addToLog("[+] Bugcrowd report: " + file);
        } catch (Throwable t) {
            addToLog("[!] Bugcrowd export error: " + t.getClass().getSimpleName() + ": " + t.getMessage());
        }
    }

    private void exportJson(List<Finding> snapshot) {
        String target = modulesPanel.getTarget();
        try {
            String json = new ReportEngine().toJson(snapshot);
            String timestamp = java.time.LocalDateTime.now()
                    .format(java.time.format.DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss"));
            java.nio.file.Path reportsDir = java.nio.file.Path.of("docs", "reports");
            java.nio.file.Files.createDirectories(reportsDir);
            java.nio.file.Path path = reportsDir.resolve("anarcry-findings-" + timestamp + ".json");
            java.nio.file.Files.writeString(path, json);
            addToLog("[+] JSON export: " + path);
        } catch (Throwable t) {
            addToLog("[!] JSON export error: " + t.getClass().getSimpleName() + ": " + t.getMessage());
        }
    }

    private void addToLog(String msg) {
        logHistory.add(msg);
        LogPanel lp = currentLog.get();
        if (lp != null) {
            lp.log(msg);
        }
    }

    private void showFindingDetail(Finding f) {
        var dialog = new BasicWindow();
        dialog.setHints(Set.of(Window.Hint.CENTERED, Window.Hint.MODAL));

        TerminalSize term = gui.getScreen().getTerminalSize();
        int w = Math.min(term.getColumns() - 6, 100);
        int textW = w - 4;
        int viewH = Math.max(6, term.getRows() - 8); // room for border + buttons

        // Collect all content lines
        List<String> allLines = new ArrayList<>();
        appendDetailLines(allLines, "Severidade", f.severity().name(), textW);
        appendDetailLines(allLines, "Módulo", f.module(), textW);
        appendDetailLines(allLines, "Endpoint", f.endpoint(), textW);
        appendDetailLines(allLines, "Evidência", f.evidence(), textW);
        appendDetailLines(allLines, "Impacto", f.impact(), textW);
        appendDetailLines(allLines, "Reprodução", f.reproduction(), textW);
        appendDetailLines(allLines, "Recomendação", f.recommendation(), textW);

        var contentList = new com.googlecode.lanterna.gui2.ActionListBox(
                new TerminalSize(w - 2, Math.min(allLines.size(), viewH)));
        allLines.forEach(line -> contentList.addItem(line, () -> {
        }));

        var panel = new Panel(new LinearLayout(Direction.VERTICAL));
        panel.addComponent(contentList);
        panel.addComponent(new EmptySpace(new TerminalSize(1, 1)));

        var buttons = new Panel(new LinearLayout(Direction.HORIZONTAL));
        buttons.addComponent(new Button("Fechar [Esc]", dialog::close));
        buttons.addComponent(new EmptySpace(new TerminalSize(2, 1)));
        buttons.addComponent(new Button("[C] Copiar curl", () -> {
            copyCurl(f.reproduction());
            dialog.close();
        }));
        panel.addComponent(buttons);

        dialog.setComponent(panel.withBorder(Borders.singleLine(f.severity().name() + " -- " + f.title())));

        dialog.addWindowListener(new WindowListenerAdapter() {
            @Override
            public void onInput(Window w2, KeyStroke ks, AtomicBoolean deliver) {
                if (ks.getKeyType() == KeyType.Escape) {
                    dialog.close();
                    deliver.set(false);
                } else if (ks.getKeyType() == KeyType.Character
                        && (ks.getCharacter() == 'c' || ks.getCharacter() == 'C')) {
                    copyCurl(f.reproduction());
                    dialog.close();
                    deliver.set(false);
                }
            }
        });

        gui.addWindow(dialog);
        gui.setActiveWindow(dialog);
    }

    private static void appendDetailLines(List<String> lines, String label, String value, int textW) {
        if (value == null || value.isBlank()) {
            return;
        }
        lines.add(" " + label + ":");
        for (String chunk : wrap(value, textW)) {
            lines.add("   " + chunk);
        }
        lines.add("");
    }

    private void copyCurl(String text) {
        if (text == null || text.isBlank()) {
            addToLog("[!] Nenhum comando curl disponível neste finding");
            return;
        }
        try {
            Process proc = new ProcessBuilder("xclip", "-selection", "clipboard").redirectErrorStream(true).start();
            proc.getOutputStream().write(text.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            proc.getOutputStream().close();
            if (proc.waitFor() == 0) {
                addToLog("[+] curl copiado para clipboard (xclip)");
                return;
            }
        } catch (Exception ignored) {
        }

        try {
            Process proc = new ProcessBuilder("xsel", "--clipboard", "--input").redirectErrorStream(true).start();
            proc.getOutputStream().write(text.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            proc.getOutputStream().close();
            if (proc.waitFor() == 0) {
                addToLog("[+] curl copiado para clipboard (xsel)");
                return;
            }
        } catch (Exception ignored) {
        }

        try {
            if (!java.awt.GraphicsEnvironment.isHeadless()) {
                var sel = new java.awt.datatransfer.StringSelection(text);
                java.awt.Toolkit.getDefaultToolkit().getSystemClipboard().setContents(sel, null);
                addToLog("[+] curl copiado para clipboard");
                return;
            }
        } catch (Exception ignored) {
        }

        addToLog("[!] Clipboard indisponível -- pressione Ctrl+C no terminal para copiar:");
        addToLog("    " + text.lines().findFirst().orElse(text));
    }

    private static List<String> wrap(String text, int width) {
        List<String> lines = new ArrayList<>();
        for (String line : text.split("\n")) {
            String chunk = line;
            while (chunk.length() > width) {
                lines.add(chunk.substring(0, width));
                chunk = chunk.substring(width);
            }
            lines.add(chunk);
        }
        return lines;
    }
}
