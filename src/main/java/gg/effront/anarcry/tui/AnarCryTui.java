package gg.effront.anarcry.tui;

import com.googlecode.lanterna.TerminalSize;
import com.googlecode.lanterna.TextColor;
import com.googlecode.lanterna.gui2.*;
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
import gg.effront.anarcry.tui.panels.FindingsPanel;
import gg.effront.anarcry.tui.panels.LogPanel;
import gg.effront.anarcry.tui.panels.ModulesPanel;
import gg.effront.anarcry.tui.panels.SiteMapPanel;

import gg.effront.anarcry.EnvLoader;

import java.io.IOException;
import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;

public class AnarCryTui {

    private final List<String>        logHistory     = Collections.synchronizedList(new ArrayList<>());
    private final List<Finding>       findingHistory = Collections.synchronizedList(new ArrayList<>());
    private final List<RequestRecord> requestHistory = Collections.synchronizedList(new ArrayList<>());
    private final AtomicReference<LogPanel>      currentLog      = new AtomicReference<>();
    private final AtomicReference<FindingsPanel> currentFindings = new AtomicReference<>();
    private final AtomicReference<SiteMapPanel>  currentSiteMap  = new AtomicReference<>();

    private MultiWindowTextGUI       gui;
    private ScanRunner               scanRunner;
    private LogPanel                 logPanel;
    private FindingsPanel            findingsPanel;
    private SiteMapPanel             siteMapPanel;
    private ModulesPanel             modulesPanel;
    private Consumer<RequestRecord>  requestCb;
    private BasicWindow        window;
    private ModeBar            modeBar;
    private StatusBar          statusBar;
    private volatile Mode      currentMode = Mode.SCAN;
    private volatile boolean   scanning    = false;
    private EnvLoader          envPreload  = null;

    public void start() throws IOException { start(null); }

    public void start(EnvLoader env) throws IOException {
        this.envPreload = env;
        var factory = new DefaultTerminalFactory();
        factory.setMouseCaptureMode(MouseCaptureMode.CLICK_RELEASE);
        TerminalScreen screen = (TerminalScreen) factory.createScreen();
        screen.startScreen();

        gui = new MultiWindowTextGUI(screen, new DefaultWindowManager(),
                new EmptySpace(TextColor.ANSI.BLACK));

        modeBar   = new ModeBar();
        statusBar = new StatusBar();

        Consumer<String> logCb = msg -> gui.getGUIThread().invokeLater(() -> {
            logHistory.add(msg);
            LogPanel lp = currentLog.get();
            if (lp != null) lp.log(msg);
        });
        Consumer<Finding> findingCb = f -> gui.getGUIThread().invokeLater(() -> {
            findingHistory.add(f);
            FindingsPanel fp = currentFindings.get();
            if (fp != null) fp.addFinding(f);
            modeBar.setFindingsCount(findingHistory.size());
            updateStatusBarCounts();
        });

        requestCb = r -> gui.getGUIThread().invokeLater(() -> {
            requestHistory.add(r);
            SiteMapPanel sm = currentSiteMap.get();
            if (sm != null) sm.addRecord(r);
        });

        scanRunner = new ScanRunner(logCb, findingCb);
        scanRunner.setOnScanStart(() -> gui.getGUIThread().invokeLater(() -> {
            scanning = true;
            modeBar.setScanning(true);
            statusBar.setTarget(modulesPanel.getTarget());
        }));
        scanRunner.setOnScanFinish(() -> gui.getGUIThread().invokeLater(() -> {
            scanning = false;
            modeBar.setScanning(false);
        }));
        scanRunner.setOnScanEvent(e -> {
            if (e.type() == ScanEvent.Type.MODULE_DONE || e.type() == ScanEvent.Type.SCAN_DONE) {
                gui.getGUIThread().invokeLater(() ->
                    statusBar.setModuleProgress(e.index(), e.total()));
            }
        });

        logHistory.add("[*] AnarCry v1.0 — pronto");
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
            // Character shortcuts (q/e/?) — blocked when a TextBox has focus so typing isn't hijacked
            @Override
            public void onInput(Window basePane, KeyStroke keyStroke, AtomicBoolean deliverEvent) {
                if (keyStroke.getKeyType() != KeyType.Character) return;
                if (window.getFocusedInteractable() instanceof TextBox) return;
                char ch = keyStroke.getCharacter();
                if (ch == 'q' || ch == 'Q') {
                    scanRunner.shutdown();
                    window.close();
                    deliverEvent.set(false);
                } else if (ch == 'e' || ch == 'E') {
                    exportFindings();
                    deliverEvent.set(false);
                } else if (ch == '?') {
                    showActionPalette();
                    deliverEvent.set(false);
                } else if (currentMode == Mode.FINDINGS && ch >= '1' && ch <= '6') {
                    String filter = switch (ch) {
                        case '1' -> null;
                        case '2' -> "CRITICAL";
                        case '3' -> "HIGH";
                        case '4' -> "MEDIUM";
                        case '5' -> "LOW";
                        default  -> "INFO";
                    };
                    findingsPanel.setFilter(filter);
                    deliverEvent.set(false);
                }
            }

            // F-key navigation — placed in onUnhandledInput so it fires after the focused
            // component (TextBox) has already returned UNHANDLED, guaranteeing delivery
            // regardless of which component currently holds focus.
            @Override
            public void onUnhandledInput(Window basePane, KeyStroke keyStroke, AtomicBoolean hasBeenHandled) {
                KeyType kt = keyStroke.getKeyType();
                if (kt == KeyType.F1) {
                    switchMode(Mode.DASHBOARD);     hasBeenHandled.set(true);
                } else if (kt == KeyType.F2) {
                    switchMode(Mode.SCAN);          hasBeenHandled.set(true);
                } else if (kt == KeyType.F3) {
                    switchMode(Mode.TARGET);        hasBeenHandled.set(true);
                } else if (kt == KeyType.F4) {
                    switchMode(Mode.FINDINGS);      hasBeenHandled.set(true);
                } else if (kt == KeyType.F5) {
                    switchMode(Mode.REPEATER);      hasBeenHandled.set(true);
                } else if (kt == KeyType.F6) {
                    switchMode(Mode.REPORT);        hasBeenHandled.set(true);
                } else if (kt == KeyType.F7) {
                    switchMode(Mode.SITEMAP);       hasBeenHandled.set(true);
                } else if (kt == KeyType.F8) {
                    EventLogDrawer.show(gui, logHistory); hasBeenHandled.set(true);
                } else if (currentMode == Mode.SCAN) {
                    if (kt == KeyType.PageUp) {
                        logPanel.scrollUp(8);       hasBeenHandled.set(true);
                    } else if (kt == KeyType.PageDown) {
                        logPanel.scrollDown(8);     hasBeenHandled.set(true);
                    } else if (keyStroke instanceof MouseAction ma) {
                        if (ma.getActionType() == MouseActionType.SCROLL_UP) {
                            logPanel.scrollUp(3);   hasBeenHandled.set(true);
                        } else if (ma.getActionType() == MouseActionType.SCROLL_DOWN) {
                            logPanel.scrollDown(3); hasBeenHandled.set(true);
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
        int chromeH   = 2; // modeBar + statusBar
        int centerH   = Math.max(5, term.getRows() - chromeH - findingsH - 4);
        int leftW     = 34;

        LogPanel      newLog      = new LogPanel(centerH);
        FindingsPanel newFindings = new FindingsPanel(findingsH, this::showFindingDetail);
        SiteMapPanel  newSiteMap  = new SiteMapPanel();

        synchronized (logHistory)     { logHistory.forEach(newLog::log); }
        synchronized (findingHistory) { findingHistory.forEach(newFindings::addFinding); }
        synchronized (requestHistory) { requestHistory.forEach(newSiteMap::addRecord); }

        currentLog.set(newLog);
        currentFindings.set(newFindings);
        currentSiteMap.set(newSiteMap);

        logPanel      = newLog;
        findingsPanel = newFindings;
        siteMapPanel  = newSiteMap;
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
            case SCAN      -> buildScanContent();
            case DASHBOARD -> buildDashboardContent();
            case TARGET    -> TargetMode.build(modulesPanel, () -> switchMode(Mode.SCAN));
            case FINDINGS  -> buildFindingsContent();
            case REPEATER  -> RepeaterMode.build(modulesPanel.getTarget(), modulesPanel.getJwt());
            case REPORT    -> buildReportContent();
            case SITEMAP   -> buildSiteMapContent();
        };
    }

    private Component buildScanContent() {
        var scanPanel  = new Panel(new BorderLayout());
        var innerPanel = new Panel(new BorderLayout());
        innerPanel.addComponent(modulesPanel.withBorder(Borders.singleLine("MODULOS")),
                BorderLayout.Location.LEFT);
        innerPanel.addComponent(logPanel.withBorder(Borders.singleLine("OUTPUT / LOG  scroll:↑↓ PgUp/Dn")),
                BorderLayout.Location.CENTER);
        scanPanel.addComponent(innerPanel, BorderLayout.Location.CENTER);
        scanPanel.addComponent(
                findingsPanel.withBorder(Borders.singleLine("FINDINGS")),
                BorderLayout.Location.BOTTOM);
        return scanPanel;
    }

    private Component buildFindingsContent() {
        var p = new Panel(new BorderLayout());
        p.addComponent(
                findingsPanel.withBorder(Borders.singleLine(
                        "FINDINGS — Enter: detalhe  F2: voltar ao scan")),
                BorderLayout.Location.CENTER);
        return p;
    }

    private Component buildSiteMapContent() {
        var p = new Panel(new BorderLayout());
        p.addComponent(
                siteMapPanel.withBorder(Borders.singleLine("SITE MAP — F7  requisições HTTP interceptadas")),
                BorderLayout.Location.CENTER);
        return p;
    }

    private Component buildDashboardContent() {
        var p = new Panel(new LinearLayout(Direction.VERTICAL));
        List<Finding> snap;
        synchronized (findingHistory) { snap = new ArrayList<>(findingHistory); }

        p.addComponent(new EmptySpace(new TerminalSize(1, 1)));

        if (snap.isEmpty()) {
            Label lbl = new Label("  Nenhum scan ainda — F2 Scan para começar");
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
            snap.stream()
                .filter(f -> f.severity() == Severity.CRITICAL || f.severity() == Severity.HIGH)
                .limit(5)
                .forEach(f -> {
                    Label fl = new Label("    [" + f.severity().name() + "] " + f.module() + " — " + f.title());
                    fl.setForegroundColor(f.severity().color);
                    p.addComponent(fl);
                });
        }

        return p.withBorder(Borders.singleLine("Dashboard"));
    }

    private Component buildReportContent() {
        var p = new Panel(new LinearLayout(Direction.VERTICAL));
        List<Finding> snap;
        synchronized (findingHistory) { snap = new ArrayList<>(findingHistory); }

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
            int  total = snap.size();

            p.addComponent(new EmptySpace(new TerminalSize(1, 1)));
            p.addComponent(new Label("  Total: " + total + " findings"));
            p.addComponent(new EmptySpace(new TerminalSize(1, 1)));
            p.addComponent(severityBar("  CRITICAL", c, total, TextColor.ANSI.RED));
            p.addComponent(severityBar("  HIGH    ", h, total, TextColor.ANSI.YELLOW));
            p.addComponent(severityBar("  MEDIUM  ", m, total, TextColor.ANSI.WHITE));
            p.addComponent(severityBar("  LOW     ", l, total, TextColor.ANSI.BLUE));
            p.addComponent(severityBar("  INFO    ", i, total, TextColor.ANSI.WHITE));
            p.addComponent(new EmptySpace(new TerminalSize(1, 1)));
            p.addComponent(new Button("[E] Exportar MD + JSON", this::exportFindings));
        }
        return p.withBorder(Borders.singleLine("Relatório"));
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
        if (statusBar == null) return;
        long c, h, m, l;
        synchronized (findingHistory) {
            c = findingHistory.stream().filter(f -> f.severity() == Severity.CRITICAL).count();
            h = findingHistory.stream().filter(f -> f.severity() == Severity.HIGH).count();
            m = findingHistory.stream().filter(f -> f.severity() == Severity.MEDIUM).count();
            l = findingHistory.stream().filter(f -> f.severity() == Severity.LOW).count();
        }
        statusBar.setSeverityCounts((int)c, (int)h, (int)m, (int)l);
    }

    private void showActionPalette() {
        gg.effront.anarcry.tui.chrome.ActionPalette.show(gui);
    }

    private void exportFindings() {
        List<Finding> snapshot;
        synchronized (findingHistory) { snapshot = new ArrayList<>(findingHistory); }
        if (snapshot.isEmpty()) {
            addToLog("[!] Nenhum finding para exportar");
            return;
        }
        String target = modulesPanel.getTarget();
        try {
            String mdFile = new ReportEngine().export(snapshot, target.isBlank() ? "unknown" : target);
            addToLog("[+] Exportado: " + mdFile + " (+" + mdFile.replace(".md", ".json") + ")");
        } catch (Throwable t) {
            addToLog("[!] Erro ao exportar: " + t.getClass().getSimpleName() + ": " + t.getMessage());
        }
    }

    private void addToLog(String msg) {
        logHistory.add(msg);
        LogPanel lp = currentLog.get();
        if (lp != null) lp.log(msg);
    }

    private void showFindingDetail(Finding f) {
        var dialog = new BasicWindow();
        dialog.setHints(Set.of(Window.Hint.CENTERED, Window.Hint.MODAL));

        int w     = Math.min(gui.getScreen().getTerminalSize().getColumns() - 6, 100);
        int textW = w - 4;

        var panel = new Panel(new LinearLayout(Direction.VERTICAL));

        addDetailRow(panel, "Severidade",   f.severity().name(), textW);
        addDetailRow(panel, "Módulo",       f.module(),          textW);
        addDetailRow(panel, "Endpoint",     f.endpoint(),        textW);
        addDetailRow(panel, "Evidência",    f.evidence(),        textW);
        addDetailRow(panel, "Impacto",      f.impact(),          textW);
        addDetailRow(panel, "Reprodução",   f.reproduction(),    textW);
        addDetailRow(panel, "Recomendação", f.recommendation(),  textW);

        panel.addComponent(new EmptySpace(new TerminalSize(1, 1)));

        var buttons = new Panel(new LinearLayout(Direction.HORIZONTAL));
        buttons.addComponent(new Button("Fechar [Esc]", dialog::close));
        buttons.addComponent(new EmptySpace(new TerminalSize(2, 1)));
        buttons.addComponent(new Button("[C] Copiar curl", () -> {
            copyCurl(f.reproduction());
            dialog.close();
        }));
        panel.addComponent(buttons);

        dialog.setComponent(panel.withBorder(Borders.singleLine(
                f.severity().name() + " — " + f.title())));

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

    private void copyCurl(String text) {
        if (text == null || text.isBlank()) {
            addToLog("[!] Nenhum comando curl disponível neste finding");
            return;
        }
        try {
            Process proc = new ProcessBuilder("xclip", "-selection", "clipboard")
                    .redirectErrorStream(true).start();
            proc.getOutputStream().write(text.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            proc.getOutputStream().close();
            if (proc.waitFor() == 0) { addToLog("[+] curl copiado para clipboard (xclip)"); return; }
        } catch (Exception ignored) {}

        try {
            Process proc = new ProcessBuilder("xsel", "--clipboard", "--input")
                    .redirectErrorStream(true).start();
            proc.getOutputStream().write(text.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            proc.getOutputStream().close();
            if (proc.waitFor() == 0) { addToLog("[+] curl copiado para clipboard (xsel)"); return; }
        } catch (Exception ignored) {}

        try {
            if (!java.awt.GraphicsEnvironment.isHeadless()) {
                var sel = new java.awt.datatransfer.StringSelection(text);
                java.awt.Toolkit.getDefaultToolkit().getSystemClipboard().setContents(sel, null);
                addToLog("[+] curl copiado para clipboard");
                return;
            }
        } catch (Exception ignored) {}

        addToLog("[!] Clipboard indisponível — pressione Ctrl+C no terminal para copiar:");
        addToLog("    " + text.lines().findFirst().orElse(text));
    }

    private static void addDetailRow(Panel panel, String label, String value, int textW) {
        if (value == null || value.isBlank()) return;
        panel.addComponent(new Label(" " + label + ":"));
        for (String chunk : wrap(value, textW)) {
            panel.addComponent(new Label("   " + chunk));
        }
        panel.addComponent(new EmptySpace(new TerminalSize(1, 1)));
    }

    private static List<String> wrap(String text, int width) {
        List<String> lines = new ArrayList<>();
        for (String line : text.split("\n")) {
            while (line.length() > width) {
                lines.add(line.substring(0, width));
                line = line.substring(width);
            }
            lines.add(line);
        }
        return lines;
    }
}
