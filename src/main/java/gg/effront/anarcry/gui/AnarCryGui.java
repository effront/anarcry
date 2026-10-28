package gg.effront.anarcry.gui;

import gg.effront.anarcry.EnvLoader;
import gg.effront.anarcry.gui.components.FindingDetailPanel;
import gg.effront.anarcry.gui.components.FindingsTable;
import gg.effront.anarcry.gui.components.GuiModulesPanel;
import gg.effront.anarcry.gui.components.GuiStatusBar;
import gg.effront.anarcry.gui.components.LogPane;
import gg.effront.anarcry.gui.theme.AnarCryLaf;
import gg.effront.anarcry.gui.views.DashboardView;
import gg.effront.anarcry.gui.views.ExportDialog;
import gg.effront.anarcry.gui.views.FindingDetailDialog;
import gg.effront.anarcry.gui.views.FindingsView;
import gg.effront.anarcry.gui.views.PreferencesDialog;
import gg.effront.anarcry.gui.views.RepeaterView;
import gg.effront.anarcry.gui.views.ReportView;
import gg.effront.anarcry.gui.views.SiteMapView;
import gg.effront.anarcry.gui.views.TargetView;
import gg.effront.anarcry.model.Finding;
import gg.effront.anarcry.model.Severity;
import gg.effront.anarcry.scanner.DiscoveredPaths;
import gg.effront.anarcry.scanner.ScanEvent;

import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.KeyEventDispatcher;
import java.awt.KeyboardFocusManager;
import java.awt.event.InputEvent;
import java.awt.event.KeyEvent;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.ArrayList;
import java.util.Collections;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;

import javax.swing.JFrame;
import javax.swing.JMenu;
import javax.swing.JTable;
import javax.swing.JMenuBar;
import javax.swing.JMenuItem;
import javax.swing.JOptionPane;
import javax.swing.JSplitPane;
import javax.swing.JTabbedPane;
import javax.swing.KeyStroke;
import javax.swing.SwingUtilities;
import javax.swing.text.JTextComponent;

public class AnarCryGui {

    private static final String FRAME_TITLE = "AnarCry v1.3";
    private static final int FRAME_WIDTH = 1400;
    private static final int FRAME_HEIGHT = 950;
    private static final int MODULES_PANEL_WIDTH = 260;
    private static final int LOG_DIVIDER_LOCATION = 350;

    private JFrame frame;
    private GuiController controller;
    private GuiModulesPanel modulesPanel;
    private LogPane logPane;
    private GuiStatusBar statusBar;

    private DashboardView dashboardView;
    private FindingsView findingsView;
    private FindingsTable scanFindingsTable;
    private FindingDetailPanel scanDetailPanel;
    private TargetView targetView;
    private SiteMapView siteMapView;
    private RepeaterView repeaterView;
    private ReportView reportView;

    private JTabbedPane tabs;

    private final List<Finding> allFindings = Collections.synchronizedList(new ArrayList<>());
    private final Map<Severity, Integer> severityCounts = new EnumMap<>(Severity.class);
    private Runnable startScanAction;

    public void start(EnvLoader env) {
        AnarCryLaf.install();

        logPane = new LogPane();
        statusBar = new GuiStatusBar();
        modulesPanel = new GuiModulesPanel();
        dashboardView = new DashboardView();
        findingsView = new FindingsView();
        scanFindingsTable = new FindingsTable();
        scanDetailPanel = new FindingDetailPanel();
        targetView = new TargetView();
        siteMapView = new SiteMapView();
        repeaterView = new RepeaterView();
        reportView = new ReportView();

        resetSeverityCounts();

        controller = new GuiController(logPane::log, this::onFinding);

        wireScanCallbacks();
        wireModulesPanelActions();

        if (env != null) {
            prefillFromEnv(env);
        }

        SwingUtilities.invokeLater(this::buildAndShowFrame);
    }

    private void onFinding(Finding f) {
        allFindings.add(f);
        findingsView.addFinding(f);
        scanFindingsTable.addFinding(f);
        dashboardView.update(new ArrayList<>(allFindings));
        incrementSeverityCount(f.severity());
    }

    private void wireScanCallbacks() {
        controller.setOnScanEvent(event -> {
            if (event.type() == ScanEvent.Type.SCAN_START || event.type() == ScanEvent.Type.MODULE_START
                    || event.type() == ScanEvent.Type.MODULE_DONE) {
                SwingUtilities.invokeLater(() -> statusBar.setModuleProgress(event.index(), event.total()));
            }
        });

        controller.setOnScanStart(() -> SwingUtilities.invokeLater(() -> {
            statusBar.setScanning(true);
            modulesPanel.setScanning(true);
            allFindings.clear();
            findingsView.clear();
            scanFindingsTable.clear();
            scanDetailPanel.clear();
            dashboardView.clear();
            siteMapView.clear();
            reportView.clear();
            logPane.clear();
            resetSeverityCounts();
            statusBar.setSeverityCounts(0, 0, 0, 0);
            statusBar.setModuleProgress(0, 0);
            String target = modulesPanel.getTarget();
            siteMapView.setRootUrl(target);
            repeaterView.setTargetUrl(target);
        }));

        controller.setOnScanFinish(() -> {
            DiscoveredPaths dp = controller.getDiscoveredPaths();
            SwingUtilities.invokeLater(() -> {
                statusBar.setScanning(false);
                modulesPanel.setScanning(false);
                reportView.update(new ArrayList<>(allFindings), modulesPanel.getTarget());
                if (dp != null) {
                    for (String path : dp.paths()) {
                        siteMapView.addPath(path);
                    }
                }
            });
        });
    }

    private void wireModulesPanelActions() {
        startScanAction = () -> {
            String target = modulesPanel.getTarget();
            statusBar.setTarget(target);
            controller.startScan(target, modulesPanel.getJwt(), modulesPanel.getJwt2(),
                    modulesPanel.getEnabledModules(), r -> siteMapView.addPath(r.url()));
        };

        modulesPanel.setOnStart(startScanAction);
        modulesPanel.setOnStop(controller::stopScan);
    }

    private void prefillFromEnv(EnvLoader env) {
        if (env.hasTarget()) {
            modulesPanel.setTarget(env.target());
            targetView.setTarget(env.target());
        }
        modulesPanel.setJwt(env.jwt1());
        modulesPanel.setJwt2(env.jwt2());
        targetView.setJwt(env.jwt1());
        targetView.setJwt2(env.jwt2());
    }

    private void buildAndShowFrame() {
        frame = new JFrame(FRAME_TITLE);
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.setJMenuBar(buildMenuBar());

        installFindingDetailHandler(scanFindingsTable);
        wireSelectionDetail(scanFindingsTable, scanDetailPanel);

        JSplitPane findingsSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT, scanFindingsTable, scanDetailPanel);
        findingsSplit.setResizeWeight(0.45);

        JSplitPane scanSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT, logPane, findingsSplit);
        scanSplit.setResizeWeight(0.35);
        scanSplit.setDividerLocation(LOG_DIVIDER_LOCATION);

        tabs = new JTabbedPane();
        tabs.addTab("Dashboard", dashboardView);
        tabs.addTab("Scan", scanSplit);
        tabs.addTab("Target", targetView);
        tabs.addTab("Findings", findingsView);
        tabs.addTab("Repeater", repeaterView);
        tabs.addTab("Report", reportView);
        tabs.addTab("SiteMap", siteMapView);
        tabs.setSelectedIndex(1);

        JSplitPane mainSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, modulesPanel, tabs);
        mainSplit.setDividerLocation(MODULES_PANEL_WIDTH);

        frame.getContentPane().setLayout(new BorderLayout());
        frame.getContentPane().add(mainSplit, BorderLayout.CENTER);
        frame.getContentPane().add(statusBar, BorderLayout.SOUTH);

        installKeyShortcuts();

        frame.setSize(FRAME_WIDTH, FRAME_HEIGHT);
        frame.setLocationRelativeTo(null);
        frame.setVisible(true);
    }

    private void wireSelectionDetail(FindingsTable table, FindingDetailPanel detail) {
        JTable jTable = table.getTable();
        jTable.getSelectionModel().addListSelectionListener(e -> {
            if (e.getValueIsAdjusting()) {
                return;
            }
            int viewRow = jTable.getSelectedRow();
            if (viewRow < 0) {
                detail.clear();
                return;
            }
            int modelRow = jTable.convertRowIndexToModel(viewRow);
            List<Finding> all = table.getFindings();
            if (modelRow >= 0 && modelRow < all.size()) {
                detail.show(all.get(modelRow));
            }
        });
    }

    private void installFindingDetailHandler(FindingsTable table) {
        JTable jTable = table.getTable();
        jTable.addMouseListener(new MouseAdapter() {

            @Override
            public void mouseClicked(MouseEvent e) {
                if (e.getClickCount() == 2) {
                    int viewRow = jTable.getSelectedRow();
                    if (viewRow < 0) {
                        return;
                    }
                    int modelRow = jTable.convertRowIndexToModel(viewRow);
                    List<Finding> all = table.getFindings();
                    if (modelRow >= 0 && modelRow < all.size()) {
                        new FindingDetailDialog(frame, all.get(modelRow)).setVisible(true);
                    }
                }
            }
        });
    }

    private void installKeyShortcuts() {
        KeyboardFocusManager.getCurrentKeyboardFocusManager().addKeyEventDispatcher(new KeyEventDispatcher() {

            @Override
            public boolean dispatchKeyEvent(KeyEvent e) {
                if (e.getID() != KeyEvent.KEY_PRESSED) {
                    return false;
                }
                if (frame == null || !frame.isActive()) {
                    return false;
                }
                Component focused = KeyboardFocusManager.getCurrentKeyboardFocusManager().getFocusOwner();
                boolean inText = focused instanceof JTextComponent;

                int code = e.getKeyCode();
                int mods = e.getModifiersEx();
                boolean noMods = mods == 0;

                if (code >= KeyEvent.VK_F1 && code <= KeyEvent.VK_F7 && noMods) {
                    tabs.setSelectedIndex(code - KeyEvent.VK_F1);
                    return true;
                }

                if (inText) {
                    return false;
                }

                if (noMods && (code == KeyEvent.VK_E)) {
                    openExportDialog();
                    return true;
                }

                boolean ctrlShift = (mods
                        & (InputEvent.CTRL_DOWN_MASK | InputEvent.SHIFT_DOWN_MASK)) == (InputEvent.CTRL_DOWN_MASK
                                | InputEvent.SHIFT_DOWN_MASK);
                if (ctrlShift && code == KeyEvent.VK_P) {
                    PrivacyFilter.toggle();
                    return true;
                }
                return false;
            }
        });
    }

    private void openExportDialog() {
        List<Finding> findings = new ArrayList<>(allFindings);
        if (findings.isEmpty()) {
            JOptionPane.showMessageDialog(frame, "No findings to export.", "Export", JOptionPane.WARNING_MESSAGE);
            return;
        }
        new ExportDialog(frame, findings, modulesPanel.getTarget()).setVisible(true);
    }

    private JMenuBar buildMenuBar() {
        JMenuBar bar = new JMenuBar();
        bar.add(buildFileMenu());
        bar.add(buildScanMenu());
        bar.add(buildExportMenu());
        bar.add(buildViewMenu());
        bar.add(buildHelpMenu());
        return bar;
    }

    private JMenu buildFileMenu() {
        JMenu menu = new JMenu("File");
        menu.setMnemonic(KeyEvent.VK_F);

        JMenuItem exit = new JMenuItem("Exit");
        exit.setAccelerator(KeyStroke.getKeyStroke(KeyEvent.VK_Q, InputEvent.CTRL_DOWN_MASK));
        exit.addActionListener(e -> dispose());
        menu.add(exit);

        return menu;
    }

    private JMenu buildScanMenu() {
        JMenu menu = new JMenu("Scan");
        menu.setMnemonic(KeyEvent.VK_S);

        JMenuItem start = new JMenuItem("Start Scan");
        start.setAccelerator(KeyStroke.getKeyStroke(KeyEvent.VK_ENTER, InputEvent.CTRL_DOWN_MASK));
        start.addActionListener(e -> startScanAction.run());
        menu.add(start);

        JMenuItem stop = new JMenuItem("Stop Scan");
        stop.setAccelerator(KeyStroke.getKeyStroke(KeyEvent.VK_PERIOD, InputEvent.CTRL_DOWN_MASK));
        stop.addActionListener(e -> controller.stopScan());
        menu.add(stop);

        return menu;
    }

    private JMenu buildExportMenu() {
        JMenu menu = new JMenu("Export");
        menu.setMnemonic(KeyEvent.VK_E);

        JMenuItem exportFindings = new JMenuItem("Export Findings...");
        exportFindings.setAccelerator(
                KeyStroke.getKeyStroke(KeyEvent.VK_E, InputEvent.CTRL_DOWN_MASK | InputEvent.SHIFT_DOWN_MASK));
        exportFindings.addActionListener(e -> openExportDialog());
        menu.add(exportFindings);

        return menu;
    }

    private JMenu buildViewMenu() {
        JMenu menu = new JMenu("View");
        menu.setMnemonic(KeyEvent.VK_V);

        JMenuItem privacyItem = new JMenuItem("Toggle Privacy Mode");
        privacyItem.setAccelerator(
                KeyStroke.getKeyStroke(KeyEvent.VK_P, InputEvent.CTRL_DOWN_MASK | InputEvent.SHIFT_DOWN_MASK));
        privacyItem.addActionListener(e -> PrivacyFilter.toggle());
        menu.add(privacyItem);

        JMenuItem toggleTheme = new JMenuItem("Toggle Theme");
        toggleTheme.setAccelerator(
                KeyStroke.getKeyStroke(KeyEvent.VK_T, InputEvent.CTRL_DOWN_MASK | InputEvent.SHIFT_DOWN_MASK));
        toggleTheme.addActionListener(e -> {
            AnarCryLaf.toggle();
            SwingUtilities.updateComponentTreeUI(frame);
        });
        menu.add(toggleTheme);

        menu.addSeparator();

        JMenuItem prefs = new JMenuItem("Preferences...");
        prefs.addActionListener(e -> new PreferencesDialog(frame).setVisible(true));
        menu.add(prefs);

        return menu;
    }

    private JMenu buildHelpMenu() {
        JMenu menu = new JMenu("Help");
        menu.setMnemonic(KeyEvent.VK_H);

        JMenuItem about = new JMenuItem("About AnarCry");
        about.addActionListener(e -> JOptionPane.showMessageDialog(frame,
                "AnarCry v1.3\nSecurity Scanner\nAuthorized testing only.", "About", JOptionPane.INFORMATION_MESSAGE));
        menu.add(about);

        return menu;
    }

    private void resetSeverityCounts() {
        for (Severity s : Severity.values()) {
            severityCounts.put(s, 0);
        }
    }

    private void incrementSeverityCount(Severity severity) {
        SwingUtilities.invokeLater(() -> {
            severityCounts.merge(severity, 1, Integer::sum);
            statusBar.setSeverityCounts(severityCounts.getOrDefault(Severity.CRITICAL, 0),
                    severityCounts.getOrDefault(Severity.HIGH, 0), severityCounts.getOrDefault(Severity.MEDIUM, 0),
                    severityCounts.getOrDefault(Severity.LOW, 0));
        });
    }

    private void dispose() {
        if (frame != null) {
            frame.dispose();
        }
    }
}
