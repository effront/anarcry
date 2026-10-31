package gg.effront.anarcry.gui;

import gg.effront.anarcry.model.AuthType;
import gg.effront.anarcry.model.Finding;
import gg.effront.anarcry.model.RequestRecord;
import gg.effront.anarcry.scanner.DiscoveredPaths;
import gg.effront.anarcry.scanner.ScanContext;
import gg.effront.anarcry.scanner.ScanEvent;
import gg.effront.anarcry.scanner.ScanOrchestrator;
import gg.effront.anarcry.scanner.ScanRunner;

import java.util.Set;
import java.util.function.Consumer;

/**
 * Mediator between the GUI layer and the scanner engine. Connects scanner
 * callbacks (log, finding, event) to GUI components without creating or owning
 * any Swing widgets itself.
 *
 * <p>
 * All scanner callbacks may fire from background threads; the GUI consumers are
 * expected to handle thread-safety (e.g. {@code SwingUtilities.invokeLater}) on
 * their own.
 */
public class GuiController {

    private final ScanRunner scanRunner;
    private final Consumer<String> logCb;
    private final Consumer<Finding> findingCb;
    private volatile ScanContext lastScanContext;

    /**
     * Creates a controller wired to the given GUI callbacks.
     *
     * @param logCb
     *            receives log lines (prefixed {@code [~]}, {@code [+]},
     *            {@code [!]}, etc.)
     * @param findingCb
     *            receives each deduplicated, non-suppressed finding
     */
    public GuiController(Consumer<String> logCb, Consumer<Finding> findingCb) {
        this.logCb = logCb;
        this.findingCb = findingCb;
        this.scanRunner = new ScanRunner(logCb, findingCb);
    }

    /**
     * Registers a callback for scan lifecycle events (module start/done, scan
     * start/done).
     */
    public void setOnScanEvent(Consumer<ScanEvent> cb) {
        scanRunner.setOnScanEvent(cb);
    }

    /** Registers a callback invoked when the scan begins executing. */
    public void setOnScanStart(Runnable r) {
        scanRunner.setOnScanStart(r);
    }

    /** Registers a callback invoked when the scan finishes (success or error). */
    public void setOnScanFinish(Runnable r) {
        scanRunner.setOnScanFinish(r);
    }

    /**
     * Validates inputs and starts a scan with the given parameters.
     *
     * @param target
     *            full target URL (e.g. {@code https://example.com})
     * @param authType
     *            authentication type (NONE, JWT, COOKIE, BEARER)
     * @param cred1
     *            primary credential (JWT token, cookie, or bearer token -- may be
     *            empty)
     * @param cred2
     *            secondary credential for IDOR testing (may be empty)
     * @param modules
     *            set of enabled module IDs (e.g. {@code "SQLi"}, {@code "TLS"})
     * @param requestLogCb
     *            consumer that receives every HTTP request/response record
     */
    public void startScan(String target, AuthType authType, String cred1, String cred2, Set<String> modules,
            Consumer<RequestRecord> requestLogCb) {

        if (target == null || target.isBlank() || "https://".equals(target)) {
            logCb.accept("[!] Target nao informado");
            return;
        }

        if (modules == null || modules.isEmpty()) {
            logCb.accept("[!] Nenhum modulo selecionado");
            return;
        }

        ScanContext ctx = ScanOrchestrator.buildContext(authType, target, cred1, cred2, modules, requestLogCb);
        lastScanContext = ctx;
        scanRunner.run(ctx);
    }

    /** Requests immediate cancellation of any running scan. */
    public void stopScan() {
        scanRunner.shutdown();
        logCb.accept("[*] Scan interrompido");
    }

    /** Returns discovered paths from the last scan, or null if no scan ran. */
    public DiscoveredPaths getDiscoveredPaths() {
        ScanContext ctx = lastScanContext;
        return ctx != null ? ctx.discoveredPaths() : null;
    }

    /** Returns the underlying {@link ScanRunner} for advanced usage or testing. */
    public ScanRunner getScanRunner() {
        return scanRunner;
    }
}
