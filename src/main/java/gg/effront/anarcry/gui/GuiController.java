package gg.effront.anarcry.gui;

import gg.effront.anarcry.model.AuthType;
import gg.effront.anarcry.model.Finding;
import gg.effront.anarcry.model.RequestRecord;
import gg.effront.anarcry.scanner.DiscoveredPaths;
import gg.effront.anarcry.scanner.ScanConfig;
import gg.effront.anarcry.scanner.ScanContext;
import gg.effront.anarcry.scanner.ScanEvent;
import gg.effront.anarcry.scanner.ScanRunner;
import gg.effront.anarcry.scanner.SuppressionLoader;
import gg.effront.anarcry.scanner.auth.AuthException;
import gg.effront.anarcry.scanner.auth.CredentialStore;
import gg.effront.anarcry.scanner.auth.ProviderDetector;
import gg.effront.anarcry.scanner.auth.harvester.Harvester;
import gg.effront.anarcry.scanner.auth.harvester.HarvesterRegistry;
import gg.effront.anarcry.scanner.util.WafState;

import java.util.Optional;
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
    private volatile Set<String> scopeHosts = Set.of();
    private volatile String sessionCookie = "";

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
        startScan(target, authType, cred1, cred2, modules, requestLogCb, false, false);
    }

    public void startScan(String target, AuthType authType, String cred1, String cred2, Set<String> modules,
            Consumer<RequestRecord> requestLogCb, boolean exploitationEnabled) {
        startScan(target, authType, cred1, cred2, modules, requestLogCb, exploitationEnabled, false);
    }

    public void startScan(String target, AuthType authType, String cred1, String cred2, Set<String> modules,
            Consumer<RequestRecord> requestLogCb, boolean exploitationEnabled, boolean debugMode) {

        if (target == null || target.isBlank() || "https://".equals(target)) {
            logCb.accept("[!] Target nao informado");
            return;
        }

        if (modules == null || modules.isEmpty()) {
            logCb.accept("[!] Nenhum modulo selecionado");
            return;
        }

        CredentialStore credStore = null;
        String jwt = "";
        String jwt2 = "";
        String cookie = "";
        String cookie2 = "";

        if (authType == AuthType.AUTO) {
            String username = cred1 != null ? cred1 : "";
            String password = cred2 != null ? cred2 : "";
            if (username.isBlank()) {
                logCb.accept("[!] AUTO requer email ou refresh token");
                return;
            }
            logCb.accept("[*] Detectando provider em " + target + " ...");
            ProviderDetector.DiscoveryResult discovery = ProviderDetector.detect(target);
            if (discovery == null) {
                logCb.accept("[!] Nenhum provider detectado em " + target);
                return;
            }
            logCb.accept("[+] Provider detectado: " + discovery.provider());
            Optional<Harvester> harvester = HarvesterRegistry.forProvider(discovery.provider());
            if (harvester.isEmpty()) {
                logCb.accept("[!] Sem harvester para " + discovery.provider());
                return;
            }
            try {
                logCb.accept("[*] Harvesting credentials via " + discovery.provider() + " ...");
                credStore = harvester.get().harvest(target, username, password, discovery.extra());
                logCb.accept("[+] Token obtido (expira em " + credStore.remainingSeconds() + "s)");
            } catch (AuthException e) {
                logCb.accept("[!] Harvest falhou: " + e.getMessage());
                return;
            }
        } else if (authType.usesBearer()) {
            jwt = cred1 != null ? cred1 : "";
            jwt2 = cred2 != null ? cred2 : "";
        } else if (authType.usesCookie()) {
            cookie = cred1 != null ? cred1 : "";
            cookie2 = cred2 != null ? cred2 : "";
        }

        if (!sessionCookie.isEmpty()) {
            cookie = sessionCookie;
        }
        ScanConfig cfg = new ScanConfig(0, cookie, cookie2, scopeHosts, SuppressionLoader.loadFromCwd(), "",
                ScanConfig.DEFAULT_PROBE_CONCURRENCY, exploitationEnabled, null, debugMode);
        ScanContext ctx = new ScanContext(target, jwt, jwt2, modules, cfg, requestLogCb, new DiscoveredPaths(),
                new WafState(), credStore);
        lastScanContext = ctx;
        scanRunner.run(ctx);
    }

    public void setScopeHosts(Set<String> hosts) {
        this.scopeHosts = hosts != null ? Set.copyOf(hosts) : Set.of();
    }

    public void setSessionCookie(String cookie) {
        this.sessionCookie = cookie != null ? cookie : "";
    }

    /** Requests immediate cancellation of any running scan. */
    public void stopScan() {
        scanRunner.shutdown();
        logCb.accept("[*] Scan interrompido");
    }

    /** Returns the last scan context, or null if no scan ran. */
    public ScanContext getLastContext() {
        return lastScanContext;
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
