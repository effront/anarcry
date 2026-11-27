package gg.effront.anarcry.tui.panels;

import com.googlecode.lanterna.TerminalSize;
import com.googlecode.lanterna.gui2.Button;
import com.googlecode.lanterna.gui2.CheckBox;
import com.googlecode.lanterna.gui2.ComboBox;
import com.googlecode.lanterna.gui2.Direction;
import com.googlecode.lanterna.gui2.EmptySpace;
import com.googlecode.lanterna.gui2.Label;
import com.googlecode.lanterna.gui2.LinearLayout;
import com.googlecode.lanterna.gui2.Panel;
import gg.effront.anarcry.model.AuthType;
import gg.effront.anarcry.model.RequestRecord;
import gg.effront.anarcry.scanner.DiscoveredPaths;
import gg.effront.anarcry.scanner.ScanConfig;
import gg.effront.anarcry.scanner.ScanContext;
import gg.effront.anarcry.scanner.ScanRunner;
import gg.effront.anarcry.scanner.SuppressionLoader;
import gg.effront.anarcry.scanner.util.TargetUtil;
import gg.effront.anarcry.scanner.auth.AuthException;
import gg.effront.anarcry.scanner.auth.CredentialStore;
import gg.effront.anarcry.scanner.auth.ProviderDetector;
import gg.effront.anarcry.scanner.auth.harvester.Harvester;
import gg.effront.anarcry.scanner.auth.harvester.HarvesterRegistry;
import gg.effront.anarcry.scanner.util.WafState;
import gg.effront.anarcry.tui.PasteableTextBox;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;

import java.util.Optional;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;

public class ModulesPanel extends Panel {

    private LogPanel logPanel;
    private final ScanRunner scanRunner;
    private Consumer<RequestRecord> requestLogCb = r -> {
    };
    private final CheckBox tlsCheck;
    private final CheckBox headersCheck;
    private final CheckBox jwtCheck;
    private final CheckBox pqcCheck;
    private final CheckBox corsCheck;
    private final CheckBox oauthCheck;
    private final CheckBox openRedirectCheck;
    private final CheckBox ssrfCheck;
    private final CheckBox graphqlCheck;
    private final CheckBox crlfCheck;
    private final CheckBox xxeCheck;
    private final CheckBox sstiCheck;
    private final CheckBox idorCheck;
    private final CheckBox hostHeaderCheck;
    private final CheckBox actuatorCheck;
    private final CheckBox massAssignCheck;
    private final CheckBox crawlerCheck;
    private final CheckBox hstsCheck;
    private final CheckBox cachePoisoningCheck;
    private final CheckBox reqSmugglingCheck;
    private final CheckBox infraCheck;
    private final CheckBox sqliCheck;
    private final CheckBox xssCheck;
    private final CheckBox lfiCheck;
    private final CheckBox cmdInjectionCheck;
    private final CheckBox csrfCheck;
    private final CheckBox secretsCheck;
    private final CheckBox raceConditionCheck;
    private final CheckBox nosqliCheck;
    private final CheckBox deserializationCheck;
    private final CheckBox fileUploadCheck;
    private final CheckBox subTakeoverCheck;
    private final CheckBox webSocketCheck;
    private final CheckBox protoPollutionCheck;
    private final CheckBox cloudMisconfigCheck;
    private final CheckBox frameworkConfigCheck;
    private final CheckBox jsAnalyzerCheck;
    private final CheckBox domSinksCheck;
    private final CheckBox backendLivenessCheck;
    private final CheckBox clickjackingCheck;
    private final CheckBox rateLimitCheck;
    private final CheckBox emailSecCheck;
    private final CheckBox clerkCheck;
    private final CheckBox errorDisclosureCheck;
    private final CheckBox exploitationCheck;
    private final List<CheckBox> allModuleChecks = new ArrayList<>();
    private final PasteableTextBox targetBox;
    private final PasteableTextBox jwtTokenBox;
    private final PasteableTextBox jwtToken2Box;
    private final PasteableTextBox concurrencyBox;
    private final ComboBox<String> authTypeCombo;
    private AuthType selectedAuthType = AuthType.NONE;
    private final Label cred1Label;
    private final Label cred2Label;

    public ModulesPanel(int width, LogPanel logPanel, FindingsPanel findingsPanel, ScanRunner scanRunner) {
        super(new LinearLayout(Direction.VERTICAL));
        this.logPanel = logPanel;
        this.scanRunner = scanRunner;

        setPreferredSize(new TerminalSize(width, 48));

        addComponent(new EmptySpace(new TerminalSize(1, 1)));

        crawlerCheck = new CheckBox("Crawler");
        crawlerCheck.setChecked(true);
        infraCheck = new CheckBox(infraLabel());
        infraCheck.setChecked(false);

        tlsCheck = new CheckBox("TLS");
        tlsCheck.setChecked(true);
        headersCheck = new CheckBox("Headers");
        headersCheck.setChecked(true);
        hstsCheck = new CheckBox("HSTS");
        hstsCheck.setChecked(true);
        jwtCheck = new CheckBox("JWT");
        pqcCheck = new CheckBox("PQC");

        corsCheck = new CheckBox("CORS");
        corsCheck.setChecked(true);
        oauthCheck = new CheckBox("OAuth");
        openRedirectCheck = new CheckBox("OpenRedirect");
        ssrfCheck = new CheckBox("SSRF");
        graphqlCheck = new CheckBox("GraphQL");
        crlfCheck = new CheckBox("CRLF");
        xxeCheck = new CheckBox("XXE");
        sstiCheck = new CheckBox("SSTI");
        idorCheck = new CheckBox("IDOR (needs 2 tokens)");
        hostHeaderCheck = new CheckBox("HostHeader");
        actuatorCheck = new CheckBox("Actuator");
        massAssignCheck = new CheckBox("MassAssign");
        cachePoisoningCheck = new CheckBox("CachePoisoning");
        reqSmugglingCheck = new CheckBox("ReqSmuggling");
        sqliCheck = new CheckBox("SQLi");
        xssCheck = new CheckBox("XSS");
        lfiCheck = new CheckBox("LFI");
        cmdInjectionCheck = new CheckBox("CmdInjection");
        csrfCheck = new CheckBox("CSRF");
        secretsCheck = new CheckBox("Secrets");
        raceConditionCheck = new CheckBox("RaceCondition (destructive)");
        nosqliCheck = new CheckBox("NoSQLi");
        deserializationCheck = new CheckBox("Deserialization");
        fileUploadCheck = new CheckBox("FileUpload (destructive)");
        subTakeoverCheck = new CheckBox("SubTakeover");
        webSocketCheck = new CheckBox("WebSocket");
        protoPollutionCheck = new CheckBox("ProtoPollution");
        cloudMisconfigCheck = new CheckBox("CloudMisconfig");
        frameworkConfigCheck = new CheckBox("FrameworkConfig");
        jsAnalyzerCheck = new CheckBox("JsAnalyzer");
        domSinksCheck = new CheckBox("DomSinks");
        backendLivenessCheck = new CheckBox("BackendLiveness");
        clickjackingCheck = new CheckBox("Clickjacking");
        rateLimitCheck = new CheckBox("RateLimit");
        emailSecCheck = new CheckBox("EmailSec");
        clerkCheck = new CheckBox("Clerk");
        errorDisclosureCheck = new CheckBox("ErrorDisclosure");

        allModuleChecks.addAll(List.of(crawlerCheck, infraCheck, tlsCheck, headersCheck, hstsCheck, jwtCheck, pqcCheck,
                corsCheck, oauthCheck, openRedirectCheck, ssrfCheck, graphqlCheck, crlfCheck, xxeCheck, sstiCheck,
                idorCheck, hostHeaderCheck, actuatorCheck, massAssignCheck, cachePoisoningCheck, reqSmugglingCheck,
                sqliCheck, xssCheck, lfiCheck, cmdInjectionCheck, csrfCheck, secretsCheck, raceConditionCheck,
                nosqliCheck, deserializationCheck, fileUploadCheck, subTakeoverCheck, webSocketCheck,
                protoPollutionCheck, cloudMisconfigCheck, frameworkConfigCheck, jsAnalyzerCheck, domSinksCheck,
                backendLivenessCheck, clickjackingCheck, rateLimitCheck, emailSecCheck, clerkCheck,
                errorDisclosureCheck));

        Label selectLabel = new Label("Select modules:");
        selectLabel.setForegroundColor(com.googlecode.lanterna.TextColor.ANSI.WHITE);
        addComponent(selectLabel);
        Panel togglePanel = new Panel(new LinearLayout(Direction.HORIZONTAL));
        Button allBtn = new Button("all", () -> allModuleChecks.forEach(c -> c.setChecked(true)));
        Button noneBtn = new Button("none", () -> allModuleChecks.forEach(c -> c.setChecked(false)));
        Button passiveBtn = new Button("passive", this::selectPassiveOnly);
        Button reconBtn = new Button("recon", this::selectRecon);
        Button injectBtn = new Button("inject", this::selectInject);
        Button apiBtn = new Button("api", this::selectApi);
        Button infraBtn = new Button("infra", this::selectInfra);
        Button owaspBtn = new Button("owasp", this::selectOwasp);
        togglePanel.addComponent(allBtn);
        togglePanel.addComponent(new Label("|"));
        togglePanel.addComponent(noneBtn);
        togglePanel.addComponent(new Label("|"));
        togglePanel.addComponent(passiveBtn);
        togglePanel.addComponent(new Label("|"));
        togglePanel.addComponent(reconBtn);
        togglePanel.addComponent(new Label("|"));
        togglePanel.addComponent(injectBtn);
        togglePanel.addComponent(new Label("|"));
        togglePanel.addComponent(apiBtn);
        togglePanel.addComponent(new Label("|"));
        togglePanel.addComponent(infraBtn);
        togglePanel.addComponent(new Label("|"));
        togglePanel.addComponent(owaspBtn);
        addComponent(togglePanel);

        addComponent(new EmptySpace(new TerminalSize(1, 1)));
        Label reconLabel = new Label("── RECON ───────────────");
        reconLabel.setForegroundColor(com.googlecode.lanterna.TextColor.ANSI.CYAN);
        addComponent(reconLabel);
        addComponent(crawlerCheck);
        addComponent(infraCheck);
        addComponent(backendLivenessCheck);
        addComponent(clickjackingCheck);

        addComponent(new EmptySpace(new TerminalSize(1, 1)));
        Label cryptoLabel = new Label("── CRYPTO ──────────────");
        cryptoLabel.setForegroundColor(com.googlecode.lanterna.TextColor.ANSI.BLUE);
        addComponent(cryptoLabel);
        addComponent(tlsCheck);
        addComponent(headersCheck);
        addComponent(hstsCheck);
        addComponent(jwtCheck);
        addComponent(pqcCheck);

        addComponent(new EmptySpace(new TerminalSize(1, 1)));
        Label injLabel = new Label("── INJECTION ───────────");
        injLabel.setForegroundColor(com.googlecode.lanterna.TextColor.ANSI.YELLOW);
        addComponent(injLabel);
        addComponent(sqliCheck);
        addComponent(nosqliCheck);
        addComponent(xssCheck);
        addComponent(sstiCheck);
        addComponent(cmdInjectionCheck);
        addComponent(crlfCheck);
        addComponent(xxeCheck);
        addComponent(lfiCheck);

        addComponent(new EmptySpace(new TerminalSize(1, 1)));
        Label authLabel = new Label("── AUTH & ACCESS ───────");
        authLabel.setForegroundColor(com.googlecode.lanterna.TextColor.ANSI.MAGENTA);
        addComponent(authLabel);
        addComponent(oauthCheck);
        addComponent(idorCheck);
        addComponent(csrfCheck);
        addComponent(massAssignCheck);
        addComponent(rateLimitCheck);
        addComponent(clerkCheck);

        addComponent(new EmptySpace(new TerminalSize(1, 1)));
        Label httpLabel = new Label("── HTTP & TRANSPORT ────");
        httpLabel.setForegroundColor(com.googlecode.lanterna.TextColor.ANSI.CYAN);
        addComponent(httpLabel);
        addComponent(corsCheck);
        addComponent(hostHeaderCheck);
        addComponent(cachePoisoningCheck);
        addComponent(reqSmugglingCheck);
        addComponent(openRedirectCheck);
        addComponent(ssrfCheck);
        addComponent(graphqlCheck);
        addComponent(webSocketCheck);

        addComponent(new EmptySpace(new TerminalSize(1, 1)));
        Label cfgLabel = new Label("── CONFIG & EXPOSURE ───");
        cfgLabel.setForegroundColor(com.googlecode.lanterna.TextColor.ANSI.GREEN);
        addComponent(cfgLabel);
        addComponent(secretsCheck);
        addComponent(frameworkConfigCheck);
        addComponent(jsAnalyzerCheck);
        addComponent(domSinksCheck);
        addComponent(protoPollutionCheck);
        addComponent(errorDisclosureCheck);
        addComponent(emailSecCheck);
        addComponent(actuatorCheck);
        addComponent(cloudMisconfigCheck);
        addComponent(subTakeoverCheck);

        addComponent(new EmptySpace(new TerminalSize(1, 1)));
        Label destLabel = new Label("── DESTRUCTIVE ─────────");
        destLabel.setForegroundColor(com.googlecode.lanterna.TextColor.ANSI.RED);
        addComponent(destLabel);
        addComponent(raceConditionCheck);
        addComponent(deserializationCheck);
        addComponent(fileUploadCheck);

        addComponent(new EmptySpace(new TerminalSize(1, 1)));
        Label postLabel = new Label("── POST-SCAN ───────────");
        postLabel.setForegroundColor(com.googlecode.lanterna.TextColor.ANSI.MAGENTA);
        addComponent(postLabel);
        exploitationCheck = new CheckBox("Exploitation (validate findings)");
        exploitationCheck.setChecked(false);
        addComponent(exploitationCheck);

        addComponent(new EmptySpace(new TerminalSize(1, 1)));
        addComponent(new Label("─".repeat(width - 2)));

        addComponent(new EmptySpace(new TerminalSize(1, 1)));
        addComponent(new Label("Target:"));
        targetBox = new PasteableTextBox(new TerminalSize(width - 2, 1));
        targetBox.setText("https://");
        addComponent(targetBox);

        addComponent(new EmptySpace(new TerminalSize(1, 1)));
        addComponent(new Label("Auth Type:"));
        authTypeCombo = new ComboBox<>("None", "JWT", "Cookie", "Bearer", "Auto");
        authTypeCombo.setReadOnly(true);
        authTypeCombo.setSelectedIndex(0);
        authTypeCombo.addListener((selectedIndex, previousSelection, changedByUserInteraction) -> {
            selectedAuthType = AuthType.values()[selectedIndex];
            updateCredentialLabels();
        });
        addComponent(authTypeCombo);

        addComponent(new EmptySpace(new TerminalSize(1, 1)));
        cred1Label = new Label("Credential 1:");
        addComponent(cred1Label);
        jwtTokenBox = new PasteableTextBox(new TerminalSize(width - 2, 2));
        addComponent(jwtTokenBox);

        addComponent(new EmptySpace(new TerminalSize(1, 1)));
        cred2Label = new Label("Credential 2:");
        addComponent(cred2Label);
        jwtToken2Box = new PasteableTextBox(new TerminalSize(width - 2, 2));
        addComponent(jwtToken2Box);

        addComponent(new EmptySpace(new TerminalSize(1, 1)));
        addComponent(new Label("Probe Concurrency:"));
        concurrencyBox = new PasteableTextBox(new TerminalSize(6, 1));
        concurrencyBox.setText(String.valueOf(ScanConfig.DEFAULT_PROBE_CONCURRENCY));
        addComponent(concurrencyBox);

        addComponent(new EmptySpace(new TerminalSize(1, 1)));
        addComponent(new Label("─".repeat(width - 2)));
        addComponent(new EmptySpace(new TerminalSize(1, 1)));

        addComponent(new Button("Iniciar", this::onStart));
        addComponent(new EmptySpace(new TerminalSize(1, 1)));
        addComponent(new Button("Parar", () -> {
            scanRunner.shutdown();
            logPanel.log("[*] Scan interrompido");
        }));
    }

    public void updateLogPanel(LogPanel newLogPanel) {
        this.logPanel = newLogPanel;
    }

    public String getTarget() {
        return targetBox.getText().trim();
    }

    public String getJwt() {
        return jwtTokenBox.getText().trim();
    }

    public AuthType getAuthType() {
        return selectedAuthType;
    }

    public void setTarget(String target) {
        targetBox.setText(target);
    }

    public void setJwt(String jwt) {
        if (jwt != null && !jwt.isBlank()) {
            jwtTokenBox.setText(jwt);
            if (selectedAuthType == AuthType.NONE) {
                selectedAuthType = AuthType.JWT;
                authTypeCombo.setSelectedIndex(AuthType.JWT.ordinal());
                updateCredentialLabels();
            }
        }
    }

    public void setJwt2(String jwt2) {
        if (jwt2 != null && !jwt2.isBlank()) {
            jwtToken2Box.setText(jwt2);
        }
    }

    public void setRequestLogCb(Consumer<RequestRecord> cb) {
        this.requestLogCb = cb != null ? cb : r -> {
        };
    }

    public void triggerStart() {
        onStart();
    }

    private void updateCredentialLabels() {
        switch (selectedAuthType) {
            case NONE -> {
                cred1Label.setText("Credential 1:");
                cred2Label.setText("Credential 2:");
            }
            case JWT -> {
                cred1Label.setText("JWT Token (user 1):");
                cred2Label.setText("JWT Token 2 (IDOR):");
            }
            case COOKIE -> {
                cred1Label.setText("Session Cookie:");
                cred2Label.setText("Session Cookie 2:");
            }
            case BEARER -> {
                cred1Label.setText("Bearer Token:");
                cred2Label.setText("Bearer Token 2 (IDOR):");
            }
            case AUTO -> {
                cred1Label.setText("Email (or Refresh Token):");
                cred2Label.setText("Password (blank if token):");
            }
        }
    }

    private static String infraLabel() {
        if (!nmapOnPath()) {
            return "Infra (port scan)";
        }
        return rootProcess() ? "Infra (port scan) [nmap+SYN]" : "Infra (port scan) [nmap]";
    }

    private static boolean nmapOnPath() {
        try {
            Process p = new ProcessBuilder("nmap", "--version").start();
            boolean done = p.waitFor(5, TimeUnit.SECONDS);
            return done && p.exitValue() == 0;
        } catch (Exception e) {
            return false;
        }
    }

    private static boolean rootProcess() {
        try {
            for (String line : Files.readAllLines(Path.of("/proc/self/status"))) {
                if (line.startsWith("Uid:")) {
                    return "0".equals(line.split("\\s+")[1]);
                }
            }
        } catch (Exception ignored) {
        }
        return false;
    }

    private void selectPassiveOnly() {
        Set<CheckBox> passive = Set.of(crawlerCheck, tlsCheck, headersCheck, hstsCheck, corsCheck);
        allModuleChecks.forEach(c -> c.setChecked(passive.contains(c)));
    }

    private void selectRecon() {
        Set<CheckBox> recon = Set.of(crawlerCheck, tlsCheck, headersCheck, hstsCheck, corsCheck, secretsCheck,
                frameworkConfigCheck, jsAnalyzerCheck, domSinksCheck, backendLivenessCheck, clickjackingCheck,
                subTakeoverCheck);
        allModuleChecks.forEach(c -> c.setChecked(recon.contains(c)));
    }

    private void selectInject() {
        Set<CheckBox> inject = Set.of(crawlerCheck, sqliCheck, nosqliCheck, xssCheck, sstiCheck, lfiCheck,
                cmdInjectionCheck, xxeCheck, crlfCheck, deserializationCheck, protoPollutionCheck);
        allModuleChecks.forEach(c -> c.setChecked(inject.contains(c)));
    }

    private void selectApi() {
        Set<CheckBox> api = Set.of(crawlerCheck, graphqlCheck, corsCheck, jwtCheck, oauthCheck, idorCheck,
                massAssignCheck, rateLimitCheck, ssrfCheck, secretsCheck, errorDisclosureCheck, clerkCheck);
        allModuleChecks.forEach(c -> c.setChecked(api.contains(c)));
    }

    private void selectInfra() {
        Set<CheckBox> infra = Set.of(crawlerCheck, tlsCheck, headersCheck, hstsCheck, pqcCheck, actuatorCheck,
                hostHeaderCheck, cloudMisconfigCheck, frameworkConfigCheck, emailSecCheck, subTakeoverCheck,
                infraCheck);
        allModuleChecks.forEach(c -> c.setChecked(infra.contains(c)));
    }

    private void selectOwasp() {
        Set<CheckBox> owasp = Set.of(crawlerCheck, sqliCheck, xssCheck, ssrfCheck, xxeCheck, cmdInjectionCheck,
                sstiCheck, corsCheck, jwtCheck, oauthCheck, idorCheck, csrfCheck, headersCheck, hstsCheck,
                actuatorCheck, massAssignCheck, deserializationCheck);
        allModuleChecks.forEach(c -> c.setChecked(owasp.contains(c)));
    }

    private void onStart() {
        String target = TargetUtil.sanitizeTarget(targetBox.getText());
        if (target.isBlank() || target.equals("https://")) {
            logPanel.log("[!] Target nao informado");
            return;
        }
        targetBox.setText(target);

        Set<String> modules = new LinkedHashSet<>();
        if (tlsCheck.isChecked()) {
            modules.add("TLS");
        }
        if (headersCheck.isChecked()) {
            modules.add("Headers");
        }
        if (jwtCheck.isChecked()) {
            modules.add("JWT");
        }
        if (pqcCheck.isChecked()) {
            modules.add("PQC");
        }
        if (corsCheck.isChecked()) {
            modules.add("CORS");
        }
        if (oauthCheck.isChecked()) {
            modules.add("OAuth");
        }
        if (openRedirectCheck.isChecked()) {
            modules.add("OpenRedirect");
        }
        if (ssrfCheck.isChecked()) {
            modules.add("SSRF");
        }
        if (graphqlCheck.isChecked()) {
            modules.add("GraphQL");
        }
        if (crlfCheck.isChecked()) {
            modules.add("CRLF");
        }
        if (xxeCheck.isChecked()) {
            modules.add("XXE");
        }
        if (sstiCheck.isChecked()) {
            modules.add("SSTI");
        }
        if (idorCheck.isChecked()) {
            modules.add("IDOR");
        }
        if (hostHeaderCheck.isChecked()) {
            modules.add("HostHeader");
        }
        if (actuatorCheck.isChecked()) {
            modules.add("Actuator");
        }
        if (massAssignCheck.isChecked()) {
            modules.add("MassAssign");
        }
        if (infraCheck.isChecked()) {
            modules.add("Infra");
        }
        if (crawlerCheck.isChecked()) {
            modules.add("Crawler");
        }
        if (hstsCheck.isChecked()) {
            modules.add("HSTS");
        }
        if (cachePoisoningCheck.isChecked()) {
            modules.add("CachePoisoning");
        }
        if (reqSmugglingCheck.isChecked()) {
            modules.add("ReqSmuggling");
        }
        if (sqliCheck.isChecked()) {
            modules.add("SQLi");
        }
        if (xssCheck.isChecked()) {
            modules.add("XSS");
        }
        if (lfiCheck.isChecked()) {
            modules.add("LFI");
        }
        if (cmdInjectionCheck.isChecked()) {
            modules.add("CmdInjection");
        }
        if (csrfCheck.isChecked()) {
            modules.add("CSRF");
        }
        if (secretsCheck.isChecked()) {
            modules.add("Secrets");
        }
        if (raceConditionCheck.isChecked()) {
            modules.add("RaceCondition");
        }
        if (nosqliCheck.isChecked()) {
            modules.add("NoSQLi");
        }
        if (deserializationCheck.isChecked()) {
            modules.add("Deserialization");
        }
        if (fileUploadCheck.isChecked()) {
            modules.add("FileUpload");
        }
        if (subTakeoverCheck.isChecked()) {
            modules.add("SubTakeover");
        }
        if (webSocketCheck.isChecked()) {
            modules.add("WebSocket");
        }
        if (protoPollutionCheck.isChecked()) {
            modules.add("ProtoPollution");
        }
        if (cloudMisconfigCheck.isChecked()) {
            modules.add("CloudMisconfig");
        }
        if (frameworkConfigCheck.isChecked()) {
            modules.add("FrameworkConfig");
        }
        if (jsAnalyzerCheck.isChecked()) {
            modules.add("JsAnalyzer");
        }
        if (domSinksCheck.isChecked()) {
            modules.add("DomSinks");
        }
        if (backendLivenessCheck.isChecked()) {
            modules.add("BackendLiveness");
        }
        if (clickjackingCheck.isChecked()) {
            modules.add("Clickjacking");
        }
        if (rateLimitCheck.isChecked()) {
            modules.add("RateLimit");
        }
        if (emailSecCheck.isChecked()) {
            modules.add("EmailSec");
        }
        if (clerkCheck.isChecked()) {
            modules.add("Clerk");
        }
        if (errorDisclosureCheck.isChecked()) {
            modules.add("ErrorDisclosure");
        }

        if (modules.isEmpty()) {
            logPanel.log("[!] Nenhum módulo selecionado");
            return;
        }

        String cred1 = jwtTokenBox.getText().trim();
        String cred2 = jwtToken2Box.getText().trim();
        int concurrency = ScanConfig.DEFAULT_PROBE_CONCURRENCY;
        try {
            concurrency = Integer.parseInt(concurrencyBox.getText().trim());
            if (concurrency < 1) {
                concurrency = 1;
            } else if (concurrency > 64) {
                concurrency = 64;
            }
        } catch (NumberFormatException ignored) {
            // keep default
        }
        boolean exploit = exploitationCheck.isChecked();
        boolean debug = logPanel.isDebugEnabled();
        logPanel.log("[*] Iniciando scan em " + target + " (auth=" + selectedAuthType + ", concurrency=" + concurrency
                + ", exploit=" + exploit + (debug ? ", debug=true" : "") + ") ...");

        CredentialStore credStore = null;
        String jwt = "";
        String jwt2 = "";
        String cookie = "";
        String cookie2 = "";

        if (selectedAuthType == AuthType.AUTO) {
            String username = cred1;
            String password = cred2;
            if (username.isBlank()) {
                logPanel.log("[!] AUTO requer email ou refresh token");
                return;
            }
            logPanel.log("[*] Detectando provider em " + target + " ...");
            ProviderDetector.DiscoveryResult discovery = ProviderDetector.detect(target);
            if (discovery == null) {
                logPanel.log("[!] Nenhum provider detectado em " + target);
                return;
            }
            logPanel.log("[+] Provider detectado: " + discovery.provider());
            Optional<Harvester> harvester = HarvesterRegistry.forProvider(discovery.provider());
            if (harvester.isEmpty()) {
                logPanel.log("[!] Sem harvester para " + discovery.provider());
                return;
            }
            try {
                logPanel.log("[*] Harvesting credentials via " + discovery.provider() + " ...");
                credStore = harvester.get().harvest(target, username, password, discovery.extra());
                logPanel.log("[+] Token obtido (expira em " + credStore.remainingSeconds() + "s)");
            } catch (AuthException e) {
                logPanel.log("[!] Harvest falhou: " + e.getMessage());
                return;
            }
        } else if (selectedAuthType.usesBearer()) {
            jwt = cred1;
            jwt2 = cred2;
        } else if (selectedAuthType.usesCookie()) {
            cookie = cred1;
            cookie2 = cred2;
        }

        ScanConfig cfg = new ScanConfig(0, cookie, cookie2, Set.of(), SuppressionLoader.loadFromCwd(), "", concurrency,
                exploit, null, debug);
        ScanContext ctx = new ScanContext(target, jwt, jwt2, modules, cfg, requestLogCb, new DiscoveredPaths(),
                new WafState(), credStore);
        scanRunner.run(ctx);
    }
}
