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
import gg.effront.anarcry.scanner.ScanConfig;
import gg.effront.anarcry.scanner.ScanContext;
import gg.effront.anarcry.scanner.ScanRunner;
import gg.effront.anarcry.scanner.SuppressionLoader;
import gg.effront.anarcry.tui.PasteableTextBox;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashSet;
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

        tlsCheck = new CheckBox("TLS");
        tlsCheck.setChecked(true);
        headersCheck = new CheckBox("Headers");
        headersCheck.setChecked(true);
        jwtCheck = new CheckBox("JWT");
        jwtCheck.setChecked(true);
        pqcCheck = new CheckBox("PQC");
        pqcCheck.setChecked(true);
        corsCheck = new CheckBox("CORS");
        corsCheck.setChecked(true);
        oauthCheck = new CheckBox("OAuth");
        oauthCheck.setChecked(true);
        openRedirectCheck = new CheckBox("OpenRedirect");
        openRedirectCheck.setChecked(true);
        ssrfCheck = new CheckBox("SSRF");
        ssrfCheck.setChecked(true);
        graphqlCheck = new CheckBox("GraphQL");
        graphqlCheck.setChecked(true);
        crlfCheck = new CheckBox("CRLF");
        crlfCheck.setChecked(true);
        xxeCheck = new CheckBox("XXE");
        xxeCheck.setChecked(true);
        sstiCheck = new CheckBox("SSTI");
        sstiCheck.setChecked(true);
        idorCheck = new CheckBox("IDOR");
        idorCheck.setChecked(false);
        hostHeaderCheck = new CheckBox("HostHeader");
        hostHeaderCheck.setChecked(true);
        actuatorCheck = new CheckBox("Actuator");
        actuatorCheck.setChecked(true);
        massAssignCheck = new CheckBox("MassAssign");
        massAssignCheck.setChecked(true);
        crawlerCheck = new CheckBox("Crawler");
        crawlerCheck.setChecked(true);
        hstsCheck = new CheckBox("HSTS");
        hstsCheck.setChecked(true);
        cachePoisoningCheck = new CheckBox("CachePoisoning");
        cachePoisoningCheck.setChecked(true);
        reqSmugglingCheck = new CheckBox("ReqSmuggling");
        reqSmugglingCheck.setChecked(true);
        infraCheck = new CheckBox(infraLabel());
        infraCheck.setChecked(false);
        sqliCheck = new CheckBox("SQLi");
        sqliCheck.setChecked(true);
        xssCheck = new CheckBox("XSS");
        xssCheck.setChecked(true);
        lfiCheck = new CheckBox("LFI");
        lfiCheck.setChecked(true);
        cmdInjectionCheck = new CheckBox("CmdInjection");
        cmdInjectionCheck.setChecked(true);

        Label reconLabel = new Label("── RECON ───────────────");
        reconLabel.setForegroundColor(com.googlecode.lanterna.TextColor.ANSI.CYAN);
        addComponent(reconLabel);
        addComponent(crawlerCheck);
        addComponent(infraCheck);

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
        Label webLabel = new Label("── WEB ─────────────────");
        webLabel.setForegroundColor(com.googlecode.lanterna.TextColor.ANSI.YELLOW);
        addComponent(webLabel);
        addComponent(corsCheck);
        addComponent(oauthCheck);
        addComponent(openRedirectCheck);
        addComponent(ssrfCheck);
        addComponent(graphqlCheck);
        addComponent(crlfCheck);
        addComponent(xxeCheck);
        addComponent(sstiCheck);
        addComponent(hostHeaderCheck);
        addComponent(actuatorCheck);
        addComponent(massAssignCheck);
        addComponent(cachePoisoningCheck);
        addComponent(reqSmugglingCheck);
        addComponent(sqliCheck);
        addComponent(xssCheck);
        addComponent(lfiCheck);
        addComponent(cmdInjectionCheck);
        addComponent(idorCheck);

        addComponent(new EmptySpace(new TerminalSize(1, 1)));
        addComponent(new Label("─".repeat(width - 2)));

        addComponent(new EmptySpace(new TerminalSize(1, 1)));
        addComponent(new Label("Target:"));
        targetBox = new PasteableTextBox(new TerminalSize(width - 2, 1));
        targetBox.setText("https://");
        addComponent(targetBox);

        addComponent(new EmptySpace(new TerminalSize(1, 1)));
        addComponent(new Label("Auth Type:"));
        authTypeCombo = new ComboBox<>("None", "JWT", "Cookie", "Bearer");
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
        }
    }

    private static String infraLabel() {
        if (!nmapOnPath()) {
            return "Infra";
        }
        return rootProcess() ? "Infra [nmap+SYN]" : "Infra [nmap]";
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

    private void onStart() {
        String target = targetBox.getText().trim();
        if (target.isBlank() || target.equals("https://")) {
            logPanel.log("[!] Target não informado");
            return;
        }

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
        logPanel.log("[*] Iniciando scan em " + target + " (auth=" + selectedAuthType + ", concurrency=" + concurrency
                + ") ...");
        ScanContext baseCtx = selectedAuthType.buildContext(target, modules, cred1, cred2, requestLogCb);
        ScanConfig cfg = new ScanConfig(0, selectedAuthType.usesCookie() ? cred1 : "", java.util.Set.of(),
                SuppressionLoader.loadFromCwd(), "", concurrency);
        scanRunner.run(new ScanContext(baseCtx.targetUrl(), baseCtx.jwtToken(), baseCtx.jwtToken2(), modules, cfg,
                requestLogCb, baseCtx.discoveredPaths(), baseCtx.wafState()));
    }
}
