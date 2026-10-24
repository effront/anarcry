package gg.effront.anarcry.tui.panels;

import com.googlecode.lanterna.TerminalSize;
import com.googlecode.lanterna.gui2.*;
import gg.effront.anarcry.model.RequestRecord;
import gg.effront.anarcry.scanner.ScanContext;
import gg.effront.anarcry.scanner.ScanRunner;
import gg.effront.anarcry.tui.PasteableTextBox;

import java.util.LinkedHashSet;
import java.util.Set;
import java.util.function.Consumer;

public class ModulesPanel extends Panel {

    private LogPanel logPanel;
    private final ScanRunner scanRunner;
    private Consumer<RequestRecord> requestLogCb = r -> {};
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
    private final PasteableTextBox targetBox;
    private final PasteableTextBox jwtTokenBox;
    private final PasteableTextBox jwtToken2Box;

    public ModulesPanel(int width, LogPanel logPanel, FindingsPanel findingsPanel, ScanRunner scanRunner) {
        super(new LinearLayout(Direction.VERTICAL));
        this.logPanel    = logPanel;
        this.scanRunner  = scanRunner;

        setPreferredSize(new TerminalSize(width, 1));

        addComponent(new EmptySpace(new TerminalSize(1, 1)));

        tlsCheck     = new CheckBox("TLS");     tlsCheck.setChecked(true);
        headersCheck = new CheckBox("Headers"); headersCheck.setChecked(true);
        jwtCheck     = new CheckBox("JWT");     jwtCheck.setChecked(true);
        pqcCheck     = new CheckBox("PQC");     pqcCheck.setChecked(true);
        corsCheck         = new CheckBox("CORS");         corsCheck.setChecked(true);
        oauthCheck        = new CheckBox("OAuth");        oauthCheck.setChecked(true);
        openRedirectCheck = new CheckBox("OpenRedirect"); openRedirectCheck.setChecked(true);
        ssrfCheck         = new CheckBox("SSRF");         ssrfCheck.setChecked(true);
        graphqlCheck      = new CheckBox("GraphQL");      graphqlCheck.setChecked(true);
        crlfCheck         = new CheckBox("CRLF");         crlfCheck.setChecked(true);
        xxeCheck          = new CheckBox("XXE");          xxeCheck.setChecked(true);
        sstiCheck         = new CheckBox("SSTI");         sstiCheck.setChecked(true);
        idorCheck         = new CheckBox("IDOR");         idorCheck.setChecked(false);
        hostHeaderCheck   = new CheckBox("HostHeader");   hostHeaderCheck.setChecked(true);
        actuatorCheck     = new CheckBox("Actuator");     actuatorCheck.setChecked(true);
        massAssignCheck   = new CheckBox("MassAssign");   massAssignCheck.setChecked(true);

        Label cryptoLabel = new Label("── CRYPTO ──────────────");
        cryptoLabel.setForegroundColor(com.googlecode.lanterna.TextColor.ANSI.BLUE);
        addComponent(cryptoLabel);
        addComponent(tlsCheck);
        addComponent(headersCheck);
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
        addComponent(idorCheck);
        addComponent(hostHeaderCheck);
        addComponent(actuatorCheck);
        addComponent(massAssignCheck);

        addComponent(new EmptySpace(new TerminalSize(1, 1)));
        addComponent(new Label("─".repeat(width - 2)));

        addComponent(new EmptySpace(new TerminalSize(1, 1)));
        addComponent(new Label("Target:"));
        targetBox = new PasteableTextBox(new TerminalSize(width - 2, 1));
        targetBox.setText("https://");
        addComponent(targetBox);

        addComponent(new EmptySpace(new TerminalSize(1, 1)));
        addComponent(new Label("JWT Token (user 1):"));
        jwtTokenBox = new PasteableTextBox(new TerminalSize(width - 2, 2));
        addComponent(jwtTokenBox);

        addComponent(new EmptySpace(new TerminalSize(1, 1)));
        addComponent(new Label("JWT Token 2 (IDOR):"));
        jwtToken2Box = new PasteableTextBox(new TerminalSize(width - 2, 2));
        addComponent(jwtToken2Box);

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

    public void updateLogPanel(LogPanel newLogPanel) { this.logPanel = newLogPanel; }

    public String getTarget() { return targetBox.getText().trim(); }

    public String getJwt() { return jwtTokenBox.getText().trim(); }

    public void setTarget(String target) { targetBox.setText(target); }

    public void setJwt(String jwt)   { if (jwt != null && !jwt.isBlank()) jwtTokenBox.setText(jwt); }

    public void setJwt2(String jwt2) { if (jwt2 != null && !jwt2.isBlank()) jwtToken2Box.setText(jwt2); }

    public void setRequestLogCb(Consumer<RequestRecord> cb) { this.requestLogCb = cb != null ? cb : r -> {}; }

    public void triggerStart() { onStart(); }

    private void onStart() {
        String target = targetBox.getText().trim();
        if (target.isBlank() || target.equals("https://")) {
            logPanel.log("[!] Target não informado");
            return;
        }

        String jwt = jwtTokenBox.getText().trim();

        Set<String> modules = new LinkedHashSet<>();
        if (tlsCheck.isChecked())     modules.add("TLS");
        if (headersCheck.isChecked()) modules.add("Headers");
        if (jwtCheck.isChecked())     modules.add("JWT");
        if (pqcCheck.isChecked())     modules.add("PQC");
        if (corsCheck.isChecked())         modules.add("CORS");
        if (oauthCheck.isChecked())        modules.add("OAuth");
        if (openRedirectCheck.isChecked()) modules.add("OpenRedirect");
        if (ssrfCheck.isChecked())         modules.add("SSRF");
        if (graphqlCheck.isChecked())      modules.add("GraphQL");
        if (crlfCheck.isChecked())         modules.add("CRLF");
        if (xxeCheck.isChecked())          modules.add("XXE");
        if (sstiCheck.isChecked())         modules.add("SSTI");
        if (idorCheck.isChecked())         modules.add("IDOR");
        if (hostHeaderCheck.isChecked())   modules.add("HostHeader");
        if (actuatorCheck.isChecked())     modules.add("Actuator");
        if (massAssignCheck.isChecked())   modules.add("MassAssign");

        if (modules.isEmpty()) {
            logPanel.log("[!] Nenhum módulo selecionado");
            return;
        }

        String jwt2 = jwtToken2Box.getText().trim();
        logPanel.log("[*] Iniciando scan em " + target + " ...");
        scanRunner.run(new ScanContext(target, jwt, modules, jwt2, requestLogCb));
    }
}
