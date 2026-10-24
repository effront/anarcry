package gg.effront.anarcry.scanner;

import gg.effront.anarcry.model.Finding;
import gg.effront.anarcry.scanner.web.cors.CorsModule;
import gg.effront.anarcry.scanner.web.crlf.CrlfModule;
import gg.effront.anarcry.scanner.web.graphql.GraphQLModule;
import gg.effront.anarcry.scanner.crypto.headers.HeadersModule;
import gg.effront.anarcry.scanner.web.idor.IdorModule;
import gg.effront.anarcry.scanner.crypto.jwt.JwtModule;
import gg.effront.anarcry.scanner.web.oauth.OAuthModule;
import gg.effront.anarcry.scanner.web.openredirect.OpenRedirectModule;
import gg.effront.anarcry.scanner.crypto.pqc.PqcModule;
import gg.effront.anarcry.scanner.web.ssrf.SsrfModule;
import gg.effront.anarcry.scanner.web.ssti.SstiModule;
import gg.effront.anarcry.scanner.crypto.tls.TlsModule;
import gg.effront.anarcry.scanner.web.xxe.XxeModule;
import gg.effront.anarcry.scanner.web.hostheader.HostHeaderModule;
import gg.effront.anarcry.scanner.web.actuator.SpringActuatorModule;
import gg.effront.anarcry.scanner.web.massassign.MassAssignmentModule;
import gg.effront.anarcry.scanner.web.cachepoisoning.CachePoisoningModule;
import gg.effront.anarcry.scanner.web.smuggling.RequestSmugglingModule;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.function.Consumer;

public class ScanRunner {

    private final Consumer<String>  logCb;
    private final Consumer<Finding> findingCb;
    private final List<Scanner> customModules = new ArrayList<>();
    private final ExecutorService   executor = Executors.newSingleThreadExecutor(r -> {
        Thread t = new Thread(r, "anarcry-scan");
        t.setDaemon(true);
        return t;
    });

    private Runnable onScanStart  = () -> {};
    private Runnable onScanFinish = () -> {};
    private Consumer<ScanEvent> eventCb = e -> {};

    public ScanRunner(Consumer<String> logCb, Consumer<Finding> findingCb) {
        this.logCb     = logCb;
        this.findingCb = findingCb;
    }

    public void setOnScanStart(Runnable r)  { this.onScanStart  = r; }
    public void setOnScanFinish(Runnable r) { this.onScanFinish = r; }
    public void setOnScanEvent(Consumer<ScanEvent> cb) { this.eventCb = cb; }

    /** For testing only — adds a custom Scanner that always runs regardless of ScanContext modules. */
    public void addModule(Scanner module) { customModules.add(module); }

    public void run(ScanContext ctx) {
        executor.submit(() -> {
            onScanStart.run();
            List<Scanner> modules = new ArrayList<>();
            if (ctx.has("TLS"))     modules.add(new TlsModule());
            if (ctx.has("Headers")) modules.add(new HeadersModule());
            if (ctx.has("JWT"))     modules.add(new JwtModule());
            if (ctx.has("PQC"))     modules.add(new PqcModule());
            if (ctx.has("CORS"))         modules.add(new CorsModule());
            if (ctx.has("OAuth"))        modules.add(new OAuthModule());
            if (ctx.has("OpenRedirect")) modules.add(new OpenRedirectModule());
            if (ctx.has("SSRF"))         modules.add(new SsrfModule());
            if (ctx.has("GraphQL"))      modules.add(new GraphQLModule());
            if (ctx.has("CRLF"))         modules.add(new CrlfModule());
            if (ctx.has("XXE"))          modules.add(new XxeModule());
            if (ctx.has("SSTI"))         modules.add(new SstiModule());
            if (ctx.has("IDOR"))         modules.add(new IdorModule());
            if (ctx.has("HostHeader"))   modules.add(new HostHeaderModule());
            if (ctx.has("Actuator"))     modules.add(new SpringActuatorModule());
            if (ctx.has("MassAssign"))      modules.add(new MassAssignmentModule());
            if (ctx.has("CachePoisoning"))  modules.add(new CachePoisoningModule());
            if (ctx.has("ReqSmuggling"))    modules.add(new RequestSmugglingModule());
            modules.addAll(customModules);

            int moduleCount = modules.size();
            eventCb.accept(new ScanEvent(ScanEvent.Type.SCAN_START, null, 0, moduleCount));

            int total = 0;
            for (int i = 0; i < modules.size(); i++) {
                Scanner module = modules.get(i);
                eventCb.accept(new ScanEvent(ScanEvent.Type.MODULE_START, module.id(), i + 1, moduleCount));
                logCb.accept("[*] Modulo " + module.id() + " iniciado");
                try {
                    List<Finding> findings = module.scan(ctx, logCb);
                    for (Finding f : findings) {
                        findingCb.accept(f);
                        total++;
                    }
                    logCb.accept("[+] " + module.id() + ": " + findings.size() + " finding(s)");
                } catch (Exception e) {
                    logCb.accept("[!] " + module.id() + " erro: " + e.getMessage());
                }
                eventCb.accept(new ScanEvent(ScanEvent.Type.MODULE_DONE, module.id(), i + 1, moduleCount));
            }
            eventCb.accept(new ScanEvent(ScanEvent.Type.SCAN_DONE, null, moduleCount, moduleCount));
            logCb.accept("[*] Scan concluído — " + total + " finding(s) no total");
            onScanFinish.run();
        });
    }

    public void shutdown() {
        executor.shutdownNow();
    }
}
