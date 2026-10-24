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
import gg.effront.anarcry.scanner.web.crawler.CrawlerModule;
import gg.effront.anarcry.scanner.web.infra.InfraModule;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.function.Consumer;

public class ScanRunner {

    private static final int DEFAULT_PARALLELISM = 4;

    private final Consumer<String> logCb;
    private final Consumer<Finding> findingCb;
    private final Set<String> seenFindings = Collections.synchronizedSet(new HashSet<>());
    private final List<Scanner> customModules = new ArrayList<>();
    private final ExecutorService executor = Executors.newSingleThreadExecutor(r -> {
        Thread t = new Thread(r, "anarcry-scan");
        t.setDaemon(true);
        return t;
    });
    private final ExecutorService modulePool = Executors.newFixedThreadPool(DEFAULT_PARALLELISM, r -> {
        Thread t = new Thread(r, "anarcry-module");
        t.setDaemon(true);
        return t;
    });

    private Runnable onScanStart = () -> {
    };
    private Runnable onScanFinish = () -> {
    };
    private Consumer<ScanEvent> eventCb = e -> {
    };

    public ScanRunner(Consumer<String> logCb, Consumer<Finding> findingCb) {
        this.logCb = logCb;
        this.findingCb = findingCb;
    }

    public void setOnScanStart(Runnable r) {
        this.onScanStart = r;
    }
    public void setOnScanFinish(Runnable r) {
        this.onScanFinish = r;
    }
    public void setOnScanEvent(Consumer<ScanEvent> cb) {
        this.eventCb = cb;
    }

    /**
     * For testing only — adds a custom Scanner that always runs regardless of
     * ScanContext modules.
     */
    public void addModule(Scanner module) {
        customModules.add(module);
    }

    public void run(ScanContext ctx) {
        executor.submit(() -> {
            onScanStart.run();
            if (!ctx.config().isInScope(ctx.host())) {
                logCb.accept("[!] Host " + ctx.host() + " fora do scope — scan cancelado");
                onScanFinish.run();
                return;
            }
            List<Scanner> modules = new ArrayList<>();
            if (ctx.has("TLS")) {
                modules.add(new TlsModule());
            }
            if (ctx.has("Headers")) {
                modules.add(new HeadersModule());
            }
            if (ctx.has("JWT")) {
                modules.add(new JwtModule());
            }
            if (ctx.has("PQC")) {
                modules.add(new PqcModule());
            }
            if (ctx.has("CORS")) {
                modules.add(new CorsModule());
            }
            if (ctx.has("OAuth")) {
                modules.add(new OAuthModule());
            }
            if (ctx.has("OpenRedirect")) {
                modules.add(new OpenRedirectModule());
            }
            if (ctx.has("SSRF")) {
                modules.add(new SsrfModule());
            }
            if (ctx.has("GraphQL")) {
                modules.add(new GraphQLModule());
            }
            if (ctx.has("CRLF")) {
                modules.add(new CrlfModule());
            }
            if (ctx.has("XXE")) {
                modules.add(new XxeModule());
            }
            if (ctx.has("SSTI")) {
                modules.add(new SstiModule());
            }
            if (ctx.has("IDOR")) {
                modules.add(new IdorModule());
            }
            if (ctx.has("HostHeader")) {
                modules.add(new HostHeaderModule());
            }
            if (ctx.has("Actuator")) {
                modules.add(new SpringActuatorModule());
            }
            if (ctx.has("MassAssign")) {
                modules.add(new MassAssignmentModule());
            }
            if (ctx.has("CachePoisoning")) {
                modules.add(new CachePoisoningModule());
            }
            if (ctx.has("ReqSmuggling")) {
                modules.add(new RequestSmugglingModule());
            }
            if (ctx.has("Crawler")) {
                modules.add(new CrawlerModule());
            }
            if (ctx.has("Infra")) {
                modules.add(new InfraModule());
            }
            modules.addAll(customModules);

            int moduleCount = modules.size();
            eventCb.accept(new ScanEvent(ScanEvent.Type.SCAN_START, null, 0, moduleCount));

            int[] total = {0};
            List<CompletableFuture<?>> futures = new ArrayList<>();

            for (int i = 0; i < modules.size(); i++) {
                final Scanner module = modules.get(i);
                final int moduleIndex = i + 1;
                eventCb.accept(new ScanEvent(ScanEvent.Type.MODULE_START, module.id(), moduleIndex, moduleCount));
                logCb.accept("[*] Modulo " + module.id() + " iniciado");

                CompletableFuture<List<Finding>> future = CompletableFuture.supplyAsync(() -> {
                    try {
                        return module.scan(ctx, logCb);
                    } catch (Exception e) {
                        throw new RuntimeException(e);
                    }
                }, modulePool);

                futures.add(future.whenComplete((findings, ex) -> {
                    if (ex != null) {
                        logCb.accept("[!] " + module.id() + " erro: " + ex.getMessage());
                    } else {
                        for (Finding f : findings) {
                            String dedupKey = f.module() + "|" + f.endpoint() + "|" + f.title();
                            if (seenFindings.add(dedupKey)) {
                                if (ctx.config().isSuppressed(f.module(), f.title(), ctx.host())) {
                                    logCb.accept("[~] suppressed: " + f.module() + " — " + f.title());
                                } else {
                                    findingCb.accept(f);
                                    synchronized (total) {
                                        total[0]++;
                                    }
                                }
                            } else {
                                logCb.accept("[~] dedup: ignorado finding duplicado — " + f.module() + " " + f.title());
                            }
                        }
                        logCb.accept("[+] " + module.id() + ": " + findings.size() + " finding(s)");
                    }
                    eventCb.accept(new ScanEvent(ScanEvent.Type.MODULE_DONE, module.id(), moduleIndex, moduleCount));
                }));
            }

            CompletableFuture.allOf(futures.toArray(new CompletableFuture[0])).join();

            eventCb.accept(new ScanEvent(ScanEvent.Type.SCAN_DONE, null, moduleCount, moduleCount));
            logCb.accept("[*] Scan concluído — " + total[0] + " finding(s) no total");
            onScanFinish.run();
        });
    }

    public void shutdown() {
        executor.shutdownNow();
        modulePool.shutdownNow();
    }
}
