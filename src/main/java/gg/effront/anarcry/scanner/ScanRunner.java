package gg.effront.anarcry.scanner;

import gg.effront.anarcry.model.Finding;
import gg.effront.anarcry.model.RequestRecord;
import gg.effront.anarcry.model.Severity;
import gg.effront.anarcry.scanner.util.BrowserTransport;
import gg.effront.anarcry.scanner.util.ChallengeSolver;
import gg.effront.anarcry.scanner.util.CircuitBreakerException;
import gg.effront.anarcry.scanner.util.HttpClientFactory;
import gg.effront.anarcry.scanner.util.StealthHttpClient;
import gg.effront.anarcry.scanner.util.WafEvasion;
import gg.effront.anarcry.scanner.util.WafState;
import gg.effront.anarcry.scanner.web.cors.CorsModule;
import gg.effront.anarcry.scanner.web.crlf.CrlfModule;
import gg.effront.anarcry.scanner.web.graphql.GraphQLModule;
import gg.effront.anarcry.scanner.crypto.headers.HeadersModule;
import gg.effront.anarcry.scanner.crypto.hsts.HSTSModule;
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
import gg.effront.anarcry.scanner.web.cmdinject.CommandInjectionModule;
import gg.effront.anarcry.scanner.web.crawler.CrawlerModule;
import gg.effront.anarcry.scanner.web.infra.InfraModule;
import gg.effront.anarcry.scanner.web.lfi.LfiModule;
import gg.effront.anarcry.scanner.web.sqli.SqlInjectionModule;
import gg.effront.anarcry.scanner.web.xss.XssModule;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.function.Consumer;

public class ScanRunner {

    private static final int DEFAULT_PARALLELISM = 4;
    private static final long MODULE_TIMEOUT_SECONDS = 300;

    private final Consumer<String> logCb;
    private final Consumer<Finding> findingCb;
    private final Set<String> seenFindings = Collections.synchronizedSet(new HashSet<>());
    private final List<String> testedClean = Collections.synchronizedList(new ArrayList<>());
    private final List<String> testedModules = Collections.synchronizedList(new ArrayList<>());
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

    private volatile ScanContext lastScanContext;

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
     * For testing only -- adds a custom Scanner that always runs regardless of
     * ScanContext modules.
     */
    public void addModule(Scanner module) {
        customModules.add(module);
    }

    public List<String> testedClean() {
        return List.copyOf(testedClean);
    }

    public List<String> testedModules() {
        return List.copyOf(testedModules);
    }

    public ScanContext getLastContext() {
        return lastScanContext;
    }

    public void run(ScanContext ctx) {
        lastScanContext = ctx;
        executor.submit(() -> {
            try {
                testedClean.clear();
                testedModules.clear();
                runScan(ctx);
            } catch (Exception e) {
                logCb.accept("[!] Scan falhou: " + e.getMessage());
            } finally {
                ctx.wafState().closeBrowserTransport();
                onScanFinish.run();
            }
        });
    }

    private void runScan(ScanContext origCtx) {
        onScanStart.run();
        if (!origCtx.config().isInScope(origCtx.host())) {
            logCb.accept("[!] Host " + origCtx.host() + " fora do scope -- scan cancelado");
            return;
        }

        Object logLock = new Object();
        Consumer<String> safeLog = msg -> {
            synchronized (logLock) {
                logCb.accept(msg);
            }
        };
        Consumer<RequestRecord> safeReqLog = rec -> {
            synchronized (logLock) {
                origCtx.requestLog().accept(rec);
            }
        };
        ScanContext ctx = new ScanContext(origCtx.targetUrl(), origCtx.jwtToken(), origCtx.jwtToken2(),
                origCtx.enabledModules(), origCtx.config(), safeReqLog, origCtx.discoveredPaths(), origCtx.wafState());
        ctx.wafState().setRuntimeLog(safeLog);
        List<Scanner> modules = new ArrayList<>();
        if (ctx.has("TLS")) {
            modules.add(new TlsModule());
        }
        if (ctx.has("Headers")) {
            modules.add(new HeadersModule());
        }
        if (ctx.has("HSTS")) {
            modules.add(new HSTSModule());
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
        if (ctx.has("SQLi")) {
            modules.add(new SqlInjectionModule());
        }
        if (ctx.has("XSS")) {
            modules.add(new XssModule());
        }
        if (ctx.has("LFI")) {
            modules.add(new LfiModule());
        }
        if (ctx.has("CmdInjection")) {
            modules.add(new CommandInjectionModule());
        }
        if (ctx.has("Crawler")) {
            modules.add(new CrawlerModule());
        }
        if (ctx.has("Infra")) {
            modules.add(new InfraModule());
        }
        modules.addAll(customModules);

        List<Scanner> enrichers = new ArrayList<>();
        List<Scanner> scanners = new ArrayList<>();
        for (Scanner m : modules) {
            if ("Crawler".equals(m.id())) {
                enrichers.add(m);
            } else {
                scanners.add(m);
            }
        }

        int moduleCount = enrichers.size() + scanners.size();
        eventCb.accept(new ScanEvent(ScanEvent.Type.SCAN_START, null, 0, moduleCount));

        int[] total = {0};

        // Phase 1: Reconnaissance (blocking)
        for (int i = 0; i < enrichers.size(); i++) {
            final Scanner enricher = enrichers.get(i);
            final int moduleIndex = i + 1;
            eventCb.accept(new ScanEvent(ScanEvent.Type.MODULE_START, enricher.id(), moduleIndex, moduleCount));
            safeLog.accept("[*] Phase 1: Reconnaissance -- " + enricher.id());
            try {
                List<Finding> findings = enricher.scan(ctx, safeLog);
                for (Finding f : findings) {
                    String dedupKey = f.module() + "|" + f.endpoint() + "|" + f.title();
                    if (seenFindings.add(dedupKey)) {
                        if (ctx.config().isSuppressed(f.module(), f.title(), ctx.host())) {
                            safeLog.accept("[~] suppressed: " + f.module() + " -- " + f.title());
                        } else {
                            findingCb.accept(f);
                            total[0]++;
                        }
                    } else {
                        safeLog.accept("[~] dedup: ignorado finding duplicado -- " + f.module() + " " + f.title());
                    }
                }
                recordModuleResult(enricher.id(), findings);
                safeLog.accept("[+] " + enricher.id() + ": " + findings.size() + " finding(s), "
                        + ctx.discoveredPaths().pathCount() + " paths, " + ctx.discoveredPaths().parameterCount()
                        + " params discovered");
            } catch (Throwable e) {
                safeLog.accept("[!] " + enricher.id() + " erro: " + e.getMessage());
            }
            eventCb.accept(new ScanEvent(ScanEvent.Type.MODULE_DONE, enricher.id(), moduleIndex, moduleCount));
        }

        // Phase 1.5: WAF detection + bypass
        if (!ctx.wafState().isWafDetected()) {
            safeLog.accept("[*] Phase 1.5: WAF detection probe em " + ctx.targetUrl());
            try {
                java.net.http.HttpClient probeHc = HttpClientFactory.http2();

                // Baseline: clean GET (no payload) to detect WAF/CDN via signatures
                java.net.http.HttpRequest cleanReq = java.net.http.HttpRequest.newBuilder()
                        .uri(java.net.URI.create(ctx.targetUrl())).timeout(java.time.Duration.ofSeconds(6)).GET()
                        .build();
                java.net.http.HttpResponse<String> cleanResp = probeHc.send(cleanReq,
                        java.net.http.HttpResponse.BodyHandlers.ofString());
                String cleanBody = cleanResp.body() != null ? cleanResp.body() : "";

                // Multi-vendor signature detection on baseline (CDN presence only -- not WAF
                // enforcement)
                var providers = WafEvasion.detectProviders(cleanResp.statusCode(), cleanResp.headers().map(), cleanBody,
                        ctx.targetUrl());
                String baselineProvider = "";
                if (!providers.isEmpty()) {
                    baselineProvider = providers.get(0).name();
                    safeLog.accept("[~] Phase 1.5: " + providers.size() + " provider(s) detectado(s) via signatures: "
                            + providers.stream().map(p -> p.name() + "(" + p.confidence() + ")")
                                    .reduce((a, b) -> a + ", " + b).orElse(""));
                }

                // Probe: inject XSS canary to trigger WAF rules
                String canary = java.net.URLEncoder.encode("<script>alert(1)</script>",
                        java.nio.charset.StandardCharsets.UTF_8);
                String probeUrl = ctx.targetUrl() + "?wafprobe=" + canary;
                java.net.http.HttpRequest probeReq = java.net.http.HttpRequest.newBuilder()
                        .uri(java.net.URI.create(probeUrl)).timeout(java.time.Duration.ofSeconds(6)).GET().build();
                java.net.http.HttpResponse<String> probeResp = probeHc.send(probeReq,
                        java.net.http.HttpResponse.BodyHandlers.ofString());
                String serverHdr = probeResp.headers().firstValue("Server").orElse("");
                String probeBody = probeResp.body() != null ? probeResp.body() : "";

                // Classify challenge type (CF-specific: managed/jsd/interactive/turnstile)
                String cfType = WafEvasion.parseCfChallengeType(probeBody, probeResp.headers().map(), probeUrl);

                // Vercel Security Checkpoint -- must be checked BEFORE CF branch
                String vercelMitigated = probeResp.headers().firstValue("x-vercel-mitigated").orElse("");
                boolean isVercel = "challenge".equalsIgnoreCase(vercelMitigated)
                        || ((probeResp.statusCode() == 403 || probeResp.statusCode() == 503)
                                && probeBody.contains("Vercel Security Checkpoint"));

                if (isVercel) {
                    ctx.wafState().markWafDetected("Vercel");
                    ctx.wafState().markBlockType(WafState.WafBlockType.VERCEL_CHALLENGE);
                    ctx.wafState().markJsChallenge("Vercel Security Checkpoint");
                    safeLog.accept("[!] Phase 1.5: Vercel Security Checkpoint detectado (HTTP " + probeResp.statusCode()
                            + ")");

                    safeLog.accept("[*] Phase 1.5: tentando ChallengeSolver (headless Chromium + WASM)...");
                    ChallengeSolver.Result csResult = ChallengeSolver.solve(ctx.targetUrl(), safeLog);

                    if (csResult != null && csResult.cookies() != null && !csResult.cookies().isBlank()) {
                        ctx.wafState().setChallengeCookies(csResult.cookies());
                        safeLog.accept("[+] Phase 1.5: Vercel challenge resolvido -- cookies de clearance extraidos");
                        safeLog.accept("[+] Phase 1.5: cookies serao injetados em todos os requests via Http.send()");

                        BrowserTransport browserTx = BrowserTransport.create(ctx.targetUrl(), safeLog);
                        if (browserTx != null) {
                            ctx.wafState().setBrowserTransport(browserTx);
                            safeLog.accept("[+] Phase 1.5: BrowserTransport ativado como transport complementar");
                        }
                    } else {
                        safeLog.accept("[-] Phase 1.5: ChallengeSolver falhou ou Playwright indisponivel");
                        safeLog.accept("[*] Fallback: abra o alvo no browser, resolva o challenge, e extraia cookies:");
                        safeLog.accept("[*]   1. No console do browser: document.cookie");
                        safeLog.accept("[*]   2. Cole o valor no campo 'Session Cookie' do AnarCry");
                        safeLog.accept("[*]   3. Mude Auth Type para Cookie e reinicie o scan");

                        if (!ctx.config().sessionCookie().isBlank()) {
                            safeLog.accept("[+] Session Cookie detectado -- tentando usar como clearance");
                            ctx.wafState().setChallengeCookies(ctx.config().sessionCookie());
                        }
                    }
                } else if (!cfType.isEmpty()) {
                    if (!ctx.wafState().isWafDetected()) {
                        ctx.wafState().markWafDetected(baselineProvider.isEmpty() ? "cloudflare" : baselineProvider);
                    }
                    if ("managed".equals(cfType) || "interactive".equals(cfType) || "non-interactive".equals(cfType)
                            || "embedded".equals(cfType)) {
                        ctx.wafState().markBlockType(WafState.WafBlockType.MANAGED_CHALLENGE);
                        ctx.wafState().markJsChallenge(cfType);
                        safeLog.accept("[!] Phase 1.5: CF Managed Challenge (" + cfType + ") -- HTTP "
                                + probeResp.statusCode() + " -- evasion strategies nao aplicaveis");
                    } else if ("turnstile".equals(cfType)) {
                        ctx.wafState().markBlockType(WafState.WafBlockType.TURNSTILE);
                        safeLog.accept("[!] Phase 1.5: CF Turnstile detectado -- HTTP " + probeResp.statusCode()
                                + " -- bypass automatizado fora do escopo");
                    } else if ("jsd".equals(cfType)) {
                        ctx.wafState().markBlockType(WafState.WafBlockType.JS_CHALLENGE);
                        ctx.wafState().markJsChallenge(cfType);
                        safeLog.accept("[!] Phase 1.5: CF JS Challenge (jsd) -- HTTP " + probeResp.statusCode()
                                + " -- tentando BrowserTransport");
                    }
                } else if (WafEvasion.isJsChallenge(probeResp.statusCode(), probeResp.headers().map(), probeBody)) {
                    String challengeType = WafEvasion.detectChallengeType(probeResp.statusCode(),
                            probeResp.headers().map(), probeBody);
                    if (!ctx.wafState().isWafDetected()) {
                        String product = !baselineProvider.isEmpty()
                                ? baselineProvider
                                : WafEvasion.detectWafProduct(serverHdr);
                        ctx.wafState().markWafDetected(product.isEmpty() ? serverHdr : product);
                    }
                    ctx.wafState().markBlockType(WafState.WafBlockType.JS_CHALLENGE);
                    ctx.wafState().markJsChallenge(challengeType);
                    safeLog.accept("[!] Phase 1.5: JS challenge detectado -- " + challengeType + " (HTTP "
                            + probeResp.statusCode() + ")");
                } else if (WafEvasion.isWafBlocked(probeResp.statusCode(), serverHdr, probeBody)) {
                    if (!ctx.wafState().isWafDetected()) {
                        String product = !baselineProvider.isEmpty()
                                ? baselineProvider
                                : WafEvasion.detectWafProduct(serverHdr);
                        ctx.wafState().markWafDetected(product.isEmpty() ? serverHdr : product);
                    }
                    ctx.wafState().markBlockType(WafState.WafBlockType.RULE_BLOCK);
                    safeLog.accept("[!] Phase 1.5: WAF rule block -- " + ctx.wafState().wafProduct() + " (HTTP "
                            + probeResp.statusCode() + ")");
                } else if (!ctx.wafState().isWafDetected()) {
                    safeLog.accept("[+] Phase 1.5: nenhum WAF detectado");
                }
            } catch (Exception e) {
                safeLog.accept("[~] Phase 1.5: WAF detection falhou: " + e.getMessage());
            }
        }

        if (ctx.wafState().isWafDetected()) {
            WafState.WafBlockType bt = ctx.wafState().blockType();
            if (ctx.wafState().isVercelChallenge()) {
                // Vercel challenge was already handled in the detection block above
                if (ctx.wafState().hasChallengeCookies()) {
                    safeLog.accept("[*] Phase 1.5: Vercel challenge resolvido -- pulando evasion probing");
                } else {
                    safeLog.accept(
                            "[*] Phase 1.5: Vercel challenge nao resolvido -- scan pode produzir falsos positivos");
                    safeLog.accept("[*] Alternativa: abra o alvo no Chrome, copie os cookies e cole em Session Cookie");
                }
            } else if (ctx.wafState().isManaged()) {
                // Managed challenge or Turnstile -- evasion/stealth won't help
                safeLog.accept("[*] Phase 1.5: " + bt + " detectado -- pulando evasion strategy probing");
                safeLog.accept("[*] Alternativa: abra o alvo no Chrome, copie os cookies e cole em Session Cookie");
            } else if (bt == WafState.WafBlockType.JS_CHALLENGE || ctx.wafState().isJsChallenge()) {
                // JS challenge -- use headless Chromium as request transport
                safeLog.accept("[*] Phase 1.5: ativando BrowserTransport (headless Chromium)...");
                BrowserTransport browserTx = BrowserTransport.create(ctx.targetUrl(), safeLog);
                if (browserTx != null) {
                    ctx.wafState().setBrowserTransport(browserTx);
                    safeLog.accept("[+] Phase 1.5: JS challenge bypassado -- requests via Chromium headless");
                    // BT solves JS challenges; any subsequent block is payload-level
                    ctx.wafState().markBlockType(WafState.WafBlockType.RULE_BLOCK);
                    // Probe payload bypass strategies through BT
                    safeLog.accept(
                            "[*] Phase 1.5: probing payload bypass strategies para " + ctx.wafState().wafProduct());
                    try {
                        java.net.http.HttpClient probeHc2 = HttpClientFactory.http2();
                        WafEvasion.Strategy effective = WafEvasion.probeStrategies(ctx, probeHc2, ctx.targetUrl(),
                                "WafProbe", safeLog);
                        if (effective != null) {
                            ctx.wafState().markEffectiveStrategy(effective);
                            safeLog.accept("[+] WAF bypass: usando " + effective + " para modulos de payload");
                        } else {
                            safeLog.accept("[-] WAF bypass: nenhuma estrategia de payload efetiva");
                        }
                    } catch (Exception e) {
                        safeLog.accept("[!] WAF probe falhou: " + e.getMessage());
                    }
                } else {
                    safeLog.accept("[-] Phase 1.5: BrowserTransport indisponivel");
                    safeLog.accept("[*] Alternativa: abra o alvo no Chrome, copie os cookies e cole em Session Cookie");
                }
            } else {
                // WAF rule block -- try TLS fingerprint bypass
                safeLog.accept("[*] Phase 1.5: TLS fingerprint bypass (Chrome JA3 + H2) em " + ctx.targetUrl());
                try {
                    String canary2 = java.net.URLEncoder.encode("<script>alert(1)</script>",
                            java.nio.charset.StandardCharsets.UTF_8);
                    String stealthUrl = ctx.targetUrl() + "?wafprobe=" + canary2;
                    java.net.http.HttpRequest stealthReq = java.net.http.HttpRequest.newBuilder()
                            .uri(java.net.URI.create(stealthUrl)).timeout(java.time.Duration.ofSeconds(6)).GET()
                            .build();
                    java.net.http.HttpResponse<String> stealthResp = StealthHttpClient.send(stealthReq);
                    String sHdr = stealthResp.headers().firstValue("Server").orElse("");
                    String sBody = stealthResp.body() != null ? stealthResp.body() : "";
                    if (!WafEvasion.isWafBlocked(stealthResp.statusCode(), sHdr, sBody)) {
                        ctx.wafState().markStealthActive();
                        safeLog.accept("[+] Phase 1.5: TLS bypass efetivo -- Chrome JA3+H2 passa WAF (HTTP "
                                + stealthResp.statusCode() + ")");
                    } else {
                        safeLog.accept(
                                "[-] Phase 1.5: TLS bypass insuficiente -- WAF bloqueia por regra, nao fingerprint"
                                        + " (HTTP " + stealthResp.statusCode() + ")");
                    }
                } catch (Exception e) {
                    safeLog.accept("[~] Phase 1.5: stealth probe falhou: " + e.getMessage());
                }

                // Payload-level bypass strategies (complementar ao TLS)
                safeLog.accept("[*] Phase 1.5: probing payload bypass strategies para " + ctx.wafState().wafProduct());
                try {
                    java.net.http.HttpClient probeHc2 = HttpClientFactory.http2();
                    WafEvasion.Strategy effective = WafEvasion.probeStrategies(ctx, probeHc2, ctx.targetUrl(),
                            "WafProbe", safeLog);
                    if (effective != null) {
                        ctx.wafState().markEffectiveStrategy(effective);
                        safeLog.accept("[+] WAF bypass: usando " + effective + " para modulos de payload");
                    } else {
                        safeLog.accept("[-] WAF bypass: nenhuma estrategia de payload efetiva");
                    }
                } catch (Exception e) {
                    safeLog.accept("[!] WAF probe falhou: " + e.getMessage());
                }
            }
        }

        // Phase 2: Scanner modules (parallel)
        int enricherCount = enrichers.size();
        List<CompletableFuture<?>> futures = new ArrayList<>();
        ConcurrentHashMap<String, Thread> moduleThreads = new ConcurrentHashMap<>();

        if (!scanners.isEmpty()) {
            safeLog.accept("[*] Phase 2: " + scanners.size() + " scanner modules (parallel)");

            for (int i = 0; i < scanners.size(); i++) {
                final Scanner module = scanners.get(i);
                final int moduleIndex = enricherCount + i + 1;
                eventCb.accept(new ScanEvent(ScanEvent.Type.MODULE_START, module.id(), moduleIndex, moduleCount));
                safeLog.accept("[*] Modulo " + module.id() + " iniciado");

                CompletableFuture<List<Finding>> future = CompletableFuture.supplyAsync(() -> {
                    moduleThreads.put(module.id(), Thread.currentThread());
                    try {
                        return module.scan(ctx, safeLog);
                    } catch (Throwable e) {
                        throw new RuntimeException(e);
                    } finally {
                        moduleThreads.remove(module.id());
                    }
                }, modulePool).orTimeout(MODULE_TIMEOUT_SECONDS, TimeUnit.SECONDS);

                futures.add(future.handle((findings, ex) -> {
                    if (ex != null) {
                        Throwable cause = ex.getCause() != null ? ex.getCause() : ex;
                        if (cause instanceof TimeoutException) {
                            safeLog.accept("[!] " + module.id() + " timeout apos " + MODULE_TIMEOUT_SECONDS
                                    + "s -- abortando modulo");
                            Thread t = moduleThreads.remove(module.id());
                            if (t != null) {
                                t.interrupt();
                            }
                        } else if (cause instanceof CircuitBreakerException) {
                            safeLog.accept("[!] " + cause.getMessage());
                        } else {
                            safeLog.accept("[!] " + module.id() + " erro: " + ex.getMessage());
                        }
                    } else {
                        recordModuleResult(module.id(), findings);
                        for (Finding f : findings) {
                            String dedupKey = f.module() + "|" + f.endpoint() + "|" + f.title();
                            if (seenFindings.add(dedupKey)) {
                                if (ctx.config().isSuppressed(f.module(), f.title(), ctx.host())) {
                                    safeLog.accept("[~] suppressed: " + f.module() + " -- " + f.title());
                                } else {
                                    findingCb.accept(f);
                                    synchronized (total) {
                                        total[0]++;
                                    }
                                }
                            } else {
                                safeLog.accept(
                                        "[~] dedup: ignorado finding duplicado -- " + f.module() + " " + f.title());
                            }
                        }
                        safeLog.accept("[+] " + module.id() + ": " + findings.size() + " finding(s)");
                    }
                    eventCb.accept(new ScanEvent(ScanEvent.Type.MODULE_DONE, module.id(), moduleIndex, moduleCount));
                    return (Void) null;
                }));
            }
        }

        CompletableFuture.allOf(futures.toArray(new CompletableFuture[0])).join();

        // Post-scan: emit INFO finding for unsolved managed/vercel challenges
        boolean unsolvedChallenge = (ctx.wafState().isManaged() || ctx.wafState().isVercelChallenge())
                && !ctx.wafState().hasChallengeCookies();
        if (unsolvedChallenge) {
            WafState.WafBlockType wafBt = ctx.wafState().blockType();
            String challengeLabel = ctx.wafState().challengeType();
            if (challengeLabel.isEmpty()) {
                challengeLabel = switch (wafBt) {
                    case TURNSTILE -> "Cloudflare Turnstile";
                    case VERCEL_CHALLENGE -> "Vercel Security Checkpoint";
                    default -> ctx.wafState().wafProduct() + " Managed Challenge";
                };
            }
            String wafFinding = challengeLabel + " -- Bypass Automatizado Nao Aplicavel";
            String dedupKey = "WAF|" + ctx.targetUrl() + "|" + wafFinding;
            if (seenFindings.add(dedupKey)) {
                Finding f = Finding.of("WAF", ctx.targetUrl(), wafFinding, Severity.INFO,
                        "Alvo protegido por " + challengeLabel + " (provider: " + ctx.wafState().wafProduct()
                                + ", block type: " + wafBt + ")",
                        "O target utiliza " + challengeLabel + " que exige interacao de browser real. "
                                + "Estrategias de evasion de payload (encoding, case mutation, etc.) "
                                + "nao sao efetivas contra este tipo de protecao.",
                        "Verificar manualmente via browser se o alvo apresenta challenge page.",
                        "Testar manualmente via browser com DevTools. "
                                + "Copiar cookies de sessao pos-challenge e usar no campo Session Cookie do scanner. "
                                + "Considerar headless browser com solve de challenge para automacao.",
                        "", "", "", 0.0);
                findingCb.accept(f);
                total[0]++;
            }
        }

        eventCb.accept(new ScanEvent(ScanEvent.Type.SCAN_DONE, null, moduleCount, moduleCount));
        safeLog.accept("[*] Scan concluido -- " + total[0] + " finding(s) no total");
    }

    private void recordModuleResult(String moduleId, List<Finding> findings) {
        testedModules.add(moduleId);
        if (findings.isEmpty()) {
            testedClean.add(moduleId);
        }
    }

    public void shutdown() {
        executor.shutdownNow();
        modulePool.shutdownNow();
    }
}
