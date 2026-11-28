package gg.effront.anarcry;

import gg.effront.anarcry.fuzzer.AttackType;
import gg.effront.anarcry.fuzzer.FilePayloadSource;
import gg.effront.anarcry.fuzzer.FuzzEngine;
import gg.effront.anarcry.fuzzer.FuzzResult;
import gg.effront.anarcry.fuzzer.GrepMatcher;
import gg.effront.anarcry.fuzzer.InlinePayloadSource;
import gg.effront.anarcry.fuzzer.PayloadProcessor;
import gg.effront.anarcry.fuzzer.PayloadSource;
import gg.effront.anarcry.fuzzer.RangePayloadSource;
import gg.effront.anarcry.gui.AnarCryGui;
import gg.effront.anarcry.mcp.McpServer;
import gg.effront.anarcry.util.HttpRequestUtil;
import gg.effront.anarcry.model.Finding;
import gg.effront.anarcry.report.ReportEngine;
import gg.effront.anarcry.scanner.ScanContext;
import gg.effront.anarcry.scanner.ScanOrchestrator;
import gg.effront.anarcry.scanner.ScanRunner;
import gg.effront.anarcry.tui.AnarCryTui;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import java.io.FileWriter;
import java.io.PrintWriter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;

public class Main {

    private static final int HEADLESS_TIMEOUT_MINUTES = 10;

    public static void main(String[] args) throws Exception {
        EnvLoader env = null;
        boolean headless = false;
        boolean tui = false;
        boolean mcp = false;
        int mcpPort = McpServer.DEFAULT_PORT;
        String target = null;
        String modules = null;
        String format = "anarcry";
        String fuzzConfig = null;
        int timeoutMinutes = HEADLESS_TIMEOUT_MINUTES;

        int idx = 0;
        while (idx < args.length) {
            String arg = args[idx];
            if ("--env".equals(arg) && idx + 1 < args.length) {
                env = EnvLoader.load(args[idx + 1]);
                System.err.println("[env] carregado: target=" + env.target() + " jwt1="
                        + (env.jwt1().isBlank() ? "(vazio)" : "(set)") + " jwt2="
                        + (env.jwt2().isBlank() ? "(vazio)" : "(set)"));
                idx += 2;
            } else if ("--headless".equals(arg) || "--e2e".equals(arg)) {
                headless = true;
                idx++;
            } else if ("--tui".equals(arg)) {
                tui = true;
                idx++;
            } else if ("--fuzz".equals(arg) && idx + 1 < args.length) {
                fuzzConfig = args[idx + 1];
                idx += 2;
            } else if ("--mcp".equals(arg)) {
                mcp = true;
                idx++;
            } else if ("--mcp-port".equals(arg) && idx + 1 < args.length) {
                mcpPort = Integer.parseInt(args[idx + 1]);
                mcp = true;
                idx += 2;
            } else if ("--target".equals(arg) && idx + 1 < args.length) {
                target = args[idx + 1];
                idx += 2;
            } else if ("--modules".equals(arg) && idx + 1 < args.length) {
                modules = args[idx + 1];
                idx += 2;
            } else if ("--timeout".equals(arg) && idx + 1 < args.length) {
                timeoutMinutes = Integer.parseInt(args[idx + 1]);
                idx += 2;
            } else if ("--format".equals(arg) && idx + 1 < args.length) {
                format = args[idx + 1];
                idx += 2;
            } else {
                idx++;
            }
        }

        if (env == null) {
            Path dotEnv = Path.of(".env.local");
            if (Files.isRegularFile(dotEnv)) {
                env = EnvLoader.load(dotEnv.toString());
                System.err.println("[env] auto-loaded .env.local: target=" + env.target() + " jwt1="
                        + (env.jwt1().isBlank() ? "(vazio)" : "(set)") + " jwt2="
                        + (env.jwt2().isBlank() ? "(vazio)" : "(set)"));
            }
        }

        if (fuzzConfig != null) {
            runFuzz(fuzzConfig);
        } else if (mcp) {
            runMcp(mcpPort);
        } else if (headless) {
            runHeadless(env, target, modules, timeoutMinutes, format);
        } else if (tui) {
            new AnarCryTui().start(env);
        } else {
            new AnarCryGui().start(env);
        }
    }

    private static void runMcp(int port) throws Exception {
        System.out.println("[*] AnarCry MCP Server starting on port " + port);
        McpServer server = new McpServer(port, System.out::println);
        server.start();

        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            System.out.println("[~] Shutdown signal received");
            server.close();
        }));

        try {
            Thread.currentThread().join();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        server.close();
    }

    private static void runFuzz(String configFile) throws Exception {
        String json = Files.readString(Path.of(configFile));
        JsonObject cfg = JsonParser.parseString(json).getAsJsonObject();

        String template = cfg.get("template").getAsString();
        AttackType attackType = AttackType.valueOf(cfg.get("attackType").getAsString());

        List<PayloadSource> sources = new ArrayList<>();
        JsonArray payloadsArr = cfg.getAsJsonArray("payloads");
        for (JsonElement el : payloadsArr) {
            JsonObject src = el.getAsJsonObject();
            String type = src.get("type").getAsString();
            switch (type) {
                case "file" -> sources.add(new FilePayloadSource(Path.of(src.get("path").getAsString())));
                case "inline" -> sources.add(new InlinePayloadSource(src.get("values").getAsString()));
                case "range" -> sources.add(new RangePayloadSource(src.get("from").getAsLong(),
                        src.get("to").getAsLong(), src.has("step") ? src.get("step").getAsLong() : 1,
                        src.has("padding") ? src.get("padding").getAsInt() : 0));
                default -> {
                    System.err.println("[!] Unknown payload type: " + type);
                    System.exit(1);
                }
            }
        }

        int threads = cfg.has("threads") ? cfg.get("threads").getAsInt() : 10;
        int delay = cfg.has("delay") ? cfg.get("delay").getAsInt() : 0;
        int jitter = cfg.has("jitter") ? cfg.get("jitter").getAsInt() : 0;
        int timeout = cfg.has("timeout") ? cfg.get("timeout").getAsInt() : 30;
        String output = cfg.has("output") ? cfg.get("output").getAsString() : null;

        List<List<PayloadProcessor>> pipelines = new ArrayList<>();
        pipelines.add(List.of());

        FuzzEngine.FuzzConfig fuzzCfg = new FuzzEngine.FuzzConfig(template, attackType, sources, pipelines, threads,
                delay, jitter, timeout, new GrepMatcher(), null, null, null, 0);

        List<FuzzResult> results = Collections.synchronizedList(new ArrayList<>());
        CountDownLatch done = new CountDownLatch(1);

        System.err.println("[*] AnarCry Fuzzer: " + attackType + " with " + sources.size() + " payload source(s)");

        FuzzEngine engine = new FuzzEngine();
        engine.start(fuzzCfg, new FuzzEngine.FuzzListener() {
            @Override
            public void onResult(FuzzResult result) {
                results.add(result);
                System.err.printf("[%d] %s -> %d (%d bytes, %dms)%n", result.requestNum(), result.payloadSummary(),
                        result.statusCode(), result.length(), result.timeMs());
            }

            @Override
            public void onProgress(int completed, long total) {
                if (completed % 100 == 0 || completed == total) {
                    System.err.printf("[*] Progress: %d/%d (%.1f%%)%n", completed, total,
                            total > 0 ? completed * 100.0 / total : 0);
                }
            }

            @Override
            public void onComplete(int totalCompleted, long elapsedMs) {
                System.err.printf("[*] Done: %d requests in %.1fs%n", totalCompleted, elapsedMs / 1000.0);
                done.countDown();
            }

            @Override
            public void onError(String message) {
                System.err.println("[!] Error: " + message);
                done.countDown();
            }
        });

        done.await();

        if (output != null) {
            if (output.endsWith(".json")) {
                try (PrintWriter pw = new PrintWriter(new FileWriter(output))) {
                    pw.print(new com.google.gson.GsonBuilder().setPrettyPrinting().create().toJson(results));
                }
            } else {
                try (PrintWriter pw = new PrintWriter(new FileWriter(output))) {
                    pw.println("#,Payload,Status,Length,Time(ms),Error");
                    for (FuzzResult r : results) {
                        pw.printf("%d,%s,%d,%d,%d,%s%n", r.requestNum(), HttpRequestUtil.csvEscape(r.payloadSummary()),
                                r.statusCode(), r.length(), r.timeMs(),
                                HttpRequestUtil.csvEscape(r.error() != null ? r.error() : ""));
                    }
                }
            }
            System.err.println("[*] Results written to: " + output);
        }

        System.exit(0);
    }

    private static void runHeadless(EnvLoader env, String targetArg, String modulesArg, int timeoutMinutes,
            String format) throws Exception {
        String target = targetArg;
        String jwt1 = "";
        String jwt2 = "";

        if (env != null) {
            if (target == null || target.isBlank()) {
                target = env.target();
            }
            jwt1 = env.jwt1();
            jwt2 = env.jwt2();
        }

        if (target == null || target.isBlank()) {
            System.err.println("[!] --headless requer --target <url> ou --env <arquivo>");
            System.exit(1);
        }
        if (!target.startsWith("http://") && !target.startsWith("https://")) {
            target = "https://" + target;
        }

        Set<String> modules = resolveModules(modulesArg);
        List<Finding> findings = Collections.synchronizedList(new ArrayList<>());
        CountDownLatch done = new CountDownLatch(1);

        // All log output goes to stderr -- stdout is reserved for structured output
        Consumer<String> log = System.err::println;

        ScanRunner runner = new ScanRunner(log, f -> {
            findings.add(f);
            System.err.printf("[FINDING] %-8s %-16s %s%n", f.severity(), f.module(), f.title());
        });
        runner.setOnScanFinish(done::countDown);

        ScanContext ctx = ScanOrchestrator.buildContext(target, jwt1, jwt2, modules);

        log.accept("[*] AnarCry headless scan: " + target);
        log.accept("[*] Modulos (" + modules.size() + "): " + String.join(", ", modules));
        log.accept("[*] Format: " + format);
        log.accept("[*] Timeout: " + timeoutMinutes + " minutos");
        runner.run(ctx);

        boolean finished = done.await(timeoutMinutes, TimeUnit.MINUTES);
        runner.shutdown();

        if (!finished) {
            System.err.println("[!] Scan timeout apos " + timeoutMinutes + " minutos");
        }

        System.err.println("[*] " + findings.size() + " finding(s)");

        // Output structured results to stdout
        List<Finding> snapshot = new ArrayList<>(findings);
        snapshot.sort(Comparator.comparingInt(f -> f.severity().ordinal()));

        ReportEngine engine = new ReportEngine();
        String output = switch (format.toLowerCase()) {
            case "json" -> engine.toJson(snapshot);
            case "md" -> buildMarkdownStdout(snapshot, target);
            case "h1" -> {
                engine.exportH1(snapshot, target, "AnarCry Scan");
                yield engine.toJson(snapshot);
            }
            case "bugcrowd" -> {
                engine.exportBugcrowd(snapshot, target);
                yield engine.toJson(snapshot);
            }
            case "sarif" -> {
                engine.exportSarif(snapshot, target);
                yield engine.toJson(snapshot);
            }
            default -> engine.toJson(snapshot);
        };
        System.out.println(output);
        System.out.flush();

        System.exit(finished ? 0 : 1);
    }

    private static Set<String> resolveModules(String modulesArg) {
        if (modulesArg == null || modulesArg.isBlank()) {
            return ScanOrchestrator.defaultModules();
        }
        Set<String> requested = new java.util.LinkedHashSet<>();
        for (String m : modulesArg.split(",")) {
            String trimmed = m.trim();
            if (!trimmed.isEmpty()) {
                if (ScanOrchestrator.ALL_MODULES.contains(trimmed)) {
                    requested.add(trimmed);
                } else {
                    System.err.println("[!] Modulo desconhecido: " + trimmed + " -- disponiveis: "
                            + String.join(", ", ScanOrchestrator.ALL_MODULES));
                    System.exit(1);
                }
            }
        }
        if (requested.isEmpty()) {
            System.err.println("[!] Nenhum modulo valido especificado");
            System.exit(1);
        }
        return requested;
    }

    private static String buildMarkdownStdout(List<Finding> findings, String targetUrl) {
        StringBuilder sb = new StringBuilder();
        sb.append("# AnarCry Headless Scan\n\n");
        sb.append("**Target:** ").append(targetUrl).append("\n");
        sb.append("**Findings:** ").append(findings.size()).append("\n\n");
        if (findings.isEmpty()) {
            sb.append("No vulnerabilities detected.\n");
            return sb.toString();
        }
        sb.append("| Severity | CVSS | CWE | Module | Endpoint | Title |\n");
        sb.append("|----------|------|-----|--------|----------|-------|\n");
        for (Finding f : findings) {
            sb.append("| ").append(f.severity()).append(" | ").append(String.format("%.1f", f.cvssScore()))
                    .append(" | ").append(f.cweId()).append(" | ").append(f.module()).append(" | ")
                    .append(f.endpoint().replace("|", "\\|")).append(" | ").append(f.title().replace("|", "\\|"))
                    .append(" |\n");
        }
        sb.append("\n");
        for (Finding f : findings) {
            sb.append("## ").append(f.module()).append(": ").append(f.title()).append("\n\n");
            sb.append("**Severity:** ").append(f.severity()).append(" (CVSS ")
                    .append(String.format("%.1f", f.cvssScore())).append(")\n");
            sb.append("**Endpoint:** `").append(f.endpoint()).append("`\n");
            sb.append("**CWE:** ").append(f.cweId()).append(" -- ").append(f.cweTitle()).append("\n\n");
            sb.append("**Evidence:**\n```\n").append(f.evidence() != null ? f.evidence() : "").append("\n```\n\n");
            sb.append("**Impact:** ").append(f.impact() != null ? f.impact() : "").append("\n\n");
            sb.append("**Reproduction:**\n```\n").append(f.reproduction() != null ? f.reproduction() : "")
                    .append("\n```\n\n");
            sb.append("**Recommendation:** ").append(f.recommendation() != null ? f.recommendation() : "")
                    .append("\n\n---\n\n");
        }
        return sb.toString();
    }
}
