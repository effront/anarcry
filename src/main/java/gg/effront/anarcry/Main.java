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

public class Main {

    private static final int HEADLESS_TIMEOUT_MINUTES = 10;

    public static void main(String[] args) throws Exception {
        EnvLoader env = null;
        boolean headless = false;
        boolean tui = false;
        String target = null;
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
            } else if ("--target".equals(arg) && idx + 1 < args.length) {
                target = args[idx + 1];
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
        } else if (headless) {
            runHeadless(env, target, timeoutMinutes, format);
        } else if (tui) {
            new AnarCryTui().start(env);
        } else {
            new AnarCryGui().start(env);
        }
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
                        pw.printf("%d,%s,%d,%d,%d,%s%n", r.requestNum(), csvEscape(r.payloadSummary()), r.statusCode(),
                                r.length(), r.timeMs(), csvEscape(r.error() != null ? r.error() : ""));
                    }
                }
            }
            System.err.println("[*] Results written to: " + output);
        }

        System.exit(0);
    }

    private static String csvEscape(String s) {
        if (s == null) {
            return "";
        }
        if (s.contains(",") || s.contains("\"") || s.contains("\n")) {
            return "\"" + s.replace("\"", "\"\"") + "\"";
        }
        return s;
    }

    private static void runHeadless(EnvLoader env, String targetArg, int timeoutMinutes, String format)
            throws Exception {
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

        Set<String> modules = ScanOrchestrator.defaultModules();
        List<Finding> findings = Collections.synchronizedList(new ArrayList<>());
        CountDownLatch done = new CountDownLatch(1);

        ScanRunner runner = new ScanRunner(System.out::println, f -> {
            findings.add(f);
            System.out.printf("[FINDING] %-8s %-16s %s%n", f.severity(), f.module(), f.title());
        });
        runner.setOnScanFinish(done::countDown);

        ScanContext ctx = ScanOrchestrator.buildContext(target, jwt1, jwt2, modules);

        System.out.println("[*] AnarCry headless scan: " + target);
        System.out.println("[*] Modulos: " + modules.size());
        runner.run(ctx);

        boolean finished = done.await(timeoutMinutes, TimeUnit.MINUTES);
        runner.shutdown();

        if (!finished) {
            System.err.println("[!] Scan timeout apos " + timeoutMinutes + " minutos");
        }

        System.out.println("\n[*] " + findings.size() + " finding(s)");
        findings.stream().sorted(Comparator.comparingInt(f -> f.severity().ordinal()))
                .forEach(f -> System.out.printf("  %-8s [%s] %s%n", f.severity(), f.module(), f.title()));

        if (!findings.isEmpty()) {
            ReportEngine engine = new ReportEngine();
            List<Finding> snapshot = new ArrayList<>(findings);
            String report = switch (format.toLowerCase()) {
                case "h1" -> engine.exportH1(snapshot, target, "AnarCry Scan");
                case "bugcrowd" -> engine.exportBugcrowd(snapshot, target);
                case "sarif" -> engine.exportSarif(snapshot, target);
                default -> engine.export(snapshot, target);
            };
            System.out.println("\n[*] Report: " + report);
        }
    }
}
