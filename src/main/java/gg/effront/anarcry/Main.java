package gg.effront.anarcry;

import gg.effront.anarcry.gui.AnarCryGui;
import gg.effront.anarcry.model.Finding;
import gg.effront.anarcry.report.ReportEngine;
import gg.effront.anarcry.scanner.ScanContext;
import gg.effront.anarcry.scanner.ScanOrchestrator;
import gg.effront.anarcry.scanner.ScanRunner;
import gg.effront.anarcry.tui.AnarCryTui;

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
            } else if ("--target".equals(arg) && idx + 1 < args.length) {
                target = args[idx + 1];
                idx += 2;
            } else if ("--timeout".equals(arg) && idx + 1 < args.length) {
                timeoutMinutes = Integer.parseInt(args[idx + 1]);
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

        if (headless) {
            runHeadless(env, target, timeoutMinutes);
        } else if (tui) {
            new AnarCryTui().start(env);
        } else {
            new AnarCryGui().start(env);
        }
    }

    private static void runHeadless(EnvLoader env, String targetArg, int timeoutMinutes) throws Exception {
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
            String report = new ReportEngine().export(new ArrayList<>(findings), target);
            System.out.println("\n[*] Report: " + report);
        }
    }
}
