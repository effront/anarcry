package gg.effront.anarcry.scanner.util;

import java.util.List;
import java.util.function.Consumer;
import java.util.stream.Collectors;

public final class ChallengeSolver {

    private static final int CHALLENGE_TIMEOUT_MS = 30_000;
    private static final int NAV_TIMEOUT_MS = 15_000;

    public record Result(String cookies, String challengeType) {
    }

    private ChallengeSolver() {
    }

    public static boolean isAvailable() {
        try {
            Class.forName("com.microsoft.playwright.Playwright");
            return true;
        } catch (ClassNotFoundException e) {
            return false;
        }
    }

    public static Result solve(String targetUrl, Consumer<String> log) {
        if (!isAvailable()) {
            log.accept("[!] Playwright nao disponivel no classpath");
            return null;
        }
        try {
            return doSolve(targetUrl, log);
        } catch (Exception e) {
            String msg = e.getMessage();
            if (msg != null && msg.contains("Executable doesn't exist")) {
                log.accept("[!] Chromium nao instalado. Execute:");
                log.accept("    java -cp <jar> com.microsoft.playwright.CLI install chromium");
            } else {
                log.accept("[!] Challenge solver falhou: " + (msg != null ? msg : e.getClass().getName()));
            }
            return null;
        }
    }

    private static Result doSolve(String targetUrl, Consumer<String> log) {
        try (var pw = com.microsoft.playwright.Playwright.create()) {
            var launchOpts = new com.microsoft.playwright.BrowserType.LaunchOptions().setHeadless(true).setArgs(List.of(
                    "--disable-blink-features=AutomationControlled", "--no-first-run", "--no-default-browser-check"));

            try (var browser = pw.chromium().launch(launchOpts)) {
                var ctxOpts = new com.microsoft.playwright.Browser.NewContextOptions()
                        .setUserAgent(StealthHttpClient.CHROME_UA);
                var ctx = browser.newContext(ctxOpts);
                var page = ctx.newPage();

                page.setDefaultTimeout(CHALLENGE_TIMEOUT_MS);

                log.accept("[*] Headless Chromium navegando para " + targetUrl);
                var resp = page.navigate(targetUrl,
                        new com.microsoft.playwright.Page.NavigateOptions().setTimeout(NAV_TIMEOUT_MS));

                if (resp == null) {
                    log.accept("[!] Navigate retornou null");
                    return null;
                }

                if (resp.status() != 403 && resp.status() != 503) {
                    log.accept("[+] Sem challenge (HTTP " + resp.status() + ")");
                    return extractCookies(ctx, "none");
                }

                String title = page.title();
                if (!title.contains("Security Checkpoint") && !title.contains("Checking")) {
                    log.accept("[~] 403 sem challenge page -- WAF rule block, nao JS challenge");
                    return null;
                }

                log.accept("[*] JS challenge detectado (" + title + "), resolvendo...");

                page.mouse().move(300, 400);
                page.waitForTimeout(500);
                page.mouse().move(520, 280);
                page.waitForTimeout(300);
                page.mouse().move(410, 350);

                try {
                    page.waitForURL(url -> true,
                            new com.microsoft.playwright.Page.WaitForURLOptions().setTimeout(CHALLENGE_TIMEOUT_MS));

                    page.waitForLoadState(com.microsoft.playwright.options.LoadState.NETWORKIDLE,
                            new com.microsoft.playwright.Page.WaitForLoadStateOptions().setTimeout(NAV_TIMEOUT_MS));
                } catch (com.microsoft.playwright.TimeoutError e) {
                    log.accept("[-] Challenge timeout -- pode requerer CAPTCHA ou interacao manual");
                    return null;
                }

                int finalStatus = 200;
                String finalTitle = page.title();

                if (finalTitle.contains("Security Checkpoint") || finalTitle.contains("Checking")) {
                    log.accept("[-] Challenge nao resolveu automaticamente");
                    return null;
                }

                log.accept("[+] Challenge resolvido (" + finalTitle + ")");

                String type = title.contains("Vercel") ? "Vercel Security Checkpoint" : "Cloudflare Managed Challenge";
                return extractCookies(ctx, type);
            }
        }
    }

    private static Result extractCookies(com.microsoft.playwright.BrowserContext ctx, String type) {
        var cookies = ctx.cookies();
        if (cookies.isEmpty()) {
            return null;
        }
        String cookieStr = cookies.stream().map(c -> c.name + "=" + c.value).collect(Collectors.joining("; "));
        return new Result(cookieStr, type);
    }
}
