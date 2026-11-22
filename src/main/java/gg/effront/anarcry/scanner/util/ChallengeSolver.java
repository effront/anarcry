package gg.effront.anarcry.scanner.util;

import java.util.List;
import java.util.function.Consumer;
import java.util.stream.Collectors;

public final class ChallengeSolver {

    private static final int CHALLENGE_TIMEOUT_MS = 45_000;
    private static final int VERCEL_TIMEOUT_MS = 60_000;
    private static final int NAV_TIMEOUT_MS = 15_000;
    private static final int INTERACTIVE_TIMEOUT_MS = 180_000;
    private static final int CDP_NAV_TIMEOUT_MS = 10_000;

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
        return solve(targetUrl, log, false);
    }

    public static Result solve(String targetUrl, Consumer<String> log, boolean debug) {
        if (!isAvailable()) {
            log.accept("[!] Playwright nao disponivel no classpath");
            return null;
        }
        try {
            return doSolve(targetUrl, log, debug);
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

    private static Result doSolve(String targetUrl, Consumer<String> log, boolean debug) {
        try (var pw = com.microsoft.playwright.Playwright.create()) {
            var launchOpts = new com.microsoft.playwright.BrowserType.LaunchOptions().setHeadless(true)
                    .setArgs(List.of("--disable-blink-features=AutomationControlled", "--no-first-run",
                            "--no-default-browser-check", "--disable-dev-shm-usage",
                            "--disable-features=IsolateOrigins,site-per-process"));

            try (var browser = pw.chromium().launch(launchOpts)) {
                var ctxOpts = new com.microsoft.playwright.Browser.NewContextOptions()
                        .setUserAgent(StealthHttpClient.CHROME_UA).setViewportSize(1920, 1080).setScreenSize(1920, 1080)
                        .setLocale("en-US").setTimezoneId("America/New_York");
                var ctx = browser.newContext(ctxOpts);
                PlaywrightStealth.apply(ctx);
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
                String pageUrl = page.url();
                boolean isVercel = title.contains("Security Checkpoint") || title.contains("Vercel");

                if (debug) {
                    log.accept(
                            "[DBG] ChallengeSolver: HTTP " + resp.status() + " title=\"" + title + "\" url=" + pageUrl);
                    String bodySnippet = page.content();
                    if (bodySnippet.length() > 500) {
                        bodySnippet = bodySnippet.substring(0, 500);
                    }
                    bodySnippet = bodySnippet.replace("\n", " ").replace("\r", "");
                    log.accept("[DBG] ChallengeSolver: body preview: " + bodySnippet);
                    logCookies(ctx, log, "before solve");
                }

                if (!title.contains("Security Checkpoint") && !title.contains("Checking")
                        && !title.contains("Just a moment") && !title.contains("Attention Required")) {
                    log.accept("[~] 403 sem challenge page -- WAF rule block, nao JS challenge");
                    return null;
                }

                int timeout = isVercel ? VERCEL_TIMEOUT_MS : CHALLENGE_TIMEOUT_MS;
                log.accept("[*] JS challenge detectado (" + title + "), resolvendo (timeout=" + (timeout / 1000)
                        + "s)...");

                page.mouse().move(300, 400);
                page.waitForTimeout(500);
                page.mouse().move(520, 280);
                page.waitForTimeout(300);
                page.mouse().move(410, 350);

                if (isVercel) {
                    tryClickVercelVerify(page, log, debug);
                }

                try {
                    page.waitForFunction(
                            "() => !document.title.includes('Checkpoint') " + "&& !document.title.includes('Checking') "
                                    + "&& !document.title.includes('Just a moment')"
                                    + " && !document.title.includes('Attention')",
                            null, new com.microsoft.playwright.Page.WaitForFunctionOptions().setTimeout(timeout));
                } catch (com.microsoft.playwright.TimeoutError e) {
                    if (isVercel) {
                        tryClickVercelVerify(page, log, debug);
                        try {
                            page.waitForFunction("() => !document.title.includes('Checkpoint')", null,
                                    new com.microsoft.playwright.Page.WaitForFunctionOptions().setTimeout(15_000));
                        } catch (com.microsoft.playwright.TimeoutError e2) {
                            // still stuck
                        }
                    }
                }

                try {
                    page.waitForLoadState(com.microsoft.playwright.options.LoadState.NETWORKIDLE,
                            new com.microsoft.playwright.Page.WaitForLoadStateOptions().setTimeout(10_000));
                } catch (com.microsoft.playwright.TimeoutError ignored) {
                    // best effort
                }

                String finalTitle = page.title();
                if (debug) {
                    String finalUrl = page.url();
                    log.accept("[DBG] ChallengeSolver: post-solve title=\"" + finalTitle + "\" url=" + finalUrl);
                    logCookies(ctx, log, "after solve");
                }

                if (finalTitle.contains("Security Checkpoint") || finalTitle.contains("Checking")
                        || finalTitle.contains("Just a moment") || finalTitle.contains("Attention Required")) {
                    log.accept("[-] Challenge nao resolveu automaticamente");
                    String detectedType = classifyChallenge(title);
                    return new Result(null, detectedType);
                }

                log.accept("[+] Challenge resolvido (" + finalTitle + ")");
                return extractCookies(ctx, classifyChallenge(title));
            }
        }
    }

    public static Result solveInteractive(String targetUrl, Consumer<String> log, boolean debug) {
        if (!isAvailable()) {
            log.accept("[!] Playwright nao disponivel no classpath");
            return null;
        }
        try {
            return doSolveInteractive(targetUrl, log, debug);
        } catch (Exception e) {
            String msg = e.getMessage();
            if (msg != null && msg.contains("Executable doesn't exist")) {
                log.accept("[!] Chromium nao instalado para modo interativo");
            } else {
                log.accept("[!] Interactive solver falhou: " + (msg != null ? msg : e.getClass().getName()));
            }
            return null;
        }
    }

    private static Result doSolveInteractive(String targetUrl, Consumer<String> log, boolean debug) {
        try (var pw = com.microsoft.playwright.Playwright.create()) {
            var launchOpts = new com.microsoft.playwright.BrowserType.LaunchOptions().setHeadless(false)
                    .setArgs(List.of("--disable-blink-features=AutomationControlled", "--no-first-run",
                            "--no-default-browser-check", "--start-maximized"));

            try (var browser = pw.chromium().launch(launchOpts)) {
                var ctxOpts = new com.microsoft.playwright.Browser.NewContextOptions()
                        .setUserAgent(StealthHttpClient.CHROME_UA).setViewportSize(1920, 1080).setScreenSize(1920, 1080)
                        .setLocale("en-US").setTimezoneId("America/New_York");
                var ctx = browser.newContext(ctxOpts);
                PlaywrightStealth.apply(ctx);
                var page = ctx.newPage();
                page.setDefaultTimeout(INTERACTIVE_TIMEOUT_MS);

                log.accept("[*] Abrindo browser visivel -- resolva o challenge manualmente");
                log.accept("[*] Timeout: " + (INTERACTIVE_TIMEOUT_MS / 1000) + "s");
                var resp = page.navigate(targetUrl,
                        new com.microsoft.playwright.Page.NavigateOptions().setTimeout(NAV_TIMEOUT_MS));

                if (resp == null) {
                    log.accept("[!] Navigate retornou null");
                    return null;
                }

                if (resp.status() != 403 && resp.status() != 503) {
                    log.accept("[+] Sem challenge (HTTP " + resp.status() + ") -- cookies extraidos");
                    return extractCookies(ctx, "none");
                }

                String title = page.title();
                log.accept("[*] Challenge detectado (" + title + ") -- aguardando resolucao manual...");

                try {
                    page.waitForFunction(
                            "() => !document.title.includes('Checkpoint') " + "&& !document.title.includes('Checking') "
                                    + "&& !document.title.includes('Just a moment')"
                                    + " && !document.title.includes('Attention')",
                            null, new com.microsoft.playwright.Page.WaitForFunctionOptions()
                                    .setTimeout(INTERACTIVE_TIMEOUT_MS));
                } catch (com.microsoft.playwright.TimeoutError e) {
                    log.accept(
                            "[-] Timeout -- challenge nao foi resolvido em " + (INTERACTIVE_TIMEOUT_MS / 1000) + "s");
                    return new Result(null, classifyChallenge(title));
                }

                try {
                    page.waitForLoadState(com.microsoft.playwright.options.LoadState.NETWORKIDLE,
                            new com.microsoft.playwright.Page.WaitForLoadStateOptions().setTimeout(10_000));
                } catch (com.microsoft.playwright.TimeoutError ignored) {
                    // best effort
                }

                String finalTitle = page.title();
                if (finalTitle.contains("Security Checkpoint") || finalTitle.contains("Checking")
                        || finalTitle.contains("Just a moment") || finalTitle.contains("Attention Required")) {
                    log.accept("[-] Challenge ainda ativo apos interacao");
                    return new Result(null, classifyChallenge(title));
                }

                log.accept("[+] Challenge resolvido interativamente (" + finalTitle + ")");
                if (debug) {
                    logCookies(ctx, log, "interactive solve");
                }
                return extractCookies(ctx, classifyChallenge(title));
            }
        }
    }

    public static Result connectCdp(String targetUrl, int cdpPort, Consumer<String> log, boolean debug) {
        if (!isAvailable()) {
            log.accept("[!] Playwright nao disponivel no classpath");
            return null;
        }
        try {
            return doConnectCdp(targetUrl, cdpPort, log, debug);
        } catch (Exception e) {
            String msg = e.getMessage();
            log.accept("[!] CDP connect falhou: " + (msg != null ? msg : e.getClass().getName()));
            return null;
        }
    }

    private static Result doConnectCdp(String targetUrl, int cdpPort, Consumer<String> log, boolean debug) {
        try (var pw = com.microsoft.playwright.Playwright.create()) {
            String endpoint = "http://127.0.0.1:" + cdpPort;
            log.accept("[*] Conectando via CDP em " + endpoint);

            try (var browser = pw.chromium().connectOverCDP(endpoint)) {
                var contexts = browser.contexts();
                if (contexts.isEmpty()) {
                    log.accept("[-] Nenhum contexto encontrado no browser CDP");
                    return null;
                }

                var ctx = contexts.get(0);
                var pages = ctx.pages();
                if (debug) {
                    log.accept("[DBG] CDP: " + contexts.size() + " context(s), " + pages.size() + " page(s)");
                }

                // Try to find a page on the target domain
                String targetHost = java.net.URI.create(targetUrl).getHost();
                com.microsoft.playwright.Page targetPage = null;
                for (var p : pages) {
                    try {
                        String pageHost = java.net.URI.create(p.url()).getHost();
                        if (targetHost.equals(pageHost)) {
                            targetPage = p;
                            break;
                        }
                    } catch (Exception ignored) {
                        // skip pages with non-URI URLs (about:blank etc)
                    }
                }

                if (targetPage == null) {
                    log.accept("[~] Nenhuma aba com " + targetHost + " -- abrindo nova aba");
                    targetPage = ctx.newPage();
                    var resp = targetPage.navigate(targetUrl,
                            new com.microsoft.playwright.Page.NavigateOptions().setTimeout(CDP_NAV_TIMEOUT_MS));
                    if (resp != null && (resp.status() == 403 || resp.status() == 503)) {
                        String title = targetPage.title();
                        if (title.contains("Security Checkpoint") || title.contains("Checking")
                                || title.contains("Just a moment")) {
                            log.accept("[-] CDP: challenge ativo na nova aba -- resolva no Chrome e tente novamente");
                            return new Result(null, classifyChallenge(title));
                        }
                    }
                }

                String title = targetPage.title();
                if (title.contains("Security Checkpoint") || title.contains("Checking")
                        || title.contains("Just a moment") || title.contains("Attention Required")) {
                    log.accept("[-] CDP: pagina ainda tem challenge ativo -- resolva no Chrome primeiro");
                    return new Result(null, classifyChallenge(title));
                }

                log.accept("[+] CDP: pagina acessivel (" + title + ")");
                if (debug) {
                    logCookies(ctx, log, "CDP connect");
                }
                Result result = extractCookies(ctx, "CDP");
                if (result == null || result.cookies() == null || result.cookies().isBlank()) {
                    log.accept("[-] CDP: nenhum cookie extraido");
                    return null;
                }
                log.accept("[+] CDP: " + ctx.cookies().size() + " cookie(s) extraidos");
                return result;
            }
        }
    }

    private static void tryClickVercelVerify(com.microsoft.playwright.Page page, Consumer<String> log, boolean debug) {
        try {
            var btn = page.locator("button, [role='button'], input[type='submit'], .verify-button, "
                    + "[data-testid='firewall-challenge-btn']");
            if (btn.count() > 0) {
                if (debug) {
                    log.accept("[DBG] ChallengeSolver: found " + btn.count() + " clickable element(s), clicking first");
                }
                btn.first().click(new com.microsoft.playwright.Locator.ClickOptions().setTimeout(5000));
                page.waitForTimeout(2000);
            }
            var iframe = page.locator("iframe[src*='challenge'], iframe[title*='challenge']");
            if (iframe.count() > 0) {
                if (debug) {
                    log.accept("[DBG] ChallengeSolver: challenge iframe detected, clicking inside");
                }
                var frame = iframe.first().contentFrame();
                if (frame != null) {
                    var innerBtn = frame.locator("button, [role='button'], input[type='submit'], .cb-i");
                    if (innerBtn.count() > 0) {
                        innerBtn.first().click(new com.microsoft.playwright.Locator.ClickOptions().setTimeout(5000));
                        page.waitForTimeout(2000);
                    }
                }
            }
        } catch (Exception e) {
            if (debug) {
                log.accept("[DBG] ChallengeSolver: click attempt: " + e.getMessage());
            }
        }
    }

    private static void logCookies(com.microsoft.playwright.BrowserContext ctx, Consumer<String> log, String label) {
        var cookies = ctx.cookies();
        if (!cookies.isEmpty()) {
            String cookieNames = cookies.stream()
                    .map(c -> c.name + "=" + c.value.substring(0, Math.min(8, c.value.length())) + "...")
                    .collect(Collectors.joining("; "));
            log.accept("[DBG] ChallengeSolver: cookies " + label + ": " + cookieNames);
        } else {
            log.accept("[DBG] ChallengeSolver: no cookies " + label);
        }
    }

    private static String classifyChallenge(String title) {
        if (title.contains("Vercel") || title.contains("Security Checkpoint")) {
            return "Vercel Security Checkpoint";
        } else if (title.contains("Just a moment") || title.contains("Attention")) {
            return "Cloudflare JS Challenge";
        }
        return "Cloudflare Managed Challenge";
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
