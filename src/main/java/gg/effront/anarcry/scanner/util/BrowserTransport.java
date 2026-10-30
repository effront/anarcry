package gg.effront.anarcry.scanner.util;

import com.microsoft.playwright.Browser;
import com.microsoft.playwright.BrowserContext;
import com.microsoft.playwright.BrowserType;
import com.microsoft.playwright.Page;
import com.microsoft.playwright.Playwright;
import com.microsoft.playwright.Response;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpHeaders;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;

public final class BrowserTransport implements AutoCloseable {

    private static final int NAVIGATE_TIMEOUT_MS = 30_000;
    private static final int FETCH_TIMEOUT_MS = 15_000;
    private static final int PAGE_DEFAULT_TIMEOUT_MS = 20_000;

    private static final String FETCH_JS = """
            async ([url, method, headers, body, timeoutMs]) => {
                try {
                    const ctrl = new AbortController();
                    const timer = setTimeout(() => ctrl.abort(), timeoutMs);
                    const opts = { method, headers, redirect: 'follow', signal: ctrl.signal };
                    if (body && method !== 'GET' && method !== 'HEAD') opts.body = body;
                    const r = await fetch(url, opts);
                    clearTimeout(timer);
                    const h = {};
                    r.headers.forEach((v, k) => { h[k] = v; });
                    return { s: r.status, h: h, b: await r.text() };
                } catch (e) {
                    return { err: e.message };
                }
            }
            """;

    private final Playwright pw;
    private final Browser browser;
    private final Page page;
    private final String targetHost;

    public static BrowserTransport stub(String targetHost) {
        return new BrowserTransport(null, null, null, targetHost);
    }

    private BrowserTransport(Playwright pw, Browser browser, Page page, String targetHost) {
        this.pw = pw;
        this.browser = browser;
        this.page = page;
        this.targetHost = targetHost;
    }

    public static BrowserTransport create(String targetUrl, Consumer<String> log) {
        try {
            Class.forName("com.microsoft.playwright.Playwright");
        } catch (ClassNotFoundException e) {
            log.accept("[!] Playwright nao disponivel no classpath");
            return null;
        }
        Playwright pw = null;
        Browser browser = null;
        try {
            pw = Playwright.create();
            browser = pw.chromium().launch(new BrowserType.LaunchOptions().setHeadless(true).setArgs(List.of(
                    "--disable-blink-features=AutomationControlled", "--no-first-run", "--no-default-browser-check")));
            BrowserContext ctx = browser
                    .newContext(new Browser.NewContextOptions().setUserAgent(StealthHttpClient.CHROME_UA));
            Page page = ctx.newPage();
            page.setDefaultTimeout(PAGE_DEFAULT_TIMEOUT_MS);

            String host = URI.create(targetUrl).getHost();
            log.accept("[*] BrowserTransport: navegando para " + targetUrl);
            Response resp = page.navigate(targetUrl, new Page.NavigateOptions().setTimeout(NAVIGATE_TIMEOUT_MS));
            int status = resp != null ? resp.status() : -1;
            log.accept("[+] BrowserTransport: Chromium ready (HTTP " + status + ")");

            return new BrowserTransport(pw, browser, page, host);
        } catch (Exception e) {
            if (browser != null) {
                try {
                    browser.close();
                } catch (Exception ignored) {
                }
            }
            if (pw != null) {
                try {
                    pw.close();
                } catch (Exception ignored) {
                }
            }
            String msg = e.getMessage();
            if (msg != null && msg.contains("Executable doesn't exist")) {
                log.accept("[!] Chromium nao instalado. Execute:");
                log.accept("    java -cp <jar> com.microsoft.playwright.CLI install chromium");
            } else {
                log.accept("[!] BrowserTransport falhou: " + (msg != null ? msg : e.getClass().getName()));
            }
            return null;
        }
    }

    public boolean isTargetHost(String url) {
        try {
            return targetHost.equalsIgnoreCase(URI.create(url).getHost());
        } catch (Exception e) {
            return false;
        }
    }

    @SuppressWarnings("unchecked")
    public synchronized HttpResponse<String> fetch(HttpRequest req) throws IOException {
        String url = req.uri().toString();
        String method = req.method();

        Map<String, String> headers = new LinkedHashMap<>();
        for (var entry : req.headers().map().entrySet()) {
            String name = entry.getKey().toLowerCase();
            if (name.equals("host") || name.equals("connection") || name.startsWith("sec-")) {
                continue;
            }
            if (!entry.getValue().isEmpty()) {
                headers.put(entry.getKey(), String.join(", ", entry.getValue()));
            }
        }

        String body = "";
        if (req.bodyPublisher().isPresent()) {
            byte[] bytes = StealthHttpClient.readBodyPublisher(req.bodyPublisher().get());
            body = new String(bytes, StandardCharsets.UTF_8);
        }

        Object raw = page.evaluate(FETCH_JS, List.of(url, method, headers, body, FETCH_TIMEOUT_MS));
        if (raw == null) {
            throw new IOException("browser fetch returned null for " + url);
        }
        var result = (Map<String, Object>) raw;

        if (result.containsKey("err")) {
            throw new IOException("browser fetch: " + result.get("err"));
        }

        int status = ((Number) result.get("s")).intValue();
        String responseBody = (String) result.get("b");
        var rawHeaders = (Map<String, String>) result.get("h");
        Map<String, List<String>> headerMap = new LinkedHashMap<>();
        if (rawHeaders != null) {
            rawHeaders.forEach((k, v) -> headerMap.put(k, List.of(v)));
        }
        HttpHeaders jdkHeaders = HttpHeaders.of(headerMap, (k, v) -> true);

        return new StealthHttpClient.StealthResponse(status, responseBody, jdkHeaders, req.uri());
    }

    @Override
    public void close() {
        try {
            browser.close();
        } catch (Exception ignored) {
        }
        try {
            pw.close();
        } catch (Exception ignored) {
        }
    }
}
