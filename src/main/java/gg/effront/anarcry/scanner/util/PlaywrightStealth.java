package gg.effront.anarcry.scanner.util;

import com.microsoft.playwright.BrowserContext;

final class PlaywrightStealth {

    private PlaywrightStealth() {
    }

    static void apply(BrowserContext ctx) {
        ctx.addInitScript(STEALTH_SCRIPT);
    }

    @SuppressWarnings("StringConcatenationInsideStringBufferAppend")
    private static final String STEALTH_SCRIPT = """
            // -- navigator.webdriver removal --
            Object.defineProperty(navigator, 'webdriver', {
                get: () => undefined
            });

            // -- chrome runtime stub --
            if (!window.chrome) {
                window.chrome = {};
            }
            if (!window.chrome.runtime) {
                window.chrome.runtime = {
                    connect: function() {},
                    sendMessage: function() {}
                };
            }

            // -- navigator.plugins (non-empty array signals real browser) --
            Object.defineProperty(navigator, 'plugins', {
                get: () => {
                    const arr = [
                        { name: 'Chrome PDF Plugin', filename: 'internal-pdf-viewer',
                          description: 'Portable Document Format', length: 1 },
                        { name: 'Chrome PDF Viewer', filename: 'mhjfbmdgcfjbbpaeojofohoefgiehjai',
                          description: '', length: 1 },
                        { name: 'Native Client', filename: 'internal-nacl-plugin',
                          description: '', length: 2 }
                    ];
                    arr.item = (i) => arr[i];
                    arr.namedItem = (name) => arr.find(p => p.name === name);
                    arr.refresh = () => {};
                    return arr;
                }
            });

            // -- navigator.languages --
            Object.defineProperty(navigator, 'languages', {
                get: () => ['en-US', 'en']
            });

            // -- permissions.query override (notifications check) --
            const origQuery = window.navigator.permissions.query.bind(window.navigator.permissions);
            window.navigator.permissions.query = (params) => {
                if (params.name === 'notifications') {
                    return Promise.resolve({ state: Notification.permission });
                }
                return origQuery(params);
            };

            // -- WebGL vendor/renderer spoofing --
            const getParam = WebGLRenderingContext.prototype.getParameter;
            WebGLRenderingContext.prototype.getParameter = function(p) {
                if (p === 37445) return 'Google Inc. (NVIDIA)';
                if (p === 37446) return 'ANGLE (NVIDIA, NVIDIA GeForce GTX 1650 SUPER, OpenGL 4.5)';
                return getParam.call(this, p);
            };

            // -- Headless detection via missing connection-rtt --
            Object.defineProperty(navigator, 'connection', {
                get: () => ({
                    rtt: 50, downlink: 10, effectiveType: '4g', saveData: false
                })
            });
            """;
}
