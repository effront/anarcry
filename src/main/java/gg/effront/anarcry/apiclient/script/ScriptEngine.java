package gg.effront.anarcry.apiclient.script;

import gg.effront.anarcry.apiclient.model.HttpRequestDef;
import gg.effront.anarcry.apiclient.model.ResponseData;
import gg.effront.anarcry.apiclient.model.ScriptDef;
import gg.effront.anarcry.apiclient.vars.VariableStore;

import org.graalvm.polyglot.Context;
import org.graalvm.polyglot.HostAccess;
import org.graalvm.polyglot.PolyglotException;
import org.graalvm.polyglot.Source;
import org.graalvm.polyglot.Value;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public class ScriptEngine {

    private static final long SCRIPT_TIMEOUT_MS = 10_000;
    private static final String TEST_FRAMEWORK_JS = """
            var __testResults = [];
            function test(name, fn) {
                try {
                    fn();
                    __testResults.push({ name: name, passed: true, message: '' });
                } catch (e) {
                    __testResults.push({ name: name, passed: false, message: e.message || String(e) });
                }
            }
            function expect(actual) {
                return {
                    toBe: function(expected) {
                        if (actual !== expected) {
                            throw new Error('Expected '
                                + JSON.stringify(expected)
                                + ' but got ' + JSON.stringify(actual));
                        }
                    },
                    toEqual: function(expected) {
                        if (JSON.stringify(actual) !== JSON.stringify(expected)) {
                            throw new Error('Expected '
                                + JSON.stringify(expected)
                                + ' but got ' + JSON.stringify(actual));
                        }
                    },
                    toBeGreaterThan: function(expected) {
                        if (!(actual > expected)) {
                            throw new Error('Expected ' + actual + ' to be greater than ' + expected);
                        }
                    },
                    toBeLessThan: function(expected) {
                        if (!(actual < expected)) {
                            throw new Error('Expected ' + actual + ' to be less than ' + expected);
                        }
                    },
                    toBeGreaterThanOrEqual: function(expected) {
                        if (!(actual >= expected)) {
                            throw new Error('Expected ' + actual + ' to be >= ' + expected);
                        }
                    },
                    toBeLessThanOrEqual: function(expected) {
                        if (!(actual <= expected)) {
                            throw new Error('Expected ' + actual + ' to be <= ' + expected);
                        }
                    },
                    toContain: function(expected) {
                        if (typeof actual === 'string') {
                            if (actual.indexOf(expected) === -1) {
                                throw new Error('Expected string to contain ' + JSON.stringify(expected));
                            }
                        } else if (Array.isArray(actual)) {
                            if (actual.indexOf(expected) === -1) {
                                throw new Error('Expected array to contain ' + JSON.stringify(expected));
                            }
                        } else {
                            throw new Error('toContain requires a string or array');
                        }
                    },
                    toHaveLength: function(expected) {
                        var len = actual ? actual.length : 0;
                        if (len !== expected) {
                            throw new Error('Expected length ' + expected + ' but got ' + len);
                        }
                    },
                    toBeTruthy: function() {
                        if (!actual) {
                            throw new Error('Expected truthy but got ' + JSON.stringify(actual));
                        }
                    },
                    toBeFalsy: function() {
                        if (actual) {
                            throw new Error('Expected falsy but got ' + JSON.stringify(actual));
                        }
                    },
                    toBeDefined: function() {
                        if (actual === undefined || actual === null) {
                            throw new Error('Expected defined but got ' + actual);
                        }
                    },
                    toBeUndefined: function() {
                        if (actual !== undefined && actual !== null) {
                            throw new Error('Expected undefined but got ' + JSON.stringify(actual));
                        }
                    },
                    toMatch: function(pattern) {
                        var regex = (typeof pattern === 'string') ? new RegExp(pattern) : pattern;
                        if (!regex.test(actual)) {
                            throw new Error('Expected ' + JSON.stringify(actual) + ' to match ' + pattern);
                        }
                    },
                    toHaveProperty: function(prop) {
                        if (actual === null || actual === undefined || !(prop in actual)) {
                            throw new Error('Expected object to have property ' + JSON.stringify(prop));
                        }
                    },
                    not: {
                        toBe: function(expected) {
                            if (actual === expected) {
                                throw new Error('Expected not to be ' + JSON.stringify(expected));
                            }
                        },
                        toEqual: function(expected) {
                            if (JSON.stringify(actual) === JSON.stringify(expected)) {
                                throw new Error('Expected not to equal ' + JSON.stringify(expected));
                            }
                        },
                        toContain: function(expected) {
                            if (typeof actual === 'string' && actual.indexOf(expected) !== -1) {
                                throw new Error('Expected string not to contain ' + JSON.stringify(expected));
                            }
                            if (Array.isArray(actual) && actual.indexOf(expected) !== -1) {
                                throw new Error('Expected array not to contain ' + JSON.stringify(expected));
                            }
                        },
                        toBeTruthy: function() {
                            if (actual) {
                                throw new Error('Expected falsy but got ' + JSON.stringify(actual));
                            }
                        },
                        toBeDefined: function() {
                            if (actual !== undefined && actual !== null) {
                                throw new Error('Expected undefined but got ' + JSON.stringify(actual));
                            }
                        },
                        toMatch: function(pattern) {
                            var regex = (typeof pattern === 'string') ? new RegExp(pattern) : pattern;
                            if (regex.test(actual)) {
                                throw new Error('Expected ' + JSON.stringify(actual) + ' not to match ' + pattern);
                            }
                        }
                    }
                };
            }
            """;

    private static final String RES_BRIDGE_WRAPPER_JS = """
            (function() {
                var __jres = res;
                res = {
                    getStatus: function() { return __jres.getStatus(); },
                    getStatusText: function() { return __jres.getStatusText(); },
                    getBody: function() {
                        var raw = __jres.getBody();
                        if (raw && typeof raw === 'string') {
                            try { return JSON.parse(raw); } catch(e) { return raw; }
                        }
                        return raw;
                    },
                    getHeader: function(n) { return __jres.getHeader(n); },
                    getHeaders: function() { return __jres.getHeaders(); },
                    getResponseTime: function() { return __jres.getResponseTime(); },
                    getSize: function() { return __jres.getSize(); }
                };
            })();
            """;

    public ScriptResult runPreRequest(ScriptDef scripts, HttpRequestDef request, VariableStore vars) {
        if (scripts == null || !scripts.hasPreRequest()) {
            return ScriptResult.empty();
        }
        return executeScript(scripts.preRequest(), request, null, vars, false);
    }

    public ScriptResult runPostResponse(ScriptDef scripts, HttpRequestDef request, ResponseData response,
            VariableStore vars) {
        if (scripts == null) {
            return ScriptResult.empty();
        }
        List<String> allLogs = new ArrayList<>();
        List<ScriptResult.TestResult> allTests = new ArrayList<>();

        if (scripts.hasPostResponse()) {
            ScriptResult postResult = executeScript(scripts.postResponse(), request, response, vars, false);
            allLogs.addAll(postResult.consoleLog());
            if (postResult.hasError()) {
                return new ScriptResult(allLogs, allTests, postResult.error());
            }
        }

        if (scripts.hasTests()) {
            ScriptResult testResult = executeScript(scripts.tests(), request, response, vars, true);
            allLogs.addAll(testResult.consoleLog());
            allTests.addAll(testResult.testResults());
            if (testResult.hasError()) {
                return new ScriptResult(allLogs, allTests, testResult.error());
            }
        }

        return new ScriptResult(allLogs, allTests, null);
    }

    private ScriptResult executeScript(String script, HttpRequestDef request, ResponseData response, VariableStore vars,
            boolean includeTestFramework) {
        List<String> consoleLog = new ArrayList<>();
        BruBridge bru = new BruBridge(vars);
        ReqBridge req = new ReqBridge(request);
        ResBridge res = new ResBridge();
        if (response != null) {
            res.setResponse(response);
        }

        HostAccess hostAccess = HostAccess.newBuilder(HostAccess.EXPLICIT)
                .targetTypeMapping(Value.class, Object.class, v -> v.hasArrayElements(), v -> {
                    long size = v.getArraySize();
                    Object[] arr = new Object[(int) size];
                    for (int i = 0; i < size; i++) {
                        arr[i] = v.getArrayElement(i).as(Object.class);
                    }
                    return arr;
                }).targetTypeMapping(Value.class, Map.class, Value::hasMembers, v -> {
                    var map = new java.util.LinkedHashMap<String, Object>();
                    for (String key : v.getMemberKeys()) {
                        map.put(key, v.getMember(key).as(Object.class));
                    }
                    return map;
                }).build();

        try (Context context = Context.newBuilder("js").allowHostAccess(hostAccess)
                .option("engine.WarnInterpreterOnly", "false").build()) {

            Value bindings = context.getBindings("js");
            bindings.putMember("bru", bru);
            bindings.putMember("req", req);
            bindings.putMember("res", res);

            ConsoleCapture console = new ConsoleCapture(consoleLog);
            bindings.putMember("__console", console);

            context.eval(Source.newBuilder("js",
                    "var console = { log: function() { __console.log(Array.prototype.join.call(arguments, ' ')); }, "
                            + "warn: function() { __console.warn(Array.prototype.join.call(arguments, ' ')); }, "
                            + "error: function() { __console.error(Array.prototype.join.call(arguments, ' ')); }, "
                            + "info: function() { __console.info(Array.prototype.join.call(arguments, ' ')); } };",
                    "console-setup").build());

            context.eval(Source.newBuilder("js", RES_BRIDGE_WRAPPER_JS, "res-wrapper").build());

            if (includeTestFramework) {
                context.eval(Source.newBuilder("js", TEST_FRAMEWORK_JS, "test-framework").build());
            }

            context.eval(Source.newBuilder("js", script, "user-script").build());

            List<ScriptResult.TestResult> testResults = new ArrayList<>();
            if (includeTestFramework) {
                Value results = context.eval("js", "__testResults");
                if (results.hasArrayElements()) {
                    for (long i = 0; i < results.getArraySize(); i++) {
                        Value item = results.getArrayElement(i);
                        String name = item.getMember("name").asString();
                        boolean passed = item.getMember("passed").asBoolean();
                        String message = item.getMember("message").asString();
                        testResults.add(new ScriptResult.TestResult(name, passed, message));
                    }
                }
            }

            return new ScriptResult(consoleLog, testResults, null);

        } catch (PolyglotException e) {
            String msg = e.getMessage();
            if (e.isGuestException()) {
                msg = e.getGuestObject() != null ? e.getGuestObject().toString() : e.getMessage();
            }
            return new ScriptResult(consoleLog, List.of(), msg);
        } catch (Exception e) {
            return new ScriptResult(consoleLog, List.of(), e.getMessage());
        }
    }

    public static class ConsoleCapture {

        private final List<String> log;

        public ConsoleCapture(List<String> log) {
            this.log = log;
        }

        @HostAccess.Export
        public void log(String message) {
            this.log.add("[log] " + message);
        }

        @HostAccess.Export
        public void warn(String message) {
            this.log.add("[warn] " + message);
        }

        @HostAccess.Export
        public void error(String message) {
            this.log.add("[error] " + message);
        }

        @HostAccess.Export
        public void info(String message) {
            this.log.add("[info] " + message);
        }
    }
}
