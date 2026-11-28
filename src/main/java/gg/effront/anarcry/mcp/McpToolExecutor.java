package gg.effront.anarcry.mcp;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import gg.effront.anarcry.model.Finding;
import gg.effront.anarcry.scanner.DiscoveredPaths;
import gg.effront.anarcry.scanner.ScanConfig;
import gg.effront.anarcry.scanner.ScanContext;
import gg.effront.anarcry.scanner.Scanner;
import gg.effront.anarcry.scanner.SuppressionLoader;
import gg.effront.anarcry.scanner.util.WafState;
import gg.effront.anarcry.scanner.crypto.headers.HeadersModule;
import gg.effront.anarcry.scanner.crypto.jwt.JwtModule;
import gg.effront.anarcry.scanner.crypto.tls.TlsModule;
import gg.effront.anarcry.scanner.web.cmdinject.CommandInjectionModule;
import gg.effront.anarcry.scanner.web.cors.CorsModule;
import gg.effront.anarcry.scanner.web.csrf.CsrfModule;
import gg.effront.anarcry.scanner.web.graphql.GraphQLModule;
import gg.effront.anarcry.scanner.web.idor.IdorModule;
import gg.effront.anarcry.scanner.web.lfi.LfiModule;
import gg.effront.anarcry.scanner.web.openredirect.OpenRedirectModule;
import gg.effront.anarcry.scanner.web.sqli.SqlInjectionModule;
import gg.effront.anarcry.scanner.web.ssrf.SsrfModule;
import gg.effront.anarcry.scanner.web.ssti.SstiModule;
import gg.effront.anarcry.scanner.web.xss.XssModule;
import gg.effront.anarcry.scanner.web.xxe.XxeModule;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.function.Consumer;

/**
 * Executes a single MCP tool call by instantiating the appropriate scanner
 * module, building a minimal ScanContext, and returning findings as JSON.
 */
public final class McpToolExecutor {

    private static final int DEFAULT_TIMEOUT_SECONDS = 120;
    private static final Gson GSON = new GsonBuilder().setPrettyPrinting().create();

    private final McpToolRegistry registry;
    private final ExecutorService executor;
    private final int timeoutSeconds;

    public McpToolExecutor(McpToolRegistry registry) {
        this(registry, DEFAULT_TIMEOUT_SECONDS);
    }

    public McpToolExecutor(McpToolRegistry registry, int timeoutSeconds) {
        this.registry = registry;
        this.timeoutSeconds = timeoutSeconds;
        this.executor = Executors.newThreadPerTaskExecutor(Thread.ofVirtual().name("mcp-exec-", 0).factory());
    }

    /**
     * Executes a tool call and returns the MCP content array JSON. Throws if the
     * tool name is unknown or execution times out.
     */
    public JsonArray execute(String toolName, String targetUrl, String authToken) throws Exception {
        String moduleId = registry.moduleIdFor(toolName);
        if (moduleId == null) {
            throw new IllegalArgumentException("Unknown tool: " + toolName);
        }

        Scanner module = instantiateModule(moduleId);
        if (module == null) {
            throw new IllegalArgumentException("No scanner module for: " + moduleId);
        }

        ScanContext ctx = buildContext(targetUrl, authToken, moduleId);
        List<String> logLines = new ArrayList<>();
        Consumer<String> log = line -> {
            synchronized (logLines) {
                logLines.add(line);
            }
        };

        Callable<List<Finding>> task = () -> module.scan(ctx, log);
        Future<List<Finding>> future = executor.submit(task);

        List<Finding> findings;
        try {
            findings = future.get(timeoutSeconds, TimeUnit.SECONDS);
        } catch (TimeoutException te) {
            future.cancel(true);
            throw new TimeoutException("Tool execution timed out after " + timeoutSeconds + "s for " + toolName);
        } catch (ExecutionException ee) {
            Throwable cause = ee.getCause();
            if (cause instanceof Exception ex) {
                throw ex;
            }
            throw new RuntimeException(cause);
        }

        return buildContentArray(findings, logLines);
    }

    /** Builds the MCP content response array with findings JSON and log. */
    private JsonArray buildContentArray(List<Finding> findings, List<String> logLines) {
        JsonObject result = new JsonObject();
        result.addProperty("finding_count", findings.size());

        JsonArray findingsArr = new JsonArray();
        for (Finding f : findings) {
            JsonObject fj = new JsonObject();
            fj.addProperty("module", f.module());
            fj.addProperty("endpoint", f.endpoint());
            fj.addProperty("title", f.title());
            fj.addProperty("severity", f.severity().name());
            fj.addProperty("evidence", f.evidence());
            fj.addProperty("impact", f.impact());
            fj.addProperty("reproduction", f.reproduction());
            fj.addProperty("recommendation", f.recommendation());
            fj.addProperty("cwe_id", f.cweId());
            fj.addProperty("cwe_title", f.cweTitle());
            fj.addProperty("cvss_vector", f.cvssVector());
            fj.addProperty("cvss_score", f.cvssScore());
            findingsArr.add(fj);
        }
        result.add("findings", findingsArr);

        JsonArray logArr = new JsonArray();
        synchronized (logLines) {
            for (String line : logLines) {
                logArr.add(line);
            }
        }
        result.add("log", logArr);

        JsonArray content = new JsonArray();
        JsonObject textBlock = new JsonObject();
        textBlock.addProperty("type", "text");
        textBlock.addProperty("text", GSON.toJson(result));
        content.add(textBlock);
        return content;
    }

    /** Instantiates the scanner module for the given module ID. */
    private static Scanner instantiateModule(String moduleId) {
        return switch (moduleId) {
            case "SQLi" -> new SqlInjectionModule();
            case "XSS" -> new XssModule();
            case "SSRF" -> new SsrfModule();
            case "SSTI" -> new SstiModule();
            case "LFI" -> new LfiModule();
            case "XXE" -> new XxeModule();
            case "CORS" -> new CorsModule();
            case "Headers" -> new HeadersModule();
            case "CmdInjection" -> new CommandInjectionModule();
            case "OpenRedirect" -> new OpenRedirectModule();
            case "GraphQL" -> new GraphQLModule();
            case "JWT" -> new JwtModule();
            case "TLS" -> new TlsModule();
            case "IDOR" -> new IdorModule();
            case "CSRF" -> new CsrfModule();
            default -> null;
        };
    }

    /**
     * Builds a minimal ScanContext for a single-module MCP execution. Only the
     * target module is enabled; auth token is wired as JWT/Bearer if provided.
     */
    private static ScanContext buildContext(String targetUrl, String authToken, String moduleId) {
        String jwt = (authToken != null && !authToken.isBlank()) ? authToken : "";
        Set<String> enabledModules = Set.of(moduleId);
        ScanConfig cfg = new ScanConfig(0, "", "", Set.of(), SuppressionLoader.loadFromCwd(), "",
                ScanConfig.DEFAULT_PROBE_CONCURRENCY);
        return new ScanContext(targetUrl, jwt, "", enabledModules, cfg, r -> {
        }, new DiscoveredPaths(), new WafState());
    }

    /** Shuts down the executor; pending tasks are cancelled. */
    public void shutdown() {
        executor.shutdownNow();
    }
}
