package gg.effront.anarcry.mcp;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import gg.effront.anarcry.artex.FindingDto;
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
import java.util.Map;
import java.util.Set;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.function.Consumer;
import java.util.function.Supplier;

/**
 * Executes a single MCP tool call by instantiating the appropriate scanner
 * module, building a minimal ScanContext, and returning findings as JSON.
 */
public final class McpToolExecutor {

    private static final int DEFAULT_TIMEOUT_SECONDS = 120;
    private static final Gson GSON = new GsonBuilder().setPrettyPrinting().create();

    private static final Map<String, Supplier<Scanner>> MODULE_FACTORIES = Map.ofEntries(
            Map.entry("SQLi", SqlInjectionModule::new), Map.entry("XSS", XssModule::new),
            Map.entry("SSRF", SsrfModule::new), Map.entry("SSTI", SstiModule::new), Map.entry("LFI", LfiModule::new),
            Map.entry("XXE", XxeModule::new), Map.entry("CORS", CorsModule::new),
            Map.entry("Headers", HeadersModule::new), Map.entry("CmdInjection", CommandInjectionModule::new),
            Map.entry("OpenRedirect", OpenRedirectModule::new), Map.entry("GraphQL", GraphQLModule::new),
            Map.entry("JWT", JwtModule::new), Map.entry("TLS", TlsModule::new), Map.entry("IDOR", IdorModule::new),
            Map.entry("CSRF", CsrfModule::new));

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
            findingsArr.add(FindingDto.toJsonObject(f));
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
        Supplier<Scanner> factory = MODULE_FACTORIES.get(moduleId);
        return factory != null ? factory.get() : null;
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
