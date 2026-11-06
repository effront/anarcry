package gg.effront.anarcry.apiclient.runner;

import gg.effront.anarcry.apiclient.model.Collection;
import gg.effront.anarcry.apiclient.model.CollectionItem;
import gg.effront.anarcry.apiclient.model.Environment;
import gg.effront.anarcry.apiclient.model.Folder;
import gg.effront.anarcry.apiclient.model.RequestItem;
import gg.effront.anarcry.apiclient.model.RequestResult;
import gg.effront.anarcry.apiclient.model.RunResult;
import gg.effront.anarcry.apiclient.model.RunSummary;
import gg.effront.anarcry.apiclient.vars.VariableStore;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;

public class CollectionRunner {

    private static final int MAX_JUMPS = 10_000;

    private final RequestExecutor executor;

    public CollectionRunner(RequestExecutor executor) {
        this.executor = executor;
    }

    public RunResult run(Collection collection, Environment env, Consumer<String> log) {
        return run(collection, env, log, new RunContext(buildVarStore(collection, env)));
    }

    public RunResult run(Collection collection, Environment env, Consumer<String> log, RunContext ctx) {
        long totalStart = System.nanoTime();
        List<RequestItem> flatRequests = flatten(collection.items());

        log.accept("[*] Running collection: " + collection.name() + " (" + flatRequests.size() + " requests)");
        if (env != null) {
            log.accept("[*] Environment: " + env.name());
        }

        int index = 0;
        int jumps = 0;

        while (index < flatRequests.size() && !ctx.shouldStop()) {
            RequestItem item = flatRequests.get(index);
            log.accept("[*] " + (index + 1) + "/" + flatRequests.size() + " " + item.name());

            RequestResult result = executor.execute(item, ctx, collection, log);
            ctx.results().add(result);

            String status = result.passed() ? "PASS" : "FAIL";
            log.accept("  -> " + status + " (" + result.durationMs() + "ms)");

            if (ctx.shouldStop()) {
                break;
            }
            if (ctx.nextRequest() != null && jumps < MAX_JUMPS) {
                int next = findByName(flatRequests, ctx.nextRequest());
                ctx.clearNextRequest();
                if (next >= 0) {
                    index = next;
                    jumps++;
                    continue;
                }
                log.accept("[!] setNextRequest target not found: " + ctx.nextRequest());
            }
            index++;
        }

        long totalDuration = (System.nanoTime() - totalStart) / 1_000_000;
        RunSummary summary = computeSummary(ctx.results(), totalDuration);

        log.accept("[*] Done: " + summary.passed() + "/" + summary.total() + " passed, " + summary.failed()
                + " failed (" + totalDuration + "ms)");

        return new RunResult(ctx.results(), summary, totalDuration);
    }

    public RequestResult runSingle(RequestItem item, Collection collection, Environment env, Consumer<String> log) {
        VariableStore vars = buildVarStore(collection, env);
        RunContext ctx = new RunContext(vars);
        return executor.execute(item, ctx, collection, log);
    }

    private VariableStore buildVarStore(Collection collection, Environment env) {
        VariableStore vars = new VariableStore();
        vars.loadCollection(collection.root());
        if (env != null) {
            vars.loadEnv(env);
        }
        return vars;
    }

    static List<RequestItem> flatten(List<CollectionItem> items) {
        List<RequestItem> result = new ArrayList<>();
        flattenRecursive(items, result);
        return result;
    }

    private static void flattenRecursive(List<CollectionItem> items, List<RequestItem> result) {
        for (CollectionItem item : items) {
            switch (item) {
                case RequestItem ri -> result.add(ri);
                case Folder folder -> flattenRecursive(folder.items(), result);
            }
        }
    }

    private int findByName(List<RequestItem> requests, String name) {
        for (int i = 0; i < requests.size(); i++) {
            if (requests.get(i).name().equals(name)) {
                return i;
            }
        }
        return -1;
    }

    private RunSummary computeSummary(List<RequestResult> results, long totalDuration) {
        int total = results.size();
        int passed = 0;
        int failed = 0;
        for (RequestResult r : results) {
            if (r.passed()) {
                passed++;
            } else {
                failed++;
            }
        }
        int skipped = 0;
        return new RunSummary(total, passed, failed, skipped, totalDuration);
    }
}
