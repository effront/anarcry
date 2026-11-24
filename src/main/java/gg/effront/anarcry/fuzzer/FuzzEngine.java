package gg.effront.anarcry.fuzzer;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.concurrent.Semaphore;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

public final class FuzzEngine {

    public record FuzzConfig(String template, AttackType attackType, List<PayloadSource> sources,
            List<List<PayloadProcessor>> processorPipelines, int threads, int delayMs, int jitterPercent,
            int timeoutSeconds, GrepMatcher grepMatcher, String sessionTokenUrl, String sessionTokenRegex,
            String sessionTokenHeader, int sessionTokenRefreshInterval) {
    }

    public interface FuzzListener {
        void onResult(FuzzResult result);

        void onProgress(int completed, long total);

        void onComplete(int totalCompleted, long elapsedMs);

        void onError(String message);
    }

    private final AtomicBoolean cancelled = new AtomicBoolean(false);
    private final AtomicBoolean paused = new AtomicBoolean(false);
    private final AtomicInteger completedCount = new AtomicInteger(0);
    private final AtomicReference<String> sessionToken = new AtomicReference<>("");
    private volatile boolean running;

    public void start(FuzzConfig config, FuzzListener listener) {
        if (running) {
            listener.onError("Fuzzer already running");
            return;
        }
        cancelled.set(false);
        paused.set(false);
        completedCount.set(0);
        running = true;

        Thread.ofVirtual().name("fuzz-orchestrator").start(() -> {
            long startTime = System.nanoTime();
            try {
                run(config, listener);
            } finally {
                long elapsed = (System.nanoTime() - startTime) / 1_000_000;
                running = false;
                listener.onComplete(completedCount.get(), elapsed);
            }
        });
    }

    public void pause() {
        paused.set(true);
    }

    public void resume() {
        paused.set(false);
    }

    public boolean isPaused() {
        return paused.get();
    }

    public void stop() {
        cancelled.set(true);
        paused.set(false);
    }

    public boolean isRunning() {
        return running;
    }

    private void run(FuzzConfig config, FuzzListener listener) {
        List<FuzzPosition> positions = FuzzPosition.parse(config.template());
        if (positions.isEmpty()) {
            listener.onError("No positions marked in template (use {{1}}, {{2}}, etc.)");
            return;
        }

        int maxIdx = FuzzPosition.maxIndex(positions);
        List<PayloadSource> sources = config.sources();
        if (sources.isEmpty()) {
            listener.onError("No payload sources configured");
            return;
        }

        long totalRequests = config.attackType().estimateRequests(maxIdx, sources);
        List<String[]> combinations = generateCombinations(config.attackType(), maxIdx, sources,
                config.processorPipelines());

        Semaphore sem = new Semaphore(config.threads());
        HttpClient httpClient = HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NORMAL)
                .connectTimeout(Duration.ofSeconds(config.timeoutSeconds())).build();

        AtomicInteger requestNum = new AtomicInteger(0);

        for (String[] payloads : combinations) {
            if (cancelled.get()) {
                break;
            }
            while (paused.get() && !cancelled.get()) {
                try {
                    Thread.sleep(100);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    return;
                }
            }
            if (cancelled.get()) {
                break;
            }

            try {
                sem.acquire();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return;
            }

            int num = requestNum.incrementAndGet();
            String[] payloadsCopy = payloads.clone();

            Thread.ofVirtual().name("fuzz-req-" + num).start(() -> {
                try {
                    FuzzResult result = executeRequest(config, positions, payloadsCopy, num, httpClient);
                    listener.onResult(result);
                    int done = completedCount.incrementAndGet();
                    listener.onProgress(done, totalRequests);
                } finally {
                    sem.release();
                }
            });

            if (config.delayMs() > 0) {
                int delay = config.delayMs();
                if (config.jitterPercent() > 0) {
                    int jitter = (int) (delay * config.jitterPercent() / 100.0);
                    delay += (int) (Math.random() * 2 * jitter) - jitter;
                    if (delay < 0) {
                        delay = 0;
                    }
                }
                try {
                    Thread.sleep(delay);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    return;
                }
            }
        }

        // wait for remaining threads
        try {
            sem.acquire(config.threads());
            sem.release(config.threads());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    private FuzzResult executeRequest(FuzzConfig config, List<FuzzPosition> positions, String[] payloads, int num,
            HttpClient httpClient) {
        String raw = FuzzPosition.inject(config.template(), positions, payloads);

        String[] parts = parseRawRequest(raw);
        String method = parts[0];
        String url = parts[1];
        String headers = parts[2];
        String body = parts[3];

        try {
            HttpRequest.Builder builder = HttpRequest.newBuilder().uri(URI.create(url))
                    .timeout(Duration.ofSeconds(config.timeoutSeconds()));

            for (String line : headers.split("\n")) {
                String trimmed = line.trim();
                if (trimmed.isEmpty()) {
                    continue;
                }
                int sep = trimmed.indexOf(':');
                if (sep > 0) {
                    String key = trimmed.substring(0, sep).trim();
                    String val = trimmed.substring(sep + 1).trim();
                    if (key.equalsIgnoreCase("host")) {
                        continue;
                    }
                    builder.header(key, val);
                }
            }

            String token = sessionToken.get();
            if (token != null && !token.isEmpty() && config.sessionTokenHeader() != null) {
                builder.header(config.sessionTokenHeader(), token);
            }

            applyMethod(builder, method, body);

            long start = System.nanoTime();
            HttpResponse<String> resp = httpClient.send(builder.build(), HttpResponse.BodyHandlers.ofString());
            long timeMs = (System.nanoTime() - start) / 1_000_000;

            String respBody = resp.body();
            StringBuilder respHeaders = new StringBuilder();
            resp.headers().map().forEach((k, vals) -> {
                for (String v : vals) {
                    respHeaders.append(k).append(": ").append(v).append("\n");
                }
            });

            int[] matchCounts = config.grepMatcher() != null ? config.grepMatcher().countMatches(respBody) : new int[0];
            String[] extracts = config.grepMatcher() != null ? config.grepMatcher().extract(respBody) : new String[0];

            return new FuzzResult(num, payloads, resp.statusCode(), respBody.length(), timeMs, respBody,
                    respHeaders.toString(), null, matchCounts, extracts);

        } catch (Exception e) {
            String errMsg = e.getClass().getSimpleName() + ": " + e.getMessage();
            return new FuzzResult(num, payloads, 0, 0, 0, "", "", errMsg, new int[0], new String[0]);
        }
    }

    private static void applyMethod(HttpRequest.Builder builder, String method, String body) {
        boolean hasBody = body != null && !body.isBlank();
        switch (method.toUpperCase()) {
            case "GET" -> builder.GET();
            case "DELETE" -> builder.DELETE();
            case "HEAD" -> builder.method("HEAD", HttpRequest.BodyPublishers.noBody());
            case "OPTIONS" -> builder.method("OPTIONS", HttpRequest.BodyPublishers.noBody());
            case "POST" -> builder.POST(HttpRequest.BodyPublishers.ofString(hasBody ? body : ""));
            case "PUT" -> builder.PUT(HttpRequest.BodyPublishers.ofString(hasBody ? body : ""));
            case "PATCH" -> builder.method("PATCH", HttpRequest.BodyPublishers.ofString(hasBody ? body : ""));
            default -> builder.method(method,
                    hasBody ? HttpRequest.BodyPublishers.ofString(body) : HttpRequest.BodyPublishers.noBody());
        }
    }

    public static String[] parseRawRequest(String raw) {
        String method = "GET";
        String url = "";
        StringBuilder headers = new StringBuilder();
        String body = "";

        String[] lines = raw.split("\n");
        if (lines.length == 0) {
            return new String[]{method, url, "", ""};
        }

        String requestLine = lines[0].trim();
        String[] rlParts = requestLine.split("\\s+");
        if (rlParts.length >= 2) {
            method = rlParts[0];
            String path = rlParts[1];

            String host = "";
            for (int i = 1; i < lines.length; i++) {
                String line = lines[i].trim();
                if (line.isEmpty()) {
                    break;
                }
                if (line.toLowerCase().startsWith("host:")) {
                    host = line.substring(5).trim();
                }
            }

            if (path.startsWith("http://") || path.startsWith("https://")) {
                url = path;
            } else if (!host.isEmpty()) {
                String scheme = host.contains(":443") ? "https" : "https";
                url = scheme + "://" + host + path;
            } else {
                url = "https://localhost" + path;
            }
        }

        boolean inBody = false;
        StringBuilder bodyBuilder = new StringBuilder();
        for (int i = 1; i < lines.length; i++) {
            String line = lines[i];
            if (!inBody && line.trim().isEmpty()) {
                inBody = true;
                continue;
            }
            if (inBody) {
                if (bodyBuilder.length() > 0) {
                    bodyBuilder.append("\n");
                }
                bodyBuilder.append(line);
            } else {
                headers.append(line.trim()).append("\n");
            }
        }
        body = bodyBuilder.toString();

        return new String[]{method, url, headers.toString(), body};
    }

    private List<String[]> generateCombinations(AttackType type, int positionCount, List<PayloadSource> sources,
            List<List<PayloadProcessor>> pipelines) {
        List<String[]> results = new ArrayList<>();

        switch (type) {
            case SNIPER -> {
                PayloadSource src = sources.getFirst();
                for (int pos = 0; pos < positionCount; pos++) {
                    src.reset();
                    Iterator<String> it = src.iterator();
                    while (it.hasNext()) {
                        String raw = it.next();
                        String processed = applyPipeline(raw, pipelines, 0);
                        if (processed == null) {
                            continue;
                        }
                        String[] payloads = new String[positionCount];
                        for (int j = 0; j < positionCount; j++) {
                            payloads[j] = "";
                        }
                        payloads[pos] = processed;
                        results.add(payloads);
                    }
                }
            }
            case BATTERING_RAM -> {
                PayloadSource src = sources.getFirst();
                Iterator<String> it = src.iterator();
                while (it.hasNext()) {
                    String raw = it.next();
                    String processed = applyPipeline(raw, pipelines, 0);
                    if (processed == null) {
                        continue;
                    }
                    String[] payloads = new String[positionCount];
                    for (int j = 0; j < positionCount; j++) {
                        payloads[j] = processed;
                    }
                    results.add(payloads);
                }
            }
            case PITCHFORK -> {
                List<Iterator<String>> iterators = new ArrayList<>();
                for (PayloadSource s : sources) {
                    s.reset();
                    iterators.add(s.iterator());
                }
                while (iterators.stream().allMatch(Iterator::hasNext)) {
                    String[] payloads = new String[positionCount];
                    for (int j = 0; j < positionCount; j++) {
                        if (j < iterators.size()) {
                            String raw = iterators.get(j).next();
                            String processed = applyPipeline(raw, pipelines, j);
                            payloads[j] = processed != null ? processed : "";
                        } else {
                            payloads[j] = "";
                        }
                    }
                    results.add(payloads);
                }
            }
            case CLUSTER_BOMB -> {
                List<List<String>> allPayloads = new ArrayList<>();
                for (int i = 0; i < positionCount; i++) {
                    List<String> list = new ArrayList<>();
                    if (i < sources.size()) {
                        sources.get(i).reset();
                        Iterator<String> it = sources.get(i).iterator();
                        while (it.hasNext()) {
                            String raw = it.next();
                            String processed = applyPipeline(raw, pipelines, i);
                            if (processed != null) {
                                list.add(processed);
                            }
                        }
                    }
                    if (list.isEmpty()) {
                        list.add("");
                    }
                    allPayloads.add(list);
                }
                cartesianProduct(allPayloads, 0, new String[positionCount], results);
            }
        }
        return results;
    }

    private static void cartesianProduct(List<List<String>> lists, int depth, String[] current,
            List<String[]> results) {
        if (depth == lists.size()) {
            results.add(current.clone());
            return;
        }
        for (String val : lists.get(depth)) {
            current[depth] = val;
            cartesianProduct(lists, depth + 1, current, results);
        }
    }

    private static String applyPipeline(String raw, List<List<PayloadProcessor>> pipelines, int index) {
        if (pipelines == null || index >= pipelines.size() || pipelines.get(index) == null) {
            return raw;
        }
        return PayloadProcessors.applyPipeline(raw, pipelines.get(index));
    }
}
