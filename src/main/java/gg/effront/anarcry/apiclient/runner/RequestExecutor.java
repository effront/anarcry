package gg.effront.anarcry.apiclient.runner;

import gg.effront.anarcry.apiclient.auth.AuthInjectorRegistry;
import gg.effront.anarcry.apiclient.model.AssertionResult;
import gg.effront.anarcry.apiclient.model.AuthConfig;
import gg.effront.anarcry.apiclient.model.BodyConfig;
import gg.effront.anarcry.apiclient.model.Collection;
import gg.effront.anarcry.apiclient.model.CollectionItem;
import gg.effront.anarcry.apiclient.model.Folder;
import gg.effront.anarcry.apiclient.model.Header;
import gg.effront.anarcry.apiclient.model.HttpRequestDef;
import gg.effront.anarcry.apiclient.model.Param;
import gg.effront.anarcry.apiclient.model.ParamsDef;
import gg.effront.anarcry.apiclient.model.RequestItem;
import gg.effront.anarcry.apiclient.model.RequestResult;
import gg.effront.anarcry.apiclient.model.RequestSettings;
import gg.effront.anarcry.apiclient.model.ResponseData;
import gg.effront.anarcry.apiclient.model.VarsDef;
import gg.effront.anarcry.apiclient.vars.Interpolator;
import gg.effront.anarcry.apiclient.vars.VariableStore;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;
import java.util.stream.Collectors;

public class RequestExecutor {

    private final HttpClient httpClient;
    private final Interpolator interpolator;
    private final AuthInjectorRegistry authRegistry;
    private final AssertionEngine assertionEngine;

    public RequestExecutor(HttpClient httpClient, Interpolator interpolator, AuthInjectorRegistry authRegistry,
            AssertionEngine assertionEngine) {
        this.httpClient = httpClient;
        this.interpolator = interpolator;
        this.authRegistry = authRegistry;
        this.assertionEngine = assertionEngine;
    }

    public RequestResult execute(RequestItem item, RunContext ctx, Collection collection, Consumer<String> log) {
        long start = System.nanoTime();

        try {
            // Phase 1: MERGE - cascade folder/collection headers, auth, vars
            HttpRequestDef merged = mergeInherited(item, collection, ctx.vars());

            // Phase 2: PRE-VARS - resolve pre-request variables
            resolvePreVars(item.vars().pre(), ctx.vars());

            // Phase 3: INTERPOLATE - {{var}} in URL, headers, body, auth, params
            HttpRequestDef interpolated = interpolateRequest(merged, ctx.vars());

            // Phase 4: AUTH INJECT - apply auth mode
            HttpRequestDef authed = authRegistry.inject(interpolated, interpolated.auth(), ctx.vars());

            // Phase 5: HTTP SEND
            ResponseData response = dispatch(authed, ctx, log);

            // Phase 6: POST-VARS - extract from response
            resolvePostVars(item.vars().post(), response, ctx.vars());

            // Phase 7: ASSERTIONS
            List<AssertionResult> assertResults = assertionEngine.evaluate(item.assertions(), response, ctx.vars());

            long duration = (System.nanoTime() - start) / 1_000_000;
            boolean passed = assertResults.stream().allMatch(AssertionResult::passed);

            return new RequestResult(item, interpolated, response, assertResults, duration, passed);
        } catch (Exception e) {
            long duration = (System.nanoTime() - start) / 1_000_000;
            log.accept("[!] Error executing " + item.name() + ": " + e.getMessage());
            ResponseData errorResponse = new ResponseData(0, "Error: " + e.getMessage(), Map.of(), "", new byte[0],
                    duration, 0);
            return new RequestResult(item, item.request(), errorResponse, List.of(), duration, false);
        }
    }

    HttpRequestDef mergeInherited(RequestItem item, Collection collection, VariableStore vars) {
        HttpRequestDef req = item.request();

        List<Header> mergedHeaders = new ArrayList<>(collection.root().headers());
        Folder parentFolder = findParentFolder(item, collection.items());
        if (parentFolder != null) {
            mergedHeaders.addAll(parentFolder.root().headers());
        }
        for (Header h : req.headers()) {
            mergedHeaders.removeIf(existing -> existing.name().equalsIgnoreCase(h.name()));
            mergedHeaders.add(h);
        }

        AuthConfig auth = req.auth();
        if (auth instanceof AuthConfig.Inherit) {
            if (parentFolder != null && !(parentFolder.root().auth() instanceof AuthConfig.None)) {
                auth = parentFolder.root().auth();
            } else {
                auth = collection.root().auth();
            }
        }

        if (parentFolder != null) {
            vars.loadFolder(parentFolder.root());
        }

        return new HttpRequestDef(req.method(), req.url(), req.params(), mergedHeaders, auth, req.body(),
                req.settings());
    }

    private Folder findParentFolder(RequestItem item, List<CollectionItem> items) {
        for (CollectionItem ci : items) {
            if (ci instanceof Folder folder) {
                for (CollectionItem child : folder.items()) {
                    if (child instanceof RequestItem ri && java.util.Objects.equals(ri.uid(), item.uid())) {
                        return folder;
                    }
                    if (child instanceof Folder sub) {
                        Folder found = findParentFolder(item, sub.items());
                        if (found != null) {
                            return found;
                        }
                    }
                }
            }
        }
        return null;
    }

    private boolean containsRequest(Folder folder, RequestItem target) {
        for (CollectionItem ci : folder.items()) {
            if (ci instanceof RequestItem ri && java.util.Objects.equals(ri.uid(), target.uid())) {
                return true;
            }
            if (ci instanceof Folder sub && containsRequest(sub, target)) {
                return true;
            }
        }
        return false;
    }

    private void resolvePreVars(List<VarsDef.VarEntry> preVars, VariableStore vars) {
        for (VarsDef.VarEntry entry : preVars) {
            String resolved = interpolator.interpolate(entry.value(), vars);
            vars.setRequest(entry.name(), resolved);
        }
    }

    HttpRequestDef interpolateRequest(HttpRequestDef req, VariableStore vars) {
        String url = interpolator.interpolateUrl(req.url(), vars);

        // Interpolate path params into URL
        for (Param p : req.params().path()) {
            if (p.enabled()) {
                String key = interpolator.interpolate(p.name(), vars);
                String val = interpolator.interpolate(p.value(), vars);
                url = url.replace(":" + key, URLEncoder.encode(val, StandardCharsets.UTF_8));
            }
        }

        List<Header> headers = req.headers().stream().filter(Header::enabled).map(
                h -> Header.of(interpolator.interpolate(h.name(), vars), interpolator.interpolate(h.value(), vars)))
                .collect(Collectors.toCollection(ArrayList::new));

        List<Param> query = req.params().query().stream().filter(Param::enabled).map(
                p -> Param.query(interpolator.interpolate(p.name(), vars), interpolator.interpolate(p.value(), vars)))
                .toList();

        List<Param> path = req.params().path().stream().filter(Param::enabled).map(
                p -> Param.path(interpolator.interpolate(p.name(), vars), interpolator.interpolate(p.value(), vars)))
                .toList();

        BodyConfig body = interpolateBody(req.body(), vars);

        return new HttpRequestDef(req.method(), url, new ParamsDef(query, path), headers, req.auth(), body,
                req.settings());
    }

    private BodyConfig interpolateBody(BodyConfig body, VariableStore vars) {
        return switch (body) {
            case BodyConfig.None n -> n;
            case BodyConfig.Json j -> new BodyConfig.Json(interpolator.interpolateJson(j.content(), vars));
            case BodyConfig.Text t -> new BodyConfig.Text(interpolator.interpolate(t.content(), vars));
            case BodyConfig.Xml x -> new BodyConfig.Xml(interpolator.interpolate(x.content(), vars));
            case BodyConfig.FormUrlEncoded f -> new BodyConfig.FormUrlEncoded(f
                    .params().stream().filter(Param::enabled).map(p -> Param
                            .query(interpolator.interpolate(p.name(), vars), interpolator.interpolate(p.value(), vars)))
                    .toList());
            case BodyConfig.MultipartForm m ->
                new BodyConfig.MultipartForm(m.fields().stream().filter(BodyConfig.MultipartField::enabled)
                        .map(f -> new BodyConfig.MultipartField(interpolator.interpolate(f.name(), vars),
                                interpolator.interpolate(f.value(), vars), f.type(), f.filePath(), f.contentType(),
                                f.enabled()))
                        .toList());
            case BodyConfig.GraphQL g -> new BodyConfig.GraphQL(interpolator.interpolate(g.query(), vars),
                    interpolator.interpolateJson(g.variables(), vars));
            case BodyConfig.FileBody fb -> fb;
        };
    }

    private ResponseData dispatch(HttpRequestDef req, RunContext ctx, Consumer<String> log)
            throws IOException, InterruptedException {
        String url = buildUrl(req);
        RequestSettings settings = req.settings();

        HttpRequest.Builder builder = HttpRequest.newBuilder().uri(URI.create(url))
                .timeout(Duration.ofMillis(settings.timeoutMs()));

        for (Header h : req.headers()) {
            builder.header(h.name(), h.value());
        }

        builder.method(req.method().toUpperCase(), buildBodyPublisher(req.body()));

        long sendStart = System.nanoTime();
        HttpResponse<String> response = httpClient.send(builder.build(), HttpResponse.BodyHandlers.ofString());
        long responseTime = (System.nanoTime() - sendStart) / 1_000_000;

        Map<String, List<String>> responseHeaders = new LinkedHashMap<>(response.headers().map());
        byte[] rawBody = response.body() != null ? response.body().getBytes(StandardCharsets.UTF_8) : new byte[0];
        long size = rawBody.length;

        log.accept("  " + req.method() + " " + url + " -> " + response.statusCode() + " (" + responseTime + "ms)");

        return new ResponseData(response.statusCode(), "", responseHeaders, response.body(), rawBody, responseTime,
                size);
    }

    private String buildUrl(HttpRequestDef req) {
        String url = req.url();
        List<Param> queryParams = req.params().query().stream().filter(Param::enabled).toList();
        if (queryParams.isEmpty()) {
            return url;
        }
        StringBuilder sb = new StringBuilder(url);
        sb.append(url.contains("?") ? "&" : "?");
        for (int i = 0; i < queryParams.size(); i++) {
            if (i > 0) {
                sb.append("&");
            }
            Param p = queryParams.get(i);
            sb.append(URLEncoder.encode(p.name(), StandardCharsets.UTF_8));
            sb.append("=");
            sb.append(URLEncoder.encode(p.value(), StandardCharsets.UTF_8));
        }
        return sb.toString();
    }

    private HttpRequest.BodyPublisher buildBodyPublisher(BodyConfig body) {
        return switch (body) {
            case BodyConfig.None ignored -> HttpRequest.BodyPublishers.noBody();
            case BodyConfig.Json j -> HttpRequest.BodyPublishers.ofString(j.content());
            case BodyConfig.Text t -> HttpRequest.BodyPublishers.ofString(t.content());
            case BodyConfig.Xml x -> HttpRequest.BodyPublishers.ofString(x.content());
            case BodyConfig.GraphQL g -> {
                String payload = "{\"query\":" + escapeJsonString(g.query());
                if (g.variables() != null && !g.variables().isBlank()) {
                    payload += ",\"variables\":" + g.variables();
                }
                payload += "}";
                yield HttpRequest.BodyPublishers.ofString(payload);
            }
            case BodyConfig.FormUrlEncoded f -> {
                String encoded = f.params().stream()
                        .map(p -> URLEncoder.encode(p.name(), StandardCharsets.UTF_8) + "="
                                + URLEncoder.encode(p.value(), StandardCharsets.UTF_8))
                        .collect(Collectors.joining("&"));
                yield HttpRequest.BodyPublishers.ofString(encoded);
            }
            case BodyConfig.MultipartForm m -> buildMultipartBody(m);
            case BodyConfig.FileBody fb -> {
                try {
                    yield HttpRequest.BodyPublishers.ofFile(Path.of(fb.filePath()));
                } catch (IOException e) {
                    yield HttpRequest.BodyPublishers.noBody();
                }
            }
        };
    }

    private HttpRequest.BodyPublisher buildMultipartBody(BodyConfig.MultipartForm multipart) {
        String boundary = "----AnarCryBoundary" + System.currentTimeMillis();
        StringBuilder sb = new StringBuilder();
        for (BodyConfig.MultipartField field : multipart.fields()) {
            sb.append("--").append(boundary).append("\r\n");
            if ("file".equals(field.type()) && field.filePath() != null) {
                sb.append("Content-Disposition: form-data; name=\"").append(field.name()).append("\"; filename=\"")
                        .append(Path.of(field.filePath()).getFileName()).append("\"\r\n");
                String ct = field.contentType() != null ? field.contentType() : "application/octet-stream";
                sb.append("Content-Type: ").append(ct).append("\r\n\r\n");
                try {
                    sb.append(Files.readString(Path.of(field.filePath())));
                } catch (IOException e) {
                    sb.append("[file read error: ").append(e.getMessage()).append("]");
                }
            } else {
                sb.append("Content-Disposition: form-data; name=\"").append(field.name()).append("\"\r\n\r\n");
                sb.append(field.value());
            }
            sb.append("\r\n");
        }
        sb.append("--").append(boundary).append("--\r\n");
        return HttpRequest.BodyPublishers.ofString(sb.toString());
    }

    private void resolvePostVars(List<VarsDef.VarEntry> postVars, ResponseData response, VariableStore vars) {
        for (VarsDef.VarEntry entry : postVars) {
            String expr = entry.value();
            String resolved = resolveResponseExpression(expr, response);
            if (resolved != null) {
                vars.setRuntime(entry.name(), resolved);
            }
        }
    }

    private String resolveResponseExpression(String expr, ResponseData response) {
        if (expr.equals("res.status")) {
            return String.valueOf(response.status());
        }
        if (expr.equals("res.responseTime")) {
            return String.valueOf(response.responseTimeMs());
        }
        if (expr.equals("res.body")) {
            return response.body();
        }
        if (expr.startsWith("res.headers.")) {
            return response.header(expr.substring("res.headers.".length()));
        }
        if (expr.startsWith("res.body.")) {
            return extractSimpleJsonPath(response.body(), expr.substring("res.body.".length()));
        }
        return expr;
    }

    private String extractSimpleJsonPath(String json, String path) {
        if (json == null || json.isBlank()) {
            return null;
        }
        String[] keys = path.split("\\.");
        String current = json.trim();
        for (String key : keys) {
            String needle = "\"" + key + "\"";
            int idx = current.indexOf(needle);
            if (idx < 0) {
                return null;
            }
            int colonIdx = current.indexOf(':', idx + needle.length());
            if (colonIdx < 0) {
                return null;
            }
            current = extractJsonValue(current, colonIdx + 1);
            if (current == null) {
                return null;
            }
        }
        if (current.startsWith("\"") && current.endsWith("\"")) {
            return current.substring(1, current.length() - 1);
        }
        return current;
    }

    private String extractJsonValue(String json, int start) {
        int i = start;
        while (i < json.length() && Character.isWhitespace(json.charAt(i))) {
            i++;
        }
        if (i >= json.length()) {
            return null;
        }
        char c = json.charAt(i);
        if (c == '"') {
            int end = json.indexOf('"', i + 1);
            while (end > 0 && json.charAt(end - 1) == '\\') {
                end = json.indexOf('"', end + 1);
            }
            if (end < 0) {
                return null;
            }
            return json.substring(i, end + 1);
        }
        if (c == '{' || c == '[') {
            int depth = 1;
            int j = i + 1;
            while (j < json.length() && depth > 0) {
                char ch = json.charAt(j);
                if (ch == '"') {
                    j = json.indexOf('"', j + 1);
                    if (j < 0) {
                        return null;
                    }
                } else if (ch == '{' || ch == '[') {
                    depth++;
                } else if (ch == '}' || ch == ']') {
                    depth--;
                }
                j++;
            }
            return json.substring(i, j).trim();
        }
        int end = i;
        while (end < json.length()) {
            char ch = json.charAt(end);
            if (ch == ',' || ch == '}' || ch == ']' || Character.isWhitespace(ch)) {
                break;
            }
            end++;
        }
        return json.substring(i, end);
    }

    private static String escapeJsonString(String value) {
        if (value == null) {
            return "null";
        }
        StringBuilder sb = new StringBuilder("\"");
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            switch (c) {
                case '\\' -> sb.append("\\\\");
                case '"' -> sb.append("\\\"");
                case '\n' -> sb.append("\\n");
                case '\r' -> sb.append("\\r");
                case '\t' -> sb.append("\\t");
                default -> sb.append(c);
            }
        }
        sb.append("\"");
        return sb.toString();
    }
}
