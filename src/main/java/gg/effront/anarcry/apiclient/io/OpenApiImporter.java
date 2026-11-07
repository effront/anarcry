package gg.effront.anarcry.apiclient.io;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import gg.effront.anarcry.apiclient.model.AuthConfig;
import gg.effront.anarcry.apiclient.model.BodyConfig;
import gg.effront.anarcry.apiclient.model.Collection;
import gg.effront.anarcry.apiclient.model.CollectionItem;
import gg.effront.anarcry.apiclient.model.EnvVariable;
import gg.effront.anarcry.apiclient.model.Folder;
import gg.effront.anarcry.apiclient.model.Header;
import gg.effront.anarcry.apiclient.model.HttpRequestDef;
import gg.effront.anarcry.apiclient.model.Param;
import gg.effront.anarcry.apiclient.model.ParamsDef;
import gg.effront.anarcry.apiclient.model.RequestItem;
import gg.effront.anarcry.apiclient.model.RootConfig;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class OpenApiImporter {

    private static final Set<String> HTTP_METHODS = Set.of("get", "post", "put", "patch", "delete", "head", "options");

    public Collection importFile(Path specFile) throws IOException {
        String content = Files.readString(specFile);
        return importJson(content);
    }

    public Collection importJson(String json) {
        JsonObject root = JsonParser.parseString(json).getAsJsonObject();

        String title = "OpenAPI Import";
        if (root.has("info") && root.getAsJsonObject("info").has("title")) {
            title = root.getAsJsonObject("info").get("title").getAsString();
        }

        String baseUrl = extractBaseUrl(root);
        List<EnvVariable> vars = List.of(new EnvVariable("baseUrl", baseUrl, false, true));
        RootConfig rootConfig = new RootConfig(List.of(), new AuthConfig.None(), vars);

        Map<String, List<CollectionItem>> taggedItems = new LinkedHashMap<>();

        if (root.has("paths")) {
            JsonObject paths = root.getAsJsonObject("paths");
            for (String path : paths.keySet()) {
                JsonObject methods = paths.getAsJsonObject(path);
                for (String method : methods.keySet()) {
                    if (!HTTP_METHODS.contains(method)) {
                        continue;
                    }
                    JsonObject operation = methods.getAsJsonObject(method);
                    RequestItem item = buildRequest(method, path, operation, root);

                    String tag = "default";
                    if (operation.has("tags") && operation.getAsJsonArray("tags").size() > 0) {
                        tag = operation.getAsJsonArray("tags").get(0).getAsString();
                    }
                    taggedItems.computeIfAbsent(tag, k -> new ArrayList<>()).add(item);
                }
            }
        }

        List<CollectionItem> items = new ArrayList<>();
        for (var entry : taggedItems.entrySet()) {
            if (taggedItems.size() == 1 && "default".equals(entry.getKey())) {
                items.addAll(entry.getValue());
            } else {
                items.add(new Folder(null, entry.getKey(), entry.getValue(), RootConfig.empty()));
            }
        }

        return new Collection(null, title, "1", List.of(), items, rootConfig, null);
    }

    private RequestItem buildRequest(String method, String path, JsonObject operation, JsonObject spec) {
        String summary = operation.has("summary") ? operation.get("summary").getAsString() : "";
        String operationId = operation.has("operationId") ? operation.get("operationId").getAsString() : "";
        String name = !operationId.isEmpty()
                ? operationId
                : (!summary.isEmpty() ? summary : method.toUpperCase() + " " + path);

        String url = "{{baseUrl}}" + path;
        List<Param> queryParams = new ArrayList<>();
        List<Param> pathParams = new ArrayList<>();
        List<Header> headers = new ArrayList<>();

        if (operation.has("parameters")) {
            for (JsonElement el : operation.getAsJsonArray("parameters")) {
                JsonObject param = resolveRef(el.getAsJsonObject(), spec);
                String pName = param.has("name") ? param.get("name").getAsString() : "";
                String pIn = param.has("in") ? param.get("in").getAsString() : "";
                String example = extractExample(param);

                switch (pIn) {
                    case "query" -> queryParams.add(Param.query(pName, example));
                    case "path" -> pathParams.add(Param.path(pName, example));
                    case "header" -> headers.add(Header.of(pName, example));
                    default -> {
                    }
                }
            }
        }

        BodyConfig body = parseRequestBody(operation, spec);
        if (body instanceof BodyConfig.Json) {
            headers.add(Header.of("Content-Type", "application/json"));
        }

        HttpRequestDef httpReq = new HttpRequestDef(method.toUpperCase(), url, new ParamsDef(queryParams, pathParams),
                headers, new AuthConfig.Inherit(), body, null);

        String docs = summary;
        if (operation.has("description")) {
            docs = operation.get("description").getAsString();
        }

        return new RequestItem(null, name, null, httpReq, null, List.of(), docs);
    }

    private BodyConfig parseRequestBody(JsonObject operation, JsonObject spec) {
        if (!operation.has("requestBody")) {
            return new BodyConfig.None();
        }
        JsonObject reqBody = resolveRef(operation.getAsJsonObject("requestBody"), spec);
        if (!reqBody.has("content")) {
            return new BodyConfig.None();
        }
        JsonObject content = reqBody.getAsJsonObject("content");
        if (content.has("application/json")) {
            JsonObject mediaType = content.getAsJsonObject("application/json");
            String example = generateSchemaExample(mediaType, spec);
            return new BodyConfig.Json(example);
        }
        if (content.has("application/x-www-form-urlencoded")) {
            JsonObject mediaType = content.getAsJsonObject("application/x-www-form-urlencoded");
            return parseFormBody(mediaType, spec);
        }
        if (content.has("multipart/form-data")) {
            JsonObject mediaType = content.getAsJsonObject("multipart/form-data");
            return parseMultipartBody(mediaType, spec);
        }
        if (content.has("application/xml") || content.has("text/xml")) {
            return new BodyConfig.Xml("");
        }
        return new BodyConfig.Text("");
    }

    private BodyConfig parseFormBody(JsonObject mediaType, JsonObject spec) {
        List<Param> params = new ArrayList<>();
        if (mediaType.has("schema")) {
            JsonObject schema = resolveRef(mediaType.getAsJsonObject("schema"), spec);
            if (schema.has("properties")) {
                for (String prop : schema.getAsJsonObject("properties").keySet()) {
                    params.add(Param.query(prop, ""));
                }
            }
        }
        return new BodyConfig.FormUrlEncoded(params);
    }

    private BodyConfig parseMultipartBody(JsonObject mediaType, JsonObject spec) {
        List<BodyConfig.MultipartField> fields = new ArrayList<>();
        if (mediaType.has("schema")) {
            JsonObject schema = resolveRef(mediaType.getAsJsonObject("schema"), spec);
            if (schema.has("properties")) {
                JsonObject props = schema.getAsJsonObject("properties");
                for (String prop : props.keySet()) {
                    JsonObject propSchema = resolveRef(props.getAsJsonObject(prop), spec);
                    String format = propSchema.has("format") ? propSchema.get("format").getAsString() : "";
                    String type = "binary".equals(format) ? "file" : "text";
                    fields.add(new BodyConfig.MultipartField(prop, "", type, null, null, true));
                }
            }
        }
        return new BodyConfig.MultipartForm(fields);
    }

    private String generateSchemaExample(JsonObject mediaType, JsonObject spec) {
        if (mediaType.has("example")) {
            return mediaType.get("example").toString();
        }
        if (mediaType.has("schema")) {
            JsonObject schema = resolveRef(mediaType.getAsJsonObject("schema"), spec);
            return generateFromSchema(schema, spec, 0);
        }
        return "{}";
    }

    private String generateFromSchema(JsonObject schema, JsonObject spec, int depth) {
        if (depth > 5) {
            return "{}";
        }
        schema = resolveRef(schema, spec);
        String type = schema.has("type") ? schema.get("type").getAsString() : "object";

        if (schema.has("example")) {
            return schema.get("example").toString();
        }

        return switch (type) {
            case "object" -> {
                if (!schema.has("properties")) {
                    yield "{}";
                }
                StringBuilder sb = new StringBuilder("{");
                JsonObject props = schema.getAsJsonObject("properties");
                boolean first = true;
                for (String key : props.keySet()) {
                    if (!first) {
                        sb.append(",");
                    }
                    sb.append("\"").append(key).append("\":");
                    sb.append(generateFromSchema(props.getAsJsonObject(key), spec, depth + 1));
                    first = false;
                }
                sb.append("}");
                yield sb.toString();
            }
            case "array" -> {
                if (schema.has("items")) {
                    yield "[" + generateFromSchema(schema.getAsJsonObject("items"), spec, depth + 1) + "]";
                }
                yield "[]";
            }
            case "string" -> {
                if (schema.has("enum")) {
                    yield schema.getAsJsonArray("enum").get(0).toString();
                }
                yield "\"string\"";
            }
            case "integer", "number" -> "0";
            case "boolean" -> "false";
            default -> "null";
        };
    }

    private String extractBaseUrl(JsonObject root) {
        if (root.has("servers")) {
            JsonArray servers = root.getAsJsonArray("servers");
            if (!servers.isEmpty()) {
                return servers.get(0).getAsJsonObject().get("url").getAsString();
            }
        }
        if (root.has("host")) {
            String scheme = root.has("schemes") && root.getAsJsonArray("schemes").size() > 0
                    ? root.getAsJsonArray("schemes").get(0).getAsString()
                    : "https";
            String host = root.get("host").getAsString();
            String basePath = root.has("basePath") ? root.get("basePath").getAsString() : "";
            return scheme + "://" + host + basePath;
        }
        return "https://api.example.com";
    }

    private String extractExample(JsonObject param) {
        if (param.has("example")) {
            JsonElement ex = param.get("example");
            return ex.isJsonPrimitive() ? ex.getAsString() : ex.toString();
        }
        if (param.has("schema") && param.getAsJsonObject("schema").has("example")) {
            JsonElement ex = param.getAsJsonObject("schema").get("example");
            return ex.isJsonPrimitive() ? ex.getAsString() : ex.toString();
        }
        return "";
    }

    private JsonObject resolveRef(JsonObject obj, JsonObject spec) {
        if (!obj.has("$ref")) {
            return obj;
        }
        String ref = obj.get("$ref").getAsString();
        if (!ref.startsWith("#/")) {
            return obj;
        }
        String[] parts = ref.substring(2).split("/");
        JsonObject current = spec;
        for (String part : parts) {
            if (!current.has(part)) {
                return obj;
            }
            current = current.getAsJsonObject(part);
        }
        return current;
    }
}
