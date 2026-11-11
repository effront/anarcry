package gg.effront.anarcry.apiclient.io;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import gg.effront.anarcry.apiclient.model.AuthConfig;
import gg.effront.anarcry.apiclient.model.BodyConfig;
import gg.effront.anarcry.apiclient.model.Collection;
import gg.effront.anarcry.apiclient.model.CollectionItem;
import gg.effront.anarcry.apiclient.model.Environment;
import gg.effront.anarcry.apiclient.model.EnvVariable;
import gg.effront.anarcry.apiclient.model.Folder;
import gg.effront.anarcry.apiclient.model.Header;
import gg.effront.anarcry.apiclient.model.HttpRequestDef;
import gg.effront.anarcry.apiclient.model.Param;
import gg.effront.anarcry.apiclient.model.ParamsDef;
import gg.effront.anarcry.apiclient.model.RequestItem;
import gg.effront.anarcry.apiclient.model.RequestMeta;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public class InsomniaImporter {

    public Collection importFile(Path file) throws IOException {
        String content = Files.readString(file);
        JsonObject root = JsonParser.parseString(content).getAsJsonObject();

        if (root.has("_type") && "export".equals(str(root, "_type"))) {
            return importExportV4(root);
        }
        if (root.has("resources")) {
            return importExportV4(root);
        }

        throw new IOException("Unsupported Insomnia format");
    }

    private Collection importExportV4(JsonObject root) {
        JsonArray resources = root.getAsJsonArray("resources");
        if (resources == null) {
            return new Collection(null, "Insomnia Import", null, List.of(), List.of(), null, null);
        }

        Map<String, JsonObject> byId = new LinkedHashMap<>();
        for (JsonElement el : resources) {
            JsonObject obj = el.getAsJsonObject();
            byId.put(str(obj, "_id"), obj);
        }

        String collectionName = "Insomnia Import";
        String workspaceId = null;
        for (JsonObject obj : byId.values()) {
            if ("workspace".equals(str(obj, "_type"))) {
                collectionName = str(obj, "name");
                workspaceId = str(obj, "_id");
                break;
            }
        }

        Map<String, List<CollectionItem>> children = new LinkedHashMap<>();
        List<Environment> environments = new ArrayList<>();
        int seq = 0;

        for (JsonObject obj : byId.values()) {
            String type = str(obj, "_type");
            String parentId = str(obj, "parentId");

            if ("request_group".equals(type)) {
                children.computeIfAbsent(parentId, k -> new ArrayList<>());
            } else if ("request".equals(type)) {
                RequestItem item = parseRequest(obj, seq++);
                children.computeIfAbsent(parentId, k -> new ArrayList<>()).add(item);
            } else if ("environment".equals(type)) {
                environments.add(parseEnvironment(obj));
            }
        }

        for (JsonObject obj : byId.values()) {
            if ("request_group".equals(str(obj, "_type"))) {
                String id = str(obj, "_id");
                String parentId = str(obj, "parentId");
                List<CollectionItem> items = children.getOrDefault(id, List.of());
                Folder folder = new Folder(null, str(obj, "name"), items, null);
                children.computeIfAbsent(parentId, k -> new ArrayList<>()).add(folder);
            }
        }

        String rootParent = workspaceId != null ? workspaceId : "";
        List<CollectionItem> topLevel = children.getOrDefault(rootParent, List.of());
        return new Collection(null, collectionName, null, environments, topLevel, null, null);
    }

    private RequestItem parseRequest(JsonObject obj, int seq) {
        String name = str(obj, "name");
        String method = str(obj, "method");
        if (method.isEmpty()) {
            method = "GET";
        }
        String url = str(obj, "url");

        List<Header> headers = new ArrayList<>();
        if (obj.has("headers") && obj.get("headers").isJsonArray()) {
            for (JsonElement hel : obj.getAsJsonArray("headers")) {
                JsonObject h = hel.getAsJsonObject();
                boolean enabled = !h.has("disabled") || !h.get("disabled").getAsBoolean();
                headers.add(new Header(str(h, "name"), str(h, "value"), enabled));
            }
        }

        List<Param> queryParams = new ArrayList<>();
        if (obj.has("parameters") && obj.get("parameters").isJsonArray()) {
            for (JsonElement pel : obj.getAsJsonArray("parameters")) {
                JsonObject p = pel.getAsJsonObject();
                queryParams.add(Param.query(str(p, "name"), str(p, "value")));
            }
        }

        BodyConfig body = parseBody(obj);
        AuthConfig auth = parseAuth(obj);

        HttpRequestDef request = new HttpRequestDef(method, url, new ParamsDef(queryParams, List.of()), headers, auth,
                body, null);
        String desc = str(obj, "description");
        RequestMeta meta = RequestMeta.http(name, seq);
        return new RequestItem(null, name, meta, request, null, List.of(), desc);
    }

    private BodyConfig parseBody(JsonObject obj) {
        if (!obj.has("body") || obj.get("body").isJsonNull()) {
            return new BodyConfig.None();
        }
        JsonObject bodyObj = obj.getAsJsonObject("body");
        String mimeType = str(bodyObj, "mimeType");
        String text = str(bodyObj, "text");

        if (mimeType.contains("json")) {
            return new BodyConfig.Json(text);
        }
        if (mimeType.contains("xml")) {
            return new BodyConfig.Xml(text);
        }
        if (mimeType.contains("form-urlencoded")) {
            List<Param> formParams = new ArrayList<>();
            if (bodyObj.has("params") && bodyObj.get("params").isJsonArray()) {
                for (JsonElement pel : bodyObj.getAsJsonArray("params")) {
                    JsonObject p = pel.getAsJsonObject();
                    formParams.add(Param.query(str(p, "name"), str(p, "value")));
                }
            }
            return new BodyConfig.FormUrlEncoded(formParams);
        }
        if (mimeType.contains("graphql")) {
            return new BodyConfig.GraphQL(text, null);
        }
        if (!text.isEmpty()) {
            return new BodyConfig.Text(text);
        }
        return new BodyConfig.None();
    }

    private AuthConfig parseAuth(JsonObject obj) {
        if (!obj.has("authentication") || obj.get("authentication").isJsonNull()) {
            return new AuthConfig.None();
        }
        JsonObject authObj = obj.getAsJsonObject("authentication");
        String type = str(authObj, "type");

        return switch (type) {
            case "basic" -> new AuthConfig.Basic(str(authObj, "username"), str(authObj, "password"));
            case "bearer" -> new AuthConfig.Bearer(str(authObj, "token"));
            case "digest" -> new AuthConfig.Digest(str(authObj, "username"), str(authObj, "password"));
            default -> new AuthConfig.None();
        };
    }

    private Environment parseEnvironment(JsonObject obj) {
        String name = str(obj, "name");
        List<EnvVariable> variables = new ArrayList<>();
        if (obj.has("data") && obj.get("data").isJsonObject()) {
            for (var entry : obj.getAsJsonObject("data").entrySet()) {
                String value = entry.getValue().isJsonPrimitive()
                        ? entry.getValue().getAsString()
                        : entry.getValue().toString();
                variables.add(EnvVariable.of(entry.getKey(), value));
            }
        }
        return Environment.of(name, variables);
    }

    private static String str(JsonObject obj, String key) {
        if (obj.has(key) && obj.get(key).isJsonPrimitive()) {
            return obj.get(key).getAsString();
        }
        return "";
    }
}
