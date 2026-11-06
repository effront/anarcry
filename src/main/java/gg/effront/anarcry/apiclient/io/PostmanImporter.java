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
import gg.effront.anarcry.apiclient.model.Environment;
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
import java.util.List;

public class PostmanImporter {

    public Collection importFile(Path postmanFile) throws IOException {
        String json = Files.readString(postmanFile);
        return importJson(json);
    }

    public Collection importJson(String json) {
        JsonObject root = JsonParser.parseString(json).getAsJsonObject();
        JsonObject info = root.getAsJsonObject("info");
        String name = info != null && info.has("name") ? info.get("name").getAsString() : "Imported";

        List<CollectionItem> items = new ArrayList<>();
        if (root.has("item")) {
            items = parseItems(root.getAsJsonArray("item"));
        }

        List<EnvVariable> vars = new ArrayList<>();
        if (root.has("variable")) {
            vars = parseVariables(root.getAsJsonArray("variable"));
        }

        RootConfig rootConfig = new RootConfig(List.of(), new AuthConfig.None(), vars);
        return new Collection(null, name, "1", List.of(), items, rootConfig, null);
    }

    public Environment importEnvironment(Path envFile) throws IOException {
        String json = Files.readString(envFile);
        return importEnvironmentJson(json);
    }

    public Environment importEnvironmentJson(String json) {
        JsonObject root = JsonParser.parseString(json).getAsJsonObject();
        String name = root.has("name") ? root.get("name").getAsString() : "Imported Environment";
        List<EnvVariable> vars = new ArrayList<>();
        if (root.has("values")) {
            for (JsonElement el : root.getAsJsonArray("values")) {
                JsonObject v = el.getAsJsonObject();
                String key = getString(v, "key");
                String value = getString(v, "value");
                boolean enabled = !v.has("enabled") || v.get("enabled").getAsBoolean();
                boolean secret = v.has("type") && "secret".equals(v.get("type").getAsString());
                vars.add(new EnvVariable(key, value, secret, enabled));
            }
        }
        return new Environment(null, name, null, vars, null);
    }

    private List<CollectionItem> parseItems(JsonArray items) {
        List<CollectionItem> result = new ArrayList<>();
        for (JsonElement el : items) {
            JsonObject item = el.getAsJsonObject();
            if (item.has("item")) {
                result.add(parseFolder(item));
            } else if (item.has("request")) {
                result.add(parseRequest(item));
            }
        }
        return result;
    }

    private Folder parseFolder(JsonObject obj) {
        String name = getString(obj, "name");
        List<CollectionItem> children = parseItems(obj.getAsJsonArray("item"));
        return new Folder(null, name, children, RootConfig.empty());
    }

    private RequestItem parseRequest(JsonObject obj) {
        String name = getString(obj, "name");
        JsonElement reqEl = obj.get("request");
        JsonObject req;
        if (reqEl.isJsonPrimitive()) {
            return new RequestItem(null, name, null, HttpRequestDef.get(reqEl.getAsString()), null, List.of(), "");
        }
        req = reqEl.getAsJsonObject();

        String method = getString(req, "method").toUpperCase();
        String url = parseUrl(req);
        List<Header> headers = parseHeaders(req);
        List<Param> queryParams = parseQueryParams(req);
        AuthConfig auth = parseAuth(req);
        BodyConfig body = parseBody(req);

        HttpRequestDef httpReq = new HttpRequestDef(method, url, new ParamsDef(queryParams, List.of()), headers, auth,
                body, null);

        String desc = getString(req, "description");
        return new RequestItem(null, name, null, httpReq, null, List.of(), desc);
    }

    private String parseUrl(JsonObject req) {
        if (!req.has("url")) {
            return "";
        }
        JsonElement urlEl = req.get("url");
        if (urlEl.isJsonPrimitive()) {
            return urlEl.getAsString();
        }
        JsonObject urlObj = urlEl.getAsJsonObject();
        String raw = getString(urlObj, "raw");
        if (!raw.isEmpty()) {
            int qIdx = raw.indexOf('?');
            return qIdx >= 0 ? raw.substring(0, qIdx) : raw;
        }
        StringBuilder sb = new StringBuilder();
        if (urlObj.has("protocol")) {
            sb.append(urlObj.get("protocol").getAsString()).append("://");
        }
        if (urlObj.has("host")) {
            JsonArray host = urlObj.getAsJsonArray("host");
            for (int i = 0; i < host.size(); i++) {
                if (i > 0) {
                    sb.append(".");
                }
                sb.append(host.get(i).getAsString());
            }
        }
        if (urlObj.has("port")) {
            sb.append(":").append(urlObj.get("port").getAsString());
        }
        if (urlObj.has("path")) {
            for (JsonElement p : urlObj.getAsJsonArray("path")) {
                sb.append("/").append(p.getAsString());
            }
        }
        return sb.toString();
    }

    private List<Header> parseHeaders(JsonObject req) {
        List<Header> headers = new ArrayList<>();
        if (!req.has("header")) {
            return headers;
        }
        for (JsonElement el : req.getAsJsonArray("header")) {
            JsonObject h = el.getAsJsonObject();
            boolean disabled = h.has("disabled") && h.get("disabled").getAsBoolean();
            headers.add(new Header(getString(h, "key"), getString(h, "value"), !disabled));
        }
        return headers;
    }

    private List<Param> parseQueryParams(JsonObject req) {
        List<Param> params = new ArrayList<>();
        if (!req.has("url")) {
            return params;
        }
        JsonElement urlEl = req.get("url");
        if (!urlEl.isJsonObject()) {
            return params;
        }
        JsonObject urlObj = urlEl.getAsJsonObject();
        if (!urlObj.has("query")) {
            return params;
        }
        for (JsonElement el : urlObj.getAsJsonArray("query")) {
            JsonObject q = el.getAsJsonObject();
            boolean disabled = q.has("disabled") && q.get("disabled").getAsBoolean();
            params.add(new Param(getString(q, "key"), getString(q, "value"), Param.ParamType.QUERY, !disabled));
        }
        return params;
    }

    private AuthConfig parseAuth(JsonObject req) {
        if (!req.has("auth")) {
            return new AuthConfig.None();
        }
        JsonObject authObj = req.getAsJsonObject("auth");
        String type = getString(authObj, "type").toLowerCase();
        return switch (type) {
            case "basic" -> {
                JsonArray basic = authObj.getAsJsonArray("basic");
                yield new AuthConfig.Basic(findAuthValue(basic, "username"), findAuthValue(basic, "password"));
            }
            case "bearer" -> {
                JsonArray bearer = authObj.getAsJsonArray("bearer");
                yield new AuthConfig.Bearer(findAuthValue(bearer, "token"));
            }
            case "apikey" -> {
                JsonArray apikey = authObj.getAsJsonArray("apikey");
                yield new AuthConfig.ApiKey(findAuthValue(apikey, "key"), findAuthValue(apikey, "value"),
                        findAuthValue(apikey, "in"));
            }
            case "digest" -> {
                JsonArray digest = authObj.getAsJsonArray("digest");
                yield new AuthConfig.Digest(findAuthValue(digest, "username"), findAuthValue(digest, "password"));
            }
            case "noauth" -> new AuthConfig.None();
            default -> new AuthConfig.None();
        };
    }

    private String findAuthValue(JsonArray arr, String key) {
        if (arr == null) {
            return "";
        }
        for (JsonElement el : arr) {
            JsonObject obj = el.getAsJsonObject();
            if (key.equals(getString(obj, "key"))) {
                return getString(obj, "value");
            }
        }
        return "";
    }

    private BodyConfig parseBody(JsonObject req) {
        if (!req.has("body")) {
            return new BodyConfig.None();
        }
        JsonObject body = req.getAsJsonObject("body");
        String mode = getString(body, "mode");
        return switch (mode) {
            case "raw" -> {
                String raw = getString(body, "raw");
                String lang = "";
                if (body.has("options") && body.getAsJsonObject("options").has("raw")) {
                    lang = getString(body.getAsJsonObject("options").getAsJsonObject("raw"), "language");
                }
                yield switch (lang) {
                    case "json" -> new BodyConfig.Json(raw);
                    case "xml" -> new BodyConfig.Xml(raw);
                    default -> {
                        if (raw.trim().startsWith("{") || raw.trim().startsWith("[")) {
                            yield new BodyConfig.Json(raw);
                        }
                        yield new BodyConfig.Text(raw);
                    }
                };
            }
            case "urlencoded" -> {
                List<Param> params = new ArrayList<>();
                if (body.has("urlencoded")) {
                    for (JsonElement el : body.getAsJsonArray("urlencoded")) {
                        JsonObject p = el.getAsJsonObject();
                        boolean disabled = p.has("disabled") && p.get("disabled").getAsBoolean();
                        params.add(new Param(getString(p, "key"), getString(p, "value"), Param.ParamType.QUERY,
                                !disabled));
                    }
                }
                yield new BodyConfig.FormUrlEncoded(params);
            }
            case "formdata" -> {
                List<BodyConfig.MultipartField> fields = new ArrayList<>();
                if (body.has("formdata")) {
                    for (JsonElement el : body.getAsJsonArray("formdata")) {
                        JsonObject f = el.getAsJsonObject();
                        boolean disabled = f.has("disabled") && f.get("disabled").getAsBoolean();
                        String type = getString(f, "type");
                        String src = "file".equals(type) ? getString(f, "src") : null;
                        fields.add(new BodyConfig.MultipartField(getString(f, "key"), getString(f, "value"), type, src,
                                null, !disabled));
                    }
                }
                yield new BodyConfig.MultipartForm(fields);
            }
            case "graphql" -> {
                JsonObject gql = body.has("graphql") ? body.getAsJsonObject("graphql") : new JsonObject();
                yield new BodyConfig.GraphQL(getString(gql, "query"), getString(gql, "variables"));
            }
            case "file" -> {
                String src = "";
                if (body.has("file") && body.getAsJsonObject("file").has("src")) {
                    src = body.getAsJsonObject("file").get("src").getAsString();
                }
                yield new BodyConfig.FileBody(src, null);
            }
            default -> new BodyConfig.None();
        };
    }

    private List<EnvVariable> parseVariables(JsonArray variables) {
        List<EnvVariable> vars = new ArrayList<>();
        for (JsonElement el : variables) {
            JsonObject v = el.getAsJsonObject();
            vars.add(new EnvVariable(getString(v, "key"), getString(v, "value"), false, true));
        }
        return vars;
    }

    private static String getString(JsonObject obj, String key) {
        if (obj.has(key) && !obj.get(key).isJsonNull()) {
            return obj.get(key).getAsString();
        }
        return "";
    }
}
