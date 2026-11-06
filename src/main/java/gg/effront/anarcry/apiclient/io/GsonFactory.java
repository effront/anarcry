package gg.effront.anarcry.apiclient.io;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonDeserializationContext;
import com.google.gson.JsonDeserializer;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParseException;
import com.google.gson.JsonSerializationContext;
import com.google.gson.JsonSerializer;
import gg.effront.anarcry.apiclient.model.AssertOp;
import gg.effront.anarcry.apiclient.model.Assertion;
import gg.effront.anarcry.apiclient.model.AuthConfig;
import gg.effront.anarcry.apiclient.model.BodyConfig;
import gg.effront.anarcry.apiclient.model.CollectionItem;
import gg.effront.anarcry.apiclient.model.Folder;
import gg.effront.anarcry.apiclient.model.RequestItem;

import java.lang.reflect.Type;
import java.util.HashMap;
import java.util.Map;

public final class GsonFactory {

    private GsonFactory() {
    }

    public static Gson create() {
        return new GsonBuilder().setPrettyPrinting()
                .registerTypeAdapter(CollectionItem.class, new CollectionItemAdapter())
                .registerTypeAdapter(AuthConfig.class, new AuthConfigAdapter())
                .registerTypeAdapter(BodyConfig.class, new BodyConfigAdapter())
                .registerTypeAdapter(Assertion.class, new AssertionAdapter()).create();
    }

    static class CollectionItemAdapter implements JsonSerializer<CollectionItem>, JsonDeserializer<CollectionItem> {

        @Override
        public JsonElement serialize(CollectionItem src, Type type, JsonSerializationContext ctx) {
            JsonObject obj = new JsonObject();
            if (src instanceof Folder folder) {
                obj.addProperty("type", "folder");
                obj.add("data", ctx.serialize(folder, Folder.class));
            } else if (src instanceof RequestItem item) {
                obj.addProperty("type", "request");
                obj.add("data", ctx.serialize(item, RequestItem.class));
            }
            return obj;
        }

        @Override
        public CollectionItem deserialize(JsonElement json, Type type, JsonDeserializationContext ctx)
                throws JsonParseException {
            JsonObject obj = json.getAsJsonObject();
            String itemType = obj.has("type") ? obj.get("type").getAsString() : "request";
            JsonElement data = obj.has("data") ? obj.get("data") : obj;
            if ("folder".equals(itemType)) {
                return ctx.deserialize(data, Folder.class);
            }
            return ctx.deserialize(data, RequestItem.class);
        }
    }

    static class AuthConfigAdapter implements JsonSerializer<AuthConfig>, JsonDeserializer<AuthConfig> {

        private static final Map<String, Class<? extends AuthConfig>> MODE_MAP = new HashMap<>();

        static {
            MODE_MAP.put("none", AuthConfig.None.class);
            MODE_MAP.put("inherit", AuthConfig.Inherit.class);
            MODE_MAP.put("basic", AuthConfig.Basic.class);
            MODE_MAP.put("bearer", AuthConfig.Bearer.class);
            MODE_MAP.put("digest", AuthConfig.Digest.class);
            MODE_MAP.put("ntlm", AuthConfig.Ntlm.class);
            MODE_MAP.put("apikey", AuthConfig.ApiKey.class);
            MODE_MAP.put("oauth2", AuthConfig.OAuth2.class);
            MODE_MAP.put("awsv4", AuthConfig.AwsV4.class);
            MODE_MAP.put("oauth1", AuthConfig.OAuth1.class);
            MODE_MAP.put("wsse", AuthConfig.Wsse.class);
            MODE_MAP.put("akamai-edgegrid", AuthConfig.EdgeGrid.class);
        }

        @Override
        public JsonElement serialize(AuthConfig src, Type type, JsonSerializationContext ctx) {
            JsonObject obj = ctx.serialize(src, src.getClass()).getAsJsonObject();
            obj.addProperty("mode", src.mode());
            return obj;
        }

        @Override
        public AuthConfig deserialize(JsonElement json, Type type, JsonDeserializationContext ctx)
                throws JsonParseException {
            JsonObject obj = json.getAsJsonObject();
            String mode = obj.has("mode") ? obj.get("mode").getAsString() : "none";
            Class<? extends AuthConfig> clazz = MODE_MAP.getOrDefault(mode, AuthConfig.None.class);
            return ctx.deserialize(obj, clazz);
        }
    }

    static class BodyConfigAdapter implements JsonSerializer<BodyConfig>, JsonDeserializer<BodyConfig> {

        private static final Map<String, Class<? extends BodyConfig>> MODE_MAP = new HashMap<>();

        static {
            MODE_MAP.put("none", BodyConfig.None.class);
            MODE_MAP.put("json", BodyConfig.Json.class);
            MODE_MAP.put("text", BodyConfig.Text.class);
            MODE_MAP.put("xml", BodyConfig.Xml.class);
            MODE_MAP.put("formUrlEncoded", BodyConfig.FormUrlEncoded.class);
            MODE_MAP.put("multipartForm", BodyConfig.MultipartForm.class);
            MODE_MAP.put("graphql", BodyConfig.GraphQL.class);
            MODE_MAP.put("file", BodyConfig.FileBody.class);
        }

        @Override
        public JsonElement serialize(BodyConfig src, Type type, JsonSerializationContext ctx) {
            JsonObject obj = ctx.serialize(src, src.getClass()).getAsJsonObject();
            obj.addProperty("mode", src.mode());
            return obj;
        }

        @Override
        public BodyConfig deserialize(JsonElement json, Type type, JsonDeserializationContext ctx)
                throws JsonParseException {
            JsonObject obj = json.getAsJsonObject();
            String mode = obj.has("mode") ? obj.get("mode").getAsString() : "none";
            Class<? extends BodyConfig> clazz = MODE_MAP.getOrDefault(mode, BodyConfig.None.class);
            return ctx.deserialize(obj, clazz);
        }
    }

    static class AssertionAdapter implements JsonSerializer<Assertion>, JsonDeserializer<Assertion> {

        @Override
        public JsonElement serialize(Assertion src, Type type, JsonSerializationContext ctx) {
            JsonObject obj = new JsonObject();
            obj.addProperty("lhs", src.lhs());
            obj.addProperty("op", src.op().symbol());
            obj.addProperty("rhs", src.rhs());
            obj.addProperty("enabled", src.enabled());
            return obj;
        }

        @Override
        public Assertion deserialize(JsonElement json, Type type, JsonDeserializationContext ctx)
                throws JsonParseException {
            JsonObject obj = json.getAsJsonObject();
            String lhs = obj.has("lhs") ? obj.get("lhs").getAsString() : "";
            String opStr = obj.has("op") ? obj.get("op").getAsString() : "eq";
            String rhs = obj.has("rhs") && !obj.get("rhs").isJsonNull() ? obj.get("rhs").getAsString() : null;
            boolean enabled = !obj.has("enabled") || obj.get("enabled").getAsBoolean();
            return new Assertion(lhs, AssertOp.fromSymbol(opStr), rhs, enabled);
        }
    }
}
