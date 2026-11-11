package gg.effront.anarcry.apiclient.io;

import gg.effront.anarcry.apiclient.model.AssertOp;
import gg.effront.anarcry.apiclient.model.Assertion;
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
import gg.effront.anarcry.apiclient.model.RequestMeta;
import gg.effront.anarcry.apiclient.model.RootConfig;
import gg.effront.anarcry.apiclient.model.VarsDef;

import java.io.IOException;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class BruImporter {

    private static final Pattern KV_PATTERN = Pattern.compile("^\\s*(~?)\\s*([^:]+):\\s*(.*)$", Pattern.MULTILINE);

    private record Block(String tag, String content) {
    }

    private static List<Block> parseBlocks(String text) {
        List<Block> blocks = new ArrayList<>();
        int len = text.length();
        int i = 0;
        while (i < len) {
            // Skip whitespace / blank lines between blocks
            while (i < len && Character.isWhitespace(text.charAt(i))) {
                i++;
            }
            if (i >= len) {
                break;
            }

            // Read the tag -- everything up to the opening '{'
            int tagStart = i;
            while (i < len && text.charAt(i) != '{') {
                i++;
            }
            if (i >= len) {
                break;
            }
            String tag = text.substring(tagStart, i).trim();
            if (tag.isEmpty()) {
                i++;
                continue;
            }

            // Skip the opening '{'
            i++;
            int depth = 1;
            int contentStart = i;

            // Walk forward counting braces to find the matching '}'
            while (i < len && depth > 0) {
                char c = text.charAt(i);
                if (c == '{') {
                    depth++;
                } else if (c == '}') {
                    depth--;
                }
                if (depth > 0) {
                    i++;
                }
            }

            String content = text.substring(contentStart, i).trim();
            blocks.add(new Block(tag, content));

            // Skip the closing '}'
            if (i < len) {
                i++;
            }
        }
        return blocks;
    }

    public Collection importDirectory(Path bruDir) throws IOException {
        String name = bruDir.getFileName().toString();
        List<CollectionItem> items = scanDir(bruDir);

        RootConfig rootConfig = RootConfig.empty();
        Path collectionBru = bruDir.resolve("collection.bru");
        if (Files.isRegularFile(collectionBru)) {
            rootConfig = parseRootConfig(Files.readString(collectionBru));
        }

        List<Environment> environments = new ArrayList<>();
        Path envDir = bruDir.resolve("environments");
        if (Files.isDirectory(envDir)) {
            try (DirectoryStream<Path> stream = Files.newDirectoryStream(envDir, "*.bru")) {
                for (Path file : stream) {
                    environments.add(parseEnvironment(file));
                }
            }
        }

        return new Collection(null, name, "1", environments, items, rootConfig, null);
    }

    public RequestItem importFile(Path bruFile) throws IOException {
        String content = Files.readString(bruFile);
        return parseBruFile(content, bruFile.getFileName().toString());
    }

    private List<CollectionItem> scanDir(Path dir) throws IOException {
        List<CollectionItem> items = new ArrayList<>();
        try (DirectoryStream<Path> stream = Files.newDirectoryStream(dir)) {
            for (Path entry : stream) {
                String fileName = entry.getFileName().toString();
                if (Files.isDirectory(entry) && !fileName.equals("environments") && !fileName.startsWith(".")) {
                    List<CollectionItem> children = scanDir(entry);
                    if (!children.isEmpty()) {
                        String folderName = fileName;
                        RootConfig folderRoot = RootConfig.empty();
                        Path folderBru = entry.resolve("folder.bru");
                        if (Files.isRegularFile(folderBru)) {
                            String content = Files.readString(folderBru);
                            String metaName = parseMetaName(content);
                            if (metaName != null && !metaName.isEmpty()) {
                                folderName = metaName;
                            }
                            folderRoot = parseRootConfig(content);
                        }
                        items.add(new Folder(null, folderName, children, folderRoot));
                    }
                } else if (fileName.endsWith(".bru") && !"collection.bru".equals(fileName)
                        && !"folder.bru".equals(fileName)) {
                    items.add(importFile(entry));
                }
            }
        }
        return items;
    }

    RequestItem parseBruFile(String content, String filename) {
        String requestName = filename.replace(".bru", "");
        String method = "GET";
        String url = "";
        List<Header> headers = new ArrayList<>();
        List<Param> queryParams = new ArrayList<>();
        List<Param> pathParams = new ArrayList<>();
        AuthConfig auth = new AuthConfig.None();
        BodyConfig body = new BodyConfig.None();
        List<VarsDef.VarEntry> preVars = new ArrayList<>();
        List<VarsDef.VarEntry> postVars = new ArrayList<>();
        List<Assertion> assertions = new ArrayList<>();
        String docs = "";
        int seq = 0;

        for (Block block : parseBlocks(content)) {
            String tag = block.tag();
            String blockContent = block.content();

            switch (tag) {
                case "meta" -> {
                    for (var kv : parseKv(blockContent)) {
                        switch (kv.key()) {
                            case "name" -> requestName = kv.value();
                            case "seq" -> {
                                try {
                                    seq = Integer.parseInt(kv.value());
                                } catch (NumberFormatException ignored) {
                                }
                            }
                            default -> {
                            }
                        }
                    }
                }
                case "get", "post", "put", "patch", "delete", "head", "options" -> {
                    method = tag.toUpperCase();
                    for (var kv : parseKv(blockContent)) {
                        if ("url".equals(kv.key())) {
                            url = kv.value();
                        } else if ("auth".equals(kv.key()) && "inherit".equals(kv.value())) {
                            auth = new AuthConfig.Inherit();
                        }
                    }
                }
                case "headers" -> {
                    for (var kv : parseKv(blockContent)) {
                        headers.add(new Header(kv.key(), kv.value(), kv.enabled()));
                    }
                }
                case "params:query" -> {
                    for (var kv : parseKv(blockContent)) {
                        queryParams.add(new Param(kv.key(), kv.value(), Param.ParamType.QUERY, kv.enabled()));
                    }
                }
                case "params:path" -> {
                    for (var kv : parseKv(blockContent)) {
                        pathParams.add(new Param(kv.key(), kv.value(), Param.ParamType.PATH, kv.enabled()));
                    }
                }
                case "auth:basic" -> {
                    String user = "";
                    String pass = "";
                    for (var kv : parseKv(blockContent)) {
                        if ("username".equals(kv.key())) {
                            user = kv.value();
                        }
                        if ("password".equals(kv.key())) {
                            pass = kv.value();
                        }
                    }
                    auth = new AuthConfig.Basic(user, pass);
                }
                case "auth:bearer" -> {
                    for (var kv : parseKv(blockContent)) {
                        if ("token".equals(kv.key())) {
                            auth = new AuthConfig.Bearer(kv.value());
                        }
                    }
                }
                case "body:json" -> body = new BodyConfig.Json(blockContent);
                case "body:text" -> body = new BodyConfig.Text(blockContent);
                case "body:xml" -> body = new BodyConfig.Xml(blockContent);
                case "body:form-urlencoded" -> {
                    List<Param> formParams = new ArrayList<>();
                    for (var kv : parseKv(blockContent)) {
                        formParams.add(new Param(kv.key(), kv.value(), Param.ParamType.QUERY, kv.enabled()));
                    }
                    body = new BodyConfig.FormUrlEncoded(formParams);
                }
                case "body:multipart-form" -> {
                    List<BodyConfig.MultipartField> fields = new ArrayList<>();
                    for (var kv : parseKv(blockContent)) {
                        fields.add(
                                new BodyConfig.MultipartField(kv.key(), kv.value(), "text", null, null, kv.enabled()));
                    }
                    body = new BodyConfig.MultipartForm(fields);
                }
                case "body:graphql" -> body = new BodyConfig.GraphQL(blockContent, null);
                case "body:graphql:vars" -> {
                    if (body instanceof BodyConfig.GraphQL gql) {
                        body = new BodyConfig.GraphQL(gql.query(), blockContent);
                    }
                }
                case "vars:pre-request" -> {
                    for (var kv : parseKv(blockContent)) {
                        preVars.add(new VarsDef.VarEntry(kv.key(), kv.value()));
                    }
                }
                case "vars:post-response" -> {
                    for (var kv : parseKv(blockContent)) {
                        postVars.add(new VarsDef.VarEntry(kv.key(), kv.value()));
                    }
                }
                case "assert" -> {
                    for (var kv : parseKv(blockContent)) {
                        Assertion a = parseAssertion(kv.key(), kv.value(), kv.enabled());
                        if (a != null) {
                            assertions.add(a);
                        }
                    }
                }
                case "docs" -> docs = blockContent;
                default -> {
                }
            }
        }

        HttpRequestDef request = new HttpRequestDef(method, url, new ParamsDef(queryParams, pathParams), headers, auth,
                body, null);
        VarsDef vars = new VarsDef(preVars, postVars);
        RequestMeta meta = RequestMeta.http(requestName, seq);

        return new RequestItem(null, requestName, meta, request, vars, assertions, docs);
    }

    private Environment parseEnvironment(Path file) throws IOException {
        String content = Files.readString(file);
        String name = file.getFileName().toString().replace(".bru", "");
        List<EnvVariable> variables = new ArrayList<>();

        for (Block block : parseBlocks(content)) {
            String tag = block.tag();
            String blockContent = block.content();
            if ("vars".equals(tag) || "vars:secret".equals(tag)) {
                boolean secret = tag.contains("secret");
                for (var kv : parseKv(blockContent)) {
                    variables.add(new EnvVariable(kv.key(), kv.value(), secret, kv.enabled()));
                }
            }
        }
        return new Environment(null, name, null, variables, null);
    }

    private RootConfig parseRootConfig(String content) {
        List<Header> headers = new ArrayList<>();
        String authMode = null;
        AuthConfig bearerAuth = null;
        AuthConfig basicAuth = null;

        for (Block block : parseBlocks(content)) {
            switch (block.tag()) {
                case "auth" -> {
                    for (var kv : parseKv(block.content())) {
                        if ("mode".equals(kv.key())) {
                            authMode = kv.value();
                        }
                    }
                }
                case "auth:bearer" -> {
                    for (var kv : parseKv(block.content())) {
                        if ("token".equals(kv.key())) {
                            bearerAuth = new AuthConfig.Bearer(kv.value());
                        }
                    }
                }
                case "auth:basic" -> {
                    String user = "";
                    String pass = "";
                    for (var kv : parseKv(block.content())) {
                        if ("username".equals(kv.key())) {
                            user = kv.value();
                        }
                        if ("password".equals(kv.key())) {
                            pass = kv.value();
                        }
                    }
                    basicAuth = new AuthConfig.Basic(user, pass);
                }
                case "headers" -> {
                    for (var kv : parseKv(block.content())) {
                        headers.add(new Header(kv.key(), kv.value(), kv.enabled()));
                    }
                }
                default -> {
                }
            }
        }

        AuthConfig auth = new AuthConfig.None();
        if (authMode != null) {
            auth = switch (authMode) {
                case "bearer" -> bearerAuth != null ? bearerAuth : new AuthConfig.None();
                case "basic" -> basicAuth != null ? basicAuth : new AuthConfig.None();
                case "inherit" -> new AuthConfig.Inherit();
                default -> new AuthConfig.None();
            };
        }

        return new RootConfig(headers, auth, List.of());
    }

    private String parseMetaName(String content) {
        for (Block block : parseBlocks(content)) {
            if ("meta".equals(block.tag())) {
                for (var kv : parseKv(block.content())) {
                    if ("name".equals(kv.key())) {
                        return kv.value();
                    }
                }
            }
        }
        return null;
    }

    private Assertion parseAssertion(String lhs, String rhs, boolean enabled) {
        String[] parts = rhs.split("\\s+", 2);
        if (parts.length < 1) {
            return null;
        }
        String opStr = parts[0].trim();
        String expected = parts.length > 1 ? parts[1].trim() : null;
        try {
            AssertOp op = AssertOp.fromSymbol(opStr);
            return new Assertion(lhs, op, expected, enabled);
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    private record KvEntry(String key, String value, boolean enabled) {
    }

    private List<KvEntry> parseKv(String blockContent) {
        List<KvEntry> entries = new ArrayList<>();
        Matcher matcher = KV_PATTERN.matcher(blockContent);
        while (matcher.find()) {
            boolean disabled = "~".equals(matcher.group(1));
            String key = matcher.group(2).trim();
            String value = matcher.group(3).trim();
            entries.add(new KvEntry(key, value, !disabled));
        }
        return entries;
    }
}
