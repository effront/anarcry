package gg.effront.anarcry.apiclient.io;

import gg.effront.anarcry.apiclient.model.AuthConfig;
import gg.effront.anarcry.apiclient.model.BodyConfig;
import gg.effront.anarcry.apiclient.model.Header;
import gg.effront.anarcry.apiclient.model.HttpRequestDef;
import gg.effront.anarcry.apiclient.model.Param;
import gg.effront.anarcry.apiclient.model.ParamsDef;
import gg.effront.anarcry.apiclient.model.RequestItem;
import gg.effront.anarcry.apiclient.model.RequestMeta;

import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class CurlImporter {

    private static final Pattern QUOTED_PATTERN = Pattern.compile("'([^']*)'|\"([^\"]*)\"|([^\\s]+)");

    public RequestItem importCurl(String curlCommand) {
        List<String> tokens = tokenize(curlCommand.trim());
        String method = "GET";
        String url = "";
        List<Header> headers = new ArrayList<>();
        String dataBody = null;
        AuthConfig auth = new AuthConfig.None();
        boolean hasData = false;

        int i = 0;
        while (i < tokens.size()) {
            String token = tokens.get(i);
            switch (token) {
                case "curl" -> {
                }
                case "-X", "--request" -> {
                    if (i + 1 < tokens.size()) {
                        i++;
                        method = tokens.get(i).toUpperCase();
                    }
                }
                case "-H", "--header" -> {
                    if (i + 1 < tokens.size()) {
                        i++;
                        String header = tokens.get(i);
                        int colon = header.indexOf(':');
                        if (colon > 0) {
                            String name = header.substring(0, colon).trim();
                            String value = header.substring(colon + 1).trim();
                            headers.add(Header.of(name, value));
                        }
                    }
                }
                case "-d", "--data", "--data-raw", "--data-binary" -> {
                    if (i + 1 < tokens.size()) {
                        i++;
                        dataBody = tokens.get(i);
                        hasData = true;
                    }
                }
                case "--data-urlencode" -> {
                    if (i + 1 < tokens.size()) {
                        i++;
                        String val = tokens.get(i);
                        dataBody = (dataBody != null ? dataBody + "&" : "") + val;
                        hasData = true;
                    }
                }
                case "-u", "--user" -> {
                    if (i + 1 < tokens.size()) {
                        i++;
                        String creds = tokens.get(i);
                        int colon = creds.indexOf(':');
                        if (colon > 0) {
                            auth = new AuthConfig.Basic(creds.substring(0, colon), creds.substring(colon + 1));
                        }
                    }
                }
                case "-b", "--cookie" -> {
                    if (i + 1 < tokens.size()) {
                        i++;
                        headers.add(Header.of("Cookie", tokens.get(i)));
                    }
                }
                case "-A", "--user-agent" -> {
                    if (i + 1 < tokens.size()) {
                        i++;
                        headers.add(Header.of("User-Agent", tokens.get(i)));
                    }
                }
                case "-e", "--referer" -> {
                    if (i + 1 < tokens.size()) {
                        i++;
                        headers.add(Header.of("Referer", tokens.get(i)));
                    }
                }
                default -> {
                    if (!token.startsWith("-") && url.isEmpty()) {
                        url = token;
                    }
                }
            }
            i++;
        }

        if (hasData && "GET".equals(method)) {
            method = "POST";
        }

        BodyConfig body = buildBody(dataBody, headers);
        List<Param> queryParams = extractQueryParams(url);
        String cleanUrl = removeQueryString(url);

        HttpRequestDef request = new HttpRequestDef(method, cleanUrl, new ParamsDef(queryParams, List.of()), headers,
                auth, body, null);

        String name = deriveName(method, url);
        return new RequestItem(null, name, RequestMeta.http(name, 0), request, null, List.of(), "");
    }

    private BodyConfig buildBody(String data, List<Header> headers) {
        if (data == null) {
            return new BodyConfig.None();
        }
        String contentType = headers.stream().filter(h -> h.name().equalsIgnoreCase("Content-Type")).map(Header::value)
                .findFirst().orElse("");

        if (contentType.contains("application/json") || (data.startsWith("{") || data.startsWith("["))) {
            return new BodyConfig.Json(data);
        }
        if (contentType.contains("application/xml") || contentType.contains("text/xml")) {
            return new BodyConfig.Xml(data);
        }
        if (contentType.contains("application/x-www-form-urlencoded") || data.contains("=")) {
            List<Param> params = new ArrayList<>();
            for (String pair : data.split("&")) {
                int eq = pair.indexOf('=');
                if (eq > 0) {
                    String key = URLDecoder.decode(pair.substring(0, eq), StandardCharsets.UTF_8);
                    String val = URLDecoder.decode(pair.substring(eq + 1), StandardCharsets.UTF_8);
                    params.add(Param.query(key, val));
                }
            }
            return new BodyConfig.FormUrlEncoded(params);
        }
        return new BodyConfig.Text(data);
    }

    private List<Param> extractQueryParams(String url) {
        List<Param> params = new ArrayList<>();
        int qIdx = url.indexOf('?');
        if (qIdx < 0) {
            return params;
        }
        String query = url.substring(qIdx + 1);
        int fragIdx = query.indexOf('#');
        if (fragIdx >= 0) {
            query = query.substring(0, fragIdx);
        }
        for (String pair : query.split("&")) {
            int eq = pair.indexOf('=');
            if (eq > 0) {
                String key = URLDecoder.decode(pair.substring(0, eq), StandardCharsets.UTF_8);
                String val = URLDecoder.decode(pair.substring(eq + 1), StandardCharsets.UTF_8);
                params.add(Param.query(key, val));
            }
        }
        return params;
    }

    private String removeQueryString(String url) {
        int qIdx = url.indexOf('?');
        return qIdx >= 0 ? url.substring(0, qIdx) : url;
    }

    private String deriveName(String method, String url) {
        try {
            URI uri = URI.create(url);
            String path = uri.getPath();
            if (path == null || path.isEmpty() || path.equals("/")) {
                return method + " " + uri.getHost();
            }
            return method + " " + path;
        } catch (Exception e) {
            return method + " request";
        }
    }

    static List<String> tokenize(String command) {
        String normalized = command.replace("\\\n", " ").replace("\\\r\n", " ").trim();
        List<String> tokens = new ArrayList<>();
        Matcher matcher = QUOTED_PATTERN.matcher(normalized);
        while (matcher.find()) {
            if (matcher.group(1) != null) {
                tokens.add(matcher.group(1));
            } else if (matcher.group(2) != null) {
                tokens.add(matcher.group(2));
            } else {
                tokens.add(matcher.group(3));
            }
        }
        return tokens;
    }
}
