package gg.effront.anarcry.apiclient.io;

import gg.effront.anarcry.apiclient.model.AuthConfig;
import gg.effront.anarcry.apiclient.model.BodyConfig;
import gg.effront.anarcry.apiclient.model.Header;
import gg.effront.anarcry.apiclient.model.HttpRequestDef;
import gg.effront.anarcry.apiclient.model.Param;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

public final class CurlGenerator {

    private CurlGenerator() {
    }

    public static String generate(HttpRequestDef req) {
        List<String> parts = new ArrayList<>();
        parts.add("curl");

        if (!"GET".equalsIgnoreCase(req.method())) {
            parts.add("-X " + req.method().toUpperCase());
        }

        String url = buildUrl(req);
        parts.add(shellQuote(url));

        for (Header h : req.headers()) {
            if (!h.enabled()) {
                continue;
            }
            parts.add("-H " + shellQuote(h.name() + ": " + h.value()));
        }

        appendAuth(req.auth(), parts);
        appendBody(req.body(), parts);

        return String.join(" \\\n  ", parts);
    }

    private static String buildUrl(HttpRequestDef req) {
        String url = req.url();

        List<Param> pathParams = req.params().path().stream().filter(Param::enabled).toList();
        for (Param p : pathParams) {
            url = url.replace(":" + p.name(), URLEncoder.encode(p.value(), StandardCharsets.UTF_8));
        }

        List<Param> queryParams = req.params().query().stream().filter(Param::enabled).toList();
        if (!queryParams.isEmpty()) {
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
            url = sb.toString();
        }

        return url;
    }

    private static void appendAuth(AuthConfig auth, List<String> parts) {
        switch (auth) {
            case AuthConfig.Bearer b -> parts.add("-H " + shellQuote("Authorization: Bearer " + b.token()));
            case AuthConfig.Basic b -> parts.add("-u " + shellQuote(b.username() + ":" + b.password()));
            case AuthConfig.ApiKey a -> {
                if ("query".equalsIgnoreCase(a.placement())) {
                    // already handled in URL query params if wired; emit as comment
                } else {
                    parts.add("-H " + shellQuote(a.key() + ": " + a.value()));
                }
            }
            case AuthConfig.Digest d -> parts.add("--digest -u " + shellQuote(d.username() + ":" + d.password()));
            default -> {
            }
        }
    }

    private static void appendBody(BodyConfig body, List<String> parts) {
        switch (body) {
            case BodyConfig.Json j -> {
                parts.add("-H " + shellQuote("Content-Type: application/json"));
                parts.add("-d " + shellQuote(j.content()));
            }
            case BodyConfig.Text t -> {
                parts.add("-H " + shellQuote("Content-Type: text/plain"));
                parts.add("-d " + shellQuote(t.content()));
            }
            case BodyConfig.Xml x -> {
                parts.add("-H " + shellQuote("Content-Type: application/xml"));
                parts.add("-d " + shellQuote(x.content()));
            }
            case BodyConfig.FormUrlEncoded f -> {
                for (Param p : f.params()) {
                    if (p.enabled()) {
                        parts.add("--data-urlencode " + shellQuote(p.name() + "=" + p.value()));
                    }
                }
            }
            case BodyConfig.GraphQL g -> {
                parts.add("-H " + shellQuote("Content-Type: application/json"));
                StringBuilder payload = new StringBuilder("{\"query\":");
                payload.append(jsonQuote(g.query()));
                if (g.variables() != null && !g.variables().isBlank()) {
                    payload.append(",\"variables\":").append(g.variables());
                }
                payload.append("}");
                parts.add("-d " + shellQuote(payload.toString()));
            }
            case BodyConfig.MultipartForm m -> {
                for (BodyConfig.MultipartField field : m.fields()) {
                    if (!field.enabled()) {
                        continue;
                    }
                    if (field.filePath() != null && !field.filePath().isEmpty()) {
                        parts.add("-F " + shellQuote(field.name() + "=@" + field.filePath()));
                    } else {
                        parts.add("-F " + shellQuote(field.name() + "=" + field.value()));
                    }
                }
            }
            case BodyConfig.FileBody f -> parts.add("--data-binary " + shellQuote("@" + f.filePath()));
            case BodyConfig.None ignored -> {
            }
        }
    }

    private static String shellQuote(String s) {
        return "'" + s.replace("'", "'\\''") + "'";
    }

    private static String jsonQuote(String s) {
        return "\"" + s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n").replace("\r", "\\r")
                .replace("\t", "\\t") + "\"";
    }
}
