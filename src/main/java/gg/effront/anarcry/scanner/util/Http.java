package gg.effront.anarcry.scanner.util;

import gg.effront.anarcry.model.RequestRecord;
import gg.effront.anarcry.scanner.ScanContext;

import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

public class Http {

    public static <T> HttpResponse<T> send(
            ScanContext ctx,
            HttpClient hc,
            HttpRequest req,
            HttpResponse.BodyHandler<T> handler,
            String moduleId) throws Exception {
        HttpResponse<T> resp = hc.send(req, handler);
        long bodySize = resp.headers().firstValueAsLong("content-length").orElse(0);
        if (bodySize == 0) {
            Object b = resp.body();
            if (b instanceof String s) bodySize = s.length();
        }
        ctx.requestLog().accept(new RequestRecord(
                req.method(),
                req.uri().toString(),
                resp.statusCode(),
                bodySize,
                System.currentTimeMillis(),
                moduleId));
        return resp;
    }
}
