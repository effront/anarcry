package gg.effront.anarcry.scanner.util;

import gg.effront.anarcry.model.RequestRecord;
import gg.effront.anarcry.scanner.ScanContext;

import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

public class Http {

    @SuppressWarnings("unchecked")
    public static <T> HttpResponse<T> send(ScanContext ctx, HttpClient hc, HttpRequest req,
            HttpResponse.BodyHandler<T> handler, String moduleId) throws Exception {
        String cookies = "";
        if (!ctx.config().sessionCookie().isBlank()) {
            cookies = ctx.config().sessionCookie();
        }
        String challengeCookies = ctx.wafState().challengeCookies();
        if (!challengeCookies.isEmpty()) {
            cookies = cookies.isEmpty() ? challengeCookies : cookies + "; " + challengeCookies;
        }
        if (!cookies.isEmpty()) {
            req = HttpRequest.newBuilder(req, (n, v) -> true).header("Cookie", cookies).build();
        }
        HttpResponse<T> resp;
        BrowserTransport bt = ctx.wafState().browserTransport();
        if (bt != null && bt.isTargetHost(req.uri().toString())) {
            resp = (HttpResponse<T>) bt.fetch(req);
        } else if (ctx.wafState().isStealthActive()) {
            resp = (HttpResponse<T>) StealthHttpClient.send(req);
        } else {
            resp = hc.send(req, handler);
        }
        if (ctx.config().delayMs() > 0) {
            try {
                Thread.sleep(ctx.config().delayMs());
            } catch (InterruptedException ie) {
                Thread.currentThread().interrupt();
            }
        }
        long bodySize = resp.headers().firstValueAsLong("content-length").orElse(0);
        if (bodySize == 0) {
            Object b = resp.body();
            if (b instanceof String s) {
                bodySize = s.length();
            }
        }
        ctx.requestLog().accept(new RequestRecord(req.method(), req.uri().toString(), resp.statusCode(), bodySize,
                System.currentTimeMillis(), moduleId));
        return resp;
    }
}
