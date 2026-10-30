package gg.effront.anarcry.scanner.util;

import com.github.zhkl0228.impersonator.ImpersonatorFactory;

import okhttp3.OkHttpClientFactory;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpHeaders;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Flow;
import java.util.concurrent.TimeUnit;

import javax.net.ssl.SSLSession;

import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;

public final class StealthHttpClient {

    static final String CHROME_UA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36"
            + " (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36";

    private static final Map<String, String> BROWSER_HEADERS;

    static {
        BROWSER_HEADERS = new LinkedHashMap<>();
        BROWSER_HEADERS.put("User-Agent", CHROME_UA);
        BROWSER_HEADERS.put("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,"
                + "image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7");
        BROWSER_HEADERS.put("Accept-Language", "en-US,en;q=0.9");
        BROWSER_HEADERS.put("Accept-Encoding", "gzip, deflate, br, zstd");
        BROWSER_HEADERS.put("sec-ch-ua",
                "\"Chromium\";v=\"130\", \"Google Chrome\";v=\"130\", \"Not?A_Brand\";v=\"99\"");
        BROWSER_HEADERS.put("sec-ch-ua-mobile", "?0");
        BROWSER_HEADERS.put("sec-ch-ua-platform", "\"macOS\"");
        BROWSER_HEADERS.put("sec-fetch-dest", "document");
        BROWSER_HEADERS.put("sec-fetch-mode", "navigate");
        BROWSER_HEADERS.put("sec-fetch-site", "none");
        BROWSER_HEADERS.put("sec-fetch-user", "?1");
        BROWSER_HEADERS.put("Upgrade-Insecure-Requests", "1");
    }

    private static volatile OkHttpClient instance;

    private StealthHttpClient() {
    }

    public static OkHttpClient chrome() {
        if (instance == null) {
            synchronized (StealthHttpClient.class) {
                if (instance == null) {
                    instance = OkHttpClientFactory.create(ImpersonatorFactory.macChrome())
                            .setConnectTimeout(6, TimeUnit.SECONDS).setReadTimeout(10, TimeUnit.SECONDS)
                            .newHttpClient();
                }
            }
        }
        return instance;
    }

    @SuppressWarnings("unchecked")
    public static <T> HttpResponse<T> send(HttpRequest jdkReq) throws IOException {
        Request okReq = toOkHttpRequest(jdkReq);
        try (Response okResp = chrome().newCall(okReq).execute()) {
            return (HttpResponse<T>) toJdkResponse(okResp, jdkReq.uri());
        }
    }

    private static Request toOkHttpRequest(HttpRequest jdkReq) {
        Request.Builder builder = new Request.Builder().url(jdkReq.uri().toString());

        Set<String> presentHeaders = new java.util.TreeSet<>(String.CASE_INSENSITIVE_ORDER);
        jdkReq.headers().map().forEach((name, values) -> {
            presentHeaders.add(name);
            for (String val : values) {
                builder.addHeader(name, val);
            }
        });

        BROWSER_HEADERS.forEach((name, val) -> {
            if (!presentHeaders.contains(name)) {
                builder.addHeader(name, val);
            }
        });

        String method = jdkReq.method();
        RequestBody body = null;
        if (jdkReq.bodyPublisher().isPresent()) {
            byte[] bytes = readBodyPublisher(jdkReq.bodyPublisher().get());
            if (bytes.length > 0) {
                String ct = jdkReq.headers().firstValue("Content-Type").orElse("application/octet-stream");
                body = RequestBody.create(bytes, MediaType.parse(ct));
            }
        }

        switch (method) {
            case "GET" -> builder.get();
            case "HEAD" -> builder.head();
            case "DELETE" -> builder.delete(body);
            case "POST" -> builder.post(body != null ? body : RequestBody.create(new byte[0], null));
            case "PUT" -> builder.put(body != null ? body : RequestBody.create(new byte[0], null));
            case "PATCH" -> builder.patch(body != null ? body : RequestBody.create(new byte[0], null));
            default -> builder.method(method, body);
        }

        return builder.build();
    }

    private static HttpResponse<String> toJdkResponse(Response okResp, URI uri) throws IOException {
        int status = okResp.code();
        String bodyStr = okResp.body() != null ? okResp.body().string() : "";
        Map<String, List<String>> headerMap = okResp.headers().toMultimap();
        HttpHeaders headers = HttpHeaders.of(headerMap, (k, v) -> true);
        return new StealthResponse(status, bodyStr, headers, uri);
    }

    static byte[] readBodyPublisher(HttpRequest.BodyPublisher publisher) {
        if (publisher.contentLength() == 0) {
            return new byte[0];
        }
        CompletableFuture<byte[]> future = new CompletableFuture<>();
        publisher.subscribe(new Flow.Subscriber<>() {

            private final List<ByteBuffer> buffers = new ArrayList<>();

            @Override
            public void onSubscribe(Flow.Subscription subscription) {
                subscription.request(Long.MAX_VALUE);
            }

            @Override
            public void onNext(ByteBuffer item) {
                buffers.add(ByteBuffer.allocate(item.remaining()).put(item).flip());
            }

            @Override
            public void onError(Throwable throwable) {
                future.completeExceptionally(throwable);
            }

            @Override
            public void onComplete() {
                int total = buffers.stream().mapToInt(ByteBuffer::remaining).sum();
                byte[] result = new byte[total];
                int pos = 0;
                for (ByteBuffer buf : buffers) {
                    int len = buf.remaining();
                    buf.get(result, pos, len);
                    pos += len;
                }
                future.complete(result);
            }
        });
        try {
            return future.get(5, TimeUnit.SECONDS);
        } catch (Exception e) {
            return new byte[0];
        }
    }

    static final class StealthResponse implements HttpResponse<String> {

        private final int statusCode;
        private final String body;
        private final HttpHeaders headers;
        private final URI uri;

        StealthResponse(int statusCode, String body, HttpHeaders headers, URI uri) {
            this.statusCode = statusCode;
            this.body = body;
            this.headers = headers;
            this.uri = uri;
        }

        @Override
        public int statusCode() {
            return statusCode;
        }

        @Override
        public HttpRequest request() {
            return null;
        }

        @Override
        public Optional<HttpResponse<String>> previousResponse() {
            return Optional.empty();
        }

        @Override
        public HttpHeaders headers() {
            return headers;
        }

        @Override
        public String body() {
            return body;
        }

        @Override
        public Optional<SSLSession> sslSession() {
            return Optional.empty();
        }

        @Override
        public URI uri() {
            return uri;
        }

        @Override
        public java.net.http.HttpClient.Version version() {
            return java.net.http.HttpClient.Version.HTTP_2;
        }
    }
}
