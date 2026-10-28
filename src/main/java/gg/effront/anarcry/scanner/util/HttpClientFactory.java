package gg.effront.anarcry.scanner.util;

import java.net.http.HttpClient;
import java.time.Duration;
import javax.net.ssl.SSLParameters;

public final class HttpClientFactory {

    // HTTP/2, follows redirects -- general purpose (Headers, JWT, CORS, OAuth,
    // GraphQL, CRLF, XXE, SSTI, IDOR)
    private static volatile HttpClient http2Instance;

    // HTTP/1.1, no redirect -- for SSRF and OpenRedirect probing
    private static volatile HttpClient noRedirectInstance;

    private HttpClientFactory() {
    }

    public static HttpClient http2() throws Exception {
        if (http2Instance == null) {
            synchronized (HttpClientFactory.class) {
                if (http2Instance == null) {
                    SSLParameters params = new SSLParameters();
                    params.setEndpointIdentificationAlgorithm("");
                    http2Instance = HttpClient.newBuilder().sslContext(TlsUtil.sslContext(TlsUtil.trustAll()))
                            .sslParameters(params).followRedirects(HttpClient.Redirect.NORMAL)
                            .version(HttpClient.Version.HTTP_2).connectTimeout(Duration.ofSeconds(5)).build();
                }
            }
        }
        return http2Instance;
    }

    public static HttpClient noRedirect() throws Exception {
        if (noRedirectInstance == null) {
            synchronized (HttpClientFactory.class) {
                if (noRedirectInstance == null) {
                    SSLParameters params = new SSLParameters();
                    params.setEndpointIdentificationAlgorithm("");
                    noRedirectInstance = HttpClient.newBuilder().sslContext(TlsUtil.sslContext(TlsUtil.trustAll()))
                            .sslParameters(params).followRedirects(HttpClient.Redirect.NEVER)
                            .version(HttpClient.Version.HTTP_1_1).connectTimeout(Duration.ofSeconds(5)).build();
                }
            }
        }
        return noRedirectInstance;
    }

    // Follows up to 1 redirect -- used by SSRF redirect-bypass probing
    public static HttpClient followOne() throws Exception {
        SSLParameters params = new SSLParameters();
        params.setEndpointIdentificationAlgorithm("");
        return HttpClient.newBuilder().sslContext(TlsUtil.sslContext(TlsUtil.trustAll())).sslParameters(params)
                .followRedirects(HttpClient.Redirect.NORMAL).version(HttpClient.Version.HTTP_1_1)
                .connectTimeout(Duration.ofSeconds(5)).build();
    }
}
