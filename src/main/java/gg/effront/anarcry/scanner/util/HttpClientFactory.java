package gg.effront.anarcry.scanner.util;

import com.github.zhkl0228.impersonator.ImpersonatorFactory;

import java.net.http.HttpClient;
import java.time.Duration;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;

public final class HttpClientFactory {

    // HTTP/2, follows redirects -- general purpose (Headers, JWT, CORS, OAuth,
    // GraphQL, CRLF, XXE, SSTI, IDOR)
    private static volatile HttpClient http2Instance;

    // HTTP/1.1, no redirect -- for SSRF and OpenRedirect probing
    private static volatile HttpClient noRedirectInstance;

    // HTTP/2, follows redirects -- Chrome TLS fingerprint (JA3/JA4 spoofing)
    private static volatile HttpClient stealthInstance;

    private HttpClientFactory() {
    }

    public static synchronized void closeAll() {
        if (http2Instance != null) {
            http2Instance.close();
            http2Instance = null;
        }
        if (noRedirectInstance != null) {
            noRedirectInstance.close();
            noRedirectInstance = null;
        }
        if (stealthInstance != null) {
            stealthInstance.close();
            stealthInstance = null;
        }
        if (followOneInstance != null) {
            followOneInstance.close();
            followOneInstance = null;
        }
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

    public static HttpClient stealth() throws Exception {
        if (stealthInstance == null) {
            synchronized (HttpClientFactory.class) {
                if (stealthInstance == null) {
                    SSLContext chromeTls = ImpersonatorFactory.macChrome().newSSLContext(null, null);
                    SSLParameters params = new SSLParameters();
                    params.setEndpointIdentificationAlgorithm("");
                    stealthInstance = HttpClient.newBuilder().sslContext(chromeTls).sslParameters(params)
                            .followRedirects(HttpClient.Redirect.NORMAL).version(HttpClient.Version.HTTP_2)
                            .connectTimeout(Duration.ofSeconds(6)).build();
                }
            }
        }
        return stealthInstance;
    }

    private static volatile HttpClient followOneInstance;

    // Follows up to 1 redirect -- used by SSRF redirect-bypass probing
    public static HttpClient followOne() throws Exception {
        if (followOneInstance == null) {
            synchronized (HttpClientFactory.class) {
                if (followOneInstance == null) {
                    SSLParameters params = new SSLParameters();
                    params.setEndpointIdentificationAlgorithm("");
                    followOneInstance = HttpClient.newBuilder().sslContext(TlsUtil.sslContext(TlsUtil.trustAll()))
                            .sslParameters(params).followRedirects(HttpClient.Redirect.NORMAL)
                            .version(HttpClient.Version.HTTP_1_1).connectTimeout(Duration.ofSeconds(5)).build();
                }
            }
        }
        return followOneInstance;
    }
}
