package gg.effront.anarcry.scanner.util;

import javax.net.ssl.*;
import java.net.InetSocketAddress;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.*;

public final class TlsUtil {

    public static final Object PROP_LOCK = new Object();

    private TlsUtil() {}

    public static TrustManager[] trustAll() {
        return new TrustManager[]{
            new X509TrustManager() {
                public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
                public void checkClientTrusted(X509Certificate[] chain, String authType) {}
                public void checkServerTrusted(X509Certificate[] chain, String authType) {}
            }
        };
    }

    public static Runnable removeDisabled(String... terms) {
        String key = "jdk.tls.disabledAlgorithms";
        String original = Security.getProperty(key);
        if (original == null) return () -> {};
        List<String> parts = new ArrayList<>(Arrays.asList(original.split(",\\s*")));
        Set<String> toRemove = new HashSet<>(Arrays.asList(terms));
        parts.removeIf(p -> toRemove.contains(p.trim()));
        Security.setProperty(key, String.join(", ", parts));
        return () -> Security.setProperty(key, original);
    }

    public static SSLContext sslContext(TrustManager[] tm) throws NoSuchAlgorithmException, KeyManagementException {
        SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(null, tm, new SecureRandom());
        return ctx;
    }

    public static SSLSocket connectSocket(String host, int port, SSLContext ctx, int timeoutMs) throws Exception {
        SSLSocket socket = (SSLSocket) ctx.getSocketFactory().createSocket();
        socket.setSoTimeout(timeoutMs);
        socket.connect(new InetSocketAddress(host, port), timeoutMs);
        return socket;
    }
}
