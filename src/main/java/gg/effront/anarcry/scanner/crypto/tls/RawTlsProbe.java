package gg.effront.anarcry.scanner.crypto.tls;

import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.security.SecureRandom;
import java.util.Optional;

public final class RawTlsProbe {

    private static final int TIMEOUT_MS = 5000;
    private static final SecureRandom RNG = new SecureRandom();

    private RawTlsProbe() {
    }

    public record CipherDef(int id, String name) {
    }

    public static final CipherDef[] RC4_CIPHERS = {new CipherDef(0x0004, "TLS_RSA_WITH_RC4_128_MD5"),
            new CipherDef(0x0005, "TLS_RSA_WITH_RC4_128_SHA"), new CipherDef(0xC011, "TLS_ECDHE_RSA_WITH_RC4_128_SHA"),
            new CipherDef(0xC007, "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA"),};

    public static final CipherDef[] NULL_CIPHERS = {new CipherDef(0x0001, "TLS_RSA_WITH_NULL_MD5"),
            new CipherDef(0x0002, "TLS_RSA_WITH_NULL_SHA"), new CipherDef(0x003B, "TLS_RSA_WITH_NULL_SHA256"),
            new CipherDef(0xC010, "TLS_ECDHE_RSA_WITH_NULL_SHA"),
            new CipherDef(0xC006, "TLS_ECDHE_ECDSA_WITH_NULL_SHA"),};

    public static final CipherDef[] ANON_CIPHERS = {new CipherDef(0x0018, "TLS_DH_anon_WITH_RC4_128_MD5"),
            new CipherDef(0x001B, "TLS_DH_anon_WITH_3DES_EDE_CBC_SHA"),
            new CipherDef(0x0034, "TLS_DH_anon_WITH_AES_128_CBC_SHA"),
            new CipherDef(0x003A, "TLS_DH_anon_WITH_AES_256_CBC_SHA"),
            new CipherDef(0xC018, "TLS_AECDH_WITH_AES_128_CBC_SHA"),
            new CipherDef(0xC019, "TLS_AECDH_WITH_AES_256_CBC_SHA"),};

    public static final CipherDef[] DES3_CIPHERS = {new CipherDef(0x000A, "TLS_RSA_WITH_3DES_EDE_CBC_SHA"),
            new CipherDef(0x0016, "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA"),
            new CipherDef(0xC012, "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA"),
            new CipherDef(0xC008, "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA"),};

    public static final CipherDef[] EXPORT_CIPHERS = {new CipherDef(0x0003, "TLS_RSA_EXPORT_WITH_RC4_40_MD5"),
            new CipherDef(0x0006, "TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5"),
            new CipherDef(0x0008, "TLS_RSA_EXPORT_WITH_DES40_CBC_SHA"),
            new CipherDef(0x000B, "TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA"),
            new CipherDef(0x000E, "TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA"),};

    public static Optional<String> probe(String host, int port, CipherDef[] ciphers) {
        byte[] clientHello = buildClientHello(host, ciphers);
        try (Socket sock = new Socket()) {
            sock.setSoTimeout(TIMEOUT_MS);
            sock.connect(new InetSocketAddress(host, port), TIMEOUT_MS);
            OutputStream out = sock.getOutputStream();
            InputStream in = sock.getInputStream();
            out.write(clientHello);
            out.flush();
            return parseServerHello(in, ciphers);
        } catch (Exception e) {
            return Optional.empty();
        }
    }

    private static byte[] buildClientHello(String host, CipherDef[] ciphers) {
        byte[] random = new byte[32];
        RNG.nextBytes(random);

        // SNI extension
        byte[] hostBytes = host.getBytes(java.nio.charset.StandardCharsets.US_ASCII);
        byte[] sniExt = buildSniExtension(hostBytes);

        // Cipher suites: 2 bytes per cipher
        int cipherLen = ciphers.length * 2;

        // ClientHello body
        int bodyLen = 2 /* version */ + 32 /* random */ + 1 /* session id len */
                + 2 /* cipher suites length */ + cipherLen + 2 /* compression */ + 2 /* extensions length */
                + sniExt.length;

        // Handshake header: type(1) + length(3)
        int handshakeLen = 1 + 3 + bodyLen;

        // TLS record: type(1) + version(2) + length(2) + handshake
        byte[] record = new byte[5 + handshakeLen];
        int pos = 0;

        // TLS record header
        record[pos++] = 0x16; // Handshake
        record[pos++] = 0x03;
        record[pos++] = 0x01; // TLS 1.0
        record[pos++] = (byte) ((handshakeLen >> 8) & 0xFF);
        record[pos++] = (byte) (handshakeLen & 0xFF);

        // Handshake header
        record[pos++] = 0x01; // ClientHello
        record[pos++] = (byte) ((bodyLen >> 16) & 0xFF);
        record[pos++] = (byte) ((bodyLen >> 8) & 0xFF);
        record[pos++] = (byte) (bodyLen & 0xFF);

        // Client version: TLS 1.2 for max compat
        record[pos++] = 0x03;
        record[pos++] = 0x03;

        // Random
        System.arraycopy(random, 0, record, pos, 32);
        pos += 32;

        // Session ID (empty)
        record[pos++] = 0x00;

        // Cipher suites
        record[pos++] = (byte) ((cipherLen >> 8) & 0xFF);
        record[pos++] = (byte) (cipherLen & 0xFF);
        for (CipherDef c : ciphers) {
            record[pos++] = (byte) ((c.id() >> 8) & 0xFF);
            record[pos++] = (byte) (c.id() & 0xFF);
        }

        // Compression methods: null only
        record[pos++] = 0x01;
        record[pos++] = 0x00;

        // Extensions length
        record[pos++] = (byte) ((sniExt.length >> 8) & 0xFF);
        record[pos++] = (byte) (sniExt.length & 0xFF);

        // SNI extension
        System.arraycopy(sniExt, 0, record, pos, sniExt.length);

        return record;
    }

    private static byte[] buildSniExtension(byte[] hostBytes) {
        int nameListLen = hostBytes.length + 3; // type(1) + name_len(2) + name
        int extDataLen = nameListLen + 2; // list_len(2) + name_list
        byte[] ext = new byte[4 + extDataLen]; // ext_type(2) + ext_len(2) + data
        int pos = 0;
        // Extension type: server_name (0x0000)
        ext[pos++] = 0x00;
        ext[pos++] = 0x00;
        // Extension data length
        ext[pos++] = (byte) ((extDataLen >> 8) & 0xFF);
        ext[pos++] = (byte) (extDataLen & 0xFF);
        // Server name list length
        ext[pos++] = (byte) ((nameListLen >> 8) & 0xFF);
        ext[pos++] = (byte) (nameListLen & 0xFF);
        // Name type: hostname (0x00)
        ext[pos++] = 0x00;
        // Hostname length
        ext[pos++] = (byte) ((hostBytes.length >> 8) & 0xFF);
        ext[pos++] = (byte) (hostBytes.length & 0xFF);
        // Hostname
        System.arraycopy(hostBytes, 0, ext, pos, hostBytes.length);
        return ext;
    }

    private static Optional<String> parseServerHello(InputStream in, CipherDef[] ciphers) throws Exception {
        // Read TLS record header (5 bytes)
        byte[] recordHdr = readExact(in, 5);
        if (recordHdr == null) {
            return Optional.empty();
        }

        int contentType = recordHdr[0] & 0xFF;
        int recordLen = ((recordHdr[3] & 0xFF) << 8) | (recordHdr[4] & 0xFF);

        // Alert = cipher rejected
        if (contentType == 0x15) {
            return Optional.empty();
        }

        // Not a handshake = unexpected
        if (contentType != 0x16) {
            return Optional.empty();
        }

        byte[] payload = readExact(in, Math.min(recordLen, 4096));
        if (payload == null || payload.length < 6) {
            return Optional.empty();
        }

        // Handshake type: ServerHello = 0x02
        if (payload[0] != 0x02) {
            return Optional.empty();
        }

        // Skip handshake length(3) + server version(2) + random(32) = 37 bytes
        int pos = 1 + 3 + 2 + 32;
        if (pos >= payload.length) {
            return Optional.empty();
        }

        // Session ID length + skip session ID
        int sessionIdLen = payload[pos] & 0xFF;
        pos += 1 + sessionIdLen;

        // Cipher suite (2 bytes)
        if (pos + 2 > payload.length) {
            return Optional.empty();
        }
        int selectedCipher = ((payload[pos] & 0xFF) << 8) | (payload[pos + 1] & 0xFF);

        for (CipherDef c : ciphers) {
            if (c.id() == selectedCipher) {
                return Optional.of(c.name());
            }
        }

        return Optional.of("0x" + String.format("%04X", selectedCipher));
    }

    private static byte[] readExact(InputStream in, int len) throws Exception {
        byte[] buf = new byte[len];
        int read = 0;
        while (read < len) {
            int n = in.read(buf, read, len - read);
            if (n < 0) {
                return null;
            }
            read += n;
        }
        return buf;
    }
}
