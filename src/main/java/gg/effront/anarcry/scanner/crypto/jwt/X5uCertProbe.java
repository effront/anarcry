package gg.effront.anarcry.scanner.crypto.jwt;

import gg.effront.anarcry.model.CvssCalculator;
import gg.effront.anarcry.model.CweRegistry;
import gg.effront.anarcry.model.Finding;
import gg.effront.anarcry.model.Severity;
import gg.effront.anarcry.scanner.ScanContext;
import gg.effront.anarcry.scanner.util.Http;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.time.Duration;
import java.util.Base64;
import java.util.List;
import java.util.Optional;
import java.util.function.Consumer;

/**
 * Probes x5u header injection: sets the x5u field to a canary URL (localhost
 * port 1) and signs the token with a throwaway key. If the server attempts to
 * fetch the x5u URL, the response will differ from a normal "invalid token"
 * rejection -- either a 500, a connection error in the body, or a measurable
 * timing anomaly.
 *
 * <p>
 * This is a detection-only probe. Full exploitation requires an
 * attacker-controlled server hosting a self-signed certificate, but the fetch
 * behavior alone confirms the vulnerability.
 */
public class X5uCertProbe {

    private static final List<String> AUTH_PATHS = List.of("/api/me", "/api/user", "/api/profile");

    // Known-unreachable URL -- localhost port 1 is almost never listening.
    // If the server tries to connect, it gets connection refused quickly.
    private static final String CANARY_X5U = "https://127.0.0.1:1/x5u-probe";

    public Optional<Finding> probe(String[] parts, ScanContext ctx, String base, HttpClient hc, Consumer<String> log) {
        if (parts.length < 3 || parts[2] == null || parts[2].isBlank()) {
            log.accept("[~] JWT: x5u -- token sem signature para baseline, pulando");
            return Optional.empty();
        }
        log.accept("[~] JWT: probe x5u remote certificate fetch -> " + base);
        try {
            // Generate throwaway key pair -- only needed to produce a signed token
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(2048);
            KeyPair kp = kpg.generateKeyPair();

            // Build JWT header with x5u pointing to canary
            String headerJson = "{\"alg\":\"RS256\",\"typ\":\"JWT\",\"x5u\":\"" + CANARY_X5U + "\"}";
            String forgedHeader = Base64.getUrlEncoder().withoutPadding()
                    .encodeToString(headerJson.getBytes(StandardCharsets.UTF_8));
            String sigInput = forgedHeader + "." + parts[1];

            Signature rsaSig = Signature.getInstance("SHA256withRSA");
            rsaSig.initSign(kp.getPrivate());
            rsaSig.update(sigInput.getBytes(StandardCharsets.UTF_8));
            String sig = Base64.getUrlEncoder().withoutPadding().encodeToString(rsaSig.sign());
            String forgedToken = sigInput + "." + sig;

            // Build baseline token with flipped last byte of original signature
            byte[] origSigBytes = Base64.getUrlDecoder().decode(padB64(parts[2]));
            origSigBytes[origSigBytes.length - 1] ^= (byte) 0xFF;
            String badSig = Base64.getUrlEncoder().withoutPadding().encodeToString(origSigBytes);
            String baselineToken = parts[0] + "." + parts[1] + "." + badSig;

            log.accept("[~] JWT: x5u token forjado, comparando com baseline de rejeicao");

            for (String path : AUTH_PATHS) {
                try {
                    // Baseline: send token with bad signature (no x5u header)
                    HttpRequest baseReq = HttpRequest.newBuilder().uri(URI.create(base + path))
                            .header("Authorization", "Bearer " + baselineToken).timeout(Duration.ofSeconds(5)).GET()
                            .build();
                    long t0 = System.nanoTime();
                    HttpResponse<String> baseResp = Http.send(ctx, hc, baseReq, HttpResponse.BodyHandlers.ofString(),
                            "JWT");
                    long baselineMs = (System.nanoTime() - t0) / 1_000_000;

                    // Skip paths that accept any token (no auth required)
                    if (baseResp.statusCode() == 200) {
                        continue;
                    }

                    // Probe: send token with x5u canary
                    HttpRequest probeReq = HttpRequest.newBuilder().uri(URI.create(base + path))
                            .header("Authorization", "Bearer " + forgedToken).timeout(Duration.ofSeconds(8)).GET()
                            .build();
                    long t1 = System.nanoTime();
                    HttpResponse<String> probeResp = Http.send(ctx, hc, probeReq, HttpResponse.BodyHandlers.ofString(),
                            "JWT");
                    long probeMs = (System.nanoTime() - t1) / 1_000_000;

                    log.accept("[~] JWT: x5u " + path + " -> baseline HTTP " + baseResp.statusCode() + " (" + baselineMs
                            + "ms), probe HTTP " + probeResp.statusCode() + " (" + probeMs + "ms)");

                    // Detection heuristics:
                    // 1. HTTP 200 -- server accepted the forged token
                    // 2. 5xx vs baseline 4xx -- server tried to fetch x5u and failed
                    // 3. Timing anomaly (>3s delta) -- server attempted connection
                    // 4. Connection error keywords in body -- server reports fetch failure
                    boolean accepted = probeResp.statusCode() == 200;
                    boolean serverError = probeResp.statusCode() >= 500 && baseResp.statusCode() < 500;
                    boolean timingAnomaly = probeMs > baselineMs + 3000;
                    String probeBody = probeResp.body() != null ? probeResp.body() : "";
                    boolean connectionError = probeBody.contains("Connection refused")
                            || probeBody.contains("connect timed out") || probeBody.contains("ECONNREFUSED")
                            || probeBody.contains("connection_refused");

                    if (accepted || serverError || timingAnomaly || connectionError) {
                        Severity sev = accepted ? Severity.CRITICAL : Severity.HIGH;
                        String detail = buildDetail(accepted, serverError, timingAnomaly, probeResp.statusCode(),
                                baseResp.statusCode(), probeMs, baselineMs);
                        String cweId = CweRegistry.cweId("JWT");
                        String cweTitle = CweRegistry.cweTitle("JWT");
                        String cvssVector = CweRegistry.cvssVector("JWT");
                        double score = CvssCalculator.calculate(cvssVector);
                        return Optional.of(Finding.of("JWT", base + path, "x5u remote certificate fetch detected", sev,
                                "Probe em " + base + path + " -- " + detail + " | x5u=" + CANARY_X5U,
                                "Servidor busca certificado de URL controlada pelo atacante"
                                        + " via x5u -- permite self-sign de tokens com chave" + " propria",
                                "# 1. Gerar chave + cert:\nopenssl req -x509 -nodes"
                                        + " -newkey rsa:2048 -keyout key.pem -out cert.pem" + " -subj '/CN=attacker'\n"
                                        + "# 2. Servir certificado:\n" + "python3 -m http.server 8443\n"
                                        + "# 3. Forjar token com x5u:\n" + "python3 jwt_tool.py <token> -X x5u"
                                        + " -xu https://attacker.com/cert.pem -pk key.pem",
                                "Ignorar o campo x5u do header; nunca buscar certificados"
                                        + " de URLs controladas pelo token; usar apenas" + " trust store local",
                                cweId, cweTitle, cvssVector, score));
                    }
                } catch (Exception ex) {
                    log.accept("[~] JWT: x5u " + path + " -- " + ex.getMessage());
                }
            }
        } catch (Exception e) {
            log.accept("[~] JWT: x5u -- " + e.getMessage());
        }
        return Optional.empty();
    }

    private static String buildDetail(boolean accepted, boolean serverError, boolean timingAnomaly, int probeStatus,
            int baselineStatus, long probeMs, long baselineMs) {
        if (accepted) {
            return "Servidor aceitou token com x5u attacker-controlled -> HTTP 200";
        }
        if (serverError) {
            return "Servidor retornou " + probeStatus + " (vs baseline " + baselineStatus
                    + ") -- indica tentativa de fetch do x5u";
        }
        if (timingAnomaly) {
            return "Probe levou " + probeMs + "ms (baseline " + baselineMs + "ms) -- delay indica fetch do x5u";
        }
        return "Response contem indicacao de connection error ao tentar fetch x5u";
    }

    private static String padB64(String s) {
        int mod = s.length() % 4;
        return mod == 0 ? s : s + "=".repeat(4 - mod);
    }
}
