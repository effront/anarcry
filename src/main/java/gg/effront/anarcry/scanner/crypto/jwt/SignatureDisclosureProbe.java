package gg.effront.anarcry.scanner.crypto.jwt;

import gg.effront.anarcry.model.Finding;
import gg.effront.anarcry.model.Severity;
import gg.effront.anarcry.scanner.ScanContext;
import gg.effront.anarcry.scanner.util.Http;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Base64;
import java.util.List;
import java.util.Optional;
import java.util.function.Consumer;
import java.util.regex.Pattern;
import gg.effront.anarcry.model.CweRegistry;
import gg.effront.anarcry.model.CvssCalculator;

public class SignatureDisclosureProbe {

    // Matches: "Expected <sig> got <sig>" -- pattern from CVE-2019-7644 / auth0
    // jwt-dotnet
    private static final Pattern DISCLOSURE = Pattern
            .compile("(?i)expected\\s+[A-Za-z0-9+/=_-]+\\s+got\\s+[A-Za-z0-9+/=_-]+");

    private static final List<String> AUTH_PATHS = List.of("/api/me", "/api/user", "/api/profile");

    public Optional<Finding> probe(String[] parts, ScanContext ctx, String base, HttpClient hc, Consumer<String> log) {
        if (parts.length < 3 || parts[2].isBlank()) {
            return Optional.empty();
        }
        try {
            byte[] sigBytes = Base64.getUrlDecoder().decode(padB64(parts[2]));
            if (sigBytes.length == 0) {
                return Optional.empty();
            }
            sigBytes[sigBytes.length - 1] ^= (byte) 0xFF; // flip last byte → wrong but deterministic
            String badSig = Base64.getUrlEncoder().withoutPadding().encodeToString(sigBytes);
            String badToken = parts[0] + "." + parts[1] + "." + badSig;

            log.accept("[~] JWT: probe signature disclosure (CVE-2019-7644) → " + base);
            for (String path : AUTH_PATHS) {
                try {
                    HttpRequest req = HttpRequest.newBuilder().uri(URI.create(base + path))
                            .header("Authorization", "Bearer " + badToken).timeout(Duration.ofSeconds(5)).GET().build();
                    HttpResponse<String> resp = Http.send(ctx, hc, req, HttpResponse.BodyHandlers.ofString(), "JWT");
                    log.accept("[~] JWT: sig disclosure " + path + " → HTTP " + resp.statusCode());
                    String body = resp.body();
                    if (body != null && DISCLOSURE.matcher(body).find()) {
                        String _cweId = CweRegistry.cweId("JWT");
                        String _cweTitle = CweRegistry.cweTitle("JWT");
                        String _cvssVector = CweRegistry.cvssVector("JWT");
                        double _score = CvssCalculator.calculate(_cvssVector);
                        return Optional.of(Finding.of("JWT", base + path,
                                "Signature correta exposta em mensagem de erro (CVE-2019-7644)", Severity.MEDIUM,
                                "Response body em " + base + path + ": " + truncate(body, 300),
                                "Servidor revela a assinatura válida em respostas de erro -- facilita forgery de tokens"
                                        + "sem brute-force",
                                "curl -H 'Authorization: Bearer " + badToken + "' " + base + path,
                                "Nunca incluir detalhes de signature em erros; usar mensagens genéricas"
                                        + " como '401 Unauthorized'",
                                _cweId, _cweTitle, _cvssVector, _score));
                    }
                } catch (Exception e) {
                    log.accept("[~] JWT: sig disclosure " + path + " -- " + e.getMessage());
                }
            }
        } catch (Exception e) {
            log.accept("[~] JWT: sig disclosure -- " + e.getMessage());
        }
        return Optional.empty();
    }

    private static String padB64(String s) {
        int mod = s.length() % 4;
        return mod == 0 ? s : s + "=".repeat(4 - mod);
    }

    private static String truncate(String s, int max) {
        return s.length() <= max ? s : s.substring(0, max) + "...";
    }
}
