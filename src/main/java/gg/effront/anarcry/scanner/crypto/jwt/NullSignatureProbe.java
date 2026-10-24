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
import java.util.List;
import java.util.Optional;
import java.util.function.Consumer;
import gg.effront.anarcry.model.CweRegistry;
import gg.effront.anarcry.model.CvssCalculator;

public class NullSignatureProbe {

    private static final List<String> AUTH_PATHS = List.of("/api/me", "/api/user", "/api/profile");

    public Optional<Finding> probe(String[] parts, ScanContext ctx, String base, HttpClient hc, Consumer<String> log) {
        String nullToken = parts[0] + "." + parts[1] + ".";
        log.accept("[~] JWT: probe null signature (CVE-2020-28042) → " + base);
        for (String path : AUTH_PATHS) {
            try {
                HttpRequest req = HttpRequest.newBuilder()
                        .uri(URI.create(base + path))
                        .header("Authorization", "Bearer " + nullToken)
                        .timeout(Duration.ofSeconds(5))
                        .GET().build();
                HttpResponse<Void> resp = Http.send(ctx, hc, req, HttpResponse.BodyHandlers.discarding(), "JWT");
                log.accept("[~] JWT: null sig " + path + " → HTTP " + resp.statusCode());
                if (resp.statusCode() == 200) {
                    String _cweId = CweRegistry.cweId("JWT");
                    String _cweTitle = CweRegistry.cweTitle("JWT");
                    String _cvssVector = CweRegistry.cvssVector("JWT");
                    double _score = CvssCalculator.calculate(_cvssVector);
                    return Optional.of(Finding.of("JWT", base + path,
                            "Null signature aceita ativamente (CVE-2020-28042)", Severity.CRITICAL,
                            "Probe em " + base + path + " → HTTP 200 com signature vazia",
                            "Servidor aceita tokens sem assinatura — o payload pode ser forjado livremente mantendo o algoritmo original",
                            "curl -H 'Authorization: Bearer " + nullToken + "' " + base + path,
                            "Rejeitar tokens cuja signature esteja ausente ou vazia; validar presença de signature para todos os algoritmos",
                            _cweId, _cweTitle, _cvssVector, _score));
                }
            } catch (Exception e) {
                log.accept("[~] JWT: null sig " + path + " — " + e.getMessage());
            }
        }
        return Optional.empty();
    }
}
