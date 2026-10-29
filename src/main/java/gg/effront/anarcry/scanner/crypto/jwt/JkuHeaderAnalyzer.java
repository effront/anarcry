package gg.effront.anarcry.scanner.crypto.jwt;

import com.google.gson.JsonObject;
import gg.effront.anarcry.model.Finding;
import gg.effront.anarcry.model.Severity;
import gg.effront.anarcry.model.CweRegistry;
import gg.effront.anarcry.model.CvssCalculator;

import java.util.Optional;

public class JkuHeaderAnalyzer {

    public Optional<Finding> analyze(JsonObject header, String evidence) {
        if (!header.has("jku")) {
            return Optional.empty();
        }

        String jku = header.get("jku").getAsString();
        boolean insecure = jku.startsWith("http://") || jku.contains("localhost") || jku.contains("127.0.0.1");

        Severity sev = insecure ? Severity.HIGH : Severity.MEDIUM;
        String detail = insecure
                ? "jku aponta para URL insegura (" + jku + ") -- facilita JWKS hijacking local"
                : "jku presente (" + jku
                        + ") -- servidor busca JWKS remotamente; atacante pode hospedar chave maliciosa";

        String vec = insecure ? "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" : "AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N";
        double score = CvssCalculator.calculate(vec);
        return Optional.of(Finding.of("JWT", "(token)", "jku header presente -- risco de JWKS hijacking", sev,
                "jku=" + jku + " | " + evidence, detail,
                "Hospedar JWKS em URL controlada pelo atacante com par de chaves RSA gerado localmente:\n"
                        + "python3 jwt_tool.py <token> -X s -ju https://evil.com/jwks.json",
                "Ignorar o campo jku do header; validar apenas com chave pré-configurada no servidor",
                CweRegistry.cweId("JWT"), CweRegistry.cweTitle("JWT"), vec, score));
    }
}
