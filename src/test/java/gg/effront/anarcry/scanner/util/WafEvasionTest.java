package gg.effront.anarcry.scanner.util;

import static org.junit.jupiter.api.Assertions.*;

import gg.effront.anarcry.scanner.ScanContext;
import java.net.http.HttpRequest;
import java.nio.charset.Charset;
import java.util.List;
import java.util.Map;
import java.net.URLEncoder;
import java.util.Set;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;

/**
 * Unit tests for WafEvasion strategy implementations -- no network required.
 */
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class WafEvasionTest {

    // -------------------------------------------------
    // DOUBLE_ENCODE
    // -------------------------------------------------

    @Test
    @Order(1)
    void doubleEncodeTransforms() {
        String result = WafEvasion.doubleEncode("<script>");
        // doubleEncode returns single-encoded; caller's URLEncoder.encode completes the
        // double
        assertTrue(result.contains("%3C"), "< deve virar %3C (single-encoded), got: " + result);
        assertTrue(result.contains("%3E"), "> deve virar %3E (single-encoded), got: " + result);
        assertFalse(result.contains("<"), "Nao deve conter < literal");
        assertFalse(result.contains(">"), "Nao deve conter > literal");
    }

    @Test
    @Order(2)
    void doubleEncodePreservesPlain() {
        String input = "hello123";
        String result = WafEvasion.doubleEncode(input);
        // Alphanumeric characters should mostly pass through unchanged
        assertTrue(result.contains("hello") || result.contains("h"),
                "Alfanumericos devem ser preservados ou minimamente alterados");
        // Should not introduce random garbage
        assertFalse(result.isEmpty(), "Resultado nao deve ser vazio");
    }

    // -------------------------------------------------
    // CASE_MUTATION
    // -------------------------------------------------

    @Test
    @Order(3)
    void mutateCaseAlternates() {
        String input = "SELECT";
        String result = WafEvasion.mutateCase(input);
        // The result should not be the same as the input (all uppercase)
        assertNotEquals(input, result, "mutateCase nao deve retornar a mesma string");
        // Should still be the same word ignoring case
        assertEquals(input.toLowerCase(), result.toLowerCase(),
                "mutateCase deve preservar os caracteres, apenas alternar case");
    }

    @Test
    @Order(4)
    void mutateCasePreservesNonAlpha() {
        String input = "12345!@#";
        String result = WafEvasion.mutateCase(input);
        assertEquals(input, result, "Numeros e simbolos devem permanecer inalterados");
    }

    // -------------------------------------------------
    // UNICODE_NORMALIZE (fullwidth)
    // -------------------------------------------------

    @Test
    @Order(5)
    void toFullwidthConverts() {
        String result = WafEvasion.toFullwidth("<");
        // ASCII '<' (0x3C) should become fullwidth U+FF1C
        assertEquals("＜", result, "< (0x3C) deve virar fullwidth U+FF1C");
    }

    @Test
    @Order(6)
    void toFullwidthPreservesNonAscii() {
        // Space (0x20) is at the boundary -- typically not converted by fullwidth
        // transform
        // since fullwidth range starts at '!' (0x21)
        String input = " ";
        String result = WafEvasion.toFullwidth(input);
        assertEquals(" ", result, "Espaco nao deve ser convertido para fullwidth");
    }

    // -------------------------------------------------
    // EBCDIC
    // -------------------------------------------------

    @Test
    @Order(7)
    void encodeEbcdicProducesBytes() throws Exception {
        byte[] result = WafEvasion.encodeEbcdic("test");
        assertNotNull(result, "Resultado nao deve ser null");
        assertTrue(result.length > 0, "Resultado nao deve ser vazio");
        // EBCDIC encoding of "test" should differ from UTF-8 encoding
        byte[] utf8 = "test".getBytes(Charset.forName("UTF-8"));
        boolean different = false;
        for (int i = 0; i < Math.min(result.length, utf8.length); i++) {
            if (result[i] != utf8[i]) {
                different = true;
                break;
            }
        }
        assertTrue(different, "EBCDIC bytes devem diferir de UTF-8 bytes");
    }

    // -------------------------------------------------
    // doubleEncode + caller URLEncode = wire double-encoding
    // -------------------------------------------------

    @Test
    @Order(3)
    void doubleEncodeWireFormIsCorrect() {
        String payload = "<script>";
        String transformed = WafEvasion.doubleEncode(payload);
        String wireForm = URLEncoder.encode(transformed, java.nio.charset.StandardCharsets.UTF_8);
        // Wire form must be double-encoded: %253C = %25 (encoded %) + 3C
        assertTrue(wireForm.contains("%253C"), "Wire form deve ser double-encoded (%253C), got: " + wireForm);
        assertTrue(wireForm.contains("%253E"), "Wire form deve ser double-encoded (%253E), got: " + wireForm);
    }

    // -------------------------------------------------
    // applyGetStrategy routing
    // -------------------------------------------------

    @Test
    @Order(8)
    void applyGetStrategyRoutes() {
        String payload = "<script>alert(1)</script>";

        // DOUBLE_ENCODE routes to doubleEncode
        String de = WafEvasion.applyGetStrategy(WafEvasion.Strategy.DOUBLE_ENCODE, payload);
        assertEquals(WafEvasion.doubleEncode(payload), de, "DOUBLE_ENCODE deve rotear para doubleEncode()");

        // CASE_MUTATION routes to mutateCase
        String cm = WafEvasion.applyGetStrategy(WafEvasion.Strategy.CASE_MUTATION, payload);
        assertEquals(WafEvasion.mutateCase(payload), cm, "CASE_MUTATION deve rotear para mutateCase()");

        // UNICODE_NORMALIZE routes to toFullwidth
        String un = WafEvasion.applyGetStrategy(WafEvasion.Strategy.UNICODE_NORMALIZE, payload);
        assertEquals(WafEvasion.toFullwidth(payload), un, "UNICODE_NORMALIZE deve rotear para toFullwidth()");

        // CHARSET_EBCDIC is not GET-compatible -- returns payload unchanged
        String eb = WafEvasion.applyGetStrategy(WafEvasion.Strategy.CHARSET_EBCDIC, payload);
        assertEquals(payload, eb, "CHARSET_EBCDIC nao e compativel com GET, deve retornar payload inalterado");
    }

    // -------------------------------------------------
    // isWafBlocked detection
    // -------------------------------------------------

    @Test
    @Order(9)
    void isWafBlockedDetectsCf() {
        assertTrue(WafEvasion.isWafBlocked(403, "cloudflare", ""),
                "403 + cloudflare server header deve ser detectado como WAF block");
    }

    @Test
    @Order(10)
    void isWafBlockedDetectsAkamai() {
        assertTrue(WafEvasion.isWafBlocked(403, "AkamaiGHost", ""),
                "403 + akamai server header deve ser detectado como WAF block");
    }

    @Test
    @Order(11)
    void isWafBlockedFalseOn200() {
        assertFalse(WafEvasion.isWafBlocked(200, "cloudflare", ""),
                "200 nao deve ser detectado como WAF block independente do header");
        assertFalse(WafEvasion.isWafBlocked(200, "AkamaiGHost", ""),
                "200 nao deve ser detectado como WAF block independente do header");
    }

    @Test
    @Order(12)
    void isWafBlockedDetectsBodySignature() {
        assertTrue(WafEvasion.isWafBlocked(403, null, "Access Denied"),
                "403 + null server + body 'Access Denied' deve ser detectado como WAF block");
    }

    // -------------------------------------------------
    // detectWafProduct
    // -------------------------------------------------

    @Test
    @Order(13)
    void detectWafProductExtractsName() {
        String product = WafEvasion.detectWafProduct("cloudflare");
        assertNotNull(product, "Produto nao deve ser null");
        assertTrue(product.toLowerCase().contains("cloudflare"),
                "Deve extrair 'cloudflare' do header, got: " + product);
    }

    @Test
    @Order(14)
    void detectWafProductEmptyOnUnknown() {
        String product = WafEvasion.detectWafProduct("nginx");
        assertNotNull(product, "Produto nao deve ser null");
        assertEquals("", product, "nginx nao e um WAF conhecido, deve retornar vazio");
    }

    // -------------------------------------------------
    // buildEbcdicPost
    // -------------------------------------------------

    @Test
    @Order(15)
    void buildEbcdicPostSetsCharsetHeader() {
        HttpRequest req = WafEvasion.buildEbcdicPost("https://example.com/test", "q", "payload");
        String contentType = req.headers().firstValue("Content-Type").orElse("");
        assertTrue(contentType.toLowerCase().contains("charset=ibm500"),
                "Content-Type deve conter charset=ibm500, got: " + contentType);
    }

    // -------------------------------------------------
    // buildHppUrl
    // -------------------------------------------------

    @Test
    @Order(16)
    void buildHppUrlDuplicatesParam() {
        String url = WafEvasion.buildHppUrl("https://example.com/search", "q", "<script>");
        // Must contain the param duplicated: param=safe&param=<encoded>
        long paramCount = url.chars().filter(ch -> ch == '?').count() + url.chars().filter(ch -> ch == '&').count();
        assertTrue(url.contains("q="), "URL deve conter o parametro q");
        // Count occurrences of "q="
        int first = url.indexOf("q=");
        int second = url.indexOf("q=", first + 1);
        assertTrue(second > first, "URL deve conter 'q=' duplicado (HPP), got: " + url);
    }

    // -------------------------------------------------
    // evasionPayload -- passthrough when no WAF
    // -------------------------------------------------

    @Test
    @Order(17)
    void evasionPayloadPassthroughWhenNoWaf() {
        ScanContext ctx = new ScanContext("https://example.com", "", Set.of());
        // wafState default: no WAF detected
        assertFalse(ctx.wafState().isWafDetected(), "WafState padrao nao deve ter WAF detectado");
        String payload = "<script>alert(1)</script>";
        String result = WafEvasion.evasionPayload(ctx, payload);
        assertEquals(payload, result, "Sem WAF detectado, payload deve passar inalterado");
    }

    // -------------------------------------------------
    // evasionPayload -- transforms when WAF detected
    // -------------------------------------------------

    @Test
    @Order(18)
    void evasionPayloadTransformsWhenWafDetected() {
        ScanContext ctx = new ScanContext("https://example.com", "", Set.of());
        ctx.wafState().markWafDetected("cloudflare");
        ctx.wafState().markEffectiveStrategy(WafEvasion.Strategy.DOUBLE_ENCODE);

        assertTrue(ctx.wafState().isWafDetected(), "WAF deve estar marcado como detectado");
        assertEquals("cloudflare", ctx.wafState().wafProduct(), "Produto WAF deve ser cloudflare");

        String payload = "<script>alert(1)</script>";
        String result = WafEvasion.evasionPayload(ctx, payload);
        assertNotEquals(payload, result, "Com WAF + strategy definida, payload deve ser transformado");
        // DOUBLE_ENCODE returns single-encoded form; caller's URLEncode completes
        // double
        assertTrue(result.contains("%3C"), "DOUBLE_ENCODE deve produzir %3C (single-encoded), got: " + result);
    }

    // -------------------------------------------------
    // isJsChallenge -- header-based detection
    // -------------------------------------------------

    @Test
    @Order(19)
    void isJsChallengeVercelHeader403() {
        Map<String, List<String>> headers = Map.of("x-vercel-mitigated", List.of("challenge"));
        assertTrue(WafEvasion.isJsChallenge(403, headers, ""),
                "403 + x-vercel-mitigated: challenge deve ser JS challenge");
    }

    @Test
    @Order(20)
    void isJsChallengeCloudflareHeader503() {
        Map<String, List<String>> headers = Map.of("cf-mitigated", List.of("challenge"));
        assertTrue(WafEvasion.isJsChallenge(503, headers, ""), "503 + cf-mitigated: challenge deve ser JS challenge");
    }

    @Test
    @Order(21)
    void isJsChallengeFalseOn200EvenWithHeader() {
        Map<String, List<String>> headers = Map.of("x-vercel-mitigated", List.of("challenge"));
        assertFalse(WafEvasion.isJsChallenge(200, headers, ""),
                "200 nao deve ser JS challenge mesmo com header de challenge");
    }

    @Test
    @Order(22)
    void isJsChallengeFalseOn200EvenWithBody() {
        assertFalse(WafEvasion.isJsChallenge(200, Map.of(), "Vercel Security Checkpoint"),
                "200 com body match nao deve ser JS challenge (status code guard)");
    }

    // -------------------------------------------------
    // isJsChallenge -- body-based detection
    // -------------------------------------------------

    @Test
    @Order(23)
    void isJsChallengeVercelBody403() {
        assertTrue(WafEvasion.isJsChallenge(403, Map.of(), "Vercel Security Checkpoint"),
                "403 + body 'Vercel Security Checkpoint' deve ser JS challenge");
    }

    @Test
    @Order(24)
    void isJsChallengeCloudflareBodyCfChlOpt503() {
        assertTrue(WafEvasion.isJsChallenge(503, Map.of(), "<div id=\"cf_chl_opt\">test</div>"),
                "503 + body com cf_chl_opt deve ser JS challenge");
    }

    @Test
    @Order(25)
    void isJsChallengeCloudflareBodyCfChallengeDash503() {
        assertTrue(WafEvasion.isJsChallenge(503, Map.of(), "<div class=\"cf-challenge-running\">"),
                "503 + body com cf-challenge- deve ser JS challenge");
    }

    // -------------------------------------------------
    // isJsChallenge -- negative / edge cases
    // -------------------------------------------------

    @Test
    @Order(26)
    void isJsChallengeFalse403NoSignals() {
        assertFalse(WafEvasion.isJsChallenge(403, Map.of(), "Access Denied"),
                "403 sem sinais de JS challenge nao deve ser detectado");
    }

    @Test
    @Order(27)
    void isJsChallengeNullBodyWithHeader() {
        Map<String, List<String>> headers = Map.of("x-vercel-mitigated", List.of("challenge"));
        assertTrue(WafEvasion.isJsChallenge(403, headers, null),
                "403 + vercel header + null body deve ser JS challenge");
    }

    @Test
    @Order(28)
    void isJsChallengeNullBodyNoHeader() {
        assertFalse(WafEvasion.isJsChallenge(403, Map.of(), null),
                "403 + no header + null body nao deve ser JS challenge");
    }

    @Test
    @Order(29)
    void isJsChallengeHeaderValueNotChallenge() {
        Map<String, List<String>> headers = Map.of("x-vercel-mitigated", List.of("blocked"));
        assertFalse(WafEvasion.isJsChallenge(403, headers, ""),
                "x-vercel-mitigated: blocked (nao 'challenge') nao deve ser JS challenge");
    }

    // -------------------------------------------------
    // detectChallengeType
    // -------------------------------------------------

    @Test
    @Order(30)
    void detectChallengeTypeVercel() {
        Map<String, List<String>> headers = Map.of("x-vercel-mitigated", List.of("challenge"));
        assertEquals("Vercel Security Checkpoint", WafEvasion.detectChallengeType(403, headers, ""),
                "Deve retornar 'Vercel Security Checkpoint'");
    }

    @Test
    @Order(31)
    void detectChallengeTypeCloudflare() {
        Map<String, List<String>> headers = Map.of("cf-mitigated", List.of("challenge"));
        assertEquals("Cloudflare Managed Challenge", WafEvasion.detectChallengeType(503, headers, ""),
                "Deve retornar 'Cloudflare Managed Challenge'");
    }

    @Test
    @Order(32)
    void detectChallengeTypeEmptyOn200() {
        Map<String, List<String>> headers = Map.of("x-vercel-mitigated", List.of("challenge"));
        assertEquals("", WafEvasion.detectChallengeType(200, headers, "Vercel Security Checkpoint"),
                "200 deve retornar vazio mesmo com sinais de challenge");
    }

    @Test
    @Order(33)
    void detectChallengeTypeEmptyNoSignals() {
        assertEquals("", WafEvasion.detectChallengeType(403, Map.of(), "some body"),
                "403 sem sinais deve retornar vazio");
    }

    @Test
    @Order(34)
    void detectChallengeTypePrioritizesVercel() {
        Map<String, List<String>> headers = Map.of("x-vercel-mitigated", List.of("challenge"), "cf-mitigated",
                List.of("challenge"));
        assertEquals("Vercel Security Checkpoint", WafEvasion.detectChallengeType(403, headers, ""),
                "Com ambos headers, Vercel deve ter prioridade");
    }

    @Test
    @Order(35)
    void detectChallengeTypeByBodyOnly() {
        assertEquals("Cloudflare Managed Challenge",
                WafEvasion.detectChallengeType(503, Map.of(), "cf_chl_opt content"),
                "Body-only Cloudflare detection deve funcionar em 503");
    }

    // -------------------------------------------------
    // isJsChallenge <-> detectChallengeType consistency
    // -------------------------------------------------

    @Test
    @Order(36)
    void isJsChallengeConsistentWithDetectType() {
        Map<String, List<String>> vercelHeaders = Map.of("x-vercel-mitigated", List.of("challenge"));
        Map<String, List<String>> cfHeaders = Map.of("cf-mitigated", List.of("challenge"));

        // Every case where detectChallengeType returns non-empty, isJsChallenge must
        // return true
        assertTrue(WafEvasion.isJsChallenge(403, vercelHeaders, ""));
        assertFalse(WafEvasion.detectChallengeType(403, vercelHeaders, "").isEmpty());

        assertTrue(WafEvasion.isJsChallenge(503, cfHeaders, ""));
        assertFalse(WafEvasion.detectChallengeType(503, cfHeaders, "").isEmpty());

        // Every case where isJsChallenge returns false, detectChallengeType must return
        // empty
        assertFalse(WafEvasion.isJsChallenge(200, vercelHeaders, ""));
        assertTrue(WafEvasion.detectChallengeType(200, vercelHeaders, "").isEmpty());
    }
}
