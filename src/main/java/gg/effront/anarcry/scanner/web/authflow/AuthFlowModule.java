package gg.effront.anarcry.scanner.web.authflow;

import gg.effront.anarcry.model.CvssCalculator;
import gg.effront.anarcry.model.Finding;
import gg.effront.anarcry.model.Severity;
import gg.effront.anarcry.scanner.ScanContext;
import gg.effront.anarcry.scanner.Scanner;
import gg.effront.anarcry.scanner.util.CircuitBreakerException;
import gg.effront.anarcry.scanner.util.Http;
import gg.effront.anarcry.scanner.util.HttpClientFactory;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.function.Consumer;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class AuthFlowModule implements Scanner {

    private static final String CWE_ID = "CWE-287";
    private static final String CWE_TITLE = "Improper Authentication";

    private static final String VECTOR_SESSION_FIX = "AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N";
    private static final double SCORE_SESSION_FIX = CvssCalculator.calculate(VECTOR_SESSION_FIX);

    private static final String VECTOR_ENUM = "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N";
    private static final double SCORE_ENUM = CvssCalculator.calculate(VECTOR_ENUM);

    private static final String VECTOR_RESET = "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N";
    private static final double SCORE_RESET = CvssCalculator.calculate(VECTOR_RESET);

    private static final String VECTOR_LOCKOUT = "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N";
    private static final double SCORE_LOCKOUT = CvssCalculator.calculate(VECTOR_LOCKOUT);

    private static final List<String> LOGIN_PATHS = List.of("/login", "/auth/login", "/api/login", "/api/auth/login",
            "/api/v1/auth/login", "/api/v1/login", "/oauth/token", "/auth/token", "/api/authenticate",
            "/api/auth/signin", "/api/sessions", "/api/v1/sessions");

    private static final List<String> RESET_PATHS = List.of("/password-reset", "/forgot-password",
            "/api/password-reset", "/api/forgot-password", "/api/auth/forgot-password", "/api/v1/auth/forgot-password",
            "/api/auth/reset-password", "/api/v1/password/reset");

    private static final String LOGIN_BODY_VALID = "{\"email\":\"test@example.com\",\"password\":\"TestPass123!\"}";
    private static final String LOGIN_BODY_INVALID = "{\"email\":\"nonexistent@example.com\",\"password\":\"WrongPass!\"}";
    private static final String LOGIN_BODY_VALID_USER = "{\"email\":\"test@example.com\",\"password\":\"WrongPass!\"}";

    private static final Pattern SESSION_COOKIE = Pattern.compile(
            "(?:JSESSIONID|PHPSESSID|session|sess_id|connect\\.sid|_session)=([^;]+)", Pattern.CASE_INSENSITIVE);
    private static final Pattern TOKEN_PATTERN = Pattern
            .compile("\"(?:token|access_token|jwt|session_token|sid)\"\\s*:\\s*\"([^\"]+)\"");
    private static final Pattern RESET_TOKEN = Pattern
            .compile("\"(?:token|reset_token|resetToken|code)\"\\s*:\\s*\"([^\"]+)\"");

    @Override
    public String id() {
        return "AuthFlow";
    }

    @Override
    public List<Finding> scan(ScanContext ctx, Consumer<String> log) throws Exception {
        List<Finding> findings = new ArrayList<>();
        HttpClient hc = HttpClientFactory.noRedirect();

        String scheme = ctx.isHttps() ? "https" : "http";
        int defPort = ctx.isHttps() ? 443 : 80;
        String base = scheme + "://" + ctx.host() + (ctx.port() != defPort ? ":" + ctx.port() : "");

        log.accept("[~] AuthFlow: analisando fluxos de autenticacao em " + base);

        // Phase 1: Discover login endpoints
        List<String> activeLoginPaths = discoverLoginEndpoints(ctx, hc, base, log);
        if (activeLoginPaths.isEmpty()) {
            log.accept("[~] AuthFlow: nenhum endpoint de login ativo encontrado");
        } else {
            log.accept("[~] AuthFlow: " + activeLoginPaths.size() + " endpoint(s) de login detectado(s)");
        }

        // Phase 2: Account enumeration via timing/response differences
        for (String loginPath : activeLoginPaths) {
            findings.addAll(probeAccountEnumeration(ctx, hc, base, loginPath, log));
        }

        // Phase 3: Session fixation check
        for (String loginPath : activeLoginPaths) {
            findings.addAll(probeSessionFixation(ctx, hc, base, loginPath, log));
        }

        // Phase 4: Account lockout detection
        for (String loginPath : activeLoginPaths) {
            findings.addAll(probeAccountLockout(ctx, hc, base, loginPath, log));
        }

        // Phase 5: Password reset flow analysis
        findings.addAll(probePasswordReset(ctx, hc, base, log));

        if (findings.isEmpty()) {
            log.accept("[+] AuthFlow: nenhuma fraqueza de autenticacao detectada");
        }
        return findings;
    }

    private List<String> discoverLoginEndpoints(ScanContext ctx, HttpClient hc, String base, Consumer<String> log) {
        List<String> active = new ArrayList<>();
        for (String path : LOGIN_PATHS) {
            try {
                // Send empty JSON POST to see if endpoint responds
                HttpRequest req = HttpRequest.newBuilder().uri(URI.create(base + path)).timeout(Duration.ofSeconds(6))
                        .header("Content-Type", "application/json").POST(HttpRequest.BodyPublishers.ofString("{}"))
                        .build();
                HttpResponse<String> resp = Http.send(ctx, hc, req, HttpResponse.BodyHandlers.ofString(), id());

                int status = resp.statusCode();
                String body = resp.body() != null ? resp.body() : "";
                // Login endpoints typically return 400/401/422 for invalid input, not 404
                if (status != 404 && status != 405 && status != 301 && status != 302 && !isHtml(body)) {
                    active.add(path);
                    log.accept("[~] AuthFlow: login endpoint detectado: " + path + " (HTTP " + status + ")");
                }
            } catch (CircuitBreakerException cbe) {
                throw cbe;
            } catch (Exception ignored) {
            }
        }
        return active;
    }

    private List<Finding> probeAccountEnumeration(ScanContext ctx, HttpClient hc, String base, String loginPath,
            Consumer<String> log) {
        List<Finding> findings = new ArrayList<>();
        log.accept("[~] AuthFlow: testando account enumeration em " + loginPath);

        try {
            // Send request with likely non-existent user
            long t0 = System.currentTimeMillis();
            HttpRequest invalidReq = HttpRequest.newBuilder().uri(URI.create(base + loginPath))
                    .timeout(Duration.ofSeconds(10)).header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(LOGIN_BODY_INVALID)).build();
            HttpResponse<String> invalidResp = Http.send(ctx, hc, invalidReq, HttpResponse.BodyHandlers.ofString(),
                    id());
            long invalidTime = System.currentTimeMillis() - t0;
            String invalidBody = invalidResp.body() != null ? invalidResp.body() : "";

            // Send request with likely valid user but wrong password
            long t1 = System.currentTimeMillis();
            HttpRequest validUserReq = HttpRequest.newBuilder().uri(URI.create(base + loginPath))
                    .timeout(Duration.ofSeconds(10)).header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(LOGIN_BODY_VALID_USER)).build();
            HttpResponse<String> validUserResp = Http.send(ctx, hc, validUserReq, HttpResponse.BodyHandlers.ofString(),
                    id());
            long validUserTime = System.currentTimeMillis() - t1;
            String validUserBody = validUserResp.body() != null ? validUserResp.body() : "";

            // Check response body differences (different error messages)
            boolean bodyDifference = !invalidBody.equals(validUserBody)
                    && invalidResp.statusCode() == validUserResp.statusCode() && !invalidBody.isBlank()
                    && !validUserBody.isBlank();

            // Check status code difference
            boolean statusDifference = invalidResp.statusCode() != validUserResp.statusCode();

            // Check timing difference (> 500ms delta suggests user lookup before password
            // check)
            long timeDelta = Math.abs(validUserTime - invalidTime);
            boolean timingDifference = timeDelta > 500;

            if (bodyDifference || statusDifference) {
                String evidence;
                if (statusDifference) {
                    evidence = "POST " + base + loginPath + " | Usuario invalido -> HTTP " + invalidResp.statusCode()
                            + " | Usuario valido+senha errada -> HTTP " + validUserResp.statusCode()
                            + " | Status codes diferentes revelam existencia do usuario";
                } else {
                    evidence = "POST " + base + loginPath + " | Usuario invalido body: "
                            + invalidBody.substring(0, Math.min(100, invalidBody.length())) + " | Usuario valido body: "
                            + validUserBody.substring(0, Math.min(100, validUserBody.length()))
                            + " | Respostas diferentes revelam existencia do usuario";
                }

                log.accept("[!] AuthFlow: account enumeration detectada em " + loginPath);
                findings.add(Finding.of(id(), loginPath, "Account Enumeration via response difference", Severity.MEDIUM,
                        evidence,
                        "O endpoint de login retorna respostas diferentes para usuarios validos e invalidos, "
                                + "permitindo que atacantes enumerem contas existentes por forca bruta",
                        "curl -X POST -H 'Content-Type: application/json' -d '" + LOGIN_BODY_INVALID + "' '" + base
                                + loginPath + "'\n" + "curl -X POST -H 'Content-Type: application/json' -d '"
                                + LOGIN_BODY_VALID_USER + "' '" + base + loginPath + "'",
                        "Usar mensagens de erro genericas identicas para login invalido (ex: "
                                + "'Credenciais invalidas'). Equalizar tempo de resposta com delay "
                                + "constante. Implementar rate limiting no endpoint de login",
                        CWE_ID, CWE_TITLE, VECTOR_ENUM, SCORE_ENUM));
            } else if (timingDifference) {
                log.accept("[!] AuthFlow: timing-based enumeration detectada em " + loginPath + " (delta: " + timeDelta
                        + "ms)");
                findings.add(Finding.of(id(), loginPath, "Account Enumeration via timing difference", Severity.MEDIUM,
                        "POST " + base + loginPath + " | Usuario invalido: " + invalidTime + "ms | "
                                + "Usuario valido+senha errada: " + validUserTime + "ms | Delta: " + timeDelta + "ms"
                                + " | Timing difference > 500ms sugere lookup de usuario antes da validacao de senha",
                        "O endpoint de login apresenta diferenca de timing significativa entre usuarios "
                                + "existentes e inexistentes, permitindo enumeracao de contas via timing attack",
                        "# Medir timing com 10 requisicoes para cada caso:\n"
                                + "for i in $(seq 1 10); do time curl -s -o /dev/null -X POST "
                                + "-H 'Content-Type: application/json' -d '" + LOGIN_BODY_INVALID + "' '" + base
                                + loginPath + "'; done",
                        "Equalizar tempo de resposta: sempre executar hash de senha mesmo quando "
                                + "usuario nao existe (use hash dummy). Implementar rate limiting. "
                                + "Adicionar delay aleatorio constante em todas as respostas de login",
                        CWE_ID, CWE_TITLE, VECTOR_ENUM, SCORE_ENUM));
            }
        } catch (CircuitBreakerException cbe) {
            throw cbe;
        } catch (Exception e) {
            log.accept("[~] AuthFlow: enumeration probe falhou em " + loginPath + ": " + e.getMessage());
        }

        return findings;
    }

    private List<Finding> probeSessionFixation(ScanContext ctx, HttpClient hc, String base, String loginPath,
            Consumer<String> log) {
        List<Finding> findings = new ArrayList<>();
        log.accept("[~] AuthFlow: testando session fixation em " + loginPath);

        try {
            // Step 1: Request login page (or POST) to get a pre-auth session
            HttpRequest preReq = HttpRequest.newBuilder().uri(URI.create(base + loginPath))
                    .timeout(Duration.ofSeconds(6)).header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString("{}")).build();
            HttpResponse<String> preResp = Http.send(ctx, hc, preReq, HttpResponse.BodyHandlers.ofString(), id());

            String preSession = extractSessionId(preResp);
            if (preSession == null || preSession.isBlank()) {
                return findings;
            }

            // Step 2: POST valid login with the pre-auth session cookie
            HttpRequest loginReq = HttpRequest.newBuilder().uri(URI.create(base + loginPath))
                    .timeout(Duration.ofSeconds(6)).header("Content-Type", "application/json")
                    .header("Cookie", preSession).POST(HttpRequest.BodyPublishers.ofString(LOGIN_BODY_VALID)).build();
            HttpResponse<String> loginResp = Http.send(ctx, hc, loginReq, HttpResponse.BodyHandlers.ofString(), id());

            String postSession = extractSessionId(loginResp);

            // If the session ID did not change after login, session fixation is possible
            if (postSession != null && !postSession.isBlank()) {
                String preValue = extractSessionValue(preSession);
                String postValue = extractSessionValue(postSession);
                if (preValue != null && preValue.equals(postValue)) {
                    log.accept("[!!] AuthFlow: session fixation -- session ID nao muda apos login em " + loginPath);
                    findings.add(Finding.of(id(), loginPath, "Session Fixation -- session ID nao regenera apos login",
                            Severity.HIGH,
                            "POST " + base + loginPath + " | Pre-login session: " + preValue + " | Post-login session: "
                                    + postValue + " | Session ID identico antes e depois da autenticacao",
                            "Session fixation -- se um atacante definir o session ID da vitima antes do login "
                                    + "(via URL, XSS, ou subdomain cookie), o atacante pode reutilizar o mesmo "
                                    + "session ID apos a vitima autenticar, obtendo acesso a sessao autenticada",
                            "# 1. Obter session pre-auth:\ncurl -c - -X POST '" + base + loginPath + "' -d '{}'\n"
                                    + "# 2. Login com esse session:\ncurl -b 'SESSION=<pre-auth-id>' -X POST " + "'"
                                    + base + loginPath + "' -d '" + LOGIN_BODY_VALID + "'\n"
                                    + "# 3. Verificar se session ID mudou no Set-Cookie",
                            "Regenerar session ID apos autenticacao bem-sucedida (session.invalidate() + "
                                    + "novo session). Implementar HttpOnly e Secure flags nos cookies de sessao. "
                                    + "Nunca aceitar session IDs via URL parameters",
                            CWE_ID, CWE_TITLE, VECTOR_SESSION_FIX, SCORE_SESSION_FIX));
                }
            }
        } catch (CircuitBreakerException cbe) {
            throw cbe;
        } catch (Exception e) {
            log.accept("[~] AuthFlow: session fixation probe falhou: " + e.getMessage());
        }

        return findings;
    }

    private List<Finding> probeAccountLockout(ScanContext ctx, HttpClient hc, String base, String loginPath,
            Consumer<String> log) {
        List<Finding> findings = new ArrayList<>();
        log.accept("[~] AuthFlow: testando account lockout em " + loginPath);

        try {
            // Send 5 failed login attempts -- if no lockout/rate limit, it is a weakness
            int attempts = 5;
            Set<Integer> statusCodes = new HashSet<>();
            boolean rateLimited = false;

            for (int i = 0; i < attempts; i++) {
                HttpRequest req = HttpRequest.newBuilder().uri(URI.create(base + loginPath))
                        .timeout(Duration.ofSeconds(6)).header("Content-Type", "application/json")
                        .POST(HttpRequest.BodyPublishers.ofString(LOGIN_BODY_VALID_USER)).build();
                HttpResponse<String> resp = Http.send(ctx, hc, req, HttpResponse.BodyHandlers.ofString(), id());
                statusCodes.add(resp.statusCode());

                if (resp.statusCode() == 429 || resp.statusCode() == 423) {
                    rateLimited = true;
                    log.accept("[~] AuthFlow: rate limiting/lockout detectado apos " + (i + 1) + " tentativas");
                    break;
                }

                String body = resp.body() != null ? resp.body() : "";
                if (body.toLowerCase().contains("locked") || body.toLowerCase().contains("too many")
                        || body.toLowerCase().contains("rate limit") || body.toLowerCase().contains("bloqueado")) {
                    rateLimited = true;
                    log.accept("[~] AuthFlow: lockout message detectada apos " + (i + 1) + " tentativas");
                    break;
                }
            }

            if (!rateLimited) {
                // Check retry-after header as additional signal
                HttpRequest finalReq = HttpRequest.newBuilder().uri(URI.create(base + loginPath))
                        .timeout(Duration.ofSeconds(6)).header("Content-Type", "application/json")
                        .POST(HttpRequest.BodyPublishers.ofString(LOGIN_BODY_VALID_USER)).build();
                HttpResponse<String> finalResp = Http.send(ctx, hc, finalReq, HttpResponse.BodyHandlers.ofString(),
                        id());
                Optional<String> retryAfter = finalResp.headers().firstValue("retry-after");

                if (retryAfter.isEmpty() && finalResp.statusCode() != 429) {
                    log.accept("[!] AuthFlow: sem lockout/rate-limit apos " + (attempts + 1) + " tentativas em "
                            + loginPath);
                    findings.add(Finding.of(id(), loginPath,
                            "No Account Lockout -- brute force possivel em " + loginPath, Severity.MEDIUM,
                            "POST " + base + loginPath + " | " + (attempts + 1)
                                    + " tentativas de login sem lockout ou rate-limiting"
                                    + " | Status codes observados: " + statusCodes,
                            "O endpoint de login nao implementa lockout ou rate-limiting, permitindo "
                                    + "ataques de forca bruta para descobrir senhas de usuarios validos",
                            "# Testar brute force:\nfor i in $(seq 1 20); do curl -s -o /dev/null -w '%{http_code} ' "
                                    + "-X POST -H 'Content-Type: application/json' -d '" + LOGIN_BODY_VALID_USER + "' '"
                                    + base + loginPath + "'; done",
                            "Implementar account lockout apos N tentativas falhas (ex: 5-10). "
                                    + "Adicionar rate limiting por IP e por conta. "
                                    + "Implementar CAPTCHA progressivo apos falhas consecutivas. "
                                    + "Usar exponential backoff no delay de resposta",
                            CWE_ID, CWE_TITLE, VECTOR_LOCKOUT, SCORE_LOCKOUT));
                }
            }
        } catch (CircuitBreakerException cbe) {
            throw cbe;
        } catch (Exception e) {
            log.accept("[~] AuthFlow: lockout probe falhou: " + e.getMessage());
        }

        return findings;
    }

    private List<Finding> probePasswordReset(ScanContext ctx, HttpClient hc, String base, Consumer<String> log) {
        List<Finding> findings = new ArrayList<>();
        log.accept("[~] AuthFlow: testando password reset flow em " + base);

        for (String path : RESET_PATHS) {
            try {
                String resetBody = "{\"email\":\"test@example.com\"}";
                HttpRequest req = HttpRequest.newBuilder().uri(URI.create(base + path)).timeout(Duration.ofSeconds(6))
                        .header("Content-Type", "application/json").POST(HttpRequest.BodyPublishers.ofString(resetBody))
                        .build();
                HttpResponse<String> resp = Http.send(ctx, hc, req, HttpResponse.BodyHandlers.ofString(), id());

                int status = resp.statusCode();
                String body = resp.body() != null ? resp.body() : "";

                if (status == 404 || status == 405 || isHtml(body)) {
                    continue;
                }

                log.accept("[~] AuthFlow: reset endpoint detectado: " + path + " (HTTP " + status + ")");

                // Check if reset token is returned in the response (should be sent via email)
                Matcher tokenMatcher = RESET_TOKEN.matcher(body);
                if (tokenMatcher.find()) {
                    String token = tokenMatcher.group(1);
                    log.accept("[!!] AuthFlow: reset token exposto na resposta em " + path);
                    findings.add(Finding.of(id(), path, "Password Reset Token exposto na resposta HTTP", Severity.HIGH,
                            "POST " + base + path + " | Reset token retornado no body: "
                                    + token.substring(0, Math.min(20, token.length())) + "..."
                                    + " | Token deveria ser enviado por email, nao na resposta HTTP",
                            "O token de reset de senha e retornado diretamente na resposta HTTP "
                                    + "em vez de ser enviado por email. Atacante pode solicitar reset "
                                    + "para qualquer email e obter o token sem acesso ao inbox da vitima",
                            "curl -X POST -H 'Content-Type: application/json' -d '" + resetBody + "' '" + base + path
                                    + "'",
                            "Nunca retornar reset tokens na resposta HTTP. Enviar tokens apenas via "
                                    + "email. Usar tokens criptograficamente aleatorios com expiracao curta. "
                                    + "Implementar rate limiting no endpoint de reset",
                            CWE_ID, CWE_TITLE, VECTOR_RESET, SCORE_RESET));
                }

                // Send two requests quickly and check if tokens are predictable
                HttpResponse<String> resp2 = Http.send(ctx, hc, req, HttpResponse.BodyHandlers.ofString(), id());
                String body2 = resp2.body() != null ? resp2.body() : "";
                Matcher t1 = RESET_TOKEN.matcher(body);
                Matcher t2 = RESET_TOKEN.matcher(body2);
                if (t1.find() && t2.find()) {
                    String tok1 = t1.group(1);
                    String tok2 = t2.group(1);
                    if (tok1.equals(tok2)) {
                        log.accept("[!] AuthFlow: reset tokens identicos em requisicoes consecutivas em " + path);
                    }
                }

                // Found an active reset endpoint -- stop after first one
                break;
            } catch (CircuitBreakerException cbe) {
                throw cbe;
            } catch (Exception ignored) {
            }
        }

        return findings;
    }

    private static String extractSessionId(HttpResponse<String> resp) {
        List<String> cookies = resp.headers().allValues("set-cookie");
        for (String cookie : cookies) {
            Matcher m = SESSION_COOKIE.matcher(cookie);
            if (m.find()) {
                return m.group(0);
            }
        }
        return null;
    }

    private static String extractSessionValue(String sessionCookie) {
        if (sessionCookie == null) {
            return null;
        }
        int eq = sessionCookie.indexOf('=');
        if (eq < 0) {
            return sessionCookie;
        }
        String value = sessionCookie.substring(eq + 1);
        int semi = value.indexOf(';');
        return semi > 0 ? value.substring(0, semi) : value;
    }

    private static boolean isHtml(String body) {
        String t = body.stripLeading();
        return t.startsWith("<!DOCTYPE") || t.startsWith("<html") || t.startsWith("<!doctype");
    }
}
