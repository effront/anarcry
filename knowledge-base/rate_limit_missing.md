---
id: rate_limit_missing
title: "Missing Rate Limiting"
module: "ratelimit"
severity: "HIGH"
cwe_id: "CWE-307"
cwe_title: "Improper Restriction of Excessive Authentication Attempts"
cvss_vector: "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
vrt_id: "broken_authentication_and_session_management.brute_force_protection_missing"
---

## Summary
Endpoints de autenticacao nao implementam rate limiting, permitindo que atacantes enviem volumes ilimitados de tentativas de login, reset de senha ou verificacao MFA sem qualquer restricao.

## Description
Rate limiting e o mecanismo que restringe a quantidade de requisicoes que um cliente pode fazer a um endpoint dentro de um intervalo de tempo. Quando ausente em endpoints de autenticacao, a aplicacao fica vulneravel a:

- **Brute-force de credenciais:** tentativas automatizadas de login usando wordlists de senhas comuns ou credenciais vazadas.
- **Credential stuffing:** reutilizacao de pares email/senha obtidos em vazamentos de outras plataformas.
- **Enumeracao de usuarios:** respostas distintas para usuarios validos vs invalidos permitem mapear contas existentes.
- **Bypass de MFA:** codigos OTP de 4-6 digitos podem ser exauridos em minutos sem throttling.
- **Abuso de password reset:** envio massivo de emails de reset para causar spam ou facilitar phishing.

A deteccao e feita enviando uma rajada de requisicoes POST a endpoints de autenticacao e verificando se o servidor responde com HTTP 429 (Too Many Requests), header `Retry-After` ou `X-RateLimit-Remaining: 0`. Ausencia desses sinais indica que o endpoint nao possui protecao contra volume excessivo.

## Impact
- Comprometimento de contas de usuario via brute-force ou credential stuffing.
- Exfiltracacao de dados pessoais e informacoes sensiveis associadas a contas comprometidas.
- Bypass de autenticacao multi-fator por enumeracao de codigos OTP.
- Spam de emails de password reset, causando impacto reputacional e fadiga de alerta nos usuarios.
- Negacao de servico por sobrecarga nos mecanismos de autenticacao e banco de dados.
- Impacto HIGH para endpoints de login/signin; MEDIUM para reset, MFA e outros endpoints auxiliares.

## Payloads and Techniques
```bash
# Teste basico -- enviar 20 requisicoes rapidas e checar rate limiting
for i in $(seq 1 20); do
  curl -s -o /dev/null -w "%{http_code}\n" -X POST \
    -H "Content-Type: application/json" \
    -d '{"email":"test@test.com","password":"test123"}' \
    https://target.com/api/auth/login
done

# Verificar headers de rate limiting na resposta
curl -v -X POST \
  -H "Content-Type: application/json" \
  -d '{"email":"test@test.com","password":"test123"}' \
  https://target.com/api/auth/login 2>&1 | grep -iE "(429|retry-after|x-ratelimit)"

# Brute-force com hydra (somente em contexto autorizado)
hydra -l admin@target.com -P /usr/share/wordlists/rockyou.txt \
  target.com https-post-form \
  "/api/auth/login:email=^USER^&password=^PASS^:Invalid credentials"

# Credential stuffing com ffuf
ffuf -w credentials.txt:CRED -X POST \
  -H "Content-Type: application/json" \
  -d '{"email":"CRED_email","password":"CRED_pass"}' \
  -u https://target.com/api/auth/login -mc 200
```

Tecnicas de bypass de rate limiting existente:
```bash
# IP rotation via headers
curl -H "X-Forwarded-For: 1.2.3.4" ...
curl -H "X-Real-IP: 5.6.7.8" ...
curl -H "X-Originating-IP: 9.10.11.12" ...

# Variacoes de endpoint (case, trailing slash, encoding)
/api/auth/Login
/api/auth/login/
/api/auth/login%00
/API/AUTH/LOGIN
```

## Target Context (Crawler Hints)
- **Endpoints comuns:** `/api/auth/login`, `/api/login`, `/auth/login`, `/login`, `/api/auth/signin`, `/api/auth/reset`, `/api/auth/forgot-password`, `/api/auth/verify`, `/api/auth/mfa`, `/api/auth/2fa`.
- **Sinais:** formularios de login, paginas de reset de senha, campos de OTP/MFA, endpoints que aceitam POST com email/password no body.
- **Headers indicativos de protecao:** `X-RateLimit-Limit`, `X-RateLimit-Remaining`, `X-RateLimit-Reset`, `Retry-After`.

## False Positive Indicators
- Servidor retorna 429 ou headers de rate limiting apos o burst -- protecao presente, nao e vulneravel.
- WAF ou CDN (Cloudflare, AWS WAF) aplica rate limiting antes do servidor -- verificar se o 429 vem do WAF e nao da aplicacao.
- Endpoint retorna 404 ou 405 -- nao e um endpoint valido de autenticacao.
- Rate limiting configurado com threshold muito alto (ex.: 1000 req/min) -- pode nao disparar com burst pequeno mas ainda existe.

## Notable CVEs

| CVE | Produto | Ano | Descricao | Tipo |
|-----|---------|-----|-----------|------|
| CVE-2024-1709 | ConnectWise ScreenConnect | 2024 | Bypass de autenticacao no setup wizard sem restricao de tentativas permite criacao de conta admin e RCE em massa | Auth Bypass (pre-auth) |
| CVE-2023-46805 | Ivanti Connect Secure | 2023 | Auth bypass no endpoint de login VPN -- ausencia de rate limiting permite exploracao automatizada em massa | Auth Bypass (pre-auth) |
| CVE-2023-42793 | JetBrains TeamCity | 2023 | Endpoint de criacao de tokens sem autenticacao ou rate limiting permite geracao ilimitada de tokens admin | Auth Bypass (pre-auth) |
| CVE-2022-40684 | Fortinet FortiOS/FortiProxy | 2022 | Bypass de autenticacao via header especial na API REST administrativa sem limitacao de tentativas | Auth Bypass (pre-auth) |
| CVE-2021-22893 | Pulse Connect Secure | 2021 | Zero-day em VPN -- bypass de autenticacao sem protecao contra brute-force no endpoint de login | Auth Bypass (zero-day) |
| CVE-2018-15473 | OpenSSH < 7.8 | 2018 | User enumeration via timing difference no processo de autenticacao sem protecao de volume | Username Enumeration |

## Recommendation
1. **HTTP 429:** retornar status 429 (Too Many Requests) apos o threshold ser excedido, com header `Retry-After` indicando tempo de espera.
2. **Rate limiting por IP e por conta:** limitar tanto por endereco IP quanto por identificador de conta para evitar ataques distribuidos.
3. **Exponential backoff:** aumentar progressivamente o tempo de bloqueio a cada tentativa falha consecutiva.
4. **Account lockout:** bloquear temporariamente a conta apos N tentativas falhas (ex.: 5-10), com desbloqueio automatico apos periodo.
5. **CAPTCHA:** exigir resolucao de CAPTCHA apos N tentativas falhas para distinguir humanos de bots.
6. **Headers padrao:** incluir `X-RateLimit-Limit`, `X-RateLimit-Remaining` e `X-RateLimit-Reset` em todas as respostas.
7. **Monitoramento:** alertar sobre picos de tentativas de login falhas; correlacionar com IPs e user-agents suspeitos.

Exemplo com Express.js (rate-limiter-flexible):
```javascript
const { RateLimiterMemory } = require('rate-limiter-flexible');
const limiter = new RateLimiterMemory({ points: 5, duration: 60 });

app.post('/api/auth/login', async (req, res) => {
  try {
    await limiter.consume(req.ip);
    // ... authentication logic
  } catch (rej) {
    res.set('Retry-After', Math.ceil(rej.msBeforeNext / 1000));
    res.status(429).json({ error: 'Too many attempts. Try again later.' });
  }
});
```

Exemplo com Spring Boot:
```java
@Bean
public FilterRegistrationBean<RateLimitFilter> rateLimitFilter() {
    // Use bucket4j, resilience4j, or similar for production rate limiting
    // Apply to /api/auth/** endpoints
}
```
