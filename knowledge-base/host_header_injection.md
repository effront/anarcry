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

## Escalation Techniques
Host header injection raramente e o fim -- e o vetor para ataques de alto impacto:

- **Password reset poisoning:** o cenario classico: o atacante envia request de reset com `Host: evil.com` e o link enviado por e-mail aponta para o dominio do atacante, capturando o token de reset. Combinado com endpoints sem rate limiting, permite account takeover em massa. O livro (Bug Bounty Bootcamp, Cap. 13) descreve como servidores confiam em headers para construir URLs.
- **Cache poisoning:** resposta contendo host injetado e cacheada por CDN/proxy e servida a outros usuarios. Links internos, canonical URLs e scripts com host dinamico passam a apontar para dominio malicioso, afetando todos os visitantes.
- **SSRF e routing bypass:** o livro (Cap. 13) explica como servidores confiam em headers de forwarding para rotear requests; `X-Forwarded-Host` ou `Host` manipulado pode direcionar o request para backends internos, painel admin, ou servicos na rede privada -- o atacante assume posicao privilegiada na rede.
- **OAuth/webhook hijack:** callbacks e webhooks construidos a partir do Host apontam para servidor do atacante, capturando tokens OAuth, notificacoes e dados de integracao.
- **Cookie scoping attack:** `Set-Cookie` com dominio derivado do Host permite fixar cookies em dominio controlado ou ampliar o escopo do cookie para subdominios nao previstos.
- **Encadeamento com open redirect:** o livro (Cap. 7) descreve como open redirects potencializam host header injection -- o atacante redireciona a vitima atraves de URL confiavel para capturar tokens via referrer. Uma allowlist de SSRFs pode ser contornada por open redirect no dominio permitido (Cap. 13).

## Hunting Methodology
Processo passo a passo para identificar host header injection, adaptado dos Cap. 7 e 13 (Bug Bounty Bootcamp):

1. **Mapear funcionalidades que geram links absolutos:** identificar endpoints de password reset, e-mail verification, webhooks, callbacks, canonical URLs, e qualquer pagina que construa URLs completas. O livro (Cap. 13) destaca que features de proxy, webhook e upload sao os alvos mais comuns para SSRF, e host header injection compartilha a mesma superficie.
2. **Testar manipulacao basica do Host:** enviar request com `Host: evil.com` e verificar se o valor aparece em headers de resposta (`Location`, `Set-Cookie`), no corpo HTML (links, forms, canonical), ou em e-mails enviados pela aplicacao.
3. **Testar headers alternativos de forwarding:** se o Host basico nao funciona, testar `X-Forwarded-Host`, `X-Forwarded-Server`, `X-Host`, `X-HTTP-Host-Override`, `Forwarded: host=evil.com`. Muitos proxies repassam esses headers sem validacao.
4. **Testar bypass de validacao:** usar tecnicas de URL manipulation do livro (Cap. 7) -- `Host: alvo.com.evil.com`, `Host: alvo.com@evil.com`, `Host: alvo.com%00.evil.com`, Host duplicado. Testar absolute-form request URI (`GET https://evil.com/path`).
5. **Verificar fluxo de password reset:** solicitar reset para conta propria com Host manipulado e verificar o link recebido por e-mail. Se o host no link reflete o valor injetado, o finding e confirmado e o impacto e account takeover.
6. **Testar cacheabilidade:** enviar request com Host injetado e verificar se a resposta e cacheada. Repetir o request com Host normal e verificar se a resposta cacheada contem o host malicioso -- isso confirma cache poisoning.
7. **Testar vhost enumeration:** enviar diferentes valores de Host para descobrir vhosts internos e paineis administrativos. Respostas diferentes (200 vs 404/403) indicam vhosts existentes. O livro (Cap. 13) explica como usar diferencas em tempo de resposta e status codes para mapear a rede interna.

## False Positive Indicators
Sinais de que o host header injection detectado pelo scanner **nao e exploravel**:

- **Host refletido apenas em paginas informativas:** o Host aparece em mensagens de erro ou paginas de debug, mas nao e usado para construir links, cookies, ou redirecionamentos -- sem impacto funcional.
- **Proxy normaliza Host antes do backend:** proxies como Nginx e Cloudflare frequentemente sobrescrevem `Host` e `X-Forwarded-Host` antes de repassar ao backend -- o valor injetado nao chega a aplicacao mesmo que o scanner detecte reflexao no nivel do proxy.
- **Host ignorado na construcao de URLs:** a aplicacao usa configuracao estatica (`app.base-url`) ou variavel de ambiente para gerar links, nao o header Host do request. O host aparece em logs ou headers informativos, mas links e e-mails usam o dominio canonico.
- **Ambiente sem envio de e-mail:** o endpoint de password reset aceita o Host manipulado, mas o ambiente de teste/staging nao envia e-mails reais -- o impacto nao pode ser demonstrado sem acesso ao servidor de e-mail.
- **Cache desabilitado ou com chave correta:** a resposta com Host injetado nao e cacheada porque o servidor envia `Cache-Control: no-store` ou a chave de cache inclui o Host canonico -- cache poisoning nao e possivel.
- **Host refletido em `X-*` response header informativo:** o Host aparece em um header de resposta como `X-Request-Host` para debug, mas nao em `Location`, `Set-Cookie`, ou no corpo HTML -- nenhum navegador interpreta headers informativos como redirecionamento.

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
