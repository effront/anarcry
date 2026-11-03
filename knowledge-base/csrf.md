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

## Escalation Techniques
CSRF isolado costuma ser classificado como medio, mas pode ser escalado para impacto critico:

- **Vazamento de informacoes via preferencias:** se CSRF permite alterar o e-mail de cobranca ou de notificacao da vitima, o atacante pode redirecionar e-mails contendo dados sensiveis (enderecos, telefones, cartoes) para seu proprio e-mail. A vitima pode nao notar a mudanca por semanas.
- **Self-XSS para Stored XSS:** campos que so o proprio usuario ve e edita (ex: apelido de conta, bio) frequentemente sao vulneraveis a self-XSS, mas nao sao exploraveis sozinhos. Um CSRF que altera esse campo pode injetar payload XSS, transformando self-XSS em stored XSS que executa toda vez que a vitima acessa a pagina.
- **Account takeover:** CSRF em endpoints de criacao/alteracao de senha, alteracao de e-mail ou reset de senha permite tomar controle da conta da vitima. Especialmente perigoso em fluxos onde usuarios cadastrados via rede social nao tem senha definida -- o atacante define uma via CSRF.
- **Encadeamento com XSS para entrega em massa:** se o site tem stored XSS em outra superficie (ex: comentarios), o atacante pode embutir o formulario CSRF no payload XSS, atingindo todos os visitantes daquela pagina automaticamente.
- **Entrega via imagem (GET CSRF):** se a acao state-changing aceita GET, o payload pode ser embutido em tag `<img>` postada em forum ou mensagem -- qualquer usuario que visualize a pagina executa a acao sem clicar.
- **Bypass de SameSite:** mesmo com `SameSite=Lax` padrao em Chrome, CSRF via GET com top-level navigation ainda funciona. Alem disso, se o cookie esta marcado como `SameSite=None` (necessario para integracoes cross-origin), CSRF classico funciona normalmente.
- **CSRF + clickjacking:** se o endpoint usa token CSRF mas a pagina e frameable (sem `X-Frame-Options`), clickjacking pode ser usado para fazer a vitima clicar no botao real da pagina legitima, que inclui o token correto.

Ao avaliar impacto, considere: qual acao e afetada (troca de senha vs trocar cor de tema)? Pode ser encadeado com outro bug? Como o payload pode ser entregue (link, imagem, XSS)?

## Hunting Methodology
Processo passo a passo para identificar CSRF:

1. **Mapear acoes state-changing:** navegar pela aplicacao e listar todos os endpoints que alteram dados -- troca de senha, envio de mensagem, exclusao, transferencia, alteracao de configuracoes. Anotar URL, metodo HTTP e parametros de cada um.
2. **Verificar ausencia de protecao:** interceptar cada requisicao com proxy e buscar por tokens CSRF (parametros ou headers com nomes como `csrf_token`, `_token`, `authenticity_token`, `X-CSRF-Token`). Verificar tambem cookies `SameSite`.
3. **Testar bypasses de token:** se ha token, tentar: remover o parametro inteiro; enviar token vazio; reutilizar token de outra sessao/usuario; trocar metodo POST por GET (ou vice-versa).
4. **Testar bypass de Referer:** se a protecao e por Referer, adicionar `<meta name="referrer" content="no-referrer">` na pagina de ataque para omitir o header. Tentar tambem colocar o dominio-alvo como subdominio ou path do Referer (`attacker.com/example.com`).
5. **Confirmar a vulnerabilidade:** criar pagina HTML com formulario auto-submit que imita a requisicao. Abrir em browser autenticado no alvo e verificar se a acao foi executada.
6. **Verificar clickjacking como alternativa:** se o endpoint usa tokens CSRF corretamente, verificar se a pagina pode ser carregada em iframe. Se sim, clickjacking pode substituir CSRF.
7. **Elaborar estrategia de entrega:** demonstrar como o payload pode ser entregue -- link em forum, imagem embarcada, stored XSS, pagina maliciosa.

## False Positive Indicators
Sinais de que a ausencia de token detectada pelo scanner **nao e CSRF exploravel**:

- **SameSite=Lax efetivo:** se o cookie de sessao usa `SameSite=Lax` (padrao em Chrome) e a acao requer POST, requisicoes cross-origin nao incluirao o cookie. CSRF classico nao funciona nesse cenario para POST requests.
- **Validacao de Origin/Referer server-side:** mesmo sem token CSRF visivel, o backend pode validar o header `Origin` ou `Referer` e rejeitar requests de origens externas. Confirmar enviando request com `Origin: https://evil.com`.
- **Custom header obrigatorio:** APIs que exigem header customizado (ex: `X-Requested-With: XMLHttpRequest`) sao protegidas por CORS preflight -- formularios HTML simples nao conseguem adicionar headers customizados.
- **Content-Type restrito com CORS:** se o endpoint exige `Content-Type: application/json` e rejeita `text/plain`/`multipart/form-data`, CSRF via formulario nao funciona, pois formularios HTML so enviam esses dois tipos sem preflight.
- **Acao nao e realmente state-changing:** scanner pode reportar ausencia de token em endpoints que apenas retornam dados (GET puro), sem alterar estado. CSRF so e relevante em acoes que modificam dados.
- **Reautenticacao obrigatoria:** se o endpoint exige senha atual ou MFA antes de executar a acao, CSRF nao consegue fornecer essa informacao e a acao falha.
- **Token presente em header/cookie nao visivel:** o scanner pode nao detectar tokens enviados via headers customizados ou cookies double-submit com assinatura HMAC.

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
