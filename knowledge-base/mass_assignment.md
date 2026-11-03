---
id: mass_assignment
title: "Mass Assignment"
module: "massassign"
severity: "HIGH"
cwe_id: "CWE-915"
cwe_title: "Improperly Controlled Modification of Dynamically-Determined Object Attributes"
cvss_vector: "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N"
vrt_id: "broken_access_control.mass_assignment"
---

## Summary
O backend vincula automaticamente todos os campos enviados pelo cliente ao objeto interno, permitindo alterar atributos não previstos como `role`, `is_admin`, `verified`, `balance` e `owner_id`.

## Description
Mass assignment (ou autobinding) ocorre quando o framework mapeia o body da requisição diretamente para um modelo de domínio, sem allowlist de campos. O atacante envia propriedades extras que o frontend não exibe, mas o backend aceita. Em Spring, `@ModelAttribute`/`@RequestBody` com a entidade; em Rails, `params.permit!` ou `Model.new(params)`; em Node, `Object.assign(user, req.body)`; em Laravel, `$request->all()` com `$fillable` mal configurado.

Impactos comuns:
- Escalada de privilégios (`role`, `isAdmin`, `permissions`).
- Bypass de verificação de e-mail/telefone (`emailVerified`, `phoneVerified`).
- Alteração de saldo/créditos/plano (`balance`, `plan`, `credits`).
- Transferência de ownership (`ownerId`, `userId`, `tenantId`).
- Alteração de campos internos (`createdAt`, `deletedAt`, `status`, `price`).
- Ativação de features e acesso a recursos pagos.

## Impact
- Escalada de privilégios e account takeover.
- Fraude financeira (saldo, créditos, preços, cupons).
- Bypass de verificação de identidade e controles de negócio.
- Acesso a dados de outros usuários/tenants.
- Impacto HIGH; CRITICAL quando leva a admin ou fraude em massa.

## Payloads and Bypasses
```json
// Escalada de role
{"email":"user@exemplo.com","password":"Senha123!","role":"admin"}

// Bypass de verificação
{"email":"user@exemplo.com","emailVerified":true,"phoneVerified":true}

// Alteração de saldo/plano
{"name":"Fulano","balance":999999,"plan":"enterprise","credits":100000}

// Alteração de ownership
{"name":"Fulano","ownerId":"123","tenantId":"outro-tenant"}

// Campos internos
{"status":"active","deletedAt":null,"price":0,"isAdmin":true}
```

Variações de payload:
```json
// Aninhado
{"user":{"email":"user@exemplo.com","role":"admin"}}
{"profile":{"user":{"role":"admin"}}}

// Case/alias
{"Role":"admin","IS_ADMIN":true,"is_admin":1,"role_id":1}

// Duplicatas (parser-dependent)
{"role":"user","role":"admin"}

// Form-urlencoded
email=user%40exemplo.com&role=admin&isAdmin=true

// XML
<user><email>user@exemplo.com</email><role>admin</role></user>

// Prototype pollution (Node)
{"__proto__":{"isAdmin":true}}
{"constructor":{"prototype":{"isAdmin":true}}}
```

Bypasses de allowlist:
```text
- Campos não documentados descobertos via GraphQL introspection / OpenAPI
- `role` vs `roles` vs `roleId` vs `permissions`
- Enviar campo em nested object quando o DTO raiz é allowlisted
- Mass assignment em PATCH parcial
- Abusar de `@JsonAnySetter` ou maps genéricos
- Explorar conversão de tipos (string "true" para boolean)
- Enviar campos em multipart/form-data
```

Casos reais e mentalidade de ataque (RWBH): Uber e GitHub (perfis/roles) mostram que campos não documentados como `role`, `verified` e `owner_id` são o alvo; o atacante compara o que o frontend envia com o que o backend aceita.

## Target Context (Crawler Hints)
- **Parâmetros comuns:** `role`, `roles`, `is_admin`, `isAdmin`, `admin`, `permissions`, `verified`, `email_verified`, `emailVerified`, `phone_verified`, `status`, `plan`, `credits`, `balance`, `price`, `owner_id`, `ownerId`, `user_id`, `tenant_id`, `org_id`, `created_at`, `deleted_at`, `active`.
- **Paths comuns:** `/api/users`, `/api/users/{id}`, `/api/register`, `/api/profile`, `/api/account`, `/api/settings`, `/api/organizations`, `/api/billing`, `/graphql`.
- **Sinais:** OpenAPI/GraphQL revela campos internos; PATCH aceita body completo; frontend envia menos campos que o backend aceita; respostas incluem `role`/`isAdmin`.

## Escalation Techniques
Mass assignment e frequentemente o vetor para escalada de privilegios e fraude -- o impacto depende de quais campos o backend aceita:

- **Privilege escalation:** enviar `{"role":"admin"}` ou `{"isAdmin":true}` junto de dados legitimos para elevar privilegios. O livro (Bug Bounty Bootcamp, Cap. 17) descreve como broken access control permite atacantes interferirem com logica de autorizacao via requests sintaticamente validos.
- **Account takeover via IDOR + mass assignment:** o livro (Cap. 10) detalha como combinar IDOR (trocar `user_id`) com mass assignment (enviar campos extras) para alterar email/password de outro usuario. Write-based IDORs em endpoints de password change sao os de maior impacto.
- **Self-XSS para stored XSS:** o livro (Cap. 10) orienta combinar write-based IDOR com self-XSS -- mass assignment que permite alterar campos de perfil de outro usuario transforma self-XSS em stored XSS exploravel.
- **Bypass de verificacao:** setar `verified: true`, `email_confirmed: true`, `2fa_enabled: false` para pular fluxos de verificacao que a aplicacao impoe. Analogo ao "skippable authentication step" descrito no Cap. 17.
- **Manipulacao financeira:** alterar `balance`, `credits`, `discount`, `price`, `plan` se o modelo expoe esses campos. O livro (Cap. 17) ilustra como logica de pagamento pode ser contornada manipulando parametros de request.
- **Ownership hijack:** alterar `owner_id`, `tenant_id`, `created_by` para tomar controle de recursos de outros usuarios ou tenants -- combina mass assignment com broken access control.

## Hunting Methodology
Processo passo a passo para identificar mass assignment, baseado nos Cap. 10, 17 e 24 (Bug Bounty Bootcamp):

1. **Criar duas contas com niveis de privilegio diferentes:** o livro (Cap. 10) recomenda criar uma conta atacante e uma vitima, alem de contas em cada nivel de permissao (admin, user, membro de grupo). Isso permite testar tanto escalada horizontal quanto vertical.
2. **Mapear endpoints de criacao e atualizacao:** usando o proxy, capturar todos os requests de register, profile update, settings, billing, e qualquer POST/PUT/PATCH que aceite body JSON ou form-data. O livro (Cap. 24) orienta enumerar APIs via documentacao publica, Swagger, e interceptacao de trafego.
3. **Inspecionar schema da API:** consultar OpenAPI/Swagger, GraphQL introspection, ou documentacao para descobrir campos ocultos no modelo. O livro (Cap. 24) destaca que APIs muitas vezes retornam mais dados que o necessario, revelando campos internos como `role`, `permissions`, `verified`.
4. **Adicionar campos extras nao presentes no formulario:** ao request capturado, adicionar campos como `role`, `is_admin`, `verified`, `balance`, `permissions`, `group_id`. Testar variantes de case e alias (`Role`, `IS_ADMIN`, `roleId`). O livro (Cap. 10) recomenda prestar atencao a parametros em todas as posicoes -- URL, body, headers, cookies.
5. **Comparar resposta antes e depois:** enviar o request com campos extras e verificar se o valor foi aceito. Fazer GET na conta para confirmar se o campo mudou. O livro (Cap. 10) alerta para blind IDORs -- o efeito pode aparecer em exports, emails ou relatorios futuros, nao na resposta imediata.
6. **Testar diferentes metodos HTTP:** o livro (Cap. 10) destaca que "applications often enable multiple request methods on the same endpoint but fail to implement the same access control for each method." Se POST nao aceita o campo extra, testar PUT, PATCH e DELETE.
7. **Testar em APIs de versao antiga:** o livro (Cap. 24) orienta testar versoes anteriores da API (`/api/v1/` vs `/api/v2/`) -- versoes mais antigas frequentemente tem menos protecoes contra mass assignment.

## False Positive Indicators
Sinais de que o mass assignment detectado pelo scanner **nao e exploravel**:

- **Servidor aceita campos extras mas ignora silenciosamente:** o request retorna `200 OK` mas o campo sensivel (`role`, `isAdmin`) nao mudou no objeto persistido -- o framework esta filtrando via allowlist ou DTO. Confirmar com GET subsequente.
- **Campo `role` aparece no response mas e populado pelo servidor:** o backend inclui `role` na resposta por conveniencia de leitura, mas o valor e derivado internamente (ex.: do token JWT ou sessao), nao do input do usuario.
- **Endpoint retorna 400/422 para campos desconhecidos:** o framework esta configurado com `FAIL_ON_UNKNOWN_PROPERTIES` ou equivalente e rejeita explicitamente campos nao permitidos -- a protecao esta funcionando.
- **Campo alteravel e intencional:** alguns campos que parecem sensiveis (ex.: `locale`, `timezone`, `theme`) sao projetados para serem alterados pelo usuario -- mass assignment aqui e o comportamento esperado, nao uma vulnerabilidade.
- **Teste feito com admin logado:** se o testador usou credenciais de admin, a alteracao de `role` pode ser funcionalidade normal do painel admin. Repetir o teste com conta de privilegio inferior para confirmar.

## Recommendation
1. Usar DTOs específicos por operação (Create/Update) com allowlist explícita de campos; nunca vincular entidade de domínio diretamente ao body.
2. Em Spring, usar `@JsonIgnoreProperties(ignoreUnknown = false)` ou `FAIL_ON_UNKNOWN_PROPERTIES` para rejeitar campos desconhecidos; evitar `@ModelAttribute` em entidades.
```java
public record UpdateUserRequest(
    @NotBlank String name,
    @Email String email
) {}
```
3. Em Rails, usar strong parameters (`params.require(:user).permit(:name, :email)`); em Node, validar com Zod/Joi e montar o objeto campo a campo; em Laravel, `$fillable` restritivo.
4. Nunca permitir que o cliente defina `role`, `isAdmin`, `permissions`, `ownerId`, `tenantId`, `balance` e `status`; esses campos devem ser derivados no servidor.
5. Aplicar autorização e regras de negócio no servidor, independentemente do que o cliente envia.
6. Rejeitar propriedades desconhecidas e retornar 400; não ignorar silenciosamente.
7. Auditar alterações sensíveis e alertar sobre mudanças de role/owner fora do fluxo administrativo.
8. Cobrir com testes que enviem campos extras em todos os endpoints de criação/atualização.

