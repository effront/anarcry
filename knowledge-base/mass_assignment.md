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

## Escalation Techniques
- **Mass assignment + privilege escalation:** enviar `{"role":"admin"}` ou `{"isAdmin":true}` em endpoint de criacao/atualizacao de usuario para obter acesso administrativo; a partir dai, acessar dados de todos os usuarios, alterar configuracoes e criar backdoors.
- **Mass assignment + account takeover:** alterar campos como `email`, `emailVerified:true` ou `resetToken` via mass assignment para sequestrar contas -- o atacante muda o e-mail para o seu, marca como verificado e redefine a senha.
- **Mass assignment + fraude financeira:** modificar campos como `balance`, `credits`, `price`, `discount` ou `plan` para obter recursos financeiros indevidos -- o impacto e direto em aplicacoes de e-commerce, fintech e SaaS.
- **Mass assignment + IDOR chain:** combinar mass assignment com IDOR enviando `{"ownerId":"ID_DO_ATACANTE"}` para transferir ownership de recursos de outros usuarios, ou `{"tenantId":"outro-tenant"}` para acessar dados cross-tenant.
- **Mass assignment via GraphQL mutation:** quando a mutation GraphQL aceita `input` com campos nao documentados, enviar campos extras descobertos via introspection para escalar privilegios -- o vetor e o mesmo, mas a superficie de ataque e diferente da REST.

## Hunting Methodology
1. **Mapear o modelo de dados:** usar documentacao OpenAPI/Swagger, introspection GraphQL, ou respostas da API para identificar todos os campos do objeto (especialmente `role`, `isAdmin`, `verified`, `balance`, `status`, `ownerId`). Comparar o que o frontend envia com o que a API retorna -- campos extras na resposta que nao sao enviados pelo frontend sao candidatos.
2. **Testar campos extras em criacao:** em endpoints de registro/criacao (`POST /api/users`, `POST /api/register`), adicionar campos sensiveis ao body (`"role":"admin"`, `"isAdmin":true`, `"verified":true`). Verificar se o objeto criado reflete os valores injetados.
3. **Testar campos extras em atualizacao:** em endpoints de atualizacao (`PUT /api/users/{id}`, `PATCH /api/profile`), enviar campos que nao fazem parte do formulario visivel. Testar variantes de nome (`role`, `roles`, `roleId`, `Role`, `is_admin`, `IS_ADMIN`).
4. **Testar formatos alternativos:** repetir os testes com diferentes Content-Types (`application/json`, `application/x-www-form-urlencoded`, `multipart/form-data`, `application/xml`) e com objetos aninhados (`{"user":{"role":"admin"}}`). Parsers diferentes podem aceitar campos que outros rejeitam.
5. **Verificar resposta e persistencia:** apos enviar o payload, verificar se a resposta da API reflete o campo alterado. Fazer um GET subsequente para confirmar que a alteracao persistiu no banco. Checar se o novo privilegio/valor e efetivo (ex.: acessar painel admin).
6. **Testar PATCH parcial:** endpoints PATCH frequentemente aceitam subsets de campos sem validacao completa do DTO; enviar apenas o campo sensivel (`{"role":"admin"}`) em PATCH pode funcionar mesmo quando PUT rejeita.

## False Positive Indicators
- **Campo enviado mas ignorado silenciosamente:** o servidor aceita o request sem erro (200 OK), mas o campo extra nao e persistido -- a resposta e o GET subsequente mostram o valor original inalterado. Isso indica que o framework ignora campos desconhecidos sem aplica-los.
- **Campo aceito mas sem efeito de privilegio:** o servidor persiste o campo (ex.: `role` aparece na resposta), mas a logica de autorizacao usa uma fonte diferente (ex.: tabela de permissoes separada, claim do JWT) -- a alteracao do campo nao concede acesso real.
- **Endpoint requer privilegio admin:** o endpoint que aceita mass assignment so e acessivel por administradores autenticados (ex.: `PUT /api/admin/users/{id}`) -- um admin alterando roles de outros usuarios e comportamento esperado, nao uma vulnerabilidade.
- **Validacao rejeita com 400:** o servidor retorna `400 Bad Request` ou `422 Unprocessable Entity` com mensagem explicita sobre campos nao permitidos -- a protecao contra mass assignment esta funcionando.
- **DTO especifico por operacao:** a API usa records/DTOs diferentes para criacao e atualizacao, com allowlist explicita de campos; campos nao declarados no DTO sao rejeitados na deserializacao -- o risco e mitigado por design.
