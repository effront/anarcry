# PRD -- SwapCult Dangling Backend PoC Validator

**Data:** 2026-11-13
**Autor:** Bullet
**Objetivo:** Validar se o slug `xmr-swap-76mw2` no DigitalOcean App Platform pode ser reivindicado por terceiros, confirmando a vulnerabilidade de dangling backend reference.

---

## 1. Contexto

O frontend do SwapCult (`swapcult.com`, Vercel) configura:

```js
window.__NUXT__.config.public.apiBase = "https://xmr-swap-76mw2.ondigitalocean.app"
```

Esse dominio retorna **NXDOMAIN** -- o app DigitalOcean foi destruido. Se um atacante conseguir registrar um app com o mesmo slug, recebe todos os requests de swap dos usuarios do SwapCult.

### Endpoints afetados (composable CkwmW5gq.js)

```
POST /api/v1/swaps/new-estimate    -- cotacao (envia currency_from, currency_to, amount)
POST /api/v1/swaps/new-exchange    -- cria exchange (envia enderecos, valores)
GET  /api/v1/swaps/exchange/{id}   -- busca exchange (retorna dados completos)
```

Nenhum endpoint usa autenticacao. Content-Type: `application/x-www-form-urlencoded`.

---

## 2. Objetivo da PoC

Criar um app **benigno** no DigitalOcean App Platform com o slug `xmr-swap-76mw2` que:

1. **Registra** todas as requests recebidas (evidence capture)
2. **Retorna respostas neutras** (nao manipula dados, nao rouba fundos)
3. **Prova** que o takeover e possivel (requests chegam de usuarios reais)
4. **Autodestroy** apos captura de evidencia

### O que a PoC NAO faz

- NAO retorna enderecos de wallet falsos
- NAO manipula valores ou taxas
- NAO intercepta ou modifica transacoes reais
- NAO persiste dados de usuarios alem do necessario pra evidencia

---

## 3. Arquitetura

```
[SwapCult Frontend]  -- $fetch() -->  [PoC App no DO]  -- log -->  [Evidence JSON]
   (swapcult.com)                     (xmr-swap-76mw2            (stdout + file)
                                       .ondigitalocean.app)
```

### Stack

- **Runtime:** Node.js 20 (minimo, sem deps externas)
- **Framework:** nenhum -- `node:http` puro (zero attack surface)
- **Deploy:** DigitalOcean App Platform (Dockerfile ou buildpack)
- **Persistencia:** stdout (DO App Logs) + arquivo local /tmp/evidence.json

---

## 4. Spec do App

### 4.1 Servidor HTTP

```
Porta: 8080 (padrao DO App Platform)
Rotas: catch-all (qualquer path)
CORS: Access-Control-Allow-Origin: * (necessario pro frontend chamar)
```

### 4.2 Comportamento por endpoint

| Rota | Metodo | Resposta da PoC | Proposito |
|---|---|---|---|
| `/api/v1/swaps/new-estimate` | POST | `{"error": "service_unavailable"}` | Resposta segura, nao retorna cotacao falsa |
| `/api/v1/swaps/new-exchange` | POST | `{"error": "service_unavailable"}` | Resposta segura, nao cria exchange falsa |
| `/api/v1/swaps/exchange/:id` | GET | `{"error": "service_unavailable"}` | Resposta segura, nao retorna dados falsos |
| `*` (qualquer outra) | ANY | `{"status": "poc_active"}` | Catch-all |

### 4.3 Evidence Logging

Cada request recebida gera um log entry:

```json
{
  "timestamp": "2026-11-13T22:30:00.000Z",
  "method": "POST",
  "path": "/api/v1/swaps/new-estimate",
  "headers": {
    "origin": "https://swapcult.com",
    "referer": "https://swapcult.com/",
    "user-agent": "Mozilla/5.0 ..."
  },
  "body": "currency_from=eth&currency_to=btc&amount=0.1",
  "ip": "[REDACTED]",
  "evidence_type": "dangling_backend_takeover"
}
```

**Regras de logging:**
- IP do usuario e REDACTADO (privacidade)
- Body e logado pra provar que dados sensiveis chegam
- Headers Origin/Referer provam que veio do SwapCult
- Timestamp pra timeline da evidencia

### 4.4 Auto-shutdown

O app se desliga automaticamente apos **1 hora** ou **50 requests** (o que vier primeiro). Isso garante:
- Minimo de exposicao
- Evidence suficiente pro report
- Nao funciona como backend permanente

---

## 5. Implementacao

### 5.1 Estrutura do projeto

```
swapcult-poc/
  server.js          -- servidor HTTP (~80 linhas)
  Dockerfile         -- container minimo
  .do/app.yaml       -- config DO App Platform
```

### 5.2 server.js (pseudo-codigo)

```
- Criar HTTP server na porta 8080
- Middleware CORS (Access-Control-Allow-Origin: *)
- Preflight handler (OPTIONS -> 204)
- Para cada request:
    - Parsear method, path, headers, body
    - Redactar IP
    - Logar evidence em stdout (JSON)
    - Appendar em /tmp/evidence.json
    - Incrementar contador
    - Se contador >= 50 ou uptime >= 3600s:
        - Logar "AUTO_SHUTDOWN: evidence collected"
        - process.exit(0)
    - Retornar {"error": "service_unavailable"} com status 503
```

### 5.3 Dockerfile

```dockerfile
FROM node:20-alpine
WORKDIR /app
COPY server.js .
EXPOSE 8080
CMD ["node", "server.js"]
```

### 5.4 .do/app.yaml

```yaml
name: xmr-swap-76mw2
services:
  - name: web
    dockerfile_path: Dockerfile
    http_port: 8080
    instance_count: 1
    instance_size_slug: apps-s-1vcpu-0.5gb
    routes:
      - path: /
```

---

## 6. Plano de Execucao

### Fase 1 -- Preparacao (5 min)
1. Criar conta DO (ou usar existente)
2. Criar o projeto local com os 3 arquivos
3. Push pra repo Git (DO App Platform deploya via Git)

### Fase 2 -- Deploy (5 min)
1. Criar app no DO App Platform com nome `xmr-swap-76mw2`
2. Se o slug estiver **disponivel**: deploy e esperar ficar live
3. Se o slug estiver **indisponivel**: documentar e reportar como "partial PoC"
   (o slug estar indisponivel nao invalida o finding -- ainda e dangling reference
   que expoe dados e poderia ser explorada por quem tem acesso ao projeto DO original)

### Fase 3 -- Captura de evidencia (5-60 min)
1. Verificar se `xmr-swap-76mw2.ondigitalocean.app` resolve agora
2. Abrir `https://swapcult.com` no browser
3. Navegar ate o swap (selecionar moedas, inserir valor)
4. Verificar nos logs do DO App se requests chegaram
5. Screenshot dos logs como evidencia
6. Exportar /tmp/evidence.json

### Fase 4 -- Validacao cruzada (2 min)
1. No browser DevTools > Network, confirmar que os requests foram pra DO
2. Verificar que Origin: swapcult.com nos headers logados
3. Verificar que body contem dados de swap

### Fase 5 -- Cleanup (2 min)
1. **DESTRUIR o app DO imediatamente** apos coleta de evidencia
2. Verificar que o dominio voltou a NXDOMAIN
3. Nao manter o app rodando -- responsabilidade etica

---

## 7. Evidence pra Report

O report pro bug bounty precisa de:

1. **Screenshot** do `__NUXT__.config` mostrando o apiBase
2. **Screenshot** do dnsNotFound no browser
3. **Screenshot** do app DO criado com o slug (se possivel)
4. **Logs** mostrando requests recebidos de swapcult.com
5. **Codigo** do composable CkwmW5gq.js mostrando endpoints sem auth
6. **Timeline** com timestamps

---

## 8. Riscos e Mitigacoes

| Risco | Mitigacao |
|---|---|
| Usuarios fazem swap real pro PoC | Responder 503, nao 200 com dados falsos |
| PoC fica rodando alem do necessario | Auto-shutdown apos 1h/50 req |
| Dados de usuarios expostos | IP redactado, evidence minima |
| DO nao permite o slug | Reportar como partial PoC, finding ainda valido |
| SwapCult considera teste em producao | Estamos observando, nao atacando -- PoC benigna |

---

## 9. Estimativa de severidade

Se o takeover for possivel:

- **Impacto:** Theft of user funds (atacante retorna wallet propria nas respostas)
- **CWE:** CWE-426 (Untrusted Search Path) / CWE-610 (Externally Controlled Reference)
- **CVSS:** 9.1+ (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N)
- **Bounty range:** $20,000 - $100,000 (Critical, theft of funds)

Se o slug nao puder ser reclamado:

- **Impacto:** Dead backend reference, swap functionality broken, data exposure risk
- **CWE:** CWE-672 (Operation on a Resource after Expiration)
- **CVSS:** 6.5 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N)
- **Bounty range:** $5,000 - $20,000 (High, information exposure + broken security assumption)
