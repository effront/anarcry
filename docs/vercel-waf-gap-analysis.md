# Vercel WAF Gap Analysis -- AnarCry v1.9.3

**Date**: 2026-11-04
**Target tested**: yatari.com.br (Vercel + Firebase Auth)
**Scan report**: `~/.anarcry/reports/anarcry-report-20261104-145733.md`

---

## TL;DR

AnarCry detecta o Vercel Security Checkpoint via `detectChallengeType()` mas nao
consegue bypassa-lo. Existe um `ChallengeSolver` pronto que suporta Vercel
(mouse simulation, WASM wait, cookie extraction) mas ele nunca e invocado.
Alem disso, `isWafBlocked()` nao reconhece Vercel 403s, fazendo modulos
gastarem requests sem saber que estao bloqueados.

---

## Evidencia do bloqueio

Headers observados em `curl -sI https://www.yatari.com.br`:

```
HTTP/2 403
server: Vercel
x-vercel-mitigated: challenge
x-vercel-challenge-token: 2.1793815222.60.YjE0ZWU5ZTkx...
retry-after: 30
```

Body: pagina "Vercel Security Checkpoint" com WebAssembly proof-of-work Worker,
MessageChannel, mouse tracking (`mouseAtProbe`), e `location.reload()` apos solve.

Impacto no scan: dos 24 modulos, apenas JWT (analise local do token) e
ReqSmuggling (timing-based) produziram findings reais. Todos os findings de
Headers mostram "HTTP 403" como evidencia -- estao lendo headers da pagina de
challenge, nao da aplicacao.

---

## O que ja funciona

### 1. `WafEvasion.detectChallengeType()` (WafEvasion.java:363)

```java
if ("challenge".equalsIgnoreCase(firstHeader(headers, "x-vercel-mitigated"))
        || (body != null && body.contains("Vercel Security Checkpoint"))) {
    return "Vercel Security Checkpoint";
}
```

Detecta Vercel corretamente via header `x-vercel-mitigated` e body content.

### 2. `ChallengeSolver` (ChallengeSolver.java)

Classe completa que:
- Lanca headless Chromium via Playwright
- Navega pro target
- Detecta challenge via title ("Security Checkpoint" / "Checking")
- Simula mouse movements (linhas 81-85) -- necessario pro Vercel mouse tracking
- Espera challenge resolver via `waitForURL` + `waitForLoadState(NETWORKIDLE)`
- Extrai cookies do BrowserContext como clearance
- Reconhece Vercel pelo title (linha 108)

### 3. `Http.send()` cookie injection (Http.java:26-28)

```java
String challengeCookies = ctx.wafState().challengeCookies();
if (!challengeCookies.isEmpty()) {
    cookies = cookies.isEmpty() ? challengeCookies : cookies + "; " + challengeCookies;
}
```

Ja injeta `challengeCookies` do WafState em todo request. O wiring do
cookie fallback ja existe no transport layer.

### 4. `BrowserTransport` (BrowserTransport.java)

Headless Chromium com `page.evaluate(fetch(...))` como transport layer.
Funciona como alternativa ao HttpClient pra sites com JS-heavy responses.

---

## Gap 1: `ChallengeSolver` nunca e invocado

**Arquivo**: nenhum (dead code)
**Impacto**: CRITICO

`ChallengeSolver` existe mas nenhum codigo o chama. `ScanRunner` Phase 1.5 usa
`BrowserTransport.create()` diretamente pra JS challenges, mas
`BrowserTransport.create()` faz apenas `page.navigate()` e retorna
imediatamente -- NAO espera challenge resolver, NAO simula mouse, NAO extrai
cookies.

Fluxo atual (quebrado):
```
ScanRunner Phase 1.5
  -> detecta JS_CHALLENGE (Vercel)
  -> BrowserTransport.create(targetUrl)
     -> page.navigate(targetUrl)  // retorna 403 challenge page
     -> return new BrowserTransport(...)  // "sucesso" com 403
  -> "JS challenge bypassado" (FALSO -- challenge nao foi resolvido)
  -> marca RULE_BLOCK (ERRADO)
  -> tenta payload evasion (INUTIL)
```

Fluxo correto:
```
ScanRunner Phase 1.5
  -> detecta Vercel challenge
  -> ChallengeSolver.solve(targetUrl)
     -> navigate + mouse sim + wait WASM + wait reload
     -> extractCookies() -> "clearance_cookie=abc123"
  -> WafState.setChallengeCookies(cookies)
  -> Http.send() injeta cookies em todo request
  -> scan funciona
```

---

## Gap 2: `isWafBlocked()` nao reconhece Vercel

**Arquivo**: WafEvasion.java:248-262
**Impacto**: ALTO

`WAF_SERVER` regex:
```
(?i)(cloudflare|akamai|incapsula|sucuri|ddos-guard|awselb|imperva|f5|barracuda)
```

Nao inclui `vercel`. `WAF_BODY` tambem nao tem strings do Vercel.

Consequencia: em runtime, quando modulos fazem requests e recebem 403 do Vercel,
`isWafBlocked()` retorna `false`. O circuit breaker nao detecta os blocks,
modulos continuam mandando requests, gastando tempo e disparando falsos positivos
(findings baseados no body/headers da challenge page em vez da aplicacao real).

**Fix**: adicionar `vercel` ao `WAF_SERVER` e `vercel security checkpoint` ou
`we're verifying your browser` ao `WAF_BODY`.

---

## Gap 3: `SIGNATURES` nao tem Vercel

**Arquivo**: WafEvasion.java:60-104
**Impacto**: MEDIO

`detectProviders()` nao identifica Vercel na baseline probe da Phase 1.5.
A deteccao so acontece via `detectChallengeType()` como fallback, mas sem
signature formal perde:
- Confidence score
- Category classification
- Hits tracking (quais signals matcharam)
- Consistencia com outros providers (CF, Akamai, AWS WAF etc)

Signals pro Vercel:
```
HEADER: x-vercel-mitigated        (confidence: 100)
HEADER: x-vercel-challenge-token  (confidence: 100)
HEADER: x-vercel-id               (confidence: 60)
CONTENT: Vercel Security Checkpoint (confidence: 95)
CONTENT: vercel.link/security-checkpoint (confidence: 90)
```

---

## Gap 4: ScanRunner Phase 1.5 -- Vercel cai no branch errado

**Arquivo**: ScanRunner.java:316-446
**Impacto**: CRITICO

Fluxo de decisao atual:

```
1. parseCfChallengeType() -> "" (nao e CF)
2. isJsChallenge() -> true (detecta Vercel via detectChallengeType)
3. Entra no branch JS_CHALLENGE (linha 375)
4. BrowserTransport.create() -- NAO resolve challenge (Gap 1)
5. Se BT != null: "JS challenge bypassado" (falso positivo)
6. Muda blockType -> RULE_BLOCK
7. Tenta payload evasion (completamente inutil contra Vercel pre-app block)
```

O Vercel Security Checkpoint e mais proximo de MANAGED_CHALLENGE do que
JS_CHALLENGE:
- Requer proof-of-work WASM (nao e um simples JS check)
- Tem mouse tracking como signal anti-bot
- Precisa de interacao de browser real
- MAS e solucionavel via headless (diferente de CF Managed que e dado como impossivel)

Precisa de branch proprio no ScanRunner:
```
if (isVercelChallenge) {
    // 1. Tentar ChallengeSolver (WASM + mouse)
    // 2. Se resolveu: setar cookies, opcionalmente ativar BrowserTransport
    // 3. Se falhou: fallback pra cookie manual
}
```

---

## Gap 5: Post-scan finding hardcoda "Cloudflare"

**Arquivo**: ScanRunner.java:517-538
**Impacto**: BAIXO

```java
String typeName = wafBt == WafState.WafBlockType.TURNSTILE
    ? "Cloudflare Turnstile"
    : "Cloudflare Managed Challenge";
```

Se Vercel fosse classificado como managed, o finding diria
"Cloudflare Managed Challenge" -- incorreto. O finding precisa usar
`wafState.wafProduct()` ou `wafState.challengeType()` pra nome correto.

---

## Gap 6: Sem `WafBlockType` pra Vercel

**Arquivo**: WafState.java:11-22
**Impacto**: MEDIO

```java
public enum WafBlockType {
    NONE,
    RULE_BLOCK,
    MANAGED_CHALLENGE,  // "browser required, evasion is useless"
    JS_CHALLENGE,       // "BrowserTransport may solve it"
    TURNSTILE           // "out of scope for automated bypass"
}
```

Nenhum type modela Vercel. O challenge Vercel e:
- Solucionavel via headless (diferente de MANAGED_CHALLENGE)
- Requer WASM + mouse (mais complexo que JS_CHALLENGE)
- Nao e captcha interativo (diferente de TURNSTILE)

Opcoes:
- **Novo type `VERCEL_CHALLENGE`**: limpo, permite branch dedicado
- **Reusar `JS_CHALLENGE` com fix no handling**: menos churn,
  mas obscurece a diferenca de complexidade

Recomendacao: `VERCEL_CHALLENGE` -- o tratamento e diferente o suficiente
(ChallengeSolver vs BrowserTransport direto).

---

## Plano de implementacao

### Approach 1 -- ChallengeSolver integration (automatico)

1. Adicionar `VERCEL_CHALLENGE` ao `WafBlockType`
2. Adicionar `WafSignature` pra Vercel em `SIGNATURES` (5 signals)
3. Adicionar `vercel` ao regex `WAF_SERVER`
4. Adicionar strings Vercel ao `WAF_BODY`
5. No `ScanRunner` Phase 1.5:
   - Detectar Vercel challenge antes do branch CF
   - Chamar `ChallengeSolver.solve()` primeiro
   - Extrair cookies -> `WafState.setChallengeCookies()`
   - Se ChallengeSolver funcionar: cookies injetados por `Http.send()`,
     scan inteiro funciona sem BrowserTransport
   - Se funcionar E Playwright disponivel: opcionalmente ativar
     BrowserTransport como transport layer pra requests que precisem
     de contexto JS (fetch in-page)
6. Fixar post-scan finding pra usar `challengeType()` ao inves de hardcode

### Approach 2 -- Cookie passthrough manual (fallback)

1. Se ChallengeSolver falhar (sem Playwright, challenge mudou, CAPTCHA novo):
   - Mensagem clara no log orientando user a extrair cookies do browser
   - Instrucao de JS pra console: `document.cookie` 
2. Cookies colados no campo "Session Cookie" sao injetados via
   `ScanConfig.sessionCookie` -> `Http.send()` (ja funciona)
3. Adicionar deteccao especifica: se Vercel challenge nao resolveu,
   emitir INFO finding com instrucoes de cookie export
4. Na TUI e GUI: hint visual quando Vercel e detectado mas
   ChallengeSolver falha, sugerindo Session Cookie

### Ordem de execucao

```
Vercel detectado
  |
  v
ChallengeSolver.solve()
  |
  +-- sucesso --> setChallengeCookies() --> scan normal
  |
  +-- falha --> log instrucoes de cookie manual
              --> user cola cookies em Session Cookie
              --> Http.send() injeta --> scan normal
```

Ambos os approaches convergem pro mesmo ponto: `Http.send()` injeta
cookies de clearance em todo request.

---

## Arquivos a modificar

| Arquivo | Mudanca |
|---------|---------|
| `WafState.java` | Novo `VERCEL_CHALLENGE` em `WafBlockType`, threshold |
| `WafEvasion.java` | Vercel em `WAF_SERVER`, `WAF_BODY`, `SIGNATURES` |
| `ScanRunner.java` | Branch Vercel na Phase 1.5, fix post-scan finding |
| `ChallengeSolver.java` | Nenhuma (ja funciona) |
| `Http.java` | Nenhuma (cookie injection ja funciona) |
| `BrowserTransport.java` | Nenhuma (transport ja funciona) |
