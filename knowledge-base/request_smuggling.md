---
id: request_smuggling
title: "HTTP Request Smuggling"
module: "reqsmuggling"
severity: "CRITICAL"
cwe_id: "CWE-444"
cwe_title: "Inconsistent Interpretation of HTTP Requests ('HTTP Request Smuggling')"
cvss_vector: "AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H"
vrt_id: "server_security_misconfiguration.http_request_smuggling"
---

## Summary
Discordância entre proxy e backend na interpretação de `Content-Length` e `Transfer-Encoding` permite contrabandear requisições, sequestrar respostas, envenenar cache e bypassar autenticação.

## Description
Request smuggling explora parsers HTTP divergentes. O front-end (CDN/proxy) e o back-end podem interpretar de forma diferente headers ambíguos, fazendo com que parte de uma requisição seja tratada como o início da próxima. O ataque depende de uma fronteira de parser -- qualquer hop onde dois componentes discordam sobre onde uma mensagem termina e a próxima começa.

### Variantes clássicas (CL vs TE)

- **CL.TE:** front-end usa `Content-Length`, back-end usa `Transfer-Encoding: chunked`. Front-end repassa N bytes; back-end interpreta chunked e o restante vira próxima requisição.
- **TE.CL:** front-end usa `Transfer-Encoding`, back-end usa `Content-Length`. Front-end processa chunked completo; back-end lê apenas CL bytes e o excedente vaza.
- **TE.TE (ofuscação):** ambos usam TE, mas um não reconhece a ofuscação (`xchunked`, `chunked\t`, TE duplicado) e cai no fallback CL, criando desync.

### HTTP/2 downgrade

- **H2.CL:** edge HTTP/2 faz downgrade para HTTP/1.1 preservando `Content-Length` controlado pelo atacante. Se DATA length difere do CL gerado, backend processa bytes excedentes.
- **H2.TE:** edge HTTP/2 preserva `Transfer-Encoding` no downgrade para HTTP/1.1, criando ambiguidade CL vs TE no backend.
- **H2.0:** edge HTTP/2 faz downgrade e backend ignora o body (equivalente a CL.0 via HTTP/2).
- **HTTP/2 request splitting:** pseudo-headers (`:method`, `:path`) contendo `\r\n` injetam headers/requisições extras no HTTP/1.1 downstream.

### Body-ignoring

- **CL.0:** servidor responde antes de consumir o body prometido pelo CL. O body residual é tratado como próxima requisição na conexão reutilizada. Comum em endpoints que ignoram body (GET-like em POST).
- **0.CL:** requisição com `Content-Length: 0` seguida de body; front-end para no CL=0, backend lê o body.

### Dechunking e parser differentials

- **TE.0 / Dechunking:** proxy dechunka o body e remove `Transfer-Encoding` antes de repassar ao backend. Se o CL recalculado estiver errado, bytes excedentes vazam.
- **Chunked parser differentials:** front-end e backend discordam sobre onde o chunked body termina -- chunk extensions, terminadores malformados, ou trailers criam a divergência (variantes TERM.EXT, EXT.TERM, TERM.SPILL, SPILL.TERM).
- **Trailers boundary:** divergência na interpretação de trailers HTTP -- um hop processa, outro ignora, alterando o limite percebido do body.

### Browser e client-side

- **Client-side desync:** requisição compatível com browser provoca early response do servidor; browser reutiliza a conexão HTTP/1.1 e o body residual afeta a próxima requisição do próprio browser.
- **Browser-powered server-side desync:** similar ao client-side, mas o body residual afeta a fila do servidor, impactando outros usuários.
- **Pause-based desync:** atacante envia headers completos mas atrasa o body. Proxy repassa headers imediatamente; backend, com timeout diferente, processa o body atrasado como nova requisição.

### Connection state

- **Connection-locked smuggling:** smuggling que só funciona em conexões persistentes onde o frontend "trava" estado de roteamento/autenticação após a primeira requisição.
- **Connection state attack:** frontend lembra Host, SNI, auth ou roteamento de requisição anterior na mesma conexão; requisição subsequente herda estado indevido.
- **Response queue poisoning:** atacante desalinha a fila de respostas -- a resposta destinada a ele é entregue ao próximo usuário (e vice-versa), permitindo roubo de sessão.
- **Request tunnelling:** smuggling dentro de uma única conexão front-end/backend, onde a requisição smuggled não atinge outros usuários mas permite acessar headers internos e endpoints ocultos.

### Protocol transition

- **h2c cleartext upgrade smuggling:** proxy aceita `Upgrade: h2c` e repassa ao backend; se o backend interpreta como HTTP/2 cleartext, rotas bloqueadas via HTTP/1.1 ficam acessíveis.
- **Upgrade / CONNECT optimistic transition:** proxy inicia tunnel otimisticamente antes de confirmar a resposta do backend; atacante injeta bytes no tunnel nascente.
- **HTTP/1.0 + Transfer-Encoding:** backend HTTP/1.0 legacy que ignora TE (não definido em HTTP/1.0) e usa CL; front-end moderno processa TE.
- **RFC 2817 / Opportunistic TLS desync:** requisição `Upgrade: TLS/1.0` (RFC 2817) cria transição de protocolo que proxy e backend interpretam diferentemente, permitindo smuggling no boundary plaintext/TLS.

### Impact chains (requerem root desync)

- **Cache poisoning desync chain:** requisição smuggled envenena cache CDN; resposta maliciosa é servida a outros usuários via cache HIT. Requer disposable cache key e plano de purge.
- **WAF / ACL bypass via parser discrepancy:** WAF analisa uma interpretação da requisição, backend processa outra; payloads bloqueados pelo WAF passam.
- **Host routing / virtual host desync:** Host header da requisição smuggled aponta para virtual host diferente, acessando aplicações internas no mesmo servidor.

### HTTP/3

- **HTTP/3 to HTTP/1 boundary:** edge HTTP/3 (QUIC) converte para HTTP/1.1 ao repassar para origin; a conversão pode criar ambiguidades similares a H2.CL/H2.TE.
- **HTTP/3 connection contamination:** connection coalescing em HTTP/3 permite que estado de authority de uma requisição contamine streams subsequentes na mesma conexão, afetando sibling authorities.

### Outras técnicas

- **TRACE-assisted desync gadget:** TRACE habilitado reflete headers internos adicionados pelo proxy; combinado com request tunnelling, revela second response oculta e headers sensíveis.
- **Hop-by-hop header confusion:** `Connection: Transfer-Encoding` instrui proxy intermediário a remover TE antes de repassar; backend recebe requisição sem TE e usa CL.
- **Expect: 100-Continue desync:** divergência no handling de `Expect: 100-continue` entre hops; um envia `100 Continue` e espera body, outro segue sem body.
- **Duplicate Content-Length:** dois headers CL com valores diferentes; front-end usa o primeiro, backend usa o segundo (ou vice-versa), criando desync.
- **Invalid Content-Length:** CL negativo, hexadecimal, com prefixo de espaço ou overflow; parser leniente aceita, parser estrito rejeita.

Consequências incluem bypass de autenticação, acesso a endpoints internos, roubo de sessão, XSS em cache e DoS.

## Impact
- Sequestro de requisições/respostas de outros usuários e roubo de sessão.
- Bypass de controles de acesso e WAF.
- Envenenamento de cache com conteúdo malicioso.
- Acesso a endpoints internos e administrativos.
- Negação de serviço e corrupção de filas.
- Impacto CRITICAL.

## Payloads and Bypasses
```http
# CL.TE
POST / HTTP/1.1
Host: alvo.com
Content-Length: 13
Transfer-Encoding: chunked

0

SMUGGLED
```

```http
# TE.CL
POST / HTTP/1.1
Host: alvo.com
Content-Length: 3
Transfer-Encoding: chunked

8
SMUGGLED
0


```

```http
# TE.TE com ofuscação
POST / HTTP/1.1
Host: alvo.com
Content-Length: 4
Transfer-Encoding: chunked
Transfer-Encoding: x

5c
GPOST / HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 15

x=1
0


```

Variações de ofuscação de `Transfer-Encoding`:
```text
Transfer-Encoding: chunked
Transfer-Encoding : chunked
Transfer-Encoding:\tchunked
Transfer-encoding: chunked
Transfer-Encoding: xchunked
Transfer-Encoding: chunked, identity
Transfer-Encoding: identity, chunked
Transfer-Encoding: chunked\r\nTransfer-Encoding: x
X: X
```

```http
# H2.CL / H2.TE (pseudo-headers)
:method: POST
:path: /
:authority: alvo.com
content-length: 0
transfer-encoding: chunked

0

SMUGGLED
```

```http
# CL.0
POST / HTTP/1.1
Host: alvo.com
Content-Length: 34

GET /admin HTTP/1.1
Host: alvo.com
```

```http
# Duplicate Content-Length
POST / HTTP/1.1
Host: alvo.com
Content-Length: 6
Content-Length: 34

GET /admin HTTP/1.1
Host: alvo.com
```

```http
# TE.0 / Dechunking -- proxy dechunka e remove TE; backend recebe CL errado
POST / HTTP/1.1
Host: alvo.com
Transfer-Encoding: chunked

1
Z
0

GET /admin HTTP/1.1
Host: alvo.com


```

```http
# Hop-by-hop TE confusion -- proxy intermediario remove TE
POST / HTTP/1.1
Host: alvo.com
Content-Length: 34
Connection: Transfer-Encoding
Transfer-Encoding: chunked

GET /admin HTTP/1.1
Host: alvo.com
```

```http
# h2c Upgrade smuggling
GET / HTTP/1.1
Host: alvo.com
Upgrade: h2c
HTTP2-Settings: AAMAAABkAAQCAAAAAAIAAAAA
Connection: Upgrade, HTTP2-Settings
```

```http
# Chunked parser differentials -- chunk extension
POST / HTTP/1.1
Host: alvo.com
Transfer-Encoding: chunked

2;ext=val
AB
0

```

```http
# Chunked parser differentials -- terminador malformado
POST / HTTP/1.1
Host: alvo.com
Transfer-Encoding: chunked

2
AB
0
X: ignored

GET /admin HTTP/1.1
Host: alvo.com


```

```text
# Pause-based desync -- enviar headers completos, atrasar body
# Passo 1: enviar headers + CL indicando body
POST / HTTP/1.1\r\nHost: alvo.com\r\nContent-Length: 34\r\n\r\n
# Passo 2: aguardar ~5s (proxy repassa headers, backend espera body)
# Passo 3: enviar body com requisicao smuggled
GET /admin HTTP/1.1\r\nHost: alvo.com\r\n\r\n
```

Bypasses e testes:
```text
- Prefixos de proxy: /, //, /./, /%2e/
- Diferentes versões HTTP/1.0 e HTTP/1.1
- Headers duplicados e ordem
- Espaços/tabs antes dos dois-pontos
- Body com chunk extensions e trailers
- Requisições pipelined para detectar fila
- Timing e resposta divergente entre front/back
- Content-Length negativo, hex, overflow, vazio
- Transfer-Encoding com espaços antes/depois do valor
- Connection: Transfer-Encoding (hop-by-hop removal)
- Upgrade: h2c em rotas protegidas
- HTTP/1.0 com Transfer-Encoding (backend legacy ignora TE)
- TRACE habilitado para revelar headers internos
- Expect: 100-Continue com body atrasado
```

Ferramentas:
```bash
# Burp Suite: HTTP Request Smuggler (extensao)
# Turbo Intruder (pause-based, timing probes)
# smuggler.py
python3 smuggler.py -u https://alvo.com
# h2csmuggler (Bishop Fox)
python3 h2csmuggler.py -x https://proxy.alvo.com http://backend-interno/admin
```

## Real-World Cases

### Pesquisa PortSwigger -- a linhagem

A pesquisa moderna de request smuggling foi sistematizada pelo PortSwigger Research em uma série de publicações que expandiu drasticamente a superficie de ataque conhecida:

| Ano | Publicação | Técnicas introduzidas |
|-----|------------|----------------------|
| 2019 | **HTTP Desync Attacks: Request Smuggling Reborn** | Reviveu CL.TE/TE.CL com metodologia timing-based; demonstrou impacto em produção |
| 2021 | **HTTP/2: The Sequel Is Always Worse** | H2.CL, H2.TE, H2.0; request splitting via pseudo-headers; tunnelling |
| 2022 | **Browser-Powered Desync Attacks** | Client-side desync, browser-powered server-side desync, CL.0 no browser |
| 2025 | **HTTP/1.1 Must Die** | TE.0/dechunking, TRACE-assisted desync, chunked parser differentials, h2c smuggling, HTTP/3 connection contamination |

**Refs:**
- [Desync Reborn](https://portswigger.net/research/http-desync-attacks-request-smuggling-reborn)
- [HTTP/2: The Sequel](https://portswigger.net/research/http2)
- [Browser-Powered](https://portswigger.net/research/browser-powered-desync-attacks)
- [HTTP/1.1 Must Die](https://portswigger.net/research/http1-must-die)

### Cloudflare Pingora (2025) -- cache poisoning via smuggling

Vulnerabilidade de request smuggling no proxy Pingora (Rust) da Cloudflare. Parser HTTP divergente entre Pingora e backend permitia cache poisoning -- resposta envenenada era servida a outros usuários via CDN cache. Corrigido no Pingora.

**Ref:** [Resolving a request smuggling vulnerability in Pingora](https://blog.cloudflare.com/resolving-a-request-smuggling-vulnerability-in-pingora/)

### Cloudflare Pingora OSS (2026) -- HTTP/1 Upgrade + TE

Segunda rodada de vulnerabilidades no Pingora OSS: handling incorreto de `Upgrade` em HTTP/1.1 e edge cases de `Transfer-Encoding` permitiam smuggling em deployments self-hosted.

**Ref:** [Fixing request smuggling vulnerabilities in Pingora OSS deployments](https://blog.cloudflare.com/pingora-oss-smuggling-vulnerabilities/)

### HAProxy CVE-2021-40346 -- duplicate Content-Length

HAProxy aceitava dois headers `Content-Length` com valores diferentes. Front-end usava o primeiro valor; backend usava o segundo. Corrigido em setembro 2021.

**Ref:** [HAProxy September 2021 -- Duplicate Content-Length Header Fixed](https://www.haproxy.com/blog/september-2021-duplicate-content-length-header-fixed)

### HAProxy CVE-2023-25725 -- header parser TE confusion

Parser de headers do HAProxy não rejeitava certas formas de `Transfer-Encoding` malformado. Backend interpretava diferente do HAProxy, criando desync.

**Ref:** [HAProxy February 2023 -- Header Parser Fixed](https://www.haproxy.com/blog/february-2023-header-parser-fixed)

### HAProxy CVE-2023-40225 -- empty Content-Length

Header `Content-Length` vazio (sem valor) era aceito pelo HAProxy. Backend interpretava como CL=0 ou ignorava, dependendo do parser -- desync.

**Ref:** [HAProxy August 2023 -- Empty Content-Length Header Vulnerability Fixed](https://www.haproxy.com/blog/august-2023-cve-2023-40225-empty-content-length-header-vulnerability-fixed)

### Akamai CVE-2025-32094 -- OPTIONS + obsolete line folding

Request smuggling via método OPTIONS combinado com obsolete line folding (obs-fold) nos headers. Akamai edge processava o fold diferente do backend, criando parser differential.

**Ref:** [CVE-2025-32094: HTTP Request Smuggling Via OPTIONS + Obsolete Line Folding](https://www.akamai.com/blog/security/cve-2025-32094-http-request-smuggling)

### Akamai CVE-2026-26365 -- Connection: Transfer-Encoding

Hop-by-hop header confusion: header `Connection: Transfer-Encoding` instruía proxy intermediário a remover TE. Backend recebia requisição sem TE e fallback para CL, criando desync.

**Ref:** [CVE-2026-26365: Connection: Transfer-Encoding](https://www.akamai.com/blog/security-research/cve-2026-26365-incorrect-processing-connection-transfer-encoding)

### Google Cloud TE.0 (Bugcrowd) -- dechunking smuggling

TE.0 request smuggling afetando milhares de sites no Google Cloud. Edge dechunkava e removia `Transfer-Encoding` antes de repassar; `Content-Length` recalculado incorretamente permitia smuggling.

**Ref:** [Unveiling TE.0 HTTP Request Smuggling](https://www.bugcrowd.com/blog/unveiling-te-0-http-request-smuggling-discovering-a-critical-vulnerability-in-thousands-of-google-cloud-websites/)

### Funky Chunks (w4ke, 2025) -- chunked parser differentials

Pesquisa demonstrando divergências de parser em chunk extensions, terminadores e trailers. Variantes TERM.EXT, EXT.TERM, TERM.SPILL e SPILL.TERM exploram diferenças na interpretação de onde o chunked body termina.

**Refs:**
- [Funky chunks: abusing ambiguous chunked parsing](https://w4ke.info/2025/06/18/funky-chunks.html)
- [Funky chunks addendum: trailer and terminator variants](https://w4ke.info/2025/10/29/funky-chunks-2.html)

### HAProxy CVE-2019-18277 -- Transfer-Encoding smuggling

Smuggling via `Transfer-Encoding` malformado (TE com espaços, `\x0b`, `\x0c` antes de "chunked"). HAProxy não reconhecia como chunked, backend (Apache/Nginx) sim.

**Ref:** [HAProxy HTTP request smuggling CVE-2019-18277](https://nathandavison.com/blog/haproxy-http-request-smuggling)

### Comparação dos casos

| Caso | Técnica raiz | Impacto |
|------|-------------|---------|
| Pingora 2025 | Parser differential | Cache poisoning via CDN |
| Pingora OSS 2026 | Upgrade + TE handling | Smuggling em self-hosted |
| HAProxy CVE-2021-40346 | Duplicate CL | Desync CL.CL |
| HAProxy CVE-2023-25725 | TE parser confusion | Desync TE.CL |
| HAProxy CVE-2023-40225 | Empty CL | Desync CL.0 |
| Akamai CVE-2025-32094 | OPTIONS + obs-fold | Parser discrepancy |
| Akamai CVE-2026-26365 | Hop-by-hop TE removal | Desync CL (sem TE) |
| Google Cloud TE.0 | Dechunking CL mismatch | Smuggling em massa |

## Detection

### Metodologia de detecção

Detectar request smuggling requer identificar a fronteira de parser (proxy/CDN/origin) e testar divergência de interpretação.

### 1. Hipótese de arquitetura

Identificar a cadeia de componentes entre o cliente e o backend:
```text
Cliente -> CDN (Cloudflare/Akamai/Fastly) -> Proxy reverso (Nginx/HAProxy/Envoy) -> Backend (app)
```
Cada transição de hop é uma fronteira de parser candidata. Coletar evidências: headers `Server`, `Via`, `X-Cache`, `X-Served-By`, `X-Forwarded-For`, fingerprinting de respostas de erro.

### 2. Baseline validation

Enviar requisição normal e medir round-trip time. O baseline confirma que o servidor responde em tempo razoável e que timeouts observados nos probes são anomalias.

### 3. Timing differential

Probe: enviar requisição ambígua (CL+TE, TE ofuscado, CL.0) e medir tempo de resposta. Se o probe excede significativamente o baseline, indica que um hop está "segurando" a conexão esperando dados que o outro hop já considerou entregues.

### 4. Response counting

Enviar uma única requisição com body que contenha uma segunda requisição embutida. Se o servidor retorna duas respostas HTTP (dois `HTTP/` headers), o body foi interpretado como nova requisição (CL.0, 0.CL).

### 5. Response queue shift

Enviar probe smuggled seguido de requisição normal. Se a resposta da requisição normal não corresponde ao esperado (response de outra requisição), indica response queue poisoning.

### 6. Cache behavior

Monitorar headers `Age`, `X-Cache` (HIT/MISS), `Cache-Control`. Se uma requisição normal retorna conteúdo envenenado com `X-Cache: HIT`, indica cache poisoning via desync.

### 7. Controles de falso positivo

- **Single-parser direct path:** se a requisição vai direto ao backend (sem proxy), timeout pode ser comportamento normal, não desync.
- **Scanner-only artifact:** scanners automatizados podem gerar artefatos que parecem desync mas são pipelining normal.
- **Pipelining confusion:** HTTP pipelining legítimo (múltiplas requisições na mesma conexão) pode ser confundido com queue poisoning. Distinguir: pipelining é controlado pelo cliente; queue poisoning afeta requisições de outros clientes.
- **Servidor fecha conexão:** se o servidor fecha a conexão após o probe (sem keep-alive), não há desync -- o body residual é descartado.

## Target Context (Crawler Hints)
- **Parâmetros comuns:** headers `Content-Length`, `Transfer-Encoding`, `Connection`, `Host`, `X-Forwarded-*`; body POST.
- **Paths comuns:** qualquer endpoint atrás de proxy/CDN, especialmente `/`, `/login`, `/api/*`, `/graphql`, `/admin`.
- **Sinais:** respostas 400/501 inconsistentes; `Age`/`X-Cache`; proxy/backend diferentes; conexões keep-alive reutilizadas; comportamento divergente com TE ofuscado.

## Escalation Techniques
Request smuggling e uma primitiva de ataque poderosa -- o desync em si nao e o objetivo, mas sim o que ele permite:

- **Hijack de sessao via response queue poisoning:** apos desalinhar a fila de respostas, a resposta destinada a vitima (contendo Set-Cookie, tokens, dados) e entregue ao atacante, e vice-versa. Permite account takeover sem interacao da vitima.
- **Bypass de WAF e ACL:** o WAF analisa uma interpretacao da requisicao, o backend processa outra. Payloads de SQLi, XSS ou command injection bloqueados pelo WAF passam na requisicao smuggled.
- **Cache poisoning via desync:** requisicao smuggled envenena cache CDN com conteudo malicioso (XSS, redirect). A resposta envenenada e servida a todos os usuarios que acessam o path via cache HIT -- impacto massivo.
- **Acesso a endpoints internos:** requisicao smuggled com `Host: internal-app.local` ou path `/admin` acessa virtual hosts e rotas internas que nao sao expostos ao frontend.
- **Roubo de headers internos via TRACE:** se TRACE esta habilitado, request tunnelling combinado com TRACE revela headers adicionados pelo proxy (ex: `X-Forwarded-For`, `X-Real-IP`, tokens internos).
- **Bypass de autenticacao:** frontend adiciona headers de autenticacao/autorizacao; requisicao smuggled bypassa o frontend e atinge o backend sem esses headers, ou com headers controlados pelo atacante.
- **Encadeamento com XSS stored via cache:** desync que envenena cache com XSS refletido transforma um XSS refletido em stored, afetando todos os usuarios do path.
- **Client-side desync para ataques direcionados:** desync compativel com browser permite atacar um usuario especifico sem necessidade de acesso ao servidor -- apenas induzindo a vitima a visitar pagina controlada pelo atacante.

A mentalidade geral do livro Bug Bounty Bootcamp (Cap. 1-5) se aplica: ao encontrar um desync, o proximo passo e sempre encadear com outros bugs para maximizar impacto. Um CL.TE sozinho e tecnico; CL.TE + cache poisoning + XSS e CRITICAL.

## Hunting Methodology
Processo passo a passo para identificar request smuggling:

1. **Mapear a arquitetura:** identificar a cadeia de componentes (CDN, proxy reverso, backend). Coletar evidencias via headers `Server`, `Via`, `X-Cache`, `X-Served-By`, fingerprinting de paginas de erro. Cada transicao de hop e uma fronteira de parser candidata.
2. **Estabelecer baseline:** enviar requisicao normal e medir round-trip time. O baseline confirma que o servidor responde em tempo razoavel e que timeouts nos probes sao anomalias reais.
3. **Testar timing differential (CL.TE):** enviar requisicao com `Content-Length` e `Transfer-Encoding: chunked` simultaneos, onde o chunked body termina prematuramente. Se o backend usa TE e espera mais dados, o timeout sera significativamente maior que o baseline.
4. **Testar timing differential (TE.CL):** inverter -- `Content-Length` curto e chunked body completo. Se o backend usa CL e ignora o restante, a resposta e rapida; se o frontend usa TE, o timing diverge.
5. **Testar ofuscacao de TE:** experimentar variantes como `Transfer-Encoding: xchunked`, `Transfer-Encoding:	chunked`, TE duplicado, `Transfer-Encoding: chunked, identity`. Parsers diferentes reagem de forma diferente a ofuscacao.
6. **Testar CL.0:** enviar POST com `Content-Length` valido em endpoint que ignora body (GET-like). Se o body residual e tratado como proxima requisicao na conexao reutilizada, ha desync.
7. **Testar H2.CL e H2.TE:** se o frontend aceita HTTP/2, testar smuggling via downgrade -- manipular pseudo-headers e `content-length`/`transfer-encoding` no frame HTTP/2.
8. **Response counting:** enviar unica requisicao com body contendo segunda requisicao embutida. Se o servidor retorna duas respostas HTTP, ha desync confirmado.
9. **Verificar impacto:** apos confirmar desync, testar response queue poisoning, cache poisoning e acesso a endpoints internos para determinar severidade real.
10. **Automatizar com ferramentas:** usar HTTP Request Smuggler (Burp), Turbo Intruder para timing probes, e h2cSmuggler para h2c upgrade. A abordagem de fuzzing (Cap. 25 do livro) se aplica -- gerar probes automaticamente e monitorar anomalias de timing/resposta.

## False Positive Indicators
Sinais de que o probe de smuggling do scanner **nao indica desync real**:

- **Path direto ao backend (sem proxy):** se a requisicao vai direto ao backend sem passar por proxy/CDN, timeouts podem ser comportamento normal do servidor, nao desync. Verificar a presenca de intermediarios antes de reportar.
- **Servidor fecha conexao (no keep-alive):** se o servidor fecha a conexao apos cada resposta (`Connection: close`), o body residual e descartado e nao ha desync. Smuggling requer conexoes persistentes.
- **Pipelining normal confundido com queue poisoning:** HTTP pipelining legitimo (multiplas requisicoes na mesma conexao pelo mesmo cliente) pode parecer queue poisoning. Distinguir: pipelining e controlado pelo cliente; queue poisoning afeta requisicoes de outros clientes.
- **Artefato do scanner:** scanners automatizados podem gerar pipelining ou respostas multiplas que parecem desync mas sao comportamento normal do protocolo HTTP/1.1. Validar manualmente com probe isolado.
- **Timeout por lentidao do servidor:** servidor com alta latencia ou rate limiting pode causar timeouts que parecem timing differential. Comparar com baseline em horarios diferentes.
- **Backend rejeita CL+TE simultaneo (RFC 7230 compliant):** se o backend retorna 400 para requisicoes com ambos os headers, o servidor esta implementando a RFC corretamente e nao e vulneravel.
- **Edge strip de Transfer-Encoding:** se o CDN/proxy remove `Transfer-Encoding` antes de repassar ao backend, as variantes CL.TE e TE.CL nao se aplicam -- o backend recebe apenas `Content-Length`.


## Recommendation
1. Usar HTTP/2 de ponta a ponta e rejeitar downgrades ambíguos; se houver conversão H2→H1, normalizar headers.
2. Rejeitar requisições com `Content-Length` e `Transfer-Encoding` simultâneos, ou com TE duplicado/ofuscado.
3. Configurar proxy e backend com o mesmo parser e versão; nunca confiar em bibliotecas divergentes.
4. Desabilitar reuso de conexão entre usuários diferentes em caso de dúvida; usar conexões isoladas por request.
5. Aplicar limites de tamanho, timeout e número de chunks; rejeitar chunk extensions desconhecidas.
6. Atualizar CDN, proxy reverso, servidor web e framework; muitas variantes são corrigidas em versões recentes.
7. Bloquear métodos/headers anômalos no WAF como defesa em profundidade, sem depender dele.
8. Monitorar respostas 400/501, filas anormais e requisições com TE ofuscado; alertar sobre picos.
9. Exemplo Nginx:
```nginx
# Rejeitar TE + CL e TE duplicado
if ($http_transfer_encoding ~* "chunked") { set $te 1; }
if ($http_content_length != "") { set $cl 1; }
if ($te$cl = "11") { return 400; }
```
10. Validar a correção com testes de regressão usando Burp Smuggler e monitoramento de fila.

## References

### Pesquisa

- [HTTP Desync Attacks: Request Smuggling Reborn](https://portswigger.net/research/http-desync-attacks-request-smuggling-reborn) -- PortSwigger, 2019
- [HTTP/2: The Sequel Is Always Worse](https://portswigger.net/research/http2) -- PortSwigger, 2021
- [Browser-Powered Desync Attacks](https://portswigger.net/research/browser-powered-desync-attacks) -- PortSwigger, 2022
- [HTTP/1.1 must die: the desync endgame](https://portswigger.net/research/http1-must-die) -- PortSwigger, 2025
- [TRACE desync attack](https://portswigger.net/research/trace-desync-attack) -- PortSwigger
- [HTTP/3 connection contamination](https://portswigger.net/research/http-3-connection-contamination) -- PortSwigger
- [Beware the false false-positive](https://portswigger.net/research/how-to-distinguish-http-pipelining-from-request-smuggling) -- PortSwigger
- [HTTP Request Smuggling original paper](https://www.cgisecurity.com/lib/HTTP-Request-Smuggling.pdf) -- Watchfire, 2005
- [Funky chunks: abusing ambiguous chunked parsing](https://w4ke.info/2025/06/18/funky-chunks.html) -- w4ke, 2025
- [Funky chunks addendum](https://w4ke.info/2025/10/29/funky-chunks-2.html) -- w4ke, 2025

### Academico

- [WAFFLED: Exploiting Parsing Discrepancies to Bypass Web Application Firewalls](https://arxiv.org/abs/2503.10846) -- arXiv, 2025
- [HTTP Request Synchronization Defeats Discrepancy Attacks](https://arxiv.org/abs/2510.09952) -- arXiv, 2025
- [A hands-on gaze on HTTP/3 security](https://arxiv.org/abs/2208.06722) -- arXiv, 2022
- [Opossum attack on opportunistic TLS upgrade handling](https://www.usenix.org/conference/usenixsecurity26/presentation/merget) -- USENIX Security, 2026

### Standards

- [CWE-444: Inconsistent Interpretation of HTTP Requests](https://cwe.mitre.org/data/definitions/444.html) -- MITRE
- [RFC 9110 -- HTTP Semantics](https://www.rfc-editor.org/rfc/rfc9110) -- IETF
- [RFC 9112 -- HTTP/1.1](https://www.rfc-editor.org/rfc/rfc9112) -- IETF
- [RFC 9113 -- HTTP/2](https://www.rfc-editor.org/rfc/rfc9113) -- IETF
- [RFC 9114 -- HTTP/3](https://www.rfc-editor.org/rfc/rfc9114) -- IETF
- [RFC 9931 -- Security Considerations for Optimistic Protocol Transitions in HTTP/1.1](https://www.rfc-editor.org/rfc/rfc9931) -- IETF
- [RFC 2817 -- Upgrading to TLS Within HTTP/1.1](https://www.rfc-editor.org/rfc/rfc2817) -- IETF

### Vendor advisories

- [Resolving a request smuggling vulnerability in Pingora](https://blog.cloudflare.com/resolving-a-request-smuggling-vulnerability-in-pingora/) -- Cloudflare, 2025
- [Fixing request smuggling vulnerabilities in Pingora OSS](https://blog.cloudflare.com/pingora-oss-smuggling-vulnerabilities/) -- Cloudflare, 2026
- [HAProxy: Duplicate Content-Length Fixed](https://www.haproxy.com/blog/september-2021-duplicate-content-length-header-fixed) -- HAProxy, 2021
- [HAProxy: Header Parser Fixed](https://www.haproxy.com/blog/february-2023-header-parser-fixed) -- HAProxy, 2023
- [HAProxy: Empty Content-Length Vulnerability Fixed](https://www.haproxy.com/blog/august-2023-cve-2023-40225-empty-content-length-header-vulnerability-fixed) -- HAProxy, 2023
- [HAProxy HTTP request smuggling CVE-2019-18277](https://nathandavison.com/blog/haproxy-http-request-smuggling) -- Nathan Davison, 2019
- [CVE-2025-32094: HTTP Request Smuggling Via OPTIONS](https://www.akamai.com/blog/security/cve-2025-32094-http-request-smuggling) -- Akamai, 2025
- [CVE-2026-26365: Connection: Transfer-Encoding](https://www.akamai.com/blog/security-research/cve-2026-26365-incorrect-processing-connection-transfer-encoding) -- Akamai, 2026
- [Akamai HTTP/2 Request Smuggling](https://www.akamai.com/blog/security/http-2-request-smuggling) -- Akamai
- [Akamai: Browser-Powered Desync Attacks](https://www.akamai.com/blog/security/akamai-has-addressed-browser-powered-desync-attacks) -- Akamai

### OWASP e testing guides

- [PortSwigger Web Security Academy -- HTTP request smuggling](https://portswigger.net/web-security/request-smuggling) -- PortSwigger
- [OWASP WSTG -- Testing for HTTP Request Smuggling](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/16-Testing_for_HTTP_Request_Smuggling) -- OWASP
- [Unveiling TE.0 HTTP Request Smuggling](https://www.bugcrowd.com/blog/unveiling-te-0-http-request-smuggling-discovering-a-critical-vulnerability-in-thousands-of-google-cloud-websites/) -- Bugcrowd

### Tooling

- [HTTP Request Smuggler](https://github.com/PortSwigger/http-request-smuggler) -- PortSwigger (Burp extension)
- [Turbo Intruder](https://github.com/PortSwigger/turbo-intruder) -- PortSwigger (pause-based, timing probes)
- [h2cSmuggler](https://bishopfox.com/tools/h2c-smuggling) -- Bishop Fox
