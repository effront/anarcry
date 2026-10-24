```
 █████╗ ███╗   ██╗ █████╗ ██████╗  ██████╗██████╗ ██╗   ██╗
██╔══██╗████╗  ██║██╔══██╗██╔══██╗██╔════╝██╔══██╗╚██╗ ██╔╝
███████║██╔██╗ ██║███████║██████╔╝██║     ██████╔╝ ╚████╔╝
██╔══██║██║╚██╗██║██╔══██║██╔══██╗██║     ██╔══██╗  ╚██╔╝
██║  ██║██║ ╚████║██║  ██║██║  ██║╚██████╗██║  ██║   ██║
╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝   ╚═╝
              Bug Bounty Security Scanner — effront
```

<div align="center">

[![Java Version](https://img.shields.io/badge/java-27-ED8B00?logo=openjdk)](https://openjdk.org/projects/jdk/27/)
[![Gradle](https://img.shields.io/badge/gradle-9.x-02303A?logo=gradle)](https://gradle.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

[![Lint](https://github.com/effront/anarcry/actions/workflows/lint.yml/badge.svg)](https://github.com/effront/anarcry/actions/workflows/lint.yml)
[![Security Scan](https://github.com/effront/anarcry/actions/workflows/security-scan.yml/badge.svg)](https://github.com/effront/anarcry/actions/workflows/security-scan.yml)
[![Spotless](https://img.shields.io/badge/code%20style-eclipse%20JDT-4CAF50)](https://github.com/diffplug/spotless)
[![Checkstyle](https://img.shields.io/badge/checkstyle-10.21.4-blue)](https://checkstyle.org/)
[![PMD](https://img.shields.io/badge/PMD-7.13.0-orange)](https://pmd.github.io/)
[![SpotBugs](https://img.shields.io/badge/SpotBugs%20+%20FindSecBugs-4.9.3-red)](https://spotbugs.github.io/)
[![Semgrep](https://img.shields.io/badge/semgrep-auto-blueviolet)](https://semgrep.dev/)

</div>

---

```
╔══════════════════════════════════════════════════════════════════════════════╗
║  ANARCRY — Java 27 Security Scanner                                          ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  Scanner TUI para bug bounty. 19 módulos de ataque, CVSS v3.1 automático,    ║
║  export direto para HackerOne e Bugcrowd. Crypto-first + OWASP Top 10.       ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

---

<details>
<summary><kbd>▶ Módulos (click to expand)</kbd></summary>

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  CRIPTOGRAFIA                                                               │
│  [■] TLS             — versão, cipher suites fracas, cert expirado, SHA-1   │
│  [■] Headers         — HSTS, CSP unsafe-inline/*, cookies, CORP/CORB        │
│  [■] JWT             — alg:none, RS256→HS256, JWK injection, kid SQLi       │
│  [■] PQC             — X25519MLKEM768, TLS 1.3, grupos pós-quânticos NIST   │
│                                                                             │
│  WEB (OWASP)                                                                │
│  [■] CORS            — origin reflection + credentials, wildcard, null      │
│  [■] OAuth           — state CSRF, redirect_uri bypass, .well-known         │
│  [■] OpenRedirect    — url/redirect/next/return/dest parameters             │
│  [■] SSRF            — URLs aceitas, bypass @/IP decimal/169.254.169.254    │
│                         Phase 3: open-redirect relay bypass (WAF evasion)   │
│  [■] GraphQL         — introspection, field suggestions, batching DoS       │
│  [■] CRLF            — header injection via \r\n                            │
│  [■] XXE             — external entity, SSRF via XXE, blind XXE             │
│  [■] SSTI            — FreeMarker, Jinja2, Velocity, Thymeleaf              │
│  [■] IDOR            — cross-user, DELETE/PATCH tampering, UUID probing     │
│  [■] HostHeader      — Host injection, cache poisoning via X-Forwarded-Host │
│  [■] Actuator        — Spring Boot /env /heapdump /mappings /beans          │
│  [■] MassAssign      — JSON mass assignment em endpoints REST               │
│  [■] CachePoisoning  — headers não-keyed refletidos e cacheados             │
│  [■] ReqSmuggling    — CL.TE e TE.CL HTTP request smuggling                 │
│  [ ] Infra           — port scan 21 portas + fingerprint SSH/Redis/Docker/  │
│                         Elasticsearch/Kibana/Coolify/Portainer/Prometheus   │
│                         nmap integrado (-sV; -sS -O quando root)            │
└─────────────────────────────────────────────────────────────────────────────┘
```

</details>

---

## Table of Contents

```
┌──────────────────────────────────────────────────────┐
│  01 · Quick Start                                    │
│  02 · Technology Stack                               │
│  03 · Export Formats                                 │
│  04 · Findings                                       │
│  05 · Interface TUI                                  │
│  06 · Testing                                        │
│  07 · Architecture                                   │
│  08 · Roadmap                                        │
└──────────────────────────────────────────────────────┘
```

---

## 01 · Quick Start

```bash
./gradlew shadowJar
java -jar build/libs/anarcry-1.0.jar
```

Sem TUI, exportando direto:

```bash
java -jar build/libs/anarcry-1.0.jar \
  --url https://alvo.com \
  --jwt eyJ... \
  --export h1 \
  --program nome-do-programa
```

---

## 02 · Technology Stack

```
╔══════════════════════╦════════════════════════════════════════════════════╗
║  LAYER               ║  TECHNOLOGY                                        ║
╠══════════════════════╬════════════════════════════════════════════════════╣
║  Language            ║  Java 27 (Azul Zulu 27+)                           ║
║  PQC                 ║  ML-KEM / ML-DSA nativos via JEP 496/497           ║
║  Build               ║  Gradle 9.x + Shadow plugin (fat JAR)              ║
║  TUI                 ║  Lanterna 3                                        ║
║  Crypto              ║  Bouncy Castle (cipher suites, TLS low-level)      ║
║  HTTP Client         ║  java.net.http.HttpClient (Java 11+)               ║
║  JSON                ║  Gson                                              ║
║  CVSS                ║  CvssCalculator.java (fórmula FIRST, sem deps)     ║
║  CWE                 ║  CweRegistry.java (24 entradas mapeadas)           ║
╚══════════════════════╩════════════════════════════════════════════════════╝
```

---

## 03 · Export Formats

| Formato | Como usar | Destino |
|---|---|---|
| Markdown | `[E]` no TUI ou `--export md` | Relatório interno |
| JSON | `--export json` | Burp / scripts externos |
| HackerOne | `--export h1 --program nome` | Submission H1 |
| Bugcrowd | `--export bugcrowd` | Submission Bugcrowd |

---

## 04 · Findings

Cada finding inclui CVSS v3.1 Base Score (fórmula FIRST, calculado localmente), CWE ID mapeado por módulo, evidência com body snippet, passo-a-passo de reprodução com `curl` e recomendação.

Exemplo exportado para HackerOne:

```
# [CRITICAL] JWT — Algorithm None Accepted

**Program:** acme-bounty
**Asset:** https://api.alvo.com
**Severity:** Critical (CVSS 9.1 — AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N)
**Weakness:** CWE-347 — Improper Verification of Cryptographic Signature
**Reported:** 2026-10-24

## Summary
Servidor aceita tokens JWT com alg:none, permitindo bypass total de autenticação.

## Steps to Reproduce
```
curl -H "Authorization: Bearer eyJhbGciOiJub25lIn0.eyJzdWIiOiIxIn0." \
     https://api.alvo.com/api/me
```
```

---

## 05 · Interface TUI

7 modos navegáveis por F-key. ModeBar com tabs coloridas (ativo = amarelo). StatusBar com contadores de severidade e barra de progresso por módulo.

```
 F1 Dashboard  F2 Scan ▶  F3 Target  F4 Findings(4)  F5 Repeater  F6 Relatório  F7 Site Map
┌──────────────┬──────────────────────────────────────────────────────────────────────────┐
│ MODULOS      │ OUTPUT / LOG  scroll:↑↓ PgUp/Dn                                          │
│              │                                                                          │
│ [x] TLS      │  [*] Módulo JWT iniciado                                                 │
│ [x] Headers  │  [!!] alg:none aceito — CRITICAL                                         │
│ [x] JWT      │  [!!] RS256→HS256 confusion — CRITICAL                                   │
│ [x] PQC      │  [!] JWK injection — HIGH                                                │
│ [x] CORS     │  [+] JWT: 3 finding(s)                                                   │
│ [x] OAuth    │  [*] Módulo CORS iniciado                                                │
│ [x] SSRF     │  [!!] Origin reflection + credentials — CRITICAL                         │
│ [x] GraphQL  │  [+] CORS: 1 finding(s)                                                  │
│ [x] IDOR     │                                                                          │
│ [x] SSTI     │                                                                          │
│ ...          │                                                                          │
│              │                                                                          │
│ Target:      │                                                                          │
│ alvo.com     │                                                                          │
│              │                                                                          │
│ JWT:         │                                                                          │
│ eyJ...       │                                                                          │
│              │                                                                          │
│ [Iniciar]    │                                                                          │
│ [Parar]      │                                                                          │
├──────────────┴──────────────────────────────────────────────────────────────────────────┤
│ FINDINGS                                                                                │
│  CRITICAL  10.0  CWE-918  SSRF — Internal SSRF via URL parameter                        │
│  CRITICAL   9.1  CWE-347  JWT — Algorithm None Accepted                                 │
│  CRITICAL   9.1  CWE-942  CORS — Origin Reflection with Credentials                     │
│  HIGH       8.1  CWE-347  JWT — JWK Injection                                           │
│  [Enter] Detalhe  [↑↓] Navegar                                                          │
├─────────────────────────────────────────────────────────────────────────────────────────┤
│ alvo: https://***.com │ ◆3 ▲1 ●0 ▼0 │ [████████░░░░] 12/18 │ [Q] Sair  [E] Export  [?]  │
└─────────────────────────────────────────────────────────────────────────────────────────┘
```

**F1 Dashboard** — resumo visual com barras `█░` por severidade e top 5 findings críticos/high.

**F3 Target** — formulário dedicado: alvo, JWT token, JWT2 (segundo token para probes IDOR cross-user).

**F4 Findings** — tela cheia. Filtro por tecla: `1`=todos, `2`=CRITICAL, `3`=HIGH, `4`=MEDIUM, `5`=LOW, `6`=INFO.

**F5 Repeater** — HTTP repeater integrado com o alvo e JWT do módulo configurado.

**F6 Relatório** — barras de severidade + `[E] Exportar MD + JSON`.

**F7 Site Map** — requisições HTTP interceptadas durante o scan.

**F8** — event log drawer com histórico completo de log.

**Atalhos globais:**

| Tecla | Ação |
|---|---|
| `F1`–`F7` | Alternar modo |
| `F8` | Event log drawer |
| `Q` | Sair |
| `E` | Exportar MD + JSON |
| `?` | Action palette |
| `Enter` | Detalhe do finding (modal com evidência + curl) |
| `C` | Copiar curl para clipboard (xclip/xsel/AWT) |
| `PgUp/PgDn` | Scroll no log (modo Scan) |

---

## 06 · Testing

```bash
./gradlew test              # unit + harness (sem rede externa) — 69 testes
./gradlew integrationTest   # testes com hosts externos (badssl.com, etc.)
```

---

## 07 · Architecture

```
src/main/java/gg/effront/anarcry/
├── Main.java
├── model/
│   ├── Finding.java          record 12 campos (inc. CVSS v3.1 + CWE)
│   ├── Severity.java
│   ├── RequestRecord.java
│   ├── CvssCalculator.java   CVSS v3.1 scorer (fórmula FIRST, sem deps)
│   └── CweRegistry.java      CWE mapping por módulo (18 entradas + fallback)
├── scanner/
│   ├── Scanner.java          interface
│   ├── ScanContext.java
│   ├── ScanRunner.java       single-thread + deduplicação por module|endpoint|title
│   ├── ScanConfig.java       delayMs · sessionCookie · inScopeHosts · suppressions · redirectRelayUrl
│   ├── ScanEvent.java
│   ├── Suppression.java
│   ├── SuppressionLoader.java
│   ├── util/
│   │   ├── Http.java
│   │   ├── HttpClientFactory.java
│   │   └── TlsUtil.java
│   ├── crypto/
│   │   ├── tls/
│   │   ├── headers/
│   │   ├── jwt/              JwtModule + 5 probes
│   │   └── pqc/
│   └── web/
│       ├── cors/  oauth/  openredirect/  ssrf/  graphql/
│       ├── crlf/  xxe/    ssti/          idor/  hostheader/
│       ├── actuator/  massassign/  cachepoisoning/  smuggling/
│       └── infra/        port scan · nmap integration · SSH/Redis/panel fingerprinting
├── report/
│   └── ReportEngine.java     MD · JSON · HackerOne · Bugcrowd
└── tui/
```

---

## 08 · Roadmap

Ver [`BOUNTY-ROADMAP.md`](./BOUNTY-ROADMAP.md):

- **Sprint 18** — CrawlerModule: extração de paths HTML/JS, wordlist 500+, OpenAPI discovery
- **Sprint 19** — Rate limit, sessionCookie, inScopeHosts
- **Sprint 20** — FP reduction: MassAssign persistence, IDOR UUID de `/api/me`
- **Sprint 21** — ScanRunner paralelo com thread pool fixo
