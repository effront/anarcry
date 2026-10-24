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
[![Modules](https://img.shields.io/badge/modules-18-4CAF50)](https://github.com/effront/anarcry)
[![Tests](https://img.shields.io/badge/tests-69-blue)](https://github.com/effront/anarcry)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

</div>

---

```
╔══════════════════════════════════════════════════════════════════════════════╗
║  ANARCRY — Java 27 Security Scanner                                          ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  Scanner TUI para bug bounty. 18 módulos de ataque, CVSS v3.1 automático,   ║
║  export direto para HackerOne e Bugcrowd. Crypto-first + OWASP Top 10.      ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

---

<details>
<summary><kbd>▶ Módulos (click to expand)</kbd></summary>

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  CRIPTOGRAFIA                                                                │
│  [■] TLS             — versão, cipher suites fracas, cert expirado, SHA-1   │
│  [■] Headers         — HSTS, CSP unsafe-inline/*, cookies, CORP/CORB        │
│  [■] JWT             — alg:none, RS256→HS256, JWK injection, kid SQLi       │
│  [■] PQC             — X25519MLKEM768, TLS 1.3, grupos pós-quânticos NIST   │
│                                                                              │
│  WEB (OWASP)                                                                 │
│  [■] CORS            — origin reflection + credentials, wildcard, null      │
│  [■] OAuth           — state CSRF, redirect_uri bypass, .well-known         │
│  [■] OpenRedirect    — url/redirect/next/return/dest parameters             │
│  [■] SSRF            — URLs aceitas, bypass @/IP decimal/169.254.169.254    │
│  [■] GraphQL         — introspection, field suggestions, batching DoS       │
│  [■] CRLF            — header injection via \r\n                            │
│  [■] XXE             — external entity, SSRF via XXE, blind XXE             │
│  [■] SSTI            — FreeMarker, Jinja2, Velocity, Thymeleaf              │
│  [■] IDOR            — cross-user, DELETE/PATCH tampering, UUID probing     │
│  [■] HostHeader      — Host injection, cache poisoning via X-Forwarded-Host │
│  [■] Actuator        — Spring Boot /env /heapdump /mappings /beans          │
│  [■] MassAssign      — JSON mass assignment em endpoints REST               │
│  [■] CachePoisoning  — headers não-keyed refletidos e cacheados             │
│  [■] ReqSmuggling    — CL.TE e TE.CL HTTP request smuggling                │
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
║  CWE                 ║  CweRegistry.java (18 módulos mapeados)            ║
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

```
┌─────────────────────────────────────────────────────────────────────┐
│  AnarCry v1.0              [Q] Quit  [E] Export  [Tab] Foco        │
├──────────────┬──────────────────────────────────────────────────────┤
│ MÓDULOS      │ LOG / OUTPUT                                         │
│              │                                                      │
│ [x] TLS      │  [*] Módulo JWT iniciado                            │
│ [x] Headers  │  [!!] alg:none aceito — CRITICAL                   │
│ [x] JWT      │  [!!] RS256→HS256 confusion — CRITICAL             │
│ [x] PQC      │  [!] JWK injection — HIGH                          │
│ [x] CORS     │  [+] JWT: 3 finding(s)                             │
│ [x] SSRF     │                                                      │
│ [x] IDOR     │                                                      │
│ ...          │                                                      │
│              │                                                      │
│ Target:      │                                                      │
│ alvo.com     │                                                      │
│              │                                                      │
│ JWT Token:   │                                                      │
│ eyJ...       │                                                      │
│              │                                                      │
│ [F5] Scan    │                                                      │
│ [F6] Parar   │                                                      │
├──────────────┴──────────────────────────────────────────────────────┤
│ FINDINGS                                                 3 total    │
├─────────────────────────────────────────────────────────────────────┤
│  CRITICAL  9.1  CWE-347  JWT — Algorithm None Accepted             │
│  CRITICAL  9.1  CWE-347  JWT — RS256/HS256 Confusion              │
│  HIGH      8.1  CWE-347  JWT — JWK Injection                      │
│                                                                     │
│  [Enter] Detalhes  [E] Exportar  [↑↓] Navegar                     │
└─────────────────────────────────────────────────────────────────────┘
```

**Atalhos:**

| Tecla | Ação |
|---|---|
| `F5` | Iniciar scan |
| `F6` | Parar scan |
| `Tab` | Alternar foco entre painéis |
| `↑↓` | Navegar findings |
| `Enter` | Abrir detalhe do finding |
| `E` | Exportar relatório |
| `C` | Copiar curl de reprodução |
| `Q` | Sair |

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
│   ├── ScanEvent.java
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
│       └── actuator/  massassign/  cachepoisoning/  smuggling/
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
