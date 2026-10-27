# Arquitetura Estratégica: AnarCry (Crypto-First, Web-Enhanced)

**Documento de Direcionamento Técnico**  
**Projeto:** `gg.effront.anarcry`  
**Data:** 2026-10-20  
**Autor:** @JavaAdvocate (Bullet)  

---

## 1. Visão Geral do Conceito

O modelo **Crypto-First, Web-Enhanced** resolve o dilema comercial e técnico do AnarCry. Em vez de limitar a ferramenta a um nicho estrito (criptografia pós-quântica e falhas de TLS) ou transformá-la em apenas mais um scanner genérico de vulnerabilidades web, esta estratégia divide o ecossistema do projeto em duas camadas sinérgicas:

1. **A Âncora de Mercado (Crypto-First):** Mantém o diferencial competitivo único do projeto (Java 27, JEP 496/497, auditoria de PQC, furos em JWT e falhas estruturais de cifras). É o que dá autoridade ao projeto no GitHub e atrai a atenção de grandes programas de Bug Bounty corporativos (Fintechs, Gov, Enterprise).
2. **A Alavanca de Payout (Web-Enhanced):** Integra módulos de alta rotatividade para falhas web críticas e de lógica (CORS, SSRF, IDOR, XXE, SSTI). É o que garante a utilidade diária do AnarCry em qualquer *recon* ou VPS de caça a bugs.

---

## 2. Nova Arquitetura de Módulos (Reorganização de Pacotes)

Para refletir essa estratégia sem poluir a base de código e o motor de execução do `ScanRunner`, os módulos do scanner passam a ser segregados em subpacotes lógicos sob `gg.effront.anarcry.scanner.*`.

```
src/main/java/gg/effront/anarcry/scanner/
├── Scanner.java (Interface)
├── ScanContext.java
├── ScanRunner.java
│
├── crypto/                  <-- Camada Core (Crypto-First)
│   ├── tls/                 - TlsModule (TLS 1.0/1.1, Cifras Fracas)
│   ├── pqc/                 - PqcModule (X25519MLKEM768, Downgrade Probes)
│   ├── jwt/                 - JwtModule (alg:none, RS256->HS256, Secret Brute)
│   └── headers/             - CryptoHeaders (HSTS, Secure Flags, CSP)
│
└── web/                     <-- Camada Expandida (Web-Enhanced)
    ├── cors/                - CorsModule (Origin Reflection, Credentials)
    ├── ssrf/                - SsrfModule (Cloud Metadata, SSR Bypass Filter)
    ├── idor/                - IdorModule (Comparação de Contexto Multi-Token)
    ├── xxe/                 - XxeModule (Content-Type XML Probes, Blind OOB)
    ├── ssti/                - SstiModule (Math Payload Engine Trees)
    ├── oauth/               - OAuthModule (Redirect Bypass, State Missing)
    └── graphql/             - GraphQLModule (Introspection, Discovery)
```

---

## 3. Impacto na Interface Gráfica (TUI)

A `ModulesPanel.java` deve refletir visualmente essa divisão para o usuário, permitindo que ele alterne rapidamente o escopo do scan de acordo com o seu objetivo (auditoria rápida de infraestrutura vs. hunting completo de web bugs).

### 3.1 Layout de Grupos na TUI (Lanterna 3)

```
┌───────────────────────────────────────────────────┐
│ MODULOS                                           │
├───────────────────────────────────────────────────┤
│ [■] CORE CRYPTO (PQC-Ready)                       │
│  └─ [x] TLS Audit    [x] PQC Probe                │
│  └─ [x] JWT Analiz.  [x] Sec Headers              │
│                                                   │
│ [■] WEB ENHANCED (Bounty Boost)                   │
│  └─ [x] CORS         [x] SSRF      [ ] IDOR       │
│  └─ [ ] XXE          [ ] SSTI                     │
│                                                   │
│ Target URL: ───────────────────────────────────── │
│ https://target.com/api                            │
│                                                   │
│ JWT Token 1 (User A): ─────────────────────────── │
│ eyJ...                                            │
│                                                   │
│ JWT Token 2 (User B - IDOR Mode): ─────────────── │
│ eyJ...                                            │
└───────────────────────────────────────────────────┘
```

- **Comportamento dinâmico:** O campo *JWT Token 2* permanece desativado/escondido na TUI a menos que o módulo `IDOR` sob o grupo *Web Enhanced* esteja marcado.

---

## 4. Otimização de Performance e Prevenção de Timeouts

A adição de módulos web complexos (como SSTI e XXE) aumenta a quantidade de requisições HTTP por parâmetro, o que pode arruinar a performance de uma ferramenta single-threaded estruturada na TUI. Devem ser aplicadas as seguintes diretrizes:

1. **Pre-Flight Sanity Checks:** Módulos de SSTI e XXE não devem injetar em massa de forma cega. 
   - O `XxeModule` deve disparar apenas se o endpoint aceitar `Content-Type: application/xml` ou responder com erro estruturado de XML a um probe inicial.
   - O `SstiModule` deve focar em parâmetros refletidos no corpo da resposta HTTP, pulando parâmetros que geram reflexão apenas em headers.
2. **Reuso de Conexões:** Configurar o `java.net.http.HttpClient` global do `ScanContext` com um pool de conexões persistentes (HTTP/2 habilitado por padrão) para reduzir o overhead de múltiplos handshakes TCP/TLS durante os probes de mutação de parâmetros.

---

## 5. Próximas Sprints Atualizadas com Foco Estratégico

Com o alinhamento desse modelo híbrido, a priorização e escopo das sprints planejadas passam a ser refinados:

*   **Sprint 11 — Módulo XXE (Web):** Foco em endpoints expostos de API enterprise. Validação inteligente de Content-Type.
*   **Sprint 12 — Módulo SSTI (Web):** Motor de injeção matemática otimizado (`${7*7}`) com árvore de decisão para fingerprinting de templates de backend sem causar negação de serviço (DoS) no alvo.
*   **Sprint 13 — Módulo IDOR (Web):** Implementação do motor de comparação lógica multi-token. O AnarCry se tornará um dos poucos scanners de terminal capazes de detectar falhas complexas de controle de acesso (BOLA) de maneira semi-automatizada.

---
*Documento gerado em conformidade com as diretrizes de arquitetura do AnarCry.*
