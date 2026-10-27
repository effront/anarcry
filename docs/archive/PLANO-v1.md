# AnarchCrypto — Plano de Implementação

**Data:** 2026-10-19

---

## Fases

```
Fase 1 — Skeleton + CLI        (1–2 dias)
Fase 2 — TLS Audit             (2–3 dias)
Fase 3 — Crypto Headers        (1 dia)
Fase 4 — JWT Analyzer          (2–3 dias)
Fase 5 — PQC Probe             (2–3 dias)
Fase 6 — Report Engine         (1–2 dias)
Fase 7 — Empacotamento         (1 dia)
```

---

## Fase 1 — Skeleton + TUI

### US-01 — Setup do projeto
**Como** developer,
**quero** um projeto Gradle 9 com Java 27 e Lanterna 3 configurados,
**para** ter a base de build antes de qualquer código de negócio.

**Critérios de aceite:**
- `gradle build` passa sem erros
- `java -jar anarchrypto.jar` abre a TUI no terminal
- Fat JAR gerado via `gradle shadowJar`
- Funciona no Kitty e terminais xterm-256color

**Tarefas:**
- [ ] `build.gradle` com toolchain Java 27, plugin Shadow, dependência Lanterna 3 + Gson
- [ ] Classe `Main` com entry point que inicializa o `TerminalFactory` do Lanterna
- [ ] Layout base: 3 painéis (Módulos esquerda, Log direita topo, Findings baixo)
- [ ] Sistema de foco com `Tab` entre painéis
- [ ] Atalho `Q` para sair limpo (restaura terminal)

---

### US-02 — Estrutura de Finding + evento de log
**Como** ferramenta,
**quero** um modelo de dados para findings e um bus de eventos de log,
**para** que todos os módulos produzam output no mesmo formato e a TUI receba updates em tempo real.

**Critérios de aceite:**
- Record `Finding` com: `module`, `title`, `severity`, `evidence`, `impact`, `reproduction`, `recommendation`
- Enum `Severity`: CRITICAL, HIGH, MEDIUM, LOW, INFO com cor Lanterna associada
- `FindingCollector` thread-safe acumula findings e notifica a TUI via listener
- `ScanLogger` emite eventos `[*]`, `[✓]`, `[!]`, `[!!]` que o painel de log exibe em tempo real

### US-02b — Painel de Módulos (esquerda)
**Como** hunter,
**quero** selecionar módulos, digitar o target e o JWT token antes de iniciar,
**para** configurar o scan sem sair da TUI.

**Critérios de aceite:**
- Checkboxes para TLS, Headers, JWT, PQC (todos marcados por padrão)
- Campo de texto para Target (validação de URL ao pressionar F5)
- Campo de texto para JWT Token (visível só quando módulo JWT marcado)
- `F5` inicia o scan, `F6` aborta
- Campos bloqueados durante scan em andamento

### US-02c — Painel de Log (direita topo)
**Como** hunter,
**quero** ver o output do scan em tempo real com cores,
**para** acompanhar o progresso como no Hydra.

**Critérios de aceite:**
- Stream live linha a linha durante o scan
- Cores: branco `[*]`, verde `[✓]`, amarelo `[!]`, vermelho `[!!]`
- Auto-scroll para o final
- Scroll manual com `↑↓` quando o painel está em foco

### US-02d — Painel de Findings (baixo)
**Como** hunter,
**quero** uma tabela navegável de findings ordenados por severidade,
**para** ver rapidamente o que foi encontrado.

**Critérios de aceite:**
- Tabela com colunas: Severidade (colorida), Módulo, Título
- Ordenação automática CRITICAL → HIGH → MEDIUM → LOW → INFO
- Atualiza em tempo real conforme findings chegam
- `Enter` abre modal de detalhe
- `E` exporta relatório markdown/JSON (dialog de escolha)

### US-02e — Modal de detalhe de finding
**Como** hunter,
**quero** ver todos os detalhes de um finding com o curl de reprodução,
**para** copiar direto para o relatório de bug bounty.

**Critérios de aceite:**
- Modal centralizado com todos os campos do `Finding`
- `C` copia o curl de reprodução para o clipboard (xclip/xsel)
- `E` exporta só esse finding
- `Esc` fecha

---

## Fase 2 — TLS Audit

### US-03 — Detecção de versão TLS fraca
**Como** hunter,
**quero** saber se o alvo aceita TLS 1.0 ou 1.1,
**para** reportar uso de protocolo depreciado (CVSSv3 ~5.3).

**Critérios de aceite:**
- Tenta handshake forçando TLS 1.0 e TLS 1.1 via `SSLContext`
- Retorna finding MEDIUM se aceitar
- Timeout respeitado

**Tarefas:**
- [ ] `TlsVersionProbe`: tenta `SSLContext.getInstance("TLSv1")` e `TLSv1.1`
- [ ] Finding gerado com evidência do protocolo negociado
- [ ] Teste unitário com mock de SSLSocket

---

### US-04 — Cipher suites fracas
**Como** hunter,
**quero** saber se o alvo aceita cipher suites depreciadas,
**para** reportar criptografia fraca.

**Critérios de aceite:**
- Detecta RC4, DES, 3DES, NULL, EXPORT, anon
- Retorna finding HIGH para cada suite fraca encontrada
- Lista as suites no campo `evidence`

**Tarefas:**
- [ ] `CipherSuiteProbe`: conecta e inspeciona `SSLSession.getCipherSuite()`
- [ ] Lista negra de suites fracas
- [ ] Teste unitário

---

### US-05 — Análise de certificado
**Como** hunter,
**quero** inspecionar o certificado X.509 do alvo,
**para** detectar expiração, autoassinatura e chave fraca.

**Critérios de aceite:**
- Detecta certificado expirado (finding LOW)
- Detecta RSA < 2048 bits (finding MEDIUM)
- Detecta certificado autoassinado (finding MEDIUM)
- Exibe CN, SANs, validade e emissor no evidence

**Tarefas:**
- [ ] `CertificateProbe`: extrai `X509Certificate` do handshake
- [ ] Verificações de validade, tamanho de chave, cadeia
- [ ] Testes unitários com certificados de fixture

---

## Fase 3 — Crypto Headers

### US-06 — Análise de headers de segurança
**Como** hunter,
**quero** verificar os headers HTTP do alvo,
**para** reportar ausência ou má configuração de headers de segurança.

**Critérios de aceite:**
- Faz GET no `--target` e inspeciona os headers da resposta
- Detecta HSTS ausente, max-age curto, sem includeSubDomains
- Detecta cookies sem Secure/HttpOnly
- Detecta CSP ausente ou permissivo (`unsafe-inline`, `*`)
- Cada achado vira um finding com severidade correta

**Tarefas:**
- [ ] `HeadersModule`: HTTP client via `java.net.http.HttpClient`
- [ ] Parser de `Strict-Transport-Security`
- [ ] Parser de `Set-Cookie` (flags)
- [ ] Parser básico de `Content-Security-Policy`
- [ ] Testes unitários com respostas HTTP mockadas

---

## Fase 4 — JWT Analyzer

### US-07 — Detecção de alg:none
**Como** hunter,
**quero** testar se o alvo aceita JWT com `alg: none`,
**para** reportar bypass de autenticação crítico.

**Critérios de aceite:**
- Dado um token JWT (`--jwt`), forge uma versão com `alg: none`
- Envia para o endpoint e detecta resposta 200/autenticado
- Finding CRITICAL com evidência e curl de reprodução

**Tarefas:**
- [ ] `JwtParser`: decodifica header/payload sem biblioteca externa (Base64 puro)
- [ ] `AlgNoneProbe`: forja token e reenvia
- [ ] Teste de integração contra mock server

---

### US-08 — RS256 → HS256 confusion
**Como** hunter,
**quero** testar algorithm confusion RS256→HS256,
**para** reportar bypass via chave pública como segredo HMAC.

**Critérios de aceite:**
- Extrai a chave pública do certificado TLS do alvo
- Forja JWT HS256 assinado com a chave pública como segredo
- Detecta resposta autenticada
- Finding CRITICAL

**Tarefas:**
- [ ] `AlgConfusionProbe`: usa `Mac.getInstance("HmacSHA256")` com chave pública extraída
- [ ] Integração com `CertificateProbe` para obter a chave pública
- [ ] Teste de integração

---

### US-09 — JWT brute-force de segredo fraco
**Como** hunter,
**quero** testar segredos HMAC fracos em JWT HS256/HS512,
**para** reportar chave criptográfica insuficiente.

**Critérios de aceite:**
- Testa lista de segredos comuns (wordlist embutida: top 100)
- Verifica assinatura localmente (sem requests)
- Finding HIGH com o segredo encontrado no evidence (censurado no output padrão, visível com `--verbose`)

**Tarefas:**
- [ ] `JwtBruteProbe`: reimplementa verificação HMAC com `javax.crypto.Mac`
- [ ] Wordlist embutida como resource
- [ ] Teste unitário com token de segredo conhecido

---

### US-10 — kid injection
**Como** hunter,
**quero** detectar `kid` com path traversal ou SQLi,
**para** reportar injeção no cabeçalho JWT.

**Critérios de aceite:**
- Analisa o campo `kid` do header JWT
- Forja tokens com payloads de path traversal (`../../etc/passwd`) e SQLi (`' OR 1=1--`)
- Detecta respostas anômalas (200 inesperado, erro diferente)
- Finding HIGH

---

## Fase 5 — PQC Probe

### US-11 — Detecção de suporte a PQC no TLS
**Como** hunter,
**quero** saber se o alvo negocia cipher suites pós-quânticas,
**para** incluir contexto de PQC no relatório (diferencial).

**Critérios de aceite:**
- Tenta negociar `X25519MLKEM768` via JEP 496 (Java 27 nativo)
- Detecta se o alvo aceita, ignora ou rejeita
- Finding INFO se suportar PQC (positivo)
- Finding LOW se não suportar (contexto: harvest now, decrypt later)

**Tarefas:**
- [ ] `PqcTlsProbe`: `SSLContext` com `KeyAgreement` ML-KEM via JCA
- [ ] Parsing da extensão `supported_groups` do ClientHello
- [ ] Teste com servidor local que suporte PQC (WireGuard ou nginx-quic como fixture)

---

### US-12 — Detecção de downgrade de PQC
**Como** hunter,
**quero** saber se o alvo permite downgrade de PQC para ECDH clássico,
**para** reportar ausência de política de crypto agility.

**Critérios de aceite:**
- Após detectar suporte PQC (US-11), tenta conexão forçando só ECDH
- Se o servidor aceitar, finding LOW (downgrade possível)
- Evidence contém os dois handshakes para comparação

---

## Fase 6 — Report Engine

### US-13 — Output Markdown
**Como** hunter,
**quero** um relatório em markdown pronto para o relatório de bug bounty,
**para** economizar tempo na escrita.

**Critérios de aceite:**
- Tabela de resumo por severidade
- Cada finding com seções: título, módulo, evidência, impacto, reprodução, recomendação
- Ordenado por severidade (CRITICAL primeiro)
- `--output report.md` salva em arquivo

---

### US-14 — Output JSON
**Como** hunter,
**quero** output em JSON estruturado,
**para** importar em outras ferramentas ou scripts.

**Critérios de aceite:**
- Schema: `{ version, target, date, duration_ms, findings: [...] }`
- Cada finding com todos os campos do record `Finding`
- `--format json` ativa o modo

---

## Fase 7 — Empacotamento

### US-15 — Fat JAR distribuível
**Como** hunter,
**quero** um único JAR executável,
**para** usar a ferramenta sem instalar nada além do Java.

**Critérios de aceite:**
- `gradle shadowJar` gera `anarchrypto-1.0.jar`
- Roda com `java -jar anarchrypto-1.0.jar --help`
- Script wrapper `anarchrypto` no PATH (opcional)

---

## Dependências entre fases

```
US-01 → todos
US-02 → US-03..US-14
US-05 → US-08 (chave pública do cert para alg confusion)
US-03 → US-11, US-12 (TLS base para PQC)
US-13, US-14 → US-15
```

---

## Ordem de implementação sugerida

```
1. US-01  (skeleton Gradle + Lanterna abrindo)
2. US-02  (Finding model + ScanLogger + bus de eventos)
3. US-02b (painel Módulos)
4. US-02c (painel Log live)
5. US-02d (painel Findings tabela)
6. US-02e (modal detalhe)
   — TUI completa, sem nenhum módulo de scan ainda —
7. US-06  (headers — módulo mais simples, valida pipeline TUI→módulo→finding)
8. US-03, US-04, US-05 (TLS)
9. US-07, US-08, US-09, US-10 (JWT)
10. US-11, US-12 (PQC)
11. US-13, US-14 (report export)
12. US-15 (fat JAR)
```

> **Princípio:** TUI funcional antes de qualquer módulo de scan. Isso permite testar a interface com findings mockados e garantir que a UX está boa antes de adicionar complexidade de rede.
