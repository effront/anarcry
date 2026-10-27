# AnarchCrypto — Product Requirements Document

**Status:** Draft v1.1
**Data:** 2026-10-19
**Autor:** Bullet
**Changelog v1.1:** Interface CLI substituída por TUI (Lanterna) estilo Hydra/Wireshark

---

## 1. Visão Geral

AnarchCrypto é uma ferramenta CLI standalone para análise de fraquezas criptográficas em alvos web, desenvolvida com Java 27 e focada em bug bounty. Preenche uma lacuna real no arsenal de hunters: a maioria das ferramentas automatizadas ignora crypto ou a trata de forma superficial. Findings de criptografia são raros, bem pagos e difíceis de disputar pelos programas.

**Stack:** Java 27 (JEP 496/497 — ML-KEM/ML-DSA nativos), Gradle 9.x, Lanterna 3 (TUI)

---

## 2. Problema

Hunters de bug bounty focam majoritariamente em XSS, IDOR e SQLi. Vulnerabilidades criptográficas ficam subnotificadas por dois motivos:

1. Ferramentas genéricas (Burp, nuclei) cobrem crypto de forma rasa
2. Testar crypto manualmente é lento e exige conhecimento específico

O resultado: findings de crypto válidos ficam na mesa.

---

## 3. Objetivo

Entregar uma ferramenta CLI que:

- Roda contra qualquer alvo com uma linha de comando
- Cobre os vetores cripto mais lucrativos em bug bounty
- Gera output em markdown pronto para colar no relatório
- Usa Java 27 nativo para probe de criptografia pós-quântica (diferencial único)

---

## 4. Usuário-alvo

Bug bounty hunter de nível iniciante a intermediário que:
- Já entende o básico de HTTP/TLS
- Quer diversificar findings além dos clássicos OWASP Top 10
- Prefere CLI a GUI

---

## 5. Módulos

### 5.1 TLS Audit (`--module tls`)
Analisa a camada TLS do alvo.

| Check | Severidade potencial |
|---|---|
| TLS 1.0 / 1.1 habilitado | Medium |
| Cipher suites fracas (RC4, DES, 3DES, NULL) | High |
| Certificado expirado | Low–Medium |
| Certificado autoassinado | Medium |
| Certificado com chave RSA < 2048 bits | Medium |
| HSTS ausente | Low |
| HSTS max-age < 6 meses | Low |
| Suporte a renegociação insegura | Medium–High |

### 5.2 PQC Probe (`--module pqc`)
Usa a JCA nativa do Java 27 (JEP 496/497) para testar negociação pós-quântica.

| Check | O que detecta |
|---|---|
| Suporte a X25519MLKEM768 | Alvo aceita PQC hybrid key exchange |
| Downgrade forçado de PQC | Servidor ignora PQC e cai para ECDH puro |
| ML-DSA em certificado | Alvo usa assinatura pós-quântica |

Contexto para o relatório: alvos que não suportam PQC são vulneráveis a "harvest now, decrypt later" — útil em programas de empresas financeiras e de saúde.

### 5.3 JWT Analyzer (`--module jwt`)
Recebe um token JWT e analisa o algoritmo e a assinatura.

| Check | Severidade potencial |
|---|---|
| `alg: none` aceito | Critical |
| RS256 → HS256 confusion | Critical |
| Chave HMAC fraca (wordlist) | High |
| Payload com dados sensíveis sem criptografia | Info |
| `exp` ausente ou expirado aceito | Medium |
| `kid` com path traversal / SQLi | High |

### 5.4 Crypto Headers (`--module headers`)
Analisa os headers HTTP relacionados a criptografia e segurança.

| Check | Severidade potencial |
|---|---|
| HSTS ausente | Low |
| HSTS sem `includeSubDomains` | Low |
| `Content-Security-Policy` ausente | Low–Medium |
| `X-Content-Type-Options` ausente | Low |
| Cookies sem `Secure` flag | Low–Medium |
| Cookies sem `HttpOnly` flag | Low |

---

## 6. Interface TUI (Lanterna 3)

Interface de terminal estilo Hydra/Wireshark: painéis divididos, live output durante o scan, navegação por teclado, cores por severidade.

### 6.1 Layout geral

```
┌─────────────────────────────────────────────────────────────────────┐
│  AnarchCrypto v1.0          [Q] Quit  [E] Export  [Tab] Foco        │
├──────────────┬──────────────────────────────────────────────────────┤
│ MÓDULOS      │ OUTPUT / LOG                                         │
│              │                                                      │
│ [x] TLS      │  [*] Conectando a alvo.com:443...                   │
│ [x] Headers  │  [✓] TLS 1.3 negociado                              │
│ [x] JWT      │  [!] TLS 1.0 aceito — MEDIUM                        │
│ [x] PQC      │  [!] Cipher RC4-SHA detectada — HIGH                │
│              │  [✓] Certificado válido até 2027-03-15               │
│ Target:      │  [*] Analisando headers...                           │
│ alvo.com     │  [!] HSTS ausente — LOW                             │
│              │  [*] Testando JWT...                                 │
│ JWT Token:   │  [!!] alg:none aceito — CRITICAL                    │
│ eyJ...       │                                                      │
│              │                                                      │
│ [F5] Iniciar │                                                      │
│ [F6] Parar   │                                                      │
├──────────────┴──────────────────────────────────────────────────────┤
│ FINDINGS                                                            │
├─────────────────────────────────────────────────────────────────────┤
│  CRITICAL  JWT — Algorithm None Accepted                            │
│  HIGH      TLS — Weak Cipher Suite: RC4-SHA                        │
│  MEDIUM    TLS — TLS 1.0 Enabled                                   │
│  LOW       Headers — HSTS Missing                                  │
│                                                                     │
│  [Enter] Detalhes  [E] Exportar  [↑↓] Navegar                     │
└─────────────────────────────────────────────────────────────────────┘
```

### 6.2 Painéis

| Painel | Conteúdo |
|---|---|
| **Módulos** (esquerda) | Checkboxes para ativar/desativar módulos, campos Target e JWT Token, botões F5/F6 |
| **Output/Log** (direita topo) | Stream live do scan, colorido por tipo: `[*]` info, `[✓]` ok, `[!]` finding, `[!!]` critical |
| **Findings** (baixo) | Tabela navegável de findings ordenados por severidade, selecionável com Enter para ver detalhes |

### 6.3 Painel de detalhe de finding (modal)

Ao pressionar Enter em um finding:
```
┌─────────────────────────────────────────────────┐
│ [CRITICAL] JWT — Algorithm None Accepted         │
├─────────────────────────────────────────────────┤
│ Módulo:   jwt                                   │
│ Target:   https://alvo.com/api/me               │
│                                                 │
│ Evidência:                                      │
│   Token com alg:none retornou HTTP 200          │
│                                                 │
│ Impacto:                                        │
│   Autenticação bypassável sem assinatura válida │
│                                                 │
│ Reprodução:                                     │
│   curl -H "Authorization: Bearer eyJ..." \     │
│        https://alvo.com/api/me                  │
│                                                 │
│ Recomendação:                                   │
│   Rejeitar tokens com alg != algoritmo esperado │
├─────────────────────────────────────────────────┤
│  [C] Copiar curl  [E] Exportar  [Esc] Fechar   │
└─────────────────────────────────────────────────┘
```

### 6.4 Cores por severidade

| Severidade | Cor no terminal |
|---|---|
| CRITICAL | Vermelho bold |
| HIGH | Laranja (amarelo bold) |
| MEDIUM | Amarelo |
| LOW | Ciano |
| INFO | Branco |

### 6.5 Atalhos de teclado

| Tecla | Ação |
|---|---|
| `F5` | Iniciar scan |
| `F6` | Parar scan |
| `Tab` | Alternar foco entre painéis |
| `↑↓` | Navegar findings |
| `Enter` | Abrir detalhe do finding |
| `E` | Exportar relatório (markdown ou JSON) |
| `C` | Copiar curl de reprodução |
| `Esc` | Fechar modal |
| `Q` | Sair |

---

## 7. Output

### 7.1 Formato Markdown (padrão)

```markdown
# AnarchCrypto Report — alvo.com
Data: 2026-10-19 | Duração: 4.2s

## Resumo
| Severidade | Quantidade |
|---|---|
| Critical | 1 |
| High | 2 |
| Medium | 3 |
| Low | 4 |
| Info | 1 |

## Findings

### [CRITICAL] JWT — Algorithm None Accepted
**Módulo:** jwt
**Evidência:** Token com `alg: none` retornou HTTP 200
**Impacto:** Autenticação bypassável sem assinatura válida
**Reprodução:**
\```
curl -H "Authorization: Bearer eyJhbGciOiJub25lIn0..." https://alvo.com/api/me
\```
**Recomendação:** Rejeitar qualquer token com alg != algoritmo esperado

[...]
```

### 7.2 Formato JSON

Schema versionado, compatível com importação em Burp / relatórios automatizados.

---

## 8. Requisitos Técnicos

- Java 27 (Azul Zulu 27+)
- Gradle 9.x
- Sem dependências externas para os módulos core (JCA nativa)
- Dependências permitidas: Lanterna 3 (TUI), Gson (JSON output)
- Distribuição: fat JAR via `gradle shadowJar`
- Compatível com Linux e macOS (terminais: kitty, xterm, alacritty, tmux)

---

## 9. Fora de escopo (v1)

- Interface gráfica
- Integração com Burp Suite
- Fuzzing de endpoints
- Autenticação OAuth/SAML (v2)
- Integração com plataformas de bug bounty (HackerOne, Bugcrowd)

---

## 10. Decisões em aberto

| Decisão | Status |
|---|---|
| Wordlist para JWT brute-force: embutida ou externa? | Aberto |
| Suporte a proxy (Burp intercept)? | Aberto |
| Modo `--passive` (só headers, sem TLS handshake)? | Aberto |
