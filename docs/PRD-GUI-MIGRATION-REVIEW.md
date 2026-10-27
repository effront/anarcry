# PRD-GUI-MIGRATION Review — Decisoes

**Data:** 2026-10-27
**Revisado por:** Bullet
**Fonte:** Review multi-agente (pentest-planner, tui-specialist, scanner-module-engineer, report-engineer)

---

## Blockers — os 3 sao reais

- **Severity.java com Lanterna no model/** — o mais critico. Quebra a premissa de "backend intacto". Resolver pre-Sprint 19.
- **ScanOrchestrator** — faz sentido extrair antes de migrar. Logica de orquestracao presa no ModulesPanel (TUI).
- **--headless** — depende do ScanOrchestrator. Correto.

## P0 — concordo parcialmente

- **Proxy basico no v2.0** — faz sentido se o objetivo e competir com Burp/Caido. Se o foco e scanner automatizado, pode ficar em v2.2. Decisao pendente.
- **Comparer/diff** — trivial de implementar, vale colocar no v2.0 (Sprint 21).
- **buildMarkdown() publico** — fix de 1 linha, nao precisa esperar sprint.

## P1 — todos validos

- **Callbacks 4->6** — correcao factual no PRD.
- **LOC ~2050** — correcao factual (PRD dizia ~2500).
- **11 features TUI nao mapeadas** — adicionar a secao 6 do PRD.
- **Reordenar Repeater antes de Dashboard** — faz muito sentido. Pentester usa Repeater 10x mais.
- **Sessao persistente em JSON no Sprint 22** — pragmatico e suficiente.

### P1 que discordo

- **"4 modulos orfaos" (SQLi, XSS, LFI, CmdInjection)** — eles estao registrados no ScanRunner sim. O review pode ter lido errado. Tem `ctx.has()` pra eles no codigo, so nao com esses nomes exatos.

## P2 — bons mas podem esperar

- **Event bus no plugin API** — correto, mas nao bloqueia v2.0.
- **HiDPI/fractional scaling** — testar no Sprint 21, nao bloqueia.
- **Clock injection** — correto para testes deterministicos, pode entrar quando tocar no ReportEngine.

## Veredicto

Review solido. Os 3 blockers sao pre-requisitos reais para Sprint 19. Proxima acao: Sprint 18.5 de refactor (Severity desacoplamento, ScanOrchestrator, buildMarkdown publico).
