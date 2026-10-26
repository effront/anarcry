---
name: new-scanner-module
description: >
  Skill para criacao de um novo modulo de scanner no AnarCry. Guia passo a passo
  para implementar, registrar e testar um novo modulo de deteccao de vulnerabilidade.
---

# Skill: Criar Novo Modulo de Scanner

Siga estes passos na ordem para criar um novo modulo de scanner no AnarCry.

## Passo 1 — Definir o Modulo

Antes de escrever codigo, definir:
- **Nome/ID**: string curta e unica (ex: "CSRF", "Deserialization")
- **CWE**: identificador CWE correto (consultar https://cwe.mitre.org/)
- **CVSS Vector**: calcular para o cenario tipico
- **Categoria**: `scanner/crypto/` ou `scanner/web/`
- **Payloads**: listar payloads de deteccao planejados
- **Anti-FP**: como evitar falsos positivos

## Passo 2 — Criar a Classe

Criar em `src/main/java/gg/effront/anarcry/scanner/web/<nome>/` ou `scanner/crypto/<nome>/`:

```java
package gg.effront.anarcry.scanner.web.<nome>;

import gg.effront.anarcry.model.Finding;
import gg.effront.anarcry.model.Severity;
import gg.effront.anarcry.scanner.ScanContext;
import gg.effront.anarcry.scanner.Scanner;
import gg.effront.anarcry.scanner.util.Http;
import gg.effront.anarcry.scanner.util.HttpClientFactory;

import java.net.http.HttpClient;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;

public class <Nome>Module implements Scanner {

    @Override
    public String id() {
        return "<ID>";
    }

    @Override
    public List<Finding> scan(ScanContext ctx, Consumer<String> log) throws Exception {
        List<Finding> findings = new ArrayList<>();
        HttpClient hc = HttpClientFactory.http2();

        String scheme = ctx.isHttps() ? "https" : "http";
        int defPort = ctx.isHttps() ? 443 : 80;
        String base = scheme + "://" + ctx.host()
            + (ctx.port() != defPort ? ":" + ctx.port() : "");

        log.accept("[~] " + id() + ": iniciando scan em " + base);

        // ... logica de deteccao ...

        if (findings.isEmpty()) {
            log.accept("[+] " + id() + ": nenhuma vulnerabilidade detectada");
        }
        return findings;
    }
}
```

## Passo 3 — Registrar no CweRegistry

Editar `src/main/java/gg/effront/anarcry/model/CweRegistry.java`:
- Adicionar mapeamento `moduleId -> CWE ID`
- Adicionar mapeamento `moduleId -> CWE Title`
- Adicionar mapeamento `moduleId -> CVSS Vector`

## Passo 4 — Registrar no ScanRunner

Editar `src/main/java/gg/effront/anarcry/scanner/ScanRunner.java`:
1. Adicionar import do novo modulo
2. Adicionar bloco `if (ctx.has("<ID>"))` no metodo `run()`

```java
if (ctx.has("<ID>")) {
    modules.add(new <Nome>Module());
}
```

## Passo 5 — Adicionar Checkbox na TUI

Editar `src/main/java/gg/effront/anarcry/tui/panels/ModulesPanel.java`:
- Adicionar checkbox para o novo modulo na categoria correta

## Passo 6 — Criar Entrada no Knowledge Base

Criar `knowledge-base/<nome_vulnerabilidade>.md` com:
- Descricao da vulnerabilidade
- Impacto
- Como o AnarCry detecta
- Exemplos de payloads
- Remediacao
- Referencias (CWE, OWASP)

## Passo 7 — Escrever Testes

Criar teste em `src/test/java/gg/effront/anarcry/harness/<Nome>ModuleTest.java`:
- True positive: resposta vulneravel gera finding
- True negative: resposta limpa NAO gera finding
- Campos do Finding corretos (module, severity, CWE, CVSS)

## Passo 8 — Verificar

```bash
./gradlew spotlessApply              # Fix formatting
./gradlew test                       # Run tests
./gradlew checkstyleMain             # Checkstyle
./gradlew spotbugsMain               # SpotBugs
```

## Checklist Final

- [ ] Scanner interface implementada (id + scan)
- [ ] CweRegistry atualizado
- [ ] ScanRunner atualizado
- [ ] ModulesPanel atualizado
- [ ] Knowledge base entry criada
- [ ] Testes escritos (TP + TN)
- [ ] Spotless + Checkstyle + SpotBugs passando
- [ ] Findings com evidence concreta, reproduction curl, recommendation actionable
