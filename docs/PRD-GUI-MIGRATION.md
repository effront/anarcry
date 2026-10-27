# AnarCry v2.0 - PRD: Migracao Lanterna TUI -> Swing + FlatLaf GUI

**Status:** Draft v1.0
**Data:** 2026-10-27
**Autor:** Bullet
**Baseline:** AnarCry v1.2 (Lanterna 3.1.3 TUI, 13 arquivos, ~2500 LOC)

---

## 1. Motivacao

O AnarCry nasceu como TUI (Lanterna) para velocidade de prototipacao. Com 21 modulos de scan,
two-phase execution, knowledge base, repeater e 4 formatos de export, o motor esta maduro.
A limitacao agora e a interface: Lanterna nao suporta tabelas com sort/filter, graficos,
syntax highlight, drag-and-drop, nem docking de paineis.

Ferramentas de referencia no mercado (Burp Suite Pro, Caido, ZAP) usam GUI desktop e
estabeleceram o padrao visual que pentesters esperam. Manter TUI limita adocao e
percepcao de profissionalismo.

### Analise de mercado (extraida dos binarios)

| Ferramenta | Framework UI | Extensao |
|---|---|---|
| Burp Suite Pro | Swing + FlatLaf + 45 UI delegates custom | Montoya API (registerSuiteTab, IScannerCheck) |
| Nope-Proxy | Swing puro | BurpExtender API |
| DBeaver | Eclipse RCP (SWT + OSGi, 160 plugins) | Eclipse extension points |
| OWASP ZAP | Swing | ZAP extension API |

**Conclusao:** Swing + FlatLaf e o stack dominante em ferramentas de seguranca. Eclipse RCP
e overkill para scanner (peso, build complexity, startup lento). JavaFX nao tem adocao no
ecossistema de pentest.

---

## 2. Objetivo

Substituir a camada `tui/` (Lanterna) por uma GUI desktop usando **Swing + FlatLaf**,
mantendo o backend (scanner, model, report, knowledge-base) intacto. O resultado deve:

- Ter visual profissional comparavel ao Burp Suite
- Suportar paineis redimensionaveis e dockaveis
- Permitir extensoes externas via plugin API
- Distribuir como binario nativo (.deb, .AppImage, .dmg, .exe) via jpackage
- Manter modo headless (`--e2e`) para CI/harness

---

## 3. Escopo

### 3.1 IN SCOPE (v2.0)

1. **Framework UI**: Swing + FlatLaf (dark/light theme)
2. **Layout principal**: MainFrame com JSplitPane tripartido
   - Esquerda: painel de modulos + config (arvore ou lista)
   - Centro: area principal com JTabbedPane (tabs dos modos)
   - Inferior: log output + findings table
3. **7 views** (equivalentes aos 7 modos atuais):
   - Dashboard (graficos de severidade via JFreeChart)
   - Scan (modulos + log + findings)
   - Target (config de alvo, JWT, scope)
   - Findings (JTable com sort/filter por severidade, modulo, endpoint)
   - Repeater (request editor + response viewer com syntax highlight)
   - Report (preview + export multi-formato)
   - SiteMap (JTree hierarquico de URLs)
4. **Chrome**:
   - StatusBar com contadores de severidade e progresso
   - MenuBar (File, Scan, View, Export, Help)
   - Toolbar com acoes rapidas
5. **Syntax highlight**: RSyntaxTextArea para HTTP requests/responses e evidencias
6. **Findings table**: JTable com TableRowSorter, filtros por coluna, export direto
7. **Dialogs**: Export (MD/JSON/H1/Bugcrowd), Finding detail, Preferences
8. **Theme**: FlatLaf IntelliJ Dark como default, com toggle light/dark
9. **Distribuicao**: jpackage para .deb e .AppImage (Linux), .dmg (macOS), .msi (Windows)
10. **Backward compat**: modo `--headless` / `--e2e` continua funcionando sem GUI

### 3.2 OUT OF SCOPE (v2.x+)

- Plugin API com classloader isolado e marketplace (v2.1)
- Proxy interceptador estilo Burp (v2.2)
- Custom FlatLaf UI delegates (v2.x - comeca com FlatLaf stock)
- Intruder/Fuzzer mode (v2.x)
- Sessoes persistentes com SQLite (v2.x)
- Collaborative scanning / multi-user (v3.x)

---

## 4. Arquitetura

### 4.1 Separacao de camadas

```
src/main/java/gg/effront/anarcry/
  model/          # INTACTO - Finding, Severity, CweRegistry, KnowledgeBase, etc.
  scanner/        # INTACTO - Scanner interface, ScanRunner, ScanContext, modulos
  report/         # INTACTO - ReportEngine (MD, JSON, H1, Bugcrowd)
  gui/            # NOVO - substitui tui/
  tui/            # REMOVIDO na v2.0 (branch separada mantem historico)
  Main.java       # MODIFICADO - detecta --headless ou lanca GUI
```

O backend ja e 100% desacoplado da UI via callbacks:
- `Consumer<String> logCb` - log messages
- `Consumer<Finding> findingCb` - findings
- `Consumer<ScanEvent> eventCb` - progress events
- `Consumer<RequestRecord> requestCb` - HTTP request log

Nenhum arquivo fora de `tui/` e `Main.java` precisa mudar.

### 4.2 Estrutura do pacote `gui/`

```
gui/
  AnarCryGui.java              # MainFrame (JFrame), inicializacao FlatLaf, layout
  GuiController.java           # Mediator entre views e ScanRunner (callbacks)
  theme/
    AnarCryLaf.java            # FlatLaf customizacoes (cores, fonts, overrides)
  views/
    DashboardView.java         # JPanel com graficos (JFreeChart)
    ScanView.java              # Split: modulos (esquerda) + log (centro) + findings (inferior)
    TargetView.java            # Config de alvo, JWT tokens, scope
    FindingsView.java          # JTable com sort/filter, detail panel
    RepeaterView.java          # Request editor (RSyntaxTextArea) + response viewer
    ReportView.java            # Preview + export buttons
    SiteMapView.java           # JTree hierarquico
  components/
    ModulesTree.java           # JTree/JPanel com checkboxes por categoria (Recon/Crypto/Web)
    FindingsTable.java         # JTable + TableModel + TableRowSorter
    LogPane.java               # JTextPane com auto-scroll e color coding
    StatusBar.java             # JPanel com severidade counts + progress
    SeverityChart.java         # Wrapper JFreeChart (pie/bar de severidades)
    HttpEditor.java            # RSyntaxTextArea configurado para HTTP
  dialogs/
    ExportDialog.java          # JDialog multi-formato
    FindingDetailDialog.java   # Modal com tabs (overview, evidence, reproduction, curl)
    PreferencesDialog.java     # Theme toggle, parallelism, timeouts
```

### 4.3 Diagrama de layout

```
+--------------------------------------------------------------------+
| MenuBar: File | Scan | View | Export | Help                        |
+--------------------------------------------------------------------+
| Toolbar: [Iniciar] [Parar] [Export] [Theme]         [target_url  ] |
+--------------------------------------------------------------------+
| Tabs: Dashboard | Scan | Target | Findings | Repeater | Report | SM|
+------------------+-------------------------------------------------+
|                  |                                                  |
| MODULES TREE     |  MAIN CONTENT (varies by tab)                   |
|                  |                                                  |
| [ ] Recon        |  [Scan tab example:]                            |
|   [x] Crawler    |  +--------------------------------------------+ |
| [ ] Crypto       |  | LOG OUTPUT                                 | |
|   [x] TLS        |  | [*] Phase 1: Crawler...                    | |
|   [x] Headers    |  | [+] Crawler: 12 paths found                | |
|   ...            |  | [*] Phase 2: 18 modules (parallel)         | |
|                  |  +--------------------------------------------+ |
| Target: ________ |  | FINDINGS TABLE                    sort/filt | |
| JWT 1:  ________ |  | Sev  | Module | Endpoint | Title           | |
| JWT 2:  ________ |  | CRIT | SQLi   | /api/v1  | Error-based ... | |
|                  |  | HIGH | XSS    | /search  | Reflected ...   | |
| [Iniciar] [Parar]|  | MED  | CORS   | /api     | Wildcard ...    | |
+------------------+-------------------------------------------------+
| StatusBar: C:2 H:5 M:8 L:3 | Modulos: 14/21 | Alvo: example.com  |
+--------------------------------------------------------------------+
```

---

## 5. Dependencias novas

```groovy
// GUI
implementation 'com.formdev:flatlaf:3.5.4'
implementation 'com.formdev:flatlaf-intellij-themes:3.5.4'

// Syntax highlight
implementation 'com.fifesoft:rsyntaxtextarea:3.5.3'

// Charts
implementation 'org.jfree:jfreechart:1.5.5'
```

### Removidas
```groovy
// implementation 'com.googlecode.lanterna:lanterna:3.1.3'  -- removida
```

---

## 6. Mapeamento TUI -> GUI

| Componente TUI (Lanterna) | Componente GUI (Swing) | Notas |
|---|---|---|
| `AnarCryTui.java` (765 LOC) | `AnarCryGui.java` + `GuiController.java` | Split em frame + controller |
| `ModeBar` (F1-F7 tabs) | `JTabbedPane` | Tabs nativas com icones |
| `StatusBar` (animacao texto) | `StatusBar` JPanel | Labels + JProgressBar |
| `LogPanel` (TextBox readonly) | `LogPane` (JTextPane) | Color coding por nivel [+]/[!]/[*] |
| `FindingsPanel` (ActionListBox) | `FindingsTable` (JTable) | Sort, filter, column resize |
| `ModulesPanel` (CheckBoxes) | `ModulesTree` (JTree + CheckboxTreeCellRenderer) | Categorias colapsaveis |
| `SiteMapPanel` (label list) | `SiteMapView` (JTree) | Arvore hierarquica de URLs |
| `RepeaterMode` (TextBox split) | `RepeaterView` (RSyntaxTextArea split) | Syntax highlight HTTP |
| `ActionPalette` (Ctrl+P) | `JDialog` com search field | Ou integrar no menu |
| `EventLogDrawer` (F8) | Tab ou painel dockavel | Sempre visivel |
| Dialogs (export, detail) | `JDialog` equivalentes | Mais espaco, tabs internas |

---

## 7. Plugin API (design antecipado, implementacao v2.1)

Baseado no modelo Montoya do Burp Suite, adaptado para o AnarCry:

```java
public interface AnarCryExtension {
    void initialize(AnarCryApi api);
}

public interface AnarCryApi {
    // Scanner
    void registerScanner(Scanner scanner);
    void registerPassiveScanner(PassiveScanner scanner);

    // UI
    void registerTab(String title, JComponent component);
    void registerFindingDecorator(FindingDecorator decorator);

    // Data
    ScanContext currentScanContext();
    List<Finding> findings();
    List<RequestRecord> requestLog();

    // Logging
    Consumer<String> logger();
}
```

Extensoes sao JARs em `~/.anarcry/plugins/` carregados via `ServiceLoader`.
Cada JAR declara `META-INF/services/gg.effront.anarcry.api.AnarCryExtension`.

**Compatibilidade com o sistema atual:** a interface `Scanner` (`id()` + `scan(ctx, log)`)
ja e o equivalente do `IScannerCheck` do Burp. Modulos internos e externos usam a mesma
interface - zero code especial.

---

## 8. Distribuicao

### 8.1 jpackage

```bash
# Linux .deb
jpackage --input build/libs \
  --main-jar anarcry-2.0.jar \
  --name AnarCry \
  --type deb \
  --icon docs/icon.png \
  --app-version 2.0 \
  --vendor "Effront" \
  --description "Security Scanner"

# Linux .AppImage
jpackage --type app-image ...

# macOS .dmg
jpackage --type dmg ...

# Windows .msi
jpackage --type msi ...
```

### 8.2 CI

- GitHub Actions: build + test + jpackage para Linux/macOS/Windows
- Artefatos: .deb, .AppImage, .dmg, .msi anexados a cada release
- Harness `--e2e` continua rodando headless

---

## 9. Plano de execucao

### Sprint 19: Foundation (GUI shell)
- [ ] Adicionar dependencias FlatLaf + RSyntaxTextArea + JFreeChart ao build.gradle
- [ ] `AnarCryGui.java`: MainFrame com FlatLaf dark, JSplitPane, JTabbedPane vazio
- [ ] `GuiController.java`: conectar callbacks do ScanRunner (logCb, findingCb, eventCb)
- [ ] `StatusBar`: severidade counts + progress bar
- [ ] `ModulesTree`: checkboxes por categoria com target/JWT inputs
- [ ] `LogPane`: JTextPane com color coding e auto-scroll
- [ ] `Main.java`: flag `--gui` (default) vs `--headless` / `--e2e`
- [ ] Funcional: iniciar scan pela GUI, ver log e findings

### Sprint 20: Views completas
- [ ] `ScanView`: layout tripartido (modulos + log + findings)
- [ ] `FindingsView`: JTable com TableRowSorter, filtros, double-click abre detail
- [ ] `FindingDetailDialog`: tabs (overview, evidence, reproduction) + copy curl
- [ ] `TargetView`: config de alvo, JWT, scope rules
- [ ] `DashboardView`: graficos JFreeChart (pie severidade, bar por modulo)
- [ ] `SiteMapView`: JTree hierarquico de URLs crawladas

### Sprint 21: Repeater + Export + Polish
- [ ] `RepeaterView`: RSyntaxTextArea para request/response, method/path/headers/body
- [ ] `ReportView`: preview markdown renderizado + export multi-formato
- [ ] `ExportDialog`: MD, JSON, H1, Bugcrowd (mesmo motor, nova UI)
- [ ] `PreferencesDialog`: theme toggle, parallelism, timeout config
- [ ] MenuBar + Toolbar + keyboard shortcuts (Ctrl+Enter = scan, etc.)
- [ ] Testar em Linux Mint (Cinnamon), Ubuntu (GNOME), macOS, Windows

### Sprint 22: Distribuicao + Cleanup
- [ ] jpackage configs para .deb, .AppImage, .dmg, .msi
- [ ] GitHub Actions workflow para build multiplataforma
- [ ] Remover dependencia Lanterna do build.gradle
- [ ] Deletar `tui/` (preservar em branch `legacy/tui` para referencia)
- [ ] Atualizar README, CLAUDE.md, PRD com nova stack
- [ ] Release v2.0

---

## 10. Riscos e mitigacoes

| Risco | Impacto | Mitigacao |
|---|---|---|
| FlatLaf nao roda em Wayland puro | GUI nao abre em distros futuras | Java AWT/Swing ja suporta Wayland via XWayland; testar em Mint Cinnamon (X11) primeiro |
| JFreeChart pesado para charts simples | Bundle size cresce ~2MB | Alternativa: pintar charts manualmente com Graphics2D se necessario |
| Swing threading (EDT) | Race conditions em updates do scanner | GuiController usa SwingUtilities.invokeLater (mesmo padrao do gui.getGUIThread().invokeLater atual) |
| Modulos externos (v2.1) podem travar a GUI | UI congela | Executar extensoes em threads separadas, timeout + kill |
| jpackage precisa de JDK completo no CI | Build falha | Usar JDK Zulu com jpackage module em GitHub Actions |

---

## 11. Criterios de aceite (v2.0)

1. GUI abre em < 2s com FlatLaf dark theme
2. Scan funciona identico ao TUI (mesmos findings, mesma ordem)
3. Findings table suporta sort por qualquer coluna e filtro por severidade
4. Log panel mostra output em tempo real com color coding
5. Repeater envia requests e mostra response com syntax highlight
6. Dashboard mostra graficos de severidade atualizados em tempo real
7. Export gera mesmos arquivos que a versao TUI (MD, JSON, H1, Bugcrowd)
8. `--headless` / `--e2e` funciona sem inicializar GUI
9. .deb instala e roda em Linux Mint sem dependencias extras
10. Todos os testes existentes passam sem modificacao
