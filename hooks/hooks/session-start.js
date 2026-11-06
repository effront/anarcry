#!/usr/bin/env node
// SessionStart hook: detects active AnarCry domain and injects context

const { detect } = require('../lib/domain-detector');
const { isAnarcryProject, anarcryVersion } = require('../lib/project');
const store = require('../lib/domain-store');

if (require.main === module) main();

function main() {
  let input = '';
  process.stdin.on('data', chunk => (input += chunk));
  process.stdin.on('end', () => handle(input));
  setTimeout(() => process.exit(0), 5000).unref();
}

function handle(input) {
  let payload = {};
  try {
    payload = JSON.parse(input) || {};
  } catch {}

  const path = require('path');
  const cwd = path.resolve(payload.cwd || process.cwd());
  if (!isAnarcryProject(cwd)) process.exit(0);

  const domain = detect(cwd);
  store.write(payload.session_id, domain);

  process.stdout.write(buildContext(domain, cwd));
  process.exit(0);
}

function buildContext(domain, cwd) {
  const version = anarcryVersion(cwd);
  const ver = version ? `v${version}` : '(versao nao resolvida no build.gradle)';

  const base =
    `AnarCry Security Scanner ${ver}: Java 21, Gradle, 25+ scanner modules, ` +
    'TUI (Lanterna) + Swing GUI, shadow jar. ' +
    'Lint: Spotless (Google Java Format) + Checkstyle + SpotBugs/FindSecBugs + Semgrep. ' +
    'Sem emojis no codigo.';

  const domains = {
    'web-scanner':
      `[AC:WEB] Modulos web: OpenRedirect, CORS, OAuth, XSS, SQLi, SSRF, SSTI, XXE, ` +
      `LFI, CmdInject, CRLF, GraphQL, HostHeader, IDOR, MassAssign, CachePoison, ` +
      `ReqSmuggling, Crawler, Infra, Actuator. ` +
      `Padrao: implements Scanner, probes via Http.send(), ProbeExecutor pra paralelismo. ` +
      `CRITICO: validar Location header por host (URI.getHost()), nao substring.`,

    'crypto-scanner':
      `[AC:CRYPTO] Modulos crypto: TLS, HSTS, JWT, PQC, SecurityHeaders. ` +
      `TLS probe via SSLSocket direto. JWT analisa alg header sem executar.`,

    exploit:
      `[AC:EXPLOIT] Modulos exploit: FirebaseExploiter, AuthBypassExploiter, IdorExploiter, ` +
      `EndpointEnumExploiter, FindingValidator. Interface Exploiter, ExploitResult record. ` +
      `CRITICO: cleanup obrigatorio (deletar contas criadas), max requests por modulo. ` +
      `Shared: scanner/auth/firebase/ (ConfigExtractor, AuthClient).`,

    auth:
      `[AC:AUTH] Auth/Credential Harvester: ProviderDetector, FirebaseHarvester, CredentialStore. ` +
      `Firebase via Identity Toolkit REST API. Token refresh automatico em Http.send(). ` +
      `CRITICO: nunca logar credentials, destroy() ao fim do scan.`,

    model:
      `[AC:MODEL] Data models: Finding, Severity, ScanContext, ScanConfig, CweRegistry, ` +
      `CvssCalculator, ExploitResult, ValidatedFinding. Records imutaveis preferred.`,

    report:
      `[AC:REPORT] ReportEngine: MD, H1, Bugcrowd exports. ValidatedFinding support. ` +
      `PoC sections para confirmed, FP section para dismissed.`,

    tui:
      `[AC:TUI] TUI via Lanterna: ModulesPanel (scan config), ScanPanel (live output), ` +
      `ReportPanel, chrome/. MultiWindowTextGUI. Sem Swing.`,

    gui:
      `[AC:GUI] Swing GUI: GuiController, GuiModulesPanel, theme/, views/. ` +
      `Roda em EDT (SwingUtilities.invokeLater). Dark theme default.`,

    assistant:
      `[AC:ASSISTANT] AI assistant: providers/ (LLM integration), tools/ (function calling). ` +
      `Analise de findings assistida por LLM.`,

    infra:
      `[AC:INFRA] Build: Gradle + shadow jar. CI: GitHub Actions (lint.yml + security-scan.yml). ` +
      `Pre-push hook: spotless/checkstyle/spotbugs/semgrep. Codacy integration.`,

    testing:
      `[AC:TEST] JUnit 5 + JDK HttpServer.create() para mocks. ` +
      `Padrao: mock server local, assertions sobre findings gerados. ` +
      `CRITICO: testes de exploit DEVEM usar mock, nunca target real.`,

    general:
      `[AC:GENERAL] Patterns: Scanner interface para detection, Exploiter interface para validation. ` +
      `Http.send() centralizado com circuit breaker. ProbeExecutor pra paralelismo. ` +
      `ScanContext carrega config + credentials. ScanRunner orquestra phases.`,
  };

  const msg = Object.hasOwn(domains, domain) ? domains[domain] : domains.general;
  return `${base}\n${msg}\n`;
}

module.exports = { buildContext };
