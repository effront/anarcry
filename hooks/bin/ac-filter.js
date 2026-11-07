#!/usr/bin/env node
// ac-filter.js - Executa o comando original e comprime o output para Claude
// Usage: node ac-filter.js <filter-type> -- <command args...>

const { spawnSync } = require('child_process');

const TIMEOUT_MS = 300_000;

const SIGNAL_NUMBERS = { SIGHUP: 1, SIGINT: 2, SIGQUIT: 3, SIGKILL: 9, SIGTERM: 15 };

const FILTERS = {
  'gradle-test':  require('../lib/filters/gradle_test'),
  checkstyle:     require('../lib/filters/checkstyle'),
  spotbugs:       require('../lib/filters/spotbugs'),
  semgrep:        require('../lib/filters/semgrep'),
};

const args = process.argv.slice(2);
const dashDash = args.indexOf('--');

if (args.length < 2 || dashDash === -1) {
  process.stderr.write('Usage: ac-filter.js <filter-type> -- <command...>\n');
  process.exit(1);
}

const filterType = args[0];
const cmdArgs = args.slice(dashDash + 1);
const fullCommand = cmdArgs.join(' ');

if (filterType === 'semgrep') {
  if (!cmdArgs.includes('--json')) cmdArgs.push('--json');
}

const result = spawnSync(cmdArgs[0], cmdArgs.slice(1), {
  encoding: 'utf8',
  stdio: ['inherit', 'pipe', 'pipe'],
  env: { ...process.env },
  timeout: TIMEOUT_MS,
});

const outcome = describe(result);

const stdout = result.stdout || '';
const stderr = result.stderr || '';
const combined = stderr && !stdout.includes(stderr.slice(0, 40))
  ? stdout + '\n' + stderr
  : stdout;

process.stdout.write(render(combined, outcome));
process.exit(outcome.code);

function describe(r) {
  if (r.error && r.error.code === 'ETIMEDOUT') return fromTimeout();
  if (typeof r.status === 'number') return fromStatus(r.status);
  if (r.signal) return fromSignal(r.signal);
  return fromSpawnFailure(r);
}

function fromTimeout() {
  return {
    ok: false,
    code: 124,
    banner: `TIMEOUT: comando excedeu ${TIMEOUT_MS / 1000}s e foi morto. Saida parcial abaixo.`,
  };
}

function fromStatus(status) {
  return { ok: status === 0, code: status, banner: status === 0 ? null : `EXIT ${status}` };
}

function fromSignal(signal) {
  const code = 128 + (SIGNAL_NUMBERS[signal] ?? 15);
  return { ok: false, code, banner: `KILLED por ${signal} (exit ${code})` };
}

function fromSpawnFailure(r) {
  const why = r.error ? r.error.message : 'comando nao produziu status de saida';
  return { ok: false, code: 1, banner: `FALHA AO EXECUTAR: ${why}` };
}

function render(raw, outcome) {
  const body = applyFilter(raw, outcome);
  if (outcome.banner === null) return body;

  const hint = `(saida bruta: rode o comando sem o ac-filter, ou com AC_HOOKS_DISABLED=1)`;
  return `${outcome.banner}\n${hint}\n\n${body}`;
}

function applyFilter(raw, outcome) {
  if (!Object.hasOwn(FILTERS, filterType)) return raw;
  const filter = FILTERS[filterType];

  try {
    const compressed = filter.compress(raw, filterType, outcome);
    if (!outcome.ok && !compressed.trim()) return raw;
    return compressed;
  } catch {
    return raw;
  }
}
