#!/usr/bin/env bash
# Instala os hooks do AnarCry no settings.json do projeto.
#
# Uso:  ./install.sh [caminho-do-projeto]
# Sem argumento, usa o diretorio pai (AnarCry root).

set -euo pipefail

HOOKS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="${1:-$(dirname "$HOOKS_DIR")}"

if [[ ! -d "$PROJECT_DIR" ]]; then
  echo "erro: projeto nao encontrado: $PROJECT_DIR" >&2
  exit 1
fi

PROJECT_DIR="$(cd "$PROJECT_DIR" && pwd)"
SETTINGS_FILE="${PROJECT_DIR}/.claude/settings.json"

echo "AnarCry Hooks: instalando em ${SETTINGS_FILE}"

chmod +x "$HOOKS_DIR/bin/ac-filter.js"

node - "$HOOKS_DIR" "$SETTINGS_FILE" << 'JSEOF'
const fs   = require('fs');
const path = require('path');

const [,, hooksDir, settingsFile] = process.argv;

const { shellArg, scriptIn } = require(path.join(hooksDir, 'lib', 'shell.js'));

const ourScript = command => scriptIn(command, hooksDir);
const cmd = rel => `node ${shellArg(`${hooksDir}/${rel}`)}`;

let settings = {};
if (fs.existsSync(settingsFile)) {
  const raw = fs.readFileSync(settingsFile, 'utf8');
  try {
    settings = JSON.parse(raw);
  } catch (err) {
    console.error(`erro: ${settingsFile} existe mas nao e JSON valido (${err.message}).`);
    console.error('corrija o arquivo ou mova ele antes de instalar.');
    process.exit(1);
  }

  const backup = `${settingsFile}.bak`;
  fs.writeFileSync(backup, raw);
  console.log('backup:', backup);
}

settings.hooks = settings.hooks || {};

function addHook(section, entry) {
  const list = settings.hooks[section] || (settings.hooks[section] = []);
  const ours = entry.hooks[0].command;
  const script = ourScript(ours);

  for (const existing of list) {
    const hook = (existing.hooks || []).find(h => ourScript(h.command) === script);
    if (hook) {
      hook.command = ours;
      return;
    }
  }

  list.push(entry);
}

addHook('SessionStart', {
  hooks: [{ type: 'command', command: cmd('hooks/session-start.js') }],
});

addHook('PreToolUse', {
  matcher: 'Bash',
  hooks: [{ type: 'command', command: cmd('hooks/pre-tool-use.js') }],
});

function isOrphan(hook) {
  const script = ourScript(hook.command);
  return script !== null && !fs.existsSync(script);
}

function pruneOrphans() {
  let removed = 0;

  for (const [section, list] of Object.entries(settings.hooks)) {
    const kept = [];

    for (const entry of list) {
      if (!Array.isArray(entry.hooks)) {
        kept.push(entry);
        continue;
      }

      const hooks = entry.hooks.filter(h => {
        if (!isOrphan(h)) return true;
        removed++;
        return false;
      });

      if (hooks.length > 0) kept.push({ ...entry, hooks });
    }

    if (kept.length > 0) settings.hooks[section] = kept;
    else delete settings.hooks[section];
  }

  if (removed > 0) console.log(`removidos ${removed} hook(s) apontando para script inexistente`);
}

pruneOrphans();

fs.mkdirSync(path.dirname(settingsFile), { recursive: true });
fs.writeFileSync(settingsFile, JSON.stringify(settings, null, 2) + '\n');
console.log('hooks instalados em:', settingsFile);
JSEOF

echo ""
echo "Reinicie o Claude Code para ativar."
echo "Para desativar temporariamente: AC_HOOKS_DISABLED=1"
