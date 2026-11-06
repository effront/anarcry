#!/usr/bin/env node
// PreToolUse hook: intercepts Bash tool calls and routes AnarCry commands through ac-filter

const path = require('path');
const { isAnarcryProject } = require('../lib/project');
const { shellArg } = require('../lib/shell');

const ROOT = path.join(__dirname, '..');
const AC_FILTER = shellArg(path.join(ROOT, 'bin', 'ac-filter.js'));

if (require.main === module) main();

function main() {
  let input = '';
  process.stdin.on('data', chunk => (input += chunk));
  process.stdin.on('end', () => handle(input));
}

function handle(input) {
  let payload;
  try {
    payload = JSON.parse(input);
  } catch {
    process.exit(0);
  }

  const command = (payload.tool_input?.command || '').trim();
  if (!applies(payload, command)) process.exit(0);

  const rewrite = getRewrite(command);
  if (!rewrite) process.exit(0);

  process.stdout.write(
    JSON.stringify({
      hookSpecificOutput: {
        hookEventName: 'PreToolUse',
        updatedInput: {
          ...payload.tool_input,
          command: rewrite,
        },
      },
    })
  );
  process.exit(0);
}

function applies(payload, command) {
  if (payload.tool_name !== 'Bash') return false;
  if (!command) return false;
  if (process.env.AC_HOOKS_DISABLED === '1') return false;

  return isAnarcryProject(payload.cwd) ||
    isAnarcryProject(payload.transcript_path) ||
    isAnarcryProject(process.cwd());
}

function getFilterType(command) {
  const c = command.trim();
  const checks = [
    [/\.\/gradlew\s+test\b/,                  'gradle-test'],
    [/\.\/gradlew\s+\S*test\S*\b/i,           'gradle-test'],
    [/\.\/gradlew\s+\S*checkstyle\S*/i,       'checkstyle'],
    [/\.\/gradlew\s+\S*spotbugs\S*/i,         'spotbugs'],
    [/^semgrep\s/,                             'semgrep'],
  ];

  for (const [pattern, type] of checks) {
    if (pattern.test(c)) return type;
  }
  return null;
}

function getRewrite(command) {
  const c = command.trim();

  if (c.includes('ac-filter.js')) return null;

  const type = getFilterType(c);
  if (type) return `node ${AC_FILTER} ${type} -- ${c}`;

  return null;
}

module.exports = { getRewrite, getFilterType };
