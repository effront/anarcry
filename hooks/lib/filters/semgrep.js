const { failed, unverified } = require('./outcome');

const TOP_RULES = 10;
const EXAMPLES_PER_RULE = 2;

function compress(output, _type, outcome) {
  const trimmed = output.trimStart();

  if (trimmed.startsWith('{')) {
    try {
      return compressJson(JSON.parse(output), outcome, output);
    } catch { /* not valid JSON, fall through to text mode */ }
  }

  return compressText(output.split('\n'), outcome, output);
}

function compressJson(data, outcome, raw) {
  const results = data.results || [];

  if (results.length === 0) {
    if (failed(outcome)) return unverified('Semgrep', raw);
    return 'Semgrep: clean. 0 findings.';
  }

  const byRule = {};
  for (const r of results) {
    const rule = r.check_id || 'unknown';
    const severity = r.extra?.severity || '?';
    const entry = byRule[rule] || (byRule[rule] = { count: 0, severity, examples: [] });
    entry.count++;
    if (entry.examples.length < EXAMPLES_PER_RULE) {
      const file = (r.path || '').replace(/^.*\/(src\/)/, '$1');
      entry.examples.push(`${file}:${r.start?.line || '?'}`);
    }
  }

  return formatFindings(results.length, byRule);
}

function compressText(lines, outcome, raw) {
  const findings = [];

  for (const line of lines) {
    const m = line.match(/^\s*(.+\.java):(\d+)\s/);
    if (m) {
      findings.push({ file: m[1].replace(/^.*\/(src\/)/, '$1'), line: m[2] });
    }
  }

  if (findings.length === 0) {
    if (failed(outcome)) return unverified('Semgrep', raw);

    const summaryLine = lines.find(l => /ran \d+ rules?/i.test(l));
    return summaryLine ? `Semgrep: ${summaryLine.trim()}` : 'Semgrep: clean.';
  }

  return `SEMGREP: ${findings.length} findings (text mode - rerun with --json for detail)\n` +
    findings.slice(0, 10).map(f => `  ${f.file}:${f.line}`).join('\n');
}

function formatFindings(total, byRule) {
  const sorted = Object.entries(byRule)
    .sort(([, a], [, b]) => b.count - a.count)
    .slice(0, TOP_RULES);

  const result = [
    `SEMGREP: ${total} findings\n`,
    'TOP RULES:',
    ...sorted.map(([rule, info]) => {
      const short = rule.split('.').slice(-2).join('.');
      const more = info.count > EXAMPLES_PER_RULE ? ', ...' : '';
      return `  [${info.severity}] ${short}: ${info.count}x  (${info.examples.join(', ')}${more})`;
    }),
  ];

  const remaining = Object.keys(byRule).length - sorted.length;
  if (remaining > 0) result.push(`  ...${remaining} more rules`);

  return result.join('\n');
}

module.exports = { compress };
