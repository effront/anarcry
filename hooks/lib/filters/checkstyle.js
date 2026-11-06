const { failed, unverified } = require('./outcome');

const TOP_RULES = 10;
const EXAMPLES_PER_RULE = 2;

function compress(output, _type, outcome) {
  const lines = output.split('\n');
  const violations = [];

  for (const line of lines) {
    const m = line.match(/^\[WARN\]\s+(.+\.java):(\d+)(?::\d+)?:\s+(.+)\s+\[(\w+)\]$/);
    if (m) {
      violations.push({
        file: m[1].replace(/^.*\/(src\/)/, '$1'),
        line: m[2],
        message: m[3].trim(),
        rule: m[4],
      });
    }
  }

  if (violations.length === 0) {
    if (failed(outcome)) return unverified('Checkstyle', output);
    return 'Checkstyle: clean. 0 violations.';
  }

  const byRule = {};
  for (const v of violations) {
    const entry = byRule[v.rule] || (byRule[v.rule] = { count: 0, examples: [] });
    entry.count++;
    if (entry.examples.length < EXAMPLES_PER_RULE) {
      entry.examples.push(`${v.file}:${v.line}`);
    }
  }

  const sorted = Object.entries(byRule)
    .sort(([, a], [, b]) => b.count - a.count)
    .slice(0, TOP_RULES);

  const result = [
    `CHECKSTYLE: ${violations.length} violations\n`,
    'TOP RULES:',
    ...sorted.map(([rule, info]) => {
      const more = info.count > EXAMPLES_PER_RULE ? ', ...' : '';
      return `  ${rule}: ${info.count}x  (${info.examples.join(', ')}${more})`;
    }),
  ];

  const remaining = Object.keys(byRule).length - sorted.length;
  if (remaining > 0) result.push(`  ...${remaining} more rules`);

  return result.join('\n');
}

module.exports = { compress };
