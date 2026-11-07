const { failed, unverified } = require('./outcome');

const TOP_BUGS = 10;

function compress(output, _type, outcome) {
  const lines = output.split('\n');
  const bugs = [];

  for (const line of lines) {
    const m = line.match(/^([A-Z])\s+([A-Z_]+):\s+(.+?)\s+At\s+(.+\.java):\[line\s+(\d+)\]/i)
           || line.match(/^([A-Z])\s+([A-Z_]+):\s+(.+?)\s+In\s+([\w.]+)/i);
    if (m) {
      bugs.push({
        priority: m[1],
        type: m[2],
        message: m[3].trim(),
        location: m[4] + (m[5] ? ':' + m[5] : ''),
      });
    }
  }

  if (bugs.length === 0) {
    if (failed(outcome)) return unverified('SpotBugs', output);
    return 'SpotBugs: clean. 0 bugs found.';
  }

  const byType = {};
  for (const b of bugs) {
    const entry = byType[b.type] || (byType[b.type] = { count: 0, priority: b.priority, examples: [] });
    entry.count++;
    if (entry.examples.length < 2) {
      entry.examples.push(b.location);
    }
  }

  const sorted = Object.entries(byType)
    .sort(([, a], [, b]) => b.count - a.count)
    .slice(0, TOP_BUGS);

  const result = [
    `SPOTBUGS: ${bugs.length} bugs\n`,
    'TOP BUGS:',
    ...sorted.map(([type, info]) => {
      const more = info.count > 2 ? ', ...' : '';
      return `  [${info.priority}] ${type}: ${info.count}x  (${info.examples.join(', ')}${more})`;
    }),
  ];

  return result.join('\n');
}

module.exports = { compress };
