const { failed, unverified } = require('./outcome');

const TOP_FAILURES = 10;

function compress(output, _type, outcome) {
  const lines = output.split('\n');

  const failures = [];
  const skipped = [];
  let totalTests = 0;
  let totalFailed = 0;
  let totalSkipped = 0;

  for (const line of lines) {
    const resultMatch = line.match(/(\d+) tests?,\s*(\d+) failures?(?:,\s*(\d+) skipped)?/i);
    if (resultMatch) {
      totalTests += parseInt(resultMatch[1], 10);
      totalFailed += parseInt(resultMatch[2], 10);
      totalSkipped += parseInt(resultMatch[3] || '0', 10);
    }

    const failMatch = line.match(/^\s*(\S+)\s+>\s+(\S+)\s+FAILED$/);
    if (failMatch) {
      failures.push({ cls: failMatch[1], method: failMatch[2] });
    }

    const skipMatch = line.match(/^\s*(\S+)\s+>\s+(\S+)\s+SKIPPED$/);
    if (skipMatch) {
      skipped.push({ cls: skipMatch[1], method: skipMatch[2] });
    }
  }

  if (failures.length === 0 && totalFailed === 0) {
    if (failed(outcome)) return unverified('Gradle Test', output);
    return `Gradle Test: PASSED. ${totalTests} tests, 0 failures, ${totalSkipped} skipped.`;
  }

  const shown = failures.slice(0, TOP_FAILURES);
  const result = [
    `GRADLE TEST: ${totalTests} tests, ${totalFailed} failures, ${totalSkipped} skipped\n`,
    'FAILURES:',
    ...shown.map(f => `  ${f.cls} > ${f.method}`),
  ];

  const remaining = failures.length - shown.length;
  if (remaining > 0) result.push(`  ...${remaining} more failures`);

  return result.join('\n');
}

module.exports = { compress };
