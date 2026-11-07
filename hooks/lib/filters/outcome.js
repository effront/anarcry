const TAIL_LINES = 20;

function failed(outcome) {
  return Boolean(outcome && outcome.ok === false);
}

function unverified(tool, output, lines = TAIL_LINES) {
  const tail = output
    .split('\n')
    .filter(l => l.trim())
    .slice(-lines)
    .join('\n');

  return `${tool}: comando falhou, "sem achados" nao verificado.\n\n${tail}`;
}

module.exports = { failed, unverified, TAIL_LINES };
