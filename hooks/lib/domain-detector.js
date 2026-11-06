const { execFileSync } = require('child_process');
const { projectRoot } = require('./project');

const DOMAIN_PATTERNS = [
  ['testing',        /^src\/test\//],
  ['exploit',        /exploit\//],
  ['auth',           /scanner\/auth\//],
  ['web-scanner',    /scanner\/web\//],
  ['crypto-scanner', /scanner\/crypto\//],
  ['model',          /model\//],
  ['report',         /report\//],
  ['tui',            /tui\//],
  ['gui',            /gui\//],
  ['assistant',      /assistant\//],
  ['infra',          /\.github\/|build\.gradle|Dockerfile|\.env/],
];

function detect(cwd) {
  const root = projectRoot(cwd);

  try {
    const status = execFileSync('git', ['-C', root, 'status', '--short'], {
      encoding: 'utf8',
      timeout: 3000,
      stdio: ['ignore', 'pipe', 'ignore'],
    });

    const files = status
      .split('\n')
      .map(l => l.trim().replace(/^\S+\s+/, ''))
      .filter(Boolean);

    if (files.length === 0) return 'general';

    for (const [domain, pattern] of DOMAIN_PATTERNS) {
      if (files.some(f => pattern.test(f))) return domain;
    }

    return 'general';
  } catch {
    return 'general';
  }
}

module.exports = { detect, DOMAIN_PATTERNS };
