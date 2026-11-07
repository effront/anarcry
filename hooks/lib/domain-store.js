const fs = require('fs');
const path = require('path');
const os = require('os');

const DIR = path.join(os.homedir(), '.claude', 'ac-domain');
const PREFIX = 'session-';
const MAX_AGE_MS = 24 * 60 * 60 * 1000;

function fileFor(sessionId) {
  const safe = String(sessionId || '').replace(/[^A-Za-z0-9_-]/g, '').slice(0, 128);
  if (!safe) return null;
  return path.join(DIR, `${PREFIX}${safe}`);
}

function read(sessionId) {
  const file = fileFor(sessionId);
  if (!file) return null;
  try {
    return fs.readFileSync(file, 'utf8').trim() || null;
  } catch {
    return null;
  }
}

function write(sessionId, domain) {
  const file = fileFor(sessionId);
  if (!file) return false;
  try {
    fs.mkdirSync(DIR, { recursive: true, mode: 0o700 });
    fs.writeFileSync(file, domain, { mode: 0o600 });
    prune();
    return true;
  } catch {
    return false;
  }
}

function prune(now = Date.now()) {
  try {
    for (const name of fs.readdirSync(DIR)) {
      if (!name.startsWith(PREFIX) || name.includes('..') || name.includes('/')) continue;
      const full = path.join(DIR, name);
      try {
        if (now - fs.statSync(full).mtimeMs > MAX_AGE_MS) fs.unlinkSync(full);
      } catch { /* stale file already gone */ }
    }
  } catch { /* dir not readable */ }
}

module.exports = { read, write, prune, fileFor, DIR };
