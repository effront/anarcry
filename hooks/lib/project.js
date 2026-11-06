const fs = require('fs');
const path = require('path');

const PROJECT_MARKER = 'AnarCry';

function isAnarcryProject(cwd) {
  return String(cwd || '').includes(PROJECT_MARKER);
}

function safeStart(cwd) {
  const candidate = String(cwd || '');
  try {
    if (path.isAbsolute(candidate) && fs.statSync(candidate).isDirectory()) {
      return candidate;
    }
  } catch {}
  return process.cwd();
}

function projectRoot(cwd) {
  const start = safeStart(cwd);
  let dir = start;

  while (true) {
    if (fs.existsSync(path.join(dir, 'build.gradle')) || fs.existsSync(path.join(dir, '.git'))) {
      return dir;
    }
    const parent = path.dirname(dir);
    if (parent === dir) return start;
    dir = parent;
  }
}

function anarcryVersion(cwd) {
  const gradle = path.join(projectRoot(cwd), 'build.gradle');
  try {
    const content = fs.readFileSync(gradle, 'utf8');
    const m = content.match(/version\s*=\s*['"](\d+\.\d+\.\d+)['"]/);
    return m ? m[1] : null;
  } catch {
    return null;
  }
}

module.exports = { isAnarcryProject, projectRoot, anarcryVersion, PROJECT_MARKER };
