const fs = require('fs');
const path = require('path');

const PROJECT_MARKER = 'AnarCry';
const MAX_TRAVERSAL_DEPTH = 10;

function isAnarcryProject(cwd) {
  return String(cwd || '').includes(PROJECT_MARKER);
}

function safeStart(cwd) {
  const candidate = String(cwd || '');
  try {
    const resolved = fs.realpathSync(candidate);
    if (path.isAbsolute(resolved) && fs.statSync(resolved).isDirectory()) {
      return resolved;
    }
  } catch { /* unresolvable path, use cwd */ }
  return process.cwd();
}

function projectRoot(cwd) {
  const start = safeStart(cwd);
  let dir = start;
  let depth = 0;

  while (depth < MAX_TRAVERSAL_DEPTH) {
    const gradlePath = path.join(dir, 'build.gradle');
    const gitPath = path.join(dir, '.git');
    try {
      const resolvedGradle = path.resolve(dir, 'build.gradle');
      const resolvedGit = path.resolve(dir, '.git');
      if (resolvedGradle.startsWith(dir) && fs.existsSync(gradlePath)) {
        return dir;
      }
      if (resolvedGit.startsWith(dir) && fs.existsSync(gitPath)) {
        return dir;
      }
    } catch { /* fs access failed, try parent */ }
    const parent = path.dirname(dir);
    if (parent === dir) return start;
    dir = parent;
    depth++;
  }
  return start;
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
