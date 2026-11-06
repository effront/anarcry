const SAFE = /^[A-Za-z0-9_@%+=:,./-]+$/;
const ESCAPED_QUOTE = "'\\''";

function shellArg(value) {
  const s = String(value);
  if (s !== '' && SAFE.test(s)) return s;
  return `'${s.replace(/'/g, ESCAPED_QUOTE)}'`;
}

function scriptIn(command, dir) {
  const c = String(command || '');
  const d = String(dir);

  for (const form of new Set([d, d.replace(/'/g, ESCAPED_QUOTE)])) {
    const start = c.indexOf(`${form}/`);
    if (start === -1) continue;

    const m = c.slice(start).match(/^(.+?\.(?:js|sh))(?=$|["'\s])/);
    if (!m) continue;

    return c[start - 1] === "'"
      ? m[1].split(ESCAPED_QUOTE).join("'")
      : m[1];
  }

  return null;
}

module.exports = { shellArg, scriptIn };
