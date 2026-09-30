/**
 * CTF Atlas — scripts/build-assets.mjs  v2.0
 * Bundles portal HTML, CSS, JS, and the terminal engine
 * into lib/assets.mjs for the authenticated portal API route.
 *
 * Usage: node scripts/build-assets.mjs
 */

import fs from 'node:fs';
import path from 'node:path';

const ROOT = process.cwd();

function read(rel) {
  const full = path.join(ROOT, rel);
  if (!fs.existsSync(full)) {
    console.warn(`  WARNING: ${full} not found, using empty string.`);
    return '';
  }
  return fs.readFileSync(full, 'utf8');
}

const html           = read('site-src/portal.html');
const css            = read('site-src/portal.css');
const js             = read('site-src/portal.js');
const terminalEngine = read('site-src/terminal-engine.js');
const textbookData   = read('site-src/textbook-data.js');

/* Build combined app.js (textbook-data.js + terminal-engine.js + portal.js) for the portal */
const combinedJs = [
  '/* CTF Atlas — Combined Portal App (auto-generated, do not edit) */',
  '/* textbook-data.js */',
  textbookData,
  '',
  '/* terminal-engine.js */',
  terminalEngine,
  '',
  '/* portal.js */',
  js,
  '',
  '/* Terminal engine global mount binding */',
  'if (typeof mountTerminal !== "undefined") { window.mountTerminal = mountTerminal; }',
].join('\n');

const safeCombinedJs = combinedJs.replace(/<\/script/gi, '<\\/script');
const safeCss = css.replace(/<\/style/gi, '<\\/style');

const out = [
  '// Generated protected assets. Do not move this file into public/.',
  '// Do not edit manually — run: node scripts/build-assets.mjs',
  `export const portalHtml = ${JSON.stringify(html)};`,
  `export const portalCss  = ${JSON.stringify(safeCss)};`,
  `export const portalJs   = ${JSON.stringify(safeCombinedJs)};`,
  `export const terminalEngineJs = ${JSON.stringify(terminalEngine)};`,
  '',
].join('\n');

const outPath = path.join(ROOT, 'lib', 'assets.mjs');
fs.mkdirSync(path.dirname(outPath), { recursive: true });
fs.writeFileSync(outPath, out);

console.log(`[build-assets] Built lib/assets.mjs`);
console.log(`  portal.html:        ${html.length.toLocaleString()} bytes`);
console.log(`  portal.css:         ${css.length.toLocaleString()} bytes`);
console.log(`  portal.js:          ${js.length.toLocaleString()} bytes`);
console.log(`  terminal-engine.js: ${terminalEngine.length.toLocaleString()} bytes`);
console.log(`  combined app.js:    ${combinedJs.length.toLocaleString()} bytes`);
console.log(`  Total output:       ${out.length.toLocaleString()} bytes`);
