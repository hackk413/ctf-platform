import fs from 'node:fs';

const html=fs.readFileSync('site-src/portal.html','utf8');
const css=fs.readFileSync('site-src/portal.css','utf8');
const js=fs.readFileSync('site-src/portal.js','utf8');
const out=`// Generated protected assets. Do not move this file into public/.\nexport const portalHtml = ${JSON.stringify(html)};\nexport const portalCss = ${JSON.stringify(css)};\nexport const portalJs = ${JSON.stringify(js)};\n`;
fs.writeFileSync('lib/assets.mjs',out);
console.log(`built lib/assets.mjs (${out.length} bytes)`);
