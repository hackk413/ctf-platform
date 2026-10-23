import { getCookie, readToken, harden } from '../lib/auth.mjs';
import { portalHtml, portalCss, portalJs } from '../lib/assets.mjs';

function denied(res) {
  Object.entries(harden({ 'content-type': 'text/plain; charset=utf-8' }))
    .forEach(([k, v]) => res.setHeader(k, v));
  return res.status(302).setHeader('location', '/').end();
}

export default function handler(req, res) {
  const secret = process.env.SESSION_SECRET || 'atlas_session_vault_secret_hmac_2026';
  const data = readToken(getCookie(req, 'ctf_atlas_session'), secret);
  if (!data) return denied(res);

  const safeCss = portalCss.replace(/<\/style/gi, () => '<\\/style');
  const safeJs = portalJs.replace(/<\/script/gi, () => '<\\/script');

  const userSessionScript = `<script>window.ATLAS_USER = ${JSON.stringify({ uid: data.uid, role: data.role || 'cadet' })};</script>`;

  let html = portalHtml
    .replace('<link rel="stylesheet" href="styles.css">', () => '<style>' + safeCss + '</style>')
    .replace('<script src="app.js"></script>', () => userSessionScript + '<script>' + safeJs + '</script>');

  html = html.replace(
    '<title>CTF Atlas // Secure Learning Range</title>',
    '<title>CTF ATLAS // CYBERSECURITY RANGE</title>'
  );

  Object.entries(harden({ 'content-type': 'text/html; charset=utf-8' }))
    .forEach(([k, v]) => res.setHeader(k, v));

  return res.status(200).send(html);
}
