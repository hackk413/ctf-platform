import { getCookie, readToken, harden } from '../lib/auth.mjs';

export default function handler(req, res) {
  const secret = process.env.SESSION_SECRET || 'atlas_session_vault_secret_hmac_2026';
  const data = readToken(getCookie(req, 'ctf_atlas_session'), secret);

  Object.entries(harden({ 'content-type': 'application/json; charset=utf-8' }))
    .forEach(([k, v]) => res.setHeader(k, v));

  if (!data) {
    return res.status(401).json({ ok: false, error: 'Unauthenticated' });
  }

  return res.status(200).json({
    ok: true,
    uid: data.uid,
    role: data.role || 'cadet'
  });
}
