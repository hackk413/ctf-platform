import fs from 'node:fs';
import { getCookie, readToken, harden } from '../lib/auth.mjs';

function loadIntel() {
  try {
    return JSON.parse(fs.readFileSync(new URL('../data/live-intel.json', import.meta.url), 'utf8'));
  } catch {
    return {
      updatedAt: null,
      status: 'unavailable',
      summary: { vulnerabilities: 0, kev: 0, releases: 0, signals: 0 },
      items: [],
      topicSignals: [],
      sources: [],
      curriculum: [],
      notes: ['No intelligence snapshot is available yet.']
    };
  }
}

export default function handler(req, res) {
  const secret = process.env.SESSION_SECRET || 'atlas_session_vault_secret_hmac_2026';
  const session = readToken(getCookie(req, 'ctf_atlas_session'), secret);
  const headers = harden({ 'content-type': 'application/json; charset=utf-8' });
  Object.entries(headers).forEach(([k, v]) => res.setHeader(k, v));

  if (!session) {
    return res.status(401).json({ ok: false, error: 'Authentication required' });
  }

  const raw = loadIntel();

  // If user is cadet, sanitize curriculum data at the network boundary
  if (session.role === 'cadet') {
    const safeCurriculum = (raw.curriculum || []).filter(m =>
      !(m.domain === 'reverse' || m.domain === 'pwn' || (m.id && (m.id.includes('pwn') || m.id.includes('reverse') || m.id.includes('binary-exploitation'))))
    );
    return res.status(200).json({ ok: true, data: { ...raw, curriculum: safeCurriculum } });
  }

  return res.status(200).json({ ok: true, data: raw });
}
