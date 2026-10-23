import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

// Automatically load .env / .env.local if present and not already loaded in process.env
try {
  for (const file of ['.env.local', '.env']) {
    const p = path.resolve(process.cwd(), file);
    if (fs.existsSync(p)) {
      const content = fs.readFileSync(p, 'utf8');
      for (const line of content.split('\n')) {
        const trimmed = line.trim();
        if (!trimmed || trimmed.startsWith('#')) continue;
        const eq = trimmed.indexOf('=');
        if (eq > 0) {
          const key = trimmed.slice(0, eq).trim();
          let val = trimmed.slice(eq + 1).trim();
          if ((val.startsWith('"') && val.endsWith('"')) || (val.startsWith("'") && val.endsWith("'"))) {
            val = val.slice(1, -1);
          }
          if (process.env[key] === undefined) {
            process.env[key] = val;
          }
        }
      }
    }
  }
} catch {}

export const COOKIE = 'ctf_atlas_session';
export const TTL = 60 * 60 * 12;

export function getCookie(req, name) {
  const raw = req.headers?.cookie || '';
  for (const piece of raw.split(';')) {
    const [k, ...rest] = piece.trim().split('=');
    if (k === name) return rest.join('=');
  }
  return null;
}

export function makeToken(user, secret) {
  const uid = typeof user === 'object' && user !== null ? user.uid : String(user || '');
  const role = typeof user === 'object' && user !== null ? (user.role || 'cadet') : 'admin';
  const now = Math.floor(Date.now() / 1000);
  const payload = Buffer.from(JSON.stringify({
    uid,
    role,
    iat: now,
    exp: now + TTL
  })).toString('base64url');
  const sig = crypto.createHmac('sha256', secret).update(payload).digest('base64url');
  return payload + '.' + sig;
}

export function readToken(token, secret) {
  try {
    const [payload, sig] = String(token || '').split('.');
    if (!payload || !sig || !secret) return null;
    const expected = crypto.createHmac('sha256', secret).update(payload).digest();
    const got = Buffer.from(sig, 'base64url');
    if (got.length !== expected.length || !crypto.timingSafeEqual(got, expected)) return null;
    const data = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
    if (!data.exp || data.exp < Math.floor(Date.now() / 1000)) return null;
    if (!data.role) data.role = 'admin';
    return data;
  } catch {
    return null;
  }
}

export function verifyPassword(inputPassword, expectedPassword) {
  if (typeof inputPassword !== 'string' || typeof expectedPassword !== 'string') return false;
  const hashA = crypto.createHash('sha256').update(inputPassword).digest();
  const hashB = crypto.createHash('sha256').update(expectedPassword).digest();
  return crypto.timingSafeEqual(hashA, hashB);
}

export function sessionCookie(token, isSecure = false) {
  const sec = isSecure ? '; Secure' : '';
  return `${COOKIE}=${token}; Max-Age=${TTL}; Path=/; HttpOnly${sec}; SameSite=Strict`;
}

export function clearCookie() {
  return `${COOKIE}=; Max-Age=0; Path=/; HttpOnly; SameSite=Strict`;
}

export function harden(headers = {}) {
  return {
    'cache-control': 'no-store, no-cache, must-revalidate, proxy-revalidate',
    'x-content-type-options': 'nosniff',
    'x-frame-options': 'DENY',
    'x-xss-protection': '1; mode=block',
    'referrer-policy': 'no-referrer',
    'permissions-policy': 'camera=(), microphone=(), geolocation=()',
    ...headers
  };
}
