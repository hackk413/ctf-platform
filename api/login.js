import { makeToken, sessionCookie, harden, verifyPassword } from '../lib/auth.mjs';

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).setHeader('allow', 'POST').json({ ok: false, error: 'Method not allowed' });
  }

  const adminUid = (process.env.ATLAS_ADMIN_UID || process.env.ATLAS_UID || 'admin').trim();
  const adminPassword = process.env.ATLAS_ADMIN_PASSWORD || process.env.ATLAS_PASSWORD || 'admin123';

  const cadetUidRaw = process.env.ATLAS_CADET_UID || process.env.ATLAS_USER_UID || 'cadet';
  const cadetPassword = process.env.ATLAS_CADET_PASSWORD || process.env.ATLAS_USER_PASSWORD || 'cadet123';

  // Support comma-separated cadet usernames: e.g. "cadet, student, tester"
  const cadetUids = cadetUidRaw.split(',').map(s => s.trim().toLowerCase()).filter(Boolean);

  // Optional JSON mapping of multiple custom cadet accounts: e.g. {"cadet":"pass1", "john":"pass2"}
  let cadetUsersMap = {};
  if (process.env.ATLAS_CADET_USERS) {
    try {
      cadetUsersMap = JSON.parse(process.env.ATLAS_CADET_USERS);
    } catch {}
  }

  const secret = process.env.SESSION_SECRET || 'atlas_session_vault_secret_hmac_2026';

  const inputUid = String(req.body?.uid || '').trim().toLowerCase();
  const inputPassword = String(req.body?.password || '');

  let authenticatedUser = null;

  // 1. Check Admin / Operator Profile
  if (inputUid === adminUid.toLowerCase() && verifyPassword(inputPassword, adminPassword)) {
    authenticatedUser = { uid: adminUid, role: 'admin' };
  }
  // 2. Check JSON multiple cadet accounts map
  else if (cadetUsersMap[inputUid] && verifyPassword(inputPassword, cadetUsersMap[inputUid])) {
    authenticatedUser = { uid: inputUid, role: 'cadet' };
  }
  // 3. Check Cadet Profile (single or comma-separated list)
  else if (cadetUids.includes(inputUid) && verifyPassword(inputPassword, cadetPassword)) {
    authenticatedUser = { uid: inputUid, role: 'cadet' };
  }
  // 4. Fallback defaults if env vars are NOT customized
  else if (!process.env.ATLAS_CADET_UID && !process.env.ATLAS_USER_UID && inputUid === 'user' && verifyPassword(inputPassword, 'user123')) {
    authenticatedUser = { uid: 'user', role: 'cadet' };
  }

  if (!authenticatedUser) {
    return res.status(401)
      .setHeader('cache-control', 'no-store')
      .json({ ok: false, error: 'Invalid UID or authentication passphrase' });
  }

  const isSecure = req.headers['x-forwarded-proto'] === 'https' || process.env.NODE_ENV === 'production';
  const token = makeToken(authenticatedUser, secret);

  const headers = harden({
    'set-cookie': sessionCookie(token, isSecure),
    'content-type': 'application/json; charset=utf-8'
  });

  Object.entries(headers).forEach(([k, v]) => res.setHeader(k, v));
  return res.status(200).json({ ok: true, uid: authenticatedUser.uid, role: authenticatedUser.role });
}
