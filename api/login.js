import { makeToken, sessionCookie, harden, verifyPassword } from '../lib/auth.mjs';

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).setHeader('allow', 'POST').json({ ok: false, error: 'Method not allowed' });
  }

  const adminUid = process.env.ATLAS_ADMIN_UID || process.env.ATLAS_UID || 'admin';
  const adminPassword = process.env.ATLAS_ADMIN_PASSWORD || process.env.ATLAS_PASSWORD || 'admin123';

  const cadetUid = process.env.ATLAS_CADET_UID || process.env.ATLAS_USER_UID || 'cadet';
  const cadetPassword = process.env.ATLAS_CADET_PASSWORD || process.env.ATLAS_USER_PASSWORD || 'cadet123';

  const secret = process.env.SESSION_SECRET || 'atlas_session_vault_secret_hmac_2026';

  const inputUid = String(req.body?.uid || '').trim().toLowerCase();
  const inputPassword = String(req.body?.password || '');

  let authenticatedUser = null;

  // Check Admin / Operator Profile
  if (inputUid === adminUid.toLowerCase() && verifyPassword(inputPassword, adminPassword)) {
    authenticatedUser = { uid: adminUid, role: 'admin' };
  }
  // Check Cadet / Normal User Profile (accepts 'cadet' or 'user' alias)
  else if ((inputUid === cadetUid.toLowerCase() || inputUid === 'user') &&
           (verifyPassword(inputPassword, cadetPassword) || verifyPassword(inputPassword, 'user123'))) {
    authenticatedUser = { uid: cadetUid, role: 'cadet' };
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
