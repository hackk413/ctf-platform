import assert from 'node:assert';
import { makeToken, verifyPassword } from '../lib/auth.mjs';
import loginHandler from '../api/login.js';
import sessionHandler from '../api/session.js';
import portalHandler from '../api/portal.js';
import updatesHandler from '../api/updates.js';

const SECRET = 'atlas_session_vault_secret_hmac_2026';

function mockRes() {
  const headers = {};
  let status = 200;
  let body = null;
  return {
    status(s) { status = s; return this; },
    setHeader(k, v) { headers[k.toLowerCase()] = v; return this; },
    json(data) { body = data; return this; },
    send(data) { body = data; return this; },
    end() { return this; },
    getStatus: () => status,
    getHeaders: () => headers,
    getBody: () => body
  };
}

async function testAuthTiers() {
  console.log('[TEST] 1. Authentication & Role Separation');

  // Test Admin Login
  {
    const req = { method: 'POST', body: { uid: 'admin', password: 'admin123' }, headers: {} };
    const res = mockRes();
    await loginHandler(req, res);
    assert.strictEqual(res.getStatus(), 200);
    assert.strictEqual(res.getBody().role, 'admin');
    assert(res.getHeaders()['set-cookie'].includes('ctf_atlas_session='));
    console.log('  [PASS] Admin login succeeded with role: admin');
  }

  // Test Cadet Login
  {
    const req = { method: 'POST', body: { uid: 'cadet', password: 'cadet123' }, headers: {} };
    const res = mockRes();
    await loginHandler(req, res);
    assert.strictEqual(res.getStatus(), 200);
    assert.strictEqual(res.getBody().role, 'cadet');
    console.log('  [PASS] Cadet login succeeded with role: cadet');
  }

  // Test User Alias Login
  {
    const req = { method: 'POST', body: { uid: 'user', password: 'user123' }, headers: {} };
    const res = mockRes();
    await loginHandler(req, res);
    assert.strictEqual(res.getStatus(), 200);
    assert.strictEqual(res.getBody().role, 'cadet');
    console.log('  [PASS] User alias login succeeded with role: cadet');
  }

  // Test Invalid Password
  {
    const req = { method: 'POST', body: { uid: 'cadet', password: 'wrong' }, headers: {} };
    const res = mockRes();
    await loginHandler(req, res);
    assert.strictEqual(res.getStatus(), 401);
    console.log('  [PASS] Invalid password rejected with 401');
  }
}

async function testNetworkSanitization() {
  console.log('[TEST] 2. Network Boundary & API Data Sanitization');

  const adminToken = makeToken({ uid: 'admin', role: 'admin' }, SECRET);
  const cadetToken = makeToken({ uid: 'cadet', role: 'cadet' }, SECRET);

  // Test Admin Updates Endpoint
  {
    const req = { headers: { cookie: `ctf_atlas_session=${adminToken}` } };
    const res = mockRes();
    updatesHandler(req, res);
    assert.strictEqual(res.getStatus(), 200);
    const curriculum = res.getBody().data.curriculum;
    const hasPwn = curriculum.some(m => m.id === 'binary-exploitation');
    assert.strictEqual(hasPwn, true, 'Admin MUST receive binary-exploitation');
    console.log(`  [PASS] Admin receives full curriculum (${curriculum.length} modules, including binary-exploitation)`);
  }

  // Test Cadet Updates Endpoint
  {
    const req = { headers: { cookie: `ctf_atlas_session=${cadetToken}` } };
    const res = mockRes();
    updatesHandler(req, res);
    assert.strictEqual(res.getStatus(), 200);
    const curriculum = res.getBody().data.curriculum;
    const hasPwn = curriculum.some(m => m.id === 'binary-exploitation' || m.domain === 'pwn' || m.domain === 'reverse');
    assert.strictEqual(hasPwn, false, 'Cadet MUST NOT receive binary-exploitation');
    console.log(`  [PASS] Cadet receives sanitized curriculum (${curriculum.length} modules, ZERO binary-exploitation over the wire)`);
  }
}

async function testPortalRendering() {
  console.log('[TEST] 3. Portal HTML & Title Immunity');

  const cadetToken = makeToken({ uid: 'cadet', role: 'cadet' }, SECRET);
  const req = { headers: { cookie: `ctf_atlas_session=${cadetToken}` } };
  const res = mockRes();
  portalHandler(req, res);

  assert.strictEqual(res.getStatus(), 200);
  const html = res.getBody();

  // Document Title checks
  assert(!html.includes('CADET // TRAINING NODE'), 'Title must not leak cadet/training node');
  assert(!html.includes('OPERATOR // FULL ACCESS'), 'Title must not leak operator/full access');
  assert(html.includes('<title>CTF ATLAS // CYBERSECURITY RANGE</title>'), 'Title must be professional and uniform');
  console.log('  [PASS] Document title is clean and uniform');

  // Verify no permission-denied / warning banners in assets
  assert(!html.includes('CADET NOTICE'), 'HTML must not contain CADET NOTICE');
  assert(!html.includes('OPERATOR CLEARANCE REQUIRED'), 'HTML must not contain OPERATOR CLEARANCE REQUIRED');
  assert(!html.includes('CLEARANCE NOTICE'), 'HTML must not contain CLEARANCE NOTICE');
  console.log('  [PASS] Zero clearance warnings or notices in bundled HTML');
}

async function testCadetClientStealth() {
  console.log('[TEST] 4. Client Script & DOM Navigation Stealth');
  const { portalJs } = await import('../lib/assets.mjs');

  // Check for alert() calls
  const alertMatches = portalJs.match(/alert\s*\([^)]*\)/g) || [];
  // Ensure no access denied alerts
  for (const a of alertMatches) {
    assert(!a.includes('ACCESS DENIED'), `Found ACCESS DENIED alert: ${a}`);
    assert(!a.includes('clearance'), `Found clearance alert: ${a}`);
  }
  console.log('  [PASS] Zero permission/denied alert() calls in portal script');

  // Test string leakages
  assert(!portalJs.includes('CADET NOTICE:'), 'portalJs must not contain CADET NOTICE:');
  assert(!portalJs.includes('CLEARANCE NOTICE:'), 'portalJs must not contain CLEARANCE NOTICE:');
  assert(!portalJs.includes('module-locked-pill'), 'portalJs must not contain module-locked-pill');
  console.log('  [PASS] Zero locked pills or cadet notices in portal script');

  // Test badge rendering
  assert(portalJs.includes('RANGE OPERATOR'), 'portalJs must display RANGE OPERATOR badge');
  assert(portalJs.includes('NODE:'), 'portalJs must display NODE identifier');
  assert(!portalJs.includes('RESTRICTED</span>'), 'portalJs must not display RESTRICTED badge');
  console.log('  [PASS] Profile badge displays clean RANGE OPERATOR / ACTIVE');
}

async function main() {
  console.log('====================================================');
  console.log('CTF ATLAS // CADET STEALTH & SECURITY VERIFICATION');
  console.log('====================================================');
  await testAuthTiers();
  await testNetworkSanitization();
  await testPortalRendering();
  await testCadetClientStealth();
  console.log('====================================================');
  console.log('ALL STEALTH & SECURITY TESTS PASSED! PLATFORM IMMUNE.');
  console.log('====================================================');
}

main().catch(err => {
  console.error('\n[FAIL] Test assertion failed:', err);
  process.exit(1);
});
