#!/usr/bin/env node
/**
 * CTF Atlas — scripts/update-intel.mjs  v2.0
 * Techniques & Writeups Aggregator
 *
 * Fetches curated security intelligence from:
 * - CISA Known Exploited Vulnerabilities (KEV) catalog
 * - NVD CVE API (recent 3-day window)
 * - GitHub release Atom feeds (OWASP, pwntools, Juice Shop)
 * - GTFOBins JSON feed (SUID privilege escalation techniques)
 *
 * Validates all items against a strict schema, deduplicates,
 * and merges into data/live-intel.json preserving the curriculum
 * section written by the curriculum builder.
 *
 * Usage:
 *   node scripts/update-intel.mjs
 *   node scripts/update-intel.mjs --dry-run
 *   node scripts/update-intel.mjs --max-items=50
 */

import fs   from 'node:fs/promises';
import path from 'node:path';

/* ── Configuration ─────────────────────────────────────── */
const ROOT = process.cwd();
const OUT  = path.join(ROOT, 'data', 'live-intel.json');
const UA   = 'CTF-Atlas-Intelligence/2.0 (+https://github.com/hackk413/ctf-platform)';
const now  = new Date();

const args       = process.argv.slice(2);
const DRY_RUN    = args.includes('--dry-run');
const MAX_ITEMS  = parseInt(args.find(a => a.startsWith('--max-items='))?.split('=')[1] ?? '90', 10);
const VERBOSE    = args.includes('--verbose') || args.includes('-v');

/* ── Source definitions ─────────────────────────────────── */
const sources = [
  {
    id:   'cisa-kev',
    name: 'CISA Known Exploited Vulnerabilities',
    type: 'kev',
    url:  'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
  },
  {
    id:   'nvd',
    name: 'NVD CVE API',
    type: 'nvd',
    url:  'https://services.nvd.nist.gov/rest/json/cves/2.0',
  },
  {
    id:   'owasp-top10',
    name: 'OWASP Top 10 repository',
    type: 'github-atom',
    url:  'https://github.com/OWASP/Top10/releases.atom',
  },
  {
    id:   'juice-shop',
    name: 'OWASP Juice Shop releases',
    type: 'github-atom',
    url:  'https://github.com/OWASP/juice-shop/releases.atom',
  },
  {
    id:   'pwntools',
    name: 'pwntools releases',
    type: 'github-atom',
    url:  'https://github.com/Gallopsled/pwntools/releases.atom',
  },
  {
    id:   'gtfobins',
    name: 'GTFOBins technique list',
    type: 'gtfobins',
    url:  'https://gtfobins.github.io/index.json',
  },
];

/* ── Topic taxonomy for auto-classification ─────────────── */
const taxonomy = [
  ['web',          'web security',          'web, http, api, csrf, xss, ssrf, injection, authentication, authorization, browser, oauth, jwt, cors, sql, sqli, php, wordpress, drupal'],
  ['crypto',       'cryptography',          'crypto, cipher, rsa, ecc, aes, des, hash, hashing, hmac, signature, nonce, random, openssl, tls, ssl, certificate'],
  ['binary',       'binary exploitation',   'buffer overflow, rop, ret2libc, format string, heap, elf, assembly, gdb, pwntools, shellcode, stack, bof, use-after-free'],
  ['reverse',      'reverse engineering',   'reverse engineering, ghidra, ida, debugger, assembly, decompiler, obfuscation, crackme, keygen, patch'],
  ['forensics',    'digital forensics',     'forensics, pcap, wireshark, memory, disk, artifact, timeline, evtx, registry, volatility, strings, binwalk, exif'],
  ['osint',        'osint',                 'osint, reconnaissance, domain, dns, metadata, search, public information, shodan, censys, whois, certificate transparency'],
  ['cloud',        'cloud and containers',  'cloud, kubernetes, docker, container, iam, metadata service, workload identity, aws, gcp, azure, eks, serverless'],
  ['supply-chain', 'software supply chain', 'dependency, package, ci/cd, supply chain, sbom, build, signing, npm, pypi, maven, gradle'],
  ['identity',     'identity and access',   'identity, authentication, authorization, kerberos, ldap, sso, oauth, saml, mfa, privilege, suid, sudo'],
  ['blue-team',    'detection and response','detection, logging, alert, siem, yara, sigma, incident response, hunting, edr, xdr, splunk, elastic'],
  ['linux',        'linux and systems',     'linux, kernel, suid, syscall, privilege escalation, gtfobins, cve linux, bash, shell, process, inode'],
  ['stego',        'steganography',         'steganography, stego, lsb, hidden, image, audio, steghide, zsteg, png, jpeg'],
];

/* ── Utility functions ──────────────────────────────────── */
function normalize(s = '') {
  return s.toLowerCase().replace(/\s+/g, ' ').trim();
}

function stripHtml(s = '') {
  return s
    .replace(/<script[\s\S]*?<\/script>/gi, ' ')
    .replace(/<style[\s\S]*?<\/style>/gi, ' ')
    .replace(/<[^>]+>/g, ' ')
    .replace(/&amp;/g, '&').replace(/&lt;/g, '<').replace(/&gt;/g, '>')
    .replace(/&#39;/g, "'").replace(/&quot;/g, '"').replace(/&#x27;/g, "'")
    .replace(/\s+/g, ' ')
    .trim();
}

function isoOrNull(x) {
  const d = new Date(x);
  return Number.isNaN(d.valueOf()) ? null : d.toISOString();
}

function topicFor(text) {
  const n      = normalize(text);
  const scored = taxonomy.map(([id, label, keys]) => {
    const score = keys.split(', ').reduce((a, k) => a + (n.includes(k) ? 1 : 0), 0);
    return { id, label, score };
  }).sort((a, b) => b.score - a.score);
  return scored[0].score > 0 ? scored[0] : { id: 'general', label: 'general security', score: 0 };
}

async function fetchText(url, timeout = 30000) {
  const controller = new AbortController();
  const timer      = setTimeout(() => controller.abort(), timeout);
  try {
    const r = await fetch(url, {
      headers: {
        'user-agent': UA,
        'accept':     'application/json, application/xml, text/xml, text/plain, text/html;q=0.9, */*;q=0.8',
      },
      signal: controller.signal,
    });
    if (!r.ok) throw new Error(`HTTP ${r.status} ${r.statusText}`);
    return await r.text();
  } finally {
    clearTimeout(timer);
  }
}

/* ── Item schema validator ──────────────────────────────── */
/**
 * Validates and normalizes a raw item object.
 * Returns null if the item fails required fields validation.
 */
function validateItem(raw) {
  if (!raw || typeof raw !== 'object')    return null;
  if (!raw.id || typeof raw.id !== 'string' || !raw.id.trim()) return null;
  if (!raw.title || typeof raw.title !== 'string')             return null;
  if (raw.title.trim().length < 3)        return null;

  return {
    id:        String(raw.id).trim().slice(0, 200),
    kind:      ['KEV','CVE','RELEASE','TECHNIQUE','WRITEUP'].includes(raw.kind) ? raw.kind : 'CVE',
    title:     String(raw.title).trim().slice(0, 300),
    summary:   String(raw.summary || '').trim().slice(0, 500),
    date:      isoOrNull(raw.date),
    severity:  ['exploited','critical','high','medium','low','info','unknown'].includes(raw.severity)
               ? raw.severity : 'unknown',
    topic:     String(raw.topic || 'general security').trim().slice(0, 80),
    source:    String(raw.source || '').trim().slice(0, 120),
    sourceUrl: String(raw.sourceUrl || '').trim().slice(0, 500),
    ...(raw.cve     ? { cve:     String(raw.cve).trim()     } : {}),
    ...(raw.product ? { product: String(raw.product).trim() } : {}),
    ...(raw.score   ? { score:   Number(raw.score)          } : {}),
  };
}

/* ── Source readers ─────────────────────────────────────── */
async function readKev(src) {
  const j      = JSON.parse(await fetchText(src.url));
  const vulns  = Array.isArray(j.vulnerabilities) ? j.vulnerabilities : [];
  const cutoff = new Date(now.getTime() - 1000 * 60 * 60 * 24 * 45); // 45-day window

  const recent = vulns
    .filter(v => new Date(v.dateAdded || v.dateLastModified || 0) >= cutoff)
    .sort((a, b) => new Date(b.dateAdded || 0) - new Date(a.dateAdded || 0))
    .slice(0, 25);

  return recent.map(v => {
    const topic = topicFor(`${v.vulnerabilityName} ${v.shortDescription || ''} ${v.product || ''}`);
    return validateItem({
      id:        `kev:${v.cveID}`,
      kind:      'KEV',
      title:     v.vulnerabilityName || v.cveID,
      summary:   v.shortDescription  || 'CISA added this vulnerability to its Known Exploited Vulnerabilities catalog.',
      date:      v.dateAdded,
      severity:  'exploited',
      topic:     topic.label,
      source:    src.name,
      sourceUrl: `https://nvd.nist.gov/vuln/detail/${v.cveID}`,
      cve:       v.cveID,
      product:   v.product || '',
    });
  }).filter(Boolean);
}

async function readNvd(src) {
  const end   = new Date();
  const start = new Date(end.getTime() - 1000 * 60 * 60 * 24 * 3); // 3-day window
  const url   = `${src.url}?lastModStartDate=${encodeURIComponent(start.toISOString())}&lastModEndDate=${encodeURIComponent(end.toISOString())}&resultsPerPage=40`;

  const j     = JSON.parse(await fetchText(url));
  const vulns = Array.isArray(j.vulnerabilities) ? j.vulnerabilities : [];

  return vulns.slice(0, 40).map(w => {
    const v     = w.cve || {};
    const desc  = (v.descriptions || []).find(x => x.lang === 'en')?.value || '';
    const topic = topicFor(`${v.id} ${v.sourceIdentifier || ''} ${desc}`);
    const cvss  = v.metrics?.cvssMetricV31?.[0]?.cvssData
               || v.metrics?.cvssMetricV30?.[0]?.cvssData
               || v.metrics?.cvssMetricV2?.[0]?.cvssData
               || {};
    return validateItem({
      id:        `cve:${v.id}`,
      kind:      'CVE',
      title:     v.id,
      summary:   desc.slice(0, 480),
      date:      v.published || v.lastModified,
      severity:  (cvss.baseSeverity || 'unknown').toLowerCase(),
      topic:     topic.label,
      source:    src.name,
      sourceUrl: `https://nvd.nist.gov/vuln/detail/${v.id}`,
      cve:       v.id,
      score:     cvss.baseScore ?? null,
    });
  }).filter(Boolean);
}

function parseAtom(xml, src) {
  const entries = [...xml.matchAll(/<entry[\s\S]*?<\/entry>/gi)].map(m => m[0]);

  return entries.slice(0, 15).map(e => {
    const text    = tag => { const m = e.match(new RegExp(`<${tag}[^>]*>([\\s\\S]*?)<\\/${tag}>`, 'i')); return m ? stripHtml(m[1]) : ''; };
    const linkm   = e.match(/<link[^>]+href=["']([^"']+)["']/i);
    const title   = text('title');
    const summary = text('summary') || text('content');
    const date    = isoOrNull(text('updated') || text('published'));
    const url     = linkm?.[1] || src.url;
    const topic   = topicFor(`${title} ${summary}`);

    return validateItem({
      id:        `release:${src.id}:${date || title}`,
      kind:      'RELEASE',
      title,
      summary:   summary.slice(0, 400),
      date,
      severity:  'info',
      topic:     topic.label,
      source:    src.name,
      sourceUrl: url,
    });
  }).filter(Boolean);
}

async function readAtom(src) {
  return parseAtom(await fetchText(src.url), src);
}

async function readGtfobins(src) {
  /**
   * GTFOBins exposes a JSON index at /index.json listing binaries
   * and their abuse categories. We convert each to a TECHNIQUE item.
   */
  const text = await fetchText(src.url);
  let bins;
  try { bins = JSON.parse(text); }
  catch (_) {
    // Fallback: parse from HTML index
    const matches = [...text.matchAll(/href="\/([^/"]+)\/"\s*>([^<]+)</g)];
    bins = matches.map(m => ({ name: m[2].trim(), functions: [] }));
  }

  if (!Array.isArray(bins)) return [];

  return bins.slice(0, 30).map(b => {
    const name  = b.name || b.binary || String(b);
    const funcs = Array.isArray(b.functions) ? b.functions.map(f => f.type || f).join(', ') : '';
    return validateItem({
      id:        `gtfobins:${name}`,
      kind:      'TECHNIQUE',
      title:     `GTFOBins: ${name}`,
      summary:   `${name} can be exploited for: ${funcs || 'privilege escalation and file operations'}. Cross-reference with SUID enumeration (find / -perm -4000 -type f).`,
      date:      now.toISOString(),
      severity:  'high',
      topic:     'linux and systems',
      source:    src.name,
      sourceUrl: `https://gtfobins.github.io/${name}/`,
    });
  }).filter(Boolean);
}

async function readSource(src) {
  if (src.type === 'kev')         return readKev(src);
  if (src.type === 'nvd')         return readNvd(src);
  if (src.type === 'github-atom') return readAtom(src);
  if (src.type === 'gtfobins')    return readGtfobins(src);
  throw new Error(`Unknown source type: ${src.type}`);
}

/* ── Load existing data to preserve curriculum ──────────── */
async function loadExisting() {
  try {
    const raw = await fs.readFile(OUT, 'utf8');
    return JSON.parse(raw);
  } catch (_) {
    return null;
  }
}

/* ── Main execution ─────────────────────────────────────── */
console.log(`\n╔══════════════════════════════════════════════╗`);
console.log(`║  CTF Atlas — Intelligence Aggregator v2.0    ║`);
if (DRY_RUN) console.log(`║  *** DRY RUN — no files will be written ***  ║`);
console.log(`╚══════════════════════════════════════════════╝`);
console.log(`  Running at: ${now.toISOString()}\n`);

const items        = [];
const sourceStatus = [];

for (const src of sources) {
  process.stdout.write(`  Fetching ${src.name.padEnd(40)}`);
  try {
    const rows = await readSource(src);
    items.push(...rows);
    sourceStatus.push({ id: src.id, name: src.name, status: 'ok', count: rows.length, url: src.url });
    console.log(`✓ ${rows.length} items`);
  } catch (err) {
    const msg = String(err?.message || err).slice(0, 200);
    sourceStatus.push({ id: src.id, name: src.name, status: 'error', count: 0, url: src.url, error: msg });
    console.log(`✗ ${msg}`);
  }
}

/* ── Deduplicate ────────────────────────────────────────── */
items.sort((a, b) => new Date(b.date || 0) - new Date(a.date || 0));

const unique = [];
const seen   = new Set();
for (const x of items) {
  if (seen.has(x.id)) continue;
  seen.add(x.id);
  unique.push(x);
}

/* ── Topic signal aggregation ───────────────────────────── */
const topicMap = new Map();
for (const x of unique) {
  if (!x.topic) continue;
  topicMap.set(x.topic, (topicMap.get(x.topic) || 0) + 1);
}

const topicSignals = [...topicMap.entries()]
  .sort((a, b) => b[1] - a[1])
  .slice(0, 12)
  .map(([topic, count]) => ({
    topic,
    count,
    reason: `Recent source activity is clustering around ${topic}. ` +
            `Review the affected curriculum module, then add or deepen a lab ` +
            `rather than copying the advisory verbatim.`,
  }));

/* ── Load existing data to preserve curriculum section ──── */
const existing = await loadExisting();
const curriculum = existing?.curriculum || [];

if (VERBOSE) {
  console.log(`\n  Topic signal distribution:`);
  topicSignals.forEach(s => console.log(`    ${s.topic.padEnd(30)} ${s.count}`));
}

/* ── Assemble final output ──────────────────────────────── */
const output = {
  updatedAt: now.toISOString(),
  status:    sourceStatus.some(s => s.status === 'error') ? 'partial' : 'ok',
  summary: {
    vulnerabilities: unique.filter(x => x.kind === 'CVE').length,
    kev:             unique.filter(x => x.kind === 'KEV').length,
    releases:        unique.filter(x => x.kind === 'RELEASE').length,
    techniques:      unique.filter(x => x.kind === 'TECHNIQUE').length,
    signals:         unique.length,
  },
  curriculum,                    // ← preserved from existing file
  items:        unique.slice(0, MAX_ITEMS),
  topicSignals,
  sources:      sourceStatus,
  notes: [
    'Signals are collected from a curated allowlist of security data sources and normalized locally.',
    'The updater is discovery-first: it suggests topics and freshness work; it does not silently rewrite core lessons or ingest untrusted executable content.',
    'Automated summaries are intentionally bounded so the site remains readable. Deep curriculum changes should be reviewed before publication.',
    'The curriculum section is preserved from the existing file and is not overwritten by this script.',
  ],
};

/* ── Write or dry-run ────────────────────────────────────── */
console.log(`\n  Results:`);
console.log(`    Total unique items: ${unique.length}`);
console.log(`    KEV: ${output.summary.kev}  CVE: ${output.summary.vulnerabilities}  RELEASE: ${output.summary.releases}  TECHNIQUE: ${output.summary.techniques}`);
console.log(`    Curriculum modules preserved: ${curriculum.length}`);

if (DRY_RUN) {
  console.log(`\n  [DRY RUN] Would write ${JSON.stringify(output).length} bytes → ${OUT}`);
  console.log('  No files written.\n');
} else {
  await fs.mkdir(path.dirname(OUT), { recursive: true });
  await fs.writeFile(OUT, JSON.stringify(output, null, 2) + '\n');
  console.log(`\n  ✓ Wrote ${unique.slice(0, MAX_ITEMS).length} signals → ${OUT}`);
}

console.table(sourceStatus.map(s => ({
  source: s.id,
  status: s.status,
  count:  s.count,
  error:  s.error?.slice(0, 50) || '',
})));
