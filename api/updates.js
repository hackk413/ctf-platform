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

export default async function handler(req, res) {
  const secret = process.env.SESSION_SECRET || 'atlas_session_vault_secret_hmac_2026';
  const session = readToken(getCookie(req, 'ctf_atlas_session'), secret);
  const headers = harden({ 'content-type': 'application/json; charset=utf-8' });
  Object.entries(headers).forEach(([k, v]) => res.setHeader(k, v));

  if (!session) {
    return res.status(401).json({ ok: false, error: 'Authentication required' });
  }

  const raw = loadIntel();

  // If user is cadet, sanitize curriculum & completely omit vulnerability research
  if (session.role === 'cadet') {
    const safeCurriculum = (raw.curriculum || []).filter(m =>
      !(m.domain === 'reverse' || m.domain === 'pwn' || (m.id && (m.id.includes('pwn') || m.id.includes('reverse') || m.id.includes('binary-exploitation'))))
    );
    const safeData = { ...raw, curriculum: safeCurriculum };
    delete safeData.advisories;
    delete safeData.vulnResearch;
    return res.status(200).json({ ok: true, data: safeData });
  }

  // Admin live auto-sync capability
  const reqUrl = req.url || '';
  const syncRequested = reqUrl.includes('sync=') || req.method === 'POST';

  if (session.role === 'admin' && syncRequested) {
    try {
      const cisaRes = await fetch('https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json', {
        headers: { 'User-Agent': 'CTF-Atlas-LiveSync/2.0' },
        signal: AbortSignal.timeout(6000)
      });
      if (cisaRes.ok) {
        const cisaJson = await cisaRes.json();
        const kevVulns = cisaJson.vulnerabilities || [];
        const advisoryMap = new Map((raw.advisories || []).map(a => [(a.cve || a.id).toUpperCase(), a]));

        // Ingest recent CISA KEV entries
        for (const it of kevVulns.slice(-15)) {
          const key = (it.cveID || '').toUpperCase();
          if (key && !advisoryMap.has(key)) {
            advisoryMap.set(key, {
              id: key.toLowerCase(),
              cve: key,
              title: it.vulnerabilityName || `${it.product || 'Enterprise Component'} Exploited Flaw`,
              severity: 'HIGH',
              cvss: 8.8,
              category: 'Active In-The-Wild Exploitation (CISA KEV)',
              status: 'CISA Known Exploited (Active Zero-Day Threat)',
              isHistoric: false,
              isZeroDay: true,
              disclosureDate: it.dateAdded || new Date().toISOString().slice(0, 10),
              discoveredBy: {
                name: 'Reported to CISA KEV Catalog',
                organization: 'CISA / Threat Intelligence Community',
                role: 'Federal Cybersecurity Agency',
                details: it.notes || 'Identified as actively exploited in-the-wild against perimeter systems.'
              },
              affected: {
                vendor: it.vendorProject || 'Vendor',
                product: it.product || 'Software Package',
                versions: 'See CISA KEV advisory notice',
                ecosystem: 'Operating Systems / Network Infrastructure'
              },
              summary: it.shortDescription || 'Actively exploited vulnerability tracked in federal intelligence feeds.',
              research: {
                rootCause: it.shortDescription || 'Security validation or boundary failure in component.',
                exploitMechanics: 'Threat actors leverage this vulnerability for perimeter breach, code execution, or credential theft.',
                diagram: `[ Attacker ] ---> [ Network Vector ] ---> [ ${it.product || 'Target Asset'} ] ---> [ State Compromise ]`,
                technicalImpact: 'Confirmed active exploitation across enterprise environments.',
                cwe: it.cwe || 'CWE-Other'
              },
              remediation: {
                immediateAction: it.requiredAction || 'Apply vendor security update or disconnect vulnerable device from public networks.',
                commands: [
                  '# Check vendor patch notes and apply latest security updates immediately',
                  '# Enforce CISA required action: ' + (it.requiredAction || 'Apply updates per vendor instructions')
                ],
                mitigations: [
                  'Isolate affected host from untrusted networks.',
                  'Enforce IP allowlisting and network segmentation.'
                ],
                detection: {
                  sigma: `title: ${key} Detection\\nstatus: high\\nlogsource:\\n  category: webserver\\ndetection:\\n  selection:\\n    cve: '${key}'\\n  condition: selection`,
                  yara: `rule CVE_${key.replace(/-/g, '_')} { strings: $cve = "${key}" condition: any of them }`,
                  snort: `alert tcp any any -> any any (msg:"CTF-ATLAS: ${key} Signal"; content:"${key}"; sid:3999999; rev:1;)`
                }
              }
            });
          }
        }
        raw.advisories = [...advisoryMap.values()];
        raw.updatedAt = new Date().toISOString();
        if (raw.summary) {
          raw.summary.advisoriesCount = raw.advisories.length;
          raw.summary.criticalAdvisories = raw.advisories.filter(a => a.severity === 'CRITICAL').length;
          raw.summary.zeroDaysCount = raw.advisories.filter(a => a.isZeroDay).length;
        }
        try {
          fs.writeFileSync(new URL('../data/live-intel.json', import.meta.url), JSON.stringify(raw, null, 2));
        } catch (_) {}
      }
    } catch (_) {
      // In case of network timeout or offline mode, keep existing data intact
      raw.updatedAt = new Date().toISOString();
    }
  }

  return res.status(200).json({ ok: true, data: raw });
}
