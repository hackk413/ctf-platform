#!/usr/bin/env node
/**
 * CTF Atlas — scripts/crawl-manpages.mjs
 * Automated Man-Page Ingestion Pipeline
 *
 * Parses manual pages for core CTF tools, strips escape codes,
 * splits into structured sections, and writes data/man-intel.json.
 *
 * Usage:
 *   node scripts/crawl-manpages.mjs
 *   node scripts/crawl-manpages.mjs --tools find,grep,openssl
 *   node scripts/crawl-manpages.mjs --out data/man-intel.json
 */

import { execSync, spawnSync }  from 'node:child_process';
import fs                        from 'node:fs/promises';
import path                      from 'node:path';
import { existsSync }            from 'node:fs';

/* ── Configuration ─────────────────────────────────────── */
const ROOT    = process.cwd();
const DEFAULT_OUT = path.join(ROOT, 'data', 'man-intel.json');

const args = process.argv.slice(2);
const outArg   = args.find(a => a.startsWith('--out='))?.split('=')[1];
const toolsArg = args.find(a => a.startsWith('--tools='))?.split('=')[1];
const OUT      = outArg ? path.resolve(outArg) : DEFAULT_OUT;

/** Core CTF tools to harvest man pages for */
const ALL_TOOLS = [
  'find', 'grep', 'awk', 'sed', 'exiftool', 'binwalk',
  'steghide', 'tshark', 'openssl', 'curl', 'socat', 'nmap', 'gdb'
];

const TARGET_TOOLS = toolsArg ? toolsArg.split(',').map(t => t.trim()) : ALL_TOOLS;

/* ── Escape-code stripper ───────────────────────────────── */
// Matches ANSI escape sequences, SGR codes, backspace sequences
const ANSI_RE = /\x1b\[[0-9;]*[A-Za-z]|\x1b\][^\x07]*[\x07\x1b\\]|\x1b[^[\]]/g;
const BS_RE   = /.\x08/g;   // character + backspace (from col -b output)

function stripEscapes(text) {
  return text
    .replace(ANSI_RE, '')
    .replace(BS_RE, '')
    .replace(/\r\n?/g, '\n');
}

/* ── Man-page fetcher ───────────────────────────────────── */
/**
 * Fetches man page text for a given tool.
 * Tries `man` with col -b for escape stripping, then falls back to
 * --help output if man is unavailable.
 * Returns null if nothing can be obtained.
 */
function fetchManPage(tool) {
  /* Try: man TOOL | col -b */
  const manResult = spawnSync('man', [tool], {
    encoding: 'utf8',
    env: { ...process.env, PAGER: 'cat', MANPAGER: 'cat', COLUMNS: '160' },
    timeout: 15000,
  });

  if (manResult.status === 0 && manResult.stdout) {
    const raw = manResult.stdout;
    /* Attempt to pipe through col -b to remove formatting */
    const colResult = spawnSync('col', ['-b'], {
      input: raw,
      encoding: 'utf8',
      timeout: 10000,
    });
    const text = colResult.status === 0 ? colResult.stdout : raw;
    return stripEscapes(text);
  }

  /* Fallback: --help output */
  const helpResult = spawnSync(tool, ['--help'], {
    encoding: 'utf8',
    timeout: 10000,
  });
  if (helpResult.stdout || helpResult.stderr) {
    return stripEscapes((helpResult.stdout || '') + (helpResult.stderr || ''));
  }

  return null;
}

/* ── Section splitter ───────────────────────────────────── */
/**
 * POSIX man pages follow a standard section layout.
 * This parser splits on known uppercase section headers.
 */
const SECTION_HEADERS = [
  'NAME', 'SYNOPSIS', 'DESCRIPTION', 'OPTIONS', 'EXAMPLES',
  'FILES', 'ENVIRONMENT', 'EXIT STATUS', 'SIGNALS', 'BUGS',
  'NOTES', 'SEE ALSO', 'AUTHOR', 'REPORTING BUGS', 'COPYRIGHT',
  'SECURITY CONSIDERATIONS', 'HISTORY', 'AVAILABILITY'
];

const SECTION_RE = new RegExp(
  `^(${SECTION_HEADERS.map(h => h.replace(/ /g, '[ \\t]+')).join('|')})\\s*$`,
  'gm'
);

function splitSections(text) {
  const sections = {};
  const matches  = [...text.matchAll(SECTION_RE)];

  if (!matches.length) {
    // Unstructured — store everything as DESCRIPTION
    sections['DESCRIPTION'] = text.trim();
    return sections;
  }

  for (let i = 0; i < matches.length; i++) {
    const header = matches[i][1].trim().toUpperCase().replace(/\s+/g, ' ');
    const start  = matches[i].index + matches[i][0].length;
    const end    = i + 1 < matches.length ? matches[i + 1].index : text.length;
    sections[header] = text.slice(start, end).trim();
  }

  return sections;
}

/* ── Option flag parser ─────────────────────────────────── */
/**
 * Extracts individual flags from the OPTIONS section.
 * Handles:
 *   -f, --flag           Description text
 *   -f FILE              Description text
 *       --flag=VALUE     Description
 */
const FLAG_RE = /^[ \t]+((?:-{1,2}[\w?@-]+(?:[=\s][\w<>[\].]+)?(?:,\s*-{1,2}[\w?@-]+(?:[=\s][\w<>[\].]+)?)*))[ \t]{2,}(.+?)(?=\n[ \t]+-{1,2}|\n\n|\n[A-Z]|$)/gms;

function parseFlags(optionsText) {
  if (!optionsText) return [];
  const flags = [];
  const seen  = new Set();

  for (const match of optionsText.matchAll(FLAG_RE)) {
    const flagRaw   = match[1].trim();
    const contextRaw = match[2].replace(/\s+/g, ' ').trim();

    if (seen.has(flagRaw)) continue;
    seen.add(flagRaw);

    if (flagRaw.length > 120 || contextRaw.length < 4) continue;

    flags.push({
      flag:    flagRaw,
      context: contextRaw.slice(0, 400),
    });
  }

  return flags;
}

/* ── Synopsis cleaner ───────────────────────────────────── */
function cleanSynopsis(text) {
  if (!text) return '';
  return text
    .replace(/\s+/g, ' ')
    .replace(/^[ \t]+/, '')
    .trim()
    .slice(0, 600);
}

/* ── Description cleaner ────────────────────────────────── */
function cleanDescription(text) {
  if (!text) return '';
  // Keep first ~1500 chars to avoid giant blobs
  return text.trim().slice(0, 1500);
}

/* ── Security Considerations extractor ─────────────────── */
function extractSecurityNotes(sections) {
  const candidates = [
    sections['SECURITY CONSIDERATIONS'],
    sections['SECURITY'],
    sections['BUGS'],
    sections['NOTES'],
  ].filter(Boolean);

  return candidates.length
    ? candidates[0].trim().slice(0, 800)
    : '';
}

/* ── Main processing loop ───────────────────────────────── */
const results  = [];
const skipped  = [];
const now      = new Date().toISOString();

console.log(`\n╔══════════════════════════════════════════════╗`);
console.log(`║  CTF Atlas — Man-Page Ingestion Pipeline     ║`);
console.log(`╚══════════════════════════════════════════════╝`);
console.log(`  Tools: ${TARGET_TOOLS.join(', ')}`);
console.log(`  Output: ${OUT}\n`);

for (const tool of TARGET_TOOLS) {
  process.stdout.write(`  Processing: ${tool.padEnd(15)}`);

  const raw = fetchManPage(tool);

  if (!raw || raw.length < 100) {
    skipped.push({ tool, reason: 'no man page or --help output available' });
    console.log(`✗ (not available)`);
    continue;
  }

  const sections = splitSections(raw);
  const flags    = parseFlags(sections['OPTIONS'] || sections['DESCRIPTION'] || '');

  const entry = {
    tool,
    fetchedAt: now,
    synopsis:  cleanSynopsis(sections['SYNOPSIS'] || ''),
    description: cleanDescription(sections['DESCRIPTION'] || ''),
    options:   cleanDescription(sections['OPTIONS'] || ''),
    security_considerations: extractSecurityNotes(sections),
    flags,
    sections:  Object.keys(sections),
    rawLength: raw.length,
  };

  results.push(entry);
  console.log(`✓ (${flags.length} flags, ${raw.length} chars)`);
}

/* ── Write output ───────────────────────────────────────── */
const output = {
  generatedAt: now,
  toolCount: results.length,
  skippedCount: skipped.length,
  tools: results,
  skipped,
  notes: [
    'Man pages are parsed from the local system. Install man-db and tool packages for complete coverage.',
    'Flag entries are extracted using heuristic pattern matching and may miss unusual formatting.',
    'This file is auto-generated. Do not manually edit — run scripts/crawl-manpages.mjs to refresh.',
  ],
};

await fs.mkdir(path.dirname(OUT), { recursive: true });
await fs.writeFile(OUT, JSON.stringify(output, null, 2) + '\n');

console.log(`\n  ✓ Wrote ${results.length} tools → ${OUT}`);
if (skipped.length) {
  console.log(`  ⚠ Skipped ${skipped.length}: ${skipped.map(s => s.tool).join(', ')}`);
}

console.table(results.map(r => ({
  tool:     r.tool,
  flags:    r.flags.length,
  sections: r.sections.length,
  chars:    r.rawLength,
})));
