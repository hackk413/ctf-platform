/* ============================================================
 * CTF Atlas — portal.js  v3.0
 * Curriculum Renderer & Portal Controller
 * Loads data/live-intel.json, renders six advanced curriculum
 * modules with terminal labs, and keeps all existing views.
 * ============================================================ */

/* ── Core application state ──────────────────────────────── */
const state = {
  view: 'dashboard',
  domain: null,
  os: localStorage.getItem('atlas-os') || 'linux',
  solved: JSON.parse(localStorage.getItem('atlas-solved') || '[]'),
  completedDomains: JSON.parse(localStorage.getItem('atlas-domains') || '[]'),
  theme: localStorage.getItem('atlas-theme') || 'dark',
  moduleQuery: localStorage.getItem('atlas-module-query') || '',
  curriculumModule: null,
  casebookTab: 'all',
  casebookQuery: '',
  tricksTab: 'all',
  tricksQuery: '',
};

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
    'linux': (conceptIndex === 2 || conceptIndex === 5) ? 'linux-pipelines' : (conceptIndex === 3 ? 'linux-proc-ipc' : 'linux-vfs'),
    'networking': (conceptIndex === 3) ? 'networking-dns' : ((conceptIndex === 4 || conceptIndex === 5) ? 'networking-nmap' : 'networking-tcp'),
    'web': (conceptIndex === 2 || conceptIndex === 5) ? 'web-auth-jwt' : (conceptIndex === 4 ? 'web-xss-csp' : 'web-sqli-ast'),
    'crypto': (conceptIndex === 1 || conceptIndex === 2) ? 'crypto-classical' : (conceptIndex === 4 ? 'crypto-rsa' : 'crypto-aes'),
    'forensics': (conceptIndex === 4) ? 'forensics-pcap' : ((conceptIndex === 3 || conceptIndex === 5) ? 'forensics-volatility' : 'forensics-disk-fs'),
    'reverse': (conceptIndex === 2 || conceptIndex === 4) ? 'reverse-x86-asm' : (conceptIndex === 3 ? 'reverse-anti-debug' : 'reverse-ghidra'),
    'pwn': (conceptIndex === 4 || conceptIndex === 5) ? 'pwn-fmtstr' : (conceptIndex === 2 ? 'pwn-heap' : 'pwn-rop'),
    'osint': 'osint-recon',
    'stego': 'stego-deep',
    'mobile-cloud': (conceptIndex >= 4) ? 'cloud-k8s-iam' : 'cloud-docker-escape',
    'blue-team': 'blue-team-telemetry'
  };
  return map[domainId] || 'foundations-threat-model';
}

function openTextbookModal(chapterId) {
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
  {name:'Nmap',cat:'Network',why:'Discovery, port scanning and service enumeration. Start with localhost or a lab target.',linux:'nmap -sV 127.0.0.1',windows:'nmap -sV 127.0.0.1',mac:'nmap -sV 127.0.0.1',url:'https://nmap.org/book/'},
  {name:'Wireshark',cat:'Network / Forensics',why:'Interactive packet inspection, streams, filters and protocol dissection.',linux:'wireshark',windows:'wireshark',mac:'wireshark',url:'https://www.wireshark.org/docs/wsug_html/'},
  {name:'tcpdump',cat:'Network',why:'Lightweight packet capture and filtering from the command line.',linux:'tcpdump -i lo',windows:'Use Wireshark/Npcap capture',mac:'sudo tcpdump -i lo0',url:'https://www.tcpdump.org/'},
  {name:'curl',cat:'Web',why:'Make and inspect HTTP requests without hiding the protocol details.',linux:'curl -i http://127.0.0.1:3000/',windows:'curl.exe -i http://127.0.0.1:3000/',mac:'curl -i http://127.0.0.1:3000/',url:'https://curl.se/docs/'},
  {name:'Burp Suite',cat:'Web',why:'Proxy, inspect and replay application requests in authorized labs.',linux:'Launch Burp → Proxy → browser through 127.0.0.1',windows:'Launch Burp → Proxy → browser through 127.0.0.1',mac:'Launch Burp → Proxy → browser through 127.0.0.1',url:'https://portswigger.net/burp'},
  {name:'OWASP ZAP',cat:'Web',why:'Open-source web proxy/scanner for learning and authorized application assessment.',linux:'zap.sh',windows:'zaproxy.exe',mac:'open /Applications/OWASP\\ ZAP.app',url:'https://www.zaproxy.org/'},
  {name:'Ghidra',cat:'Reverse',why:'Disassembly/decompilation and binary exploration across platforms.',linux:'./ghidraRun',windows:'ghidraRun.bat',mac:'./ghidraRun',url:'https://github.com/NationalSecurityAgency/ghidra'},
  {name:'gdb + extensions',cat:'Pwn / Reverse',why:'Debug local binaries, inspect registers/memory and validate hypotheses.',linux:'gdb ./binary',windows:'gdb ./binary (WSL/MSYS2)',mac:'lldb ./binary  # or gdb via package manager',url:'https://sourceware.org/gdb/'},
  {name:'pwntools',cat:'Pwn',why:'Python toolkit for packing, parsing and process interaction in CTFs.',linux:'python3 -m pip install --user pwntools',windows:'python -m pip install --user pwntools',mac:'python3 -m pip install --user pwntools',url:'https://docs.pwntools.com/'},
  {name:'CyberChef',cat:'General / Encoding',why:'Visual workbench for decoding, transformations and data inspection.',linux:'Open the web app / self-host the repo',windows:'Open the web app / self-host the repo',mac:'Open the web app / self-host the repo',url:'https://github.com/gchq/CyberChef'},
  {name:'file / xxd / strings',cat:'Forensics',why:'Fast first-look triage for unknown files, bytes and printable data.',linux:'file sample.bin && xxd sample.bin | head && strings sample.bin | head',windows:'Use PowerShell Format-Hex; strings.exe is available via Sysinternals/other toolsets',mac:'file sample.bin && xxd sample.bin | head && strings sample.bin | head',url:'https://man7.org/linux/man-pages/'},
  {name:'jq',cat:'Data / APIs',why:'Parse, filter and transform JSON cleanly.',linux:'jq ".items[] | .name" data.json',windows:'jq ".items[] | .name" data.json',mac:'jq ".items[] | .name" data.json',url:'https://jqlang.github.io/jq/'},
  {name:'dig / nslookup',cat:'DNS / Network',why:'Inspect DNS records, servers, TTLs and resolution behavior.',linux:'dig example.test A',windows:'nslookup -type=A example.test',mac:'dig example.test A',url:'https://bind9.readthedocs.io/'},
  {name:'git',cat:'Dev / Forensics',why:'History, branches and object metadata can expose how a project evolved.',linux:'git log --oneline --decorate --all',windows:'git log --oneline --decorate --all',mac:'git log --oneline --decorate --all',url:'https://git-scm.com/doc'},
  {name:'hashcat',cat:'Crypto / Passwords',why:'Offline password-audit and cracking tool for hashes you are authorized to test.',linux:'hashcat --example-hashes',windows:'hashcat.exe --example-hashes',mac:'hashcat --example-hashes',url:'https://hashcat.net/hashcat/'},
  {name:'OpenSSL CLI',cat:'Crypto / PKI',why:'Inspect certificates and test cryptographic primitives and encodings locally.',linux:'openssl x509 -in cert.pem -text -noout',windows:'openssl x509 -in cert.pem -text -noout',mac:'openssl x509 -in cert.pem -text -noout',url:'https://docs.openssl.org/'},
  {name:'Python',cat:'Automation',why:'Glue language for parsing, encoding, protocol reasoning and repeatable solves.',linux:'python3',windows:'py',mac:'python3',url:'https://docs.python.org/3/'},
  {name:'YARA',cat:'Forensics / Detection',why:'Pattern-matching rules for identifying files and behaviors in controlled samples.',linux:'yara rule.yar sample.bin',windows:'yara64.exe rule.yar sample.bin',mac:'yara rule.yar sample.bin',url:'https://yara.readthedocs.io/'},
  {name:'Binwalk',cat:'Forensics',why:'Identify and extract embedded content from firmware-like or compound files.',linux:'binwalk sample.bin',windows:'Use container/WSL or Python packaging',mac:'binwalk sample.bin',url:'https://github.com/ReFirmLabs/binwalk'},
  {name:'FFmpeg',cat:'Media / Forensics',why:'Inspect and transform audio/video containers while preserving evidence copies.',linux:'ffprobe sample.mp4',windows:'ffprobe.exe sample.mp4',mac:'ffprobe sample.mp4',url:'https://ffmpeg.org/ffprobe.html'},
  {name:'SQLite CLI',cat:'Forensics / Web',why:'Inspect embedded application databases and challenge artifacts.',linux:'sqlite3 app.db',windows:'sqlite3.exe app.db',mac:'sqlite3 app.db',url:'https://sqlite.org/cli.html'},
  {name:'ripgrep',cat:'General',why:'Fast recursive text search across source trees, extracted files and notes.',linux:'rg -n "flag|token|password" .',windows:'rg -n "flag|token|password" .',mac:'rg -n "flag|token|password" .',url:'https://github.com/BurntSushi/ripgrep'}
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
  document.documentElement.classList.toggle('light', state.theme === 'light');
  document.getElementById('themeToggle').textContent = state.theme === 'light' ? 'AM' : 'NEON';
}

function setView(view) {
  state.view = view; state.domain = null; state.curriculumModule = null;
  document.querySelectorAll('.nav-item').forEach(b => b.classList.toggle('active', b.dataset.view === view));
  document.getElementById('breadcrumbs').textContent = {
    dashboard:'Dashboard', path:'Learning path', modules:'Learning modules', domains:'Learning paths',
    tools:'Tool lab', labs:'Micro-labs', playbook:'Methodology', casebook:'Casebook',
    library:'Reference vault', glossary:'Glossary', intel:'Live intel', curriculum:'Curriculum',
    tricks:'Tricks & tips'
  }[view] || 'CTF Atlas';
  render();
  window.scrollTo({ top: 0, behavior: 'smooth' });
}

function openDomain(id) {
  state.view = 'domains'; state.domain = id;
  document.querySelectorAll('.nav-item').forEach(b => b.classList.toggle('active', b.dataset.view === 'domains'));
  document.getElementById('breadcrumbs').textContent = 'Domains / ' + domains.find(d => d.id === id)?.name;
  render();
  window.scrollTo({ top: 0, behavior: 'smooth' });
}

function markDomain(id) {
  if (!state.completedDomains.includes(id)) state.completedDomains.push(id);
  save(); render();
}

/* ── Main render dispatcher ──────────────────────────────── */
function render() {
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
  if (!intel) {
    return `<div class="section-head"><div><h2>Curriculum</h2>
      <p>Loading textbook-grade exploitation curriculum...</p></div></div>
      <div class="empty">⏳ Fetching curriculum data...</div>`;
  }

  const modules = intel.curriculum || [];
  if (!modules.length) {
    return `<div class="section-head"><div><h2>Curriculum</h2>
      <p>No curriculum modules loaded yet.</p></div></div>`;
  }

  /* If a specific module is selected, render its full detail */
  if (state.curriculumModule) {
    const mod = modules.find(m => m.id === state.curriculumModule);
    if (mod) return curriculumModuleDetailHTML(mod);
  }

  /* Module listing grid */
  return `
  <div class="section-head">
    <div>
      <div class="eyebrow">TEXTBOOK-GRADE CURRICULUM // ${modules.length} ADVANCED MODULES</div>
      <h2>Exploitation Curriculum</h2>
      <p>Production-quality deep-dives into the six core exploitation domains. Each module contains OS internals, attack mechanics, tool command references, real-world case studies, and a browser-native terminal lab.</p>
    </div>
    <div class="tag-row">
      <span class="tag accent">zero-backend</span>
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
  const items = intel.items     || [];
  const sigs  = intel.topicSignals || [];
  const srcs  = intel.sources   || [];
  const ts    = intel.updatedAt ? new Date(intel.updatedAt).toLocaleString() : 'unknown';
  const statusColor = intel.status === 'ok' ? 'var(--green)' : 'var(--amber)';

  return `
  <div class="section-head">
    <div>
      <div class="eyebrow">INTELLIGENCE SNAPSHOT</div>
      <h2>Live Intel</h2>
      <p>Discovery signals from CISA KEV, NVD CVE, and tool release feeds. Use these to prioritize which curriculum areas to deepen.</p>
    </div>
    <div>
      <div class="update-pill"><span class="pulse"></span>Updated ${esc(ts)}</div>
    </div>
  </div>
  <div class="intel-kpis">
    <div class="intel-kpi"><span class="num">${sum.kev || 0}</span><span class="label">Known Exploited</span></div>
    <div class="intel-kpi"><span class="num">${sum.vulnerabilities || 0}</span><span class="label">CVEs</span></div>
    <div class="intel-kpi"><span class="num">${sum.releases || 0}</span><span class="label">Tool Releases</span></div>
    <div class="intel-kpi"><span class="num">${sum.signals || 0}</span><span class="label">Total Signals</span></div>
  </div>
  ${sigs.length ? `
  <div class="section-head" style="margin-top:24px"><div><h2>Topic Signals</h2><p>Curriculum areas with elevated recent activity.</p></div></div>
  <div class="signal-grid">
    ${sigs.slice(0, 9).map(s => `
      <div class="signal-card">
        <strong>${esc(s.topic)}</strong>
        <span>Activity: ${s.count} signals</span>
        <span style="font-size:11px;color:#7e8ea2;margin-top:6px;display:block">${esc(s.reason || '')}</span>
      </div>`).join('')}
  </div>` : ''}
  <div class="section-head" style="margin-top:24px"><div><h2>Recent Signals</h2></div></div>
  <div class="intel-list">
    ${items.slice(0, 30).map(it => `
      <div class="intel-item">
        <div class="kind"><span class="tag ${it.kind==='KEV'?'warn':it.kind==='CVE'?'accent':'success'}">${esc(it.kind)}</span></div>
        <div>
          <h3>${esc(it.title)}</h3>
          <p>${esc(it.summary || '').slice(0, 220)}${(it.summary||'').length > 220 ? '…' : ''}</p>
          <div class="tag-row" style="margin-top:6px">
            <span class="tag">${esc(it.topic || '')}</span>
            ${it.severity ? `<span class="tag ${it.severity==='exploited'?'warn':''}">${esc(it.severity)}</span>` : ''}
          </div>
        </div>
        <div class="meta">
          ${it.date ? new Date(it.date).toLocaleDateString() : ''}
          ${it.sourceUrl ? `<br><a href="${esc(it.sourceUrl)}" target="_blank" rel="noopener">→ source</a>` : ''}
        </div>
      </div>`).join('') || '<div class="empty">No intelligence items loaded. Run the update script to populate.</div>'}
  </div>
  <div class="section-head" style="margin-top:24px"><div><h2>Source Status</h2></div></div>
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
  const solved = state.solved.length, total = challenges.length;
  return `<div class="hero">
    <div class="hero-main">
      <div class="eyebrow">CTF Atlas / self-paced cyber range</div>
      <h1>Understand the system. Operate the tools. Prove the idea.</h1>
      <p>A pin-to-pin CTF curriculum that fills the gaps between tutorials: foundations, Linux, networking, web, crypto, forensics, reverse engineering, pwn, OSINT, stego, modern app surfaces, and defender context — with safe hands-on practice at every stage.</p>
      <div class="tag-row"><span class="tag accent">offline-friendly</span><span class="tag accent">OS-independent</span><span class="tag success">localStorage progress</span><span class="tag">browser micro-labs</span></div>
      <div class="hero-actions"><button class="btn primary" data-action="goto-path">Start the path</button><button class="btn" data-action="goto-labs">Open micro-labs</button><button class="btn" data-action="goto-domains">Browse domains</button><button class="btn" data-action="goto-curriculum">🎓 Curriculum</button><button class="btn" data-action="goto-tricks">⚡ Tricks &amp; tips</button></div>
    </div>
    <div class="hero-side">
      <div><div class="metric-label">Browser lab completion</div><div class="big-number">${solved}/${total}</div><div class="muted">micro-challenges solved</div></div>
      <div><div class="meter"><div style="width:${completion()}%"></div></div><div class="mini-stat"><span>Overall practice</span><strong>${completion()}%</strong></div></div>
    </div>
  </div>
  <div class="section-head"><div><h2>What's inside</h2><p>Designed to prevent the "I know the commands but not the reasoning" problem.</p></div></div>
  <div class="grid cols-4">
    <div class="card"><div class="metric">12</div><div class="metric-label">learning domains</div><p style="margin-top:8px">Each has theory, workflows, practice and source material.</p></div>
    <div class="card"><div class="metric">6</div><div class="metric-label">textbook modules</div><p style="margin-top:8px">Exploitation curriculum with interactive terminal labs and case studies.</p></div>
    <div class="card"><div class="metric">18</div><div class="metric-label">micro-labs</div><p style="margin-top:8px">Local browser drills with instant feedback and saved progress.</p></div>
    <div class="card"><div class="metric">18+</div><div class="metric-label">reference panels</div><p style="margin-top:8px">In-site notes, formulas, workflows and local-practice recipes.</p></div>
  </div>
  <div class="section-head"><div><h2>Recommended route</h2><p>Follow the sequence, but jump directly to a domain whenever you need it.</p></div></div>
  <div class="grid cols-3">
    ${domains.slice(0,6).map((d,i)=>`<button class="card domain-card" data-domain="${d.id}" style="text-align:left"><div class="domain-icon">${d.icon}</div><div class="card-top"><div><h3>${d.name}</h3><p>${d.summary}</p></div><div class="arrow">→</div></div><div class="tag-row" style="margin-top:10px"><span class="tag">${d.level}</span><span class="tag">${d.duration}</span>${state.completedDomains.includes(d.id)?'<span class="tag success">complete</span>':''}</div></button>`).join('')}
  </div>`;
}

function pathHTML() {
  return `<div class="section-head"><div><h2>The Atlas learning path</h2><p>Build fundamentals first; then specialize. Each stage is tied to a practical feedback loop.</p></div><div class="tag-row"><span class="tag accent">progress saved locally</span><span class="tag success">session protected</span></div></div>
  <div class="grid cols-2">
    <div class="detail"><div class="detail-head"><h3 style="margin:0 0 4px">Core spine</h3><p style="margin:0;color:var(--muted);font-size:12px">The shortest path from zero to competent CTF problem solving.</p></div><div class="detail-body">${domains.map((d,i)=>`<div class="path-node" style="padding-bottom:18px"><div class="path-row"><div class="step-badge">${String(i+1).padStart(2,'0')}</div><div class="path-content"><div class="card-top"><div><h3>${d.name}</h3><p>${d.summary}</p></div><button class="icon-btn" data-domain="${d.id}" title="Open domain">→</button></div><div class="bar-small"><span style="width:${state.completedDomains.includes(d.id)?100:0}%"></span></div><div class="tag-row" style="margin-top:8px"><span class="tag">${d.level}</span><span class="tag">${d.duration}</span>${state.completedDomains.includes(d.id)?'<span class="tag success">done</span>':''}</div></div></div></div>`).join('')}</div></div>
    <div class="detail"><div class="detail-head"><h3 style="margin:0 0 4px">How to study a topic</h3><p style="margin:0;color:var(--muted);font-size:12px">Use the same six-step loop for every category.</p></div><div class="detail-body"><div class="grid">${[['1','Define','Write the problem in plain language. What must be true for the flag to appear?'],['2','Model','Draw the data flow, protocol, memory region or trust boundary.'],['3','Observe','Collect the smallest useful evidence with a tool.'],['4','Hypothesize','Choose one explanation and predict what you should see.'],['5','Test','Change one variable. Prefer local, reversible experiments.'],['6','Explain','Write the root cause, proof, impact and defensive lesson.']].map(x=>`<div class="card"><div class="card-top"><span class="tag accent">${x[0]}</span><h3 style="margin:0;flex:1">${x[1]}</h3></div><p style="margin-top:8px">${x[2]}</p></div>`).join('')}</div><div class="note warn-note"><strong>When stuck:</strong> reduce scope. Verify file type. Inspect inputs/outputs. Read the help text. Make a tiny reproducer. Search the exact protocol term, not the whole mystery.</div></div></div>
  </div>`;
}

function modulesHTML(query) {
  const q = normalizeAnswer(query || '');
  const rows = [];
  domains.forEach(d => d.concepts.forEach((c, i) => rows.push({ d, index: i+1, title: c[0], theory: c[1], practice: c[2], domain: d })));
  const hits = rows.filter(r => !q || normalizeAnswer(r.title + ' ' + r.theory + ' ' + r.practice + ' ' + r.domain.name).includes(q));
  return `<div class="section-head"><div><div class="eyebrow">KNOWLEDGE MATRIX / ${rows.length} MODULES</div><h2>Learning modules</h2><p>Every concept is readable here before you touch a tool. Open the textbook chapter for exhaustive theory, architecture diagrams, and master command tables.</p></div><div class="tag-row"><span class="tag accent">in-site textbook</span><span class="tag">searchable</span></div></div>
  <div class="module-search"><span>&gt;</span><input id="moduleSearch" value="${esc(query||'')}" placeholder="search a concept, protocol, technique, or domain" autocomplete="off"><span class="cursor">█</span></div>
  <div class="module-count"><span>${hits.length}</span> modules visible</div>
  <div class="module-grid" id="modulesGrid">${hits.map(r=>{
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
  }).join('') || '<div class="empty">No modules matched. Try "HTTP", "ELF", "XOR", "permissions", or "DNS".</div>'}</div>
  <div class="note"><strong>Study contract:</strong> Read the concept, reproduce the observation in a safe lab, then explain it without looking at the text.</div>`;
}

function domainsHTML() {
  return `<div class="section-head"><div><h2>Domains</h2><p>Every domain follows the same pattern: concept map → workflow → tools → practice → real-world transfer.</p></div></div><div class="grid cols-3">${domains.map(d=>`<button class="card domain-card" data-domain="${d.id}" style="text-align:left"><div class="domain-icon">${d.icon}</div><div class="card-top"><div><h3>${d.name}</h3><p>${d.summary}</p></div><div class="arrow">→</div></div><div class="tag-row" style="margin-top:10px"><span class="tag">${d.level}</span><span class="tag">${d.duration}</span>${state.completedDomains.includes(d.id)?'<span class="tag success">complete</span>':''}</div></button>`).join('')}</div>`;
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
  const os = state.os;
  return `<div class="section-head"><div><h2>Tool lab</h2><p>Command examples for your OS. Always use against systems you own or are authorized to test.</p></div>
  <div class="os-tabs">${['linux','windows','mac'].map(o=>`<button class="os-btn${os===o?' active':''}" data-os="${o}">${o.toUpperCase()}</button>`).join('')}</div>
  </div>
  <div class="tool-grid">${tools.map(t=>`<div class="tool-card"><div class="card-top"><h3>${esc(t.name)}</h3><span class="tool-os">${esc(t.cat)}</span></div><p class="why">${esc(t.why)}</p><pre><code>${esc(t[os]||t.linux)}</code></pre>${t.url?`<a class="btn outline" href="${esc(t.url)}" target="_blank" rel="noopener" style="margin-top:8px;font-size:11px">Docs →</a>`:''}</div>`).join('')}</div>`;
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
  const steps = [
    {n:'01',title:'Triage',items:['Identify category (crypto, web, pwn, forensics, OSINT, stego, reverse).','Read the problem statement twice. Highlight concrete clues.','List what artifacts you have: file, URL, service, image, pcap.']},
    {n:'02',title:'Gather evidence',items:['Run the minimal set of observation commands for the category.','Capture all output. Do not interpret yet—just collect.','Check file types, sizes, magic bytes, strings, entropy.']},
    {n:'03',title:'Form one hypothesis',items:['State it in plain language: "This is X because I see Y."','Write the predicted evidence if the hypothesis is correct.','Rank your top two and choose the more falsifiable one.']},
    {n:'04',title:'Test & iterate',items:['Change one variable. Run the relevant tool. Compare output to prediction.','If evidence doesn\'t match, update the hypothesis—don\'t the test.','Prefer local, reversible experiments. Keep a command log.']},
    {n:'05',title:'Exploit & extract',items:['Apply the narrowest proof-of-concept that produces the flag.','Verify the flag format before submitting.','Record the minimal reproduction: file + one command = flag.']},
    {n:'06',title:'Write it up',items:['Root cause → exploit chain → flag → defensive lesson.','3–8 sentences is enough. Include the key command.','Map to ATT&CK if it\'s an offensive technique.']}
  ];
  return `<div class="section-head"><div><h2>Methodology</h2><p>A repeatable solve loop that works across every CTF category.</p></div></div>
  <div class="playbook">${steps.map(s=>`<div class="play-card card"><div class="card-top"><span class="tag accent">${s.n}</span><h3>${s.title}</h3></div><ol>${s.items.map(i=>`<li>${i}</li>`).join('')}</ol></div>`).join('')}</div>
  <div class="note" style="margin-top:24px"><strong>Anti-patterns to avoid:</strong> Running every tool without a hypothesis. Accepting tool output as ground truth without verification. Giving up before checking the simplest explanation. Sharing flags or solutions in active competitions.</div>`;
}

function casebookHTML() {
  const tab = state.casebookTab || 'all';
  const q = normalizeAnswer(state.casebookQuery || '');
  const allWriteups = window.TOURNAMENT_WRITEUPS || [];

  const filteredWriteups = allWriteups.filter(w => {
    if (tab === 'hackquest') {
      const isHQ = (w.event && w.event.toLowerCase().includes('hackquest')) || (w.id && w.id.includes('hackquest')) || (w.title && w.title.toLowerCase().includes('hackquest'));
      if (!isHQ) return false;
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
  const allTricks = window.CTF_TRICKS_DATA || [];
  const tab = state.tricksTab || 'all';
  const query = (state.tricksQuery || '').trim().toLowerCase();

  const filtered = allTricks.filter(t => {
    const matchesTab = (tab === 'all') || (t.category === tab);
    if (!matchesTab) return false;
    if (!query) return true;
    const hay = `${t.title} ${t.categoryLabel} ${t.payload} ${t.context} ${t.why} ${t.internals} ${t.mitigation}`.toLowerCase();
    return hay.includes(query);
  });

  return `
  <div class="section-head">
    <div>
      <div class="eyebrow">TACTICAL CHEAT SHEET // CTF PAYLOADS &amp; ESCAPES</div>
      <h2>Tricks, Payloads &amp; Command Injection Vault</h2>
      <p>Curated catalog of command separators, whitespace bypasses, keyword obfuscation, SUID exploits, and web injection techniques. Explains why each trick functions, its underlying OS/parser mechanics, and defensive mitigations.</p>
    </div>
    <div class="tag-row">
      <span class="tag accent">${filtered.length} active tricks</span>
      <span class="tag warn">educational lab scope</span>
      <span class="tag success">mitigation included</span>
    </div>
  </div>

  <div class="module-search" style="margin-bottom:14px">
    <span>&gt;</span>
    <input id="tricksSearch" value="${esc(state.tricksQuery || '')}" placeholder="search tricks by payload (e.g. '; ls', '$IFS'), technique, or evasion context..." autocomplete="off">
    <span class="cursor">█</span>
  </div>

  <div class="os-tabs" style="margin-bottom:18px">
    ${[
      ['all', 'All Tricks & Payloads'],
      ['chaining', 'Command Chaining (; && ||)'],
      ['whitespace', 'Whitespace Evasion ($IFS)'],
      ['obfuscation', 'Keyword Evasion (c\\at glob)'],
      ['web', 'Web & Injection (SQLi/XSS/SSRF)'],
      ['privesc', 'SUID & GTFOBins'],
      ['shells', 'Interactive Shells & PTY']
    ].map(([catKey, label]) => `
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

        <div style="margin:10px 0">
          <span style="font-family:var(--display);color:var(--cyan);font-size:11px;letter-spacing:.08em;text-transform:uppercase">// Payload Expression</span>
          <pre class="code-block" style="background:#090d16;padding:12px;border:1px solid #1e293b;border-radius:4px;overflow-x:auto"><code id="trick-code-${esc(t.id)}" style="color:#00ff88;font-size:13px;font-weight:bold;font-family:var(--mono)">${esc(t.payload)}</code></pre>
        </div>

        <div style="margin:12px 0">
          <h4 style="font-family:var(--display);color:var(--cyan);font-size:12px;letter-spacing:.08em;text-transform:uppercase;margin:0 0 4px">Vulnerable Execution Context</h4>
          <p style="color:#cbd5e1;line-height:1.7;margin:0">${esc(t.context)}</p>
        </div>

        <div class="note" style="margin:12px 0;border-left-color:var(--cyan)">
          <h4 style="font-family:var(--display);color:var(--cyan);font-size:12px;letter-spacing:.08em;text-transform:uppercase;margin:0 0 4px">Offensive Mechanics &amp; Why It Works</h4>
          <p style="color:#cbd5e1;line-height:1.7;margin:0">${esc(t.why)}</p>
        </div>

        <div style="margin:12px 0">
          <h4 style="font-family:var(--display);color:var(--amber);font-size:12px;letter-spacing:.08em;text-transform:uppercase;margin:0 0 4px">OS Kernel &amp; Lexer Internals</h4>
          <p style="color:#cbd5e1;line-height:1.7;margin:0">${esc(t.internals)}</p>
        </div>

        <div class="note warn-note" style="margin-top:12px">
          <h4 style="font-family:var(--display);color:var(--pink);font-size:12px;letter-spacing:.08em;text-transform:uppercase;margin:0 0 4px">Defensive Mitigation &amp; Safe Coding</h4>
          <p style="color:#cbd5e1;line-height:1.7;margin:0">${esc(t.mitigation)}</p>
        </div>
      </article>
    `).join('') || '<div class="empty">No tricks or payloads matched this query.</div>'}
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
  /* Sidebar nav items */
  document.querySelectorAll('.nav-item[data-view]').forEach(btn => {
    btn.addEventListener('click', () => setView(btn.dataset.view));
  });

  /* Mobile menu */
  const sidebar  = document.getElementById('sidebar');
  const menuBtn  = document.getElementById('menuToggle');
  const closeBtn = document.getElementById('mobileClose');
  if (menuBtn) menuBtn.addEventListener('click', () => sidebar?.classList.add('open'));
  if (closeBtn) closeBtn.addEventListener('click', () => sidebar?.classList.remove('open'));
  document.addEventListener('click', e => {
    if (sidebar?.classList.contains('open') && !sidebar.contains(e.target) && e.target !== menuBtn) {
      sidebar.classList.remove('open');
    }
  });

  /* Theme toggle */
  document.getElementById('themeToggle')?.addEventListener('click', () => {
    state.theme = state.theme === 'dark' ? 'light' : 'dark';
    save();
    setTheme();
  });

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

  /* Modal backdrop and escape key closing */
  document.getElementById('modalClose')?.addEventListener('click', closeModal);
  document.getElementById('modalBackdrop')?.addEventListener('click', e => {
    if (e.target.id === 'modalBackdrop') closeModal();
  });
  document.addEventListener('keydown', e => {
    if (e.key === 'Escape') closeModal();
  });

  /* Background-preload live intelligence and curriculum */
  loadIntel();

  render();
}

/* ── Boot ────────────────────────────────────────────────── */
let booted = false;
function boot() {
  if (booted) return;
  booted = true;
  init();
}
document.addEventListener('DOMContentLoaded', boot);
if (document.readyState !== 'loading') boot();
