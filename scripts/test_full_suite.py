import json
import re
import subprocess
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
assets_text = (ROOT / 'lib' / 'assets.mjs').read_text(encoding='utf-8')
intel_text  = (ROOT / 'data' / 'live-intel.json').read_text(encoding='utf-8')

m_html = re.search(r'export const portalHtml\s*=\s*(.*?);\nexport const portalCss', assets_text, re.DOTALL)
m_css  = re.search(r'export const portalCss\s*=\s*(.*?);\nexport const portalJs', assets_text, re.DOTALL)
m_js   = re.search(r'export const portalJs\s*=\s*(.*?);\nexport const terminalEngineJs', assets_text, re.DOTALL)

portal_html = json.loads(m_html.group(1))
portal_css  = json.loads(m_css.group(1))
portal_js   = json.loads(m_js.group(1))

inlined_css = portal_css.replace('</style', '<\\/style')
inlined_js  = portal_js.replace('</script', '<\\/script')

html = portal_html.replace('<link rel="stylesheet" href="styles.css">', f'<style>{inlined_css}</style>')
html = html.replace('<script src="app.js"></script>', f'<script>{inlined_js}</script>')

# Add comprehensive test probe
test_probe = f"""
<script>
window.addEventListener('DOMContentLoaded', () => {{
  // Mock live intel fetch for local browser test
  const liveIntelData = {intel_text};
  const originalFetch = window.fetch;
  window.fetch = function(url, opts) {{
    if (url.includes('live-intel.json') || url.includes('/api/updates')) {{
      return Promise.resolve({{
        ok: true,
        status: 200,
        json: () => Promise.resolve({{ ok: true, data: liveIntelData }})
      }});
    }}
    return originalFetch.apply(this, arguments);
  }};

  const testLogs = [];
  function log(msg) {{ testLogs.push(msg); }}

  try {{
    // 1. Initial State
    log('INITIAL_VIEW:' + state.view);
    log('TEXTBOOK_CHAPTERS_COUNT:' + Object.keys(window.TEXTBOOK_CHAPTERS || {{}}).length);
    log('TOURNAMENT_WRITEUPS_COUNT:' + (window.TOURNAMENT_WRITEUPS || []).length);
    log('CTF_TRICKS_DATA_COUNT:' + (window.CTF_TRICKS_DATA || []).length);

    // 2. Test Navigation to all 14 views
    const views = ['path', 'modules', 'domains', 'tools', 'labs', 'playbook', 'casebook', 'library', 'glossary', 'intel', 'curriculum', 'tricks', 'workbench', 'dashboard'];
    for (const v of views) {{
      const btn = document.querySelector(`.nav-item[data-view="${{v}}"]`);
      if (!btn) {{ log(`MISSING_NAV_BTN:${{v}}`); continue; }}
      btn.click();
      const curView = state.view;
      const vEl = document.getElementById('view');
      log(`NAV_CLICK:${{v}}->state=${{curView}},hasContent=${{vEl && vEl.innerHTML.length > 50}}`);
    }}

    // 3. Test Learning Modules & Textbook Modal
    document.querySelector('.nav-item[data-view="modules"]').click();
    const firstTextbookBtn = document.querySelector('[data-textbook]');
    if (firstTextbookBtn) {{
      const chId = firstTextbookBtn.dataset.textbook;
      log('CLICK_TEXTBOOK_BTN_FROM_MODULES:' + chId);
      firstTextbookBtn.click();
      
      const modalBackdrop = document.getElementById('modalBackdrop');
      const modalBody = document.getElementById('modalBody');
      const isVisible = modalBackdrop && !modalBackdrop.hidden;
      const hasDiagram = modalBody && modalBody.querySelector('.textbook-diagram') !== null;
      const hasCmdTable = modalBody && modalBody.querySelector('.cmd-table') !== null;
      const hasWorkflows = modalBody && modalBody.querySelector('.wf-box') !== null;
      log(`MODAL_STATE:visible=${{isVisible}},hasDiagram=${{hasDiagram}},hasCmdTable=${{hasCmdTable}},hasWorkflows=${{hasWorkflows}}`);

      // Test close button
      const closeBtn = document.getElementById('closeModalBtn');
      if (closeBtn) closeBtn.click();
      log('MODAL_CLOSED_VIA_BTN:' + (modalBackdrop && modalBackdrop.hidden));
    }} else {{
      log('NO_TEXTBOOK_BTN_IN_MODULES');
    }}

    // 4. Test Domain Detail & Textbook Modal
    document.querySelector('.nav-item[data-view="domains"]').click();
    openDomain('linux');
    const domainTextbookBtn = document.querySelector('[data-textbook="linux-vfs"]');
    if (domainTextbookBtn) {{
      domainTextbookBtn.click();
      const modalBackdrop = document.getElementById('modalBackdrop');
      const modalTitle = document.getElementById('modalTitle');
      log('DOMAIN_TEXTBOOK_MODAL:visible=' + (!modalBackdrop.hidden) + ',title=' + (modalTitle ? modalTitle.textContent : ''));
      closeModal();
      log('DOMAIN_MODAL_CLOSED:' + modalBackdrop.hidden);
    }} else {{
      log('NO_LINUX_VFS_TEXTBOOK_BTN_IN_DOMAIN');
    }}

    // 5. Test Casebook View & Writeups
    document.querySelector('.nav-item[data-view="casebook"]').click();
    const writeupCards = document.querySelectorAll('.writeup-card');
    log('CASEBOOK_INITIAL_WRITEUPS_COUNT:' + writeupCards.length);

    // Test filter by Pwn tab
    const pwnTabBtn = document.querySelector('[data-casebook-tab="pwn"]');
    if (pwnTabBtn) {{
      pwnTabBtn.click();
      const pwnCards = document.querySelectorAll('.writeup-card');
      log('CASEBOOK_PWN_TAB_CLICK:count=' + pwnCards.length + ',tab=' + state.casebookTab);
    }}

    // Test filter by Web tab
    const webTabBtn = document.querySelector('[data-casebook-tab="web"]');
    if (webTabBtn) {{
      webTabBtn.click();
      const webCards = document.querySelectorAll('.writeup-card');
      log('CASEBOOK_WEB_TAB_CLICK:count=' + webCards.length);
    }}

    // Test exploit script code block presence
    const firstCodeBlock = document.querySelector('.writeup-card pre code');
    log('EXPLOIT_CODE_BLOCK_PRESENT:' + (firstCodeBlock !== null && firstCodeBlock.textContent.length > 50));

    // Test Historic CVEs tab
    const cveTabBtn = document.querySelector('[data-casebook-tab="cve"]');
    if (cveTabBtn) {{
      cveTabBtn.click();
      const cveCards = document.querySelectorAll('.card');
      log('CASEBOOK_CVE_TAB_CLICK:cardCount=' + cveCards.length);
    }}

    // 6. Test Curriculum and Virtual Terminal SUID escalation
    intelCache = liveIntelData;
    document.querySelector('.nav-item[data-view="curriculum"]').click();
    const modCard = document.querySelector('[data-curriculum-module="linux-cli"]');
    if (modCard) {{
      modCard.click();
      const termContainer = document.getElementById('terminal-lab-mount');
      const termInput = termContainer ? termContainer.querySelector('.vterm-input') : null;
      const termOutput = termContainer ? termContainer.querySelector('.vterm-output') : null;

      if (termInput) {{
        termInput.value = '/usr/local/bin/find / -name flag.txt -exec cat {{}} \\\\;';
        const enterEvent = new KeyboardEvent('keydown', {{ key: 'Enter', keyCode: 13, which: 13, bubbles: true }});
        termInput.dispatchEvent(enterEvent);
        const termText = termOutput ? termOutput.textContent : '';
        const hasFlag = termText.includes('CTF{{SUID_GT_F0_Bins_R00t}}');
        log('TERMINAL_EXPLOIT_FLAG_SOLVED:' + hasFlag);
      }}
    }}

    // 7. Test Tricks & Tips View
    const tricksNavBtn = document.querySelector('.nav-item[data-view="tricks"]');
    if (tricksNavBtn) {{
      tricksNavBtn.click();
      const trickCards = document.querySelectorAll('.writeup-card');
      log('TRICKS_INITIAL_COUNT:' + trickCards.length);

      // Test filter by chaining tab
      const chainingTabBtn = document.querySelector('[data-tricks-tab="chaining"]');
      if (chainingTabBtn) {{
        chainingTabBtn.click();
        const chainingCards = document.querySelectorAll('.writeup-card');
        log('TRICKS_CHAINING_TAB_CLICK:count=' + chainingCards.length + ',tab=' + state.tricksTab);
      }}

      // Test filter by whitespace tab
      const whitespaceTabBtn = document.querySelector('[data-tricks-tab="whitespace"]');
      if (whitespaceTabBtn) {{
        whitespaceTabBtn.click();
        const wsCards = document.querySelectorAll('.writeup-card');
        log('TRICKS_WHITESPACE_TAB_CLICK:count=' + wsCards.length + ',tab=' + state.tricksTab);
      }}

      // Test search filter for '$IFS' while on whitespace tab
      const tsInput = document.getElementById('tricksSearch');
      if (tsInput) {{
        tsInput.value = '$IFS';
        tsInput.dispatchEvent(new Event('input', {{ bubbles: true }}));
        const wsSearchCards = document.querySelectorAll('.writeup-card');
        log('TRICKS_SEARCH_IFS_IN_WHITESPACE:count=' + wsSearchCards.length);
      }}

      // Switch back to all tab and search for '; ls'
      const allTabBtn = document.querySelector('[data-tricks-tab="all"]');
      if (allTabBtn) allTabBtn.click();
      const tsInputAll = document.getElementById('tricksSearch');
      if (tsInputAll) {{
        tsInputAll.value = '; ls';
        tsInputAll.dispatchEvent(new Event('input', {{ bubbles: true }}));
        const searchCards = document.querySelectorAll('.writeup-card');
        log('TRICKS_SEARCH_SEMICOLON_LS_IN_ALL:count=' + searchCards.length);
      }}
    }} else {{
      log('MISSING_TRICKS_NAV_BTN');
    }}

    // 8. Test Live Intel Tab Filtering & Threat Dossier Modal
    document.querySelector('.nav-item[data-view="intel"]').click();
    const allIntelCards = document.querySelectorAll('.intel-item');
    log('INTEL_INITIAL_COUNT:' + allIntelCards.length);

    const kevTabBtn = document.querySelector('[data-intel-tab="KEV"]');
    if (kevTabBtn) {{
      kevTabBtn.click();
      const kevCards = document.querySelectorAll('.intel-item');
      log('INTEL_KEV_TAB_CLICK:count=' + kevCards.length + ',tab=' + state.intelTab);
    }}

    const firstIntelCard = document.querySelector('[data-open-intel]');
    if (firstIntelCard) {{
      const itId = firstIntelCard.dataset.openIntel;
      firstIntelCard.click();
      const modalBackdrop = document.getElementById('modalBackdrop');
      const modalTitle = document.getElementById('modalTitle');
      log('INTEL_DOSSIER_MODAL_OPEN:visible=' + (!modalBackdrop.hidden) + ',title=' + (modalTitle ? modalTitle.textContent : ''));
      closeModal();
      log('INTEL_DOSSIER_MODAL_CLOSED:' + modalBackdrop.hidden);
    }}

    // 9. Test Cyber Workbench (View 14)
    const wbNavBtn = document.querySelector('.nav-item[data-view="workbench"]');
    if (wbNavBtn) {{
      wbNavBtn.click();
      log('WORKBENCH_ACTIVE_TAB:' + state.workbenchTab);

      // Test Base64 Encode & Decode
      const encInp = document.getElementById('encoderInput');
      const encOut = document.getElementById('encoderOutput');
      if (encInp && encOut) {{
        encInp.value = 'CTF{{ATLAS_2026}}';
        document.getElementById('btnB64Enc').click();
        const b64Val = encOut.value;
        log('WORKBENCH_B64_ENCODE:' + b64Val);

        encInp.value = b64Val;
        document.getElementById('btnB64Dec').click();
        log('WORKBENCH_B64_DECODE:' + encOut.value);

        // Test Hex Encode
        encInp.value = 'flag';
        document.getElementById('btnHexEnc').click();
        log('WORKBENCH_HEX_ENCODE:' + encOut.value);
      }}

      // Test Reverse Shell Generator
      const shellsTabBtn = document.querySelector('[data-workbench-tab="shells"]');
      if (shellsTabBtn) {{
        shellsTabBtn.click();
        const lhostInp = document.getElementById('workbenchLhost');
        const lportInp = document.getElementById('workbenchLport');
        if (lhostInp && lportInp) {{
          lhostInp.value = '192.168.1.100';
          lhostInp.dispatchEvent(new Event('input', {{ bubbles: true }}));
          lportInp.value = '9001';
          lportInp.dispatchEvent(new Event('input', {{ bubbles: true }}));
          const firstShellCode = document.querySelector('#shellsList code');
          const hasCustomHost = firstShellCode && firstShellCode.textContent.includes('192.168.1.100/9001');
          log('WORKBENCH_SHELL_BINDING_UPDATED:' + hasCustomHost);
        }}
      }}

      // Test SUID Permissions Calculator
      const permTabBtn = document.querySelector('[data-workbench-tab="permissions"]');
      if (permTabBtn) {{
        permTabBtn.click();
        const permOctal = document.getElementById('permOctal');
        const permSym = document.getElementById('permSymbolic');
        const permRisk = document.getElementById('permRiskText');
        if (permOctal && permSym) {{
          permOctal.value = '4755';
          permOctal.dispatchEvent(new Event('input', {{ bubbles: true }}));
          const isSymMatch = permSym.textContent === '-rwsr-xr-x';
          const hasSuidRisk = permRisk && permRisk.textContent.includes('SUID');
          log(`WORKBENCH_PERM_CALC:sym=${{permSym.textContent}},symMatch=${{isSymMatch}},suidRisk=${{hasSuidRisk}}`);
        }}
      }}

      // Test CIDR Subnet Calculator
      const subnetTabBtn = document.querySelector('[data-workbench-tab="subnets"]');
      if (subnetTabBtn) {{
        subnetTabBtn.click();
        const subIp = document.getElementById('subnetIp');
        const subPfx = document.getElementById('subnetPrefix');
        const subRes = document.getElementById('subnetResults');
        if (subIp && subPfx && subRes) {{
          subIp.value = '192.168.1.50';
          subIp.dispatchEvent(new Event('input', {{ bubbles: true }}));
          subPfx.value = '24';
          subPfx.dispatchEvent(new Event('change', {{ bubbles: true }}));
          const hasNet = subRes.textContent.includes('192.168.1.0');
          const hasHosts = subRes.textContent.includes('254');
          log(`WORKBENCH_SUBNET_CALC:hasNet=${{hasNet}},hasHosts=${{hasHosts}}`);
        }}
      }}
    }} else {{
      log('MISSING_WORKBENCH_NAV_BTN');
    }}

    // Output Final Results
    const resDiv = document.createElement('div');
    resDiv.id = 'suite-results';
    resDiv.textContent = testLogs.join('\\n');
    document.body.appendChild(resDiv);

  }} catch (err) {{
    const errDiv = document.createElement('div');
    errDiv.id = 'suite-results';
    errDiv.textContent = 'FATAL_TEST_ERROR: ' + err.stack;
    document.body.appendChild(errDiv);
  }}
}});
</script>
"""

test_file = ROOT / 'scratch' / 'full-suite-test.html'
test_file.parent.mkdir(exist_ok=True)
test_file.write_text(html + test_probe, encoding='utf-8')

chrome_path = os.path.expandvars(r'%LOCALAPPDATA%\Google\Chrome\Application\chrome.exe')
if not os.path.exists(chrome_path):
    chrome_path = r'C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe'

print(f"Running automated interaction suite in {chrome_path}...")
cmd = [chrome_path, '--headless=new', '--dump-dom', f'file:///{test_file.as_posix()}']
proc = subprocess.run(cmd, capture_output=True, encoding='utf-8', errors='replace', timeout=20)
dom = proc.stdout

if 'id="suite-results"' in dom:
    m = re.search(r'<div id="suite-results">(.*?)</div>', dom, re.DOTALL)
    if m:
        print("\n=== INTERACTION TEST SUITE REPORT ===")
        safe_output = m.group(1).encode('ascii', errors='backslashreplace').decode('ascii')
        print(safe_output)
        print("=====================================\n")
else:
    print("Suite did not append results div.")
    print("Stdout snippet:", dom[:1000])
