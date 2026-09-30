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

# Add interactive test harness simulating real user clicks
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

    // 2. Test Navigation to all 12 views
    const views = ['path', 'modules', 'domains', 'tools', 'labs', 'playbook', 'casebook', 'library', 'glossary', 'intel', 'curriculum', 'dashboard'];
    for (const v of views) {{
      const btn = document.querySelector(`.nav-item[data-view="${{v}}"]`);
      if (!btn) {{ log(`MISSING_NAV_BTN:${{v}}`); continue; }}
      btn.click();
      const curView = state.view;
      const vEl = document.getElementById('view');
      log(`NAV_CLICK:${{v}}->state=${{curView}},hasContent=${{vEl && vEl.innerHTML.length > 50}}`);
    }}

    // 3. Test Hero action buttons
    document.querySelector('.nav-item[data-view="dashboard"]').click();
    const heroPathBtn = document.querySelector('[data-action="goto-path"]');
    if (heroPathBtn) {{
      heroPathBtn.click();
      log('HERO_GOTO_PATH:' + state.view);
    }}

    const heroLabsBtn = document.querySelector('[data-action="goto-labs"]');
    if (heroLabsBtn) {{
      heroLabsBtn.click();
      log('HERO_GOTO_LABS:' + state.view);
    }}

    // 4. Test Micro-labs interactive flag submission
    const labBtn = document.querySelector('[data-check="find-the-flag"]');
    const labInput = document.querySelector('#ans-find-the-flag');
    if (labBtn && labInput) {{
      labInput.value = 'CTF{{inspect_element_first_clue}}';
      labBtn.click();
      const resEl = document.querySelector('#res-find-the-flag');
      log('MICRO_LAB_SOLVE:' + (resEl ? resEl.textContent.trim() : 'NO_RES'));
    }}

    // 5. Test Curriculum and Virtual Terminal Mount
    // Directly seed intelCache so curriculum is immediately ready
    intelCache = liveIntelData;
    document.querySelector('.nav-item[data-view="curriculum"]').click();
    log('CURRICULUM_VIEW:' + state.view);
    
    // Select linux-cli module card
    const modCard = document.querySelector('[data-curriculum-module="linux-cli"]');
    if (modCard) {{
      modCard.click();
      log('CURRICULUM_MODULE_SELECT:' + state.curriculumModule);
      
      const termContainer = document.getElementById('terminal-lab-mount');
      const termInput = termContainer ? termContainer.querySelector('.vterm-input') : null;
      const termOutput = termContainer ? termContainer.querySelector('.vterm-output') : null;
      log('TERMINAL_MOUNTED:' + (termInput !== null && termOutput !== null));

      if (termInput) {{
        // Test terminal command execution
        termInput.value = 'whoami';
        const enterEvent = new KeyboardEvent('keydown', {{ key: 'Enter', keyCode: 13, which: 13, bubbles: true }});
        termInput.dispatchEvent(enterEvent);
        
        termInput.value = 'find / -perm -4000 -type f';
        termInput.dispatchEvent(enterEvent);

        termInput.value = '/usr/local/bin/find / -name flag.txt -exec cat {{}} \\\\;';
        termInput.dispatchEvent(enterEvent);

        const termText = termOutput ? termOutput.textContent : '';
        const hasFlag = termText.includes('CTF{{SUID_GT_F0_Bins_R00t}}');
        log('TERMINAL_EXPLOIT_SOLVED:' + hasFlag);
      }}
    }} else {{
      log('MOD_CARD_LINUX_CLI_NOT_FOUND');
    }}

    // 6. Test Visual theme toggle
    const themeBtn = document.getElementById('themeToggle');
    if (themeBtn) {{
      const oldTheme = state.theme;
      themeBtn.click();
      log(`THEME_TOGGLE:${{oldTheme}}->${{state.theme}}`);
    }}

    // 7. Output Final Results
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

test_file = ROOT / 'scratch' / 'interactive-test.html'
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
        print(m.group(1))
        print("=====================================\n")
else:
    print("Suite did not append results div.")
