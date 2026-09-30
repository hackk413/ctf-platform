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

safe_css = re.sub(r'</style', r'<\\/style', portal_css, flags=re.IGNORECASE)
safe_js  = re.sub(r'</script', r'<\\/script', portal_js, flags=re.IGNORECASE)

html = portal_html.replace('<link rel="stylesheet" href="styles.css">', f'<style>{safe_css}</style>')
html = html.replace('<script src="app.js"></script>', f'<script>{safe_js}</script>')

# Add test probe specifically verifying modal command table and TCS HackQuest writeups
test_probe = f"""
<script>
window.addEventListener('DOMContentLoaded', () => {{
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

  const report = {{}};

  try {{
    // 1. Open foundations-threat-model modal
    openTextbookModal('foundations-threat-model');
    const modalBackdrop = document.getElementById('modalBackdrop');
    const modalBody = document.getElementById('modalBody');
    report.modal_visible = !modalBackdrop.hidden;

    // Check command table
    const cmdRows = modalBody.querySelectorAll('.cmd-table tbody tr');
    report.cmd_row_count = cmdRows.length;
    report.commands = [];
    cmdRows.forEach(tr => {{
      const cmdCell = tr.querySelector('td:nth-child(1)');
      const whyCell = tr.querySelector('td:nth-child(2)');
      report.commands.push({{
        cmd_text: cmdCell ? cmdCell.textContent.trim() : '',
        why_text: whyCell ? whyCell.textContent.trim().substring(0, 30) : ''
      }});
    }});

    // Check Theory
    const theoryHeaders = modalBody.querySelectorAll('h4');
    report.theory_header_count = theoryHeaders.length;

    // Check Workflows
    const wfPanes = modalBody.querySelectorAll('.wf-pane');
    report.wf_pane_count = wfPanes.length;

    // Check Triage Checklist
    const checklistItems = modalBody.querySelectorAll('.checklist li');
    report.checklist_count = checklistItems.length;

    // Check Case Study Exploit Script
    const exploitCode = modalBody.querySelector('.code-block');
    report.has_exploit_code = !!exploitCode && exploitCode.textContent.length > 20;

    // Close Modal
    closeModal();
    report.modal_closed = modalBackdrop.hidden;

    // 2. Test Casebook TCS HackQuest Tab
    const casebookBtn = document.querySelector('.nav-item[data-view="casebook"]');
    if (casebookBtn) casebookBtn.click();

    const hqTab = document.querySelector('[data-casebook-tab="hackquest"]');
    report.has_hq_tab = !!hqTab;
    if (hqTab) {{
      hqTab.click();
      const writeupCards = document.querySelectorAll('.writeup-card');
      report.hq_card_count = writeupCards.length;
      report.hq_sample_titles = [];
      writeupCards.forEach((c, idx) => {{
        if (idx < 5) {{
          const h3 = c.querySelector('h3');
          if (h3) report.hq_sample_titles.push(h3.textContent);
        }}
      }});
    }}

  }} catch (e) {{
    report.error = e.toString();
  }}

  const d = document.createElement('div');
  d.id = 'deep-audit-results';
  d.textContent = JSON.stringify(report);
  document.body.appendChild(d);
}});
</script>
"""

out_file = ROOT / 'scratch' / 'modal_hq_audit.html'
out_file.write_text(html + test_probe, encoding='utf-8')

chrome_path = os.path.expandvars(r'%LOCALAPPDATA%\Google\Chrome\Application\chrome.exe')
if not os.path.exists(chrome_path):
    chrome_path = r'C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe'

cmd = [chrome_path, '--headless=new', '--dump-dom', f'file:///{out_file.as_posix()}']
proc = subprocess.run(cmd, capture_output=True, encoding='utf-8', errors='replace', timeout=15)
dom = proc.stdout

if 'id="deep-audit-results"' in dom:
    m = re.search(r'<div id="deep-audit-results">(.*?)</div>', dom)
    if m:
        data = json.loads(m.group(1))
        print("=== DEEP AUDIT RESULTS ===")
        print(f"Modal Visible: {data.get('modal_visible')}")
        print(f"Command Row Count: {data.get('cmd_row_count')}")
        for i, c in enumerate(data.get('commands', [])):
            print(f"  Row {i+1}: CMD='{c['cmd_text']}' | WHY='{c['why_text']}...'")
        print(f"Theory Headers: {data.get('theory_header_count')}")
        print(f"Workflow Panes: {data.get('wf_pane_count')}")
        print(f"Checklist Items: {data.get('checklist_count')}")
        print(f"Has Exploit Code Block: {data.get('has_exploit_code')}")
        print(f"Has TCS HackQuest Tab: {data.get('has_hq_tab')}")
        print(f"TCS HackQuest Writeups Rendered: {data.get('hq_card_count')}")
        print("Sample Titles:")
        for t in data.get('hq_sample_titles', []):
            print(f"  - {t}")
        
        # Assertions
        assert data.get('cmd_row_count', 0) > 0, "No command rows rendered!"
        assert all(c['cmd_text'] != '' for c in data.get('commands', [])), "Found empty command text in table!"
        assert data.get('hq_card_count', 0) >= 27, f"Expected at least 27 TCS HackQuest writeups, got {data.get('hq_card_count')}"
        print("\n[SUCCESS] ALL ASSERTIONS PASSED! COMMANDS RENDER PROPERLY & TCS HACKQUEST READY!")
else:
    print("Test probe did not render. Output:", dom[:300])
