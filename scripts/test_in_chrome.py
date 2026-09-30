import json
import re
import subprocess
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
assets_text = (ROOT / 'lib' / 'assets.mjs').read_text(encoding='utf-8')

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

# Add test probe script to log results and dump to a div
test_probe = """
<script>
window.addEventListener('DOMContentLoaded', () => {
  const v = document.getElementById('view');
  const out = [
    'VIEW_CHILDREN_COUNT:' + (v ? v.children.length : -1),
    'VIEW_INNER_HTML_LEN:' + (v ? v.innerHTML.length : -1),
    'HAS_TERMINAL_ENGINE:' + (typeof window.CTFTerminalEngine),
    'HAS_MOUNT_TERMINAL:' + (typeof window.mountTerminal),
    'CURRENT_VIEW:' + (typeof state !== 'undefined' ? state.view : 'undefined')
  ].join(' | ');
  const d = document.createElement('div');
  d.id = 'test-results';
  d.textContent = out;
  document.body.appendChild(d);
});
</script>
"""

test_file = ROOT / 'scratch' / 'portal-test.html'
test_file.parent.mkdir(exist_ok=True)
test_file.write_text(html + test_probe, encoding='utf-8')

chrome_path = os.path.expandvars(r'%LOCALAPPDATA%\Google\Chrome\Application\chrome.exe')
if not os.path.exists(chrome_path):
    chrome_path = r'C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe'

print(f"Testing in {chrome_path}...")
cmd = [chrome_path, '--headless=new', '--dump-dom', f'file:///{test_file.as_posix()}']
try:
    proc = subprocess.run(cmd, capture_output=True, encoding='utf-8', errors='replace', timeout=15)
    dom = proc.stdout
    if 'id="test-results"' in dom:
        m = re.search(r'<div id="test-results">(.*?)</div>', dom)
        if m:
            print("TEST RESULTS:")
            print(m.group(1))
    else:
        print("DOM output length:", len(dom))
        m_view = re.search(r'<section id="view"[^>]*>(.*?)</section>', dom, re.DOTALL)
        if m_view:
            print("View inner content length:", len(m_view.group(1)))
            print("View preview:", m_view.group(1)[:200])
        else:
            print("Section #view not found!")
except Exception as e:
    print("Error running browser:", e)
