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

print('portal_html len:', len(portal_html))
print('portal_css len:', len(portal_css))
print('portal_js len:', len(portal_js))

# Check portal_js for raw </script
raw_script_closing = re.findall(r'</script', portal_js, re.IGNORECASE)
print('Raw </script in portal_js:', len(raw_script_closing))
assert len(raw_script_closing) == 0, f"Found {len(raw_script_closing)} unescaped </script in portal_js!"

# Now test html assembly as done in api/portal.js
safe_css = re.sub(r'</style', r'<\\/style', portal_css, flags=re.IGNORECASE)
safe_js  = re.sub(r'</script', r'<\\/script', portal_js, flags=re.IGNORECASE)

html = portal_html.replace('<link rel="stylesheet" href="styles.css">', f'<style>{safe_css}</style>')
html = html.replace('<script src="app.js"></script>', f'<script>{safe_js}</script>')

# Add headless browser test probe
test_probe = """
<script>
window.addEventListener('DOMContentLoaded', () => {
  const v = document.getElementById('view');
  const d = document.createElement('div');
  d.id = 'suite-results';
  
  const results = {
    view_children: v ? v.children.length : 0,
    has_terminal_engine: typeof window.CTFTerminalEngine !== 'undefined',
    has_textbook: typeof window.TEXTBOOK_CHAPTERS !== 'undefined',
    textbook_count: typeof window.TEXTBOOK_CHAPTERS !== 'undefined' ? Object.keys(window.TEXTBOOK_CHAPTERS).length : 0,
    has_writeups: typeof window.TOURNAMENT_WRITEUPS !== 'undefined',
    writeups_count: typeof window.TOURNAMENT_WRITEUPS !== 'undefined' ? window.TOURNAMENT_WRITEUPS.length : 0,
    current_view: typeof state !== 'undefined' ? state.view : 'none',
    active_nav: document.querySelector('.nav-btn.active')?.dataset.view,
    raw_leak_detected: document.body.innerText.includes('Standard non-destructive cookie exfiltration') || document.body.innerText.includes('"cmd":')
  };
  
  d.textContent = JSON.stringify(results);
  document.body.appendChild(d);
});
</script>
"""

out_file = ROOT / 'scratch' / 'verify_portal.html'
out_file.write_text(html + test_probe, encoding='utf-8')
print('Wrote test file to:', out_file)

chrome_path = os.path.expandvars(r'%LOCALAPPDATA%\Google\Chrome\Application\chrome.exe')
if not os.path.exists(chrome_path):
    chrome_path = r'C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe'

print(f"Testing in browser: {chrome_path}...")
cmd = [chrome_path, '--headless=new', '--dump-dom', f'file:///{out_file.as_posix()}']
proc = subprocess.run(cmd, capture_output=True, encoding='utf-8', errors='replace', timeout=15)
dom = proc.stdout

if 'id="suite-results"' in dom:
    m = re.search(r'<div id="suite-results">(.*?)</div>', dom)
    if m:
        data = json.loads(m.group(1))
        print("BROWSER TEST RESULTS:")
        for k, v in data.items():
            print(f"  {k}: {v}")
        if data.get('raw_leak_detected') is False and data.get('view_children', 0) > 0 and data.get('has_terminal_engine') and data.get('has_textbook'):
            print("\n[SUCCESS] PORTAL ENGINE FULLY OPERATIONAL IN REAL BROWSER! NO LEAKS!")
        else:
            print("\n[FAILURE] Browser test assertions failed!")
    else:
        print("Could not parse suite-results content!")
else:
    print("suite-results element NOT found in DOM! Check JS syntax errors.")
    # Look for any text leaks in the DOM
    if 'Standard non-destructive cookie exfiltration' in dom:
        print("CRITICAL: Raw leak detected in DOM!")
    else:
        print("No raw leak found, but script did not complete execution.")
