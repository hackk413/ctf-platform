import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

assets_text = (ROOT / 'lib' / 'assets.mjs').read_text(encoding='utf-8')

m_html = re.search(r'export const portalHtml\s*=\s*(.*?);\nexport const portalCss', assets_text, re.DOTALL)
m_css  = re.search(r'export const portalCss\s*=\s*(.*?);\nexport const portalJs', assets_text, re.DOTALL)
m_js   = re.search(r'export const portalJs\s*=\s*(.*?);\nexport const terminalEngineJs', assets_text, re.DOTALL)

portal_html = json.loads(m_html.group(1))
portal_css  = json.loads(m_css.group(1))
portal_js   = json.loads(m_js.group(1))

# Simulate api/portal.js
inlined_css = portal_css.replace('</style', '<\\/style')
inlined_js  = portal_js.replace('</script', '<\\/script')

html = portal_html.replace('<link rel="stylesheet" href="styles.css">', f'<style>{inlined_css}</style>')
html = html.replace('<script src="app.js"></script>', f'<script>{inlined_js}</script>')
html = html.replace('<title>CTF Atlas // Secure Learning Range</title>', '<title>CTF ATLAS // AUTHENTICATED RANGE</title>')

print(f"Generated HTML size: {len(html):,} bytes")
print("Starts with <!doctype html>:", html.startswith('<!doctype html>'))
print("Contains <style>:", '<style>' in html)
print("Contains <script>:", '<script>' in html)

# Verify script tag closure
script_start = html.find('<script>')
first_closing_script = html.find('</script>')
print(f"Script starts at offset: {script_start:,}")
print(f"First closing script tag at: {first_closing_script:,}")
print(f"Total HTML length: {len(html):,}")

# Verify that the first closing script tag is AFTER the inlined app.js
app_js_len = len(inlined_js)
print(f"App JS length: {app_js_len:,}")
assert first_closing_script > script_start + app_js_len, "Script tag closed prematurely!"

# Verify no unhandled dollar replacement tokens in html
assert '$&' not in html, "Found unexpanded $& token in html!"
assert '$$' not in html, "Found unexpanded $$ token in html!"

print("[SUCCESS] All portal inlining tests PASSED!")
