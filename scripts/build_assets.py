"""
CTF Atlas — scripts/build_assets.py
Python replica of scripts/build-assets.mjs
Bundles portal HTML, CSS, JS, and terminal engine into lib/assets.mjs.
"""

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

def read(rel: str) -> str:
    path = ROOT / rel
    if not path.exists():
        print(f"  WARNING: {path} not found")
        return ""
    return path.read_text(encoding="utf-8")

html = read("site-src/portal.html")
css = read("site-src/portal.css")
js = read("site-src/portal.js")
terminal_engine = read("site-src/terminal-engine.js")
textbook_data = read("site-src/textbook-data.js")

combined_js = "\n".join([
    "/* CTF Atlas — Combined Portal App (auto-generated, do not edit) */",
    "/* textbook-data.js */",
    textbook_data,
    "",
    "/* terminal-engine.js */",
    terminal_engine,
    "",
    "/* portal.js */",
    js,
    "",
    "/* Terminal engine global mount binding */",
    'if (typeof mountTerminal !== "undefined") { window.mountTerminal = mountTerminal; }',
])

out = "\n".join([
    "// Generated protected assets. Do not move this file into public/.",
    "// Do not edit manually — run: node scripts/build-assets.mjs or python scripts/build_assets.py",
    f"export const portalHtml = {json.dumps(html)};",
    f"export const portalCss  = {json.dumps(css)};",
    f"export const portalJs   = {json.dumps(combined_js)};",
    f"export const terminalEngineJs = {json.dumps(terminal_engine)};",
    "",
])

out_path = ROOT / "lib" / "assets.mjs"
out_path.parent.mkdir(parents=True, exist_ok=True)
out_path.write_text(out, encoding="utf-8")

print(f"[build_assets] Built {out_path}")
print(f"  portal.html:        {len(html):,} bytes")
print(f"  portal.css:         {len(css):,} bytes")
print(f"  portal.js:          {len(js):,} bytes")
print(f"  terminal-engine.js: {len(terminal_engine):,} bytes")
print(f"  combined app.js:    {len(combined_js):,} bytes")
print(f"  Total output:       {len(out):,} bytes")
