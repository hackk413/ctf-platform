"""
Master Knowledge Base & Textbook Builder for CTF Atlas
Compiles all modular chapters and tournament writeups into site-src/textbook-data.js.
"""

import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent.parent
CHAPTERS_DIR = ROOT / 'scripts' / 'chapters'
sys.path.insert(0, str(CHAPTERS_DIR))

# Import all chapters
import foundations
import linux
import networking
import web
import crypto
import forensics
import reverse
import pwn
import stego
import osint
import cloud
import blue_team

all_chapters = {}
modules = [
    foundations,
    linux,
    networking,
    web,
    crypto,
    forensics,
    reverse,
    pwn,
    stego,
    osint,
    cloud,
    blue_team
]

for mod in modules:
    all_chapters.update(mod.chapters)

# Load tournament writeups from JSON
writeups_file = ROOT / "data" / "tournament-writeups.json"
if writeups_file.exists():
    all_writeups = json.loads(writeups_file.read_text(encoding="utf-8"))
else:
    all_writeups = []

# Write out site-src/textbook-data.js
js_content = [
    "/* CTF Atlas — Master Textbook & Knowledge Vault v3.0 */",
    "/* Zero-backend educational knowledge base & tournament writeups */",
    "'use strict';",
    "",
    f"window.TEXTBOOK_CHAPTERS = {json.dumps(all_chapters, indent=2)};",
    "",
    f"window.TOURNAMENT_WRITEUPS = {json.dumps(all_writeups, indent=2)};",
    ""
]

out_file = ROOT / "site-src" / "textbook-data.js"
out_file.write_text("\n".join(js_content), encoding="utf-8")

print(f"[+] Successfully compiled Master Knowledge Base: {out_file}")
print(f"    Total Size: {len(out_file.read_text(encoding='utf-8')):,} bytes")
print(f"    Total Textbook Chapters: {len(all_chapters)}")
print(f"    Total Tournament Writeups: {len(all_writeups)}")
print(f"    Chapters List: {list(all_chapters.keys())}")
