"""
CTF Atlas — scripts/build_all.py
Master build pipeline orchestrator:
1. Compiles authentic TCS HackQuest writeups (Seasons 1-10, Rounds 1 & 2).
2. Assembles full textbook knowledge base and tournament writeups into site-src/textbook-data.js.
3. Bundles all client portal assets into lib/assets.mjs for Vercel deployment.
4. Validates data integrity and test suites.
"""

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

def run_step(desc, script_name):
    print(f"\n[+] STEP: {desc} ({script_name})...")
    res = subprocess.run([sys.executable, str(ROOT / 'scripts' / script_name)], capture_output=True, text=True)
    if res.stdout:
        print(res.stdout.strip())
    if res.stderr:
        print("[STDERR]", res.stderr.strip())
    if res.returncode != 0:
        print(f"[!] FAILED step: {script_name}")
        sys.exit(res.returncode)

if __name__ == '__main__':
    print("=" * 65)
    print("CTF ATLAS // MASTER PIPELINE BUILD & AUDIT")
    print("=" * 65)
    
    run_step("1. Build TCS HackQuest Writeups (All Seasons)", "build_tcs_hackquest_writeups.py")
    run_step("2. Compile Textbook & Knowledge Base", "build_full_knowledge_base.py")
    run_step("3. Bundle Portal Assets to lib/assets.mjs", "build_assets.py")
    run_step("4. Run TCS HackQuest Audit Suite", "verify_tcs_hackquest.py")
    run_step("5. Run Inlined Portal & Modal Audit", "test_modal_and_hackquest.py")

    print("\n" + "=" * 65)
    print("BUILD COMPLETE! ALL PLATFORM ARRANGEMENTS & WRITEUPS READY.")
    print("=" * 65)
