"""
CTF Atlas — Foundations & Threat Modeling Chapters
"""

chapters = {}

chapters["foundations-threat-model"] = {
    "id": "foundations-threat-model",
    "domain": "foundations",
    "category": "Foundations & Threat Modeling",
    "title": "CTF Problem Solving Anatomy, CIA Triad & Trust Boundaries",
    "subtitle": "Scientific Hypothesis Cycles, Data-Flow Deconstruction & Reproducible Evidence Chains",
    "diagram": """+-------------------------------------------------------------------+
|               The Scientific CTF Solver Cycle                     |
+-------------------------------------------------------------------+
       1. TRIAGE & OBSERVE          2. MODEL TRUST BOUNDARIES
   Identify Category Clues      Draw 4-Box Architecture
   Check Magic Bytes / Strings   Map Client -> API -> DB -> Host
              |                                 |
              v                                 v
       3. FORM HYPOTHESIS           4. REVERSIBLE EXPERIMENT
   "System is vulnerable to X   Change single variable (payload)
    because invariant Y broke"  Log raw request and response
              |                                 |
              +----------------+----------------+
                               |
                               v
                       5. PROVE & REPRODUCE
                 Construct minimal 1-line script
                 Validate flag token: CTF{...}
                 Document defensive invariant breach""",
    "theory": """Capture The Flag (CTF) challenges are designed not as random puzzles, but as observable deterministic state machines with specific security boundary violations. Beginners often fail because they guess random payloads or blindly run automated scanners without understanding the underlying state machine.

Core Security Invariants & The CIA Triad:
1. Confidentiality: Preserving authorized restrictions on access and disclosure. In CTF, broken by unauthorized read primitives: SQLi data extraction, local file inclusion (/etc/passwd), memory disclosure leaks (puts(GOT)), or cryptographic key recovery.
2. Integrity: Guarding against improper information modification or destruction. Broken by write primitives: stack return address overwrites, SQL UPDATE injection, CSRF, or deserialization object tampering.
3. Availability: Ensuring timely and reliable access. In Attack/Defense CTFs, SLA (Service Level Agreements) mandate uptime while patching vulnerabilities.
4. Authenticity & Authorization: Authenticity establishes identity (Who are you? e.g. Passwords, PKI); Authorization establishes privilege (What are you permitted to do?). The most common real-world and CTF bugs live at the authorization boundary: Insecure Direct Object References (IDOR), privilege escalation via SUID or sudo, and role confusion.

Trust Boundary Modeling:
A trust boundary exists wherever data transitions between two disparate execution contexts or privilege domains:
- Browser DOM <-> HTTP Reverse Proxy <-> Backend Application (Flask/Express/Spring)
- Application Server <-> SQL Database Engine / Redis Cache
- Web Service <-> Operating System Shell (via execve/system)
- Unprivileged User Process <-> Linux Kernel Space (via syscalls/VFS)
Vulnerabilities occur almost exclusively at trust boundaries where the receiving system assumes data has been validated by the sender.""",
    "commands": [
        {
            "cmd": "curl -sI https://target.ctf | grep -iE 'server|x-powered-by|set-cookie'",
            "why": "Extracts HTTP response headers to identify web server technology, runtime versions, and session flags.",
            "when": "First 10 seconds of web challenge reconnaissance.",
            "internals": "Performs TCP handshake and issues HTTP HEAD request; parses initial header token lines.",
            "pitfalls": "Modern proxies often strip or spoof header banners. Treat headers as clues, not proofs."
        },
        {
            "cmd": "file target_artifact && strings -n 8 target_artifact | head -n 30",
            "why": "Determines authoritative file type via magic bytes and inspects human-readable strings.",
            "when": "First step upon downloading any mystery binary, firmware, or memory dump.",
            "internals": "file uses libmagic pattern database; strings scans binary stream for 8+ sequential ASCII chars.",
            "pitfalls": "Attacker could forge file extension; never rely on filename suffix."
        },
        {
            "cmd": "nc -zv -w 2 target.ctf 1-1000",
            "why": "Fast non-intrusive TCP port scan across common service ports.",
            "when": "Initial network discovery on remote infrastructure.",
            "internals": "Issues non-blocking connect() syscalls with a 2-second timeout.",
            "pitfalls": "Full connect scan creates logged connections on firewalled targets."
        }
    ],
    "cli_vs_gui": {
        "cli_workflow": "Terminal pipeline: `curl -s http://target/ | htmlq 'a' --attribute href | sort -u` to extract all endpoints instantaneously.",
        "gui_workflow": "Burp Suite: Configure browser proxy -> Target tab -> Site Map -> View tree view of endpoints and parameter taxonomy.",
        "speed_tip": "Keep a split terminal with tmux: left pane for target interaction (curl/nc/gdb), right pane for Python solver script editor."
    },
    "triage_workflow": [
        "1. Read the prompt twice. Extract literal keywords, developer names, and subtle hints.",
        "2. Inspect Artifacts: Run `file`, `ls -la`, and `sha256sum` on all provided challenge files.",
        "3. Draw Data-Flow: Map inputs, interpreters, databases, and expected flag location.",
        "4. Form Falsifiable Hypothesis: Predict exactly what output should appear upon test input.",
        "5. Execute Minimal Test: Use curl or raw socket; avoid heavy scanners initially.",
        "6. Exploit & Document: Write a self-contained Python script to extract and display the flag."
    ],
    "writeup": {
        "ctf_event": "Collegiate CTF / National Cyber League",
        "challenge_name": "Sanity Check & Triage Discipline",
        "scenario": "A target server hosts a mystery service on port 1337. Players are given no source code.",
        "solve_steps": [
            "1. Connect via netcat: nc target.ctf 1337",
            "2. Observe prompt: 'Enter authorization token hex:'",
            "3. Test basic input: send '00' -> returns 'Invalid length: expected 32 bytes'",
            "4. Hypothesize fixed token check: provide 32 bytes of zeros.",
            "5. Server returns: 'XOR verification failed at index 0: expected 0x43, got 0x00'.",
            "6. Notice server is acting as an index-by-index oracle leaking the expected bytes!",
            "7. Write Python script to iterate 32 bytes, reading the expected byte leaked by error message.",
            "8. Flag recovered: CTF{THINK_M0D3L_EXP3R1M3NT_PR0V3}"
        ],
        "exploit_code": """#!/usr/bin/env python3
import socket

def solve():
    s = socket.create_connection(('target.ctf', 1337))
    token = bytearray(32)
    for idx in range(32):
        s.sendall(token.hex().encode() + b'\\n')
        resp = s.recv(1024).decode()
        if 'CTF{' in resp:
            print("[+] Flag:", resp)
            return
        if 'expected 0x' in resp:
            leak_hex = resp.split('expected 0x')[1][:2]
            token[idx] = int(leak_hex, 16)
            print(f"[+] Byte {idx}: {token[idx]:02x}")

if __name__ == '__main__':
    solve()""",
        "flag": "CTF{THINK_M0D3L_EXP3R1M3NT_PR0V3}",
        "mitigation": "Avoid leaking internal cryptographic comparison mismatches or validation offsets to end users. Perform comparisons in constant time."
    }
}
