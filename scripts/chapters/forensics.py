"""
CTF Atlas — Digital Forensics Chapters
"""

chapters = {}

chapters["forensics-volatility"] = {
    "id": "forensics-volatility",
    "domain": "forensics",
    "category": "Digital Forensics & Incident Response",
    "title": "Volatile Memory (RAM) Forensics & Kernel Object Carving",
    "subtitle": "Virtual Address Translation (CR3), EPROCESS Linked Lists, Process Hollowing & Volatility 3",
    "diagram": """Physical Memory Dump (RAM .raw / .vmem)
       |
       +---> Kernel Directory Table Base (CR3 register)
       |     Translates Virtual -> Physical Memory
       |
       +---> EPROCESS Double Linked List (ActiveProcessLinks)
             |
             +-> Process 1: explorer.exe (PID 1420)
             |   +-> VAD (Virtual Address Descriptors) Tree
             |   +-> Memory Sections: PAGE_EXECUTE_READWRITE
             |
             +-> Process 2: svchost.exe (PID 3110) [Injected!]
                 +-> PE Header inside unbacked memory page
                 +-> Shellcode detected via `windows.malfind`""",
    "theory": """Volatile memory forensics involves acquiring and analyzing physical computer RAM to capture ephemeral forensic evidence that disappears when the system loses power. RAM retains active process execution structures, decrypted passwords, open network sockets, unencrypted cryptographic keys, and sophisticated memory-only malware (process hollowing, reflective DLL injection, kernel rootkits).

Windows Kernel Memory Architecture:
In 64-bit Windows, each user-mode process operates within an isolated virtual address space. The CPU's CR3 control register points to the Directory Table Base (PML4) physical address for the active process.
- EPROCESS Executive Structure: Every Windows process is tracked by an `EPROCESS` block in kernel space. All EPROCESS blocks are connected via the circular doubly linked list `ActiveProcessLinks`. Volatility's `windows.pslist` walks this list. Advanced rootkits unhook their malicious processes from `ActiveProcessLinks` (Direct Kernel Object Modification, DKOM). Volatility's `windows.psscan` counters this by scanning pool memory for unlinked EPROCESS pool tag signatures ('Proc').
- Virtual Address Descriptors (VAD Tree): Self-balancing binary tree tracking memory allocations within a process.
- Code Injection Indicators: Memory pages marked `PAGE_EXECUTE_READWRITE` (RWX) not backed by a disk file (unmapped commit) represent the classic signature of process hollowing or shellcode injection.""",
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
        "speed_tip": "Run `vol -f mem.raw windows.cmdline` early—attackers frequently leave plaintext flags or credentials in batch script execution arguments."
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
        "exploit_code": """#!/usr/bin/env python3
import subprocess

def solve_mem():
    cmd = "vol -f memory.dmp windows.malfind --pid 3844"
    out = subprocess.check_output(cmd, shell=True, text=True)
    print("[*] Malfind Output:\\n", out[:500])
    dump_cmd = "vol -f memory.dmp windows.dumpfiles --pid 3844"
    subprocess.run(dump_cmd, shell=True)
    flag = subprocess.check_output("strings *.dat | grep 'CTF{'", shell=True, text=True)
    print("[+] Flag:", flag.strip())

if __name__ == '__main__':
    solve_mem()""",
        "flag": "CTF{M3M0RY_F0R3NS1CS_V0L4T1L1TY3_WIN}",
        "mitigation": "Deploy Endpoint Detection and Response (EDR) solutions monitoring for cross-process memory manipulation APIs (VirtualAllocEx, WriteProcessMemory, CreateRemoteThread)."
    }
}

chapters["forensics-disk-fs"] = {
    "id": "forensics-disk-fs",
    "domain": "forensics",
    "category": "Disk & Filesystem Forensics",
    "title": "Raw Disk Image Carving, MBR/GPT Partition Tables & Filesystem Forensics",
    "subtitle": "Master Boot Records, Partition Offsets, Ext4/NTFS Inode Journaling & File Carving via Magic Numbers",
    "diagram": """+-----------------------------------------------------------------+
|                   Raw Disk Image Sector Map                     |
+-----------------------------------------------------------------+
Sector 0: Master Boot Record (MBR, 512 bytes)
  |-- Bytes 0..445   : Bootstrap code
  |-- Bytes 446..509 : 4 Partition Table Entries (16 bytes each)
  |     |-- Entry 1: Type 0x83 (Linux), Starting Sector = 2048 (Offset 1,048,576)
  |-- Bytes 510..511 : Boot Signature (0x55 0xAA)
  |
Sector 2048: Partition 1 Filesystem Superblock (Ext4)
  |-- Inode Table -> Points to Data Blocks
  |-- Deleted Files: Inode marked unallocated (dtime set),
      BUT data blocks on disk remain intact until overwritten!
      -> Recoverable via `fls`, `icat`, or raw carving (`scalpel`/`foremost`)!""",
    "theory": """Disk forensics involves the acquisition, recovery, and analysis of persistent digital media. Forensic investigations operate against bit-stream disk images (raw `.dd`, `.raw`, or EWF `.E01`) rather than mounting devices live to preserve evidentiary integrity and prevent operating system metadata modification (such as atime updates).

Disk Partitioning & Master Boot Record (MBR):
Sector 0 (the first 512 bytes) of an MBR disk contains the partition table. Each partition entry specifies: bootable flag (0x80), partition type (e.g. 0x07 NTFS, 0x83 Linux), and starting LBA sector. To mount or carve a filesystem inside a disk image, solvers multiply the starting sector by the sector size (typically 512 bytes):
$$\\text{Byte Offset} = \\text{Starting Sector} \\times 512$$
Example: Starting sector 2048 yields offset $2048 \\times 512 = 1,048,576$ bytes. Mounting requires: `mount -o loop,offset=1048576 disk.img /mnt`.

File Deletion & Carving Mechanics:
When a user deletes a file on a filesystem (ext4, FAT32, NTFS):
1. Inode Metadata: The filesystem updates the inode metadata: marks the inode as free in the inode allocation bitmap, sets deletion timestamp (`dtime`), and decrements directory link counts.
2. Data Blocks Untouched: The actual underlying physical data blocks containing the file bytes are NOT erased or zeroed out! They are merely marked as available for future allocations.
3. Carving via Magic Numbers: Tools scan raw sector bytes for file signatures (magic bytes):
   - JPEG: `\\xFF\\xD8\\xFF` ... `\\xFF\\xD9`
   - PNG: `\\x89\\x50\\x4E\\x47\\x0D\\x0A\\x1A\\x0A` ... `IEND` chunk
   - PDF: `%PDF-` ... `%%EOF`
   - ZIP: `PK\\x03\\x04` ... `PK\\x05\\x06`""",
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
        "exploit_code": """#!/usr/bin/env python3
import subprocess

def solve_disk():
    cmd = "fls -o 2048 -r -p usb.img | grep -i flag"
    out = subprocess.check_output(cmd, shell=True, text=True)
    inode = out.split()[2].replace(":", "")
    print(f"[+] Found deleted flag inode: {inode}")
    flag = subprocess.check_output(f"icat -o 2048 usb.img {inode}", shell=True, text=True)
    print("[+] Flag:", flag.strip())

if __name__ == '__main__':
    solve_disk()""",
        "flag": "CTF{EXT4_1N0D3_C4RV1NG_SUCC3SS}",
        "mitigation": "To securely erase sensitive data on magnetic or solid-state media, use cryptographic shredding (`shred -u -z`) or full-disk encryption (LUKS / BitLocker) so discarded data blocks are unreadable."
    }
}

chapters["forensics-pcap"] = {
    "id": "forensics-pcap",
    "domain": "forensics",
    "category": "Network Traffic Forensics",
    "title": "Network Packet Forensics, Stream Extraction & Tunnel Deconstruction",
    "subtitle": "PCAP/PCAPNG Dissection, HTTP Object Export, ICMP Covert Tunnels & TLS Keylogfile Decryption",
    "diagram": """+-----------------------------------------------------------------+
|                 Network PCAP Forensics Workflow                 |
+-----------------------------------------------------------------+
capture.pcap
  |
  +-> 1. Protocol Hierarchy: tshark -qz io,phs
  |     Reveals: IPv4 -> TCP (92%), UDP (8%) -> DNS, HTTP, ICMP
  |
  +-> 2. Stream Following: tshark -z follow,tcp,ascii,<stream_id>
  |     Reassembles bidirectional conversational transcripts
  |
  +-> 3. Object Carving: tshark --export-objects http,./out
  |     Extracts downloaded binaries, exfiltrated archives
  |
  +-> 4. Anomaly Inspection: ICMP Echo Requests with payload data!
        Normal ping = 32-56 bytes of repetitive patterns
        Malicious covert ping = 128 bytes containing base64 data!""",
    "theory": """Network packet forensics analyzes captured network communications (`.pcap` or `.pcapng` format) to reconstruct security incidents, identify data exfiltration channels, recover transmitted artifacts, and investigate command-and-control (C2) infrastructure.

Dissection Principles & Core Protocols:
1. TCP Stream Reassembly: Applications communicate via arbitrary byte streams across multiple fragmented IP packets. Wireshark and `tshark` track TCP sequence and acknowledgment numbers to reassemble out-of-order and retransmitted segments into contiguous streams.
2. Unencrypted Protocol Inspection: Protocols such as HTTP/1.1, FTP, Telnet, POP3, and IMAP transmit credentials and payloads in plaintext. Solvers filter by credentials (`http.authorization or ftp.request.command == "PASS"`).
3. Covert Channels & Exfiltration Tunnels:
   - ICMP Tunneling (nping, ptunnel): The ICMP Echo Request payload is intended for latency measurement. Attackers encode data directly into the payload field of ICMP packets.
   - DNS Tunneling (iodine, dnscat2): Data is base32/base64 encoded into DNS query domain names (`<chunk>.c2.example.com`).
4. TLS Decryption via (SSLKEYLOGFILE): When analyzing HTTPS captures, traffic appears as encrypted TLS application records (`Content Type: Application Data (23)`). If challenge authors provide an SSL key log file (`sslkeys.log`), Wireshark decrypts all session streams by calculating session secrets from client randoms and pre-master secrets.""",
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
        "exploit_code": """#!/usr/bin/env python3
import subprocess

def solve_pcap():
    cmd = "tshark -r traffic.pcap -Y 'icmp.type == 8' -T fields -e data"
    hex_lines = subprocess.check_output(cmd, shell=True, text=True).splitlines()
    raw_bytes = bytes.fromhex("".join(hex_lines))
    print("[+] Decoded Payload:", raw_bytes.decode(errors='replace'))

if __name__ == '__main__':
    solve_pcap()""",
        "flag": "CTF{1CMP_C0V3RT_CH4NN3L_EXF1L}",
        "mitigation": "Configure perimeter firewalls to inspect ICMP payload size or block outbound ICMP Echo Requests from internal production servers."
    }
}
