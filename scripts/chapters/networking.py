"""
CTF Atlas — Networking Chapters
"""

chapters = {}

chapters["networking-tcp"] = {
    "id": "networking-tcp",
    "domain": "networking",
    "category": "Network Architecture & Protocols",
    "title": "TCP State Machine, Packet Framing & Stream Reconstruction",
    "subtitle": "Three-Way Handshake, Sequence Arithmetic, Sliding Windows & PCAP Forensics",
    "diagram": """Client (Port: Ephemeral 49152)             Server (Port: 80/443)
      |                                              |
      | -------- 1. SYN (seq=x) -------------------> | [LISTEN -> SYN_RCVD]
      |                                              |
      | <------- 2. SYN-ACK (seq=y, ack=x+1) ------- | 
[SYN_SENT -> ESTABLISHED]                            |
      |                                              |
      | -------- 3. ACK (seq=x+1, ack=y+1) --------> | [ESTABLISHED]
      |                                              |
      | <====== Full-Duplex Bidirectional Data =====>|
      |                                              |
      | -------- 4. FIN (seq=u) -------------------> | [CLOSE_WAIT]
[FIN_WAIT_1]                                         |
      | <------- 5. ACK (ack=u+1) ------------------ |
[FIN_WAIT_2]                                         |
      | <------- 6. FIN (seq=w) -------------------- | [LAST_ACK]
[TIME_WAIT (2*MSL)]                                  |
      | -------- 7. ACK (ack=w+1) -----------------> | [CLOSED]""",
    "theory": """The Transmission Control Protocol (TCP, RFC 793 / RFC 9293) is a connection-oriented, reliable transport-layer protocol providing byte-stream delivery with end-to-end flow control and congestion avoidance. Unlike UDP, which transmits stateless independent datagrams, TCP requires mutual state establishment via a 3-Way Handshake before user-space application data (HTTP, SSH, TLS) can be transferred.

Every TCP packet consists of a 20-to-60 byte header:
- Source Port (16 bits) and Destination Port (16 bits): Endpoint multiplexing.
- Sequence Number (32 bits): Tracks the offset of the first data byte in this segment relative to the Initial Sequence Number (ISN).
- Acknowledgment Number (32 bits): Indicates the next byte offset the receiving host expects to receive (cumulative acknowledgment).
- Data Offset (4 bits): Header length in 32-bit words (minimum 5 = 20 bytes).
- Flags (9 bits): URG (urgent pointer valid), ACK (acknowledgment valid), PSH (push data to application immediately), RST (reset connection abruptly), SYN (synchronize sequence numbers), FIN (sender finished transmitting).
- Window Size (16 bits): Flow control buffer capacity advertised by receiver.

In CTF network forensics, solvers analyze packet captures (PCAP) to reconstruct communications. Common puzzles include: (1) extracting unencrypted credentials transmitted over HTTP/FTP/Telnet, (2) carving hidden attachments transported over multipart MIME or raw TCP streams, (3) identifying covert channels that encode data in TCP initial sequence numbers (ISN) or IP TTL headers, and (4) detecting port scans by analyzing SYN/RST ratios.""",
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
        "exploit_code": """#!/usr/bin/env python3
import subprocess, urllib.parse, base64

def solve():
    cmd = "tshark -r dump.pcap -Y 'http.request.uri contains \"data=\"' -T fields -e http.request.uri"
    lines = subprocess.check_output(cmd, shell=True, text=True).splitlines()
    raw_b64 = "".join([l.split("data=")[-1] for l in lines if "data=" in l])
    decoded = base64.b64decode(urllib.parse.unquote(raw_b64)).decode()
    print("[+] Decoded Payload:", decoded)

if __name__ == '__main__':
    solve()""",
        "flag": "CTF{TCP_STR3AM_R3CONSTRUCTION_SUCCESS}",
        "mitigation": "Enforce TLS 1.3 encryption across all internal and external network channels to prevent plain-text eavesdropping and packet inspection."
    }
}

chapters["networking-nmap"] = {
    "id": "networking-nmap",
    "domain": "networking",
    "category": "Network Reconnaissance",
    "title": "Network Reconnaissance Architecture & Nmap Scanning Internals",
    "subtitle": "Raw Socket BPF Crafting, SYN Stealth State Machines, Timing Templates & NSE Scripting",
    "diagram": """+-----------------------------------------------------------------+
|                   Nmap Port Scanning State Machine              |
+-----------------------------------------------------------------+
Attacker (Raw Socket)                      Target Port
       |                                       |
       | ------------ 1. TCP SYN ------------> |
       |                                       |
       | <--- 2a. TCP SYN/ACK (PORT OPEN) ---- |
       | ------------ 3. TCP RST ------------> | (Connection torn down,
       |                                       |  half-open, no app log!)
       |                                       |
       | <--- 2b. TCP RST/ACK (PORT CLOSED) -- |
       |                                       |
       | <--- 2c. No Response / ICMP (FILTERED)- [Firewall / Drop]""",
    "theory": """Network port scanners identify active network hosts and exposed transport-layer listening ports. The Network Mapper (Nmap) achieves high performance by bypassing high-level operating system socket APIs and constructing raw Ethernet and IP frames directly in user space using `libpcap`.

Scanning Techniques & Internal Protocol Signatures:
1. TCP SYN Stealth Scan (`-sS`, Default Root): Executes a 'half-open' handshake. Sends a raw SYN segment. If the target returns SYN-ACK, Nmap records the port as OPEN and immediately transmits a RST packet to tear down the embryonic connection. Because the full 3-way handshake never completes, application-layer listeners (Apache, Nginx, OpenSSH) rarely log the interaction, reducing detection.
2. TCP Connect Scan (`-sT`, Non-Root): When raw socket creation privileges (`CAP_NET_RAW`) are unavailable, Nmap falls back to invoking the standard POSIX `connect()` system call. The operating system kernel completes the full 3-way handshake. Slower, and heavily logged by target firewalls.
3. UDP Scan (`-sU`): UDP is connectionless. When Nmap sends an empty UDP packet to a closed port, the target host generates an ICMP Port Unreachable packet (Type 3, Code 3). If no ICMP response arrives after retransmissions, Nmap marks the port as `open|filtered`.
4. Service Version Fingerprinting (`-sV`): Nmap establishes a connection and interrogates listening ports using a database of protocol-specific probes (nmap-service-probes) and regular expression response signatures.
5. Nmap Scripting Engine (NSE, `--script`): Lua-based subsystem executing scripts in parallel against open ports to automate vulnerability validation (vuln), authentication auditing, and service enumeration.""",
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
        "exploit_code": """#!/usr/bin/env python3
import socket, time

TARGET = "10.10.10.20"
KNOCKS = [7000, 8000, 9000]

def knock():
    for port in KNOCKS:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.2)
            s.connect((TARGET, port))
            s.close()
        except:
            pass
        time.sleep(0.1)
    print("[+] Knock sequence transmitted!")

if __name__ == '__main__':
    knock()""",
        "flag": "CTF{KN0CK_KN0CK_WH05_TH3R3_F1R3W4LL}",
        "mitigation": "Do not rely on port-knocking as a sole security control (security through obscurity). Deploy authenticated VPNs with mutual TLS."
    }
}

chapters["networking-dns"] = {
    "id": "networking-dns",
    "domain": "networking",
    "category": "Network Architecture & Protocols",
    "title": "Domain Name System (DNS) Architecture, Zone Transfers & Tunneling",
    "subtitle": "Hierarchical Resolution, Resource Records (A, CNAME, TXT), AXFR Replication & Covert C2 Channels",
    "diagram": """+-----------------------------------------------------------------+
|                  DNS Resolution & Covert Tunneling              |
+-----------------------------------------------------------------+
Client Query: 'data.attacker.com'
  |
  +-> 1. Recursive Resolver (8.8.8.8)
        |
        +-> 2. Root Nameserver (.) -> .com TLD Nameserver
              |
              +-> 3. Authoritative Nameserver (attacker.com)
                    [ Controlled by Adversary! ]
                    - Inspects subdomain: 'data' = base32(secret)
                    - Returns TXT record containing C2 command!
                    - Bypasses corporate firewalls allowing outbound UDP 53!""",
    "theory": """The Domain Name System (DNS, RFC 1034 / 1035) provides distributed hierarchical hostname-to-IP address resolution. DNS primarily uses UDP port 53 for standard queries and TCP port 53 for queries exceeding 512 bytes (or EDNS0) and zone replication.

Resource Record (RR) Taxonomy:
- A & AAAA: IPv4 (32-bit) and IPv6 (128-bit) host addresses.
- CNAME (Canonical Name): Alias pointing to another domain name.
- MX (Mail Exchange): Routing destinations for SMTP mail.
- TXT (Text): Arbitrary string data (used for SPF, DKIM, site verification, and CTF flag storage).
- SOA (Start of Authority): Zone serial numbers, refresh timers, and admin email.
- NS (Name Server): Authoritative nameservers for a zone.

Critical CTF Attack & Exfiltration Classes:
1. DNS Zone Transfer (AXFR): Designed for primary and secondary nameservers to synchronize zone records over TCP. If an administrator leaves AXFR queries unauthenticated, any client can run `dig axfr @ns1.target target.com` to dump the entire internal DNS zone map, exposing hidden internal staging subdomains, development servers, and VPN endpoints.
2. DNS Tunneling & Exfiltration: Because almost all enterprise firewalls permit outbound UDP port 53 queries to resolve external domains, attackers abuse DNS as a covert channel. By encoding exfiltrated data into subdomain labels (`<base64-chunk>.attacker.com`), the queries travel through trusted recursive resolvers to the attacker's authoritative server.
3. DNS Rebinding: Attacker-controlled DNS server answers initial query with external IP, then immediately switches the A record to `127.0.0.1` with a TTL of 0 seconds. Bypasses browser Same-Origin Policy (SOP) to access internal localhost services.""",
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
        "exploit_code": """#!/usr/bin/env python3
import dns.zone, dns.query

def solve_axfr():
    z = dns.zone.from_xfr(dns.query.xfr('10.10.10.53', 'company.lab'))
    for name, node in z.nodes.items():
        for rdataset in node.rdatasets:
            print(f"{name} -> {rdataset}")

if __name__ == '__main__':
    solve_axfr()""",
        "flag": "CTF{DNS_AXFR_Z0N3_TR4NSF3R_DUMP}",
        "mitigation": "Restrict AXFR zone transfers to authorized secondary nameserver IP addresses only (e.g. `allow-transfer { 192.168.1.2; };` in BIND)."
    }
}
