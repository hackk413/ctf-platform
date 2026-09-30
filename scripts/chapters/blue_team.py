"""
CTF Atlas — Blue Team & Detection Engineering Chapters
"""

chapters = {}

chapters["blue-team-telemetry"] = {
    "id": "blue-team-telemetry",
    "domain": "blue-team",
    "category": "Detection Engineering & Incident Response",
    "title": "Kernel Telemetry, Detection Engineering (Sigma/YARA) & ATT&CK Mapping",
    "subtitle": "Auditd Kernel Syscall Hooking, Behavioral Signatures, Memory Pattern Matching & Forensic Incident Triage",
    "diagram": """+-----------------------------------------------------------------+
|                  Adversary Activity vs Telemetry Sensors        |
+-----------------------------------------------------------------+
Adversary Action (e.g. SUID Exec / Memory Injection)
       |
       +---> 1. Linux Kernel Audit Subsystem (Auditd)
       |        Hooks execve() system call (arch=b64, a0=/bin/sh)
       |        Emits event: type=SYSCALL euid=0 auid=1000
       |
       +---> 2. Endpoint Detection & Response (EDR / eBPF)
       |        Evaluates behavioral graph (Word -> cmd.exe -> certutil)
       |
       +---> 3. Sigma & YARA Detection Rules
       |        YARA matches byte sequences in memory: { 48 89 e5 31 c0 }
       |        Sigma rule matches log event: Image ends with 'powershell'
       |
       +---> 4. Security Information & Event Management (SIEM)
                Correlates alert with MITRE ATT&CK Tactic: T1548.001""",
    "theory": """Every offensive action produces an immutable telemetry artifact. In modern security operations, the objective of detection engineering is to translate low-level operating system and network observables into high-fidelity, resilient detection rules that detect adversarial behaviors regardless of tool modifications or payload obfuscation (following David Bianco's Pyramid of Pain).

Kernel Telemetry & Sensor Architecture:
1. Linux Audit Framework (`auditd`): Operates in kernel space via netlink sockets. System administrators configure rules (`/etc/audit/rules.d/audit.rules`) to monitor sensitive file accesses (`-w /etc/shadow -p wa -k shadow_tamper`) and privileged system calls (`-a always,exit -F arch=b64 -S execve -F euid=0 -k root_exec`).
2. YARA Rule Engine: The industry standard for pattern matching on binary files and process memory. YARA rules evaluate hexadecimal byte strings, ASCII/wide strings, regular expressions, and PE/ELF headers to identify malware families.
3. Sigma Rules: An open, vendor-agnostic signature format for SIEM log events. Sigma rules describe suspicious log patterns (Windows Event Logs, Linux Syslog, CloudTrail) in standard YAML, which compiles into Splunk, Elasticsearch, or QRadar queries.
4. MITRE ATT&CK Mapping: Categorizes adversary activity into Tactics (the adversary's technical goal, e.g. TA0006 Credential Access) and Techniques (the specific mechanism, e.g. T1003 OS Credential Dumping). Mapping findings to ATT&CK communicates risk and defensive posture across enterprise teams.""",
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
        "exploit_code": """# Sigma Rule: Detect GTFOBins SUID Find Execution
title: SUID Find Shell Execution
id: 4a2b9f12-2026-4c31-9a11-8f2a4e9b7d12
status: experimental
description: Detects execution of find with -exec spawning a privileged shell
logsource:
    category: process_creation
    product: linux
detection:
    selection:
        Image|endswith: '/find'
        CommandLine|contains:
            - '-exec'
            - 'sh'
    condition: selection
level: high
tags:
    - attack.privilege_escalation
    - attack.t1548.001""",
        "flag": "CTF{S1GM4_D3T3CT10N_ENG1N33R_2026}",
        "mitigation": "Enforce strict audit rules on all SUID executables, alert immediately when an unprivileged process executes an SUID binary that spawns a shell, and employ AppArmor/SELinux mandatory access controls."
    }
}
