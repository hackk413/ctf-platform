const state = {
  view: 'dashboard',
  domain: null,
  os: localStorage.getItem('atlas-os') || 'linux',
  solved: JSON.parse(localStorage.getItem('atlas-solved') || '[]'),
  completedDomains: JSON.parse(localStorage.getItem('atlas-domains') || '[]'),
  theme: localStorage.getItem('atlas-theme') || 'dark',
  moduleQuery: localStorage.getItem('atlas-module-query') || ''
};

let intelCache = null;
let intelLoading = false;


const domains = [
  {id:'foundations',icon:'01',name:'Foundations',level:'Start here',duration:'6–10 h',summary:'What CTFs are, threat modeling, flags, trust boundaries, internet basics, ethics, and a repeatable solve loop.',
   concepts:[
    ['CTF anatomy','Challenges are small, observable systems with an objective. A strong solver moves through hypothesis → experiment → evidence → validation instead of guessing.','Recognize category clues. Keep a scratchpad. Record commands, assumptions and output.'],
    ['CIA + security properties','Confidentiality, integrity and availability are useful lenses, but CTFs also test authenticity, authorization, isolation and provenance.','Map each clue to what property is being broken or proven.'],
    ['Trust boundaries','A browser, API, database, process, file parser and kernel are separate trust zones. Vulnerabilities often occur where data crosses between them.','Draw a 4-box data-flow diagram before touching a hard web or pwn problem.'],
    ['Evidence discipline','A finding is not “real” because a tool says so. Reproduce it, minimize it, explain why it happens and identify the security impact.','Capture input → transformation → output. Prefer small test cases.'],
    ['Legal sandboxing','Use local intentionally vulnerable apps, CTF infrastructure and systems you are explicitly authorized to test.','Keep practice targets on loopback/host-only networks when possible.']
   ],practice:['Do the browser challenge “Find the flag,” then write a 5-line solve note.','Complete OverTheWire Bandit Level 0–5.','Build a local folder: notes/, evidence/, scripts/, samples/.']},
  {id:'linux',icon:'02',name:'Linux + CLI',level:'Core',duration:'8–14 h',summary:'Shell fluency, processes, files, permissions, pipes, text processing, networking utilities and automation.',
   concepts:[
    ['Filesystem model','Paths, inodes, links, permissions, ownership, mount points and special files explain most beginner Linux CTF tasks.','Learn ls/stat/find/file/strings/xargs. Understand absolute vs relative paths.'],
    ['Pipelines','Small programs become a forensic toolkit when composed with pipes and redirection.','Think producer → filter → reducer. Examples: grep → cut → sort → uniq.'],
    ['Processes','PID, parent/child relationships, environment variables, file descriptors and signals explain how processes interact.','Inspect with ps, /proc, lsof, pgrep and command-line flags.'],
    ['Permissions','Read/write/execute differ for owner/group/other; special bits and ACLs add complexity.','Practice chmod/chown and reason from symbolic and numeric forms.'],
    ['Text as data','Logs and protocol transcripts are often solved by transforming text, not writing a large program.','Use awk/sed/grep, Python one-liners, jq and regex carefully.']
   ],practice:['Bandit or pwn.college Linux modules.','Recreate a log-triage pipeline from the playbook.','Solve browser labs on permissions and process reasoning.']},
  {id:'networking',icon:'03',name:'Networking',level:'Core',duration:'10–16 h',summary:'Ethernet, IP, TCP/UDP, DNS, HTTP, TLS, sockets, packet capture, scanning and service fingerprinting.',
   concepts:[
    ['Packets + layers','A packet is a structured byte sequence moving through protocols. CTFs often reward knowing which layer owns the clue.','Practice identifying MAC/IP/port/protocol from packet snippets.'],
    ['TCP state','SYN, SYN-ACK, ACK, sequence numbers, retransmission and connection lifecycle explain port scanning and capture artifacts.','Use Wireshark display filters and tcpdump on your own captures.'],
    ['DNS','Name resolution is a protocol and a data source. A record type can change the investigative path.','Learn A/AAAA/CNAME/MX/TXT/NS and dig.'],
    ['HTTP','Methods, paths, headers, cookies, content types, caching and status codes form the language of web CTFs.','Inspect requests manually with browser devtools or Burp.'],
    ['Scanning methodology','Discovery answers “what exists”; enumeration answers “what is there to interact with”; validation answers “is the finding real?”','Prefer targeted, rate-aware scans on authorized lab targets.']
   ],practice:['Run Nmap against 127.0.0.1 only and inspect localhost services.','Load a sample PCAP in Wireshark and reconstruct an HTTP exchange.','Use curl to compare headers across two local endpoints.']},
  {id:'web',icon:'04',name:'Web + APIs',level:'Core',duration:'16–24 h',summary:'Requests, sessions, authentication, access control, injections, client-side behavior, APIs and browser trust boundaries.',
   concepts:[
    ['Request anatomy','Method, target, headers, cookies, body, encoding and response metadata define the web transaction.','Learn to redraw any request in 6 fields.'],
    ['Authentication vs authorization','Authentication asks “who are you?” Authorization asks “may you do this?” Many real-world bugs live in the second question.','Create an identity/role matrix and test object-level access in a lab.'],
    ['Input handling','Injection occurs when data is interpreted as code or syntax in another language. Encodings can hide the true value from casual inspection.','Trace the data through parser boundaries before choosing a payload.'],
    ['Client-side security','DOM, browser APIs, storage, CORS and prototype behavior can shift the trust boundary into the browser.','Use devtools Sources/Network/Application panels.'],
    ['APIs','JSON, REST, GraphQL, JWTs and rate limits expose application logic in a machine-friendly form.','Map endpoints, inputs, auth requirements and object identifiers.']
   ],practice:['PortSwigger learning paths + labs.','Local OWASP Juice Shop with the tutorial mode.','Build an API request worksheet and fill it for a local training target.']},
  {id:'crypto',icon:'05',name:'Cryptography',level:'Core',duration:'12–20 h',summary:'Encodings, XOR, modular arithmetic, hashes, MACs, symmetric/asymmetric crypto and common CTF failure patterns.',
   concepts:[
    ['Encoding ≠ encryption','Base64, hex, URL encoding and ASCII are representations. They do not provide secrecy.','Try decoding before reaching for cryptanalysis.'],
    ['XOR','XOR is reversible and appears in stream ciphers and simple CTF puzzles. Multi-byte reasoning often depends on key repetition.','Practice truth tables, bytes, hex and XOR identities.'],
    ['Hashes','Cryptographic hashes map arbitrary input to a fixed digest. They are designed to resist specific attack classes—not to be reversible like encryption.','Recognize common digest formats, salts and why “hash = encryption” is wrong.'],
    ['Public-key crypto','RSA, ECC and key agreement rely on mathematical structure. CTFs often expose textbook or flawed parameters rather than breaking sound primitives.','Learn modular arithmetic, inverses and why parameter choices matter.'],
    ['Protocol failures','Most practical crypto weaknesses come from misuse: nonce reuse, weak randomness, missing authentication, poor key handling or unsafe composition.','Ask “what assumption failed?” before attempting brute force.']
   ],practice:['CryptoHack introductory/general challenges.','Implement Base64, Caesar, XOR and modular inverse in Python.','Write a one-page “crypto smell” checklist.']},
  {id:'forensics',icon:'06',name:'Forensics',level:'Core',duration:'10–18 h',summary:'Files, metadata, archives, logs, memory concepts, timelines, packet captures and evidence handling.',
   concepts:[
    ['File signatures','Extensions lie; magic bytes, headers and parsers reveal actual file types.','Use file, xxd/hexdump, strings and binwalk in local samples.'],
    ['Metadata','Timestamps, EXIF-like fields, document properties and filesystem metadata provide context but may be edited.','Treat metadata as a clue, not proof.'],
    ['Logs + timelines','Correlate timestamps across sources; account for timezone, clock skew and log rotation.','Normalize time to UTC in notes and preserve raw values.'],
    ['PCAP analysis','Capture files can answer who talked to whom, when, over which protocol, and what content crossed the wire.','Filter narrowly, then broaden; reconstruct the conversation.'],
    ['Memory concepts','Process state, mappings, handles and strings may survive in memory after they disappear from disk.','Learn conceptual memory layout before using a full memory framework.']
   ],practice:['Use the browser packet/log labs.','Open Wireshark’s User Guide alongside a sample capture.','Build a timeline from three synthetic log sources.']},
  {id:'reverse',icon:'07',name:'Reverse Engineering',level:'Advanced',duration:'16–28 h',summary:'Executable formats, control flow, disassembly, decompilation, strings, symbols, calling conventions and patch reasoning.',
   concepts:[
    ['ELF/PE basics','Executables contain headers, sections/segments, imports/exports, symbols and relocation data.','Learn the difference between what the file declares and what the loader creates.'],
    ['Assembly reading','Recognize function prologues, branches, calls, returns, comparisons, memory access and register conventions.','Track data flow instead of translating every instruction word-for-word.'],
    ['Static vs dynamic analysis','Static analysis asks what the program could do; dynamic analysis observes what it does with a chosen input/state.','Use static first, then instrument targeted functions.'],
    ['Control flow','Branches and call graphs reveal validation logic, parser boundaries and hidden states.','Mark the “gate” that decides success/failure.'],
    ['Ghidra workflow','Import → analyze → locate interesting functions/strings → rename → decompile → confirm with disassembly.','Keep hypotheses in comments and verify by tracing callers.']
   ],practice:['Open the Ghidra docs and a tiny local binary you wrote yourself.','Use Linux Insides + Beej C as prerequisites.','Solve the browser “reverse the logic” lab.']},
  {id:'pwn',icon:'08',name:'Binary Exploitation',level:'Advanced',duration:'18–32 h',summary:'Memory safety, stack frames, calling conventions, mitigations, debugging and exploit-development concepts—inside local CTF binaries.',
   concepts:[
    ['Memory model','Stack, heap, data, code and shared libraries occupy different regions with different purposes and protections.','Draw a process address-space map before writing exploit code.'],
    ['Memory corruption','Out-of-bounds reads/writes and lifetime bugs can change data or control flow.','Start from root cause and exact bytes in memory, not from a payload recipe.'],
    ['Mitigations','NX, ASLR, PIE, stack canaries, RELRO and CFI change what is feasible.','Learn what each mitigation protects and what assumptions remain.'],
    ['Debugging','A debugger turns “crash” into evidence: registers, stack, memory, call stack and instruction pointer.','Use breakpoints and watchpoints in local programs you own.'],
    ['pwntools mindset','Automate repetitive interaction and packing/parsing after you understand the target.','Use scripts as executable lab notes, not magic incantations.']
   ],practice:['pwn.college core material.','Write a tiny vulnerable C program locally and inspect it with a debugger.','Use pwntools docs for packing/unpacking and process interaction in local labs.']},
  {id:'osint',icon:'09',name:'OSINT + Research',level:'Core',duration:'8–14 h',summary:'Source validation, metadata, public data correlation, search operators, timelines and uncertainty management.',
   concepts:[
    ['Source quality','A source can be primary, secondary, anonymous, copied, stale or manipulated. Record provenance.','Prefer primary documents; corroborate important claims.'],
    ['Pivoting','Each artifact creates another search dimension: name, domain, username, timestamp, identifier, hash or location.','Pivot one variable at a time and record why it is useful.'],
    ['Geolocation','Buildings, shadows, road signs, terrain, metadata and map context can converge on a location.','Separate observation from inference.'],
    ['Timeline reasoning','Public artifacts often gain value when ordered in time.','Use exact timestamps where available and label uncertainty.'],
    ['OPSEC','OSINT research can leak your own identity and intent.','Use safe accounts, read-only access and respect site policies.']
   ],practice:['Solve a synthetic source-correlation case in the challenge set.','Make a provenance table with source, claim, date and confidence.']},
  {id:'stego',icon:'10',name:'Steganography',level:'Core',duration:'6–10 h',summary:'Hidden data in images, audio, text and file structure; distinguish stego from ordinary encoding.',
   concepts:[
    ['Container inspection','The first move is often file type, dimensions, metadata and trailing data.','Compare declared size vs actual size.'],
    ['Image planes','LSB-like techniques modify low-significance bits; visual inspection may not reveal changes.','Understand channels, bit depth and pixel ordering.'],
    ['Text stego','Whitespace, capitalization, Unicode confusables and formatting can encode data.','Normalize carefully, but preserve a raw copy.'],
    ['Audio stego','Spectral or sample-level patterns can encode hidden data.','Know that “listen to it” is only one view.'],
    ['Tool discipline','A stego tool is a hypothesis engine, not an oracle.','Check outputs against the original artifact and expected structure.']
   ],practice:['Use strings/binwalk/hexdump on local synthetic files.','Create your own whitespace-encoded message and decode it.']},
  {id:'mobile-cloud',icon:'11',name:'Mobile + Cloud + Containers',level:'Advanced',duration:'14–22 h',summary:'Android packages, app storage, tokens, cloud identity, container boundaries and modern deployment surfaces.',
   concepts:[
    ['Mobile package anatomy','APK/IPA packages contain manifests, resources, code and configuration.','Start with metadata, permissions and embedded endpoints.'],
    ['Cloud identity','Modern systems depend heavily on machine identities, roles and scoped permissions.','Map identities to resources and actions.'],
    ['Container model','Containers isolate processes, not the whole machine. Images, layers, capabilities, mounts and networks matter.','Learn image inspection and least-privilege concepts.'],
    ['Secrets in builds','Tokens and keys can leak into source, images, logs or client bundles.','Treat exposed secrets as sensitive even in labs.'],
    ['API-first systems','Mobile/cloud CTFs frequently reduce to API discovery + authorization + data-flow reasoning.','Reuse the web/API methodology instead of learning a separate universe.']
   ],practice:['Run a local containerized vulnerable web app.','Inspect a toy JSON API and identify authorization boundaries.']},
  {id:'blue-team',icon:'12',name:'Detection + Blue Team Context',level:'Cross-cutting',duration:'8–14 h',summary:'Turn CTF offensive clues into defender knowledge: telemetry, triage, detection engineering and ATT&CK mapping.',
   concepts:[
    ['Telemetry','Security events come from endpoints, identity systems, DNS, proxies, applications and network sensors.','Ask which sensor could prove or disprove a hypothesis.'],
    ['Triage','Triage is a prioritization problem: what happened, where, when, and what evidence is trustworthy?','Write a 6-line incident summary from synthetic logs.'],
    ['ATT&CK mapping','Tactics answer “why”; techniques answer “how”. Mapping helps communicate behavior without relying on vendor names.','Map a solved challenge to one or two ATT&CK techniques where appropriate.'],
    ['Detection logic','Good detections describe observable behavior and constrain false positives.','State data source, condition, context and response.'],
    ['Recovery thinking','A CTF flag is not the end of a real incident. Defenders care about containment, eradication, recovery and lessons learned.','Write the defender action after every offensive lab.']
   ],practice:['Map the incident-triage challenge to ATT&CK.','Use NIST CSF 2.0 as a high-level risk-management lens.']}
];

const tools = [
  {name:'Nmap',cat:'Network',why:'Discovery, port scanning and service enumeration. Start with localhost or a lab target.',linux:'nmap -sV 127.0.0.1',windows:'nmap -sV 127.0.0.1',mac:'nmap -sV 127.0.0.1',url:'https://nmap.org/book/'},
  {name:'Wireshark',cat:'Network / Forensics',why:'Interactive packet inspection, streams, filters and protocol dissection.',linux:'wireshark',windows:'wireshark',mac:'wireshark',url:'https://www.wireshark.org/docs/wsug_html/'},
  {name:'tcpdump',cat:'Network',why:'Lightweight packet capture and filtering from the command line.',linux:'tcpdump -i lo',windows:'Use Wireshark/Npcap capture',mac:'sudo tcpdump -i lo0',url:'https://www.tcpdump.org/'},
  {name:'curl',cat:'Web',why:'Make and inspect HTTP requests without hiding the protocol details.',linux:'curl -i http://127.0.0.1:3000/',windows:'curl.exe -i http://127.0.0.1:3000/',mac:'curl -i http://127.0.0.1:3000/',url:'https://curl.se/docs/'},
  {name:'Burp Suite',cat:'Web',why:'Proxy, inspect and replay application requests in authorized labs.',linux:'Launch Burp → Proxy → browser through 127.0.0.1',windows:'Launch Burp → Proxy → browser through 127.0.0.1',mac:'Launch Burp → Proxy → browser through 127.0.0.1',url:'https://portswigger.net/burp'},
  {name:'OWASP ZAP',cat:'Web',why:'Open-source web proxy/scanner for learning and authorized application assessment.',linux:'zap.sh',windows:'zaproxy.exe',mac:'open /Applications/OWASP\ ZAP.app',url:'https://www.zaproxy.org/'},
  {name:'Ghidra',cat:'Reverse',why:'Disassembly/decompilation and binary exploration across platforms.',linux:'./ghidraRun',windows:'ghidraRun.bat',mac:'./ghidraRun',url:'https://github.com/NationalSecurityAgency/ghidra'},
  {name:'gdb + extensions',cat:'Pwn / Reverse',why:'Debug local binaries, inspect registers/memory and validate hypotheses.',linux:'gdb ./binary',windows:'gdb ./binary (WSL/MSYS2)',mac:'lldb ./binary  # or gdb via package manager',url:'https://sourceware.org/gdb/'},
  {name:'pwntools',cat:'Pwn',why:'Python toolkit for packing, parsing and process interaction in CTFs.',linux:'python3 -m pip install --user pwntools',windows:'python -m pip install --user pwntools',mac:'python3 -m pip install --user pwntools',url:'https://docs.pwntools.com/'},
  {name:'CyberChef',cat:'General / Encoding',why:'Visual workbench for decoding, transformations and data inspection.',linux:'Open the web app / self-host the repo',windows:'Open the web app / self-host the repo',mac:'Open the web app / self-host the repo',url:'https://github.com/gchq/CyberChef'},
  {name:'file / xxd / strings',cat:'Forensics',why:'Fast first-look triage for unknown files, bytes and printable data.',linux:'file sample.bin && xxd sample.bin | head && strings sample.bin | head',windows:'Use PowerShell Format-Hex; strings.exe is available via Sysinternals/other toolsets',mac:'file sample.bin && xxd sample.bin | head && strings sample.bin | head',url:'https://man7.org/linux/man-pages/'},
  {name:'jq',cat:'Data / APIs',why:'Parse, filter and transform JSON cleanly.',linux:'jq ".items[] | .name" data.json',windows:'jq ".items[] | .name" data.json',mac:'jq ".items[] | .name" data.json',url:'https://jqlang.github.io/jq/'},
  {name:'dig / nslookup',cat:'DNS / Network',why:'Inspect DNS records, servers, TTLs and resolution behavior.',linux:'dig example.test A',windows:'nslookup -type=A example.test',mac:'dig example.test A',url:'https://bind9.readthedocs.io/'},
  {name:'git',cat:'Dev / Forensics',why:'History, branches and object metadata can expose how a project evolved.',linux:'git log --oneline --decorate --all',windows:'git log --oneline --decorate --all',mac:'git log --oneline --decorate --all',url:'https://git-scm.com/doc'},
  {name:'hashcat',cat:'Crypto / Passwords',why:'Offline password-audit and cracking tool for hashes you are authorized to test.',linux:'hashcat --example-hashes',windows:'hashcat.exe --example-hashes',mac:'hashcat --example-hashes',url:'https://hashcat.net/hashcat/'},
  {name:'OpenSSL CLI',cat:'Crypto / PKI',why:'Inspect certificates and test cryptographic primitives and encodings locally.',linux:'openssl x509 -in cert.pem -text -noout',windows:'openssl x509 -in cert.pem -text -noout',mac:'openssl x509 -in cert.pem -text -noout',url:'https://docs.openssl.org/'},
  {name:'Python',cat:'Automation',why:'Glue language for parsing, encoding, protocol reasoning and repeatable solves.',linux:'python3',windows:'py',mac:'python3',url:'https://docs.python.org/3/'},
  {name:'YARA',cat:'Forensics / Detection',why:'Pattern-matching rules for identifying files and behaviors in controlled samples.',linux:'yara rule.yar sample.bin',windows:'yara64.exe rule.yar sample.bin',mac:'yara rule.yar sample.bin',url:'https://yara.readthedocs.io/'},
  {name:'Binwalk',cat:'Forensics',why:'Identify and extract embedded content from firmware-like or compound files.',linux:'binwalk sample.bin',windows:'Use container/WSL or Python packaging',mac:'binwalk sample.bin',url:'https://github.com/ReFirmLabs/binwalk'},
  {name:'FFmpeg',cat:'Media / Forensics',why:'Inspect and transform audio/video containers while preserving evidence copies.',linux:'ffprobe sample.mp4',windows:'ffprobe.exe sample.mp4',mac:'ffprobe sample.mp4',url:'https://ffmpeg.org/ffprobe.html'},
  {name:'SQLite CLI',cat:'Forensics / Web',why:'Inspect embedded application databases and challenge artifacts.',linux:'sqlite3 app.db',windows:'sqlite3.exe app.db',mac:'sqlite3 app.db',url:'https://sqlite.org/cli.html'},
  {name:'ripgrep',cat:'General',why:'Fast recursive text search across source trees, extracted files and notes.',linux:'rg -n "flag|token|password" .',windows:'rg -n "flag|token|password" .',mac:'rg -n "flag|token|password" .',url:'https://github.com/BurntSushi/ripgrep'}
];

const challenges = [
  {id:'b64',name:'Decode the postcard',cat:'Encoding',diff:'Warm-up',points:50,prompt:'Decode this Base64 string: ZmxhZ3tGSVJTVF9TVEVQfQ==',hint:['This is representation, not encryption.','Base64 decoders are built into most languages.'],answer:'flag{FIRST_STEP}',why:'Build the habit of testing simple encodings before trying exotic techniques.'},
  {id:'hex',name:'Hex trail',cat:'Encoding',diff:'Warm-up',points:50,prompt:'Hex bytes: 66 6c 61 67 7b 48 45 58 5f 49 54 7d',hint:['Group into bytes and map to ASCII.','Python: bytes.fromhex(...).decode()'],answer:'flag{HEX_IT}',why:'Byte representations are foundational to forensics and crypto.'},
  {id:'caesar',name:'Shifted note',cat:'Crypto',diff:'Easy',points:75,prompt:'Caesar-shifted note (shift +3): Iodj{FDHVDU_3}',hint:['To decrypt, move letters backwards.','Keep punctuation and digits unchanged.'],answer:'flag{CAESAR_3}',why:'Cipher recognition comes before brute-force tooling.'},
  {id:'xor',name:'One-byte XOR',cat:'Crypto',diff:'Easy',points:100,prompt:'Cipher bytes (hex): 0f 05 08 0e 12 31 26 3b 36 22 2c 30 14. Key = 0x69. Decode to text.',hint:['XOR each byte with the same key.','The XOR operation is reversible: x ^ k ^ k = x.'],answer:'flag{XOR_KEY}',why:'CTF crypto often expects you to reason at the byte level.'},
  {id:'url',name:'Encoded endpoint',cat:'Web',diff:'Easy',points:75,prompt:'Decode: /api%2Fv1%2Fusers%3Frole%3Dadmin',hint:['Percent-encoding represents bytes/characters in URLs.','Decode only the URL-encoded layer first.'],answer:'/api/v1/users?role=admin',why:'Seeing the real request path is essential in API testing.'},
  {id:'jwt',name:'JWT payload',cat:'Web / API',diff:'Easy',points:100,prompt:'Decode the payload segment of eyJhbGciOiJub25lIn0.eyJ1c2VyIjoiYWxpY2UiLCJyb2xlIjoidXNlciJ9.',hint:['JWT has dot-separated segments; the middle is Base64URL JSON.','Do not treat a decoded token as proof that a token is trustworthy.'],answer:'{"user":"alice","role":"user"}',why:'Separating token encoding from token validation prevents common reasoning mistakes.'},
  {id:'log',name:'Find the suspicious line',cat:'Forensics',diff:'Easy',points:100,prompt:'Which event is most suspicious?\n10:12:03 GET /health 200\n10:12:04 GET /static/app.js 200\n10:12:06 POST /login 401\n10:12:08 GET /../../etc/passwd 400\n10:12:10 GET /dashboard 200',hint:['Look for an input that attempts path traversal.','A 400 can still be meaningful evidence of probing.'],answer:'10:12:08 GET /../../etc/passwd 400',why:'Detection is about behavior and context, not only successful exploitation.'},
  {id:'subnet',name:'Network boundary',cat:'Networking',diff:'Medium',points:100,prompt:'Host 10.10.14.23/24: what is the network address?',hint:['/24 means 24 network bits.','The final octet becomes 0 for the network address.'],answer:'10.10.14.0',why:'Subnet reasoning supports scanning, routing and incident triage.'},
  {id:'http',name:'HTTP status reasoning',cat:'Web',diff:'Medium',points:100,prompt:'A server returns 401 to /api/me before login and 403 to /api/admin after login as a normal user. What is the best interpretation?',hint:['401 generally indicates missing/invalid authentication.','403 generally indicates the server understood the request but refuses it.'],answer:'401 means unauthenticated; 403 means authenticated but not authorized',why:'Precise terminology helps you test the right trust boundary.'},
  {id:'elf',name:'ELF clue',cat:'Reverse',diff:'Medium',points:125,prompt:'A binary has a section named .text and another named .rodata. Which is the best mental model?',hint:['Executable code is usually in .text.','Read-only constants/strings are commonly in .rodata.'],answer:'Code in .text; read-only constants/data in .rodata',why:'Executable layout gives you a map before disassembly.'},
  {id:'endianness',name:'Byte order',cat:'Reverse',diff:'Medium',points:100,prompt:'Interpret bytes 78 56 34 12 as a 32-bit little-endian integer.',hint:['Little-endian stores the least significant byte first.','Reverse the byte order for the human-readable hex value.'],answer:'0x12345678',why:'Endianness appears constantly in binary parsing and exploit development.'},
  {id:'regex',name:'Extract the ticket',cat:'Automation',diff:'Medium',points:125,prompt:'From "INFO ticket=ABC-2417 user=demo" extract only the ticket value.',hint:['Pattern: ticket=([A-Z]+-[0-9]+).','Use a capture group.'],answer:'ABC-2417',why:'Regex is a force multiplier for repeatable evidence extraction.'},
  {id:'perm',name:'Permission math',cat:'Linux',diff:'Medium',points:100,prompt:'What permissions does 640 grant on a file?',hint:['6 = rw-, 4 = r--, 0 = ---.','Order is owner, group, other.'],answer:'owner rw-, group r--, other ---',why:'Permissions are easier once you translate the octal digits consistently.'},
  {id:'assembly',name:'Branch meaning',cat:'Reverse',diff:'Medium',points:125,prompt:'Pseudo-assembly: cmp eax, 42; jne fail; call success. What must be true to reach success?',hint:['jne means jump if not equal.','So the call occurs when the comparison finds equality.'],answer:'eax == 42',why:'Reverse engineering starts with control-flow truth tables, not decompiler magic.'},
  {id:'stego',name:'Container clue',cat:'Stego / Forensics',diff:'Medium',points:100,prompt:'A PNG is 120 KB on disk, has valid PNG headers, and contains a large ZIP archive appended after the IEND chunk. What should you test first?',hint:['Do not assume the PNG itself is corrupted.','Treat the trailing bytes as a second artifact and inspect/extract them.'],answer:'Inspect/extract the trailing ZIP data',why:'Compound-file thinking solves many “mystery image” challenges.'},
  {id:'osint',name:'Provenance first',cat:'OSINT',diff:'Hard',points:150,prompt:'A screenshot claims a software project released version 9.2 on March 3, but the project’s signed release page says version 9.1 on March 5. What should you do before concluding the screenshot is false?',hint:['Corroborate with another primary source, such as tags, release notes or repository history.','Check timezone/date conventions and whether the screenshot refers to a fork or pre-release.'],answer:'Corroborate with primary release artifacts and check context',why:'Strong OSINT separates observation, verification and inference.'},
  {id:'incident',name:'Map the behavior',cat:'Blue Team',diff:'Hard',points:150,prompt:'A lab endpoint shows repeated credential guessing followed by successful remote login and local process discovery. Which sequence best describes the behavior?',hint:['Think in behaviors rather than malware names.','ATT&CK tactics can form a sequence.'],answer:'Credential Access → Initial Access/Valid Accounts → Discovery',why:'CTF clues become more transferable when translated into defender language.'},
  {id:'method',name:'Choose the next move',cat:'Methodology',diff:'Hard',points:175,prompt:'You have a web app with an authenticated user and a numeric object ID in the URL. Which is the strongest next hypothesis to test in a local lab?',hint:['Authorization bugs often occur when object references are trusted without checking ownership.','Build two accounts and compare access to each other’s objects.'],answer:'Test object-level authorization with two users',why:'Good CTF solving is hypothesis-driven and testable.'}
];

const casebook = [
  {title:'Heartbleed (CVE-2014-0160)',domain:'Crypto / Protocols',lesson:'A memory-safety bug in a TLS implementation became a global security problem because a security-critical parser crossed a memory boundary without sufficient validation.',study:['bounds checking','memory disclosure','patching and validation','why crypto primitives can still fail in implementation'],source:'https://nvd.nist.gov/vuln/detail/CVE-2014-0160'},
  {title:'Shellshock (CVE-2014-6271)',domain:'Linux / Command Injection',lesson:'Bash function parsing in environment variables created command-execution paths across trust boundaries in multiple configurations.',study:['environment variables','parser boundaries','command injection concepts','defensive patching and exposure mapping'],source:'https://nvd.nist.gov/vuln/detail/CVE-2014-6271'},
  {title:'Log4Shell (CVE-2021-44228)',domain:'Web / Java / Supply Chain',lesson:'A logging feature accepted attacker-controlled data that could trigger unexpected lookups, showing how “non-security” components can become attack surfaces.',study:['data-to-code boundaries','dependency inventory','egress controls','defense-in-depth'],source:'https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-339a'},
  {title:'MOVEit Transfer (CVE-2023-34362)',domain:'Web / SQL Injection',lesson:'A SQL injection issue in a widely deployed file-transfer product was actively exploited; the case demonstrates why input validation, rapid patching and monitoring matter together.',study:['SQL injection root cause','web input validation','asset exposure','threat detection and patch management'],source:'https://www.cisa.gov/known-exploited-vulnerabilities-catalog'},
  {title:'What the cases have in common',domain:'Cross-cutting',lesson:'Different technologies fail for recurring reasons: untrusted input crossing an interpreter boundary, insufficient validation, excessive trust, weak visibility, or delayed patching.',study:['trust boundaries','secure defaults','telemetry','defense in depth'],source:'https://attack.mitre.org/'}
];

const glossary = [
 ['ACL','Access Control List: explicit permissions attached to a resource beyond basic owner/group/other bits.'],
 ['ASLR','Address Space Layout Randomization: randomizes locations of memory regions to complicate reliable memory-corruption attacks.'],
 ['API','Application Programming Interface: a defined interface through which software components communicate.'],
 ['ASR','Attack Surface Reduction: limiting exposed functionality and execution paths to reduce opportunities for abuse.'],
 ['C2','Command and Control: communication used to remotely direct a compromised system; useful as a defensive concept.'],
 ['CTF','Capture The Flag: a competition or practice format where solvers find hidden tokens by applying security skills.'],
 ['ELF','Executable and Linkable Format: a common Unix-like binary object format.'],
 ['Entropy','A measure of unpredictability or information density; useful for identifying compressed/encrypted-looking data.'],
 ['Fuzzing','Systematically supplying varied or unexpected inputs to find crashes, parsing errors or logic flaws.'],
 ['JWT','JSON Web Token: a compact token format; its encoding is not itself proof of trust.'],
 ['LSB','Least Significant Bit: lowest-order bit; often discussed in steganography and binary operations.'],
 ['MITM','Man-in-the-Middle: a position where a party can observe or influence communication between endpoints.'],
 ['NAT','Network Address Translation: maps address/port information between network domains.'],
 ['PCAP','Packet Capture: a file containing captured network traffic.'],
 ['PIE','Position-Independent Executable: executable layout supporting randomized placement under ASLR.'],
 ['ROP','Return-Oriented Programming: composing existing instruction sequences to influence execution after memory corruption.'],
 ['SAST','Static Application Security Testing: analyzing code without running the application.'],
 ['TLS','Transport Layer Security: cryptographic protocol used to protect data in transit.'],
 ['TTL','Time To Live: a bounded lifetime field, used in several protocol/data contexts.'],
 ['WAF','Web Application Firewall: filters or blocks web traffic based on policies and observed request characteristics.']
];

function esc(s){return String(s).replace(/[&<>'"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[c]));}
function save(){localStorage.setItem('atlas-solved',JSON.stringify(state.solved));localStorage.setItem('atlas-domains',JSON.stringify(state.completedDomains));localStorage.setItem('atlas-os',state.os);localStorage.setItem('atlas-theme',state.theme);localStorage.setItem('atlas-module-query',state.moduleQuery)}
function completion(){return Math.round((state.solved.length/challenges.length)*100)}
function setTheme(){document.documentElement.classList.toggle('light',state.theme==='light');document.getElementById('themeToggle').textContent=state.theme==='light'?'AM':'NEON'}
function setView(view){state.view=view;state.domain=null;document.querySelectorAll('.nav-item').forEach(b=>b.classList.toggle('active',b.dataset.view===view));document.getElementById('breadcrumbs').textContent={dashboard:'Dashboard',path:'Learning path',modules:'Learning modules',domains:'Learning paths',tools:'Tool lab',labs:'Micro-labs',playbook:'Methodology',casebook:'Casebook',library:'Reference vault',glossary:'Glossary'}[view]||'CTF Atlas';render();window.scrollTo({top:0,behavior:'smooth'});}
function openDomain(id){state.view='domains';state.domain=id;document.querySelectorAll('.nav-item').forEach(b=>b.classList.toggle('active',b.dataset.view==='domains'));document.getElementById('breadcrumbs').textContent='Domains / '+domains.find(d=>d.id===id).name;render();window.scrollTo({top:0,behavior:'smooth'});}
function markDomain(id){if(!state.completedDomains.includes(id)) state.completedDomains.push(id);save();render()}

function render(){
  const view=document.getElementById('view');
  if(state.view==='dashboard') view.innerHTML=dashboardHTML();
  if(state.view==='path') view.innerHTML=pathHTML();
  if(state.view==='modules') view.innerHTML=modulesHTML(state.moduleQuery);
  if(state.view==='domains') view.innerHTML=state.domain?domainDetailHTML(state.domain):domainsHTML();
  if(state.view==='tools') view.innerHTML=toolsHTML();
  if(state.view==='labs') view.innerHTML=labsHTML();
  if(state.view==='playbook') view.innerHTML=playbookHTML();
  if(state.view==='casebook') view.innerHTML=casebookHTML();
  if(state.view==='library') view.innerHTML=libraryHTML();
  if(state.view==='glossary') view.innerHTML=glossaryHTML('');
  if(state.view==='intel') view.innerHTML=intelHTML(intelCache);
  bindViewEvents();
  if(state.view==='intel' && !intelCache) loadIntel();
  document.getElementById('sidebarProgress').textContent=completion()+'%';
  document.getElementById('sidebarProgressBar').style.width=completion()+'%';
  setTheme();
}

function dashboardHTML(){
  const solved=state.solved.length, total=challenges.length;
  return `<div class="hero">
    <div class="hero-main">
      <div class="eyebrow">CTF Atlas / self-paced cyber range</div>
      <h1>Understand the system. Operate the tools. Prove the idea.</h1>
      <p>A pin-to-pin CTF curriculum that fills the gaps between tutorials: foundations, Linux, networking, web, crypto, forensics, reverse engineering, pwn, OSINT, stego, modern app surfaces, and defender context — with safe hands-on practice at every stage.</p>
      <div class="tag-row"><span class="tag accent">offline-friendly</span><span class="tag accent">OS-independent</span><span class="tag success">localStorage progress</span><span class="tag">browser micro-labs</span></div>
      <div class="hero-actions"><button class="btn primary" data-action="goto-path">Start the path</button><button class="btn" data-action="goto-labs">Open micro-labs</button><button class="btn" data-action="goto-domains">Browse domains</button></div>
    </div>
    <div class="hero-side">
      <div><div class="metric-label">Browser lab completion</div><div class="big-number">${solved}/${total}</div><div class="muted">micro-challenges solved</div></div>
      <div><div class="meter"><div style="width:${completion()}%"></div></div><div class="mini-stat"><span>Overall practice</span><strong>${completion()}%</strong></div></div>
    </div>
  </div>
  <div class="section-head"><div><h2>What’s inside</h2><p>Designed to prevent the “I know the commands but not the reasoning” problem.</p></div></div>
  <div class="grid cols-4">
    <div class="card"><div class="metric">12</div><div class="metric-label">learning domains</div><p style="margin-top:8px">Each has theory, workflows, practice and source material.</p></div>
    <div class="card"><div class="metric">22</div><div class="metric-label">tool cards</div><p style="margin-top:8px">Windows / Linux / macOS command examples where practical.</p></div>
    <div class="card"><div class="metric">18</div><div class="metric-label">micro-labs</div><p style="margin-top:8px">Local browser drills with instant feedback and saved progress.</p></div>
    <div class="card"><div class="metric">18+</div><div class="metric-label">reference panels</div><p style="margin-top:8px">In-site notes, formulas, workflows and local-practice recipes.</p></div>
  </div>
  <div class="section-head"><div><h2>Recommended route</h2><p>Follow the sequence, but jump directly to a domain whenever you need it.</p></div></div>
  <div class="grid cols-3">
    ${domains.slice(0,6).map((d,i)=>`<button class="card domain-card" data-domain="${d.id}" style="text-align:left"><div class="domain-icon">${d.icon}</div><div class="card-top"><div><h3>${d.name}</h3><p>${d.summary}</p></div><div class="arrow">→</div></div><div class="tag-row" style="margin-top:10px"><span class="tag">${d.level}</span><span class="tag">${d.duration}</span>${state.completedDomains.includes(d.id)?'<span class="tag success">complete</span>':''}</div></button>`).join('')}
  </div>
  <div class="section-head"><div><h2>Safe local practice ladder</h2><p>Start in-browser, then point tools at localhost or offline samples you control.</p></div></div>
  <div class="grid cols-3">
    <div class="card"><h3>Level 1 · Browser only</h3><p>Use the built-in micro-labs to learn encodings, byte reasoning, HTTP semantics, logs and binary concepts.</p></div>
    <div class="card"><h3>Level 2 · Local tools</h3><p>Install Nmap, Wireshark, Ghidra, Python and friends. Point them at localhost or samples you control.</p></div>
    <div class="card"><h3>Level 3 · Deliberately vulnerable apps</h3><p>Run Juice Shop or WebGoat locally and work through guided web scenarios.</p></div>
  </div>`;
}

function pathHTML(){
  return `<div class="section-head"><div><h2>The Atlas learning path</h2><p>Build fundamentals first; then specialize. Each stage is tied to a practical feedback loop.</p></div><div class="tag-row"><span class="tag accent">progress saved locally</span><span class="tag success">session protected</span></div></div>
  <div class="grid cols-2">
    <div class="detail"><div class="detail-head"><h3 style="margin:0 0 4px">Core spine</h3><p style="margin:0;color:var(--muted);font-size:12px">The shortest path from zero to competent CTF problem solving.</p></div><div class="detail-body">${domains.map((d,i)=>`<div class="path-node" style="padding-bottom:18px"><div class="path-row"><div class="step-badge">${String(i+1).padStart(2,'0')}</div><div class="path-content"><div class="card-top"><div><h3>${d.name}</h3><p>${d.summary}</p></div><button class="icon-btn" data-domain="${d.id}" title="Open domain">→</button></div><div class="bar-small"><span style="width:${state.completedDomains.includes(d.id)?100:0}%"></span></div><div class="tag-row" style="margin-top:8px"><span class="tag">${d.level}</span><span class="tag">${d.duration}</span>${state.completedDomains.includes(d.id)?'<span class="tag success">done</span>':''}</div></div></div></div>`).join('')}</div></div>
    <div class="detail"><div class="detail-head"><h3 style="margin:0 0 4px">How to study a topic</h3><p style="margin:0;color:var(--muted);font-size:12px">Use the same six-step loop for every category.</p></div><div class="detail-body"><div class="grid">${[['1','Define','Write the problem in plain language. What must be true for the flag to appear?'],['2','Model','Draw the data flow, protocol, memory region or trust boundary.'],['3','Observe','Collect the smallest useful evidence with a tool.'],['4','Hypothesize','Choose one explanation and predict what you should see.'],['5','Test','Change one variable. Prefer local, reversible experiments.'],['6','Explain','Write the root cause, proof, impact and defensive lesson.']].map(x=>`<div class="card"><div class="card-top"><span class="tag accent">${x[0]}</span><h3 style="margin:0;flex:1">${x[1]}</h3></div><p style="margin-top:8px">${x[2]}</p></div>`).join('')}</div><div class="note warn-note"><strong>When stuck:</strong> reduce scope. Verify file type. Inspect inputs/outputs. Read the help text. Make a tiny reproducer. Search the exact protocol term, not the whole mystery.</div></div></div>
  </div>`;
}

function modulesHTML(query){
  const q=normalizeAnswer(query||'');
  const rows=[];
  domains.forEach(d=>d.concepts.forEach((c,i)=>rows.push({d,index:i+1,title:c[0],theory:c[1],practice:c[2],domain:d})));
  const hits=rows.filter(r=>!q||normalizeAnswer(r.title+' '+r.theory+' '+r.practice+' '+r.domain.name).includes(q));
  return `<div class="section-head"><div><div class="eyebrow">KNOWLEDGE MATRIX / ${rows.length} MODULES</div><h2>Learning modules</h2><p>Every concept is readable here before you touch a tool. Open the domain when you want the full workflow and practice ladder.</p></div><div class="tag-row"><span class="tag accent">in-site curriculum</span><span class="tag">searchable</span></div></div>
  <div class="module-search"><span>&gt;</span><input id="moduleSearch" value="${esc(query||'')}" placeholder="search a concept, protocol, technique, or domain" autocomplete="off"><span class="cursor">█</span></div>
  <div class="module-count"><span>${hits.length}</span> modules visible</div>
  <div class="module-grid" id="modulesGrid">${hits.map(r=>`<article class="card module-card"><div class="module-top"><span class="tag accent">${r.domain.icon} / ${r.domain.name}</span><span class="tag">M${String(r.index).padStart(2,'0')}</span></div><h3>${esc(r.title)}</h3><p>${esc(r.theory)}</p><div class="module-action"><span class="tag">practice</span><span>${esc(r.practice)}</span></div><button class="btn outline" data-domain="${r.domain.id}">open full path →</button></article>`).join('') || '<div class="empty">No modules matched. Try “HTTP”, “ELF”, “XOR”, “permissions”, or “DNS”.</div>'}</div>
  <div class="note"><strong>Study contract:</strong> Read the concept, reproduce the observation in a safe lab, then explain it without looking at the text.</div>`;
}

function domainsHTML(){
  return `<div class="section-head"><div><h2>Domains</h2><p>Every domain follows the same pattern: concept map → workflow → tools → practice → real-world transfer.</p></div></div><div class="grid cols-3">${domains.map(d=>`<button class="card domain-card" data-domain="${d.id}" style="text-align:left"><div class="domain-icon">${d.icon}</div><div class="card-top"><div><h3>${d.name}</h3><p>${d.summary}</p></div><div class="arrow">→</div></div><div class="tag-row" style="margin-top:10px"><span class="tag">${d.level}</span><span class="tag">${d.duration}</span>${state.completedDomains.includes(d.id)?'<span class="tag success">complete</span>':''}</div></button>`).join('')}</div>`;
}

function domainDetailHTML(id){
  const d=domains.find(x=>x.id===id);
  return `<div class="section-head"><div><div class="tag-row"><span class="tag accent">${d.level}</span><span class="tag">${d.duration}</span></div><h2 style="margin-top:8px">${d.name}</h2><p>${d.summary}</p></div><button class="btn primary" data-action="complete-domain" data-domain-id="${d.id}">${state.completedDomains.includes(d.id)?'Completed ✓':'Mark domain complete'}</button></div>
  <div class="detail"><div class="detail-head"><h3 style="margin:0">Concept map</h3><p style="margin:3px 0 0;color:var(--muted);font-size:12px">Read these in order before memorizing commands.</p></div><div class="detail-body"><div class="concept-grid">${d.concepts.map((c,i)=>`<article class="concept"><div class="card-top"><h4>${i+1}. ${c[0]}</h4><span class="tag">theory</span></div><p>${c[1]}</p><ul><li>${c[2]}</li></ul></article>`).join('')}</div><div class="section-head" style="margin-top:20px"><div><h2>Practice plan</h2><p>Concrete exercises that turn the ideas into muscle memory.</p></div></div><div class="grid cols-3">${d.practice.map((p,i)=>`<div class="card"><div class="tag accent">Exercise ${i+1}</div><p style="margin-top:9px;color:var(--text)">${p}</p></div>`).join('')}</div><div class="note"><strong>Transfer rule:</strong> After solving a CTF task, write the defender view: what evidence would reveal the behavior? what control would reduce the risk? what assumption failed?</div></div></div>`;
}

function toolsHTML(){
  return `<div class="section-head"><div><h2>Tool lab</h2><p>Tools are grouped by the question they answer. Switch OS to see platform-aware examples.</p></div><div class="os-tabs">${['linux','windows','mac'].map(o=>`<button class="os-btn ${state.os===o?'active':''}" data-os="${o}">${o==='mac'?'macOS':o[0].toUpperCase()+o.slice(1)}</button>`).join('')}</div></div>
  <div class="tool-grid">${tools.map(t=>`<article class="tool-card"><div class="card-top"><div><h3>${t.name}</h3><div class="tool-meta"><span class="tag accent">${t.cat}</span><span class="tag">local notes</span></div></div><span class="tool-os">${state.os.toUpperCase()}</span></div><div class="why">${t.why}</div><pre>${esc(t[state.os])}</pre><div class="tool-meta"><span class="tag">use on authorized targets</span><span class="tag">read the in-site notes</span></div></article>`).join('')}</div>`;
}

function labsHTML(){
  return `<div class="section-head"><div><h2>Micro-labs</h2><p>Small, deterministic exercises. Submit your answer locally; progress is stored in your browser.</p></div><div class="tag-row"><span class="tag accent">${state.solved.length}/${challenges.length} solved</span><span class="tag">${challenges.reduce((a,c)=>a+c.points,0)} total points</span></div></div><div class="challenge-list">${challenges.map(c=>challengeHTML(c)).join('')}</div>`;
}

function challengeHTML(c){
  const solved=state.solved.includes(c.id);
  return `<article class="challenge-card ${solved?'solved':''}"><div class="card-top"><div><h3>${c.name}</h3><div class="challenge-meta"><span class="tag accent">${c.cat}</span><span class="tag">${c.diff}</span><span class="tag">${c.points} pts</span></div></div><span class="tag ${solved?'success':''}">${solved?'solved':'unsolved'}</span></div><div class="challenge-prompt"><strong>Prompt</strong><pre style="background:var(--panel-2);border:1px solid var(--line);border-radius:10px;padding:10px;white-space:pre-wrap;overflow:auto;font-size:11px;color:var(--text)">${esc(c.prompt)}</pre></div><input class="challenge-input" data-challenge-input="${c.id}" placeholder="Type your answer" ${solved?'disabled':''}><div class="challenge-actions"><button class="btn primary" data-check="${c.id}" ${solved?'disabled':''}>Check</button><button class="btn" data-hint="${c.id}">Hint</button><button class="btn" data-explain="${c.id}">Why this matters</button></div><div class="hint" id="hint-${c.id}"></div><div class="result" id="result-${c.id}"></div></article>`;
}

function normalizeAnswer(s){return String(s).trim().replace(/\s+/g,' ').toLowerCase()}
function checkAnswer(id){
  const c=challenges.find(x=>x.id===id); const input=document.querySelector(`[data-challenge-input="${id}"]`); const result=document.getElementById(`result-${id}`); if(!c||!input)return;
  if(normalizeAnswer(input.value)===normalizeAnswer(c.answer)){ if(!state.solved.includes(id))state.solved.push(id); save(); result.className='result ok'; result.textContent='Correct. Evidence verified locally; concept unlocked.'; render(); }
  else { result.className='result bad'; result.textContent='Not yet. Re-check the representation, data flow, or exact wording.'; }
}

function casebookHTML(){
  return `<div class="section-head"><div><h2>Casebook</h2><p>Documented incidents become in-site learning anchors. Focus on root cause, evidence and defense—not exploit recipes.</p></div><span class="tag warn">high-level / in-site</span></div><div class="grid cols-2">${casebook.map((c,i)=>`<article class="card"><div class="card-top"><div><span class="tag accent">${c.domain}</span><h3 style="margin-top:8px">${c.title}</h3></div><span class="tag">case ${i+1}</span></div><p style="margin-top:8px">${c.lesson}</p><div class="tag-row" style="margin-top:10px">${c.study.map(x=>`<span class="tag">study: ${x}</span>`).join('')}</div><div class="note" style="margin-top:12px"><strong>Study focus:</strong> identify the trust boundary, attacker-controlled input, vulnerable component, observable evidence and defensive control.</div></article>`).join('')}</div><div class="note warn-note"><strong>Transfer exercise:</strong> Write a five-line root-cause summary without using an exploit payload. The goal is to explain why the system behaved unsafely.</div>`;
}

function playbookHTML(){
  const workflow=[['1','Scope','Confirm authorization and define the exact lab/target. Record IP/URL, credentials, files and expected objective.'],['2','Surface map','Identify protocols, inputs, files, endpoints, processes, parsers and trust boundaries.'],['3','Enumerate','Use low-noise, targeted methods. Prefer understanding over blind scanning.'],['4','Validate','Reproduce the clue with the smallest possible test and record exact evidence.'],['5','Exploit or prove','In CTFs this means obtaining the flag. In assessment work it means proving impact without unnecessary damage.'],['6','Explain','Write root cause, security property affected, evidence, impact and defensive fix.']];
  return `<div class="section-head"><div><h2>Methodology</h2><p>A repeatable solve process matters more than memorizing a thousand commands.</p></div></div><div class="playbook">${workflow.map(x=>`<article class="play-card"><div class="tag accent">STEP ${x[0]}</div><h3 style="margin-top:8px">${x[1]}</h3><p style="color:var(--muted);font-size:12px">${x[2]}</p></article>`).join('')}<article class="play-card"><div class="tag success">ANTI-GUESSING CHECKLIST</div><h3 style="margin-top:8px">When a challenge feels impossible</h3><ol><li>Verify the file type / protocol / language.</li><li>Find one simple observable fact.</li><li>List 3 hypotheses and one test per hypothesis.</li><li>Reduce the input.</li><li>Search the exact technical term from the evidence.</li><li>Write down what you now know before continuing.</li></ol></article><article class="play-card"><div class="tag warn">REPORTING TEMPLATE</div><h3 style="margin-top:8px">Turn a solve into reusable knowledge</h3><pre style="background:var(--panel-2);padding:12px;border-radius:10px;white-space:pre-wrap;font-size:11px">Target:
Objective:
Observed:
Hypothesis:
Test:
Result:
Root cause:
Impact:
Defender view:
Tools / references:</pre></article></div>`;
}

function libraryHTML(){
  const conceptBlocks=domains.map(d=>`<article class="card ref-block"><div class="card-top"><div><span class="tag accent">${d.icon} / ${d.name}</span><h3 style="margin-top:8px">${d.name} reference</h3></div><span class="tag">${d.concepts.length} modules</span></div><div class="ref-list">${d.concepts.map((c,i)=>`<div class="ref-item"><div><strong>${i+1}. ${esc(c[0])}</strong><p>${esc(c[1])}</p></div><span class="tag">${esc(c[2])}</span></div>`).join('')}</div></article>`).join('');
  return `<div class="section-head"><div><div class="eyebrow">LOCAL REFERENCE VAULT</div><h2>Everything you need on this site</h2><p>No training link is required to understand the core theory: the reference vault mirrors the learning path and keeps definitions, workflows, and practice cues inside the portal.</p></div><div class="tag-row"><span class="tag success">self-contained</span><span class="tag">offline-readable after login</span></div></div>
  <div class="grid cols-2">${conceptBlocks}</div>
  <div class="section-head"><div><h2>Local practice recipes</h2><p>Small-footprint exercises you can run without a large remote backend.</p></div></div>
  <div class="grid cols-3"><div class="card"><span class="tag accent">WEB</span><h3 style="margin-top:8px">Synthetic HTTP lab</h3><p>Use the built-in HTTP challenges, then run a tiny localhost server and inspect requests with curl or a proxy.</p><pre>python3 -m http.server 8000
curl -i http://127.0.0.1:8000/</pre></div><div class="card"><span class="tag accent">PCAP</span><h3 style="margin-top:8px">Packet replay study</h3><p>Open a supplied capture, isolate one conversation, identify endpoints, protocol, timing, and payload format, then document the evidence.</p><pre>wireshark sample.pcapng
tcpdump -r sample.pcapng</pre></div><div class="card"><span class="tag accent">BINARY</span><h3 style="margin-top:8px">ELF triage</h3><p>Work from a copy of a harmless local executable and practice file type, strings, symbols, sections, control flow, and debugging concepts.</p><pre>file ./sample
strings ./sample | head
gdb ./sample</pre></div></div>
  <div class="note warn-note"><strong>Operational rule:</strong> Keep practice targets local or explicitly authorized. This portal teaches concepts and safe workflows; it does not assume permission to probe third-party systems.</div>`;
}

function glossaryHTML(query){
  const q=normalizeAnswer(query); const items=glossary.filter(x=>!q||normalizeAnswer(x[0]).includes(q)||normalizeAnswer(x[1]).includes(q));
  return `<div class="section-head"><div><h2>Glossary</h2><p>Fast definitions while you work a challenge. Search by term or meaning.</p></div></div><div class="glossary-search"><input id="glossaryInput" value="${esc(query)}" placeholder="e.g. ASLR, JWT, PCAP, trust boundary"><button class="btn" data-action="glossary-search">Search</button></div><div class="card" style="margin-top:14px">${items.map(x=>`<div class="glossary-item"><strong>${x[0]}</strong><span>${x[1]}</span></div>`).join('') || '<div class="empty">No terms matched. Try a broader word.</div>'}</div>`;
}


function intelHTML(data){
  if(!data) return `<div class="section-head"><div><div class="eyebrow">SECURITY INTELLIGENCE PIPELINE</div><h2>Live intelligence</h2><p>Loading the latest curated signals...</p></div></div><div class="card"><div class="terminal-line"><span class="prompt">atlas@range:~$</span> <span>sync --security-intel</span><span class="cursor">█</span></div></div>`;
  const items=(data.items||[]).slice(0,40);
  const signals=(data.topicSignals||[]).slice(0,9);
  const sources=(data.sources||[]);
  const when=data.updatedAt?new Date(data.updatedAt).toLocaleString(): 'not yet reported';
  const status=data.status||'unknown';
  const statusClass=status==='ok'?'success':status==='partial'?'warn':'';
  return `<div class="section-head"><div><div class="eyebrow">CURATED INTERNET SIGNALS</div><h2>Live intelligence</h2><p>The updater watches authoritative vulnerability data and selected security-project release feeds. It creates discovery signals for the curriculum without silently rewriting your core lessons.</p></div><div class="tag-row"><span class="update-pill"><i class="pulse"></i> ${status}</span><span class="tag">updated ${esc(when)}</span></div></div>
  <div class="intel-kpis"><div class="intel-kpi"><span class="num">${data.summary?.vulnerabilities||0}</span><span class="label">CVE signals</span></div><div class="intel-kpi"><span class="num">${data.summary?.kev||0}</span><span class="label">CISA KEV</span></div><div class="intel-kpi"><span class="num">${data.summary?.releases||0}</span><span class="label">project releases</span></div><div class="intel-kpi"><span class="num">${data.summary?.signals||0}</span><span class="label">total signals</span></div></div>
  <div class="intel-hero"><article class="card terminal"><div class="eyebrow">WHAT CHANGED</div><h3>New signals to study</h3><p>Use these as a queue for deeper reading: identify the underlying concept, map it to the relevant domain, then add or extend a local lab.</p><div class="intel-list">${items.map(x=>`<article class="intel-item"><div class="kind"><span class="tag accent">${esc(x.kind)}</span></div><div><h3>${esc(x.title||'Untitled signal')}</h3><p>${esc(x.summary||'No summary provided.')}</p><div class="tag-row"><span class="tag">${esc(x.topic||'general security')}</span>${x.cve?`<span class="tag">${esc(x.cve)}</span>`:''}</div></div><div class="meta">${esc(x.date?new Date(x.date).toLocaleDateString():'—')}<br>${esc(x.severity||'info')}</div></article>`).join('') || '<div class="empty">No signals have been published yet. Run the updater workflow once to seed the feed.</div>'}</div></article>
  <aside class="card holographic"><div class="eyebrow">TOPIC RADAR</div><h3>Where activity is clustering</h3><div class="signal-grid">${signals.map(s=>`<div class="signal-card"><strong>${esc(s.topic)}</strong><span>${s.count} recent signal${s.count===1?'':'s'}</span><span>${esc(s.reason)}</span></div>`).join('') || '<div class="empty">Radar will populate after the first successful refresh.</div>'}</div><div class="note"><strong>Publication rule:</strong> automated signals are suggestions, not authoritative curriculum. Review them before promoting a topic into a permanent learning module.</div></aside></div>
  <article class="card"><div class="eyebrow">SOURCE HEALTH</div><h3>Collection status</h3><div class="source-status">${sources.map(s=>`<div class="source-status-row"><span><b>${esc(s.name)}</b></span><span>${esc(s.status)} // ${s.count||0} items</span></div>`).join('') || '<div class="empty">No source status is available.</div>'}</div></article>`;
}

async function loadIntel(){
  if(intelLoading) return;
  intelLoading=true;
  try{const r=await fetch('/api/updates',{credentials:'same-origin',cache:'no-store'});const j=await r.json();if(!r.ok||!j.ok)throw new Error(j.error||'intel request failed');intelCache=j.data;render();}
  catch(err){intelCache={updatedAt:null,status:'error',summary:{vulnerabilities:0,kev:0,releases:0,signals:0},items:[],topicSignals:[],sources:[],notes:[String(err?.message||err)]};render();}
  finally{intelLoading=false;}
}

function bindViewEvents(){
  document.querySelectorAll('[data-domain]').forEach(b=>b.addEventListener('click',e=>{const id=e.currentTarget.dataset.domain;openDomain(id)}));
  document.querySelectorAll('[data-action="goto-path"]').forEach(b=>b.addEventListener('click',()=>setView('path')));
  document.querySelectorAll('[data-action="goto-labs"]').forEach(b=>b.addEventListener('click',()=>setView('labs')));
  document.querySelectorAll('[data-action="goto-domains"]').forEach(b=>b.addEventListener('click',()=>setView('domains')));
  document.querySelectorAll('[data-action="complete-domain"]').forEach(b=>b.addEventListener('click',()=>markDomain(b.dataset.domainId)));
  document.querySelectorAll('[data-os]').forEach(b=>b.addEventListener('click',()=>{state.os=b.dataset.os;save();render()}));
  document.querySelectorAll('[data-check]').forEach(b=>b.addEventListener('click',()=>checkAnswer(b.dataset.check)));
  document.querySelectorAll('[data-hint]').forEach(b=>b.addEventListener('click',()=>{const c=challenges.find(x=>x.id===b.dataset.hint);const el=document.getElementById('hint-'+c.id);el.classList.add('show');el.innerHTML='<strong>Hint:</strong> '+esc(c.hint[0])+'<br><br><strong>Second hint:</strong> '+esc(c.hint[1]);}));
  document.querySelectorAll('[data-explain]').forEach(b=>b.addEventListener('click',()=>{const c=challenges.find(x=>x.id===b.dataset.explain);openModal(c.name,'<p>'+esc(c.why)+'</p>')}));
  const gi=document.getElementById('glossaryInput'); if(gi){gi.addEventListener('keydown',e=>{if(e.key==='Enter'){state.view='glossary';document.getElementById('view').innerHTML=glossaryHTML(gi.value);bindViewEvents()}})}
  const mi=document.getElementById('moduleSearch'); if(mi){mi.addEventListener('input',e=>{state.moduleQuery=e.target.value;save();const grid=document.getElementById('modulesGrid');const q=normalizeAnswer(state.moduleQuery);const rows=[];domains.forEach(d=>d.concepts.forEach((c,i)=>rows.push({d,index:i+1,title:c[0],theory:c[1],practice:c[2]})));const hits=rows.filter(r=>!q||normalizeAnswer(r.title+' '+r.theory+' '+r.practice+' '+r.d.name).includes(q));document.getElementById('modulesGrid').innerHTML=hits.map(r=>`<article class=\"card module-card\"><div class=\"module-top\"><span class=\"tag accent\">${r.d.icon} / ${r.d.name}</span><span class=\"tag\">M${String(r.index).padStart(2,'0')}</span></div><h3>${esc(r.title)}</h3><p>${esc(r.theory)}</p><div class=\"module-action\"><span class=\"tag\">practice</span><span>${esc(r.practice)}</span></div><button class=\"btn outline\" data-domain=\"${r.d.id}\">open full path →</button></article>`).join('') || '<div class=\"empty\">No modules matched. Try “HTTP”, “ELF”, “XOR”, “permissions”, or “DNS”.</div>';document.querySelector('.module-count span').textContent=hits.length;bindViewEvents()})}
  document.querySelectorAll('[data-action="glossary-search"]').forEach(b=>b.addEventListener('click',()=>{const q=document.getElementById('glossaryInput').value;document.getElementById('view').innerHTML=glossaryHTML(q);bindViewEvents()}));
}

function openModal(title,body){document.getElementById('modalTitle').textContent=title;document.getElementById('modalBody').innerHTML=body;document.getElementById('modalBackdrop').hidden=false}
function closeModal(){document.getElementById('modalBackdrop').hidden=true}

document.querySelectorAll('.nav-item').forEach(b=>b.addEventListener('click',()=>{setView(b.dataset.view);document.getElementById('sidebar').classList.remove('open')}));
document.getElementById('themeToggle').addEventListener('click',()=>{state.theme=state.theme==='dark'?'light':'dark';save();setTheme()});
document.getElementById('menuToggle').addEventListener('click',()=>document.getElementById('sidebar').classList.add('open'));
document.getElementById('mobileClose').addEventListener('click',()=>document.getElementById('sidebar').classList.remove('open'));
document.getElementById('modalClose').addEventListener('click',closeModal);document.getElementById('modalBackdrop').addEventListener('click',e=>{if(e.target.id==='modalBackdrop')closeModal()});
document.getElementById('globalSearch').addEventListener('input',e=>{
  const q=normalizeAnswer(e.target.value); if(!q){setView(state.view);return}
  const hits=[];
  domains.forEach(d=>{if(normalizeAnswer(d.name+' '+d.summary+' '+d.concepts.map(c=>c.join(' ')).join(' ')).includes(q))hits.push({kind:'Domain',title:d.name,action:()=>openDomain(d.id)})});
  tools.forEach(t=>{if(normalizeAnswer(t.name+' '+t.cat+' '+t.why).includes(q))hits.push({kind:'Tool',title:t.name,action:()=>{setView('tools')}})});
  challenges.forEach(c=>{if(normalizeAnswer(c.name+' '+c.cat+' '+c.prompt).includes(q))hits.push({kind:'Lab',title:c.name,action:()=>setView('labs')})});
  if(state.view!=='dashboard' || q){document.getElementById('view').innerHTML=`<div class="section-head"><div><h2>Search results</h2><p>${hits.length} matches for “${esc(e.target.value)}”</p></div></div>${hits.length?'<div class="grid cols-3">'+hits.slice(0,24).map((h,i)=>`<button class="card" data-search-index="${i}" style="text-align:left"><span class="tag accent">${h.kind}</span><h3 style="margin-top:8px">${esc(h.title)}</h3></button>`).join('')+'</div>':'<div class="empty">No results. Try “JWT”, “ELF”, “Nmap”, “forensics”, or “permissions”.</div>'}`;
    document.querySelectorAll('[data-search-index]').forEach((b,i)=>b.addEventListener('click',()=>hits[i].action()));
  }
});

setTheme();render();
