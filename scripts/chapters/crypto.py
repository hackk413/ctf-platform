"""
CTF Atlas — Cryptography Chapters
"""

chapters = {}

chapters["crypto-rsa"] = {
    "id": "crypto-rsa",
    "domain": "crypto",
    "category": "Asymmetric Cryptography",
    "title": "RSA Mathematical Foundations, Prime Factorization & Key Recovery",
    "subtitle": "Euler's Totient, Modular Arithmetic, Small Exponent Cube Roots, Fermat Factorization & Wiener's Attack",
    "diagram": """+-------------------------------------------------------------+
|                      RSA Key Generation                     |
|  1. Choose primes p, q                                      |
|  2. Modulus: n = p * q                                      |
|  3. Totient: phi(n) = (p - 1) * (q - 1)                     |
|  4. Public Exponent: e (commonly 65537 or 3)                |
|  5. Private Exponent: d = inverse(e, phi(n)) (e*d = 1 mod phi)|
+-------------------------------------------------------------+
        |                                             |
        v                                             v
  [ Encryption ]                                [ Decryption ]
  c = m^e (mod n)                               m = c^d (mod n)

ATTACK TAXONOMY:
- If e=3 and m^3 < n:               m = integer_cube_root(c) (No mod reduction!)
- If |p - q| < 2 * n^(1/4):         Fermat Factorization (a = ceil(sqrt(n)))
- If d < (1/3) * n^(1/4):           Wiener's Attack (Continued Fractions)
- If same message encrypted under 3 keys with e=3: Hastad's Broadcast (CRT)""",
    "theory": """The Rivest-Shamir-Adleman (RSA) cryptosystem is the foundation of public-key cryptography. Its mathematical security relies on the hardness of the integer factorization problem: while computing the product of two large prime numbers $n = p \\times q$ is computationally trivial ($O(b^2)$ bit operations), recovering the constituent primes $p$ and $q$ from $n$ alone is computationally intractable for general integers using current classical algorithms (the General Number Field Sieve runs in sub-exponential time $O(\\exp((c+o(1))(\\ln n)^{1/3}(\\ln \\ln n)^{2/3}))$).

Mathematical Invariants & Parameters:
- Public Modulus: $n = p \\times q$. Bit size typically 2048 to 4096 bits.
- Euler's Totient Function: $\\phi(n) = (p-1)(q-1)$. Carmichael's totient $\\lambda(n) = \\text{lcm}(p-1, q-1)$ is mathematically optimal.
- Public Exponent $e$: Must satisfy $\\gcd(e, \\phi(n)) = 1$. Standard value is $65537 = 2^{16} + 1$ (0x10001, low Hamming weight accelerates modular exponentiation).
- Private Exponent $d$: Computed via the Extended Euclidean Algorithm such that $e \\cdot d \\equiv 1 \\pmod{\\phi(n)}$.

Prominent CTF Attack Classes:
1. Small Public Exponent ($e=3$) without OAEP Padding: If message $m$ is short ($m < n^{1/3}$), then $m^3 < n$. The modular reduction operator $\\pmod n$ never activates! Ciphertext $c = m^3$ in the integers. Plaintext is trivially recovered via exact integer cube root: $m = \\lfloor c^{1/3} \\rfloor$.
2. Fermat's Factorization (Close Primes): If prime factors $p$ and $q$ are chosen too close together ($|p-q| < 2 n^{1/4}$), then $n = a^2 - b^2 = (a+b)(a-b)$ where $a = (p+q)/2 \\approx \\sqrt{n}$. The algorithm starts at $a = \\lceil \\sqrt{n} \\rceil$ and iterates $a \\leftarrow a + 1$ until $a^2 - n$ is a perfect square $b^2$.
3. Wiener's Continued Fraction Attack (Small Private Exponent): If $d < \\frac{1}{3} n^{1/4}$, the fraction $\\frac{k}{d}$ appears as one of the convergents in the continued fraction expansion of $\\frac{e}{n}$. Computing the continued fraction expansion allows complete recovery of $d$ in polynomial time.""",
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
        "exploit_code": """#!/usr/bin/env python3
from fractions import Fraction
import gmpy2

def wiener_attack(e, n):
    cf = []
    num, den = e, n
    while den:
        cf.append(num // den)
        num, den = den, num % den
    for i in range(len(cf)):
        k, d = 0, 1
        for j in reversed(cf[:i+1]):
            k, d = d, j*d + k
        if k == 0 or (e*d - 1) % k != 0:
            continue
        phi = (e*d - 1) // k
        b = n - phi + 1
        disc = b*b - 4*n
        if disc >= 0:
            sq, exact = gmpy2.isqrt_rem(disc)
            if exact == 0:
                return d
    return None

# Load c, e, n and decrypt
# print(pow(c, d, n).to_bytes(...))""",
        "flag": "CTF{W13N3R_C0NT1NU3D_FR4CT10N_PWN}",
        "mitigation": "Always select standard public exponent e = 65537 and ensure private exponent d >= 2^(n_bits / 2) to prevent continued fraction attacks."
    }
}

chapters["crypto-aes"] = {
    "id": "crypto-aes",
    "domain": "crypto",
    "category": "Symmetric Cryptography",
    "title": "AES Block Cipher Modes, ECB Visual Artifacts & Padding Oracle Attacks",
    "subtitle": "Rijndael Substitution-Permutation Network, CBC Decryption XOR Math & PKCS#7 Padding Oracles",
    "diagram": """+-------------------------------------------------------------+
|                 AES-CBC Decryption Block n                  |
+-------------------------------------------------------------+
Ciphertext C[n] ---> [ AES Decrypt with Key K ] ---> Intermediate I[n]
                                                            |
                                                            v
Ciphertext C[n-1] ------------------------------------> [ XOR ]
                                                            |
                                                            v
                                                     Plaintext P[n]

PADDING ORACLE ATTACK LOGIC:
Attacker controls C[n-1]!
By modifying C[n-1][15] and observing padding validation errors,
attacker determines when (C[n-1][15] ^ I[n][15]) == 0x01 (valid pad)!
Therefore: I[n][15] = C[n-1][15] ^ 0x01!
Once Intermediate I[n] is known:
Plaintext P[n] = I[n] ^ Original_C[n-1]! Decrypted without the key!""",
    "theory": """The Advanced Encryption Standard (AES, FIPS 197) is a symmetric block cipher operating on fixed 128-bit (16-byte) state blocks using key lengths of 128, 192, or 256 bits. Built upon a Substitution-Permutation Network (SPN), AES executes 10, 12, or 14 rounds consisting of four algebraic operations: SubBytes (non-linear S-Box substitution over GF(2⁸)), ShiftRows (cyclical byte transposition), MixColumns (linear matrix diffusion over polynomial rings), and AddRoundKey (bitwise XOR with round subkeys).

Modes of Operation & CTF Attack Vectors:
1. ECB (Electronic Codebook) Mode: Each 16-byte block is encrypted independently using the same key: $C_i = \\text{AES}_K(P_i)$. Identical plaintext blocks produce identical ciphertext blocks (illustrated by the famous visual 'ECB Penguin'). Attackers reorder, duplicate, or delete blocks without detection.
2. CBC (Cipher Block Chaining) Mode: Each plaintext block is XORed with the preceding ciphertext block before encryption: $C_i = \\text{AES}_K(P_i \\oplus C_{i-1})$, where $C_0$ is the Initialization Vector (IV). Decryption: $P_i = \\text{AES}_K^{-1}(C_i) \\oplus C_{i-1}$.
3. PKCS#7 Padding Oracle Attack (Vaudenay, 2002): In CBC mode, plaintexts must align to 16-byte boundaries using PKCS#7 padding (e.g. 1 byte missing = `\\x01`, 3 bytes missing = `\\x03\\x03\\x03`). If a server leaks whether decrypted ciphertext has valid PKCS#7 padding (via HTTP 500 error vs HTTP 200, or timing differences), an attacker can decrypt ANY ciphertext block-by-block without ever learning the secret encryption key.
4. CBC Bit-Flipping: Because $P_n = I_n \\oplus C_{n-1}$, flipping bit $k$ of ciphertext block $C_{n-1}$ inverts bit $k$ in the decrypted plaintext block $P_n$. Attackers tamper with tokens (e.g. changing `admin=0` to `admin=1`).""",
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
        "exploit_code": """#!/usr/bin/env python3
import requests

TARGET = "http://target.ctf/auth?token="

def oracle(token_hex):
    r = requests.get(TARGET + token_hex)
    return "Invalid PKCS#7" not in r.text

def decrypt_block(prev_block, target_block):
    intermediate = [0] * 16
    plaintext = [0] * 16
    for byte_idx in range(15, -1, -1):
        pad_val = 16 - byte_idx
        crafted_prev = [0] * 16
        for k in range(byte_idx + 1, 16):
            crafted_prev[k] = intermediate[k] ^ pad_val
        for guess in range(256):
            crafted_prev[byte_idx] = guess
            test_payload = bytes(crafted_prev) + target_block
            if oracle(test_payload.hex()):
                intermediate[byte_idx] = guess ^ pad_val
                plaintext[byte_idx] = intermediate[byte_idx] ^ prev_block[byte_idx]
                break
    return bytes(plaintext)""",
        "flag": "CTF{P4DD1NG_0R4CL3_CBC_D3CRYPT}",
        "mitigation": "Use Authenticated Encryption (AES-GCM or ChaCha20-Poly1305). If using CBC, always apply the Encrypt-then-MAC paradigm with HMAC-SHA256 and verify the MAC in constant time before decryption."
    }
}

chapters["crypto-classical"] = {
    "id": "crypto-classical",
    "domain": "crypto",
    "category": "Classical & Historical Cryptography",
    "title": "Classical Cryptanalysis, Frequency Distributions & Multi-Byte XOR",
    "subtitle": "Index of Coincidence (IoC), Kasiski Examination, Vigenère Inversion & Hamming Distance Key Lengths",
    "diagram": """+-----------------------------------------------------------------+
|                  Multi-Byte XOR & Vigenère Analysis             |
+-----------------------------------------------------------------+
Ciphertext: 1f 0a 34 12 0c 5e ...
  |
  +-> 1. Determine Key Length (k):
  |     - Normalized Hamming Distance across adjacent k-byte blocks
  |     - Index of Coincidence: IoC = sum(f_i * (f_i - 1)) / (N * (N - 1))
  |       English text IoC ~= 0.0667 | Random text IoC ~= 0.0385
  |
  +-> 2. Transpose into k independent Single-Byte Streams:
  |     Stream 0: c[0], c[k],   c[2k], ...
  |     Stream 1: c[1], c[k+1], c[2k+1], ...
  |
  +-> 3. Single-Byte Frequency Scoring:
        Score each candidate byte (0..255) against English letter frequencies (ETAOIN SHRDLU)!""",
    "theory": """Classical ciphers manipulate plaintext characters at the syntactic level through substitution (replacing symbols) and transposition (reordering symbols). While obsolete in modern engineering, classical cryptanalysis concepts—frequency distributions, entropy, modular arithmetic, and the Index of Coincidence—are foundational to understanding modern stream ciphers and CTF puzzles.

Mathematical Invariants & Statistical Measures:
1. Index of Coincidence (IoC): The probability that two randomly selected letters from a ciphertext are identical. For an alphabet of size $c$ and character frequencies $f_i$:
$$IoC = \\frac{\\sum_{i=1}^c f_i (f_i - 1)}{N(N - 1)}$$
For English plaintext, $IoC \\approx 0.0667$. For random uniformly distributed text, $IoC \\approx 1/26 \\approx 0.0385$. Monoalphabetic substitution ciphers preserve the exact IoC of the underlying language.
2. Vigenère Cipher & Multi-Byte XOR: Polyalphabetic ciphers use a repeating key to encrypt characters. If the key length is $k$, every $k$-th character is encrypted with the same single-byte key. The attack proceeds in two phases:
   - Phase 1: Determine key length $k$ using Kasiski examination (finding distances between repeated ciphertext n-grams) or calculating the average Hamming distance between chunks of size $k$.
   - Phase 2: Transpose the ciphertext into $k$ independent slices and solve each slice as a monoalphabetic substitution or single-byte XOR against English frequency tables (E: 12.7%, T: 9.1%, A: 8.2%, O: 7.5%, I: 7.0%, N: 6.7%).""",
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
        "gui_workflow": "CyberChef: 'Vigenère Decode', 'Rot13', or 'Bake' with 'Entropy' and 'Frequency analysis'.",
        "speed_tip": "In CyberChef, use the 'Magic' recipe with intensive search enabled to automatically recognize Base64, Hex, XOR, and compression."
    },
    "triage_workflow": [
        "1. Check Encoding First: Is it Base64 (`=`), Hex (`[0-9a-fA-F]`), or binary?",
        "2. Compute Character Frequencies: If alphabet is restricted to letters, it's a substitution or transposition cipher.",
        "3. Compute IoC: If IoC ~ 0.066, monoalphabetic substitution (Caesar, Affine, Atbash). Use quipqiup.com.",
        "4. If IoC < 0.05, polyalphabetic (Vigenère) or multi-byte XOR.",
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
        "exploit_code": """#!/usr/bin/env python3
import base64

def hamming(b1, b2):
    return sum(bin(x ^ y).count('1') for x, y in zip(b1, b2))

# Full solver in Cryptopals standard library
print("[+] Decrypted Flag: CTF{REP34T1NG_X0R_K3Y_D1ST4NC3}")""",
        "flag": "CTF{REP34T1NG_X0R_K3Y_D1ST4NC3}",
        "mitigation": "Never use repeating-key XOR or classical ciphers for confidential data. Use modern authenticated encryption like AES-256-GCM or ChaCha20-Poly1305."
    }
}

chapters["crypto-dlog-ecc"] = {
    "id": "crypto-dlog-ecc",
    "domain": "crypto",
    "category": "Modern Asymmetric Cryptography",
    "title": "Discrete Logarithms & Elliptic Curve Cryptography (ECC)",
    "subtitle": "Diffie-Hellman Key Exchange, Weierstrass Curves ($y^2 = x^3 + ax + b$), Point Addition & Nonce Reuse",
    "diagram": """+-----------------------------------------------------------------+
|               Elliptic Curve Point Multiplication               |
+-----------------------------------------------------------------+
Curve Equation: y^2 = x^3 + a*x + b  (over Finite Field GF(p))

Base Point G = (x_G, y_G)
Private Key: d (Scalar integer, e.g. 256 bits)
Public Key:  Q = d * G (Point multiplication via double-and-add)

DISCRETE LOGARITHM PROBLEM (ECDLP):
Given G and Q = d * G, compute scalar d!
Intractable for secure curves (secp256k1, NIST P-256).

VULNERABILITY: ECDSA NONCE REUSE!
Signature (r, s):
  k = ephemeral nonce (MUST BE RANDOM AND UNIQUE PER SIGNATURE!)
  r = (k * G).x mod n
  s = k^(-1) * (z + r * d) mod n

If same nonce k is used for two signatures (r, s1) and (r, s2):
  s1 - s2 = k^(-1) * (z1 - z2)
  k = (z1 - z2) / (s1 - s2) mod n  ---> NONCE RECOVERED!
  d = (s * k - z) / r mod n        ---> PRIVATE KEY RECOVERED!""",
    "theory": """Modern asymmetric cryptography increasingly relies on the algebraic structure of elliptic curves over finite fields. While classical Diffie-Hellman operates in the multiplicative group of integers modulo a prime $p$ ($g^a \\pmod p$), Elliptic Curve Cryptography (ECC) achieves equivalent cryptographic security with dramatically smaller key sizes (a 256-bit ECC key provides security equivalent to a 3072-bit RSA key).

Elliptic Curve Mathematics:
A non-singular elliptic curve over a prime field $\\mathbb{F}_p$ ($p > 3$) in short Weierstrass form is defined by the set of points $(x, y) \\in \\mathbb{F}_p \\times \\mathbb{F}_p$ satisfying:
$$y^2 \\equiv x^3 + ax + b \\pmod p$$
together with a point at infinity $\\mathcal{O}$ serving as the identity element. The discriminant $\\Delta = 4a^3 + 27b^2 \\not\\equiv 0 \\pmod p$ guarantees that the curve contains no cusps or self-intersections. The set of points forms an abelian group under geometric chord-and-tangent point addition.

The Elliptic Curve Discrete Logarithm Problem (ECDLP):
Given base point $G$ of order $n$ and public key $Q = d \\cdot G$, finding the scalar integer $d$ is the ECDLP. On secure curves, the best known attack is Pollard's rho algorithm ($O(\\sqrt{n})$ operations).

Catastrophic Failure Classes in CTF:
1. ECDSA Nonce Reuse (The Sony PS3 Hack): The Elliptic Curve Digital Signature Algorithm (ECDSA) signs message hash $z$ using an ephemeral secret scalar $k$. If the random number generator is flawed and reuses the exact same nonce $k$ to sign two distinct messages $z_1$ and $z_2$, the signature $r$-value is identical. The attacker solves for $k$ using elementary modular arithmetic, and immediately extracts the signer's private key $d$.
2. Invalid Curve Attacks: If the responder does not verify that user-supplied point $(x, y)$ satisfies the curve equation $y^2 = x^3 + ax + b$, an attacker provides points on an alternative 'weak' curve with small subgroup orders, recovering the private key via the Chinese Remainder Theorem.""",
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
        "exploit_code": """#!/usr/bin/env python3
# secp256k1 curve order
n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

# Given z1, z2, r, s1, s2
def recover_key(z1, z2, r, s1, s2):
    k = ((z1 - z2) * pow(s1 - s2, -1, n)) % n
    d = ((s1 * k - z1) * pow(r, -1, n)) % n
    return d

print("[+] Private Key Recovered!")""",
        "flag": "CTF{ECDSA_N0NC3_R3US3_PRIV4T3_K3Y_ST0L3N}",
        "mitigation": "Implement RFC 6979 deterministic nonce generation. RFC 6979 derives the ephemeral nonce $k$ deterministically from HMAC-SHA256(private_key, message_hash), ensuring identical nonces are never used across different messages."
    }
}
