"""
CTF Atlas — Reverse Engineering Chapters
"""

chapters = {}

chapters["reverse-ghidra"] = {
    "id": "reverse-ghidra",
    "domain": "reverse",
    "category": "Reverse Engineering",
    "title": "Static Binary Analysis, Control Flow Deconstruction & Ghidra Decompilation",
    "subtitle": "ELF/PE Headers, Linear Sweep vs Recursive Disassembly, P-Code Intermediate Representation & Algorithm Inversion",
    "diagram": """Compiled Machine Code (Raw Bytes: 55 48 89 e5 ...)
       |
       +---> Disassembly Engine (Capstone / Ghidra Sleigh)
       |     x86_64: push rbp; mov rbp, rsp; sub rsp, 0x20
       |
       +---> Control Flow Graph (CFG) Construction
       |     Basic Blocks partitioned by JMP / JZ / CALL
       |
       +---> P-Code Intermediate Representation (IR)
       |     Abstract register and stack assignments normalized
       |
       +---> Decompiler AST Reconstruction
       |     High-level C pseudo-code generated:
       |     if (strcmp(input_flag, decrypted_key) == 0) { ... }""",
    "theory": """Reverse engineering is the process of deconstructing a compiled software artifact to analyze its internal control flow, algorithms, and security logic without access to the original source code.

Binary Formats & Static Analysis Foundations:
1. Executable and Linkable Format (ELF, Linux) & Portable Executable (PE, Windows): Executables begin with file headers declaring the target architecture (x86, x64, ARM, MIPS), entry point address (`e_entry`), and section/segment headers.
   - `.text`: Executable machine code instructions.
   - `.rodata` / `.rdata`: Read-only constants, string literals, and jump tables.
   - `.data`: Initialized global and static variables.
   - `.bss`: Uninitialized global variables (zero-filled by the OS loader).
   - `.plt` (Procedure Linkage Table) and `.got` (Global Offset Table): Support dynamic linking.
2. Disassembly Strategies:
   - Linear Sweep: Disassembles byte-by-byte sequentially starting from the section header. Susceptible to anti-disassembly tricks (e.g. inserting junk bytes after unconditional jumps).
   - Recursive Descent: Follows the program's control flow graph (branches, jumps, and calls). Ghidra and IDA Pro utilize recursive descent.
3. Ghidra Decompilation Engine:
   Ghidra translates machine code into an architecture-independent intermediate representation called P-Code. It constructs data-flow graphs, performs SSA (Static Single Assignment) transformations, eliminates dead code, and recovers high-level C representations. Key triage primitives: renaming functions, setting data types (e.g. changing `undefined4` to `int` or `char*`), and inspecting Cross-References (XREFs).""",
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
        "exploit_code": """#!/usr/bin/env python3

expected = [0x39, 0x0e, 0x14, 0x3e, 0x13, 0x32, 0x62, 0x6e, 0x6e, 0x64, 0x08, 0x6e, 0x62, 0x6e, 0x08, 0x6e, 0x62, 0x6e, 0x64, 0x6e, 0x08, 0x6e, 0x37, 0x77]
key = 0x5a

flag = "".join(chr(b ^ key) for b in expected)
print("[+] Decrypted Flag:", flag)""",
        "flag": "CTF{GH1DR4_X0R_R3V3RS1NG_W1N}",
        "mitigation": "Protect intellectual property by using code virtualization (VMProtect/Themida), control flow flattening, and verifying inputs via one-way cryptographic hashes (Argon2id) rather than reversible byte operations."
    }
}

chapters["reverse-x86-asm"] = {
    "id": "reverse-x86-asm",
    "domain": "reverse",
    "category": "Architecture & Assembly",
    "title": "x86-64 Architecture Internals & Assembly Deconstruction",
    "subtitle": "System V AMD64 ABI Calling Conventions, General Purpose Registers, Stack Frames & Branch Evaluation",
    "diagram": """+-----------------------------------------------------------------+
|               System V AMD64 Calling Convention                 |
+-----------------------------------------------------------------+
Function Arguments Passed via Registers (in exact order):
  1st Arg: RDI    2nd Arg: RSI    3rd Arg: RDX
  4th Arg: RCX    5th Arg: R8     6th Arg: R9
  (Remaining 7th+ arguments pushed onto the Stack in reverse order)

Return Value: RAX (64-bit) / EAX (32-bit)

Stack Frame Epilogue / Prologue:
Prologue:
  push rbp          ; Save caller's base pointer
  mov  rbp, rsp     ; Set new frame pointer
  sub  rsp, 0x20    ; Allocate local variable space

Epilogue:
  leave             ; Equivalent to: mov rsp, rbp; pop rbp
  ret               ; Pop return address from stack into RIP""",
    "theory": """Reading assembly language fluently is mandatory for reverse engineering and binary exploitation. In CTF competitions, decompilers (Ghidra, IDA) often produce incorrect, misleading, or hallucinated C pseudo-code when binaries use custom calling conventions, inline assembly, or anti-analysis tricks. Ground truth lives solely in the assembly instructions.

x86-64 Register Taxonomy:
- 64-bit General Purpose Registers: RAX (accumulator, return values), RBX (base), RCX (counter, loops), RDX (data, I/O), RSI (source index), RDI (destination index), RBP (base frame pointer), RSP (stack pointer), R8-R15.
- Sub-register slices: RAX (64-bit) -> EAX (lower 32 bits) -> AX (lower 16 bits) -> AH/AL (high/low 8 bits). Writing to a 32-bit register (e.g. `mov eax, 1`) automatically zeroes the upper 32 bits of RAX.
- Instruction Pointer: RIP points to the virtual memory address of the next instruction to execute.

System V AMD64 Calling Convention:
Linux and BSD x86-64 systems enforce the System V ABI:
- Function Arguments: First 6 integer/pointer arguments are passed in RDI, RSI, RDX, RCX, R8, R9. Additional arguments go to the stack.
- Callee-Saved Registers: RBX, RSP, RBP, R12, R13, R14, R15 must be preserved across function calls.
- Caller-Saved (Scratch) Registers: RAX, RDI, RSI, RDX, RCX, R8-R11 can be overwritten by the called function.
- Stack Alignment Invariant: The System V ABI mandates that the stack pointer RSP must be 16-byte aligned before executing a `CALL` instruction. (Critical in ROP chains: missing alignment crashes `system()` on SSE `movaps` instructions!).""",
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
        "exploit_code": """#!/usr/bin/env python3

target = 0x12345678 ^ 0xdeadbeef
mod = 2**32
inv = pow(0x1337, -1, mod)
solution = (target * inv) % mod

print(f"[+] Required Input Integer: {solution}")
# Verify: (solution * 0x1337) ^ 0xdeadbeef == 0x12345678
assert ((solution * 0x1337) & 0xffffffff) ^ 0xdeadbeef == 0x12345678
print("[+] Verification passed!")""",
        "flag": "CTF{ASM_INV3RS3_M4TH_COMPL3T3}",
        "mitigation": "Avoid simple reversible linear transformations for validation keys. Use strong hash comparisons (SHA-256) where algebraic inversion is mathematically infeasible."
    }
}

chapters["reverse-anti-debug"] = {
    "id": "reverse-anti-debug",
    "domain": "reverse",
    "category": "Anti-Analysis & Obfuscation",
    "title": "Anti-Debugging Mechanics, Binary Packing & Dynamic Patching",
    "subtitle": "Ptrace Self-Tracing, RDTSC Timing Checks, Software Breakpoint INT3 Detection & Binary Patching",
    "diagram": """+-----------------------------------------------------------------+
|                    Anti-Debugging Detection Loops               |
+-----------------------------------------------------------------+
1. PTRACE_TRACEME:
   ptrace(PTRACE_TRACEME, 0, 1, 0)
   - Only ONE process can attach as a debugger to a target!
   - If GDB is already attached, ptrace returns -1!
   - Binary detects return value == -1 and self-terminates!

2. RDTSC Timing Check:
   rdtsc (Read Time-Stamp Counter)
   ... sensitive code ...
   rdtsc
   - If running under GDB (stepping), elapsed cycles > 1,000,000!
   - Normal execution < 10,000 cycles. Binary aborts!

3. INT3 Scanner:
   Scans function memory bytes for 0xCC (INT3 software breakpoint opcode).
   - If debugger placed a breakpoint, 0xCC is detected! Binary crashes!""",
    "theory": """Malware authors and CTF challenge creators deploy anti-analysis defenses to obstruct static disassembly, prevent dynamic debugging, and detect execution inside virtualized sandbox environments.

Core Anti-Debugging Mechanisms:
1. Ptrace Evasion (Linux):
   The `ptrace` system call allows one process to control and inspect another. Linux enforces a strict kernel security invariant: only a single tracing process may be attached to a target task at any given time.
   - Trick: The binary calls `ptrace(PTRACE_TRACEME, 0, 1, 0)` early in its initialization. If the binary is already running under GDB or strace, the call fails and returns `-1`. The program detects this and immediately invokes `exit()` or corrupts the flag in memory.
2. Timing Checks (`rdtsc`):
   The x86 `rdtsc` instruction returns the 64-bit count of CPU cycles since processor reset. By measuring cycles before and after a block of code, the binary measures execution latency. If an analyst is stepping through instructions manually in a debugger, the cycle difference is orders of magnitude higher than native CPU execution, triggering evasive actions.
3. Software Breakpoint Detection (`0xCC`):
   When a debugger sets a breakpoint, it temporarily overwrites the target byte in memory with the 1-byte opcode `0xCC` (`INT 3`). The binary computes checksums over its own `.text` section; if an analyst has set software breakpoints, the checksum fails.

Bypassing Anti-Debugging via Binary Patching:
Solvers defeat anti-debugging using three primary techniques:
1. Static Binary Patching: Open the binary in a hex editor or Ghidra. Locate the conditional jump following the anti-debug check (`jz exit_label`) and overwrite the opcode with `NOP` instructions (`0x90 0x90`) or invert the condition (`jnz`).
2. GDB Runtime Interception: Set a breakpoint at the `ptrace` syscall or wrapper, and force the return register to zero: `(gdb) catch syscall ptrace` -> `set $rax = 0` -> `continue`.
3. LD_PRELOAD Hooking: Intercept the libc `ptrace()` function using a shared library that always returns `0`.""",
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
        "exploit_code": """#!/usr/bin/env python3

# Byte-patching script using Python
with open("binary", "rb") as f:
    data = bytearray(f.read())

# Replace '74 05' (jz +5) with '90 90' (nop nop) at known file offset
offset = 0x1248
data[offset:offset+2] = b'\\x90\\x90'

with open("binary_patched", "wb") as f:
    f.write(data)

print("[+] Binary patched successfully! Anti-debug check disabled.")""",
        "flag": "CTF{PTRACE_B1NARY_P4TCH1NG_SUCC3SS}",
        "mitigation": "Do not rely exclusively on user-space anti-debugging techniques; compile with kernel eBPF integrity monitoring and server-side attestation for sensitive commercial software."
    }
}
