# Part 26: Mobile Security Testing (Steps 251-260)

## ภาพรวม
ส่วนนี้ครอบคลุมการทดสอบความปลอดภัยของ Mobile Applications ทั้ง Android และ iOS รวมถึง Static Analysis, Dynamic Analysis, Frida Hooking, Traffic Interception และ OWASP Mobile Top 10

---

## Step 251: Android Security Testing Setup

### Android Testing Environment
```bash
# ติดตั้ง Android testing tools
apt install adb
pip3 install frida-tools objection

# ติดตั้ง apktool
wget https://raw.githubusercontent.com/iBotPeaches/Apktool/master/scripts/linux/apktool
wget https://bitbucket.org/iBotPeaches/apktool/downloads/apktool_2.x.x.jar
mv apktool_2.x.x.jar /usr/local/bin/apktool.jar
mv apktool /usr/local/bin/apktool
chmod +x /usr/local/bin/apktool

# ติดตั้ง jadx
wget https://github.com/skylot/jadx/releases/download/v1.4.7/jadx-1.4.7.zip
unzip jadx-1.4.7.zip -d /opt/jadx
export PATH=$PATH:/opt/jadx/bin

# ติดตั้ง MobSF
docker pull opensecurity/mobile-security-framework-mobsf
docker run -it --rm -p 8000:8000 opensecurity/mobile-security-framework-mobsf:latest

# ติดตั้ง drozer
pip3 install drozer
```

### ADB Commands สำหรับ Android Testing
```bash
# Basic ADB
adb devices
adb connect DEVICE_IP:5555
adb shell

# เข้าถึง root shell
adb root
adb shell
whoami  # should be root

# Install/Uninstall APK
adb install app.apk
adb uninstall com.package.name

# Pull ไฟล์จาก device
adb pull /data/data/com.app.name/databases/ ./
adb pull /sdcard/ ./backup/

# Push ไฟล์ไป device
adb push frida-server /data/local/tmp/
adb shell chmod 755 /data/local/tmp/frida-server

# Screenshot
adb shell screencap /sdcard/screen.png
adb pull /sdcard/screen.png

# Logcat (application logs)
adb logcat | grep -i 'com.target.app'
adb logcat -d > device_logs.txt

# Start frida-server
adb shell /data/local/tmp/frida-server &
```

---

## Step 252: APK Static Analysis

### APK เดอมบักและวิเคราะห์
```python
#!/usr/bin/env python3
# apk_static_analyzer.py

import subprocess
import zipfile
import os
import re
import json

class APKStaticAnalyzer:
    def __init__(self, apk_path):
        self.apk_path = apk_path
        self.output_dir = '/tmp/apk_analysis'
        os.makedirs(self.output_dir, exist_ok=True)
        self.findings = []
    
    def decompile_apk(self):
        """เดอมบัค APK"""
        print("[*] Decompiling APK with apktool...")
        subprocess.run([
            'apktool', 'd', self.apk_path,
            '-o', f'{self.output_dir}/apktool',
            '-f'
        ])
        
        print("[*] Decompiling APK with jadx...")
        subprocess.run([
            'jadx', self.apk_path,
            '-d', f'{self.output_dir}/jadx'
        ])
    
    def extract_apk(self):
        """แตกไฟล์ APK"""
        print("[*] Extracting APK contents...")
        with zipfile.ZipFile(self.apk_path, 'r') as apk:
            apk.extractall(f'{self.output_dir}/raw')
    
    def analyze_manifest(self):
        """วิเคราะห์ AndroidManifest.xml"""
        print("[*] Analyzing AndroidManifest.xml...")
        
        manifest_path = f'{self.output_dir}/apktool/AndroidManifest.xml'
        
        if not os.path.exists(manifest_path):
            print("[-] Manifest not found")
            return
        
        with open(manifest_path) as f:
            content = f.read()
        
        issues = []
        
        # Check debuggable
        if 'android:debuggable="true"' in content:
            issues.append({
                'severity': 'High',
                'issue': 'App is debuggable',
                'detail': 'android:debuggable="true" in manifest'
            })
        
        # Check allowBackup
        if 'android:allowBackup="true"' in content:
            issues.append({
                'severity': 'Medium',
                'issue': 'Backup enabled',
                'detail': 'android:allowBackup="true"'
            })
        
        # Check exported activities
        exported = re.findall(
            r'<activity[^>]*android:name="([^"]+)"[^>]*android:exported="true"',
            content
        )
        for activity in exported:
            issues.append({
                'severity': 'Medium',
                'issue': 'Exported activity',
                'detail': f'Activity {activity} is exported'
            })
        
        # Check network security config
        if 'android:networkSecurityConfig' not in content:
            issues.append({
                'severity': 'Medium',
                'issue': 'No Network Security Config',
                'detail': 'App may allow cleartext traffic'
            })
        
        # Check permissions
        permissions = re.findall(r'<uses-permission android:name="([^"]+)"', content)
        dangerous_perms = [
            'READ_CONTACTS', 'WRITE_CONTACTS', 'READ_SMS', 'SEND_SMS',
            'RECORD_AUDIO', 'CAMERA', 'ACCESS_FINE_LOCATION'
        ]
        for perm in permissions:
            if any(d in perm for d in dangerous_perms):
                issues.append({
                    'severity': 'Info',
                    'issue': 'Dangerous permission',
                    'detail': perm
                })
        
        self.findings.extend(issues)
        
        for issue in issues:
            print(f"  [{issue['severity']}] {issue['issue']}: {issue['detail']}")
    
    def search_hardcoded_secrets(self):
        """ค้นหา hardcoded secrets"""
        print("[*] Searching for hardcoded secrets...")
        
        secret_patterns = [
            (r'password[\s]*=[\s]*["\'][^"\'\']+["\']', 'Hardcoded Password'),
            (r'api[_-]?key[\s]*=[\s]*["\'][^"\'\']+["\']', 'API Key'),
            (r'secret[\s]*=[\s]*["\'][^"\'\']+["\']', 'Secret'),
            (r'token[\s]*=[\s]*["\'][^"\'\']+["\']', 'Token'),
            (r'aws[_-]?access[_-]?key[_-]?id[\s]*=[\s]*["\'][^"\'\']+["\']', 'AWS Key'),
            (r'AAAA[A-Za-z0-9_-]{140,}', 'Firebase Token'),
            (r'https?://[a-zA-Z0-9.-]+\.amazonaws\.com[/a-zA-Z0-9.-]*', 'AWS URL')
        ]
        
        for root, dirs, files in os.walk(f'{self.output_dir}/jadx'):
            for filename in files:
                if filename.endswith('.java'):
                    filepath = os.path.join(root, filename)
                    with open(filepath, errors='ignore') as f:
                        content = f.read()
                    
                    for pattern, issue_type in secret_patterns:
                        matches = re.findall(pattern, content, re.IGNORECASE)
                        for match in matches:
                            self.findings.append({
                                'severity': 'High',
                                'file': filepath.replace(self.output_dir, ''),
                                'issue': issue_type,
                                'detail': match[:100]
                            })
                            print(f"  [High] {issue_type} in {filename}: {match[:60]}")
    
    def check_insecure_storage(self):
        """ตรวจสอป insecure storage"""
        print("[*] Checking for insecure storage...")
        
        patterns = [
            (r'getSharedPreferences', 'SharedPreferences usage'),
            (r'MODE_WORLD_READABLE', 'World-readable storage'),
            (r'MODE_WORLD_WRITEABLE', 'World-writable storage'),
            (r'openFileOutput.*MODE_WORLD', 'World-accessible file'),
            (r'SQLiteOpenHelper', 'SQLite database'),
            (r'Environment\.getExternalStorage', 'External storage'),
        ]
        
        for root, dirs, files in os.walk(f'{self.output_dir}/jadx'):
            for filename in files:
                if filename.endswith('.java'):
                    filepath = os.path.join(root, filename)
                    with open(filepath, errors='ignore') as f:
                        content = f.read()
                    
                    for pattern, issue_type in patterns:
                        if re.search(pattern, content):
                            print(f"  [{issue_type}] in {filename}")
    
    def check_ssl_pinning(self):
        """ตรวจสอป SSL Pinning implementation"""
        print("[*] Checking SSL pinning...")
        
        pinning_indicators = [
            'CertificatePinner', 'TrustManager', 'X509TrustManager',
            'checkServerTrusted', 'SSLContext', 'KeyStore',
            'OkHttpClient.Builder', 'NetworkSecurityConfig'
        ]
        
        found = []
        for root, dirs, files in os.walk(f'{self.output_dir}/jadx'):
            for filename in files:
                if filename.endswith('.java'):
                    filepath = os.path.join(root, filename)
                    with open(filepath, errors='ignore') as f:
                        content = f.read()
                    
                    for indicator in pinning_indicators:
                        if indicator in content:
                            if indicator not in found:
                                found.append(indicator)
                                print(f"  [+] Found: {indicator} in {filename}")
        
        if not found:
            print("  [!] No SSL pinning detected")
    
    def report(self):
        print("\n" + "="*60)
        print("APK Static Analysis Report")
        print("="*60)
        print(f"Total findings: {len(self.findings)}")
        
        by_severity = {}
        for f in self.findings:
            sev = f.get('severity', 'Unknown')
            by_severity[sev] = by_severity.get(sev, 0) + 1
        
        for sev, count in by_severity.items():
            print(f"  {sev}: {count}")

# การใช้งาน
if __name__ == '__main__':
    analyzer = APKStaticAnalyzer('target.apk')
    analyzer.extract_apk()
    analyzer.decompile_apk()
    analyzer.analyze_manifest()
    analyzer.search_hardcoded_secrets()
    analyzer.check_insecure_storage()
    analyzer.check_ssl_pinning()
    analyzer.report()
```

---

## Step 253: Frida Dynamic Analysis

### Frida Scripts
```javascript
// frida_script.js - Android SSL unpinning

// Method 1: OkHttp3 CertificatePinner bypass
java.perform(function() {
    console.log('[*] Starting SSL unpinning...');
    
    // OkHttp3
    try {
        var CertificatePinner = Java.use('okhttp3.CertificatePinner');
        CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function(hostname, peerCertificates) {
            console.log('[+] Bypassed OkHttp CertificatePinner for: ' + hostname);
        };
    } catch(e) {}
    
    // TrustManagerImpl  
    try {
        var TrustManagerImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl');
        TrustManagerImpl.verifyChain.implementation = function(untrustedChain, trustAnchorChain, host, clientAuth, ocspData, tlsSctData) {
            console.log('[+] TrustManagerImpl.verifyChain bypassed for: ' + host);
            return untrustedChain;
        };
    } catch(e) {}
    
    // SSLContext
    try {
        var SSLContext = Java.use('javax.net.ssl.SSLContext');
        SSLContext.init.overload('[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom').implementation = function(keyManagers, trustManagers, secureRandom) {
            var AllTrustManager = Java.registerClass({
                name: 'com.frida.AllTrustManager',
                implements: [Java.use('javax.net.ssl.X509TrustManager')],
                methods: {
                    checkClientTrusted: function(chain, authType) {},
                    checkServerTrusted: function(chain, authType) {},
                    getAcceptedIssuers: function() { return []; }
                }
            });
            this.init(keyManagers, [AllTrustManager.$new()], secureRandom);
            console.log('[+] SSLContext.init bypassed');
        };
    } catch(e) {}
    
    console.log('[*] SSL unpinning complete');
});
```

```python
#!/usr/bin/env python3
# frida_controller.py

import frida
import sys
import json

class FridaController:
    def __init__(self, package_name, device_type='usb'):
        self.package_name = package_name
        if device_type == 'usb':
            self.device = frida.get_usb_device()
        else:
            self.device = frida.get_remote_device()
    
    def spawn_and_attach(self, script_path):
        """เริ่ม app และ inject script"""
        pid = self.device.spawn(self.package_name)
        session = self.device.attach(pid)
        
        with open(script_path) as f:
            script_code = f.read()
        
        script = session.create_script(script_code)
        script.on('message', self._on_message)
        script.load()
        
        self.device.resume(pid)
        print(f"[+] Attached to {self.package_name} (PID: {pid})")
        return session, script
    
    def attach_to_running(self, script_code):
        """Attach ไปยัง app ที่รันอยู่"""
        session = self.device.attach(self.package_name)
        script = session.create_script(script_code)
        script.on('message', self._on_message)
        script.load()
        print(f"[+] Attached to {self.package_name}")
        return session, script
    
    def _on_message(self, message, data):
        if message['type'] == 'send':
            print(f"[Frida] {message['payload']}")
        elif message['type'] == 'error':
            print(f"[Error] {message['stack']}")

# Script: Hook login function
hook_login_script = """
java.perform(function() {
    var LoginActivity = Java.use('com.target.app.LoginActivity');
    
    if (LoginActivity.authenticate) {
        LoginActivity.authenticate.overload('java.lang.String', 'java.lang.String').implementation = function(username, password) {
            console.log('[*] Login attempt:');
            console.log('    Username: ' + username);
            console.log('    Password: ' + password);
            
            // Call original method
            var result = this.authenticate(username, password);
            console.log('    Result: ' + result);
            return result;
        };
    }
    
    // Hook SharedPreferences
    var SharedPreferences = Java.use('android.content.SharedPreferences$Editor');
    SharedPreferences.putString.implementation = function(key, value) {
        console.log('[*] SharedPreferences.putString: ' + key + ' = ' + value);
        return this.putString(key, value);
    };
});
"""

# การใช้งาน
if __name__ == '__main__':
    controller = FridaController('com.target.app')
    session, script = controller.attach_to_running(hook_login_script)
    
    print("[*] Hooked! Press Ctrl+C to stop...")
    try:
        sys.stdin.read()
    except KeyboardInterrupt:
        session.detach()
```

### Objection สำหรับ Mobile Testing
```bash
# เริ่ม objection
objection -g com.target.app explore

# สั่ง objection:
android hooking list classes            # list all classes
android hooking list class_methods com.target.app.MainActivity  # list methods
android hooking watch class com.target.app.crypto.AESUtils       # hook all methods in class
android sslpinning disable             # bypass SSL pinning
android root disable                   # bypass root detection
android ui screenshot /tmp/screen.png  # screenshot
env                                    # show app environment
file download /data/data/com.target.app/databases/app.db ./  # download file
android intent launch_activity com.target.app/.AdminActivity  # launch hidden activity

# Frida CLI
frida -U -l script.js com.target.app
frida -U -l ssl_bypass.js -f com.target.app --no-pause
```

---

## Step 254: Android Traffic Interception

### Setup MitM proxy สำหรับ Android
```bash
# Setup Burp Suite proxy
# 1. ตั้ง Burp Proxy Listener: 0.0.0.0:8080
# 2. ตั้ง proxy บน Android: Settings -> WiFi -> Proxy -> Manual
# 3. ติดตั้ง Burp CA:

# Download Burp CA
curl http://BURP_IP:8080/cert -o burp.der
openssl x509 -inform DER -in burp.der -out burp.pem
adb push burp.pem /sdcard/
# ติดตั้งใน Android: Settings -> Security -> Install from storage

# สำหรับ Android 7+ (Certificate trust)
# ต้อง root หรือ patch APK

# Network Security Config bypass - แก้ไข APK
# 1. Decompile APK
apktool d target.apk -o target_decompiled

# 2. สร้าง network_security_config.xml
cat > target_decompiled/res/xml/network_security_config.xml << 'EOF'
<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
  <base-config cleartextTrafficPermitted="true">
    <trust-anchors>
      <certificates src="system" />
      <certificates src="user" />
    </trust-anchors>
  </base-config>
</network-security-config>
EOF

# 3. แก้ไข AndroidManifest.xml เพิ่ม networkSecurityConfig
# android:networkSecurityConfig="@xml/network_security_config"

# 4. Rebuild APK
apktool b target_decompiled -o target_patched.apk

# 5. Sign APK
keytool -genkey -v -keystore test.keystore -alias test -keyalg RSA -keysize 2048 -validity 365
jarsigner -verbose -sigalg SHA1withRSA -digestalg SHA1 -keystore test.keystore target_patched.apk test

# 6. Align APK
zipalign -v 4 target_patched.apk target_final.apk

# 7. Install
adb install target_final.apk
```

### mitmproxy สำหรับ Mobile Traffic Analysis
```python
#!/usr/bin/env python3
# mobile_traffic_analyzer.py (mitmproxy addon)

from mitmproxy import http
import json
import re

class MobileTrafficAnalyzer:
    def __init__(self):
        self.sensitive_patterns = [
            r'password["\']?\s*[=:]\s*["\'][^"\']+',
            r'token["\']?\s*[=:]\s*["\'][^"\']+',
            r'api[_-]?key["\']?\s*[=:]\s*["\'][^"\']+',
            r'secret["\']?\s*[=:]\s*["\'][^"\']+',
        ]
    
    def request(self, flow: http.HTTPFlow):
        req = flow.request
        
        print(f"[>] {req.method} {req.url}")
        
        # Check for HTTP (not HTTPS)
        if req.scheme == 'http' and not req.host.startswith('localhost'):
            print(f"  [!] Cleartext HTTP: {req.url}")
        
        # Check request body for sensitive data
        if req.content:
            try:
                body = req.content.decode('utf-8', errors='ignore')
                for pattern in self.sensitive_patterns:
                    matches = re.findall(pattern, body, re.IGNORECASE)
                    for match in matches:
                        print(f"  [!] Sensitive data in request: {match[:100]}")
            except:
                pass
    
    def response(self, flow: http.HTTPFlow):
        resp = flow.response
        
        if resp.status_code >= 400:
            print(f"  [!] Error response: {resp.status_code} {flow.request.url}")
        
        # Check response for sensitive data
        if resp.content:
            try:
                body = resp.content.decode('utf-8', errors='ignore')
                
                # Check for sensitive fields
                try:
                    data = json.loads(body)
                    self._check_json_sensitive(data, flow.request.url)
                except json.JSONDecodeError:
                    pass
            except:
                pass
    
    def _check_json_sensitive(self, data, url, path=''):
        if isinstance(data, dict):
            for k, v in data.items():
                sensitive_keys = ['password', 'secret', 'token', 'key', 'hash', 'salt']
                if any(s in k.lower() for s in sensitive_keys):
                    print(f"  [!] Sensitive field in response from {url}: {path}.{k}")
                self._check_json_sensitive(v, url, f"{path}.{k}")
        elif isinstance(data, list):
            for i, item in enumerate(data):
                self._check_json_sensitive(item, url, f"{path}[{i}]")

# mitmproxy addon registration
addons = [MobileTrafficAnalyzer()]

# Run: mitmproxy -s mobile_traffic_analyzer.py
```

---

## Step 255: iOS Security Testing

### iOS Testing Setup
```bash
# ต้องการ Jailbroken device
# เครื่องมือหลัก:
# - Frida, Objection
# - iProxy (SSH through USB)
# - Clutch / flexdecrypt (IPA dump)
# - r2frida

# ติดตั้ง iProxy
wget https://github.com/libimobiledevice/libusbmuxd/releases
iproxy 2222 22  # Forward SSH
ssh -p 2222 root@localhost  # เข้า SSH

# ติดตั้ง Frida บน iOS device (Cydia)
# เพิ่ม repo: https://build.frida.re
# ติดตั้ง: Frida

# Frida-ios-dump - dump decrypted IPA
git clone https://github.com/AloneMonkey/frida-ios-dump
cd frida-ios-dump
python3 dump.py -o target.ipa com.target.app

# ตรวจสอบ iOS apps
# iOS Security Toolkit
git clone https://github.com/securing/IOSSecuritySuite

# objection สำหรับ iOS
objection -N -h 127.0.0.1 -p 2222 -g com.target.app explore

# Objection commands for iOS:
ios hooking list classes
ios hooking list class_methods ClassName
ios jailbreak disable  # bypass jailbreak detection
ios sslpinning disable  # bypass SSL pinning
ios nsurlcredentialstorage dump  # dump credentials
ios keychain dump  # dump keychain
```

### IPA Static Analysis
```bash
# Extract IPA
unzip target.ipa -d ipa_extracted
cd ipa_extracted/Payload/App.app

# Strings analysis
strings App | grep -E '(password|token|api|key|secret)'

# Check binary protection
otool -hv App  # Mach-O header
otool -l App | grep -A 5 LC_ENCRYPTION  # Check if encrypted
otool -l App | grep stack_size

# ตรวจสอป binary hardening
check_binary_protections.py App

# radare2 analysis
r2 -AA App
afl  # list functions
afs?  # function info

# class-dump - dump Objective-C headers
class-dump App > App_headers.h

# Keychain analysis
objection -N -h 127.0.0.1 -p 2222 -g com.target.app explore
# In objection:
ios keychain dump
```

---

## Step 256: Mobile API Security Testing

### Mobile API ทดสอบ
```python
#!/usr/bin/env python3
# mobile_api_tester.py

import requests
import json

class MobileAPITester:
    def __init__(self, base_url, api_version='v1'):
        self.base_url = base_url
        self.api_version = api_version
        self.session = requests.Session()
        self.session.verify = False
        self.findings = []
    
    def test_token_in_url(self):
        """ตรวจสอป token ใน URL"""
        # Token ใน URL จะถูก log ใน server logs
        test_urls = [
            f'{self.base_url}/api/{self.api_version}/profile?token=SECRET_TOKEN',
            f'{self.base_url}/api/auth?access_token=TOKEN'
        ]
        
        for url in test_urls:
            resp = self.session.get(url)
            if resp.status_code == 200:
                self.findings.append({
                    'issue': 'Token in URL',
                    'url': url,
                    'severity': 'High'
                })
                print(f"[!] Token accepted in URL: {url}")
    
    def test_device_id_bypass(self):
        """ทดสอปการ bypass device binding"""
        # บาง app ผูก session กับ device ID
        test_device_ids = [
            '00000000-0000-0000-0000-000000000000',
            'FAKE-DEVICE-ID-12345',
            '',
            None
        ]
        
        for device_id in test_device_ids:
            headers = {}
            if device_id is not None:
                headers['X-Device-ID'] = device_id
            
            resp = self.session.post(
                f'{self.base_url}/api/{self.api_version}/auth',
                json={'username': 'test', 'password': 'test', 'device_id': device_id},
                headers=headers
            )
            print(f"[*] Device ID '{device_id}': {resp.status_code}")
    
    def test_version_downgrade(self):
        """ทดสอป API version downgrade"""
        versions = ['v1', 'v2', 'v3', 'v0', 'beta']
        
        for version in versions:
            resp = self.session.get(f'{self.base_url}/api/{version}/users')
            if resp.status_code not in [404, 410]:
                print(f"[!] API version {version} accessible: {resp.status_code}")
    
    def test_certificate_pinning_bypass(self):
        """ทดสอปโดยใช้ custom SSL context"""
        import ssl
        import urllib.request
        
        # Create unverified context
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        
        try:
            response = urllib.request.urlopen(
                f'{self.base_url}/api/{self.api_version}/profile',
                context=ctx
            )
            print(f"[!] SSL verification can be bypassed")
        except Exception as e:
            print(f"[-] {e}")
    
    def test_insecure_direct_object_reference(self, auth_token, valid_user_id):
        """ทดสอป IDOR"""
        headers = {'Authorization': f'Bearer {auth_token}'}
        
        for user_id in range(max(1, valid_user_id-5), valid_user_id+6):
            resp = self.session.get(
                f'{self.base_url}/api/{self.api_version}/users/{user_id}',
                headers=headers
            )
            
            if resp.status_code == 200 and user_id != valid_user_id:
                data = resp.json()
                print(f"[!] IDOR: Accessed user {user_id}: {data.get('email', 'N/A')}")

# การใช้งาน
if __name__ == '__main__':
    tester = MobileAPITester('https://api.targetapp.com')
    tester.test_token_in_url()
    tester.test_version_downgrade()
```

---

## Step 257: Root/Jailbreak Detection Bypass

### Root Detection Bypass
```javascript
// frida_root_bypass.js - Android root detection bypass

java.perform(function() {
    
    // 1. Bypass common root checks via RootBeer library
    try {
        var RootBeer = Java.use('com.scottyab.rootbeer.RootBeer');
        RootBeer.isRooted.overload().implementation = function() {
            console.log('[+] RootBeer.isRooted() bypassed');
            return false;
        };
        RootBeer.isRootedWithoutBusyBoxCheck.implementation = function() {
            return false;
        };
    } catch(e) {}
    
    // 2. Bypass file existence checks
    var File = Java.use('java.io.File');
    File.exists.implementation = function() {
        var path = this.getAbsolutePath();
        var rootFiles = ['/system/bin/su', '/system/xbin/su', '/sbin/su',
                        '/su/bin', '/system/app/Superuser.apk'];
        
        for (var i = 0; i < rootFiles.length; i++) {
            if (path.indexOf(rootFiles[i]) !== -1) {
                console.log('[+] Hiding root file: ' + path);
                return false;
            }
        }
        return this.exists();
    };
    
    // 3. Bypass Build.TAGS check
    var Build = Java.use('android.os.Build');
    Build.TAGS.value = 'release-keys';
    
    // 4. Bypass exec su command check
    var Runtime = Java.use('java.lang.Runtime');
    Runtime.exec.overload('java.lang.String').implementation = function(cmd) {
        if (cmd.indexOf('su') !== -1) {
            console.log('[+] Blocked su exec: ' + cmd);
            // Return fake process
            return this.exec('ls');  // harmless command instead
        }
        return this.exec(cmd);
    };
    
    // 5. Bypass SafetyNet (Google)
    try {
        var AttestationResult = Java.use('com.google.android.gms.safetynet.SafetyNetApi$AttestationResponse');
        AttestationResult.isSuccess.implementation = function() {
            return true;
        };
    } catch(e) {}
    
    console.log('[*] Root detection bypass complete');
});
```

---

## Step 258: Mobile App Data Storage Analysis

### Storage Security Analysis
```bash
# Android data storage locations
adb shell run-as com.target.app ls /data/data/com.target.app/
adb shell run-as com.target.app ls /data/data/com.target.app/databases/
adb shell run-as com.target.app ls /data/data/com.target.app/shared_prefs/
adb shell run-as com.target.app ls /data/data/com.target.app/files/

# Pull database files
adb shell run-as com.target.app cat /data/data/com.target.app/databases/app.db > app.db
sqlite3 app.db
.tables
SELECT * FROM users;

# Pull SharedPreferences
adb shell run-as com.target.app cat /data/data/com.target.app/shared_prefs/prefs.xml

# Automated backup
adb backup -noapk com.target.app
# Extract:
python3 android_backup.py backup.ab
```

### iOS Data Storage
```bash
# iOS Keychain dump
# Using objection:
ios keychain dump

# NSUserDefaults
ios nsuserdefaults get

# Files
ls /var/mobile/Containers/Data/Application/UUID/

# iOS filesystem exploration
ifuse /mnt/ios  # ต้อง jailbroken
ls /mnt/ios/

# Plist files
find / -name '*.plist' 2>/dev/null | grep 'com.target.app'
plutil -p target.plist  # convert to JSON
```

---

## Step 259: Mobile OWASP Top 10 Testing

### OWASP Mobile Top 10 Checklist
```python
#!/usr/bin/env python3
# owasp_mobile_checker.py

class OWASPMobileChecker:
    def __init__(self):
        self.checks = {
            'M1_ImproperCredentialUsage': [
                'Hardcoded credentials in APK/IPA',
                'Credentials stored in SharedPreferences',
                'Credentials in clear logs',
                'Weak or default credentials'
            ],
            'M2_InadequateSupplyChainSecurity': [
                'Third-party libraries not updated',
                'Malicious SDK included',
                'Build pipeline not secured'
            ],
            'M3_InsecureAuthentication': [
                'Biometric bypass possible',
                'Token not expiring',
                'No account lockout',
                'Insecure token storage'
            ],
            'M4_InsufficientInputOutputValidation': [
                'SQL injection in local database',
                'XSS via WebView',
                'Path traversal',
                'Command injection'
            ],
            'M5_InsecureCommunication': [
                'HTTP instead of HTTPS',
                'No certificate pinning',
                'Weak TLS cipher suites',
                'Certificate validation disabled'
            ],
            'M6_InadequatePrivacyControls': [
                'PII logged to logcat',
                'PII in screenshots',
                'Third-party analytics with PII',
                'Geolocation without consent'
            ],
            'M7_InsufficientBinaryProtection': [
                'App debuggable in production',
                'No code obfuscation',
                'Anti-tamper missing',
                'Root/jailbreak detection missing'
            ],
            'M8_SecurityMisconfiguration': [
                'Debug logging enabled',
                'App backup enabled',
                'Exported components with no permission',
                'Clear-text in network config'
            ],
            'M9_InsecureDataStorage': [
                'Sensitive data in external storage',
                'Unencrypted database',
                'Sensitive data in logs',
                'Credentials in shared preferences'
            ],
            'M10_InsufficientCryptography': [
                'Hardcoded encryption key',
                'Weak algorithm (MD5, SHA1, DES)',
                'ECB mode encryption',
                'Random seed from timestamp'
            ]
        }
    
    def print_checklist(self):
        for vuln_class, checks in self.checks.items():
            print(f"\n[{vuln_class}]")
            for check in checks:
                print(f"  [ ] {check}")
    
    def generate_report_template(self):
        template = "# OWASP Mobile Top 10 Assessment\n\n"
        for vuln_class, checks in self.checks.items():
            template += f"## {vuln_class}\n\n"
            template += "| Check | Status | Notes |\n"
            template += "|-------|--------|-------|\n"
            for check in checks:
                template += f"| {check} | [ ] | |\n"
            template += "\n"
        return template

# การใช้งาน
checker = OWASPMobileChecker()
checker.print_checklist()
```

---

## Step 260: Mobile Security Report

### Mobile Security Report Generator
```python
#!/usr/bin/env python3
# mobile_security_report.py

from datetime import datetime

def generate_mobile_report(app_name, platform, version, findings):
    """สร้างรายงาน Mobile Security Assessment"""
    
    report = f"""# Mobile Application Security Assessment Report

**Application:** {app_name}
**Platform:** {platform}
**Version:** {version}
**Assessment Date:** {datetime.now().strftime('%B %d, %Y')}

## Executive Summary

This report presents the findings from the security assessment of the "{app_name}" mobile application.

### Risk Summary

| Risk Level | Count |
|------------|-------|
"""
    severities = {}
    for f in findings:
        s = f.get('severity', 'Low')
        severities[s] = severities.get(s, 0) + 1
    
    for sev in ['Critical', 'High', 'Medium', 'Low', 'Info']:
        count = severities.get(sev, 0)
        report += f"| {sev} | {count} |\n"
    
    report += "\n## Findings\n"
    
    for i, finding in enumerate(findings, 1):
        report += f"""
### Finding {i}: {finding['title']}

- **Severity:** {finding.get('severity', 'Unknown')}
- **OWASP Mobile:** {finding.get('owasp', 'N/A')}
- **File/Location:** {finding.get('location', 'N/A')}

**Description:**
{finding['description']}

**Evidence:**
```
{finding.get('evidence', 'See finding details')}
```

**Recommendation:**
{finding['recommendation']}

---"""
    
    return report

# Sample
sample_findings = [
    {
        'title': 'Hardcoded API Key',
        'severity': 'Critical',
        'owasp': 'M1 - Improper Credential Usage',
        'location': 'com/target/app/api/ApiClient.java:45',
        'description': 'API key hardcoded in source code.',
        'evidence': 'private static final String API_KEY = "sk-abc123def456";',
        'recommendation': 'Store API keys in secure server-side configuration.'
    },
    {
        'title': 'No Certificate Pinning',
        'severity': 'High',
        'owasp': 'M5 - Insecure Communication',
        'location': 'AndroidManifest.xml',
        'description': 'App does not implement certificate pinning.',
        'evidence': 'Network traffic can be intercepted with a custom CA.',
        'recommendation': 'Implement certificate pinning using OkHttp CertificatePinner.'
    }
]

report = generate_mobile_report(
    app_name='TargetApp',
    platform='Android',
    version='2.5.1',
    findings=sample_findings
)

print(report)
```

---

## สรุป Part 26

| Step | หัวข้อ | เครื่องมือหลัก |
|------|--------|---------------|
| 251 | Android Setup | ADB, apktool, jadx, MobSF |
| 252 | APK Static Analysis | jadx, apktool, custom analyzer |
| 253 | Frida Dynamic Analysis | Frida, objection |
| 254 | Traffic Interception | Burp Suite, mitmproxy |
| 255 | iOS Security Testing | Frida, objection, clutch |
| 256 | Mobile API Security | Custom tester |
| 257 | Root/Jailbreak Bypass | Frida scripts |
| 258 | Data Storage Analysis | ADB, sqlite3 |
| 259 | OWASP Mobile Top 10 | Checklist framework |
| 260 | Mobile Security Report | Report generator |
