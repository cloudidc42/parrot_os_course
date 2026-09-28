# Part 58: OSINT Advanced Techniques (Steps 571-580)

## Step 571: Maltego & Link Analysis

Maltego ใช้สำหรับสร้าง entity relationship graphs เพื่อวิเคราะห์ความสัมพันธ์บุคคล/องค์กร

```python
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Set
import json
import requests
import re

@dataclass
class OSINTEntity:
    entity_type: str  # person, organization, domain, email, ip, phone
    value: str
    properties: Dict = field(default_factory=dict)
    links: List[str] = field(default_factory=list)
    source: str = ""

class OSINTGraph:
    def __init__(self):
        self.entities: Dict[str, OSINTEntity] = {}
        self.edges: List[tuple] = []
    
    def add_entity(self, entity: OSINTEntity):
        self.entities[entity.value] = entity
    
    def add_relationship(self, from_entity: str, to_entity: str, 
                          relationship_type: str):
        self.edges.append((from_entity, to_entity, relationship_type))
    
    def get_connections(self, entity_value: str) -> List[tuple]:
        return [(f, t, r) for f, t, r in self.edges 
                if f == entity_value or t == entity_value]
    
    def export_to_json(self) -> dict:
        return {
            "entities": {
                k: {
                    "type": v.entity_type,
                    "value": v.value,
                    "properties": v.properties,
                    "source": v.source
                } for k, v in self.entities.items()
            },
            "edges": [
                {"from": f, "to": t, "type": r} 
                for f, t, r in self.edges
            ]
        }
    
    def find_pivot_points(self) -> List[str]:
        """Find entities with most connections"""
        connection_count = {}
        for f, t, _ in self.edges:
            connection_count[f] = connection_count.get(f, 0) + 1
            connection_count[t] = connection_count.get(t, 0) + 1
        
        return sorted(connection_count.keys(), 
                      key=lambda x: connection_count[x], reverse=True)[:10]

class AdvancedOSINT:
    def __init__(self):
        self.graph = OSINTGraph()
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
    
    def enumerate_domain(self, domain: str) -> dict:
        """Comprehensive domain enumeration"""
        results = {
            "domain": domain,
            "subdomains": [],
            "emails": [],
            "technologies": [],
            "related_domains": []
        }
        
        # หา subdomains ผ่าน Certificate Transparency
        ct_url = f"https://crt.sh/?q=%.{domain}&output=json"
        try:
            r = self.session.get(ct_url, timeout=10)
            if r.status_code == 200:
                certs = r.json()
                subdomains = set()
                for cert in certs:
                    name = cert.get('name_value', '')
                    for sub in name.split('\n'):
                        sub = sub.strip().lstrip('*.')
                        if domain in sub and sub not in subdomains:
                            subdomains.add(sub)
                            results["subdomains"].append(sub)
        except Exception as e:
            print(f"[-] crt.sh error: {e}")
        
        # Entity เพิ่มใน graph
        domain_entity = OSINTEntity(
            entity_type="domain",
            value=domain,
            properties={"subdomains_count": len(results["subdomains"])},
            source="crt.sh"
        )
        self.graph.add_entity(domain_entity)
        
        for sub in results["subdomains"]:
            sub_entity = OSINTEntity(
                entity_type="subdomain",
                value=sub,
                source="crt.sh"
            )
            self.graph.add_entity(sub_entity)
            self.graph.add_relationship(domain, sub, "has_subdomain")
        
        return results
    
    def search_hunter_io(self, domain: str, api_key: str) -> List[dict]:
        """Hunter.io email discovery"""
        url = f"https://api.hunter.io/v2/domain-search"
        params = {
            "domain": domain,
            "api_key": api_key,
            "limit": 100
        }
        
        try:
            r = self.session.get(url, params=params)
            data = r.json()
            
            emails = []
            for email_data in data.get('data', {}).get('emails', []):
                email_info = {
                    "email": email_data.get('value'),
                    "first_name": email_data.get('first_name'),
                    "last_name": email_data.get('last_name'),
                    "position": email_data.get('position'),
                    "confidence": email_data.get('confidence')
                }
                emails.append(email_info)
                
                # Add to graph
                email_entity = OSINTEntity(
                    entity_type="email",
                    value=email_info["email"],
                    properties=email_info,
                    source="hunter.io"
                )
                self.graph.add_entity(email_entity)
                self.graph.add_relationship(domain, email_info["email"], "has_email")
            
            return emails
        except Exception as e:
            return [{"error": str(e)}]
    
    def reverse_image_search(self, image_url: str) -> dict:
        """Reverse image search via multiple engines"""
        return {
            "google_reverse": f"https://images.google.com/searchbyimage?image_url={image_url}",
            "tineye": f"https://tineye.com/search?url={image_url}",
            "yandex": f"https://yandex.com/images/search?url={image_url}&rpt=imageview",
            "bing_visual": f"https://www.bing.com/images/search?q=imgurl:{image_url}&view=detailv2"
        }
    
    def phone_number_osint(self, phone: str) -> dict:
        """OSINT สำหรับ phone number"""
        # Format normalization
        phone_clean = re.sub(r'[^0-9+]', '', phone)
        
        resources = {
            "truecaller": f"https://www.truecaller.com/search/{phone_clean}",
            "sync_me": f"https://sync.me/search/?number={phone_clean}",
            "eyecon": f"https://www.eyecon.com/",
            "numverify": "API: http://apilayer.net/api/validate?number={phone_clean}",
            "opencnam": "API: https://api.opencnam.com/v3/phone/{phone_clean}",
            "verispy": f"https://www.verispy.com/search?q={phone_clean}"
        }
        
        # Carrier lookup via number prefix
        area_code = phone_clean[:3] if len(phone_clean) >= 3 else ""
        
        return {
            "phone": phone_clean,
            "area_code": area_code,
            "lookup_resources": resources,
            "social_search": [
                f"Facebook search: site:facebook.com {phone_clean}",
                f"LinkedIn search: site:linkedin.com {phone_clean}",
                f"Google dork: \"{phone_clean}\" site:linkedin.com"
            ]
        }

if __name__ == '__main__':
    osint = AdvancedOSINT()
    
    # Domain enumeration
    results = osint.enumerate_domain("example.com")
    print(f"[*] Found {len(results['subdomains'])} subdomains")
    
    # Graph analysis
    pivots = osint.graph.find_pivot_points()
    print(f"[*] Pivot points: {pivots[:5]}")
    
    graph_data = osint.graph.export_to_json()
    print(f"[*] Graph: {len(graph_data['entities'])} entities, {len(graph_data['edges'])} edges")
```

## Step 572: Dark Web OSINT

การหาข้อมูลบน Dark Web อย่างถูกต้องและปลอดภัย

```python
import requests
import json
from typing import List, Dict

class DarkWebOSINT:
    """Dark Web intelligence gathering tools (requires Tor)"""
    
    def __init__(self, tor_proxy: str = "socks5h://127.0.0.1:9050"):
        self.session = requests.Session()
        self.session.proxies = {
            'http': tor_proxy,
            'https': tor_proxy
        }
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/115.0'
        })
    
    def check_tor_connection(self) -> bool:
        """Verify Tor is working"""
        try:
            r = self.session.get('http://check.torproject.org/', timeout=30)
            return 'Congratulations' in r.text
        except:
            return False
    
    def search_ahmia(self, query: str) -> List[dict]:
        """Search Ahmia.fi dark web search engine"""
        url = f"http://juhanurmihxlp77nkq76byazcldy2hlmovfu2epvl5ankdibsot4csyd.onion/search/?q={query}"
        results = []
        
        try:
            r = self.session.get(url, timeout=30)
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(r.text, 'html.parser')
            
            for result in soup.find_all('li', class_='result'):
                title_elem = result.find('h4')
                url_elem = result.find('cite')
                desc_elem = result.find('p')
                
                if title_elem and url_elem:
                    results.append({
                        'title': title_elem.text.strip(),
                        'url': url_elem.text.strip(),
                        'description': desc_elem.text.strip() if desc_elem else ''
                    })
        except Exception as e:
            print(f"[-] Ahmia search error: {e}")
        
        return results
    
    def check_paste_sites(self, search_terms: List[str]) -> List[dict]:
        """Check paste sites for leaked credentials/data"""
        paste_sites = [
            "https://pastebin.com",
            "https://paste.ee",
            "https://ghostbin.com",
            "https://privatebin.net"
        ]
        
        results = []
        for term in search_terms:
            for site in paste_sites:
                search_url = f"https://www.google.com/search?q=site:{site.replace('https://', '')}+\"{term}\""
                results.append({
                    "search_term": term,
                    "search_url": search_url,
                    "note": f"Check Google: site:{site} \"{{term}}\""
                })
        
        return results
    
    def monitor_breach_databases(self, email: str, api_key: str = None) -> dict:
        """Check HIBP and other breach databases"""
        results = {
            "email": email,
            "breaches": [],
            "pastes": [],
            "last_checked": None
        }
        
        # Have I Been Pwned
        headers = {"hibp-api-key": api_key} if api_key else {}
        headers["User-Agent"] = "OSINTResearch"
        
        try:
            r = requests.get(
                f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}",
                headers=headers,
                timeout=10
            )
            if r.status_code == 200:
                breaches = r.json()
                for breach in breaches:
                    results["breaches"].append({
                        "name": breach.get('Name'),
                        "domain": breach.get('Domain'),
                        "date": breach.get('BreachDate'),
                        "pwn_count": breach.get('PwnCount'),
                        "data_classes": breach.get('DataClasses', [])
                    })
            elif r.status_code == 404:
                results["note"] = "No breaches found"
        except Exception as e:
            results["error"] = str(e)
        
        return results
    
    def search_leaked_credentials(self, domain: str) -> dict:
        """Search for leaked credentials via multiple sources"""
        return {
            "domain": domain,
            "search_queries": [
                f'site:pastebin.com "{domain}" password',
                f'site:github.com "{domain}" password',
                f'site:trello.com "{domain}"',
                f'"{domain}" credentials filetype:txt',
                f'"{domain}" config.php site:github.com',
                f'"{domain}" .env site:github.com'
            ],
            "services": {
                "dehashed": "https://dehashed.com - leaked credential search",
                "leakcheck": "https://leakcheck.io - breach data",
                "snusbase": "https://snusbase.com - database leaks",
                "intelx": "https://intelx.io - paste/dark web search"
            },
            "breach_databases": [
                "Collection 1-5 (87GB)",
                "RockYou2021 (8.4B passwords)",
                "Anti-Public Combo List",
                "LinkedIn breach (117M)",
                "Facebook scrape (533M)"
            ]
        }
    
    def find_company_on_darkweb(self, company_name: str) -> dict:
        """Search for company mentions on dark web markets/forums"""
        search_queries = [
            f"{company_name} database",
            f"{company_name} breach",
            f"{company_name} credentials",
            f"{company_name} access",
            f"{company_name} rdp",
            f"{company_name} vpn"
        ]
        
        return {
            "company": company_name,
            "search_queries": search_queries,
            "dark_web_markets": [
                "AlphaBay (marketplace)",
                "RAMP (ransomware forum)",
                "XSS.is (Russian hacker forum)",
                "Exploit.in (credential marketplace)",
                "Telegram channels: @combolist, @credleaks"
            ],
            "monitoring_tools": [
                "DarkOwl - automated dark web monitoring",
                "Recorded Future - threat intelligence platform",
                "Flashpoint - cybercrime intelligence",
                "Intel471 - underground monitoring"
            ]
        }

if __name__ == '__main__':
    dwosint = DarkWebOSINT()
    
    # Check Tor
    if dwosint.check_tor_connection():
        print("[+] Tor connected")
    else:
        print("[-] Tor not connected - install: sudo apt install tor && tor &")
    
    # Check breaches
    breach_data = dwosint.monitor_breach_databases("target@example.com")
    print(f"[*] Breaches found: {len(breach_data['breaches'])}")
    
    # Search leaked creds
    leaks = dwosint.search_leaked_credentials("example.com")
    for query in leaks["search_queries"]:
        print(f"[*] Google: {query}")
```

## Step 573: Shodan & IoT Intelligence

Shodan คือ search engine สำหรับ Internet-connected devices

```python
import shodan
import json
from dataclasses import dataclass
from typing import List

@dataclass
class ShodanResult:
    ip: str
    port: int
    banner: str
    org: str
    country: str
    os: str
    vulns: List[str]
    tags: List[str]

class ShodanIntelligence:
    def __init__(self, api_key: str):
        self.api = shodan.Shodan(api_key)
    
    def search_organization(self, org_name: str) -> List[ShodanResult]:
        """Find all internet-facing assets of an organization"""
        results = []
        try:
            query = f'org:"{org_name}"'
            response = self.api.search(query, limit=100)
            
            for match in response['matches']:
                result = ShodanResult(
                    ip=match.get('ip_str', ''),
                    port=match.get('port', 0),
                    banner=match.get('data', '')[:200],
                    org=match.get('org', ''),
                    country=match.get('location', {}).get('country_name', ''),
                    os=match.get('os', 'Unknown'),
                    vulns=list(match.get('vulns', {}).keys()),
                    tags=match.get('tags', [])
                )
                results.append(result)
                
        except shodan.APIError as e:
            print(f"[-] Shodan error: {e}")
        
        return results
    
    def search_vulnerable_assets(self, query: str) -> List[dict]:
        """Search for specific vulnerabilities across the internet"""
        vulnerability_queries = {
            "log4shell": 'vuln:CVE-2021-44228',
            "eternalblue": 'vuln:CVE-2017-0144',
            "default_creds": 'default password http.title:"admin"',
            "open_rdp": 'port:3389 os:"Windows"',
            "exposed_elasticsearch": 'product:"Elastic" port:9200',
            "open_mongodb": 'product:"MongoDB" port:27017',
            "exposed_redis": 'port:6379 product:"Redis"',
            "open_docker": 'port:2375 product:"Docker"',
            "citrix_vuln": 'vuln:CVE-2019-19781',
            "pulse_vpn": 'product:"Pulse Secure" vuln:CVE-2019-11510'
        }
        
        results = []
        if query in vulnerability_queries:
            actual_query = vulnerability_queries[query]
        else:
            actual_query = query
        
        try:
            response = self.api.search(actual_query, limit=50)
            for match in response['matches']:
                results.append({
                    "ip": match.get('ip_str'),
                    "port": match.get('port'),
                    "org": match.get('org', 'Unknown'),
                    "country": match.get('location', {}).get('country_name', ''),
                    "vulns": list(match.get('vulns', {}).keys()),
                    "timestamp": match.get('timestamp')
                })
        except shodan.APIError as e:
            print(f"[-] Error: {e}")
        
        return results
    
    def get_host_details(self, ip: str) -> dict:
        """Get comprehensive info about a specific IP"""
        try:
            host = self.api.host(ip)
            return {
                "ip": ip,
                "hostnames": host.get('hostnames', []),
                "domains": host.get('domains', []),
                "org": host.get('org', ''),
                "isp": host.get('isp', ''),
                "asn": host.get('asn', ''),
                "country": host.get('country_name', ''),
                "city": host.get('city', ''),
                "ports": host.get('ports', []),
                "vulns": list(host.get('vulns', {}).keys()),
                "tags": host.get('tags', []),
                "os": host.get('os', 'Unknown'),
                "services": [
                    {
                        "port": svc.get('port'),
                        "product": svc.get('product', ''),
                        "version": svc.get('version', ''),
                        "banner": svc.get('data', '')[:100]
                    }
                    for svc in host.get('data', [])
                ]
            }
        except shodan.APIError as e:
            return {"error": str(e)}
    
    def monitor_network_range(self, cidr: str) -> List[dict]:
        """Monitor entire network range"""
        try:
            results = list(self.api.search_cursor(f'net:{cidr}'))
            return [{
                "ip": r.get('ip_str'),
                "port": r.get('port'),
                "product": r.get('product', ''),
                "vulns": list(r.get('vulns', {}).keys())
            } for r in results]
        except shodan.APIError as e:
            return [{"error": str(e)}]
    
    def generate_attack_surface_report(self, org_name: str) -> dict:
        """Generate attack surface report for organization"""
        assets = self.search_organization(org_name)
        
        report = {
            "organization": org_name,
            "total_exposed_assets": len(assets),
            "vulnerable_assets": [a for a in assets if a.vulns],
            "exposed_services": {},
            "geographic_distribution": {},
            "risk_summary": {
                "critical": 0,
                "high": 0,
                "medium": 0
            }
        }
        
        # Count services by port
        for asset in assets:
            port_str = str(asset.port)
            report["exposed_services"][port_str] = report["exposed_services"].get(port_str, 0) + 1
            
            country = asset.country
            report["geographic_distribution"][country] = report["geographic_distribution"].get(country, 0) + 1
            
            if asset.vulns:
                report["risk_summary"]["critical"] += 1
        
        return report


class ShodanDorkLibrary:
    """Collection of useful Shodan dorks"""
    
    @staticmethod
    def get_dorks() -> Dict[str, List[str]]:
        return {
            "industrial_control": [
                'product:"Siemens S7" port:102',
                'port:102 Siemens',
                'product:"Allen-Bradley" port:44818',
                'port:20000 DNP3',
                'port:502 Modbus'
            ],
            "cameras": [
                'http.title:"Network Camera"',
                'http.title:"webcamXP"',
                'product:"Axis" http.title:"Camera"',
                'port:554 RTSP "live.sdp"',
                'http.favicon.hash:1602430775'
            ],
            "routers": [
                'http.title:"RouterOS" port:8291',
                'product:"Cisco IOS" port:23',
                'http.html:"Netgear" port:80',
                'product:"MikroTik"'
            ],
            "databases": [
                'port:27017 product:MongoDB -authentication',
                'port:6379 product:Redis -authentication',
                'port:9200 product:Elasticsearch',
                'port:5432 product:PostgreSQL',
                'port:3306 product:MySQL'
            ],
            "cloud_misconfig": [
                'http.title:"Index of /" amazonaws.com',
                'http.title:"Grafana" port:3000',
                'http.title:"Kibana" port:5601',
                'product:"Kubernetes" port:8001',
                'http.title:"Docker"'
            ]
        }

if __name__ == '__main__':
    # shodan_api = ShodanIntelligence("YOUR_API_KEY")
    
    dorks = ShodanDorkLibrary.get_dorks()
    print("[*] Shodan Dork Categories:")
    for category, queries in dorks.items():
        print(f"\n  {category}:")
        for q in queries[:2]:
            print(f"    {q}")
```

## Step 574: Social Media Intelligence (SOCMINT)

เทคนิคการเก็บข้อมูลจาก social media platforms

```python
import requests
from bs4 import BeautifulSoup
import json
import re
from typing import List, Dict

class SOCMINTCollector:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
    
    def search_twitter_advanced(self, query: str, 
                                  filters: dict = None) -> List[dict]:
        """Twitter/X advanced search dorks"""
        advanced_queries = [
            f"{query} filter:links",           # เฉพาะ tweets ที่มี links
            f"{query} filter:images",          # เฉพาะ tweets ที่มี images
            f"{query} since:2024-01-01",       # หลังจากวันที่
            f"{query} -filter:retweets",      # Original tweets only
            f"from:{query}",                   # Tweets from specific user
            f"to:{query}",                     # Tweets to specific user  
            f"@{query}"                         # Mentions
        ]
        
        return [
            {"query": q, "search_url": f"https://twitter.com/search?q={q}"}
            for q in advanced_queries
        ]
    
    def check_username_across_platforms(self, username: str) -> dict:
        """Check if username exists across multiple platforms"""
        platforms = {
            "twitter": f"https://twitter.com/{username}",
            "github": f"https://github.com/{username}",
            "instagram": f"https://www.instagram.com/{username}/",
            "reddit": f"https://www.reddit.com/user/{username}",
            "linkedin": f"https://www.linkedin.com/in/{username}",
            "facebook": f"https://www.facebook.com/{username}",
            "youtube": f"https://www.youtube.com/@{username}",
            "tiktok": f"https://www.tiktok.com/@{username}",
            "snapchat": f"https://www.snapchat.com/add/{username}",
            "pinterest": f"https://www.pinterest.com/{username}",
            "tumblr": f"https://{username}.tumblr.com",
            "medium": f"https://medium.com/@{username}",
            "telegram": f"https://t.me/{username}",
            "discord": f"Check manually on Discord",
            "pastebin": f"https://pastebin.com/u/{username}",
            "hackerone": f"https://hackerone.com/{username}",
            "bugcrowd": f"https://bugcrowd.com/{username}"
        }
        
        results = {"username": username, "found": {}, "not_found": {}}
        
        for platform, url in platforms.items():
            if url.startswith("Check"):
                results["found"][platform] = {"url": url, "note": url}
                continue
            
            try:
                r = self.session.get(url, timeout=5, allow_redirects=True)
                if r.status_code == 200 and username.lower() in r.url.lower():
                    results["found"][platform] = {"url": url, "status": r.status_code}
                else:
                    results["not_found"][platform] = url
            except:
                results["not_found"][platform] = url
        
        return results
    
    def extract_metadata_from_image(self, image_path: str) -> dict:
        """Extract EXIF metadata from image"""
        try:
            from PIL import Image
            from PIL.ExifTags import TAGS, GPSTAGS
            
            img = Image.open(image_path)
            exif_data = img._getexif()
            
            if not exif_data:
                return {"error": "No EXIF data found"}
            
            metadata = {}
            gps_data = {}
            
            for tag_id, value in exif_data.items():
                tag = TAGS.get(tag_id, tag_id)
                if tag == 'GPSInfo':
                    for gps_tag_id, gps_value in value.items():
                        gps_tag = GPSTAGS.get(gps_tag_id, gps_tag_id)
                        gps_data[gps_tag] = gps_value
                else:
                    metadata[str(tag)] = str(value)[:100]
            
            # Convert GPS to decimal coordinates
            if gps_data:
                def convert_to_degrees(value):
                    d, m, s = value
                    return float(d) + float(m)/60 + float(s)/3600
                
                if 'GPSLatitude' in gps_data:
                    lat = convert_to_degrees(gps_data['GPSLatitude'])
                    if gps_data.get('GPSLatitudeRef') == 'S':
                        lat = -lat
                    lon = convert_to_degrees(gps_data['GPSLongitude'])
                    if gps_data.get('GPSLongitudeRef') == 'W':
                        lon = -lon
                    
                    metadata['GPS_Coordinates'] = f"{lat}, {lon}"
                    metadata['Google_Maps'] = f"https://maps.google.com/?q={lat},{lon}"
            
            return metadata
        except Exception as e:
            return {"error": str(e)}
    
    def analyze_writing_style(self, texts: List[str]) -> dict:
        """Analyze writing patterns for attribution"""
        combined = ' '.join(texts)
        words = combined.lower().split()
        
        # คำนวน word frequency
        word_freq = {}
        for word in words:
            word_freq[word] = word_freq.get(word, 0) + 1
        
        # Top words
        top_words = sorted(word_freq.items(), key=lambda x: x[1], reverse=True)[:20]
        
        # Punctuation patterns
        punct_patterns = {
            "uses_oxford_comma": bool(re.search(r',\s*and\s', combined)),
            "uses_em_dash": '--' in combined or '\u2014' in combined,
            "uses_ellipsis": '...' in combined,
            "capitalizes_internet": 'Internet' in combined,
        }
        
        return {
            "total_words": len(words),
            "unique_words": len(word_freq),
            "vocabulary_richness": len(word_freq) / len(words) if words else 0,
            "avg_sentence_length": len(words) / max(combined.count('.'), 1),
            "top_words": top_words[:10],
            "punctuation_patterns": punct_patterns
        }
    
    def geolocation_from_post(self, post_text: str, 
                               post_image_url: str = None) -> dict:
        """Extract geolocation clues from social media post"""
        geoclues = {
            "explicit_mentions": [],
            "implicit_clues": [],
            "time_zone_hints": [],
            "language_indicators": []
        }
        
        # Location name patterns
        location_patterns = [
            r'\b([A-Z][a-z]+,\s*[A-Z]{2})\b',  # City, State
            r'\b(downtown|uptown|manhattan|brooklyn)\b',
            r'#([A-Z][a-z]+(?:City|Town|burg|ville))'
        ]
        
        for pattern in location_patterns:
            matches = re.findall(pattern, post_text, re.IGNORECASE)
            geoclues["explicit_mentions"].extend(matches)
        
        # Time zone hints
        if re.search(r'\b(AM|PM)\b', post_text):
            geoclues["time_zone_hints"].append("12-hour clock (US/UK style)")
        
        # Weather clues
        if any(word in post_text.lower() for word in ['snow', 'celsius', 'fahrenheit', 'tornado']):
            geoclues["implicit_clues"].append("Weather reference found")
        
        return geoclues

if __name__ == '__main__':
    collector = SOCMINTCollector()
    
    # Username enumeration
    username_results = collector.check_username_across_platforms("johndoe")
    print(f"[*] Checking username 'johndoe' across {len(username_results['found'])} platforms found")
    
    for platform, data in username_results['found'].items():
        print(f"    [+] {platform}: {data.get('url', '')[:50]}")
```

## Step 575: Google Dorking Advanced

Google Dorks ขั้นสูงสำหรับค้นหาข้อมูล sensitive

```python
from dataclasses import dataclass
from typing import List, Dict

@dataclass
class GoogleDork:
    category: str
    dork: str
    description: str
    risk_level: str

class GoogleDorkLibrary:
    def get_all_dorks(self, target_domain: str = "example.com") -> Dict[str, List[GoogleDork]]:
        """รวบรวม Google Dorks แยกตามหมวดหมู่"""
        d = target_domain
        
        return {
            "sensitive_files": [
                GoogleDork("files", f'site:{d} ext:sql', "SQL dump files", "Critical"),
                GoogleDork("files", f'site:{d} ext:env', ".env configuration files", "Critical"),
                GoogleDork("files", f'site:{d} ext:bak', "Backup files", "High"),
                GoogleDork("files", f'site:{d} ext:log', "Log files", "High"),
                GoogleDork("files", f'site:{d} ext:conf OR ext:config', "Config files", "High"),
                GoogleDork("files", f'site:{d} ext:xml inurl:config', "XML config files", "Medium"),
                GoogleDork("files", f'site:{d} filetype:xls site:{d} username', "Excel with usernames", "High"),
                GoogleDork("files", f'site:{d} filetype:pdf confidential', "Confidential PDFs", "Medium"),
            ],
            "credentials": [
                GoogleDork("creds", f'site:{d} intext:password filetype:txt', "Text files with passwords", "Critical"),
                GoogleDork("creds", f'site:{d} inurl:wp-config.php', "WordPress config", "Critical"),
                GoogleDork("creds", f'site:{d} intext:"api_key" OR intext:"api key" filetype:txt', "API keys", "Critical"),
                GoogleDork("creds", f'site:{d} intext:"BEGIN RSA PRIVATE KEY"', "Private keys", "Critical"),
                GoogleDork("creds", f'site:{d} intext:"aws_access_key_id"', "AWS credentials", "Critical"),
            ],
            "admin_portals": [
                GoogleDork("admin", f'site:{d} inurl:admin', "Admin panels", "High"),
                GoogleDork("admin", f'site:{d} inurl:login', "Login pages", "Medium"),
                GoogleDork("admin", f'site:{d} inurl:phpmyadmin', "phpMyAdmin", "Critical"),
                GoogleDork("admin", f'site:{d} intitle:"phpMyAdmin"', "phpMyAdmin interfaces", "Critical"),
                GoogleDork("admin", f'site:{d} inurl:wp-admin', "WordPress admin", "High"),
                GoogleDork("admin", f'site:{d} intitle:"Tomcat Manager"', "Tomcat manager", "High"),
            ],
            "exposed_directories": [
                GoogleDork("dirs", f'site:{d} intitle:"Index of /"', "Open directory listings", "High"),
                GoogleDork("dirs", f'site:{d} intitle:"Index of" inurl:backup', "Backup directories", "Critical"),
                GoogleDork("dirs", f'site:{d} intitle:"Index of /" inurl:git', "Git directories", "Critical"),
                GoogleDork("dirs", f'site:{d} intitle:"Index of" passwd', "Passwd exposed", "Critical"),
            ],
            "error_messages": [
                GoogleDork("errors", f'site:{d} "SQL syntax" OR "mysql_fetch"', "SQL errors", "High"),
                GoogleDork("errors", f'site:{d} "Warning: mysql" OR "Warning: pg_"', "DB errors", "High"),
                GoogleDork("errors", f'site:{d} intitle:"Error 500"', "Server errors", "Medium"),
                GoogleDork("errors", f'site:{d} "Traceback" "Python" OR "Django"', "Python tracebacks", "Medium"),
            ],
            "cloud_storage": [
                GoogleDork("cloud", f'site:s3.amazonaws.com "{d}"', "S3 bucket references", "High"),
                GoogleDork("cloud", f'site:blob.core.windows.net "{d}"', "Azure blob storage", "High"),
                GoogleDork("cloud", f'site:storage.googleapis.com "{d}"', "GCS buckets", "High"),
                GoogleDork("cloud", f'"s3.amazonaws.com" site:{d}', "S3 references in site", "High"),
            ],
            "github_code": [
                GoogleDork("github", f'site:github.com "{d}" password', "Password in GitHub", "Critical"),
                GoogleDork("github", f'site:github.com "{d}" api_key', "API key in GitHub", "Critical"),
                GoogleDork("github", f'site:github.com "{d}" secret', "Secrets in GitHub", "Critical"),
                GoogleDork("github", f'site:github.com "{d}" token', "Tokens in GitHub", "Critical"),
            ]
        }
    
    def generate_dork_report(self, domain: str) -> str:
        """Generate formatted dork report"""
        all_dorks = self.get_all_dorks(domain)
        
        report = f"Google Dork Report for {domain}\n"
        report += "=" * 50 + "\n\n"
        
        for category, dorks in all_dorks.items():
            report += f"\n## {category.upper()}\n"
            report += "-" * 40 + "\n"
            for dork in dorks:
                report += f"[{dork.risk_level}] {dork.description}\n"
                report += f"  Query: {dork.dork}\n"
                report += f"  URL: https://www.google.com/search?q={dork.dork}\n\n"
        
        return report

if __name__ == '__main__':
    library = GoogleDorkLibrary()
    report = library.generate_dork_report("targetcorp.com")
    print(report[:2000])
    print(f"\n[*] Full report would cover all dork categories")
```

## Step 576: Recon-ng Framework

Recon-ng เป็น framework สำหรับ automated OSINT

```python
import subprocess
import os
from pathlib import Path

class ReconNGAutomation:
    def __init__(self):
        self.recon_path = "/usr/bin/recon-ng"
    
    def run_recon_script(self, target_domain: str) -> str:
        """Generate recon-ng automation script"""
        script = f"""
# Recon-ng Automation Script for {target_domain}
# Run: recon-ng < recon_script.txt

workspaces create {target_domain.replace('.', '_')}
workspaces select {target_domain.replace('.', '_')}

# Add target
db insert domains
{target_domain}

# Load and run modules
modules load recon/domains-hosts/hackertarget
run

modules load recon/domains-hosts/dns_brute
set WILDCARD_DOMAINS True
run

modules load recon/hosts-hosts/resolve
run

modules load recon/domains-contacts/whois_pocs
run

modules load recon/contacts-contacts/mailtester
run

modules load recon/domains-credentials/pwnedlist_domain
run

modules load recon/hosts-ports/shodan_ip
set SOURCE hosts
run

# Harvest email addresses
modules load recon/domains-contacts/pgp_search
run

modules load recon/domains-contacts/metacrawler
run

# Report
modules load reporting/html
set FILENAME /tmp/{target_domain}_report.html
run

modules load reporting/json
set FILENAME /tmp/{target_domain}_data.json  
run

show hosts
show contacts
show credentials
        """
        return script
    
    def run_theHarvester(self, domain: str, sources: List[str] = None) -> str:
        """Run theHarvester for email/subdomain harvesting"""
        if sources is None:
            sources = ["google", "bing", "linkedin", "twitter", "github"]
        
        commands = []
        for source in sources:
            cmd = f"theHarvester -d {domain} -b {source} -l 500"
            commands.append(cmd)
        
        # Full combined command
        all_sources = ','.join(sources)
        full_cmd = f"theHarvester -d {domain} -b {all_sources} -l 500 -f /tmp/{domain}_harvest"
        
        return {
            "individual_commands": commands,
            "combined_command": full_cmd,
            "output_files": [
                f"/tmp/{domain}_harvest.xml",
                f"/tmp/{domain}_harvest.json"
            ]
        }
    
    def run_spiderfoot(self, target: str, scan_type: str = "all") -> dict:
        """SpiderFoot automated OSINT"""
        scan_modules = {
            "passive": ["sfp_dns", "sfp_whois", "sfp_shodan", "sfp_certspotter"],
            "osint": ["sfp_linkedin", "sfp_twitter", "sfp_instagram", "sfp_github"],
            "darkweb": ["sfp_darkweb", "sfp_breach", "sfp_pastebin"],
            "all": "All modules (comprehensive scan)"
        }
        
        return {
            "target": target,
            "scan_type": scan_type,
            "modules": scan_modules.get(scan_type, []),
            "command": f"python3 sf.py -s {target} -t {target} -m sfp_all -o /tmp/{target}_spiderfoot.json",
            "web_ui": "python3 sf.py -l 127.0.0.1:5001 (then browse to http://127.0.0.1:5001)"
        }

if __name__ == '__main__':
    recon = ReconNGAutomation()
    
    script = recon.run_recon_script("targetcorp.com")
    print("[*] Recon-ng Script Generated:")
    print(script[:500])
    
    harvest_cmds = recon.run_theHarvester("targetcorp.com")
    print(f"\n[*] theHarvester combined: {harvest_cmds['combined_command']}")
    
    sf_config = recon.run_spiderfoot("targetcorp.com", "all")
    print(f"[*] SpiderFoot: {sf_config['command']}")
```

## Step 577-580: Comprehensive OSINT Automation Framework

```python
import asyncio
import aiohttp
import json
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Optional
import hashlib
import time

@dataclass
class OSINTTarget:
    name: str
    domain: str
    email: str = ""
    ip: str = ""
    organization: str = ""
    person_name: str = ""

@dataclass 
class OSINTReport:
    target: OSINTTarget
    subdomains: List[str] = field(default_factory=list)
    emails: List[str] = field(default_factory=list)
    ips: List[str] = field(default_factory=list)
    ports: List[dict] = field(default_factory=list)
    technologies: List[str] = field(default_factory=list)
    breaches: List[str] = field(default_factory=list)
    social_profiles: Dict[str, str] = field(default_factory=dict)
    github_repos: List[str] = field(default_factory=list)
    leaked_credentials: List[dict] = field(default_factory=list)
    whois_data: dict = field(default_factory=dict)
    dns_records: dict = field(default_factory=dict)
    vulnerabilities: List[str] = field(default_factory=list)

class ComprehensiveOSINT:
    def __init__(self):
        self.rate_limit_delay = 1.0
    
    async def run_full_recon(self, target: OSINTTarget) -> OSINTReport:
        """Full automated OSINT reconnaissance"""
        report = OSINTReport(target=target)
        
        print(f"[*] Starting OSINT for {target.domain}")
        
        # Phase 1: DNS
        await self._enumerate_dns(target.domain, report)
        await asyncio.sleep(self.rate_limit_delay)
        
        # Phase 2: Certificate Transparency
        await self._ct_log_search(target.domain, report)
        await asyncio.sleep(self.rate_limit_delay)
        
        # Phase 3: WHOIS
        await self._whois_lookup(target.domain, report)
        await asyncio.sleep(self.rate_limit_delay)
        
        # Phase 4: Technology stack
        await self._detect_technologies(target.domain, report)
        
        print(f"[+] Recon complete: {len(report.subdomains)} subdomains, "
              f"{len(report.emails)} emails, {len(report.ips)} IPs found")
        
        return report
    
    async def _enumerate_dns(self, domain: str, report: OSINTReport):
        """DNS enumeration"""
        import dns.resolver
        
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']
        dns_results = {}
        
        for rtype in record_types:
            try:
                answers = dns.resolver.resolve(domain, rtype)
                dns_results[rtype] = [str(r) for r in answers]
                
                if rtype == 'A':
                    for r in answers:
                        if str(r) not in report.ips:
                            report.ips.append(str(r))
            except:
                pass
        
        report.dns_records = dns_results
    
    async def _ct_log_search(self, domain: str, report: OSINTReport):
        """Search Certificate Transparency logs"""
        async with aiohttp.ClientSession() as session:
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            try:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=15)) as r:
                    if r.status == 200:
                        certs = await r.json(content_type=None)
                        for cert in certs:
                            name = cert.get('name_value', '')
                            for sub in name.split('\n'):
                                sub = sub.strip().lstrip('*.')
                                if domain in sub and sub not in report.subdomains:
                                    report.subdomains.append(sub)
            except:
                pass
    
    async def _whois_lookup(self, domain: str, report: OSINTReport):
        """WHOIS data collection"""
        try:
            import whois
            w = whois.whois(domain)
            report.whois_data = {
                "registrar": str(w.registrar),
                "creation_date": str(w.creation_date),
                "expiration_date": str(w.expiration_date),
                "name_servers": w.name_servers,
                "emails": w.emails if isinstance(w.emails, list) else [w.emails] if w.emails else []
            }
            if report.whois_data["emails"]:
                report.emails.extend([e for e in report.whois_data["emails"] 
                                       if e and e not in report.emails])
        except:
            pass
    
    async def _detect_technologies(self, domain: str, report: OSINTReport):
        """Technology stack detection"""
        async with aiohttp.ClientSession() as session:
            try:
                async with session.get(f"https://{domain}", 
                                        timeout=aiohttp.ClientTimeout(total=10)) as r:
                    headers = dict(r.headers)
                    text = await r.text()
                    
                    tech_signatures = {
                        "WordPress": "wp-content",
                        "Drupal": "Drupal.settings",
                        "Joomla": "joomla",
                        "Django": "csrfmiddlewaretoken",
                        "Laravel": "laravel_session",
                        "ASP.NET": "__VIEWSTATE",
                        "PHP": ".php",
                        "React": "__REACT_DEVTOOLS",
                        "Angular": "ng-version",
                        "jQuery": "jquery"
                    }
                    
                    for tech, sig in tech_signatures.items():
                        if sig.lower() in text.lower():
                            if tech not in report.technologies:
                                report.technologies.append(tech)
                    
                    # Server header
                    if 'Server' in headers:
                        report.technologies.append(f"Server: {headers['Server']}")
                    if 'X-Powered-By' in headers:
                        report.technologies.append(f"Powered-By: {headers['X-Powered-By']}")
            except:
                pass
    
    def generate_report(self, report: OSINTReport) -> str:
        """Generate formatted OSINT report"""
        output = f"""
OSINT Intelligence Report
=========================
Target: {report.target.domain}
Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}

## Domain Intelligence
- Subdomains found: {len(report.subdomains)}
- IP addresses: {len(report.ips)}
- Email addresses: {len(report.emails)}
- Technologies: {', '.join(report.technologies[:5])}

## DNS Records
{json.dumps(report.dns_records, indent=2)[:500]}

## Subdomains (Top 20)
{chr(10).join(report.subdomains[:20])}

## IP Addresses
{chr(10).join(report.ips)}

## WHOIS Data
Registrar: {report.whois_data.get('registrar', 'Unknown')}
Created: {report.whois_data.get('creation_date', 'Unknown')}
Expires: {report.whois_data.get('expiration_date', 'Unknown')}
        """
        return output

if __name__ == '__main__':
    target = OSINTTarget(
        name="Target Corp Recon",
        domain="example.com",
        organization="Example Corp"
    )
    
    osint = ComprehensiveOSINT()
    
    # Run async recon
    report = asyncio.run(osint.run_full_recon(target))
    
    # Generate report
    formatted = osint.generate_report(report)
    print(formatted)
```
