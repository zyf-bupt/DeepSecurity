"""
证据链固化模块
生成可验证的哈希证据链和防篡改证据包
"""
import hashlib
import json
import uuid
from datetime import datetime
from typing import Any


class EvidenceBlock:
    """单个证据块"""

    def __init__(self, evidence_data: dict, previous_hash: str = ""):
        self.block_id = str(uuid.uuid4())
        self.timestamp = datetime.now().isoformat()
        self.data = evidence_data
        self.previous_hash = previous_hash
        self.block_hash = self._compute_hash()

    def _compute_hash(self) -> str:
        content = json.dumps({
            "block_id": self.block_id,
            "timestamp": self.timestamp,
            "data": self.data,
            "previous_hash": self.previous_hash
        }, sort_keys=True, ensure_ascii=False)
        return hashlib.sha256(content.encode()).hexdigest()

    def to_dict(self) -> dict:
        return {
            "block_id": self.block_id,
            "timestamp": self.timestamp,
            "data": self.data,
            "previous_hash": self.previous_hash,
            "block_hash": self.block_hash
        }


class EvidenceChain:
    """证据哈希链"""

    def __init__(self, chain_name: str = "default"):
        self.chain_name = chain_name
        self.chain_id = str(uuid.uuid4())
        self.blocks: list[EvidenceBlock] = []
        self._sealed = False

    def add_evidence(self, evidence_data: dict) -> EvidenceBlock:
        """添加证据块"""
        if self._sealed:
            raise ValueError("证据链已封存，无法添加新证据")

        prev_hash = self.blocks[-1].block_hash if self.blocks else "GENESIS"
        block = EvidenceBlock(evidence_data, prev_hash)
        self.blocks.append(block)
        return block

    def seal(self) -> str:
        """封存证据链"""
        self._sealed = True
        # 添加封存块
        seal_data = {
            "action": "CHAIN_SEALED",
            "chain_id": self.chain_id,
            "chain_name": self.chain_name,
            "total_blocks": len(self.blocks),
            "final_hash": self.get_final_hash()
        }
        seal_block = EvidenceBlock(seal_data, self.blocks[-1].block_hash if self.blocks else "GENESIS")
        self.blocks.append(seal_block)
        return seal_block.block_hash

    def verify(self) -> dict:
        """验证证据链完整性"""
        issues = []
        for i in range(len(self.blocks)):
            block = self.blocks[i]

            # 检查哈希
            expected = block._compute_hash()
            if expected != block.block_hash:
                issues.append(f"Block {i} ({block.block_id}): 哈希不匹配")

            # 检查链
            if i > 0:
                prev = self.blocks[i - 1]
                if block.previous_hash != prev.block_hash:
                    issues.append(f"Block {i} ({block.block_id}): 前驱哈希链断裂")

        return {
            "chain_id": self.chain_id,
            "chain_name": self.chain_name,
            "total_blocks": len(self.blocks),
            "valid": len(issues) == 0,
            "issues": issues,
            "verified_at": datetime.now().isoformat()
        }

    def get_final_hash(self) -> str:
        return self.blocks[-1].block_hash if self.blocks else "EMPTY_CHAIN"

    def to_dict(self) -> dict:
        return {
            "chain_id": self.chain_id,
            "chain_name": self.chain_name,
            "sealed": self._sealed,
            "total_blocks": len(self.blocks),
            "final_hash": self.get_final_hash(),
            "blocks": [b.to_dict() for b in self.blocks]
        }


class EvidencePackage:
    """证据固化包 —— 包含完整的证据链和元数据"""

    def __init__(self, case_name: str = ""):
        self.case_id = str(uuid.uuid4())
        self.case_name = case_name
        self.created_at = datetime.now().isoformat()
        self.evidence_chains: dict[str, EvidenceChain] = {}
        self.metadata: dict[str, Any] = {
            "case_id": self.case_id,
            "case_name": case_name,
            "created_at": self.created_at,
            "investigator": "LLM-Security-System",
            "methodology": "AgentStalker Multi-Agent Framework",
            "hash_algorithm": "SHA-256",
            "evidence_standard": "ISO 27037 Compliant"
        }

    def create_chain(self, chain_name: str) -> EvidenceChain:
        chain = EvidenceChain(chain_name)
        self.evidence_chains[chain_name] = chain
        return chain

    def seal_all(self):
        """封存所有证据链"""
        for chain in self.evidence_chains.values():
            if not chain._sealed:
                chain.seal()

    def verify_all(self) -> dict:
        results = {}
        for name, chain in self.evidence_chains.items():
            results[name] = chain.verify()
        return {
            "case_id": self.case_id,
            "all_valid": all(r["valid"] for r in results.values()),
            "chain_results": results
        }

    def to_dict(self) -> dict:
        return {
            "metadata": self.metadata,
            "evidence_chains": {name: c.to_dict() for name, c in self.evidence_chains.items()},
            "verification": self.verify_all()
        }

    def export(self, filepath: str):
        """导出证据包为JSON"""
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(self.to_dict(), f, ensure_ascii=False, indent=2)
