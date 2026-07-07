"""
攻击溯源归因引擎 (TAA-EPLMR风格)
证据路径增强的LLM推理 + 威胁情报融合 + TTP相似度匹配
"""
import json
import os
from datetime import datetime
from typing import Any


class AttributionEngine:
    """攻击溯源归因引擎"""

    def __init__(self):
        self.apt_groups_data: list[dict] = []
        self.attck_techniques: list[dict] = []
        self._load_knowledge()

    def _load_knowledge(self):
        """加载威胁情报知识库"""
        base = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        kb_path = os.path.join(base, "knowledge_base")

        # 加载APT组织数据
        apt_path = os.path.join(kb_path, "apt_groups.json")
        if os.path.exists(apt_path):
            with open(apt_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                self.apt_groups_data = data.get("apt_groups", [])

        # 加载ATT&CK技术数据
        attck_path = os.path.join(kb_path, "attck_techniques.json")
        if os.path.exists(attck_path):
            with open(attck_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                self.attck_techniques = data.get("techniques", [])

    def attribute(self, verdict: dict, chains: list[dict],
                  evidence: list[dict]) -> dict:
        """
        执行完整的归因分析
        返回归因结果
        """
        # 1. 提取TTPs
        ttps = self._extract_ttps(chains, evidence)

        # 2. 提取IOCs
        iocs = verdict.get("iocs", {})

        # 3. TTP相似度匹配
        ttp_matches = self._match_ttps_to_apt(ttps)

        # 4. 行为画像分析
        behavioral_profile = self._analyze_behavior(ttps, chains)

        # 5. 基础设施分析
        infra_analysis = self._analyze_infrastructure(iocs)

        # 6. 综合归因
        attribution_result = self._synthesize_attribution(
            ttp_matches, behavioral_profile, infra_analysis, verdict
        )

        return {
            "attribution": attribution_result,
            "ttps_extracted": ttps,
            "ttp_matches": ttp_matches,
            "behavioral_profile": behavioral_profile,
            "infrastructure_analysis": infra_analysis,
            "iocs": iocs,
            "timestamp": datetime.now().isoformat()
        }

    def _extract_ttps(self, chains: list[dict], evidence: list[dict]) -> list[dict]:
        """提取TTP列表"""
        ttps = []
        seen = set()

        for chain in chains:
            for stage in chain.get("stages", []):
                tid = stage.get("technique_id", "")
                if tid and tid not in seen:
                    seen.add(tid)
                    ttps.append({
                        "technique_id": tid,
                        "technique_name": stage.get("technique_name", ""),
                        "tactic": stage.get("tactic", ""),
                        "processes": stage.get("processes", [])
                    })

        return ttps

    def _match_ttps_to_apt(self, ttps: list[dict]) -> list[dict]:
        """TTP与已知APT组织的相似度匹配"""
        results = []
        extracted_ids = set(t["technique_id"] for t in ttps)

        if not extracted_ids or not self.apt_groups_data:
            return results

        for group in self.apt_groups_data:
            group_ttps = set(group.get("signature_ttps", []))
            if not group_ttps:
                continue

            # Jaccard相似度
            intersection = extracted_ids & group_ttps
            union = extracted_ids | group_ttps
            jaccard = len(intersection) / len(union) if union else 0

            # 加权: 匹配到越多关键TTP越重要
            matched_ttps = list(intersection)
            weight = len(matched_ttps) / max(len(extracted_ids), 1)

            # 综合分析
            score = jaccard * 0.6 + weight * 0.4

            if score > 0.05:
                results.append({
                    "group_name": group["name"],
                    "group_id": group.get("id", ""),
                    "aliases": group.get("aliases", []),
                    "country": group.get("country", ""),
                    "motivation": group.get("motivation", ""),
                    "similarity_score": round(score, 4),
                    "jaccard_similarity": round(jaccard, 4),
                    "matched_ttps": matched_ttps,
                    "unmatched_ttps": list(extracted_ids - group_ttps),
                    "group_ttps": group.get("signature_ttps", []),
                    "tools": group.get("tools", []),
                    "description": group.get("description", "")
                })

        results.sort(key=lambda x: x["similarity_score"], reverse=True)
        return results[:5]

    def _analyze_behavior(self, ttps: list[dict], chains: list[dict]) -> dict:
        """行为画像分析"""
        tactics = [t["tactic"] for t in ttps]

        # 计算战术覆盖度
        all_tactics = ["Reconnaissance", "Initial Access", "Execution", "Persistence",
                       "Privilege Escalation", "Defense Evasion", "Credential Access",
                       "Discovery", "Lateral Movement", "Collection",
                       "Command and Control", "Exfiltration", "Impact"]
        covered = set(tactics) & set(all_tactics)

        # 技能水平评估
        advanced_techniques = {"T1055", "T1071.004", "T1095", "T1003.001"}
        use_advanced = sum(1 for t in ttps if t["technique_id"] in advanced_techniques)

        if use_advanced >= 3 and len(covered) >= 6:
            skill_level = "Advanced (高级)"
        elif use_advanced >= 1 or len(covered) >= 4:
            skill_level = "Intermediate (中级)"
        else:
            skill_level = "Novice (初级)"

        # 攻击复杂度
        total_stages = sum(len(c.get("stages", [])) for c in chains)
        complexity = "High" if total_stages >= 8 else ("Medium" if total_stages >= 4 else "Low")

        # AI特征分析
        ai_indicators = []
        for t in ttps:
            if "AI" in t.get("technique_name", "") or "LLM" in t.get("technique_name", ""):
                ai_indicators.append(t["technique_name"])

        return {
            "tactics_covered": list(covered),
            "tactics_count": len(covered),
            "total_stages": total_stages,
            "skill_level": skill_level,
            "attack_complexity": complexity,
            "has_ai_indicators": len(ai_indicators) > 0,
            "ai_indicators": ai_indicators,
            "primary_objective": self._infer_objective(tactics),
            "operational_security": self._assess_opsec(ttps)
        }

    def _infer_objective(self, tactics: list[str]) -> str:
        if "Exfiltration" in tactics and "Impact" in tactics:
            return "数据窃取 + 破坏 (双重目的)"
        elif "Exfiltration" in tactics:
            return "数据窃取 (Espionage/Data Theft)"
        elif "Impact" in tactics:
            return "破坏/勒索 (Sabotage/Ransomware)"
        elif "Command and Control" in tactics:
            return "建立持久访问 (Long-term Access)"
        else:
            return "侦察与情报收集 (Reconnaissance)"

    def _assess_opsec(self, ttps: list[dict]) -> str:
        has_evasion = any(t["tactic"] == "Defense Evasion" for t in ttps)
        has_log_clear = any("T1070" in t.get("technique_id", "") for t in ttps)
        if has_log_clear:
            return "High - 主动清除痕迹"
        elif has_evasion:
            return "Medium - 有规避检测意识"
        else:
            return "Low - 未观察到防御规避"

    def _analyze_infrastructure(self, iocs: dict) -> dict:
        """基础设施分析"""
        ips = iocs.get("ips", [])
        domains = [ip for ip in ips if not ip.replace(".", "").isdigit()
                   or ip.count(".") > 2]

        external_ips = [ip for ip in ips
                        if not ip.startswith("192.168.")
                        and not ip.startswith("10.")
                        and not ip.startswith("172.16.")]

        return {
            "total_ips": len(ips),
            "external_ips": external_ips,
            "internal_ips": [ip for ip in ips if ip.startswith("192.168.")],
            "domains_found": domains,
            "c2_count": len(external_ips),
            "infrastructure_complexity": "High" if len(external_ips) >= 3 else (
                "Medium" if len(external_ips) >= 1 else "Low")
        }

    def _synthesize_attribution(self, ttp_matches: list[dict],
                                 behavioral: dict,
                                 infra: dict,
                                 verdict: dict) -> dict:
        """综合归因分析"""
        confidence = verdict.get("confidence_level", 0)

        if ttp_matches:
            best = ttp_matches[0]
            similarity = best["similarity_score"]

            if similarity >= 0.3:
                attr_type = "Known APT"
                best_match = best["group_name"]
                attr_confidence = min(similarity + 0.2, 0.95)
            elif similarity >= 0.1:
                attr_type = "Suspected Group"
                best_match = f"Possible {best['group_name']} (Low Confidence)"
                attr_confidence = similarity + 0.1
            else:
                attr_type = "Unknown Cluster"
                best_match = f"Unidentified ({len(ttp_matches[0].get('matched_ttps', []))} TTP matches)"
                attr_confidence = 0.3
        else:
            attr_type = "Unknown Threat Actor"
            best_match = "No known APT match"
            attr_confidence = 0.1

        # 证据路径推理
        evidence_path = self._build_evidence_path(verdict, behavioral)

        return {
            "type": attr_type,
            "result": {
                "best_match": best_match,
                "confidence_score": round(attr_confidence, 4),
                "top_matches": ttp_matches[:3],
                "behavioral_profile": behavioral,
                "infrastructure": infra
            },
            "evidence_path": evidence_path,
            "overall_confidence": round((attr_confidence * 0.6 + confidence * 0.4), 2)
        }

    def _build_evidence_path(self, verdict: dict, behavioral: dict) -> list[dict]:
        """构建证据推理路径"""
        path = []
        stage = 1

        # 1. 初始访问证据
        path.append({
            "step": stage, "phase": "入口识别",
            "finding": "通过告警关联识别攻击入口点",
            "confidence": "Medium"
        })
        stage += 1

        # 2. TTP链证据
        if behavioral.get("tactics_count", 0) > 0:
            path.append({
                "step": stage, "phase": "TTP提取",
                "finding": f"提取{behavioral['tactics_count']}个战术阶段的TTP特征",
                "confidence": "High"
            })
            stage += 1

        # 3. IOC证据
        path.append({
            "step": stage, "phase": "IOC提取",
            "finding": f"提取IOC用于威胁情报比对",
            "confidence": "Medium"
        })
        stage += 1

        # 4. 归因推理
        path.append({
            "step": stage, "phase": "归因推理",
            "finding": "基于TTP相似度和IOC关联进行攻击者归因",
            "confidence": "Varies"
        })

        return path

    def generate_attribution_report(self, attribution_data: dict) -> str:
        """生成归因报告"""
        attr = attribution_data.get("attribution", {})
        result = attr.get("result", {})
        behavioral = result.get("behavioral_profile", {})
        infra = result.get("infrastructure", {})
        top_matches = result.get("top_matches", [])

        lines = []
        lines.append("# 攻击溯源归因分析报告")
        lines.append(f"\n**生成时间**: {attribution_data.get('timestamp', 'N/A')}")
        lines.append(f"\n## 一、归因结论")
        lines.append(f"- **归因类型**: {attr.get('type', 'Unknown')}")
        lines.append(f"- **最佳匹配**: {result.get('best_match', 'N/A')}")
        lines.append(f"- **综合置信度**: {attr.get('overall_confidence', 0):.0%}")

        if top_matches:
            lines.append(f"\n## 二、APT组织匹配详情")
            for i, match in enumerate(top_matches[:3]):
                lines.append(f"\n### {i + 1}. {match['group_name']} (相似度: {match['similarity_score']:.2%})")
                lines.append(f"- 国家/地区: {match.get('country', 'N/A')}")
                lines.append(f"- 别名: {', '.join(match.get('aliases', []))}")
                lines.append(f"- 动机: {match.get('motivation', 'N/A')}")
                lines.append(f"- 匹配TTP: {', '.join(match.get('matched_ttps', []))}")
                if match.get('unmatched_ttps'):
                    lines.append(f"- 未匹配TTP: {', '.join(match['unmatched_ttps'])}")

        lines.append(f"\n## 三、行为画像")
        lines.append(f"- **技能水平**: {behavioral.get('skill_level', 'N/A')}")
        lines.append(f"- **攻击复杂度**: {behavioral.get('attack_complexity', 'N/A')}")
        lines.append(f"- **主要目的**: {behavioral.get('primary_objective', 'N/A')}")
        lines.append(f"- **战术覆盖**: {behavioral.get('tactics_count', 0)}个阶段")
        lines.append(f"- **行动安全**: {behavioral.get('operational_security', 'N/A')}")

        lines.append(f"\n## 四、基础设施分析")
        lines.append(f"- **总IP数**: {infra.get('total_ips', 0)}")
        lines.append(f"- **外部C2节点**: {len(infra.get('external_ips', []))}")
        lines.append(f"- **基础设施复杂度**: {infra.get('infrastructure_complexity', 'N/A')}")

        lines.append(f"\n## 五、证据推理路径")
        for step in attr.get("evidence_path", []):
            lines.append(f"{step['step']}. [{step['phase']}] {step['finding']} (置信度: {step['confidence']})")

        return "\n".join(lines)
