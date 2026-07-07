"""
攻击者画像生成器
从行为模式、技能水平、动机等方面生成攻击者/组织的综合画像
"""
from datetime import datetime
from typing import Any


class AttackerProfiler:
    """攻击者画像生成器"""

    def __init__(self):
        self.skill_indicators = {
            "advanced": [
                "使用零日漏洞", "自定义恶意软件", "多层C2架构",
                "分段数据外传", "反取证技术", "内存驻留载荷"
            ],
            "intermediate": [
                "使用公开漏洞", "常见C2框架", "PowerShell Empire",
                "Cobalt Strike", "Mimikatz", "DNS隧道"
            ],
            "novice": [
                "基础扫描器", "已知漏洞利用", "简单的反向Shell",
                "未混淆载荷", "无规避检测"
            ]
        }

    def build_profile(self, attribution_data: dict, behavioral: dict,
                       iocs: dict, ttps: list[dict]) -> dict:
        """构建攻击者综合画像"""
        attr = attribution_data.get("attribution", {})
        result = attr.get("result", {})
        top_match = result.get("top_matches", [{}])[0] if result.get("top_matches") else {}

        profile = {
            "profile_id": f"PROFILE_{datetime.now().strftime('%Y%m%d%H%M%S')}",
            "generated_at": datetime.now().isoformat(),

            # 身份画像
            "identity": {
                "known_actor": top_match.get("group_name", "Unknown") if top_match else "Unknown",
                "aliases": top_match.get("aliases", []),
                "country_of_origin": top_match.get("country", "Unknown"),
                "attribution_type": attr.get("type", "Unknown"),
                "attribution_confidence": attr.get("overall_confidence", 0)
            },

            # 能力画像
            "capability": {
                "skill_level": behavioral.get("skill_level", "Unknown"),
                "attack_complexity": behavioral.get("attack_complexity", "Unknown"),
                "operational_security": behavioral.get("operational_security", "Unknown"),
                "tools_used": self._infer_tools(ttps, top_match),
                "techniques_mastered": [t["technique_id"] for t in ttps],
                "tactical_range": len(behavioral.get("tactics_covered", [])),
                "ai_capability": behavioral.get("has_ai_indicators", False)
            },

            # 动机画像
            "motivation": {
                "primary_objective": behavioral.get("primary_objective", "Unknown"),
                "likely_motivation": top_match.get("motivation", "Unknown"),
                "target_sectors": self._infer_target_sectors(behavioral),
                "impact_assessment": self._assess_impact(iocs, ttps)
            },

            # 行为画像
            "behavioral_patterns": {
                "preferred_initial_access": self._find_tactic_techniques(ttps, "Initial Access"),
                "preferred_lateral_movement": self._find_tactic_techniques(ttps, "Lateral Movement"),
                "c2_methods": self._find_tactic_techniques(ttps, "Command and Control"),
                "exfiltration_methods": self._find_tactic_techniques(ttps, "Exfiltration"),
                "uses_defense_evasion": any(t["tactic"] == "Defense Evasion" for t in ttps),
                "uses_persistence": any(t["tactic"] == "Persistence" for t in ttps),
                "ai_indicators": behavioral.get("ai_indicators", [])
            },

            # IOC画像
            "ioc_profile": {
                "infrastructure_type": self._classify_infrastructure(iocs),
                "c2_ips": [ip for ip in iocs.get("ips", [])
                           if not ip.startswith("192.168.") and not ip.startswith("10.")],
                "internal_pivots": [ip for ip in iocs.get("ips", []) if ip.startswith("192.168.")],
                "tools_hashes": iocs.get("file_hashes", []),
                "domains": iocs.get("domains", [])
            },

            # 威胁等级
            "threat_rating": self._calculate_threat_rating(behavioral, iocs)
        }

        return profile

    def _infer_tools(self, ttps: list[dict], top_match: dict) -> list[str]:
        tools = list(top_match.get("tools", []))
        # AI相关工具
        for t in ttps:
            processes = t.get("processes", [])
            for p in processes:
                if p in ["claude", "python3", "curl", "wget", "sshpass", "base64",
                          "nmap", "mimikatz", "psexec", "wmic"]:
                    if p not in tools:
                        tools.append(p)
        return tools[:10]

    def _infer_target_sectors(self, behavioral: dict) -> list[str]:
        tactics = behavioral.get("tactics_covered", [])
        sectors = []
        if "Exfiltration" in tactics:
            sectors.append("Data-rich organizations")
        if "Impact" in tactics:
            sectors.append("Critical infrastructure")
        if "Lateral Movement" in tactics:
            sectors.append("Enterprise networks")
        if behavioral.get("has_ai_indicators"):
            sectors.append("AI/ML Infrastructure")
        return sectors if sectors else ["Unknown"]

    def _assess_impact(self, iocs: dict, ttps: list[dict]) -> dict:
        has_exfil = any("Exfiltration" in t.get("tactic", "") for t in ttps)
        has_impact = any("Impact" in t.get("tactic", "") for t in ttps)
        has_lateral = any("Lateral Movement" in t.get("tactic", "") for t in ttps)

        if has_exfil and has_impact:
            severity = "CRITICAL"
        elif has_exfil and has_lateral:
            severity = "HIGH"
        elif has_exfil:
            severity = "MEDIUM"
        else:
            severity = "LOW"

        return {
            "severity": severity,
            "data_loss_possible": has_exfil,
            "system_damage_possible": has_impact,
            "lateral_spread_possible": has_lateral,
            "affected_ips_count": len(iocs.get("ips", []))
        }

    def _find_tactic_techniques(self, ttps: list[dict], tactic: str) -> list[str]:
        return [t["technique_name"] for t in ttps if t.get("tactic") == tactic]

    def _classify_infrastructure(self, iocs: dict) -> str:
        external = len([ip for ip in iocs.get("ips", [])
                        if not ip.startswith("192.168.") and not ip.startswith("10.")])
        if external >= 3:
            return "Distributed C2 Infrastructure"
        elif external >= 1:
            return "Single C2 Node"
        else:
            return "Internal-only (No external C2 detected)"

    def _calculate_threat_rating(self, behavioral: dict, iocs: dict) -> dict:
        skill_map = {"Advanced (高级)": 8, "Intermediate (中级)": 5, "Novice (初级)": 2}
        complexity_map = {"High": 3, "Medium": 2, "Low": 1}

        base_score = skill_map.get(behavioral.get("skill_level", "Novice (初级)"), 2)
        complexity_bonus = complexity_map.get(behavioral.get("attack_complexity", "Low"), 1)

        total = min(base_score + complexity_bonus, 10)

        if total >= 7:
            level = "CRITICAL"
        elif total >= 5:
            level = "HIGH"
        elif total >= 3:
            level = "MEDIUM"
        else:
            level = "LOW"

        return {
            "score": total,
            "level": level,
            "factors": {
                "skill": behavioral.get("skill_level", ""),
                "complexity": behavioral.get("attack_complexity", ""),
                "scope": len(iocs.get("ips", [])),
                "coverage": behavioral.get("tactics_count", 0)
            }
        }
