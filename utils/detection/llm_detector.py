"""
基于大语言模型的攻击行为检测引擎
支持RAG增强检测、多模型协同、告警分级
"""
import json
import os
import re
from datetime import datetime
from typing import Any

from .rag_knowledge_base import get_rag_kb


class LLMDetector:
    """LLM增强的攻击行为检测器"""

    def __init__(self, use_llm: bool = True):
        self.use_llm = use_llm
        self.rag_kb = get_rag_kb()
        self._llm_client = None

        # 检测统计
        self.stats = {
            "total_analyzed": 0,
            "alerts_generated": 0,
            "high_severity": 0,
            "medium_severity": 0,
            "low_severity": 0,
            "false_positives_suppressed": 0
        }

        # 已见事件去重
        self._seen_hashes: set[str] = set()

        # 初始化LLM客户端
        if use_llm:
            self._init_llm()

    def _init_llm(self):
        """Initialize LLM client — defaults to DeepSeek (OpenAI-compatible)"""
        try:
            api_key = os.getenv("LLM_API_KEY", "")
            if not api_key:
                self.use_llm = False
                return
            base_url = os.getenv("LLM_BASE_URL", "https://api.deepseek.com")
            from openai import OpenAI
            self._llm_client = OpenAI(api_key=api_key, base_url=base_url)
        except Exception:
            self.use_llm = False

    def detect(self, event: dict) -> list[dict]:
        """
        检测单个事件是否为攻击行为
        返回告警列表
        """
        self.stats["total_analyzed"] += 1

        # 去重检查
        event_hash = self._hash_event(event)
        if event_hash in self._seen_hashes:
            return []
        self._seen_hashes.add(event_hash)

        alerts = []

        # 1. 规则匹配检测 (快速通道)
        rule_alerts = self._rule_based_detect(event)
        alerts.extend(rule_alerts)

        # 2. RAG增强检测 (语义理解)
        if self.use_llm:
            rag_alerts = self._rag_enhanced_detect(event, rule_alerts)
            alerts.extend(rag_alerts)

        # 3. 去重与合并
        alerts = self._deduplicate_alerts(alerts)

        # 4. 分级
        for alert in alerts:
            self._classify_severity(alert)
            self._update_stats(alert)

        self.stats["alerts_generated"] += len(alerts)
        return alerts

    def _rule_based_detect(self, event: dict) -> list[dict]:
        """基于规则的快速检测"""
        alerts = []
        entities = event.get("entities", {})
        features = event.get("features", {})

        cmdline = entities.get("command_line", "")
        process_name = entities.get("process_name", "")
        event_type = event.get("event_type", "")

        # 规则0: 端口扫描检测
        if event_type in ["port_scan", "network_scan"] or (
            "scan" in str(event_type).lower() and features.get("scan_type")):
            alerts.append({
                "rule_id": "LLM_DET_000",
                "title": "检测到网络扫描行为",
                "description": f"发现端口/网络扫描活动: {event_type}",
                "technique_id": "T1046",
                "technique_name": "Network Service Scanning",
                "tactic": "Discovery",
                "severity": "medium",
                "confidence": 0.72,
                "source": "rule_based"
            })

        # 规则1: 异常父进程
        if features.get("is_abnormal_parent"):
            alerts.append({
                "rule_id": "LLM_DET_001",
                "title": "检测到异常父进程创建",
                "description": f"进程 {process_name} 由异常父进程启动: {cmdline[:100]}",
                "technique_id": "T1059",
                "technique_name": "Command and Scripting Interpreter",
                "tactic": "Execution",
                "severity": "medium",
                "confidence": 0.75,
                "source": "rule_based"
            })

        # 规则2: 敏感文件访问
        if features.get("is_sensitive_path") or "shadow" in cmdline:
            alerts.append({
                "rule_id": "LLM_DET_002",
                "title": "检测到敏感文件访问",
                "description": f"进程访问敏感文件: {cmdline[:100]}",
                "technique_id": "T1003.008",
                "technique_name": "OS Credential Dumping",
                "tactic": "Credential Access",
                "severity": "high",
                "confidence": 0.85,
                "source": "rule_based"
            })

        # 规则3: 隐蔽信道
        if features.get("is_covert_channel") or event_type in ["dns_tunnel_suspected", "icmp_tunnel_suspected"]:
            alerts.append({
                "rule_id": "LLM_DET_003",
                "title": "检测到隐蔽信道通信",
                "description": f"发现 {features.get('channel_type', 'covert')} 隐蔽信道",
                "technique_id": "T1071.004" if "DNS" in str(features.get("channel_type", ""))
                else "T1095",
                "technique_name": "DNS Tunneling" if "DNS" in str(features.get("channel_type", ""))
                else "Non-Application Layer Protocol",
                "tactic": "Command and Control",
                "severity": "high",
                "confidence": 0.90,
                "source": "rule_based"
            })

        # 规则4: WMI可疑执行
        if process_name == "WmiPrvSE.exe" or "wmic" in cmdline.lower():
            alerts.append({
                "rule_id": "LLM_DET_004",
                "title": "检测到WMI可疑执行",
                "description": f"WMI进程执行可疑命令: {cmdline[:100]}",
                "technique_id": "T1047",
                "technique_name": "Windows Management Instrumentation",
                "tactic": "Execution",
                "severity": "medium",
                "confidence": 0.80,
                "source": "rule_based"
            })

        # 规则5: 数据外传
        if event_type == "data_exfiltration" or features.get("is_outbound_c2"):
            alerts.append({
                "rule_id": "LLM_DET_005",
                "title": "检测到数据外传行为",
                "description": "大量数据向外部IP传输",
                "technique_id": "T1048",
                "technique_name": "Exfiltration Over Alternative Protocol",
                "tactic": "Exfiltration",
                "severity": "high",
                "confidence": 0.88,
                "source": "rule_based"
            })

        # 规则6: AI Agent模式检测
        if features.get("llm_generated") or features.get("ai_pattern"):
            ai_pattern = features.get("ai_pattern", "unknown")
            alerts.append({
                "rule_id": "LLM_DET_006",
                "title": "检测到AI Agent攻击模式",
                "description": f"发现AI智能体攻击特征: {ai_pattern}。{cmdline[:80]}",
                "technique_id": "T1059",
                "technique_name": "Command and Scripting Interpreter (AI-Generated)",
                "tactic": "Execution",
                "severity": "high",
                "confidence": 0.82,
                "source": "rule_based",
                "ai_specific": True,
                "ai_pattern": ai_pattern
            })

        # 规则7: 凭据暴力破解
        if event_type in ["user_logon_failed"]:
            alerts.append({
                "rule_id": "LLM_DET_007",
                "title": "检测到登录失败事件",
                "description": f"用户 {entities.get('user', 'unknown')} 登录失败",
                "technique_id": "T1110",
                "technique_name": "Brute Force",
                "tactic": "Credential Access",
                "severity": "low",
                "confidence": 0.60,
                "source": "rule_based"
            })

        # 规则8: SSH横向移动工具
        if process_name == "sshpass":
            alerts.append({
                "rule_id": "LLM_DET_008",
                "title": "检测到SSH自动化横向移动",
                "description": f"使用sshpass进行自动化SSH登录: {cmdline[:100]}",
                "technique_id": "T1021.004",
                "technique_name": "SSH Lateral Movement",
                "tactic": "Lateral Movement",
                "severity": "high",
                "confidence": 0.87,
                "source": "rule_based"
            })

        # 规则9: 日志清除
        if event_type == "log_clear" or "history -c" in cmdline:
            alerts.append({
                "rule_id": "LLM_DET_009",
                "title": "检测到日志/痕迹清除",
                "description": f"尝试清除系统日志或命令历史",
                "technique_id": "T1070",
                "technique_name": "Indicator Removal on Host",
                "tactic": "Defense Evasion",
                "severity": "medium",
                "confidence": 0.78,
                "source": "rule_based"
            })

        return alerts

    def _rag_enhanced_detect(self, event: dict, existing_alerts: list[dict]) -> list[dict]:
        """RAG增强检测——利用知识库进行语义判断"""
        rag_alerts = []

        entities = event.get("entities", {})
        features = event.get("features", {})
        cmdline = entities.get("command_line", "")
        process_name = entities.get("process_name", "")

        # 构建查询
        query_parts = []
        if event.get("event_type"):
            query_parts.append(event["event_type"])
        if process_name:
            query_parts.append(process_name)
        if cmdline:
            query_parts.append(cmdline[:200])

        # AI Agent特征检测
        if features.get("ai_pattern"):
            query_parts.append(f"AI agent abuse pattern: {features['ai_pattern']}")

        query = " ".join(query_parts)

        # RAG检索
        if query.strip():
            results = self.rag_kb.search(query, top_k=3)
            for r in results:
                if r["similarity"] > 0.1:
                    # 检查是否与已有告警重复
                    is_new = True
                    for existing in existing_alerts:
                        if existing.get("technique_id", "") in r["content"]:
                            is_new = False
                            break

                    if is_new and r["category"] == "apt_group" and r["similarity"] > 0.2:
                        rag_alerts.append({
                            "rule_id": "RAG_DET_001",
                            "title": f"RAG匹配: 可能关联{r['title']}",
                            "description": f"知识库匹配到APT组织TTP特征 (相似度: {r['similarity']})",
                            "technique_id": "TTP-MATCH",
                            "technique_name": "APT TTP Match",
                            "tactic": "Multiple",
                            "severity": "medium",
                            "confidence": min(r["similarity"] + 0.3, 0.95),
                            "source": "rag_enhanced",
                            "rag_match": r
                        })

        # LLM深度分析（仅对高可疑事件）
        if self._llm_client and self._is_highly_suspicious(event):
            try:
                llm_result = self._llm_analyze(event)
                if llm_result and llm_result.get("is_attack"):
                    rag_alerts.append({
                        "rule_id": "LLM_DEEP_001",
                        "title": f"LLM深度分析: {llm_result.get('attack_type', 'Suspicious')}",
                        "description": llm_result.get("explanation", ""),
                        "technique_id": llm_result.get("technique_id", "Unknown"),
                        "technique_name": llm_result.get("technique_name", "Unknown Technique"),
                        "tactic": llm_result.get("tactic", "Unknown"),
                        "severity": llm_result.get("severity", "medium"),
                        "confidence": llm_result.get("confidence", 0.70),
                        "source": "llm_deep_analysis"
                    })
            except Exception:
                pass

        return rag_alerts

    def _llm_analyze(self, event: dict) -> dict | None:
        """使用LLM进行深度安全分析"""
        if not self._llm_client:
            return None

        entities = event.get("entities", {})
        cmdline = entities.get("command_line", "")

        system_prompt = """你是一名资深网络安全分析师。分析以下日志事件，判断是否为攻击行为。
请以JSON格式返回分析结果:
{
  "is_attack": true/false,
  "attack_type": "攻击类型简称",
  "technique_id": "MITRE ATT&CK技术ID(如未知填Unknown)",
  "technique_name": "技术名称",
  "tactic": "战术阶段",
  "severity": "high/medium/low",
  "confidence": 0.0-1.0,
  "explanation": "简短解释"
}"""

        event_str = json.dumps({
            "event_type": event.get("event_type"),
            "process": entities.get("process_name"),
            "cmdline": cmdline[:300],
            "features": event.get("features", {}),
        }, ensure_ascii=False)

        try:
            resp = self._llm_client.chat.completions.create(
                model=os.getenv("LLM_MODEL", "deepseek-chat"),
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": f"分析事件: {event_str}"}
                ],
                temperature=0.1,
                max_tokens=300
            )
            content = resp.choices[0].message.content
            # 提取JSON
            json_match = re.search(r'\{[\s\S]*\}', content)
            if json_match:
                return json.loads(json_match.group())
        except Exception:
            pass
        return None

    def _is_highly_suspicious(self, event: dict) -> bool:
        """判断事件是否高度可疑"""
        features = event.get("features", {})
        entities = event.get("entities", {})
        cmdline = entities.get("command_line", "")

        suspicious_indicators = [
            features.get("is_abnormal_parent"),
            features.get("is_sensitive_path"),
            features.get("is_covert_channel"),
            features.get("llm_generated"),
            features.get("ai_pattern"),
            event.get("event_type") in ["dns_tunnel_suspected", "icmp_tunnel_suspected",
                                         "data_exfiltration", "port_scan"],
            "shadow" in cmdline,
            "sshpass" in cmdline,
            "base64" in cmdline,
            "wmic" in cmdline.lower(),
            "mimikatz" in cmdline.lower()
        ]
        return sum(1 for i in suspicious_indicators if i) >= 2

    def _classify_severity(self, alert: dict):
        """告警分级"""
        # 如果已经设置了severity就不覆盖
        if alert.get("severity") in ["high", "medium", "low"]:
            return

        confidence = alert.get("confidence", 0.5)
        technique = alert.get("technique_id", "")

        # C2和外传技术 → 高危
        high_techs = ["T1071", "T1095", "T1041", "T1048", "T1486", "T1003", "T1055", "T1021"]
        # 发现和执行 → 中危
        medium_techs = ["T1059", "T1047", "T1046", "T1082", "T1547", "T1053"]

        if any(technique.startswith(t) for t in high_techs):
            alert["severity"] = "high"
        elif any(technique.startswith(t) for t in medium_techs):
            alert["severity"] = "medium"
        elif confidence > 0.8:
            alert["severity"] = "high"
        elif confidence > 0.5:
            alert["severity"] = "medium"
        else:
            alert["severity"] = "low"

    def _update_stats(self, alert: dict):
        sev = alert.get("severity", "low")
        if sev == "high":
            self.stats["high_severity"] += 1
        elif sev == "medium":
            self.stats["medium_severity"] += 1
        else:
            self.stats["low_severity"] += 1

    def _deduplicate_alerts(self, alerts: list[dict]) -> list[dict]:
        """告警去重"""
        seen = set()
        unique = []
        for a in alerts:
            key = (a.get("technique_id", ""), a.get("title", ""))
            if key not in seen:
                seen.add(key)
                unique.append(a)
        return unique

    def _hash_event(self, event: dict) -> str:
        """事件哈希用于去重"""
        import hashlib
        key_parts = [
            event.get("timestamp", ""),
            event.get("event_type", ""),
            event.get("host_ip", ""),
            str(event.get("entities", {}).get("pid", "")),
            str(event.get("entities", {}).get("command_line", ""))[:100]
        ]
        return hashlib.md5("|".join(key_parts).encode()).hexdigest()

    def get_stats(self) -> dict:
        return self.stats.copy()

    def batch_detect(self, events: list[dict]) -> list[dict]:
        """批量检测"""
        all_alerts = []
        for evt in events:
            alerts = self.detect(evt)
            all_alerts.extend(alerts)
        return all_alerts
