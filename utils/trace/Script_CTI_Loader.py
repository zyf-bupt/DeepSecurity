#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Script_CTI_Loader.py

目的（防御/溯源用途）：
- 读取本地攻击/仿真脚本（例如 utils/trace/scripts/apt_killchain_orchestrator.py）
- 从脚本中抽取：Technique、IOC、Tool、阶段顺序
- 写入 Neo4j，形成可解释 CTI 图谱

图谱模型（新增）：
(:SimulationScript {id, name, path, sha256, created_at})
(:IOC {id, type, value})
(:Tool {id, name})
(:Technique {id, name})   # Technique.id = 'Txxxx'（与你现有库一致）

关系：
(SimulationScript)-[:INDICATES]->(IOC)
(SimulationScript)-[:USES_TOOL]->(Tool)
(SimulationScript)-[:HAS_TECHNIQUE {phase, step, evidence}]->(Technique)
(Technique)-[:NEXT_TECHNIQUE {script_id, order_from, order_to}]->(Technique)
"""

from __future__ import annotations

import argparse
import hashlib
import logging
import os
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from neo4j import GraphDatabase

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")


# ----------------------------
# 数据结构
# ----------------------------
@dataclass
class TechniqueItem:
    id: str
    name: str
    phase: str
    step: int
    evidence: str


@dataclass
class IOCItem:
    type: str
    value: str


@dataclass
class ToolItem:
    name: str


# ----------------------------
# Loader
# ----------------------------
class ScriptCTILoader:
    def __init__(self, uri: str, user: str, password: str) -> None:
        self.driver = GraphDatabase.driver(uri, auth=(user, password))

    def close(self) -> None:
        self.driver.close()

    # ========= 公共工具 =========
    @staticmethod
    def _sha256_file(path: str) -> str:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()

    @staticmethod
    def _utc_now() -> str:
        return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    @staticmethod
    def _dedupe_keep_order(items: list[str]) -> list[str]:
        seen = set()
        out = []
        for x in items:
            if x in seen:
                continue
            seen.add(x)
            out.append(x)
        return out

    # ========= 抽取逻辑（针对你这个脚本的结构，先用“规则抽取”）=========
    def extract_cti_from_text(self, text: str) -> dict[str, Any]:
        """
        返回结构：
        {
          "tools": [ToolItem...],
          "iocs": [IOCItem...],
          "techniques": [TechniqueItem...],  # 按 step 排好序
          "sequence": ["T1105","T1046",...]
        }
        """

        # ---- 工具抽取（粗粒度：看 import / 命令字符串）----
        tools: list[str] = []
        if "sshpass" in text:
            tools.append("sshpass")
        if "wget" in text:
            tools.append("wget")
        if "impacket" in text or "SMBConnection" in text or "DCOMConnection" in text:
            tools.append("impacket")
        if "nslookup" in text:
            tools.append("nslookup")
        if "ping -s" in text or " ping " in text:
            tools.append("ping")

        tools = self._dedupe_keep_order(tools)

        # ---- IOC 抽取（IP/Domain/URL/User-Agent）----
        iocs: list[IOCItem] = []

        # 1) IP（简单 IPv4 正则）
        ip_re = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
        for ip in sorted(set(ip_re.findall(text))):
            # 过滤常见无关 IP（你脚本里有 8.8.8.8/127.0.0.1，也保留但可按需过滤）
            iocs.append(IOCItem(type="ip", value=ip))

        # 2) Domain（非常简化：抓明显的域名）
        # 针对你的 Config.APT_DOMAIN 这种：update-kernel-security.com
        domain_re = re.compile(r"\b[a-zA-Z0-9][a-zA-Z0-9\-]{1,62}(?:\.[a-zA-Z0-9\-]{1,63})+\b")
        domains = set()
        for d in domain_re.findall(text):
            # 避免把 python 模块名等误判；这里只过滤明显不是域名的
            if d.endswith(".py"):
                continue
            if d in {"localhost"}:
                continue
            # 过滤纯数字点分（已经当 IP 了）
            if ip_re.fullmatch(d):
                continue
            # 过滤 "Windows" 这种
            if d.lower() in {"windows"}:
                continue
            # 你的脚本里出现过 update-kernel-security.com
            domains.add(d)

        for d in sorted(domains):
            # 只保留看起来像公网域（至少一个点）
            if "." in d:
                iocs.append(IOCItem(type="domain", value=d))

        # 3) URL（http://...）
        url_re = re.compile(r"\bhttps?://[^\s'\"\\]+")
        for u in sorted(set(url_re.findall(text))):
            iocs.append(IOCItem(type="url", value=u))

        # 4) User-Agent（从脚本里 Config.APT_USER_AGENT 提取）
        # 用较稳妥规则：查找 "User-Agent": 或 wget -U 'xxx'
        ua_values = set()
        ua_json_re = re.compile(r"User-Agent['\"]\s*:\s*['\"]([^'\"]+)['\"]")
        ua_wget_re = re.compile(r"wget\s+-U\s+['\"]([^'\"]+)['\"]")
        for m in ua_json_re.findall(text):
            ua_values.add(m.strip())
        for m in ua_wget_re.findall(text):
            ua_values.add(m.strip())
        for ua in sorted(ua_values):
            iocs.append(IOCItem(type="user-agent", value=ua))

        # ---- Technique 抽取（从脚本阶段函数/命令行为映射）----
        # 说明：这里不是“执行攻击”，只是把脚本出现的行为归类到 ATT&CK 技术，作为 CTI 知识库。
        techniques: list[TechniqueItem] = []

        # 阶段/顺序（对应你的 phase_1..phase_6）
        # 你也可以把这些定义挪到一个 YAML/JSON，让它可配置。
        step = 1

        # Phase 1: Resource Development（脚本写 /tmp/apt_config.dat）
        if "phase_1_preparation" in text:
            techniques.append(
                TechniqueItem(
                    id="T1588",
                    name="Acquire Infrastructure / Capabilities (simulated fingerprint prep)",
                    phase="Resource Development",
                    step=step,
                    evidence="Writes /tmp/apt_config.dat as campaign config/fingerprint",
                )
            )
            step += 1

        # Phase 2: wget 下载 dropper
        if "wget -U" in text and "dropper.sh" in text:
            techniques.append(
                TechniqueItem(
                    id="T1105",
                    name="Ingress Tool Transfer",
                    phase="Initial Access",
                    step=step,
                    evidence="wget with custom User-Agent downloads dropper.sh",
                )
            )
            step += 1

        # Phase 3: 扫描 22/445
        if "for p in [22, 445]" in text or "connect_ex" in text:
            techniques.append(
                TechniqueItem(
                    id="T1046",
                    name="Network Service Scanning",
                    phase="Discovery",
                    step=step,
                    evidence="Multi-thread port scan for 22/445",
                )
            )
            step += 1

        # Phase 4: sshpass / SMB login
        if "sshpass -p" in text:
            techniques.append(
                TechniqueItem(
                    id="T1110",
                    name="Brute Force",
                    phase="Credential Access",
                    step=step,
                    evidence="sshpass used to attempt multiple username/password combos",
                )
            )
            step += 1

            techniques.append(
                TechniqueItem(
                    id="T1021",
                    name="Remote Services",
                    phase="Lateral Movement",
                    step=step,
                    evidence="SSH remote command execution after successful login",
                )
            )
            step += 1

        if "SMBConnection" in text:
            # SMB 也归 Remote Services
            techniques.append(
                TechniqueItem(
                    id="T1021",
                    name="Remote Services",
                    phase="Lateral Movement",
                    step=step,
                    evidence="SMB login via Impacket SMBConnection",
                )
            )
            step += 1

        # WMI
        if "IWbemLevel1Login" in text or "Win32_Process" in text or "wmi" in text:
            techniques.append(
                TechniqueItem(
                    id="T1047",
                    name="Windows Management Instrumentation",
                    phase="Execution",
                    step=step,
                    evidence="DCOM/WMI create Win32_Process for remote command",
                )
            )
            step += 1

        # DNS 隧道（nslookup 高熵子域）
        if "nslookup" in text and "generate_high_entropy_data" in text:
            techniques.append(
                TechniqueItem(
                    id="T1071.004",
                    name="Application Layer Protocol: DNS",
                    phase="Command and Control",
                    step=step,
                    evidence="nslookup with high-entropy subdomain to C2 IP",
                )
            )
            step += 1

        # ICMP 大包
        if "ping -s 1200" in text:
            techniques.append(
                TechniqueItem(
                    id="T1095",
                    name="Non-Application Layer Protocol",
                    phase="Command and Control",
                    step=step,
                    evidence="ICMP large payload ping -s 1200",
                )
            )
            step += 1

        # HTTP 外传 /api/v2/sync
        if "/api/v2/sync" in text and "application/octet-stream" in text:
            techniques.append(
                TechniqueItem(
                    id="T1048",
                    name="Exfiltration Over Alternative Protocol",
                    phase="Exfiltration",
                    step=step,
                    evidence="HTTP POST binary data to /api/v2/sync with custom headers",
                )
            )
            step += 1

        # 去重：按 (id, phase, evidence) 防止重复插入同一脚本多次解析导致多条相同 technique 记录
        seen = set()
        uniq_techniques: list[TechniqueItem] = []
        for t in techniques:
            k = (t.id, t.phase, t.evidence)
            if k in seen:
                continue
            seen.add(k)
            uniq_techniques.append(t)

        uniq_techniques.sort(key=lambda x: x.step)

        sequence = [t.id for t in uniq_techniques]
        sequence = self._dedupe_keep_order(sequence)

        return {
            "tools": [ToolItem(name=x) for x in tools],
            "iocs": iocs,
            "techniques": uniq_techniques,
            "sequence": sequence,
        }

    # ========= Neo4j 导入逻辑（参考 CTI_Loader.py 批量 UNWIND）=========
    def load_script_file(self, path: str) -> dict[str, Any]:
        if not os.path.exists(path):
            raise FileNotFoundError(f"Script not found: {path}")

        text = open(path, "r", encoding="utf-8", errors="ignore").read()

        sha256 = self._sha256_file(path)
        script_name = os.path.basename(path)
        script_id = sha256  # 你已确认用 sha256 做唯一键

        cti = self.extract_cti_from_text(text)

        script_node = {
            "id": script_id,
            "name": script_name,
            "path": path,
            "sha256": sha256,
            "created_at": self._utc_now(),
        }

        self._ingest_to_neo4j(script_node, cti)

        return {
            "ok": True,
            "script": script_node,
            "counts": {
                "tools": len(cti["tools"]),
                "iocs": len(cti["iocs"]),
                "techniques": len(cti["techniques"]),
                "sequence": len(cti["sequence"]),
            },
        }

    def _ingest_to_neo4j(self, script_node: dict[str, Any], cti: dict[str, Any]) -> None:
        logging.info("开始写入 Neo4j：SimulationScript / IOC / Tool / Technique / NEXT_TECHNIQUE ...")

        tools = [{"id": f"tool:{t.name.lower()}", "name": t.name} for t in cti["tools"]]
        iocs = [{"id": f"{ioc.type}:{ioc.value}", "type": ioc.type, "value": ioc.value} for ioc in cti["iocs"]]
        techniques = [
            {
                "id": t.id,
                "name": t.name,
                "phase": t.phase,
                "step": t.step,
                "evidence": t.evidence,
            }
            for t in cti["techniques"]
        ]

        # NEXT_TECHNIQUE 边
        seq = cti["sequence"]
        next_edges = []
        for idx in range(len(seq) - 1):
            next_edges.append(
                {
                    "script_id": script_node["id"],
                    "from": seq[idx],
                    "to": seq[idx + 1],
                    "order_from": idx + 1,
                    "order_to": idx + 2,
                }
            )

        with self.driver.session() as session:
            # 1) Script 节点
            q_script = """
            MERGE (s:SimulationScript {id: $id})
            SET s.name = $name,
                s.path = $path,
                s.sha256 = $sha256,
                s.created_at = $created_at
            """
            session.run(q_script, **script_node)

            # 2) Tool
            q_tool = """
            UNWIND $batch AS x
            MERGE (t:Tool {id: x.id})
            SET t.name = x.name
            """
            self._batch_execute(session, q_tool, tools)

            q_script_tool = """
            UNWIND $batch AS x
            MATCH (s:SimulationScript {id: $script_id})
            MATCH (t:Tool {id: x.id})
            MERGE (s)-[:USES_TOOL]->(t)
            """
            self._batch_execute(session, q_script_tool, tools, extra_params={"script_id": script_node["id"]})

            # 3) IOC
            q_ioc = """
            UNWIND $batch AS x
            MERGE (i:IOC {id: x.id})
            SET i.type = x.type,
                i.value = x.value
            """
            self._batch_execute(session, q_ioc, iocs)

            q_script_ioc = """
            UNWIND $batch AS x
            MATCH (s:SimulationScript {id: $script_id})
            MATCH (i:IOC {id: x.id})
            MERGE (s)-[:INDICATES]->(i)
            """
            self._batch_execute(session, q_script_ioc, iocs, extra_params={"script_id": script_node["id"]})

            # 4) Technique（保证 Technique.id='Txxxx' 存在）
            q_technique = """
            UNWIND $batch AS x
            MERGE (t:Technique {id: x.id})
            ON CREATE SET t.name = x.name
            SET t.name = coalesce(t.name, x.name)
            """
            self._batch_execute(session, q_technique, [{"id": t["id"], "name": t["name"]} for t in techniques])

            # 5) Script -> Technique（带 phase/step/evidence）
            q_script_technique = """
            UNWIND $batch AS x
            MATCH (s:SimulationScript {id: $script_id})
            MATCH (t:Technique {id: x.id})
            MERGE (s)-[r:HAS_TECHNIQUE {technique_id: x.id}]->(t)
            SET r.phase = x.phase,
                r.step = x.step,
                r.evidence = x.evidence
            """
            self._batch_execute(session, q_script_technique, techniques, extra_params={"script_id": script_node["id"]})

            # 6) NEXT_TECHNIQUE（阶段顺序）
            q_next = """
            UNWIND $batch AS x
            MATCH (a:Technique {id: x.from})
            MATCH (b:Technique {id: x.to})
            MERGE (a)-[r:NEXT_TECHNIQUE {script_id: x.script_id, from: x.from, to: x.to}]->(b)
            SET r.order_from = x.order_from,
                r.order_to = x.order_to
            """
            self._batch_execute(session, q_next, next_edges)

        logging.info("脚本 CTI 写入完成：script_id=%s", script_node["id"])

    @staticmethod
    def _batch_execute(session, query: str, data: list[dict], batch_size: int = 500, extra_params: dict | None = None) -> None:
        if not data:
            return
        extra_params = extra_params or {}
        for i in range(0, len(data), batch_size):
            batch = data[i : i + batch_size]
            params = {"batch": batch}
            params.update(extra_params)
            session.run(query, **params)


def main() -> None:
    parser = argparse.ArgumentParser(description="Load CTI from simulation script into Neo4j")
    parser.add_argument("--path", required=True, help="Path to script file, e.g. utils/trace/scripts/apt_killchain_orchestrator.py")
    parser.add_argument("--uri", default="bolt://localhost:7687")
    parser.add_argument("--user", default="neo4j")
    parser.add_argument("--password", default=os.getenv("NEO4J_PASSWORD", ""))
    args = parser.parse_args()

    loader = ScriptCTILoader(args.uri, args.user, args.password)
    try:
        result = loader.load_script_file(args.path)
        logging.info("DONE: %s", result)
    finally:
        loader.close()


if __name__ == "__main__":
    main()
