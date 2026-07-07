"""
Dashboard 业务层：组合存储层数据，做容错/格式化/摘要提取。
当 SQL Server 不可用时自动降级为内存模拟模式。
"""

from __future__ import annotations

import json
from typing import Any
from datetime import datetime

try:
    from utils.dashboard.dashboard_storage import (
        count_table,
        get_latest_time,
        list_recent_attack_reports,
    )
    _HAS_DB = True
except Exception:
    _HAS_DB = False

from utils.data_bridge import get_bridge


def _safe_parse_report_json(text: Any) -> dict[str, Any]:
    if not text:
        return {}
    if isinstance(text, dict):
        return text
    try:
        obj = json.loads(str(text))
        return obj if isinstance(obj, dict) else {"_raw": obj}
    except Exception:
        return {}


def _infer_trigger_technique(report_obj: dict[str, Any], fallback: str = "") -> str:
    """
    从 report_json.attack_chain 推断“触发技术/最后技���”。
    你的 report_json 例子里 attack_chain 是一个 list[str]。
    """
    chain = report_obj.get("attack_chain")
    if isinstance(chain, list) and chain:
        last = chain[-1]
        return str(last) if last is not None else fallback
    # 兜底：也可以尝试从 root_cause_analysis/evidence 提取，但先保持简单
    return fallback


def get_dashboard_data(*, recent_limit: int = 10) -> dict[str, Any]:
    """返回 dashboard 数据，SQL Server 不可用时自动降级"""

    # 尝试真实DB，失败则降级
    try:
        if _HAS_DB:
            stats = {
                "log_count": count_table("HostLogs"),
                "process_count": count_table("HostBehaviors"),
                "flow_count": count_table("NetworkTraffic"),
                "attack_count": count_table("AttackReports") + count_table("AnalysisReports"),
            }
            freshness = {
                "HostLogs": get_latest_time("HostLogs", "create_time"),
                "HostBehaviors": get_latest_time("HostBehaviors", "create_time"),
                "NetworkTraffic": get_latest_time("NetworkTraffic", "create_time"),
                "AttackReports": get_latest_time("AttackReports", "created_at"),
            }
            rows = list_recent_attack_reports(limit=recent_limit)
            # Also try AnalysisReports
            try:
                from utils.db.db import fetch_all as _fa
                ar_rows = _fa("SELECT TOP 10 * FROM dbo.AnalysisReports ORDER BY created_at DESC")
                for ar in ar_rows:
                    rows.append({
                        "id": ar.get("id"), "scenario_id": ar.get("report_id"),
                        "victim_ip": "", "attacker_ip": "",
                        "confidence": ar.get("confidence"), "attribution_type": "Multi-Source LLM",
                        "attribution_name": ar.get("data_sources", ""),
                        "created_at": ar.get("created_at"),
                        "report_json": ar.get("report_json"),
                    })
            except: pass
        else:
            raise Exception("No DB")
    except Exception:
        # 降级到内存桥接层
        bridge = get_bridge()
        kpi = bridge.get_kpi()
        stats = {
            "log_count": kpi.get("HostLogs", 0),
            "process_count": kpi.get("HostBehaviors", 0),
            "flow_count": kpi.get("NetworkTraffic", 0),
            "attack_count": kpi.get("AttackReports", 0),
        }
        freshness = kpi.get("freshness", {
            "HostLogs": datetime.now().isoformat(),
            "HostBehaviors": datetime.now().isoformat(),
            "NetworkTraffic": datetime.now().isoformat(),
            "AttackReports": datetime.now().isoformat(),
        })
        rows = bridge.query("AttackReports", limit=recent_limit)

    recent_reports = []
    for r in rows:
        robj = _safe_parse_report_json(r.get("report_json"))
        recent_reports.append({
            "id": r.get("id"), "scenario_id": r.get("scenario_id"),
            "victim_ip": r.get("victim_ip"), "attacker_ip": r.get("attacker_ip"),
            "confidence": r.get("confidence"), "attribution_type": r.get("attribution_type"),
            "attribution_name": r.get("attribution_name"),
            "start_time": r.get("start_time"), "end_time": r.get("end_time"),
            "created_at": r.get("created_at"),
            "time_window": robj.get("time_window"),
            "trigger_technique": _infer_trigger_technique(
                robj, fallback=str(r.get("attribution_name") or "Attack Scenario")
            ),
        })

    return {"stats": stats, "freshness": freshness, "recent_reports": recent_reports}