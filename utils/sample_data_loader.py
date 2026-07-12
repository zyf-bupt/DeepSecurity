"""
Centralized sample data loader — reads sample files, parses through respective parsers, and ingests.

Used by the /datasource API for demo / verification workflows.
"""
from __future__ import annotations

import json
import logging
import os
from typing import Any

logger = logging.getLogger(__name__)

# Base directory for sample data files
_SAMPLE_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "samples")


def _read_json_file(filename: str) -> list[dict]:
    """Read a JSON file (list of objects or one object per line) from samples dir."""
    path = os.path.join(_SAMPLE_DIR, filename)
    if not os.path.isfile(path):
        logger.warning("Sample file not found: %s", path)
        return []
    with open(path, "r", encoding="utf-8") as f:
        content = f.read()
    if not content.strip():
        return []
    try:
        data = json.loads(content)
        if isinstance(data, list):
            return data
        if isinstance(data, dict):
            return [data]
        return []
    except json.JSONDecodeError:
        # Try JSON lines format
        result = []
        for line in content.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                if isinstance(obj, dict):
                    result.append(obj)
            except json.JSONDecodeError:
                continue
        return result


def _read_text_file(filename: str) -> str:
    """Read text file from samples dir."""
    path = os.path.join(_SAMPLE_DIR, filename)
    if not os.path.isfile(path):
        logger.warning("Sample file not found: %s", path)
        return ""
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


# ═══════════════════════════════════════════════════════════════════════


def load_sysmon_samples(host_name: str = "win-dc01-sysmon") -> dict[str, int]:
    """
    Load and ingest Sysmon sample events.
    Returns {collected, inserted, skipped, errors}.
    """
    from utils.winlog.service.sysmon_ingest import ingest_sysmon_events

    raw_data = _read_json_file("sysmon_samples.json")
    if not raw_data:
        return {"collected": 0, "inserted": 0, "skipped": 0, "errors": 1, "error": "no sample data"}

    # Extract XML strings
    events: list[str] = []
    for item in raw_data:
        xml = item.get("xml") or item.get("_raw_xml") or ""
        if xml:
            events.append(xml)

    # Build raw content for storage
    raw_content = json.dumps(raw_data, ensure_ascii=False, indent=2)

    return ingest_sysmon_events(
        events=events,
        raw_content=raw_content,
        host_name=host_name,
    )


def load_auditd_samples(host_name: str = "linux-server-auditd") -> dict[str, int]:
    """
    Load and ingest Auditd sample events.
    Returns {collected, inserted, skipped, errors}.
    """
    from utils.behavior_monitor.service.auditd_ingest import ingest_auditd_events

    raw_data = _read_json_file("auditd_samples.json")
    if not raw_data:
        return {"collected": 0, "inserted": 0, "skipped": 0, "errors": 1, "error": "no sample data"}

    events: list[str] = []
    for item in raw_data:
        line = item.get("line", "")
        if line:
            events.append(line)

    raw_content = json.dumps(raw_data, ensure_ascii=False, indent=2)

    return ingest_auditd_events(
        events=events,
        raw_content=raw_content,
        host_name=host_name,
    )


def load_falco_samples(host_name: str = "linux-server-falco") -> dict[str, int]:
    """
    Load and ingest Falco sample events.
    Returns {collected, inserted, skipped, errors}.
    """
    from utils.behavior_monitor.service.auditd_ingest import ingest_falco_events

    raw_data = _read_json_file("falco_samples.json")
    if not raw_data:
        return {"collected": 0, "inserted": 0, "skipped": 0, "errors": 1, "error": "no sample data"}

    events: list[str] = []
    for item in raw_data:
        line = item.get("json", "")
        if line:
            events.append(line)

    raw_content = json.dumps(raw_data, ensure_ascii=False, indent=2)

    return ingest_falco_events(
        events=events,
        raw_content=raw_content,
        host_name=host_name,
    )


def load_zeek_samples(host_name: str = "zeek-sensor") -> dict[str, int]:
    """
    Load and ingest Zeek sample events (conn.log).
    Returns {inserted, skipped, errors}.
    """
    from utils.traffic_fenxi.ingest_zeek_suricata import ingest_zeek_file

    file_path = os.path.join(_SAMPLE_DIR, "zeek_conn.log")
    return ingest_zeek_file(
        file_path=file_path,
        host_name=host_name,
        log_type="conn",
    )


def load_suricata_samples(host_name: str = "suricata-sensor") -> dict[str, int]:
    """
    Load and ingest Suricata sample events (eve.json lines).
    Returns {inserted, skipped, errors}.
    """
    from utils.traffic_fenxi.ingest_zeek_suricata import ingest_suricata_lines

    raw_data = _read_json_file("suricata_samples.json")
    if not raw_data:
        return {"inserted": 0, "skipped": 0, "errors": 1, "error": "no sample data"}

    lines: list[str] = []
    for item in raw_data:
        line = item.get("json", "")
        if line:
            lines.append(line)

    raw_content = json.dumps(raw_data, ensure_ascii=False, indent=2)

    return ingest_suricata_lines(
        lines=lines,
        raw_content=raw_content,
        host_name=host_name,
    )


# ═══════════════════════════════════════════════════════════════════════


def load_all_samples() -> dict[str, Any]:
    """
    Load all sample data for all sources.
    Returns {source_name: {inserted, skipped, errors}, ...}
    """
    results: dict[str, Any] = {}

    for source_name, loader in [
        ("sysmon", load_sysmon_samples),
        ("auditd", load_auditd_samples),
        ("falco", load_falco_samples),
        ("zeek", load_zeek_samples),
        ("suricata", load_suricata_samples),
    ]:
        try:
            results[source_name] = loader()
        except Exception as exc:
            logger.exception("Failed to load %s samples", source_name)
            results[source_name] = {
                "inserted": 0, "skipped": 0, "errors": 1,
                "error": str(exc)[:200],
            }

    return results


def load_sample(source_name: str) -> dict[str, int]:
    """
    Load sample data for a single source.

    Args:
        source_name: One of "sysmon", "auditd", "falco", "zeek", "suricata"
    """
    loaders = {
        "sysmon": load_sysmon_samples,
        "auditd": load_auditd_samples,
        "falco": load_falco_samples,
        "zeek": load_zeek_samples,
        "suricata": load_suricata_samples,
    }

    loader = loaders.get(source_name)
    if not loader:
        return {"inserted": 0, "skipped": 0, "errors": 1, "error": f"unknown source: {source_name}"}

    return loader()
