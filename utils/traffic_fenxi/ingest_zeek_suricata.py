"""
Zeek & Suricata ingest service — orchestrates parsing and inserting into NetworkTraffic table.
Follows the pattern of ingest_offline.py.
"""
from __future__ import annotations

import json
import logging
from typing import Any

from utils.traffic_fenxi.parser_zeek_suricata import (
    parse_zeek_log,
    parse_zeek_file,
    parse_suricata_eve,
    parse_suricata_file,
)
from utils.traffic_fenxi.storage_sqlserver import insert_networktraffic_from_dict
from utils.datasource_status import get_status_tracker

logger = logging.getLogger(__name__)


# ── Zeek ──────────────────────────────────────────────────────────────


def ingest_zeek_entries(
    *,
    entries: list[dict],
    raw_content: str | None = None,
    host_name: str | None = None,
    log_type: str = "conn",
    collected_override: int | None = None,
) -> dict[str, int]:
    """
    Ingest pre-parsed Zeek log entries (unified dicts) into NetworkTraffic.

    Args:
        entries: List of unified event dicts from parse_zeek_log / parse_zeek_file
        raw_content: Raw log file content
        host_name: Sensor name
        log_type: Log type for status reporting
        collected_override: If set, use this as collected count instead of len(entries).
                            Use when the caller pre-filters lines and some are not parseable.

    Returns:
        {collected, inserted, skipped, errors}
    """
    collected = collected_override if collected_override is not None else len(entries)
    inserted = 0
    skipped = 0
    errors = 0

    for ev in entries:
        try:
            ev.setdefault("data_source", "zeek")
            if host_name:
                ev.setdefault("host_name", host_name)

            result = insert_networktraffic_from_dict(
                result_dict=ev,
                content=raw_content or json.dumps(ev, ensure_ascii=False),
                host_name=host_name or ev.get("host_name"),
            )
            inserted += result.get("inserted", 0)
            skipped += result.get("skipped", 0)
            errors += result.get("errors", 0)
        except Exception:
            errors += 1
            logger.debug("Zeek ingest error", exc_info=True)

    tracker = get_status_tracker()
    tracker.record_ingestion(
        "zeek",
        inserted=inserted, skipped=skipped, errors=errors,
        collected=collected, host_name=host_name,
    )

    return {"collected": collected, "inserted": inserted, "skipped": skipped, "errors": errors}


def ingest_zeek_log_lines(
    *,
    lines: list[str],
    raw_content: str | None = None,
    host_name: str | None = None,
    log_type: str = "conn",
) -> dict[str, int]:
    """
    Parse raw Zeek TSV log lines and ingest into NetworkTraffic.

    Args:
        lines: Raw log lines (including #fields header for first line)
        raw_content: Original raw content
        host_name: Sensor name
        log_type: One of "conn", "dns", "http", "files", "ssl"

    Returns:
        {collected, inserted, skipped, errors}
    """
    attempt_count = 0
    parsed: list[dict] = []
    for line in lines:
        if not line or not isinstance(line, str):
            continue
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        attempt_count += 1
        ev = parse_zeek_log(line, log_type=log_type, host_name=host_name)
        if ev:
            parsed.append(ev)

    return ingest_zeek_entries(
        entries=parsed,
        raw_content=raw_content or "\n".join(lines),
        host_name=host_name,
        log_type=log_type,
        collected_override=attempt_count,
    )


def ingest_zeek_file(
    *,
    file_path: str,
    host_name: str | None = None,
    log_type: str | None = None,
) -> dict[str, int]:
    """
    Parse a Zeek .log file and ingest all records.

    Args:
        file_path: Path to the .log file
        host_name: Sensor name
        log_type: Override log type (auto-detected from filename)

    Returns:
        {inserted, skipped, errors}
    """
    with open(file_path, "r", encoding="utf-8", errors="replace") as f:
        raw_content = f.read()

    entries = parse_zeek_file(file_path, log_type=log_type, host_name=host_name)

    return ingest_zeek_entries(
        entries=entries,
        raw_content=raw_content,
        host_name=host_name,
        log_type=log_type or "conn",
    )


# ── Suricata ──────────────────────────────────────────────────────────


def ingest_suricata_entries(
    *,
    entries: list[dict],
    raw_content: str | None = None,
    host_name: str | None = None,
    collected_override: int | None = None,
) -> dict[str, int]:
    """
    Ingest pre-parsed Suricata eve.json entries (unified dicts) into NetworkTraffic.

    Args:
        collected_override: If set, use this as collected count instead of len(entries).

    Returns:
        {collected, inserted, skipped, errors}
    """
    collected = collected_override if collected_override is not None else len(entries)
    inserted = 0
    skipped = 0
    errors = 0

    for ev in entries:
        try:
            ev.setdefault("data_source", "suricata")
            if host_name:
                ev.setdefault("host_name", host_name)

            result = insert_networktraffic_from_dict(
                result_dict=ev,
                content=raw_content or json.dumps(ev, ensure_ascii=False),
                host_name=host_name or ev.get("host_name"),
            )
            inserted += result.get("inserted", 0)
            skipped += result.get("skipped", 0)
            errors += result.get("errors", 0)
        except Exception:
            errors += 1
            logger.debug("Suricata ingest error", exc_info=True)

    tracker = get_status_tracker()
    tracker.record_ingestion(
        "suricata",
        inserted=inserted, skipped=skipped, errors=errors,
        collected=collected, host_name=host_name,
    )

    return {"collected": collected, "inserted": inserted, "skipped": skipped, "errors": errors}


def ingest_suricata_lines(
    *,
    lines: list[str],
    raw_content: str | None = None,
    host_name: str | None = None,
) -> dict[str, int]:
    """
    Parse raw Suricata eve.json lines and ingest into NetworkTraffic.

    Returns:
        {collected, inserted, skipped, errors}
    """
    attempt_count = 0
    parsed: list[dict] = []
    for line in lines:
        if not line or not isinstance(line, str):
            continue
        line = line.strip()
        if not line:
            continue
        attempt_count += 1
        ev = parse_suricata_eve(line, host_name=host_name)
        if ev:
            parsed.append(ev)

    return ingest_suricata_entries(
        entries=parsed,
        raw_content=raw_content or "\n".join(lines),
        host_name=host_name,
        collected_override=attempt_count,
    )


def ingest_suricata_file(
    *,
    file_path: str,
    host_name: str | None = None,
) -> dict[str, int]:
    """
    Parse a Suricata eve.json file and ingest all records.

    Returns:
        {inserted, skipped, errors}
    """
    with open(file_path, "r", encoding="utf-8", errors="replace") as f:
        raw_content = f.read()

    entries = parse_suricata_file(file_path, host_name=host_name)

    return ingest_suricata_entries(
        entries=entries,
        raw_content=raw_content,
        host_name=host_name,
    )
