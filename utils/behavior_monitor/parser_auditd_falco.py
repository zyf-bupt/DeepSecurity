"""
Linux Auditd & Falco parser — converts raw audit.log lines and Falco JSON into unified host_behavior dicts.

Auditd log format:  key=value pairs, e.g.:
  type=SYSCALL msg=audit(1234567890.123:456): arch=c000003e syscall=59 success=yes exit=0 ...

Falco JSON format (one per line):
  {"output":"...","priority":"Warning","rule":"...","time":"2026-07-09T14:30:00Z","output_fields":{...}}

Unified output:
  {timestamp, data_source, host_ip, event_type, entities, features, description}
"""
from __future__ import annotations

import json
import logging
import re
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)

# ── Auditd syscall → event_type mapping ─────────────────────────────
AUDITD_SYSCALL_MAP: dict[int, tuple[str, str]] = {
    59:  ("process_create", "execution"),      # execve
    56:  ("process_create", "execution"),      # clone
    57:  ("process_create", "execution"),      # fork
    58:  ("process_create", "execution"),      # vfork
    2:   ("file_access", "access"),            # open
    257: ("file_access", "access"),            # openat
    21:  ("file_access", "access"),            # access
    4:   ("file_access", "write"),             # write (stat)
    5:   ("file_access", "access"),            # fstat
    42:  ("network_connection", "connection"), # connect
    41:  ("network_connection", "connection"), # socket
    49:  ("network_connection", "connection"), # bind
    87:  ("file_delete", "deletion"),          # unlink
    263: ("file_delete", "deletion"),          # unlinkat
    84:  ("file_delete", "deletion"),          # rmdir
    3:   ("file_access", "read"),              # read
    0:   ("file_access", "read"),              # read (legacy)
    1:   ("file_access", "write"),             # write
}

# ── Falco rule → event_type mapping ──────────────────────────────────
FALCO_RULE_MAP: list[tuple[str, str]] = [
    # (substring match, event_type)
    ("shell", "process_create"),
    ("terminal shell", "process_create"),
    ("spawned", "process_create"),
    ("process", "process_create"),
    ("exec", "process_create"),
    ("file", "file_access"),
    ("write below", "file_access"),
    ("read", "file_access"),
    ("open", "file_access"),
    ("network", "network_connection"),
    ("connection", "network_connection"),
    ("outbound", "network_connection"),
    ("delete", "file_delete"),
    ("remove", "file_delete"),
    ("rm ", "file_delete"),
    ("change thread namespace", "process_injection"),
    ("ptrace", "process_injection"),
]


def _clean_field(value: str | None) -> str | None:
    if value is None:
        return None
    v = value.strip().strip('"').strip("'")
    return v or None


# ═══════════════════════════════════════════════════════════════════════
# Auditd parser
# ═══════════════════════════════════════════════════════════════════════


def parse_auditd_line(line: str, host_ip: str | None = None, host_name: str | None = None) -> dict | None:
    """
    Parse a single Linux Auditd raw log line into unified event dict.

    Example input:
      type=SYSCALL msg=audit(1700000000.123:456): arch=c000003e syscall=59 success=yes exit=0
        a0=7f... a1=7f... a2=7f... a3=7f... items=2 ppid=1234 pid=5678
        auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0
        tty=pts0 ses=1 comm="curl" exe="/usr/bin/curl" key="audit-exec"

    Returns unified dict or None on parse failure.
    """
    if not line or not isinstance(line, str):
        return None

    text = line.strip()
    if not text:
        return None

    # Extract the record type
    m = re.match(r'type=(\w+)', text)
    if not m:
        return None
    record_type = m.group(1)

    # Parse key=value pairs (handles quoted values)
    pairs: dict[str, str] = {}
    # Simple key=value split for known patterns
    for match in re.finditer(r'(\w+)=("(?:[^"\\]|\\.)*"|\'(?:[^\'\\]|\\.)*\'|\S+)', text):
        key = match.group(1)
        value = match.group(2).strip('\'"')
        pairs[key] = value

    # Extract timestamp from msg=audit(...) — must be valid; never fall back to now()
    ts_match = re.search(r'msg=audit\(([\d.]+):', text)
    timestamp: str | None = None
    if ts_match:
        try:
            ts_epoch = float(ts_match.group(1))
            timestamp = datetime.fromtimestamp(ts_epoch, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        except (ValueError, OSError):
            logger.debug("Auditd line rejected: unparseable timestamp in msg=audit(...)")
            return None
    else:
        logger.debug("Auditd line rejected: missing msg=audit(timestamp) pattern")
        return None

    # Determine syscall number
    syscall_num: int | None = None
    syscall_str = pairs.get("syscall")
    if syscall_str and syscall_str.isdigit():
        syscall_num = int(syscall_str)

    # Determine event_type
    if syscall_num in AUDITD_SYSCALL_MAP:
        event_type, action = AUDITD_SYSCALL_MAP[syscall_num]
    elif record_type in ("USER_AUTH", "USER_LOGIN", "USER_START", "USER_END", "CRED_ACQ", "CRED_REFR"):
        event_type, action = "user_auth", "authentication"
    elif record_type in ("USER_CMD",):
        event_type, action = "process_create", "execution"
    elif record_type in ("SERVICE_START", "SERVICE_STOP"):
        event_type, action = "service_event", record_type.lower()
    else:
        # Unsupported — return None to skip
        return None

    # Build entities
    entities: dict[str, Any] = {}

    pname = _clean_field(pairs.get("comm") or pairs.get("exe", "").split("/")[-1])
    exe_path = _clean_field(pairs.get("exe"))

    if pname:
        entities["process_name"] = pname
    if exe_path:
        entities["process_path"] = exe_path

    # PID / PPID
    for ak, ek in [("pid", "pid"), ("ppid", "parent_pid")]:
        if ak in pairs:
            try:
                entities[ek] = int(pairs[ak])
            except (ValueError, TypeError):
                pass

    # User
    for uk in ("uid", "auid", "euid"):
        if uk in pairs and uk not in entities:
            entities["user"] = pairs[uk]

    # Arguments (a0, a1, ...)
    args = []
    for i in range(6):
        arg_key = f"a{i}"
        if arg_key in pairs:
            args.append(pairs[arg_key])
    if args:
        entities["command_line"] = " ".join(args)

    # Key (audit rule key)
    if "key" in pairs:
        entities["audit_key"] = pairs["key"]

    # For network connections
    if event_type == "network_connection":
        # Try to extract addr from a0/a1 (sockaddr struct)
        # This is an approximation — real extraction is more complex
        entities["protocol"] = "tcp"  # default assumption for connect()

    # Build features
    features: dict[str, Any] = {}
    if "success" in pairs:
        features["success"] = pairs["success"] == "yes"
    if "exit" in pairs:
        features["exit_code"] = pairs["exit"]
    if "ses" in pairs:
        features["session_id"] = pairs["ses"]
    if "tty" in pairs:
        features["tty"] = pairs["tty"]
    if "arch" in pairs:
        features["arch"] = pairs["arch"]
    features["audit_type"] = record_type

    # Description
    pname_str = entities.get("process_name") or "unknown"
    pid_str = entities.get("pid", "?")
    desc = f"Auditd: {record_type} — {event_type} ({pname_str}, PID {pid_str})"

    return {
        "timestamp": timestamp,
        "data_source": "auditd",
        "host_ip": host_ip or "",
        "host_name": host_name or "",
        "event_type": event_type,
        "action": action,
        "entities": {k: v for k, v in entities.items() if v not in (None, "") or k in ("pid", "parent_pid")},
        "features": features,
        "description": desc,
    }


def parse_auditd_lines(lines: str | list[str], host_ip: str | None = None, host_name: str | None = None) -> list[dict]:
    """
    Parse multiple Auditd log lines (newline-separated string or list).
    """
    if isinstance(lines, str):
        lines = lines.splitlines()
    results: list[dict] = []
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            parsed = parse_auditd_line(line, host_ip=host_ip, host_name=host_name)
            if parsed:
                results.append(parsed)
        except Exception:
            logger.debug("Failed to parse auditd line", exc_info=True)
    return results


# ═══════════════════════════════════════════════════════════════════════
# Falco parser
# ═══════════════════════════════════════════════════════════════════════


def parse_falco_event(json_string: str, host_ip: str | None = None, host_name: str | None = None) -> dict | None:
    """
    Parse a single Falco JSON alert line into unified event dict.

    Example input:
      {"output":"14:30:00.123: Warning A shell was spawned in a container (user=root ...)",
       "priority":"Warning","rule":"A shell was spawned in a container",
       "time":"2026-07-09T14:30:00.123456789Z",
       "output_fields":{"container.id":"abc123","proc.name":"sh","proc.pid":1234,...}}

    Returns unified dict or None on parse failure.
    """
    if not json_string or not isinstance(json_string, str):
        return None

    try:
        data = json.loads(json_string.strip())
    except json.JSONDecodeError:
        logger.debug("Failed to parse Falco JSON")
        return None

    if not isinstance(data, dict):
        return None

    # Extract fields
    rule = str(data.get("rule") or "")
    priority = str(data.get("priority") or "Notice")
    output_fields: dict[str, Any] = data.get("output_fields") or {}

    # Parse timestamp — must be valid; never fall back to now()
    timestamp: str | None = None
    raw_time = data.get("time")
    if raw_time:
        if isinstance(raw_time, str):
            try:
                if raw_time.endswith("Z"):
                    timestamp = raw_time
                else:
                    dt = datetime.fromisoformat(raw_time.replace("Z", "+00:00"))
                    timestamp = dt.strftime("%Y-%m-%dT%H:%M:%SZ")
            except (ValueError, OSError):
                logger.debug("Falco event rejected: unparseable timestamp %r",
                             str(raw_time)[:60])
                return None
        else:
            logger.debug("Falco event rejected: timestamp is not a string (type=%s)",
                         type(raw_time).__name__)
            return None
    else:
        logger.debug("Falco event rejected: missing timestamp")
        return None

    # Determine event_type from rule name
    event_type = "unknown_behavior"
    rule_lower = rule.lower()
    for pattern, etype in FALCO_RULE_MAP:
        if pattern in rule_lower:
            event_type = etype
            break

    # Build entities from output_fields
    entities: dict[str, Any] = {}

    field_map = {
        "proc.name": "process_name",
        "proc.pname": "parent_process",
        "proc.exe": "process_path",
        "proc.cmdline": "command_line",
        "proc.pid": "pid",
        "proc.ppid": "parent_pid",
        "user.name": "user",
        "user.uid": "uid",
        "user.loginuid": "login_uid",
        "fd.name": "file_path",
        "fd.directory": "file_directory",
        "fd.filename": "file_name",
        "evt.dir": "event_direction",
        "container.id": "container_id",
        "container.name": "container_name",
        "evt.type": "syscall_type",
    }

    for src, dst in field_map.items():
        val = output_fields.get(src)
        if val is not None and val != "":
            if dst in ("pid", "parent_pid"):
                try:
                    entities[dst] = int(val)
                except (ValueError, TypeError):
                    entities[dst] = val
            else:
                entities[dst] = str(val)

    # Network-specific fields (for Falco network rules)
    for src, dst in [
        ("fd.sip", "src_ip"),
        ("fd.sport", "src_port"),
        ("fd.dip", "dst_ip"),
        ("fd.dport", "dst_port"),
        ("fd.l4proto", "protocol"),
    ]:
        val = output_fields.get(src)
        if val is not None and val != "":
            entities[dst] = str(val)

    # Features
    features: dict[str, Any] = {
        "priority": priority,
        "rule": rule,
        "falco_output": data.get("output", ""),
    }
    if "tags" in data:
        features["tags"] = data["tags"]
    if "hostname" in data:
        features["falco_hostname"] = data["hostname"]

    # Detect suspicious patterns
    rule_lower_full = rule.lower()
    if any(kw in rule_lower_full for kw in ("shell", "reverse", "c2", "malware", "trojan")):
        features["is_suspicious"] = True
        features["suspicious_reason"] = f"Falco rule match: {rule}"

    # Description
    evt_desc = data.get("output") or f"Falco: {rule}"
    desc = f"Falco [{priority}]: {evt_desc}"

    return {
        "timestamp": timestamp,
        "data_source": "falco",
        "host_ip": host_ip or "",
        "host_name": host_name or "",
        "event_type": event_type,
        "action": "alert",
        "entities": {k: v for k, v in entities.items() if v not in (None, "") or k in ("pid", "parent_pid")},
        "features": features,
        "description": desc[:500],
    }


def parse_falco_lines(lines: str | list[str], host_ip: str | None = None, host_name: str | None = None) -> list[dict]:
    """
    Parse multiple Falco JSON lines (one per line, newline-separated).
    """
    if isinstance(lines, str):
        lines = lines.splitlines()
    results: list[dict] = []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            parsed = parse_falco_event(line, host_ip=host_ip, host_name=host_name)
            if parsed:
                results.append(parsed)
        except Exception:
            logger.debug("Failed to parse Falco line", exc_info=True)
    return results
