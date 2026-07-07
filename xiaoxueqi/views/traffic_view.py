"""
网络流量分析视图（dumpcap 稳定版）
- 在线抓包：dumpcap 子进程写 pcapng
- 停止抓包：读取 pcapng -> 解析 -> 入库
- 避免 scapy AsyncSniffer 导致 Python 进程崩溃
"""
from __future__ import annotations

import os
import time
import threading
import json
from pathlib import Path

from flask import Blueprint, current_app, jsonify, render_template, request, abort, url_for

from config import Config
from utils.traffic_fenxi.parser import PcapParser
from utils.traffic_fenxi.ingest_offline import ingest_pcap_to_database
from utils.traffic_fenxi.live_capture_dumpcap import DumpcapCaptureConfig, DumpcapCaptureHandle
from utils.traffic_fenxi.storage_sqlserver import (
    get_networktraffic_by_id,
    list_networktraffic,
    parse_result_json,
)

bp = Blueprint("traffic", __name__)

PAGE_SIZE = 20


def _get_conn_str() -> str:
    return Config.SQL_CONN_STR


# =========================
# 全局 Live Capture 管理（dumpcap handle）
# =========================
class _TrafficCaptureManager:
    def __init__(self):
        self.lock = threading.Lock()
        self.handle: DumpcapCaptureHandle | None = None
        self.last_error: str | None = None
        self.last_error_time: float | None = None
        self.last_capture_file: str | None = None
        self.last_import: dict | None = None


def _mgr() -> _TrafficCaptureManager:
    mgr = current_app.extensions.get("traffic_capture_manager")
    if mgr is None:
        mgr = _TrafficCaptureManager()
        current_app.extensions["traffic_capture_manager"] = mgr
    return mgr


# =========================
# event_type 筛选
# =========================
def _event_type_options() -> list[dict[str, str]]:
    return [
        {"value": "", "label": "全部"},
        {"value": "__alert__", "label": "仅告警（suspected）"},
        {"value": "dns_tunnel_suspected", "label": "DNS 隧道（suspected）"},
        {"value": "http_tunnel_suspected", "label": "HTTP 隧道（suspected）"},
        {"value": "icmp_tunnel_suspected", "label": "ICMP 隧道（suspected）"},
        {"value": "dns_query", "label": "DNS 查询（dns_query）"},
        {"value": "tcp_connection", "label": "TCP 连接（tcp_connection）"},
    ]


def _filter_match_event_type(event_type_value: str, item_event_type: str) -> bool:
    if not event_type_value:
        return True
    if event_type_value == "__alert__":
        return "suspected" in (item_event_type or "")
    return (item_event_type or "") == event_type_value


def _row_to_list_item(r) -> dict:
    ev = parse_result_json(r.result)
    return {
        "id": r.id,
        "create_time": str(r.create_time or ""),
        "timestamp": str(ev.get("timestamp") or ""),
        "src_ip": ev.get("src_ip") or "",
        "dst_ip": ev.get("dst_ip") or "",
        "protocol": ev.get("protocol") or "",
        "event_type": ev.get("event_type") or "",
        "description": (ev.get("description") or ""),
    }


@bp.route("/api/list", methods=["GET"])
def api_traffic_list():
    """Dedicated JSON endpoint for the Vue SPA — always returns JSON from both sources"""
    page = request.args.get("page", 1, type=int)
    page = max(page, 1)
    event_type = (request.args.get("event_type") or "").strip()

    all_items: list[dict] = []
    debug = {"sql_rows": 0, "sql_error": None, "bridge_rows": 0, "bridge_error": None}

    # Read from SQL Server
    try:
        rows = list_networktraffic(offset=0, limit=2000, host_name=None, conn_str=_get_conn_str())
        debug["sql_rows"] = len(rows)
        for r in rows:
            all_items.append(_row_to_list_item(r))
    except Exception as e:
        debug["sql_error"] = str(e)[:200]

    # Read from DataBridge ONLY if SQL returned nothing
    if debug["sql_rows"] == 0:
        try:
            from utils.data_bridge import get_bridge
            bridge = get_bridge()
            db_rows = bridge.query("NetworkTraffic", order_by="create_time", desc=True, limit=500)
            debug["bridge_rows"] = len(db_rows)
            for r in db_rows:
                ev = parse_result_json(r.get("result", ""))
                all_items.append({
                    "id": r.get("id", 0),
                    "create_time": str(r.get("create_time") or ""),
                    "timestamp": str(ev.get("timestamp") or ""),
                    "src_ip": ev.get("src_ip") or "",
                    "dst_ip": ev.get("dst_ip") or "",
                    "protocol": ev.get("protocol") or "",
                    "event_type": ev.get("event_type") or "",
                    "description": ev.get("description") or "",
                })
        except Exception as e:
            debug["bridge_error"] = str(e)[:200]

    filtered = [it for it in all_items if _filter_match_event_type(event_type, it.get("event_type") or "")]
    filtered.sort(key=lambda x: str(x.get("create_time", "")), reverse=True)

    total = len(filtered)
    total_pages = max((total + PAGE_SIZE - 1) // PAGE_SIZE, 1)
    if page > total_pages:
        page = total_pages
    start = (page - 1) * PAGE_SIZE
    items = filtered[start: start + PAGE_SIZE]

    return jsonify({
        "ok": True, "items": items, "total": total,
        "page": page, "total_pages": total_pages, "page_size": PAGE_SIZE,
        "_debug": debug,
    })


@bp.route("/", methods=["GET"])
def index():
    page = request.args.get("page", 1, type=int)
    page = max(page, 1)
    event_type = (request.args.get("event_type") or "").strip()

    all_items: list[dict] = []

    # 1) Try SQL Server first
    try:
        scan_limit = 2000
        rows = list_networktraffic(offset=0, limit=scan_limit, host_name=None, conn_str=_get_conn_str())
        for r in rows:
            all_items.append(_row_to_list_item(r))
    except Exception:
        pass  # will fall back to DataBridge below

    # 2) Always also read from DataBridge (captures/uploads go there when SQL is down)
    try:
        from utils.data_bridge import get_bridge
        bridge = get_bridge()
        db_rows = bridge.query("NetworkTraffic", order_by="create_time", desc=True, limit=2000)
        for r in db_rows:
            ev = parse_result_json(r.get("result", ""))
            all_items.append({
                "id": r.get("id", 0) + 100000,  # offset to avoid collision with SQL rows
                "create_time": str(r.get("create_time") or ""),
                "timestamp": str(ev.get("timestamp") or ""),
                "src_ip": ev.get("src_ip") or "",
                "dst_ip": ev.get("dst_ip") or "",
                "protocol": ev.get("protocol") or "",
                "event_type": ev.get("event_type") or "",
                "description": ev.get("description") or "",
            })
    except Exception:
        pass

    # 3) Filter, sort, paginate
    filtered = [it for it in all_items if _filter_match_event_type(event_type, it.get("event_type") or "")]
    filtered.sort(key=lambda x: x.get("create_time", ""), reverse=True)

    total = len(filtered)
    total_pages = max((total + PAGE_SIZE - 1) // PAGE_SIZE, 1)
    if page > total_pages:
        page = total_pages
    start = (page - 1) * PAGE_SIZE
    items = filtered[start : start + PAGE_SIZE]

    # JSON API for SPA frontend
    if request.headers.get("Accept") == "application/json" or request.args.get("format") == "json":
        return jsonify({
            "ok": True, "items": items, "total": total,
            "page": page, "total_pages": total_pages, "page_size": PAGE_SIZE,
        })

    mgr = _mgr()
    with mgr.lock:
        live_status = mgr.handle.status() if mgr.handle else {"running": False}
        last_capture_file = mgr.last_capture_file
        last_import = mgr.last_import
        last_error = mgr.last_error

    return render_template(
        "traffic.html",
        items=items,
        page=page,
        total=total,
        total_pages=total_pages,
        page_size=PAGE_SIZE,
        event_type=event_type,
        event_type_options=_event_type_options(),
        live_status=live_status,
        last_capture_file=last_capture_file,
        last_import=last_import,
        last_error=last_error,
    )


# =========================
# Live capture APIs（dumpcap）
# =========================
@bp.route("/api/dumpcap/info", methods=["GET"])
def api_dumpcap_info():
    """Return auto-detected dumpcap path and available interfaces"""
    import subprocess as _sp
    dumpcap_path = _resolve_dumpcap_path()
    info = {"dumpcap_path": dumpcap_path, "found": os.path.isfile(dumpcap_path), "interfaces": []}
    if info["found"]:
        try:
            # Use shell=True for proper PATH resolution on Windows
            result = _sp.run(
                [dumpcap_path, "-D"],
                capture_output=True, timeout=10, shell=True,
                encoding="utf-8", errors="replace",  # handle GBK chars
            )
            for line in (result.stdout or "").splitlines():
                line = line.strip()
                # Format: "1. \Device\NPF_{GUID} (description)" or without desc
                if not line or '.' not in line:
                    continue
                # Split at first ". " to get index and rest
                dot_idx = line.find('.')
                if dot_idx <= 0:
                    continue
                num = line[:dot_idx].strip()
                rest = line[dot_idx + 1:].strip()
                if not rest:
                    continue
                # Extract description in last parentheses
                iface_id = rest
                desc = ""
                if '(' in rest and rest.endswith(')'):
                    paren_idx = rest.rfind('(')
                    iface_id = rest[:paren_idx].strip()
                    desc = rest[paren_idx + 1:-1].strip()
                elif '(' in rest and ')' in rest:
                    paren_idx = rest.rfind('(')
                    iface_id = rest[:paren_idx].strip()
                    desc = rest[paren_idx + 1:rest.rfind(')')].strip()
                info["interfaces"].append({"index": num, "id": iface_id, "description": desc})
        except Exception as e:
            info["error"] = str(e)
    return jsonify({"ok": True, **info})


@bp.route("/api/live/status", methods=["GET"])
def api_live_status():
    mgr = _mgr()
    with mgr.lock:
        st = mgr.handle.status() if mgr.handle else {"running": False, "iface": None, "bpf": None, "pcap_file": None, "uptime_sec": 0}
        return jsonify(
            {
                "ok": True,
                **st,
                "last_error": mgr.last_error,
                "last_error_time": mgr.last_error_time,
                "last_capture_file": mgr.last_capture_file,
                "last_import": mgr.last_import,
            }
        )


def _resolve_dumpcap_path(user_path: str = "") -> str:
    """Resolve dumpcap path: user specified > env var > auto-detect PATH > common locations"""
    import shutil as _shutil
    if user_path and os.path.isfile(user_path):
        return user_path
    # Check env var
    env_path = os.environ.get("DUMPCAP_PATH", "")
    if env_path and os.path.isfile(env_path):
        return env_path
    # Check PATH
    found = _shutil.which("dumpcap")
    if found:
        return found
    # Common install locations
    for candidate in [
        r"E:\Wireshark\dumpcap.exe",
        r"D:\Wireshark\dumpcap.exe",
        r"C:\Program Files\Wireshark\dumpcap.exe",
        r"C:\Program Files (x86)\Wireshark\dumpcap.exe",
    ]:
        if os.path.isfile(candidate):
            return candidate
    return Config.DUMPCAP_PATH or r"C:\Program Files\Wireshark\dumpcap.exe"


@bp.route("/api/live/start", methods=["POST"])
def api_live_start():
    payload = request.get_json(silent=True) or {}
    iface = (payload.get("iface") or "").strip()
    bpf = (payload.get("bpf") or "").strip() or None
    host_name = (payload.get("host_name") or "").strip() or None
    dumpcap_path = _resolve_dumpcap_path((payload.get("dumpcap_path") or "").strip())

    if not iface:
        return jsonify({"ok": False, "error": "iface required"}), 400

    if not os.path.isfile(dumpcap_path):
        return jsonify({"ok": False, "error": f"dumpcap not found: {dumpcap_path}. Set DUMPCAP_PATH env var or install Wireshark."}), 400

    mgr = _mgr()
    with mgr.lock:
        try:
            if mgr.handle and mgr.handle.is_running():
                return jsonify({"ok": False, "error": "live capture already running"}), 400

            cfg = DumpcapCaptureConfig(
                iface=iface,
                bpf=bpf,
                dumpcap_path=dumpcap_path,
                output_dir=Config.LIVE_CAPTURE_DIR,
                host_name=host_name or iface,
            )
            mgr.handle = DumpcapCaptureHandle(cfg)
            info = mgr.handle.start()

            mgr.last_error = None
            mgr.last_error_time = None
            mgr.last_capture_file = mgr.handle.pcap_file
            mgr.last_import = None

            return jsonify({"ok": True, "message": "started", "capture": info, "status": mgr.handle.status()})
        except Exception as exc:
            mgr.last_error = f"live start failed: {exc}"
            mgr.last_error_time = time.time()
            mgr.handle = None
            return jsonify({"ok": False, "error": str(exc)}), 500


@bp.route("/api/live/stop", methods=["POST"])
def api_live_stop():
    """
    stop 后会自动导入入库（离线解析）
    body 可选：
    {
      "enable_analysis": true,
      "host_name": "VMnet1"
    }
    """
    payload = request.get_json(silent=True) or {}
    enable_analysis = bool(payload.get("enable_analysis", True))
    host_name = (payload.get("host_name") or "").strip() or None

    mgr = _mgr()
    with mgr.lock:
        if not mgr.handle:
            return jsonify({"ok": True, "message": "already stopped", "import": mgr.last_import})

        handle = mgr.handle
        mgr.handle = None

    # stop & import 放到锁外，避免卡住其他请求
    try:
        stop_info = handle.stop()
        pcap_file = stop_info.get("pcap_file") or handle.pcap_file
        if not pcap_file or not os.path.exists(pcap_file):
            raise RuntimeError(f"capture file missing: {pcap_file}")

        parser = PcapParser(pcap_file)
        if not parser.load():
            raise RuntimeError("failed to read captured pcap")

        parsed_packets = parser.parse_all()
        raw_content = parser.get_raw_content()

        import_result = ingest_pcap_to_database(
            parsed_packets=parsed_packets,
            raw_content=raw_content,
            conn_str=_get_conn_str(),
            enable_analysis=enable_analysis,
            host_name=host_name or (handle.cfg.host_name or "live_capture"),
        )

        with mgr.lock:
            mgr.last_capture_file = pcap_file
            mgr.last_import = import_result
            mgr.last_error = None
            mgr.last_error_time = None

        return jsonify({"ok": True, "message": "stopped_and_imported", "pcap_file": pcap_file, "import": import_result})
    except Exception as exc:
        with mgr.lock:
            mgr.last_error = f"live stop/import failed: {exc}"
            mgr.last_error_time = time.time()
        return jsonify({"ok": False, "error": str(exc)}), 500


# =========================
# Offline upload
# =========================
@bp.route("/api/upload", methods=["POST"])
def api_upload():
    if "file" not in request.files:
        return jsonify({"ok": False, "error": "file required"}), 400

    f = request.files["file"]
    if not f or not f.filename:
        return jsonify({"ok": False, "error": "invalid file"}), 400

    host_name = (request.form.get("host_name") or "").strip() or None
    enable_analysis = (request.form.get("enable_analysis") or "").strip() not in ("0", "false", "False")

    filename = f.filename
    ext = Path(filename).suffix.lower()
    if ext not in (".pcap", ".pcapng", ".cap"):
        return jsonify({"ok": False, "error": "only .pcap/.pcapng/.cap supported"}), 400

    upload_dir = current_app.config.get("UPLOAD_FOLDER") or Config.UPLOAD_FOLDER
    os.makedirs(upload_dir, exist_ok=True)

    saved_path = os.path.join(upload_dir, f"{int(time.time())}_{filename}")
    f.save(saved_path)

    parser = PcapParser(saved_path)
    if not parser.load():
        return jsonify({"ok": False, "error": "failed to read pcap"}), 500

    parsed_packets = parser.parse_all()
    raw_content = parser.get_raw_content()

    result = ingest_pcap_to_database(
        parsed_packets=parsed_packets,
        raw_content=raw_content,
        conn_str=_get_conn_str(),
        enable_analysis=enable_analysis,
        host_name=host_name or filename,
    )
    return jsonify({"ok": True, "saved_path": saved_path, "result": result})


# =========================
# Detail APIs / pages（修正路由：必须带 traffic_id）
# =========================
@bp.route("/api/detail/<int:traffic_id>", methods=["GET"])
def api_detail(traffic_id: int):
    row = get_networktraffic_by_id(traffic_id, conn_str=_get_conn_str())
    if not row:
        return jsonify({"ok": False, "error": "not found"}), 404
    ev = parse_result_json(row.result)
    return jsonify(
        {
            "ok": True,
            "row": {
                "id": row.id,
                "create_time": str(row.create_time or ""),
                "event_hash": row.event_hash,
                "host_name": row.host_name,
                "event_time_utc": str(row.event_time_utc or ""),
                "result": ev,
                "content": row.content,
            },
        }
    )


@bp.route("/detail/<int:traffic_id>", methods=["GET"])
def detail_page(traffic_id: int):
    row = get_networktraffic_by_id(traffic_id, conn_str=_get_conn_str())
    if not row:
        abort(404)

    ev = parse_result_json(row.result) or {}
    pretty = json.dumps(ev, ensure_ascii=False, indent=2) if ev else (row.result or "")
    back_url = url_for("traffic.index", event_type=(request.args.get("event_type") or "").strip() or None)

    return render_template(
        "traffic_detail.html",
        traffic={
            "id": row.id,
            "create_time": str(row.create_time or ""),
            "event_hash": row.event_hash,
            "event_time_utc": str(row.event_time_utc or ""),
            "timestamp": str(ev.get("timestamp") or ""),
            "src_ip": ev.get("src_ip") or "",
            "dst_ip": ev.get("dst_ip") or "",
            "protocol": ev.get("protocol") or "",
            "event_type": ev.get("event_type") or "",
            "description": ev.get("description") or "",
            "result_json_pretty": pretty,
            "raw_content": row.content or "",
            "back_url": back_url,
        },
    )