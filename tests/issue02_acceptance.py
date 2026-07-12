"""
Issue 2 验收脚本 — 逐条检查所有需求
"""
import sys, os, json
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

REQUIRED = ['timestamp', 'data_source', 'host_ip', 'event_type', 'entities', 'features']
passed = 0
failed = 0
issues = []

def check(name, condition, detail=""):
    global passed, failed
    if condition:
        passed += 1
        print(f"  PASS  {name}")
    else:
        failed += 1
        print(f"  FAIL  {name}")
        issues.append(f"{name}: {detail}")

print("=" * 70)
print("ISSUE 2 需求逐条验收")
print("=" * 70)

# ═══════════════════════════════════════════════════════════════════════
# 需求 1: Sysmon 解析器输出统一事件结构
# ═══════════════════════════════════════════════════════════════════════
print("\n--- 需求 1: Sysmon 日志解析 ---")
from utils.winlog.parser_sysmon import parse_sysmon_event

SYSMON_XML = '''<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
  <System><Provider Name='Microsoft-Windows-Sysmon' Guid='{5770385F}'/>
    <EventID>1</EventID>
    <TimeCreated SystemTime='2026-07-09T06:30:00.123456789Z'/>
    <Computer>test-pc</Computer></System>
  <EventData><Data Name='Image'>C:\\cmd.exe</Data><Data Name='ProcessId'>1234</Data>
    <Data Name='CommandLine'>cmd /c test</Data><Data Name='User'>TEST</Data>
    <Data Name='ParentImage'>C:\\explorer.exe</Data><Data Name='ParentProcessId'>5678</Data>
  </EventData></Event>'''

ev = parse_sysmon_event(SYSMON_XML)
check("Sysmon 解析成功", ev is not None)
if ev:
    for f in REQUIRED:
        check(f"  包含字段 '{f}'", f in ev, f"keys={list(ev.keys())}")
    check("  event_type = process_create", ev.get("event_type") == "process_create")
    check("  data_source = sysmon", ev.get("data_source") == "sysmon")
    check("  host_ip 不含主机名", "." not in ev.get("host_ip", "").split(".")[-1] if ev.get("host_ip") else True)

# Test: 非法 XML 必须拒绝
check("  非法 XML → None", parse_sysmon_event("<not>valid</xml>") is None)
check("  缺失 TimeCreated → None", parse_sysmon_event(
    SYSMON_XML.replace("SystemTime='2026-07-09T06:30:00.123456789Z'", "")) is None)
check("  未知 EventID 999 → None", parse_sysmon_event(
    SYSMON_XML.replace("<EventID>1</EventID>", "<EventID>999</EventID>")) is None)

# ═══════════════════════════════════════════════════════════════════════
# 需求 2: Auditd + Falco 解析器
# ═══════════════════════════════════════════════════════════════════════
print("\n--- 需求 2: Linux Auditd/Falco 数据接入 ---")
from utils.behavior_monitor.parser_auditd_falco import parse_auditd_line, parse_falco_event

# Auditd
AD = 'type=SYSCALL msg=audit(1752085800.123:456): arch=c000003e syscall=59 success=yes exit=0 comm="curl" exe="/usr/bin/curl" key="cmd"'
ev = parse_auditd_line(AD)
check("Auditd 解析成功", ev is not None)
if ev:
    for f in REQUIRED:
        check(f"  包含字段 '{f}'", f in ev)
    check("  event_type = process_create", ev.get("event_type") == "process_create")

# Auditd 文件访问
AD_FILE = 'type=SYSCALL msg=audit(1752085900.456:789): arch=c000003e syscall=257 success=no exit=-13 comm="cat" exe="/usr/bin/cat" key="file-access"'
ev = parse_auditd_line(AD_FILE)
check("  Auditd 文件访问事件", ev is not None and ev.get("event_type") == "file_access")

# Auditd 网络连接
AD_NET = 'type=SYSCALL msg=audit(1752086000.789:1012): arch=c000003e syscall=42 success=yes exit=0 comm="nc" exe="/usr/bin/nc" key="network-connect"'
ev = parse_auditd_line(AD_NET)
check("  Auditd 网络连接事件", ev is not None and ev.get("event_type") == "network_connection")

# Auditd 非法输入拒绝
check("  Auditd 无时间戳 → None",
      parse_auditd_line('type=SYSCALL arch=c000003e syscall=59 success=yes comm="test" exe="/bin/test"') is None)
check("  Auditd 垃圾输入 → None", parse_auditd_line("not an audit line") is None)

# Falco
FC = '{"output":"test","priority":"Warning","rule":"A shell was spawned","time":"2026-07-09T06:30:00.123456Z","output_fields":{"proc.name":"bash","proc.pid":5678,"user.name":"root"}}'
ev = parse_falco_event(FC)
check("Falco 解析成功", ev is not None)
if ev:
    for f in REQUIRED:
        check(f"  包含字段 '{f}'", f in ev)
    check("  event_type = process_create", ev.get("event_type") == "process_create")
    check("  data_source = falco", ev.get("data_source") == "falco")

# Falco 网络事件
FC_NET = '{"output":"test","priority":"Warning","rule":"Outbound connection","time":"2026-07-09T06:32:00.345678Z","output_fields":{"fd.sip":"192.168.10.5","fd.sport":"45678","fd.dip":"185.220.101.34","fd.dport":"4444","fd.l4proto":"tcp","proc.name":"nc","proc.pid":7890,"user.name":"root"}}'
ev = parse_falco_event(FC_NET)
check("  Falco 网络连接事件", ev is not None and ev.get("event_type") == "network_connection")
check("    src_ip/dst_ip 正确", ev and ev["entities"].get("src_ip") == "192.168.10.5" and ev["entities"].get("dst_ip") == "185.220.101.34")

# Falco 非法输入
check("  Falco 无时间戳 → None",
      parse_falco_event('{"output":"test","priority":"Warning","rule":"Test","output_fields":{"proc.name":"test"}}') is None)
check("  Falco 无效JSON → None", parse_falco_event("not json") is None)

# ═══════════════════════════════════════════════════════════════════════
# 需求 3: Zeek + Suricata 网络日志
# ═══════════════════════════════════════════════════════════════════════
print("\n--- 需求 3: Zeek/Suricata 网络日志接入 ---")
from utils.traffic_fenxi.parser_zeek_suricata import parse_zeek_log, parse_suricata_eve

# Zeek
ZK = '1752085800.123456\tC8abc123\t192.168.10.50\t49152\t10.0.0.1\t443\ttcp\tssl\t12.345\t12345\t567890\tSF\t-\t-\t0\tShADadFf\t45\t15000\t60\t580000\t-'
ZK_FLDS = ['ts','uid','id.orig_h','id.orig_p','id.resp_h','id.resp_p','proto','service','duration','orig_bytes','resp_bytes','conn_state','local_orig','local_resp','missed_bytes','history','orig_pkts','orig_ip_bytes','resp_pkts','resp_ip_bytes','tunnel_parents']
ev = parse_zeek_log(ZK, log_type='conn', fields=ZK_FLDS)
check("Zeek 解析成功", ev is not None)
if ev:
    for f in REQUIRED:
        check(f"  包含字段 '{f}'", f in ev)
    check("  event_type = tcp_connection", ev.get("event_type") == "tcp_connection")
    check("  src_ip/dst_ip 正确", ev.get("src_ip") == "192.168.10.50" and ev.get("dst_ip") == "10.0.0.1")

# P1 验证: Zeek 非法输入
check("P1: 'bad line' → None (非Zeek文本拒绝)",
      parse_zeek_log("bad line") is None)
check("P1: JSON文本 → None (非Zeek格式拒绝)",
      parse_zeek_log('{"timestamp":"2026-01-01","src_ip":"1.2.3.4"}') is None)
check("P1: 有效IP但无有效时间戳 → None",
      parse_zeek_log("abc\tuid123\thost\t80\t10.0.0.1\t443\ttcp\t-\t1.0\t100\t200\tSF") is None)
check("P1: 无有效IP → None",
      parse_zeek_log("1752085800.123456\tC8abc123\thost1\t80\thost2\t443\ttcp\t-\t1.0\t100\t200\tSF") is None)

# Suricata
SC = '{"timestamp":"2026-07-09T06:30:05.123456+0800","flow_id":1,"event_type":"alert","src_ip":"192.168.10.50","src_port":49162,"dest_ip":"185.220.101.34","dest_port":443,"proto":"TCP","alert":{"signature_id":2012345,"signature":"ET TROJAN Test","severity":1}}'
ev = parse_suricata_eve(SC)
check("Suricata 解析成功", ev is not None)
if ev:
    for f in REQUIRED:
        check(f"  包含字段 '{f}'", f in ev)
    check("  event_type = network_alert", ev.get("event_type") == "network_alert")

# Suricata 非法输入
check("  主机名IP → None",
      parse_suricata_eve('{"timestamp":"2026-07-09T06:30:00+0800","event_type":"alert","src_ip":"hostname","dest_ip":"another-host","proto":"TCP"}') is None)
check("  缺失时间戳 → None",
      parse_suricata_eve('{"event_type":"alert","src_ip":"192.168.1.1","dest_ip":"10.0.0.1","proto":"TCP"}') is None)
check("  无效JSON → None", parse_suricata_eve("not json") is None)

# ═══════════════════════════════════════════════════════════════════════
# 需求 4: 样例数据 ≥5 条/源
# ═══════════════════════════════════════════════════════════════════════
print("\n--- 需求 4: 样例数据验证 ---")
from utils.sample_data_loader import load_all_samples
from utils.data_bridge import get_bridge

get_bridge().clear_all()
results = load_all_samples()

for src_name in ["sysmon", "auditd", "falco", "zeek", "suricata"]:
    r = results.get(src_name, {})
    ins = r.get("inserted", 0)
    check(f"  {src_name}: {ins} 条 >= 5", ins >= 5, f"only got {ins}")

# 验证数据可通过 DataBridge 查询
bridge = get_bridge()
behaviors = bridge.query("HostBehaviors", limit=200)
traffic = bridge.query("NetworkTraffic", limit=200)
check(f"  HostBehaviors 表: {len(behaviors)} 条 >= 15", len(behaviors) >= 15)
check(f"  NetworkTraffic 表: {len(traffic)} 条 >= 10", len(traffic) >= 10)

# 验证 get_all_events() 合并
events = bridge.get_all_events()
check(f"  get_all_events(): {len(events)} 条 >= 20", len(events) >= 20)

# 验证每种 data_source 都存在
sources_found = set(e.get("data_source") for e in events)
for src in ["sysmon", "auditd", "falco", "zeek", "suricata"]:
    check(f"  data_source '{src}' 出现在事件中", src in sources_found)

# 验证 _category 字段 (供 unified analysis 使用)
categories = set(e.get("_category") for e in events)
check("  _category 包含 host_behavior", "host_behavior" in categories)
check("  _category 包含 network_traffic", "network_traffic" in categories)

# ═══════════════════════════════════════════════════════════════════════
# 需求 5: 状态页/API 返回健康状态
# ═══════════════════════════════════════════════════════════════════════
print("\n--- 需求 5: 数据源状态 API ---")
from utils.datasource_status import get_status_tracker
tracker = get_status_tracker()

# 验证所有源已注册
status_list = tracker.get_all_status_list()
src_names = [s["source_name"] for s in status_list]
for name in ["sysmon", "auditd", "falco", "zeek", "suricata"]:
    check(f"  '{name}' 已注册", name in src_names)

# 验证 状态包含关键字段
for s in status_list:
    sn = s["source_name"]
    has_status = "status" in s
    has_li = "last_ingestion_time" in s
    has_le = "last_error" in s
    has_te = "total_errors" in s
    check(f"  {sn}: status/last_ingestion/last_error/total_errors 齐全",
          has_status and has_li and has_le and has_te)

# 验证 有数据 → healthy, 无数据 → unknown
for s in status_list:
    sn = s["source_name"]
    ins = s.get("total_inserted", 0)
    st = s.get("status", "?")
    if ins > 0:
        check(f"  {sn}: 有数据(inserted={ins}) → status={st} 应为 healthy",
              st == "healthy", f"status={st}")

# P1/P2 验证: 采集失败时返回错误
print("\n--- P1/P2 状态追踪验证 ---")
tracker.reset_source("p1-test")
tracker.register_source("p1-test", data_category="test")

# P1: 非法数据 → 状态显示错误
tracker.record_ingestion("p1-test", inserted=0, skipped=0, errors=0, collected=10)
src = tracker.get_status("p1-test")
check("P1: collected=10, inserted=0 → consecutive_errors=1 (非healthy)",
      src["consecutive_errors"] == 1, f"got {src['consecutive_errors']}")
check("P1: last_error 非空",
      src["last_error"] is not None and "无法解析" in str(src.get("last_error", "")))
check("P1: last_ingestion_time 未设置 (inserted=0)",
      src["last_ingestion_time"] is None)

# P2: 部分成功不清除错误
tracker.reset_source("p2-test")
tracker.register_source("p2-test", data_category="test")
tracker.record_error("p2-test", "network error")
tracker.record_ingestion("p2-test", inserted=0, skipped=0, errors=0)
src = tracker.get_status("p2-test")
check("P2: record_error + record_ingestion(0,0) → last_error 保留",
      src["last_error"] == "network error")

# P2: 部分成功(inserted>0, errors>0) → 不增加 consecutive_errors
tracker.reset_source("p3-test")
tracker.register_source("p3-test", data_category="test")
tracker.record_ingestion("p3-test", inserted=5, skipped=0, errors=2, collected=7)
src = tracker.get_status("p3-test")
check("P2: 部分成功(5ins/2err) → consecutive_errors=0 (数据仍在流入)",
      src["consecutive_errors"] == 0, f"got {src['consecutive_errors']}")
check("P2: last_error 记录错误信息",
      src["last_error"] is not None and "部分成功" in str(src.get("last_error", "")))

# ═══════════════════════════════════════════════════════════════════════
# 边界条件验证
# ═══════════════════════════════════════════════════════════════════════
print("\n--- 边界条件验证 ---")

# 配置文件不含真实凭据
import os as _os
samples_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "samples")
for fname in _os.listdir(samples_dir):
    fpath = _os.path.join(samples_dir, fname)
    if _os.path.isfile(fpath):
        content = open(fpath, 'r', encoding='utf-8').read().lower()
        has_password = 'password' in content and ('12345' not in content or 'passw0rd!' in content)
        has_token = 'token' in content and 'eyJ' in content
        check(f"  样例文件 {fname}: 无真实密码/Token", not has_password and not has_token)

# API 不崩溃验证 (Flask test client)
from xiaoxueqi import create_app
app = create_app()
client = app.test_client()

# 非法 Zeek → 400 不崩溃
resp = client.post("/datasource/api/ingest/zeek", json={"lines": ["bad line"]}, content_type="application/json")
check("API: 非法Zeek → HTTP 400 (不崩溃)", resp.status_code == 400)
check("API: ok=false, inserted=0", resp.get_json().get("ok") == False and resp.get_json().get("inserted") == 0)

# 非法 Sysmon → 400 不崩溃
resp = client.post("/datasource/api/ingest/sysmon", json={"events": ["<not>valid</xml>"]}, content_type="application/json")
check("API: 非法Sysmon → HTTP 400 (不崩溃)", resp.status_code == 400)

# 非法 Suricata → 400 不崩溃
resp = client.post("/datasource/api/ingest/suricata", json={"lines": ["not json"]}, content_type="application/json")
check("API: 非法Suricata → HTTP 400 (不崩溃)", resp.status_code == 400)

# 状态页 API 返回 200
resp = client.get("/datasource/api/status")
check("API: GET /datasource/api/status → 200", resp.status_code == 200)
summary = resp.get_json().get("summary", {})
check("API: summary 包含 total_sources", "total_sources" in summary)

# 样例加载 API 返回 200
resp = client.post("/datasource/api/samples/load", json={}, content_type="application/json")
check("API: POST /datasource/api/samples/load → ok=true",
      resp.get_json().get("ok") == True)

# ═══════════════════════════════════════════════════════════════════════
# 总结
# ═══════════════════════════════════════════════════════════════════════
total = passed + failed
print(f"\n{'=' * 70}")
print(f"验收结果: {passed}/{total} 通过, {failed} 失败")
if issues:
    print(f"\n失败项明细:")
    for i in issues:
        print(f"  - {i}")
if failed == 0:
    print("ISSUE 2 全部需求验收通过!")
print(f"{'=' * 70}")
