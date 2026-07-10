"""
End-to-end API tests for Issue 2: Data source ingestion endpoints.
Uses Flask test client — no server needed.
"""
import json
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from xiaoxueqi import create_app

app = create_app()
client = app.test_client()

passed = 0
failed = 0


def check(name, condition, detail=""):
    global passed, failed
    if condition:
        passed += 1
        print(f"  PASS {name}")
    else:
        failed += 1
        print(f"  FAIL {name}")
        if detail:
            print(f"       Details: {detail}")


print("=" * 60)
print("E2E API Tests — Issue 2 Data Source Ingestion")
print("=" * 60)

# ── Test 1: Status API ──
print("\n[Test 1] GET /datasource/api/status")
resp = client.get("/datasource/api/status")
data = resp.get_json()
check("status code is 200", resp.status_code == 200, f"got {resp.status_code}")
check("ok is True", data.get("ok"), data)
check(">= 5 sources", len(data.get("sources", [])) >= 5, f"got {len(data.get('sources', []))}")
src_names = [s["source_name"] for s in data.get("sources", [])]
for expected in ["sysmon", "auditd", "falco", "zeek", "suricata"]:
    check(f"source '{expected}' registered", expected in src_names, src_names)
print(f"  Summary: {data.get('summary')}")

# ── Test 2: Zeek invalid "bad line" (P1 verification) ──
print("\n[Test 2] POST /datasource/api/ingest/zeek — P1: 'bad line' rejected")
resp = client.post("/datasource/api/ingest/zeek",
    json={"lines": ["bad line"]},
    content_type="application/json")
data = resp.get_json()
check("status 400", resp.status_code == 400, f"got {resp.status_code}: {data}")
check("ok is False", data.get("ok") == False, data)
check("inserted is 0", data.get("inserted") == 0, f"got {data.get('inserted')}")
check("has error message", bool(data.get("error")), data)

# ── Test 3: Zeek arbitrary text ──
print("\n[Test 3] POST /datasource/api/ingest/zeek — arbitrary text rejected")
resp = client.post("/datasource/api/ingest/zeek",
    json={"lines": ["this is just random text that is not a zeek log"]},
    content_type="application/json")
data = resp.get_json()
check("status 400", resp.status_code == 400, f"got {resp.status_code}: {data}")
check("inserted is 0", data.get("inserted") == 0, f"got {data.get('inserted')}")

# ── Test 4: Zeek JSON pretending to be Zeek ──
print("\n[Test 4] POST /datasource/api/ingest/zeek — JSON rejected")
resp = client.post("/datasource/api/ingest/zeek",
    json={"lines": ['{"timestamp":"2026-01-01","src_ip":"1.2.3.4"}']},
    content_type="application/json")
data = resp.get_json()
check("status 400", resp.status_code == 400, f"got {resp.status_code}: {data}")
check("inserted is 0", data.get("inserted") == 0, f"got {data.get('inserted')}")

# ── Test 5: Zeek valid conn log ──
print("\n[Test 5] POST /datasource/api/ingest/zeek — valid conn log accepted")
ZEEK_HEADER = "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tservice\tduration\torig_bytes\tresp_bytes\tconn_state"
ZEEK_LINE = "1752085800.123456\tC8abc123\t192.168.10.50\t49152\t10.0.0.1\t443\ttcp\tssl\t12.345\t12345\t567890\tSF"
resp = client.post("/datasource/api/ingest/zeek",
    json={"lines": [ZEEK_HEADER, ZEEK_LINE], "host_name": "test-zeek"},
    content_type="application/json")
data = resp.get_json()
check("status 200", resp.status_code == 200, f"got {resp.status_code}: {data}")
check("ok is True", data.get("ok"), data)
check("inserted >= 1", data.get("inserted", 0) >= 1, f"got {data.get('inserted')}")

# ── Test 6: Suricata hostname IPs ──
print("\n[Test 6] POST /datasource/api/ingest/suricata — hostname IPs rejected")
resp = client.post("/datasource/api/ingest/suricata",
    json={"lines": ['{"timestamp":"2026-07-09T06:30:00+0800","event_type":"alert","src_ip":"hostname","dest_ip":"another-host","proto":"TCP"}']},
    content_type="application/json")
data = resp.get_json()
check("status 400", resp.status_code == 400, f"got {resp.status_code}: {data}")
check("inserted is 0", data.get("inserted") == 0, f"got {data.get('inserted')}")

# ── Test 7: Suricata missing timestamp (our new fix) ──
print("\n[Test 7] POST /datasource/api/ingest/suricata — missing timestamp rejected")
resp = client.post("/datasource/api/ingest/suricata",
    json={"lines": ['{"event_type":"alert","src_ip":"192.168.1.1","dest_ip":"10.0.0.1","proto":"TCP"}']},
    content_type="application/json")
data = resp.get_json()
check("status 400", resp.status_code == 400, f"got {resp.status_code}: {data}")
check("inserted is 0", data.get("inserted") == 0, f"got {data.get('inserted')}")
check("has error message", bool(data.get("error")), data)

# ── Test 8: Suricata bad timestamp (our new fix) ──
print("\n[Test 8] POST /datasource/api/ingest/suricata — bad timestamp rejected")
resp = client.post("/datasource/api/ingest/suricata",
    json={"lines": ['{"timestamp":"garbage","event_type":"dns","src_ip":"192.168.1.100","dest_ip":"10.0.0.53","proto":"UDP","dns":{"rrname":"test.com","rrtype":"A"}}']},
    content_type="application/json")
data = resp.get_json()
check("status 400", resp.status_code == 400, f"got {resp.status_code}: {data}")
check("inserted is 0", data.get("inserted") == 0, f"got {data.get('inserted')}")

# ── Test 9: Suricata valid alert ──
print("\n[Test 9] POST /datasource/api/ingest/suricata — valid alert accepted")
resp = client.post("/datasource/api/ingest/suricata",
    json={"lines": ['{"timestamp":"2026-07-09T06:30:05.123456+0800","flow_id":1,"event_type":"alert","src_ip":"192.168.10.50","src_port":49162,"dest_ip":"185.220.101.34","dest_port":443,"proto":"TCP","alert":{"action":"allowed","signature_id":2012345,"signature":"ET TROJAN Test","category":"A Network Trojan","severity":1}}']},
    content_type="application/json")
data = resp.get_json()
check("status 200", resp.status_code == 200, f"got {resp.status_code}: {data}")
check("ok is True", data.get("ok"), data)
check("inserted >= 1", data.get("inserted", 0) >= 1, f"got {data.get('inserted')}")

# ── Test 10: Sysmon valid XML ──
print("\n[Test 10] POST /datasource/api/ingest/sysmon — valid XML accepted")
SYSMON_XML = """<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Sysmon' Guid='{5770385F-C22A-43E0-BF4C-06F5698FFBD9}'/><EventID>1</EventID><TimeCreated SystemTime='2026-07-09T06:30:00.123456789Z'/><Computer>test-pc</Computer></System><EventData><Data Name='Image'>C:\\Windows\\System32\\cmd.exe</Data><Data Name='ProcessId'>1234</Data><Data Name='CommandLine'>cmd.exe /c whoami</Data><Data Name='User'>TEST\\user</Data><Data Name='ParentImage'>C:\\Windows\\explorer.exe</Data><Data Name='ParentProcessId'>5678</Data><Data Name='Hashes'>SHA256=ABCD</Data></EventData></Event>"""
resp = client.post("/datasource/api/ingest/sysmon",
    json={"events": [SYSMON_XML], "host_name": "test-host"},
    content_type="application/json")
data = resp.get_json()
check("status 200", resp.status_code == 200, f"got {resp.status_code}: {data}")
check("ok is True", data.get("ok"), data)
check("inserted >= 1", data.get("inserted", 0) >= 1, f"got {data.get('inserted')}")

# ── Test 11: Sysmon invalid XML ──
print("\n[Test 11] POST /datasource/api/ingest/sysmon — invalid XML rejected")
resp = client.post("/datasource/api/ingest/sysmon",
    json={"events": ["<not>valid</xml>"], "host_name": "test-host"},
    content_type="application/json")
data = resp.get_json()
check("status 400", resp.status_code == 400, f"got {resp.status_code}: {data}")
check("inserted is 0", data.get("inserted") == 0, f"got {data.get('inserted')}")

# ── Test 12: Auditd lines (mix of valid and invalid) ──
print("\n[Test 12] POST /datasource/api/ingest/auditd — mixed valid/invalid")
AUDITD_VALID = 'type=SYSCALL msg=audit(1752085800.123:456): arch=c000003e syscall=59 success=yes exit=0 comm="curl" exe="/usr/bin/curl" key="cmd"'
resp = client.post("/datasource/api/ingest/auditd",
    json={"events": [AUDITD_VALID, "not a valid auditd line at all"]},
    content_type="application/json")
data = resp.get_json()
check("status 200 (at least one valid)", resp.status_code == 200, f"got {resp.status_code}: {data}")
check("ok is True", data.get("ok"), data)
check("inserted >= 1", data.get("inserted", 0) >= 1, f"got {data.get('inserted')}")
# Invalid line is counted as 'collected' but not 'inserted'
# It's silently dropped (not counted as skipped or error)
col = data.get("collected", 0)
ins = data.get("inserted", 0)
check("collected > inserted (invalid line counted in collected)",
      col > ins, f"collected={col}, inserted={ins}")
print(f"  Result: {data}")

# ── Test 13: Sample data loading ──
print("\n[Test 13] POST /datasource/api/samples/load — load all samples")
resp = client.post("/datasource/api/samples/load", json={}, content_type="application/json")
data = resp.get_json()
check("ok is True", data.get("ok"), data)
for src_name, r in data.get("results", {}).items():
    ins = r.get("inserted", 0)
    skp = r.get("skipped", 0)
    err = r.get("errors", 0)
    check(f"  {src_name}: inserted={ins} >= 5", ins >= 5, f"inserted={ins}, skipped={skp}, errors={err}")

# ── Test 14: Status after sample load ──
print("\n[Test 14] GET /datasource/api/status — health after sample load")
resp = client.get("/datasource/api/status")
data = resp.get_json()
check("status 200", resp.status_code == 200)
for s in data.get("sources", []):
    sn = s.get("source_name", "?")
    st = s.get("status", "?")
    ins = s.get("total_inserted", 0)
    errs = s.get("total_errors", 0)
    le = s.get("last_error")
    li = s.get("last_ingestion_time")
    has_data = ins > 0
    is_healthy = st == "healthy"
    print(f"  {sn}: status={st}, inserted={ins}, errors={errs}, last_ingestion={'set' if li else 'None'}, last_error={'set' if le else 'None'}")
    if has_data:
        check(f"  {sn}: status is 'healthy' (has data)", is_healthy,
              f"status={st} with {ins} inserted events")

# ── Test 15: Error recovery in status (P2 verification) ──
print("\n[Test 15] P2 verification: status correctly tracks errors")
from utils.datasource_status import get_status_tracker
tracker = get_status_tracker()

# Simulate: record_error then record_ingestion with inserted=0
tracker.reset_source("p2-test")
tracker.register_source("p2-test", data_category="host_behavior")
tracker.record_error("p2-test", "network timeout")
tracker.record_ingestion("p2-test", inserted=0, skipped=0, errors=0)
src = tracker.get_status("p2-test")
check("error preserved after record_ingestion(0,0,0)", src.get("last_error") == "network timeout",
      f"last_error={src.get('last_error')}")
check("consecutive_errors not reset", src.get("consecutive_errors", 0) >= 1,
      f"consecutive_errors={src.get('consecutive_errors')}")

# Now a successful batch
tracker.record_ingestion("p2-test", inserted=5, skipped=0, errors=0)
src = tracker.get_status("p2-test")
check("error cleared after success", src.get("last_error") is None,
      f"last_error={src.get('last_error')}")
check("status is healthy", src.get("status") == "healthy",
      f"status={src.get('status')}")
check("last_ingestion_time is set", src.get("last_ingestion_time") is not None)

tracker.reset_source("p2-test")

# ── Summary ──
print("\n" + "=" * 60)
print(f"RESULTS: {passed} passed, {failed} failed out of {passed + failed} checks")
if failed == 0:
    print("ALL E2E API TESTS PASSED")
else:
    print(f"{failed} CHECKS FAILED")
print("=" * 60)
sys.exit(0 if failed == 0 else 1)
