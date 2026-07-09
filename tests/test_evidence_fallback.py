import json
import unittest
from unittest.mock import patch

from utils.data_bridge import get_bridge
from utils.db.db import fetch_all
from utils.evidence.evidence_service import create_evidence_case, verify_evidence_case


class EvidenceFallbackTest(unittest.TestCase):
    def setUp(self):
        self.bridge = get_bridge()
        self.bridge.clear_all()
        self._db_patch = patch("utils.db.db._get_conn", side_effect=RuntimeError("forced fallback"))
        self._db_patch.start()

    def tearDown(self):
        self._db_patch.stop()
        self.bridge.clear_all()

    def test_fetch_all_supports_top_and_where_in_fallback(self):
        self.bridge.insert("EvidenceRecords", {
            "case_id": "case-a",
            "evidence_id": "ev-1",
            "summary": "expected",
        })
        self.bridge.insert("EvidenceRecords", {
            "case_id": "case-b",
            "evidence_id": "ev-2",
            "summary": "other",
        })

        rows = fetch_all(
            """
            SELECT TOP (?)
                id, case_id, evidence_id, summary
            FROM dbo.EvidenceRecords
            WHERE case_id = ?
            ORDER BY id ASC
            """,
            [10, "case-a"],
        )

        self.assertEqual(1, len(rows))
        self.assertEqual("case-a", rows[0]["case_id"])
        self.assertEqual("ev-1", rows[0]["evidence_id"])

    def test_evidence_hash_uses_same_source_payload_for_store_and_verify(self):
        source_event = {
            "timestamp": "2026-07-08T17:00:00",
            "event_type": "process_create",
            "host_ip": "192.168.10.5",
            "entities": {
                "process_name": "powershell.exe",
                "command_line": "powershell -enc AAAA",
            },
        }
        result_json = json.dumps(source_event, ensure_ascii=False, sort_keys=True)
        self.bridge.insert("HostLogs", {
            "id": 7,
            "result": result_json,
            "content": result_json,
            "event_hash": "",
            "host_name": "host-1",
            "create_time": "2026-07-08T17:00:01",
        })

        evidence_case = create_evidence_case(
            verdict={"verdict_id": "verdict-1", "iocs": {"ips": ["192.168.10.5"]}},
            chains=[],
            evidence=[{
                "evidence_id": "evi-1",
                "technique_id": "T1059",
                "technique_name": "Command and Scripting Interpreter",
                "tactic": "Execution",
                "sources": [{
                    "source_table": "HostLogs",
                    "source_record_id": 7,
                    "event_hash": "",
                    "collected_at": "2026-07-08T17:00:00",
                    "evidence_type": "process_create",
                }],
                "raw_events": [{
                    "source_record_id": 7,
                    "event_type": "process_create",
                    "host_ip": "192.168.10.5",
                    "entities": source_event["entities"],
                }],
            }],
            report="demo-report",
        )

        verify_ok = verify_evidence_case(evidence_case["case_id"])
        self.assertTrue(verify_ok["all_matched"])

        tampered_event = dict(source_event)
        tampered_event["entities"] = dict(source_event["entities"])
        tampered_event["entities"]["command_line"] = "powershell -enc BBBB"
        self.bridge._memory_store["HostLogs"][0]["result"] = json.dumps(tampered_event, ensure_ascii=False, sort_keys=True)

        verify_bad = verify_evidence_case(evidence_case["case_id"])
        self.assertFalse(verify_bad["all_matched"])
        self.assertFalse(verify_bad["checks"][0]["matched"])


if __name__ == "__main__":
    unittest.main()
