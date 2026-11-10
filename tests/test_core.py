import json
import tempfile
import unittest
from pathlib import Path

from endpointledger.core import EvidenceError, build_report, inspect_startup_artifact, inventory, parse_journal_json, parse_syslog


class CoreTests(unittest.TestCase):
    def test_syslog_year_and_timezone(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "auth.log"
            path.write_text("Jan  2 03:04:05 host sshd[123]: Failed password for invalid user guest from 192.0.2.10 port 22 ssh2\n")
            events, issues = parse_syslog(path, 2026, "America/Denver")
        self.assertEqual(issues, [])
        self.assertEqual(events[0].kind, "authentication_failure")
        self.assertEqual(events[0].source_ip, "192.0.2.10")
        self.assertTrue(events[0].timestamp_utc.startswith("2026-01-02T10:04:05"))

    def test_journal_export_and_bad_record(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "journal.jsonl"
            path.write_text(json.dumps({"__REALTIME_TIMESTAMP": "1700000000000000", "_HOSTNAME": "host",
                                        "MESSAGE": "sshd: Accepted publickey for analyst from 192.0.2.3 port 22"}) + "\nnot-json\n")
            events, issues = parse_journal_json(path)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].kind, "authentication_success")
        self.assertEqual(len(issues), 1)

    def test_artifact_marker_does_not_export_command(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "crontab"
            path.write_text("@reboot /sensitive/command --token=nonfunctional-test\n")
            markers = inspect_startup_artifact(path)
        self.assertEqual(markers[0]["marker"], "cron_at_reboot")
        self.assertNotIn("nonfunctional-test", json.dumps(markers))

    def test_inventory_and_custody_hash_chain(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "journal.jsonl"
            path.write_text(json.dumps({"__REALTIME_TIMESTAMP": "1700000000000000", "MESSAGE": "test"}) + "\n")
            report = build_report([(path, "journal"), (path, "journal")], "analyst", "lab export", 2026, "UTC")
        self.assertEqual(len(report["timeline"]), 2)
        self.assertEqual(report["custody_records"][1]["previous_hash"], report["custody_records"][0]["record_hash"])

    def test_reject_symlink(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = root / "original"
            original.write_text("test")
            link = root / "link"
            link.symlink_to(original)
            with self.assertRaises(EvidenceError):
                inventory(link, "test")


if __name__ == "__main__":
    unittest.main()
