"""SOC evidence integrity: empty samples, time windows and safe handoffs."""
import csv
import io
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from sniff4hound import export, logger
from sniff4hound.store import SniffStore


class SocEvidenceTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.store = SniffStore(Path(directory.name) / "soc.db")
        self.addCleanup(self.store.close)

    def packet(self, timestamp, **overrides):
        packet = {
            "proto": "tcp", "src_ip": "10.0.0.10", "dst_ip": "8.8.8.8",
            "src_port": 50000, "dst_port": 443, "direction": "outbound",
            "payload_text": '{"status":"ok"}', "tags": [{"key": "service", "value": "https"}],
        }
        packet.update(overrides)
        with patch("sniff4hound.store.utc_now", return_value=timestamp):
            return self.store.register_packet(packet)

    def test_empty_sample_is_not_a_low_risk_assessment(self):
        for depth in range(1, 5):
            payload = self.store.soc_analysis_snapshot(cycles=depth)
            self.assertIsNone(payload["soc_summary"]["risk_score"])
            self.assertEqual(payload["soc_summary"]["verdict"], "insufficient-evidence")
            self.assertEqual(payload["findings"], [])
            self.assertEqual(payload["cycles"], [])
            self.assertEqual(payload["soc_summary"]["findings_total"], 0)

    def test_time_cutoff_applies_to_all_evidence(self):
        self.packet("2026-09-01T10:00:00+00:00", src_ip="10.0.0.11")
        self.packet("2026-09-05T10:00:00+00:00")
        cutoff = "2026-09-05T09:00:00+00:00"
        payload = self.store.soc_analysis_snapshot(since=cutoff)
        summary = payload["soc_summary"]
        for field in ("sampled_packets", "sampled_payloads", "sampled_tags", "sampled_flows"):
            self.assertEqual(summary[field], 1, field)
        self.assertEqual(payload["analysis_context"]["since"], cutoff)
        self.assertEqual(payload["analysis_context"]["available_packets"], 1)
        self.assertNotIn("10.0.0.11", [row["ip"] for row in payload["top_hosts"]])
        self.assertEqual(payload["summary"]["ports"], 1)
        self.assertIsNone(self.store.soc_analysis_snapshot(since="2027-01-01T00:00:00+00:00")["soc_summary"]["risk_score"])

    def test_one_public_packet_does_not_establish_local_dominance(self):
        self.packet("2026-09-05T10:00:00+00:00")
        payload = self.store.soc_analysis_snapshot()
        titles = [row["title"] for row in payload["findings"]]
        self.assertFalse(any("local traffic dominate" in title for title in titles))
        self.assertFalse(any("local traffic" in title for title in titles))
        self.assertFalse(any("honeypot artifacts" in title for title in titles))

    def test_host_ports_belong_to_the_correct_endpoint(self):
        self.packet("2026-09-05T10:00:00+00:00", src_port=51234, dst_port=443)
        hosts = {row["ip"]: row for row in self.store.soc_analysis_snapshot()["top_hosts"]}
        self.assertEqual(hosts["10.0.0.10"]["ports"], "51234")
        self.assertEqual(hosts["8.8.8.8"]["ports"], "443")

    def test_sample_discloses_truncation_and_method(self):
        for port in range(251):
            self.packet("2026-09-05T10:00:00+00:00", src_port=50000 + port)
        payload = self.store.soc_analysis_snapshot(limit=250)
        self.assertEqual(payload["soc_summary"]["sampled_packets"], 250)
        self.assertEqual(payload["analysis_context"]["available_packets"], 251)
        self.assertTrue(payload["analysis_context"]["sample_truncated"])
        self.assertEqual(payload["analysis_context"]["method"], "heuristic")

    def test_flow_export_filters_activity_and_discloses_lifetime_counts(self):
        self.packet("2026-09-01T10:00:00+00:00", src_ip="10.0.0.11")
        self.packet("2026-09-01T10:00:00+00:00")
        self.packet("2026-09-05T10:00:00+00:00")
        result = export.build_export(self.store, "flows", since="2026-09-05T09:00:00+00:00")
        self.assertEqual(result["count"], 1)
        self.assertEqual(result["rows"][0]["src_ip"], "10.0.0.10")
        self.assertEqual(result["rows"][0]["packet_count"], 2)
        self.assertIn("lifetime", result["counter_scope"])

    def test_http_and_both_websocket_channels_filter_the_same_window(self):
        import sniff4hound.app as app
        from wsbuilder import Request
        self.packet("2026-09-01T10:00:00+00:00")
        self.packet("2026-09-05T10:00:00+00:00")
        params = app._normalize_feed_params(Request("GET", "/ws/soc", "since=15m&limit=250", {}, b"", ("127.0.0.1", 0)))
        with patch.object(app, "store", self.store), patch("sniff4hound.utils.utc_since", return_value="2026-09-05T09:00:00+00:00"):
            http = app.soc_analysis(Request("GET", "/api/soc/analysis/", "since=15m&limit=250", {}, b"", ("127.0.0.1", 0)))
            streamed = app._feed_payload("soc", params)
            self.assertEqual(http["soc_summary"], streamed["data"]["soc_summary"])
            self.assertEqual(streamed["params"]["since"], "15m")
            self.assertEqual(len(app._feed_payload("ports", params)["data"]), 1)
            self.assertEqual(len(app._protocol_snapshot_payload(params)["snapshot"]["packets"]), 1)
            with self.assertRaises(ValueError):
                app._feed_payload("soc", {**params, "since": "nonsense"})


class HandoffSafetyTests(unittest.TestCase):
    def test_csv_neutralizes_formulas_without_changing_json_evidence(self):
        values = ["=1+1", "+SUM(A1)", "-1+2", "@SUM(A1)", "  =1", "\ttext", "\ntext", 'a,b"c\nd', -5, "8.8.8.8"]
        rows = [{"evidence": value} for value in values]
        parsed = list(csv.DictReader(io.StringIO(export.rows_to_csv(["evidence"], rows))))
        self.assertEqual([r["evidence"] for r in parsed[:7]], ["'" + value for value in values[:7]])
        self.assertEqual([r["evidence"] for r in parsed[7:]], [str(value) for value in values[7:]])
        self.assertEqual([r["evidence"] for r in rows], values)

    def test_logger_reconfiguration_closes_old_file(self):
        with tempfile.TemporaryDirectory() as directory:
            first = logger.get_logger("soc-qa", log_file=Path(directory) / "first.log")
            first.info("Open the original log file")
            file_handler = first.handlers[-1]
            previous_file = file_handler._file
            second = logger.get_logger("soc-qa", log_file=Path(directory) / "second.log")
            self.assertIsNone(file_handler._file)
            self.assertTrue(previous_file.closed)
            for handler in second.handlers[:]:
                second.removeHandler(handler)
                handler.close()
