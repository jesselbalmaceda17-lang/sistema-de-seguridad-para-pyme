"""Group diversity and fail-closed behavior for the retained official 42-1 pair."""
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import tempfile
import unittest

from seguridad_pymes.label_audit import audit_packet_correspondences, read_packet_evidence
from seguridad_pymes.pcap_extract import extract_capture
from seguridad_pymes.pcap_reader import CaptureError
from seguridad_pymes.zeek_labels import import_zeek_labels
from tests.test_label_audit import row
import tests.test_label_reconciliation as fixtures

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("corpus_group_evidence", ROOT / "docs/validacion_ampliacion_corpus/analizar_grupos.py")
GROUPS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GROUPS)


class GroupEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="sipymes-corpus-group-")
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)

    def census(self, specs, values):
        extraction, imported, evidence = fixtures.PacketReconciliationTests.fixture(self, specs, [values])
        audit = audit_packet_correspondences(extraction, imported, evidence)
        return extraction, audit, GROUPS.group_census(extraction, audit)

    def test_bidirectional_group_survives_opposite_first_packet_orientation_in_siblings(self):
        extraction, audit, result = self.census([fixtures.packet(1), fixtures.packet(302, reverse=True)],
            row(duration="301", orig_pkts="1", resp_pkts="1", orig_ip_bytes="40", resp_ip_bytes="40"))
        self.assertEqual(len(extraction["flows"]), 2)
        self.assertTrue(all(f["features"]["reverse_packet_count"]["value"] == 0 for f in extraction["flows"]))
        self.assertEqual(audit["summary"]["admitted_flows"], 2)
        self.assertEqual(result["admitted_groups"], 1)
        self.assertEqual(result["summary"]["Benign"]["tcp_bidirectional_packet_groups"], 1)
        self.assertEqual(result["groups"][0]["direction_packets"], [1, 1])
        self.assertFalse(result["groups"][0]["bidirectional_payload"])

    def test_syn_retransmissions_are_one_unidirectional_group_not_independent_attacks(self):
        _, _, result = self.census([fixtures.packet(1, flags=2), fixtures.packet(2, flags=2)],
            row(label="Malicious", orig_pkts="2", resp_pkts="0", orig_ip_bytes="80", resp_ip_bytes="0", **{"detailed-label": "C&C"}))
        self.assertEqual(result["admitted_groups"], 1)
        summary = result["summary"]["Malicious"]
        self.assertEqual(summary["tcp_pure_syn_groups"], 1)
        self.assertEqual(summary["tcp_other_pattern_groups"], 0)
        self.assertEqual(summary["tcp_bidirectional_packet_groups"], 0)
        self.assertEqual(summary["tcp_packets_with_syn"], 2)

    def test_unverified_flow_never_contributes_a_class_or_group(self):
        _, audit, result = self.census([fixtures.packet(1)], row(duration="0", orig_pkts="-"))
        self.assertEqual(audit["summary"]["admitted_flows"], 0)
        self.assertEqual(result["admitted_groups"], 0)
        self.assertEqual(result["summary"], {})
        self.assertEqual(result["flow_counts"], {})

    def test_udp_bidirectionality_does_not_invent_tcp_flags(self):
        _, _, result = self.census([fixtures.packet(1, protocol="udp"), fixtures.packet(2, protocol="udp", reverse=True)],
            row(proto="udp", orig_pkts="1", resp_pkts="1", orig_ip_bytes="28", resp_ip_bytes="28"))
        self.assertEqual(result["summary"]["Benign"]["udp_bidirectional_packet_groups"], 1)
        self.assertIsNone(result["groups"][0]["tcp_flag_counts"])
        self.assertNotIn("tcp_packets_with_syn", result["summary"]["Benign"])


class LocalOfficial42RejectionTests(unittest.TestCase):
    def test_official_truncated_capture_is_rejected_by_extractor_and_packet_auditor(self):
        raw = ROOT / "data/raw/iot23_trojan_42_1"
        path = raw / "2019-01-10-14-34-38-192.168.1.197.pcap"
        if not path.is_file():
            self.skipTest("Local authorized source absent; tests never download")
        content = path.read_bytes()
        self.assertEqual(len(content), 2908160)
        self.assertEqual(hashlib.sha256(content).hexdigest(), "7573797f17aae96e3804a3cfb22d531b74c17bbae740de1e14048f89130fba37")
        _, _, captured, original = struct.unpack_from("<IIII", content, 2908099)
        self.assertEqual((captured, original), (91, 91))
        self.assertEqual(len(content) - 2908115, 45)
        with self.assertRaisesRegex(CaptureError, "TShark failed.*14"):
            extract_capture(path, tshark_path=Path(r"C:\Program Files\Wireshark\tshark.exe"))
        with self.assertRaisesRegex(ValueError, "truncated"):
            read_packet_evidence(path)
        self.assertFalse((ROOT / "data/processed/iot23_trojan_42_1/extraction.json").exists())
        self.assertFalse((ROOT / "data/processed/iot23_trojan_42_1/audit_v2/label_audit.json").exists())
        labels = raw / "conn.log.labeled"
        self.assertEqual(hashlib.sha256(labels.read_bytes()).hexdigest(), "269fa1b22d9a37e159cf41b81a213a0032d21306f5d39b4c20cb0d211b04e8aa")
        imported = import_zeek_labels(labels)
        self.assertEqual(imported["quality"]["records_imported"], 4426)
        self.assertEqual(imported["quality"]["label_distribution"], {"Malicious": 6, "Benign": 4420})
        self.assertEqual(path.read_bytes(), content)
