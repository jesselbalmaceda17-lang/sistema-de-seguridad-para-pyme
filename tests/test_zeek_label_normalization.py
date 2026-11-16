"""Exact source aliases cannot bypass packet/time/counter/contradiction checks."""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from seguridad_pymes.label_audit import audit_packet_correspondences
from seguridad_pymes.zeek_labels import import_zeek_labels
from tests.test_label_audit import row, log_text
import tests.test_label_reconciliation as packet_fixtures

ROOT = Path(__file__).resolve().parents[1]


class ExplicitLabelNormalizationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="sipymes-label-alias-")
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.path = self.directory / "labels.log"

    def imported(self, rows):
        self.path.write_text(log_text(rows), encoding="utf-8")
        before = self.path.read_bytes()
        result = import_zeek_labels(self.path)
        self.assertEqual(self.path.read_bytes(), before)
        self.assertEqual(result["source"]["sha256"], hashlib.sha256(before).hexdigest())
        return result

    def audit(self, rows, specs=None):
        specs = specs or [packet_fixtures.packet(1), packet_fixtures.packet(1.5, reverse=True), packet_fixtures.packet(2)]
        values = packet_fixtures.PacketReconciliationTests.fixture(self, specs, rows)
        return audit_packet_correspondences(*values)

    def test_only_three_documented_literals_are_normalized_and_originals_preserved(self):
        for original, canonical, binary in (("Benign", "Benign", 0), ("benign", "Benign", 0), ("Malicious", "Malicious", 1)):
            with self.subTest(original=original):
                result = self.imported([row(label=original)])
                record = result["records"][0]
                self.assertEqual((record["label_original"], record["label_normalized"], record["binary_label"]), (original, canonical, binary))
                self.assertEqual(record["raw_fields"]["label"], original)
                self.assertEqual(record["uid"], "C1")
                self.assertNotIn("label", record["field_problems"])
                self.assertEqual(result["label_normalization_policy"]["version"], "sipymes.iot23.label-aliases.v1")
                self.assertEqual(result["label_normalization_policy"]["exact_aliases"], {"Benign": "Benign", "benign": "Benign", "Malicious": "Malicious"})
                self.assertEqual(result["quality"]["label_distribution"], {original: 1})
                self.assertEqual(result["quality"]["normalized_label_distribution"], {canonical: 1})

    def test_undocumented_uppercase_lowercase_mixed_and_unknown_literals_are_rejected(self):
        for text in ("BENIGN", "MALICIOUS", "malicious", "bEnIgN", "mAlIcIoUs", " Benign", "Benign ", " ", "0", "normal", "attack", "Background", "benıgn"):
            with self.subTest(text=text):
                record = self.imported([row(label=text)])["records"][0]
                self.assertEqual(record["label_original"], text)
                self.assertIsNone(record["label_normalized"])
                self.assertIsNone(record["binary_label"])
                self.assertEqual(record["field_problems"]["label"], "unrecognized_label")

    def test_empty_and_unset_fields_stay_unknown_with_original_markers(self):
        for text, reason in (("", "empty"), ("(empty)", "empty"), ("-", "unset")):
            with self.subTest(text=text):
                record = self.imported([row(label=text)])["records"][0]
                self.assertEqual(record["raw_fields"]["label"], text)
                self.assertIsNone(record["label_original"])
                self.assertIsNone(record["label_normalized"])
                self.assertIsNone(record["binary_label"])
                self.assertEqual(record["field_problems"]["label"], reason)

    def test_documented_benign_alias_is_admitted_with_exact_packet_evidence(self):
        report = self.audit([row(label="benign")])
        self.assertEqual(report["summary"]["admitted_flows"], 1)
        self.assertEqual(report["flow_correspondences"][0]["binary_label"], 0)
        self.assertEqual(report["flow_correspondences"][0]["references"][0]["label_original"], "benign")

    def test_alias_cannot_bypass_missing_counters_duration_orientation_protocol_or_times(self):
        for changes in ({"orig_pkts": "-"}, {"duration": "-"}, {"orig_pkts": "1", "resp_pkts": "2"},
                        {"proto": "udp"}, {"ts": "1.000000001"}, {"id.orig_p": "40001"}):
            with self.subTest(changes=changes):
                report = self.audit([row(label="benign", **changes)])
                self.assertEqual(report["summary"]["admitted_flows"], 0)
                self.assertIsNone(report["flow_correspondences"][0]["binary_label"])

    def test_alias_with_nonbenign_detail_remains_contradictory(self):
        values = row(label="benign", **{"detailed-label": "C&C"})
        record = self.imported([values])["records"][0]
        self.assertIn("benign_label_with_nonbenign_detail", record["contradictions"])
        report = self.audit([values])
        self.assertEqual(report["flow_correspondences"][0]["status"], "contradictory")
        self.assertIsNone(report["flow_correspondences"][0]["binary_label"])

    def test_overlapping_malicious_and_lowercase_benign_remain_contradictory(self):
        report = self.audit([row(label="benign"), row(uid="C2", label="Malicious", **{"detailed-label": "C&C"})])
        self.assertEqual(report["flow_correspondences"][0]["status"], "contradictory")
        self.assertEqual(report["summary"]["admitted_flows"], 0)

    def test_alias_does_not_merge_duplicate_uid_records_with_different_original_text(self):
        result = self.imported([row(label="Benign"), row(label="benign")])
        self.assertEqual(result["quality"]["records_with_contradictions"], 2)
        self.assertTrue(all("uid_reused_with_different_record" in r["contradictions"] for r in result["records"]))
        self.assertEqual(self.audit([row(label="Benign"), row(label="benign")])["summary"]["admitted_flows"], 0)

    def test_lowercase_alias_does_not_override_partial_or_incorrect_checksum_quarantine(self):
        for checksum, expected in (("partial", "quarantined_partial_checksum"), ("incorrect", "quarantined_incorrect_checksum")):
            with self.subTest(checksum=checksum):
                report = self.audit([row(label="benign", duration="0", orig_pkts="1", resp_pkts="0", orig_ip_bytes="40", resp_ip_bytes="0")],
                                    specs=[packet_fixtures.packet(1, checksum=checksum)])
                self.assertEqual(report["flow_correspondences"][0]["status"], expected)
                self.assertIsNone(report["flow_correspondences"][0]["binary_label"])


class OriginalScenarioImportRegressionTests(unittest.TestCase):
    def test_hakai_and_pilot_original_record_fields_and_binary_labels_are_unchanged(self):
        cases = (("iot23_hakai_8_1", "data/processed/iot23_hakai_8_1/audit_v2/imported_labels.json"),
                 ("iot23_pilot_20_1", "docs/validacion_reconciliacion_iot23_20_1/audit_v2/imported_labels.json"))
        for folder, previous in cases:
            with self.subTest(folder=folder):
                raw = ROOT / "data/raw" / folder / "conn.log.labeled"
                if not raw.is_file():
                    self.skipTest("Local authorized sources absent; tests never download")
                before = json.loads((ROOT / previous).read_text(encoding="utf-8"))
                after = import_zeek_labels(raw)
                self.assertEqual(len(before["records"]), len(after["records"]))
                for old, new in zip(before["records"], after["records"]):
                    self.assertEqual({k: new[k] for k in old}, old)
                    self.assertEqual(new["label_normalized"], old["label_original"])
                self.assertEqual({k: after["quality"][k] for k in before["quality"]}, before["quality"])
