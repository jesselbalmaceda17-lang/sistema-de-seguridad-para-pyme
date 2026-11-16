"""Pinned local snapshots; no network, training, source edits or live capture."""
import hashlib
import importlib.util
import json
import lzma
from pathlib import Path
import struct
import tempfile
import unittest

from seguridad_pymes.label_audit import audit_packet_correspondences, read_packet_evidence
from seguridad_pymes.pcap_extract import extract_capture
from seguridad_pymes.pcap_schema import ExtractionConfig, feature_definitions
from seguridad_pymes.zeek_labels import import_zeek_labels

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("controlled_iot23_stage", ROOT / "docs/validacion_adquisicion_iot23_8_4/ejecutar_etapa.py")
STAGE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(STAGE)
HEADER = struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
SHA = lambda data: hashlib.sha256(data).hexdigest()


class SafeXZCompatibilityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="sipymes-xz-test-")
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.source = self.directory / "fixture.pcap.xz"
        self.target = self.directory / "fixture.pcap"
        self.compressed = lzma.compress(HEADER, preset=0)
        self.source.write_bytes(self.compressed)

    def test_single_stream_preserves_original_and_writes_exact_pcap(self):
        result = STAGE.decompress_xz_capture(self.source, self.target, expected_sha256=SHA(HEADER))
        self.assertEqual(self.target.read_bytes(), HEADER)
        self.assertEqual(self.source.read_bytes(), self.compressed)
        self.assertEqual(result["sha256"], SHA(HEADER))
        self.assertEqual(result["lzma_memlimit_bytes"], 96 * 1024**2)

    def test_corrupt_truncated_and_trailing_streams_do_not_create_output(self):
        for payload in (self.compressed[:-1], b"bad" + self.compressed[3:], self.compressed + b"trailing", self.compressed * 2):
            with self.subTest(payload=payload[:8]):
                self.source.write_bytes(payload)
                with self.assertRaises((ValueError, lzma.LZMAError)):
                    STAGE.decompress_xz_capture(self.source, self.target)
                self.assertFalse(self.target.exists())
                self.assertEqual(self.source.read_bytes(), payload)

    def test_bounded_output_rejects_before_creating_pcap(self):
        with self.assertRaisesRegex(ValueError, "exceeds"):
            STAGE.decompress_xz_capture(self.source, self.target, maximum_bytes=len(HEADER) - 1)
        self.assertFalse(self.target.exists())

    def test_existing_output_is_never_overwritten(self):
        self.target.write_bytes(b"preserve me")
        with self.assertRaisesRegex(ValueError, "exists"):
            STAGE.decompress_xz_capture(self.source, self.target)
        self.assertEqual(self.target.read_bytes(), b"preserve me")

    def test_wrong_expected_hash_or_non_pcap_does_not_create_output(self):
        with self.assertRaisesRegex(ValueError, "SHA-256"):
            STAGE.decompress_xz_capture(self.source, self.target, expected_sha256="0" * 64)
        self.source.write_bytes(lzma.compress(b"not a pcap"))
        with self.assertRaisesRegex(ValueError, "PCAP"):
            STAGE.decompress_xz_capture(self.source, self.target)
        self.assertFalse(self.target.exists())

    def test_header_proof_cannot_hide_other_header_or_packet_differences(self):
        data = HEADER + b"controlled packet record bytes"
        publisher = SHA(data[:16] + struct.pack("<I", 262144) + data[20:])
        proof = STAGE.verify_hue_header_difference(data, publisher)
        self.assertTrue(proof["packet_records_identical_to_published_digest"])
        self.assertFalse(proof["actual_byte_identity"])
        for changed in (data[:-1] + b"!", data[:12] + b"\x01" + data[13:]):
            with self.assertRaisesRegex(ValueError, "beyond"):
                STAGE.verify_hue_header_difference(changed, publisher)


class LocalAdditionalScenarioTests(unittest.TestCase):
    def _paths(self, key):
        scenario = STAGE.SCENARIOS[key]
        raw = ROOT / "data/raw" / scenario["folder"]
        processed = ROOT / "data/processed" / scenario["folder"]
        if not (processed / "audit_v2/label_audit.json").is_file():
            self.skipTest("Authorized local scenario absent; tests never download")
        return scenario, raw, processed

    def _repeat(self, key, expected_packets, expected_flows, pcap_sha, label_sha):
        scenario, raw, processed = self._paths(key)
        capture = raw / scenario["capture"]
        self.assertEqual(SHA(capture.read_bytes()), pcap_sha)
        self.assertEqual(SHA((raw / "conn.log.labeled").read_bytes()), label_sha)
        saved_extraction = json.loads((processed / "extraction.json").read_text(encoding="utf-8"))
        extraction = extract_capture(capture, tshark_path=STAGE.TSHARK)
        self.assertEqual(extraction, saved_extraction)
        self.assertEqual(extraction["configuration"], ExtractionConfig().to_dict())
        self.assertEqual(extraction["feature_definitions"], feature_definitions())
        self.assertEqual(extraction["quality"]["packets_seen"], expected_packets)
        self.assertEqual(len(extraction["flows"]), expected_flows)
        imported = import_zeek_labels(raw / "conn.log.labeled")
        report = audit_packet_correspondences(extraction, imported, read_packet_evidence(capture))
        # The original Hue report remains immutable as pre-normalization evidence.
        # Compare current behavior with the separately stored normalized audit.
        audit_path = (ROOT / "docs/validacion_normalizacion_hue/audit_v2_hue/label_audit.json"
                      if key == "hue" else processed / "audit_v2/label_audit.json")
        saved = json.loads(audit_path.read_text(encoding="utf-8"))
        for name in ("summary", "flow_correspondences", "reference_correspondences", "packet_ledger"):
            self.assertEqual(report[name], saved[name], name)
        owned = [n for flow in extraction["flows"] for n in flow["packet_frames"]]
        self.assertEqual(len(owned), len(set(owned)))
        self.assertEqual(len(owned), extraction["quality"]["packets_accepted"])
        return extraction, imported, report

    def test_hakai_full_capture_has_exact_exclusive_same_label_partitions(self):
        extraction, imported, report = self._repeat("hakai", 23623, 4237,
            "80dcc2602519479ddcde889fa902fee19a76696630811452f8df38888af894f2",
            "4877ca8f0f01902fbd18d28b7d06cb3d0be082355b7f2c8862c9deef1782eb8a")
        self.assertEqual(report["summary"]["flow_status_counts"], {"admitted_unique": 2181, "admitted_partition": 2056})
        self.assertEqual(report["summary"]["matched_reference_connections"], 10403)
        self.assertEqual(report["summary"]["labeled_packets"], 16677)
        references = {r["reference_id"]: r for r in imported["records"]}
        validations = {r["reference_id"]: r for r in report["reference_correspondences"]}
        used = []
        for flow in report["flow_correspondences"]:
            frames = []
            labels = set()
            for rid in flow["admitted_reference_ids"]:
                used.append(rid)
                frames.extend(validations[rid]["accounted_packet_frames"])
                labels.add((references[rid]["label_original"], references[rid]["detailed_label"]))
            self.assertEqual(len(labels), 1)
            self.assertEqual(len(frames), len(set(frames)))
            self.assertEqual(sorted(frames), flow["packet_frames"])
        self.assertEqual(len(used), len(set(used)))
        self.assertEqual(len(used), len(references))

    def test_hue_documented_alias_recovers_only_verified_flows_and_keeps_partials_quarantined(self):
        extraction, imported, report = self._repeat("hue", 21664, 2200,
            "3fb775c0391b6ad313a3f7845e634a277b07c3f6377346c2486ba63e1c22e90c",
            "aebe40ea0e03b120265a5c7bc140dd9b0d3fe2fce65559e84776b7dd5360e71e")
        self.assertEqual(len(imported["records"]), 452)
        self.assertTrue(all(r["label_original"] == "benign" and r["label_normalized"] == "Benign"
                            and r["binary_label"] == 0 and "label" not in r["field_problems"] for r in imported["records"]))
        self.assertEqual(report["summary"]["admitted_flows"], 2107)
        self.assertEqual(report["summary"]["labeled_packets"], 15942)
        self.assertEqual(report["summary"]["matched_reference_connections"], 359)
        self.assertEqual(report["summary"]["pending_quarantined_flows"], 93)
        self.assertEqual(report["summary"]["flow_status_counts"], {
            "admitted_sibling_segment": 1762, "admitted_unique": 298, "admitted_tcp_closure": 47,
            "segmentation_mismatch": 86, "quarantined_partial_checksum": 7})
        partials = [p for p in report["packet_ledger"] if p.get("transport_checksum_status") == "partial_pseudoheader"]
        self.assertEqual([p["frame"] for p in partials], [7755, 14676, 15673, 19636, 19642, 19690, 20640, 20954, 20955])
        self.assertTrue(all(not p["flow_label_admitted"] for p in partials))
        self.assertTrue(all(f["binary_label"] is None for f in report["flow_correspondences"]
                            if not f["status"].startswith("admitted_")))

    def test_actual_hue_xz_matches_preserved_pcap_with_only_metadata_snaplen_discrepancy(self):
        scenario, raw, _ = self._paths("hue")
        compressed = raw / (scenario["capture"] + ".xz")
        self.assertEqual(SHA(compressed.read_bytes()), "bc5a57306d9a5f614b09d9c0976f007667fee5b6de3427fbab094fa3084b9b64")
        with tempfile.TemporaryDirectory(prefix="sipymes-hue-repeat-") as temp:
            destination = Path(temp) / "verified.pcap"
            proof = STAGE.decompress_xz_capture(compressed, destination,
                expected_sha256=scenario["snapshot_pcap_sha256"],
                publisher_header_sha256=scenario["published_pcap_sha256"])
            self.assertEqual(destination.read_bytes(), (raw / scenario["capture"]).read_bytes())
            self.assertEqual(proof["size_bytes"], 4594492)
            self.assertFalse(proof["publisher_header_verification"]["actual_byte_identity"])
            self.assertFalse(proof["publisher_header_verification"]["probe_written_to_disk"])
