"""Independent correspondence oracles; no training and no network acquisition in tests."""

from copy import deepcopy
import hashlib
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from seguridad_pymes.iot23_sources import download_pilot, _fetch, ROOT, BASE, PCAP_NAME, PCAP_URL, LABEL_URL
from seguridad_pymes.label_audit import audit_correspondences, audit_files
from seguridad_pymes.zeek_labels import import_zeek_labels


FIELDS = ["ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto",
          "duration", "orig_pkts", "resp_pkts", "orig_ip_bytes", "resp_ip_bytes",
          "tunnel_parents", "label", "detailed-label"]
TYPES = ["time", "string", "addr", "port", "addr", "port", "enum", "interval",
         "count", "count", "count", "count", "set[string]", "string", "string"]


def row(**changes):
    values = dict(zip(FIELDS, ["1.000000", "C1", "10.0.0.1", "40000", "10.0.0.2", "443", "tcp",
                              "1.000000", "2", "1", "80", "40", "-", "Benign", "-"]))
    values.update(changes)
    return values


def log_text(rows, mixed=False):
    def encode(values):
        return "\t".join(values[:-3]) + "\t" + "   ".join(values[-3:]) if mixed else "\t".join(values)
    return ("#separator \\x09\n#empty_field\t(empty)\n#unset_field\t-\n"
            + "#fields\t" + encode(FIELDS) + "\n#types\t" + encode(TYPES) + "\n"
            + "".join(encode([r[k] for k in FIELDS]) + "\n" for r in rows) + "#close\tfixture\n")


def flow(identifier="f1", start=1_000_000_000, end=2_000_000_000, reverse=False,
         forward_packets=2, reverse_packets=1, forward_bytes=80, reverse_bytes=40, port=40000, protocol="tcp"):
    source, destination = {"ipv4": "10.0.0.1", "port": port}, {"ipv4": "10.0.0.2", "port": 443}
    if reverse:
        source, destination = destination, source
        forward_packets, reverse_packets = reverse_packets, forward_packets
        forward_bytes, reverse_bytes = reverse_bytes, forward_bytes
    return {"flow_id": identifier, "first_timestamp_epoch_ns": str(start), "last_timestamp_epoch_ns": str(end),
            "forward_endpoint": source, "reverse_endpoint": destination,
            "features": {"transport_protocol": {"value": protocol, "status": "ok"},
                         "forward_packet_count": {"value": forward_packets, "status": "ok"},
                         "reverse_packet_count": {"value": reverse_packets, "status": "ok"},
                         "forward_ipv4_byte_count": {"value": forward_bytes, "status": "ok"},
                         "reverse_ipv4_byte_count": {"value": reverse_bytes, "status": "ok"}}}


def extracted(flows):
    packets = sum(f["features"][d + "_packet_count"]["value"] for f in flows for d in ("forward", "reverse"))
    return {"schema_version": "sipymes.offline.ipv4.v1", "extractor_version": "1.0.1",
            "source": {"sha256": "capture-fixture"}, "flows": flows,
            "quality": {"packets_seen": packets, "packets_accepted": packets, "packets_rejected": 0}}


class _LabelFixture:
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "labels.log"

    def imported(self, rows, mixed=False):
        self.path.write_text(log_text(rows, mixed), encoding="utf-8")
        return import_zeek_labels(self.path)


class LabelImporterTests(_LabelFixture, unittest.TestCase):
    def test_normal_zeek_headers_and_original_values_preserved(self):
        result = self.imported([row()])
        record = result["records"][0]
        self.assertEqual(record["start_epoch_ns"], "1000000000")
        self.assertEqual(record["duration_ns"], "1000000000")
        self.assertEqual(record["binary_label"], 0)
        self.assertEqual(record["raw_fields"]["detailed-label"], "-")
        self.assertIsNone(record["detailed_label"])
        self.assertEqual(record["field_problems"]["detailed-label"], "unset")
        self.assertTrue(result["quality"]["close_marker_present"])

    def test_iot23_mixed_tail_and_detailed_label_with_single_space(self):
        result = self.imported([row(label="Malicious", **{"detailed-label": "Web Attack"})], mixed=True)
        self.assertEqual(result["records"][0]["detailed_label"], "Web Attack")
        self.assertEqual(result["records"][0]["binary_label"], 1)
        self.assertTrue(result["header"]["iot23_mixed_tail"])

    def test_unknown_duration_and_counts_are_not_zero(self):
        record = self.imported([row(duration="-", orig_pkts="-", resp_pkts="(empty)")])["records"][0]
        for field in ("duration_ns", "orig_pkts", "resp_pkts"):
            self.assertIsNone(record[field])

    def test_missing_data_columns_are_quarantined(self):
        self.path.write_text(log_text([row()]).replace("\tBenign\t-", "\tBenign"), encoding="utf-8")
        result = import_zeek_labels(self.path)
        self.assertEqual(result["records"], [])
        self.assertEqual(result["quality"]["rows_rejected"], 1)

    def test_missing_or_duplicate_headers_are_errors(self):
        for text in ("not a log\n", log_text([row()]).replace("\tuid\t", "\tts\t", 1)):
            self.path.write_text(text, encoding="utf-8")
            with self.assertRaises(ValueError):
                import_zeek_labels(self.path)

    def test_wrong_declared_types_are_rejected(self):
        self.path.write_text(log_text([row()]).replace("#types\ttime", "#types\tstring"), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "type"):
            import_zeek_labels(self.path)

    def test_invalid_identifiers_times_and_counts_are_preserved_as_unknown(self):
        record = self.imported([row(ts="NaN", duration="-1", orig_pkts="-2",
                                     **{"id.orig_h": "invalid", "id.resp_p": "70000"})])["records"][0]
        for field in ("start_epoch_ns", "duration_ns", "orig_pkts", "orig_ip", "resp_port"):
            self.assertIsNone(record[field])
        self.assertEqual(record["raw_fields"]["id.orig_h"], "invalid")

    def test_nanosecond_precision_is_not_rounded(self):
        result = self.imported([row(ts="1.000000001"), row(uid="C2", ts="1.0000000001")])
        self.assertEqual(result["records"][0]["start_epoch_ns"], "1000000001")
        self.assertIsNone(result["records"][1]["start_epoch_ns"])

    def test_unknown_label_is_never_converted_to_benign(self):
        for label in ("-", "Background", "infected-host", "(empty)"):
            self.assertIsNone(self.imported([row(label=label)])["records"][0]["binary_label"])

    def test_internal_contradiction_is_recorded(self):
        record = self.imported([row(**{"detailed-label": "C&C"})])["records"][0]
        self.assertIn("benign_label_with_nonbenign_detail", record["contradictions"])

    def test_duplicate_uid_identical_and_conflicting_records(self):
        result = self.imported([row(), row()])
        self.assertTrue(result["duplicate_uids"][0]["identical"])
        self.assertEqual(result["quality"]["records_with_contradictions"], 0)
        result = self.imported([row(), row(label="Malicious", **{"detailed-label": "C&C"})])
        self.assertFalse(result["duplicate_uids"][0]["identical"])
        self.assertEqual(result["quality"]["records_with_contradictions"], 2)

    def test_repeated_logs_are_not_silently_concatenated(self):
        self.path.write_text(log_text([row()]) * 2, encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "Concatenated"):
            import_zeek_labels(self.path)


class CorrespondenceTests(_LabelFixture, unittest.TestCase):
    def audited(self, flows, rows):
        return audit_correspondences(extracted(flows), self.imported(rows))

    def test_exact_tuple_and_time_match(self):
        result = self.audited([flow()], [row()])
        self.assertEqual(result["summary"]["flow_label_coverage_percent"], 100)
        self.assertEqual(result["flow_correspondences"][0]["binary_label"], 0)

    def test_inverted_connection_maps_source_counters_correctly(self):
        result = self.audited([flow(reverse=True)], [row(label="Malicious", **{"detailed-label": "C&C"})])
        self.assertEqual(result["flow_correspondences"][0]["status"], "matched_unique")
        self.assertEqual(result["flow_correspondences"][0]["binary_label"], 1)

    def test_no_tuple_or_protocol_match_has_no_label(self):
        for f in (flow(port=40001), flow(protocol="udp")):
            result = self.audited([f], [row()])
            self.assertEqual(result["flow_correspondences"][0]["status"], "not_found")
            self.assertIsNone(result["flow_correspondences"][0]["binary_label"])

    def test_one_nanosecond_outside_interval_is_not_accepted(self):
        result = self.audited([flow(end=2_000_000_001)], [row()])
        self.assertEqual(result["flow_correspondences"][0]["status"], "segmentation_mismatch")
        result = self.audited([flow(start=2_000_000_001, end=3_000_000_000)], [row()])
        self.assertEqual(result["flow_correspondences"][0]["status"], "not_found")

    def test_port_reuse_is_resolved_by_disjoint_times(self):
        result = self.audited([flow(), flow("f2", 4_000_000_000, 5_000_000_000)],
                              [row(), row(uid="C2", ts="4", label="Malicious", **{"detailed-label": "C&C"})])
        self.assertEqual([f["binary_label"] for f in result["flow_correspondences"]], [0, 1])

    def test_duplicate_covering_references_are_ambiguous(self):
        result = self.audited([flow()], [row(), row(uid="C2")])
        self.assertEqual(result["flow_correspondences"][0]["status"], "ambiguous")
        self.assertIsNone(result["flow_correspondences"][0]["binary_label"])

    def test_disagreeing_labels_are_contradictory(self):
        result = self.audited([flow()], [row(), row(uid="C2", label="Malicious", **{"detailed-label": "C&C"})])
        self.assertEqual(result["flow_correspondences"][0]["status"], "contradictory")

    def test_merging_references_is_not_labeled_even_when_labels_agree(self):
        result = self.audited([flow()], [row(duration="0.4"), row(uid="C2", ts="1.6", duration="0.4")])
        self.assertEqual(result["flow_correspondences"][0]["status"], "segmentation_mismatch")
        self.assertIsNone(result["flow_correspondences"][0]["binary_label"])

    def test_single_packet_point_support_does_not_change_unknown_duration(self):
        imported = self.imported([row(duration="-", orig_pkts="1", resp_pkts="0", orig_ip_bytes="40", resp_ip_bytes="0")])
        result = audit_correspondences(extracted([flow(end=1_000_000_000, forward_packets=1,
                    reverse_packets=0, forward_bytes=40, reverse_bytes=0)]), imported)
        self.assertEqual(result["flow_correspondences"][0]["status"], "matched_unique")
        self.assertEqual(result["flow_correspondences"][0]["support_kind"], "single_packet_proven_by_counts")
        self.assertIsNone(imported["records"][0]["duration_ns"])

    def test_unknown_end_is_not_extended_to_fit_a_flow(self):
        result = self.audited([flow()], [row(duration="-")])
        self.assertEqual(result["flow_correspondences"][0]["status"], "incomplete_reference")

    def test_incomplete_key_and_missing_label_are_detected(self):
        result = self.audited([flow()], [row(**{"id.orig_p": "-"})])
        self.assertEqual(result["summary"]["reference_states"], {"incomplete_key": 1})
        self.assertEqual(result["flow_correspondences"][0]["status"], "not_found")
        result = self.audited([flow()], [row(label="-")])
        self.assertEqual(result["flow_correspondences"][0]["status"], "incomplete_reference")

    def test_counter_conflict_cannot_be_ignored(self):
        result = self.audited([flow(forward_bytes=81)], [row()])
        self.assertEqual(result["flow_correspondences"][0]["status"], "counter_mismatch")
        self.assertIsNone(result["flow_correspondences"][0]["binary_label"])

    def test_aggregate_children_cannot_reuse_parent_packet_budget(self):
        result = self.audited([flow("f1", end=1_500_000_000), flow("f2", start=1_600_000_000)], [row()])
        self.assertEqual(result["summary"]["flow_status_counts"]["counter_mismatch"], 2)
        self.assertEqual(result["summary"]["flow_status_counts"]["matched_unique"], 0)

    def test_split_reference_can_match_children_when_totals_are_compatible(self):
        result = self.audited([flow("f1", end=1_500_000_000), flow("f2", start=1_600_000_000)],
                              [row(orig_pkts="4", resp_pkts="2", orig_ip_bytes="160", resp_ip_bytes="80")])
        self.assertEqual(result["summary"]["references_split_across_matched_flows"], 1)
        self.assertEqual(result["summary"]["flow_status_counts"]["matched_unique"], 2)

    def test_repeated_audit_is_identical_and_inputs_are_not_modified(self):
        e, r = extracted([flow()]), self.imported([row()])
        original = deepcopy((e, r))
        self.assertEqual(audit_correspondences(e, r), audit_correspondences(e, r))
        self.assertEqual((e, r), original)

    def test_wrong_extractor_duplicate_flows_and_invalid_totals_are_rejected(self):
        e, r = extracted([flow()]), self.imported([row()])
        e["extractor_version"] = "different"
        with self.assertRaises(ValueError):
            audit_correspondences(e, r)
        with self.assertRaises(ValueError):
            audit_correspondences(extracted([flow(), flow()]), r)
        e = extracted([flow()]); e["quality"]["packets_accepted"] += 1
        with self.assertRaises(ValueError):
            audit_correspondences(e, r)

    def test_empty_denominators_are_unknown_not_zero(self):
        result = self.audited([], [])
        self.assertIsNone(result["summary"]["flow_label_coverage_percent"])
        self.assertIsNone(result["summary"]["reference_coverage_percent"])

    def test_audit_files_bind_hashes_and_never_overwrite(self):
        self.imported([row()])
        e = extracted([flow()])
        extraction = self.path.parent / "extraction.json"
        extraction.write_text(json.dumps(e), encoding="utf-8")
        provenance = self.path.parent / "provenance.json"
        manifest = {"scenario": "fixture", "files": [{"role": "pcap", "sha256": "capture-fixture"},
            {"role": "labels", "sha256": hashlib.sha256(self.path.read_bytes()).hexdigest()}]}
        provenance.write_text(json.dumps(manifest), encoding="utf-8")
        out = self.path.parent / "audit"
        self.assertEqual(audit_files(extraction, self.path, provenance, out)["summary"]["extracted_flows"], 1)
        with self.assertRaises(ValueError):
            audit_files(extraction, self.path, provenance, out)
        manifest["files"][1]["sha256"] = "wrong"
        provenance.write_text(json.dumps(manifest), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "hashes"):
            audit_files(extraction, self.path, provenance, self.path.parent / "not-created")
        self.assertFalse((self.path.parent / "not-created").exists())


class AcquisitionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.destination = Path(self.temp.name) / "pair"

    def response(self, url, maximum):
        mapping = {ROOT: b'IndividualScenarios/', BASE: (PCAP_NAME + ' <a href="bro/">bro</a>').encode(),
                   BASE + 'bro/': b'conn.log.labeled',
                   BASE + 'README.md': b'CTU-IoT-Malware-Capture-20 192.168.100.103',
                   PCAP_URL: b'\xd4\xc3\xb2\xa1' + b'fixture',
                   LABEL_URL: log_text([row()], mixed=True).encode()}
        data = mapping[url]
        self.assertLessEqual(len(data), maximum)
        return data, {"url": url, "sha256": hashlib.sha256(data).hexdigest(), "size_bytes": len(data)}

    def test_only_two_scenario_files_are_fetched_after_metadata_checks(self):
        with patch("seguridad_pymes.iot23_sources._fetch", side_effect=self.response) as fetch:
            manifest = download_pilot(self.destination)
        self.assertEqual([c.args[0] for c in fetch.call_args_list][-2:], [PCAP_URL, LABEL_URL])
        self.assertEqual(len(manifest["files"]), 2)
        self.assertEqual(len(list(self.destination.iterdir())), 3)

    def test_version_association_failure_stops_before_data_download(self):
        def invalid(url, maximum):
            if url == BASE:
                return b'other-version', {"url": url}
            return self.response(url, maximum)
        with patch("seguridad_pymes.iot23_sources._fetch", side_effect=invalid) as fetch:
            with self.assertRaisesRegex(ValueError, "association"):
                download_pilot(self.destination)
        self.assertFalse(self.destination.exists())
        self.assertNotIn(PCAP_URL, [c.args[0] for c in fetch.call_args_list])

    def test_existing_acquisition_is_not_overwritten_or_downloaded_again(self):
        self.destination.mkdir()
        with patch("seguridad_pymes.iot23_sources._fetch") as fetch:
            with self.assertRaises(ValueError):
                download_pilot(self.destination)
        fetch.assert_not_called()

    def test_transport_keeps_tls_and_size_limits(self):
        def launch(command, **kwargs):
            self.assertNotIn("--insecure", command)
            self.assertEqual(command[command.index("--proto") + 1], "=https")
            self.assertEqual(command[command.index("--max-filesize") + 1], "100")
            Path(command[command.index("--dump-header") + 1]).write_text('Content-Length: 4\n', encoding='ascii')
            metadata = {"http_code": 200, "url_effective": BASE, "ssl_verify_result": 0}
            return SimpleNamespace(returncode=0, stdout=b'data\n__SIPYMES_CURL_METADATA__' + json.dumps(metadata).encode(), stderr=b'')
        with patch("seguridad_pymes.iot23_sources.shutil.which", return_value="curl.exe"), patch("seguridad_pymes.iot23_sources.subprocess.run", side_effect=launch):
            data, info = _fetch(BASE, 100)
        self.assertEqual(data, b'data')
        self.assertEqual(info["size_bytes"], 4)


PILOT = Path(__file__).resolve().parents[1] / 'data/raw/iot23_pilot_20_1'


@unittest.skipUnless((PILOT / PCAP_NAME).is_file() and (PILOT / 'conn.log.labeled').is_file(),
                     'Local official scenario pair is not present; tests never download it')
class LocalPilotRegressionTests(unittest.TestCase):
    def test_downloaded_pair_and_saved_results_are_reproducible(self):
        self.assertEqual(hashlib.sha256((PILOT / PCAP_NAME).read_bytes()).hexdigest(), '4d0a00c33a4bf11228158baddd47c38f702731ea8d75ef1201061fc8bbd878b9')
        self.assertEqual(hashlib.sha256((PILOT / 'conn.log.labeled').read_bytes()).hexdigest(), 'ef48ad72f65efd13d517223e61e4d877ba53a082ddb8159324b18d3f310d0711')
        project = PILOT.parents[2]
        extraction = json.loads((project / 'data/processed/iot23_pilot_20_1/extraction.json').read_text(encoding='utf-8'))
        imported = import_zeek_labels(PILOT / 'conn.log.labeled')
        report = audit_correspondences(extraction, imported)
        self.assertEqual(report['summary']['reference_connections'], 3209)
        self.assertEqual(report['summary']['extracted_flows'], 3499)
        self.assertEqual(report['summary']['flow_status_counts'], {
            'matched_unique':3207, 'ambiguous':0, 'not_found':0, 'segmentation_mismatch':6,
            'incomplete_reference':0, 'contradictory':0, 'counter_mismatch':286})
        self.assertEqual(report['summary']['class_coverage']['Malicious']['matched_extractor_flows'], 0)
