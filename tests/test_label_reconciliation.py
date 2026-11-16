"""Packet-level reconciliation oracles from independently constructed PCAP bytes."""

from copy import deepcopy
import hashlib
import json
from pathlib import Path
import socket
import struct
import tempfile
import unittest

from seguridad_pymes.label_audit import (
    audit_files, audit_packet_correspondences, read_packet_evidence,
)
from seguridad_pymes.pcap_extract import _aggregate
from seguridad_pymes.pcap_reader import Packet, PacketObservation
from seguridad_pymes.pcap_schema import ExtractionConfig
from seguridad_pymes.zeek_labels import import_zeek_labels
from tests.test_label_audit import FIELDS, TYPES, PILOT, PCAP_NAME, row


A, B = "10.0.0.1", "10.0.0.2"


def internet_checksum(data):
    """Fixture encoder: sum network-order words; RFC 1071 vector tested below."""
    padded = data + (b"\0" if len(data) % 2 else b"")
    total = sum(int.from_bytes(padded[i:i + 2], "big") for i in range(0, len(padded), 2))
    total = (total & 65535) + (total >> 16)
    total = (total & 65535) + (total >> 16)
    return total ^ 65535


def packet(time, *, reverse=False, flags=0x10, seq=100, ack=500, payload=b"", checksum="valid", protocol="tcp"):
    return {"ns": round(time * 1_000_000_000), "src": B if reverse else A,
            "dst": A if reverse else B, "sport": 443 if reverse else 40000,
            "dport": 40000 if reverse else 443, "flags": flags, "seq": seq, "ack": ack,
            "payload": payload, "checksum": checksum, "protocol": protocol}


def encode_packet(p):
    proto = 6 if p["protocol"] == "tcp" else 17
    if proto == 6:
        transport = struct.pack("!HHIIBBHHH", p["sport"], p["dport"], p["seq"], p["ack"],
                                0x50, p["flags"], 4096, 0, 0) + p["payload"]
        checksum_offset = 16
    else:
        transport = struct.pack("!HHHH", p["sport"], p["dport"], 8 + len(p["payload"]), 0) + p["payload"]
        checksum_offset = 6
    addresses = socket.inet_aton(p["src"]) + socket.inet_aton(p["dst"])
    pseudo = addresses + bytes((0, proto)) + len(transport).to_bytes(2, "big")
    checksum = internet_checksum(pseudo + transport)
    if p["checksum"] == "partial":
        checksum = (~internet_checksum(pseudo)) & 65535
    elif p["checksum"] == "incorrect":
        checksum ^= 0x1234
    elif p["checksum"] == "not_present":
        checksum = 0
    transport = transport[:checksum_offset] + struct.pack("!H", checksum) + transport[checksum_offset + 2:]
    ip = struct.pack("!BBHHHBBH", 0x45, 0, 20 + len(transport), 1, 0, 64, proto, 0) + addresses
    ip = ip[:10] + struct.pack("!H", internet_checksum(ip)) + ip[12:]
    return b"\x02" * 12 + b"\x08\x00" + ip + transport


class PacketReconciliationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)

    def fixture(self, specs, rows, *, nanoseconds=False, endian="<"):
        capture = self.directory / "fixture.pcap"
        magic = ({("<", False): b"\xd4\xc3\xb2\xa1", (">", False): b"\xa1\xb2\xc3\xd4",
                  ("<", True): b"\x4d\x3c\xb2\xa1", (">", True): b"\xa1\xb2\x3c\x4d"})[(endian, nanoseconds)]
        content = magic + struct.pack(endian + "HHIIII", 2, 4, 0, 0, 65535, 1)
        observations = []
        for number, spec in enumerate(specs, 1):
            raw = encode_packet(spec)
            seconds, fraction = divmod(spec["ns"], 1_000_000_000)
            self.assertEqual(fraction % (1 if nanoseconds else 1000), 0)
            content += struct.pack(endian + "IIII", seconds, fraction if nanoseconds else fraction // 1000,
                                   len(raw), len(raw)) + raw
            decoded = Packet(number, spec["ns"], "implicit-single-interface", spec["src"], spec["sport"],
                             spec["dst"], spec["dport"], spec["protocol"], len(raw) - 14,
                             spec["flags"] if spec["protocol"] == "tcp" else None,
                             spec["seq"] if spec["protocol"] == "tcp" else None)
            observations.append(PacketObservation(number, spec["ns"], decoded))
        capture.write_bytes(content)
        flows, quality = _aggregate(observations, ExtractionConfig(), "controlled-independent-packet-fixture")
        extraction = {"schema_version": "sipymes.offline.ipv4.v1", "extractor_version": "1.0.1",
            "source": {"sha256": hashlib.sha256(content).hexdigest()}, "flows": flows, "quality": quality}
        fields, types = FIELDS + ["conn_state", "history", "missed_bytes"], TYPES + ["string", "string", "count"]
        text = ("#separator \\x09\n#unset_field\t-\n#empty_field\t(empty)\n#fields\t"
                + "\t".join(fields) + "\n#types\t" + "\t".join(types) + "\n")
        for values in rows:
            text += "\t".join(values.get(name, "-") for name in fields) + "\n"
        labels = self.directory / "conn.log.labeled"
        labels.write_text(text + "#close\tfixture\n", encoding="utf-8")
        return extraction, import_zeek_labels(labels), read_packet_evidence(capture)

    def audit(self, specs, rows):
        return audit_packet_correspondences(*self.fixture(specs, rows))

    def normal(self):
        return [packet(1), packet(1.5, reverse=True), packet(2)]

    def siblings(self, checksum="partial", **changes):
        specs = [packet(1), packet(2, payload=b"abc", checksum=checksum),
                 packet(3, reverse=True), packet(302, reverse=True)]
        values = row(duration="301", orig_pkts="1", resp_pkts="2", orig_ip_bytes="40", resp_ip_bytes="80",
                     history="C", missed_bytes="3", **changes)
        return specs, [values]

    def syn_partition(self):
        specs = [packet(t, flags=2, seq=77) for t in (1, 2, 3, 8, 16)]
        rows = [row(duration="2", orig_pkts="3", resp_pkts="0", orig_ip_bytes="120", resp_ip_bytes="0"),
                row(uid="C2", ts="8", duration="-", orig_pkts="1", resp_pkts="0", orig_ip_bytes="40", resp_ip_bytes="0"),
                row(uid="C3", ts="16", duration="-", orig_pkts="1", resp_pkts="0", orig_ip_bytes="40", resp_ip_bytes="0")]
        return specs, rows

    def closure(self):
        specs = [packet(1), packet(2, flags=0x11, seq=10, ack=20),
                 packet(2.1, reverse=True, flags=0x11, seq=20, ack=11),
                 packet(2.2, flags=0x10, seq=11, ack=21)]
        values = row(duration="1.1", orig_pkts="3", orig_ip_bytes="120", conn_state="SF", history="Ff")
        return specs, [values]

    def test_rfc1071_encoder_vector_and_checksum_classification(self):
        self.assertEqual(internet_checksum(bytes.fromhex("0001f203f4f5f6f7")), 0x220d)
        for value, expected in [("valid", "valid"), ("partial", "partial_pseudoheader"), ("incorrect", "incorrect")]:
            with self.subTest(checksum=value):
                _, _, evidence = self.fixture([packet(1, payload=b"odd", checksum=value)], [row()])
                self.assertEqual(evidence["packets"][0]["transport_checksum_status"], expected)

    def test_unique_mapping_has_frame_uid_line_and_connection_group(self):
        report = self.audit(self.normal(), [row()])
        self.assertEqual(report["summary"]["admitted_flows"], 1)
        self.assertEqual(report["flow_correspondences"][0]["status"], "admitted_unique")
        self.assertEqual([p["frame"] for p in report["packet_ledger"]], [1, 2, 3])
        self.assertTrue(all(p["reference_uid"] == "C1" and p["reference_source_line"] for p in report["packet_ledger"]))

    def test_inverted_orientation_uses_actual_packet_directions(self):
        specs = [packet(1, reverse=True), packet(2, reverse=True)]
        result = self.audit(specs, [row(orig_pkts="0", resp_pkts="2", orig_ip_bytes="0", resp_ip_bytes="80")])
        self.assertEqual(result["summary"]["admitted_flows"], 1)

    def test_partial_segment_quarantined_but_healthy_sibling_admitted(self):
        report = self.audit(*self.siblings())
        self.assertEqual([f["status"] for f in report["flow_correspondences"]],
                         ["quarantined_partial_checksum", "admitted_sibling_segment"])
        self.assertIsNone(report["flow_correspondences"][0]["binary_label"])
        self.assertEqual(report["reference_correspondences"][0]["partial_checksum_frames"], [2])
        self.assertEqual(report["reference_correspondences"][0]["state"], "verified")
        self.assertEqual(len({f["connection_group_id"] for f in report["flow_correspondences"]}), 1)

    def test_incorrect_checksum_does_not_recover_siblings_as_partial(self):
        report = self.audit(*self.siblings(checksum="incorrect"))
        self.assertEqual(report["summary"]["admitted_flows"], 0)
        self.assertEqual(report["flow_correspondences"][0]["status"], "quarantined_incorrect_checksum")
        self.assertEqual(report["reference_correspondences"][0]["state"], "incorrect_checksum_evidence")

    def test_partial_pattern_alone_without_zeek_evidence_is_insufficient(self):
        for history, missed in [("-", "3"), ("c", "3"), ("C", "4"), ("C", "-")]:
            specs, rows = self.siblings()
            rows[0].update(history=history, missed_bytes=missed)
            self.assertEqual(self.audit(specs, rows)["summary"]["admitted_flows"], 0)

    def test_partial_packet_cannot_be_silently_subtracted_from_counted_reference(self):
        specs, rows = self.siblings()
        rows[0].update(orig_pkts="2", orig_ip_bytes="83")
        report = self.audit(specs, rows)
        self.assertEqual(report["summary"]["admitted_flows"], 0)
        self.assertEqual(report["reference_correspondences"][0]["state"], "counter_mismatch")

    def test_synthetic_syn_partition_is_complete_exclusive_and_preserves_uids(self):
        report = self.audit(*self.syn_partition())
        result = report["flow_correspondences"][0]
        self.assertEqual(result["status"], "admitted_partition")
        self.assertEqual({r["uid"] for r in result["references"]}, {"C1", "C2", "C3"})
        frames = [n for r in report["reference_correspondences"] for n in r["accounted_packet_frames"]]
        self.assertEqual(sorted(frames), [1, 2, 3, 4, 5])
        self.assertEqual(len(set(frames)), len(frames))

    def test_missing_syn_reference_leaves_uncovered_packet_unlabeled(self):
        specs, rows = self.syn_partition()
        report = self.audit(specs, [rows[0], rows[2]])
        self.assertEqual(report["summary"]["admitted_flows"], 0)
        self.assertEqual(report["packet_ledger"][3]["packet_state"], "not_found")

    def test_identical_duplicate_references_are_ambiguous_not_deduplicated(self):
        report = self.audit(self.normal(), [row(), row(uid="C2")])
        self.assertEqual(report["flow_correspondences"][0]["status"], "ambiguous")
        self.assertIsNone(report["flow_correspondences"][0]["binary_label"])

    def test_conflicting_labels_and_details_never_form_a_valid_partition(self):
        for label, detail in [("Malicious", "C&C"), ("Benign", "Attack")]:
            specs, rows = self.syn_partition()
            rows[1].update(label=label, **{"detailed-label": detail})
            report = self.audit(specs, rows)
            self.assertEqual(report["flow_correspondences"][0]["status"], "contradictory")
        specs, rows = self.syn_partition()
        for r in rows:r.update(label="Malicious", **{"detailed-label": "A"})
        rows[1]["detailed-label"] = "B"
        self.assertEqual(self.audit(specs, rows)["summary"]["admitted_flows"], 0)

    def test_exact_fin_ack_chain_reconciles_ack_after_duration(self):
        report = self.audit(*self.closure())
        self.assertEqual(report["flow_correspondences"][0]["status"], "admitted_tcp_closure")
        self.assertEqual(report["packet_ledger"][-1]["support_rule"], "exact_fin_finack_ack_chain")
        self.assertEqual(report["reference_correspondences"][0]["observed_counts"]["orig_pkts"], 3)

    def test_closure_has_no_generic_time_tolerance(self):
        specs, rows = self.closure()
        specs[-1]["ns"] += 900_000_000_000
        # Exact sequence proof can survive a delay; timing distance alone proves nothing.
        report = self.audit(specs, rows)
        self.assertEqual(report["summary"]["admitted_flows"], 2)
        specs[-1]["ack"] += 1
        self.assertEqual(self.audit(specs, rows)["summary"]["admitted_flows"], 0)

    def test_wrong_ack_payload_flags_fin_or_source_evidence_prevents_extension(self):
        for mutation in ("ack", "seq", "payload", "flags", "fin_ack", "source", "boundary"):
            with self.subTest(mutation=mutation):
                specs, rows = self.closure()
                if mutation in {"ack", "seq"}:specs[-1][mutation] += 1
                elif mutation == "payload":specs[-1]["payload"] = b"x"
                elif mutation == "flags":specs[-1]["flags"] = 0x18
                elif mutation == "fin_ack":specs[-2]["ack"] += 1
                elif mutation == "source":rows[0]["conn_state"] = "-"
                elif mutation == "boundary":rows[0]["duration"] = "1.100001"
                self.assertEqual(self.audit(specs, rows)["summary"]["admitted_flows"], 0)

    def test_new_syn_between_fins_and_ack_blocks_old_connection_extension(self):
        specs, rows = self.closure()
        specs.insert(-1, packet(2.15, flags=2, seq=999))
        report = self.audit(specs, rows)
        self.assertEqual(report["summary"]["admitted_flows"], 0)

    def test_closure_does_not_choose_between_duplicate_references(self):
        specs, rows = self.closure()
        duplicate = dict(rows[0], uid="C2")
        report = self.audit(specs, rows + [duplicate])
        self.assertEqual(report["flow_correspondences"][0]["status"], "ambiguous")
        self.assertEqual(report["packet_ledger"][-1]["packet_state"], "ambiguous")

    def test_partition_requires_whole_references_inside_the_flow(self):
        specs = [packet(1), packet(2), packet(302, reverse=True)]
        rows = [row(duration="-", orig_pkts="1", resp_pkts="0", orig_ip_bytes="40", resp_ip_bytes="0"),
                row(uid="C2", ts="2", duration="300", orig_pkts="1", resp_pkts="1", orig_ip_bytes="40", resp_ip_bytes="40")]
        report = self.audit(specs, rows)
        self.assertEqual([f["status"] for f in report["flow_correspondences"]],
                         ["segmentation_mismatch", "admitted_sibling_segment"])
        self.assertEqual(len({f["connection_group_id"] for f in report["flow_correspondences"]}), 1)

    def test_counter_excess_and_deficit_both_prevent_reconciliation(self):
        for count in ("1", "3"):
            report = self.audit(self.normal(), [row(orig_pkts=count)])
            self.assertEqual(report["summary"]["admitted_flows"], 0)
            self.assertTrue(report["reference_correspondences"][0]["counter_conflicts"])

    def test_empty_capture_and_labels_have_unknown_coverage(self):
        report = self.audit([], [])
        self.assertEqual(report["summary"]["admitted_flows"], 0)
        self.assertIsNone(report["summary"]["flow_label_coverage_percent"])
        self.assertEqual(report["packet_ledger"], [])

    def test_sequence_wraparound_is_checked_modulo_32_bits(self):
        specs, rows = self.closure()
        specs[1].update(seq=0xffffffff, ack=0xffffffff)
        specs[2].update(seq=0xffffffff, ack=0)
        specs[3].update(seq=0, ack=0)
        self.assertEqual(self.audit(specs, rows)["summary"]["admitted_flows"], 1)

    def test_port_reuse_with_distinct_syn_sequences_and_times(self):
        specs = [packet(1, flags=2, seq=100), packet(2, flags=2, seq=200)]
        rows = [row(duration="-", orig_pkts="1", resp_pkts="0", orig_ip_bytes="40", resp_ip_bytes="0"),
                row(uid="C2", ts="2", duration="-", orig_pkts="1", resp_pkts="0", orig_ip_bytes="40", resp_ip_bytes="0")]
        report = self.audit(specs, rows)
        self.assertEqual(report["summary"]["admitted_flows"], 2)
        self.assertEqual(len({f["connection_group_id"] for f in report["flow_correspondences"]}), 2)

    def test_missing_packet_evidence_unknown_counters_and_unknown_label(self):
        extraction, imported, evidence = self.fixture(self.normal(), [row()])
        with self.assertRaisesRegex(ValueError, "requires original packet evidence"):
            audit_packet_correspondences(extraction, imported, None)
        for changes in ({"orig_pkts":"-"}, {"duration":"-"}, {"label":"-"}):
            self.assertEqual(self.audit(self.normal(), [row(**changes)])["summary"]["admitted_flows"], 0)

    def test_missing_duplicate_or_changed_frame_binding_fails_closed(self):
        for mutation in ("missing", "duplicate", "counter", "time", "hash"):
            extraction, imported, evidence = self.fixture(self.normal(), [row()])
            if mutation == "missing":extraction["flows"][0]["packet_frames"] = [99]
            elif mutation == "duplicate":extraction["flows"][0]["packet_frames"] = [1, 1, 3]
            elif mutation == "counter":extraction["flows"][0]["features"]["forward_ipv4_byte_count"]["value"] += 1
            elif mutation == "time":extraction["flows"][0]["last_timestamp_epoch_ns"] = "1999999999"
            else:evidence["source"]["sha256"] = "wrong"
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                audit_packet_correspondences(extraction, imported, evidence)

    def test_udp_absent_checksum_is_explicit_and_direction_contradiction_is_not_fixed(self):
        specs = [packet(1, protocol="udp", checksum="not_present"), packet(2, protocol="udp", checksum="not_present")]
        report = self.audit(specs, [row(proto="udp", orig_pkts="2", resp_pkts="0", orig_ip_bytes="56", resp_ip_bytes="0")])
        self.assertEqual(report["summary"]["admitted_flows"], 1)
        self.assertEqual(report["packet_ledger"][0]["transport_checksum_status"], "not_present_ipv4_udp")
        report = self.audit(specs, [row(proto="udp", orig_pkts="1", resp_pkts="1", orig_ip_bytes="28", resp_ip_bytes="28", history="D^d")])
        self.assertEqual(report["summary"]["admitted_flows"], 0)

    def test_ip_header_checksum_corruption_does_not_masquerade_as_tcp_partial(self):
        extraction, imported, evidence = self.fixture(*self.siblings())
        path = self.directory / "fixture.pcap"
        raw = bytearray(path.read_bytes())
        raw[24 + 16 + 14 + 10] ^= 1
        path.write_bytes(raw)
        extraction["source"]["sha256"] = hashlib.sha256(raw).hexdigest()
        report = audit_packet_correspondences(extraction, imported, read_packet_evidence(path))
        self.assertEqual(report["summary"]["admitted_flows"], 0)

    def test_pcap_endian_nanoseconds_corruption_and_resource_limits(self):
        for endian in ("<", ">"):
            _, _, evidence = self.fixture([packet(1)], [row()], nanoseconds=True, endian=endian)
            self.assertEqual(evidence["packets"][0]["timestamp_epoch_ns"], "1000000000")
        path = self.directory / "fixture.pcap"
        for kwargs in ({"max_bytes":1}, {"max_frames":0}):
            with self.assertRaises(ValueError):read_packet_evidence(path, **kwargs)
        raw = path.read_bytes()
        for data in (raw[:-1], b"\x0a\x0d\x0d\x0a" + raw[4:], raw[:25]):
            path.write_bytes(data)
            with self.assertRaises(ValueError):read_packet_evidence(path)

    def test_audit_is_repeatable_and_never_changes_features_labels_or_packet_bytes(self):
        values = self.fixture(*self.siblings())
        original = deepcopy(values)
        first = audit_packet_correspondences(*values)
        self.assertEqual(first, audit_packet_correspondences(*values))
        self.assertEqual(values, original)
        self.assertEqual(hashlib.sha256((self.directory/'fixture.pcap').read_bytes()).hexdigest(), values[0]["source"]["sha256"])

    def test_file_api_binds_actual_pcap_and_keeps_legacy_mode_available(self):
        extraction, imported, _ = self.fixture(self.normal(), [row()])
        extraction_path = self.directory / "extraction.json"
        extraction_path.write_text(json.dumps(extraction), encoding="utf-8")
        provenance = self.directory / "provenance.json"
        provenance.write_text(json.dumps({"scenario":"fixture", "files":[
            {"role":"pcap", "sha256":extraction["source"]["sha256"]},
            {"role":"labels", "sha256":imported["source"]["sha256"]}]}), encoding="utf-8")
        args = (extraction_path, self.directory/'conn.log.labeled', provenance)
        report = audit_files(*args, self.directory/'new', capture_path=self.directory/'fixture.pcap')
        self.assertEqual(report["audit_version"], "sipymes.label-audit.v2")
        self.assertEqual(report["summary"]["admitted_flows"], 1)
        with self.assertRaises(ValueError):
            audit_files(*args, self.directory/'new', capture_path=self.directory/'fixture.pcap')
        self.assertEqual(audit_files(*args, self.directory/'legacy')["audit_version"], "sipymes.label-audit.v1")


@unittest.skipUnless((PILOT / PCAP_NAME).is_file() and (PILOT / 'conn.log.labeled').is_file()
                     and (PILOT.parents[2] / 'data/processed/iot23_pilot_20_1/extraction.json').is_file(),
                     'Local official pilot is absent; tests never download data')
class LocalPacketReconciliationRegressionTests(unittest.TestCase):
    def test_real_pilot_conserves_packets_and_keeps_all_partial_segments_quarantined(self):
        capture = PILOT / PCAP_NAME
        labels = PILOT / 'conn.log.labeled'
        self.assertEqual(hashlib.sha256(capture.read_bytes()).hexdigest(),
                         '4d0a00c33a4bf11228158baddd47c38f702731ea8d75ef1201061fc8bbd878b9')
        self.assertEqual(hashlib.sha256(labels.read_bytes()).hexdigest(),
                         'ef48ad72f65efd13d517223e61e4d877ba53a082ddb8159324b18d3f310d0711')
        extraction = json.loads((PILOT.parents[2] / 'data/processed/iot23_pilot_20_1/extraction.json').read_text(encoding='utf-8'))
        report = audit_packet_correspondences(extraction, import_zeek_labels(labels), read_packet_evidence(capture))
        self.assertEqual(report['summary']['flow_status_counts'], {
            'admitted_unique':3177, 'admitted_sibling_segment':313, 'admitted_partition':4,
            'admitted_tcp_closure':1, 'quarantined_partial_checksum':3, 'counter_mismatch':1})
        self.assertEqual(report['summary']['admitted_flows'], 3495)
        self.assertEqual(report['summary']['labeled_packets'], 40921)
        self.assertEqual(report['summary']['class_coverage']['Malicious']['matched_references'], 14)
        self.assertEqual(len(report['packet_ledger']), 50156)
        partial = [p for p in report['packet_ledger'] if p.get('transport_checksum_status')=='partial_pseudoheader']
        self.assertEqual([p['frame'] for p in partial], [266, 24789, 24825, 24828])
        self.assertTrue(all(not p['flow_label_admitted'] for p in partial))
        self.assertEqual(sum(p['flow_label_admitted'] for p in report['packet_ledger']), 40921)
        self.assertEqual(sum(p['support_rule']=='exact_fin_finack_ack_chain' for p in report['packet_ledger']), 1)
