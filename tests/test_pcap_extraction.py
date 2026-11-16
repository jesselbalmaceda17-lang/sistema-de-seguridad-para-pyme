"""Offline tests: controlled decoded fields, mocked subprocess transport, optional real TShark."""

from contextlib import redirect_stderr, redirect_stdout
from dataclasses import replace
import csv
import hashlib
import io
import json
from pathlib import Path
import subprocess
import struct
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from seguridad_pymes.pcap_extract import _aggregate, extract_capture, main
from seguridad_pymes.pcap_reader import (
    FIELDS, CaptureError, Packet, PacketObservation, TSharkReader,
    TSharkUnavailable, decode_row, find_tshark,
)
from seguridad_pymes.pcap_schema import ExtractionConfig, SCHEMA_VERSION, feature_definitions
from tests.pcap_fixtures import ethernet_packet, pcap, pcapng


def decoded_fields(**changes):
    values = dict.fromkeys(FIELDS, "")
    values.update({"frame.number": "1", "frame.time_epoch": "1.000000001",
                   "frame.len": "54", "frame.cap_len": "54", "frame.encap_type": "1",
                   "eth.type": "0x0800", "ip.version": "4", "ip.src": "10.0.0.1",
                   "ip.dst": "10.0.0.2", "ip.len": "40", "ip.hdr_len": "20",
                   "ip.flags.mf": "0", "ip.frag_offset": "0", "ip.proto": "6",
                   "tcp.srcport": "40000", "tcp.dstport": "8080", "tcp.hdr_len": "20",
                   "tcp.flags": "0x0002", "tcp.seq_raw": "100"})
    values.update(changes)
    return values


def packet(frame=1, ns=1_000_000_000, *, reverse=False, protocol="tcp", flags=0x10,
           length=40, sequence=100, interface="0"):
    endpoints = ("10.0.0.1", 40000, "10.0.0.2", 8080)
    if reverse:
        endpoints = ("10.0.0.2", 8080, "10.0.0.1", 40000)
    return Packet(frame, ns, interface, *endpoints, protocol, length,
                  flags if protocol == "tcp" else None, sequence if protocol == "tcp" else None)


def aggregate(packets, config=None):
    observations = [PacketObservation(p.frame, p.timestamp_ns, p) for p in packets]
    return _aggregate(observations, config or ExtractionConfig(), "test-identity")


class FlowExtractionTests(unittest.TestCase):
    def test_counts_ipv4_bytes_sizes_intervals_and_flags_with_manual_oracle(self):
        flows, quality = aggregate([
            packet(1, 1_000_000_000, flags=2, length=40),
            packet(2, 1_100_000_000, reverse=True, flags=18, length=60),
            packet(3, 1_300_000_000, flags=16, length=60),
            packet(4, 1_800_000_000, flags=24, length=80),
        ])
        self.assertEqual(len(flows), 1)
        flow = flows[0]
        f = flow["features"]
        self.assertEqual(set(f), set(feature_definitions()))
        self.assertEqual(len(f), 38)
        expected = {"observed_duration_seconds": .8, "transport_protocol": "tcp",
                    "forward_packet_count": 3, "reverse_packet_count": 1,
                    "forward_ipv4_byte_count": 180, "reverse_ipv4_byte_count": 60,
                    "forward_ipv4_size_min_bytes": 40, "forward_ipv4_size_max_bytes": 80,
                    "forward_ipv4_size_mean_bytes": 60, "forward_iat_min_seconds": .3,
                    "forward_iat_max_seconds": .5, "forward_iat_mean_seconds": .4,
                    "forward_iat_population_std_seconds": .1,
                    "forward_tcp_syn_count": 1, "reverse_tcp_syn_count": 1,
                    "forward_tcp_ack_count": 2, "forward_tcp_psh_count": 1,
                    "forward_tcp_rst_count": 0}
        for name, value in expected.items():
            self.assertEqual(f[name]["status"], "ok", name)
            if isinstance(value, float):
                self.assertAlmostEqual(f[name]["value"], value, places=12, msg=name)
            else:
                self.assertEqual(f[name]["value"], value, name)
        self.assertAlmostEqual(f["forward_ipv4_size_population_std_bytes"]["value"], (800 / 3) ** .5)
        self.assertEqual(f["reverse_iat_mean_seconds"]["reason"], "fewer_than_two_packets_in_direction")
        self.assertEqual(flow["packet_frames"], [1, 2, 3, 4])
        self.assertEqual(flow["quality"]["start_observation"], "initial_syn_observed")
        self.assertEqual(quality["packets_accepted"], 4)

    def test_singleton_zero_duration_and_absent_direction_not_invented(self):
        flow = aggregate([packet()])[0][0]
        f = flow["features"]
        self.assertEqual(f["observed_duration_seconds"]["value"], 0)
        self.assertEqual(f["reverse_packet_count"]["value"], 0)
        self.assertIsNone(f["reverse_ipv4_size_mean_bytes"]["value"])
        self.assertEqual(f["reverse_ipv4_size_mean_bytes"]["reason"], "no_packets_in_direction")
        self.assertIsNone(f["forward_iat_mean_seconds"]["value"])
        self.assertEqual(flow["quality"]["start_observation"], "midstream_or_start_unknown")
        self.assertEqual(flow["quality"]["end_observation"], "connection_end_not_observed")

    def test_udp_tcp_flags_not_applicable(self):
        f = aggregate([packet(protocol="udp", length=28)])[0][0]["features"]
        self.assertEqual(f["forward_tcp_syn_count"], {"value": None, "status": "unavailable", "reason": "not_applicable_to_udp"})

    def test_orientation_is_first_observed_endpoint(self):
        flow = aggregate([packet(reverse=True), packet(2, 2_000_000_000)])[0][0]
        self.assertEqual(flow["forward_endpoint"]["ipv4"], "10.0.0.2")
        self.assertEqual(flow["features"]["reverse_packet_count"]["value"], 1)

    def test_interfaces_and_protocols_are_not_merged(self):
        flows, _ = aggregate([packet(), packet(2, interface="1"), packet(3, protocol="udp")])
        self.assertEqual(len(flows), 3)

    def test_idle_boundary_and_active_timeout(self):
        config = ExtractionConfig(tcp_idle_seconds=2, active_timeout_seconds=3)
        flows, _ = aggregate([packet(1, 0), packet(2, 2_000_000_000)], config)
        self.assertEqual(len(flows), 2)
        self.assertEqual(flows[0]["close_reason"], "idle_timeout")
        flows, _ = aggregate([packet(1, 0), packet(2, 1_000_000_000), packet(3, 2_000_000_000), packet(4, 3_000_000_000)], config)
        self.assertEqual([x["packet_frames"] for x in flows], [[1, 2, 3], [4]])
        self.assertEqual(flows[0]["close_reason"], "active_timeout")

    def test_udp_has_its_own_idle_timeout(self):
        config = ExtractionConfig(udp_idle_seconds=1)
        flows, _ = aggregate([packet(1, 0, protocol="udp"), packet(2, 1_000_000_000, protocol="udp")], config)
        self.assertEqual(len(flows), 2)

    def test_rst_closes_immediately(self):
        flows, _ = aggregate([packet(flags=4), packet(2, 2_000_000_000)])
        self.assertEqual(len(flows), 2)
        self.assertEqual(flows[0]["close_reason"], "tcp_rst")
        self.assertEqual(flows[0]["quality"]["end_observation"], "rst_observed")

    def test_fin_keeps_final_ack_and_new_syn_opens_new_flow(self):
        flows, _ = aggregate([packet(1, 0, flags=2), packet(2, 1, flags=17),
                              packet(3, 2, reverse=True, flags=17), packet(4, 3, flags=16),
                              packet(5, 4, flags=2)])
        self.assertEqual([f["packet_frames"] for f in flows], [[1, 2, 3, 4], [5]])
        self.assertEqual(flows[0]["quality"]["end_observation"], "fin_observed_in_both_directions")

    def test_syn_retransmission_and_reused_tuple(self):
        flows, _ = aggregate([packet(1, 0, flags=2), packet(2, 1, flags=2),
                              packet(3, 2, flags=2, sequence=200)])
        self.assertEqual([f["packet_frames"] for f in flows], [[1, 2], [3]])

    def test_same_timestamp_is_a_real_zero_interval(self):
        f = aggregate([packet(), packet(2)])[0][0]["features"]
        self.assertEqual(f["forward_iat_mean_seconds"]["value"], 0)

    def test_non_monotonic_time_and_frames_fail(self):
        for packets in ([packet(1, 2), packet(2, 1)], [packet(2, 1), packet(1, 2)]):
            with self.assertRaisesRegex(CaptureError, "ordered"):
                aggregate(packets)

    def test_rejections_are_counted_and_affect_quality(self):
        observations = [PacketObservation(1, 0, None, "unsupported_transport_protocol"),
                        PacketObservation(2, 1, packet(2, 1))]
        flows, q = _aggregate(observations, ExtractionConfig(), "test")
        self.assertEqual(q["packets_seen"], q["packets_accepted"] + q["packets_rejected"])
        self.assertEqual(q["rejections_by_reason"], {"unsupported_transport_protocol": 1})
        self.assertTrue(flows[0]["quality"]["capture_has_rejected_packets"])

    def test_indistinguishable_endpoints_are_rejected(self):
        p = replace(packet(), dst="10.0.0.1", dport=40000)
        flows, q = aggregate([p])
        self.assertFalse(flows)
        self.assertEqual(q["rejections_by_reason"], {"indistinguishable_flow_endpoints": 1})

    def test_all_resource_limits_fail_explicitly(self):
        cases = [(ExtractionConfig(max_packets=1), [packet(), packet(2)]),
                 (ExtractionConfig(max_active_flows=1), [packet(), packet(2, interface="1")]),
                 (ExtractionConfig(max_flows=1), [packet(flags=4), packet(2)])]
        for config, packets in cases:
            with self.assertRaisesRegex(CaptureError, "limit exceeded"):
                aggregate(packets, config)

    def test_repeated_extraction_and_heap_compaction_are_deterministic(self):
        packets = [packet(i + 1, i) for i in range(2200)]
        left = aggregate(packets)
        self.assertEqual(left, aggregate(packets))
        self.assertEqual(left[1]["packets_accepted"], 2200)

    def test_empty_input_and_configuration_validation(self):
        flows, quality = aggregate([])
        self.assertEqual(flows, [])
        self.assertIsNone(quality["first_timestamp_epoch_ns"])
        for kwargs in ({"tcp_idle_seconds": 0}, {"udp_idle_seconds": float("nan")},
                       {"active_timeout_seconds": True}, {"max_packets": 1.5},
                       {"max_active_flows": -1}, {"tcp_idle_seconds": 1.1e-9}):
            with self.assertRaises(ValueError):
                ExtractionConfig(**kwargs)


class PacketDecoderTests(unittest.TestCase):
    def test_decodes_tcp_and_nanosecond_timestamp(self):
        observation = decode_row(decoded_fields())
        self.assertEqual(observation.packet.timestamp_ns, 1_000_000_001)
        self.assertEqual(observation.packet.ipv4_bytes, 40)
        self.assertEqual(observation.packet.tcp_flags, 2)

    def test_decodes_udp(self):
        p = decode_row(decoded_fields(**{"ip.proto":"17", "ip.len":"28", "udp.srcport":"53", "udp.dstport":"40000", "udp.length":"8"})).packet
        self.assertEqual(p.protocol, "udp")
        self.assertIsNone(p.tcp_flags)

    def test_real_tshark_boolean_representations_are_strict(self):
        for value in ("False", "false", "FALSE", "0"):
            with self.subTest(value=value):
                self.assertIsNotNone(decode_row(decoded_fields(**{"ip.flags.mf": value})).packet)
        for value in ("True", "true", "TRUE", "1"):
            with self.subTest(value=value):
                self.assertEqual(decode_row(decoded_fields(**{"ip.flags.mf": value})).rejection_reason,
                                 "ipv4_fragment_not_supported")
        for value in ("", "unknown", "2"):
            with self.subTest(value=value):
                self.assertEqual(decode_row(decoded_fields(**{"ip.flags.mf": value})).rejection_reason,
                                 "missing_or_invalid_header")

    def test_unsupported_truncated_fragmented_and_invalid_headers(self):
        cases = [({"frame.cap_len":"40"}, "truncated_packet"),
                 ({"frame.encap_type":"113"}, "unsupported_link_layer"),
                 ({"eth.type":"0x86dd"}, "unsupported_ethernet_payload"),
                 ({"vlan.id":"3"}, "unsupported_ethernet_payload"),
                 ({"ip.proto":"1"}, "unsupported_transport_protocol"),
                 ({"ip.flags.mf":"1"}, "ipv4_fragment_not_supported"),
                 ({"ip.frag_offset":"8"}, "ipv4_fragment_not_supported"),
                 ({"_ws.malformed":"Malformed Packet"}, "malformed_packet"),
                 ({"ip.len":"800"}, "invalid_ipv4_length"),
                 ({"tcp.hdr_len":"12"}, "invalid_tcp_header"),
                 ({"tcp.srcport":""}, "missing_or_invalid_header"),
                 ({"tcp.srcport":"70000"}, "invalid_transport_port")]
        for changes, reason in cases:
            with self.subTest(changes=changes):
                observation = decode_row(decoded_fields(**changes))
                self.assertIsNone(observation.packet)
                self.assertEqual(observation.rejection_reason, reason)

    def test_invalid_timestamp_or_frame_fails_capture(self):
        for changes in ({"frame.time_epoch":"NaN"}, {"frame.time_epoch":"1.0000000001"},
                        {"frame.number":"0"}, {"frame.time_epoch":"1e100"}):
            with self.assertRaises(CaptureError):
                decode_row(decoded_fields(**changes))


class _FakeProcess:
    """Subprocess transport double, not a packet decoder or a real TShark run."""
    def __init__(self, output, code=0):
        self.stdout = io.StringIO(output)
        self.code = code
        self.killed = False

    def poll(self):
        return self.code

    def wait(self):
        return self.code

    def kill(self):
        self.killed = True


def tsv(rows):
    output = io.StringIO()
    writer = csv.writer(output, delimiter="\t", quoting=csv.QUOTE_ALL)
    writer.writerow(FIELDS)
    for row in rows:
        writer.writerow([row[name] for name in FIELDS])
    return output.getvalue()


class TSharkTransportTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.capture = Path(self.temp.name) / "lab capture.pcap"
        self.capture.write_bytes(pcap([(1_000_000, ethernet_packet())]))

    def mocked_reader(self, rows=None, code=0):
        reader = TSharkReader(sys.executable)
        process = _FakeProcess(tsv(rows if rows is not None else [decoded_fields()]), code)
        return reader, process

    def test_optional_dependency_missing_gives_manual_steps(self):
        with patch("seguridad_pymes.pcap_reader.shutil.which", return_value=None), patch("seguridad_pymes.pcap_reader.Path.is_file", return_value=False):
            with self.assertRaisesRegex(TSharkUnavailable, "Instale manualmente"):
                find_tshark()

    def test_absolute_executable_and_program_files_work_without_path(self):
        with patch("seguridad_pymes.pcap_reader.shutil.which", return_value=None):
            self.assertEqual(find_tshark(sys.executable), Path(sys.executable).resolve())
            with patch.dict("os.environ", {"ProgramFiles": self.temp.name, "ProgramFiles(x86)": ""}):
                executable = Path(self.temp.name) / "Wireshark" / "tshark.exe"
                executable.parent.mkdir()
                executable.write_bytes(b"discovery-fixture-not-executable")
                self.assertEqual(find_tshark(), executable.resolve())

    def test_mocked_command_is_offline_and_profile_is_isolated(self):
        reader, process = self.mocked_reader()
        profile_directories = []
        def launch_process(*args, **kwargs):
            profile_directories.append(kwargs["env"]["WIRESHARK_CONFIG_DIR"])
            self.assertTrue(Path(profile_directories[-1]).is_dir())
            return process
        with patch("seguridad_pymes.pcap_reader.subprocess.run", return_value=SimpleNamespace(stdout="TShark fixture-version\n")), patch("seguridad_pymes.pcap_reader.subprocess.Popen", side_effect=launch_process) as launch:
            result = list(reader.observations(self.capture))
            args, kwargs = launch.call_args
            command = args[0]
            self.assertEqual(command[command.index("-r") + 1], str(self.capture.resolve()))
            self.assertNotIn("-i", command)
            self.assertNotIn("-w", command)
            self.assertFalse(kwargs.get("shell", False))
        self.assertEqual(len(result), 1)
        self.assertTrue(process.stdout.closed)
        self.assertFalse(Path(profile_directories[0]).exists())

    def test_nonzero_exit_rejects_report_even_after_valid_packets(self):
        reader, process = self.mocked_reader(code=2)
        with patch("seguridad_pymes.pcap_reader.subprocess.run", return_value=SimpleNamespace(stdout="TShark fixture\n")), patch("seguridad_pymes.pcap_reader.subprocess.Popen", return_value=process):
            with self.assertRaisesRegex(CaptureError, "failed"):
                list(reader.observations(self.capture))

    def test_invalid_backend_output_rejected(self):
        for output in ("bad-header\n", tsv([]) + "one-field\n"):
            reader, _ = self.mocked_reader()
            with patch("seguridad_pymes.pcap_reader.subprocess.run", return_value=SimpleNamespace(stdout="TShark fixture\n")), patch("seguridad_pymes.pcap_reader.subprocess.Popen", return_value=_FakeProcess(output)):
                with self.assertRaises(CaptureError):
                    list(reader.observations(self.capture))

    def test_version_timeout_is_explicit(self):
        reader, _ = self.mocked_reader()
        with patch("seguridad_pymes.pcap_reader.subprocess.run", side_effect=subprocess.TimeoutExpired("tshark", 10)):
            with self.assertRaises(CaptureError):
                list(reader.observations(self.capture))

    def test_processing_timeout_is_explicit(self):
        class SlowOutput(io.StringIO):
            def __next__(self):
                time.sleep(.02)
                return super().__next__()
        reader, process = self.mocked_reader()
        reader.timeout_seconds = .005
        process.stdout = SlowOutput(tsv([decoded_fields()]))
        with patch("seguridad_pymes.pcap_reader.subprocess.run", return_value=SimpleNamespace(stdout="TShark fixture\n")), patch("seguridad_pymes.pcap_reader.subprocess.Popen", return_value=process):
            with self.assertRaisesRegex(CaptureError, "timeout"):
                list(reader.observations(self.capture))

    def test_real_bad_container_header_fails_before_backend(self):
        self.capture.write_bytes(b"not a pcap file")
        with patch("seguridad_pymes.pcap_extract.TSharkReader") as reader:
            with self.assertRaisesRegex(CaptureError, "container header"):
                extract_capture(self.capture)
        reader.assert_not_called()

    def test_report_hash_schema_repeatability_and_no_inference_import(self):
        def run():
            with patch("seguridad_pymes.pcap_reader.subprocess.run", return_value=SimpleNamespace(stdout="TShark fixture\n")), patch("seguridad_pymes.pcap_reader.subprocess.Popen", return_value=_FakeProcess(tsv([decoded_fields()]))):
                return extract_capture(self.capture, tshark_path=sys.executable)
        result = run()
        self.assertEqual(result, run())
        self.assertEqual(result["schema_version"], SCHEMA_VERSION)
        self.assertEqual(len(result["source"]["sha256"]), 64)
        json.dumps(result, allow_nan=False)
        self.assertNotIn("predictions", result)
        self.assertNotIn("alerts", result)

    def test_offline_import_does_not_load_application_or_ml_dependencies(self):
        program = (
            "import sys; import seguridad_pymes.pcap_extract; "
            "forbidden = {'seguridad_pymes.inference', 'seguridad_pymes.database', "
            "'seguridad_pymes.training', 'joblib', 'sklearn', 'sqlite3', 'streamlit'}; "
            "assert not forbidden.intersection(sys.modules), forbidden.intersection(sys.modules)"
        )
        result = subprocess.run([sys.executable, "-B", "-c", program], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_source_mutation_is_rejected(self):
        with patch("seguridad_pymes.pcap_extract._hash_file", side_effect=["before", "after"]), patch("seguridad_pymes.pcap_reader.subprocess.run", return_value=SimpleNamespace(stdout="TShark fixture\n")), patch("seguridad_pymes.pcap_reader.subprocess.Popen", return_value=_FakeProcess(tsv([]))):
            with self.assertRaisesRegex(CaptureError, "changed"):
                extract_capture(self.capture, tshark_path=sys.executable)

    def test_cli_does_not_overwrite_and_does_not_write_on_failure(self):
        output = Path(self.temp.name) / "existing.json"
        output.write_text("preserve", encoding="utf-8")
        with redirect_stderr(io.StringIO()):
            self.assertEqual(main([str(self.capture), "--output", str(output)]), 2)
        self.assertEqual(output.read_text(encoding="utf-8"), "preserve")
        output = Path(self.temp.name) / "not-created.json"
        with patch("seguridad_pymes.pcap_extract.extract_capture", side_effect=CaptureError("corrupt capture")), redirect_stderr(io.StringIO()):
            self.assertEqual(main([str(self.capture), "--output", str(output)]), 2)
        self.assertFalse(output.exists())

    def test_cli_success_with_controlled_report(self):
        output = Path(self.temp.name) / "new.json"
        with patch("seguridad_pymes.pcap_extract.extract_capture", return_value={"flows": []}), redirect_stdout(io.StringIO()):
            self.assertEqual(main([str(self.capture), "--output", str(output)]), 0)
        self.assertEqual(json.loads(output.read_text(encoding="utf-8")), {"flows": []})


try:
    REAL_TSHARK = find_tshark()
except TSharkUnavailable:
    REAL_TSHARK = None


@unittest.skipUnless(REAL_TSHARK, "Real PCAP/PCAPNG integration requires optional TShark; nothing is installed automatically")
class RealTSharkIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def assert_all_features(self, actual, expected):
        """Independent complete oracle: None means unavailable with the supplied reason."""
        self.assertEqual(len(actual), 38)
        self.assertEqual(set(actual), set(expected))
        for name, (value, reason) in expected.items():
            with self.subTest(feature=name):
                self.assertEqual(actual[name]["status"], "ok" if reason is None else "unavailable")
                self.assertEqual(actual[name]["reason"], reason)
                if isinstance(value, float):
                    self.assertAlmostEqual(actual[name]["value"], value, places=12)
                else:
                    self.assertEqual(actual[name]["value"], value)

    def test_pcap_and_pcapng_bidirectional_counts_and_repetition(self):
        packets = [(1_000_000, ethernet_packet(payload=b"abc")),
                   (1_250_000, ethernet_packet(reverse=True, payload=b"x")),
                   (1_500_000, ethernet_packet(payload=b"abcde"))]
        for build, extension in ((pcap, ".pcap"), (pcapng, ".pcapng")):
            path = self.root / ("udp" + extension)
            path.write_bytes(build(packets))
            report = extract_capture(path, tshark_path=REAL_TSHARK)
            self.assertEqual(report, extract_capture(path, tshark_path=REAL_TSHARK))
            self.assertEqual(report["quality"]["packets_accepted"], 3)
            self.assertEqual(report["quality"]["packets_rejected"], 0)
            self.assertEqual(len(report["flows"]), 1)
            self.assertEqual(report["source"]["format"], extension[1:])
            self.assertEqual(report["source"]["sha256"], hashlib.sha256(path.read_bytes()).hexdigest())
            self.assertEqual(report["backend"]["executable"], str(REAL_TSHARK))
            self.assertIn("TShark", report["backend"]["version"])
            self.assertEqual(report["schema_version"], "sipymes.offline.ipv4.v1")
            flow = report["flows"][0]
            self.assertEqual(flow["forward_endpoint"], {"ipv4": "10.0.0.1", "port": 40000})
            self.assertEqual(flow["reverse_endpoint"], {"ipv4": "10.0.0.2", "port": 8080})
            self.assertEqual(flow["packet_frames"], [1, 2, 3])
            self.assertEqual(flow["quality"], {
                "start_observation": "udp_session_start_not_observable",
                "end_observation": "udp_session_end_not_observable",
                "capture_completeness": "not_provable_from_pcap"})
            f = report["flows"][0]["features"]
            known = {
                "observed_duration_seconds": .5, "transport_protocol": "udp",
                "forward_packet_count": 2, "reverse_packet_count": 1,
                "forward_ipv4_byte_count": 64, "reverse_ipv4_byte_count": 29,
                "forward_ipv4_size_min_bytes": 31, "forward_ipv4_size_max_bytes": 33,
                "forward_ipv4_size_mean_bytes": 32, "forward_ipv4_size_population_std_bytes": 1,
                "reverse_ipv4_size_min_bytes": 29, "reverse_ipv4_size_max_bytes": 29,
                "reverse_ipv4_size_mean_bytes": 29, "reverse_ipv4_size_population_std_bytes": 0,
                "forward_iat_min_seconds": .5, "forward_iat_max_seconds": .5,
                "forward_iat_mean_seconds": .5, "forward_iat_population_std_seconds": 0,
            }
            expected = {name: (value, None) for name, value in known.items()}
            for stat in ("min", "max", "mean", "population_std"):
                expected[f"reverse_iat_{stat}_seconds"] = (None, "fewer_than_two_packets_in_direction")
            for direction in ("forward", "reverse"):
                for flag in ("fin", "syn", "rst", "psh", "ack", "urg", "ece", "cwr"):
                    expected[f"{direction}_tcp_{flag}_count"] = (None, "not_applicable_to_udp")
            self.assert_all_features(f, expected)

    def test_all_38_tcp_features_in_both_formats_with_manual_oracle(self):
        packets = [
            (1_000_000, ethernet_packet("tcp", flags=2)),
            (1_100_000, ethernet_packet("tcp", reverse=True, flags=18, sequence=200)),
            (1_400_000, ethernet_packet("tcp", flags=248, sequence=101, payload=b"x" * 20)),
            (1_600_000, ethernet_packet("tcp", reverse=True, flags=17, sequence=201, payload=b"x" * 10)),
            (2_000_000, ethernet_packet("tcp", flags=17, sequence=121, payload=b"x" * 40)),
            (2_600_000, ethernet_packet("tcp", reverse=True, flags=20, sequence=211, payload=b"x" * 30)),
        ]
        known = {
            "observed_duration_seconds": 1.6, "transport_protocol": "tcp",
            "forward_packet_count": 3, "reverse_packet_count": 3,
            "forward_ipv4_byte_count": 180, "reverse_ipv4_byte_count": 160,
            "forward_ipv4_size_min_bytes": 40, "forward_ipv4_size_max_bytes": 80,
            "forward_ipv4_size_mean_bytes": 60,
            "forward_ipv4_size_population_std_bytes": (800 / 3) ** .5,
            "reverse_ipv4_size_min_bytes": 40, "reverse_ipv4_size_max_bytes": 70,
            "reverse_ipv4_size_mean_bytes": 160 / 3,
            "reverse_ipv4_size_population_std_bytes": (1400 / 9) ** .5,
            "forward_iat_min_seconds": .4, "forward_iat_max_seconds": .6,
            "forward_iat_mean_seconds": .5, "forward_iat_population_std_seconds": .1,
            "reverse_iat_min_seconds": .5, "reverse_iat_max_seconds": 1.0,
            "reverse_iat_mean_seconds": .75, "reverse_iat_population_std_seconds": .25,
            "forward_tcp_fin_count": 1, "forward_tcp_syn_count": 1,
            "forward_tcp_rst_count": 0, "forward_tcp_psh_count": 1,
            "forward_tcp_ack_count": 2, "forward_tcp_urg_count": 1,
            "forward_tcp_ece_count": 1, "forward_tcp_cwr_count": 1,
            "reverse_tcp_fin_count": 1, "reverse_tcp_syn_count": 1,
            "reverse_tcp_rst_count": 1, "reverse_tcp_psh_count": 0,
            "reverse_tcp_ack_count": 3, "reverse_tcp_urg_count": 0,
            "reverse_tcp_ece_count": 0, "reverse_tcp_cwr_count": 0,
        }
        for build, extension in ((pcap, ".pcap"), (pcapng, ".pcapng")):
            with self.subTest(format=extension):
                path = self.root / ("all-tcp-flags" + extension)
                path.write_bytes(build(packets))
                report = extract_capture(path, tshark_path=REAL_TSHARK)
                self.assertEqual(report["quality"]["packets_rejected"], 0)
                self.assertEqual(report["quality"]["packets_accepted"], 6)
                self.assertEqual(len(report["flows"]), 1)
                flow = report["flows"][0]
                self.assertEqual(flow["packet_frames"], [1, 2, 3, 4, 5, 6])
                self.assertEqual(flow["close_reason"], "tcp_rst")
                self.assertEqual(flow["quality"]["start_observation"], "initial_syn_observed")
                self.assertEqual(flow["quality"]["end_observation"], "rst_observed")
                self.assert_all_features(flow["features"], {name: (value, None) for name, value in known.items()})

    def test_singleton_unknown_values_and_quality_in_both_formats(self):
        for protocol, length in (("tcp", 40), ("udp", 28)):
            known = {"observed_duration_seconds": 0, "transport_protocol": protocol,
                     "forward_packet_count": 1, "reverse_packet_count": 0,
                     "forward_ipv4_byte_count": length, "reverse_ipv4_byte_count": 0}
            expected = {name: (value, None) for name, value in known.items()}
            for stat in ("min", "max", "mean", "population_std"):
                expected[f"forward_ipv4_size_{stat}_bytes"] = (0 if stat == "population_std" else length, None)
                expected[f"reverse_ipv4_size_{stat}_bytes"] = (None, "no_packets_in_direction")
                for direction in ("forward", "reverse"):
                    expected[f"{direction}_iat_{stat}_seconds"] = (None, "fewer_than_two_packets_in_direction")
            for direction in ("forward", "reverse"):
                for flag in ("fin", "syn", "rst", "psh", "ack", "urg", "ece", "cwr"):
                    expected[f"{direction}_tcp_{flag}_count"] = (
                        (1 if direction == "forward" and flag == "ack" else 0, None)
                        if protocol == "tcp" else (None, "not_applicable_to_udp"))
            for build, extension in ((pcap, ".pcap"), (pcapng, ".pcapng")):
                with self.subTest(protocol=protocol, format=extension):
                    path = self.root / ("singleton-" + protocol + extension)
                    path.write_bytes(build([(1_000_000, ethernet_packet(protocol))]))
                    report = extract_capture(path, tshark_path=REAL_TSHARK)
                    self.assertEqual(report["quality"]["packets_rejected"], 0)
                    flow = report["flows"][0]
                    self.assertEqual(flow["close_reason"], "end_of_capture")
                    self.assertEqual(flow["quality"]["start_observation"],
                                     "midstream_or_start_unknown" if protocol == "tcp" else "udp_session_start_not_observable")
                    self.assertEqual(flow["quality"]["end_observation"],
                                     "connection_end_not_observed" if protocol == "tcp" else "udp_session_end_not_observable")
                    self.assert_all_features(flow["features"], expected)

    def test_real_absolute_path_and_automatic_discovery_with_empty_path(self):
        path = self.root / "no-path.pcap"
        path.write_bytes(pcap([(1_000_000, ethernet_packet())]))
        with patch.dict("os.environ", {"PATH": ""}):
            self.assertEqual(find_tshark(REAL_TSHARK), REAL_TSHARK)
            self.assertEqual(find_tshark(), REAL_TSHARK)
            self.assertEqual(extract_capture(path, tshark_path=REAL_TSHARK)["quality"]["packets_accepted"], 1)
            self.assertEqual(extract_capture(path)["quality"]["packets_accepted"], 1)

    def test_truncated_packet_is_reported_with_real_tshark(self):
        path = self.root / "packet-truncated.pcap"
        frame = ethernet_packet("tcp")
        content = bytearray(pcap([(1_000_000, frame)]))
        struct.pack_into("<I", content, 36, len(frame) + 20)
        path.write_bytes(content)
        report = extract_capture(path, tshark_path=REAL_TSHARK)
        self.assertEqual(report["flows"], [])
        self.assertEqual(report["quality"]["rejections_by_reason"], {"truncated_packet": 1})

    def test_tcp_partial_and_rst(self):
        path = self.root / "partial.pcap"
        path.write_bytes(pcap([(1_000_000, ethernet_packet("tcp", flags=16)),
                               (1_100_000, ethernet_packet("tcp", reverse=True, flags=4))]))
        flow = extract_capture(path, tshark_path=REAL_TSHARK)["flows"][0]
        self.assertEqual(flow["quality"]["start_observation"], "midstream_or_start_unknown")
        self.assertEqual(flow["close_reason"], "tcp_rst")

    def test_unsupported_ethernet_payload_is_reported(self):
        path = self.root / "unsupported.pcap"
        frame = bytes.fromhex("ffffffffffff02000000000188b5") + b"\0" * 46
        path.write_bytes(pcap([(1_000_000, frame)]))
        result = extract_capture(path, tshark_path=REAL_TSHARK)
        self.assertEqual(result["quality"]["packets_rejected"], 1)
        self.assertEqual(result["flows"], [])

    def test_corrupt_capture_fails_without_report(self):
        path = self.root / "corrupt.pcap"
        path.write_bytes(b"not a capture file")
        with self.assertRaises(CaptureError):
            extract_capture(path, tshark_path=REAL_TSHARK)

    def test_corrupt_tail_after_valid_packet_fails(self):
        path = self.root / "truncated-container.pcap"
        path.write_bytes(pcap([(1_000_000, ethernet_packet())]) + b"\x01\x02\x03")
        with self.assertRaises(CaptureError):
            extract_capture(path, tshark_path=REAL_TSHARK)
