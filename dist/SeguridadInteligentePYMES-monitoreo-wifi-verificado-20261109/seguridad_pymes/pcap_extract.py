"""Deterministic offline flow extraction. Does not import inference or persistence."""

import argparse
from collections import Counter
from dataclasses import dataclass, field
from decimal import Decimal
import hashlib
import heapq
import json
import math
from pathlib import Path
import sys

from seguridad_pymes.pcap_reader import CaptureError, TSharkReader
from seguridad_pymes.pcap_schema import (
    EXTRACTOR_VERSION, SCHEMA_VERSION, TCP_FLAGS, ExtractionConfig,
    feature, feature_definitions,
)


def _hash_file(path):
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _capture_format(path):
    with path.open("rb") as source:
        header = source.read(28)
    if header[:4] in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d") and len(header) >= 24:
        return "pcap"
    if header[:4] == b"\x0a\x0d\x0d\x0a" and len(header) >= 28:
        return "pcapng"
    raise CaptureError("Invalid or truncated PCAP/PCAPNG container header")


@dataclass
class _Stats:
    count: int = 0
    total: int = 0
    squares: int = 0
    minimum: int | None = None
    maximum: int | None = None

    def add(self, value):
        self.count += 1
        self.total += value
        self.squares += value * value
        self.minimum = value if self.minimum is None else min(self.minimum, value)
        self.maximum = value if self.maximum is None else max(self.maximum, value)

    def features(self, scale=1, missing="no_packets_in_direction"):
        if not self.count:
            return {name: feature(reason=missing) for name in ("min", "max", "mean", "population_std")}
        variance = (self.squares * self.count - self.total ** 2) / self.count ** 2
        return {"min": feature(self.minimum / scale if scale != 1 else self.minimum),
                "max": feature(self.maximum / scale if scale != 1 else self.maximum),
                "mean": feature(self.total / self.count / scale),
                "population_std": feature(math.sqrt(variance) / scale)}


@dataclass
class _Direction:
    sizes: _Stats = field(default_factory=_Stats)
    intervals: _Stats = field(default_factory=_Stats)
    flags: Counter = field(default_factory=Counter)
    last_ns: int | None = None

    def add(self, packet):
        self.sizes.add(packet.ipv4_bytes)
        if self.last_ns is not None:
            self.intervals.add(packet.timestamp_ns - self.last_ns)
        self.last_ns = packet.timestamp_ns
        if packet.tcp_flags is not None:
            for name, mask in TCP_FLAGS.items():
                if packet.tcp_flags & mask:
                    self.flags[name] += 1


class _Flow:
    def __init__(self, packet, ordinal):
        self.ordinal = ordinal
        self.interface = packet.interface
        self.source = (packet.src, packet.sport)
        self.destination = (packet.dst, packet.dport)
        self.protocol = packet.protocol
        self.first_ns = self.last_ns = packet.timestamp_ns
        self.frames = []
        self.directions = [_Direction(), _Direction()]
        self.initial_syn_sequence = packet.tcp_sequence if _bare_syn(packet) else None
        self.initial_syn_observed = _bare_syn(packet)

    def add(self, packet):
        direction = 0 if (packet.src, packet.sport) == self.source else 1
        self.directions[direction].add(packet)
        self.frames.append(packet.frame)
        self.last_ns = packet.timestamp_ns

    def finish(self, reason, identity):
        values = {"observed_duration_seconds": feature((self.last_ns - self.first_ns) / 1e9),
                  "transport_protocol": feature(self.protocol)}
        for name, direction in zip(("forward", "reverse"), self.directions):
            values[f"{name}_packet_count"] = feature(direction.sizes.count)
            values[f"{name}_ipv4_byte_count"] = feature(direction.sizes.total)
            for stat, value in direction.sizes.features().items():
                values[f"{name}_ipv4_size_{stat}_bytes"] = value
            for stat, value in direction.intervals.features(1e9, "fewer_than_two_packets_in_direction").items():
                values[f"{name}_iat_{stat}_seconds"] = value
            for flag in TCP_FLAGS:
                values[f"{name}_tcp_{flag}_count"] = (
                    feature(direction.flags[flag]) if self.protocol == "tcp"
                    else feature(reason="not_applicable_to_udp"))
        if self.protocol == "udp":
            start, end = "udp_session_start_not_observable", "udp_session_end_not_observable"
        else:
            start = "initial_syn_observed" if self.initial_syn_observed else "midstream_or_start_unknown"
            if any(d.flags["rst"] for d in self.directions):
                end = "rst_observed"
            elif all(d.flags["fin"] for d in self.directions):
                end = "fin_observed_in_both_directions"
            else:
                end = "connection_end_not_observed"
        token = f"{identity}:{self.ordinal}:{self.frames[0]}".encode()
        return {"flow_id": hashlib.sha256(token).hexdigest(), "ordinal": self.ordinal,
                "interface_id": self.interface,
                "forward_endpoint": {"ipv4": self.source[0], "port": self.source[1]},
                "reverse_endpoint": {"ipv4": self.destination[0], "port": self.destination[1]},
                "first_timestamp_epoch_ns": str(self.first_ns),
                "last_timestamp_epoch_ns": str(self.last_ns), "packet_frames": self.frames,
                "close_reason": reason,
                "quality": {"start_observation": start, "end_observation": end,
                            "capture_completeness": "not_provable_from_pcap"},
                "features": values}


def _bare_syn(packet):
    return packet.protocol == "tcp" and bool(packet.tcp_flags & 2) and not bool(packet.tcp_flags & 16)


def _key(packet):
    endpoints = tuple(sorted(((packet.src, packet.sport), (packet.dst, packet.dport))))
    return packet.interface, packet.protocol, endpoints


def _aggregate(observations, config, identity):
    active, deadlines, completed = {}, [], []
    rejected, examples = Counter(), []
    seen = accepted = ordinal = 0
    previous_frame, previous_time = 0, None
    first_time = None

    def expire_flow(key, reason):
        completed.append(active.pop(key).finish(reason, identity))

    def deadline(flow):
        idle = config.tcp_idle_seconds if flow.protocol == "tcp" else config.udp_idle_seconds
        idle_ns = flow.last_ns + int(Decimal(str(idle)) * 1_000_000_000)
        active_ns = flow.first_ns + int(Decimal(str(config.active_timeout_seconds)) * 1_000_000_000)
        return min(idle_ns, active_ns), "active_timeout" if active_ns <= idle_ns else "idle_timeout"

    for observation in observations:
        seen += 1
        if first_time is None:
            first_time = observation.timestamp_ns
        if seen > config.max_packets:
            raise CaptureError("Packet limit exceeded; extraction is incomplete")
        if observation.frame <= previous_frame or (previous_time is not None and observation.timestamp_ns < previous_time):
            raise CaptureError("Frames/timestamps must be ordered; capture is not silently reordered")
        previous_frame, previous_time = observation.frame, observation.timestamp_ns
        while deadlines and deadlines[0][0] <= observation.timestamp_ns:
            due, number, last_frame, key = heapq.heappop(deadlines)
            flow = active.get(key)
            if flow is not None and flow.ordinal == number and flow.frames[-1] == last_frame:
                expire_flow(key, deadline(flow)[1])
        packet = observation.packet
        if packet is None:
            rejected[observation.rejection_reason] += 1
            if len(examples) < 20:
                examples.append({"frame": observation.frame, "reason": observation.rejection_reason})
            continue
        if packet.src == packet.dst and packet.sport == packet.dport:
            rejected["indistinguishable_flow_endpoints"] += 1
            if len(examples) < 20:
                examples.append({"frame": observation.frame, "reason": "indistinguishable_flow_endpoints"})
            continue
        key = _key(packet)
        flow = active.get(key)
        if flow is not None and _bare_syn(packet):
            if (packet.src, packet.sport) != flow.source or packet.tcp_sequence != flow.initial_syn_sequence or all(d.flags["fin"] for d in flow.directions):
                expire_flow(key, "new_tcp_syn")
                flow = None
        if flow is None:
            if len(active) >= config.max_active_flows or ordinal >= config.max_flows:
                raise CaptureError("Flow limit exceeded; extraction is incomplete")
            ordinal += 1
            flow = active[key] = _Flow(packet, ordinal)
        flow.add(packet)
        accepted += 1
        if packet.protocol == "tcp" and packet.tcp_flags & 4:
            expire_flow(key, "tcp_rst")
        else:
            heapq.heappush(deadlines, (deadline(flow)[0], flow.ordinal, packet.frame, key))
        if len(deadlines) > max(1024, 4 * len(active)):
            deadlines = [(deadline(f)[0], f.ordinal, f.frames[-1], k) for k, f in active.items()]
            heapq.heapify(deadlines)
    for key in list(active):
        expire_flow(key, "end_of_capture")
    completed.sort(key=lambda flow: flow["ordinal"])
    if rejected:
        for flow in completed:
            flow["quality"]["capture_has_rejected_packets"] = True
    return completed, {"packets_seen": seen, "packets_accepted": accepted,
                       "packets_rejected": sum(rejected.values()),
                       "rejections_by_reason": dict(sorted(rejected.items())),
                       "rejection_examples_first_20": examples,
                       "flows_produced": len(completed),
                       "first_timestamp_epoch_ns": None if not seen else str(first_time),
                       "last_timestamp_epoch_ns": None if not seen else str(previous_time),
                       "capture_loss": "unknown; file contents cannot prove absence of capture loss"}


def extract_capture(capture_path, *, config=None, tshark_path=None):
    """Return a completed extraction report or raise; never run a classifier."""
    config = config or ExtractionConfig()
    capture = Path(capture_path).expanduser().resolve()
    if not capture.is_file():
        raise CaptureError(f"Capture file not found: {capture}")
    capture_format = _capture_format(capture)
    source_hash = _hash_file(capture)
    configuration = config.to_dict()
    config_hash = hashlib.sha256(json.dumps(configuration, sort_keys=True).encode()).hexdigest()
    identity = f"{SCHEMA_VERSION}:{EXTRACTOR_VERSION}:{source_hash}:{config_hash}"
    reader = TSharkReader(tshark_path, config.tshark_timeout_seconds)
    observations = reader.observations(capture)
    try:
        flows, quality = _aggregate(observations, config, identity)
    finally:
        observations.close()
    if _hash_file(capture) != source_hash:
        raise CaptureError("Capture changed during extraction; report discarded")
    return {"schema_version": SCHEMA_VERSION, "extractor_version": EXTRACTOR_VERSION,
            "source": {"path": str(capture), "format": capture_format,
                       "sha256": source_hash, "size_bytes": capture.stat().st_size},
            "backend": {"name": "tshark", "executable": str(reader.executable),
                        "version": reader.version, "diagnostics_first_4000_bytes": reader.diagnostics,
                        "profile": "isolated_empty_configuration",
                        "name_resolution": False, "ip_reassembly": False, "tcp_reassembly": False},
            "configuration": configuration, "configuration_sha256": config_hash,
            "orientation": "source of first accepted packet is forward; no client/server inference",
            "feature_definitions": feature_definitions(), "quality": quality, "flows": flows}


def main(argv=None):
    parser = argparse.ArgumentParser(description="Extract offline IPv4 TCP/UDP flows; no attack classification.")
    parser.add_argument("capture", type=Path)
    parser.add_argument("--output", type=Path, required=True, help="New JSON file; existing files are never overwritten")
    parser.add_argument("--tshark", type=Path)
    parser.add_argument("--tcp-idle-seconds", type=float, default=120.0)
    parser.add_argument("--udp-idle-seconds", type=float, default=30.0)
    parser.add_argument("--active-timeout-seconds", type=float, default=300.0)
    parser.add_argument("--tshark-timeout-seconds", type=float, default=120.0)
    parser.add_argument("--max-packets", type=int, default=1_000_000)
    parser.add_argument("--max-active-flows", type=int, default=50_000)
    parser.add_argument("--max-flows", type=int, default=100_000)
    args = parser.parse_args(argv)
    try:
        if args.output.exists():
            raise CaptureError("Output already exists; choose a new path")
        config = ExtractionConfig(**{name: getattr(args, name) for name in ExtractionConfig.__dataclass_fields__})
        report = extract_capture(args.capture, config=config, tshark_path=args.tshark)
        encoded = (json.dumps(report, indent=2, ensure_ascii=False, allow_nan=False) + "\n").encode("utf-8")
        with args.output.open("xb") as output:
            output.write(encoded)
    except (CaptureError, ValueError, OSError) as error:
        print(f"Extraction failed: {error}", file=sys.stderr)
        return 2
    print(f"Extracted {len(report['flows'])} flows to {args.output}; no classification performed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
