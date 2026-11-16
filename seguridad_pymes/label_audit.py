"""Conservative tuple/time/counter audit. No classifier, nearest match or imputation."""

import argparse
from collections import Counter, defaultdict
import hashlib
import ipaddress
import json
from pathlib import Path
import struct

from seguridad_pymes.zeek_labels import import_zeek_labels, reference_key


AUDIT_VERSION = "sipymes.label-audit.v1"
PACKET_AUDIT_VERSION = "sipymes.label-audit.v2"
STATUSES = ("matched_unique", "ambiguous", "not_found", "segmentation_mismatch",
            "incomplete_reference", "contradictory", "counter_mismatch")


def _percentage(numerator, denominator):
    return None if denominator == 0 else 100 * numerator / denominator


def _support(record):
    """A singleton's point support follows from counts; its duration remains unknown."""
    if record["start_epoch_ns"] is None:
        return None, "unknown_start"
    start = int(record["start_epoch_ns"])
    if record["duration_ns"] is not None:
        return (start, start + int(record["duration_ns"])), "reported_duration"
    if (record["orig_pkts"] is not None and record["resp_pkts"] is not None
            and record["orig_pkts"] + record["resp_pkts"] == 1):
        return (start, start), "single_packet_proven_by_counts"
    return None, "unknown_end"


def _reference_state(record):
    key = reference_key(record)
    if key is None or record["start_epoch_ns"] is None:
        return "incomplete_key"
    if key[0] not in {"tcp", "udp"} or any(ipaddress.ip_address(e[0]).version != 4 for e in key[1]):
        return "unsupported"
    if record["contradictions"]:
        return "contradictory"
    if _support(record)[0] is None:
        return "unknown_interval"
    if record["binary_label"] is None:
        return "unknown_label"
    return "usable"


def _flow_data(flow):
    values = flow["features"]
    first, last = int(flow["first_timestamp_epoch_ns"]), int(flow["last_timestamp_epoch_ns"])
    if first < 0 or last < first:
        raise ValueError("Invalid extracted flow timestamps")
    endpoints = []
    for direction in ("forward", "reverse"):
        endpoint = flow[f"{direction}_endpoint"]
        address = str(ipaddress.IPv4Address(endpoint["ipv4"]))
        port = endpoint["port"]
        if type(port) is not int or not 0 <= port <= 65535:
            raise ValueError("Invalid extracted endpoint")
        endpoints.append((address, port))
    protocol = values["transport_protocol"]["value"]
    if protocol not in {"tcp", "udp"}:
        raise ValueError("Unsupported extracted protocol")
    counters = []
    for direction in ("forward", "reverse"):
        pair = []
        for name in ("packet_count", "ipv4_byte_count"):
            measurement = values[f"{direction}_{name}"]
            value = measurement["value"]
            if measurement["status"] != "ok" or type(value) is not int or value < 0:
                raise ValueError("Audit requires observed nonnegative integer counters")
            pair.append(value)
        counters.append(pair)
    if sum(p[0] for p in counters) == 0:
        raise ValueError("An extracted flow must contain packets")
    return (protocol, tuple(sorted(endpoints))), first, last, endpoints, counters


def _mapped_counters(record, endpoints, counters):
    same_direction = endpoints[0] == (record["orig_ip"], record["orig_port"])
    orig, resp = counters if same_direction else counters[::-1]
    return {"orig_pkts": orig[0], "resp_pkts": resp[0],
            "orig_ip_bytes": orig[1], "resp_ip_bytes": resp[1]}


def audit_correspondences(extraction, imported):
    if extraction.get("schema_version") != "sipymes.offline.ipv4.v1" or extraction.get("extractor_version") != "1.0.1":
        raise ValueError("This audit contract requires extractor 1.0.1 / IPv4 schema v1")
    references = imported["records"]
    by_key, by_id = defaultdict(list), {}
    reference_states = {}
    for record in references:
        identifier = record["reference_id"]
        if identifier in by_id:
            raise ValueError("Reference IDs must be unique")
        by_id[identifier] = record
        reference_states[identifier] = _reference_state(record)
        key = reference_key(record)
        if key is not None:
            by_key[key].append(record)
    results, mapped = [], {}
    seen_ids = set()
    for flow in extraction["flows"]:
        identifier = flow["flow_id"]
        if identifier in seen_ids:
            raise ValueError("Flow IDs must be unique")
        seen_ids.add(identifier)
        key, first, last, endpoints, counters = _flow_data(flow)
        same_tuple = by_key.get(key, [])
        overlap, covering, unknown = [], [], []
        for record in same_tuple:
            support, kind = _support(record)
            if support is None:
                if record["start_epoch_ns"] is None or int(record["start_epoch_ns"]) <= last:
                    unknown.append(record)
            elif support[0] <= last and support[1] >= first:
                overlap.append(record)
                if support[0] <= first and last <= support[1]:
                    covering.append(record)
        candidates = overlap + unknown
        status, reason = "not_found", "no_reference_with_temporal_support"
        binary_label = reference_id = None
        checks = []
        if any(r["contradictions"] for r in candidates):
            status, reason = "contradictory", "contradictory_reference_record"
        elif len({r["binary_label"] for r in overlap if r["binary_label"] is not None}) > 1:
            status, reason = "contradictory", "overlapping_references_disagree_on_label"
        elif unknown:
            status, reason = "incomplete_reference", "unknown_reference_end_cannot_be_excluded"
        elif len(overlap) > 1:
            status = "ambiguous" if len(covering) > 1 else "segmentation_mismatch"
            reason = "multiple_covering_references" if len(covering) > 1 else "multiple_references_overlap_one_extracted_flow"
        elif overlap and not covering:
            status, reason = "segmentation_mismatch", "reference_covers_only_part_of_extracted_flow"
        elif len(covering) == 1:
            record = covering[0]
            reference_id = record["reference_id"]
            if record["binary_label"] is None:
                status, reason = "incomplete_reference", "unrecognized_or_missing_label"
            else:
                counts = _mapped_counters(record, endpoints, counters)
                for name, value in counts.items():
                    if record[name] is not None and value > record[name]:
                        checks.append({"field": name, "flow_count": value, "reference_count": record[name]})
                if checks:
                    status, reason = "counter_mismatch", "extracted_counters_exceed_reference"
                else:
                    status, reason = "matched_unique", "unique_full_temporal_support_and_compatible_counters"
                    binary_label = record["binary_label"]
                    mapped[identifier] = counts
        results.append({"flow_id": identifier, "status": status, "reason": reason,
                        "binary_label": binary_label, "reference_id": reference_id,
                        "reference_uid": by_id[reference_id]["uid"] if reference_id else None,
                        "reference_label_original": by_id[reference_id]["label_original"] if reference_id else None,
                        "detailed_label": by_id[reference_id]["detailed_label"] if reference_id else None,
                        "same_tuple_reference_count": len(same_tuple),
                        "candidate_reference_ids": [r["reference_id"] for r in candidates],
                        "counter_conflicts": checks,
                        "flow_packet_count": sum(p[0] for p in counters),
                        "support_kind": _support(by_id[reference_id])[1] if reference_id else None})

    # Several individually plausible children must not reuse more packets/bytes than their parent.
    assigned = defaultdict(list)
    for result in results:
        if result["status"] == "matched_unique":
            assigned[result["reference_id"]].append(result)
    for reference_id, children in assigned.items():
        record = by_id[reference_id]
        totals = {name: sum(mapped[c["flow_id"]][name] for c in children) for name in ("orig_pkts", "resp_pkts", "orig_ip_bytes", "resp_ip_bytes")}
        conflicts = [{"field": name, "children_count": value, "reference_count": record[name]}
                     for name, value in totals.items() if record[name] is not None and value > record[name]]
        if conflicts:
            for result in children:
                result.update(status="counter_mismatch", reason="combined_children_exceed_reference",
                              binary_label=None, counter_conflicts=conflicts)

    matched_refs, touched_refs = defaultdict(list), defaultdict(list)
    for result in results:
        for ref_id in result["candidate_reference_ids"]:
            touched_refs[ref_id].append(result["flow_id"])
        if result["status"] == "matched_unique":
            matched_refs[result["reference_id"]].append(result["flow_id"])
    status_counts = {status: 0 for status in STATUSES}
    status_counts.update(Counter(r["status"] for r in results))
    eligible_ids = {ref_id for ref_id, state in reference_states.items() if state == "usable"}
    eligible_packets = sum(r["orig_pkts"] + r["resp_pkts"] for r in references
                           if r["reference_id"] in eligible_ids and r["orig_pkts"] is not None and r["resp_pkts"] is not None)
    class_coverage = {}
    for label, name in ((0, "Benign"), (1, "Malicious")):
        ids = {r["reference_id"] for r in references if r["reference_id"] in eligible_ids and r["binary_label"] == label}
        class_coverage[name] = {"eligible_references": len(ids), "matched_references": len(ids.intersection(matched_refs)),
                                "reference_coverage_percent": _percentage(len(ids.intersection(matched_refs)), len(ids)),
                                "matched_extractor_flows": sum(r["status"] == "matched_unique" and r["binary_label"] == label for r in results)}
    matched_packets = sum(r["flow_packet_count"] for r in results if r["status"] == "matched_unique")
    quality = extraction["quality"]
    if sum(r["flow_packet_count"] for r in results) != quality["packets_accepted"]:
        raise ValueError("Extracted flow counters do not conserve accepted packet count")
    return {"audit_version": AUDIT_VERSION,
            "extraction_source": extraction["source"], "label_source": imported["source"],
            "policy": {"temporal_tolerance_ns": 0, "intervals": "closed, exact integer nanoseconds",
                       "tuple": "same capture pair, protocol and unordered IPv4/port endpoints",
                       "direction": "source counters swapped when extraction orientation is reversed",
                       "unknown_duration": "point support only if reference counters prove exactly one packet; original duration remains null",
                       "assignment": "only a sole covering reference with no competing overlap, known label and compatible counters",
                       "unknown": "never converted to Benign; no nearest-neighbour or host/capture-name labels"},
            "summary": {"packets_seen": quality["packets_seen"], "packets_accepted": quality["packets_accepted"],
                        "packets_rejected": quality["packets_rejected"],
                        "packet_extraction_coverage_percent": _percentage(quality["packets_accepted"], quality["packets_seen"]),
                        "extracted_flows": len(results), "reference_connections": len(references),
                        "rejected_reference_rows": len(imported["rejected_rows"]),
                        "reference_states": dict(Counter(reference_states.values())),
                        "flow_status_counts": status_counts,
                        "flow_label_coverage_percent": _percentage(status_counts["matched_unique"], len(results)),
                        "matched_reference_connections": len(matched_refs), "eligible_reference_connections": len(eligible_ids),
                        "eligible_reference_packet_count_where_known": eligible_packets,
                        "reference_coverage_percent": _percentage(len(matched_refs), len(eligible_ids)),
                        "labeled_packets_in_extracted_flows": matched_packets,
                        "label_coverage_of_accepted_packets_percent": _percentage(matched_packets, quality["packets_accepted"]),
                        "label_coverage_of_all_packets_percent": _percentage(matched_packets, quality["packets_seen"]),
                        "references_split_across_matched_flows": sum(len(ids) > 1 for ids in matched_refs.values()),
                        "flows_with_multiple_candidate_references": sum(len(r["candidate_reference_ids"]) > 1 for r in results),
                        "class_coverage": class_coverage},
            "flow_correspondences": results,
            "reference_correspondences": [{"reference_id": r["reference_id"], "uid": r["uid"],
                "source_line": r["source_line"], "state": reference_states[r["reference_id"]],
                "binary_label": r["binary_label"], "candidate_flow_ids": touched_refs[r["reference_id"]],
                "matched_flow_ids": matched_refs[r["reference_id"]],
                "support_kind": _support(r)[1], "contradictions": r["contradictions"]} for r in references]}


def _checksum(data):
    """Internet checksum over bytes, including the stored checksum if present."""
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 65535) + (total >> 16)
    return (~total) & 65535


def _decode_evidence_frame(frame, timestamp_ns, data, wire_length):
    item = {"frame": frame, "timestamp_epoch_ns": str(timestamp_ns),
            "captured_bytes": len(data), "wire_bytes": wire_length,
            "packet_sha256": hashlib.sha256(data).hexdigest(),
            "auditable": False, "reason": "unsupported_or_incomplete_packet"}
    if len(data) < wire_length or len(data) < 14 or wire_length != len(data):
        return item
    item["ethernet_type"] = int.from_bytes(data[12:14], "big")
    if item["ethernet_type"] != 0x0800:
        item["reason"] = "outside_ethernet_ipv4_scope"
        return item
    ip = data[14:]
    if len(ip) < 20 or ip[0] >> 4 != 4:
        return item
    header = (ip[0] & 15) * 4
    length = int.from_bytes(ip[2:4], "big")
    if not 20 <= header <= 60 or not header <= length <= len(ip):
        return item
    if int.from_bytes(ip[6:8], "big") & 0x3fff:
        item["reason"] = "fragment_not_supported"
        return item
    protocol = ip[9]
    if protocol not in (6, 17):
        return item
    transport = ip[header:length]
    if len(transport) < (20 if protocol == 6 else 8):
        return item
    sport, dport = struct.unpack_from("!HH", transport)
    item.update(protocol="tcp" if protocol == 6 else "udp",
                src=str(ipaddress.IPv4Address(ip[12:16])), sport=sport,
                dst=str(ipaddress.IPv4Address(ip[16:20])), dport=dport,
                ipv4_bytes=length, ipv4_header_bytes=header,
                ip_checksum_status="valid" if _checksum(ip[:header]) == 0 else "incorrect")
    pseudo = ip[12:20] + bytes((0, protocol)) + len(transport).to_bytes(2, "big")
    checksum_offset = 16 if protocol == 6 else 6
    stored = int.from_bytes(transport[checksum_offset:checksum_offset + 2], "big")
    seed = (~_checksum(pseudo)) & 65535
    if protocol == 17 and stored == 0:
        status = "not_present_ipv4_udp"
    elif _checksum(pseudo + transport) == 0:
        status = "valid"
    elif stored == seed:
        status = "partial_pseudoheader"
    else:
        status = "incorrect"
    item.update(transport_checksum_status=status, stored_transport_checksum=stored,
                pseudoheader_sum=seed)
    if protocol == 6:
        tcp_header = (transport[12] >> 4) * 4
        if not 20 <= tcp_header <= 60 or tcp_header > len(transport):
            return item
        item.update(tcp_sequence=int.from_bytes(transport[4:8], "big"),
                    tcp_acknowledgment=int.from_bytes(transport[8:12], "big"),
                    tcp_flags=((transport[12] & 1) << 8) | transport[13],
                    transport_header_bytes=tcp_header,
                    payload_bytes=len(transport) - tcp_header)
    else:
        if int.from_bytes(transport[4:6], "big") != len(transport):
            return item
        item.update(transport_header_bytes=8, payload_bytes=len(transport) - 8)
    item.update(auditable=True, reason=None)
    return item


def read_packet_evidence(capture_path, *, max_bytes=128 * 1024 * 1024, max_frames=1_000_000):
    """Bounded, read-only classic Ethernet PCAP reader for audit v2.

    PCAPNG remains supported by the unchanged extractor; audit v2 explicitly
    requires classic PCAP until interface-aware raw evidence is implemented.
    Partial checksums are a mathematical observation, not proof of NIC offload.
    """
    path = Path(capture_path).resolve()
    if path.stat().st_size > max_bytes:
        raise ValueError("Packet evidence exceeds the configured byte limit")
    with path.open("rb") as source:
        content = source.read(max_bytes + 1)
    if len(content) > max_bytes or len(content) < 24:
        raise ValueError("Invalid or oversized PCAP evidence")
    formats = {b"\xd4\xc3\xb2\xa1": ("<", 1000), b"\xa1\xb2\xc3\xd4": (">", 1000),
               b"\x4d\x3c\xb2\xa1": ("<", 1), b"\xa1\xb2\x3c\x4d": (">", 1)}
    if content[:4] not in formats:
        raise ValueError("Audit v2 requires classic Ethernet PCAP, not PCAPNG")
    endian, scale = formats[content[:4]]
    major, minor, _, _, snaplen, network = struct.unpack_from(endian + "HHIIII", content, 4)
    if (major, minor) != (2, 4) or network != 1 or snaplen == 0:
        raise ValueError("Unsupported PCAP version or link layer")
    packets, offset, previous = [], 24, None
    while offset < len(content):
        if len(packets) >= max_frames or offset + 16 > len(content):
            raise ValueError("PCAP frame limit exceeded or truncated record header")
        seconds, fraction, captured, wire = struct.unpack_from(endian + "IIII", content, offset)
        offset += 16
        timestamp = seconds * 1_000_000_000 + fraction * scale
        if (fraction * scale >= 1_000_000_000 or captured > snaplen
                or offset + captured > len(content) or previous is not None and timestamp < previous):
            raise ValueError("Invalid, truncated or unordered PCAP record")
        packets.append(_decode_evidence_frame(len(packets) + 1, timestamp,
                                              content[offset:offset + captured], wire))
        offset += captured
        previous = timestamp
    return {"evidence_version": "sipymes.packet-evidence.v1", "source": {
                "path": str(path), "sha256": hashlib.sha256(content).hexdigest(),
                "size_bytes": len(content), "format": "pcap"},
            "reader": "independent classic PCAP bytes; Internet checksum and exact pseudoheader seed",
            "limits": {"max_bytes": max_bytes, "max_frames": max_frames}, "packets": packets}


def _packet_key(packet):
    return packet["protocol"], tuple(sorted(((packet["src"], packet["sport"]),
                                               (packet["dst"], packet["dport"]))))


def _packet_counts(packets, record):
    counts = {name: 0 for name in ("orig_pkts", "resp_pkts", "orig_ip_bytes", "resp_ip_bytes")}
    for packet in packets:
        direction = "orig" if (packet["src"], packet["sport"]) == (record["orig_ip"], record["orig_port"]) else "resp"
        counts[direction + "_pkts"] += 1
        counts[direction + "_ip_bytes"] += packet["ipv4_bytes"]
    return counts


def _validate_packet_binding(extraction, evidence):
    if evidence is None or evidence.get("evidence_version") != "sipymes.packet-evidence.v1":
        raise ValueError("Audit v2 requires original packet evidence")
    if evidence["source"]["sha256"] != extraction["source"]["sha256"]:
        raise ValueError("Packet evidence hash does not match extraction")
    packets = {p["frame"]: p for p in evidence["packets"]}
    if len(packets) != len(evidence["packets"]) or set(packets) != set(range(1, len(packets) + 1)):
        raise ValueError("Evidence frame numbers must be consecutive and unique")
    if len(packets) != extraction["quality"]["packets_seen"]:
        raise ValueError("Packet evidence does not conserve capture frame count")
    owners = {}
    for flow in extraction["flows"]:
        key, first, last, endpoints, counters = _flow_data(flow)
        frames = flow.get("packet_frames", [])
        if not frames or frames != sorted(set(frames)):
            raise ValueError("A flow requires ordered unique packet frames")
        observed = [[0, 0], [0, 0]]
        for frame in frames:
            if frame not in packets or frame in owners:
                raise ValueError("Missing frame or packet reused by several flows")
            packet = packets[frame]
            if not packet["auditable"] or _packet_key(packet) != key:
                raise ValueError("Packet endpoints/protocol do not match the extracted flow")
            direction = 0 if (packet["src"], packet["sport"]) == endpoints[0] else 1
            observed[direction][0] += 1
            observed[direction][1] += packet["ipv4_bytes"]
            owners[frame] = flow["flow_id"]
        if (observed != counters or int(packets[frames[0]]["timestamp_epoch_ns"]) != first
                or int(packets[frames[-1]]["timestamp_epoch_ns"]) != last):
            raise ValueError("Packet evidence disagrees with extracted counters or timestamps")
    if len(owners) != extraction["quality"]["packets_accepted"]:
        raise ValueError("Packet ownership does not conserve accepted packets")
    return packets, owners


def _verified_transport(packet):
    return (packet["ip_checksum_status"] == "valid"
            and packet["transport_checksum_status"] in {"valid", "not_present_ipv4_udp"})


def _closure_reference(packet, preceding, records):
    """Exact FIN, FIN+ACK, ACK sequence; no elapsed-time threshold or nearest match."""
    if (packet["protocol"] != "tcp" or packet["tcp_flags"] != 0x10
            or packet["payload_bytes"] != 0 or not _verified_transport(packet) or len(preceding) < 2):
        return []
    first, second = preceding[-2:]
    if any(p.get("tcp_flags") != 0x11 or p["payload_bytes"] != 0 or not _verified_transport(p)
           for p in (first, second)):
        return []
    first_origin = (first["src"], first["sport"])
    if ((second["src"], second["sport"]) == first_origin
            or (packet["src"], packet["sport"]) != first_origin):
        return []
    increment = lambda value: (value + 1) % (1 << 32)
    if (second["tcp_sequence"] != first["tcp_acknowledgment"]
            or second["tcp_acknowledgment"] != increment(first["tcp_sequence"])
            or packet["tcp_sequence"] != increment(first["tcp_sequence"])
            or packet["tcp_acknowledgment"] != increment(second["tcp_sequence"])):
        return []
    found = []
    for record in records:
        support, _ = _support(record)
        history = record["raw_fields"].get("history", "")
        if (support is not None and support[0] <= int(first["timestamp_epoch_ns"]) <= support[1]
                and int(second["timestamp_epoch_ns"]) == support[1]
                and support[1] < int(packet["timestamp_epoch_ns"])
                and record["raw_fields"].get("conn_state") == "SF"
                and "F" in history and "f" in history):
            found.append(record)
    return found


def _partial_omission_supported(record, packets):
    """Require source evidence as well as exact counter conservation, checked later."""
    history = record["raw_fields"].get("history", "")
    for packet in packets:
        origin = (packet["src"], packet["sport"]) == (record["orig_ip"], record["orig_port"])
        if ("C" if origin else "c") not in history:
            return False
    try:
        missed = int(record["raw_fields"]["missed_bytes"])
    except (KeyError, ValueError, TypeError):
        return False
    return missed == sum(p["payload_bytes"] for p in packets)


def audit_packet_correspondences(extraction, imported, evidence):
    """Versioned packet reconciliation, independent of every model and feature formula.

    A flow with a partial/incorrect checksum never receives a label. Its healthy
    siblings need full reference conservation and documented omission evidence.
    Reference labels and extracted features are never mutated.
    """
    baseline = audit_correspondences(extraction, imported)
    packets, owners = _validate_packet_binding(extraction, evidence)
    references = {r["reference_id"]: r for r in imported["records"]}
    flows = {f["flow_id"]: f for f in extraction["flows"]}
    by_key = defaultdict(list)
    for record in references.values():
        key = reference_key(record)
        if key is not None:
            by_key[key].append(record)
    previous = defaultdict(list)
    accounting, partials, poisoned = defaultdict(list), defaultdict(list), set()
    ledger = []
    for frame, packet in sorted(packets.items()):
        entry = {**packet, "extraction_flow_id": owners.get(frame), "candidate_reference_ids": [],
                 "accounting_reference_id": None, "support_rule": None,
                 "packet_state": "outside_extraction"}
        if frame not in owners:
            ledger.append(entry)
            continue
        key = _packet_key(packet)
        moment = int(packet["timestamp_epoch_ns"])
        candidates = []
        for record in by_key[key]:
            support, _ = _support(record)
            if (support is not None and support[0] <= moment <= support[1]
                    or support is None and (record["start_epoch_ns"] is None
                                            or int(record["start_epoch_ns"]) <= moment)):
                candidates.append(record)
        rule = "exact_declared_interval"
        if not candidates:
            candidates = _closure_reference(packet, previous[key], by_key[key])
            rule = "exact_fin_finack_ack_chain" if candidates else None
        entry["candidate_reference_ids"] = [r["reference_id"] for r in candidates]
        entry["support_rule"] = rule
        bad_checksum = (packet["ip_checksum_status"] != "valid"
                        or packet["transport_checksum_status"] == "incorrect")
        if bad_checksum:
            poisoned.update(entry["candidate_reference_ids"])
        if any(r["contradictions"] for r in candidates):
            entry["packet_state"] = "contradictory"
        elif len(candidates) > 1:
            entry["packet_state"] = "ambiguous"
        elif not candidates:
            entry["packet_state"] = "not_found"
        elif _reference_state(candidates[0]) != "usable":
            entry["packet_state"] = "incomplete_reference"
        elif bad_checksum:
            entry["packet_state"] = "incorrect_checksum"
        elif packet["transport_checksum_status"] == "partial_pseudoheader":
            entry["packet_state"] = "partial_checksum"
            partials[candidates[0]["reference_id"]].append(packet)
        else:
            entry["packet_state"] = "supported"
            entry["accounting_reference_id"] = candidates[0]["reference_id"]
            accounting[candidates[0]["reference_id"]].append(packet)
        # No unchecked packet can be hidden behind a failed interval match.
        if bad_checksum:
            entry["checksum_exclusion_reason"] = "incorrect_checksum_or_ipv4_header_checksum"
        elif packet["transport_checksum_status"] == "partial_pseudoheader":
            entry["checksum_exclusion_reason"] = "partial_pattern_is_observed_but_flow_label_is_quarantined"
        previous[key].append(packet)
        ledger.append(entry)

    validations = {}
    for rid, record in references.items():
        observed = _packet_counts(accounting[rid], record)
        expected = {name: record[name] for name in observed}
        conflicts = [{"field": name, "observed": observed[name], "expected": value}
                     for name, value in expected.items() if value is not None and observed[name] != value]
        state = _reference_state(record)
        if state == "usable":
            if rid in poisoned:
                state = "incorrect_checksum_evidence"
            elif any(value is None for value in expected.values()):
                state = "incomplete_counters"
            elif partials[rid] and not _partial_omission_supported(record, partials[rid]):
                state = "partial_omission_not_demonstrated"
            elif conflicts:
                state = "counter_mismatch"
            else:
                support, _ = _support(record)
                times = [int(p["timestamp_epoch_ns"]) for p in accounting[rid]]
                state = ("verified" if times and min(times) == support[0] and support[1] in times
                         else "interval_boundaries_not_witnessed")
        validations[rid] = {"reference_id": rid, "uid": record["uid"], "source_line": record["source_line"],
                            "state": state, "expected_counts": expected, "observed_counts": observed,
                            "counter_conflicts": conflicts,
                            "accounted_packet_frames": [p["frame"] for p in accounting[rid]],
                            "partial_checksum_frames": [p["frame"] for p in partials[rid]],
                            "contradictions": record["contradictions"]}

    entries_by_flow = defaultdict(list)
    for entry in ledger:
        if entry["extraction_flow_id"] is not None:
            entries_by_flow[entry["extraction_flow_id"]].append(entry)
    baseline_by_id = {f["flow_id"]: f for f in baseline["flow_correspondences"]}
    results = []
    for fid, flow in flows.items():
        entries = entries_by_flow[fid]
        candidates = sorted({rid for entry in entries for rid in entry["candidate_reference_ids"]})
        mapped_ids = sorted({entry["accounting_reference_id"] for entry in entries
                             if entry["accounting_reference_id"] is not None})
        states = {entry["packet_state"] for entry in entries}
        labels = {(references[rid]["label_original"], references[rid]["detailed_label"])
                  for rid in candidates if references[rid]["binary_label"] is not None}
        status, reason = "not_found", "no_packet_reference"
        if "contradictory" in states or len(labels) > 1:
            status, reason = "contradictory", "contradictory_records_or_incompatible_reference_labels"
        elif "ambiguous" in states:
            status, reason = "ambiguous", "a_packet_has_multiple_candidate_references"
        elif any("checksum_exclusion_reason" in entry and
                 entry["checksum_exclusion_reason"].startswith("incorrect") for entry in entries):
            status, reason = "quarantined_incorrect_checksum", "flow_contains_incorrect_checksum"
        elif any(entry["transport_checksum_status"] == "partial_pseudoheader" for entry in entries):
            status, reason = "quarantined_partial_checksum", "flow_contains_partial_checksum_pattern"
        elif "incomplete_reference" in states:
            status, reason = "incomplete_reference", "packet_reference_has_unknown_or_incomplete_evidence"
        elif "not_found" in states:
            status = "segmentation_mismatch" if mapped_ids else "not_found"
            reason = "some_packets_have_no_verified_reference" if mapped_ids else "no_packet_reference"
        elif any(validations[rid]["state"] != "verified" for rid in mapped_ids):
            status, reason = "counter_mismatch", "full_reference_conservation_or_source_evidence_failed"
        elif len(mapped_ids) > 1:
            frames = set(flow["packet_frames"])
            if all(set(validations[rid]["accounted_packet_frames"]) <= frames for rid in mapped_ids):
                status, reason = "admitted_partition", "complete_exclusive_packet_partition_with_compatible_labels"
            else:
                status, reason = "segmentation_mismatch", "multi_reference_partition_is_not_complete_in_this_flow"
        elif mapped_ids:
            if any(entry["support_rule"] == "exact_fin_finack_ack_chain" for entry in entries):
                status, reason = "admitted_tcp_closure", "final_ack_verified_by_fin_chain_and_full_reference_counters"
            elif len({owners[p["frame"]] for p in accounting[mapped_ids[0]]}) > 1:
                status, reason = "admitted_sibling_segment", "unique_packet_mapping_and_full_parent_conservation"
            else:
                status, reason = "admitted_unique", "unique_packet_mapping_and_exact_reference_conservation"
        admitted = status.startswith("admitted_")
        admitted_ids = mapped_ids if admitted else []
        results.append({"flow_id": fid, "status": status, "reason": reason,
                        "binary_label": references[admitted_ids[0]]["binary_label"] if admitted else None,
                        "reference_ids": candidates, "admitted_reference_ids": admitted_ids,
                        "references": [{"reference_id": rid, "uid": references[rid]["uid"],
                            "source_line": references[rid]["source_line"],
                            "label_original": references[rid]["label_original"],
                            "detailed_label": references[rid]["detailed_label"]} for rid in candidates],
                        "packet_frames": flow["packet_frames"], "flow_packet_count": len(entries),
                        "excluded_frames": [entry["frame"] for entry in entries
                                            if entry["packet_state"] != "supported"],
                        "reference_validation_states": {rid: validations[rid]["state"] for rid in candidates},
                        "baseline_status": baseline_by_id[fid]["status"]})

    # Connected reference components are evaluation groups, including quarantined
    # flows. A multi-reference flow links its references; siblings share the UID.
    parents = {rid: rid for rid in references}

    def find(rid):
        while parents[rid] != rid:
            parents[rid] = parents[parents[rid]]
            rid = parents[rid]
        return rid

    for result in results:
        ids = result["reference_ids"]
        for rid in ids[1:]:
            left, right = sorted((find(ids[0]), find(rid)))
            parents[right] = left
    components = defaultdict(list)
    for rid in references:
        components[find(rid)].append(rid)
    matched_refs = defaultdict(list)
    for result in results:
        ids = result["reference_ids"]
        token = ":".join(sorted(components[find(ids[0])])) if ids else result["flow_id"]
        result["connection_group_id"] = hashlib.sha256((extraction["source"]["sha256"] + ":" + token).encode()).hexdigest()
        result["capture_group_id"] = extraction["source"]["sha256"]
        for rid in result["admitted_reference_ids"]:
            matched_refs[rid].append(result["flow_id"])
    results_by_id = {result["flow_id"]: result for result in results}
    for entry in ledger:
        rid = entry["accounting_reference_id"]
        entry["reference_uid"] = references[rid]["uid"] if rid else None
        entry["reference_source_line"] = references[rid]["source_line"] if rid else None
        entry["reference_validation_state"] = validations[rid]["state"] if rid else None
        fid = entry["extraction_flow_id"]
        entry["flow_label_admitted"] = fid is not None and results_by_id[fid]["binary_label"] is not None
    admitted = [result for result in results if result["binary_label"] is not None]
    labeled_packets = sum(result["flow_packet_count"] for result in admitted)
    class_coverage = {}
    for label, name in ((0, "Benign"), (1, "Malicious")):
        ids = {rid for rid, r in references.items() if r["binary_label"] == label}
        class_coverage[name] = {"reference_connections": len(ids),
            "matched_references": len(ids.intersection(matched_refs)),
            "reference_coverage_percent": _percentage(len(ids.intersection(matched_refs)), len(ids)),
            "admitted_flows": sum(result["binary_label"] == label for result in admitted)}
    terminal = {"not_found", "ambiguous", "contradictory"}
    rejected = sum(result["status"] in terminal for result in results)
    summary = {"packets_seen": extraction["quality"]["packets_seen"],
        "packets_accepted": extraction["quality"]["packets_accepted"],
        "packets_rejected_by_extractor": extraction["quality"]["packets_rejected"],
        "extracted_flows": len(results), "reference_connections": len(references),
        "admitted_flows": len(admitted), "rejected_correspondences": rejected,
        "pending_quarantined_flows": len(results) - len(admitted) - rejected,
        "flow_status_counts": dict(Counter(r["status"] for r in results)),
        "flow_label_coverage_percent": _percentage(len(admitted), len(results)),
        "labeled_packets": labeled_packets,
        "label_coverage_of_accepted_packets_percent": _percentage(labeled_packets, len(owners)),
        "label_coverage_of_all_packets_percent": _percentage(labeled_packets, len(packets)),
        "matched_reference_connections": len(matched_refs),
        "reference_coverage_percent": _percentage(len(matched_refs), len(references)),
        "reference_validation_counts": dict(Counter(v["state"] for v in validations.values())),
        "accepted_packet_checksum_states": dict(Counter(packets[n]["transport_checksum_status"] for n in owners)),
        "class_coverage": class_coverage}
    return {"audit_version": PACKET_AUDIT_VERSION, "extraction_source": extraction["source"],
        "label_source": imported["source"], "packet_evidence_source": evidence["source"],
        "packet_reader": evidence["reader"], "packet_reader_limits": evidence["limits"],
        "baseline_summary": baseline["summary"], "summary": summary,
        "policy": {"temporal_tolerance_ns": 0,
            "partial_checksum": "exact pseudoheader seed pattern; all containing flows quarantined; never repair bytes or features",
            "sibling_reconciliation": "exact full reference counters, witnessed interval boundaries and source history/gap evidence for omitted partials",
            "incorrect_checksum": "quarantine containing flow and invalidate affected reference conservation",
            "final_ack": "immediately preceding opposite FIN+ACK pair, exact seq/ack modulo 2^32, second FIN at declared end, SF/Ff and exact full counters",
            "partition": "every packet assigned exclusively; each reference fully accounted inside this flow; identical original/detailed labels",
            "unknown": "no invented values or labels; full known reference counters required",
            "future_evaluation": "never split connection_group_id or capture_group_id across evaluation partitions"},
        "flow_correspondences": results,
        "reference_correspondences": [{**value, "admitted_flow_ids": matched_refs.get(rid, [])}
                                      for rid, value in validations.items()],
        "packet_ledger": ledger}


def audit_files(extraction_path, labels_path, provenance_path, output_directory, *, capture_path=None):
    """Bind file hashes to the acquired pair; reports cannot be silently mixed."""
    output_directory = Path(output_directory)
    if output_directory.exists():
        raise ValueError("Choose a new audit output directory")
    extraction_path, labels_path = Path(extraction_path), Path(labels_path)
    extraction = json.loads(extraction_path.read_text(encoding="utf-8"))
    provenance = json.loads(Path(provenance_path).read_text(encoding="utf-8"))
    imported = import_zeek_labels(labels_path)
    roles = {item["role"]: item for item in provenance["files"]}
    if (extraction["source"]["sha256"] != roles["pcap"]["sha256"]
            or imported["source"]["sha256"] != roles["labels"]["sha256"]):
        raise ValueError("Capture/labels hashes do not match acquisition provenance")
    evidence = read_packet_evidence(capture_path) if capture_path is not None else None
    report = (audit_packet_correspondences(extraction, imported, evidence) if evidence is not None
              else audit_correspondences(extraction, imported))
    report["provenance_manifest_sha256"] = hashlib.sha256(Path(provenance_path).read_bytes()).hexdigest()
    report["extraction_report_sha256"] = hashlib.sha256(extraction_path.read_bytes()).hexdigest()
    report["scenario"] = provenance["scenario"]
    report["auditor_module_sha256"] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    output_directory.mkdir(parents=True)
    for name, content in (("imported_labels.json", imported), ("label_audit.json", report)):
        with (output_directory / name).open("x", encoding="utf-8") as output:
            json.dump(content, output, indent=2, ensure_ascii=False, allow_nan=False)
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Audit label correspondence; no model training or prediction")
    parser.add_argument("extraction", type=Path)
    parser.add_argument("labels", type=Path)
    parser.add_argument("provenance", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--capture", type=Path, help="Original classic PCAP; enables packet reconciliation v2")
    args = parser.parse_args()
    audited = audit_files(args.extraction, args.labels, args.provenance, args.output, capture_path=args.capture)
    print(json.dumps(audited["summary"], indent=2))
