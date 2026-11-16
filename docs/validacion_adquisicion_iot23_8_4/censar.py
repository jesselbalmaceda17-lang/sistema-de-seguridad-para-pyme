"""Read saved evidence; produce counts, never labels or a training table."""
from collections import Counter, defaultdict
from datetime import datetime, timezone
import json
from pathlib import Path

from ejecutar_etapa import ROOT, EVIDENCE, SCENARIOS, save_json


def census(scenario, extraction_path, audit_path, imported_path):
    extraction = json.loads(extraction_path.read_text(encoding="utf-8"))
    audit = json.loads(audit_path.read_text(encoding="utf-8"))
    imported = json.loads(imported_path.read_text(encoding="utf-8"))
    flows = {f["flow_id"]: f for f in extraction["flows"]}
    protocols = defaultdict(Counter)
    groups = defaultdict(set)
    groups_protocol = defaultdict(lambda: defaultdict(set))
    group_classes = defaultdict(set)
    unknown_reasons = defaultdict(Counter)
    unknown_features = defaultdict(lambda: defaultdict(Counter))
    packet_counts = Counter()
    bytes_counts = Counter()
    quality = defaultdict(Counter)
    for result in audit["flow_correspondences"]:
        label = {0: "Benign", 1: "Malicious", None: "unlabeled"}[result["binary_label"]]
        flow = flows[result["flow_id"]]
        protocol = flow["features"]["transport_protocol"]["value"]
        protocols[label][protocol] += 1
        groups[label].add(result["connection_group_id"])
        groups_protocol[label][protocol].add(result["connection_group_id"])
        group_classes[result["connection_group_id"]].add(label)
        packet_counts[label] += len(flow["packet_frames"])
        bytes_counts[label] += sum(flow["features"][direction + "_ipv4_byte_count"]["value"]
                                   for direction in ("forward", "reverse"))
        quality[label][flow["close_reason"]] += 1
        assert len(flow["features"]) == 38
        for name, measurement in flow["features"].items():
            if measurement["status"] == "unavailable":
                assert measurement["value"] is None and measurement["reason"]
                unknown_reasons[label][measurement["reason"]] += 1
                unknown_features[label][name][measurement["reason"]] += 1
    raw_protocols = defaultdict(Counter)
    field_problems = Counter()
    for record in imported["records"]:
        raw_protocols[record["label_original"]][record["protocol"]] += 1
        field_problems.update(f"{name}:{reason}" for name, reason in record["field_problems"].items())
    result = {"scenario": scenario, "summary": audit["summary"],
        "extraction_quality": extraction["quality"], "configuration": extraction["configuration"],
        "feature_count": len(extraction["feature_definitions"]),
        "duration_observed_seconds": (int(extraction["quality"]["last_timestamp_epoch_ns"]) - int(extraction["quality"]["first_timestamp_epoch_ns"])) / 1e9,
        "flow_protocol_by_admitted_class": {k: dict(v) for k, v in protocols.items()},
        "connection_groups_by_admitted_class": {k: len(v) for k, v in groups.items()},
        "connection_groups_by_class_and_protocol": {k: {p: len(g) for p, g in v.items()} for k, v in groups_protocol.items()},
        "groups_with_multiple_classes": sum(len(v) > 1 for v in group_classes.values()),
        "packets_by_admitted_class": dict(packet_counts), "ipv4_bytes_by_admitted_class": dict(bytes_counts),
        "flow_close_reason_by_class": {k: dict(v) for k, v in quality.items()},
        "unknown_feature_cells_by_class_and_reason": {k: dict(v) for k, v in unknown_reasons.items()},
        "unknown_feature_cells_by_class_feature_reason": {k: {n: dict(c) for n, c in v.items()} for k, v in unknown_features.items()},
        "reference_import_quality": imported["quality"],
        "reference_protocol_by_original_label": {k: dict(v) for k, v in raw_protocols.items()},
        "reference_field_problems": dict(field_problems),
        "reference_detail_counts": dict(Counter(r["detailed_label"] or "unset" for r in imported["records"])),
        "outside_extraction_by_reason": dict(Counter(str(p["reason"]) for p in audit["packet_ledger"] if p["extraction_flow_id"] is None)),
        "outside_extraction_by_ethertype": dict(Counter(str(p.get("ethernet_type")) for p in audit["packet_ledger"] if p["extraction_flow_id"] is None)),
        "capture_groups": len({r["capture_group_id"] for r in audit["flow_correspondences"]}),
        "statistical_independence": "connection groups prevent split leakage; groups within the same capture/device/time remain dependent"}
    return result, extraction, audit, imported


def hue_diagnosis(extraction, audit, imported):
    # Diagnose packet compatibility without normalizing even one source label,
    # changing any audit object, or emitting a hypothetical admitted dataset.
    reference_packets = defaultdict(list)
    for packet in audit["packet_ledger"]:
        if packet["extraction_flow_id"] is not None and len(packet["candidate_reference_ids"]) == 1:
            reference_packets[packet["candidate_reference_ids"][0]].append(packet)
    states = Counter()
    examples = []
    for record in imported["records"]:
        packets = reference_packets[record["reference_id"]]
        measured = {"orig_pkts": 0, "resp_pkts": 0, "orig_ip_bytes": 0, "resp_ip_bytes": 0}
        for packet in packets:
            direction = "orig" if (packet["src"], packet["sport"]) == (record["orig_ip"], record["orig_port"]) else "resp"
            measured[direction + "_pkts"] += 1
            measured[direction + "_ip_bytes"] += packet["ipv4_bytes"]
        counter_equal = all(record[k] is not None and record[k] == v for k, v in measured.items())
        times = [int(p["timestamp_epoch_ns"]) for p in packets]
        start = int(record["start_epoch_ns"]) if record["start_epoch_ns"] is not None else None
        end = start + int(record["duration_ns"]) if start is not None and record["duration_ns"] is not None else (start if record["orig_pkts"] is not None and record["resp_pkts"] is not None and record["orig_pkts"] + record["resp_pkts"] == 1 else None)
        boundaries = bool(times) and min(times) == start and end in times
        checksum_states = dict(Counter(p["transport_checksum_status"] for p in packets))
        state = "counters_and_boundaries_agree" if counter_equal and boundaries else "additional_packet_discrepancy"
        states[state] += 1
        if state == "additional_packet_discrepancy" or len(examples) < 3:
            examples.append({"reference_id": record["reference_id"], "uid": record["uid"],
                "source_line": record["source_line"], "original_label": record["label_original"],
                "binary_label": record["binary_label"], "protocol": record["protocol"],
                "source_start_ns": record["start_epoch_ns"], "source_end_ns": str(end) if end is not None else None,
                "expected_counters": {k: record[k] for k in measured}, "observed_unique_candidate_counters": measured,
                "boundaries_witnessed": boundaries, "checksum_states": checksum_states,
                "candidate_frames": [p["frame"] for p in packets],
                "flow_ids": sorted({p["extraction_flow_id"] for p in packets}), "diagnostic_state": state})
    partial = [{k: p.get(k) for k in ("frame", "timestamp_epoch_ns", "extraction_flow_id", "candidate_reference_ids", "stored_transport_checksum", "pseudoheader_sum", "transport_checksum_status")}
               for p in audit["packet_ledger"] if p.get("transport_checksum_status") == "partial_pseudoheader"]
    return {"diagnostic_only_no_admissions": True, "original_labels_unchanged": True,
            "primary_blocker": "452 literal lowercase benign labels are unrecognized by the current importer",
            "caution": "These are candidate tuple/time/counter checks including all checksum states, NOT accepted correspondence or recovered coverage; unknown labels prevent the auditor from performing full conservation validation",
            "candidate_reference_checks": dict(states), "examples": examples, "partial_checksum_packets": partial}


if __name__ == "__main__":
    censuses = {}
    for key, scenario in SCENARIOS.items():
        processed = ROOT / "data/processed" / scenario["folder"]
        result, extraction, audit, imported = census(scenario["scenario"], processed / "extraction.json",
            processed / "audit_v2/label_audit.json", processed / "audit_v2/imported_labels.json")
        result["execution"] = json.loads((EVIDENCE / (key + "_ejecucion.json")).read_text(encoding="utf-8"))
        result["raw_storage_bytes"] = sum(p.stat().st_size for p in (ROOT / "data/raw" / scenario["folder"]).rglob("*") if p.is_file())
        result["processed_storage_bytes"] = sum(p.stat().st_size for p in processed.rglob("*") if p.is_file())
        result["artifact_sizes"] = {p.relative_to(ROOT).as_posix(): p.stat().st_size for p in processed.rglob("*") if p.is_file()}
        censuses[key] = result
        if key == "hue":
            save_json(EVIDENCE / "diagnostico_hue.json", hue_diagnosis(extraction, audit, imported))
    previous = ROOT / "docs/validacion_reconciliacion_iot23_20_1/audit_v2"
    censuses["pilot_20_1"] = census("CTU-IoT-Malware-Capture-20-1", ROOT / "data/processed/iot23_pilot_20_1/extraction.json",
                                  previous / "label_audit.json", previous / "imported_labels.json")[0]
    save_json(EVIDENCE / "censo.json", {"generated_at_utc": datetime.now(timezone.utc).isoformat(), "scenarios": censuses})
    for key, c in censuses.items():
        print(key, json.dumps({k: c[k] for k in ("flow_protocol_by_admitted_class", "connection_groups_by_admitted_class", "unknown_feature_cells_by_class_and_reason", "reference_protocol_by_original_label", "reference_field_problems", "outside_extraction_by_ethertype")}, ensure_ascii=False))
