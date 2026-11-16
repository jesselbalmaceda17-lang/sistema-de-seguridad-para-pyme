"""Reaudit retained captures; descriptive census, not classifier evaluation."""
from collections import Counter, defaultdict
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from seguridad_pymes.label_audit import audit_packet_correspondences, read_packet_evidence
from seguridad_pymes.zeek_labels import import_zeek_labels

OUTPUT = Path(__file__).resolve().parent
FLAGS = ("syn", "ack", "fin", "rst", "psh", "urg", "ece", "cwr")
SCENARIOS = (
    ("pilot_20_1", "iot23_pilot_20_1", "2018-10-02-13-12-30-192.168.100.103.pcap", "docs/validacion_reconciliacion_iot23_20_1/audit_v2"),
    ("hakai", "iot23_hakai_8_1", "2018-07-31-15-15-09-192.168.100.113.pcap", "data/processed/iot23_hakai_8_1/audit_v2"),
    ("hue", "iot23_hue_4_1", "2018-10-25-14-06-32-192.168.1.132.pcap", "docs/validacion_normalizacion_hue/audit_v2_hue"))


def read(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def save(name, value):
    with (OUTPUT / name).open("x", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2, ensure_ascii=False, allow_nan=False)


def census(extraction, audit):
    flows = {f["flow_id"]: f for f in extraction["flows"]}
    data = defaultdict(lambda: {"flow_protocol_counts": Counter(), "group_protocols": defaultdict(set),
        "packet_count": 0, "tcp_packets": 0, "tcp_flag_packet_counts": Counter(),
        "tcp_flag_flow_counts": Counter(), "tcp_flag_combinations": Counter(),
        "pure_syn_tcp_flows": 0, "groups": defaultdict(list), "missing_feature_cells": Counter(),
        "distinct_host_pairs": set()})
    labels_by_flow = {}
    for result in audit["flow_correspondences"]:
        flow = flows[result["flow_id"]]
        label = {0: "Benign", 1: "Malicious", None: "unlabeled"}[result["binary_label"]]
        labels_by_flow[result["flow_id"]] = label
        values = flow["features"]
        protocol = values["transport_protocol"]["value"]
        x = data[label]
        x["flow_protocol_counts"][protocol] += 1
        x["packet_count"] += len(flow["packet_frames"])
        x["group_protocols"][protocol].add(result["connection_group_id"])
        x["distinct_host_pairs"].add(tuple(sorted(flow[d + "_endpoint"]["ipv4"] for d in ("forward", "reverse"))))
        pure_syn = False
        if protocol == "tcp":
            flag_counts = {}
            for flag in FLAGS:
                measurements = [values[d + "_tcp_" + flag + "_count"] for d in ("forward", "reverse")]
                assert all(m["status"] == "ok" and m["value"] is not None for m in measurements)
                flag_counts[flag] = sum(m["value"] for m in measurements)
                x["tcp_flag_packet_counts"][flag] += flag_counts[flag]
                x["tcp_flag_flow_counts"][flag] += int(flag_counts[flag] > 0)
            x["tcp_packets"] += len(flow["packet_frames"])
            pure_syn = flag_counts["syn"] == len(flow["packet_frames"]) and not any(flag_counts[f] for f in FLAGS if f != "syn")
            x["pure_syn_tcp_flows"] += int(pure_syn)
        x["groups"][result["connection_group_id"]].append({"protocol": protocol, "pure_syn": pure_syn})
        for measurement in values.values():
            if measurement["status"] != "ok":
                assert measurement["value"] is None and measurement["reason"]
                x["missing_feature_cells"][measurement["reason"]] += 1
    for packet in audit["packet_ledger"]:
        if packet["extraction_flow_id"] is not None and packet.get("protocol") == "tcp":
            data[labels_by_flow[packet["extraction_flow_id"]]]["tcp_flag_combinations"][hex(packet["tcp_flags"])] += 1
    result = {}
    for label, x in data.items():
        result[label] = {"flow_protocol_counts": dict(x["flow_protocol_counts"]),
            "connection_groups": len(x["groups"]),
            "group_protocol_counts": {p: len(g) for p, g in x["group_protocols"].items()},
            "packets": x["packet_count"], "tcp_packets": x["tcp_packets"],
            "tcp_flag_packet_counts": dict(x["tcp_flag_packet_counts"]),
            "tcp_flag_flow_counts": dict(x["tcp_flag_flow_counts"]),
            "tcp_flag_combinations": dict(x["tcp_flag_combinations"]),
            "pure_syn_tcp_flows": x["pure_syn_tcp_flows"],
            "pure_syn_tcp_groups": sum(all(f["protocol"] == "tcp" and f["pure_syn"] for f in entries) for entries in x["groups"].values()),
            "missing_feature_cells": dict(x["missing_feature_cells"]),
            "distinct_host_pairs": len(x["distinct_host_pairs"])}
    return result


def main():
    results, regressions = {}, []
    for key, folder, pcap_name, saved_directory in SCENARIOS:
        started = time.perf_counter()
        raw = ROOT / "data/raw" / folder
        extraction = read(ROOT / "data/processed" / folder / "extraction.json")
        expected = read(ROOT / saved_directory / "label_audit.json")
        imported = import_zeek_labels(raw / "conn.log.labeled")
        actual = audit_packet_correspondences(extraction, imported, read_packet_evidence(raw / pcap_name))
        for name, value in actual.items():
            assert value == expected[name], (key, name)
        if key != "hue":
            old_imported = read(ROOT / saved_directory / "imported_labels.json")
            assert len(imported["records"]) == len(old_imported["records"])
            for old, new in zip(old_imported["records"], imported["records"]):
                assert {k: new[k] for k in old} == old
        regressions.append({"scenario": key, "auditor_core_output_identical_to_expected": True,
            "expected_report": saved_directory + "/label_audit.json",
            "original_record_fields_unchanged": key != "hue",
            "pcap_sha256": actual["extraction_source"]["sha256"],
            "label_sha256": imported["source"]["sha256"], "wall_seconds": time.perf_counter()-started})
        results[key] = {"summary": actual["summary"], "class_census": census(extraction, actual)}
        if key == "hue":
            original_cases = {c["reference_id"]: c for c in read(OUTPUT / "diagnostico_93.json")["cases"]}
            records = {r["reference_id"]: r for r in imported["records"]}
            related = defaultdict(list)
            for flow in actual["flow_correspondences"]:
                for rid in flow["reference_ids"]:
                    related[rid].append(flow)
            references = []
            for r in actual["reference_correspondences"]:
                record = records[r["reference_id"]]
                pending = not r["admitted_flow_ids"]
                assert (r["reference_id"] in original_cases) == pending
                references.append({**r, "label_original": record["label_original"],
                    "label_normalized": record["label_normalized"], "source_binary_label": record["binary_label"],
                    "label_correspondence_admitted": not pending,
                    "cause_group": original_cases[r["reference_id"]]["category"] if pending else None,
                    "related_flows": [{k: f[k] for k in ("flow_id", "status", "binary_label", "connection_group_id")} for f in related[r["reference_id"]]]})
            save("referencias_hue.json", {"represented_references": 359, "pending_references": 93,
                "verified_references_including_unrepresented": 361,
                "source_label_normalization_is_not_flow_admission": True, "references": references})
    pooled = {}
    for label in ("Benign", "Malicious"):
        counts, groups, flags = Counter(), Counter(), Counter()
        pure_flows = pure_groups = 0
        for result in results.values():
            c = result["class_census"].get(label, {})
            counts.update(c.get("flow_protocol_counts", {}))
            groups.update(c.get("group_protocol_counts", {}))
            flags.update(c.get("tcp_flag_packet_counts", {}))
            pure_flows += c.get("pure_syn_tcp_flows", 0)
            pure_groups += c.get("pure_syn_tcp_groups", 0)
        pooled[label] = {"flow_protocol_counts": dict(counts), "group_protocol_counts": dict(groups),
            "tcp_flag_packet_counts": dict(flags), "pure_syn_tcp_flows": pure_flows, "pure_syn_tcp_groups": pure_groups}
    save("regresiones.json", {"checked_at_utc": datetime.now(timezone.utc).isoformat(), "results": regressions})
    save("censo_comparativo.json", {"generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "scenarios": results, "pooled_descriptive_counts": pooled,
        "not_classifier_evaluation": True,
        "independence": "Never split connection or capture groups; counts of groups do not establish independent attacks, devices or campaigns"})
    print(json.dumps({key: value["class_census"] for key, value in results.items()}, indent=2))


if __name__ == "__main__":
    main()
