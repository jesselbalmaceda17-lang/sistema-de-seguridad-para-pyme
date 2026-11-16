"""Descriptive packet-based connection groups; no statistical independence claim."""
from collections import Counter, defaultdict
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
OUTPUT = Path(__file__).resolve().parent
FLAGS = {"syn": 2, "ack": 16, "fin": 1, "rst": 4, "psh": 8, "urg": 32, "ece": 64, "cwr": 128}


def group_census(extraction, audit):
    """Canonical endpoints avoid direction flips between extractor siblings.

    Bidirectional means captured packets from both endpoints, not demonstrated
    application success. Only admitted flows contribute to class summaries.
    """
    flows = {f["flow_id"]: f for f in extraction["flows"]}
    results = {r["flow_id"]: r for r in audit["flow_correspondences"]}
    groups = {}
    flow_counts = Counter()
    for r in results.values():
        if r["binary_label"] is None:
            continue
        flow = flows[r["flow_id"]]
        protocol = flow["features"]["transport_protocol"]["value"]
        label = {0: "Benign", 1: "Malicious"}[r["binary_label"]]
        flow_counts[(label, protocol)] += 1
        endpoints = tuple(sorted((flow[d + "_endpoint"]["ipv4"], flow[d + "_endpoint"]["port"]) for d in ("forward", "reverse")))
        group = groups.setdefault(r["connection_group_id"], {"connection_group_id": r["connection_group_id"],
            "capture_group_id": r["capture_group_id"], "protocol": protocol, "canonical_endpoints": endpoints,
            "labels": set(), "flow_ids": [], "reference_uids": set(), "frames": [],
            "direction_packets": [0, 0], "direction_payload_bytes": [0, 0], "tcp_flag_counts": Counter(),
            "tcp_pure_syn_packets": 0})
        assert group["protocol"] == protocol and group["canonical_endpoints"] == endpoints
        group["labels"].add(label)
        group["flow_ids"].append(r["flow_id"])
        group["reference_uids"].update(x["uid"] for x in r["references"] if x["reference_id"] in r["admitted_reference_ids"])
    for packet in audit["packet_ledger"]:
        flow_result = results.get(packet["extraction_flow_id"])
        if flow_result is None or flow_result["binary_label"] is None:
            continue
        group = groups[flow_result["connection_group_id"]]
        direction = 0 if (packet["src"], packet["sport"]) == group["canonical_endpoints"][0] else 1
        assert (packet["src"], packet["sport"]) in group["canonical_endpoints"]
        group["direction_packets"][direction] += 1
        group["direction_payload_bytes"][direction] += packet["payload_bytes"]
        group["frames"].append(packet["frame"])
        if packet["protocol"] == "tcp":
            for name, mask in FLAGS.items():
                group["tcp_flag_counts"][name] += int(bool(packet["tcp_flags"] & mask))
            group["tcp_pure_syn_packets"] += int(packet["tcp_flags"] == 2 and packet["payload_bytes"] == 0)
    summaries = defaultdict(Counter)
    all_frames = []
    for group in groups.values():
        assert len(group["frames"]) == len(set(group["frames"]))
        all_frames.extend(group["frames"])
        group["labels"] = sorted(group["labels"])
        group["class"] = group["labels"][0] if len(group["labels"]) == 1 else "mixed_admitted_labels"
        group["reference_uids"] = sorted(group["reference_uids"])
        group["packet_count"] = len(group["frames"])
        group["first_frame"], group["last_frame"] = min(group["frames"]), max(group["frames"])
        del group["frames"]
        group["bidirectional_packets"] = all(n > 0 for n in group["direction_packets"])
        group["bidirectional_payload"] = all(n > 0 for n in group["direction_payload_bytes"])
        group["pure_syn_without_ack"] = group["protocol"] == "tcp" and group["tcp_pure_syn_packets"] == group["packet_count"]
        group["tcp_flag_counts"] = dict(group["tcp_flag_counts"]) if group["protocol"] == "tcp" else None
        x = summaries[group["class"]]
        protocol = group["protocol"]
        x[protocol + "_groups"] += 1
        x[protocol + "_bidirectional_packet_groups"] += int(group["bidirectional_packets"])
        x[protocol + "_bidirectional_payload_groups"] += int(group["bidirectional_payload"])
        x[protocol + "_packets"] += group["packet_count"]
        if protocol == "tcp":
            x["tcp_pure_syn_groups"] += int(group["pure_syn_without_ack"])
            x["tcp_other_pattern_groups"] += int(not group["pure_syn_without_ack"])
            x["tcp_groups_with_ack"] += int(group["tcp_flag_counts"]["ack"] > 0)
            for name, value in group["tcp_flag_counts"].items():
                x["tcp_packets_with_" + name] += value
    assert len(all_frames) == len(set(all_frames)) == audit["summary"]["labeled_packets"]
    return {"summary": {k: dict(v) for k, v in summaries.items()},
        "flow_counts": {label: {p: n for (l, p), n in flow_counts.items() if l == label} for label, _ in flow_counts},
        "admitted_groups": len(groups), "groups": sorted(groups.values(), key=lambda g: g["connection_group_id"]),
        "definitions": {"direction": "lexically sorted IPv4/port endpoints across all packets, independent of per-segment orientation",
            "bidirectional_packets": "at least one accepted labeled packet from each endpoint; not proof of application success",
            "pure_syn_without_ack": "every TCP packet in admitted group has exactly SYN and no payload",
            "groups": "connection groups for split isolation, not independent attacks or experiments"}}


def main():
    cases = (("pilot_20_1", "data/processed/iot23_pilot_20_1/extraction.json", "docs/validacion_reconciliacion_iot23_20_1/audit_v2/label_audit.json"),
             ("hakai", "data/processed/iot23_hakai_8_1/extraction.json", "data/processed/iot23_hakai_8_1/audit_v2/label_audit.json"),
             ("hue", "data/processed/iot23_hue_4_1/extraction.json", "docs/validacion_normalizacion_hue/audit_v2_hue/label_audit.json"))
    report = {}
    for name, extraction, audit in cases:
        report[name] = group_census(json.loads((ROOT / extraction).read_text(encoding="utf-8")),
                                  json.loads((ROOT / audit).read_text(encoding="utf-8")))
        print(name, json.dumps(report[name]["summary"]), flush=True)
    with (OUTPUT / "censo_inicial_grupos.json").open("x", encoding="utf-8") as stream:
        json.dump(report, stream, indent=2, ensure_ascii=False)


if __name__ == "__main__":
    main()
