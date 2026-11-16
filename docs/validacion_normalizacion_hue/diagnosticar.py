"""Read-only grouping of the original 93 Hue discrepancies, with packet proof."""
from collections import Counter, defaultdict
from pathlib import Path
import json

ROOT = Path(__file__).resolve().parents[2]
OUTPUT = Path(__file__).resolve().parent
FIELDS = ("orig_pkts", "resp_pkts", "orig_ip_bytes", "resp_ip_bytes")


def counts(packets, reference):
    totals = dict.fromkeys(FIELDS, 0)
    for p in packets:
        origin = (p["src"], p["sport"]) == (reference["orig_ip"], reference["orig_port"])
        direction = "orig" if origin else "resp"
        totals[direction + "_pkts"] += 1
        totals[direction + "_ip_bytes"] += p["ipv4_bytes"]
    return totals


def main():
    previous = ROOT / "docs/validacion_adquisicion_iot23_8_4/diagnostico_hue.json"
    diagnostics = json.loads(previous.read_text(encoding="utf-8"))
    base = ROOT / "data/processed/iot23_hue_4_1/audit_v2"
    imported = json.loads((base / "imported_labels.json").read_text(encoding="utf-8"))
    audit = json.loads((base / "label_audit.json").read_text(encoding="utf-8"))
    references = {r["reference_id"]: r for r in imported["records"]}
    by_flow = defaultdict(list)
    for packet in audit["packet_ledger"]:
        if packet["extraction_flow_id"] is not None:
            by_flow[packet["extraction_flow_id"]].append(packet)
    results = []
    for case in diagnostics["examples"]:
        if case["diagnostic_state"] != "additional_packet_discrepancy":
            continue
        reference = references[case["reference_id"]]
        packets = sorted([p for fid in case["flow_ids"] for p in by_flow[fid]], key=lambda p: p["frame"])
        supported = [p for p in packets if reference["reference_id"] in p["candidate_reference_ids"]]
        outside = [p for p in packets if reference["reference_id"] not in p["candidate_reference_ids"]]
        partials = [p for p in packets if p["transport_checksum_status"] == "partial_pseudoheader"]
        start = int(reference["start_epoch_ns"])
        end = start + int(reference["duration_ns"])
        pure_after = bool(outside) and all(p["tcp_flags"] == 0x10 and p["payload_bytes"] == 0
                         and p["ipv4_bytes"] == 40 and int(p["timestamp_epoch_ns"]) > end
                         and p["transport_checksum_status"] == "valid" for p in outside)
        all_counters_equal = counts(packets, reference) == {k: reference[k] for k in FIELDS}
        if partials:
            category = "partial_checksum_and_post_end_ack" if pure_after else "partial_checksum_without_post_end_ack"
        elif pure_after and all_counters_equal:
            category = "one_post_end_ack" if len(outside) == 1 else "multiple_post_end_acks"
        else:
            category = "unresolved_other"
        # Diagnostic TCP relations, never used to grant a label.
        fins = [p for p in supported if p.get("tcp_flags") == 0x11 and p["payload_bytes"] == 0]
        tcp = None
        if len(fins) >= 2:
            first, second = fins[-2:]
            intervening = [p["frame"] for p in packets if first["frame"] < p["frame"] < second["frame"]]
            opposite = (first["src"], first["sport"]) != (second["src"], second["sport"])
            tcp = {"fin_frames": [first["frame"], second["frame"]], "intervening_frames": intervening,
                "opposite_directions": opposite,
                "second_seq_equals_first_ack": second["tcp_sequence"] == first["tcp_acknowledgment"],
                "second_ack_equals_first_seq_plus_one": second["tcp_acknowledgment"] == (first["tcp_sequence"] + 1) % 2**32,
                "post_end_acks": [{"frame": p["frame"],
                    "seq_equals_first_fin_seq_plus_one": p["tcp_sequence"] == (first["tcp_sequence"] + 1) % 2**32,
                    "ack_equals_second_fin_seq_plus_one": p["tcp_acknowledgment"] == (second["tcp_sequence"] + 1) % 2**32}
                    for p in outside]}
        observed = counts(supported, reference)
        measured_partial_payload = sum(p["payload_bytes"] for p in partials)
        history = reference["raw_fields"].get("history", "")
        direction_history = all(("C" if (p["src"], p["sport"]) == (reference["orig_ip"], reference["orig_port"]) else "c") in history for p in partials)
        results.append({"reference_id": reference["reference_id"], "uid": reference["uid"],
            "source_line": reference["source_line"], "original_label": reference["label_original"],
            "flow_ids": case["flow_ids"], "category": category,
            "start_epoch_ns": str(start), "end_epoch_ns": str(end),
            "expected_counts": {k: reference[k] for k in FIELDS}, "original_candidate_counts": observed,
            "expected_minus_candidate": {k: reference[k] - observed[k] for k in FIELDS},
            "whole_related_flow_counts": counts(packets, reference),
            "whole_flow_counters_equal_reference": all_counters_equal,
            "post_end_frames": [p["frame"] for p in outside],
            "partial_frames": [p["frame"] for p in partials],
            "partial_payload_bytes": measured_partial_payload,
            "source_missed_bytes": reference["raw_fields"].get("missed_bytes"),
            "source_history": history, "partial_history_direction_present": direction_history,
            "source_gap_equals_partial_payload": bool(partials) and reference["raw_fields"].get("missed_bytes") == str(measured_partial_payload),
            "tcp_relation_diagnostics": tcp, "packets": packets,
            "diagnostic_only_no_new_packet_assignments": True})
    assert len(results) == 93
    report = {"source": "Original saved pre-normalization audit and source records; never rewritten",
        "group_counts": dict(Counter(r["category"] for r in results)), "cases": results,
        "caution": "Causal grouping describes observed packet patterns. It neither changes audit rules nor admits a flow. Exact full-flow counters alone do not justify admitting post-end packets."}
    with (OUTPUT / "diagnostico_93.json").open("x", encoding="utf-8") as stream:
        json.dump(report, stream, indent=2, ensure_ascii=False)
    print(json.dumps(report["group_counts"], indent=2))


if __name__ == "__main__":
    main()
