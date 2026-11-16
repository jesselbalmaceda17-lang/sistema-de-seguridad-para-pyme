"""Read-only diagnostics and protected-file verification after real execution."""
from collections import Counter, defaultdict
from contextlib import closing
from datetime import datetime, timezone
import json
from pathlib import Path
import shutil
import sqlite3
import struct
import zipfile

from ejecutar_etapa import ROOT, EVIDENCE, SCENARIOS, save_json, digest


def diversity():
    result = {}
    for key, folder, audit_directory in (
        ("hakai", "iot23_hakai_8_1", ROOT / "data/processed/iot23_hakai_8_1/audit_v2"),
        ("hue", "iot23_hue_4_1", ROOT / "data/processed/iot23_hue_4_1/audit_v2"),
        ("pilot_20_1", "iot23_pilot_20_1", ROOT / "docs/validacion_reconciliacion_iot23_20_1/audit_v2")):
        extraction = json.loads((ROOT / "data/processed" / folder / "extraction.json").read_text(encoding="utf-8"))
        audit = json.loads((audit_directory / "label_audit.json").read_text(encoding="utf-8"))
        flows = {f["flow_id"]: f for f in extraction["flows"]}
        data = defaultdict(lambda: {"host_pairs": set(), "tuples": set(), "groups": set(),
                                    "packets_per_flow": Counter(), "tcp_flags": Counter()})
        states_per_group = defaultdict(set)
        flow_count_per_group = Counter()
        for r in audit["flow_correspondences"]:
            label = {0: "Benign", 1: "Malicious", None: "unlabeled"}[r["binary_label"]]
            flow = flows[r["flow_id"]]
            endpoints = [(flow[d + "_endpoint"]["ipv4"], flow[d + "_endpoint"]["port"]) for d in ("forward", "reverse")]
            x = data[label]
            x["host_pairs"].add(tuple(sorted(p[0] for p in endpoints)))
            x["tuples"].add((flow["features"]["transport_protocol"]["value"], *sorted(endpoints)))
            x["groups"].add(r["connection_group_id"])
            x["packets_per_flow"][len(flow["packet_frames"])] += 1
            states_per_group[r["connection_group_id"]].add(label)
            flow_count_per_group[r["connection_group_id"]] += 1
            if flow["features"]["transport_protocol"]["value"] == "tcp":
                for direction in ("forward", "reverse"):
                    for flag in ("syn", "ack", "fin", "rst", "psh"):
                        x["tcp_flags"][flag] += flow["features"][direction + "_tcp_" + flag + "_count"]["value"]
        result[key] = {"by_admitted_class": {label: {
            "distinct_host_pairs": len(x["host_pairs"]), "host_pairs": sorted(x["host_pairs"]),
            "distinct_five_tuples": len(x["tuples"]), "connection_groups": len(x["groups"]),
            "packets_per_flow_histogram": dict(x["packets_per_flow"]), "tcp_flag_counts": dict(x["tcp_flags"])}
            for label, x in data.items()},
            "unique_groups_including_quarantine": len(states_per_group),
            "groups_with_both_labeled_and_unlabeled_segments": sum("unlabeled" in v and len(v) > 1 for v in states_per_group.values()),
            "groups_with_conflicting_admitted_binary_labels": sum("Benign" in v and "Malicious" in v for v in states_per_group.values()),
            "flows_per_connection_group_histogram": dict(Counter(flow_count_per_group.values()))}
        if key == "hue":
            imported = json.loads((audit_directory / "imported_labels.json").read_text(encoding="utf-8"))
            traces = []
            for uid in ("CGQf8t1kjdxB5PHXL4", "C0wssT3JKSiAqhCZw"):
                record = next(r for r in imported["records"] if r["uid"] == uid)
                endpoints = {(record["orig_ip"], record["orig_port"]), (record["resp_ip"], record["resp_port"])}
                same_key = [p for p in audit["packet_ledger"] if p.get("protocol") == record["protocol"] and
                    {(p.get("src"), p.get("sport")), (p.get("dst"), p.get("dport"))} == endpoints]
                stop = int(record["start_epoch_ns"]) + int(record["duration_ns"])
                flow_ids = {p["extraction_flow_id"] for p in same_key if record["reference_id"] in p["candidate_reference_ids"]}
                selected = [p for p in same_key if p["extraction_flow_id"] in flow_ids]
                traces.append({"reference": record, "declared_end_ns": str(stop), "packets_of_related_extracted_flows": selected,
                    "post_end_frames": [p["frame"] for p in selected if int(p["timestamp_epoch_ns"]) > stop],
                    "diagnosis": "Final pure ACK outside published interval; preceding FINs have intervening packets, so the current consecutive FIN/FIN+ACK/ACK rule does not admit it. Unknown source label also blocks admission. No rule or timestamp changed."})
            save_json(EVIDENCE / "diagnostico_hue_tcp.json", {"diagnostic_only": True, "examples": traces})
    save_json(EVIDENCE / "diversidad.json", result)


def integrity():
    backup_record = json.loads((EVIDENCE / "respaldo.json").read_text(encoding="utf-8"))
    backup = ROOT / backup_record["backup"]
    assert digest(backup.read_bytes()) == backup_record["sha256"]
    with zipfile.ZipFile(backup) as archive:
        assert archive.testzip() is None
        baseline = json.loads(archive.read("BACKUP_MANIFEST.json"))
    checked, sqlite_checks = [], []
    for entry in baseline["files"]:
        path = ROOT / entry["path"]
        actual = digest(path.read_bytes())
        assert actual == entry["source_sha256"], entry["path"]
        checked.append({"path": entry["path"], "before_sha256": entry["source_sha256"], "after_sha256": actual})
        if path.suffix in {".sqlite3", ".db"}:
            with closing(sqlite3.connect(path.as_uri() + "?mode=ro", uri=True)) as database:
                messages = [r[0] for r in database.execute("PRAGMA integrity_check")]
            assert messages == ["ok"] and digest(path.read_bytes()) == actual
            sqlite_checks.append({"path": entry["path"], "integrity_check": messages, "unchanged": True})
    old_backups = []
    for entry in baseline["preserved_backups"]:
        path = ROOT / entry["path"]
        assert digest(path.read_bytes()) == entry["sha256"]
        with zipfile.ZipFile(path) as archive:
            assert archive.testzip() is None
        old_backups.append({**entry, "rechecked_unchanged": True})
    sources = []
    for scenario in SCENARIOS.values():
        raw = ROOT / "data/raw" / scenario["folder"]
        provenance = json.loads((raw / "provenance.json").read_text(encoding="utf-8"))
        for item in provenance["files"]:
            path = raw / item["local_name"]
            assert digest(path.read_bytes()) == item["sha256"] and path.stat().st_size == item["size_bytes"]
            sources.append({"path": path.relative_to(ROOT).as_posix(), "role": item["role"], "sha256": item["sha256"], "size_bytes": item["size_bytes"]})
    save_json(EVIDENCE / "integridad.json", {"checked_at_utc": datetime.now(timezone.utc).isoformat(),
        "git": "Not a Git repository; no Git metadata created", "baseline_files": len(checked),
        "unchanged_files": checked, "modified_existing_files": [], "deleted_existing_files": [],
        "sqlite_integrity": sqlite_checks, "preserved_backups": old_backups,
        "new_backup": backup_record, "acquired_sources_unchanged": sources,
        "free_bytes_after_processing_and_tests": shutil.disk_usage(ROOT).free})


if __name__ == "__main__":
    diversity()
    integrity()
