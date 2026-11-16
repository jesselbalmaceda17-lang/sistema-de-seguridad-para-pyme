"""Build a provenance-bound table exclusively from three admitted capture audits."""

from collections import Counter, defaultdict
import csv
import json
import math
from pathlib import Path

import numpy as np

from seguridad_pymes.label_audit import audit_packet_correspondences, read_packet_evidence
from seguridad_pymes.pcap_schema import EXTRACTOR_VERSION, SCHEMA_VERSION, ExtractionConfig, feature_definitions
from seguridad_pymes.zeek_labels import import_zeek_labels
from pcap_experiment.common import ROOT, read_json, require, sha256, write_json
from pcap_experiment.contract import FEATURE_NAMES, PROTOCOL_ENCODING, PROTOCOL_VERSION

SOURCES = (
    {"name": "torii", "raw": "iot23_pilot_20_1", "processed": "iot23_pilot_20_1",
     "pcap": "2018-10-02-13-12-30-192.168.100.103.pcap",
     "audit": "docs/validacion_reconciliacion_iot23_20_1/audit_v2/label_audit.json",
     "flows": 3495, "benign": 3207, "malicious": 288, "groups": 3198},
    {"name": "hakai", "raw": "iot23_hakai_8_1", "processed": "iot23_hakai_8_1",
     "pcap": "2018-07-31-15-15-09-192.168.100.113.pcap",
     "audit": "data/processed/iot23_hakai_8_1/audit_v2/label_audit.json",
     "flows": 4237, "benign": 2181, "malicious": 2056, "groups": 4237},
    {"name": "hue", "raw": "iot23_hue_4_1", "processed": "iot23_hue_4_1",
     "pcap": "2018-10-25-14-06-32-192.168.1.132.pcap",
     "audit": "docs/validacion_normalizacion_hue/audit_v2_hue/label_audit.json",
     "flows": 2107, "benign": 2107, "malicious": 0, "groups": 359},
)


def feature_row(flow):
    """Strict allowlist; metadata can never be implicitly selected as predictors."""
    require(set(flow["features"]) == set(FEATURE_NAMES), "Expected exactly the 38 documented features")
    values = []
    unknowns = {}
    for name in FEATURE_NAMES:
        item = flow["features"][name]
        value = item["value"]
        if item["status"] == "unavailable":
            require(value is None and bool(item["reason"]), "Unknown value requires explicit reason")
            require(name != "transport_protocol", "Protocol must be observable")
            unknowns[name] = item["reason"]
        else:
            require(item["status"] == "ok" and item["reason"] is None and value is not None,
                    "Inconsistent observed feature")
            if name == "transport_protocol":
                require(value in PROTOCOL_ENCODING, "Unsupported protocol")
                value = PROTOCOL_ENCODING[value]
            else:
                require(type(value) in (int, float) and math.isfinite(value), "Invalid numeric feature")
        values.append(value)
    return values, unknowns


def eligible(result):
    admitted = result["status"].startswith("admitted_")
    require(admitted == (result["binary_label"] is not None), "Inconsistent audit admission")
    if admitted:
        require(type(result["binary_label"]) is int and result["binary_label"] in (0, 1), "Invalid label")
        require(bool(result["admitted_reference_ids"]), "Missing admitted reference evidence")
        require(all(result["reference_validation_states"].get(r) == "verified"
                    for r in result["admitted_reference_ids"]), "Unverified admitted reference")
    return admitted


def table_files(directory, rows, metadata):
    """Missing cells remain empty; row position joins three separate artifacts."""
    with (directory / "features.csv").open("x", encoding="utf-8", newline="") as stream:
        writer = csv.writer(stream, lineterminator="\n")
        writer.writerow(FEATURE_NAMES)
        writer.writerows(rows)
    with (directory / "targets.csv").open("x", encoding="utf-8", newline="") as stream:
        writer = csv.writer(stream, lineterminator="\n")
        writer.writerow(["binary_label"])
        writer.writerows([[r["binary_label"]] for r in metadata])
    with (directory / "metadata.jsonl").open("x", encoding="utf-8", newline="\n") as stream:
        for record in metadata:
            stream.write(json.dumps(record, sort_keys=True, ensure_ascii=False, allow_nan=False) + "\n")


def build_dataset(directory, *, root=ROOT):
    directory, root = Path(directory), Path(root)
    directory.mkdir(parents=True, exist_ok=False)
    rows, metadata, source_manifest, census = [], [], [], {}
    for spec in SOURCES:
        name = spec["name"]
        paths = {"pcap": root / "data/raw" / spec["raw"] / spec["pcap"],
                 "labels": root / "data/raw" / spec["raw"] / "conn.log.labeled",
                 "provenance": root / "data/raw" / spec["raw"] / "provenance.json",
                 "extraction": root / "data/processed" / spec["processed"] / "extraction.json",
                 "audit": root / spec["audit"]}
        before = {role: sha256(path) for role, path in paths.items()}
        provenance = read_json(paths["provenance"])
        roles = {item["role"]: item for item in provenance["files"]}
        require(all(roles[role]["sha256"] == before[role] for role in ("pcap", "labels")), "Acquisition provenance binding failed")
        extraction, saved = read_json(paths["extraction"]), read_json(paths["audit"])
        require(extraction["extractor_version"] == EXTRACTOR_VERSION == "1.0.1", "Extractor version drift")
        require(extraction["schema_version"] == SCHEMA_VERSION, "Schema drift")
        require(extraction["feature_definitions"] == feature_definitions(), "Feature definition drift")
        require(extraction["configuration"] == ExtractionConfig().to_dict(), "Configuration drift")
        require("4.6.9" in extraction["backend"]["version"], "Unexpected extraction TShark version")
        require(extraction["source"]["sha256"] == before["pcap"], "Capture binding failed")
        imported = import_zeek_labels(paths["labels"])
        evidence = read_packet_evidence(paths["pcap"])
        fresh = audit_packet_correspondences(extraction, imported, evidence)
        require(all(saved.get(key) == value for key, value in fresh.items()), "Saved/fresh auditor results differ")
        require(fresh["label_source"]["sha256"] == before["labels"], "Label source binding failed")
        refs = {r["reference_id"]: r for r in imported["records"]}
        correspondence = {r["flow_id"]: r for r in fresh["flow_correspondences"]}
        require(len(correspondence) == len(extraction["flows"]), "Duplicate or missing flow correspondence")
        pure = defaultdict(lambda: True)
        for packet in fresh["packet_ledger"]:
            fid = packet["extraction_flow_id"]
            if fid is not None:
                pure[fid] &= (packet["protocol"] == "tcp" and packet["tcp_flags"] == 2 and packet["payload_bytes"] == 0)
        start = len(metadata)
        for flow in sorted(extraction["flows"], key=lambda f: f["ordinal"]):
            result = correspondence[flow["flow_id"]]
            if not eligible(result):
                continue
            values, unknowns = feature_row(flow)
            records = [refs[r] for r in result["admitted_reference_ids"]]
            require(all(r["binary_label"] == result["binary_label"] and not r["contradictions"]
                        for r in records), "Contradictory admitted labels")
            protocol = flow["features"]["transport_protocol"]["value"]
            metadata.append({"row_index": len(rows), "flow_id": flow["flow_id"], "capture": name,
                "capture_group_id": result["capture_group_id"], "connection_group_id": result["connection_group_id"],
                "binary_label": result["binary_label"], "protocol": protocol,
                "label_original": sorted({r["label_original"] for r in records}),
                "label_normalized": sorted({r["label_normalized"] for r in records}),
                "references": [{k: r[k] for k in ("reference_id", "uid", "source_line", "label_original", "label_normalized", "detailed_label")} for r in records],
                "source_sha256": before, "quality": flow["quality"], "close_reason": flow["close_reason"],
                "feature_unknown_reasons": unknowns, "audit_status": result["status"], "audit_reason": result["reason"],
                "packet_frames": flow["packet_frames"], "forward_endpoint": flow["forward_endpoint"],
                "reverse_endpoint": flow["reverse_endpoint"],
                "first_timestamp_epoch_ns": flow["first_timestamp_epoch_ns"],
                "last_timestamp_epoch_ns": flow["last_timestamp_epoch_ns"],
                "behavior_flow": "udp" if protocol == "udp" else "tcp_pure_syn" if pure[flow["flow_id"]] else "tcp_other"})
            rows.append(values)
        current = metadata[start:]
        groups = {m["connection_group_id"] for m in current}
        counts = Counter(m["binary_label"] for m in current)
        require((len(current), counts[0], counts[1], len(groups)) ==
                (spec["flows"], spec["benign"], spec["malicious"], spec["groups"]), "Corpus count drift")
        census[name] = {"admitted_flows": len(current), "benign": counts[0], "malicious": counts[1],
                        "groups": len(groups), "audit_summary": fresh["summary"], "fresh_audit_identical": True}
        require(all(sha256(path) == before[role] for role, path in paths.items()), "Source changed during dataset construction")
        source_manifest.append({"capture": name, "provenance": provenance, "files": [{"role": role, "path": path.relative_to(root).as_posix(),
                               "sha256": before[role], "size_bytes": path.stat().st_size} for role, path in paths.items()]})
    groups = defaultdict(list)
    for m in metadata:
        groups[m["connection_group_id"]].append(m)
    for members in groups.values():
        require(len({m["capture_group_id"] for m in members}) == len({m["binary_label"] for m in members}) == 1,
                "Group spans captures or incompatible labels")
        group_behavior = ("udp" if members[0]["protocol"] == "udp" else
                          "tcp_pure_syn" if all(m["behavior_flow"] == "tcp_pure_syn" for m in members) else "tcp_other")
        for m in members:
            m["behavior_group"] = group_behavior
            m["group_admitted_segment_count"] = len(members)
    require(len(rows) == 9839 and len(groups) == 7794, "Unexpected complete corpus size")
    require(len({m["flow_id"] for m in metadata}) == len(rows), "Duplicate flow IDs")
    table_files(directory, rows, metadata)
    files = {name: sha256(directory / name) for name in ("features.csv", "targets.csv", "metadata.jsonl")}
    reasons = Counter(reason for m in metadata for reason in m["feature_unknown_reasons"].values())
    manifest = {"dataset_version": "sipymes.pcap-table.v1", "rows": len(rows), "groups": len(groups),
                "predictors": list(FEATURE_NAMES), "predictor_count": len(FEATURE_NAMES),
                "schema_version": SCHEMA_VERSION, "extractor_version": EXTRACTOR_VERSION,
                "protocol_encoding_version": PROTOCOL_VERSION, "protocol_encoding": PROTOCOL_ENCODING,
                "missing": "empty cells, no invented zeros; reasons in metadata; model consumes NaN",
                "excluded": {"torii": 4, "hue": 93, "trojan_42_1": "entire capture; zero rows"},
                "census": census, "unknown_reason_counts": dict(reasons), "sources": source_manifest,
                "files_sha256": files,
                "feature_unknown_counts": dict(Counter(k for m in metadata for k in m["feature_unknown_reasons"]))}
    write_json(directory / "manifest.json", manifest)
    return manifest


def load_dataset(directory):
    directory = Path(directory)
    manifest = read_json(directory / "manifest.json")
    require(manifest["predictors"] == list(FEATURE_NAMES) and manifest["predictor_count"] == 38, "Predictor contract mismatch")
    require(manifest["protocol_encoding_version"] == PROTOCOL_VERSION and manifest["protocol_encoding"] == PROTOCOL_ENCODING,
            "Protocol encoding mismatch")
    for name, expected in manifest["files_sha256"].items():
        require(name in {"features.csv", "targets.csv", "metadata.jsonl"}, "Unexpected dataset artifact")
        require(sha256(directory / name) == expected, "Dataset artifact hash mismatch")
    require(set(manifest["files_sha256"]) == {"features.csv", "targets.csv", "metadata.jsonl"}, "Missing dataset artifacts")
    with (directory / "features.csv").open(encoding="utf-8", newline="") as f:
        reader = csv.reader(f)
        require(next(reader) == list(FEATURE_NAMES), "Predictor columns are not the exact allowlist")
        values = []
        for row in reader:
            require(len(row) == 38, "Wrong feature width")
            require(all(cell == "" or math.isfinite(float(cell)) for cell in row), "Nonfinite serialized value")
            values.append([float(v) if v != "" else np.nan for v in row])
        X = np.array(values, dtype=np.float64)
    with (directory / "targets.csv").open(encoding="utf-8", newline="") as f:
        reader = csv.reader(f)
        require(next(reader) == ["binary_label"], "Unexpected target columns")
        target_rows = list(reader)
        require(all(row in (["0"], ["1"]) for row in target_rows), "Invalid target")
        y = np.array([int(row[0]) for row in target_rows], dtype=np.int64)
    with (directory / "metadata.jsonl").open(encoding="utf-8") as f:
        metadata = [json.loads(line) for line in f]
    require(len(X) == len(y) == len(metadata) == manifest["rows"], "Row alignment mismatch")
    for i, m in enumerate(metadata):
        require(m["row_index"] == i and m["binary_label"] == int(y[i]), "Metadata/target alignment mismatch")
        require(X[i, FEATURE_NAMES.index("transport_protocol")] == PROTOCOL_ENCODING[m["protocol"]], "Protocol alignment mismatch")
        require(set(m["feature_unknown_reasons"]) == {name for name, v in zip(FEATURE_NAMES, X[i]) if np.isnan(v)},
                "Missing reasons do not match missing predictors")
    return X, y, metadata, manifest
