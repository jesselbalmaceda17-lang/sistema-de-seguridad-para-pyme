"""Independent, loss-aware importer for Zeek ASCII and IoT-23 labeled conn logs."""

from collections import Counter, defaultdict
from decimal import Decimal, InvalidOperation
import hashlib
import ipaddress
from pathlib import Path
import re


IMPORT_VERSION = "sipymes.zeek-labels.v1.1"
REQUIRED_FIELDS = {"ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto", "label"}
LABELS = {"Benign": 0, "Malicious": 1}
# Exact literals verified in the retained IoT-23 20-1, 8-1 and Hue 4-1 logs.
# Do not casefold, strip, infer from the capture, or accept undocumented aliases.
LABEL_NORMALIZATION_VERSION = "sipymes.iot23.label-aliases.v1"
LABEL_ALIASES = {"Benign": "Benign", "Malicious": "Malicious", "benign": "Benign"}
COUNT_FIELDS = ("orig_pkts", "resp_pkts", "orig_ip_bytes", "resp_ip_bytes")


def _time_ns(value):
    number = Decimal(value) * 1_000_000_000
    if not number.is_finite() or number < 0 or number > 9_000_000_000_000_000_000 or number != number.to_integral_value():
        raise ValueError("Time must be finite, nonnegative and have nanosecond precision")
    return str(int(number))


def reference_key(record):
    values = (record["protocol"], record["orig_ip"], record["orig_port"], record["resp_ip"], record["resp_port"])
    if any(value is None for value in values):
        return None
    return values[0], tuple(sorted(((values[1], values[2]), (values[3], values[4]))))


def _record(raw, line, source_hash, unset, empty):
    problems = {}

    def value(name, parser=str):
        if name not in raw:
            problems[name] = "missing_column"
            return None
        if raw[name] == unset:
            problems[name] = "unset"
            return None
        if raw[name] in {empty, ""}:
            problems[name] = "empty"
            return None
        try:
            return parser(raw[name])
        except (ValueError, InvalidOperation, OverflowError):
            problems[name] = "invalid_value"
            return None

    def port(text):
        number = int(text)
        if not 0 <= number <= 65535:
            raise ValueError("Invalid port")
        return number

    def count(text):
        number = int(text)
        if number < 0:
            raise ValueError("Invalid count")
        return number

    record = {
        "reference_id": hashlib.sha256(f"{source_hash}:{line}".encode()).hexdigest(),
        "source_line": line, "uid": value("uid"),
        "start_epoch_ns": value("ts", _time_ns), "duration_ns": value("duration", _time_ns),
        "orig_ip": value("id.orig_h", lambda x: str(ipaddress.ip_address(x))),
        "orig_port": value("id.orig_p", port),
        "resp_ip": value("id.resp_h", lambda x: str(ipaddress.ip_address(x))),
        "resp_port": value("id.resp_p", port), "protocol": value("proto"),
        "label_original": value("label"), "detailed_label": value("detailed-label"),
        "raw_fields": raw, "field_problems": problems,
    }
    for name in COUNT_FIELDS:
        record[name] = value(name, count)
    record["label_normalized"] = LABEL_ALIASES.get(record["label_original"])
    record["binary_label"] = LABELS.get(record["label_normalized"])
    record["contradictions"] = []
    if record["binary_label"] is None:
        problems["label"] = problems.get("label", "unrecognized_label")
    if record["binary_label"] == 0 and record["detailed_label"] not in (None, "Benign"):
        record["contradictions"].append("benign_label_with_nonbenign_detail")
    return record


def import_zeek_labels(path):
    path = Path(path).resolve()
    content = path.read_bytes()
    source_hash = hashlib.sha256(content).hexdigest()
    separator, unset, empty = "\t", "-", "(empty)"
    fields, types, records, rejected = None, None, [], []
    mixed_tail = False
    close_marker = False
    for line_number, line in enumerate(content.decode("utf-8-sig").splitlines(), 1):
        if line.startswith("#separator "):
            if fields is not None:
                raise ValueError("Concatenated Zeek logs must be imported separately")
            specification = line[len("#separator "):]
            if specification not in (r"\x09", r"\x2c", r"\x7c"):
                raise ValueError("Unsupported Zeek field separator")
            separator = bytes.fromhex(specification[2:]).decode("ascii")
        elif line.startswith("#unset_field" + separator):
            unset = line.split(separator, 1)[1]
        elif line.startswith("#empty_field" + separator):
            empty = line.split(separator, 1)[1]
        elif line.startswith("#fields" + separator):
            if fields is not None:
                raise ValueError("Repeated field headers are not supported")
            fields = line.split(separator)[1:]
            tail = re.split(r" {2,}", fields[-1])
            if len(tail) > 1:
                if tail != ["tunnel_parents", "label", "detailed-label"]:
                    raise ValueError("Unknown mixed-delimiter header")
                fields[-1:] = tail
                mixed_tail = True
            if len(fields) != len(set(fields)) or not REQUIRED_FIELDS.issubset(fields):
                raise ValueError("Missing or duplicate required Zeek field headers")
        elif line.startswith("#types" + separator):
            types = line.split(separator)[1:]
            if mixed_tail:
                types[-1:] = re.split(r" {2,}", types[-1])
            if fields is None or len(types) != len(fields):
                raise ValueError("Zeek type/field header mismatch")
            expected_types = {"ts": "time", "uid": "string", "duration": "interval",
                              "id.orig_h": "addr", "id.resp_h": "addr",
                              "id.orig_p": "port", "id.resp_p": "port", "proto": "enum",
                              "label": "string", "detailed-label": "string",
                              **{name: "count" for name in COUNT_FIELDS}}
            if any(name in expected_types and kind != expected_types[name] for name, kind in zip(fields, types)):
                raise ValueError("Unexpected type for a required label field")
        elif line.startswith("#close"):
            close_marker = True
        elif line.startswith("#") or not line:
            continue
        else:
            if fields is None or types is None:
                raise ValueError("Zeek #fields and #types must precede data")
            values = line.split(separator)
            if mixed_tail and len(values) == len(fields) - 2:
                values[-1:] = re.split(r" {2,}", values[-1], maxsplit=2)
            if len(values) != len(fields):
                rejected.append({"source_line": line_number, "reason": "field_count_mismatch",
                                 "raw_line_sha256": hashlib.sha256(line.encode()).hexdigest()})
                continue
            records.append(_record(dict(zip(fields, values)), line_number, source_hash, unset, empty))
    if fields is None or types is None:
        raise ValueError("No usable Zeek headers")

    uid_groups, interval_groups = defaultdict(list), defaultdict(list)
    for record in records:
        if record["uid"] is not None:
            uid_groups[record["uid"]].append(record)
        key = reference_key(record)
        if key is not None and record["start_epoch_ns"] is not None:
            interval_groups[(key, record["start_epoch_ns"], record["duration_ns"])].append(record)
    duplicates = []
    for uid, group in uid_groups.items():
        if len(group) > 1:
            signatures = {tuple(sorted(record["raw_fields"].items())) for record in group}
            duplicates.append({"uid": uid, "reference_ids": [r["reference_id"] for r in group],
                               "identical": len(signatures) == 1})
            if len(signatures) > 1:
                for record in group:
                    record["contradictions"].append("uid_reused_with_different_record")
    for group in interval_groups.values():
        labels = {(r["label_original"], r["detailed_label"]) for r in group if r["binary_label"] is not None}
        if len(labels) > 1:
            for record in group:
                record["contradictions"].append("conflicting_labels_for_same_tuple_and_interval")
    return {"import_version": IMPORT_VERSION,
            "label_normalization_policy": {"version": LABEL_NORMALIZATION_VERSION,
                "exact_aliases": dict(LABEL_ALIASES),
                "unknown": "unlisted literals remain null; originals and contradiction checks preserved"},
            "source": {"path": str(path),
            "sha256": source_hash, "size_bytes": len(content)},
            "header": {"fields": fields, "types": types, "separator": separator,
                       "unset_field": unset, "empty_field": empty, "iot23_mixed_tail": mixed_tail},
            "quality": {"records_imported": len(records), "rows_rejected": len(rejected),
                        "close_marker_present": close_marker,
                        "label_distribution": dict(Counter(r["label_original"] or "unknown" for r in records)),
                        "normalized_label_distribution": dict(Counter(r["label_normalized"] or "unknown" for r in records)),
                        "records_with_field_problems": sum(bool(r["field_problems"]) for r in records),
                        "records_with_contradictions": sum(bool(r["contradictions"]) for r in records)},
            "duplicate_uids": duplicates, "rejected_rows": rejected, "records": records}
