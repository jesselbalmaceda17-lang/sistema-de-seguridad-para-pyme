"""Explicit undefined metrics, complete-capture isolation, and complete-group aggregation."""

from collections import defaultdict
import math
import numpy as np
from sklearn.metrics import average_precision_score

from pcap_experiment.common import require
from pcap_experiment.contract import THRESHOLD


def metric_report(y, probabilities):
    y, p = np.asarray(y, dtype=int), np.asarray(probabilities, dtype=float)
    require(y.shape == p.shape and y.ndim == 1 and np.isin(y, [0, 1]).all(), "Invalid metric labels")
    require(np.isfinite(p).all() and ((p >= 0) & (p <= 1)).all(), "Invalid prediction probabilities")
    pred = p >= THRESHOLD
    tn = int(((y == 0) & ~pred).sum()); fp = int(((y == 0) & pred).sum())
    fn = int(((y == 1) & ~pred).sum()); tp = int(((y == 1) & pred).sum())
    negative, positive = tn+fp, tp+fn
    undefined = {}

    def ratio(key, numerator, denominator, reason):
        if not denominator:
            undefined[key] = reason
            return None
        return numerator / denominator

    precision = ratio("precision_malicious", tp, tp+fp, "no_predicted_malicious")
    recall = ratio("recall_malicious", tp, positive, "no_true_malicious")
    fpr = ratio("false_positive_rate", fp, negative, "no_true_benign")
    if positive:
        f1 = 2*tp/(2*tp+fp+fn)
    else:
        f1 = None
        undefined["f1_malicious"] = "no_true_malicious"
    if positive and negative:
        balanced = (tp/positive + tn/negative)/2
        ap = float(average_precision_score(y, p))
    else:
        balanced = ap = None
        undefined["balanced_accuracy"] = undefined["pr_auc_average_precision"] = "both_true_classes_required"
    return {"n": len(y), "benign": negative, "malicious": positive,
            "confusion_matrix_true_rows_predicted_columns_B_M": [[tn, fp], [fn, tp]],
            "precision_malicious": precision, "recall_malicious": recall,
            "f1_malicious": f1, "false_positive_rate": fpr,
            "balanced_accuracy": balanced, "pr_auc_average_precision": ap,
            "undefined_reasons": undefined}


def split_indices(metadata, specification):
    train_names, test_name = set(specification["train"]), specification["test"]
    require(test_name not in train_names, "Capture leakage")
    train = np.array([i for i, m in enumerate(metadata) if m["capture"] in train_names], dtype=int)
    test = np.array([i for i, m in enumerate(metadata) if m["capture"] == test_name], dtype=int)
    require(len(train) > 0 and len(test) > 0, "Empty partition")
    for field in ("connection_group_id", "capture_group_id", "flow_id"):
        require(not {metadata[i][field] for i in train}.intersection(metadata[i][field] for i in test),
                f"Partition leakage through {field}")
    require(len(train)+len(test) == len(metadata), "Partition omits or overlaps rows")
    return train, test


def aggregate_groups(metadata, probabilities):
    require(len(metadata) == len(probabilities), "Group probability alignment mismatch")
    by_group = defaultdict(list)
    for m, p in zip(metadata, probabilities):
        by_group[m["connection_group_id"]].append((m, float(p)))
    result = []
    for gid, members in sorted(by_group.items()):
        first = members[0][0]
        for field in ("binary_label", "capture", "capture_group_id", "protocol", "behavior_group"):
            require(len({m[field] for m, _ in members}) == 1, f"Incompatible group {field}")
        require(len({m["flow_id"] for m, _ in members}) == len(members), "Duplicate group segment")
        require(all(m["group_admitted_segment_count"] == len(members) for m, _ in members), "Incomplete group aggregation")
        probabilities = [p for _, p in members]
        # An average of identical numbers must remain exactly that number.
        # Summing repeated float priors can otherwise break AP ties by group size.
        score = (probabilities[0] if all(p == probabilities[0] for p in probabilities)
                 else math.fsum(probabilities) / len(probabilities))
        result.append({"connection_group_id": gid, "capture": first["capture"],
                       "binary_label": first["binary_label"], "protocol": first["protocol"],
                       "behavior": first["behavior_group"], "segments": len(members),
                       "probability_malicious": score, "prediction": int(score >= THRESHOLD)})
    return result


def evaluate_views(metadata, probabilities):
    groups = aggregate_groups(metadata, probabilities)
    flow_records = [{"binary_label": m["binary_label"], "protocol": m["protocol"],
                     "behavior": m["behavior_flow"], "probability_malicious": float(p)}
                    for m, p in zip(metadata, probabilities)]
    views = {}
    for unit, records in (("flow", flow_records), ("group", groups)):
        output = {}
        for name in ("all", "tcp", "udp", "tcp_pure_syn", "tcp_other"):
            selected = [r for r in records if name == "all" or r["protocol"] == name or r["behavior"] == name]
            output[name] = metric_report([r["binary_label"] for r in selected], [r["probability_malicious"] for r in selected])
        views[unit] = output
    return views, groups


def paired_comparison(y, forest, baseline):
    y = np.array(y); rf = np.array(forest) >= THRESHOLD; rule = np.array(baseline) >= THRESHOLD
    return {"n": len(y), "prediction_agreement": float(np.mean(rf == rule)),
            "both_correct": int(((rf == y) & (rule == y)).sum()),
            "rf_only_correct": int(((rf == y) & (rule != y)).sum()),
            "baseline_only_correct": int(((rf != y) & (rule == y)).sum()),
            "both_wrong": int(((rf != y) & (rule != y)).sum())}
