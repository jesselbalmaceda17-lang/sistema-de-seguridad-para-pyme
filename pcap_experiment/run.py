"""Reproduce all three exploratory folds; exclusively creates a new output directory."""

import argparse
import csv
from datetime import datetime, timezone
import importlib.metadata
import platform
from pathlib import Path
import threading
import time
import traceback

import joblib
import numpy as np
import psutil

from pcap_experiment.common import ROOT, require, sha256, write_json
from pcap_experiment.contract import FEATURE_NAMES, SPECIFICATION, THRESHOLD
from pcap_experiment.dataset import build_dataset, load_dataset
from pcap_experiment.evaluation import evaluate_views, paired_comparison, split_indices
from pcap_experiment.models import make_models, positive_scores, training_weights


class Measurement:
    """Sampled process RSS, not an exact allocation peak or whole-system RAM."""
    def __enter__(self):
        self.process = psutil.Process()
        self.baseline = self.maximum = self.process.memory_info().rss
        self.samples = 1
        self.stop = threading.Event()
        self.started = time.perf_counter()
        self.cpu_started = sum(self.process.cpu_times()[:2])

        def sample():
            while not self.stop.wait(0.01):
                self.maximum = max(self.maximum, self.process.memory_info().rss)
                self.samples += 1
        self.thread = threading.Thread(target=sample, daemon=True)
        self.thread.start()
        return self

    def __exit__(self, *args):
        self.stop.set(); self.thread.join()
        self.maximum = max(self.maximum, self.process.memory_info().rss)
        self.result = {"wall_seconds": time.perf_counter()-self.started,
                       "cpu_seconds": sum(self.process.cpu_times()[:2])-self.cpu_started,
                       "rss_baseline_bytes": self.baseline, "sampled_rss_peak_bytes": self.maximum,
                       "sampled_rss_increase_bytes": self.maximum-self.baseline,
                       "sampling_interval_seconds": 0.01, "samples": self.samples,
                       "memory_method": "sampled Python process working set; includes resident data and previous fits; not an exact per-model allocation peak"}


def predictions_file(path, metadata, probabilities):
    with path.open("x", encoding="utf-8", newline="") as f:
        writer = csv.writer(f, lineterminator="\n")
        writer.writerow(["row_index", "flow_id", "connection_group_id", "binary_label", "probability_malicious", "prediction"])
        for m, p in zip(metadata, probabilities):
            writer.writerow([m["row_index"], m["flow_id"], m["connection_group_id"], m["binary_label"], float(p), int(p >= THRESHOLD)])


def run_experiment(output):
    output = Path(output)
    output.mkdir(parents=True, exist_ok=False)
    started = datetime.now(timezone.utc).isoformat()
    # Persist the contract before constructing data or evaluating any model.
    write_json(output / "prespecified.json", SPECIFICATION)
    environment = {"python": platform.python_version(), "platform": platform.platform(),
        "versions": {name: importlib.metadata.version(name) for name in ("numpy", "scikit-learn", "joblib", "psutil")},
        "code_sha256": {p.relative_to(ROOT).as_posix(): sha256(p) for p in sorted((ROOT / "pcap_experiment").glob("*.py"))},
        "physical_memory_bytes": psutil.virtual_memory().total,
        "available_memory_before_bytes": psutil.virtual_memory().available,
        "thread_policy": "Random Forest n_jobs=1; seed fixed; no hyperparameter search"}
    write_json(output / "environment.json", environment)
    try:
        with Measurement() as dataset_measurement:
            manifest = build_dataset(output / "dataset")
            X, y, metadata, _ = load_dataset(output / "dataset")
        folds = {}
        for split in SPECIFICATION["splits"]:
            test_name = split["test"]
            directory = output / ("held_out_" + test_name)
            directory.mkdir()
            train, test = split_indices(metadata, split)
            require(set(y[train]) == {0, 1}, "Training partition needs both known classes")
            train_meta = [metadata[i] for i in train]; test_meta = [metadata[i] for i in test]
            weights = training_weights(train_meta)
            split_manifest = {"train_captures": split["train"], "test_capture": test_name,
                "train_rows": len(train), "test_rows": len(test),
                "train_group_count": len({m["connection_group_id"] for m in train_meta}),
                "test_group_count": len({m["connection_group_id"] for m in test_meta}),
                "train_row_indices": train.tolist(), "test_row_indices": test.tolist(),
                "train_connection_groups": sorted({m["connection_group_id"] for m in train_meta}),
                "test_connection_groups": sorted({m["connection_group_id"] for m in test_meta}),
                "connection_and_capture_groups_disjoint": True,
                "weight_min": float(weights.min()), "weight_max": float(weights.max()),
                "weight_sum": float(weights.sum())}
            write_json(directory / "split.json", split_manifest)
            reports, scores, group_outputs = {}, {}, {}
            for name, model in make_models().items():
                with Measurement() as fit:
                    model.fit(X[train], y[train], classifier__sample_weight=weights)
                with Measurement() as inference:
                    p = positive_scores(model, X[test])
                scores[name] = p
                views, groups = evaluate_views(test_meta, p)
                group_outputs[name] = groups
                model_path = directory / (name + ".joblib")
                with model_path.open("xb") as stream:
                    joblib.dump(model, stream, compress=3)
                predictions_file(directory / (name + "_predictions.csv"), test_meta, p)
                write_json(directory / (name + "_group_predictions.json"), groups)
                report = {"metrics": views, "training": fit.result, "inference": inference.result,
                    "model": {"path": model_path.relative_to(output).as_posix(), "size_bytes": model_path.stat().st_size,
                              "sha256": sha256(model_path), "training_captures": split["train"]},
                    "native_missing_values": name == "random_forest"}
                if name == "random_forest":
                    importance = model.named_steps["classifier"].feature_importances_
                    report["impurity_importance_not_causal"] = dict(zip(FEATURE_NAMES, map(float, importance)))
                    report["importance_protocol"] = float(importance[FEATURE_NAMES.index("transport_protocol")])
                    report["importance_tcp_flags_sum"] = float(sum(v for k, v in zip(FEATURE_NAMES, importance) if "_tcp_" in k))
                reports[name] = report
                print(test_name, name, "flow", views["flow"]["all"], "group", views["group"]["all"], flush=True)
            comparisons = {}
            for name in ("dummy", "tcp_rule", "syn_no_ack_rule"):
                rf_groups, baseline_groups = group_outputs["random_forest"], group_outputs[name]
                comparisons[name] = {
                    "flow": paired_comparison(y[test], scores["random_forest"], scores[name]),
                    "group": paired_comparison([r["binary_label"] for r in rf_groups],
                        [r["probability_malicious"] for r in rf_groups],
                        [r["probability_malicious"] for r in baseline_groups])}
            folds[test_name] = {"models": reports, "paired_rf_comparisons": comparisons}
            write_json(directory / "results.json", folds[test_name])
        result = {"experiment_version": SPECIFICATION["version"], "started_at_utc": started,
            "finished_at_utc": datetime.now(timezone.utc).isoformat(),
            "prespecified_sha256": sha256(output / "prespecified.json"),
            "dataset_manifest_sha256": sha256(output / "dataset/manifest.json"),
            "dataset_files_sha256": manifest["files_sha256"], "dataset_preparation_resources": dataset_measurement.result,
            "folds": folds, "scope": SPECIFICATION["scope"],
            "final_all_capture_model": "not trained; only three fold models per method; no model selection"}
        write_json(output / "results.json", result)
        return result
    except Exception as error:
        write_json(output / "failure.json", {"type": type(error).__name__, "message": str(error), "traceback": traceback.format_exc()})
        raise


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True, help="New directory; existing outputs are never overwritten")
    run_experiment(parser.parse_args().output)
