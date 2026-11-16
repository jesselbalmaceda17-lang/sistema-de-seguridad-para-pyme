"""Retain actual unit-test, replay and protected-integrity evidence."""

import argparse
from contextlib import closing, redirect_stderr, redirect_stdout
from datetime import datetime, timezone
import json
from pathlib import Path
import sqlite3
import time
import unittest
import zipfile

from pcap_experiment.common import ROOT, read_json, require, sha256, write_json


def tests(scope, output):
    output = Path(output)
    started = time.perf_counter()
    with output.with_suffix(".log").open("x", encoding="utf-8") as log, redirect_stdout(log), redirect_stderr(log):
        suite = (unittest.defaultTestLoader.loadTestsFromName("tests.test_pcap_experiment") if scope == "specific"
                 else unittest.defaultTestLoader.discover(str(ROOT / "tests")))
        result = unittest.TextTestRunner(stream=log, verbosity=2).run(suite)
    report = {"checked_at_utc": datetime.now(timezone.utc).isoformat(), "scope": scope,
        "tests_run": result.testsRun,
        "passed": result.testsRun-len(result.failures)-len(result.errors)-len(result.skipped)-len(result.expectedFailures)-len(result.unexpectedSuccesses),
        "failures": len(result.failures), "errors": len(result.errors), "skipped": len(result.skipped),
        "expected_failures": len(result.expectedFailures), "unexpected_successes": len(result.unexpectedSuccesses),
        "successful": result.wasSuccessful(), "wall_seconds": time.perf_counter()-started,
        "failure_details": [(str(t), detail) for t, detail in result.failures],
        "error_details": [(str(t), detail) for t, detail in result.errors],
        "skipped_details": [(str(t), detail) for t, detail in result.skipped],
        "log_sha256": sha256(output.with_suffix(".log"))}
    write_json(output.with_suffix(".json"), report)
    return report


def integrity(backup_evidence, output):
    backup = read_json(backup_evidence)
    checked, sqlite_checks = [], []
    for item in backup["baseline"]:
        path = ROOT / item["path"]
        require(path.is_file() and sha256(path) == item["source_sha256"], "Protected file changed: "+item["path"])
        checked.append({"path": item["path"], "sha256": item["source_sha256"]})
        if path.suffix == ".sqlite3":
            with closing(sqlite3.connect(path.as_uri()+"?mode=ro", uri=True)) as db:
                state = db.execute("PRAGMA integrity_check").fetchall()
            require(state == [("ok",)] and sha256(path) == item["source_sha256"], "SQLite integrity failed")
            sqlite_checks.append({"path": item["path"], "integrity_check": "ok", "sha256_unchanged": True})
    archive = ROOT / backup["archive"]
    require(sha256(archive) == backup["archive_sha256"], "Backup changed")
    with zipfile.ZipFile(archive) as z:
        require(z.testzip() is None, "Backup CRC failed")
    report = {"checked_at_utc": datetime.now(timezone.utc).isoformat(), "protected_files": len(checked),
              "all_unchanged": True, "files": checked, "sqlite": sqlite_checks,
              "backup_sha256": backup["archive_sha256"], "backup_crc_valid": True,
              "restoration_previously_verified_files": backup["restored_files_verified"]}
    write_json(output, report)
    return report


def replay(first, second, output):
    first, second = Path(first), Path(second)
    checks = {}
    for name in ("prespecified.json", "dataset/manifest.json", "dataset/features.csv", "dataset/targets.csv", "dataset/metadata.jsonl"):
        checks[name] = sha256(first/name) == sha256(second/name)
    for capture in ("torii", "hakai", "hue"):
        for method in ("dummy", "tcp_rule", "syn_no_ack_rule", "random_forest"):
            prefix = "held_out_"+capture+"/"+method
            for suffix in ("_predictions.csv", "_group_predictions.json", ".joblib"):
                name = prefix+suffix
                checks[name] = sha256(first/name) == sha256(second/name)
        a = read_json(first/("held_out_"+capture)/"results.json")
        b = read_json(second/("held_out_"+capture)/"results.json")
        for method in a["models"]:
            checks[capture+"/"+method+"/metrics"] = a["models"][method]["metrics"] == b["models"][method]["metrics"]
    report = {"checked_at_utc": datetime.now(timezone.utc).isoformat(),
              "checks": checks, "all_identical": all(checks.values()),
              "excluded_from_identity": "wall/CPU time, sampled memory and execution timestamps; intentionally measured anew"}
    write_json(output, report)
    require(report["all_identical"], "Replay is not byte-identical; inspect evidence before claiming reproducibility")
    return report


def model_roundtrip(run_directory, output):
    """Only call for this session's own newly trained and hash-verified artifacts."""
    import csv
    import joblib
    import numpy as np
    from pcap_experiment.dataset import load_dataset
    from pcap_experiment.models import positive_scores
    run_directory = Path(run_directory)
    results = read_json(run_directory / "results.json")
    X, _, metadata, _ = load_dataset(run_directory / "dataset")
    checks = []
    for capture, fold in results["folds"].items():
        indices = [i for i, m in enumerate(metadata) if m["capture"] == capture]
        for method, report in fold["models"].items():
            path = run_directory / report["model"]["path"]
            require(path.resolve().is_relative_to(run_directory.resolve()), "Model outside this run")
            require(sha256(path) == report["model"]["sha256"], "Local model hash changed")
            model = joblib.load(path)
            require(model.n_features_in_ == 38, "Serialized pipeline changed predictor width")
            scores = positive_scores(model, X[indices])
            with (run_directory / ("held_out_"+capture) / (method+"_predictions.csv")).open(encoding="utf-8") as stream:
                expected = np.array([float(row["probability_malicious"]) for row in csv.DictReader(stream)])
            require(np.array_equal(scores, expected), "Serialized model changed predictions")
            checks.append({"capture": capture, "model": method, "sha256": sha256(path),
                           "predictions_exact": True, "predictors": 38})
    report = {"models_checked": len(checks), "all_predictions_exact": True, "checks": checks,
              "trust": "locally created in this session; SHA verified before loading; never use for unknown joblib files"}
    write_json(output, report)
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("scope", choices=("specific", "full"))
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = tests(args.scope, args.output)
    print(json.dumps(report, indent=2))
    raise SystemExit(0 if report["successful"] else 1)
