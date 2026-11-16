"""Run relevant tests before the full suite, retaining real logs and counters."""
from contextlib import redirect_stdout, redirect_stderr
from datetime import datetime, timezone
import json
from pathlib import Path
import sys
import time
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
OUTPUT = Path(__file__).resolve().parent
scope = sys.argv[1]
if scope not in {"especificas", "completas"}:
    raise ValueError("Expected especificas or completas")
start, started = time.perf_counter(), datetime.now(timezone.utc).isoformat()
with (OUTPUT / ("pruebas_" + scope + "_cierre.log")).open("x", encoding="utf-8") as log, redirect_stdout(log), redirect_stderr(log):
    suite = (unittest.defaultTestLoader.loadTestsFromNames([
        "tests.test_corpus_expansion", "tests.test_zeek_label_normalization", "tests.test_label_audit",
        "tests.test_label_reconciliation", "tests.test_iot23_acquisition_compatibility"])
        if scope == "especificas" else unittest.defaultTestLoader.discover(str(ROOT / "tests")))
    result = unittest.TextTestRunner(stream=log, verbosity=2).run(suite)
report = {"started_at_utc": started, "finished_at_utc": datetime.now(timezone.utc).isoformat(),
    "wall_seconds_including_discovery": time.perf_counter()-start, "tests_run": result.testsRun,
    "passed": result.testsRun-len(result.failures)-len(result.errors)-len(result.skipped)-len(result.expectedFailures)-len(result.unexpectedSuccesses),
    "failures": len(result.failures), "errors": len(result.errors), "skipped": len(result.skipped),
    "expected_failures": len(result.expectedFailures), "unexpected_successes": len(result.unexpectedSuccesses),
    "successful": result.wasSuccessful(), "failure_details": [(str(t), message) for t, message in result.failures],
    "error_details": [(str(t), message) for t, message in result.errors],
    "skipped_details": [(str(t), message) for t, message in result.skipped]}
with (OUTPUT / ("resultado_" + scope + "_cierre.json")).open("x", encoding="utf-8") as stream:
    json.dump(report, stream, indent=2)
print(json.dumps(report, indent=2))
raise SystemExit(0 if result.wasSuccessful() else 1)
