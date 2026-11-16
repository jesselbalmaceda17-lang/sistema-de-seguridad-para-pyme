"""Persist actual unittest results; fixture training tests use temporary data only."""
from contextlib import redirect_stdout, redirect_stderr
from datetime import datetime, timezone
import json
import sys
import time
import unittest

from ejecutar_etapa import ROOT, EVIDENCE, save_json

scope = sys.argv[1]
if scope not in {"especificas", "completas"}:
    raise ValueError("Expected especificas or completas")
started = datetime.now(timezone.utc).isoformat()
timer = time.perf_counter()
pattern = "test_iot23_acquisition_compatibility.py" if scope == "especificas" else "test*.py"
with (EVIDENCE / ("pruebas_" + scope + ".log")).open("x", encoding="utf-8") as log:
    with redirect_stdout(log), redirect_stderr(log):
        suite = unittest.defaultTestLoader.discover(str(ROOT / "tests"), pattern=pattern)
        result = unittest.TextTestRunner(stream=log, verbosity=2).run(suite)
report = {"started_at_utc": started, "finished_at_utc": datetime.now(timezone.utc).isoformat(),
    "wall_seconds": time.perf_counter()-timer, "pattern": pattern,
    "tests_run": result.testsRun,
    "passed": result.testsRun-len(result.failures)-len(result.errors)-len(result.skipped)-len(result.expectedFailures)-len(result.unexpectedSuccesses),
    "failures": len(result.failures), "errors": len(result.errors), "skipped": len(result.skipped),
    "expected_failures": len(result.expectedFailures), "unexpected_successes": len(result.unexpectedSuccesses),
    "successful": result.wasSuccessful(), "failure_details": [(str(t), message) for t, message in result.failures],
    "error_details": [(str(t), message) for t, message in result.errors],
    "skipped_details": [(str(t), message) for t, message in result.skipped]}
save_json(EVIDENCE / ("resultado_" + scope + ".json"), report)
print(json.dumps(report, indent=2))
raise SystemExit(0 if result.wasSuccessful() else 1)
