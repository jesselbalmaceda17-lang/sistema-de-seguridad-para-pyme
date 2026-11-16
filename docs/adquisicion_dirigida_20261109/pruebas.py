"""Run relevant acquisition checks and the unchanged original complete suite."""
from contextlib import redirect_stdout, redirect_stderr
from datetime import datetime, timezone
from pathlib import Path
import sys
import time
import unittest

ROOT = Path(__file__).resolve().parents[2]
OUT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
from proteccion import save, sha

scope = sys.argv[1]
assert scope in ('specific', 'full')
start = time.perf_counter()
path = OUT / ('pruebas_' + scope + '.log')
with path.open('x', encoding='utf-8') as log, redirect_stdout(log), redirect_stderr(log):
    suite = (unittest.defaultTestLoader.loadTestsFromNames([
        'pruebas_analisis', 'tests.test_pcap_extraction', 'tests.test_label_audit',
        'tests.test_label_reconciliation', 'tests.test_zeek_label_normalization',
        'tests.test_iot23_acquisition_compatibility', 'tests.test_corpus_expansion'])
        if scope == 'specific' else unittest.defaultTestLoader.discover(str(ROOT / 'tests')))
    result = unittest.TextTestRunner(stream=log, verbosity=2).run(suite)
report = {'scope': scope, 'finished_at_utc': datetime.now(timezone.utc).isoformat(),
    'tests_run': result.testsRun, 'passed': result.testsRun-len(result.failures)-len(result.errors)-len(result.skipped),
    'failures': len(result.failures), 'errors': len(result.errors), 'skipped': len(result.skipped),
    'expected_failures': len(result.expectedFailures), 'unexpected_successes': len(result.unexpectedSuccesses),
    'successful': result.wasSuccessful(), 'wall_seconds': time.perf_counter()-start,
    'failure_details': [(str(t), detail) for t, detail in result.failures],
    'error_details': [(str(t), detail) for t, detail in result.errors],
    'log_sha256': sha(path),
    'training_scope': 'No training on acquired or real project data. The unchanged full regression suite includes synthetic temporary model-fitting fixtures; existing project models are never replaced.'}
save(OUT / ('pruebas_' + scope + '.json'), report)
print(__import__('json').dumps(report, indent=2))
raise SystemExit(0 if result.wasSuccessful() else 1)
