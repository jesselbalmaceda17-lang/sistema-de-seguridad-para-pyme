"""Bounded, isolated-process CSV load measurements; never fits a model."""
import argparse
import csv
from dataclasses import asdict
import hashlib
import io
import json
import math
import os
from pathlib import Path
import subprocess
import sys
import time

START = time.perf_counter()


def worker(package, csv_path, database, output):
    package = package.resolve()
    os.chdir(package)
    sys.path.insert(0, str(package))
    import psutil
    from unittest.mock import patch
    import seguridad_pymes.dashboard as dashboard
    import seguridad_pymes.inference as inference
    from seguridad_pymes.database import list_alerts, list_analysis_runs
    ready = time.perf_counter()
    for module in (dashboard, inference):
        assert Path(module.__file__).resolve().is_relative_to(package)
    stages = {}

    def timed(name, function):
        def wrapped(*args, **kwargs):
            started = time.perf_counter()
            try:
                return function(*args, **kwargs)
            finally:
                stages[name] = stages.get(name, 0) + time.perf_counter() - started
        return wrapped

    started = time.perf_counter()
    raw = csv_path.read_bytes()
    read = time.perf_counter() - started
    started = time.perf_counter()
    frame, headers = dashboard._read_uploaded_csv(io.BytesIO(raw))
    parsed = time.perf_counter() - started
    oracle = json.loads((package / 'demo/resultados_esperados.json').read_text(encoding='utf-8'))
    features = [name for name in headers if name != 'id']
    started = time.perf_counter()
    records, ids, _ = dashboard._prepare_uploaded_records(frame, headers, features, csv_path.name)
    prepared = time.perf_counter() - started
    with patch.object(inference, 'load_trained_model', timed('model_load_seconds', inference.load_trained_model)), \
         patch.object(inference, 'initialize_database', timed('sqlite_initialize_seconds', inference.initialize_database)), \
         patch.object(inference, 'create_analysis_run', timed('sqlite_create_run_seconds', inference.create_analysis_run)), \
         patch.object(inference, 'complete_analysis_run', timed('sqlite_complete_and_alerts_seconds', inference.complete_analysis_run)):
        started = time.perf_counter()
        result = inference.run_model_analysis(records, ids, source=csv_path.name, database_path=database)
        analysis = time.perf_counter() - started
    expected = [oracle['predictions'][index % 8] for index in range(len(ids))]
    assert list(result.predictions) == expected
    assert all(math.isclose(score, oracle['scores'][index % 8], rel_tol=0, abs_tol=1e-15)
               for index, score in enumerate(result.attack_scores))
    started = time.perf_counter()
    run = list_analysis_runs(database, limit=1)[0]
    alerts = list_alerts(database, run_id=result.run_id, limit=10000)
    query = time.perf_counter() - started
    assert result.alerts_created == sum(expected) == run['alerts_created']
    started = time.perf_counter()
    report = dashboard._prediction_report(result, ids, csv_path.name)
    csv_export = dashboard._csv_download_bytes(dashboard._prediction_report_for_display(report))
    json_export = json.dumps({'run': run, 'records': [
                                 {key: None if dashboard.pd.isna(value) else value for key, value in row.items()}
                                 for row in dashboard._prediction_report_for_display(report).to_dict(orient='records')],
                             'normal_predictions': len(ids) - sum(expected),
                             'suspicious_predictions': sum(expected),
                             'resource_measurement': asdict(result.resource_measurement),
                             'alerts': alerts, 'alerts_total': result.alerts_created,
                             'alerts_returned': len(alerts), 'alerts_limit': 10000,
                             'alerts_truncated': len(alerts) < result.alerts_created}, ensure_ascii=False, indent=2, default=str).encode()
    generated = time.perf_counter() - started
    import sqlite3
    from contextlib import closing
    with closing(sqlite3.connect(database)) as connection:
        assert connection.execute('SELECT COUNT(*) FROM alerts').fetchone()[0] == sum(expected)
        assert connection.execute('PRAGMA integrity_check').fetchone()[0] == 'ok'
    metrics = {'records': len(ids), 'input_bytes': len(raw), 'predicted_suspicious': sum(expected),
               'imports_and_start_seconds': ready - START, 'file_read_seconds': read,
               'csv_parse_seconds': parsed, 'csv_prepare_seconds': prepared,
               'analysis_total_seconds': analysis, **stages,
               'classification_including_scores_seconds': result.resource_measurement.elapsed_seconds,
               'inference_resources': asdict(result.resource_measurement),
               'sqlite_query_seconds': query, 'report_build_and_serialization_seconds': generated,
               'sqlite_bytes': database.stat().st_size, 'csv_export_bytes': len(csv_export),
               'json_export_bytes': len(json_export), 'json_alerts_returned': len(alerts),
               'json_alerts_truncated': len(alerts) < result.alerts_created,
               'classes_and_scores_match_oracle': True, 'sqlite_integrity': 'ok',
               'module_paths': [str(Path(module.__file__).relative_to(package)) for module in (dashboard, inference)],
               'worker_wall_seconds': time.perf_counter() - START}
    output.write_text(json.dumps(metrics, indent=2), encoding='utf-8')


def supervise(package, python, output):
    import psutil
    output.mkdir(parents=True, exist_ok=False)
    assert psutil.virtual_memory().available > 4 * 1024**3
    assert __import__('shutil').disk_usage(output).free > 5 * 1024**3
    package = package.resolve()
    with (package / 'demo/demostracion_sintetica.csv').open(encoding='utf-8', newline='') as handle:
        reader = csv.DictReader(handle)
        names, base = reader.fieldnames, list(reader)
    assert len(base) == 8
    limits = {'max_seconds_per_worker': 120, 'max_peak_rss_bytes': 1536 * 1024**2,
              'min_available_memory_bytes_before_case': 4 * 1024**3,
              'batches': [8, 100, 1000, 10000, 50000]}
    (output / 'limites_previos.json').write_text(json.dumps(limits, indent=2), encoding='utf-8')
    results = []
    for count in limits['batches']:
        if psutil.virtual_memory().available < limits['min_available_memory_bytes_before_case']:
            results.append({'records': count, 'status': 'NOT_STARTED_RESOURCE_GUARD'})
            break
        csv_path = output / f'synthetic_{count}.csv'
        with csv_path.open('w', encoding='utf-8', newline='') as handle:
            writer = csv.DictWriter(handle, fieldnames=names)
            writer.writeheader()
            for index in range(count):
                row = dict(base[index % 8])
                row['id'] = f'load-{index + 1}'
                writer.writerow(row)
        result_path = output / f'result_{count}.json'
        command = [str(python), '-I', '-B', str(Path(__file__).resolve()), '--worker', str(package), str(csv_path),
                   str(output / f'history_{count}.sqlite3'), str(result_path)]
        started = time.perf_counter()
        peak, aborted = 0, None
        with (output / f'worker_{count}.log').open('w', encoding='utf-8') as log:
            process = subprocess.Popen(command, cwd=package, stdout=log, stderr=subprocess.STDOUT)
            observed = psutil.Process(process.pid)
            while process.poll() is None:
                try:
                    # Windows venv python.exe may be a small redirector process.
                    # Observe the whole owned tree, including the actual worker.
                    tree = [observed, *observed.children(recursive=True)]
                    total_rss = 0
                    for member in tree:
                        try:
                            total_rss += member.memory_info().rss
                        except psutil.NoSuchProcess:
                            pass
                    peak = max(peak, total_rss)
                except psutil.NoSuchProcess:
                    pass
                elapsed = time.perf_counter() - started
                if elapsed > limits['max_seconds_per_worker'] or peak > limits['max_peak_rss_bytes']:
                    aborted = 'TIME_LIMIT' if elapsed > limits['max_seconds_per_worker'] else 'MEMORY_LIMIT'
                    for child in observed.children(recursive=True):
                        child.kill()
                    process.kill()
                    break
                time.sleep(0.05)
            process.wait()
        row = {'records': count, 'status': aborted or ('PASSED' if process.returncode == 0 else 'FAILED'),
               'returncode': process.returncode, 'parent_observed_peak_rss_bytes': peak,
               'subprocess_total_seconds': time.perf_counter() - started, 'command': command}
        if result_path.exists():
            row['metrics'] = json.loads(result_path.read_text(encoding='utf-8'))
        results.append(row)
        print(json.dumps({key: value for key, value in row.items() if key not in {'metrics', 'command'}}), flush=True)
        if row['status'] != 'PASSED':
            break
    (output / 'resultados.json').write_text(json.dumps({'limits': limits, 'cases': results,
        'all_passed': len(results) == 5 and all(row['status'] == 'PASSED' for row in results),
        'memory_method': 'Sum of RSS over owned launcher and recursive descendants, sampled every 50 ms; conservative process-tree total, not unique physical memory.',
        'scope': 'Synthetic local software load; 10000-row reference batch, 50000-row exploratory batch. Not real traffic, accuracy, concurrency or 100-MiB certification.'}, indent=2), encoding='utf-8')
    return 0 if len(results) == 5 and all(row['status'] == 'PASSED' for row in results) else 2


if __name__ == '__main__':
    if sys.argv[1] == '--worker':
        worker(*(Path(value) for value in sys.argv[2:]))
    else:
        parser = argparse.ArgumentParser()
        parser.add_argument('package', type=Path)
        parser.add_argument('python', type=Path)
        parser.add_argument('output', type=Path)
        args = parser.parse_args()
        raise SystemExit(supervise(args.package, args.python.resolve(), args.output.resolve()))
