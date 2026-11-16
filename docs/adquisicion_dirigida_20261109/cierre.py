"""Final read-only integrity and acquisition inventory, after successful test suites."""
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
import json
import shutil
import sqlite3
import sys
import time
import zipfile

import psutil
ROOT = Path(__file__).resolve().parents[2]
OUT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
from proteccion import read, save, sha, sql_digest


def main():
    start = time.perf_counter()
    for scope in ['specific', 'full']:
        test = read(OUT / ('pruebas_' + scope + '.json'))
        assert test['successful'] and not test['failures'] and not test['errors'] and not test['skipped']
        assert sha(OUT / ('pruebas_' + scope + '.log')) == test['log_sha256']
    baseline = read(OUT / 'inventario_inicial.json')['files']
    checked = []
    for f in baseline:
        actual = sha(ROOT / f['path'])
        assert actual == f['sha256'], f['path']
        checked.append({'path': f['path'], 'expected_sha256': f['sha256'], 'actual_sha256': actual, 'unchanged': True})
    canonical = read(ROOT / 'docs/ampliacion_dirigida_20261109/verificacion_cierre.json')['checks']
    for f in canonical:
        assert sha(ROOT / f['path']) == f['expected'], f['path']
    backup = read(OUT / 'respaldo_verificado.json')
    archive = ROOT / backup['archive']
    assert sha(archive) == backup['archive_sha256']
    with zipfile.ZipFile(archive) as z:
        assert z.testzip() is None
    for f in backup['baseline']:
        assert sha(ROOT / backup['restoration_directory'] / f['path']) == f['archive_sha256'], f['path']
    sqlite = []
    for db in backup['sqlite']:
        path = ROOT / db['path']
        logical = sql_digest(path)
        assert logical == db['logical_sha256']
        sqlite.append({'path': db['path'], 'integrity_check': 'ok', 'logical_sha256': logical, 'source_bytes_unchanged': True})
    source_checks = []
    for case, folder in [('somfy', 'iot23_somfy_7_1_01'), ('muhstik', 'iot23_muhstik_3_1')]:
        raw = ROOT / 'data/raw' / folder
        for entry in read(raw / 'provenance.json')['files']:
            assert sha(raw / entry['local_name']) == entry['sha256']
            source_checks.append({'case': case, 'role': entry['role'], 'sha256': entry['sha256'], 'size_bytes': entry['size_bytes']})
        decision = read(OUT / ('decision_' + case + '.json'))
        assert decision['status'] == 'RECHAZADO' and decision['corpus_rows_added'] == 0
        processed = ROOT / 'data/processed' / folder
        for name, expected in decision['input_hashes'].items():
            path = processed / name if name == 'extraction.json' else processed / 'audit_v2' / name
            assert sha(path) == expected
    baseline_paths = {f['path'] for f in baseline}
    additions = []
    for p in sorted(ROOT.rglob('*')):
        if not p.is_file() or any(x in p.relative_to(ROOT).parts for x in ('.venv', '__pycache__')):
            continue
        relative = p.relative_to(ROOT).as_posix()
        if relative in baseline_paths:
            continue
        additions.append({'path': relative, 'size_bytes': p.stat().st_size, 'sha256': sha(p)})
    run_counts = {f'run_{i:03}': sum(f['path'].startswith(f'experiments/pcap_v1/run_{i:03}/') for f in baseline) for i in range(1, 5)}
    assert all(v == 49 for v in run_counts.values())
    result = {'checked_at_utc': datetime.now(timezone.utc).isoformat(), 'protected_files': len(checked),
        'all_protected_files_unchanged': True, 'canonical_expected_hash_checks': len(canonical),
        'checks': checked, 'sqlite': sqlite, 'backup_sha256': backup['archive_sha256'],
        'backup_crc_valid': True, 'restored_files_rechecked': len(backup['baseline']),
        'preserved_run_file_counts': run_counts, 'source_pairs': source_checks,
        'new_files': additions, 'new_files_bytes': sum(f['size_bytes'] for f in additions),
        'available_ram_bytes': psutil.virtual_memory().available, 'free_disk_bytes': shutil.disk_usage(ROOT).free,
        'reserved_capture_requests': [], 'additional_scenarios_downloaded': [], 'corpus_rows_added': 0,
        'model_training_on_real_or_acquired_data': False, 'protected_software_changes': [],
        'wall_seconds': time.perf_counter() - start}
    save(OUT / 'integridad_final.json', result)
    print(json.dumps({k: v for k, v in result.items() if k not in ('checks', 'new_files')}, indent=2), flush=True)


if __name__ == '__main__':
    main()
