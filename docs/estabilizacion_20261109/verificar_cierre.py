"""Read-only verification of pre-stabilization assets and restored backup."""
from contextlib import closing
from pathlib import Path
import difflib
import hashlib
import json
import sqlite3
import time
import zipfile

ROOT = Path(__file__).resolve().parents[2]
OUT = Path(__file__).resolve().parent


def digest(path):
    with path.open('rb') as handle:
        return hashlib.file_digest(handle, 'sha256').hexdigest()


def database_state(path):
    with closing(sqlite3.connect(path.resolve().as_uri() + '?mode=ro&immutable=1', uri=True)) as connection:
        integrity = connection.execute('PRAGMA integrity_check').fetchall()
        dump = '\n'.join(connection.iterdump())
    return {'integrity_check': integrity, 'logical_sha256': hashlib.sha256(dump.encode()).hexdigest()}


def main():
    started = time.perf_counter()
    backup = json.loads((OUT / 'respaldo_inicial.json').read_text(encoding='utf-8'))
    checked, changed, missing = [], [], []
    for entry in backup['protected_files']:
        path = ROOT / entry['path']
        if not path.is_file():
            missing.append(entry['path'])
            continue
        actual = digest(path)
        row = {'path': entry['path'], 'before_sha256': entry['sha256'], 'after_sha256': actual}
        (checked if actual == entry['sha256'] else changed).append(row)
    assert not missing, missing
    assert [item['path'] for item in changed] == ['seguridad_pymes/dashboard.py'], changed
    restored = ROOT / backup['restore']
    restored_checks = []
    for entry in backup['source_manifest']:
        actual = digest(restored / entry['path'])
        assert actual == entry.get('archive_sha256', entry['sha256']), entry['path']
        restored_checks.append({'path': entry['path'], 'sha256': actual})
    archive = ROOT / backup['archive']
    assert digest(archive) == backup['archive_sha256']
    with zipfile.ZipFile(archive) as compressed:
        assert compressed.testzip() is None
    databases = []
    for entry in backup['sqlite']:
        current = database_state(ROOT / entry['path'])
        restored_state = database_state(restored / entry['path'])
        assert current == restored_state, entry['path']
        assert current['integrity_check'] == [('ok',)], entry['path']
        databases.append({'path': entry['path'], **current, 'restored_identity': True,
                          'bytes_unchanged': any(row['path'] == entry['path'] for row in checked)})
    old = (restored / 'seguridad_pymes/dashboard.py').read_text(encoding='utf-8').splitlines(keepends=True)
    new = (ROOT / 'seguridad_pymes/dashboard.py').read_text(encoding='utf-8').splitlines(keepends=True)
    (OUT / 'correcciones.diff').write_text(''.join(difflib.unified_diff(old, new, fromfile='before/dashboard.py', tofile='after/dashboard.py')), encoding='utf-8')
    runs = {}
    for run in sorted((ROOT / 'experiments/pcap_v1').glob('run_*')):
        if not run.is_dir():
            continue
        prefix = run.relative_to(ROOT).as_posix() + '/'
        rows = [row for row in checked if row['path'].startswith(prefix)]
        runs[run.name] = {'files_unchanged': len(rows), 'models_unchanged': sum(row['path'].endswith('.joblib') for row in rows)}
    assert len(runs) == 4 and all(row['files_unchanged'] == 49 for row in runs.values()), runs
    model_rows = [row for row in checked if row['path'].endswith('.joblib') and not row['path'].startswith('_backups/')]
    result = {
        'protected_total': len(backup['protected_files']), 'unchanged_count': len(checked),
        'changed_count': len(changed), 'changed': changed, 'missing': missing,
        'unchanged': checked, 'restored_files_verified': len(restored_checks),
        'archive_sha256': backup['archive_sha256'], 'archive_crc_valid': True,
        'sqlite_logical_serialization': 'UTF-8 iterdump statements joined by LF, without trailing LF; actual/restored compared using this same method',
        'sqlite_originals': databases, 'experimental_runs': runs,
        'models_unchanged': model_rows,
        'new_test_file': {'path': 'tests/test_stabilization.py', 'sha256': digest(ROOT / 'tests/test_stabilization.py')},
        'wall_seconds': time.perf_counter() - started,
    }
    (OUT / 'integridad_final.json').write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding='utf-8')
    print(json.dumps({key: value for key, value in result.items() if key not in ('unchanged', 'models_unchanged')}, ensure_ascii=False))


if __name__ == '__main__':
    main()
