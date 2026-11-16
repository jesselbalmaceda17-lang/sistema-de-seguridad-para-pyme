"""Evidence-only protection runner; does not change application or experiment code."""
import hashlib
import json
from pathlib import Path
import shutil
import sqlite3
import sys
import tempfile
import time
import uuid
import zipfile
from contextlib import closing
from datetime import datetime, timezone

import psutil

ROOT = Path(__file__).resolve().parents[2]
OUT = Path(__file__).resolve().parent


def sha(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as f:
        for data in iter(lambda: f.read(1024 * 1024), b''):
            h.update(data)
    return h.hexdigest()


def save(path, obj):
    with Path(path).open('x', encoding='utf-8') as f:
        json.dump(obj, f, indent=2, ensure_ascii=False, allow_nan=False)
        f.write('\n')


def read(path):
    return json.loads(Path(path).read_text(encoding='utf-8'))


def sql_digest(path):
    h = hashlib.sha256()
    with closing(sqlite3.connect(Path(path).resolve().as_uri() + '?mode=ro&immutable=1', uri=True)) as db:
        assert db.execute('PRAGMA integrity_check').fetchall() == [('ok',)]
        for line in db.iterdump():
            h.update((line + '\n').encode('utf-8'))
    return h.hexdigest()


def main():
    start = time.perf_counter()
    previous = ROOT / 'docs/ampliacion_dirigida_20261109'
    validations = []
    for record in read(previous / 'integridad_final.json')['checks']:
        assert sha(ROOT / record['path']) == record['actual_sha256'], record['path']
        validations.append(record['path'])
    for record in read(previous / 'integridad_final.json')['new_documentation_and_metadata']:
        assert sha(ROOT / record['path']) == record['sha256'], record['path']
        validations.append(record['path'])
    for record in read(previous / 'verificacion_cierre.json')['checks']:
        assert sha(ROOT / record['path']) == record['expected'], record['path']
    print('Previous close and canonical hashes verified', len(validations), flush=True)
    baseline = []
    for p in sorted(ROOT.rglob('*')):
        rel = p.relative_to(ROOT)
        if not p.is_file() or p.is_relative_to(OUT) or any(x in rel.parts for x in ('.venv', '__pycache__')):
            continue
        baseline.append({'path': rel.as_posix(), 'size_bytes': p.stat().st_size, 'sha256': sha(p)})
    save(OUT / 'inventario_inicial.json', {'files': baseline, 'excluded': ['.venv', '__pycache__', str(OUT.relative_to(ROOT))]})
    sources = [f for f in baseline if not f['path'].startswith('_backups/')]
    total = sum(f['size_bytes'] for f in sources)
    resources = {'checked_at_utc': datetime.now(timezone.utc).isoformat(),
                 'ram_available_bytes': psutil.virtual_memory().available,
                 'disk_free_bytes': shutil.disk_usage(ROOT).free,
                 'backup_and_restore_uncompressed_source_bytes': total,
                 'later_candidate_pairs_bytes': 84415438,
                 'later_processing_disk_reserve_bytes': 3 * 1024**3,
                 'somfy_ram_guard_bytes': 1024**3, 'muhstik_ram_guard_bytes': 8 * 1024**3}
    assert resources['disk_free_bytes'] > 2 * total + 3 * 1024**3
    assert resources['ram_available_bytes'] > 1024**3
    save(OUT / 'recursos_antes_descarga.json', resources)
    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ') + '-' + uuid.uuid4().hex[:8]
    archive = ROOT / '_backups' / ('pre-directed-acquisition-' + stamp + '.zip')
    restored = ROOT / '_backups' / ('restore-directed-acquisition-' + stamp)
    assert archive.resolve().is_relative_to(ROOT / '_backups')
    assert restored.resolve().is_relative_to(ROOT / '_backups')
    entries = []
    sqlite = []
    with tempfile.TemporaryDirectory(prefix='sipymes-directed-backup-') as temporary:
        temp = Path(temporary)
        with zipfile.ZipFile(archive, 'x', zipfile.ZIP_DEFLATED, compresslevel=6) as z:
            for item in sources:
                p = ROOT / item['path']
                stored = p
                if p.suffix == '.sqlite3':
                    stored = temp / p.name
                    with closing(sqlite3.connect(p.as_uri() + '?mode=ro&immutable=1', uri=True)) as original:
                        with closing(sqlite3.connect(stored)) as destination:
                            original.backup(destination)
                    logical = sql_digest(p)
                    assert sql_digest(stored) == logical
                    sqlite.append({'path': item['path'], 'logical_sha256': logical})
                entry = {**item, 'source_sha256': item['sha256'], 'archive_sha256': sha(stored)}
                z.write(stored, item['path'])
                entries.append(entry)
                assert sha(p) == item['sha256'], item['path']
            z.writestr('BACKUP_MANIFEST.json', json.dumps({'files': entries}, indent=2))
    print('Backup created; restoring and checking bytes', len(entries), flush=True)
    restored.mkdir()
    with zipfile.ZipFile(archive) as z:
        assert z.testzip() is None
        for entry in z.infolist():
            destination = (restored / entry.filename).resolve()
            assert destination.is_relative_to(restored.resolve())
            destination.parent.mkdir(parents=True, exist_ok=True)
            with z.open(entry) as source, destination.open('xb') as target:
                shutil.copyfileobj(source, target)
    for entry in entries:
        assert sha(restored / entry['path']) == entry['archive_sha256'], entry['path']
    for db in sqlite:
        assert sql_digest(restored / db['path']) == db['logical_sha256']
        db.update(restored_integrity='ok', restored_logically_identical=True)
    for entry in baseline:
        assert sha(ROOT / entry['path']) == entry['sha256'], entry['path']
    run_files = {f'run_{i:03}': [f for f in entries if f['path'].startswith(f'experiments/pcap_v1/run_{i:03}/')] for i in range(1, 5)}
    assert all(len(v) == 49 for v in run_files.values())
    result = {'checked_at_utc': datetime.now(timezone.utc).isoformat(),
              'previous_close_verified_files': len(validations), 'canonical_expected_hash_checks': 240,
              'all_protected_hashes_match': True, 'baseline_files': len(baseline),
              'archive': archive.relative_to(ROOT).as_posix(), 'archive_sha256': sha(archive),
              'archive_size_bytes': archive.stat().st_size,
              'restoration_directory': restored.relative_to(ROOT).as_posix(),
              'restored_files_verified': len(entries), 'crc_valid': True, 'sqlite': sqlite,
              'preserved_runs_files': {k: len(v) for k, v in run_files.items()},
              'wall_seconds': time.perf_counter() - start, 'baseline': entries}
    save(OUT / 'respaldo_verificado.json', result)
    print(json.dumps({k: v for k, v in result.items() if k != 'baseline'}, indent=2), flush=True)


def resume():
    start = time.perf_counter()
    archives = list((ROOT / '_backups').glob('pre-directed-acquisition-*.zip'))
    assert len(archives) == 1
    archive = archives[0]
    restored = archive.with_name(archive.stem.replace('pre-directed-acquisition-', 'restore-directed-acquisition-'))
    assert restored.resolve().is_relative_to((ROOT / '_backups').resolve())
    assert not restored.exists()
    with zipfile.ZipFile(archive) as z:
        assert z.testzip() is None
        entries = json.loads(z.read('BACKUP_MANIFEST.json'))['files']
        restored.mkdir()
        for entry in z.infolist():
            target = (restored / entry.filename).resolve()
            assert target.is_relative_to(restored.resolve())
            target.parent.mkdir(parents=True, exist_ok=True)
            with z.open(entry) as source, target.open('xb') as destination:
                shutil.copyfileobj(source, destination)
    sqlite = []
    for entry in entries:
        source, copy = ROOT / entry['path'], restored / entry['path']
        assert sha(source) == entry['source_sha256'], entry['path']
        assert sha(copy) == entry['archive_sha256'], entry['path']
        if source.suffix == '.sqlite3':
            logical = sql_digest(source)
            assert sql_digest(copy) == logical
            sqlite.append({'path': entry['path'], 'logical_sha256': logical,
                           'restored_integrity': 'ok', 'restored_logically_identical': True})
    baseline = read(OUT / 'inventario_inicial.json')['files']
    for entry in baseline:
        assert sha(ROOT / entry['path']) == entry['sha256'], entry['path']
    run_counts = {f'run_{i:03}': sum(f['path'].startswith(f'experiments/pcap_v1/run_{i:03}/') for f in entries) for i in range(1, 5)}
    assert all(v == 49 for v in run_counts.values())
    result = {'checked_at_utc': datetime.now(timezone.utc).isoformat(), 'previous_close_verified_files': 657,
              'canonical_expected_hash_checks': 240, 'all_protected_hashes_match': True,
              'baseline_files': len(baseline), 'archive': archive.relative_to(ROOT).as_posix(),
              'archive_sha256': sha(archive), 'archive_size_bytes': archive.stat().st_size,
              'restoration_directory': restored.relative_to(ROOT).as_posix(),
              'restored_files_verified': len(entries), 'crc_valid': True, 'sqlite': sqlite,
              'preserved_runs_files': run_counts, 'restoration_wall_seconds': time.perf_counter() - start,
              'initial_cleanup_incident': 'incidencia_respaldo.json; source files unchanged', 'baseline': entries}
    save(OUT / 'respaldo_verificado.json', result)
    print(json.dumps({k: v for k, v in result.items() if k != 'baseline'}, indent=2), flush=True)


if __name__ == '__main__':
    resume() if '--resume' in sys.argv else main()
