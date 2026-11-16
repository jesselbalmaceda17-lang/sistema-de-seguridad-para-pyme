"""Verify stabilization evidence and back up the untouched development project."""
from contextlib import closing
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import shutil
import sqlite3
import time
import zipfile

ROOT = Path(__file__).resolve().parents[2]
OUT = Path(__file__).resolve().parent


def sha(path):
    with path.open('rb') as handle:
        return hashlib.file_digest(handle, 'sha256').hexdigest()


def db_state(path):
    with closing(sqlite3.connect(path.resolve().as_uri() + '?mode=ro&immutable=1', uri=True)) as conn:
        integrity = conn.execute('PRAGMA integrity_check').fetchall()
        logical = hashlib.sha256('\n'.join(conn.iterdump()).encode()).hexdigest()
    return {'integrity': integrity, 'logical_sha256': logical}


def ignored(path):
    rel = path.relative_to(ROOT)
    return any(part in {'.venv', '__pycache__', '_delivery_validation', 'dist'} for part in rel.parts) or rel.as_posix().startswith('docs/entrega_20261109/')


def main():
    start = time.perf_counter()
    prior = ROOT / 'docs/estabilizacion_20261109'
    ledger = json.loads((prior / 'evidencias_sha256.json').read_text(encoding='utf-8'))
    for entry in ledger:
        assert sha(prior / entry['path']) == entry['sha256'], entry['path']
    protection = json.loads((prior / 'integridad_final.json').read_text(encoding='utf-8'))
    for entry in protection['unchanged'] + protection['changed']:
        assert sha(ROOT / entry['path']) == entry['after_sha256'], entry['path']
    resources = shutil.disk_usage(ROOT)
    assert resources.free > 15 * 1024**3, resources
    timestamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    archive = ROOT / '_backups' / f'pre-delivery-{timestamp}.zip'
    restore = ROOT / '_backups' / f'restore-delivery-{timestamp}'
    entries = []
    for path in sorted(ROOT.rglob('*')):
        if path.is_file() and not ignored(path):
            entries.append({'path': path.relative_to(ROOT).as_posix(), 'size_bytes': path.stat().st_size, 'sha256': sha(path)})
    source = [row for row in entries if not row['path'].startswith('_backups/')]
    stage = OUT / 'sqlite_backup_stage'
    stage.mkdir()
    dbs = []
    for row in protection['sqlite_originals']:
        path = ROOT / row['path']
        target = stage / path.name
        with closing(sqlite3.connect(path.resolve().as_uri() + '?mode=ro', uri=True)) as current:
            with closing(sqlite3.connect(target)) as dest:
                current.backup(dest)
        assert db_state(path) == db_state(target), str(path)
        dbs.append({'path': row['path'], 'state': db_state(path)})
    archive_hashes = []
    db_paths = {row['path'] for row in dbs}
    with zipfile.ZipFile(archive, 'x', compression=zipfile.ZIP_DEFLATED, compresslevel=1, allowZip64=True) as output:
        for row in source:
            path = stage / Path(row['path']).name if row['path'] in db_paths else ROOT / row['path']
            output.write(path, row['path'])
            archive_hashes.append({'path': row['path'], 'sha256': sha(path)})
    with zipfile.ZipFile(archive) as compressed:
        assert compressed.testzip() is None
        restore.mkdir()
        # Entries are created above exclusively from relative project paths.
        assert all((restore / name).resolve().is_relative_to(restore.resolve()) for name in compressed.namelist())
        compressed.extractall(restore)
    for row in archive_hashes:
        assert sha(restore / row['path']) == row['sha256'], row['path']
    for row in dbs:
        assert db_state(restore / row['path']) == row['state'], row['path']
        assert row['state']['integrity'] == [('ok',)]
    result = {'created_at_utc': datetime.now(timezone.utc).isoformat(),
              'prior_evidence_files_verified': len(ledger), 'prior_protected_files_verified': len(protection['unchanged']) + len(protection['changed']),
              'protected_files': entries, 'source_manifest': archive_hashes,
              'archive': archive.relative_to(ROOT).as_posix(), 'archive_sha256': sha(archive), 'archive_bytes': archive.stat().st_size,
              'restore': restore.relative_to(ROOT).as_posix(), 'restored_files': len(archive_hashes),
              'crc_valid': True, 'sqlite': dbs, 'disk_free_before_bytes': resources.free,
              'wall_seconds': time.perf_counter() - start}
    (OUT / 'respaldo_inicial.json').write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding='utf-8')
    print(json.dumps({key: val for key, val in result.items() if key not in {'protected_files', 'source_manifest', 'sqlite'}}, ensure_ascii=False))


if __name__ == '__main__':
    main()
