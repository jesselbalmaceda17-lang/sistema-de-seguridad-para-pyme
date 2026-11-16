"""Snapshot and actually restore the pre-monitoring project before source edits."""
from contextlib import closing
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import shutil
import sqlite3
import zipfile

ROOT = Path(__file__).resolve().parents[2]
OUT = Path(__file__).resolve().parent


def sha(path):
    with path.open('rb') as handle:
        return hashlib.file_digest(handle, 'sha256').hexdigest()


def database(path):
    with closing(sqlite3.connect(path.resolve().as_uri() + '?mode=ro&immutable=1', uri=True)) as conn:
        assert conn.execute('PRAGMA integrity_check').fetchall() == [('ok',)]
        return hashlib.sha256('\n'.join(conn.iterdump()).encode()).hexdigest()


prior = ROOT / 'docs/entrega_20261109'
ledger = json.loads((prior / 'evidencias_sha256.json').read_text(encoding='utf-8'))
for row in ledger:
    assert sha(prior / row['path']) == row['sha256'], row['path']
old = json.loads((prior / 'integridad_final.json').read_text(encoding='utf-8'))
for row in old['checks']:
    assert sha(ROOT / row['path']) == row['sha256'], row['path']
assert shutil.disk_usage(ROOT).free > 15 * 1024**3
excluded = {'.venv', '_delivery_validation', '__pycache__'}
files = []
for path in sorted(ROOT.rglob('*')):
    rel = path.relative_to(ROOT)
    if path.is_file() and not any(part in excluded for part in rel.parts) and not rel.as_posix().startswith('docs/monitoreo_20261109/'):
        files.append({'path': rel.as_posix(), 'size_bytes': path.stat().st_size, 'sha256': sha(path)})
stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
archive = ROOT / '_backups' / f'pre-live-monitor-{stamp}.zip'
restore = ROOT / '_backups' / f'restore-live-monitor-{stamp}'
stage = OUT / 'sqlite_stage'
stage.mkdir()
dbs = []
for row in old['sqlite_originals']:
    path = ROOT / row['path']
    dest = stage / path.name
    with closing(sqlite3.connect(path.resolve().as_uri() + '?mode=ro', uri=True)) as source:
        with closing(sqlite3.connect(dest)) as target:
            source.backup(target)
    assert database(path) == database(dest)
    dbs.append({'path': row['path'], 'logical_sha256': database(path)})
db_paths = {row['path'] for row in dbs}
archived = []
with zipfile.ZipFile(archive, 'x', zipfile.ZIP_DEFLATED, compresslevel=1, allowZip64=True) as target:
    for row in files:
        if row['path'].startswith('_backups/'):
            continue
        path = stage / Path(row['path']).name if row['path'] in db_paths else ROOT / row['path']
        target.write(path, row['path'])
        archived.append({'path': row['path'], 'sha256': sha(path)})
with zipfile.ZipFile(archive) as source:
    assert source.testzip() is None
    assert all((restore / name).resolve().is_relative_to(restore.resolve()) for name in source.namelist())
    source.extractall(restore)
for row in archived:
    assert sha(restore / row['path']) == row['sha256']
for row in dbs:
    assert database(restore / row['path']) == row['logical_sha256']
result = {'created_utc': datetime.now(timezone.utc).isoformat(), 'prior_evidences_verified': len(ledger),
          'prior_protected_verified': len(old['checks']), 'protected_files': files,
          'archive': archive.relative_to(ROOT).as_posix(), 'archive_sha256': sha(archive), 'archive_bytes': archive.stat().st_size,
          'restore': restore.relative_to(ROOT).as_posix(), 'restored_files': archived, 'sqlite': dbs, 'crc_ok': True}
(OUT / 'respaldo_inicial.json').write_text(json.dumps(result, indent=2), encoding='utf-8')
print(json.dumps({key: value for key, value in result.items() if key not in {'protected_files', 'restored_files', 'sqlite'}}))
