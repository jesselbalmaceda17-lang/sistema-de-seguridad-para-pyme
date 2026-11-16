"""Final read-only comparison of development assets, backup and distribution."""
from contextlib import closing
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sqlite3
import zipfile

ROOT = Path(__file__).resolve().parents[2]
OUT = Path(__file__).resolve().parent


def sha(path):
    with path.open('rb') as handle:
        return hashlib.file_digest(handle, 'sha256').hexdigest()


backup = json.loads((OUT / 'respaldo_inicial.json').read_text(encoding='utf-8'))
checks = []
for row in backup['protected_files']:
    path = ROOT / row['path']
    actual = sha(path) if path.is_file() else None
    checks.append({'path': row['path'], 'sha256': actual, 'unchanged': actual == row['sha256']})
assert all(row['unchanged'] for row in checks), [row for row in checks if not row['unchanged']]
assert sha(ROOT / backup['archive']) == backup['archive_sha256']
with zipfile.ZipFile(ROOT / backup['archive']) as archive:
    assert archive.testzip() is None
for row in backup['source_manifest']:
    assert sha(ROOT / backup['restore'] / row['path']) == row['sha256'], row['path']
databases = []
for row in backup['sqlite']:
    with closing(sqlite3.connect((ROOT / row['path']).resolve().as_uri() + '?mode=ro&immutable=1', uri=True)) as connection:
        integrity = connection.execute('PRAGMA integrity_check').fetchall()
        logical = hashlib.sha256('\n'.join(connection.iterdump()).encode()).hexdigest()
    assert integrity == [('ok',)] and logical == row['state']['logical_sha256']
    databases.append({'path': row['path'], 'integrity_check': 'ok', 'bytes_unchanged': True, 'logical_sha256': logical})
final = json.loads((OUT / 'paquete_final.json').read_text(encoding='utf-8'))
package = ROOT / final['package']
manifest = json.loads((package / 'manifest.sha256.json').read_text(encoding='utf-8'))
assert sha(ROOT / final['archive']) == final['archive_sha256']
assert sha(package / 'manifest.sha256.json') == final['manifest_sha256']
for row in manifest['files']:
    assert sha(package / row['path']) == row['sha256']
    assert sha(Path(final['external_copy']) / row['path']) == row['sha256']
selection = json.loads((OUT / 'seleccion_archivos.json').read_text(encoding='utf-8'))
for row in selection['operational_copies']:
    assert sha(package / row['path']) == row['sha256'] == sha(ROOT / row['path'])
assert len(list(package.rglob('*.joblib'))) == 1
assert not any(package.rglob('*.sqlite3'))
assert not any(package.rglob('*.pcap')) and not any(package.rglob('*.pcapng'))
runs = {}
for run in sorted((ROOT / 'experiments/pcap_v1').glob('run_*')):
    if not run.is_dir():
        continue
    prefix = run.relative_to(ROOT).as_posix() + '/'
    rows = [row for row in checks if row['path'].startswith(prefix)]
    assert len(rows) == 49
    runs[run.name] = {'files_unchanged': len(rows), 'models_unchanged': sum(row['path'].endswith('.joblib') for row in rows)}
result = {'checked_at_utc': datetime.now(timezone.utc).isoformat(), 'protected_files': len(checks),
          'unchanged_files': len(checks), 'changed': [], 'missing': [], 'checks': checks,
          'sqlite_originals': databases, 'experimental_runs': runs,
          'new_backup_sha256': backup['archive_sha256'], 'new_backup_crc_ok': True,
          'restored_files_verified': len(backup['source_manifest']),
          'package_files_verified': len(manifest['files']) + 1,
          'runtime_copies_identical_to_original': len(selection['operational_copies']),
          'source_code_changes_this_phase': 0, 'model_changes': 0, 'original_database_writes': 0,
          'archive_sha256': final['archive_sha256'], 'manifest_sha256': final['manifest_sha256']}
(OUT / 'integridad_final.json').write_text(json.dumps(result, indent=2), encoding='utf-8')
print(json.dumps({key: value for key, value in result.items() if key != 'checks'}))
