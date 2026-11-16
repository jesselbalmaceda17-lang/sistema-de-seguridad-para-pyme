"""Freeze the final distribution and extract an independent validation copy."""
import hashlib
import json
from pathlib import Path
import zipfile

ROOT = Path(__file__).resolve().parents[2]
OUT = Path(__file__).resolve().parent
PACKAGE = ROOT / 'dist/SeguridadInteligentePYMES-entrega-20261109'
ARCHIVE = PACKAGE.with_suffix('.zip')
EXTERNAL = Path('C:/Users/Ideapad15-itl6/AppData/Local/Temp/vscode-agent-codex-sandbox-bFK4Zt/SIPYMES entrega aislada')
manifest = json.loads((PACKAGE / 'manifest.sha256.json').read_text(encoding='utf-8'))
files = [entry['path'] for entry in manifest['files']] + ['manifest.sha256.json']
actual = [path.relative_to(PACKAGE).as_posix() for path in PACKAGE.rglob('*') if path.is_file()]
assert set(actual) == set(files), set(actual) ^ set(files)
with zipfile.ZipFile(ARCHIVE, 'x', zipfile.ZIP_DEFLATED, compresslevel=6) as output:
    for name in sorted(files):
        output.write(PACKAGE / name, PACKAGE.name + '/' + name)
assert not EXTERNAL.exists()
EXTERNAL.mkdir(parents=True)
with zipfile.ZipFile(ARCHIVE) as compressed:
    assert compressed.testzip() is None
    assert all((EXTERNAL / name).resolve().is_relative_to(EXTERNAL.resolve()) for name in compressed.namelist())
    compressed.extractall(EXTERNAL)
target = EXTERNAL / PACKAGE.name
for row in manifest['files']:
    with (target / row['path']).open('rb') as handle:
        assert hashlib.file_digest(handle, 'sha256').hexdigest() == row['sha256'], row['path']
assert (target / 'manifest.sha256.json').read_bytes() == (PACKAGE / 'manifest.sha256.json').read_bytes()
with ARCHIVE.open('rb') as handle:
    digest = hashlib.file_digest(handle, 'sha256').hexdigest()
record = {'package': PACKAGE.relative_to(ROOT).as_posix(), 'archive': ARCHIVE.relative_to(ROOT).as_posix(),
          'archive_bytes': ARCHIVE.stat().st_size, 'archive_sha256': digest,
          'manifest_sha256': hashlib.sha256((PACKAGE / 'manifest.sha256.json').read_bytes()).hexdigest(),
          'file_count_including_manifest': len(files), 'external_copy': str(target),
          'external_to_development_folder': not target.is_relative_to(ROOT), 'zip_crc_valid': True,
          'all_extracted_hashes_verified': True, 'uncompressed_bytes': sum((PACKAGE / name).stat().st_size for name in files)}
(OUT / 'paquete_final.json').write_text(json.dumps(record, indent=2), encoding='utf-8')
print(json.dumps(record))
