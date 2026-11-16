"""Validate final evidence, deliverable links and the frozen package inventory."""
import hashlib
import json
from pathlib import Path
import re
import zipfile

ROOT = Path(__file__).resolve().parents[2]
OUT = Path(__file__).resolve().parent
PACKAGE = ROOT / 'dist/SeguridadInteligentePYMES-entrega-20261109'
links = []
for document in [OUT / 'informe_entrega_tecnica.md', OUT / 'reproduccion.md', *PACKAGE.glob('*.md')]:
    for target in re.findall(r'\]\(([^)]+)\)', document.read_text(encoding='utf-8')):
        if '://' in target:
            continue
        assert (document.parent / target).exists(), (document.name, target)
        links.append({'document': document.name, 'target': target})
for path in PACKAGE.rglob('*'):
    if path.is_file() and path.suffix in {'.py', '.json', '.md', '.ps1', '.txt', '.toml'}:
        text = path.read_text(encoding='utf-8')
        assert not re.search(r'[A-Za-z]:[\\/]+Users[\\/]', text, flags=re.I), str(path)
manifest = json.loads((PACKAGE / 'manifest.sha256.json').read_text(encoding='utf-8'))
assert len(manifest['files']) == 23
assert len([path for path in PACKAGE.rglob('*') if path.is_file()]) == 24
for row in manifest['files']:
    with (PACKAGE / row['path']).open('rb') as handle:
        assert hashlib.file_digest(handle, 'sha256').hexdigest() == row['sha256']
for name in ['pruebas_paquete_001', 'pruebas_reubicado_001', 'pruebas_externo_001']:
    data = json.loads((OUT / name / 'resultados.json').read_text(encoding='utf-8'))
    assert data['successful'] and data['tests_run'] == 7 and data['failures'] == data['errors'] == 0
assert json.loads((OUT / 'suite_235.json').read_text(encoding='utf-8'))['passed']
assert json.loads((OUT / 'rendimiento_003/resultados.json').read_text(encoding='utf-8'))['all_passed']
assert json.loads((OUT / 'navegador_final.json').read_text(encoding='utf-8'))['history_survived_restart']
assert json.loads((OUT / 'navegador_externo_final.json').read_text(encoding='utf-8'))['model_sha256_matches']
assert json.loads((OUT / 'arranque_externo.json').read_text(encoding='utf-8'))['stopped_after_validation']
assert json.loads((OUT / 'servidor_reinicio_detenido.json').read_text(encoding='utf-8'))['all_stopped']
integrity = json.loads((OUT / 'integridad_final.json').read_text(encoding='utf-8'))
assert integrity['protected_files'] == integrity['unchanged_files'] == 1743
assert not integrity['changed'] and not integrity['missing']
package_record = json.loads((OUT / 'paquete_final.json').read_text(encoding='utf-8'))
with (ROOT / package_record['archive']).open('rb') as handle:
    assert hashlib.file_digest(handle, 'sha256').hexdigest() == package_record['archive_sha256']
with zipfile.ZipFile(ROOT / package_record['archive']) as archive:
    assert archive.testzip() is None
    assert len(archive.namelist()) == 24
state = {'delivery_links_checked': len(links), 'broken_links': [], 'hardcoded_windows_user_paths_in_package': [],
         'frozen_package_files': 24, 'manifest_files_excluding_self': 23,
         'all_acceptance_locations_passed': True, 'test_servers_stopped': True,
         'original_files_unchanged': 1743, 'ready_for_local_windows11_csv_demonstration': True,
         'another_physical_machine_tested': False}
(OUT / 'comprobacion_entrega.json').write_text(json.dumps(state, indent=2), encoding='utf-8')
inventory = []
for path in sorted(OUT.rglob('*')):
    if path.is_file() and path.name != 'evidencias_sha256.json' and '__pycache__' not in path.parts:
        with path.open('rb') as handle:
            digest = hashlib.file_digest(handle, 'sha256').hexdigest()
        inventory.append({'path': path.relative_to(OUT).as_posix(), 'size_bytes': path.stat().st_size, 'sha256': digest})
(OUT / 'evidencias_sha256.json').write_text(json.dumps(inventory, indent=2), encoding='utf-8')
print(json.dumps({**state, 'evidence_files': len(inventory)}))
