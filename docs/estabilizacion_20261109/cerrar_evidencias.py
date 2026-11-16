"""Check deliverable links, normalize matrix labels and inventory local evidence."""
import csv
import hashlib
import io
import json
from pathlib import Path
import re
import shutil

OUT = Path(__file__).resolve().parent
ROOT = OUT.parents[1]
matrix = OUT / 'matriz_pruebas.csv'
with matrix.open(encoding='utf-8-sig', newline='') as handle:
    rows = list(csv.DictReader(handle))
labels = {
    'B01': 'HTTP inicio Windows 11',
    'B02': 'Carga CSV e inferencia original sin mocks',
    'B03': 'Métricas y alertas iguales al oráculo',
    'B04': 'Revisión manual y reinicio del servidor',
    'B05': 'Descargas CSV/JSON servidas por HTTP',
    'B06': 'CSV vacío rechazado en navegador',
    'B07': 'Columnas faltantes rechazadas en navegador',
    'B08': 'Valores inválidos rechazados en navegador',
    'B09': 'Límite visible 100 MB',
}
for row in rows:
    if row['ID'] in labels:
        row['Caso'] = labels[row['ID']]
with matrix.open('w', encoding='utf-8-sig', newline='') as handle:
    writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
    writer.writeheader()
    writer.writerows(rows)
assert len(rows) == 29 and all(row['Resultado'] == 'APROBADO' for row in rows)
links = []
for document in [OUT / 'informe_estabilizacion.md', OUT / 'inicio_verificado.md']:
    for target in re.findall(r'\]\(([^)]+)\)', document.read_text(encoding='utf-8')):
        if '://' in target:
            continue
        assert (document.parent / target).exists(), (document.name, target)
        links.append({'document': document.name, 'target': target})
integrity_file = OUT / 'integridad_final.json'
integrity = json.loads(integrity_file.read_text(encoding='utf-8'))
integrity['sqlite_logical_serialization'] = 'UTF-8 iterdump statements joined by LF, without trailing LF; actual/restored compared using this same method'
integrity_file.write_text(json.dumps(integrity, indent=2, ensure_ascii=False), encoding='utf-8')
suite = json.loads((OUT / 'suite_final.json').read_text(encoding='utf-8'))
assert suite['successful'] and suite['exit_code'] == 0 and suite['tests_run'] == 235
assert json.loads((OUT / 'servidor_detenido.json').read_text(encoding='utf-8'))['stopped_after_tests']
usage = shutil.disk_usage(ROOT)
(OUT / 'entrega_verificada.json').write_text(json.dumps({
    'deliverable_links_checked': len(links), 'broken_links': [], 'matrix_cases': len(rows),
    'tests_passed': 235, 'original_files_unchanged': integrity['unchanged_count'],
    'original_files_intentionally_changed': integrity['changed_count'],
    'disk_free_bytes_at_close': usage.free,
}, indent=2, ensure_ascii=False), encoding='utf-8')
manifest = []
for path in sorted(OUT.rglob('*')):
    if not path.is_file() or path.name == 'evidencias_sha256.json' or '__pycache__' in path.parts:
        continue
    with path.open('rb') as handle:
        sha = hashlib.file_digest(handle, 'sha256').hexdigest()
    manifest.append({'path': path.relative_to(OUT).as_posix(), 'size_bytes': path.stat().st_size, 'sha256': sha})
(OUT / 'evidencias_sha256.json').write_text(json.dumps(manifest, indent=2, ensure_ascii=False), encoding='utf-8')
print(json.dumps({'links_checked': len(links), 'matrix_cases': len(rows), 'evidence_files': len(manifest), 'disk_free_gib': usage.free / 1024**3}))
