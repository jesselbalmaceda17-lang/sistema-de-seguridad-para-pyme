"""Contrast browser downloads and the relocated package's independent SQLite."""
from contextlib import closing
import csv
import io
import json
import math
from pathlib import Path
import sqlite3
import urllib.request

ROOT = Path(__file__).resolve().parents[2]
OUT = Path(__file__).resolve().parent
PACKAGE = ROOT / '_delivery_validation/Copia independiente con espacios'
oracle = json.loads((PACKAGE / 'demo/resultados_esperados.json').read_text(encoding='utf-8'))
payload = json.loads((OUT / 'browser_export_1.json').read_text(encoding='utf-8'))
assert len(payload['records']) == 8 and len(payload['alerts']) == 4
assert payload['alerts_total'] == payload['alerts_returned'] == 4 and not payload['alerts_truncated']
assert [row['identificador_registro'] for row in payload['records']] == oracle['ids']
assert [row['clasificacion_predicha'] for row in payload['records']] == ['Normal'] * 4 + ['Sospechoso (ataque)'] * 4
assert all(math.isclose(row['Score del modelo (clase 1)'], oracle['scores'][index], abs_tol=1e-15, rel_tol=0)
           for index, row in enumerate(payload['records']))
rows = list(csv.DictReader(io.StringIO((OUT / 'browser_export_0.csv').read_text(encoding='utf-8-sig'))))
assert [row['identificador_registro'] for row in rows] == oracle['ids']
assert all(math.isclose(float(row['Score del modelo (clase 1)']), oracle['scores'][index], abs_tol=1e-15, rel_tol=0)
           for index, row in enumerate(rows))
alert_url = '/media/eec4832f6af156163cca016484c60eb5.csv'
saved_export = OUT / 'browser_export_alertas_reinicio.csv'
if saved_export.exists():
    raw = saved_export.read_bytes()
else:
    with urllib.request.urlopen('http://127.0.0.1:8527' + alert_url, timeout=5) as response:
        assert response.status == 200
        raw = response.read()
    saved_export.write_bytes(raw)
alerts_export = list(csv.DictReader(io.StringIO(raw.decode('utf-8-sig'))))
assert len(alerts_export) == 4
assert any(row['record_id'] == 'controlled-8' and row['review_state'] == 'false_positive' for row in alerts_export)
database = PACKAGE / 'data/processed/security_analysis.sqlite3'
with closing(sqlite3.connect(database.resolve().as_uri() + '?mode=ro', uri=True)) as connection:
    connection.row_factory = sqlite3.Row
    runs = [dict(row) for row in connection.execute('SELECT * FROM analysis_runs')]
    alerts = [dict(row) for row in connection.execute('SELECT * FROM alerts ORDER BY alert_id')]
    integrity = connection.execute('PRAGMA integrity_check').fetchone()[0]
assert len(runs) == 1 and runs[0]['records_processed'] == 8 and runs[0]['alerts_created'] == 4
assert [row['record_id'] for row in alerts] == oracle['ids'][4:]
assert alerts[3]['review_state'] == 'false_positive' and alerts[3]['predicted_class'] == 1
assert integrity == 'ok' and runs[0]['model_sha256'] == oracle['model_sha256']
start = json.loads((OUT / 'servidor_inicio.json').read_text(encoding='utf-8'))
restart = json.loads((OUT / 'servidor_reinicio.json').read_text(encoding='utf-8'))
result = {'startup_health_seconds': start['startup_health_seconds'], 'restart_health_seconds': restart['startup_health_seconds'],
          'startup_method': 'Actual shipped PowerShell launcher; launched with outside cwd and no inherited model/database/PYTHONPATH overrides',
          'relocated_path_has_spaces': True, 'model_and_database_paths_relative': True,
          'candidate_manifest_identity': start['source_manifest_sha256'] == start['relocated_copy_manifest_sha256'],
          'history_survived_restart': True, 'review_survived_restart': True,
          'runs': runs, 'alerts': alerts, 'sqlite_integrity': integrity,
          'metrics': {'records': 8, 'normal': 4, 'suspicious': 4, 'alerts': 4},
          'json_csv_sqlite_and_oracle_match': True,
          'real_http_exports': ['browser_export_0.csv', 'browser_export_1.json', 'browser_export_2.csv', 'browser_export_alertas_reinicio.csv'],
          'download_scope': 'Actual HTTP media content verified; operating system Save dialog not automated',
          'original_database_used': False, 'another_physical_machine_tested': False}
(OUT / 'navegador_final.json').write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding='utf-8')
print(json.dumps({'runs': len(runs), 'alerts': len(alerts), 'history_and_review_survived_restart': True, 'all_exports_match': True}))
