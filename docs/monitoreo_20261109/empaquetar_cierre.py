"""Freeze tested code, verify the actual ZIP outside development, and record closure."""
from contextlib import closing
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
import time
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parents[2]
OUT = Path(__file__).resolve().parent / 'cierre_001'
PYTHON = ROOT / '_delivery_validation/venv_entrega/Scripts/python.exe'
PACKAGE = ROOT / 'dist/SeguridadInteligentePYMES-monitoreo-20261109'
ZIP = PACKAGE.with_suffix('.zip')


def sha(path):
    with path.open('rb') as handle:
        return hashlib.file_digest(handle, 'sha256').hexdigest()


def main():
    import psutil
    unit = json.loads((OUT / 'monitoreo.json').read_text(encoding='utf-8'))
    suite = json.loads((OUT / 'suite_completa.json').read_text(encoding='utf-8'))
    csv = json.loads((OUT / 'csv_independiente/resultados.json').read_text(encoding='utf-8'))
    live = json.loads((OUT / 'streamlit_en_vivo.json').read_text(encoding='utf-8'))
    assert unit['successful'] and suite['successful'] and csv['successful']
    assert live['counters']['status'] == 'stopped' and not live['capture_processes_remaining']
    assert (OUT / 'servidor_detenido.json').is_file()
    initial = json.loads((OUT / 'estado_inicial.json').read_text(encoding='utf-8'))
    for name, expected in initial['source_sha256'].items():
        assert sha(ROOT / 'seguridad_pymes' / name) == expected, 'Source changed after tests.'
    location = json.loads((OUT / 'ubicacion_independiente.json').read_text(encoding='utf-8'))
    tested = Path(location['package'])
    differences = []
    files = sorted(p for p in PACKAGE.rglob('*') if p.is_file())
    for path in files:
        relative = path.relative_to(PACKAGE)
        assert '__pycache__' not in path.parts and path.suffix not in {'.pyc', '.sqlite3', '.pcapng'}
        if sha(path) != sha(tested / relative):
            differences.append(relative.as_posix())
        if path.suffix in {'.py', '.ps1', '.md', '.json', '.txt', '.toml'}:
            assert str(ROOT) not in path.read_text(encoding='utf-8'), 'Development path shipped.'
    assert set(differences) <= {'README.md', 'VERIFICACION.md', 'manifest.sha256.json'}, differences
    assert {p.name for p in (PACKAGE / 'models').iterdir()} == {
        'unsw_nb15_random_forest.joblib', 'unsw_nb15_random_forest.joblib.metadata.json'}
    assert sha(PACKAGE / 'models/unsw_nb15_random_forest.joblib') == '58505ee89df22c4c223b66d5e7172388d5d1fad6b7d135fce800a2765b2029e9'
    with zipfile.ZipFile(ZIP, 'x', zipfile.ZIP_DEFLATED, compresslevel=6) as archive:
        for path in files:
            archive.write(path, PACKAGE.name + '/' + path.relative_to(PACKAGE).as_posix())
    digest = sha(ZIP)
    ZIP.with_suffix('.zip.sha256').write_text(f'{digest}  {ZIP.name}\n', encoding='ascii')
    area = Path(location['area']) / 'ZIP final con espacios'
    area.mkdir(exist_ok=False)
    assert not area.resolve().is_relative_to(ROOT)
    with zipfile.ZipFile(ZIP) as archive:
        assert archive.testzip() is None
        assert all((area / name).resolve().is_relative_to(area.resolve()) for name in archive.namelist())
        archive.extractall(area)
    extracted = area / PACKAGE.name
    assert {p.relative_to(extracted).as_posix() for p in extracted.rglob('*') if p.is_file()} == {
        p.relative_to(PACKAGE).as_posix() for p in files}
    for path in files:
        assert sha(path) == sha(extracted / path.relative_to(PACKAGE))
    verified = subprocess.run([str(PYTHON), '-I', '-B', str(extracted / 'herramientas/verificar_paquete.py')],
                              cwd=area, capture_output=True, text=True, check=True, timeout=15)
    smoke_code = '''import csv,io,json,math,pathlib,sys
p=pathlib.Path(sys.argv[1]); sys.path.insert(0,str(p))
from seguridad_pymes.dashboard import _read_uploaded_csv,_prepare_uploaded_records
from seguridad_pymes.inference import run_model_analysis
import seguridad_pymes.inference as module
assert pathlib.Path(module.__file__).resolve().is_relative_to(p)
fixture=p/'demo/demostracion_sintetica.csv'
frame,headers=_read_uploaded_csv(io.BytesIO(fixture.read_bytes()))
records,ids=_prepare_uploaded_records(frame,headers,[n for n in headers if n!='id'],fixture.name)[:2]
result=run_model_analysis(records,ids,source=fixture.name,database_path=pathlib.Path(sys.argv[2]),model_path=p/'models/unsw_nb15_random_forest.joblib')
oracle=json.loads((p/'demo/resultados_esperados.json').read_text())
assert list(result.predictions)==oracle['predictions']
assert result.records_processed==8 and result.alerts_created==4
assert result.model_sha256==oracle['model_sha256']
assert all(math.isclose(s,oracle['scores'][i],rel_tol=0,abs_tol=1e-15) for i,s in enumerate(result.attack_scores))
print(json.dumps({'records':8,'alerts':4,'matches_original_oracle':True,'module':str(module.__file__),'model_sha256':result.model_sha256}))
'''
    smoke = subprocess.run([str(PYTHON), '-I', '-B', '-c', smoke_code, str(extracted), str(area / 'csv_final.sqlite3')],
                           cwd=area, capture_output=True, text=True, timeout=30)
    (OUT / 'zip_csv_final.log').write_text(smoke.stdout + smoke.stderr, encoding='utf-8')
    assert smoke.returncode == 0, smoke.stderr
    assert not any(c.status == 'LISTEN' and c.laddr.port == 8532 for c in psutil.net_connections(kind='tcp'))
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE='1', SIPYMES_DATABASE_PATH=str(area / 'ui_final.sqlite3'),
               SIPYMES_MONITOR_DIR=str(area / 'monitor_final'))
    env.pop('PYTHONPATH', None)
    env.pop('PYTHONHOME', None)
    command = ['powershell.exe', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', str(extracted / 'iniciar.ps1'),
               '-PythonPath', str(PYTHON), '-Port', '8532']
    with (OUT / 'zip_servidor_final.log').open('w', encoding='utf-8') as log:
        child = subprocess.Popen(command, cwd=area, env=env, stdout=log, stderr=subprocess.STDOUT,
                                 creationflags=subprocess.CREATE_NO_WINDOW)
    started = time.monotonic()
    parent = psutil.Process(child.pid)
    try:
        while True:
            assert child.poll() is None, 'Final ZIP launcher failed.'
            try:
                with urllib.request.urlopen('http://127.0.0.1:8532/_stcore/health', timeout=1) as response:
                    if response.status == 200:
                        break
            except OSError:
                pass
            assert time.monotonic() - started < 30
            time.sleep(.1)
        health_seconds = time.monotonic() - started
    finally:
        owned = [parent, *parent.children(recursive=True)]
        for proc in reversed(owned):
            try:
                proc.terminate()
            except psutil.NoSuchProcess:
                pass
        _, alive = psutil.wait_procs(owned, timeout=5)
        assert not alive
    # Recheck originals that matter after the final packaging; the large historical audit is reused.
    integrity = json.loads((OUT / 'integridad.json').read_text(encoding='utf-8'))
    protected_final = [r for r in integrity['unchanged'] if r['path'].startswith('models/') or
                       r['path'] in {d['path'] for d in integrity['sqlite_originals']}]
    for row in protected_final:
        assert sha(ROOT / row['path']) == row['sha256']
    for row in integrity['sqlite_originals']:
        with closing(sqlite3.connect((ROOT / row['path']).resolve().as_uri() + '?mode=ro&immutable=1', uri=True)) as conn:
            assert conn.execute('PRAGMA integrity_check').fetchone()[0] == 'ok'
    remaining = [p.info for p in psutil.process_iter(['pid', 'name', 'cmdline'])
                 if p.info['name'].lower() in {'tshark.exe', 'dumpcap.exe'}]
    assert not remaining
    assert sha(ZIP) == digest
    state = {'utc': datetime.now(timezone.utc).isoformat(), 'status': 'approved_with_documented_scope',
        'zip': str(ZIP), 'zip_bytes': ZIP.stat().st_size, 'sha256': digest, 'zip_crc_ok': True,
        'extracted_package': str(extracted), 'all_extracted_files_byte_identical': True,
        'code_identical_to_independent_live_test': True, 'changes_since_live_test': differences,
        'manifest_result': json.loads(verified.stdout), 'csv_smoke': json.loads(smoke.stdout),
        'launcher_health_http_status': 200, 'launcher_health_seconds': health_seconds,
        'owned_server_pids_stopped': [p.pid for p in owned], 'capture_processes_remaining': remaining,
        'monitor_tests': unit['tests_run'], 'complete_suite': suite['tests_run'], 'csv_acceptance': csv['tests_run'],
        'protected_models_and_original_databases_rechecked': len(protected_final),
        'remaining_reproducible_defects': [],
        'unverified': ['another physical machine / fresh driver installation', 'physical NIC / business network',
                       'sustained production load', 'production detection accuracy', 'HTTP upload/download transport'],
        'new_source_changes_during_closure': [], 'new_large_backups': 0}
    (OUT / 'zip_final.json').write_text(json.dumps(state, indent=2, ensure_ascii=False), encoding='utf-8')
    print(json.dumps(state, ensure_ascii=False), flush=True)


if __name__ == '__main__':
    main()
