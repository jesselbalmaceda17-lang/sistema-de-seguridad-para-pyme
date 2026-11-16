"""Start the actual PowerShell launcher from outside a relocated package."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import time
import urllib.request

ROOT = Path(__file__).resolve().parents[2]
OUT = Path(__file__).resolve().parent
SOURCE = ROOT / 'dist/SeguridadInteligentePYMES-entrega-20261109'
TARGET = ROOT / '_delivery_validation/Copia independiente con espacios'
PYTHON = ROOT / '_delivery_validation/venv_entrega/Scripts/python.exe'
PORT = 8527
with socket.socket() as probe:
    probe.bind(('127.0.0.1', PORT))
if not TARGET.exists():
    shutil.copytree(SOURCE, TARGET)
manifest = json.loads((TARGET / 'manifest.sha256.json').read_text(encoding='utf-8'))
for row in manifest['files']:
    with (TARGET / row['path']).open('rb') as handle:
        assert hashlib.file_digest(handle, 'sha256').hexdigest() == row['sha256']
environment = dict(os.environ)
for name in ['SIPYMES_MODEL_PATH', 'SIPYMES_DATABASE_PATH', 'PYTHONPATH', 'PYTHONHOME']:
    environment.pop(name, None)
environment['PYTHONDONTWRITEBYTECODE'] = '1'
environment['PYTHONNOUSERSITE'] = '1'
outside = ROOT / '_delivery_validation/launcher_fuera_del_paquete'
outside.mkdir(exist_ok=True)
command = ['powershell.exe', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', str(TARGET / 'iniciar.ps1'),
           '-PythonPath', str(PYTHON), '-Port', str(PORT)]
logfile = OUT / ('servidor_reinicio.log' if (OUT / 'servidor_inicio.json').exists() else 'servidor_inicio.log')
started = time.perf_counter()
with logfile.open('w', encoding='utf-8') as log:
    process = subprocess.Popen(command, cwd=outside, env=environment, stdout=log, stderr=subprocess.STDOUT,
                               creationflags=subprocess.CREATE_NO_WINDOW)
    try:
        while True:
            if process.poll() is not None:
                raise RuntimeError(f'Launcher exited: {process.returncode}; inspect {logfile}')
            try:
                with urllib.request.urlopen(f'http://127.0.0.1:{PORT}/_stcore/health', timeout=1) as response:
                    if response.status == 200:
                        assert response.read().strip() == b'ok'
                        break
            except OSError:
                pass
            if time.perf_counter() - started > 45:
                raise TimeoutError('45-second startup guard reached')
            time.sleep(0.1)
    except BaseException:
        import psutil
        owned = psutil.Process(process.pid)
        for child in owned.children(recursive=True):
            child.kill()
        process.kill()
        raise
state = {'pid': process.pid, 'command': command, 'cwd': str(outside), 'package': str(TARGET),
         'port': PORT, 'startup_health_seconds': time.perf_counter() - started,
         'default_database': str(TARGET / 'data/processed/security_analysis.sqlite3'),
         'new_sqlite_default': True, 'source_manifest_sha256': hashlib.sha256((SOURCE / 'manifest.sha256.json').read_bytes()).hexdigest(),
         'relocated_copy_manifest_sha256': hashlib.sha256((TARGET / 'manifest.sha256.json').read_bytes()).hexdigest()}
name = 'servidor_reinicio.json' if (OUT / 'servidor_inicio.json').exists() else 'servidor_inicio.json'
(OUT / name).write_text(json.dumps(state, indent=2), encoding='utf-8')
print(json.dumps(state))
