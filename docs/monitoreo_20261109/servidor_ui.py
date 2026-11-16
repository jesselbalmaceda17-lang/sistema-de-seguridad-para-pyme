"""Actual new distribution, previous clean interpreter, isolated UI histories."""
import json
import os
from pathlib import Path
import subprocess
import time
import urllib.request

ROOT = Path(__file__).resolve().parents[2]
OUT = Path(__file__).resolve().parent
package = ROOT / 'dist/SeguridadInteligentePYMES-monitoreo-20261109'
python = ROOT / '_delivery_validation/venv_entrega/Scripts/python.exe'
env = dict(os.environ)
env.pop('PYTHONPATH', None)
env.pop('PYTHONHOME', None)
env['SIPYMES_DATABASE_PATH'] = str(OUT / 'browser_csv.sqlite3')
env['SIPYMES_MONITOR_DIR'] = str(OUT / 'browser_monitor')
env['PYTHONDONTWRITEBYTECODE'] = '1'
command = ['powershell.exe', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', str(package / 'iniciar.ps1'),
           '-PythonPath', str(python), '-Port', '8530']
started = time.perf_counter()
with (OUT / 'servidor_ui.log').open('w', encoding='utf-8') as log:
    process = subprocess.Popen(command, cwd=OUT, env=env, stdout=log, stderr=subprocess.STDOUT, creationflags=subprocess.CREATE_NO_WINDOW)
    while True:
        if process.poll() is not None:
            raise RuntimeError('UI server exited; see log.')
        try:
            with urllib.request.urlopen('http://127.0.0.1:8530/_stcore/health', timeout=1) as response:
                if response.status == 200:
                    break
        except OSError:
            pass
        if time.perf_counter() - started > 40:
            process.terminate()
            raise TimeoutError('UI server startup deadline exceeded')
        time.sleep(.1)
state = {'pid': process.pid, 'command': command, 'cwd': str(OUT), 'package': str(package),
         'health_seconds': time.perf_counter() - started, 'histories_isolated': True}
(OUT / 'servidor_ui.json').write_text(json.dumps(state, indent=2), encoding='utf-8')
print(json.dumps(state))
