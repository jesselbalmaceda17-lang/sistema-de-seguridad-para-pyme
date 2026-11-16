"""Exercise and stop the shipped launcher after extraction outside development."""
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import urllib.request
import psutil

ROOT = Path(__file__).resolve().parents[2]
OUT = Path(__file__).resolve().parent
state_path = OUT / 'arranque_externo.json'
if len(sys.argv) > 1 and sys.argv[1] == '--stop':
    state = json.loads(state_path.read_text(encoding='utf-8'))
    owner = psutil.Process(state['pid'])
    assert any(state['package'] in arg for arg in owner.cmdline())
    tree = [owner, *owner.children(recursive=True)]
    for process in reversed(tree):
        try:
            process.terminate()
        except psutil.NoSuchProcess:
            pass
    psutil.wait_procs(tree, timeout=5)
    assert not any(process.is_running() for process in tree)
    state['stopped_after_validation'] = True
    state_path.write_text(json.dumps(state, indent=2), encoding='utf-8')
    print('External test server stopped.')
    raise SystemExit(0)
record = json.loads((OUT / 'paquete_final.json').read_text(encoding='utf-8'))
package = Path(record['external_copy'])
environment = dict(os.environ)
for name in ['PYTHONPATH', 'PYTHONHOME', 'SIPYMES_MODEL_PATH', 'SIPYMES_DATABASE_PATH']:
    environment.pop(name, None)
environment['PYTHONDONTWRITEBYTECODE'] = '1'
command = ['powershell.exe', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', str(package / 'iniciar.ps1'),
           '-PythonPath', str(ROOT / '_delivery_validation/venv_entrega/Scripts/python.exe'), '-Port', '8528']
started = time.perf_counter()
with (OUT / 'arranque_externo.log').open('w', encoding='utf-8') as log:
    process = subprocess.Popen(command, cwd=package.parent, env=environment, stdout=log, stderr=subprocess.STDOUT,
                               creationflags=subprocess.CREATE_NO_WINDOW)
    try:
        while True:
            if process.poll() is not None:
                raise RuntimeError('The external launcher exited; see its log.')
            try:
                with urllib.request.urlopen('http://127.0.0.1:8528/_stcore/health', timeout=1) as response:
                    if response.status == 200 and response.read().strip() == b'ok':
                        break
            except OSError:
                pass
            if time.perf_counter() - started > 45:
                raise TimeoutError('External startup exceeded the 45-second guard.')
            time.sleep(0.1)
    except BaseException:
        owned = psutil.Process(process.pid)
        for child in owned.children(recursive=True):
            child.kill()
        process.kill()
        raise
state = {'pid': process.pid, 'package': str(package), 'working_directory': str(package.parent), 'command': command,
         'outside_development': not package.is_relative_to(ROOT), 'health_seconds': time.perf_counter() - started,
         'health_http_status': 200, 'explicit_clean_interpreter': str(ROOT / '_delivery_validation/venv_entrega/Scripts/python.exe'),
         'no_original_virtualenv_used': True}
state_path.write_text(json.dumps(state, indent=2), encoding='utf-8')
print(json.dumps(state))
