"""Record complete suite and previous delivery's CSV acceptance in new outputs."""
import json
from pathlib import Path
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
OUT = Path(__file__).resolve().parent
python = ROOT / '_delivery_validation/venv_entrega/Scripts/python.exe'
started = time.perf_counter()
command = [str(python), '-B', '-m', 'unittest', 'discover', '-s', 'tests', '-v']
with (OUT / 'suite_completa.log').open('w', encoding='utf-8') as log:
    result = subprocess.run(command, cwd=ROOT, stdout=log, stderr=subprocess.STDOUT, timeout=240)
state = {'command': command, 'exit_code': result.returncode, 'wall_seconds': time.perf_counter() - started}
text = (OUT / 'suite_completa.log').read_text(encoding='utf-8')
import re
match = re.search(r'Ran (\d+) tests in ([\d.]+)s', text)
state.update(tests_run=int(match[1]) if match else None, successful=result.returncode == 0,
             suite_seconds=float(match[2]) if match else None)
(OUT / 'suite_completa.json').write_text(json.dumps(state, indent=2), encoding='utf-8')
print(json.dumps(state), flush=True)
if result.returncode:
    raise SystemExit(result.returncode)
with (OUT / 'csv_paquete.log').open('w', encoding='utf-8') as log:
    check = subprocess.run([str(python), '-I', '-B', str(ROOT / 'docs/entrega_20261109/test_paquete.py'),
        str(ROOT / 'dist/SeguridadInteligentePYMES-monitoreo-20261109'), str(OUT / 'csv_paquete_001')],
        cwd=ROOT, stdout=log, stderr=subprocess.STDOUT, timeout=120)
print(json.dumps({'csv_package_acceptance_exit_code': check.returncode}))
raise SystemExit(check.returncode)
