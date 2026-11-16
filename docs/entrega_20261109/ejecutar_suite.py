"""Record the actual subprocess return code of the unchanged development suite."""
import json
from pathlib import Path
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
OUT = Path(__file__).resolve().parent
started = time.perf_counter()
command = [str((ROOT / '_delivery_validation/venv_entrega/Scripts/python.exe').resolve()), '-B', '-m', 'unittest', 'discover', '-s', 'tests', '-v']
with (OUT / 'suite_235.log').open('w', encoding='utf-8') as log:
    result = subprocess.run(command, cwd=ROOT, stdout=log, stderr=subprocess.STDOUT, timeout=180)
text = (OUT / 'suite_235.log').read_text(encoding='utf-8')
state = {'command': command, 'returncode': result.returncode,
         'wall_seconds': time.perf_counter() - started, 'passed': result.returncode == 0 and 'Ran 235 tests' in text}
(OUT / 'suite_235.json').write_text(json.dumps(state, indent=2), encoding='utf-8')
print(json.dumps(state))
raise SystemExit(0 if state['passed'] else 2)
