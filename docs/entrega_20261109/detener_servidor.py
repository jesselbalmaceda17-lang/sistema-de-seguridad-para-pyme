"""Stop only the test server tree whose launcher was recorded by this task."""
import json
from pathlib import Path
import psutil

OUT = Path(__file__).resolve().parent
record = OUT / ('servidor_reinicio.json' if (OUT / 'servidor_reinicio.json').exists() else 'servidor_inicio.json')
state = json.loads(record.read_text(encoding='utf-8'))
owned = psutil.Process(state['pid'])
command = owned.cmdline()
assert any('iniciar.ps1' in arg for arg in command), command
assert any(state['package'] in arg for arg in command), command
tree = [owned, *owned.children(recursive=True)]
stopped = []
for process in reversed(tree):
    try:
        process.terminate()
        stopped.append(process.pid)
    except psutil.NoSuchProcess:
        pass
psutil.wait_procs(tree, timeout=5)
assert not any(process.is_running() for process in tree)
name = 'servidor_reinicio_detenido.json' if 'reinicio' in record.name else 'servidor_inicio_detenido.json'
(OUT / name).write_text(json.dumps({'stopped_pids': stopped, 'owned_launcher': state['pid'], 'all_stopped': True}, indent=2), encoding='utf-8')
print(json.dumps({'stopped_pids': stopped, 'all_stopped': True}))
