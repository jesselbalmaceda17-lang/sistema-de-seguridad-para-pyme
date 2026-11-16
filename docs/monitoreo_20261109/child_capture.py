"""Crash-test child: only a parent-supplied, owned loopback UDP port is captured."""
import json
import os
from pathlib import Path
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from seguridad_pymes.monitoring import CaptureManager, CaptureConfig
from seguridad_pymes.monitor_capture import list_interfaces

output, port = Path(sys.argv[1]), int(sys.argv[2])
manager = CaptureManager(output)
manager.start(next(item.identifier for item in list_interfaces() if item.loopback),
              CaptureConfig(duration_seconds=30, allowed_ports=(port,)), authorized=True)
deadline = time.monotonic() + 8
while manager.source is None and time.monotonic() < deadline:
    manager.heartbeat()
    time.sleep(.05)
if manager.source is None:
    raise RuntimeError(manager.snapshot())
import psutil
parent = psutil.Process(manager.source.tree.process.pid)
time.sleep(.5)
(output / 'owned_processes.json').write_text(json.dumps({'app_pid': os.getpid(),
    'capture_pids': [parent.pid, *[p.pid for p in parent.children(recursive=True)]]}), encoding='utf-8')
while not (output / 'crash_now').exists():
    manager.heartbeat()
    time.sleep(.05)
os._exit(97)  # deliberately bypasses Python finally/atexit; Windows job must clean capture
