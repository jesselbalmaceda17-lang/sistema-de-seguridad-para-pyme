"""Actual authorized Npcap loopback, replay and crash recovery; isolated artifacts."""
from contextlib import closing
import ctypes
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import time
import sqlite3

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
import psutil
from seguridad_pymes.monitor_capture import LiveSource, list_interfaces
from seguridad_pymes.monitor_demo import LocalTrafficLab
from seguridad_pymes.monitoring import CaptureManager, CaptureConfig
from seguridad_pymes.monitor_rules import RuleConfig
from seguridad_pymes.monitor_store import MonitorStore

OUT = Path(__file__).resolve().parent / (sys.argv[1] if len(sys.argv) > 1 else 'integracion_003')
OUT.mkdir(exist_ok=False)
interface = next(item for item in list_interfaces() if item.loopback)
evidence = {'scope': 'Real Npcap loopback capture restricted to owned lab listener ports; no physical interfaces captured',
            'is_admin_token': bool(ctypes.windll.shell32.IsUserAnAdmin()), 'interface': interface.__dict__, 'cases': []}


def wait_ready(manager):
    deadline = time.monotonic() + 8
    while time.monotonic() < deadline:
        manager.heartbeat()
        if manager.source is not None and manager.source.ready.is_set():
            return
        if manager.snapshot()['status'] == 'failed':
            raise AssertionError(manager.snapshot())
        time.sleep(.05)
    raise AssertionError('Capture readiness deadline exceeded')


def finish(manager):
    deadline = time.monotonic() + 8
    while manager.active and time.monotonic() < deadline:
        manager.heartbeat()
        time.sleep(.05)
    assert not manager.active, manager.snapshot()


def flows(store):
    with store.connect(read=True) as connection:
        return [json.loads(row[0]) for row in connection.execute('SELECT flow_json FROM monitoring_flows')]


with LocalTrafficLab(6) as lab:
    manager = CaptureManager(OUT / 'live')
    config = CaptureConfig(duration_seconds=30, allowed_ports=tuple(lab.ports),
                           rules=RuleConfig(syn_packets=5, destination_ports=4, ipv4_bytes=1024))
    session = manager.start(interface.identifier, config, authorized=True)
    try:
        wait_ready(manager)
        first_pid = manager.source.tree.process.pid
        assert manager.start(interface.identifier, config, authorized=True) == session
        assert manager.source.tree.process.pid == first_pid
        parent = psutil.Process(first_pid)
        owned = [parent, *parent.children(recursive=True)]
        generated = lab.generate()
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            manager.heartbeat()
            if manager.snapshot()['alerts_persisted'] >= 3 and manager.snapshot()['packets_seen'] >= 100:
                break
            time.sleep(.05)
    finally:
        manager.stop(wait=True)
    state = manager.snapshot()
    assert state['status'] == 'stopped' and not state['forced_stop'], state
    assert state['packets_accepted'] >= 100 and state['flows_persisted'] >= 13, state
    assert {row['rule'] for row in manager.store.alerts()} == {'syn_observed', 'destination_ports', 'ipv4_volume'}
    assert len(manager.store.alerts()) == 3
    psutil.wait_procs(owned, timeout=3)
    assert not any(process.is_running() for process in owned)
    event = manager.store.alerts()[0]
    manager.store.review(event['event_id'], 'false_positive')
    assert MonitorStore(manager.store.root).alerts()[0]['review_state'] == 'false_positive'
    with closing(sqlite3.connect(manager.store.path)) as conn:
        assert conn.execute('PRAGMA integrity_check').fetchone()[0] == 'ok'
    live_flows = flows(manager.store)
    raw = manager.store.root / 'sessions' / session / 'capture.pcapng'
    replay = CaptureManager(OUT / 'replay', source_factory=lambda i, d, c: LiveSource(i, d, c, replay=raw),
                            interface_provider=lambda: [interface])
    replay.start(interface.identifier, config, authorized=True)
    finish(replay)
    replay_state = replay.snapshot()
    assert replay_state['status'] == 'completed', replay_state
    assert replay_state['source_kind'] == 'laboratory_replay'
    assert replay_state['packets_accepted'] == state['packets_accepted']
    assert [row['features'] for row in sorted(flows(replay.store), key=lambda row: row['ordinal'])] == [row['features'] for row in sorted(live_flows, key=lambda row: row['ordinal'])]
    evidence['cases'].append({'name': 'real_live_start_duplicate_start_rules_flows_sqlite_review_stop_no_orphans',
        'passed': True, 'generation': generated, 'state': state, 'alerts': manager.store.alerts(),
        'capture_sha256': hashlib.sha256(raw.read_bytes()).hexdigest(), 'owned_pids_reaped': [p.pid for p in owned]})
    evidence['cases'].append({'name': 'complete_lab_pcap_replay_same_38_features', 'passed': True, 'state': replay_state})
    # Same manager can start a fresh empty capture without overwriting the first session.
    second = manager.start(interface.identifier, CaptureConfig(duration_seconds=.5, allowed_ports=(lab.ports[-1],)), authorized=True)
    finish(manager)
    assert second != session and manager.snapshot()['status'] == 'completed'
    assert len(manager.store.sessions()) == 2
    evidence['cases'].append({'name': 'restart_new_session_natural_duration_no_traffic', 'passed': True, 'state': manager.snapshot()})
    # Deliberately kill a separate owning app; job lifetime must kill tshark/dumpcap.
    crash_root = OUT / 'crash'
    crash = subprocess.Popen([sys.executable, '-I', '-B', str(Path(__file__).with_name('child_capture.py')), str(crash_root), str(lab.ports[-1])],
                             stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    ready = crash_root / 'owned_processes.json'
    deadline = time.monotonic() + 10
    while not ready.exists() and time.monotonic() < deadline and crash.poll() is None:
        time.sleep(.05)
    assert ready.exists(), crash.communicate(timeout=3)[1]
    pids = json.loads(ready.read_text(encoding='utf-8'))
    processes = [psutil.Process(pid) for pid in pids['capture_pids']]
    (crash_root / 'crash_now').write_text('authorized crash test', encoding='utf-8')
    assert crash.wait(timeout=5) == 97
    crash.stderr.close()
    _, alive = psutil.wait_procs(processes, timeout=5)
    assert not alive, [process.pid for process in alive]
    recovered = MonitorStore(crash_root)
    recovered.initialize()
    assert recovered.sessions()[0]['status'] == 'interrupted'
    evidence['cases'].append({'name': 'abrupt_app_exit_job_reaps_children_and_sqlite_recovers', 'passed': True, 'pids': pids})
evidence['all_passed'] = True
(OUT / 'resultados.json').write_text(json.dumps(evidence, indent=2, ensure_ascii=False), encoding='utf-8')
print(json.dumps({'all_passed': True, 'cases': len(evidence['cases']), 'packets_live': state['packets_seen'],
                  'flows_live': state['flows_persisted'], 'alerts_live': state['alerts_persisted'], 'forced_stop': state['forced_stop']}))
