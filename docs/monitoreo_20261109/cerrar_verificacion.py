"""Finish the interrupted verification, preserving all earlier evidence."""
from contextlib import closing
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parents[2]
OUT = Path(__file__).resolve().parent / 'cierre_001'
PYTHON = ROOT / '_delivery_validation/venv_entrega/Scripts/python.exe'
OUT.mkdir(exist_ok=True)


def sha(path):
    with path.open('rb') as handle:
        return hashlib.file_digest(handle, 'sha256').hexdigest()


def save(name, value):
    (OUT / name).write_text(json.dumps(value, indent=2, ensure_ascii=False), encoding='utf-8')


def processes():
    import psutil
    return [p.info for p in psutil.process_iter(['pid', 'ppid', 'name', 'create_time', 'cmdline'])
            if (p.info['name'] or '').lower() in {'python.exe', 'pythonw.exe', 'tshark.exe', 'dumpcap.exe'}]


def inventory():
    import psutil
    state = json.loads((OUT.parent / 'servidor_ui.json').read_text(encoding='utf-8'))
    try:
        previous = psutil.Process(state['pid'])
        previous = {'pid': previous.pid, 'name': previous.name(), 'command': previous.cmdline(),
                    'created': previous.create_time()}
    except psutil.NoSuchProcess:
        previous = None
    listeners = [c._asdict() for c in psutil.net_connections(kind='tcp')
                 if c.status == 'LISTEN' and c.laddr.port == 8530]
    modules = {p.name: sha(p) for p in (ROOT / 'seguridad_pymes').glob('*.py')}
    state = {'utc': datetime.now(timezone.utc).isoformat(), 'previous_server_pid_now': previous,
             'previous_server_port_listeners': listeners, 'processes': processes(), 'source_sha256': modules,
             'action': 'Old server absent; recycled PID belongs to Chrome, left untouched.'}
    save('estado_inicial.json', state)
    print(json.dumps({'previous_pid': previous, 'port_8530_listeners': listeners, 'source_modules': len(modules)}))


def tests():
    results = []
    for name, arguments in [('monitoreo', ['tests.test_monitoring', '-v']),
                            ('suite_completa', ['discover', '-s', 'tests', '-v'])]:
        command = [str(PYTHON), '-B', '-m', 'unittest', *arguments]
        start = time.perf_counter()
        with (OUT / f'{name}.log').open('w', encoding='utf-8') as log:
            result = subprocess.run(command, cwd=ROOT, stdout=log, stderr=subprocess.STDOUT, timeout=240)
        content = (OUT / f'{name}.log').read_text(encoding='utf-8')
        match = re.search(r'Ran (\d+) tests in ([\d.]+)s', content)
        state = {'command': command, 'exit_code': result.returncode, 'successful': result.returncode == 0,
                 'tests_run': int(match[1]) if match else None, 'wall_seconds': time.perf_counter() - start}
        save(f'{name}.json', state)
        print(json.dumps(state), flush=True)
        results.append(state)
        if result.returncode:
            raise SystemExit(result.returncode)
    save('pruebas.json', results)


def integrity():
    baseline = json.loads((OUT.parent / 'respaldo_inicial.json').read_text(encoding='utf-8'))
    same, changes, missing = [], [], []
    for row in baseline['protected_files']:
        path = ROOT / row['path']
        if not path.is_file():
            missing.append(row['path'])
            continue
        actual = sha(path)
        detail = {'path': row['path'], 'sha256': actual, 'expected_sha256': row['sha256']}
        (same if actual == row['sha256'] else changes).append(detail)
    archive = ROOT / baseline['archive']
    archive_sha = sha(archive)
    assert archive_sha == baseline['archive_sha256']
    with zipfile.ZipFile(archive) as source:
        crc_error = source.testzip()
    assert crc_error is None
    databases = []
    for row in baseline['sqlite']:
        path = ROOT / row['path']
        with closing(sqlite3.connect(path.resolve().as_uri() + '?mode=ro&immutable=1', uri=True)) as conn:
            check = conn.execute('PRAGMA integrity_check').fetchall()
            logical = hashlib.sha256('\n'.join(conn.iterdump()).encode()).hexdigest()
        assert check == [('ok',)] and logical == row['logical_sha256'], row['path']
        databases.append({'path': row['path'], 'integrity': 'ok', 'logical_sha256': logical})
    state = {'utc': datetime.now(timezone.utc).isoformat(), 'baseline_files': len(baseline['protected_files']),
             'unchanged': same, 'changed': changes, 'missing': missing, 'sqlite_originals': databases,
             'existing_backup': {'path': baseline['archive'], 'sha256': archive_sha, 'crc_ok': True,
                                 'previous_restoration_verified_files': len(baseline['restored_files'])}}
    save('integridad.json', state)
    print(json.dumps({'unchanged': len(same), 'changed': changes, 'missing': missing, 'backup_crc_ok': True}), flush=True)
    assert not missing
    assert {r['path'] for r in changes} <= {'seguridad_pymes/dashboard.py'}, changes


def independent():
    sandbox = Path(r'C:\Users\Ideapad15-itl6\AppData\Local\Temp\vscode-agent-codex-sandbox-Le0Mxc')
    area = Path(tempfile.mkdtemp(prefix='Validacion monitoreo independiente ', dir=sandbox))
    package = area / 'SeguridadInteligentePYMES-monitoreo-20261109'
    assert not area.is_relative_to(ROOT)
    source = ROOT / 'dist' / package.name
    shutil.copytree(source, package)
    for path in (package / 'seguridad_pymes').glob('*.py'):
        original = ROOT / 'seguridad_pymes' / path.name
        if original.exists():
            assert sha(original) == sha(path), path.name
    save('ubicacion_independiente.json', {'area': str(area), 'package': str(package),
         'python': str(PYTHON), 'dependencies': 'Reused previously verified isolated venv; lock rechecked by acceptance tests.'})
    command = [str(PYTHON), '-I', '-B', str(ROOT / 'docs/entrega_20261109/test_paquete.py'),
               str(package), str(OUT / 'csv_independiente')]
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE='1', SIPYMES_MONITOR_DIR=str(area / 'csv_test_monitor'))
    env.pop('PYTHONPATH', None)
    env.pop('PYTHONHOME', None)
    with (OUT / 'csv_independiente.log').open('w', encoding='utf-8') as log:
        result = subprocess.run(command, cwd=area, env=env, stdout=log, stderr=subprocess.STDOUT, timeout=120)
    print(json.dumps({'independent_package': str(package), 'csv_acceptance_exit_code': result.returncode}), flush=True)
    assert result.returncode == 0


def server():
    import psutil
    state = json.loads((OUT / 'ubicacion_independiente.json').read_text(encoding='utf-8'))
    area, package = Path(state['area']), Path(state['package'])
    assert not any(c.status == 'LISTEN' and c.laddr.port == 8531 for c in psutil.net_connections(kind='tcp'))
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE='1', SIPYMES_MONITOR_DIR=str(area / 'historial_monitor'),
               SIPYMES_DATABASE_PATH=str(area / 'historial_csv.sqlite3'))
    env.pop('PYTHONPATH', None)
    env.pop('PYTHONHOME', None)
    command = ['powershell.exe', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', str(package / 'iniciar.ps1'),
               '-PythonPath', str(PYTHON), '-Port', '8531']
    started = time.monotonic()
    with (OUT / 'servidor_independiente.log').open('w', encoding='utf-8') as log:
        child = subprocess.Popen(command, cwd=area, env=env, stdout=log, stderr=subprocess.STDOUT,
                                 creationflags=subprocess.CREATE_NO_WINDOW)
    parent = psutil.Process(child.pid)
    while True:
        assert child.poll() is None, 'Server exited; consult log.'
        try:
            with urllib.request.urlopen('http://127.0.0.1:8531/_stcore/health', timeout=1) as response:
                if response.status == 200:
                    break
        except OSError:
            pass
        assert time.monotonic() - started < 40, 'Startup timed out.'
        time.sleep(.1)
    state.update(pid=child.pid, created=parent.create_time(), command=command, port=8531,
                 started_utc=datetime.now(timezone.utc).isoformat(), health_seconds=time.monotonic()-started,
                 tree=[{'pid': p.pid, 'created': p.create_time(), 'name': p.name(), 'command': p.cmdline()}
                       for p in [parent, *parent.children(recursive=True)]])
    save('servidor_independiente.json', state)
    print(json.dumps(state), flush=True)


def stop_server():
    import psutil
    state = json.loads((OUT / 'servidor_independiente.json').read_text(encoding='utf-8'))
    owned = []
    for row in state['tree']:
        try:
            proc = psutil.Process(row['pid'])
            assert abs(proc.create_time() - row['created']) < .01, 'PID recycled; refusing to stop.'
            assert proc.cmdline() == row['command'], 'Command changed; refusing to stop.'
            owned.append(proc)
        except psutil.NoSuchProcess:
            pass
    assert not any((p.info['name'] or '').lower() in {'tshark.exe', 'dumpcap.exe'}
                   for p in psutil.process_iter(['name'])), 'Stop UI capture first.'
    for proc in reversed(owned):
        try:
            proc.terminate()
        except psutil.NoSuchProcess:
            pass
    _, alive = psutil.wait_procs(owned, timeout=5)
    assert not alive
    save('servidor_detenido.json', {'terminated_owned_pids': [p.pid for p in owned],
         'capture_processes_remaining': [p for p in processes() if p['name'].lower() in {'tshark.exe', 'dumpcap.exe'}]})
    print('Only the identity-verified independent test server was stopped.')


def live_evidence():
    import psutil
    location = json.loads((OUT / 'ubicacion_independiente.json').read_text(encoding='utf-8'))
    area, package = Path(location['area']), Path(location['package'])
    evidence = OUT / 'browser_evidencias'
    evidence.mkdir(exist_ok=False)
    db = area / 'historial_monitor/history.sqlite3'
    with closing(sqlite3.connect(db.as_uri() + '?mode=ro', uri=True)) as conn:
        conn.row_factory = sqlite3.Row
        sessions = [dict(row) for row in conn.execute('SELECT * FROM monitoring_sessions')]
        alerts = [dict(row) for row in conn.execute('SELECT * FROM monitoring_alerts')]
        flow_rows = [json.loads(row[0]) for row in conn.execute('SELECT flow_json FROM monitoring_flows')]
        check = conn.execute('PRAGMA integrity_check').fetchall()
        assert check[0][0] == 'ok'
        with closing(sqlite3.connect(evidence / 'history.sqlite3')) as target:
            conn.backup(target)
    assert len(sessions) == 1 and sessions[0]['status'] == 'stopped'
    counters = json.loads(sessions[0]['counters_json'])
    assert counters['status'] == sessions[0]['status']
    assert counters['source_kind'] == 'live' and not counters['partial'] and not counters['forced_stop']
    assert counters['packets_seen'] > 100 and counters['connections_observed'] >= 13
    assert {a['rule'] for a in alerts} == {'syn_observed', 'destination_ports', 'ipv4_volume'}
    assert any(a['review_state'] == 'false_positive' for a in alerts)
    assert all(a['detector'] == 'transparent_rules_v1' for a in alerts)
    demo = json.loads((OUT / 'trafico_local.json').read_text(encoding='utf-8'))
    lab_ports = set(demo['owned_service_ports'])
    owned_flows = [f for f in flow_rows if f['forward_endpoint']['port'] in lab_ports or f['reverse_endpoint']['port'] in lab_ports]
    assert len(owned_flows) >= 13
    capture = Path(sessions[0]['capture_path'])
    shutil.copy2(capture, evidence / 'capture.pcapng')
    import sys as _sys
    _sys.path.insert(0, str(package))
    from seguridad_pymes.pcap_reader import find_tshark
    tool = find_tshark()
    version = subprocess.run([str(tool), '--version'], capture_output=True, text=True, check=True, timeout=8)
    (OUT / 'tshark_version.txt').write_text(version.stdout, encoding='utf-8')
    bad_filter = 'tcp.port == 8531 or udp.port == 8531 or ip.src != 127.0.0.1 or ip.dst != 127.0.0.1'
    bad = subprocess.run([str(tool), '-n', '-r', str(capture), '-Y', bad_filter, '-T', 'fields', '-e', 'frame.number'],
                         capture_output=True, text=True, check=True, timeout=10)
    assert not bad.stdout.strip(), 'Control channel or non-loopback traffic was captured.'
    remaining = [p.info for p in psutil.process_iter(['pid', 'name', 'create_time'])
                 if p.info['name'].lower() in {'tshark.exe', 'dumpcap.exe'}]
    assert not remaining
    offline = subprocess.run([str(PYTHON), '-B', '-m', 'seguridad_pymes.pcap_extract',
               str(package / 'demo/laboratorio_sintetico.pcap'), '--output', str(evidence / 'extraccion_sintetica.json')],
               cwd=package, capture_output=True, text=True, timeout=15)
    assert offline.returncode == 0, offline.stderr
    (OUT / 'pcap_sintetico.log').write_text(offline.stdout + offline.stderr, encoding='utf-8')
    prior = json.loads((OUT.parent / 'integracion_003/resultados.json').read_text(encoding='utf-8'))
    first = prior['cases'][0]
    old_raw = OUT.parent / 'integracion_003/live/sessions' / first['state']['session_id'] / 'capture.pcapng'
    assert sha(old_raw) == first['capture_sha256'] and prior['all_passed']
    save('streamlit_en_vivo.json', {'utc': datetime.now(timezone.utc).isoformat(), 'package': str(package),
         'ui_url': 'http://127.0.0.1:8531', 'interface': r'\Device\NPF_Loopback', 'sessions': sessions,
         'counters': counters, 'alerts': alerts, 'integrity': 'ok', 'pcap_sha256': sha(capture),
         'lab_flows_found': len(owned_flows), 'no_control_port_or_non_loopback_packets': True,
         'capture_processes_remaining': remaining, 'live_scope': 'Streamlit browser buttons and actual local TCP/UDP; other local loopback background is included.',
         'previous_integration_reused': {'path': '../integracion_003/resultados.json', 'all_passed': True,
             'pcap_sha256_verified': first['capture_sha256'], 'cases': [c['name'] for c in prior['cases']]}})
    print(json.dumps({'live_packets': counters['packets_seen'], 'connections': counters['connections_observed'],
          'flows': counters['flows_persisted'], 'alerts': len(alerts), 'lab_flows': len(owned_flows),
          'manual_review': 'false_positive', 'status_matches_sqlite': True, 'orphans': remaining}))


if __name__ == '__main__':
    {'inventory': inventory, 'tests': tests, 'integrity': integrity, 'independent': independent,
     'server': server, 'stop_server': stop_server, 'live_evidence': live_evidence}[sys.argv[1]]()
