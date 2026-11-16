"""Short authorized physical-interface check of the already frozen package."""
from contextlib import closing
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import time
import urllib.request

ROOT = Path(__file__).resolve().parents[2]
OUT = Path(__file__).resolve().parent
PYTHON = ROOT / '_delivery_validation/venv_entrega/Scripts/python.exe'
PRIOR = ROOT / 'docs/monitoreo_20261109/cierre_001'
RELEASE = json.loads((PRIOR / 'zip_final.json').read_text(encoding='utf-8'))
PACKAGE = Path(RELEASE['extracted_package'])


def save(name, value):
    (OUT / name).write_text(json.dumps(value, indent=2, ensure_ascii=False), encoding='utf-8')


def sha(path):
    with path.open('rb') as handle:
        return hashlib.file_digest(handle, 'sha256').hexdigest()


def original_checks():
    previous = json.loads((PRIOR / 'integridad.json').read_text(encoding='utf-8'))
    databases = {r['path'] for r in previous['sqlite_originals']}
    rows = [r for r in previous['unchanged'] if r['path'].startswith('models/') or r['path'] in databases]
    for row in rows:
        assert sha(ROOT / row['path']) == row['sha256'], row['path']
    for relative in databases:
        with closing(sqlite3.connect((ROOT / relative).resolve().as_uri() + '?mode=ro&immutable=1', uri=True)) as conn:
            assert conn.execute('PRAGMA integrity_check').fetchone()[0] == 'ok'
    assert sha(Path(RELEASE['zip'])) == RELEASE['sha256']
    return rows


def start_server():
    import psutil
    originals = original_checks()
    command = [str(PYTHON), '-I', '-B', str(PACKAGE / 'herramientas/verificar_paquete.py')]
    checked = subprocess.run(command, capture_output=True, text=True, check=True, timeout=15)
    assert not any(c.status == 'LISTEN' and c.laddr.port == 8533 for c in psutil.net_connections(kind='tcp'))
    assert not [p for p in psutil.process_iter(['name']) if p.info['name'].lower() in {'tshark.exe', 'dumpcap.exe'}]
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE='1', SIPYMES_DATABASE_PATH=str(OUT / 'csv_prueba.sqlite3'),
               SIPYMES_MONITOR_DIR=str(OUT / 'monitor'))
    env.pop('PYTHONPATH', None)
    env.pop('PYTHONHOME', None)
    command = ['powershell.exe', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', str(PACKAGE / 'iniciar.ps1'),
               '-PythonPath', str(PYTHON), '-Port', '8533']
    with (OUT / 'servidor.log').open('w', encoding='utf-8') as log:
        child = subprocess.Popen(command, cwd=OUT, env=env, stdout=log, stderr=subprocess.STDOUT,
                                 creationflags=subprocess.CREATE_NO_WINDOW)
    parent = psutil.Process(child.pid)
    start = time.monotonic()
    while True:
        assert child.poll() is None
        try:
            with urllib.request.urlopen('http://127.0.0.1:8533/_stcore/health', timeout=1) as response:
                if response.status == 200:
                    break
        except OSError:
            pass
        assert time.monotonic() - start < 30
        time.sleep(.1)
    state = {'package': str(PACKAGE), 'zip_sha256': RELEASE['sha256'], 'package_check': json.loads(checked.stdout),
             'originals_verified': originals, 'tree': [{'pid': p.pid, 'created': p.create_time(), 'command': p.cmdline()}
                         for p in [parent, *parent.children(recursive=True)]]}
    save('servidor.json', state)
    print(json.dumps({'url': 'http://127.0.0.1:8533', 'package_verified': True, 'originals_verified': len(originals)}))


def traffic():
    import psutil
    db = OUT / 'monitor/history.sqlite3'
    deadline = time.monotonic() + 7
    session = None
    while time.monotonic() < deadline:
        if db.exists():
            with closing(sqlite3.connect(db)) as conn:
                conn.row_factory = sqlite3.Row
                row = conn.execute('SELECT * FROM monitoring_sessions ORDER BY started_at DESC LIMIT 1').fetchone()
                if row and json.loads(row['counters_json']).get('status') == 'capturing':
                    session = dict(row)
                    break
        time.sleep(.1)
    assert session is not None, 'Capture not ready.'
    assert session['interface_id'] == r'\Device\NPF_{014603EF-B8E8-4F1A-9B1B-535F0D5E99D3}'
    owner = psutil.Process(session['owner_pid'])
    tree = [{'pid': p.pid, 'created': p.create_time(), 'command': p.cmdline()}
            for p in owner.children(recursive=True) if p.name().lower() in {'tshark.exe', 'dumpcap.exe'}]
    assert any('-p' in r['command'] and '-i' in r['command'] for r in tree), tree
    start = datetime.fromisoformat(session['started_at'])
    results = []
    for index in range(2):
        command = ['curl.exe', '-4', '--http1.1', '--connect-timeout', '4', '--max-time', '6',
                   '--silent', '--show-error', '--output', 'NUL', '--write-out',
                   '%{http_code} %{remote_ip} %{size_download} %{time_total}', f'https://example.com/?sipymes={index+1}']
        completed = subprocess.run(command, capture_output=True, text=True, timeout=8)
        results.append({'command': command, 'exit_code': completed.returncode, 'result': completed.stdout,
                        'stderr': completed.stderr})
    elapsed = (datetime.now(timezone.utc) - start).total_seconds()
    if elapsed < 15:
        time.sleep(15 - elapsed)
    with closing(sqlite3.connect(db)) as conn:
        row = conn.execute('SELECT counters_json FROM monitoring_sessions WHERE session_id=?', (session['session_id'],)).fetchone()
    state = {'requests': results, 'owned_capture_processes': tree, 'session_id': session['session_id'],
             'after_traffic_counters': json.loads(row[0]), 'scope': 'Two limited ordinary IPv4 HTTPS requests to example.com; no scans or attacks.'}
    save('trafico_https.json', state)
    print(json.dumps(state), flush=True)


def validate():
    import csv
    import math
    import psutil
    sys.path.insert(0, str(PACKAGE))
    from seguridad_pymes.monitor_capture import LIVE_FIELDS, decode_live_row
    from seguridad_pymes.pcap_reader import find_tshark
    from seguridad_pymes.pcap_extract import _Flow
    db = OUT / 'monitor/history.sqlite3'
    with closing(sqlite3.connect(db.as_uri() + '?mode=ro', uri=True)) as conn:
        conn.row_factory = sqlite3.Row
        sessions = [dict(r) for r in conn.execute('SELECT * FROM monitoring_sessions')]
        alerts = [dict(r) for r in conn.execute('SELECT * FROM monitoring_alerts')]
        flows = [json.loads(r[0]) for r in conn.execute('SELECT flow_json FROM monitoring_flows')]
        assert conn.execute('PRAGMA integrity_check').fetchone()[0] == 'ok'
    assert len(sessions) == 1
    session = sessions[0]
    state = json.loads(session['counters_json'])
    assert session['source_kind'] == 'live' and session['status'] == state['status'] == 'stopped'
    assert not state['partial'] and not state['forced_stop'] and not state['errors'], state
    assert 15 <= state['elapsed_seconds'] <= 30, state['elapsed_seconds']
    assert state['packets_accepted'] > 0 and state['connections_observed'] > 0 and flows
    assert len({a['event_id'] for a in alerts}) == len(alerts)
    for a in alerts:
        assert a['detector'] == 'transparent_rules_v1'
    raw = Path(session['capture_path'])
    command = [str(find_tshark()), '-n', '-r', str(raw), '-o', 'ip.defragment:FALSE',
               '-o', 'tcp.desegment_tcp_streams:FALSE', '-o', 'tcp.analyze_sequence_numbers:FALSE',
               '-T', 'fields', '-E', 'header=y', '-E', 'separator=/t', '-E', 'quote=d', '-E', 'occurrence=f']
    for field in LIVE_FIELDS:
        command += ['-e', field]
    decoded = subprocess.run(command, capture_output=True, text=True, check=True, timeout=15)
    rows = list(csv.DictReader(decoded.stdout.splitlines(), delimiter='\t'))
    observations = {int(r['frame.number']): decode_live_row(r) for r in rows}
    packets = {k: v.packet for k,v in observations.items() if v.packet is not None}
    checked = 0
    for flow in flows:
        frames = flow['packet_frames']
        assert frames
        rebuilt = _Flow(packets[frames[0]], flow['ordinal'])
        for frame in frames:
            rebuilt.add(packets[frame])
        expected = rebuilt.finish(flow['close_reason'], session['session_id'])['features']
        assert len(flow['features']) == 38 and flow['features'] == expected
        checked += 1
    assert len(packets) == state['packets_accepted']
    https = json.loads((OUT / 'trafico_https.json').read_text(encoding='utf-8'))
    assert all(r['exit_code'] == 0 and r['result'].startswith('200 ') for r in https['requests']), https['requests']
    remote_ips = {r['result'].split()[1] for r in https['requests']}
    assert any(p.dport == 443 and p.dst in remote_ips for p in packets.values())
    remaining = [p.info for p in psutil.process_iter(['pid','name']) if p.info['name'].lower() in {'tshark.exe','dumpcap.exe'}]
    assert not remaining
    originals = original_checks()
    save('resultado.json', {'utc': datetime.now(timezone.utc).isoformat(), 'passed': True,
        'interface_name': 'Wi-Fi', 'interface_description': 'Intel(R) Wi-Fi 6 AX201 160MHz',
        'interface_id': session['interface_id'], 'type': 'Physical Native 802.11, managed mode',
        'sessions': sessions, 'counters': state, 'alerts': alerts, 'sqlite_integrity': 'ok',
        'pcap_sha256': sha(raw), 'link_encapsulations': sorted({r['frame.encap_type'] for r in rows}),
        'protocols': sorted({p.protocol for p in packets.values()}), 'all_38_features_recomputed_for_flows': checked,
        'https_requests_successful': 2, 'https_remote_ips_observed': sorted(remote_ips), 'duplicate_alert_ids': 0,
        'capture_processes_remaining': remaining, 'original_models_and_databases_verified': len(originals),
        'source_changes': [], 'old_zip_unchanged': True,
        'scope_limit': 'Only traffic visible to this computer on its authorized physical NIC; not evidence of security for an entire business.'})
    print(json.dumps({'passed':True,'packets':state['packets_accepted'],'connections':state['connections_observed'],
        'duration':state['elapsed_seconds'],'alerts':len(alerts),'features_checked_flows':checked,'orphans':remaining}))


def stop_server():
    import psutil
    state = json.loads((OUT / 'servidor.json').read_text(encoding='utf-8'))
    owned = []
    for row in state['tree']:
        try:
            process = psutil.Process(row['pid'])
            assert abs(process.create_time()-row['created']) < .01 and process.cmdline() == row['command']
            owned.append(process)
        except psutil.NoSuchProcess:
            pass
    assert not any(p.info['name'].lower() in {'tshark.exe','dumpcap.exe'} for p in psutil.process_iter(['name']))
    for process in reversed(owned):
        try:
            process.terminate()
        except psutil.NoSuchProcess:
            pass
    _, alive = psutil.wait_procs(owned, timeout=5)
    assert not alive
    save('servidor_detenido.json', {'owned_pids_stopped':[p.pid for p in owned]})
    print('Own test server stopped; no capture children remain.')


if __name__ == '__main__':
    {'start':start_server,'traffic':traffic,'validate':validate,'stop':stop_server}[sys.argv[1]]()
