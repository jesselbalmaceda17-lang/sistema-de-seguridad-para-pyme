"""Authorized acquisition and evidence only; existing components imported unchanged."""
import argparse
from collections import Counter
from datetime import datetime, timezone
import gc
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import threading
import time
import traceback

import psutil

ROOT = Path(__file__).resolve().parents[2]
OUT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
from seguridad_pymes.iot23_sources import _fetch
from seguridad_pymes.label_audit import audit_files, read_packet_evidence
from seguridad_pymes.pcap_extract import extract_capture
from seguridad_pymes.pcap_schema import ExtractionConfig
from seguridad_pymes.zeek_labels import import_zeek_labels
from proteccion import sha, save, read

BASE = 'https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset/IndividualScenarios/'
CASES = {
    'somfy': {'scenario': 'CTU-Honeypot-Capture-7-1/Somfy-01', 'folder': 'iot23_somfy_7_1_01',
              'capture': '2019-07-03-15-15-47-first_start_somfy_gateway.pcap',
              'pcap_bytes': 2094105, 'labels_bytes': 18024, 'target_class': 0},
    'muhstik': {'scenario': 'CTU-IoT-Malware-Capture-3-1', 'folder': 'iot23_muhstik_3_1',
                'capture': '2018-05-21_capture.pcap', 'pcap_bytes': 57919772,
                'labels_bytes': 24383537, 'target_class': 1}}


def utc():
    return datetime.now(timezone.utc).isoformat()


def head(url):
    process = subprocess.run(['curl.exe', '--head', '--fail', '--silent', '--show-error',
                              '--proto', '=https', '--max-time', '35', url], capture_output=True,
                             timeout=45, creationflags=subprocess.CREATE_NO_WINDOW)
    if process.returncode:
        raise RuntimeError(process.stderr.decode(errors='replace'))
    text = process.stdout.decode('iso-8859-1')
    assert text.startswith('HTTP/1.1 200') or text.startswith('HTTP/2 200'), text
    headers = {k.lower(): v.strip() for line in text.splitlines() if ':' in line
               for k, v in [line.split(':', 1)]}
    return {'url': url, 'checked_at_utc': utc(), 'method': 'HEAD', 'headers': headers,
            'size_bytes': int(headers['content-length']), 'body_bytes_downloaded': 0}


def acquire(case, spec):
    assert read(OUT / 'respaldo_verificado.json')['all_protected_hashes_match']
    if case == 'muhstik':
        assert read(OUT / 'decision_somfy.json')['status'] in ('ACEPTADO', 'RECHAZADO', 'PENDIENTE')
    raw = ROOT / 'data/raw' / spec['folder']
    assert not raw.exists(), 'Never overwrite an acquisition'
    ram, free = psutil.virtual_memory().available, shutil.disk_usage(ROOT).free
    assert ram >= (8 * 1024**3 if case == 'muhstik' else 1024**3)
    assert free >= 3 * 1024**3
    urls = [('pcap', BASE + spec['scenario'] + '/' + spec['capture'], spec['pcap_bytes']),
            ('labels', BASE + spec['scenario'] + '/bro/conn.log.labeled', spec['labels_bytes'])]
    heads = []
    for role, url, expected in urls:
        entry = head(url)
        assert entry['size_bytes'] == expected, 'Remote size changed; stop for review'
        heads.append({'role': role, **entry})
    save(OUT / ('decision_descarga_' + case + '.json'), {
        'decided_at_utc': utc(), 'resources': {'ram_available_bytes': ram, 'disk_free_bytes': free},
        'authorized_pair': heads, 'configuration': ExtractionConfig().to_dict(),
        'audit_max_bytes': 128 * 1024**2, 'audit_max_frames': 1000000,
        'reserved_not_requested': ['Mirai 34-1', 'Amazon Echo 5-1'],
        'previous_somfy_closed': case == 'muhstik',
        'source': 'official IndividualScenarios snapshot; full Zenodo archive byte identity unverified'})
    raw.mkdir(parents=True)
    files = []
    for role, url, expected in urls:
        content, transport = _fetch(url, expected)
        before = next(h for h in heads if h['role'] == role)
        assert len(content) == expected
        assert transport['headers'].get('etag') == before['headers'].get('etag')
        name = spec['capture'] if role == 'pcap' else 'conn.log.labeled'
        if role == 'pcap':
            assert content[:4] in {b'\xd4\xc3\xb2\xa1', b'\xa1\xb2\xc3\xd4', b'\x4d\x3c\xb2\xa1', b'\xa1\xb2\x3c\x4d'}
        else:
            assert b'#fields' in content and b'detailed-label' in content
        with (raw / name).open('xb') as f:
            f.write(content)
        assert sha(raw / name) == transport['sha256']
        files.append({'role': role, 'local_name': name, **transport,
                      'head': before, 'full_content_length_verified': True})
        save(raw / (role + '_transport.json'), files[-1])
        print('Downloaded complete', case, role, expected, transport['sha256'], flush=True)
        del content
    save(raw / 'provenance.json', {'manifest_version': 'sipymes.iot23.sources.v1',
        'scenario': spec['scenario'], 'obtained_at_utc': utc(), 'files': files,
        'dataset_release': 'IoT-23 1.0.0 official IndividualScenarios snapshot',
        'release_citation': 'https://zenodo.org/records/4743746',
        'pair_verification': 'Official capture and bro/conn.log.labeled in same selected scenario directory',
        'archive_byte_identity': 'Not verified against full Zenodo archive; archive not downloaded',
        'decision_manifest_sha256': sha(OUT / ('decision_descarga_' + case + '.json'))})


def validate(case, spec):
    raw = ROOT / 'data/raw' / spec['folder']
    pcap = raw / spec['capture']
    prov = read(raw / 'provenance.json')
    assert all(sha(raw / f['local_name']) == f['sha256'] for f in prov['files'])
    # Complete existing independent PCAP reader validates record boundaries, time order and link layer.
    evidence = read_packet_evidence(pcap)
    packets = evidence['packets']
    imported = import_zeek_labels(raw / 'conn.log.labeled')
    save(OUT / ('etiquetas_importadas_' + case + '.json'), imported)
    keys = set()
    classes = Counter()
    flags = Counter()
    for p in packets:
        if not p['auditable']:
            continue
        key = p['protocol'], tuple(sorted(((p['src'], p['sport']), (p['dst'], p['dport']))))
        keys.add(key)
        classes[p['protocol']] += 1
        if p['protocol'] == 'tcp':
            for name, mask in {'syn': 2, 'ack': 16, 'fin': 1, 'rst': 4}.items():
                flags[name] += bool(p['tcp_flags'] & mask)
    result = {'checked_at_utc': utc(), 'complete_container_valid': True, 'format': 'classic Ethernet PCAP 2.4',
        'source': evidence['source'], 'limits': evidence['limits'], 'frames': len(packets),
        'auditable_packets': sum(p['auditable'] for p in packets),
        'raw_protocol_packets': dict(classes), 'raw_tcp_flag_packets': dict(flags),
        'raw_canonical_tuples': len(keys), 'import_quality': imported['quality'],
        'zeek_references': len(imported['records']),
        'zeek_target_bidirectional_tcp_references_by_reported_counters': sum(
            r['protocol'] == 'tcp' and r['binary_label'] == spec['target_class']
            and (r['orig_pkts'] or 0) > 0 and (r['resp_pkts'] or 0) > 0 for r in imported['records']),
        'checksum_states': dict(Counter(p.get('transport_checksum_status', p['reason']) for p in packets)),
        'extractor_configuration': ExtractionConfig().to_dict(),
        'note': 'Header tuple counts and Zeek references are not extractor flows; no labels assigned by this validation'}
    save(OUT / ('validacion_integridad_' + case + '.json'), result)
    print(json.dumps(result, indent=2), flush=True)


def process(case, spec):
    assert read(OUT / ('validacion_integridad_' + case + '.json'))['complete_container_valid']
    if case == 'muhstik':
        assert read(OUT / 'viabilidad_muhstik.json')['full_processing_viable']
    raw, processed = ROOT / 'data/raw' / spec['folder'], ROOT / 'data/processed' / spec['folder']
    assert not processed.exists()
    processed.mkdir(parents=True)
    extraction = extract_capture(raw / spec['capture'])
    assert len(extraction['feature_definitions']) == 38
    assert extraction['configuration'] == ExtractionConfig().to_dict()
    save(processed / 'extraction.json', extraction)
    print('Complete extraction', case, extraction['quality'], flush=True)
    del extraction
    gc.collect()
    audit = audit_files(processed / 'extraction.json', raw / 'conn.log.labeled', raw / 'provenance.json',
                        processed / 'audit_v2', capture_path=raw / spec['capture'])
    print('Complete audit', case, json.dumps(audit['summary']), flush=True)


def measured(case, action):
    end = threading.Event()
    peak = [0, 0, 0]
    parent = psutil.Process()
    def sample():
        while not end.is_set():
            try:
                rss = parent.memory_info().rss
                total = rss
                for child in parent.children(recursive=True):
                    try:
                        total += child.memory_info().rss
                    except psutil.Error:
                        pass
                peak[0] = max(peak[0], rss)
                peak[1] = max(peak[1], total)
                peak[2] += 1
            except psutil.Error:
                pass
            end.wait(.02)
    thread = threading.Thread(target=sample, daemon=True)
    thread.start()
    start, cpu = time.perf_counter(), time.process_time()
    report = {'case': case, 'action': action, 'started_at_utc': utc(), 'configuration_changes': []}
    try:
        {'adquirir': acquire, 'validar': validate, 'procesar': process}[action](case, CASES[case])
        report['successful'] = True
    except Exception as error:
        report.update(successful=False, error=str(error), traceback=traceback.format_exc())
        raise
    finally:
        end.set()
        thread.join()
        report.update(finished_at_utc=utc(), wall_seconds=time.perf_counter()-start,
                      python_cpu_seconds=time.process_time()-cpu,
                      memory={'sampled_python_rss_peak_bytes': peak[0], 'sampled_tree_rss_peak_bytes': peak[1],
                              'target_interval_seconds': .02, 'samples': peak[2], 'exact_peak': False},
                      raw_storage_bytes=sum(p.stat().st_size for p in (ROOT/'data/raw'/CASES[case]['folder']).rglob('*') if p.is_file()),
                      processed_storage_bytes=sum(p.stat().st_size for p in (ROOT/'data/processed'/CASES[case]['folder']).rglob('*') if p.is_file()))
        save(OUT / ('ejecucion_' + case + '_' + action + '.json'), report)
        print(json.dumps(report, indent=2), flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('case', choices=CASES)
    parser.add_argument('action', choices=['adquirir', 'validar', 'procesar'])
    args = parser.parse_args()
    measured(args.case, args.action)
