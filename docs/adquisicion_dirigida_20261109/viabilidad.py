"""Read-only counting preflight, using the original TShark decoder and segmentation conditions.

No feature table, labels, model or partial capture is produced by this diagnostic.
The existing extractor remains the only producer of experimental features.
"""
from collections import Counter
from datetime import datetime, timezone
import heapq
from pathlib import Path
import shutil
import sys
import time
import psutil

ROOT = Path(__file__).resolve().parents[2]
OUT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
from seguridad_pymes.pcap_extract import _bare_syn, _key
from seguridad_pymes.pcap_reader import TSharkReader
from seguridad_pymes.pcap_schema import ExtractionConfig
from ejecutar import CASES
from proteccion import read, save, sha


def count_trace(path):
    config = ExtractionConfig()
    ns_idle = {'tcp': int(config.tcp_idle_seconds * 1e9), 'udp': int(config.udp_idle_seconds * 1e9)}
    active_ns = int(config.active_timeout_seconds * 1e9)
    active, deadlines = {}, []
    ordinal = seen = accepted = maximum_active = 0
    rejections = Counter()
    previous_frame, previous_time = 0, None
    def deadline(state):
        return min(state['last'] + ns_idle[state['protocol']], state['first'] + active_ns)
    reader = TSharkReader(timeout_seconds=config.tshark_timeout_seconds)
    source_before = sha(path)
    for observation in reader.observations(path):
        seen += 1
        assert observation.frame > previous_frame
        assert previous_time is None or observation.timestamp_ns >= previous_time
        previous_frame, previous_time = observation.frame, observation.timestamp_ns
        while deadlines and deadlines[0][0] <= observation.timestamp_ns:
            _, number, last_frame, key = heapq.heappop(deadlines)
            state = active.get(key)
            if state is not None and state['ordinal'] == number and state['last_frame'] == last_frame:
                del active[key]
        packet = observation.packet
        if packet is None:
            rejections[observation.rejection_reason] += 1
            continue
        if packet.src == packet.dst and packet.sport == packet.dport:
            rejections['indistinguishable_flow_endpoints'] += 1
            continue
        key = _key(packet)
        state = active.get(key)
        if state is not None and _bare_syn(packet):
            if (packet.src, packet.sport) != state['source'] or packet.tcp_sequence != state['initial_syn_sequence'] or state['fin_mask'] == 3:
                del active[key]
                state = None
        if state is None:
            ordinal += 1
            state = active[key] = {'ordinal': ordinal, 'first': packet.timestamp_ns, 'last': packet.timestamp_ns,
                'source': (packet.src, packet.sport), 'protocol': packet.protocol, 'fin_mask': 0,
                'initial_syn_sequence': packet.tcp_sequence if _bare_syn(packet) else None}
        state['last'] = packet.timestamp_ns
        state['last_frame'] = packet.frame
        if packet.protocol == 'tcp' and packet.tcp_flags & 1:
            state['fin_mask'] |= 1 if (packet.src, packet.sport) == state['source'] else 2
        maximum_active = max(maximum_active, len(active))
        accepted += 1
        if packet.protocol == 'tcp' and packet.tcp_flags & 4:
            del active[key]
        else:
            heapq.heappush(deadlines, (deadline(state), state['ordinal'], packet.frame, key))
        if len(deadlines) > max(1024, 4 * len(active)):
            deadlines = [(deadline(s), s['ordinal'], s['last_frame'], k) for k, s in active.items()]
            heapq.heapify(deadlines)
    assert source_before == sha(path)
    return {'complete_trace_counted': True, 'source_sha256': source_before, 'frames': seen,
            'accepted_packet_count': accepted, 'rejection_counts': dict(rejections),
            'estimated_total_flows': ordinal, 'maximum_simultaneously_active_flows': maximum_active,
            'configuration': config.to_dict(), 'tshark_version': reader.version,
            'note': 'Counting simulation of unchanged segmentation conditions; no feature extraction output or label admission'}


def main(case):
    start = time.perf_counter()
    spec = CASES[case]
    validation = read(OUT / ('validacion_integridad_' + case + '.json'))
    assert validation['complete_container_valid']
    result = count_trace(ROOT / 'data/raw' / spec['folder'] / spec['capture'])
    if case == 'somfy':
        actual = read(ROOT / 'data/processed' / spec['folder'] / 'extraction.json')
        assert result['estimated_total_flows'] == len(actual['flows'])
        assert result['accepted_packet_count'] == actual['quality']['packets_accepted']
        assert result['rejection_counts'] == actual['quality']['rejections_by_reason']
        result['validated_against_completed_somfy_extraction'] = True
    else:
        assert read(OUT / 'conteo_previo_somfy.json')['validated_against_completed_somfy_extraction']
    config = ExtractionConfig()
    ram = psutil.virtual_memory().available
    disk = shutil.disk_usage(ROOT).free
    estimated_ram = max(3 * 1024**3, result['estimated_total_flows'] * 24000 + validation['zeek_references'] * 8000 + result['frames'] * 4500)
    guards = {'within_packet_limit': result['frames'] <= config.max_packets,
              'within_total_flow_limit': result['estimated_total_flows'] <= config.max_flows,
              'within_active_flow_limit': result['maximum_simultaneously_active_flows'] <= config.max_active_flows,
              'within_audit_byte_limit': validation['source']['size_bytes'] <= 128 * 1024**2,
              'ram_headroom': ram >= max(8 * 1024**3, estimated_ram),
              'disk_headroom': disk >= 6 * 1024**3}
    result.update(checked_at_utc=datetime.now(timezone.utc).isoformat(),
        guards=guards, full_processing_viable=all(guards.values()),
        resources={'available_ram_bytes': ram, 'free_disk_bytes': disk,
                   'estimated_processing_ram_bytes': estimated_ram, 'reserved_processing_disk_bytes': 6 * 1024**3,
                   'estimate_basis': 'Planning envelope 24 KB/flow + 8 KB/reference + 4.5 KB/frame; not a measured future peak',
                   'counting_process_peak_working_set_bytes': getattr(psutil.Process().memory_info(), 'peak_wset', None),
                   'wall_seconds': time.perf_counter() - start},
        configuration_changes=[],
        qualification='Limits checked before expensive feature serialization/audit. Original TShark timeout still enforced during actual extraction; any failure stops with no usable dataset.')
    save(OUT / ('conteo_previo_somfy.json' if case == 'somfy' else 'viabilidad_muhstik.json'), result)
    print(__import__('json').dumps(result, indent=2), flush=True)


if __name__ == '__main__':
    main(sys.argv[1])
