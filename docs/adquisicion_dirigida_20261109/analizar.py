"""Descriptive admission and acceptance evidence; never adds training rows."""
from collections import Counter, defaultdict
from datetime import datetime, timezone
import importlib.util
import json
from pathlib import Path
import sys
import time
import psutil

ROOT = Path(__file__).resolve().parents[2]
OUT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
from ejecutar import CASES
from proteccion import read, save, sha

spec = importlib.util.spec_from_file_location('retained_group_census', ROOT / 'docs/validacion_ampliacion_corpus/analizar_grupos.py')
groups_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(groups_module)
FLAGS = {'syn': 2, 'ack': 16, 'fin': 1, 'rst': 4, 'psh': 8}


def profile(packets):
    packets = [p for p in packets if p.get('auditable') and p.get('protocol') in ('tcp', 'udp')]
    if not packets:
        return {'packets': 0, 'bidirectional': False, 'payload_bidirectional': False, 'tcp_pure_syn': False}
    endpoints = sorted({(p['src'], p['sport']) for p in packets} | {(p['dst'], p['dport']) for p in packets})
    assert len(endpoints) == 2
    counts, payload = [0, 0], [0, 0]
    flags = Counter()
    for p in packets:
        direction = endpoints.index((p['src'], p['sport']))
        counts[direction] += 1
        payload[direction] += p['payload_bytes']
        if p['protocol'] == 'tcp':
            for name, mask in FLAGS.items():
                flags[name] += bool(p['tcp_flags'] & mask)
    return {'packets': len(packets), 'protocol': packets[0]['protocol'],
            'canonical_endpoints': endpoints, 'direction_packets': counts, 'direction_payload_bytes': payload,
            'bidirectional': all(counts), 'payload_bidirectional': all(payload), 'tcp_flag_packets': dict(flags),
            'tcp_pure_syn': packets[0]['protocol'] == 'tcp' and all(p['tcp_flags'] == 2 and p['payload_bytes'] == 0 for p in packets),
            'first_frame': packets[0]['frame'], 'last_frame': packets[-1]['frame']}


def established_with_data(packets):
    # An observation predicate only: no reconstruction, relabeling or feature changes.
    opening = {}
    for p in packets:
        if p.get('protocol') != 'tcp':
            continue
        source, target = (p['src'], p['sport']), (p['dst'], p['dport'])
        flags = p['tcp_flags']
        if flags & 4:
            opening.clear()
            continue
        if flags & 2 and not flags & 16:
            opening[source] = {'syn': p, 'synack': None}
        elif flags & 2 and flags & 16 and target in opening:
            syn = opening[target]['syn']
            if p['tcp_acknowledgment'] == (syn['tcp_sequence'] + 1 + syn['payload_bytes']) % 2**32:
                opening[target]['synack'] = p
        elif flags & 16 and not flags & 2 and source in opening and opening[source]['synack'] is not None:
            syn, synack = opening[source]['syn'], opening[source]['synack']
            if (p['tcp_sequence'] == (syn['tcp_sequence'] + 1 + syn['payload_bytes']) % 2**32
                    and p['tcp_acknowledgment'] == (synack['tcp_sequence'] + 1 + synack['payload_bytes']) % 2**32):
                data = []
                for x in packets:
                    if x['frame'] < p['frame']:
                        continue
                    if x['tcp_flags'] & 4 or (x['frame'] > p['frame'] and x['tcp_flags'] & 2 and not x['tcp_flags'] & 16):
                        break
                    if x.get('payload_bytes', 0) > 0:
                        data.append(x['frame'])
                if data:
                    return {'observed': True, 'syn_frame': syn['frame'], 'synack_frame': synack['frame'],
                            'ack_frame': p['frame'], 'subsequent_or_ack_payload_frames_first_10': data[:10]}
    return {'observed': False}


def analyze(case):
    start = time.perf_counter()
    s = CASES[case]
    base = ROOT / 'data/processed' / s['folder']
    extraction = read(base / 'extraction.json')
    audit = read(base / 'audit_v2/label_audit.json')
    imported = read(base / 'audit_v2/imported_labels.json')
    census = groups_module.group_census(extraction, audit)
    flow = {f['flow_id']: f for f in extraction['flows']}
    records = {r['reference_id']: r for r in imported['records']}
    refs = {r['reference_id']: r for r in audit['reference_correspondences']}
    ledger = {p['frame']: p for p in audit['packet_ledger']}
    by_group = defaultdict(list)
    by_ref_group = defaultdict(set)
    for r in audit['flow_correspondences']:
        by_group[r['connection_group_id']].append(r)
        for rid in r['reference_ids']:
            by_ref_group[rid].add(r['connection_group_id'])
    observed_groups = []
    complete_groups = set()
    for gid, parts in by_group.items():
        frames = sorted({n for part in parts for n in flow[part['flow_id']]['packet_frames']})
        admitted_frames = sorted({n for part in parts if part['binary_label'] is not None for n in flow[part['flow_id']]['packet_frames']})
        entire = len(admitted_frames) == len(frames)
        if entire:
            complete_groups.add(gid)
        entry = {'connection_group_id': gid, 'extracted_segments': len(parts),
                 'admitted_segments': sum(p['binary_label'] is not None for p in parts),
                 'all_segments_admitted': entire, 'statuses': dict(Counter(p['status'] for p in parts)),
                 'admitted_binary_labels': sorted({p['binary_label'] for p in parts if p['binary_label'] is not None}),
                 'all_observed_packets_unlabeled': profile([ledger[n] for n in frames]),
                 'admitted_packet_profile': profile([ledger[n] for n in admitted_frames]),
                 'admitted_handshake_and_data': established_with_data([ledger[n] for n in admitted_frames]),
                 'observed_handshake_and_data_not_a_label': established_with_data([ledger[n] for n in frames])}
        observed_groups.append(entry)
    candidate_frames = defaultdict(list)
    for p in ledger.values():
        for rid in p.get('candidate_reference_ids', []):
            candidate_frames[rid].append(p)
    target, unknown = [], []
    for rid, r in records.items():
        if r['protocol'] != 'tcp' or r['binary_label'] != s['target_class']:
            continue
        if r['orig_pkts'] is None or r['resp_pkts'] is None:
            unknown.append({'reference_id': rid, 'reason': 'unknown_direction_counter', 'uid': r['uid']})
            continue
        if not (r['orig_pkts'] > 0 and r['resp_pkts'] > 0):
            continue
        observed = profile(candidate_frames[rid])
        if not observed['bidirectional']:
            unknown.append({'reference_id': rid, 'reason': 'reported_bidirectional_not_witnessed', 'uid': r['uid']})
        v = refs[rid]
        complete = bool(v['admitted_flow_ids']) and all(g in complete_groups for g in by_ref_group[rid])
        target.append({'reference_id': rid, 'uid': r['uid'], 'reported_counts': {'orig_pkts': r['orig_pkts'], 'resp_pkts': r['resp_pkts']},
                       'observed_packet_profile_not_a_label': observed, 'reference_state': v['state'],
                       'represented_in_complete_admitted_groups': complete, 'verified': v['state'] == 'verified',
                       'candidate_frame_count': len(candidate_frames[rid])})
    covered = sum(r['verified'] and r['represented_in_complete_admitted_groups'] for r in target)
    coverage = 100 * covered / len(target) if target and not unknown else None
    target_groups = [g for g in observed_groups if g['all_segments_admitted'] and g['admitted_binary_labels'] == [s['target_class']]
                     and g['admitted_packet_profile'].get('protocol') == 'tcp']
    bidirectional = [g for g in target_groups if g['admitted_packet_profile']['bidirectional']]
    payload = [g for g in target_groups if g['admitted_packet_profile']['payload_bidirectional']]
    non_syn = [g for g in target_groups if not g['admitted_packet_profile']['tcp_pure_syn']]
    established = [g for g in target_groups if g['admitted_handshake_and_data']['observed']]
    criteria = {'integrity_and_complete_processing': True, 'target_coverage_at_least_80_percent': coverage is not None and coverage >= 80}
    if case == 'somfy':
        criteria.update(at_least_5_admitted_bidirectional_benign_tcp_groups=len(bidirectional) >= 5,
                        at_least_1_admitted_both_direction_payload_group=len(payload) >= 1)
    else:
        criteria.update(at_least_5_admitted_malicious_non_pure_syn_groups=len(non_syn) >= 5,
                        at_least_3_admitted_bidirectional_malicious_groups=len(bidirectional) >= 3,
                        at_least_1_observed_establishment_and_data_group=len(established) >= 1)
    result = {'case': case, 'closed_at_utc': datetime.now(timezone.utc).isoformat(),
              'status': 'ACEPTADO' if all(criteria.values()) else 'RECHAZADO', 'criteria': criteria,
              'counts': {'complete_target_tcp_groups': len(target_groups), 'target_bidirectional_groups': len(bidirectional),
                         'target_bidirectional_payload_groups': len(payload), 'target_non_pure_syn_groups': len(non_syn),
                         'target_established_and_data_groups': len(established)},
              'target_coverage': {'target_references': len(target), 'verified_and_completely_represented': covered,
                                  'coverage_percent': coverage, 'indeterminate': unknown, 'references': target},
              'audit_summary': audit['summary'], 'extraction_quality': extraction['quality'], 'admitted_census': census,
              'all_extracted_connection_groups': observed_groups,
              'unadmitted_reference_states': dict(Counter(r['state'] for r in refs.values() if not r['admitted_flow_ids'])),
              'references_verified_but_not_admitted': sum(r['state'] == 'verified' and not r['admitted_flow_ids'] for r in refs.values()),
              'input_hashes': {p.name: sha(p) for p in [base/'extraction.json', base/'audit_v2/label_audit.json', base/'audit_v2/imported_labels.json']},
              'resource_measurement': {'wall_seconds': time.perf_counter() - start,
                                       'python_peak_working_set_bytes': getattr(psutil.Process().memory_info(), 'peak_wset', None)},
              'corpus_rows_added': 0,
              'definitions': {'groups': 'Auditor connection components; segments are not independent connections or attacks',
                              'target_coverage': 'All labeled target-class bidirectional TCP references, including failed audit references; verified and represented in completely admitted groups / target references; unknown direction evidence makes the percentage indeterminate',
                              'unadmitted': 'Only physical behavior and publisher reference annotation; no binary training label assigned',
                              'payload': 'Observed TCP payload byte lengths; encrypted bytes count, application success not inferred'}}
    save(OUT / ('decision_' + case + '.json'), result)
    print(json.dumps({k: v for k, v in result.items() if k in ('case', 'status', 'criteria', 'counts', 'audit_summary', 'resource_measurement')}, indent=2))
    print('target_coverage', json.dumps({k: v for k, v in result['target_coverage'].items() if k != 'references'}))


if __name__ == '__main__':
    analyze(sys.argv[1])
