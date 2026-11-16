"""Oracles for new descriptive evidence, separate from protected project tests."""
import unittest
from pathlib import Path
from proteccion import read, sha
from analizar import established_with_data, profile


def packet(frame, reverse=False, flags=16, sequence=11, acknowledgment=21, payload=0):
    left, right = ('192.0.2.1', 40000), ('192.0.2.2', 443)
    source, destination = (right, left) if reverse else (left, right)
    return {'frame': frame, 'auditable': True, 'protocol': 'tcp',
            'src': source[0], 'sport': source[1], 'dst': destination[0], 'dport': destination[1],
            'tcp_flags': flags, 'tcp_sequence': sequence, 'tcp_acknowledgment': acknowledgment,
            'payload_bytes': payload}


def exchange():
    return [packet(1, flags=2, sequence=10, acknowledgment=0),
            packet(2, reverse=True, flags=18, sequence=20, acknowledgment=11),
            packet(3), packet(4, payload=3),
            packet(5, reverse=True, sequence=21, acknowledgment=14, payload=5)]


class DescriptiveOracles(unittest.TestCase):
    def test_complete_handshake_and_data_observed(self):
        result = established_with_data(exchange())
        self.assertTrue(result['observed'])
        self.assertEqual((result['syn_frame'], result['synack_frame'], result['ack_frame']), (1, 2, 3))
        self.assertEqual(result['subsequent_or_ack_payload_frames_first_10'], [4, 5])

    def test_reset_breaks_handshake(self):
        rows = exchange()
        rows[2] = packet(3, flags=4)
        self.assertFalse(established_with_data(rows)['observed'])

    def test_incorrect_ack_is_not_establishment(self):
        rows = exchange()
        for row in rows[2:]:
            row['tcp_acknowledgment'] = 999
        self.assertFalse(established_with_data(rows)['observed'])

    def test_syn_synack_reset_has_no_establishment(self):
        self.assertFalse(established_with_data(exchange()[:2] + [packet(3, flags=4)])['observed'])

    def test_handshake_without_data_does_not_satisfy_data_condition(self):
        self.assertFalse(established_with_data(exchange()[:3])['observed'])

    def test_data_only_after_a_reset_is_not_part_of_the_handshake(self):
        self.assertFalse(established_with_data(exchange()[:3] + [packet(4, flags=4), packet(5, payload=3)])['observed'])

    def test_bidirectional_packets_are_distinct_from_bidirectional_payload(self):
        rows = exchange()[:3]
        rows.append(packet(4, payload=3))
        result = profile(rows)
        self.assertTrue(result['bidirectional'])
        self.assertFalse(result['payload_bidirectional'])
        self.assertEqual(result['direction_payload_bytes'], [3, 0])

    def test_direction_is_canonical_when_first_packet_is_reverse(self):
        rows = [packet(1, reverse=True, payload=5), packet(2, payload=3)]
        result = profile(rows)
        self.assertEqual(result['direction_packets'], [1, 1])
        self.assertEqual(result['direction_payload_bytes'], [3, 5])
        self.assertTrue(result['payload_bidirectional'])

    def test_pure_syn_requires_all_flags_and_payload(self):
        rows = [packet(1, flags=2, payload=0), packet(2, flags=2, payload=0)]
        self.assertTrue(profile(rows)['tcp_pure_syn'])
        rows.append(packet(3, flags=18))
        self.assertFalse(profile(rows)['tcp_pure_syn'])


class RealAcquisitionEvidence(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.output = Path(__file__).resolve().parent
        cls.root = cls.output.parents[1]
        cls.somfy = read(cls.output / 'decision_somfy.json')
        cls.muhstik = read(cls.output / 'decision_muhstik.json')

    def test_only_authorized_full_pairs_have_verified_sizes_and_hashes(self):
        for folder, sizes in [('iot23_somfy_7_1_01', {'pcap': 2094105, 'labels': 18024}),
                              ('iot23_muhstik_3_1', {'pcap': 57919772, 'labels': 24383537})]:
            raw = self.root / 'data/raw' / folder
            provenance = read(raw / 'provenance.json')
            self.assertEqual({x['role'] for x in provenance['files']}, {'pcap', 'labels'})
            for item in provenance['files']:
                self.assertEqual(item['size_bytes'], sizes[item['role']])
                self.assertEqual((raw / item['local_name']).stat().st_size, sizes[item['role']])
                self.assertEqual(sha(raw / item['local_name']), item['sha256'])

    def test_somfy_excluded_exchange_is_not_counted_as_admitted_benign(self):
        self.assertEqual(self.somfy['status'], 'RECHAZADO')
        self.assertEqual(self.somfy['counts']['target_bidirectional_groups'], 0)
        observed = [g for g in self.somfy['all_extracted_connection_groups']
                    if g['all_observed_packets_unlabeled']['payload_bidirectional']
                    and g['all_observed_packets_unlabeled'].get('protocol') == 'tcp']
        self.assertEqual(len(observed), 1)
        self.assertEqual(observed[0]['admitted_binary_labels'], [])
        self.assertEqual(observed[0]['all_observed_packets_unlabeled']['packets'], 5839)
        self.assertEqual(self.somfy['target_coverage']['target_references'], 1)
        self.assertEqual(self.somfy['target_coverage']['coverage_percent'], 0)

    def test_muhstik_high_global_coverage_does_not_hide_zero_target_coverage(self):
        self.assertEqual(self.muhstik['status'], 'RECHAZADO')
        mal = self.muhstik['admitted_census']['summary']['Malicious']
        self.assertEqual(mal['tcp_groups'], mal['tcp_pure_syn_groups'])
        self.assertEqual(mal['tcp_other_pattern_groups'], 0)
        target = self.muhstik['target_coverage']
        self.assertEqual(target['target_references'], 5969)
        self.assertTrue(all(r['reference_state'] == 'incorrect_checksum_evidence' for r in target['references']))
        self.assertEqual(target['coverage_percent'], 0)
        self.assertEqual(target['indeterminate'], [])
        diagnostic = read(self.output / 'diagnostico_checksum_ipv4_muhstik.json')
        self.assertEqual(diagnostic['ipv4_header_checksum_counts']['incorrect_ipv4_header'], 102973)
        self.assertEqual(diagnostic['bad_ip_header_zero_stored_checksum'], 102973)

    def test_full_preflight_counts_match_completed_extractions(self):
        for file, decision in [('conteo_previo_somfy.json', self.somfy), ('viabilidad_muhstik.json', self.muhstik)]:
            counting = read(self.output / file)
            self.assertTrue(counting['complete_trace_counted'])
            self.assertEqual(counting['estimated_total_flows'], decision['extraction_quality']['flows_produced'])
            self.assertEqual(counting['frames'], decision['extraction_quality']['packets_seen'])
            self.assertEqual(counting['accepted_packet_count'], decision['extraction_quality']['packets_accepted'])


if __name__ == '__main__':
    unittest.main(verbosity=2)
