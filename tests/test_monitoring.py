"""Monitoring tests use synthetic observations; live proof is a separate opt-in lab."""
from contextlib import closing
import json
import os
from pathlib import Path
import queue
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from seguridad_pymes.monitor_capture import CaptureInterface, decode_live_row, list_interfaces
from seguridad_pymes.monitor_flows import IncrementalFlows
from seguridad_pymes.monitor_rules import RuleConfig, RuleEngine
from seguridad_pymes.monitor_store import MonitorStore
from seguridad_pymes.monitoring import CaptureConfig, CaptureManager
from seguridad_pymes.pcap_extract import _aggregate
from seguridad_pymes.pcap_reader import CaptureError, FIELDS, Packet, PacketObservation
from seguridad_pymes.pcap_schema import ExtractionConfig


INTERFACE = CaptureInterface(r'\Device\NPF_Loopback', 'Laboratorio', True)


def packet(frame=1, ns=1000000000, protocol='tcp', flags=2, *, reverse=False, dport=80, sequence=1, size=40):
    return Packet(frame, ns, '0', '10.0.0.2' if reverse else '10.0.0.1', dport if reverse else 40000,
                  '10.0.0.1' if reverse else '10.0.0.2', 40000 if reverse else dport, protocol, size,
                  flags if protocol == 'tcp' else None, sequence if protocol == 'tcp' else None)


def wait_for(manager, timeout=4):
    deadline = time.monotonic() + timeout
    while manager.active and time.monotonic() < deadline:
        time.sleep(.02)
    if manager.active:
        manager.stop(wait=True)
        raise AssertionError('Manager exceeded bounded test time')
    return manager.snapshot()


class ConfigAndDecodeTests(unittest.TestCase):
    def test_invalid_resource_limits(self):
        for kwargs in [{'storage_mib': 0}, {'capture_memory_mib': True}, {'duration_seconds': float('nan')},
                       {'max_packets': 0}, {'allowed_ports': (0,)}, {'rules': {}}]:
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                CaptureConfig(**kwargs)

    def test_invalid_rule_limits(self):
        for kwargs in [{'window_seconds': 0}, {'syn_packets': True}, {'ipv4_bytes': -1}]:
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                RuleConfig(**kwargs)

    def row(self, protocol=6):
        row = dict.fromkeys(FIELDS, '')
        row.update({'frame.number': '1', 'frame.time_epoch': '1.123456789', 'frame.len': '44',
            'frame.cap_len': '44', 'frame.encap_type': '15', 'null.family': '2', 'ip.version': '4',
            'ip.src': '127.0.0.1', 'ip.dst': '127.0.0.1', 'ip.len': '40', 'ip.hdr_len': '20',
            'ip.flags.mf': '0', 'ip.frag_offset': '0', 'ip.proto': str(protocol),
            'tcp.srcport': '40000', 'tcp.dstport': '80', 'tcp.hdr_len': '20', 'tcp.flags': '0x0002', 'tcp.seq_raw': '1'})
        return row

    def test_loopback_tcp_observable_headers(self):
        result = decode_live_row(self.row())
        self.assertEqual(result.timestamp_ns, 1123456789)
        self.assertEqual(result.packet.ipv4_bytes, 40)
        self.assertEqual(result.packet.tcp_flags, 2)

    def test_loopback_udp(self):
        row = self.row(17)
        row.update({'frame.len': '32', 'frame.cap_len': '32', 'ip.len': '28', 'udp.srcport': '40000', 'udp.dstport': '53', 'udp.length': '8'})
        self.assertEqual(decode_live_row(row).packet.protocol, 'udp')

    def test_truncation_rejected(self):
        row = self.row()
        row['frame.cap_len'] = '43'
        self.assertEqual(decode_live_row(row).rejection_reason, 'truncated_packet')

    def test_fragments_rejected(self):
        row = self.row()
        row['ip.flags.mf'] = '1'
        self.assertIsNone(decode_live_row(row).packet)

    def test_bad_loopback_family(self):
        row = self.row()
        row['null.family'] = '24'
        self.assertEqual(decode_live_row(row).rejection_reason, 'unsupported_loopback_family')

    def test_ethernet_and_vlan_policy_unchanged(self):
        row = self.row()
        row.update({'frame.encap_type': '1', 'eth.type': '0x0800', 'frame.len': '54', 'frame.cap_len': '54'})
        self.assertIsNotNone(decode_live_row(row).packet)
        row['vlan.id'] = '3'
        self.assertEqual(decode_live_row(row).rejection_reason, 'unsupported_ethernet_payload')

    def test_interface_list_excludes_extcap(self):
        listing = '1. \\Device\\NPF_Loopback (Local)\n2. etwdump (ETW)\n'
        with patch('seguridad_pymes.monitor_capture.find_tshark', return_value=Path('tshark')), \
             patch('seguridad_pymes.monitor_capture.subprocess.run', return_value=SimpleNamespace(returncode=0, stdout=listing, stderr='')):
            self.assertEqual(list_interfaces()[0].identifier, INTERFACE.identifier)

    def test_dependency_failure_is_explained(self):
        with patch('seguridad_pymes.monitor_capture.find_tshark', side_effect=CaptureError('missing')):
            with self.assertRaisesRegex(CaptureError, 'Npcap'):
                list_interfaces()

    @unittest.skipUnless(os.name == 'nt', 'Windows console helper')
    def test_console_helper_does_not_require_venv_packages(self):
        tool = Path(__file__).resolve().parents[1] / 'seguridad_pymes/monitor_process.py'
        result = subprocess.run([str(Path(sys.base_prefix) / 'python.exe'), '-I', '-B', str(tool), '--break', '0'], capture_output=True, text=True, timeout=3)
        self.assertNotIn('ModuleNotFoundError', result.stderr)
        self.assertEqual(result.returncode, 2)


class FlowTests(unittest.TestCase):
    def test_features_and_grouping_match_offline_extractor(self):
        packets = [packet(1, flags=2), packet(2, 1100000000, flags=18, reverse=True),
                   packet(3, 1200000000, flags=16), packet(4, 1300000000, flags=4, reverse=True),
                   packet(5, 1400000000, protocol='udp')]
        observations = [PacketObservation(p.frame, p.timestamp_ns, p) for p in packets]
        expected, _ = _aggregate(observations, ExtractionConfig(), 'same')
        adapter = IncrementalFlows('same')
        actual = []
        for item in observations:
            actual.extend(adapter.push(item)[0])
        actual.extend(adapter.finish('end_of_capture'))
        self.assertEqual(sorted(actual, key=lambda row: row['ordinal']), expected)
        self.assertTrue(all(len(row['features']) == 38 for row in actual))

    def test_idle_expiry_without_new_packets(self):
        adapter = IncrementalFlows('idle', ExtractionConfig(tcp_idle_seconds=1))
        adapter.push(PacketObservation(1, 1000000000, packet()))
        self.assertEqual(adapter.expire(2000000000)[0]['close_reason'], 'idle_timeout')
        self.assertFalse(adapter.active)

    def test_packet_windows_bound_frame_retention(self):
        adapter = IncrementalFlows('bounded', max_flow_packets=2)
        adapter.push(PacketObservation(1, 1000000000, packet(flags=16)))
        done, _ = adapter.push(PacketObservation(2, 1100000000, packet(2, 1100000000, flags=16)))
        self.assertEqual(done[0]['close_reason'], 'live_packet_window')
        self.assertFalse(adapter.active)

    def test_syn_retransmission_and_new_connection(self):
        adapter = IncrementalFlows('syn')
        adapter.push(PacketObservation(1, 1000000000, packet()))
        self.assertFalse(adapter.push(PacketObservation(2, 1100000000, packet(2, 1100000000)))[0])
        done, _ = adapter.push(PacketObservation(3, 1200000000, packet(3, 1200000000, sequence=2)))
        self.assertEqual(done[0]['close_reason'], 'new_tcp_syn')

    def test_out_of_order_and_rejection_counts(self):
        adapter = IncrementalFlows('reject')
        adapter.push(PacketObservation(2, 2000000000, packet(2, 2000000000)))
        adapter.push(PacketObservation(1, 1000000000, packet()))
        adapter.push(PacketObservation(3, 3000000000, None, 'truncated_packet'))
        self.assertEqual(adapter.accepted, 1)
        self.assertEqual(sum(adapter.rejections.values()), 2)

    def test_active_flow_limit_never_evicts_silently(self):
        adapter = IncrementalFlows('max', ExtractionConfig(max_active_flows=1))
        adapter.push(PacketObservation(1, 1000000000, packet()))
        with self.assertRaises(CaptureError):
            adapter.push(PacketObservation(2, 1100000000, packet(2, 1100000000, dport=81)))


class RuleTests(unittest.TestCase):
    def test_syn_counts_observed_packets_including_retransmission(self):
        engine = RuleEngine('syn', RuleConfig(syn_packets=2, destination_ports=100))
        self.assertFalse(engine.push(packet()))
        alerts = engine.push(packet(2, 1100000000))
        self.assertEqual([a['rule'] for a in alerts], ['syn_observed'])
        self.assertEqual(alerts[0]['observed'], 2)
        self.assertIn('retransmisiones', alerts[0]['message'])

    def test_ack_is_not_a_syn_attempt(self):
        engine = RuleEngine('ack', RuleConfig(syn_packets=1))
        self.assertFalse(engine.push(packet(flags=18)))

    def test_ports_are_distinct_initial_syn_destination_ports(self):
        engine = RuleEngine('ports', RuleConfig(destination_ports=2))
        self.assertFalse(engine.push(packet()))
        self.assertFalse(engine.push(packet(2, 1100000000)))
        self.assertEqual(engine.push(packet(3, 1200000000, dport=81))[0]['rule'], 'destination_ports')

    def test_udp_only_triggers_observed_volume(self):
        alerts = RuleEngine('udp', RuleConfig(syn_packets=1, destination_ports=1, ipv4_bytes=28)).push(packet(protocol='udp', size=28))
        self.assertEqual([a['rule'] for a in alerts], ['ipv4_volume'])
        self.assertEqual(alerts[0]['severity'], 'baja')

    def test_cooldown_and_window_expiry(self):
        engine = RuleEngine('cool', RuleConfig(window_seconds=1, syn_packets=1))
        first = engine.push(packet())
        self.assertEqual(len(first), 1)
        self.assertFalse(engine.push(packet(2, 1500000000)))
        next_alert = engine.push(packet(3, 2500000000))
        self.assertEqual(len(next_alert), 1)
        self.assertNotEqual(first[0]['event_id'], next_alert[0]['event_id'])

    def test_rule_window_memory_bound(self):
        engine = RuleEngine('bounded', RuleConfig(max_events=1))
        engine.push(packet())
        with self.assertRaises(CaptureError):
            engine.push(packet(2, 1100000000))


class StoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.store = MonitorStore(self.temp.name)
        self.store.initialize()
        self.store.create('session', INTERFACE, {}, 'isolated.pcapng')

    def test_duplicate_alert_insert_preserves_manual_review(self):
        alert = RuleEngine('session', RuleConfig(syn_packets=1)).push(packet())[0]
        self.store.persist('session', [], [alert], {})
        self.store.review(alert['event_id'], 'false_positive')
        self.store.persist('session', [], [alert], {})
        self.assertEqual(len(self.store.alerts()), 1)
        self.assertEqual(self.store.alerts()[0]['review_state'], 'false_positive')
        with closing(sqlite3.connect(self.store.path)) as conn:
            self.assertEqual(conn.execute('PRAGMA integrity_check').fetchone()[0], 'ok')

    def test_review_validation_and_parameter_binding(self):
        with self.assertRaises(ValueError):
            self.store.review("'; DROP TABLE monitoring_alerts; --", 'pending')
        with self.assertRaises(ValueError):
            self.store.review('id', 'invented')
        self.assertEqual(self.store.alerts(), [])

    def test_dead_owner_session_recovered(self):
        with self.store.connect() as conn:
            conn.execute('UPDATE monitoring_sessions SET owner_pid=999999999,owner_created=0')
        self.store.initialize()
        self.assertEqual(self.store.sessions()[0]['status'], 'interrupted')

    def test_read_empty_history_creates_no_database(self):
        other = MonitorStore(Path(self.temp.name) / 'other')
        self.assertEqual(other.sessions(), [])
        self.assertEqual(other.alerts(), [])
        self.assertFalse(other.path.exists())


class FakeSource:
    kind = 'unit_test'

    def __init__(self, interface, directory, config):
        self.queue = queue.Queue()
        self.ended, self.ready = threading.Event(), threading.Event()
        self.ready.set()
        self.error, self.diagnostics, self.forced = None, 'unit-test transport; not a real capture', False
        self.tree = SimpleNamespace(process=SimpleNamespace(pid=os.getpid(), returncode=0), rss=lambda: 1024)
        self.closed = 0

    def close(self):
        self.closed += 1
        self.ended.set()


class LifecycleTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.sources = []

        def factory(*args):
            source = FakeSource(*args)
            self.sources.append(source)
            return source
        self.manager = CaptureManager(self.temp.name, source_factory=factory, interface_provider=lambda: [INTERFACE])
        self.addCleanup(self.manager.shutdown)

    def start(self, **kwargs):
        return self.manager.start(INTERFACE.identifier, CaptureConfig(**kwargs), authorized=True)

    def test_authorization_required(self):
        with self.assertRaises(CaptureError):
            self.manager.start(INTERFACE.identifier)

    def test_unknown_interface_cannot_become_a_command(self):
        with self.assertRaises(CaptureError):
            self.manager.start('1; malicious', authorized=True)
        self.assertFalse(self.sources)

    def test_unique_start_and_idempotent_stop(self):
        first = self.start()
        self.assertEqual(self.start(), first)
        self.manager.stop(wait=True)
        self.manager.stop(wait=True)
        self.assertEqual(len(self.sources), 1)
        self.assertEqual(self.sources[0].closed, 1)
        self.assertEqual(self.manager.snapshot()['status'], 'stopped')

    def test_lease_expiry_stops_abandoned_capture(self):
        self.start(heartbeat_seconds=.2)
        state = wait_for(self.manager)
        self.assertEqual(state['status'], 'stopped')
        self.assertIn('Sin conexión', state['reason'])

    def test_memory_limit_stops_capture(self):
        self.start()
        deadline = time.monotonic() + 1
        while not self.sources and time.monotonic() < deadline:
            time.sleep(.01)
        self.sources[0].tree.rss = lambda: 1024**3
        state = wait_for(self.manager)
        self.assertEqual(state['status'], 'failed')
        self.assertTrue(state['partial'])

    def test_capture_error_is_recorded_and_restart_possible(self):
        self.start()
        deadline = time.monotonic() + 1
        while not self.sources and time.monotonic() < deadline:
            time.sleep(.01)
        self.sources[0].error = 'Permiso denegado para captura.'
        self.assertEqual(wait_for(self.manager)['status'], 'failed')
        self.start()
        self.manager.stop(wait=True)
        self.assertEqual(len(self.sources), 2)

    def test_server_capture_slot_prevents_second_manager(self):
        self.start()
        other = CaptureManager(Path(self.temp.name) / 'other', source_factory=FakeSource, interface_provider=lambda: [INTERFACE])
        with self.assertRaises(CaptureError):
            other.start(INTERFACE.identifier, authorized=True)

    def test_duration_stops_without_render_loop(self):
        self.start(duration_seconds=.1)
        self.assertEqual(wait_for(self.manager)['status'], 'completed')


class MonitoringUITests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.manager = CaptureManager(Path(self.temp.name) / 'monitor', source_factory=FakeSource,
                                      interface_provider=lambda: [INTERFACE])
        self.addCleanup(self.manager.shutdown)
        self.patches = [
            patch('seguridad_pymes.monitor_ui._manager', return_value=self.manager),
            patch('seguridad_pymes.monitor_ui._interfaces', return_value=[INTERFACE]),
            patch.dict(os.environ, {'SIPYMES_DATABASE_PATH': str(Path(self.temp.name) / 'csv.sqlite3')})]
        for context in self.patches:
            context.start()
            self.addCleanup(context.stop)
        from streamlit.testing.v1 import AppTest
        self.app = AppTest.from_file(str(Path(__file__).resolve().parents[1] / 'app.py')).run(timeout=30)

    def test_start_disabled_without_authorization(self):
        self.assertTrue(self.app.button(key='monitor_start').disabled)
        self.assertFalse(self.manager.active)
        self.assertTrue(any(header.value == 'Monitoreo de red' for header in self.app.header))
        self.assertTrue(any(header.value == 'Análisis CSV con aprendizaje automático' for header in self.app.header))

    def test_ui_start_packets_alerts_review_and_stop_without_duplicate(self):
        self.app.checkbox(key='monitor_authorized').check().run()
        self.app.number_input(key='monitor_syn').set_value(2).run()
        self.app.number_input(key='monitor_ports').set_value(2).run()
        self.app.number_input(key='monitor_volume').set_value(1).run()
        self.app.button(key='monitor_start').click().run()
        source = self.manager.source
        self.assertIsNotNone(source)
        now = time.time_ns()
        for index in range(3):
            pkt = packet(index + 1, now + index * 1000000, dport=80 + index, size=600)
            source.queue.put(PacketObservation(pkt.frame, pkt.timestamp_ns, pkt))
        deadline = time.monotonic() + 2
        while (self.manager.snapshot()['alerts_persisted'] < 3 or self.manager.snapshot().get('packets_seen', 0) < 3) and time.monotonic() < deadline:
            time.sleep(.02)
        self.app.run()
        self.assertFalse(self.app.exception)
        self.assertTrue(self.app.button(key='monitor_start').disabled)
        self.assertEqual(self.manager.snapshot()['packets_seen'], 3)
        self.assertEqual(len(self.manager.store.alerts()), 3)
        state_widget = next(widget for widget in self.app.selectbox if widget.key.startswith('monitor_review_state_'))
        state_widget.select('Falso positivo').run()
        self.app.button(key='monitor_review_save').click().run()
        self.assertFalse(self.app.exception)
        self.assertEqual(self.manager.store.alerts()[0]['review_state'], 'false_positive')
        self.app.button(key='monitor_stop').click().run()
        wait_for(self.manager)
        self.app.run()
        self.assertFalse(self.app.exception)
        self.assertEqual(len(self.manager.store.sessions()), 1)
        self.assertEqual(len(self.manager.store.alerts()), 3)
        self.assertEqual(source.closed, 1)
        session = self.manager.store.sessions()[0]
        self.assertEqual(json.loads(session['counters_json'])['status'], session['status'])

    def test_capture_dependency_error_leaves_csv_available(self):
        with patch('seguridad_pymes.monitor_ui._interfaces', side_effect=CaptureError('TShark/Npcap no disponible')):
            self.app.run()
        self.assertFalse(self.app.exception)
        self.assertTrue(any('TShark/Npcap' in element.value for element in self.app.error))
        self.assertTrue(any(header.value == 'Analizar un archivo' for header in self.app.header))


if __name__ == '__main__':
    unittest.main()
