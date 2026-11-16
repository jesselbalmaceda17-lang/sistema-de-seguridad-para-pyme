"""Single-owner, bounded background capture lifecycle; no Streamlit calls or ML."""
import atexit
from collections import deque
from copy import deepcopy
from dataclasses import asdict, dataclass, field
import hashlib
import json
import os
from pathlib import Path
import queue
import shutil
import threading
import time
import uuid
import weakref

from seguridad_pymes.database import PersistenceError
from seguridad_pymes.monitor_capture import LiveSource, list_interfaces
from seguridad_pymes.monitor_flows import IncrementalFlows
from seguridad_pymes.monitor_rules import RuleConfig, RuleEngine
from seguridad_pymes.monitor_store import MonitorStore, storage_bytes
from seguridad_pymes.pcap_reader import CaptureError
from seguridad_pymes.pcap_schema import ExtractionConfig

_CAPTURE_SLOT = threading.Lock()  # desktop application: at most one capture per server
_MANAGERS = weakref.WeakSet()


@dataclass(frozen=True)
class CaptureConfig:
    duration_seconds: float = 300
    capture_memory_mib: int = 256
    storage_mib: int = 128
    max_packets: int = 100000
    max_active_flows: int = 2000
    max_flows: int = 10000
    queue_packets: int = 1024
    max_flow_packets: int = 256
    heartbeat_seconds: float = 20
    tcp_idle_seconds: float = 5
    udp_idle_seconds: float = 5
    active_seconds: float = 30
    allowed_ports: tuple[int, ...] = ()  # laboratory isolation, not arbitrary shell/filter text
    excluded_ports: tuple[int, ...] = ()  # UI control channel must not observe its own refresh traffic
    rules: RuleConfig = field(default_factory=RuleConfig)

    def __post_init__(self):
        for name, low, high in [('capture_memory_mib', 64, 2048), ('storage_mib', 16, 2048),
            ('max_packets', 1, 1000000), ('max_active_flows', 1, 10000), ('max_flows', 1, 100000),
            ('queue_packets', 1, 10000), ('max_flow_packets', 1, 4096)]:
            value = getattr(self, name)
            if type(value) is not int or not low <= value <= high:
                raise ValueError(f'Límite de monitoreo inválido: {name}.')
        import math
        for name, low, high in [('duration_seconds', .1, 3600), ('heartbeat_seconds', .2, 120),
            ('tcp_idle_seconds', .001, 300), ('udp_idle_seconds', .001, 300), ('active_seconds', .001, 300)]:
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or not low <= value <= high:
                raise ValueError(f'Tiempo de monitoreo inválido: {name}.')
        for ports in (self.allowed_ports, self.excluded_ports):
            if not isinstance(ports, tuple) or len(ports) > 32 or any(type(port) is not int or not 1 <= port <= 65535 for port in ports):
                raise ValueError('Puertos de alcance inválidos.')
        if not isinstance(self.rules, RuleConfig):
            raise ValueError('Configuración de reglas inválida.')

    @property
    def raw_capture_kib(self):
        return self.storage_mib * 1024 // 2


def connection_id(session, interface, protocol, source, destination):
    endpoints = sorted((source, destination))
    return hashlib.sha256(json.dumps([session, interface, protocol, endpoints], separators=(',', ':')).encode()).hexdigest()


class CaptureManager:
    def __init__(self, root, *, source_factory=LiveSource, interface_provider=list_interfaces):
        self.store = MonitorStore(root)
        self.source_factory = source_factory
        self.interface_provider = interface_provider
        self.lock = threading.RLock()
        self.thread = None
        self.source = None
        self.stop_event = threading.Event()
        self.last_heartbeat = time.monotonic()
        self.state = {'status': 'idle', 'session_id': None, 'reason': '', 'errors': []}
        _MANAGERS.add(self)

    @property
    def active(self):
        return self.thread is not None and self.thread.is_alive()

    def heartbeat(self):
        with self.lock:
            self.last_heartbeat = time.monotonic()

    def snapshot(self):
        with self.lock:
            return deepcopy(self.state)

    def start(self, interface_id, config=None, *, authorized=False):
        if authorized is not True:
            raise CaptureError('Confirme que está autorizado para monitorear esta interfaz.')
        config = config or CaptureConfig()
        with self.lock:
            if self.active:
                return self.state['session_id']
            interfaces = {item.identifier: item for item in self.interface_provider()}
            if interface_id not in interfaces:
                raise CaptureError('La interfaz ya no está disponible. Actualice la lista y vuelva a seleccionarla.')
            if not _CAPTURE_SLOT.acquire(blocking=False):
                raise CaptureError('Ya hay otro monitoreo activo en este servidor. Debe detenerse primero.')
            try:
                self.store.initialize()
                if storage_bytes(self.store.root) >= config.storage_mib * 1024**2 - 4 * 1024**2:
                    raise CaptureError('El historial y las capturas alcanzan el presupuesto de almacenamiento. Respalde antes de liberar espacio o elija otro directorio.')
                if shutil.disk_usage(self.store.root).free < config.storage_mib * 1024**2 + 16 * 1024**2:
                    raise CaptureError('No hay espacio libre suficiente para el presupuesto de captura.')
                session = uuid.uuid4().hex
                directory = self.store.root / 'sessions' / session
                directory.mkdir(parents=True, exist_ok=False)
                interface = interfaces[interface_id]
                (directory / 'config.json').write_text(json.dumps(asdict(config), indent=2), encoding='utf-8')
                self.store.create(session, interface, asdict(config), directory / 'capture.pcapng')
                self.stop_event = threading.Event()
                self.last_heartbeat = time.monotonic()
                self.state = {'status': 'starting', 'session_id': session, 'interface': interface.description,
                    'reason': '', 'errors': [], 'packets_seen': 0, 'packets_accepted': 0, 'packets_rejected': 0,
                    'connections_observed': 0, 'flows_closed': 0, 'flows_persisted': 0,
                    'alerts_generated': 0, 'alerts_persisted': 0, 'capture_rss_peak': 0,
                    'partial': False, 'forced_stop': False, 'source_kind': 'live', 'recent_flows': []}
                self.thread = threading.Thread(target=self._run, args=(interface, directory, config),
                                               name=f'sipymes-capture-{session[:8]}', daemon=True)
                self.thread.start()
                return session
            except BaseException:
                _CAPTURE_SLOT.release()
                raise

    def stop(self, *, reason='Detenido por el usuario.', wait=False):
        with self.lock:
            if self.active:
                self.state['status'] = 'stopping'
                self.state['reason'] = reason
                self.stop_event.set()
            thread = self.thread
        if wait and thread is not None and thread is not threading.current_thread():
            thread.join(timeout=12)
            if thread.is_alive():
                raise CaptureError('La captura aún está cerrando; no se iniciará otra hasta liberar recursos.')

    def shutdown(self):
        self.stop(reason='La sesión de interfaz se cerró.', wait=True)

    def _run(self, interface, directory, config):
        session = self.state['session_id']
        aggregator = IncrementalFlows(session, ExtractionConfig(tcp_idle_seconds=config.tcp_idle_seconds,
            udp_idle_seconds=config.udp_idle_seconds, active_timeout_seconds=config.active_seconds,
            max_packets=config.max_packets, max_active_flows=config.max_active_flows, max_flows=config.max_flows), config.max_flow_packets)
        rules = RuleEngine(session, config.rules)
        pending_flows, pending_alerts = [], []
        recent = deque(maxlen=30)
        connections = set()
        source = None
        finished = 'stopped'
        started, checkpoint = time.monotonic(), 0
        resource_check = 0
        wall_offset = None
        quota = config.storage_mib * 1024**2

        def accept(observation):
            nonlocal wall_offset
            flows, packet = aggregator.push(observation)
            if wall_offset is None:
                wall_offset = observation.timestamp_ns - time.time_ns()
            pending_flows.extend(flows)
            if packet is not None:
                connections.add(connection_id(session, interface.identifier, packet.protocol,
                                              (packet.src, packet.sport), (packet.dst, packet.dport)))
                alerts = rules.push(packet)
                pending_alerts.extend(alerts)
                with self.lock:
                    self.state['alerts_generated'] += len(alerts)

        def update():
            with self.lock:
                self.state.update(packets_seen=aggregator.seen, packets_accepted=aggregator.accepted,
                    packets_rejected=sum(aggregator.rejections.values()), rejections=dict(aggregator.rejections),
                    connections_observed=len(connections), flows_closed=aggregator.closed,
                    active_flows=len(aggregator.active), elapsed_seconds=round(time.monotonic() - started, 2),
                    storage_bytes=storage_bytes(self.store.root), recent_flows=list(recent))

        def persist(status='capturing', *, enforce_quota=True):
            for flow in pending_flows:
                flow['connection_id'] = connection_id(session, interface.identifier, flow['features']['transport_protocol']['value'],
                    (flow['forward_endpoint']['ipv4'], flow['forward_endpoint']['port']),
                    (flow['reverse_endpoint']['ipv4'], flow['reverse_endpoint']['port']))
                flow['quality']['monitor_session_partial'] = self.state.get('partial', False)
            update()
            counters = self.snapshot()
            counters.pop('recent_flows', None)
            counters['status'] = status
            counters['flows_persisted'] += len(pending_flows)
            counters['alerts_persisted'] += len(pending_alerts)
            self.store.persist(session, pending_flows, pending_alerts, counters, status=status,
                               reason=self.state['reason'], quota_bytes=quota if enforce_quota else None)
            for flow in pending_flows:
                recent.append({'protocolo': flow['features']['transport_protocol']['value'],
                    'origen': f"{flow['forward_endpoint']['ipv4']}:{flow['forward_endpoint']['port']}",
                    'destino': f"{flow['reverse_endpoint']['ipv4']}:{flow['reverse_endpoint']['port']}",
                    'paquetes': len(flow['packet_frames']), 'cierre': flow['close_reason']})
            with self.lock:
                self.state['flows_persisted'] = counters['flows_persisted']
                self.state['alerts_persisted'] = counters['alerts_persisted']
            pending_flows.clear()
            pending_alerts.clear()

        try:
            source = self.source_factory(interface, directory, config)
            with self.lock:
                self.source = source
                self.state['source_kind'] = source.kind
                self.state['pid'] = source.tree.process.pid
            # Persist source identity as well for laboratory replay evidence.
            with self.store.connect() as conn:
                conn.execute('UPDATE monitoring_sessions SET source_kind=? WHERE session_id=?', (source.kind, session))
            while not self.stop_event.is_set():
                if source.error:
                    raise CaptureError(source.error)
                now = time.monotonic()
                if source.ready.is_set():
                    with self.lock:
                        self.state['status'] = 'capturing'
                if now - self.last_heartbeat > config.heartbeat_seconds:
                    self.stop(reason='Sin conexión con la interfaz de usuario; captura detenida por seguridad.')
                    break
                if now - started >= config.duration_seconds + 1:
                    self.stop(reason='Límite de duración alcanzado.')
                    finished = 'completed'
                    break
                if now - resource_check >= .25:
                    rss = source.tree.rss()
                    with self.lock:
                        self.state['capture_rss_peak'] = max(self.state['capture_rss_peak'], rss)
                    if rss > config.capture_memory_mib * 1024**2:
                        raise CaptureError('Límite de memoria del proceso de captura alcanzado.')
                    resource_check = now
                try:
                    accept(source.queue.get(timeout=.1))
                except queue.Empty:
                    if wall_offset is not None:
                        pending_flows.extend(aggregator.expire(time.time_ns() + wall_offset))
                if pending_alerts or len(pending_flows) >= 32 or now - checkpoint >= 1:
                    if storage_bytes(self.store.root) >= quota - 2 * 1024**2:
                        raise CaptureError('Presupuesto de almacenamiento alcanzado; sesión parcial.')
                    persist()
                    checkpoint = now
                if source.ended.is_set() and source.queue.empty():
                    finished = 'completed'
                    break
        except Exception as error:
            finished = 'failed'
            with self.lock:
                self.state['partial'] = True
                self.state['reason'] = str(error)
                self.state['errors'] = [str(error)]
        finally:
            try:
                if source is not None:
                    source.close()
                    with self.lock:
                        self.state['forced_stop'] = source.forced
                        self.state['diagnostics'] = source.diagnostics
                        self.state['stop_signal'] = getattr(source.tree, 'signal_diagnostic', None)
                    if source.error or source.forced or (source.tree.process.returncode and not self.stop_event.is_set()):
                        finished = 'failed'
                        with self.lock:
                            self.state['partial'] = True
                            self.state['reason'] = source.error or ('Cierre forzado; captura posiblemente incompleta.' if source.forced else source.diagnostics[-1500:])
                    while not source.queue.empty():
                        accept(source.queue.get_nowait())
                pending_flows.extend(aggregator.finish('monitor_partial' if self.state['partial'] else 'monitor_stopped'))
                persist(finished)
            except Exception as error:
                finished = 'failed'
                with self.lock:
                    self.state.update(partial=True, reason=str(error), flows_not_persisted=len(pending_flows),
                                      alerts_not_persisted=len(pending_alerts), errors=[str(error)])
                pending_flows.clear()
                pending_alerts.clear()
                try:
                    persist('failed', enforce_quota=False)  # final small diagnostic, no new flow/alert payload
                except Exception as final_error:
                    with self.lock:
                        self.state['errors'].append(str(final_error))
            finally:
                with self.lock:
                    self.state['status'] = finished
                try:
                    update()
                finally:
                    _CAPTURE_SLOT.release()


def _cleanup():
    for manager in list(_MANAGERS):
        try:
            manager.shutdown()
        except Exception:
            pass


atexit.register(_cleanup)
