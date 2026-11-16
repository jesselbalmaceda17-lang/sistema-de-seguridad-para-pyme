"""Transparent rolling-window observations; never labels an attack as confirmed."""
from collections import Counter, deque
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import hashlib

from seguridad_pymes.pcap_reader import CaptureError


@dataclass(frozen=True)
class RuleConfig:
    window_seconds: int = 30
    syn_packets: int = 100
    destination_ports: int = 30
    ipv4_bytes: int = 10 * 1024**2
    max_events: int = 50000

    def __post_init__(self):
        for name, maximum in [('window_seconds', 300), ('syn_packets', 1000000),
                              ('destination_ports', 65536), ('ipv4_bytes', 1024**4), ('max_events', 100000)]:
            value = getattr(self, name)
            if type(value) is not int or not 1 <= value <= maximum:
                raise ValueError(f'Configuración de regla inválida: {name}.')


class RuleEngine:
    def __init__(self, session_id, config=None):
        self.session_id = session_id
        self.config = config or RuleConfig()
        self.events = deque()
        self.syns, self.bytes = Counter(), Counter()
        self.ports = {}
        self.last_alert = {}

    def expire(self, now):
        cutoff = now - self.config.window_seconds * 10**9
        while self.events and self.events[0][0] <= cutoff:
            _, source, syn, port, size = self.events.popleft()
            self.bytes[source] -= size
            if syn:
                self.syns[source] -= 1
                self.ports[source][port] -= 1
                if self.ports[source][port] == 0:
                    del self.ports[source][port]
            if self.bytes[source] == 0:
                del self.bytes[source]
                self.syns.pop(source, None)
                self.ports.pop(source, None)
        for key, timestamp in list(self.last_alert.items()):
            if timestamp <= cutoff:
                del self.last_alert[key]

    def push(self, packet):
        self.expire(packet.timestamp_ns)
        if len(self.events) >= self.config.max_events:
            raise CaptureError('Ventana de reglas llena; se detiene sin descartar evidencia silenciosamente.')
        syn = packet.protocol == 'tcp' and bool(packet.tcp_flags & 2) and not bool(packet.tcp_flags & 16)
        self.events.append((packet.timestamp_ns, packet.src, syn, packet.dport, packet.ipv4_bytes))
        self.bytes[packet.src] += packet.ipv4_bytes
        if syn:
            self.syns[packet.src] += 1
            self.ports.setdefault(packet.src, Counter())[packet.dport] += 1
        definitions = [
            ('syn_observed', self.syns[packet.src], self.config.syn_packets, 'media',
             'Muchos paquetes TCP SYN sin ACK observados desde este origen; pueden incluir retransmisiones.'),
            ('destination_ports', len(self.ports.get(packet.src, {})), self.config.destination_ports, 'media',
             'Se observaron SYN iniciales hacia numerosos puertos de destino distintos desde este origen.'),
            ('ipv4_volume', self.bytes[packet.src], self.config.ipv4_bytes, 'baja',
             'El volumen IPv4 observado desde este origen superó el umbral; un volumen alto puede ser legítimo.'),
        ]
        alerts = []
        window = self.config.window_seconds * 10**9
        for rule, value, threshold, severity, message in definitions:
            key = (rule, packet.src)
            if value < threshold or packet.timestamp_ns - self.last_alert.get(key, -10**30) < window:
                continue
            self.last_alert[key] = packet.timestamp_ns
            start = packet.timestamp_ns - window
            identifier = f'{self.session_id}:{rule}:{packet.src}:{packet.timestamp_ns}'
            alerts.append({'event_id': hashlib.sha256(identifier.encode()).hexdigest(), 'session_id': self.session_id,
                'detector': 'transparent_rules_v1', 'rule': rule, 'source': packet.src, 'severity': severity,
                'detected_at': datetime.fromtimestamp(packet.timestamp_ns / 1e9, timezone.utc).isoformat(),
                'window_start_ns': str(start), 'window_end_ns': str(packet.timestamp_ns),
                'window_seconds': self.config.window_seconds, 'threshold': threshold, 'observed': value,
                'evidence': {'value': value, 'operator': '>=', 'window_seconds': self.config.window_seconds,
                             'destination_ports': sorted(self.ports.get(packet.src, {}))[:100],
                             'visibility': 'observed IPv4 TCP/UDP only; capture completeness not established'},
                'message': message + ' Requiere revisión; no confirma un ataque.', 'review_state': 'pending'})
        return alerts
