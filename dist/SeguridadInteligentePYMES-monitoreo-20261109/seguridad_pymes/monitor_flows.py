"""Incremental adapter reusing the offline extractor's actual flow calculations."""
from collections import Counter
from decimal import Decimal
import heapq

from seguridad_pymes.pcap_extract import _Flow, _key, _bare_syn
from seguridad_pymes.pcap_reader import CaptureError
from seguridad_pymes.pcap_schema import ExtractionConfig


class IncrementalFlows:
    def __init__(self, identity, config=None, max_flow_packets=256):
        self.identity = identity
        self.config = config or ExtractionConfig()
        self.max_flow_packets = max_flow_packets
        self.active = {}
        self.deadlines = []
        self.ordinal = self.seen = self.accepted = self.closed = 0
        self.previous_frame = 0
        self.previous_time = None
        self.rejections = Counter()

    def _deadline(self, flow):
        idle = self.config.tcp_idle_seconds if flow.protocol == 'tcp' else self.config.udp_idle_seconds
        idle_ns = flow.last_ns + int(Decimal(str(idle)) * 1_000_000_000)
        active_ns = flow.first_ns + int(Decimal(str(self.config.active_timeout_seconds)) * 1_000_000_000)
        return min(idle_ns, active_ns), 'active_timeout' if active_ns <= idle_ns else 'idle_timeout'

    def _close(self, key, reason):
        self.closed += 1
        result = self.active.pop(key).finish(reason, self.identity)
        if self.rejections:
            result['quality']['capture_has_rejected_packets'] = True
        return result

    def expire(self, timestamp_ns):
        done = []
        while self.deadlines and self.deadlines[0][0] <= timestamp_ns:
            _, ordinal, frame, key = heapq.heappop(self.deadlines)
            flow = self.active.get(key)
            if flow is not None and flow.ordinal == ordinal and flow.frames[-1] == frame:
                done.append(self._close(key, self._deadline(flow)[1]))
        return done

    def push(self, observation):
        self.seen += 1
        if self.seen > self.config.max_packets:
            raise CaptureError('Límite de paquetes de la sesión alcanzado.')
        if observation.frame <= self.previous_frame or (self.previous_time is not None and observation.timestamp_ns < self.previous_time):
            self.rejections['out_of_order_frame_or_timestamp'] += 1
            return [], None
        self.previous_frame, self.previous_time = observation.frame, observation.timestamp_ns
        done = self.expire(observation.timestamp_ns)
        packet = observation.packet
        if packet is None:
            self.rejections[observation.rejection_reason] += 1
            return done, None
        if packet.src == packet.dst and packet.sport == packet.dport:
            self.rejections['indistinguishable_flow_endpoints'] += 1
            return done, None
        key = _key(packet)
        flow = self.active.get(key)
        if flow is not None and _bare_syn(packet):
            if (packet.src, packet.sport) != flow.source or packet.tcp_sequence != flow.initial_syn_sequence or all(d.flags['fin'] for d in flow.directions):
                done.append(self._close(key, 'new_tcp_syn'))
                flow = None
        if flow is None:
            if len(self.active) >= self.config.max_active_flows or self.ordinal >= self.config.max_flows:
                raise CaptureError('Límite de flujos alcanzado; la sesión es parcial.')
            self.ordinal += 1
            flow = self.active[key] = _Flow(packet, self.ordinal)
        flow.add(packet)
        self.accepted += 1
        if packet.protocol == 'tcp' and packet.tcp_flags & 4:
            done.append(self._close(key, 'tcp_rst'))
        elif len(flow.frames) >= self.max_flow_packets:
            done.append(self._close(key, 'live_packet_window'))
        else:
            heapq.heappush(self.deadlines, (self._deadline(flow)[0], flow.ordinal, packet.frame, key))
        if len(self.deadlines) > max(1024, 4 * len(self.active)):
            self.deadlines = [(self._deadline(f)[0], f.ordinal, f.frames[-1], k) for k, f in self.active.items()]
            heapq.heapify(self.deadlines)
        return done, packet

    def finish(self, reason='monitor_stopped'):
        done = [self._close(key, reason) for key in list(self.active)]
        self.deadlines.clear()
        return done
