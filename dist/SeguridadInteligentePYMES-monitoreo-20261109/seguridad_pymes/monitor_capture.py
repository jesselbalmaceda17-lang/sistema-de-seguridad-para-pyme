"""Bounded live field transport. The conservative offline reader is unchanged."""
import csv
from dataclasses import dataclass
import ipaddress
import os
from pathlib import Path
import queue
import re
import subprocess
import threading

from seguridad_pymes.monitor_process import ProcessTree
from seguridad_pymes.pcap_reader import (
    CaptureError, FIELDS, Packet, PacketObservation, _boolean, _integer,
    decode_row, find_tshark,
)

LIVE_FIELDS = (*FIELDS, 'null.family')
LIVE_HELP = 'Para capturar se requieren TShark y Npcap con permiso de captura. No se elevan privilegios automáticamente.'


@dataclass(frozen=True)
class CaptureInterface:
    identifier: str
    description: str
    loopback: bool = False


def list_interfaces(executable=None):
    try:
        tool = find_tshark(executable)
        options = {'creationflags': subprocess.CREATE_NO_WINDOW} if os.name == 'nt' else {}
        result = subprocess.run([str(tool), '-D'], capture_output=True, text=True, encoding='utf-8',
                                errors='replace', timeout=8, **options)
        if result.returncode:
            raise CaptureError(result.stderr[:1500])
        interfaces = []
        for line in result.stdout.splitlines():
            match = re.fullmatch(r'\d+\.\s+(\S+)(?:\s+\((.*)\))?', line.strip())
            if not match:
                continue
            identifier, description = match.groups()
            if os.name == 'nt' and not identifier.startswith('\\Device\\NPF_'):
                continue  # extcap plugins/remote interfaces are outside this local capture UI
            interfaces.append(CaptureInterface(identifier, description or identifier, 'loopback' in identifier.lower()))
        if not interfaces:
            raise CaptureError('No hay interfaces locales Npcap disponibles.')
        return sorted(interfaces, key=lambda item: (not item.loopback, item.description))
    except (OSError, subprocess.SubprocessError, CaptureError) as error:
        raise CaptureError(f'{LIVE_HELP} Detalle: {error}') from error


def decode_live_row(row):
    base = decode_row(row)
    if row.get('frame.encap_type') != '15':
        return base
    if base.rejection_reason != 'unsupported_link_layer':
        return base

    def reject(reason):
        return PacketObservation(base.frame, base.timestamp_ns, None, reason)

    if row.get('null.family') != '2':
        return reject('unsupported_loopback_family')
    try:
        if row['ip.version'] != '4' or _boolean(row['ip.flags.mf']) or _integer(row['ip.frag_offset']):
            return reject('ipv4_fragment_or_non_ipv4_not_supported')
        src, dst = str(ipaddress.IPv4Address(row['ip.src'])), str(ipaddress.IPv4Address(row['ip.dst']))
        length, header, captured = int(row['ip.len']), int(row['ip.hdr_len']), int(row['frame.cap_len'])
        if not (20 <= header <= 60 and header % 4 == 0 and header <= length <= 65535 and length + 4 <= captured):
            return reject('invalid_ipv4_length')
        number = int(row['ip.proto'])
        if number not in (6, 17):
            return reject('unsupported_transport_protocol')
        protocol = 'tcp' if number == 6 else 'udp'
        sport, dport = int(row[f'{protocol}.srcport']), int(row[f'{protocol}.dstport'])
        if not 0 <= sport <= 65535 or not 0 <= dport <= 65535:
            return reject('invalid_transport_port')
        flags = sequence = None
        if protocol == 'tcp':
            th = int(row['tcp.hdr_len'])
            flags, sequence = _integer(row['tcp.flags']), int(row['tcp.seq_raw'])
            if not (20 <= th <= 60 and th % 4 == 0 and header + th <= length and 0 <= flags <= 511 and 0 <= sequence <= 0xffffffff):
                return reject('invalid_tcp_header')
        elif int(row['udp.length']) != length - header or length - header < 8:
            return reject('invalid_udp_length')
        packet = Packet(base.frame, base.timestamp_ns, row['frame.interface_id'] or 'implicit-single-interface',
                        src, sport, dst, dport, protocol, length, flags, sequence)
        return PacketObservation(base.frame, base.timestamp_ns, packet)
    except (ValueError, KeyError, TypeError):
        return reject('missing_or_invalid_header')


class LiveSource:
    kind = 'live'

    def __init__(self, interface, directory, config, *, executable=None, replay=None):
        self.queue = queue.Queue(maxsize=config.queue_packets)
        self.ended = threading.Event()
        self.ready = threading.Event()
        self.error = None
        self.diagnostics = ''
        self.config = config
        self.tree = None
        self._threads = []
        self.forced = False
        try:
            tool = find_tshark(executable)
        except CaptureError as error:
            raise CaptureError(LIVE_HELP) from error
        directory = Path(directory)
        profile = directory / 'profile'
        profile.mkdir(exist_ok=False)
        env = dict(os.environ, WIRESHARK_CONFIG_DIR=str(profile), LC_ALL='C')
        if replay is None:
            bpf = 'ip and (tcp or udp)'
            if config.allowed_ports:
                bpf += ' and (' + ' or '.join(f'port {port}' for port in config.allowed_ports) + ')'
            if config.excluded_ports:
                bpf += ' and not (' + ' or '.join(f'port {port}' for port in config.excluded_ports) + ')'
            command = [str(tool), '-i', interface.identifier, '-p', '-n', '-l', '-B', '2', '-s', '65535',
                       '-f', bpf, '-a', f'duration:{config.duration_seconds}',
                       '-a', f'filesize:{config.raw_capture_kib}', '-c', str(config.max_packets),
                       '-w', str(directory / 'capture.pcapng'), '-P']
        else:
            self.kind = 'laboratory_replay'
            command = [str(tool), '-n', '-l', '-r', str(Path(replay).resolve())]
        command += ['-o', 'ip.defragment:FALSE', '-o', 'tcp.desegment_tcp_streams:FALSE',
                    '-o', 'tcp.analyze_sequence_numbers:FALSE', '-T', 'fields',
                    '-E', 'header=y', '-E', 'separator=/t', '-E', 'quote=d', '-E', 'occurrence=f']
        for field in LIVE_FIELDS:
            command += ['-e', field]
        self.command = command
        try:
            self.tree = ProcessTree(command, env=env, memory_mib=config.capture_memory_mib)
            self._threads = [threading.Thread(target=self._read, daemon=True), threading.Thread(target=self._stderr, daemon=True)]
            for thread in self._threads:
                thread.start()
        except BaseException:
            if self.tree:
                self.tree.close()
            raise

    def _read(self):
        try:
            rows = csv.reader(self.tree.process.stdout, delimiter='\t', quotechar='"', strict=True)
            header = next(rows, None)
            if header is None:
                return  # no packets may mean no fields header; check exit code/diagnostics
            if header != list(LIVE_FIELDS):
                raise CaptureError('La salida de TShark no tiene el esquema de campos esperado.')
            self.ready.set()
            for values in rows:
                if len(values) != len(LIVE_FIELDS):
                    raise CaptureError('Fila incompleta en la captura; se conserva como sesión parcial.')
                observation = decode_live_row(dict(zip(LIVE_FIELDS, values)))
                try:
                    self.queue.put_nowait(observation)
                except queue.Full:
                    raise CaptureError('Cola de paquetes llena; se detiene para no ocultar pérdida de datos.')
        except (CaptureError, csv.Error, OSError, UnicodeError) as error:
            self.error = str(error)
        finally:
            self.ended.set()

    def _stderr(self):
        try:
            for line in self.tree.process.stderr:
                self.diagnostics = (self.diagnostics + line)[-4000:]
                if 'Capturing on' in line:
                    self.ready.set()
        except OSError:
            pass

    def close(self):
        self.tree.close()
        for thread in self._threads:
            thread.join(timeout=1)
        self.forced = self.tree.forced
        self.tree.close_pipes()
