"""Offline TShark transport; standard library only, no interface capture."""

import csv
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
import ipaddress
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import threading


FIELDS = (
    "frame.number", "frame.time_epoch", "frame.len", "frame.cap_len",
    "frame.encap_type", "frame.interface_id", "eth.type", "vlan.id",
    "ip.version", "ip.src", "ip.dst", "ip.len", "ip.hdr_len",
    "ip.flags.mf", "ip.frag_offset", "ip.proto",
    "tcp.srcport", "tcp.dstport", "tcp.hdr_len", "tcp.flags", "tcp.seq_raw",
    "udp.srcport", "udp.dstport", "udp.length", "_ws.malformed",
)

INSTALL_HELP = (
    "TShark no disponible. Instale manualmente Wireshark para Windows 11 desde "
    "https://www.wireshark.org/download.html seleccionando TShark. "
    "Compruebe tshark --version o use --tshark con la ruta a tshark.exe. "
    "Este componente solo lee archivos; no necesita capturar interfaces ni instalar Npcap para esa lectura."
)


class CaptureError(ValueError):
    """The capture could not be processed reliably; no completed report exists."""


class TSharkUnavailable(CaptureError):
    pass


@dataclass(frozen=True)
class Packet:
    frame: int
    timestamp_ns: int
    interface: str
    src: str
    sport: int
    dst: str
    dport: int
    protocol: str
    ipv4_bytes: int
    tcp_flags: int | None = None
    tcp_sequence: int | None = None


@dataclass(frozen=True)
class PacketObservation:
    frame: int
    timestamp_ns: int
    packet: Packet | None
    rejection_reason: str | None = None


def find_tshark(explicit=None):
    if explicit is not None:
        path = Path(explicit).expanduser().resolve()
        if not path.is_file():
            raise TSharkUnavailable(INSTALL_HELP)
        return path
    found = shutil.which("tshark")
    if found:
        return Path(found).resolve()
    for base in (os.environ.get("ProgramFiles"), os.environ.get("ProgramFiles(x86)")):
        if base:
            candidate = Path(base) / "Wireshark" / "tshark.exe"
            if candidate.is_file():
                return candidate.resolve()
    raise TSharkUnavailable(INSTALL_HELP)


def _integer(value):
    return int(value, 16) if value.lower().startswith("0x") else int(value)


def _boolean(value):
    """TShark fields may render booleans as True/False or 1/0."""
    normalized = value.casefold()
    if normalized in {"true", "1"}:
        return True
    if normalized in {"false", "0"}:
        return False
    raise ValueError(f"Invalid boolean field: {value!r}")


def decode_row(row):
    """Reject unobservable/unsupported packets; never infer absent header values."""
    try:
        frame = int(row["frame.number"])
        seconds = Decimal(row["frame.time_epoch"])
        ns = seconds * 1_000_000_000
        if (frame <= 0 or not ns.is_finite()
                or abs(ns) > 9_000_000_000_000_000_000
                or ns != ns.to_integral_value()):
            raise ValueError("invalid packet timestamp/frame")
        timestamp = int(ns)
    except (KeyError, ValueError, InvalidOperation, OverflowError) as error:
        raise CaptureError("Invalid frame number or timestamp in TShark output") from error

    def reject(reason):
        return PacketObservation(frame, timestamp, None, reason)

    try:
        if row["_ws.malformed"]:
            return reject("malformed_packet")
        wire, captured = int(row["frame.len"]), int(row["frame.cap_len"])
        if captured < wire:
            return reject("truncated_packet")
        if captured < 0 or wire < 14 or captured > wire:
            return reject("invalid_frame_length")
        if row["frame.encap_type"] != "1" or not row["eth.type"]:
            return reject("unsupported_link_layer")
        if row["vlan.id"] or _integer(row["eth.type"]) != 0x0800:
            return reject("unsupported_ethernet_payload")
        if row["ip.version"] != "4":
            return reject("unsupported_network_protocol")
        if _boolean(row["ip.flags.mf"]) or _integer(row["ip.frag_offset"]):
            return reject("ipv4_fragment_not_supported")
        source = str(ipaddress.IPv4Address(row["ip.src"]))
        destination = str(ipaddress.IPv4Address(row["ip.dst"]))
        length, header = int(row["ip.len"]), int(row["ip.hdr_len"])
        if (not 20 <= header <= 60 or header % 4
                or not header <= length <= 65535 or length + 14 > captured):
            return reject("invalid_ipv4_length")
        protocol_number = int(row["ip.proto"])
        if protocol_number not in (6, 17):
            return reject("unsupported_transport_protocol")
        protocol = "tcp" if protocol_number == 6 else "udp"
        sport, dport = int(row[f"{protocol}.srcport"]), int(row[f"{protocol}.dstport"])
        if not 0 <= sport <= 65535 or not 0 <= dport <= 65535:
            return reject("invalid_transport_port")
        flags = sequence = None
        if protocol == "tcp":
            transport_header = int(row["tcp.hdr_len"])
            flags, sequence = _integer(row["tcp.flags"]), int(row["tcp.seq_raw"])
            if (not 20 <= transport_header <= 60 or transport_header % 4
                    or header + transport_header > length or not 0 <= flags <= 511
                    or not 0 <= sequence <= 0xffffffff):
                return reject("invalid_tcp_header")
        elif int(row["udp.length"]) != length - header or length - header < 8:
            return reject("invalid_udp_length")
        interface = row["frame.interface_id"]
        if not interface:
            interface = "implicit-single-interface"
        packet = Packet(frame, timestamp, interface, source, sport, destination,
                        dport, protocol, length, flags, sequence)
        return PacketObservation(frame, timestamp, packet)
    except (ValueError, KeyError, TypeError):
        return reject("missing_or_invalid_header")


class TSharkReader:
    def __init__(self, executable=None, timeout_seconds=120.0):
        self.executable = find_tshark(executable)
        self.timeout_seconds = timeout_seconds
        self.version = None
        self.diagnostics = ""

    def _environment(self, directory):
        env = os.environ.copy()
        env["WIRESHARK_CONFIG_DIR"] = directory
        env["LC_ALL"] = "C"
        return env

    def observations(self, capture):
        capture = Path(capture).resolve()
        if not capture.is_file():
            raise CaptureError(f"Capture file not found: {capture}")
        with tempfile.TemporaryDirectory(prefix="sipymes-tshark-") as profile:
            env = self._environment(profile)
            options = {"creationflags": subprocess.CREATE_NO_WINDOW} if os.name == "nt" else {}
            try:
                version = subprocess.run([str(self.executable), "--version"], capture_output=True,
                                         text=True, encoding="utf-8", errors="replace", timeout=10,
                                         env=env, check=True, **options)
                self.version = version.stdout.splitlines()[0]
                command = [str(self.executable), "-n", "-r", str(capture),
                           "-o", "ip.defragment:FALSE", "-o", "tcp.desegment_tcp_streams:FALSE",
                           "-T", "fields", "-E", "header=y", "-E", "separator=/t",
                           "-E", "quote=d", "-E", "occurrence=f"]
                for field in FIELDS:
                    command.extend(["-e", field])
                with tempfile.TemporaryFile() as stderr:
                    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=stderr,
                                               text=True, encoding="utf-8", errors="strict", env=env, **options)
                    expired = threading.Event()

                    def timeout():
                        expired.set()
                        if process.poll() is None:
                            process.kill()

                    timer = threading.Timer(self.timeout_seconds, timeout)
                    timer.daemon = True
                    timer.start()
                    try:
                        rows = csv.reader(process.stdout, delimiter="\t", quotechar='"', strict=True)
                        if next(rows, None) != list(FIELDS):
                            raise CaptureError("TShark output has an incompatible header")
                        for values in rows:
                            if len(values) != len(FIELDS):
                                raise CaptureError("TShark output has an invalid field count")
                            yield decode_row(dict(zip(FIELDS, values)))
                        code = process.wait()
                        stderr.seek(0)
                        self.diagnostics = stderr.read(4000).decode("utf-8", errors="replace").strip()
                        if expired.is_set():
                            raise CaptureError("TShark exceeded its processing timeout")
                        if code:
                            raise CaptureError(f"TShark failed ({code}): {self.diagnostics}")
                    finally:
                        timer.cancel()
                        if process.poll() is None:
                            process.kill()
                        process.wait()
                        process.stdout.close()
            except (OSError, subprocess.SubprocessError, UnicodeError, csv.Error, IndexError) as error:
                raise CaptureError(f"Unable to read capture with TShark: {error}") from error
