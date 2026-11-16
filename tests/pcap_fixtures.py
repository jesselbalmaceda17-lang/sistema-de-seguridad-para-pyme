"""Tiny synthetic Ethernet/IPv4 fixtures; standard library, no live interfaces."""

import struct


def ethernet_packet(protocol="udp", *, reverse=False, flags=0x10, sequence=100, payload=b""):
    source = b"\x0a\x00\x00\x01"
    destination = b"\x0a\x00\x00\x02"
    sport, dport = 40000, 8080
    if reverse:
        source, destination = destination, source
        sport, dport = dport, sport
    if protocol == "tcp":
        transport = struct.pack("!HHIIBBHHH", sport, dport, sequence, 0, 0x50, flags, 1024, 0, 0)
        number = 6
    else:
        transport = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0)
        number = 17
    header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(transport) + len(payload),
                         1, 0, 64, number, 0, source, destination)
    words = struct.unpack("!10H", header)
    total = sum(words)
    while total >> 16:
        total = (total & 0xffff) + (total >> 16)
    checksum = (~total) & 0xffff
    header = header[:10] + struct.pack("!H", checksum) + header[12:]
    return b"\x02\x00\x00\x00\x00\x02\x02\x00\x00\x00\x00\x01\x08\x00" + header + transport + payload


def pcap(packets):
    data = struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
    for timestamp_us, packet in packets:
        seconds, microseconds = divmod(timestamp_us, 1_000_000)
        data += struct.pack("<IIII", seconds, microseconds, len(packet), len(packet)) + packet
    return data


def pcapng(packets):
    def block(kind, body):
        length = 12 + len(body)
        return struct.pack("<II", kind, length) + body + struct.pack("<I", length)
    data = block(0x0a0d0d0a, struct.pack("<IHHq", 0x1a2b3c4d, 1, 0, -1))
    data += block(1, struct.pack("<HHI", 1, 0, 65535))
    for timestamp_us, packet in packets:
        body = struct.pack("<IIIII", 0, timestamp_us >> 32, timestamp_us & 0xffffffff, len(packet), len(packet))
        body += packet + b"\0" * ((-len(packet)) % 4)
        data += block(6, body)
    return data
