"""Safe demonstration: connects only to TCP/UDP listeners it owns on 127.0.0.1."""
import argparse
import json
import socket
import threading
import time


class LocalTrafficLab:
    def __init__(self, ports=6):
        if type(ports) is not int or not 1 <= ports <= 16:
            raise ValueError('Use entre uno y dieciséis servicios locales propios.')
        self.stop_event = threading.Event()
        self.sockets, self.threads, self.ports = [], [], []
        try:
            for _ in range(ports):
                server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.sockets.append(server)
                server.bind(('127.0.0.1', 0))
                server.listen(8)
                server.settimeout(.1)
                self.ports.append(server.getsockname()[1])
                thread = threading.Thread(target=self._tcp, args=(server,), daemon=True)
                self.threads.append(thread)
                thread.start()
            self.udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.sockets.append(self.udp)
            self.udp.bind(('127.0.0.1', 0))
            self.udp.settimeout(.1)
            self.ports.append(self.udp.getsockname()[1])
            thread = threading.Thread(target=self._udp, daemon=True)
            self.threads.append(thread)
            thread.start()
        except BaseException:
            self.close()
            raise

    def _tcp(self, server):
        while not self.stop_event.is_set():
            try:
                client, _ = server.accept()
                with client:
                    client.settimeout(1)
                    data = client.recv(2048)
                    client.sendall(data)
            except (OSError, TimeoutError):
                pass

    def _udp(self):
        while not self.stop_event.is_set():
            try:
                data, address = self.udp.recvfrom(2048)
                self.udp.sendto(data, address)
            except (OSError, TimeoutError):
                pass

    def generate(self, connections=12, udp_packets=8):
        if any(type(count) is not int or not 0 <= count <= 1000 for count in (connections, udp_packets)):
            raise ValueError('Límite de demostración: 0–1.000 intercambios locales por protocolo.')
        payload = b'SIPYMES authorized local laboratory. ' + b'x' * 200
        for index in range(connections):
            with socket.create_connection(('127.0.0.1', self.ports[index % (len(self.ports) - 1)]), timeout=2) as client:
                client.sendall(payload)
                assert client.recv(2048) == payload
            time.sleep(.02)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
            client.settimeout(2)
            for _ in range(udp_packets):
                client.sendto(payload, ('127.0.0.1', self.ports[-1]))
                assert client.recvfrom(2048)[0] == payload
                time.sleep(.02)
        return {'scope': 'Only self-owned loopback listeners; no remote targets or scanning',
                'tcp_connections_completed': connections, 'udp_echoes_completed': udp_packets,
                'owned_service_ports': self.ports}

    def close(self):
        self.stop_event.set()
        for sock in self.sockets:
            sock.close()
        for thread in self.threads:
            thread.join(timeout=1.2)

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--ports', type=int, default=6)
    parser.add_argument('--connections', type=int, default=12)
    parser.add_argument('--udp-packets', type=int, default=8)
    args = parser.parse_args()
    with LocalTrafficLab(args.ports) as lab:
        print(json.dumps(lab.generate(args.connections, args.udp_packets)))


if __name__ == '__main__':
    main()
