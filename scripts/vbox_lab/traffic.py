#!/usr/bin/env python3
"""Small HTTP/UDP service and bounded peer-only traffic for the VBox lab."""
import argparse
import http.server
import json
import socket
import subprocess
import threading
import time
import urllib.request

PEERS = ('192.168.56.10', '192.168.56.20')


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = bytes(range(256)) * 4 if self.path.startswith('/bytes') else b'Sniff4Hound isolated lab: healthy\n'
        self.send_response(200)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def serve():
    def udp():
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.bind(('0.0.0.0', 9999))
            while True:
                data, source = sock.recvfrom(2048)
                if source[0] in PEERS:
                    sock.sendto(data[::-1], source)
    threading.Thread(target=udp, daemon=True).start()
    http.server.HTTPServer(('0.0.0.0', 8080), Handler).serve_forever()


def traffic(peer, rounds):
    if peer not in PEERS:
        raise ValueError('Only the two isolated lab peers are allowed')
    for i in range(rounds):
        result = {'sequence': i, 'peer': peer}
        for path in ('/health', '/bytes'):
            try:
                with urllib.request.urlopen(f'http://{peer}:8080{path}?n={i}', timeout=2) as response:
                    result[path] = len(response.read())
            except OSError as exc:
                result[path] = str(exc)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(2)
            try:
                sock.sendto(bytes((v + i) % 256 for v in range(256)), (peer, 9999))
                result['udp_bytes'] = len(sock.recv(2048))
            except OSError as exc:
                result['udp_error'] = str(exc)
        result['ping_exit'] = subprocess.run(['ping', '-c', '1', '-W', '1', peer], stdout=subprocess.DEVNULL).returncode
        print(json.dumps(result), flush=True)
        time.sleep(2)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('mode', choices=['serve', 'traffic'])
    parser.add_argument('--peer', choices=PEERS)
    parser.add_argument('--rounds', type=int, default=300)
    args = parser.parse_args()
    if args.mode == 'serve':
        serve()
    else:
        if not args.peer or not 1 <= args.rounds <= 900:
            parser.error('traffic requires --peer and 1–900 rounds')
        traffic(args.peer, args.rounds)
