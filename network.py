"""
network.py
Tiny length-prefixed JSON message protocol shared by client and server.

Wire format: 4-byte big-endian length, followed by that many bytes of UTF-8 JSON.
"""

import json
import struct


def send_msg(sock, obj: dict):
    payload = json.dumps(obj).encode("utf-8")
    header = struct.pack(">I", len(payload))
    sock.sendall(header + payload)


def recv_exact(sock, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Connection closed while reading")
        buf += chunk
    return buf


def recv_msg(sock) -> dict:
    header = recv_exact(sock, 4)
    (length,) = struct.unpack(">I", header)
    payload = recv_exact(sock, length)
    return json.loads(payload.decode("utf-8"))