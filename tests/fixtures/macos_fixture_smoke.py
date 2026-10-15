"""隔离客户端内核实受控远端；不能作为苹果原生证据。"""
import secrets
import socket
import time
import os
import struct

from macos_dns import read_exact

identity = os.environ.get("VAP_FIXTURE_ID", "")
prefix = (identity + ":").encode() if identity else b""

deadline = time.monotonic() + 30
marker = secrets.token_bytes(24)
while True:
    try:
        with socket.create_connection(("10.231.66.1", 19090), timeout=2) as tcp:
            actual = b""
            while len(actual) < len(prefix):
                part = tcp.recv(len(prefix) - len(actual))
                if not part:
                    raise RuntimeError("受控远端提前关闭身份标记")
                actual += part
            assert actual == prefix
            tcp.sendall(marker)
            reply = b""
            while len(reply) < len(marker):
                part = tcp.recv(len(marker) - len(reply))
                if not part:
                    raise RuntimeError("受控流式回显提前关闭")
                reply += part
            assert reply == marker
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
            udp.settimeout(2)
            udp.connect(("10.231.66.1", 19090))
            udp.send(marker)
            assert udp.recv(256) == prefix + marker
        if identity:
            for truncated in (False, True):
                name = ("truncated." if truncated else "") + identity + ".test"
                query = secrets.token_bytes(2) + b"\x01\0\0\x01" + b"\0" * 6
                query += b"".join(bytes([len(label)]) + label.encode() for label in name.split("."))
                query += b"\0\0\x01\0\x01"
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
                    udp.settimeout(2)
                    udp.connect(("10.231.66.1", 53))
                    udp.send(query)
                    reply = udp.recv(512)
                assert reply[:2] == query[:2] and reply[12:len(query)] == query[12:]
                if truncated:
                    assert reply[2:12] == b"\x83\x80\0\x01" + b"\0" * 6
                    with socket.create_connection(("10.231.66.1", 53), timeout=2) as tcp:
                        tcp.sendall(struct.pack("!H", len(query)) + query)
                        count = struct.unpack("!H", read_exact(tcp, 2))[0]
                        assert count <= 512
                        reply = read_exact(tcp, count)
                assert reply[:2] == query[:2] and reply[12:len(query)] == query[12:]
                assert reply[2:12] == b"\x81\x80\0\x01\0\x01" + b"\0" * 4
                assert reply[len(query):] == b"\xc0\x0c\0\x01\0\x01\0\0\0\0\0\x04\x0a\xe7\x42\x01"
        print("隔离客户端的真实隧道与双向回显通过")
        break
    except OSError:
        if time.monotonic() >= deadline:
            raise
        time.sleep(0.1)
