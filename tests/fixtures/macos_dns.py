"""专属隧道的确定性解析夹具；仅回答本远端标记下的测试域名。"""
import os
import errno
import socketserver
import struct
import threading


def response(query, identity, tcp=False):
    if len(query) < 12 or len(query) > 512 or query[2:12] != b"\x01\x00\x00\x01" + b"\0" * 6:
        raise ValueError("受控解析请求头无效")
    labels, offset = [], 12
    while offset < len(query) and query[offset]:
        size = query[offset]
        if size > 63 or offset + size + 1 >= len(query):
            raise ValueError("受控解析名称无效")
        labels.append(query[offset + 1:offset + size + 1].decode("ascii"))
        offset += size + 1
    if query[offset:] != b"\0\0\x01\0\x01":
        raise ValueError("受控解析仅接受单个地址问题")
    name = ".".join(labels)
    known = name in (f"{identity}.test", f"truncated.{identity}.test")
    truncated = known and name.startswith("truncated.") and not tcp
    flags = 0x8380 if truncated else 0x8180 if known else 0x8183
    count = int(known and not truncated)
    header = query[:2] + struct.pack("!HHHHH", flags, 1, count, 0, 0)
    answer = b"\xc0\x0c\0\x01\0\x01\0\0\0\0\0\x04\x0a\xe7\x42\x01" if count else b""
    return header + query[12:] + answer


def read_exact(sock, count):
    result = b""
    while len(result) < count:
        part = sock.recv(count - len(result))
        if not part:
            raise ValueError("受控流式解析提前关闭")
        result += part
    return result


def servers(address, identity):
    class UDP(socketserver.BaseRequestHandler):
        def handle(self):
            query, sock = self.request
            try:
                sock.sendto(response(query, identity), self.client_address)
            except (ValueError, UnicodeError):
                return

    class TCP(socketserver.BaseRequestHandler):
        def handle(self):
            self.request.settimeout(2)
            try:
                count = struct.unpack("!H", read_exact(self.request, 2))[0]
                if not 12 <= count <= 512:
                    return
                reply = response(read_exact(self.request, count), identity, tcp=True)
                self.request.sendall(struct.pack("!H", len(reply)) + reply)
            except (ValueError, UnicodeError, OSError):
                return

    # UDP 的临时端口不保证 TCP 也空闲；先取得 TCP 端口，再核对 UDP。
    for attempt in range(16):
        tcp = socketserver.ThreadingTCPServer(address, TCP)
        try:
            udp = socketserver.ThreadingUDPServer(tcp.server_address, UDP)
            break
        except OSError as error:
            tcp.server_close()
            if address[1] != 0 or error.errno != errno.EADDRINUSE or attempt == 15:
                raise
        except BaseException:
            tcp.server_close()
            raise
    for server in (udp, tcp):
        server.daemon_threads = True
    return udp, tcp


if __name__ == "__main__":
    identity = os.environ.get("VAP_FIXTURE_ID", "")
    if not identity or len(identity) > 63 or any(not (c.isascii() and (c.isalnum() or c == "-")) for c in identity):
        raise ValueError("受控解析远端标记无效")
    udp, tcp = servers(("0.0.0.0", 53), identity)
    threading.Thread(target=tcp.serve_forever, daemon=True).start()
    udp.serve_forever()
