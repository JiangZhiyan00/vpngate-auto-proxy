"""仅在专属夹具容器内提供流式与数据报回显。"""
import socketserver
import threading
import os

identity = os.environ.get("VAP_FIXTURE_ID", "")
if len(identity) > 64 or any(not (c.isascii() and (c.isalnum() or c == "-")) for c in identity):
    raise ValueError("受控远端标记无效")
prefix = (identity + ":").encode() if identity else b""


class TCP(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(10)
        if prefix:
            self.request.sendall(prefix)
        while True:
            data = self.request.recv(128)
            if not data:
                return
            self.request.sendall(data)


class UDP(socketserver.BaseRequestHandler):
    def handle(self):
        data, sock = self.request
        sock.sendto(prefix + data, self.client_address)


tcp = socketserver.ThreadingTCPServer(("0.0.0.0", 19090), TCP)
udp = socketserver.ThreadingUDPServer(("0.0.0.0", 19090), UDP)
threading.Thread(target=udp.serve_forever, daemon=True).start()
tcp.serve_forever()
