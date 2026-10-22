"""受控 HTTP、HTTPS、DNS 与节点来源；仅供隔离测试容器使用。"""
import argparse
import base64
import csv
import io
import json
import re
import socket
import socketserver
import ssl
import struct
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

HEADER = ["HostName","IP","Score","Ping","Speed","CountryLong","CountryShort","NumVpnSessions","Uptime","TotalUsers","TotalTraffic","LogType","Operator","Message","OpenVPN_ConfigData_Base64"]

def serve(directory, source):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_GET(self):
            state_path = directory / "state.json"
            state = json.loads(state_path.read_text()) if state_path.exists() else {}
            if source:
                if state.get("source_delay", 0):
                    time.sleep(state["source_delay"])
                out = io.StringIO()
                out.write("*vpn_servers\n#")
                writer = csv.writer(out)
                writer.writerow(HEADER)
                protocols = state.get("source_protocols", ["tcp", "udp"])
                entries = state.get("source_nodes")
                for index in range(len(entries) if entries is not None else state.get("source_count", len(protocols))):
                    entry = entries[index] if entries is not None else {}
                    protocol = entry.get("protocol", protocols[index % len(protocols)])
                    profile = (directory / (protocol + ".ovpn")).read_bytes()
                    if "source_port" in state:
                        original = 1194 if protocol == "tcp" else 1195
                        profile = profile.replace(f"remote 11.53.0.2 {original}".encode(), f"remote 11.53.0.2 {state['source_port']}".encode())
                    if index >= 2:
                        original = 1194 if protocol == "tcp" else 1195
                        profile = profile.replace(f"remote 11.53.0.2 {original}".encode(), f"remote 11.53.0.2 {20000 + index}".encode())
                    if "port" in entry:
                        profile = re.sub(rb"(remote 11\.53\.0\.2 )\d+", lambda match: match[1] + str(entry["port"]).encode(), profile)
                    endpoint = state.get("source_ip", "11.53.0.2")
                    profile = profile.replace(b"remote 11.53.0.2 ", f"remote {endpoint} ".encode())
                    countries = state.get("source_countries", ["ZZ"])
                    country = countries[index % len(countries)]
                    writer.writerow([protocol, endpoint, entry.get("score", 0), entry.get("ping_ms", 1), entry.get("speed_bps", 0), "Test", country, entry.get("sessions", 0), entry.get("uptime_ms", 0), 0, 0, "", "", "", base64.b64encode(profile).decode()])
                out.write("*\n")
                body = out.getvalue().encode()
                self.send_response(state.get("source_code", 200))
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            if self.path.startswith("/slow"):
                time.sleep(state.get("delay", 20))
            code = state.get("code", 204 if self.path.startswith("/generate_204") else 200)
            transport = "tcp" if self.client_address[0].startswith("10.77.") else "udp"
            code = state.get("transport_codes", {}).get(transport, code)
            if state.get("transport_delays", {}).get(transport, 0):
                time.sleep(state["transport_delays"][transport])
            if self.path.startswith("/redirect"):
                self.send_response(302)
                self.send_header("Location", "/generate_204")
            elif self.path.startswith("/failure"):
                self.send_response(503)
            else:
                self.send_response(code)
            body = b"" if code == 204 else b"fixture"
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            try:
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError):
                pass

    address = ("0.0.0.0", 18080 if source else 80)
    httpd = ThreadingHTTPServer(address, Handler)
    if not source:
        class EchoTCP(socketserver.BaseRequestHandler):
            def handle(self):
                while True:
                    data = self.request.recv(128)
                    if not data:
                        return
                    self.request.sendall(data)
        class EchoUDP(socketserver.BaseRequestHandler):
            def handle(self):
                data, sock = self.request
                sock.sendto(data, self.client_address)
        for port in (19090, 19091):
            for factory, handler in ((socketserver.ThreadingTCPServer, EchoTCP), (socketserver.ThreadingUDPServer, EchoUDP)):
                echo = factory(("0.0.0.0", port), handler)
                threading.Thread(target=echo.serve_forever, daemon=True).start()
        httpsd = ThreadingHTTPServer(("0.0.0.0", 443), Handler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(directory / "server.crt", directory / "server.key")
        httpsd.socket = context.wrap_socket(httpsd.socket, server_side=True)
        threading.Thread(target=httpsd.serve_forever, daemon=True).start()

        class DNS(socketserver.BaseRequestHandler):
            def handle(self):
                message, sock = self.request
                if len(message) < 12:
                    return
                end = 12
                try:
                    while message[end]:
                        end += message[end] + 1
                    end += 5
                    if end > len(message):
                        return
                    question = message[12:end]
                    header = message[:2] + struct.pack("!HHHHH", 0x8180, 1, 1, 0, 0)
                    answer = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 30, 4) + socket.inet_aton("11.54.0.2")
                    sock.sendto(header + question + answer, self.client_address)
                except (IndexError, OSError):
                    return
        server = socketserver.ThreadingUDPServer(("1.1.1.1", 53), DNS)
        threading.Thread(target=server.serve_forever, daemon=True).start()
    httpd.serve_forever()

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--source", action="store_true")
    args = parser.parse_args()
    serve(args.directory, args.source)
