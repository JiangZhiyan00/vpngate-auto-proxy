"""测试管理路径是否精确允许指定用户、承载和端口。"""
import socket
import sys

protocol, host, port = sys.argv[1:]
try:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM if protocol == "tcp" else socket.SOCK_DGRAM) as sock:
        sock.settimeout(0.5)
        sock.connect((host, int(port)))
        sock.sendall(b"vap-echo")
        sys.exit(0 if sock.recv(128) == b"vap-echo" else 1)
except OSError:
    sys.exit(1)
