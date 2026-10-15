"""受控客户端：配置经私有标准输入传递，不在参数或输出中包含凭据。"""
import json
import socket
import sys


def receive(connection, size):
    result = bytearray()
    while len(result) < size:
        part = connection.recv(size - len(result))
        if not part:
            raise RuntimeError("连接意外关闭")
        result.extend(part)
    return bytes(result)


def connect(config):
    connection = socket.create_connection((config["host"], config["port"]), timeout=3)
    try:
        connection.sendall(bytes([5, 1, 2]))
        if receive(connection, 2) != bytes([5, 2]):
            raise RuntimeError("认证方法被拒绝")
        username, password = config["username"].encode(), config["password"].encode()
        connection.sendall(bytes([1, len(username)]) + username + bytes([len(password)]) + password)
        if receive(connection, 2) != bytes([1, 0]):
            raise RuntimeError("认证被拒绝")
        name = b"fixture.example"
        connection.sendall(bytes([5, 1, 0, 3, len(name)]) + name + (19090).to_bytes(2, "big"))
        header = receive(connection, 4)
        if header != bytes([5, 0, 0, 1]):
            raise RuntimeError("受控目标建连失败")
        receive(connection, 6)
        return connection
    except BaseException:
        connection.close()
        raise


def emit(value):
    print(json.dumps(value, separators=(",", ":")), flush=True)


def main():
    connections = []
    try:
        config = json.loads(sys.stdin.readline())
        if config.get("expect_rejection"):
            # 只认可服务端明确拒绝或关闭，超时不能冒充超额拒绝。
            connection = socket.create_connection((config["host"], config["port"]), timeout=3)
            try:
                connection.sendall(bytes([5, 1, 2]))
                try:
                    reply = connection.recv(2)
                except ConnectionResetError:
                    reply = b""
                if reply not in [b"", bytes([5, 255])]:
                    raise RuntimeError("超额连接没有被拒绝")
            finally:
                connection.close()
            emit({"rejected": True})
            return
        for _ in range(config["connections"]):
            connections.append(connect(config))
        emit({"connected": len(connections), "source": connections[0].getsockname()[0]})
        for line in sys.stdin:
            command = json.loads(line)["command"]
            if command == "tick":
                for index, connection in enumerate(connections):
                    payload = f"受控往返-{index}".encode()
                    connection.sendall(payload)
                    if receive(connection, len(payload)) != payload:
                        raise RuntimeError("受控往返数据不一致")
                emit({"round_trips": len(connections)})
            elif command == "close_one":
                connections.pop().close()
                emit({"connected": len(connections)})
            elif command == "open_one":
                connections.append(connect(config))
                emit({"connected": len(connections)})
            elif command == "stop":
                emit({"stopped": True})
                return
            else:
                raise RuntimeError("未知客户端控制命令")
    except Exception:
        # 不回显配置、业务地址或原始异常中的命令参数。
        emit({"error": "受控客户端认证、建连或往返失败"})
        raise SystemExit(1)
    finally:
        for connection in connections:
            connection.close()


if __name__ == "__main__":
    main()
