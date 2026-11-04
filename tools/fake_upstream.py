"""测试用假上游代理：只记录收到的 CONNECT 目标和首个 ClientHello，然后断开。

用来验证 Mewway 的「直连握手被阻断 -> 改走上游并重放 ClientHello」这条路径
确实把浏览器发出的握手字节原样送到了上游。真实上游不可用时也能验证。
"""

import os
import socket
import sys
import threading

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 18080
LOG_PATH = os.path.join(os.environ.get("TEMP", "."), "fake_upstream.log")
LOG = open(LOG_PATH, "w", encoding="utf-8", buffering=1)


def handle(conn):
    conn.settimeout(12)
    data = b""
    try:
        while b"\r\n\r\n" not in data:
            chunk = conn.recv(4096)
            if not chunk:
                return
            data += chunk
        head = data.split(b"\r\n\r\n", 1)[0].decode("latin1")
        first = head.split("\r\n")[0]
        LOG.write("CONNECT %s\n" % first)
        conn.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")

        buf = b""
        while len(buf) < 5:
            chunk = conn.recv(4096)
            if not chunk:
                break
            buf += chunk
        if len(buf) >= 5 and buf[0] == 0x16:
            need = 5 + int.from_bytes(buf[3:5], "big")
            while len(buf) < need:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                buf += chunk
        first_byte = buf[0] if buf else -1
        LOG.write("  first=0x%02x len=%d tls=%s\n" % (first_byte, len(buf), first_byte == 0x16))
    except Exception as exc:  # noqa: BLE001
        LOG.write("  err %r\n" % (exc,))
    finally:
        try:
            conn.close()
        except OSError:
            pass


def main():
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", PORT))
    srv.listen(64)
    LOG.write("fake upstream listening on 127.0.0.1:%d\n" % PORT)
    while True:
        conn, _ = srv.accept()
        threading.Thread(target=handle, args=(conn,), daemon=True).start()


if __name__ == "__main__":
    main()
