"""诊断中继：对同一 IP 分别做「带 SNI / 不带 SNI」的 TLS 握手，再发一个 HTTP/1.1 请求。

用来回答三个问题：
  1. 不带 SNI 的握手这个站收不收（中继能不能建起来）
  2. 建起来之后发请求会不会被掐（"connection error" / "closed before message completed"）
  3. 带 SNI 是不是反而正常（说明这条规则根本不该是中继）

用法：python tools/diag_relay.py github.com steamcommunity.com ...
"""
import socket
import ssl
import sys
import time

CTX = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE
CTX.set_alpn_protocols(["http/1.1"])


def handshake(ip, port, sni, timeout=6.0):
    """返回 (ok, 描述)。sni=None 表示不发 SNI 扩展。"""
    raw = socket.socket()
    raw.settimeout(timeout)
    t0 = time.time()
    try:
        raw.connect((ip, port))
    except Exception as e:
        return False, f"TCP 失败 {e}"
    try:
        s = CTX.wrap_socket(raw, server_hostname=sni)
    except Exception as e:
        return False, f"握手失败 {type(e).__name__}: {e}"
    ms = int((time.time() - t0) * 1000)
    cert = s.getpeercert(binary_form=True)
    try:
        sub = ssl.DER_cert_to_PEM_cert(cert).splitlines()
        # 证书 CN 不方便解析，只看长度
        cdesc = f"cert {len(cert)}B"
    except Exception:
        cdesc = "no cert"
    return True, f"握手 OK {ms}ms alpn={s.selected_alpn_protocol()} {cdesc}"


def http_get(s, host, path="/", timeout=8.0):
    s.settimeout(timeout)
    req = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n"
        "Accept: */*\r\n"
        "Connection: close\r\n\r\n"
    )
    try:
        s.sendall(req.encode())
        buf = b""
        while b"\r\n\r\n" not in buf:
            d = s.recv(4096)
            if not d:
                return f"读响应失败（对端直接关了），已收 {len(buf)}B"
            buf += d
        head = buf.split(b"\r\n\r\n", 1)[0].decode("latin-1")
        status = head.splitlines()[0]
        body = len(buf.split(b"\r\n\r\n", 1)[1])
        return f"{status} | 已收 body {body}B"
    except Exception as e:
        return f"请求异常 {type(e).__name__}: {e}"


def main():
    hosts = sys.argv[1:] or ["github.com", "steamcommunity.com"]
    for host in hosts:
        try:
            infos = socket.getaddrinfo(host, 443, socket.AF_INET, socket.SOCK_STREAM)
        except Exception as e:
            print(f"\n=== {host} 解析失败 {e}")
            continue
        ips = []
        for i in infos:
            if i[4][0] not in ips:
                ips.append(i[4][0])
        print(f"\n=== {host}  系统解析 {ips[:3]}")
        for ip in ips[:2]:
            print(f"  -- {ip}")
            for label, sni in (("无SNI", None), ("带SNI", host)):
                ok, desc = handshake(ip, 443, sni)
                print(f"     {label:6} {desc}")
                if ok:
                    # 重开一条做请求，避免前面状态干扰
                    ok2, desc2 = handshake(ip, 443, sni)
                    if not ok2:
                        print(f"            (复连失败 {desc2})")
                        continue
                    raw = socket.socket()
                    raw.settimeout(6.0)
                    raw.connect((ip, 443))
                    s = CTX.wrap_socket(raw, server_hostname=sni)
                    print(f"            请求 → {http_get(s, host)}")
                    try:
                        s.close()
                    except Exception:
                        pass


if __name__ == "__main__":
    main()
