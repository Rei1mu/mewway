"""把一个域名归类：TCP 黑洞 / DNS 污染 / SNI 阻断（按域名）/ 按 IP 掐 / 正常。

`策略规则.md` 里的那张对照表就是用它跑出来的。墙是动态的，结论会过期 ——
隔一段时间重跑一次，别信文档里写死的时间点。

和 `diag_relay.py` 的分工：这个只做**快速归类**（多域名、多 IP、自动判类型、顺带比 DNS 污染），
`diag_relay.py` 是**深挖单个域名** —— 它还会真发一个 HTTP 请求，回答「中继建起来之后会不会挂」。

用法：
    python tools/classify.py                 # 测内置的一批代表域名
    python tools/classify.py registry.npmjs.org discord.com
    python tools/classify.py --dns           # 只比系统解析和 DoH

判据只看「明确证据」，超时不算结论（和中继的 probe.rs 一致）：
    TCP 都不通                                  -> 黑洞
    系统解析的 IP 全不可用 + 和 DoH 不一致      -> DNS 污染
    TCP 通 + 带 SNI 全被掐 + 不带 SNI 能成      -> SNI 阻断（按域名掐）
    TCP 通 + 带 SNI 部分成功                    -> 按 IP 掐
    带 SNI 全部成功                             -> 正常

**「系统解析 ≠ DoH」本身不等于污染。** Fastly / Cloudflare 这类 CDN 对不同的递归解析器
本来就会返回不同的就近节点（EDNS Client Subnet 不一样），实测 `static.crates.io` 系统给
`140.248.166.137`、DoH 给 `167.82.50.137`，两个都是通的 —— 这叫「就近不同」，不叫污染。
只有**系统解析给的 IP 全部连不上**，才说明它被投毒了。
"""
import json
import socket
import ssl
import sys
import time
import urllib.request

SAMPLE = [
    "github.com",
    "raw.githubusercontent.com",
    "registry.npmjs.org",
    "crates.io",
    "pypi.org",
    "nodejs.org",
    "store.steampowered.com",
    "discord.com",
    "pixiv.net",
    "huggingface.co",
    "edge.microsoft.com",
]
MAX_IP = 3
T = 4.0
DOH = "https://dns.alidns.com/resolve?name={}&type=A"


def sys_ips(host):
    try:
        return sorted({a[4][0] for a in socket.getaddrinfo(host, 443, socket.AF_INET)})
    except Exception as e:
        return ["ERR:" + type(e).__name__]


def doh_ips(host):
    """程序自己的出站请求一律 no_proxy，否则会绕回本地代理（见 README 的自噬问题）。"""
    try:
        op = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with op.open(DOH.format(host), timeout=8) as r:
            d = json.load(r)
        return sorted({a["data"] for a in d.get("Answer", []) if a.get("type") == 1})
    except Exception as e:
        return ["ERR:" + type(e).__name__]


def tls(ip, sni):
    """返回 (毫秒, 状态)；状态 ok / tcp（连不上）/ tls（握手被掐）。"""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    t0 = time.perf_counter()
    try:
        s = socket.create_connection((ip, 443), timeout=T)
    except Exception:
        return None, "tcp"
    try:
        ss = ctx.wrap_socket(s, server_hostname=sni)
        ms = (time.perf_counter() - t0) * 1000
        ss.close()
        return ms, "ok"
    except Exception:
        try:
            s.close()
        except Exception:
            pass
        return None, "tls"


def classify(host):
    sys_list, doh_list = sys_ips(host), doh_ips(host)
    differ = sys_list != doh_list
    ips = [i for i in sys_list if not i.startswith("ERR")][:MAX_IP]
    if not ips:
        return host, "解析失败", [], differ, False

    rows = []
    for ip in ips:
        s_ms, s_st = tls(ip, host)
        n_ms, n_st = tls(ip, None)
        rows.append((ip, s_st, s_ms, n_st, n_ms))

    sni_ok = sum(1 for r in rows if r[1] == "ok")
    tcp_ok = sum(1 for r in rows if r[1] != "tcp" or r[3] != "tcp")
    if tcp_ok == 0:
        kind = "DNS 污染 + TCP 黑洞" if differ else "TCP 黑洞"
    elif sni_ok == 0 and any(r[3] == "ok" for r in rows):
        kind = "SNI 阻断（按域名）"
    elif 0 < sni_ok < len(rows):
        kind = "按 IP 掐"
    elif sni_ok == len(rows):
        kind = "正常"
    else:
        kind = "需复查"

    # 系统解析能用就不算污染 —— 不一致只说明 DoH 给了另一个就近节点
    polluted = differ and sni_ok == 0
    return host, kind, rows, differ, polluted


def fmt(st, ms):
    return "—" if st != "ok" else f"{round(ms)}ms"


def main(argv):
    if "--dns" in argv:
        for h in argv[1:] or SAMPLE:
            s, d = sys_ips(h), doh_ips(h)
            print(f"{h:26} 系统={','.join(s)[:44]:46} DoH={','.join(d)[:44]:46} "
                  f"{'一致' if s == d else '不一致 <- 污染'}")
        return

    hosts = [a for a in argv if not a.startswith("-")] or SAMPLE
    for host in hosts:
        host, kind, rows, differ, polluted = classify(host)
        if polluted:
            mark = "  [DNS 污染]"
        elif differ:
            mark = "  [解析与 DoH 不同，但系统解析可用 —— 不是污染]"
        else:
            mark = ""
        print(f"\n{host}  ->  {kind}{mark}")
        for ip, s_st, s_ms, n_st, n_ms in rows:
            print(f"   {ip:16} 带SNI={fmt(s_st, s_ms):>8}  不带SNI={fmt(n_st, n_ms):>8}"
                  f"   ({s_st}/{n_st})")


if __name__ == "__main__":
    main(sys.argv[1:])
