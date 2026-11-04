//! TCP 建连：择优 IP / 上游代理 / 系统解析

use crate::proxy::Ctx;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// 单次 TCP 建连的上限。Windows 默认 SYN 重试能拖到 20 秒以上，必须自己掐断，
/// 否则「先试加速、失败再走代理」会让人等到怀疑人生。
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

async fn dial(addr: SocketAddr) -> std::io::Result<TcpStream> {
    match tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(addr)).await {
        Ok(r) => r,
        Err(_) => Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "连接超时")),
    }
}

/// 建立到目标站点的 TCP 连接。
///
/// - `best_ip`：先 DoH 解析 + 测速，连最快的那个 IP（TLS 仍由客户端自己握手，SNI 不变）
/// - `via_upstream`：走用户配置的上游代理（只给「未命中规则」的流量用）
pub async fn connect(host: &str, port: u16, ctx: &Ctx, best_ip: bool, via_upstream: bool) -> anyhow::Result<TcpStream> {
    let cfg = ctx.settings();

    // 1) 未命中规则的流量交给你原本的代理，命中规则的自己加速，互不打扰
    if via_upstream {
        if let Some(proxy) = cfg.upstream_addr() {
            return via_proxy(proxy, host, port).await;
        }
    }

    // 2) 择优 IP。缓存里的 IP 可能已经死了，所以要重来一轮：
    //    作废缓存 -> 重新测速（含 IP 池）-> 再拨一次。
    //    少了这一步，一个过期的缓存会让每次请求都白等 5 秒超时。
    if best_ip {
        for attempt in 0..2 {
            let Some((addr, _ms)) = ctx.resolver.best(host, port).await else {
                break;
            };
            match dial(addr).await {
                Ok(s) => {
                    s.set_nodelay(true).ok();
                    return Ok(s);
                }
                Err(e) => {
                    ctx.resolver.invalidate(host);
                    if attempt == 0 {
                        ctx.log(
                            crate::shared::Level::Warn,
                            format!("连接 {addr} 失败({e})，作废缓存后重新选 IP"),
                        );
                    } else {
                        ctx.log(
                            crate::shared::Level::Warn,
                            format!("连接 {addr} 失败({e})，回退系统解析"),
                        );
                    }
                }
            }
        }
    }

    // 3) 系统解析兜底
    let addr: SocketAddr = tokio::net::lookup_host((host, port))
        .await?
        .next()
        .ok_or_else(|| anyhow::anyhow!("无法解析域名 {host}"))?;
    let s = dial(addr).await?;
    s.set_nodelay(true).ok();
    Ok(s)
}

/// 双向搬运用的缓冲区大小。
///
/// tokio 默认是 8KB。8KB 在「拖一个几十 G 的模型 / 游戏」这种场景下意味着
/// 每个方向每秒上千次 read/write 系统调用，纯搬运的 CPU 占比会明显上去。
/// 32KB 能把系统调用砍到四分之一，而每条连接只多花 64KB 内存
///（两条方向各 32KB，而且只在真正有流量时才分配）。
const PUMP_BUF: usize = 32 * 1024;

/// 双向搬运。语义和 `tokio::io::copy_bidirectional` 完全一致（含半关闭处理），
/// 只是把缓冲区调大了 —— 所以可以放心替换，不会改变连接的生命周期。
pub async fn pump<A, B>(a: &mut A, b: &mut B) -> std::io::Result<(u64, u64)>
where
    A: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    B: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    tokio::io::copy_bidirectional_with_sizes(a, b, PUMP_BUF, PUMP_BUF).await
}

/// 只走上游代理建连。用于「加速被阻断」时的在线回退。
pub async fn connect_upstream(host: &str, port: u16, ctx: &Ctx) -> anyhow::Result<TcpStream> {
    let proxy = ctx
        .settings()
        .upstream_addr()
        .ok_or_else(|| anyhow::anyhow!("未配置上游代理"))?;
    via_proxy(proxy, host, port).await
}

async fn via_proxy(proxy: SocketAddr, host: &str, port: u16) -> anyhow::Result<TcpStream> {
    let mut tcp = dial(proxy).await?;
    tcp.set_nodelay(true).ok();
    let req = format!("CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\nProxy-Connection: keep-alive\r\n\r\n");
    tcp.write_all(req.as_bytes()).await?;

    let mut buf = Vec::new();
    let mut tmp = [0u8; 1024];
    loop {
        let n = tcp.read(&mut tmp).await?;
        if n == 0 {
            anyhow::bail!("上游代理断开连接");
        }
        buf.extend_from_slice(&tmp[..n]);
        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
        if buf.len() > 16 * 1024 {
            anyhow::bail!("上游代理响应异常");
        }
    }
    let head = String::from_utf8_lossy(&buf);
    if !(head.starts_with("HTTP/1.1 200") || head.starts_with("HTTP/1.0 200")) {
        let first = head.lines().next().unwrap_or("").to_string();
        anyhow::bail!("上游代理拒绝 CONNECT: {first}");
    }
    Ok(tcp)
}
