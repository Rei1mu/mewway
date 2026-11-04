//! 无 SNI 中继
//!
//! 为什么需要它：GFW 会看 ClientHello 里明文的 SNI 扩展来决定要不要掐断连接。
//! 「透传」（TLS 原样搬运）没法干预这件事 —— 它只是搬字节，ClientHello 里写着
//! `raw.githubusercontent.com`，该断还是断。
//!
//! 中继换了个打法：本地终结客户端的 TLS（用我们自己的 CA 签证书），然后**自己**
//! 跟源站建 TLS 时用 IP 当 server_name —— 按 RFC 6066，IP 地址不产生 SNI 扩展，
//! 于是这条握手在链路上只是一段没有域名的密文，阻断规则匹配不上。
//!
//! 代价是必须做中间人（要装 CA），而且不校验证书（我们只关心把 HTTP 搬过去）。

use crate::proxy::forward::{self, ResBody};
use crate::proxy::probe::client_config;
use crate::proxy::{BoxError, Ctx};
use crate::shared::{err_chain, Level};
use bytes::Bytes;
use futures_util::StreamExt;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Empty, StreamBody};
use hyper::body::{Frame, Incoming};
use hyper::client::conn::http1::SendRequest;
use hyper::http::request::Parts;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use rustls::pki_types::ServerName;
use std::collections::HashMap;
use std::future::Future;
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::{Mutex as StdMutex, OnceLock};
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

const DIAL_TIMEOUT: Duration = Duration::from_secs(4);
/// 复用缓存地址时只给这么点时间，卡住就换一批
const FAST_TIMEOUT: Duration = Duration::from_millis(1200);
/// 一轮最多并发试几个候选 IP
const MAX_TLS_TRY: usize = 10;
/// 一条空闲的源站连接最多复用多久。
///
/// 浏览器会长时间挂着一个 CONNECT 隧道（标签页开着不动），隧道里这条源站连接
/// 早就被对端回收了。`ready()` 不一定看得出来（对端的 FIN 可能还没读到），
/// 于是下一个请求打过去就是 `connection error`。超时短一点，代价只是多一次握手。
const IDLE_MAX: Duration = Duration::from_secs(10);
/// 第一次尝试时，等响应头的上限。
///
/// 必须有这个上限：源站把请求收下了却不回话（烂 IP 被限速就是这么表现的），
/// `send_request` 会**一直挂着**，浏览器那边就是转圈到超时。
/// 4 秒拿不到响应头就认定这条线路不行，换一个 IP 再来 —— 健康的边缘节点
/// 首字节通常在 1 秒内，4 秒足够宽松，而比让用户干等 8 秒、20 秒好得多。
const FIRST_BYTE: Duration = Duration::from_secs(4);
/// 换过一次 IP 之后仍然等不到响应头时，给多久。
///
/// 比第一次宽松：有些接口是真的慢（搜索、模型页），不能因为「慢」就判死。
/// 到这一步已经不重试了，直接如实报错。
const FIRST_BYTE_LAST: Duration = Duration::from_secs(30);
/// 第一个候选握手成功之后，再多等这么久看有没有更快的。
///
/// 只取「第一个完成的」会经常挑中一个**握手快、服务慢**的 IP ——
/// 实测同一个 github.com 页面，好 IP 首字节 0.7 秒、差 IP 要 4 秒以上。
/// 多等 180ms 换一个真正快的线路，这笔账是划算的（而且结果会缓存 3 分钟）。
const GRACE: Duration = Duration::from_millis(180);

/// 发给源站的请求体。
///
/// 用 `BoxBody` 而不是直接拿客户端的 `Incoming`，是为了**能重放**：
/// `Incoming` 一旦交给 `send_request` 就拿不回来了，连接断了只能让用户看到 502。
/// 换成 `BoxBody` 之后，GET 这类没有 body 的请求可以原样再发一次。
pub type Body = BoxBody<Bytes, BoxError>;

/// 一条到源站的「无 SNI」TLS 连接，可复用于同一条客户端连接上的多个请求
pub type Sender = SendRequest<Body>;

/// 一条客户端连接对应的上游连接。
///
/// 记着它用的是哪个地址：请求失败时要把这个地址拉黑，不然下次重建连接
/// 很可能又抽到同一个坏 IP，用户看到的就是「这个站时好时坏」。
pub type Slot = tokio::sync::Mutex<Option<(Sender, SocketAddr, Instant)>>;

fn empty_body() -> Body {
    Empty::<Bytes>::new().map_err(|e| -> BoxError { match e {} }).boxed()
}

/// host -> 上次握手成功时**带没带 SNI**。
///
/// 大多数站不需要它（不带 SNI 才是中继的意义）；但有些多租户 CDN 根本不接受
/// 无 SNI 的握手，而它的 SNI 又没被墙 —— 这时带真 SNI 反而能通。记住这个结论，
/// 免得每次都先白试一轮无 SNI。
fn sni_cache() -> &'static StdMutex<HashMap<String, bool>> {
    static C: OnceLock<StdMutex<HashMap<String, bool>>> = OnceLock::new();
    C.get_or_init(|| StdMutex::new(HashMap::new()))
}

fn remember_mode(host: &str, with_sni: bool) {
    if let Ok(mut g) = sni_cache().lock() {
        if g.len() > 4096 {
            g.clear();
        }
        g.insert(host.to_string(), with_sni);
    }
}

fn preferred_mode(host: &str) -> Option<bool> {
    sni_cache().lock().ok().and_then(|g| g.get(host).copied())
}

/// 建连：候选 IP 并发做「无 SNI 的 TLS 握手」，谁先成功用谁。
///
/// 为什么不能用 `resolver.best()` 的 TCP 结果直接连：SNI 阻断的特征恰恰是
/// **TCP 正常、TLS 握手被掐**。只按 TCP 延迟挑，会挑到一个连不上的 IP，
/// 然后白等一轮超时 —— 这正是之前 github.com 时好时坏的原因。
async fn dial(ctx: &Ctx, host: &str, port: u16) -> anyhow::Result<(Sender, SocketAddr)> {
    let prefer_sni = preferred_mode(host);

    // 快路：上次已经握手成功的地址，直接复用。
    // 只给 1.2 秒 —— 这个 IP 可能只是「刚才」能用，卡太久不如立刻换一批。
    if let Some(addr) = ctx.resolver.cached_best(host) {
        let sni = if prefer_sni.unwrap_or(false) { Some(host) } else { None };
        if let Ok(s) = try_tls_timeout(addr, FAST_TIMEOUT, sni).await {
            return Ok((s, addr));
        }
        ctx.resolver.invalidate(host);
    }

    // 候选：公开 IP 池优先（这些是真正能通的入口），再补 DoH / 系统解析的结果
    let mut all: Vec<SocketAddr> = Vec::new();
    for ip in crate::proxy::ipdb::candidates(host) {
        let a = SocketAddr::new(ip, port);
        if !all.contains(&a) {
            all.push(a);
        }
    }

    // 兄弟域名借 IP：自己的解析被污染时（steamcommunity.com 的系统解析、阿里 DoH、
    // 腾讯 DoH 各给一个不同的假 IP），同一 CDN 属性下别的域名往往解析还是干净的，
    // 而且边缘按 Host 头路由、共用同一批 IP。实测 cdn.akamai.steamstatic.com
    // 的 IP 拿来做 steamcommunity.com 能直接 200。
    let sibs = crate::proxy::ipdb::siblings(host);
    if !sibs.is_empty() {
        let got = futures_util::future::join_all(sibs.iter().map(|s| ctx.resolver.ips(s))).await;
        for ips in got {
            for ip in ips {
                let a = SocketAddr::new(ip, port);
                if !all.contains(&a) {
                    all.push(a);
                }
            }
        }
    }

    for ip in ctx.resolver.ips(host).await {
        let a = SocketAddr::new(ip, port);
        if !all.contains(&a) {
            all.push(a);
        }
    }
    if all.is_empty() {
        anyhow::bail!("无法解析 {host}");
    }

    // 冷藏期内的地址优先排除（见 resolver::mark_bad）。
    // 但**不能因此把候选池抽干**：抖一阵子之后可能全被冷藏，
    // 这时候宁可去试一个「可疑」的 IP，也比直接告诉用户连不上好。
    let mut addrs: Vec<SocketAddr> = all.iter().copied().filter(|a| !ctx.resolver.is_bad(*a)).collect();
    if addrs.is_empty() {
        addrs = all;
    }

    // 第一、二轮都是「不带 SNI」。第二轮不是多余：
    // 实测同一个 IP 这一下 SYN 直接丢了、150ms 后重试 119ms 就通。
    // 只扫一轮，会把「线路抖了一下」当成「这个站没法中继」。
    for round in 0..2 {
        if round > 0 {
            tokio::time::sleep(Duration::from_millis(150)).await;
        }
        if let Some((s, addr, ms)) = sweep(&addrs, None).await {
            ctx.resolver.remember(host, addr, ms);
            remember_mode(host, false);
            return Ok((s, addr));
        }
    }

    // 第三轮：带真 SNI。有些站（多租户 CDN）压根不接受无 SNI 的握手，
    // 但它的 SNI 又没被墙 —— 这时候带 SNI 能通，只是少了「绕开 SNI 阻断」这一层。
    if let Some((s, addr, ms)) = sweep(&addrs, Some(host)).await {
        ctx.resolver.remember(host, addr, ms);
        remember_mode(host, true);
        ctx.log(Level::Info, format!("[{host}] 这个站不接受无 SNI 握手，已改用带 SNI 直连"));
        return Ok((s, addr));
    }

    anyhow::bail!(
        "{host} 的 {} 个候选 IP 都没能完成握手（TCP/TLS 均失败；系统解析结果可能是被污染的）",
        addrs.len().min(MAX_TLS_TRY)
    )
}

/// 一轮并发握手，返回最先成功的那个
async fn sweep(addrs: &[SocketAddr], sni: Option<&str>) -> Option<(Sender, SocketAddr, u32)> {
    let mut set: tokio::task::JoinSet<Option<(SocketAddr, Sender, u32)>> = tokio::task::JoinSet::new();
    for (i, addr) in addrs.iter().take(MAX_TLS_TRY).enumerate() {
        let addr = *addr;
        let sni = sni.map(|s| s.to_string());
        set.spawn(async move {
            // 前面的候选先跑，后面的按 120ms 递延（Happy Eyeballs 的思路）：
            // 既保留「池子里靠前的 IP 更好」这个优先级，又能在前面的卡住时由后面的顶上。
            // 全部一起抢的话，先回来的往往是某个很慢的 IP，用户就会看到「时快时慢」。
            if i > 0 {
                tokio::time::sleep(Duration::from_millis(120 * i as u64)).await;
            }
            let t0 = Instant::now();
            try_tls_timeout(addr, DIAL_TIMEOUT, sni.as_deref())
                .await
                .ok()
                .map(|s| (addr, s, t0.elapsed().as_millis() as u32))
        });
    }
    let mut best: Option<(Sender, SocketAddr, u32)> = None;
    let mut deadline: Option<Instant> = None;
    loop {
        let next = match deadline {
            Some(d) => {
                let now = Instant::now();
                if now >= d {
                    break;
                }
                match tokio::time::timeout(d - now, set.join_next()).await {
                    Ok(v) => v,
                    Err(_) => break,
                }
            }
            None => set.join_next().await,
        };
        let Some(r) = next else { break };
        if let Ok(Some((addr, s, ms))) = r {
            if best.as_ref().map_or(true, |(_, _, bm)| ms < *bm) {
                best = Some((s, addr, ms));
            }
            // 第一个回来之后开始计时，多收几个再决定（见 GRACE 的注释）
            if deadline.is_none() {
                deadline = Some(Instant::now() + GRACE);
            }
        }
    }
    best
}

/// 对单个 IP 做一次 TLS + HTTP/1.1 握手。`sni` 为 None 时不发 SNI 扩展。
async fn try_tls_timeout(addr: SocketAddr, budget: Duration, sni: Option<&str>) -> anyhow::Result<Sender> {
    let tcp = tokio::time::timeout(budget, TcpStream::connect(addr))
        .await
        .map_err(|_| anyhow::anyhow!("连接 {addr} 超时"))??;
    tcp.set_nodelay(true).ok();

    let name = match sni {
        Some(h) => ServerName::try_from(h.to_string()).map_err(|e| anyhow::anyhow!("域名无效：{e}"))?,
        // 关键的一行：server_name 给 IP，rustls 就不会发 SNI 扩展
        None => ServerName::IpAddress(addr.ip().into()),
    };
    let tls = tokio::time::timeout(budget, TlsConnector::from(client_config()).connect(name, tcp))
        .await
        .map_err(|_| anyhow::anyhow!("与 {addr} 握手超时"))??;

    let (sender, conn) = hyper::client::conn::http1::handshake::<_, Body>(TokioIo::new(tls)).await?;
    tokio::spawn(async move {
        let _ = conn.await;
    });
    Ok(sender)
}

/// 把一个客户端请求转给源站，响应流式回传。
///
/// `slot` 里存着这条客户端连接对应的上游连接，能复用就复用（省掉每次的 TLS 握手）。
pub async fn relay(
    ctx: &Ctx,
    req: Request<Incoming>,
    host: &str,
    port: u16,
    slot: &Slot,
    conn_id: u64,
) -> Response<ResBody> {
    let (parts, incoming) = req.into_parts();

    // 能不能重放：没有 body 的请求（GET/HEAD/OPTIONS，或显式 content-length: 0）
    // 失败了重发一次是安全的。带 body 的（上传）不能重放 —— 字节已经被消费过了。
    let replayable = matches!(parts.method, hyper::Method::GET | hyper::Method::HEAD | hyper::Method::OPTIONS)
        || parts
            .headers
            .get(hyper::header::CONTENT_LENGTH)
            .map(|v| v.as_bytes() == b"0")
            .unwrap_or(false);
    let mut payload: Option<Body> = if replayable {
        None
    } else {
        Some(incoming.map_err(|e| -> BoxError { Box::new(e) }).boxed())
    };

    for attempt in 0..2 {
        // ---- 取一条能用的源站连接 ----
        let mut guard = slot.lock().await;
        let addr = {
            let usable = match guard.as_mut() {
                Some((s, a, at)) => {
                    if at.elapsed() < IDLE_MAX && s.ready().await.is_ok() {
                        Some(*a)
                    } else {
                        None
                    }
                }
                None => None,
            };
            match usable {
                Some(a) => a,
                None => {
                    *guard = None;
                    let t0 = Instant::now();
                    match dial(ctx, host, port).await {
                        Ok((s, a)) => {
                            // 中继的延迟就是「从零建一条无 SNI 的 TLS」要多久 ——
                            // 这个数字最能说明当前 IP 好不好，也才让连接页的按延迟排序有意义。
                            ctx.shared.set_conn_lat(conn_id, t0.elapsed().as_millis() as u32);
                            let ca_known_missing = ctx.shared.ca_checked.load(Ordering::Relaxed)
                                && !ctx.shared.ca_installed.load(Ordering::Relaxed);
                            if ca_known_missing {
                                ctx.log(Level::Warn, format!("[{host}] 中继已建立（本地 CA 未安装，浏览器可能报证书错误）"));
                            }
                            *guard = Some((s, a, Instant::now()));
                            a
                        }
                        Err(e) => {
                            drop(guard);
                            let text = format!("{e:#}");
                            ctx.log(Level::Warn, format!("[{host}] 中继建连失败：{text}"));
                            // 必须写进连接记录：只在日志里说一句，用户翻连接页时
                            // 看到的是「这条连接一切正常」，等于把故障藏起来了。
                            ctx.shared.fail_conn(conn_id, format!("中继建连失败：{text}"));
                            return forward::text(StatusCode::BAD_GATEWAY, format!("中继无法连接 {host}:{port}：{text}"));
                        }
                    }
                }
            }
        };

        // ---- 发请求 ----
        let out = match build_request(&parts, payload.take().unwrap_or_else(empty_body)) {
            Ok(r) => r,
            Err(e) => {
                drop(guard);
                return forward::text(StatusCode::BAD_REQUEST, format!("构造中继请求失败：{e}"));
            }
        };
        let budget = if attempt == 0 { FIRST_BYTE } else { FIRST_BYTE_LAST };
        let outcome: Result<Response<Incoming>, String> = match guard.as_mut() {
            Some((s, _, _)) => match tokio::time::timeout(budget, s.send_request(out)).await {
                Ok(Ok(r)) => Ok(r),
                Ok(Err(e)) => Err(err_chain(&e)),
                Err(_) => Err(format!("{}s 内没等到响应头", budget.as_secs())),
            },
            None => unreachable!("上面刚确保有连接"),
        };

        match outcome {
            Ok(resp) => {
                // 429 / 503 不是加速失败：链路是通的，是对方按出口 IP 限流了
                // （Steam 社区的 WAF 就是这样）。状态码和 Retry-After 原样透传给浏览器，
                // 这里只挂个备注 —— 用户得知道「等一会儿」，而不是去重启程序、乱改策略。
                if matches!(resp.status().as_u16(), 429 | 503) {
                    ctx.shared.note_conn(
                        conn_id,
                        format!(
                            "服务端限流（{}），等几分钟再试；链路是通的，不是加速失败",
                            resp.status().as_u16()
                        ),
                    );
                }
                // 这条连接还能用，刷新一下「最近使用时间」留给下一个请求
                if let Some(e) = guard.as_mut() {
                    e.2 = Instant::now();
                }
                drop(guard);
                return stream_back(resp);
            }
            Err(text) => {
                *guard = None;
                drop(guard);
                // 这个地址是「握手能过、请求必挂/不回」—— 冷藏它，别下次又抽到
                ctx.resolver.mark_bad(addr);
                ctx.resolver.invalidate(host);
                ctx.log(Level::Warn, format!("[{host}] 中继请求失败（{addr}）：{text}"));
                if attempt == 0 && replayable {
                    // 换一个 IP 再来一次，浏览器完全无感
                    continue;
                }
                ctx.shared.fail_conn(conn_id, format!("中继请求失败：{text}"));
                return forward::text(StatusCode::BAD_GATEWAY, format!("中继请求失败：{text}"));
            }
        }
    }

    forward::text(StatusCode::BAD_GATEWAY, format!("中继无法连接 {host}:{port}"))
}

fn build_request(parts: &Parts, body: Body) -> Result<Request<Body>, hyper::http::Error> {
    let pq = parts.uri.path_and_query().map(|p| p.as_str()).unwrap_or("/");
    // 用 origin-form 请求行（只有路径），Host 头由客户端带过来的原值决定
    let mut builder = Request::builder().method(parts.method.clone()).uri(pq);
    for (k, v) in parts.headers.iter() {
        if forward::is_hop(k.as_str()) {
            continue;
        }
        builder = builder.header(k, v);
    }
    builder.body(body)
}

/// 响应体「多久没有新字节」就放弃。
///
/// 首字节到了不代表就没事了：实测 github.com 首页（530KB）有一半概率传到一半
/// 就彻底不动 —— 那个 IP 被限速了。不掐的话浏览器会挂在那里等几分钟，
/// 用户看到的是「页面永远转圈」；掐掉之后浏览器立刻报错、可以重试（也会换 IP）。
/// 只掐「静默」，不掐「总时长」—— 否则大文件下载会被误杀。
const BODY_IDLE: Duration = Duration::from_secs(20);
/// 响应头到了、但第一个 body 字节迟迟不来时给多久。
///
/// 这种情况基本都是「这条线路已经废了」，没必要按 BODY_IDLE 等 20 秒。
/// 掐短一点，浏览器能更快重试。
const BODY_FIRST: Duration = Duration::from_secs(6);

fn stream_back(resp: Response<Incoming>) -> Response<ResBody> {
    let (rparts, rbody) = resp.into_parts();
    let mut rb = Response::builder().status(rparts.status);
    for (k, v) in rparts.headers.iter() {
        let name = k.as_str();
        // 逐跳头要丢掉；长度我们自己重算（回传时是流式的）
        if forward::is_hop(name) || name == "content-length" {
            continue;
        }
        rb = rb.header(k, v);
    }

    let stream = BodyExt::map_err(rbody, |e| -> BoxError { Box::new(e) })
        .into_data_stream()
        .map(|r| r.map(Frame::data));
    let body = StreamBody::new(guard_idle(stream, BODY_FIRST, BODY_IDLE)).boxed_unsync();
    rb.body(body)
        .unwrap_or_else(|_| forward::text(StatusCode::BAD_GATEWAY, "构造中继响应失败"))
}

/// 给一个流加「静默超时」：超过 `idle` 没有新元素就吐一个错误并结束。
/// `first` 是第一个元素专用的预算（比后续短，见 BODY_FIRST 的注释）。
fn guard_idle<S>(
    stream: S,
    first: Duration,
    idle: Duration,
) -> impl futures_util::Stream<Item = Result<Frame<Bytes>, BoxError>>
where
    S: futures_util::Stream<Item = Result<Frame<Bytes>, BoxError>> + Unpin,
{
    let mut inner = Box::pin(stream);
    let mut sleep = Box::pin(tokio::time::sleep(first));
    let mut done = false;
    futures_util::stream::poll_fn(move |cx| {
        if done {
            return std::task::Poll::Ready(None);
        }
        if sleep.as_mut().poll(cx).is_ready() {
            done = true;
            // Item 是 Result<Frame<Bytes>, BoxError>，这里只能给出错误
            return std::task::Poll::Ready(Some(Err(
                Box::new(std::io::Error::new(std::io::ErrorKind::TimedOut, "上游静默超时")) as BoxError
            )));
        }
        match inner.as_mut().poll_next(cx) {
            std::task::Poll::Ready(Some(item)) => {
                // 收到数据就把预算放宽到 idle，后续按 idle 计
                sleep.as_mut().reset(tokio::time::Instant::now() + idle);
                std::task::Poll::Ready(Some(item))
            }
            other => other,
        }
    })
}
