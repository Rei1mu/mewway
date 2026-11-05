//! 本地代理监听：CONNECT 隧道 / 明文 HTTP 转发

use crate::config::{Fallback, Settings};
use crate::proxy::forward::{self, ResBody};
use crate::proxy::rules::{self, Route};
use crate::proxy::{tunnel, Ctx};
use crate::shared::{Command, Level, Shared};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use std::convert::Infallible;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_util::sync::CancellationToken;

/// 有上游兜底时，一次直连尝试最多花多久
const DIRECT_BUDGET: Duration = Duration::from_secs(4);

/// 启动监听，返回运行期上下文与取消令牌
pub async fn spawn(
    cfg: Arc<Settings>,
    shared: Arc<Shared>,
    tx: tokio::sync::mpsc::UnboundedSender<Command>,
) -> anyhow::Result<(Arc<Ctx>, CancellationToken)> {
    let ctx = Ctx::new(cfg.clone(), shared.clone(), tx)?;

    let listener = TcpListener::bind(("127.0.0.1", cfg.port))
        .await
        .map_err(|e| anyhow::anyhow!("端口 {} 无法监听：{e}", cfg.port))?;

    let token = CancellationToken::new();
    let t = token.clone();
    let c = ctx.clone();
    tokio::spawn(async move { accept_loop(listener, c, t).await });

    shared.port.store(cfg.port as u64, std::sync::atomic::Ordering::Relaxed);
    shared.set_running(true);
    shared.log(Level::Ok, format!("代理已启动：127.0.0.1:{}", cfg.port));

    Ok((ctx, token))
}

async fn accept_loop(listener: TcpListener, ctx: Arc<Ctx>, token: CancellationToken) {
    loop {
        tokio::select! {
            _ = token.cancelled() => break,
            accepted = listener.accept() => {
                let (stream, _peer) = match accepted {
                    Ok(v) => v,
                    Err(e) => {
                        ctx.log(Level::Warn, format!("accept 失败：{e}"));
                        tokio::time::sleep(std::time::Duration::from_millis(60)).await;
                        continue;
                    }
                };
                let _ = stream.set_nodelay(true);
                ctx.shared.inc_conn();
                let ctx = ctx.clone();
                tokio::spawn(async move {
                    let io = TokioIo::new(stream);
                    let svc = service_fn(move |req| {
                        let ctx = ctx.clone();
                        async move { Ok::<_, Infallible>(handle(req, ctx).await) }
                    });
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(io, svc)
                        .with_upgrades()
                        .await;
                });
            }
        }
    }
}

async fn handle(req: Request<Incoming>, ctx: Arc<Ctx>) -> Response<ResBody> {
    ctx.shared.inc_req();
    // 浏览器来取 PAC。这条请求本身不能被规则处理，也不能记进连接列表。
    if req.uri().path() == "/pac" {
        return pac_response(&ctx);
    }
    // 本地 CA 签发的 CRL。Windows 原生 TLS 栈（schannel / .NET / GCM）会对自定义根 CA
    // 做强制吊销检查，叶子证书里指向这个地址；这里直接把 DER 返回，让它查到「未吊销」，
    // 否则 git / GitHub 身份验证会在 TLS 握手阶段因 CRYPT_E_NO_REVOCATION_CHECK 失败。
    // 注意：这条请求也不记进连接列表、不打日志（Windows 会高频拉取）。
    if req.uri().path() == "/mewway.crl" {
        return crl_response(&ctx);
    }
    if req.method() == Method::CONNECT {
        return connect(req, ctx).await;
    }
    plain_http(req, ctx).await
}

/// 返回本地 CA 签发的 CRL（DER 编码，content-type 用 PKIX CRL）。
fn crl_response(ctx: &Ctx) -> Response<ResBody> {
    let der = ctx.ca.crl_der().to_vec();
    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/pkix-crl")
        .header("cache-control", "no-store, no-cache, must-revalidate")
        .body(forward::body_from_bytes(der))
        .unwrap_or_else(|_| forward::text(StatusCode::INTERNAL_SERVER_ERROR, "CRL 生成失败"))
}

/// 把当前规则渲染成 PAC 返回给浏览器。
///
/// 为什么不用 `file://`：Chromium 系读系统 PAC 时对本地文件并不可靠，
/// 实测 Edge 根本不去取，于是规则域名全部直连 —— 「PAC 配好了但浏览器还是打不开」。
fn pac_response(ctx: &Ctx) -> Response<ResBody> {
    // 注意：这条请求**不**记进连接列表，也不打日志 —— 浏览器会高频取 PAC
    //（启动、定时刷新、每次开新标签页都可能再来一次），打日志只会把日志框刷满，
    // 而且对用户没有任何信息量。
    let cfg = ctx.settings();
    let body = crate::sys::pac::render(&cfg.sites, &cfg.proxy_addr());
    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/x-ns-proxy-autoconfig; charset=utf-8")
        .header("cache-control", "no-store, no-cache, must-revalidate")
        .body(forward::body_from(body))
        .unwrap_or_else(|_| forward::text(StatusCode::INTERNAL_SERVER_ERROR, "PAC 生成失败"))
}

/// 决定一条连接该怎么走。
///
/// 顺序：规则表 -> 镜像降级 -> 未命中时的智能兜底
fn resolve_route(ctx: &Ctx, host: &str, port: u16) -> rules::Decision {
    let cfg = ctx.settings();
    let mut dec = rules::decide(&cfg.sites, host);
    let has_upstream = cfg.upstream_addr().is_some();
    let ca_ok = ctx.shared.ca_installed.load(Ordering::Relaxed) || std::env::var("MEWWAY_FORCE_MITM").is_ok();

    // 需要本地 CA 的策略：只要 CA 还没确认装好（包括「检测还没回来」的窗口）就别硬上，
    // 否则客户端会拿到未受信的证书、握手偶发失败。CA 就绪后立刻恢复正常策略，
    // 启动期那几百毫秒最多只是中继先走隧道/上游，比证书错误安全得多。
    if matches!(dec.route, Route::Mirror(_) | Route::Relay) && !ca_ok {
        dec.route = if has_upstream { Route::Upstream } else { Route::Tunnel };
        return dec;
    }

    // 命中规则就按规则来。规则是策略，不能被探测结果悄悄改掉 ——
    // 用户给某个站点了「加速」，那就是加速；连不上宁可报错让他看见，也不能
    // 自己改成走代理（改走代理请把那条规则改成「代理」或「中继」）。
    if !matches!(dec.route, Route::Direct) {
        return dec;
    }

    // 没命中规则（或规则里写的是「直连」）：默认原样放行。
    //
    // 这里曾经默认「乐观加速」——所有域名都先 DoH 一遍再测速。对国内 CDN 是灾难：
    // 系统 DNS 本来给的是就近节点，DoH 换成泛播 IP 后反而变慢，4 秒预算一到就降级，
    // 用户看到的就是「B 站视频转圈、原本能开的站打不开」。加速器把能用的东西搞坏，
    // 那就不是加速器了。所以默认改成 Direct，Auto 只作为可选项。
    dec.route = match cfg.fallback {
        Fallback::Direct => Route::Direct,
        Fallback::Auto => {
            if !has_upstream {
                // 没配上游，「不行再走代理」没有去处，那就全都加速
                Route::Tunnel
            } else {
                match ctx.probes.cached(host) {
                    Some(true) => Route::Tunnel,
                    Some(false) => Route::Upstream,
                    None => {
                        // 没记录：先乐观加速，同时后台补一次真实握手探测。
                        // 万一判断错了，tunnel_out 里的握手观察会当场改走上游，不会真的失败。
                        ctx.probes.spawn_check(host.to_string(), port, ctx.resolver.clone());
                        Route::Tunnel
                    }
                }
            }
        }
    };
    dec
}

/// 展示用策略名
fn policy_label(route: &Route) -> &'static str {
    match route {
        Route::Tunnel => "透传",
        Route::Relay => "中继",
        Route::Mirror(_) => "镜像",
        Route::Upstream => "代理",
        Route::Direct => "直连",
    }
}

async fn connect(req: Request<Incoming>, ctx: Arc<Ctx>) -> Response<ResBody> {
    let Some(authority) = req.uri().authority().cloned() else {
        return forward::text(StatusCode::BAD_REQUEST, "CONNECT 缺少目标地址");
    };
    let host = authority.host().to_string();
    let port = authority.port_u16().unwrap_or(443);

    let dec = resolve_route(&ctx, &host, port);
    let label = policy_label(&dec.route);

    match dec.route {
        Route::Mirror(target) => {
            if port != 443 {
                // 非标准端口不做中间人，退化成隧道
                return tunnel_out(req, ctx, &host, port, true, false, dec.rule, label).await;
            }
            let id = ctx.shared.push_conn(&host, port, dec.rule, label, None);
            let ctx2 = ctx.clone();
            let h = host.clone();
            tokio::spawn(async move {
                match hyper::upgrade::on(req).await {
                    Ok(up) => ctx2.mitm.serve(up, h.clone(), target, ctx2.clone(), id).await,
                    Err(e) => ctx2.log(Level::Warn, format!("[{h}] 升级连接失败：{e}")),
                }
                ctx2.shared.close_conn(id, 0, 0);
            });
            Response::new(forward::empty_body())
        }
        Route::Relay => {
            if port != 443 {
                return tunnel_out(req, ctx, &host, port, true, false, dec.rule, label).await;
            }
            let id = ctx.shared.push_conn(&host, port, dec.rule, label, None);
            let ctx2 = ctx.clone();
            let h = host.clone();
            tokio::spawn(async move {
                match hyper::upgrade::on(req).await {
                    Ok(up) => ctx2.mitm.serve_relay(up, h.clone(), port, ctx2.clone(), id).await,
                    Err(e) => ctx2.log(Level::Warn, format!("[{h}] 升级连接失败：{e}")),
                }
                ctx2.shared.close_conn(id, 0, 0);
            });
            Response::new(forward::empty_body())
        }
        // 自己择优直连，绕开用户原有的代理（命中规则，或智能判定为可加速）
        Route::Tunnel => tunnel_out(req, ctx, &host, port, true, false, dec.rule, label).await,
        // 放行：系统解析 + 直连，不测速、不碰上游。和没装本程序时一模一样。
        Route::Direct => tunnel_out(req, ctx, &host, port, false, false, dec.rule, label).await,
        // 交给上游代理（也就是你原本的代理），没配就直接走
        Route::Upstream => tunnel_out(req, ctx, &host, port, false, true, dec.rule, label).await,
    }
}

#[allow(clippy::too_many_arguments)]
async fn tunnel_out(
    req: Request<Incoming>,
    ctx: Arc<Ctx>,
    host: &str,
    port: u16,
    best_ip: bool,
    via_upstream: bool,
    rule: Option<String>,
    label: &'static str,
) -> Response<ResBody> {
    let mut via = via_upstream;
    let t0 = std::time::Instant::now();
    // 命中规则 = 用户已经明确指定了策略，后面所有「自动兜底」都不许碰它
    let is_rule = rule.is_some();
    let conn_id = ctx.shared.push_conn(host, port, rule, label, None);
    let has_upstream = ctx.settings().upstream_addr().is_some();
    // 规则命中的站点默认不参与自动兜底：规则说了算，失败了就报错让人看见。
    // 想让它们也兜底的话，在设置里打开「规则站点失败兜底」。
    let allow_rule_fallback = ctx.settings().rule_fallback;
    let may_fallback = best_ip && !via_upstream && has_upstream && (!is_rule || allow_rule_fallback);

    let direct = tunnel::connect(host, port, &ctx, best_ip, via_upstream);
    let direct = if may_fallback {
        match tokio::time::timeout(DIRECT_BUDGET, direct).await {
            Ok(r) => r,
            Err(_) => Err(anyhow::anyhow!("直连超过 {}s 预算", DIRECT_BUDGET.as_secs())),
        }
    } else {
        direct.await
    };

    let upstream = match direct {
        Ok(s) => {
            ctx.shared.set_conn_lat(conn_id, t0.elapsed().as_millis() as u32);
            s
        }
        Err(e) => {
            // 一个字节都还没发，换上游完全无损
            if may_fallback {
                match tunnel::connect_upstream(host, port, &ctx).await {
                    Ok(s) => {
                        ctx.probes.set(host, false);
                        ctx.log(Level::Warn, format!("[{host}] 直连不通（{e}），已改走上游代理"));
                        via = true;
                        ctx.shared.set_conn_lat(conn_id, t0.elapsed().as_millis() as u32);
                        ctx.shared.set_conn_policy(conn_id, "代理");
                        ctx.shared.set_conn_note(conn_id, format!("直连不通（{e}），已改走上游代理"));
                        s
                    }
                    Err(up_err) => {
                        ctx.shared.fail_conn(conn_id, format!("直连不通（{e}），上游代理也不通（{up_err}）"));
                        ctx.log(Level::Err, format!("连接 {host}:{port} 失败：直连 {e}；上游 {up_err}"));
                        return forward::text(
                            StatusCode::BAD_GATEWAY,
                            format!("无法连接 {host}:{port}：直连 {e}；上游代理 {up_err}"),
                        );
                    }
                }
            } else {
                let hint = if is_rule { "，这条规则指定的是「透传」，直连被阻断了；把它改成「中继」或「代理」即可" } else { "" };
                ctx.shared.fail_conn(conn_id, format!("{e}{hint}"));
                ctx.log(Level::Warn, format!("连接 {host}:{port} 失败：{e}{hint}"));
                return forward::text(StatusCode::BAD_GATEWAY, format!("无法连接 {host}:{port}：{e}{hint}"));
            }
        }
    };

    let ctx2 = ctx.clone();
    let h = host.to_string();
    // 自己直连的 TLS 连接都可以观察握手是否被掐断。
    // 规则站点也观察 —— 不是为了改策略，而是为了在失败时能说出人话：
    // 「这条规则是加速，但握手被 SNI 阻断了，改成中继就能打开」。
    let watch = best_ip && !via && port == 443;

    tokio::spawn(async move {
        let upgraded = match hyper::upgrade::on(req).await {
            Ok(u) => u,
            Err(e) => {
                ctx2.shared.log(Level::Warn, format!("[{h}] 升级连接失败：{e}"));
                ctx2.shared.fail_conn(conn_id, format!("升级连接失败：{e}"));
                return;
            }
        };
        let mut client = TokioIo::new(upgraded);
        let mut server = upstream;

        if watch {
            // 把客户端的第一个 TLS 记录（ClientHello）读出来自己转发，
            // 这样「服务器肯不肯回 ServerHello」就变成可观测的了。
            // 此时我们只发过这一段，改走别的线路重放它，浏览器完全无感。
            if let Some(head) = read_tls_record(&mut client).await {
                let is_tls = head.first() == Some(&0x16);
                let reply = match server.write_all(&head).await {
                    Ok(()) => server_replies(&mut server).await,
                    // 写都写不出去，等于被掐
                    Err(_) => Reply::Closed,
                };
                let alive = reply == Reply::Yes;

                if is_tls && reply == Reply::Closed {
                    let mut retried = false;
                    if may_fallback {
                        if let Ok(mut s2) = tunnel::connect_upstream(&h, port, &ctx2).await {
                            if s2.write_all(&head).await.is_ok() {
                                retried = true;
                                ctx2.probes.mark_blocked(&h);
                                ctx2.log(Level::Warn, format!("[{h}] 直连握手被阻断，已自动改走上游代理"));
                                ctx2.shared.set_conn_policy(conn_id, "代理");
                                ctx2.shared.set_conn_note(conn_id, "直连握手被阻断，已自动改走上游代理");
                                let shared = ctx2.shared.clone();
                                let (up, down) = tunnel::pump(&mut client, &mut s2).await.unwrap_or((0, 0));
                                shared.add_bytes(up, down);
                                shared.close_conn(conn_id, up, down);
                            }
                        }
                    }
                    if !retried {
                        ctx2.probes.mark_blocked(&h);
                        let why = if is_rule && !allow_rule_fallback {
                            "握手被 SNI 阻断了，已自动改为「中继」，刷新一下就好"
                        } else if has_upstream {
                            "且上游代理不可用"
                        } else {
                            "且未配置上游代理"
                        };
                        ctx2.log(Level::Err, format!("[{h}] 直连握手被阻断，{why}"));
                        ctx2.shared.fail_conn(conn_id, format!("直连握手被阻断，{why}"));
                    }
                    return;
                }
                if is_tls && alive {
                    // 记一笔「这个域名确实能加速」，省掉下次的探测
                    ctx2.probes.set(&h, true);
                }
                // Reply::Slow：一个字都没等到，但也可能是这个站就是慢。
                // 这时候**什么都不做**，把已经发出去的 ClientHello 留在原地，
                // 继续双向搬运 —— 让服务器自己把 ServerHello 慢慢吐回来。
                // 以前这里会直接判死并 return，TTFB > 1.5s 的站点就再也打不开了。
            }
        }

        let shared = ctx2.shared.clone();
        let (up, down) = tunnel::pump(&mut client, &mut server).await.unwrap_or((0, 0));
        shared.add_bytes(up, down);
        shared.close_conn(conn_id, up, down);
    });

    Response::new(forward::empty_body())
}

/// 读客户端发来的第一个 TLS 记录（含 5 字节记录头）。
/// 首字节不是 `0x16`（非 TLS）时只读 1 字节就返回，后续交给双向搬运。
async fn read_tls_record<C: AsyncRead + Unpin>(c: &mut C) -> Option<Vec<u8>> {
    let mut one = [0u8; 1];
    match tokio::time::timeout(Duration::from_secs(5), c.read(&mut one)).await {
        Ok(Ok(1)) => {}
        _ => return None,
    }
    if one[0] != 0x16 {
        return Some(vec![one[0]]);
    }

    let mut hdr = [0u8; 4];
    tokio::time::timeout(Duration::from_secs(5), c.read_exact(&mut hdr)).await.ok()?.ok()?;
    let len = u16::from_be_bytes([hdr[2], hdr[3]]) as usize;
    let mut out = Vec::with_capacity(5 + len.min(16 * 1024));
    out.push(0x16);
    out.extend_from_slice(&hdr);
    if len == 0 || len > 16 * 1024 {
        return Some(out);
    }

    let mut body = vec![0u8; len];
    tokio::time::timeout(Duration::from_secs(5), c.read_exact(&mut body)).await.ok()?.ok()?;
    out.extend_from_slice(&body);
    Some(out)
}

/// 服务器对 ClientHello 的反应。
///
/// 必须把「超时」和「被关」分开：以前这里只返回 bool，1.5 秒没动静就当成被墙，
/// 于是 TTFB 慢一点的站点会被**直接掐断**（客户端一个字节都拿不到），
/// 还会把那条规则误升级成中继。线路抖一下不该让用户永久失去透传。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Reply {
    /// 有回话，握手在正常进行
    Yes,
    /// EOF / RST：明确被掐
    Closed,
    /// 1.5 秒没动静：可能只是慢，也可能被静默丢弃 —— 不下结论
    Slow,
}

/// 服务器有没有回话。
async fn server_replies(s: &mut TcpStream) -> Reply {
    let mut b = [0u8; 1];
    match tokio::time::timeout(Duration::from_millis(1500), s.peek(&mut b)).await {
        Ok(Ok(n)) if n > 0 => Reply::Yes,
        Ok(Ok(_)) => Reply::Closed,
        Ok(Err(_)) => Reply::Closed,
        Err(_) => Reply::Slow,
    }
}

async fn plain_http(req: Request<Incoming>, ctx: Arc<Ctx>) -> Response<ResBody> {
    let uri = req.uri().clone();
    let Some(host) = uri.host().map(|h| h.to_string()) else {
        return forward::text(StatusCode::BAD_REQUEST, "无效的代理请求");
    };
    let port = uri.port_u16();
    let pq = uri.path_and_query().map(|p| p.as_str().to_string()).unwrap_or_else(|| "/".to_string());

    let dec = resolve_route(&ctx, &host, port.unwrap_or(80));
    let via_upstream = dec.route.via_upstream();
    let target = match &dec.route {
        Route::Mirror(t) => t.clone(),
        _ => host.clone(),
    };
    let hostport = match port {
        Some(p) if p != 80 => format!("{target}:{p}"),
        _ => target,
    };

    let t0 = std::time::Instant::now();
    let id = ctx.shared.push_conn(
        &host,
        port.unwrap_or(80),
        dec.rule,
        policy_label(&dec.route),
        None,
    );
    let resp = forward::forward(&ctx, req, "http", &hostport, &host, &pq, via_upstream).await;
    ctx.shared.set_conn_lat(id, t0.elapsed().as_millis() as u32);
    ctx.shared.close_conn(id, 0, 0);
    resp
}
