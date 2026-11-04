//! 加速可用性探测
//!
//! 「加速」只解决 DNS 污染 / 选到差 IP。如果 IP 本身被 SNI 阻断，TCP 能连上但
//! TLS 握手会被重置 —— 而我们是透传的，看不到握手失败，没法在线回退。
//!
//! 所以这里主动做一次真实 TLS 握手（不校验证书，只关心对方有没有回 ServerHello），
//! 把「这个域名能不能透传」变成一张可缓存的表，路由时直接查表：
//! 能透传就走透传（不碰证书、最省 CPU），不能就升级成中继。
//!
//! 这张表会落盘到 `%APPDATA%\mewway\probes.json`，否则每次启动都要把上百条规则
//! 重新探一遍，用户会看到「刚开程序网络一顿」。

use crate::config::Settings;
use crate::proxy::resolver::Resolver;
use crate::shared::{Command, Shared};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, SignatureScheme};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc::UnboundedSender;
use tokio_rustls::TlsConnector;

const TTL_OK: Duration = Duration::from_secs(1800);
/// 判定「必须中继」也记久一点：否则每过几分钟就要重新白等一次透传握手
const TTL_FAIL: Duration = Duration::from_secs(1800);
const TIMEOUT: Duration = Duration::from_secs(4);
/// 握手完成之后，等第一个响应字节的时间
const REPLY_TIMEOUT: Duration = Duration::from_secs(3);
/// 落盘后多久算过期。SNI 阻断是很稳定的属性，一天足够。
const DISK_TTL_SECS: i64 = 24 * 3600;

/// 一次探测的结论。
///
/// 分成三态而不是一个 bool，是因为「慢」和「被墙」必须分开：
/// 超时只说明这一秒线路不好，据此把规则改成中继，用户就再也回不到透传了
/// （透传不碰证书、CPU 最低、支持任意协议，是更好的那条路）。
/// 只有**明确被掐**（握手中 RST、或握手过了但数据被丢）才值得改规则。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// 真的通了：握手完成 + 收到真实响应字节
    Ok,
    /// 明确被 SNI 阻断：只有中继能救
    Blocked,
    /// 说不清（超时 / 解析不到 / TCP 就不通）—— 不要据此改任何配置
    Unclear,
}

/// 冷启动时的已知答案：这些域名按 SNI 阻断处理，不用等探测就先走中继。
///
/// 为什么需要它：探测是异步的，用户打开浏览器往往比探测快。没有这张表的话，
/// 程序刚起来第一次访问 github.com 会走透传 → 被掐 → 报错一次，下次才好。
/// 实测（同一 IP、同一时刻）github.com 带 SNI 握手超时、不带 SNI 立刻 200。
const SEED_RELAY: &[&str] = &["github.com", "githubusercontent.com", "githubassets.com", "github.io"];

fn seeded_blocked(host: &str) -> bool {
    let h = host.trim_end_matches('.').to_ascii_lowercase();
    SEED_RELAY.iter().any(|s| h == *s || h.ends_with(&format!(".{s}")))
}

struct Entry {
    ok: bool,
    at: Instant,
}

pub struct Probes {
    shared: Arc<Shared>,
    /// 用来请引擎改规则（配置的唯一写入方是引擎）
    tx: UnboundedSender<Command>,
    cache: Mutex<HashMap<String, Entry>>,
    inflight: Mutex<HashSet<String>>,
    /// 有没有新结果还没落盘
    dirty: std::sync::atomic::AtomicBool,
}

impl Probes {
    pub fn new(shared: Arc<Shared>, tx: UnboundedSender<Command>) -> Self {
        let mut cache = HashMap::new();
        // 先把上次的结论捞回来，过期就丢掉
        if let Ok(s) = std::fs::read_to_string(Self::path()) {
            if let Ok(map) = serde_json::from_str::<HashMap<String, DiskEntry>>(&s) {
                let now = chrono::Local::now().timestamp();
                for (host, e) in map {
                    if now - e.at > DISK_TTL_SECS {
                        continue;
                    }
                    // 把「多久以前测的」折进 Instant，让内存 TTL 接着算
                    let age = (now - e.at).max(0) as u64;
                    let at = Instant::now().checked_sub(Duration::from_secs(age)).unwrap_or_else(Instant::now);
                    cache.insert(host, Entry { ok: e.ok, at });
                }
            }
        }
        Self {
            shared,
            tx,
            cache: Mutex::new(cache),
            inflight: Mutex::new(HashSet::new()),
            dirty: std::sync::atomic::AtomicBool::new(false),
        }
    }

    pub fn path() -> std::path::PathBuf {
        Settings::dir().join("probes.json")
    }

    /// 查表：Some(true) 可以透传，Some(false) 必须中继，None 未知
    pub fn cached(&self, host: &str) -> Option<bool> {
        if let Ok(g) = self.cache.lock() {
            if let Some(e) = g.get(host) {
                let ttl = if e.ok { TTL_OK } else { TTL_FAIL };
                if e.at.elapsed() < ttl {
                    return Some(e.ok);
                }
            }
        }
        // 表里没有 / 已过期：冷启动的已知答案兜底
        if seeded_blocked(host) {
            return Some(false);
        }
        None
    }

    pub fn set(&self, host: &str, ok: bool) {
        if let Ok(mut g) = self.cache.lock() {
            g.insert(host.to_string(), Entry { ok, at: Instant::now() });
        }
        self.shared.set_cap(host, ok);
        self.dirty.store(true, std::sync::atomic::Ordering::Relaxed);
    }

    /// 确认这个域名**被 SNI 阻断**了。
    ///
    /// 和 `set(host, false)` 的区别很关键：`set(false)` 还包括「TCP 连不上」这种
    /// 线路问题，换成中继也未必有用；而这里是握手被掐 —— 只有中继能救。
    /// 所以这里额外请引擎把对应的「透传」规则改成「中继」并写回配置。
    pub fn mark_blocked(&self, host: &str) {
        self.set(host, false);
        let _ = self.tx.send(Command::Escalate(host.to_string()));
    }

    /// 有变化才写盘，由引擎循环定期调用
    pub fn flush(&self) {
        if !self.dirty.swap(false, std::sync::atomic::Ordering::Relaxed) {
            return;
        }
        let map: HashMap<String, DiskEntry> = {
            let Ok(g) = self.cache.lock() else { return };
            let now = chrono::Local::now().timestamp();
            g.iter()
                .map(|(k, e)| {
                    let age = e.at.elapsed().as_secs() as i64;
                    (k.clone(), DiskEntry { ok: e.ok, at: now - age })
                })
                .collect()
        };
        if let Ok(s) = serde_json::to_string(&map) {
            let _ = std::fs::write(Self::path(), s);
        }
    }

    /// 后台发起一次探测（同一域名去重）
    pub fn spawn_check(self: &Arc<Self>, host: String, port: u16, resolver: Arc<Resolver>) {
        if self.inflight.lock().map(|g| g.contains(&host)).unwrap_or(true) {
            return;
        }
        if let Ok(mut g) = self.inflight.lock() {
            g.insert(host.clone());
        }
        let me = self.clone();
        tokio::spawn(async move {
            match me.probe(&host, port, &resolver).await {
                Verdict::Ok => me.set(&host, true),
                Verdict::Blocked => me.set(&host, false),
                // 说不清就别写表：写进去会污染「能不能加速」的判断
                Verdict::Unclear => {}
            }
            if let Ok(mut g) = me.inflight.lock() {
                g.remove(&host);
            }
        });
    }

    /// 启动预热：把所有「透传」规则先探一遍，这样浏览器来的时候已经知道该不该走中继。
    ///
    /// 探出「被 SNI 阻断」的，顺手把那条规则改成「中继」并写回配置 ——
    /// 于是用户第一次访问这类站点就是通的，不用先失败一次再刷新。
    ///
    /// 并发 6 路 —— 探测全是网络等待，几乎不吃 CPU；限流只是为了别把 DNS 打爆。
    pub fn warmup(self: &Arc<Self>, sites: &[crate::config::Site], resolver: Arc<Resolver>) {
        let hosts: Vec<String> = sites
            .iter()
            .filter(|s| s.enabled && s.mode == crate::config::Mode::Tunnel)
            .map(|s| s.host.trim_start_matches("*.").to_string())
            .filter(|h| !h.is_empty() && self.cached(h).is_none())
            .collect();
        if hosts.is_empty() {
            return;
        }
        let n = hosts.len();
        let me = self.clone();
        tokio::spawn(async move {
            let sem = Arc::new(tokio::sync::Semaphore::new(6));
            let mut set = tokio::task::JoinSet::new();
            for h in hosts {
                let sem = sem.clone();
                let me = me.clone();
                let resolver = resolver.clone();
                set.spawn(async move {
                    let Ok(_permit) = sem.acquire_owned().await else { return };
                    match me.probe(&h, 443, &resolver).await {
                        Verdict::Ok => me.set(&h, true),
                        // 被 SNI 阻断：请引擎把这条规则改成「中继」
                        Verdict::Blocked => me.mark_blocked(&h),
                        // 超时之类一律不动配置 —— 宁可让它继续透传，
                        // 也别因为一次线路抖动就把用户的规则永久改成中继
                        Verdict::Unclear => {}
                    }
                });
            }
            while set.join_next().await.is_some() {}
            me.flush();
            let blocked = {
                let g = me.cache.lock().ok().map(|g| g.values().filter(|e| !e.ok).count()).unwrap_or(0);
                g
            };
            me.shared.log(
                crate::shared::Level::Info,
                format!("加速预热完成：{n} 条规则，其中 {blocked} 条需要走中继"),
            );
        });
    }

    /// 真正探一次：TLS 握手 + 一个真实的 HTTP 请求。
    ///
    /// 为什么不能只握手：实测 `github.com` **带 SNI 的握手是能成功的**（ServerHello
    /// 正常返回），但紧接着的应用层数据会被丢掉 —— 只握手会把它判成「能透传」，
    /// 然后浏览器打开就是一直转圈。所以要看到第一个响应字节才算数。
    pub async fn probe(&self, host: &str, port: u16, resolver: &Resolver) -> Verdict {
        let Some((addr, _)) = resolver.best(host, port).await else {
            // 解析不到 / TCP 全不通：这是线路问题，换成中继也没用
            return Verdict::Unclear;
        };
        let tcp = match tokio::time::timeout(TIMEOUT, TcpStream::connect(addr)).await {
            Ok(Ok(s)) => s,
            // 连不上：可能是 IP 被黑洞，也可能是这一下丢包 —— 都不算 SNI 阻断
            Ok(Err(_)) | Err(_) => return Verdict::Unclear,
        };
        let _ = tcp.set_nodelay(true);
        let Ok(name) = ServerName::try_from(host.to_string()) else {
            return Verdict::Unclear;
        };
        let mut tls = match tokio::time::timeout(TIMEOUT, TlsConnector::from(client_config()).connect(name, tcp)).await {
            Ok(Ok(t)) => t,
            // 握手阶段被 RST —— 这是最典型的 SNI 阻断特征
            Ok(Err(_)) => return Verdict::Blocked,
            // 握手超时：也可能只是慢
            Err(_) => return Verdict::Unclear,
        };

        let req = format!(
            "GET / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: mewway-probe\r\nAccept: */*\r\nConnection: close\r\n\r\n"
        );
        if tls.write_all(req.as_bytes()).await.is_err() {
            return Verdict::Blocked;
        }
        let mut b = [0u8; 1];
        match tokio::time::timeout(REPLY_TIMEOUT, tls.read(&mut b)).await {
            Ok(Ok(n)) if n > 0 => Verdict::Ok,
            // 握手都成了，却一个字节都不给就关：数据面被丢，只有中继能绕
            Ok(Ok(_)) | Ok(Err(_)) => Verdict::Blocked,
            Err(_) => Verdict::Unclear,
        }
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
struct DiskEntry {
    ok: bool,
    /// unix 秒
    at: i64,
}

pub(crate) fn client_config() -> Arc<ClientConfig> {
    static CFG: std::sync::OnceLock<Arc<ClientConfig>> = std::sync::OnceLock::new();
    CFG.get_or_init(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let mut cfg = ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerify))
            .with_no_client_auth();
        // 中继模式要在这条连接上跑 HTTP/1.1
        cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
        Arc::new(cfg)
    })
    .clone()
}

/// 只关心「握手能不能走完」，证书真伪交给浏览器去验
#[derive(Debug)]
pub(crate) struct NoVerify;

impl ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}
