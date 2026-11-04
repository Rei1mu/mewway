//! DNS：DoH 拿真实 IP + 多 IP 并发测速择优

use crate::shared::Shared;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tokio::task::JoinSet;

const IP_TTL: Duration = Duration::from_secs(300);
const BEST_TTL: Duration = Duration::from_secs(180);
const PROBE_TIMEOUT: Duration = Duration::from_millis(1200);
const MAX_PROBE: usize = 8;
/// 找到可用 IP 之后，再多等这么久看有没有更快的
const GRACE: Duration = Duration::from_millis(250);
/// 一个 IP 在「TLS/HTTP 层面明确失败」之后要冷藏多久。
///
/// 和 `invalidate` 不一样：`invalidate` 只是忘掉「最优」这个结论，
/// 下次测速它还会被算进候选；而有些 IP 是 **TCP 能连、握手也能成，但一发请求就断**
/// （实测 githubassets 的 185.199.110.215 就是这样），这种 IP 必须真的排掉，
/// 否则每次重建连接都可能又抽到它，用户看到的就是「时好时坏」。
///
/// 不能太长：冷藏是「宁可信其有」的保守判断，判错了要能自己恢复。
/// 90 秒足够避开一次抖动，又不至于把一个好 IP 关太久。
const BAD_TTL: Duration = Duration::from_secs(90);
/// 冷藏表最多记这么多，防止长期运行无限涨
const MAX_BAD: usize = 512;

struct Entry {
    ips: Vec<IpAddr>,
    ips_at: Instant,
    best: Option<(SocketAddr, u32)>,
    best_at: Instant,
}

pub struct Resolver {
    shared: Arc<Shared>,
    http: reqwest::Client,
    doh: RwLock<String>,
    cache: Mutex<HashMap<String, Entry>>,
    /// 「这个地址发请求必挂」的冷藏表（见 BAD_TTL 的注释）
    bad: Mutex<HashMap<SocketAddr, Instant>>,
}

impl Resolver {
    pub fn new(shared: Arc<Shared>, doh: String) -> Self {
        let http = reqwest::Client::builder()
            // 同上：DoH 必须直连出去，走系统代理会绕回自己
            .no_proxy()
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap_or_default();
        Self {
            shared,
            http,
            doh: RwLock::new(doh),
            cache: Mutex::new(HashMap::new()),
            bad: Mutex::new(HashMap::new()),
        }
    }

    /// 记一个「握手能过、请求必挂」的地址。中继在请求失败时调用。
    pub fn mark_bad(&self, addr: SocketAddr) {
        if let Ok(mut g) = self.bad.lock() {
            if g.len() >= MAX_BAD {
                g.retain(|_, at| at.elapsed() < BAD_TTL);
                if g.len() >= MAX_BAD {
                    g.clear();
                }
            }
            g.insert(addr, Instant::now());
        }
    }

    pub fn is_bad(&self, addr: SocketAddr) -> bool {
        let Ok(mut g) = self.bad.lock() else { return false };
        match g.get(&addr) {
            Some(at) if at.elapsed() < BAD_TTL => true,
            Some(_) => {
                g.remove(&addr);
                false
            }
            None => false,
        }
    }

    pub fn set_doh(&self, doh: String) {
        if let Ok(mut g) = self.doh.write() {
            if *g != doh {
                *g = doh;
                if let Ok(mut c) = self.cache.lock() {
                    c.clear();
                }
            }
        }
    }

    fn doh_endpoint(&self) -> String {
        self.doh.read().map(|g| g.clone()).unwrap_or_default()
    }

    /// 解析域名的候选 IP（带缓存）
    pub async fn ips(&self, host: &str) -> Vec<IpAddr> {
        if let Ok(ip) = host.parse::<IpAddr>() {
            return vec![ip];
        }
        if let Ok(c) = self.cache.lock() {
            if let Some(e) = c.get(host) {
                if e.ips_at.elapsed() < IP_TTL && !e.ips.is_empty() {
                    return e.ips.clone();
                }
            }
        }

        let doh = self.doh_lookup(host).await;
        let sys = system_lookup(host).await;
        // DoH 和系统解析各有各的用处：DoH 抗污染，系统解析对国内 CDN 往往更准
        // （运营商给的才是就近节点）。两个一起测速，让延迟说话。
        //
        // 这一条是「加速不能比直连差」的硬保证：直连能连上的 IP 一定在候选里，
        // 所以不存在「直连好好的，开了加速反而连不上」。
        let mut ips: Vec<IpAddr> = Vec::with_capacity(doh.len() + sys.len());
        let mut di = doh.into_iter();
        let mut si = sys.into_iter();
        loop {
            let mut moved = false;
            if let Some(ip) = di.next() {
                moved = true;
                if !ips.contains(&ip) {
                    ips.push(ip);
                }
            }
            if let Some(ip) = si.next() {
                moved = true;
                if !ips.contains(&ip) {
                    ips.push(ip);
                }
            }
            if !moved {
                break;
            }
        }
        if !ips.is_empty() {
            if let Ok(mut c) = self.cache.lock() {
                let e = c.entry(host.to_string()).or_insert(Entry {
                    ips: Vec::new(),
                    ips_at: Instant::now(),
                    best: None,
                    best_at: Instant::now() - BEST_TTL,
                });
                e.ips = ips.clone();
                e.ips_at = Instant::now();
            }
        }
        ips
    }

    async fn doh_lookup(&self, host: &str) -> Vec<IpAddr> {
        let base = self.doh_endpoint();
        if base.is_empty() {
            return Vec::new();
        }
        let url = format!("{base}?name={host}&type=A");
        let resp = self.http.get(&url).header("accept", "application/dns-json").send().await;
        let Ok(resp) = resp else {
            return Vec::new();
        };
        let Ok(v) = resp.json::<serde_json::Value>().await else {
            return Vec::new();
        };
        let mut out = Vec::new();
        if let Some(ans) = v.get("Answer").and_then(|a| a.as_array()) {
            for a in ans {
                // type 1 = A 记录
                let t = a.get("type").and_then(|t| t.as_u64()).unwrap_or(0);
                if t != 1 {
                    continue;
                }
                if let Some(ip) = a.get("data").and_then(|d| d.as_str()).and_then(|d| d.parse::<IpAddr>().ok()) {
                    if !out.contains(&ip) {
                        out.push(ip);
                    }
                }
            }
        }
        out
    }

    /// 只读缓存里的最优地址，不做任何探测。给中继的「快路」用。
    pub fn cached_best(&self, host: &str) -> Option<SocketAddr> {
        let addr = {
            let c = self.cache.lock().ok()?;
            let e = c.get(host)?;
            if e.best_at.elapsed() < BEST_TTL {
                e.best.map(|(a, _)| a)?
            } else {
                return None;
            }
        };
        // 冷藏期内的地址直接当没有 —— 否则「快路」每次都去撞那面墙
        if self.is_bad(addr) {
            return None;
        }
        Some(addr)
    }

    /// 记住一个「已经验证过能用」的地址（比如中继做过完整 TLS 握手成功的），
    /// 下次直接复用它，省掉一轮并发尝试。
    pub fn remember(&self, host: &str, addr: SocketAddr, ms: u32) {
        if let Ok(mut c) = self.cache.lock() {
            let e = c.entry(host.to_string()).or_insert(Entry {
                ips: Vec::new(),
                ips_at: Instant::now(),
                best: None,
                best_at: Instant::now() - BEST_TTL,
            });
            e.best = Some((addr, ms));
            e.best_at = Instant::now();
        }
        self.shared.set_lat(host, ms);
    }

    /// 作废某个域名的最优记录。拨号失败时必须调用 ——
    /// 否则会把一个已经失效的 IP 缓存三分钟，每次都白等一次建连超时。
    pub fn invalidate(&self, host: &str) {
        if let Ok(mut c) = self.cache.lock() {
            if let Some(e) = c.get_mut(host) {
                e.best = None;
                e.best_at = Instant::now() - BEST_TTL;
            }
        }
    }

    /// 测速选最优 IP，返回 (地址, 毫秒)；失败返回 None（调用方自行回退系统解析）
    pub async fn best(&self, host: &str, port: u16) -> Option<(SocketAddr, u32)> {
        self.pick(host, port, true).await
    }

    /// 和 `best()` 一样，但**不认缓存**。
    ///
    /// 测速按钮要的是「现在多少」，不是「三分钟前挑中的那个 IP 当时多少」。
    /// `best()` 命中 `BEST_TTL`（180 秒）缓存时会直接把旧结论写回界面 ——
    /// 用户点第二次看到的还是上一次的数字，就是这里造成的。
    pub async fn best_fresh(&self, host: &str, port: u16) -> Option<(SocketAddr, u32)> {
        self.pick(host, port, false).await
    }

    async fn pick(&self, host: &str, port: u16, use_cache: bool) -> Option<(SocketAddr, u32)> {
        if let Ok(ip) = host.parse::<IpAddr>() {
            return Some((SocketAddr::new(ip, port), 0));
        }

        if use_cache {
            let cached = {
                let c = self.cache.lock().ok();
                c.and_then(|c| c.get(host).and_then(|e| e.best.filter(|_| e.best_at.elapsed() < BEST_TTL)))
            };
            if let Some((addr, ms)) = cached {
                if !self.is_bad(addr) {
                    self.shared.set_lat(host, ms);
                    return Some((addr, ms));
                }
            }
        }

        let ips = self.ips(host).await;
        // 冷藏期内的 IP 不进候选，否则每次测速都会把它算进来、又挑中它
        let live: Vec<IpAddr> = ips.iter().copied().filter(|ip| !self.is_bad(SocketAddr::new(*ip, port))).collect();
        let mut bestv = if live.is_empty() {
            None
        } else {
            probe(&live[..live.len().min(MAX_PROBE)], port).await
        };

        // DNS 给的 IP 全都不通时，翻一翻公开 IP 池。
        // 直连在这一步就已经彻底失败了，这里还有第二次机会 —— 这就是「加速」
        // 在 TCP 被黑洞时唯一还能赢过直连的地方。
        if bestv.is_none() {
            let pool: Vec<IpAddr> = crate::proxy::ipdb::candidates(host)
                .into_iter()
                .filter(|ip| !self.is_bad(SocketAddr::new(*ip, port)))
                .collect();
            if !pool.is_empty() {
                self.shared
                    .log(crate::shared::Level::Info, format!("[{host}] DNS 给的 IP 都不通，改试公开 IP 池"));
                bestv = probe(&pool, port).await;
            }
        }

        if let Some((addr, ms)) = bestv {
            self.shared.set_lat(host, ms);
            if let Ok(mut c) = self.cache.lock() {
                if let Some(e) = c.get_mut(host) {
                    e.best = Some((addr, ms));
                    e.best_at = Instant::now();
                }
            }
            Some((addr, ms))
        } else {
            None
        }
    }

    /// 「直连」规则专用的测速：**只**用系统解析，不走 DoH、不翻 IP 池。
    ///
    /// 为什么不能直接用 `best()`：`Route::Direct` 实际就是「系统解析 + 直连」，
    /// 而 `best()` 会把 DoH 泛播 IP 和公开 IP 池一起拿来比快慢，挑出来的通常
    /// 比用户真实走的路径更快 —— 界面上显示一个比真实情况漂亮的数字，等于骗自己。
    ///
    /// 注意这里量的仍然是 TCP 握手，不是 TLS：SNI 阻断型域名 TCP 是通的、
    /// 握手才被掐，所以这一列只能回答「连得上、多快」，通不通由 `cap_of` 那列负责。
    pub async fn best_system(&self, host: &str, port: u16) -> Option<(SocketAddr, u32)> {
        if let Ok(ip) = host.parse::<IpAddr>() {
            return Some((SocketAddr::new(ip, port), 0));
        }
        let ips = system_lookup(host).await;
        if ips.is_empty() {
            return None;
        }
        probe(&ips[..ips.len().min(MAX_PROBE)], port).await
    }

    /// 「中继」规则专用的测速：量的是**无 SNI 的 TLS 握手**，不是 TCP。
    ///
    /// 中继实际建连时就是这么干的（`relay.rs`：`ServerName::IpAddress`，RFC 6066 规定
    /// IP 不产生 SNI 扩展）。所以 TCP 握手快**不代表**它快 —— 有些 IP 的 TCP 通、
    /// TLS 却被掐，用 TCP 数字去显示中继的延迟，等于骗自己。
    ///
    /// 镜像不走这里：它由 reqwest 带真 SNI 连镜像站，TCP 数字就够了。
    pub async fn best_relay(&self, host: &str, port: u16) -> Option<(SocketAddr, u32)> {
        let ips = self.ips(host).await;
        let live: Vec<IpAddr> = ips
            .iter()
            .copied()
            .filter(|ip| !self.is_bad(SocketAddr::new(*ip, port)))
            .collect();
        if live.is_empty() {
            return None;
        }
        probe_relay(&live[..live.len().min(MAX_PROBE)], port).await
    }
}

/// 并发探测一组 IP 的「TCP + 无 SNI 握手」耗时，返回最快且握手成功的那个。
///
/// 不建 hyper 连接：测速只要一个数字，`relay.rs` 那套 `try_tls_timeout` 会顺手
/// 建一条 HTTP/1.1 连接，用来量延迟太重了。
async fn probe_relay(ips: &[IpAddr], port: u16) -> Option<(SocketAddr, u32)> {
    if ips.is_empty() {
        return None;
    }
    let mut set: JoinSet<(SocketAddr, u32)> = JoinSet::new();
    for ip in ips {
        let addr = SocketAddr::new(*ip, port);
        set.spawn(async move {
            let t0 = Instant::now();
            let ok = async {
                let tcp = tokio::time::timeout(PROBE_TIMEOUT, TcpStream::connect(addr)).await.ok()?.ok()?;
                let _ = tcp.set_nodelay(true);
                let name = rustls::pki_types::ServerName::IpAddress(addr.ip().into());
                let cfg = crate::proxy::probe::client_config();
                tokio::time::timeout(PROBE_TIMEOUT, tokio_rustls::TlsConnector::from(cfg).connect(name, tcp))
                    .await
                    .ok()?
                    .ok()?;
                Some(())
            }
            .await;
            match ok {
                Some(()) => (addr, t0.elapsed().as_millis() as u32),
                None => (addr, u32::MAX),
            }
        });
    }

    let mut best: Option<(SocketAddr, u32)> = None;
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
        if let Ok((addr, ms)) = r {
            if ms != u32::MAX && best.map_or(true, |(_, bm)| ms < bm) {
                best = Some((addr, ms));
            }
            if deadline.is_none() {
                deadline = Some(Instant::now() + GRACE);
            }
        }
    }
    best
}

/// 并发探测一组 IP 的 TCP 握手耗时，返回最快且连得上的那个
async fn probe(ips: &[IpAddr], port: u16) -> Option<(SocketAddr, u32)> {
    if ips.is_empty() {
        return None;
    }
    let mut set: JoinSet<(SocketAddr, u32)> = JoinSet::new();
    for ip in ips {
        let addr = SocketAddr::new(*ip, port);
        set.spawn(async move {
            let t0 = Instant::now();
            match tokio::time::timeout(PROBE_TIMEOUT, TcpStream::connect(addr)).await {
                Ok(Ok(s)) => {
                    drop(s);
                    (addr, t0.elapsed().as_millis() as u32)
                }
                _ => (addr, u32::MAX),
            }
        });
    }

    let mut best: Option<(SocketAddr, u32)> = None;
    let mut deadline: Option<Instant> = None;
    loop {
        // 已经有一个能连的之后，只再多等一小会儿看有没有更快的。
        // 否则一个死 IP 的 1.2 秒超时会把整轮拖慢，用户感知就是「卡一下」。
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
        if let Ok((addr, ms)) = r {
            if ms != u32::MAX && best.map_or(true, |(_, bm)| ms < bm) {
                best = Some((addr, ms));
                deadline = Some(Instant::now() + GRACE);
            }
        }
    }
    best
}

async fn system_lookup(host: &str) -> Vec<IpAddr> {
    match tokio::net::lookup_host((host, 443)).await {
        Ok(it) => {
            let mut v = Vec::new();
            for a in it {
                let ip = a.ip();
                if !v.contains(&ip) {
                    v.push(ip);
                }
            }
            v
        }
        Err(_) => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shared::Shared;

    /// 手动跑：cargo test -- --ignored --nocapture
    #[tokio::test]
    #[ignore]
    async fn probe_smoke() {
        let shared = Arc::new(Shared::new());
        let r = Resolver::new(shared, "https://dns.alidns.com/resolve".into());
        for h in ["api.github.com", "hf-mirror.com", "store.steampowered.com", "open.spotify.com"] {
            println!("{h} -> {:?}", r.best(h, 443).await);
        }
        // 直连规则走的是「系统解析 + TCP」，这里单独确认这条路也能量出数
        for h in ["edge.microsoft.com", "www.bing.com"] {
            println!("{h} (直连) -> {:?}", r.best_system(h, 443).await);
        }
    }
}
