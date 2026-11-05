//! 代理内核：本地 HTTP 代理 + CONNECT 隧道 + 可选 TLS 中间人

pub mod ca;
pub mod engine;
pub mod forward;
pub mod ipdb;
pub mod mitm;
pub mod probe;
pub mod relay;
pub mod resolver;
pub mod rules;
pub mod server;
pub mod tunnel;

use crate::config::Settings;
use crate::shared::{Command, Level, Shared};
use std::sync::{Arc, RwLock};
use std::time::Duration;
use tokio::sync::mpsc::UnboundedSender;

pub type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// 一次「代理运行期」的上下文，启停/重载时整体替换
pub struct Ctx {
    pub cfg: RwLock<Arc<Settings>>,
    pub shared: Arc<Shared>,
    pub resolver: Arc<resolver::Resolver>,
    /// 「这个域名能不能加速」的探测表
    pub probes: Arc<probe::Probes>,
    /// 本地 CA（签发叶子证书 + 提供 CRL），CRL 端点 /mewway.crl 需要读它
    pub ca: Arc<ca::Ca>,
    pub mitm: mitm::Mitm,
    /// 直连客户端：加速/镜像用
    pub http: reqwest::Client,
    /// 上游客户端：未命中规则的明文 HTTP 用
    pub http_upstream: RwLock<Option<reqwest::Client>>,
}

fn client_builder() -> reqwest::ClientBuilder {
    reqwest::Client::builder()
        // 关键：绝不能读系统代理。接管系统代理后它就是指向我们自己，
        // 自己的请求再走自己 -> 自噬死循环，DoH 直接卡到超时。
        .no_proxy()
        .no_gzip()
        .no_brotli()
        .no_deflate()
        .redirect(reqwest::redirect::Policy::none())
        .pool_max_idle_per_host(16)
        .connect_timeout(Duration::from_secs(12))
        // 「多久没有新字节就放弃」而不是「整个请求多久超时」。
        // 镜像站 / 源站把连接挂住不回数据时（实测 hf-mirror 会），
        // 没有这一条浏览器就一直转圈；而总时长超时会误杀几十 G 的模型下载，
        // 所以只能掐「静默」，不能掐「总时长」。
        .read_timeout(Duration::from_secs(30))
}

fn upstream_client(cfg: &Settings) -> Option<reqwest::Client> {
    let addr = cfg.upstream_addr()?;
    let url = if cfg.upstream.contains("://") {
        cfg.upstream.trim().to_string()
    } else {
        format!("http://{addr}")
    };
    client_builder().proxy(reqwest::Proxy::all(url).ok()?).build().ok()
}

impl Ctx {
    pub fn new(cfg: Arc<Settings>, shared: Arc<Shared>, tx: UnboundedSender<Command>) -> anyhow::Result<Arc<Self>> {
        let ca = Arc::new(ca::Ca::load_or_create()?);
        let http = client_builder().build()?;
        let http_upstream = RwLock::new(upstream_client(&cfg));
        let resolver = Arc::new(resolver::Resolver::new(shared.clone(), cfg.doh.clone()));
        let probes = Arc::new(probe::Probes::new(shared.clone(), tx.clone()));
        let mitm = mitm::Mitm::new(ca.clone(), cfg.port);
        Ok(Arc::new(Self {
            cfg: RwLock::new(cfg),
            shared,
            resolver,
            probes,
            ca,
            mitm,
            http,
            http_upstream,
        }))
    }

    pub fn settings(&self) -> Arc<Settings> {
        self.cfg.read().unwrap_or_else(|e| e.into_inner()).clone()
    }

    pub fn replace(&self, cfg: Arc<Settings>) {
        self.resolver.set_doh(cfg.doh.clone());
        if let Ok(mut g) = self.http_upstream.write() {
            *g = upstream_client(&cfg);
        }
        *self.cfg.write().unwrap_or_else(|e| e.into_inner()) = cfg;
    }

    /// 明文 HTTP 转发时选哪个客户端：未命中规则且配了上游 -> 走上游
    pub fn client(&self, via_upstream: bool) -> reqwest::Client {
        if via_upstream {
            if let Some(c) = self.http_upstream.read().ok().and_then(|g| g.clone()) {
                return c;
            }
        }
        self.http.clone()
    }

    pub fn log(&self, level: Level, msg: impl Into<String>) {
        self.shared.log(level, msg);
    }
}
