//! TLS 中间人：给被改写的域名签发本地证书，然后把请求转给镜像站

use crate::proxy::ca::Ca;
use crate::proxy::forward;
use crate::proxy::Ctx;
use crate::shared::Level;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::Request;
use hyper_util::rt::TokioIo;
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls::ServerConfig;
use std::collections::HashMap;
use std::convert::Infallible;
use std::sync::{Arc, Mutex};
use tokio_rustls::TlsAcceptor;

pub struct Mitm {
    tls: Arc<ServerConfig>,
}

impl Mitm {
    pub fn new(ca: Arc<Ca>, port: u16) -> Self {
        let _ = rustls::crypto::ring::default_provider().install_default();
        // 叶子证书里的 CRL Distribution Point 指向本代理暴露的 CRL 端点。
        let crl_url = format!("http://127.0.0.1:{port}/mewway.crl");
        let resolver = Arc::new(CertResolver {
            ca,
            cache: Mutex::new(HashMap::new()),
            crl_url,
        });
        let mut cfg = ServerConfig::builder().with_no_client_auth().with_cert_resolver(resolver);
        // 只谈 HTTP/1.1，避免 h2 帧解析的复杂度
        cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
        Self { tls: Arc::new(cfg) }
    }

    /// 接管一条已经 CONNECT 上来的隧道：本地终结 TLS，再把请求转给 `target`
    pub async fn serve(
        &self,
        upgraded: hyper::upgrade::Upgraded,
        host: String,
        target: String,
        ctx: Arc<Ctx>,
        conn_id: u64,
    ) {
        let io = TokioIo::new(upgraded);
        let acceptor = TlsAcceptor::from(self.tls.clone());
        let tls = match acceptor.accept(io).await {
            Ok(t) => t,
            Err(e) => {
                ctx.log(Level::Warn, format!("[{host}] TLS 握手失败：{e}（本地 CA 可能未安装）"));
                return;
            }
        };

        let io = TokioIo::new(tls);
        // 镜像的延迟没法在建连时量（真正干活的是 reqwest），
        // 就取「第一条请求从发出到拿到响应头」这一段，作为连接页的延迟。
        let first = Arc::new(std::sync::atomic::AtomicBool::new(true));
        let svc = service_fn(move |req: Request<Incoming>| {
            let ctx = ctx.clone();
            let target = target.clone();
            let host = host.clone();
            let first = first.clone();
            async move {
                let pq = req
                    .uri()
                    .path_and_query()
                    .map(|p| p.as_str().to_string())
                    .unwrap_or_else(|| "/".to_string());
                let t0 = std::time::Instant::now();
                let resp = forward::forward(&ctx, req, "https", &target, &host, &pq, false).await;
                if first.swap(false, std::sync::atomic::Ordering::Relaxed) {
                    ctx.shared.set_conn_lat(conn_id, t0.elapsed().as_millis() as u32);
                }
                Ok::<_, Infallible>(resp)
            }
        });

        let _ = hyper::server::conn::http1::Builder::new().serve_connection(io, svc).await;
    }

    /// 中继模式：本地终结 TLS，但不用 reqwest 转发 ——
    /// 每个请求交给 `relay`，它用「不带 SNI」的 TLS 直连源站。
    pub async fn serve_relay(
        &self,
        upgraded: hyper::upgrade::Upgraded,
        host: String,
        port: u16,
        ctx: Arc<Ctx>,
        conn_id: u64,
    ) {
        let io = TokioIo::new(upgraded);
        let acceptor = TlsAcceptor::from(self.tls.clone());
        let tls = match acceptor.accept(io).await {
            Ok(t) => t,
            Err(e) => {
                ctx.log(Level::Warn, format!("[{host}] TLS 握手失败：{e}（本地 CA 可能未安装）"));
                return;
            }
        };

        // 这条客户端连接对应一条上游连接，复用能省掉每次请求的 TLS 握手
        let slot: std::sync::Arc<crate::proxy::relay::Slot> = std::sync::Arc::new(tokio::sync::Mutex::new(None));
        let svc = service_fn(move |req: Request<Incoming>| {
            let ctx = ctx.clone();
            let host = host.clone();
            let slot = slot.clone();
            async move {
                let resp = crate::proxy::relay::relay(&ctx, req, &host, port, &slot, conn_id).await;
                Ok::<_, Infallible>(resp)
            }
        });

        let _ = hyper::server::conn::http1::Builder::new().serve_connection(TokioIo::new(tls), svc).await;
    }
}

struct CertResolver {
    ca: Arc<Ca>,
    cache: Mutex<HashMap<String, Arc<CertifiedKey>>>,
    crl_url: String,
}

impl std::fmt::Debug for CertResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CertResolver")
    }
}

impl ResolvesServerCert for CertResolver {
    fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let name = hello.server_name()?.to_ascii_lowercase();
        if let Ok(g) = self.cache.lock() {
            if let Some(ck) = g.get(&name) {
                return Some(ck.clone());
            }
        }
        match self.ca.leaf(&name, &self.crl_url) {
            Ok(ck) => {
                let ck = Arc::new(ck);
                if let Ok(mut g) = self.cache.lock() {
                    g.insert(name, ck.clone());
                }
                Some(ck)
            }
            Err(_) => None,
        }
    }
}
