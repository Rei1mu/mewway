//! 请求转发：把客户端请求转给真实站点（或镜像站），流式回传

use crate::proxy::{BoxError, Ctx};
use crate::shared::Level;
use bytes::Bytes;
use futures_util::StreamExt;
use http_body_util::combinators::UnsyncBoxBody;
use http_body_util::{BodyExt, Empty, Full, StreamBody};
use hyper::body::{Frame, Incoming};
use hyper::header::HeaderValue;
use hyper::{Request, Response, StatusCode};

pub type ResBody = UnsyncBoxBody<Bytes, BoxError>;

pub fn empty_body() -> ResBody {
    Empty::<Bytes>::new().map_err(|e| -> BoxError { match e {} }).boxed_unsync()
}

/// 一段纯文本 body（PAC 之类的小响应直接用这个）
pub fn body_from(msg: impl Into<String>) -> ResBody {
    Full::new(Bytes::from(msg.into())).map_err(|e| -> BoxError { match e {} }).boxed_unsync()
}

pub fn text(status: StatusCode, msg: impl Into<String>) -> Response<ResBody> {
    let body = Full::new(Bytes::from(msg.into())).map_err(|e| -> BoxError { match e {} }).boxed_unsync();
    Response::builder()
        .status(status)
        .header("content-type", "text/plain; charset=utf-8")
        .body(body)
        .unwrap()
}

pub(crate) fn is_hop(h: &str) -> bool {
    matches!(
        h,
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "proxy-connection"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
    )
}

/// `target_host` 是真正要连的域名（镜像模式已被改写），`orig_host` 是客户端请求的原始域名
pub async fn forward(
    ctx: &Ctx,
    req: Request<Incoming>,
    scheme: &str,
    target_host: &str,
    orig_host: &str,
    path_query: &str,
    via_upstream: bool,
) -> Response<ResBody> {
    let (parts, body) = req.into_parts();

    let url = format!("{scheme}://{target_host}{path_query}");
    let mut headers = hyper::HeaderMap::new();
    for (k, v) in parts.headers.iter() {
        let name = k.as_str();
        if is_hop(name) || name == "host" || name == "content-length" || name == "accept-encoding" {
            continue;
        }
        headers.append(k.clone(), v.clone());
    }
    if let Ok(hv) = HeaderValue::from_str(target_host) {
        headers.insert(hyper::header::HOST, hv);
    }

    let no_body = matches!(parts.method, hyper::Method::GET | hyper::Method::HEAD)
        || parts
            .headers
            .get(hyper::header::CONTENT_LENGTH)
            .map(|v| v.as_bytes() == b"0")
            .unwrap_or(false);

    let mut rb = ctx.client(via_upstream).request(parts.method.clone(), &url).headers(headers);
    if !no_body {
        rb = rb.body(reqwest::Body::wrap_stream(body.into_data_stream()));
    }
    let sent = rb.send().await;

    let resp = match sent {
        Ok(r) => r,
        Err(e) => {
            ctx.log(Level::Warn, format!("{} {orig_host}{path_query} -> {e}", parts.method));
            return text(StatusCode::BAD_GATEWAY, format!("上游请求失败：{e}"));
        }
    };

    let status = resp.status();
    let mut builder = Response::builder().status(status);
    for (k, v) in resp.headers().iter() {
        let name = k.as_str();
        if is_hop(name) || name == "content-length" {
            continue;
        }
        let mut val = v.clone();
        // 把镜像站的跳转地址改回原域名，保证后续请求仍然经过代理
        if (name == "location" || name == "content-location") && target_host != orig_host {
            if let Ok(s) = v.to_str() {
                let from = format!("://{target_host}");
                let to = format!("://{orig_host}");
                if s.contains(&from) {
                    if let Ok(nv) = HeaderValue::from_str(&s.replace(&from, &to)) {
                        val = nv;
                    }
                }
            }
        }
        if let Some(hs) = builder.headers_mut() {
            hs.append(k.clone(), val);
        }
    }

    let stream = resp
        .bytes_stream()
        .map(|r| r.map(Frame::data).map_err(|e| -> BoxError { Box::new(e) }));
    let body = StreamBody::new(stream).boxed_unsync();

    builder.body(body).unwrap_or_else(|_| text(StatusCode::BAD_GATEWAY, "构造响应失败"))
}
