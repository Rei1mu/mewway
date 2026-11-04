//! 站点规则匹配：域名 -> 处理策略

use crate::config::{Mode, Site};

#[derive(Debug, Clone)]
pub enum Route {
    /// 没命中任何规则，或规则里写了「直连」：
    /// 按系统解析直接连出去，不 DoH、不测速、不碰上游 —— 行为和不开本程序一样。
    Direct,
    /// DoH + 择优 IP 隧道
    Tunnel,
    /// 本地终结 TLS 后用「无 SNI」连接源站反向代理（绕过 SNI 阻断）
    Relay,
    /// 改写目标域名（镜像）
    Mirror(String),
    /// 强制交给上游代理（加速注定无效的站点）
    Upstream,
}

impl Route {
    /// 是否应该交给上游代理。
    ///
    /// 只有「代理」这一种。放行不等于走代理 —— 早期版本把两者混为一谈，
    /// 结果所有没命中规则的流量都被塞进了用户自己的 Clash，出问题都不知道找谁。
    pub fn via_upstream(&self) -> bool {
        matches!(self, Route::Upstream)
    }
}

/// 匹配结果：怎么走 + 命中的是哪条规则
#[derive(Debug, Clone)]
pub struct Decision {
    pub route: Route,
    /// 命中的规则 host（`None` = 没命中任何规则）
    pub rule: Option<String>,
}

impl Decision {
    fn new(route: Route, rule: Option<String>) -> Self {
        Self { route, rule }
    }
}

fn is_local(host: &str) -> bool {
    host == "localhost"
        || host == "127.0.0.1"
        || host == "::1"
        || host == "0.0.0.0"
        || host.ends_with(".localhost")
        || host.starts_with("127.")
}

/// 在规则表里查一个域名。精确匹配优先，其次是最长的通配后缀。
pub fn decide(sites: &[Site], host: &str) -> Decision {
    let h = host.trim_end_matches('.').to_ascii_lowercase();
    if h.is_empty() || is_local(&h) {
        return Decision::new(Route::Direct, None);
    }

    // 精确匹配
    for s in sites.iter().filter(|s| s.enabled && !s.host.contains('*')) {
        if s.host.eq_ignore_ascii_case(&h) {
            return Decision::new(s.route_for(&h), Some(s.host.clone()));
        }
    }

    // 通配匹配：取后缀最长的那个
    let mut best: Option<&Site> = None;
    for s in sites.iter().filter(|s| s.enabled && s.host.starts_with("*.")) {
        let base = &s.host[2..];
        if h == base || h.ends_with(&s.host[1..]) {
            if best.map_or(true, |b| b.host.len() < s.host.len()) {
                best = Some(s);
            }
        }
    }

    match best {
        Some(s) => Decision::new(s.route_for(&h), Some(s.host.clone())),
        None => Decision::new(Route::Direct, None),
    }
}

/// 找出命中某个域名的规则下标（精确优先，其次最长通配后缀）。
///
/// 引擎把「透传」规则改成「中继」时要用它 —— 改的是**规则**，
/// 不是这次连接，所以必须找到规则表里真正匹配的那一条。
pub fn find_rule(sites: &[Site], host: &str) -> Option<usize> {
    let h = host.trim_end_matches('.').to_ascii_lowercase();
    if h.is_empty() {
        return None;
    }
    for (i, s) in sites.iter().enumerate().filter(|(_, s)| s.enabled && !s.host.contains('*')) {
        if s.host.eq_ignore_ascii_case(&h) {
            return Some(i);
        }
    }
    let mut best: Option<(usize, &Site)> = None;
    for (i, s) in sites.iter().enumerate().filter(|(_, s)| s.enabled && s.host.starts_with("*.")) {
        let base = &s.host[2..];
        if h == base || h.ends_with(&s.host[1..]) {
            if best.map_or(true, |(_, b)| b.host.len() < s.host.len()) {
                best = Some((i, s));
            }
        }
    }
    best.map(|(i, _)| i)
}

impl Site {
    fn route_for(&self, host: &str) -> Route {
        match self.mode {
            Mode::Direct => Route::Direct,
            // 旧版的「加速（自动）」等价于透传（老配置加载时已经迁移过了）
            Mode::Auto | Mode::Tunnel => Route::Tunnel,
            Mode::Relay => Route::Relay,
            Mode::Proxy => Route::Upstream,
            Mode::Mirror => {
                if self.mirror.trim().is_empty() {
                    Route::Tunnel
                } else {
                    Route::Mirror(self.target_for(host))
                }
            }
        }
    }

    /// 把 `cdn-lfs.huggingface.co` + 规则(`*.huggingface.co` -> `*.hf-mirror.com`)
    /// 变成 `cdn-lfs.hf-mirror.com`
    fn target_for(&self, host: &str) -> String {
        let target = self.mirror.trim();
        if let Some(pat) = target.strip_prefix("*.") {
            let suffix = &self.host[1..]; // ".huggingface.co"
            let sub = if host.len() > suffix.len() { &host[..host.len() - suffix.len()] } else { "" };
            if sub.is_empty() {
                pat.to_string()
            } else {
                format!("{sub}.{pat}")
            }
        } else {
            target.to_string()
        }
    }
}
