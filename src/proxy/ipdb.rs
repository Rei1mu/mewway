//! 公开 IP 池：DNS 只给一个答案，那个 IP 被黑洞时，得自己有牌可打。
//!
//! 这是「加速」真正能比直连强的地方。直连只有系统 DNS 给的唯一 IP，
//! 那个 IP 一旦被黑洞，直连就彻底没戏；而本程序知道这些站点的公开网段，
//! 可以换个 IP 再试。FastGithub 靠的就是这一招。
//!
//! 只放**公开且长期稳定**的入口 IP，宁可少放也不要放错的 —— 候选 IP 都会真去
//! TCP 握手测一遍，连不上的自然会被淘汰，所以多放几个是安全的。

/// (域名后缀, 候选 IP)
const POOL: &[(&str, &[&str])] = &[
    (
        "github.com",
        &[
            // 顺序有意义：中继是按顺序递延尝试的，越靠前越先试。
            // 这几个是实测「无 SNI 握手能成」的入口，放在最前面。
            "4.237.22.38",
            "140.82.112.3",
            "140.82.113.3",
            "140.82.114.3",
            "140.82.116.3",
            "140.82.121.3",
            "20.27.177.113",
            "20.205.243.165",
            "20.200.245.247",
            "20.175.192.147",
            "20.205.243.166",
        ],
    ),
    (
        "githubusercontent.com",
        &["185.199.108.133", "185.199.109.133", "185.199.110.133", "185.199.111.133"],
    ),
    ("githubassets.com", &["185.199.108.154", "185.199.109.154", "185.199.110.154"]),
    ("github.io", &["185.199.108.153", "185.199.109.153", "185.199.110.153"]),
    ("crates.io", &["146.75.78.137", "146.75.118.137"]),
    (
        "steamcommunity.com",
        &[
            // Akamai 上 Steam **社区**属性的边缘。挑 IP 的判据不是「能连上」，
            // 而是「无 SNI 握手 + Host: steamcommunity.com 能拿到 200」——
            // 因为中继连源站时不发 SNI（见 relay.rs::try_tls_timeout），
            // Akamai 得靠 Host 头找回正确的属性。
            //
            // 别拿 store 那批（23.55.210.x / 23.35.102.x）来顶：它们是另一个
            // property，不共享 hostname，无 SNI 只会给 403。
            "23.56.0.142",
            "23.56.0.138",
            "23.56.0.139",
            "23.56.0.141",
        ],
    ),
    (
        // 和社区同属一个 Akamai 属性（实测带 SNI 直接 200）。
        // 单独列出来是因为 DoH 给的 23.35.102.114 在我们这儿 TCP 就不通。
        "store.steampowered.com",
        &["23.56.0.142", "23.56.0.138", "23.56.0.139", "23.56.0.141"],
    ),
];

/// 自己的解析被污染时，可以从这些「兄弟域名」借 IP。
///
/// 判据（实测出来的，不是猜的）：兄弟域名**自己解析是干净的**（DoH 没被投毒），
/// 而且「无 SNI 握手 + 本域名 Host」能拿到 200 —— 说明两者在同一个 CDN 属性下，
/// 边缘按 Host 头路由，共用同一批 IP。
///
/// 比硬编码 IP 抗过期：IP 换了，兄弟域名的解析会跟着换。
const SIBLINGS: &[(&str, &[&str])] = &[
    (
        "steamcommunity.com",
        // cdn.akamai.steamstatic.com 的 DoH 结果是干净的，而且和社区主站同属性。
        &["cdn.akamai.steamstatic.com", "steamcommunity-a.akamaihd.net"],
    ),
];

/// 该域名的备用 IP。没有登记就返回空。
pub fn candidates(host: &str) -> Vec<std::net::IpAddr> {
    let h = host.trim_end_matches('.').to_ascii_lowercase();
    for (suffix, ips) in POOL {
        if h == *suffix || h.ends_with(&format!(".{suffix}")) {
            return ips.iter().filter_map(|s| s.parse().ok()).collect();
        }
    }
    Vec::new()
}

/// 可以借 IP 的兄弟域名。没有登记就返回空。
pub fn siblings(host: &str) -> &'static [&'static str] {
    let h = host.trim_end_matches('.').to_ascii_lowercase();
    for (suffix, list) in SIBLINGS {
        if h == *suffix || h.ends_with(&format!(".{suffix}")) {
            return list;
        }
    }
    &[]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_subdomains() {
        assert!(!candidates("github.com").is_empty());
        assert!(!candidates("api.github.com").is_empty());
        assert!(!candidates("raw.githubusercontent.com").is_empty());
        assert!(!candidates("cdn.githubassets.com").is_empty());
        // 别把 notgithub.com 当成 github.com
        assert!(candidates("notgithub.com").is_empty());
        assert!(candidates("example.com").is_empty());

        // Steam 这批是按 Akamai **属性**分的，不是按域名后缀：
        // 社区和商店同属性（共用边缘 IP），api 不是（它有自己的 DoH 结果）。
        assert!(!candidates("steamcommunity.com").is_empty());
        assert!(!candidates("www.steamcommunity.com").is_empty());
        assert!(!candidates("store.steampowered.com").is_empty());
        assert!(candidates("api.steampowered.com").is_empty());
    }

    #[test]
    fn siblings_are_scoped() {
        assert!(!siblings("steamcommunity.com").is_empty());
        assert!(siblings("github.com").is_empty());
    }
}
