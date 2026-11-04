//! PAC 脚本：只把规则表里的域名交给本程序，其余流量直连。
//!
//! 为什么要有这个东西：如果直接把系统代理指向本程序，浏览器里**每一个**请求
//! 都要先经过我们。本程序任何一个 bug（大文件、WebSocket、HTTP/2、证书）都会
//! 变成「整个浏览器打不开网页」。PAC 把影响面收窄到规则表里的那几个域名，
//! 规则外的东西和没装本程序时完全一样。

use crate::config::{Mode, Site};
use std::path::PathBuf;

pub fn path() -> PathBuf {
    crate::config::Settings::dir().join("mewway.pac")
}

/// 给 `AutoConfigURL` 用的地址。
///
/// **必须走 http，不能用 `file://`**：Chromium 系（Chrome / Edge）读系统 PAC 时
/// 对 `file://` 的支持并不可靠，实测 Edge 完全不去取，于是所有规则域名都直接
/// 落到直连 —— 表现就是「PAC 看着配好了，浏览器还是打不开」。
/// 改成由本机代理自己提供 `/pac`，这条路是确定的。
pub fn url_for(addr: &str) -> String {
    format!("http://{addr}/pac")
}

/// 本地文件地址。
///
/// 只用来把脚本落盘给人排查，**不要拿它当 `AutoConfigURL`** —— 见 [`url_for`]。
#[allow(dead_code)]
pub fn file_url() -> String {
    let p = path().display().to_string().replace('\\', "/");
    format!("file:///{}", p.trim_start_matches('/'))
}

/// 把当前规则渲染成 PAC 脚本
pub fn render(sites: &[Site], addr: &str) -> String {
    let mut exact: Vec<String> = Vec::new();
    let mut suffix: Vec<String> = Vec::new();

    for s in sites.iter().filter(|s| s.enabled && s.mode != Mode::Direct) {
        let h = s.host.trim().trim_end_matches('.').to_ascii_lowercase();
        if h.is_empty() {
            continue;
        }
        match h.strip_prefix("*.") {
            Some(base) => {
                let base = base.to_string();
                if !suffix.contains(&base) {
                    suffix.push(base);
                }
            }
            None => {
                if !exact.contains(&h) {
                    exact.push(h);
                }
            }
        }
    }

    let js = |v: &[String]| v.iter().map(|s| format!("\"{s}\"")).collect::<Vec<_>>().join(",");

    format!(
        r#"// Mewway 自动生成，每次启动会重写，请不要手改这个文件。
// 规则表里的域名走本地代理，其余一律 DIRECT —— 规则外的网站完全不受影响。
var EXACT  = [{exact}];
var SUFFIX = [{suffix}];
// 代理不可用时退回直连：本程序挂了也不会把能开的站弄成打不开
var PROXY  = "PROXY {addr}; DIRECT";

function FindProxyForURL(url, host) {{
  var h = host.toLowerCase();
  if (isPlainHostName(h)) return "DIRECT";
  for (var i = 0; i < EXACT.length; i++) {{
    if (h === EXACT[i]) return PROXY;
  }}
  for (var j = 0; j < SUFFIX.length; j++) {{
    var s = SUFFIX[j];
    if (h === s || h.substring(h.length - s.length - 1) === "." + s) return PROXY;
  }}
  return "DIRECT";
}}
"#,
        exact = js(&exact),
        suffix = js(&suffix),
        addr = addr
    )
}

/// 写盘。规则一改就重写；同时供 `/pac` 接口读取内存里的最新版本。
pub fn write(sites: &[Site], addr: &str) -> std::io::Result<()> {
    std::fs::write(path(), render(sites, addr))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_contains_rules() {
        let sites = vec![
            Site::tunnel("github.com"),
            Site::relay("raw.githubusercontent.com"),
            Site::tunnel("*.huggingface.co"),
            Site {
                host: "example.com".into(),
                mode: Mode::Direct,
                mirror: String::new(),
                enabled: true,
            },
        ];
        let pac = render(&sites, "127.0.0.1:26501");
        assert!(pac.contains("\"github.com\""));
        assert!(pac.contains("\"raw.githubusercontent.com\""));
        assert!(pac.contains("\"huggingface.co\""));
        // 直连规则不该进 PAC，否则白白把流量引进来
        assert!(!pac.contains("\"example.com\""));
        assert!(pac.contains("PROXY 127.0.0.1:26501; DIRECT"));
    }
}
