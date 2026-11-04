//! 配置与站点规则

use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::path::PathBuf;

/// 单个站点的处理方式
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    /// 直连：完全不做处理，按系统 DNS 走
    Direct,
    /// 旧版的「加速（自动）」。只保留是为了能读懂老配置，
    /// 加载时会迁移成「透传」，界面上再也选不到。
    Auto,
    /// 透传：DoH 解析出真实 IP，多 IP 并发测速后择优建连，TLS 原样搬运。
    /// 不碰证书、不限制协议、CPU 最低，但**拦不住 SNI 阻断**。
    Tunnel,
    /// 中继：本地 TLS 中间人后，用「不带 SNI」的 TLS 连源站再反向代理。
    /// 专门对付按 SNI 阻断的站点。需要本地 CA，只支持 HTTP/1.1。
    Relay,
    /// 镜像：本地 TLS 中间人，把 Host 改写到镜像站（需要安装本地 CA）
    Mirror,
    /// 代理：强制交给上游代理（加速注定无效的站点，比如 pixiv）
    Proxy,
}

impl Mode {
    /// 界面上能选到的策略。
    ///
    /// 五选一：直连 / 透传 / 中继 / 镜像 / 代理。
    /// 透传和中继是两条**互补**的线路，不是同一件事的两种叫法：
    /// 没被 SNI 墙拦的站用透传（不碰证书、最省 CPU），
    /// 被拦的站只能中继（本地终结 TLS，出站不带 SNI）。
    /// 引擎会在确认某个域名被 SNI 阻断时，把那条「透传」规则改成「中继」并写回配置。
    pub const ALL: [Mode; 5] = [Mode::Direct, Mode::Tunnel, Mode::Relay, Mode::Mirror, Mode::Proxy];

    pub fn label(self) -> &'static str {
        match self {
            Mode::Direct => "直连",
            Mode::Auto => "加速（自动）",
            Mode::Tunnel => "透传",
            Mode::Relay => "中继",
            Mode::Mirror => "镜像",
            Mode::Proxy => "代理",
        }
    }

    pub fn hint(self) -> &'static str {
        match self {
            Mode::Direct => "完全放行，不经过任何处理",
            Mode::Auto => "旧版策略，加载时会迁移成「透传」",
            Mode::Tunnel => "DoH 选真实 IP、多 IP 择优，TLS 原样搬运：不碰证书、最省 CPU；但被 SNI 阻断的站会连不上",
            Mode::Relay => "本地终结 TLS 后用「不带 SNI」连源站，能绕过 SNI 阻断；需要先装本地 CA，只支持 HTTP/1.1",
            Mode::Mirror => "改写到镜像站，需要先安装本地 CA",
            Mode::Proxy => "强制走上游代理，适合加速注定无效的站点",
        }
    }
}

/// 未命中规则时的默认行为
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Fallback {
    /// 直接放行
    Direct,
    /// 先试加速，不行再交给上游代理
    Auto,
}

impl Default for Fallback {
    fn default() -> Self {
        // 默认「智能」：规则外的域名先试一把加速，握手被阻断就交给上游代理。
        // 早期默认是「放行」（完全不干预），代价是规则表没覆盖到的站会一直是原样 ——
        // 用户装加速器的预期是「该快的地方快起来」，所以默认改成主动尝试。
        // 真被拖慢的站点（国内 CDN）用一条「直连」规则摘出去就行。
        Fallback::Auto
    }
}

impl Fallback {
    pub const ALL: [Fallback; 2] = [Fallback::Direct, Fallback::Auto];

    /// 下拉里展开时的完整说明
    pub fn label(self) -> &'static str {
        match self {
            Fallback::Direct => "放行（不干预）",
            Fallback::Auto => "智能（先加速，不行走代理）",
        }
    }

    /// 下拉收起时显示的两字简称 —— 工具条那一行放不下长文案
    pub fn short(self) -> &'static str {
        match self {
            Fallback::Direct => "放行",
            Fallback::Auto => "智能",
        }
    }

    pub fn hint(self) -> &'static str {
        match self {
            Fallback::Direct => "规则外的域名完全不干预：系统解析 + 直连，不 DoH、不测速、不碰上游",
            Fallback::Auto => "规则外的域名先试加速，握手被阻断就交给上游代理（没填上游则直连）",
        }
    }
}

fn yes() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Site {
    /// 域名，支持 `*.example.com` 通配
    pub host: String,
    pub mode: Mode,
    /// mode = Mirror 时生效，目标镜像域名，支持 `*.example.com`
    #[serde(default)]
    pub mirror: String,
    #[serde(default = "yes")]
    pub enabled: bool,
}

/// 一套命名的规则集（界面上叫「配置1」「配置2」）。
///
/// **当前生效的那套不在这里** —— 它就是 `Settings::sites` 本身。
/// 只维护一份真相：界面永远读写 `sites`，切换配置时才把 `sites` 存回 `profiles`。
/// 两份都存「当前」的话，很容易出现「改了规则但忘了同步」的错位。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Profile {
    pub name: String,
    pub sites: Vec<Site>,
}

impl Site {
    /// 透传：DoH 选 IP + TLS 原样搬运。默认站点几乎都用这个。
    pub fn tunnel(host: &str) -> Self {
        Self { host: host.into(), mode: Mode::Tunnel, mirror: String::new(), enabled: true }
    }
    /// 中继：本地终结 TLS + 无 SNI 出站。给已知被 SNI 阻断的站用。
    pub fn relay(host: &str) -> Self {
        Self { host: host.into(), mode: Mode::Relay, mirror: String::new(), enabled: true }
    }
    pub fn mirror(host: &str, target: &str) -> Self {
        Self { host: host.into(), mode: Mode::Mirror, mirror: target.into(), enabled: true }
    }
    pub fn proxy(host: &str) -> Self {
        Self { host: host.into(), mode: Mode::Proxy, mirror: String::new(), enabled: true }
    }
    /// 直连：显式写进规则表，表示「这个站不要动它」。
    ///
    /// 没命中规则的域名会按 `fallback` 走（`Auto` 会先试透传、握手失败再走上游）。
    /// 对微软这类国内本来就有 CDN 的服务，那套试探是负优化 —— 写一条直连规则
    /// 等于把它从兜底流程里摘出来，老老实实用系统解析直连。
    pub fn direct(host: &str) -> Self {
        Self { host: host.into(), mode: Mode::Direct, mirror: String::new(), enabled: true }
    }
}

/// 系统代理的接管方式。
///
/// 这个选择决定了「本程序出 bug 时能影响多大范围」：
/// PAC 只把规则表里的域名交进来，其余流量根本不经过本程序，所以坏也只坏那几个站；
/// 全局则一旦本程序卡住，整台机器都没网。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum ProxyMode {
    /// 只把规则表里的域名交给本程序
    Pac,
    /// 全部流量都经过本程序（默认）
    #[default]
    Global,
}

impl ProxyMode {
    pub const ALL: [ProxyMode; 2] = [ProxyMode::Pac, ProxyMode::Global];

    pub fn label(self) -> &'static str {
        match self {
            ProxyMode::Pac => "只代理规则域名",
            ProxyMode::Global => "全部流量",
        }
    }

    pub fn hint(self) -> &'static str {
        match self {
            ProxyMode::Pac => "用 PAC 精确分流，规则外的网站完全不受影响（推荐）",
            ProxyMode::Global => "所有流量都进来，配合「智能」兜底用；本程序异常时会影响全机上网",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    /// 本地代理端口
    pub port: u16,
    /// 系统代理的接管方式
    #[serde(default)]
    pub proxy_mode: ProxyMode,
    /// DoH JSON 接口，用于拿到未被污染的 IP
    pub doh: String,
    /// 上游代理（如 `127.0.0.1:7890`），留空则直连
    pub upstream: String,
    /// 程序启动即开始加速
    pub auto_start: bool,
    /// 启动/停止时自动改系统代理
    pub set_system_proxy: bool,
    /// 点关闭按钮时最小化到托盘而不是退出
    pub close_to_tray: bool,
    /// 没命中规则时怎么处理
    pub fallback: Fallback,
    /// 规则命中的站点直连失败时，是否允许自动改走上游代理。
    /// 默认关闭：规则是策略，不该被悄悄改写。开启后「加速」不通会自动兜底到上游。
    #[serde(default)]
    pub rule_fallback: bool,
    /// 右侧「运行日志」面板是否展开。
    ///
    /// 关掉它不只是视觉问题：日志面板要每帧克隆一遍日志环，常驻时纯属白烧 CPU。
    #[serde(default = "yes")]
    pub show_logs: bool,
    /// 确认某个域名被 SNI 阻断时，把那条「透传」规则自动改成「中继」并写回配置。
    ///
    /// 透传和中继是互补的两条线路：被墙拦的只能中继，没被拦的透传更省。
    /// 与其让用户自己判断哪些站被拦，不如让引擎实测一次并把结论固化下来。
    /// 关掉它就变成「只提示、不改配置」。
    #[serde(default = "yes")]
    pub auto_escalate: bool,
    /// 规则页里展开着的节点组名。
    ///
    /// 纯界面状态：分组只是展示上的归类（见 `GROUPS`），不影响路由。
    /// 默认空 = 全部收起，一进来先看到十几个组和它们各自的策略，而不是上百行域名。
    #[serde(default)]
    pub open_groups: Vec<String>,
    /// 已经同步到第几版默认规则（见 `DEFAULTS_VER`）。0 = 还没同步过。
    #[serde(default)]
    pub defaults_ver: u32,
    pub sites: Vec<Site>,
    /// 备用的规则集。当前生效的那套是 `sites` 本身，见 `Profile` 的注释。
    #[serde(default)]
    pub profiles: Vec<Profile>,
    /// 当前 `sites` 属于哪一套。空字符串 = 还没命名过，界面上显示「默认」。
    #[serde(default)]
    pub active_profile: String,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            port: 26501,
            proxy_mode: ProxyMode::Global,
            doh: "https://dns.alidns.com/resolve".into(),
            upstream: String::new(),
            auto_start: true,
            set_system_proxy: true,
            close_to_tray: true,
            fallback: Fallback::Auto,
            rule_fallback: false,
            show_logs: true,
            auto_escalate: true,
            open_groups: Vec::new(),
            defaults_ver: DEFAULTS_VER,
            sites: default_sites(),
            profiles: Vec::new(),
            active_profile: String::new(),
        }
    }
}

impl Settings {
    /// 当前配置的显示名。没命名过就叫「默认」。
    pub fn profile_name(&self) -> &str {
        if self.active_profile.is_empty() {
            "默认"
        } else {
            &self.active_profile
        }
    }

    /// 所有配置名（含当前这套），当前这套排第一。
    pub fn profile_names(&self) -> Vec<String> {
        let cur = self.profile_name().to_string();
        let mut v = vec![cur.clone()];
        for p in &self.profiles {
            if p.name != cur {
                v.push(p.name.clone());
            }
        }
        v
    }

    /// 把 `sites` 存回它所属的那一套。
    ///
    /// 切换 / 新建之前**必须**先调这个 —— 否则当前这一轮的改动会在切换的一瞬间丢掉。
    fn stash_profile(&mut self) {
        let name = self.profile_name().to_string();
        let sites = self.sites.clone();
        match self.profiles.iter_mut().find(|p| p.name == name) {
            Some(p) => p.sites = sites,
            None => self.profiles.push(Profile { name, sites }),
        }
    }

    /// 切到另一套。返回 true 表示真的换了（调用方要接着 `apply()` 让它生效）。
    pub fn switch_profile(&mut self, name: &str) -> bool {
        if name == self.profile_name() {
            return false;
        }
        let Some(target) = self.profiles.iter().find(|p| p.name == name).map(|p| p.sites.clone()) else {
            return false;
        };
        self.stash_profile();
        self.sites = target;
        self.active_profile = name.to_string();
        true
    }

    /// 以当前规则为底复制出一套新的，并切过去。
    ///
    /// 不给「空白配置」：内置规则有 116 条，从零建一套不现实，
    /// 用户想要的通常是「在这套基础上改几条」。
    pub fn new_profile(&mut self, name: &str) -> bool {
        let name = name.trim();
        if name.is_empty() || name == self.profile_name() || self.profiles.iter().any(|p| p.name == name) {
            return false;
        }
        self.stash_profile();
        let sites = self.sites.clone();
        self.profiles.push(Profile { name: name.to_string(), sites });
        self.active_profile = name.to_string();
        true
    }

    /// 删掉一套。当前这套不能删（要删先切走）。
    pub fn delete_profile(&mut self, name: &str) -> bool {
        if name == self.profile_name() {
            return false;
        }
        let before = self.profiles.len();
        self.profiles.retain(|p| p.name != name);
        self.profiles.len() != before
    }
}

/// 默认规则集的版本号。**每次往 `default_sites()` 里加规则就 +1。**
///
/// 老配置里的 `sites` 是一份快照，不会自己长出新的默认规则 —— 没有这个版本号，
/// 升级后新加的规则（比如 Microsoft 那一族）对老用户就是不存在的。
/// `load()` 看到版本号落后就补一次缺失的，然后记成当前版本，只补这一次。
pub const DEFAULTS_VER: u32 = 2;

/// 规则页的「节点组」。
///
/// 纯**展示上的归类**，不参与路由 —— 路由永远按 `sites` 里每条规则自己的 `mode` 来。
/// 这样分组可以随时改，不会牵动配置格式，也不会让「组策略」变成第二套规则来源。
///
/// 顺序就是页面上的顺序。匹配用后缀（`steamstatic.com` 能命中
/// `cdn.akamai.steamstatic.com` 和 `*.steamstatic.com`）。
pub const GROUPS: &[(&str, &[&str])] = &[
    ("GitHub", &["github.com", "githubusercontent.com", "githubassets.com", "github.io"]),
    (
        "Microsoft",
        &[
            "microsoft.com",
            "microsoftonline.com",
            "live.com",
            "office.com",
            "office365.com",
            "sharepoint.com",
            "onedrive.com",
            "visualstudio.com",
            "vscode.dev",
            "xboxlive.com",
            "xbox.com",
            "msn.com",
            "bing.com",
            "aka.ms",
            "windowsupdate.com",
        ],
    ),
    ("HuggingFace", &["huggingface.co", "hf.co", "hf-mirror.com"]),
    (
        "Steam",
        &[
            "steampowered.com",
            "steamcommunity.com",
            "steamstatic.com",
            "steamcdn-a.akamaihd.net",
            "steamcommunity-a.akamaihd.net",
            "steamstore-a.akamaihd.net",
            "steam-chat.com",
        ],
    ),
    ("Spotify", &["spotify.com", "scdn.co", "spotifycdn.com"]),
    ("Discord", &["discord.com", "discordapp.com", "discord.gg", "discord.media"]),
    ("EA / Origin", &["ea.com", "origin.com", "origin-a.akamaihd.net", "eaassets-a.akamaihd.net"]),
    ("Ubisoft", &["ubisoft.com", "ubi.com", "ubisoftconnect.com"]),
    ("Nexus / mod.io", &["nexusmods.com", "nexus-cdn.com", "mod.io"]),
    ("Docker", &["docker.io", "docker.com"]),
    (
        "包仓库",
        &["crates.io", "npmjs.org", "pypi.org", "pythonhosted.org", "proxy.golang.org", "sum.golang.org", "go.dev", "nodejs.org"],
    ),
    ("代码托管", &["gitlab.com", "bitbucket.org"]),
    ("PyTorch", &["pytorch.org"]),
    ("Pixiv", &["pixiv.net", "pximg.net"]),
];

/// `host` 属于哪个节点组。没有匹配就返回 `None`（页面上单独一行，不折叠）。
///
/// 注意这里**不用 `format!`**：规则页每帧都要对上百条规则各判一次，
/// 拼 `".{suffix}"` 会在热路径上产生上千次分配。
pub fn group_of(host: &str) -> Option<&'static str> {
    let h = host.trim().trim_start_matches("*.").trim_end_matches('.').to_ascii_lowercase();
    for (name, suffixes) in GROUPS {
        for s in *suffixes {
            if h == *s || (h.len() > s.len() && h.ends_with(s) && h.as_bytes()[h.len() - s.len() - 1] == b'.') {
                return Some(name);
            }
        }
    }
    None
}

pub fn default_sites() -> Vec<Site> {
    let mut v = Vec::new();
    fn tunnel(v: &mut Vec<Site>, hosts: &[&str]) {
        v.extend(hosts.iter().map(|h| Site::tunnel(h)));
    }
    fn relay(v: &mut Vec<Site>, hosts: &[&str]) {
        v.extend(hosts.iter().map(|h| Site::relay(h)));
    }
    fn direct(v: &mut Vec<Site>, hosts: &[&str]) {
        v.extend(hosts.iter().map(|h| Site::direct(h)));
    }

    // ---- GitHub ----
    // 实测（同一 IP、同一时刻）：github.com 带 SNI 的握手被掐，不带 SNI 立刻 200。
    // 也就是「SNI 阻断」型：ClientHello 里的域名是明文，墙看得见，纯透传怎么选 IP 都没用。
    // 所以这一族直接配成「中继」——本地终结 TLS，再用 IP 当 server_name 连源站，
    // RFC 6066 规定 IP 不产生 SNI 扩展，和 FastGithub 的做法一致。
    relay(&mut v, &[
        "github.com",
        "api.github.com",
        "codeload.github.com",
        "github.githubassets.com",
        "github.io",
        "collector.github.com",
        "alive.github.com",
    ]);
    // `*.githubusercontent.com` 这一族在国内是按 SNI 掐断的（TCP 能连上，握手被 RST），
    // 纯透传怎么选 IP 都没用，必须走「中继」——本地终结 TLS 后用无 SNI 连源站。
    relay(&mut v, &[
        "gist.github.com",
        "raw.githubusercontent.com",
        "objects.githubusercontent.com",
        "gist.githubusercontent.com",
        "avatars.githubusercontent.com",
        "camo.githubusercontent.com",
        "user-images.githubusercontent.com",
        "private-user-images.githubusercontent.com",
        "media.githubusercontent.com",
    ]);
    relay(&mut v, &["*.githubusercontent.com"]);

    // ---- Microsoft ----
    // 这一族国内基本都有 CDN、直连最快，所以配「直连」而不是加速。
    //
    // 注意直连在这里不是「什么都不做」：没命中规则的域名会按 `fallback` 走，
    // 而 `Auto` 会先 DoH 换 IP、再试透传、握手不成就丢给上游代理 —— 对国内 CDN
    // 是彻底的负优化（泛播 IP 反而更远）。写一条直连等于把它从兜底流程里摘出来，
    // 老老实实用系统解析连出去。
    //
    // edge.microsoft.com 就是典型：它本身没被墙，之前却因为落进兜底而走了上游代理。
    direct(&mut v, &[
        "*.microsoft.com",
        "*.microsoftonline.com",
        "*.live.com",
        "*.office.com",
        "*.office365.com",
        "*.sharepoint.com",
        "*.onedrive.com",
        "*.visualstudio.com",
        "*.vscode.dev",
        "*.xboxlive.com",
        "*.xbox.com",
        "*.msn.com",
        "*.bing.com",
        "*.aka.ms",
        // 系统更新流量很大，而且 BITS 根本不读系统代理，让它在兜底里试透传没有意义
        "*.windowsupdate.com",
    ]);

    // ---- HuggingFace：官方域名整体走 hf-mirror 镜像 ----
    v.push(Site::mirror("huggingface.co", "hf-mirror.com"));
    v.push(Site::mirror("hf.co", "hf-mirror.com"));
    v.push(Site::mirror("*.huggingface.co", "*.hf-mirror.com"));

    // ---- Steam（商店 / 社区 / 静态资源 CDN）----
    tunnel(&mut v, &[
        "store.steampowered.com",
        "steamcommunity.com",
        "api.steampowered.com",
        "help.steampowered.com",
        "login.steampowered.com",
        "checkout.steampowered.com",
        "steamcdn-a.akamaihd.net",
        "steamcommunity-a.akamaihd.net",
        "steamstore-a.akamaihd.net",
        "cdn.akamai.steamstatic.com",
        "cdn.cloudflare.steamstatic.com",
        "community.akamai.steamstatic.com",
        "community.cloudflare.steamstatic.com",
        "shared.akamai.steamstatic.com",
        "shared.cloudflare.steamstatic.com",
        "store.akamai.steamstatic.com",
        "store.cloudflare.steamstatic.com",
        "avatars.akamai.steamstatic.com",
        "avatars.cloudflare.steamstatic.com",
        "clan.akamai.steamstatic.com",
        "clan.cloudflare.steamstatic.com",
    ]);
    tunnel(&mut v, &["*.steamstatic.com"]);

    // ---- Spotify ----
    tunnel(&mut v, &[
        "open.spotify.com",
        "api.spotify.com",
        "accounts.spotify.com",
        "login5.spotify.com",
        "spclient.wg.spotify.com",
        "apresolve.spotify.com",
        "audio-fa.scdn.co",
        "i.scdn.co",
        "mosaic.scdn.co",
        "image-cdn-ak.spotifycdn.com",
    ]);
    tunnel(&mut v, &["*.scdn.co", "*.spotifycdn.com"]);

    // ---- EA / Origin ----
    tunnel(&mut v, &[
        "www.ea.com",
        "accounts.ea.com",
        "signin.ea.com",
        "api1.origin.com",
        "origin-a.akamaihd.net",
        "eaassets-a.akamaihd.net",
    ]);
    tunnel(&mut v, &["*.ea.com", "*.origin.com"]);

    // ---- Ubisoft / Uplay ----
    tunnel(&mut v, &["ubisoftconnect.com", "public-ubiservices.ubi.com", "static2.cdn.ubi.com", "cdn.ubi.com"]);
    tunnel(&mut v, &["*.ubisoft.com", "*.ubi.com"]);

    // ---- Nexus Mods / mod.io ----
    tunnel(&mut v, &[
        "www.nexusmods.com",
        "users.nexusmods.com",
        "api.nexusmods.com",
        "staticdelivery.nexusmods.com",
        "files.nexus-cdn.com",
        "mod.io",
        "api.mod.io",
        "cdn.mod.io",
    ]);
    tunnel(&mut v, &["*.nexusmods.com", "*.mod.io"]);

    // ---- 包仓库：crates.io / PyPI 实测全通，配直连 ----
    // 2026-11-04 实测：带 SNI 握手 3/3 全通、150ms 左右（Fastly 的国内节点）。
    // 这类站点系统解析给的就是最近的那个，走透传要多一次 DoH + 一轮并发测速，
    // 换来的还是同一个 IP —— 纯浪费，而且多开一个故障入口。
    // 实测记录见 `策略规则.md`。npm 不在此列：它是「按 IP 掐」型，见下面的 tunnel 列表。
    direct(&mut v, &[
        "crates.io",
        "static.crates.io",
        "index.crates.io",
        "pypi.org",
        "files.pythonhosted.org",
    ]);

    // ---- 其他常用 ----
    tunnel(&mut v, &[
        "discord.com",
        "discordapp.com",
        "cdn.discordapp.com",
        "gateway.discord.gg",
        "registry.npmjs.org",
        "gitlab.com",
        "bitbucket.org",
        "registry-1.docker.io",
        "production.cloudflare.docker.com",
        "download.pytorch.org",
        "pytorch.org",
        "nodejs.org",
        "go.dev",
        "proxy.golang.org",
        "sum.golang.org",
    ]);

    // ---- 加速注定无效（SNI 阻断），直接交给上游代理 ----
    // 这类站点的 IP 是通的，但 TLS 握手一定会被重置，自己加速没有任何意义。
    v.extend(["pixiv.net", "*.pixiv.net", "*.pximg.net"].iter().map(|h| Site::proxy(h)));

    v
}

impl Settings {
    /// 数据目录（配置 / CA / 连接记录 / 探测缓存都在这里）。
    ///
    /// `MEWWAY_HOME` 可以整体改掉它：便携模式、多开、以及自动化测试都要用。
    /// 没有它的时候，想用「换 APPDATA 环境变量」来隔离是**不生效**的 ——
    /// Windows 上 `dirs::config_dir()` 走的是 KnownFolder API，不看环境变量。
    pub fn dir() -> PathBuf {
        if let Ok(d) = std::env::var("MEWWAY_HOME") {
            if !d.trim().is_empty() {
                let p = PathBuf::from(d);
                let _ = std::fs::create_dir_all(&p);
                return p;
            }
        }
        let base = dirs::config_dir().unwrap_or_else(|| PathBuf::from("."));
        let d = base.join("mewway");
        let _ = std::fs::create_dir_all(&d);
        d
    }

    pub fn path() -> PathBuf {
        Self::dir().join("config.json")
    }

    pub fn load() -> Self {
        match std::fs::read_to_string(Self::path()) {
            Ok(s) => {
                // 老配置里没有 proxy_mode 字段，说明是「全局代理 + 未命中就乐观加速」那一版。
                // 那一版会把 B 站、抖音这类国内站点也拖进来加速，必须一次性迁移到保守默认值。
                let legacy = !s.contains("\"proxy_mode\"");
                let mut cfg: Self = serde_json::from_str(&s).unwrap_or_else(|e| {
                    eprintln!("配置文件解析失败({e})，使用默认配置");
                    Self::default()
                });
                if legacy {
                    cfg.fallback = Fallback::Direct;
                    cfg.proxy_mode = ProxyMode::Pac;
                    cfg.save();
                }
                // 老配置里的「加速（自动）」现在拆成了「透传」和「中继」两条独立策略。
                // 迁移时查默认规则表：默认就配成「中继」的（github 这类 SNI 阻断型）
                // 直接给「中继」，其余给「透传」—— 这样老配置升级后第一次访问就是通的，
                // 不用先失败一次、再等预热探测把它自动升级成中继。
                let defaults = default_sites();
                let def_mode: std::collections::HashMap<&str, Mode> =
                    defaults.iter().map(|s| (s.host.as_str(), s.mode)).collect();
                let mut merged = false;
                for s in cfg.sites.iter_mut() {
                    if s.mode == Mode::Auto {
                        s.mode = match def_mode.get(s.host.as_str()) {
                            Some(Mode::Relay) => Mode::Relay,
                            _ => Mode::Tunnel,
                        };
                        merged = true;
                    }
                }
                if merged {
                    cfg.save();
                }

                // 默认规则集升级：把这一版新增的规则补进老配置。
                // 只按版本号补一次 —— 否则用户手动删掉的规则每次启动都会复活。
                if cfg.defaults_ver < DEFAULTS_VER {
                    for d in default_sites() {
                        if !cfg.sites.iter().any(|s| s.host.eq_ignore_ascii_case(&d.host)) {
                            cfg.sites.push(d);
                        }
                    }
                    cfg.defaults_ver = DEFAULTS_VER;
                    cfg.save();
                }
                cfg
            }
            Err(_) => {
                let s = Self::default();
                s.save();
                s
            }
        }
    }

    pub fn save(&self) {
        if let Ok(s) = serde_json::to_string_pretty(self) {
            let _ = std::fs::write(Self::path(), s);
        }
    }

    /// 解析上游代理地址
    pub fn upstream_addr(&self) -> Option<SocketAddr> {
        let raw = self.upstream.trim();
        if raw.is_empty() {
            return None;
        }
        let raw = raw
            .trim_start_matches("http://")
            .trim_start_matches("https://")
            .trim_start_matches("socks5://")
            .trim_start_matches("socks5h://")
            .trim_end_matches('/');
        if let Ok(a) = raw.parse::<SocketAddr>() {
            return Some(a);
        }
        let host = raw.rsplit_once(':').map(|(h, _)| h).unwrap_or(raw);
        let port = raw.rsplit_once(':').and_then(|(_, p)| p.parse::<u16>().ok()).unwrap_or(7890);
        use std::net::ToSocketAddrs;
        (host, port).to_socket_addrs().ok()?.next()
    }

    pub fn proxy_addr(&self) -> String {
        format!("127.0.0.1:{}", self.port)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn site_mode_roundtrip() {
        let raw = r#"{"host":"huggingface.co","mode":"mirror","mirror":"hf-mirror.com","enabled":true}"#;
        let site: Site = serde_json::from_str(raw).unwrap();
        assert_eq!(site.mode, Mode::Mirror, "解析 mirror 失败");
        let back = serde_json::to_string(&site).unwrap();
        assert_eq!(back, raw, "回写不一致");
    }

    #[test]
    fn settings_default_parses() {
        let s = Settings::default();
        let json = serde_json::to_string(&s).unwrap();
        let back: Settings = serde_json::from_str(&json).unwrap();
        assert_eq!(back.sites.len(), s.sites.len());
        assert!(back.sites.iter().any(|x| x.mode == Mode::Mirror));
        // 默认值也是产品决策，锁死它，免得哪天顺手改回去没人发现
        assert_eq!(s.proxy_mode, ProxyMode::Global, "默认代理范围");
        assert_eq!(s.fallback, Fallback::Auto, "默认未命中规则");
    }

    /// 每个设置项存进 json 再读回来都必须还是原值。
    ///
    /// 这是「设置页改了、重启就丢」这类问题的唯一守门人：
    /// 少一个 `serde` 字段、或者序列化名字对不上，用户看到的就是「选项没持久化」。
    #[test]
    fn settings_roundtrip_keeps_every_field() {
        let mut s = Settings::default();
        s.port = 12345;
        s.proxy_mode = ProxyMode::Global;
        s.doh = "https://example.com/resolve".into();
        s.upstream = "127.0.0.1:7890".into();
        s.auto_start = false;
        s.set_system_proxy = false;
        s.close_to_tray = false;
        s.fallback = Fallback::Auto;
        s.rule_fallback = true;
        s.show_logs = false;
        s.auto_escalate = false;
        s.open_groups = vec!["Steam".into(), "GitHub".into()];

        let json = serde_json::to_string_pretty(&s).unwrap();
        let back: Settings = serde_json::from_str(&json).unwrap();

        assert_eq!(back.port, 12345, "端口");
        assert_eq!(back.proxy_mode, ProxyMode::Global, "代理范围");
        assert_eq!(back.doh, "https://example.com/resolve", "DoH");
        assert_eq!(back.upstream, "127.0.0.1:7890", "上游代理");
        assert!(!back.auto_start, "启动即加速");
        assert!(!back.set_system_proxy, "接管系统代理");
        assert!(!back.close_to_tray, "关闭最小化到托盘");
        assert_eq!(back.fallback, Fallback::Auto, "未命中规则");
        assert!(back.rule_fallback, "规则站点兜底");
        assert!(!back.show_logs, "日志面板");
        assert!(!back.auto_escalate, "自动升级策略");
        assert_eq!(back.open_groups, vec!["Steam".to_string(), "GitHub".to_string()], "展开的节点组");
    }

    /// 每条默认规则都得有归属 —— 否则规则页里会冒出一堆散落在组外面的行，
    /// 「按节点组收起来」就不成立了。
    #[test]
    fn groups_cover_all_default_sites() {
        let sites = default_sites();
        let orphan: Vec<&str> = sites
            .iter()
            .map(|s| s.host.as_str())
            .filter(|h| group_of(h).is_none())
            .collect();
        assert!(orphan.is_empty(), "这些默认规则没归到任何节点组：{orphan:?}");
    }

    /// `edge.microsoft.com` 必须命中「直连」规则，而不是掉进 fallback。
    ///
    /// 这正是用户看到的现象：规则表里没有 microsoft，它就走了 `fallback=Auto`
    /// （DoH 换 IP → 试透传 → 握手失败丢给上游代理），一个国内直连很快的域名
    /// 被绕到了代理上。
    #[test]
    fn microsoft_edge_resolves_to_direct_rule() {
        use crate::proxy::rules::{decide, Route};
        let sites = default_sites();
        let d = decide(&sites, "edge.microsoft.com");
        assert!(matches!(d.route, Route::Direct), "edge.microsoft.com 应该直连，实际是 {:?}", d.route);
        assert_eq!(d.rule.as_deref(), Some("*.microsoft.com"), "命中的规则");
        assert_eq!(group_of("edge.microsoft.com"), Some("Microsoft"), "节点组归属");
        // 微软登录 / OneDrive 这些也一并覆盖
        assert!(matches!(decide(&sites, "login.microsoftonline.com").route, Route::Direct));
        assert!(matches!(decide(&sites, "onedrive.live.com").route, Route::Direct));
    }

    #[test]
    fn group_matches_wildcard_and_subdomain() {
        assert_eq!(group_of("*.steamstatic.com"), Some("Steam"));
        assert_eq!(group_of("cdn.akamai.steamstatic.com"), Some("Steam"));
        assert_eq!(group_of("store.steampowered.com"), Some("Steam"));
        assert_eq!(group_of("api.github.com"), Some("GitHub"));
        assert_eq!(group_of("*.githubusercontent.com"), Some("GitHub"));
        assert_eq!(group_of("*.pximg.net"), Some("Pixiv"));
        // 别把 notgithub.com 当成 github
        assert_eq!(group_of("notgithub.com"), None);
        assert_eq!(group_of("example.com"), None);
    }
}

#[cfg(test)]
mod dump {
    use super::*;

    /// 手动跑：cargo test dump_default -- --ignored --nocapture
    #[test]
    #[ignore]
    fn dump_default() {
        println!("---BEGIN---");
        println!("{}", serde_json::to_string_pretty(&Settings::default()).unwrap());
        println!("---END---");
    }
}
