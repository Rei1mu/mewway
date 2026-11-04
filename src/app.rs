//! egui 界面

use crate::config::{Fallback, Mode, ProxyMode, Settings, Site};
use crate::shared::{fmt_bytes, fmt_uptime, policy_rank, Command, ConnState, Level, Shared, Snap};
use crate::sys;
use eframe::egui;
use egui::{Color32, CornerRadius, RichText};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc::UnboundedSender;

const BG: Color32 = Color32::from_rgb(0x0f, 0x11, 0x15);
const PANEL: Color32 = Color32::from_rgb(0x15, 0x18, 0x1e);
const CARD: Color32 = Color32::from_rgb(0x1b, 0x1f, 0x26);
const HOVER: Color32 = Color32::from_rgb(0x22, 0x27, 0x30);
const LINE: Color32 = Color32::from_rgb(0x27, 0x2d, 0x37);
const EDGE: Color32 = Color32::from_rgb(0x3a, 0x43, 0x51);
const EDGE_HOVER: Color32 = Color32::from_rgb(0x5a, 0x68, 0x7d);
const TEXT: Color32 = Color32::from_rgb(0xe7, 0xea, 0xf0);
const DIM: Color32 = Color32::from_rgb(0x8a, 0x93, 0xa2);
const FAINT: Color32 = Color32::from_rgb(0x5b, 0x63, 0x70);
const ACCENT: Color32 = Color32::from_rgb(0x4d, 0x9d, 0xff);
const OK: Color32 = Color32::from_rgb(0x3d, 0xd6, 0x8c);
const WARN: Color32 = Color32::from_rgb(0xe8, 0xb3, 0x39);
const ERR: Color32 = Color32::from_rgb(0xef, 0x5b, 0x5b);

// ---- 规则页的「节点组」外观 ----
// 组头和组内域名以前长得几乎一样（同字号、同颜色、同一列起点），扫一眼分不出
// 哪行是标题哪行是规则。现在靠三层区分：整行底色条 + 左侧竖标记 + 字号字重，
// 组内域名则压暗一档并缩进。注意**不要**用 ▶ ✓ 这类符号 —— egui 自带字体没有字形。
const GROUP_BG: Color32 = Color32::from_rgb(0x22, 0x28, 0x34);
const GROUP_TEXT: Color32 = Color32::from_rgb(0xf4, 0xf7, 0xfc);
const HOST_TEXT: Color32 = Color32::from_rgb(0xb6, 0xbf, 0xcd);
/// 延迟列的固定宽度。不固定的话「—」和「1234 ms」宽度差几十像素，
/// 右边那道分隔线会随行跳动，整列看起来是歪的。
const LAT_W: f32 = 46.0;
/// 单测按钮宽度，组头的「测速」按钮要按 `LAT_W + 5 + 这个` 来定宽才能和子行对齐
const PROBE_W: f32 = 24.0;
/// 规则表格里**所有**控件的高度：策略下拉、测速、测、展开/收起、镜像输入框。
///
/// 不统一的话这一行会高高低低：egui 的 ComboBox 默认比 Button 高 4px（差在
/// `button_padding.y`），一个 22 一个 18，看着就是「没对齐」。
const CTRL_H: f32 = 18.0;

/// 连接页里的一行：同一个域名的多次连接压成一条
struct ConnRow {
    host: String,
    port: u16,
    rule: Option<String>,
    policy: String,
    lat: Option<u32>,
    up: u64,
    down: u64,
    /// 这个域名一共开了几条连接
    count: u32,
    /// 最近一条记录的 id，用来排序
    last_id: u64,
    time: String,
    state: ConnState,
    note: Option<String>,
    failed: bool,
}

struct TrayHandles {
    _icon: tray_icon::TrayIcon,
    show: tray_icon::menu::MenuItem,
    start: tray_icon::menu::MenuItem,
    stop: tray_icon::menu::MenuItem,
    quit: tray_icon::menu::MenuItem,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Tab {
    Rules,
    Conns,
    Settings,
}

impl Tab {
    const ALL: [Tab; 3] = [Tab::Rules, Tab::Conns, Tab::Settings];

    fn label(self) -> &'static str {
        match self {
            Tab::Rules => "规则",
            Tab::Conns => "连接",
            Tab::Settings => "设置",
        }
    }

    fn hint(self) -> &'static str {
        match self {
            Tab::Rules => "站点处理策略",
            Tab::Conns => "经过本程序的连接记录",
            Tab::Settings => "端口、上游代理、证书",
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum RuleSort {
    Default,
    Policy,
    Latency,
}

impl RuleSort {
    const ALL: [RuleSort; 3] = [RuleSort::Default, RuleSort::Policy, RuleSort::Latency];

    fn label(self) -> &'static str {
        match self {
            RuleSort::Default => "默认顺序",
            RuleSort::Policy => "按策略",
            RuleSort::Latency => "按延迟",
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ConnSort {
    Time,
    Policy,
    Latency,
}

impl ConnSort {
    const ALL: [ConnSort; 3] = [ConnSort::Time, ConnSort::Policy, ConnSort::Latency];

    fn label(self) -> &'static str {
        match self {
            ConnSort::Time => "按时间",
            ConnSort::Policy => "按策略",
            ConnSort::Latency => "按延迟",
        }
    }
}

pub struct App {
    cfg: Settings,
    shared: Arc<Shared>,
    tx: UnboundedSender<Command>,
    snap: Snap,
    quitting: bool,
    /// 窗口被收进托盘了（此时整帧跳过绘制，只留 1 秒一次的托盘事件轮询）
    hidden: bool,
    /// 左上角那个 logo，从 logo.ico 解出来贴到 GPU 上，只传一次
    logo: egui::TextureHandle,
    tab: Tab,
    new_host: String,
    new_mode: Mode,
    new_mirror: String,
    rule_q: String,
    rule_sort: RuleSort,
    conn_q: String,
    conn_sort: ConnSort,
    tray: Option<TrayHandles>,
    last_port: u16,
    /// 每隔几帧对一次系统代理的真实状态（用户可能在别处改过）
    sp_tick: u32,
    /// 上次读到的「配置版本号」。引擎自动把「透传」改成「中继」时会 bump 它，
    /// 界面感知到变化后重新读盘，把自动改写的结果刷回界面（规则表 / 复选框）。
    last_cfg_ver: u64,
    /// 上一帧看到的「会变的数字」。没变就别按 500ms 一帧重绘 ——
    /// 一帧要把上百个控件重新布局再 tessellate，闲着的时候这笔开销纯属白烧。
    last_sig: (u64, u64, u64, u64, usize, bool),
    /// 「还原默认规则」按了一次之后进入待确认状态，几秒内再按才真的还原。
    /// 还原会覆盖一百多条规则，误点一下代价太大。
    confirm_reset: Option<Instant>,
    /// 「全部加入规则」的两段式确认，同上。
    confirm_add_all: Option<Instant>,
    /// 新建规则配置时输入的名字，以及那一行输入框是否展开。
    profile_input: String,
    show_profile_input: bool,
}

impl App {
    pub fn new(
        cc: &eframe::CreationContext<'_>,
        cfg: Settings,
        shared: Arc<Shared>,
        tx: UnboundedSender<Command>,
        tab: &str,
        hidden: bool,
    ) -> Self {
        setup_fonts(&cc.egui_ctx);
        setup_style(&cc.egui_ctx);
        let logo = load_logo(&cc.egui_ctx);

        let last_port = cfg.port;
        let mut app = Self {
            cfg,
            shared: shared.clone(),
            tx,
            snap: Snap::default(),
            quitting: false,
            hidden,
            logo,
            tab: initial_tab(tab),
            new_host: String::new(),
            new_mode: Mode::Tunnel,
            new_mirror: String::new(),
            rule_q: String::new(),
            rule_sort: RuleSort::Default,
            conn_q: String::new(),
            conn_sort: ConnSort::Time,
            tray: None,
            last_port,
            sp_tick: 0,
            last_cfg_ver: shared.cfg_ver(),
            last_sig: (0, 0, 0, 0, 0, false),
            confirm_reset: None,
            confirm_add_all: None,
            profile_input: String::new(),
            show_profile_input: false,
        };
        app.tray = build_tray();
        if app.tray.is_none() {
            app.shared.log(Level::Warn, "系统托盘不可用，关闭窗口将直接退出程序");
        }

        // 后台检查证书状态，避免阻塞首帧
        let s = shared.clone();
        let addr = app.cfg.proxy_addr();
        let pac = sys::pac::url_for(&addr);
        std::thread::spawn(move || {
            let ok = sys::cert::installed();
            s.ca_installed.store(ok, Ordering::Relaxed);
            // 顺序不能反：先给结论再置「已检测」，否则会有一瞬间读到
            // 「检测完了但还没写结论」的中间态
            s.ca_checked.store(true, Ordering::Relaxed);
            s.sysproxy.store(sys::sysproxy::state(&addr, &pac), Ordering::Relaxed);
        });

        if app.cfg.auto_start {
            app.start();
        }
        app
    }

    /// PAC 地址（`AutoConfigURL` 用）。走 http，由本机代理的 `/pac` 提供 ——
    /// Chromium 系对 `file://` 的 PAC 支持不可靠，实测 Edge 完全不去取。
    fn pac_url(&self) -> String {
        sys::pac::url_for(&self.cfg.proxy_addr())
    }

    /// 规则变了就重写 PAC，浏览器会自动重新加载
    fn refresh_pac(&self) {
        if self.cfg.proxy_mode != ProxyMode::Pac {
            return;
        }
        if let Err(e) = sys::pac::write(&self.cfg.sites, &self.cfg.proxy_addr()) {
            self.shared.log(Level::Warn, format!("写入 PAC 失败：{e}"));
        }
    }

    /// 接管 / 还原系统代理。按 `proxy_mode` 决定用 PAC 还是全局。
    fn sys_proxy(&mut self, on: bool) {
        if on {
            self.refresh_pac();
        }
        let addr = self.cfg.proxy_addr();
        let pac = self.pac_url();
        match sys::sysproxy::apply(on, self.cfg.proxy_mode, &addr, &pac) {
            Ok(()) => {
                self.shared.sysproxy.store(on, Ordering::Relaxed);
                self.snap.sysproxy = on;
                if on {
                    let how = match self.cfg.proxy_mode {
                        ProxyMode::Pac => "PAC，只代理规则域名",
                        ProxyMode::Global => "全局",
                    };
                    self.shared.log(Level::Ok, format!("已接管系统代理（{how}）"));
                } else {
                    self.shared.log(Level::Info, "已还原系统代理设置");
                }
            }
            Err(e) => {
                // 只在「想接管却没成功」时把意向退回 false，免得下次启动继续失败。
                //
                // 「想还原却没成功」**不能**反过来写成 true：那等于把用户的
                // 「不要接管」悄悄改成「要接管」，下次启动程序就会自己去接管 ——
                // 越修越糟，而且用户完全看不出是谁改的。
                if on {
                    self.cfg.set_system_proxy = false;
                    self.shared.sysproxy.store(false, Ordering::Relaxed);
                    self.snap.sysproxy = false;
                    self.cfg.save();
                }
                self.shared.log(Level::Err, format!("设置系统代理失败：{e}"));
            }
        }
    }

    fn start(&mut self) {
        let _ = self.tx.send(Command::Start(Arc::new(self.cfg.clone())));
        if self.cfg.set_system_proxy {
            // PAC 由本机代理的 /pac 提供，必须等监听真的起来再接管，
            // 否则浏览器第一次取 PAC 会失败、直接退回直连。
            wait_port(self.cfg.port);
            self.sys_proxy(true);
        }
        self.shared.log(Level::Info, "正在启动代理…");
    }

    fn stop(&mut self) {
        let _ = self.tx.send(Command::Stop);
        if self.cfg.set_system_proxy {
            self.sys_proxy(false);
        }
    }

    fn apply(&mut self) {
        self.cfg.save();
        let _ = self.tx.send(Command::Reload(Arc::new(self.cfg.clone())));
        if self.cfg.port != self.last_port {
            self.last_port = self.cfg.port;
            if self.shared.is_running() {
                self.start();
            }
        }
        // 规则改了要重写 PAC，否则新加的域名还是不会走本程序
        if self.shared.is_running() && self.cfg.set_system_proxy {
            self.refresh_pac();
        }
    }

    /// 规则的延迟要测「真正会连的那个域名」，镜像站测镜像域名
    fn rule_target(s: &Site) -> String {
        let base = s.host.strip_prefix("*.").unwrap_or(&s.host).to_string();
        if s.mode == Mode::Mirror && !s.mirror.trim().is_empty() {
            s.mirror.trim().trim_start_matches("*.").to_string()
        } else {
            base
        }
    }

    fn probe_all(&mut self) {
        let mut items: Vec<(String, String)> = Vec::new();
        for s in &self.cfg.sites {
            // 直连也测：引擎会按「系统解析 + TCP」去量，和它实际走的路径一致，
            // 所以这一列对直连规则同样有意义（以前是跳过的，导致 Microsoft 整组测不了）
            if !s.enabled {
                continue;
            }
            items.push((s.host.clone(), Self::rule_target(s)));
        }
        if items.is_empty() {
            return;
        }
        self.shared.log(Level::Info, format!("开始测速：{} 条规则", items.len()));
        self.shared.clear_lat();
        let _ = self.tx.send(Command::Probe(items));
    }

    /// 只测一个节点组。和「全部测速」的区别只有范围 ——
    /// **不清空**全局延迟，否则测一个组会把别的组已经测出来的数字抹掉。
    fn probe_group(&mut self, name: &str, idxs: &[usize]) {
        let items: Vec<(String, String)> = idxs
            .iter()
            .filter_map(|&i| {
                let s = &self.cfg.sites[i];
                s.enabled.then(|| (s.host.clone(), Self::rule_target(s)))
            })
            .collect();
        if items.is_empty() {
            return;
        }
        self.shared
            .log(Level::Info, format!("开始测速：{name} 组 {} 个域名", items.len()));
        // 只清这一组的旧值：测速失败的条目不写新值，不清的话会一直显示上一次的数字
        self.shared.clear_lat_for(&items.iter().map(|(k, _)| k.clone()).collect::<Vec<_>>());
        let _ = self.tx.send(Command::Probe(items));
    }

    /// 只测一个域名
    fn probe_one(&mut self, key: &str, target: &str) {
        self.shared.clear_lat_for(&[key.to_string()]);
        let _ = self.tx.send(Command::Probe(vec![(key.to_string(), target.to_string())]));
    }

    /// 把规则表恢复成出厂的默认规则。
    ///
    /// **用户自己加的域名保留**（追加在末尾）—— 「还原」不该变成「删数据」，
    /// 何况那些域名往往是排查了半天才加进去的。内置的那批则完全按 `default_sites()`
    /// 重来，包括用户改过的策略。
    fn restore_defaults(&mut self) {
        let defaults = crate::config::default_sites();
        let known: std::collections::HashSet<String> = defaults.iter().map(|s| s.host.clone()).collect();
        let kept: Vec<Site> = self
            .cfg
            .sites
            .iter()
            .filter(|s| !known.contains(&s.host))
            .cloned()
            .collect();
        let n_kept = kept.len();
        self.cfg.sites = defaults;
        self.cfg.sites.extend(kept);
        self.cfg.defaults_ver = crate::config::DEFAULTS_VER;
        let total = self.cfg.sites.len();
        self.shared.log(
            Level::Info,
            format!("已还原默认规则：{total} 条（保留自定义 {n_kept} 条）"),
        );
        self.apply();
    }

    fn install_ca(&mut self) {
        let der = match crate::proxy::ca::Ca::load_or_create() {
            Ok(ca) => ca.der_path(),
            Err(e) => {
                self.shared.log(Level::Err, format!("生成证书失败：{e}"));
                return;
            }
        };
        let s = self.shared.clone();
        s.log(Level::Info, "正在安装本地 CA 到「受信任的根证书颁发机构」…");
        std::thread::spawn(move || match sys::cert::install(&der) {
            Ok(()) => {
                s.ca_installed.store(true, Ordering::Relaxed);
                s.ca_checked.store(true, Ordering::Relaxed);
                s.log(Level::Ok, "本地 CA 安装成功，镜像加速已可用");
            }
            Err(e) => s.log(Level::Err, format!("证书安装失败：{e}")),
        });
    }

    fn show_window(&mut self, ctx: &egui::Context) {
        self.hidden = false;
        ctx.send_viewport_cmd(egui::ViewportCommand::Visible(true));
        ctx.send_viewport_cmd(egui::ViewportCommand::Minimized(false));
        ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
        // 只靠上面这三条是不够的：Windows 有「前台锁定」，后台进程调 SetForegroundWindow
        // 只会让任务栏闪一下。而且 `Visible(true)` 要下一帧才真的 ShowWindow，
        // 同一时刻去抢前台时窗口还是隐藏的，会被直接忽略。所以延后一点再来一次。
        #[cfg(windows)]
        std::thread::spawn(|| {
            std::thread::sleep(std::time::Duration::from_millis(120));
            crate::sys::win::activate_main_window();
        });
        ctx.request_repaint();
    }

    fn quit(&mut self, ctx: &egui::Context) {
        self.quitting = true;
        self.cfg.save();
        let _ = self.tx.send(Command::Shutdown);
        if self.cfg.set_system_proxy {
            self.sys_proxy(false);
        }
        ctx.send_viewport_cmd(egui::ViewportCommand::Close);
    }

    fn poll_tray(&mut self, ctx: &egui::Context) {
        while let Ok(ev) = tray_icon::menu::MenuEvent::receiver().try_recv() {
            let Some(t) = &self.tray else { continue };
            if &ev.id == t.show.id() {
                self.show_window(ctx);
            } else if &ev.id == t.start.id() {
                self.start();
            } else if &ev.id == t.stop.id() {
                self.stop();
            } else if &ev.id == t.quit.id() {
                self.quit(ctx);
            }
        }
        while let Ok(ev) = tray_icon::TrayIconEvent::receiver().try_recv() {
            if let tray_icon::TrayIconEvent::Click {
                button: tray_icon::MouseButton::Left,
                button_state: tray_icon::MouseButtonState::Up,
                ..
            } = ev
            {
                self.show_window(ctx);
            }
        }
    }

    fn handle_close(&mut self, ctx: &egui::Context) {
        if ctx.input(|i| i.viewport().close_requested()) {
            if self.cfg.close_to_tray && !self.quitting && self.tray.is_some() {
                ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
                ctx.send_viewport_cmd(egui::ViewportCommand::Visible(false));
                self.hidden = true;
            } else {
                self.cfg.save();
                let _ = self.tx.send(Command::Shutdown);
                if self.cfg.set_system_proxy {
                    self.sys_proxy(false);
                }
            }
        }
    }
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.poll_tray(ctx);
        self.handle_close(ctx);

        // 窗口被收进托盘 / 最小化时，把整帧绘制全跳过。
        //
        // 之前是「不管看不看得见都每 400ms 画一遍」，后台常驻时这一笔开销白烧 ——
        // 用户要的是「挂在后台几乎不占 CPU」，而不是「挂着还每秒重绘两次」。
        // 托盘事件还是要靠 update 轮询，所以留一个 1 秒的低频唤醒。
        let minimized = ctx.input(|i| i.viewport().minimized).unwrap_or(false);
        if self.hidden || minimized {
            ctx.request_repaint_after(Duration::from_secs(1));
            return;
        }

        // 只刷计数类字段；连接 / 日志这类列表有变化才重新克隆
        self.shared.refresh(&mut self.snap, self.cfg.show_logs);

        // 引擎可能在后台改了配置（确认某域名被 SNI 阻断，把「透传」自动改成「中继」并落盘）。
        // 这里感知到版本号变化就重新读盘，把自动改写的结果同步回界面。
        let v = self.shared.cfg_ver();
        if v != self.last_cfg_ver {
            self.last_cfg_ver = v;
            self.cfg = Settings::load();
            self.shared.log(Level::Info, "规则被自动改写（透传 → 中继），已重新载入配置");
        }

        // 大约每 2 秒对一次真实状态：系统代理有没有真的指过来
        self.sp_tick = self.sp_tick.wrapping_add(1);
        if self.sp_tick % 5 == 0 {
            let real = sys::sysproxy::state(&self.cfg.proxy_addr(), &self.pac_url());
            if real != self.shared.sysproxy.load(Ordering::Relaxed) {
                self.shared.sysproxy.store(real, Ordering::Relaxed);
                self.snap.sysproxy = real;
            }
        }

        self.header(ctx);
        self.toolbar(ctx);
        self.sysproxy_banner(ctx);
        self.ca_banner(ctx);
        self.nav(ctx);
        self.log_panel(ctx);

        egui::CentralPanel::default()
            .frame(egui::Frame::new().fill(BG).inner_margin(egui::Margin::symmetric(16, 12)))
            .show(ctx, |ui| match self.tab {
                Tab::Rules => self.view_rules(ui),
                Tab::Conns => self.view_conns(ui),
                Tab::Settings => self.view_settings(ui),
            });

        // 刷新节奏跟着「这一帧有没有新东西」走。
        //
        // 原来固定 500ms 一帧：哪怕一个字节都没动，也要把上百个控件重新布局
        // 再 tessellate 一遍。实测这就是可见时那 1.25% 单核的全部来源。
        // 现在只有计数/流量真的在动时才 500ms，闲下来就降到 1.2s / 2s。
        //
        // 注意别把 uptime 放进签名里：它每秒都变，放进去等于永远算「有变化」。
        let sig = (
            self.snap.reqs,
            self.snap.down,
            self.snap.up,
            self.snap.conn_count,
            self.snap.lat.len(),
            self.snap.sysproxy,
        );
        let moving = sig != self.last_sig;
        self.last_sig = sig;
        let tick = if moving {
            500
        } else if self.snap.running {
            1200
        } else {
            2000
        };
        ctx.request_repaint_after(Duration::from_millis(tick));
    }
}

impl App {
    fn header(&mut self, ctx: &egui::Context) {
        egui::TopBottomPanel::top("header")
            .frame(egui::Frame::new().fill(PANEL).inner_margin(egui::Margin::symmetric(18, 12)))
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    let (rect, _) = ui.allocate_exact_size(egui::vec2(36.0, 36.0), egui::Sense::hover());
                    paint_logo(ui, rect, &self.logo);

                    ui.add_space(6.0);
                    ui.vertical(|ui| {
                        ui.add_space(1.0);
                        ui.label(RichText::new("Mewway").size(19.0).strong().color(TEXT));
                        ui.label(
                            RichText::new(
                                "一款为 Steam / GitHub 等受污染但未完全阻断的站点进行本地加速的代理工具",
                            )
                            .size(11.0)
                            // 一整句话用 FAINT 太暗了（对比度不到 3:1），提到 DIM；
                            // 仍然明显弱于 19px 的标题，层级没变
                            .color(DIM),
                        );
                    });

                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        let running = self.snap.running;
                        let (txt, fill) = if running { ("停止加速", ERR) } else { ("开始加速", ACCENT) };
                        if pill_button(ui, txt, fill, egui::vec2(104.0, 34.0)).clicked() {
                            if running {
                                self.stop();
                            } else {
                                self.start();
                            }
                        }
                        ui.add_space(12.0);

                        let (label, color) = if running { ("运行中", OK) } else { ("已停止", FAINT) };
                        let (rect, _) = ui.allocate_exact_size(egui::vec2(64.0, 20.0), egui::Sense::hover());
                        ui.painter().circle_filled(egui::pos2(rect.left() + 5.0, rect.center().y), 4.0, color);
                        ui.painter().text(
                            egui::pos2(rect.left() + 16.0, rect.center().y),
                            egui::Align2::LEFT_CENTER,
                            label,
                            egui::FontId::proportional(12.5),
                            color,
                        );
                    });
                });
            });
    }

    /// 工具条上的「代理范围 / 未命中规则」两个下拉。
    ///
    /// 这两个是**路由的总开关**，比端口、上游这些设置项更常改，所以从设置页提到顶部。
    /// 返回 `(有改动, 是否需要重写注册表)` —— 从 PAC 切到全局（或反过来）必须重新写一遍
    /// 系统代理设置，光 reload 引擎是不会变的。
    fn route_combos(&mut self, ui: &mut egui::Ui) -> (bool, bool) {
        // 和左边那个复选框对齐：egui 默认 ComboBox 比复选框高 4px（22 vs 18），
        // 并排放在一行里会一个顶得高、一个压得低，看着就像没对齐。
        // 压 button_padding 把下拉压到 18，和 interact_size 一致；
        // 字号、颜色也统一成复选框那一套（12.0 / DIM）。
        ui.scope(|ui| {
            ui.spacing_mut().button_padding = egui::vec2(6.0, 2.0);
            ui.spacing_mut().interact_size.y = 18.0;
            ui.spacing_mut().item_spacing.x = 6.0;

            let mut changed = false;
            let mut switch_mode = false;

            ui.label(RichText::new("代理范围").size(12.0).color(DIM));
            egui::ComboBox::from_id_salt("proxy_mode")
                .selected_text(RichText::new(self.cfg.proxy_mode.label()).size(12.0))
                .width(112.0)
                .show_ui(ui, |ui| {
                    for m in ProxyMode::ALL {
                        if ui
                            .selectable_label(self.cfg.proxy_mode == m, m.label())
                            .on_hover_text(m.hint())
                            .clicked()
                            && self.cfg.proxy_mode != m
                        {
                            self.cfg.proxy_mode = m;
                            changed = true;
                            switch_mode = true;
                        }
                    }
                })
                .response
                .on_hover_text(self.cfg.proxy_mode.hint());

            ui.add_space(8.0);
            ui.label(RichText::new("未命中").size(12.0).color(DIM));
            egui::ComboBox::from_id_salt("fallback")
                .selected_text(RichText::new(self.cfg.fallback.short()).size(12.0))
                .width(70.0)
                .show_ui(ui, |ui| {
                    for f in Fallback::ALL {
                        if ui
                            .selectable_label(self.cfg.fallback == f, f.label())
                            .on_hover_text(f.hint())
                            .clicked()
                            && self.cfg.fallback != f
                        {
                            self.cfg.fallback = f;
                            changed = true;
                        }
                    }
                })
                .response
                .on_hover_text(format!("未命中规则时的行为：{}", self.cfg.fallback.hint()));

            (changed, switch_mode)
        })
        .inner
    }

    fn toolbar(&mut self, ctx: &egui::Context) {        egui::TopBottomPanel::top("toolbar")
            .frame(egui::Frame::new().fill(BG).inner_margin(egui::Margin::symmetric(18, 8)))
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    let port = if self.snap.running && self.snap.port != 0 { self.snap.port } else { self.cfg.port };
                    let addr = format!("127.0.0.1:{port}");
                    chip(ui, "监听", &addr, if self.snap.running { ACCENT } else { FAINT });

                    ui.add_space(4.0);
                    let mut sp = self.cfg.set_system_proxy;
                    if ui.checkbox(&mut sp, RichText::new("接管系统代理").size(12.0).color(DIM)).changed() {
                        self.cfg.set_system_proxy = sp;
                        if sp && self.snap.running {
                            self.sys_proxy(true);
                        } else if !sp {
                            self.sys_proxy(false);
                        }
                        self.apply();
                    }

                    ui.add_space(4.0);
                    let (route_changed, switch_mode) = self.route_combos(ui);
                    if route_changed {
                        self.apply();
                    }
                    if switch_mode && self.snap.running && self.cfg.set_system_proxy {
                        // 从 PAC 切到全局（或反过来）必须重写注册表，
                        // 光 reload 引擎不会改变系统代理的接管方式
                        self.sys_proxy(true);
                    }

                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        // 日志面板开关。关掉它同时也省掉每帧克隆日志环的开销。
                        let mut show_logs = self.cfg.show_logs;
                        if ui
                            .selectable_label(show_logs, RichText::new("日志").size(12.0))
                            .on_hover_text("显示 / 隐藏右侧运行日志")
                            .clicked()
                        {
                            show_logs = !show_logs;
                            self.cfg.show_logs = show_logs;
                            self.cfg.save();
                        }
                        ui.add_space(8.0);

                        let up = fmt_bytes(self.snap.up);
                        let down = fmt_bytes(self.snap.down);
                        let txt = format!(
                            "运行 {}   连接 {}   请求 {}   上行 {up}   下行 {down}",
                            fmt_uptime(self.snap.uptime),
                            self.snap.conn_count,
                            self.snap.reqs
                        );
                        ui.label(RichText::new(txt).size(11.5).color(FAINT));
                    });
                });
            });
    }

    /// 代理开着、但系统代理没指过来 —— 浏览器根本不经过本程序。
    /// 这是「为什么我开了加速，网页还是打不开」最常见的原因，必须显眼。
    fn sysproxy_banner(&mut self, ctx: &egui::Context) {
        if !self.snap.running || self.snap.sysproxy {
            return;
        }
        egui::TopBottomPanel::top("sysproxy")
            .frame(egui::Frame::new().fill(Color32::from_rgb(0x2a, 0x1d, 0x1d)).inner_margin(egui::Margin::symmetric(18, 8)))
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new("未接管系统代理 —— 浏览器和其他程序不会经过 Mewway，加速对它们无效")
                            .size(12.0)
                            .color(ERR),
                    );
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui.button(RichText::new("立即接管").size(12.0)).clicked() {
                            self.cfg.set_system_proxy = true;
                            self.sys_proxy(true);
                            self.apply();
                        }
                    });
                });
            });
    }

    fn ca_banner(&mut self, ctx: &egui::Context) {
        if self.snap.ca_installed {
            return;
        }
        egui::TopBottomPanel::top("ca")
            .frame(egui::Frame::new().fill(Color32::from_rgb(0x2a, 0x23, 0x12)).inner_margin(egui::Margin::symmetric(18, 8)))
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    ui.label(RichText::new("镜像加速需要先安装本地 CA 证书（否则 HuggingFace 走隧道而非镜像）").size(12.0).color(WARN));
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui.button(RichText::new("安装证书").size(12.0)).clicked() {
                            self.install_ca();
                        }
                    });
                });
            });
    }

    fn nav(&mut self, ctx: &egui::Context) {
        egui::SidePanel::left("nav")
            .resizable(false)
            .exact_width(150.0)
            .frame(egui::Frame::new().fill(PANEL).inner_margin(egui::Margin::symmetric(10, 12)))
            .show(ctx, |ui| {
                ui.add_space(2.0);

                for t in Tab::ALL {
                    let active = self.tab == t;
                    let (rect, resp) =
                        ui.allocate_exact_size(egui::vec2(ui.available_width(), 36.0), egui::Sense::click());
                    if active {
                        ui.painter().rect_filled(rect, CornerRadius::same(8), CARD);
                        let bar = egui::Rect::from_min_size(
                            egui::pos2(rect.left() + 1.0, rect.top() + 8.0),
                            egui::vec2(3.0, rect.height() - 16.0),
                        );
                        ui.painter().rect_filled(bar, CornerRadius::same(2), ACCENT);
                    } else if resp.hovered() {
                        ui.painter().rect_filled(rect, CornerRadius::same(8), HOVER);
                    }
                    ui.painter().text(
                        egui::pos2(rect.left() + 18.0, rect.center().y),
                        egui::Align2::LEFT_CENTER,
                        t.label(),
                        egui::FontId::proportional(13.5),
                        if active { TEXT } else { DIM },
                    );
                    if resp.clicked() {
                        self.tab = t;
                    }
                    resp.on_hover_text(t.hint());
                    ui.add_space(4.0);
                }

                ui.with_layout(egui::Layout::bottom_up(egui::Align::LEFT), |ui| {
                    let (n, bad) = self.snap.cap_stats();
                    if n > 0 {
                        ui.label(RichText::new(format!("探测 {n} 个域名")).size(10.5).color(FAINT));
                        if bad > 0 {
                            ui.label(RichText::new(format!("{bad} 个走中继")).size(10.5).color(WARN));
                        }
                    }
                });
            });
    }

    fn log_panel(&mut self, ctx: &egui::Context) {
        egui::SidePanel::right("logs")
            .resizable(true)
            .default_width(300.0)
            .width_range(220.0..=520.0)
            .frame(egui::Frame::new().fill(PANEL).inner_margin(egui::Margin::symmetric(12, 10)))
            .show_animated(ctx, self.cfg.show_logs, |ui| {
                ui.horizontal(|ui| {
                    ui.label(RichText::new("运行日志").size(13.0).strong().color(TEXT));
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        ui.label(RichText::new(format!("{} 条", self.snap.logs.len())).size(11.0).color(FAINT));
                    });
                });
                ui.add_space(4.0);
                ui.separator();
                egui::ScrollArea::vertical()
                    .stick_to_bottom(true)
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        for line in &self.snap.logs {
                            let color = match line.level {
                                Level::Info => DIM,
                                Level::Ok => OK,
                                Level::Warn => WARN,
                                Level::Err => ERR,
                            };
                            ui.horizontal_wrapped(|ui| {
                                ui.spacing_mut().item_spacing.x = 6.0;
                                ui.label(RichText::new(&line.time).monospace().size(10.0).color(FAINT));
                                ui.label(RichText::new(&line.text).monospace().size(11.0).color(color));
                            });
                        }
                    });
            });
    }

    // ---------------- 规则 ----------------

    fn rule_order(&self) -> Vec<usize> {
        let q = self.rule_q.trim().to_ascii_lowercase();
        let mut v: Vec<usize> = (0..self.cfg.sites.len())
            .filter(|&i| {
                if q.is_empty() {
                    return true;
                }
                let s = &self.cfg.sites[i];
                s.host.to_ascii_lowercase().contains(&q) || s.mirror.to_ascii_lowercase().contains(&q)
            })
            .collect();

        match self.rule_sort {
            RuleSort::Default => {}
            RuleSort::Policy => v.sort_by(|&a, &b| {
                let (sa, sb) = (&self.cfg.sites[a], &self.cfg.sites[b]);
                mode_rank(sa.mode).cmp(&mode_rank(sb.mode)).then_with(|| sa.host.cmp(&sb.host))
            }),
            RuleSort::Latency => v.sort_by(|&a, &b| {
                let la = self.snap.lat_of(&self.cfg.sites[a].host);
                let lb = self.snap.lat_of(&self.cfg.sites[b].host);
                lat_cmp(la, lb).then_with(|| self.cfg.sites[a].host.cmp(&self.cfg.sites[b].host))
            }),
        }
        v
    }

    /// 画一行规则。`indent` 是组内缩进（组外的规则不缩进）。
    ///
    /// 返回 `(有改动, 要测速的 (显示键, 探测域名), 要删除)` —— 调用方负责统一收口：
    /// 改配置要一起 `apply()`，删规则要等整轮画完再删（边遍历边删会错位）。
    fn site_row(&mut self, ui: &mut egui::Ui, idx: usize, indent: f32) -> (bool, Option<(String, String)>, bool) {
        let mut changed = false;
        let mut probe: Option<(String, String)> = None;
        let mut remove = false;

        let host = self.cfg.sites[idx].host.clone();
        let lat = self.snap.lat_of(&host);
        let blocked = self.snap.cap_of(&host) == Some(false);
        let target = App::rule_target(&self.cfg.sites[idx]);
        let site = &mut self.cfg.sites[idx];

        ui.horizontal(|ui| {
            ui.spacing_mut().item_spacing.x = 8.0;
            if indent > 0.0 {
                ui.add_space(indent);
            }
            // 复选框列固定 18 宽。组头要用同样宽度占位，两边的域名列才会落在同一 x 上。
            let (check_rect, _) = ui.allocate_exact_size(egui::vec2(18.0, 18.0), egui::Sense::hover());
            if ui.put(check_rect, egui::Checkbox::without_text(&mut site.enabled)).changed() {
                changed = true;
            }

            // 域名列吃掉剩余宽度。固定宽度 + truncate，否则域名一长就把后面的列挤出面板。
            let host_w = (ui.available_width() - 430.0).max(110.0);
            // 比组名暗一档：组名是标题，域名是内容，同亮度就分不出层级了
            let color = if site.enabled { HOST_TEXT } else { FAINT };
            let host_rect = egui::Rect::from_min_size(ui.cursor().min, egui::vec2(host_w, 18.0));
            ui.scope_builder(
                egui::UiBuilder::new()
                    .max_rect(host_rect)
                    .layout(egui::Layout::left_to_right(egui::Align::Center)),
                |ui| {
                    ui.add(
                        egui::Label::new(
                            RichText::new(&site.host).monospace().size(11.5).color(color),
                        )
                        .truncate(),
                    );
                },
            );
            // scope_builder 只按**内容宽度**推进游标，必须手动占满整列，
            // 否则「策略」会被拉到域名文字右边，长短域名各占一个位置。
            ui.advance_cursor_after_rect(host_rect);

            egui::ComboBox::from_id_salt(("mode", idx))
                .selected_text(RichText::new(site.mode.label()).size(12.0))
                .width(62.0)
                .show_ui(ui, |ui| {
                    for m in Mode::ALL {
                        if ui
                            .selectable_label(site.mode == m, m.label())
                            .on_hover_text(m.hint())
                            .clicked()
                            && site.mode != m
                        {
                            site.mode = m;
                            changed = true;
                        }
                    }
                });

            // 延迟（带单测按钮）
            ui.horizontal(|ui| {
                ui.spacing_mut().item_spacing.x = 5.0;
                if blocked {
                    // 这一格只有 LAT_W 宽，长文案会把「测」按钮挤出去
                    ui.add_sized(
                        egui::vec2(LAT_W, CTRL_H),
                        egui::Label::new(RichText::new("被阻断").size(10.5).color(ERR)),
                    )
                    .on_hover_text("这个域名直连握手会被重置，已自动改走上游代理");
                } else {
                    lat_text(ui, lat);
                }
                // 用 add_sized 固定尺寸：small_button 会按剩余宽度排字，
                // 列一紧就被压成几像素的缝，连字都看不见
                if ui
                    .add_sized(
                        egui::vec2(PROBE_W, CTRL_H),
                        egui::Button::new(RichText::new("测").size(12.0).color(DIM)),
                    )
                    .on_hover_text("单独测这个域名")
                    .clicked()
                {
                    probe = Some((host.clone(), target.clone()));
                }
            });

            // 分隔：延迟 | 镜像
            ui.label(RichText::new("│").size(12.0).color(Color32::from_rgb(0x39, 0x41, 0x4f)));

            // 镜像（只对镜像策略有意义）
            if site.mode == Mode::Mirror {
                if ui
                    .add_sized(
                        egui::vec2(180.0, CTRL_H),
                        egui::TextEdit::singleline(&mut site.mirror)
                            .hint_text("镜像域名")
                            .font(egui::TextStyle::Monospace),
                    )
                    .changed()
                {
                    changed = true;
                }
            } else {
                ui.add_sized(
                    egui::vec2(180.0, CTRL_H),
                    egui::Label::new(RichText::new("—").size(11.0).color(FAINT)),
                );
            }

            if ui.small_button(RichText::new("×").size(13.0).color(FAINT)).clicked() {
                remove = true;
            }
        });

        (changed, probe, remove)
    }

    fn view_rules(&mut self, ui: &mut egui::Ui) {
        let mut changed = false;
        let mut pending: Option<(String, String)> = None;
        let order = self.rule_order();
        let shown = order.len();
        let total = self.cfg.sites.len();

        // 配置切换：下拉里改的是 self.cfg，闭包里借不到，先记下来统一处理
        let names = self.cfg.profile_names();
        let cur = self.cfg.profile_name().to_string();
        let mut switch_to: Option<String> = None;
        let mut del_profile: Option<String> = None;

        ui.horizontal(|ui| {
            ui.label(RichText::new("站点规则").size(15.0).strong().color(TEXT));
            ui.add_space(8.0);
            // 规则配置（「默认」「工作」「游戏」…）。当前生效的那套就是 cfg.sites，
            // 切换时先把它存回 profiles，再把目标那套读出来 —— 见 config::Profile。
            ui.label(RichText::new("配置").size(12.0).color(DIM));
            ui.scope(|ui| {
                // 和工具条其它控件等高：ComboBox 不走 add_sized，只能压 button_padding.y
                ui.spacing_mut().button_padding = egui::vec2(6.0, 2.0);
                ui.spacing_mut().interact_size.y = CTRL_H;
                egui::ComboBox::from_id_salt("profile")
                    .selected_text(RichText::new(cur.clone()).size(12.0))
                    .width(88.0)
                    .show_ui(ui, |ui| {
                        ui.set_min_width(150.0);
                        for n in &names {
                            if ui.selectable_label(*n == cur, n).clicked() && *n != cur {
                                switch_to = Some(n.clone());
                            }
                        }
                        ui.separator();
                        if ui.button(RichText::new("+ 新建配置…").size(12.0)).clicked() {
                            self.show_profile_input = true;
                            self.profile_input.clear();
                        }
                        for n in &names {
                            if *n == cur {
                                continue;
                            }
                            if ui
                                .button(RichText::new(format!("删除「{n}」（不可恢复）")).size(12.0))
                                .clicked()
                            {
                                del_profile = Some(n.clone());
                            }
                        }
                    });
            });
            ui.add_space(6.0);
            search_box(ui, &mut self.rule_q, "搜索域名 / 镜像", 168.0);
            ui.add_space(2.0);
            sort_combo(ui, "rule_sort", &mut self.rule_sort, &RuleSort::ALL, |v| v.label());
            ui.add_space(2.0);
            if ui.button(RichText::new("全部测速").size(12.0)).clicked() {
                self.probe_all();
            }
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                let txt = if shown == total { format!("{total} 条") } else { format!("{shown} / {total} 条") };
                ui.label(RichText::new(txt).size(11.0).color(FAINT));
            });
        });

        // 新建配置的输入行：只在点了「+ 新建配置…」之后出现，不占常驻空间
        if self.show_profile_input {
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                ui.label(RichText::new("新配置名").size(12.0).color(DIM));
                let r = ui.add(
                    egui::TextEdit::singleline(&mut self.profile_input)
                        .desired_width(160.0)
                        .hint_text("如 工作、游戏"),
                );
                let enter = r.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
                if ui.button(RichText::new("创建").size(12.0)).clicked() || enter {
                    let name = self.profile_input.trim().to_string();
                    // 以当前规则为底复制一套，不是空白 —— 116 条规则没人想从零建
                    if self.cfg.new_profile(&name) {
                        self.shared
                            .log(Level::Info, format!("已新建配置「{name}」并切换过去（复制自当前规则）"));
                        self.apply();
                        self.profile_input.clear();
                        self.show_profile_input = false;
                    } else {
                        self.shared
                            .log(Level::Warn, format!("配置名「{name}」不可用：不能为空，也不能和已有配置重名"));
                    }
                }
                if ui.button(RichText::new("取消").size(12.0)).clicked() {
                    self.show_profile_input = false;
                    self.profile_input.clear();
                }
                ui.label(RichText::new("新配置会复制当前这一整套规则").size(11.0).color(FAINT));
            });
        }

        if let Some(n) = switch_to {
            if self.cfg.switch_profile(&n) {
                self.shared.log(Level::Info, format!("已切换到配置「{n}」"));
                self.apply();
            }
        }
        if let Some(n) = del_profile {
            if self.cfg.delete_profile(&n) {
                self.shared.log(Level::Info, format!("已删除配置「{n}」"));
                self.apply();
            }
        }
        ui.add_space(2.0);
        ui.label(
            RichText::new(
                "透传 = 择优 IP 原样搬运（不碰证书）   中继 = 无 SNI 连源站（绕过 SNI 阻断）   镜像 = 改写域名到镜像站   代理 = 强制走上游   直连 = 不干预",
            )
            .size(11.0)
            .color(FAINT),
        );
        ui.add_space(8.0);

        // 添加自定义规则。**放在表格上面** —— 以前在页面最底部，
        // 要滚过一百多条规则才看得见，等于没这个功能。
        egui::Frame::new()
            .fill(PANEL)
            .corner_radius(CornerRadius::same(10))
            .inner_margin(egui::Margin::same(10))
            .show(ui, |ui| {
                ui.set_min_width(ui.available_width());
                ui.horizontal(|ui| {
                    ui.label(RichText::new("新规则").size(12.0).color(DIM));
                    ui.add(
                        egui::TextEdit::singleline(&mut self.new_host)
                            .desired_width(220.0)
                            .hint_text("域名，如 example.com 或 *.example.com"),
                    );
                    ui.scope(|ui| {
                        // 和输入框等高，别让下拉比旁边高 4px
                        ui.spacing_mut().button_padding = egui::vec2(6.0, 2.0);
                        ui.spacing_mut().interact_size.y = CTRL_H;
                        egui::ComboBox::from_id_salt("new_mode")
                            .selected_text(RichText::new(self.new_mode.label()).size(12.0))
                            .width(62.0)
                            .show_ui(ui, |ui| {
                                for m in Mode::ALL {
                                    ui.selectable_value(&mut self.new_mode, m, m.label()).on_hover_text(m.hint());
                                }
                            });
                    });
                    if self.new_mode == Mode::Mirror {
                        ui.add(
                            egui::TextEdit::singleline(&mut self.new_mirror)
                                .desired_width(150.0)
                                .hint_text("镜像域名"),
                        );
                    }
                    if ui.button(RichText::new("添加").size(12.0)).clicked() {
                        let h = self.new_host.trim().to_ascii_lowercase();
                        if h.is_empty() {
                            self.shared.log(Level::Warn, "域名不能为空");
                        } else if self.cfg.sites.iter().any(|s| s.host == h) {
                            self.shared.log(Level::Warn, format!("{h} 已经在规则里了"));
                        } else {
                            self.cfg.sites.push(Site {
                                host: h,
                                mode: self.new_mode,
                                mirror: self.new_mirror.trim().to_string(),
                                enabled: true,
                            });
                            self.new_host.clear();
                            self.new_mirror.clear();
                            changed = true;
                        }
                    }
                    ui.label(
                        RichText::new("连接页里右键域名也能加进来")
                            .size(11.0)
                            .color(FAINT),
                    );
                });
            });
        ui.add_space(8.0);

        // 按节点组归类。组只是展示上的归类（见 config::GROUPS），
        // 路由永远按每条规则自己的 mode 走 —— 所以「改整组」本质上就是批量改子项的 mode。
        let mut groups: Vec<(&'static str, Vec<usize>)> = Vec::new();
        let mut loose: Vec<usize> = Vec::new();
        for &idx in &order {
            match crate::config::group_of(&self.cfg.sites[idx].host) {
                Some(name) => {
                    if let Some(g) = groups.iter_mut().find(|(n, _)| *n == name) {
                        g.1.push(idx);
                    } else {
                        groups.push((name, vec![idx]));
                    }
                }
                None => loose.push(idx),
            }
        }
        // 固定成 GROUPS 的声明顺序，免得每次打开顺序都变
        groups.sort_by_key(|(n, _)| {
            crate::config::GROUPS.iter().position(|(g, _)| g == n).unwrap_or(usize::MAX)
        });

        egui::Frame::new()
            .fill(PANEL)
            .corner_radius(CornerRadius::same(10))
            .inner_margin(egui::Margin::same(12))
            .show(ui, |ui| {
                ui.set_min_width(ui.available_width());
                egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
                    let mut remove: Option<usize> = None;

                    // 整个表格的控件统一 18 高。**只压 button_padding.y**：
                    // 连 x 一起改会把策略下拉的宽度变掉，而列头是按 62 宽占位的，
                    // 一变列头就和数据行错开了。
                    let bp = ui.spacing().button_padding;
                    ui.spacing_mut().button_padding = egui::vec2(bp.x, 2.0);
                    ui.spacing_mut().interact_size.y = CTRL_H;

                    // 列头（列位置由固定占位决定，和数据行完全同构）
                    ui.horizontal(|ui| {
                        ui.spacing_mut().item_spacing.x = 8.0;
                        ui.add_space(18.0);
                        // 占住复选框那一列，否则整个列头会左移 18+8
                        ui.allocate_exact_size(egui::vec2(18.0, 14.0), egui::Sense::hover());
                        let host_w = (ui.available_width() - 430.0).max(110.0);
                        ui.add_sized(
                            egui::vec2(host_w, 14.0),
                            egui::Label::new(RichText::new("域名").size(11.0).color(FAINT)),
                        );
                        ui.add_sized(
                            egui::vec2(62.0, 14.0),
                            egui::Label::new(RichText::new("策略").size(11.0).color(FAINT)),
                        );
                        ui.add_sized(
                            egui::vec2(LAT_W, 14.0),
                            egui::Label::new(RichText::new("延迟").size(11.0).color(FAINT)),
                        );
                        // 跳过「测」按钮 + 分隔线，正好落到镜像列
                        ui.add_space(5.0 + PROBE_W + 8.0 + 5.0 + 8.0);
                        ui.label(RichText::new("镜像").size(11.0).color(FAINT));
                    });
                    ui.add_space(2.0);

                    for (name, idxs) in &groups {
                        let open = self.cfg.open_groups.iter().any(|g| g.as_str() == *name);
                        let mut toggle = false;
                        let mut set_mode: Option<Mode> = None;
                        let mut probe_group = false;

                        // 组内策略全一致就显示那个策略，不一致显示「混合」
                        let first = self.cfg.sites[idxs[0]].mode;
                        let common = if idxs.iter().all(|&i| self.cfg.sites[i].mode == first) {
                            Some(first)
                        } else {
                            None
                        };

                        // 底色条画在控件**之前**：painter 是立即绘制，后面的控件自然盖在上面。
                        // 用 painter 而不是 Frame，是为了完全不动这一行的布局 ——
                        // 组头的策略下拉必须和子行严格同列，任何内边距都会把它推歪。
                        let band = egui::Rect::from_min_size(
                            ui.cursor().min,
                            egui::vec2(ui.available_width(), 24.0),
                        );
                        ui.painter()
                            .rect_filled(band, egui::CornerRadius::same(6), GROUP_BG);
                        ui.painter().rect_filled(
                            egui::Rect::from_min_size(band.min + egui::vec2(4.0, 5.0), egui::vec2(3.0, 14.0)),
                            egui::CornerRadius::same(2),
                            ACCENT,
                        );

                        // 行高**必须**和底色条一样高（24），否则内容按自己那 18~20 排在条的
                        // 顶部，组名会明显偏上（实测偏高 3px）。这里用 allocate_ui_with_layout
                        // 把整行撑到 24 并让内容垂直居中，底色条的中心才是文字的中心。
                        ui.allocate_ui_with_layout(
                            egui::vec2(band.width(), 24.0),
                            egui::Layout::left_to_right(egui::Align::Center),
                            |ui| {
                            ui.spacing_mut().item_spacing.x = 8.0;
                            // 这三段和子行的「缩进 + 复选框 + 间距」一一对应，
                            // 让下面的策略下拉正好落在和子节点**同一列**上 ——
                            // 组头和组内行错位的话，眼睛要来回找两次才知道哪格是策略。
                            ui.add_space(18.0);
                            ui.allocate_exact_size(egui::vec2(18.0, 18.0), egui::Sense::hover());

                            let host_w = (ui.available_width() - 430.0).max(110.0);

                            // 组名整块可点，点名字也能展开/收起（比只认那个小按钮好找）。
                            // 高度取满 24（= 行高），文字才会落在整行的垂直中线上。
                            let name_rect =
                                egui::Rect::from_min_size(ui.cursor().min, egui::vec2(host_w, 24.0));
                            let name_resp = ui
                                .scope_builder(
                                    egui::UiBuilder::new()
                                        .max_rect(name_rect)
                                        .layout(egui::Layout::left_to_right(egui::Align::Center)),
                                    |ui| {
                                        ui.add(
                                            egui::Label::new(
                                                RichText::new(*name)
                                                    .size(13.0)
                                                    .strong()
                                                    .color(GROUP_TEXT),
                                            )
                                            .truncate()
                                            .sense(egui::Sense::click()),
                                        )
                                    },
                                )
                                .inner;
                            // 同子行：scope_builder 不占满宽度，要自己补
                            ui.advance_cursor_after_rect(name_rect);
                            if name_resp.clicked() {
                                toggle = true;
                            }
                            if name_resp.hovered() {
                                ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
                            }

                            egui::ComboBox::from_id_salt(("grp_mode", *name))
                                .selected_text(
                                    RichText::new(common.map(|m| m.label()).unwrap_or("混合")).size(11.5),
                                )
                                .width(62.0)
                                .show_ui(ui, |ui| {
                                    for m in Mode::ALL {
                                        // 镜像必须逐条填镜像域名，整组改只会得到一堆空镜像
                                        if m == Mode::Mirror {
                                            continue;
                                        }
                                        if ui
                                            .selectable_label(common == Some(m), m.label())
                                            .on_hover_text(m.hint())
                                            .clicked()
                                        {
                                            set_mode = Some(m);
                                        }
                                    }
                                    ui.separator();
                                    ui.label(
                                        RichText::new("镜像要逐条填镜像域名，不能整组改")
                                            .size(10.0)
                                            .color(FAINT),
                                    );
                                })
                                .response
                                .on_hover_text("整组一起改策略；组内单条之后仍然可以单独改");

                            // 延迟列：子行这里是「延迟 + 测」，组头换成「测速」。
                            // 宽度按 LAT_W + 5 + PROBE_W 算，右边那道分隔线才能和子行对齐。
                            if ui
                                .add_sized(
                                    egui::vec2(LAT_W + 5.0 + PROBE_W, CTRL_H),
                                    egui::Button::new(RichText::new("测速").size(12.0).color(DIM)),
                                )
                                .on_hover_text(format!("测这一组 {} 个域名的延迟", idxs.len()))
                                .clicked()
                            {
                                probe_group = true;
                            }
                            ui.label(RichText::new("│").size(12.0).color(Color32::from_rgb(0x39, 0x41, 0x4f)));

                            // 展开/收起放在子行「镜像」那一列，整行结构就同构了
                            if ui
                                .add_sized(
                                    egui::vec2(48.0, CTRL_H),
                                    egui::Button::new(
                                        RichText::new(if open { "收起" } else { "展开" }).size(12.0).color(DIM),
                                    ),
                                )
                                .clicked()
                            {
                                toggle = true;
                            }
                            ui.label(RichText::new(format!("{} 条", idxs.len())).size(10.5).color(FAINT));
                        },
                        );

                        if toggle {
                            if open {
                                self.cfg.open_groups.retain(|g| g.as_str() != *name);
                            } else {
                                self.cfg.open_groups.push((*name).to_string());
                            }
                            // 纯界面状态，直接落盘，不用惊动引擎重新加载
                            self.cfg.save();
                        }
                        if let Some(m) = set_mode {
                            for &i in idxs {
                                if self.cfg.sites[i].mode != m {
                                    self.cfg.sites[i].mode = m;
                                    changed = true;
                                }
                            }
                        }
                        if probe_group {
                            self.probe_group(name, idxs);
                        }

                        if open {
                            for &idx in idxs {
                                // 缩进 30：组名在 44，子域名在 56 往后，一眼看出是从属关系。
                                // 加大缩进**不会**把策略列推歪 —— 域名列是「剩余宽度 - 430」，
                                // 缩进吃掉多少，域名列就自动少多少，策略列落在同一个 x。
                                let (c, p, r) = self.site_row(ui, idx, 30.0);
                                changed |= c;
                                if p.is_some() {
                                    pending = p;
                                }
                                if r {
                                    remove = Some(idx);
                                }
                            }
                        }
                        ui.add_space(3.0);
                    }

                    // 没归到任何组里的（用户自己加的域名）单独列出，不折叠
                    for &idx in &loose {
                        let (c, p, r) = self.site_row(ui, idx, 0.0);
                        changed |= c;
                        if p.is_some() {
                            pending = p;
                        }
                        if r {
                            remove = Some(idx);
                        }
                    }

                    if let Some(i) = remove {
                        self.cfg.sites.remove(i);
                        changed = true;
                    }
                });
            });

        if let Some((k, t)) = pending {
            self.probe_one(&k, &t);
        }
        if changed {
            self.apply();
        }
    }

    // ---------------- 连接 ----------------

    /// 把 300 条连接记录按域名压成一行。
    ///
    /// 浏览器一条页面能开出几十条连接（静态资源、preconnect、重试），
    /// 按连接逐条列出来的结果是「github.com 出现 27 次」，根本看不出信息。
    /// 压成一行之后：最近一次的时间 / 策略 / 延迟，加上累计次数和流量。
    fn conn_rows(&self) -> Vec<ConnRow> {
        let mut rows: Vec<ConnRow> = Vec::new();
        let mut index: std::collections::HashMap<&str, usize> = std::collections::HashMap::new();
        // 记录是按时间正序的，所以后面的覆盖前面的，天然就是「最近一次」
        for c in &self.snap.conns {
            let key = c.host.as_str();
            match index.get(key) {
                Some(&i) => {
                    let r = &mut rows[i];
                    r.count += 1;
                    r.up = r.up.saturating_add(c.up);
                    r.down = r.down.saturating_add(c.down);
                    r.time = c.time.clone();
                    r.policy = c.policy.clone();
                    r.rule = c.rule.clone();
                    r.lat = c.lat.or(r.lat);
                    r.state = c.state;
                    r.failed = c.failed;
                    r.note = c.note.clone();
                }
                None => {
                    index.insert(key, rows.len());
                    rows.push(ConnRow {
                        host: c.host.clone(),
                        port: c.port,
                        rule: c.rule.clone(),
                        policy: c.policy.clone(),
                        lat: c.lat,
                        up: c.up,
                        down: c.down,
                        count: 1,
                        last_id: c.id,
                        time: c.time.clone(),
                        state: c.state,
                        note: c.note.clone(),
                        failed: c.failed,
                    });
                }
            }
        }
        rows
    }

    fn conn_order(&self, rows: &[ConnRow]) -> Vec<usize> {
        let q = self.conn_q.trim().to_ascii_lowercase();
        let mut v: Vec<usize> = (0..rows.len())
            .filter(|&i| {
                if q.is_empty() {
                    return true;
                }
                let c = &rows[i];
                c.host.to_ascii_lowercase().contains(&q)
                    || c.policy.to_ascii_lowercase().contains(&q)
                    || c.rule.as_deref().unwrap_or("").to_ascii_lowercase().contains(&q)
            })
            .collect();

        match self.conn_sort {
            ConnSort::Time => v.sort_by(|&a, &b| rows[b].last_id.cmp(&rows[a].last_id)),
            ConnSort::Policy => v.sort_by(|&a, &b| {
                policy_rank(&rows[a].policy)
                    .cmp(&policy_rank(&rows[b].policy))
                    .then_with(|| rows[b].last_id.cmp(&rows[a].last_id))
            }),
            ConnSort::Latency => {
                v.sort_by(|&a, &b| lat_cmp(rows[a].lat, rows[b].lat).then_with(|| rows[b].last_id.cmp(&rows[a].last_id)))
            }
        }
        v
    }

    fn view_conns(&mut self, ui: &mut egui::Ui) {
        let mut pending: Option<(String, String)> = None;
        // 右键「加入自定义规则」：菜单在 Grid 闭包里，改不了 self，先记下来统一处理
        let mut add_rule: Option<(String, Mode)> = None;
        // 「全部加入规则」也是两段式确认，同样先记下来
        let mut add_all: Option<Vec<String>> = None;
        let rows = self.conn_rows();
        let order = self.conn_order(&rows);
        let shown = order.len();
        let total = self.snap.conns.len();

        // 连接里**还没被任何规则覆盖**的域名。已经有的再插一条毫无意义，
        // 所以按钮上的数字是「真正会新增几条」，不是「连接有几条」。
        let missing: Vec<String> = {
            let known: std::collections::HashSet<&str> = self.cfg.sites.iter().map(|s| s.host.as_str()).collect();
            let mut set = std::collections::BTreeSet::new();
            for c in &self.snap.conns {
                let h = c.host.to_ascii_lowercase();
                if !known.contains(h.as_str()) {
                    set.insert(h);
                }
            }
            set.into_iter().collect()
        };

        ui.horizontal(|ui| {
            ui.label(RichText::new("连接").size(15.0).strong().color(TEXT));
            ui.add_space(10.0);
            search_box(ui, &mut self.conn_q, "搜索域名 / 策略 / 规则", 200.0);
            ui.add_space(2.0);
            sort_combo(ui, "conn_sort", &mut self.conn_sort, &ConnSort::ALL, |v| v.label());
            ui.add_space(2.0);
            if ui.button(RichText::new("清空").size(12.0)).clicked() {
                self.shared.clear_conns();
                self.snap.conns.clear();
            }
            ui.add_space(2.0);
            // 「全部加入规则」：连接页最常见的诉求就是「这个域名以后按 X 走」。
            // 两段式确认 + 只列未覆盖的域名，避免一次把几百个 CDN / 统计域名灌进规则表。
            if !missing.is_empty() {
                let armed = self.confirm_add_all.map_or(false, |t| t.elapsed() < Duration::from_secs(4));
                let label = if armed {
                    format!("确认加入 {} 条？", missing.len())
                } else {
                    "全部加入规则".to_string()
                };
                if ui
                    .add_sized(
                        egui::vec2(if armed { 116.0 } else { 92.0 }, CTRL_H),
                        egui::Button::new(RichText::new(label).size(12.0).color(if armed { WARN } else { TEXT })),
                    )
                    .on_hover_text("把这一页里还没被任何规则覆盖的域名加进来，策略默认「透传」")
                    .clicked()
                {
                    if armed {
                        add_all = Some(missing.clone());
                        self.confirm_add_all = None;
                    } else {
                        self.confirm_add_all = Some(Instant::now());
                    }
                }
            }
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                let txt = if shown == total {
                    format!("{total} 条")
                } else {
                    format!("{shown} 个域名 / {total} 条")
                };
                ui.label(RichText::new(txt).size(11.0).color(FAINT));
            });
        });
        ui.add_space(2.0);
        ui.label(
            RichText::new("按域名归并，同一域名只留一行　记录写入 connections.json，重启后仍在（保留最近 300 条）")
                .size(11.0)
                .color(FAINT),
        );
        // 解释「为什么看不到规则外的连接」：PAC 模式下只有命中规则的域名才会
        // 被浏览器交给本程序，其余流量直连、根本不经过这里，自然不会出现。
        if self.cfg.proxy_mode == ProxyMode::Pac {
            ui.add_space(3.0);
            ui.label(
                RichText::new("当前是 PAC 模式：只有命中规则的域名经过本程序，所以这一页看不到规则外的连接。要监控全部流量，把「系统代理 · 接管方式」改成「全部流量」")
                    .size(11.0)
                    .color(FAINT),
            );
        }
        ui.add_space(8.0);

        egui::Frame::new()
            .fill(PANEL)
            .corner_radius(CornerRadius::same(10))
            .inner_margin(egui::Margin::same(12))
            .show(ui, |ui| {
                ui.set_min_width(ui.available_width());
                if order.is_empty() {
                    ui.add_space(24.0);
                    ui.vertical_centered(|ui| {
                        ui.label(RichText::new("还没有连接记录").size(12.5).color(FAINT));
                        ui.add_space(4.0);
                        ui.label(
                            RichText::new("勾选「接管系统代理」后随便打开一个网页，这里就会有条目")
                                .size(11.0)
                                .color(FAINT),
                        );
                    });
                    ui.add_space(24.0);
                    return;
                }

                // 表格宽度是死的、内容宽度是活的：日志面板一开，右边就少 300 多像素，
                // 按固定字数截断会让最后一列（「测」按钮）被裁成几像素的缝。
                // 所以先量可用宽度，再决定域名 / 规则各留几个字、要不要显示字节数。
                let w = ui.available_width();
                let (dmax, rmax, with_bytes) = if w >= 720.0 {
                    (32, 20, true)
                } else if w >= 560.0 {
                    (24, 15, true)
                } else {
                    (16, 10, false)
                };

                egui::ScrollArea::both().auto_shrink([false, false]).show(ui, |ui| {
                    // 6 列：把「测」按钮并进最后一格。单独占一列时，
                    // 前面几列一宽它就被挤成几像素的缝，点都点不到。
                    egui::Grid::new("conns_grid").num_columns(6).spacing([9.0, 5.0]).show(ui, |ui| {
                        ui.label(RichText::new("最近").size(11.0).color(FAINT));
                        ui.label(RichText::new("域名").size(11.0).color(FAINT));
                        ui.label(RichText::new("命中规则").size(11.0).color(FAINT));
                        ui.label(RichText::new("策略").size(11.0).color(FAINT));
                        ui.label(RichText::new("延迟").size(11.0).color(FAINT));
                        ui.label(RichText::new("次数 / 流量").size(11.0).color(FAINT));
                        ui.end_row();

                        for idx in &order {
                            let c = &rows[*idx];

                            ui.horizontal(|ui| {
                                ui.spacing_mut().item_spacing.x = 5.0;
                                let dot = if c.state == ConnState::Open { OK } else { FAINT };
                                let (rect, _) = ui.allocate_exact_size(egui::vec2(6.0, 6.0), egui::Sense::hover());
                                ui.painter().circle_filled(rect.center(), 2.5, dot);
                                // 只显示时分秒；日期挂在悬停里 —— 表格列宽很紧，日期天天都是今天
                                let hms = c.time.split(' ').nth(1).unwrap_or(&c.time);
                                ui.label(RichText::new(hms).monospace().size(10.5).color(FAINT))
                                    .on_hover_text(&c.time);
                            });

                            let host = if c.port == 443 || c.port == 80 {
                                c.host.clone()
                            } else {
                                format!("{}:{}", c.host, c.port)
                            };
                            ui.horizontal(|ui| {
                                ui.spacing_mut().item_spacing.x = 4.0;
                                let resp = ui
                                    .label(
                                        RichText::new(short(&host, dmax))
                                            .monospace()
                                            .size(11.0)
                                            .color(if c.failed { ERR } else { TEXT }),
                                    )
                                    .on_hover_text(&host);
                                // 右键：把这条连接里的域名加进规则表。
                                // 用户看到某个域名走直连很慢、或者未命中被放行，最想做的就是这件事。
                                resp.context_menu(|ui| {
                                    ui.set_min_width(150.0);
                                    ui.label(RichText::new("把该域名加入规则").size(11.0).color(FAINT));
                                    ui.separator();
                                    for m in [Mode::Tunnel, Mode::Relay, Mode::Direct, Mode::Proxy] {
                                        let hit = ui.button(RichText::new(m.label()).size(12.0));
                                        if hit.on_hover_text(m.hint()).clicked() {
                                            add_rule = Some((c.host.clone(), m));
                                            ui.close();
                                        }
                                    }
                                });
                                if let Some(note) = &c.note {
                                    let (col, ch) = if c.failed { (ERR, "!") } else { (WARN, "*") };
                                    ui.label(RichText::new(ch).size(11.0).strong().color(col))
                                        .on_hover_text(note);
                                }
                            });

                            // 规则通常和域名一模一样，那种情况只打一个 ✓，别白占一整列宽度
                            match &c.rule {
                                Some(r) if r.eq_ignore_ascii_case(&c.host) => ui
                                    .label(RichText::new("同").size(11.0).color(OK))
                                    .on_hover_text(format!("命中的规则就是它自己：{r}")),
                                Some(r) => ui
                                    .label(RichText::new(short(r, rmax)).monospace().size(10.5).color(OK))
                                    .on_hover_text(r),
                                None => ui.label(RichText::new("未命中").size(11.0).color(FAINT)),
                            };

                            ui.label(RichText::new(&c.policy).size(11.5).color(policy_color(&c.policy)));

                            lat_text(ui, c.lat);

                            // 列宽有限，只写「次数」和下行；完整上下行放在悬停里
                            let traffic = if !with_bytes || c.down == 0 {
                                format!("{} 次", c.count)
                            } else {
                                format!("{} 次 · {}", c.count, fmt_bytes(c.down))
                            };
                            ui.horizontal(|ui| {
                                ui.spacing_mut().item_spacing.x = 6.0;
                                ui.label(RichText::new(traffic).monospace().size(10.5).color(FAINT))
                                    .on_hover_text(format!(
                                        "{} 次连接\n上行 {} / 下行 {}",
                                        c.count,
                                        fmt_bytes(c.up),
                                        fmt_bytes(c.down)
                                    ));
                                if ui
                                    .add_sized(
                                        egui::vec2(24.0, 16.0),
                                        egui::Button::new(RichText::new("测").size(12.0).color(DIM)),
                                    )
                                    .on_hover_text("测这个域名的延迟")
                                    .clicked()
                                {
                                    pending = Some((c.host.clone(), c.host.clone()));
                                }
                            });
                            ui.end_row();
                        }
                    });
                });
            });

        if let Some((k, t)) = pending {
            self.probe_one(&k, &t);
        }
        if let Some((h, m)) = add_rule {
            self.add_custom_rule(&h, m);
        }
        if let Some(hosts) = add_all {
            self.add_missing_rules(&hosts);
        }
    }

    /// 批量把连接页里的域名加进规则表，策略统一给「透传」。
    ///
    /// 为什么默认是透传而不是中继：透传不碰证书、支持 HTTP/2 和 WebSocket，
    /// 是唯一「加了不会把站搞坏」的策略。真的需要中继的，引擎的握手观察会自己升级。
    fn add_missing_rules(&mut self, hosts: &[String]) {
        let mut n = 0;
        for h in hosts {
            if self.cfg.sites.iter().any(|s| s.host == *h) {
                continue;
            }
            self.cfg.sites.push(Site {
                host: h.clone(),
                mode: Mode::Tunnel,
                mirror: String::new(),
                enabled: true,
            });
            n += 1;
        }
        if n > 0 {
            self.shared
                .log(Level::Info, format!("已把 {n} 个连接域名加入规则（策略：透传）"));
            self.apply();
        }
    }

    /// 从连接页把某个域名加进规则表（右键菜单）。
    ///
    /// 已经存在就**改策略**而不是报错 —— 用户右键一个「未命中」的域名，
    /// 想要的往往是「以后这个站按 X 走」，而不是「再插一条重复规则」。
    fn add_custom_rule(&mut self, host: &str, mode: Mode) {
        let h = host.trim().to_ascii_lowercase();
        if h.is_empty() {
            return;
        }
        if let Some(s) = self.cfg.sites.iter_mut().find(|s| s.host == h) {
            s.mode = mode;
            s.enabled = true;
            self.shared
                .log(Level::Info, format!("{h} 的策略改成「{}」", mode.label()));
        } else {
            self.cfg.sites.push(Site {
                host: h.clone(),
                mode,
                mirror: String::new(),
                enabled: true,
            });
            self.shared
                .log(Level::Info, format!("已加入自定义规则：{h} → {}", mode.label()));
        }
        self.apply();
    }

    // ---------------- 设置 ----------------

    fn view_settings(&mut self, ui: &mut egui::Ui) {
        egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
            ui.label(RichText::new("设置").size(15.0).strong().color(TEXT));
            ui.add_space(8.0);
            self.settings_card(ui);
            ui.add_space(12.0);
            self.tips_card(ui);
            ui.add_space(12.0);
        });
    }

    fn settings_card(&mut self, ui: &mut egui::Ui) {
        let mut changed = false;
        let mut switch_mode = false;
        egui::Frame::new()
            .fill(PANEL)
            .corner_radius(CornerRadius::same(10))
            .inner_margin(egui::Margin::same(14))
            .show(ui, |ui| {
                ui.set_min_width(ui.available_width());
                egui::Grid::new("settings_grid").num_columns(2).spacing([14.0, 10.0]).show(ui, |ui| {
                    ui.label(RichText::new("本地端口").size(12.0).color(DIM));
                    if ui.add(egui::DragValue::new(&mut self.cfg.port).range(1024..=65535).speed(1.0)).changed() {
                        changed = true;
                    }
                    ui.end_row();

                    ui.label(RichText::new("DoH 解析").size(12.0).color(DIM));
                    if ui
                        .add(
                            egui::TextEdit::singleline(&mut self.cfg.doh)
                                .desired_width(340.0)
                                .font(egui::TextStyle::Monospace),
                        )
                        .changed()
                    {
                        changed = true;
                    }
                    ui.end_row();

                    ui.label(RichText::new("上游代理").size(12.0).color(DIM));
                    if ui
                        .add(
                            egui::TextEdit::singleline(&mut self.cfg.upstream)
                                .desired_width(340.0)
                                .hint_text("该走代理的流量走这里，如 127.0.0.1:7890")
                                .font(egui::TextStyle::Monospace),
                        )
                        .changed()
                    {
                        changed = true;
                    }
                    ui.end_row();

                    // 和顶部工具条上的两个下拉是**同一份配置**，改哪边另一边都会跟着变
                    // （两处都直接读写 `self.cfg`，不存在两份状态）。
                    ui.label(RichText::new("代理范围").size(12.0).color(DIM));
                    ui.horizontal(|ui| {
                        egui::ComboBox::from_id_salt("proxy_mode_settings")
                            .selected_text(RichText::new(self.cfg.proxy_mode.label()).size(12.0))
                            .width(226.0)
                            .show_ui(ui, |ui| {
                                for m in ProxyMode::ALL {
                                    if ui.selectable_label(self.cfg.proxy_mode == m, m.label()).clicked()
                                        && self.cfg.proxy_mode != m
                                    {
                                        self.cfg.proxy_mode = m;
                                        changed = true;
                                        switch_mode = true;
                                    }
                                }
                            });
                        ui.label(RichText::new(self.cfg.proxy_mode.hint()).size(11.0).color(FAINT));
                    });
                    ui.end_row();

                    ui.label(RichText::new("未命中规则").size(12.0).color(DIM));
                    ui.horizontal(|ui| {
                        egui::ComboBox::from_id_salt("fallback_settings")
                            .selected_text(RichText::new(self.cfg.fallback.label()).size(12.0))
                            .width(226.0)
                            .show_ui(ui, |ui| {
                                for f in Fallback::ALL {
                                    if ui.selectable_label(self.cfg.fallback == f, f.label()).clicked()
                                        && self.cfg.fallback != f
                                    {
                                        self.cfg.fallback = f;
                                        changed = true;
                                    }
                                }
                            });
                        ui.label(RichText::new(self.cfg.fallback.hint()).size(11.0).color(FAINT));
                    });
                    ui.end_row();

                    ui.label(RichText::new("规则站点").size(12.0).color(DIM));
                    ui.horizontal(|ui| {
                        if ui
                            .checkbox(&mut self.cfg.rule_fallback, RichText::new("加速失败时允许自动改走上游").size(12.0))
                            .changed()
                        {
                            changed = true;
                        }
                        ui.label(
                            RichText::new(if self.cfg.rule_fallback {
                                "规则站点连不上会兜底到上游代理"
                            } else {
                                "规则说了算：连不上就报错，不会偷偷换策略"
                            })
                            .size(11.0)
                            .color(FAINT),
                        );
                    });
                    ui.end_row();

                    ui.label(RichText::new("规则表").size(12.0).color(DIM));
                    ui.horizontal(|ui| {
                        // 两段式：先按一下进入待确认，4 秒内再按才真的还原。
                        // 这一下会覆盖一百多条规则，误点的代价太大。
                        let armed = self.confirm_reset.map_or(false, |t| t.elapsed() < Duration::from_secs(4));
                        if ui
                            .add_sized(
                                egui::vec2(112.0, CTRL_H),
                                egui::Button::new(RichText::new(if armed {
                                    "确认还原？"
                                } else {
                                    "还原默认规则"
                                })
                                .size(12.0)
                                // 待确认时变红，平时用默认色 —— 用 DIM 会被当成禁用状态
                                .color(if armed { ERR } else { TEXT })),
                            )
                            .clicked()
                        {
                            if armed {
                                self.restore_defaults();
                                self.confirm_reset = None;
                            } else {
                                self.confirm_reset = Some(Instant::now());
                            }
                        }
                        ui.label(
                            RichText::new(if armed {
                                "内置规则会恢复成出厂策略，你自己加的域名保留"
                            } else {
                                "把内置规则恢复成出厂策略"
                            })
                            .size(11.0)
                            .color(FAINT),
                        );
                    });
                    ui.end_row();

                    ui.label(RichText::new("行为").size(12.0).color(DIM));
                    ui.horizontal(|ui| {
                        if ui.checkbox(&mut self.cfg.auto_start, RichText::new("启动即加速").size(12.0)).changed() {
                            changed = true;
                        }
                        if ui
                            .checkbox(&mut self.cfg.close_to_tray, RichText::new("关闭时最小化到托盘").size(12.0))
                            .changed()
                        {
                            changed = true;
                        }
                        let mut boot = sys::autostart::enabled();
                        if ui.checkbox(&mut boot, RichText::new("开机自启").size(12.0)).changed() {
                            if let Err(e) = sys::autostart::set(boot) {
                                self.shared.log(Level::Err, format!("设置开机自启失败：{e}"));
                            }
                        }
                    });
                    ui.end_row();

                    ui.label(RichText::new("系统代理").size(12.0).color(DIM));
                    ui.horizontal(|ui| {
                        if self.snap.sysproxy {
                            ui.label(RichText::new("已接管").size(12.0).color(OK));
                            ui.label(RichText::new("浏览器流量会经过本程序").size(11.0).color(FAINT));
                        } else {
                            ui.label(RichText::new("未接管").size(12.0).color(ERR));
                            ui.label(RichText::new("浏览器不会经过本程序，加速对它无效").size(11.0).color(FAINT));
                        }
                        if ui.button(RichText::new("接管").size(12.0)).clicked() {
                            self.cfg.set_system_proxy = true;
                            self.sys_proxy(true);
                            self.apply();
                        }
                        if ui.button(RichText::new("还原").size(12.0)).clicked() {
                            self.cfg.set_system_proxy = false;
                            self.sys_proxy(false);
                            self.apply();
                        }
                    });
                    ui.end_row();

                    ui.label(RichText::new("证书").size(12.0).color(DIM));
                    ui.horizontal(|ui| {
                        let state = if self.snap.ca_installed {
                            RichText::new("已安装").size(12.0).color(OK)
                        } else {
                            RichText::new("未安装").size(12.0).color(WARN)
                        };
                        ui.label(state);
                        if ui.button(RichText::new("安装").size(12.0)).clicked() {
                            self.install_ca();
                        }
                        if ui.button(RichText::new("卸载").size(12.0)).clicked() {
                            match sys::cert::uninstall() {
                                Ok(()) => {
                                    self.shared.ca_installed.store(false, Ordering::Relaxed);
                                    self.shared.ca_checked.store(true, Ordering::Relaxed);
                                    self.shared.log(Level::Ok, "已移除本地 CA");
                                }
                                Err(e) => self.shared.log(Level::Err, e),
                            }
                        }
                        if ui.button(RichText::new("打开配置目录").size(12.0)).clicked() {
                            let dir = Settings::dir();
                            #[cfg(windows)]
                            let _ = std::process::Command::new("explorer").arg(dir).spawn();
                            #[cfg(not(windows))]
                            let _ = std::process::Command::new("xdg-open").arg(dir).spawn();
                        }
                    });
                    ui.end_row();
                });
            });
        if switch_mode && self.shared.is_running() && self.cfg.set_system_proxy {
            // 切换 PAC / 全局要重新写注册表，否则要等下次启动才生效
            self.sys_proxy(true);
        }
        if changed {
            self.apply();
        }
    }

    fn tips_card(&mut self, ui: &mut egui::Ui) {
        let addr = self.cfg.proxy_addr();
        egui::Frame::new()
            .fill(PANEL)
            .corner_radius(CornerRadius::same(10))
            .inner_margin(egui::Margin::same(14))
            .show(ui, |ui| {
                ui.set_min_width(ui.available_width());
                ui.label(RichText::new("怎么用").size(13.0).strong().color(TEXT));
                ui.add_space(6.0);
                let rows: [(&str, String); 4] = [
                    ("浏览器", format!("勾选上方「接管系统代理」后直接访问；也可手动把代理设为 {addr}")),
                    ("Git", format!("git config --global http.proxy http://{addr}")),
                    ("命令行", format!("curl -x http://{addr} https://api.github.com")),
                    ("HuggingFace", "先装本地 CA 镜像才生效；或直接 set HF_ENDPOINT=https://hf-mirror.com".to_string()),
                ];
                for (k, v) in rows {
                    ui.horizontal(|ui| {
                        ui.allocate_ui_with_layout(
                            egui::vec2(84.0, 16.0),
                            egui::Layout::left_to_right(egui::Align::Center),
                            |ui| {
                                ui.label(RichText::new(k).size(11.5).color(FAINT));
                            },
                        );
                        ui.label(RichText::new(v).monospace().size(11.5).color(DIM));
                    });
                }
                if self.cfg.set_system_proxy && self.cfg.upstream.trim().is_empty() {
                    ui.add_space(4.0);
                    ui.label(
                        RichText::new("注意：已接管系统代理但没填上游代理 —— 未命中规则的流量会自己加速直连，你原来的代理不会生效")
                            .size(11.5)
                            .color(WARN),
                    );
                }
                if self.cfg.fallback == Fallback::Auto {
                    ui.add_space(2.0);
                    let (n, bad) = self.snap.cap_stats();
                    let txt = if n == 0 {
                        "智能模式：未命中规则的域名会先试加速，握手失败自动改走上游代理".to_string()
                    } else {
                        format!("智能模式：已探测 {n} 个域名，其中 {bad} 个需要中继")
                    };
                    ui.label(RichText::new(txt).size(11.5).color(FAINT));
                }
            });
    }
}

// ---------------- 小工具 ----------------

/// 启动页：`--tab conns` / `--tab settings`
fn initial_tab(arg: &str) -> Tab {
    match arg.trim().to_ascii_lowercase().as_str() {
        "conns" | "connections" | "连接" => Tab::Conns,
        "settings" | "setting" | "设置" => Tab::Settings,
        _ => Tab::Rules,
    }
}

fn mode_rank(m: Mode) -> u8 {
    match m {
        Mode::Direct => 0,
        Mode::Auto => 1,
        Mode::Tunnel => 2,
        Mode::Relay => 3,
        Mode::Mirror => 4,
        Mode::Proxy => 5,
    }
}

/// 有延迟的排前面（升序），没测过的排最后
/// 太长的域名截断，完整值挂在悬停里 —— 表格列宽有限，长域名会把后面的列顶出屏幕
fn short(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    let head: String = s.chars().take(max.saturating_sub(1)).collect();
    format!("{head}…")
}

fn lat_cmp(a: Option<u32>, b: Option<u32>) -> std::cmp::Ordering {
    match (a, b) {
        (Some(x), Some(y)) => x.cmp(&y),
        (Some(_), None) => std::cmp::Ordering::Less,
        (None, Some(_)) => std::cmp::Ordering::Greater,
        (None, None) => std::cmp::Ordering::Equal,
    }
}

/// 等本地端口开始监听（最多约 1.5 秒）
pub fn wait_port(port: u16) {
    use std::net::{SocketAddr, TcpStream};
    let addr: SocketAddr = ([127, 0, 0, 1], port).into();
    for _ in 0..30 {
        if TcpStream::connect_timeout(&addr, Duration::from_millis(50)).is_ok() {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn lat_color(ms: u32) -> Color32 {
    if ms < 300 {
        OK
    } else if ms < 900 {
        WARN
    } else {
        ERR
    }
}

fn lat_text(ui: &mut egui::Ui, lat: Option<u32>) {
    // 固定宽度：不固定的话「—」和「1234 ms」宽度差几十像素，
    // 右边那道分隔线会随行跳动，整列看起来是歪的
    let (text, color) = match lat {
        Some(ms) => (format!("{ms} ms"), lat_color(ms)),
        None => ("—".to_string(), FAINT),
    };
    ui.add_sized(
        egui::vec2(LAT_W, CTRL_H),
        egui::Label::new(RichText::new(text).size(11.5).monospace().color(color)),
    );
}

fn policy_color(p: &str) -> Color32 {
    match p {
        "透传" => ACCENT,
        "中继" => Color32::from_rgb(0x4d, 0xd0, 0xc8),
        "镜像" => Color32::from_rgb(0xb0, 0x8c, 0xff),
        "代理" => WARN,
        "直连" => DIM,
        _ => DIM,
    }
}

fn search_box(ui: &mut egui::Ui, text: &mut String, hint: &str, width: f32) {
    ui.add(egui::TextEdit::singleline(text).desired_width(width).hint_text(hint));
    if !text.is_empty() && ui.small_button(RichText::new("×").size(12.0).color(FAINT)).clicked() {
        text.clear();
    }
}

fn sort_combo<T: Copy + PartialEq, const N: usize>(
    ui: &mut egui::Ui,
    id: &str,
    value: &mut T,
    all: &[T; N],
    label: impl Fn(T) -> &'static str,
) {
    egui::ComboBox::from_id_salt(id)
        .selected_text(RichText::new(label(*value)).size(12.0))
        .width(92.0)
        .show_ui(ui, |ui| {
            for v in all.iter().copied() {
                ui.selectable_value(value, v, label(v));
            }
        });
}

fn chip(ui: &mut egui::Ui, key: &str, value: &str, accent: Color32) {
    egui::Frame::new()
        .fill(CARD)
        .corner_radius(CornerRadius::same(7))
        .inner_margin(egui::Margin::symmetric(9, 4))
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.spacing_mut().item_spacing.x = 6.0;
                ui.label(RichText::new(key).size(11.0).color(FAINT));
                ui.label(RichText::new(value).monospace().size(11.5).color(accent));
            });
        });
}

fn pill_button(ui: &mut egui::Ui, text: &str, fill: Color32, size: egui::Vec2) -> egui::Response {
    let (rect, resp) = ui.allocate_exact_size(size, egui::Sense::click());
    let hovered = resp.hovered();
    let bg = if hovered { lighten(fill, 0.10) } else { fill };
    ui.painter().rect_filled(rect, CornerRadius::same(9), bg);
    ui.painter().text(
        rect.center(),
        egui::Align2::CENTER_CENTER,
        text,
        egui::FontId::proportional(13.0),
        Color32::WHITE,
    );
    if hovered {
        ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
    }
    resp
}

fn lighten(c: Color32, t: f32) -> Color32 {
    let f = |v: u8| (v as f32 + (255.0 - v as f32) * t) as u8;
    Color32::from_rgb(f(c.r()), f(c.g()), f(c.b()))
}

/// 把 logo.ico 解成纹理。只做一次，之后每帧只是贴一张图。
fn load_logo(ctx: &egui::Context) -> egui::TextureHandle {
    let (rgba, w, h) = crate::icon::rgba(128).unwrap_or((vec![0x4d, 0x9d, 0xff, 0xff], 1, 1));
    let img = egui::ColorImage::from_rgba_unmultiplied([w as usize, h as usize], &rgba);
    ctx.load_texture("logo", img, egui::TextureOptions::LINEAR)
}

fn paint_logo(ui: &mut egui::Ui, rect: egui::Rect, logo: &egui::TextureHandle) {
    let uv = egui::Rect::from_min_max(egui::pos2(0.0, 0.0), egui::pos2(1.0, 1.0));
    ui.painter().image(logo.id(), rect, uv, Color32::WHITE);
}

fn build_tray() -> Option<TrayHandles> {
    use tray_icon::menu::{Menu, MenuItem, PredefinedMenuItem};
    use tray_icon::{Icon, TrayIconBuilder};

    let menu = Menu::new();
    let show = MenuItem::new("显示主界面", true, None);
    let start = MenuItem::new("开始加速", true, None);
    let stop = MenuItem::new("停止加速", true, None);
    let quit = MenuItem::new("退出", true, None);
    menu.append_items(&[&show, &start, &stop, &PredefinedMenuItem::separator(), &quit]).ok()?;

    let (rgba, w, h) = crate::icon::rgba(32)?;
    let icon = Icon::from_rgba(rgba, w, h).ok()?;
    let tray = TrayIconBuilder::new()
        .with_menu(Box::new(menu))
        .with_tooltip("Mewway 本地加速")
        .with_icon(icon)
        .build()
        .ok()?;

    Some(TrayHandles { _icon: tray, show, start, stop, quit })
}

fn setup_fonts(ctx: &egui::Context) {
    let mut fonts = egui::FontDefinitions::default();
    let candidates = [
        "C:/Windows/Fonts/msyh.ttc",
        "C:/Windows/Fonts/msyh.ttf",
        "C:/Windows/Fonts/simhei.ttf",
        "C:/Windows/Fonts/Deng.ttf",
        "C:/Windows/Fonts/simsun.ttc",
        "/System/Library/Fonts/PingFang.ttc",
        "/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc",
    ];
    for path in candidates {
        if let Ok(bytes) = std::fs::read(path) {
            fonts
                .font_data
                .insert("cjk".to_owned(), Arc::new(egui::FontData::from_owned(bytes)));
            for family in [egui::FontFamily::Proportional, egui::FontFamily::Monospace] {
                fonts.families.entry(family).or_default().push("cjk".to_owned());
            }
            break;
        }
    }
    ctx.set_fonts(fonts);
}

fn setup_style(ctx: &egui::Context) {
    let mut style = (*ctx.style()).clone();
    style.visuals = egui::Visuals::dark();
    style.visuals.panel_fill = BG;
    style.visuals.window_fill = PANEL;
    style.visuals.extreme_bg_color = Color32::from_rgb(0x0a, 0x0c, 0x10);
    style.visuals.faint_bg_color = CARD;
    style.visuals.widgets.noninteractive.bg_fill = PANEL;
    style.visuals.widgets.noninteractive.bg_stroke = egui::Stroke::new(1.0, LINE);
    style.visuals.widgets.noninteractive.fg_stroke = egui::Stroke::new(1.0, DIM);
    style.visuals.widgets.inactive.bg_fill = CARD;
    style.visuals.widgets.inactive.weak_bg_fill = CARD;
    style.visuals.widgets.inactive.fg_stroke = egui::Stroke::new(1.0, TEXT);
    // 没勾上的复选框默认只有一圈几乎看不见的深色描边，整行看着像没有控件。
    // 给控件补一道比分隔线亮一点的边框，复选框和按钮的边界才认得出来。
    style.visuals.widgets.inactive.bg_stroke = egui::Stroke::new(1.0, EDGE);
    style.visuals.widgets.hovered.bg_stroke = egui::Stroke::new(1.0, EDGE_HOVER);
    style.visuals.widgets.active.bg_stroke = egui::Stroke::new(1.0, ACCENT);
    style.visuals.widgets.hovered.bg_fill = HOVER;
    style.visuals.widgets.hovered.weak_bg_fill = HOVER;
    style.visuals.widgets.active.bg_fill = Color32::from_rgb(0x2d, 0x34, 0x40);
    style.visuals.widgets.active.weak_bg_fill = Color32::from_rgb(0x2d, 0x34, 0x40);
    style.visuals.selection.bg_fill = Color32::from_rgb(0x1f, 0x3a, 0x5e);
    style.visuals.selection.stroke = egui::Stroke::new(1.0, ACCENT);
    style.visuals.override_text_color = Some(TEXT);
    style.spacing.item_spacing = egui::vec2(8.0, 7.0);
    style.spacing.button_padding = egui::vec2(9.0, 4.0);
    style.spacing.scroll.bar_width = 8.0;
    ctx.set_style(style);
}

