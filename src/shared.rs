//! 进程内共享状态：GUI 与代理内核之间唯一的通信面

use crate::config::Settings;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, VecDeque};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    Info,
    Ok,
    Warn,
    Err,
}

#[derive(Debug, Clone)]
pub struct LogLine {
    pub time: String,
    pub level: Level,
    pub text: String,
}

pub enum Command {
    Start(Arc<Settings>),
    Reload(Arc<Settings>),
    Stop,
    /// 对一批域名做延迟探测：(显示用的键, 实际探测的域名)
    Probe(Vec<(String, String)>),
    /// 确认这个域名被 SNI 阻断：请把对应的「透传」规则改成「中继」并写回配置。
    /// 由引擎（配置的唯一写入方）处理，避免和界面抢着写 config.json。
    Escalate(String),
    Shutdown,
}

const MAX_LOG: usize = 500;
const MAX_CONN: usize = 400;
const KEEP_CONN: usize = 300;
/// 列表类快照最快多久刷一次。
///
/// 连接 / 日志是带 String 的大对象，300 条全量克隆一次就是几万个字节的分配。
/// 而每建一条连接都会 bump 版本号 —— 一个页面几十条连接，界面就被逼着每帧重克隆。
/// 5Hz 已经比人眼快得多，计数类字段（流量、请求数）仍然每帧都是最新的。
const SNAP_MIN_GAP: Duration = Duration::from_millis(200);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ConnState {
    Open,
    Closed,
}

fn open_state() -> ConnState {
    ConnState::Open
}

/// 一条连接记录。会写进 `%APPDATA%\mewway\connections.json`，重启后还在。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Conn {
    pub id: u64,
    /// unix 秒，排序用
    pub at: i64,
    /// 展示用的本地时间
    pub time: String,
    pub host: String,
    pub port: u16,
    /// 命中的规则（`None` = 没命中任何规则）
    #[serde(default)]
    pub rule: Option<String>,
    /// 展示用策略名：透传 / 中继 / 镜像 / 代理 / 直连
    pub policy: String,
    /// 建连耗时（毫秒）
    #[serde(default)]
    pub lat: Option<u32>,
    #[serde(default)]
    pub up: u64,
    #[serde(default)]
    pub down: u64,
    #[serde(default = "open_state")]
    pub state: ConnState,
    /// 降级 / 失败的原因，正常连接为 `None`
    #[serde(default)]
    pub note: Option<String>,
    /// 这条连接最终没建成
    #[serde(default)]
    pub failed: bool,
}

/// 策略排序用的权重：透传 -> 中继 -> 镜像 -> 代理 -> 直连
pub fn policy_rank(p: &str) -> u8 {
    match p {
        "透传" => 1,
        "中继" => 2,
        "镜像" => 3,
        "代理" => 4,
        "直连" => 5,
        _ => 9,
    }
}

pub struct Shared {
    pub running: AtomicBool,
    pub port: AtomicU64,
    pub conn_count: AtomicU64,
    pub reqs: AtomicU64,
    pub up: AtomicU64,
    pub down: AtomicU64,
    pub ca_installed: AtomicBool,
    /// CA 检测跑完了没有。
    ///
    /// 这个标志是为了一个具体的坑：`cert::installed()` 要起一个 `certutil` 进程，
    /// 几百毫秒才回来。检测没回来之前如果按 `ca_installed == false` 处理，
    /// 中继 / 镜像规则会被「降级」成走上游代理 —— 也就是刚启动那一下，
    /// 规则里的站点被塞给了用户的 Clash。用户那边代理正好是直连模式的话，
    /// 表现就是「刚开程序，浏览器打不开 github」。
    /// 所以：没检测完 = 按规则来；检测完且确实没装，才降级。
    pub ca_checked: AtomicBool,
    pub sysproxy: AtomicBool,
    /// 配置文件版本号。
    ///
    /// 引擎可能自己改规则（确认某域名被 SNI 阻断后，把「透传」改成「中继」并落盘）。
    /// 改完 +1，界面每帧比一下，变了就重新读一遍 config.json 把界面刷新过来。
    /// 界面自己是配置的另一个写入方，所以改配置这件事必须由引擎统一来。
    pub cfg_ver: AtomicU64,
    /// 无界面模式下把日志同时打到控制台
    pub console: AtomicBool,
    started_at: Mutex<Option<Instant>>,
    lat: Mutex<BTreeMap<String, u32>>,
    /// 加速可用性：true = 能加速，false = 必须走代理
    caps: Mutex<BTreeMap<String, bool>>,
    logs: Mutex<VecDeque<LogLine>>,
    conn_seq: AtomicU64,
    conn_list: Mutex<VecDeque<Conn>>,
    conn_dirty: AtomicBool,
    /// 「界面该重新取一次快照了」的版本号。
    ///
    /// 界面每帧都要画，但连接/日志/测速表这些东西可能几秒才变一次。
    /// 每帧全量克隆 300 条连接 + 日志环，是常驻时最没意义的一笔 CPU 开销。
    ver: AtomicU64,
    /// 上次真正克隆列表的时刻（给 SNAP_MIN_GAP 限流用）
    last_snap: Mutex<Option<Instant>>,
}

impl Shared {
    pub fn new() -> Self {
        let s = Self {
            running: AtomicBool::new(false),
            port: AtomicU64::new(0),
            conn_count: AtomicU64::new(0),
            reqs: AtomicU64::new(0),
            up: AtomicU64::new(0),
            down: AtomicU64::new(0),
            ca_installed: AtomicBool::new(false),
            ca_checked: AtomicBool::new(false),
            sysproxy: AtomicBool::new(false),
            cfg_ver: AtomicU64::new(0),
            console: AtomicBool::new(false),
            started_at: Mutex::new(None),
            lat: Mutex::new(BTreeMap::new()),
            caps: Mutex::new(BTreeMap::new()),
            logs: Mutex::new(VecDeque::new()),
            conn_seq: AtomicU64::new(0),
            conn_list: Mutex::new(VecDeque::new()),
            conn_dirty: AtomicBool::new(false),
            ver: AtomicU64::new(0),
            last_snap: Mutex::new(None),
        };
        s.load_conns();
        s
    }

    pub fn log(&self, level: Level, text: impl Into<String>) {
        let line = LogLine { time: chrono::Local::now().format("%H:%M:%S").to_string(), level, text: text.into() };
        if self.console.load(Ordering::Relaxed) {
            println!("[{}] {}", line.time, line.text);
        }
        if let Ok(mut g) = self.logs.lock() {
            if g.len() >= MAX_LOG {
                g.pop_front();
            }
            g.push_back(line);
        }
        self.bump();
    }

    pub fn set_running(&self, on: bool) {
        self.running.store(on, Ordering::Relaxed);
        if let Ok(mut g) = self.started_at.lock() {
            *g = if on { Some(Instant::now()) } else { None };
        }
        self.bump();
    }

    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::Relaxed)
    }

    pub fn inc_conn(&self) {
        self.conn_count.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_req(&self) {
        self.reqs.fetch_add(1, Ordering::Relaxed);
    }

    pub fn add_bytes(&self, up: u64, down: u64) {
        self.up.fetch_add(up, Ordering::Relaxed);
        self.down.fetch_add(down, Ordering::Relaxed);
    }

    pub fn set_lat(&self, host: &str, ms: u32) {
        if let Ok(mut g) = self.lat.lock() {
            g.insert(host.to_string(), ms);
        }
        self.bump();
    }

    pub fn clear_lat(&self) {
        if let Ok(mut g) = self.lat.lock() {
            g.clear();
        }
        self.bump();
    }

    /// 只清掉这几条规则的延迟。组测速 / 单条测速用它 ——
    /// 不清掉旧值的话，这一次测速失败的那几条会继续显示上一次的数字，
    /// 用户会以为「点了没反应」。
    pub fn clear_lat_for(&self, hosts: &[String]) {
        if let Ok(mut g) = self.lat.lock() {
            for h in hosts {
                g.remove(h);
            }
        }
        self.bump();
    }

    /// 记录一个域名能否加速（探测结果 / 在线握手观察结果）
    pub fn set_cap(&self, host: &str, ok: bool) {
        if let Ok(mut g) = self.caps.lock() {
            if g.len() > 8192 {
                g.clear();
            }
            g.insert(host.to_string(), ok);
        }
        self.bump();
    }

    // ---- 连接记录 ----

    pub fn push_conn(&self, host: &str, port: u16, rule: Option<String>, policy: &str, lat: Option<u32>) -> u64 {
        let id = self.conn_seq.fetch_add(1, Ordering::Relaxed) + 1;
        let now = chrono::Local::now();
        let c = Conn {
            id,
            at: now.timestamp(),
            time: now.format("%m-%d %H:%M:%S").to_string(),
            host: host.to_string(),
            port,
            rule,
            policy: policy.to_string(),
            lat,
            up: 0,
            down: 0,
            state: ConnState::Open,
            note: None,
            failed: false,
        };
        if let Ok(mut g) = self.conn_list.lock() {
            if g.len() >= MAX_CONN {
                g.pop_front();
            }
            g.push_back(c);
        }
        self.conn_dirty.store(true, Ordering::Relaxed);
        self.bump();
        id
    }

    pub fn set_conn_lat(&self, id: u64, ms: u32) {
        if let Ok(mut g) = self.conn_list.lock() {
            if let Some(c) = g.iter_mut().rev().find(|c| c.id == id) {
                c.lat = Some(ms);
            }
        }
        self.conn_dirty.store(true, Ordering::Relaxed);
        self.bump();
    }

    pub fn close_conn(&self, id: u64, up: u64, down: u64) {
        if let Ok(mut g) = self.conn_list.lock() {
            if let Some(c) = g.iter_mut().rev().find(|c| c.id == id) {
                c.up = up;
                c.down = down;
                c.state = ConnState::Closed;
            }
        }
        self.conn_dirty.store(true, Ordering::Relaxed);
        self.bump();
    }

    /// 记一句说明（降级原因、改走代理之类），连接页会挂一个可悬停的标记
    pub fn set_conn_note(&self, id: u64, note: impl Into<String>) {
        if let Ok(mut g) = self.conn_list.lock() {
            if let Some(c) = g.iter_mut().rev().find(|c| c.id == id) {
                c.note = Some(note.into());
            }
        }
        self.conn_dirty.store(true, Ordering::Relaxed);
        self.bump();
    }

    /// 实际走的线路跟最初判断的不一样时（比如加速失败改走代理），把策略改成真实的
    pub fn set_conn_policy(&self, id: u64, policy: &str) {
        if let Ok(mut g) = self.conn_list.lock() {
            if let Some(c) = g.iter_mut().rev().find(|c| c.id == id) {
                c.policy = policy.to_string();
            }
        }
        self.conn_dirty.store(true, Ordering::Relaxed);
        self.bump();
    }

    /// 连接彻底没建成
    pub fn fail_conn(&self, id: u64, note: impl Into<String>) {
        if let Ok(mut g) = self.conn_list.lock() {
            if let Some(c) = g.iter_mut().rev().find(|c| c.id == id) {
                c.note = Some(note.into());
                c.failed = true;
                c.state = ConnState::Closed;
            }
        }
        self.conn_dirty.store(true, Ordering::Relaxed);
        self.bump();
    }

    /// 给一条连接挂个备注，但**不算失败**。
    ///
    /// 给「链路是通的、只是对方不想给你」这种情况用 —— 典型是服务端限流（429）。
    /// 标成失败会让用户以为加速坏了，去重启程序或者乱改策略；标成备注才看得出
    /// 「等一会儿就好」。界面上非 failed 的备注是一个黄色的 `*`。
    pub fn note_conn(&self, id: u64, note: impl Into<String>) {
        if let Ok(mut g) = self.conn_list.lock() {
            if let Some(c) = g.iter_mut().rev().find(|c| c.id == id) {
                c.note = Some(note.into());
            }
        }
        self.conn_dirty.store(true, Ordering::Relaxed);
        self.bump();
    }

    pub fn clear_conns(&self) {
        if let Ok(mut g) = self.conn_list.lock() {
            g.clear();
        }
        self.conn_dirty.store(true, Ordering::Relaxed);
        self.bump();
    }

    fn conns_path() -> PathBuf {
        Settings::dir().join("connections.json")
    }

    fn load_conns(&self) {
        let Ok(raw) = std::fs::read_to_string(Self::conns_path()) else { return };
        let Ok(list) = serde_json::from_str::<Vec<Conn>>(&raw) else { return };
        let max_id = list.iter().map(|c| c.id).max().unwrap_or(0);
        self.conn_seq.store(max_id, Ordering::Relaxed);
        if let Ok(mut g) = self.conn_list.lock() {
            g.clear();
            for mut c in list {
                // 上次退出时还开着的，一律标成已结束
                c.state = ConnState::Closed;
                g.push_back(c);
            }
            while g.len() > MAX_CONN {
                g.pop_front();
            }
        }
    }

    /// 有变化才写盘，由引擎循环每几秒调一次
    pub fn flush_conns(&self) {
        if !self.conn_dirty.swap(false, Ordering::Relaxed) {
            return;
        }
        let list: Vec<Conn> = {
            let Ok(g) = self.conn_list.lock() else { return };
            let skip = g.len().saturating_sub(KEEP_CONN);
            g.iter().skip(skip).cloned().collect()
        };
        if let Ok(s) = serde_json::to_string(&list) {
            let _ = std::fs::write(Self::conns_path(), s);
        }
    }

    /// 通知界面「有东西变了，下一帧去取一次快照」
    fn bump(&self) {
        self.ver.fetch_add(1, Ordering::Relaxed);
    }

    /// 配置文件被引擎改了（自动把「透传」改成「中继」这类），通知界面重新读盘
    pub fn bump_cfg(&self) {
        self.cfg_ver.fetch_add(1, Ordering::Relaxed);
        self.bump();
    }

    pub fn cfg_ver(&self) -> u64 {
        self.cfg_ver.load(Ordering::Relaxed)
    }

    /// 把最新状态刷进 `snap`。
    ///
    /// 分两段：计数类的（字节数、请求数、运行状态）每帧都读，反正只是几个原子量；
    /// 列表类的（连接、日志、测速表）只在版本号变了才重新克隆 —— 这几坨是带 String 的
    /// 大对象，300 条连接每帧克隆一遍，常驻时纯属白烧 CPU。
    ///
    /// `need_logs` 为 false 时连日志都不碰：日志面板关着的时候没必要为它付钱。
    pub fn refresh(&self, snap: &mut Snap, need_logs: bool) {
        snap.running = self.is_running();
        snap.port = self.port.load(Ordering::Relaxed) as u16;
        snap.conn_count = self.conn_count.load(Ordering::Relaxed);
        snap.reqs = self.reqs.load(Ordering::Relaxed);
        snap.up = self.up.load(Ordering::Relaxed);
        snap.down = self.down.load(Ordering::Relaxed);
        snap.ca_installed = self.ca_installed.load(Ordering::Relaxed);
        snap.sysproxy = self.sysproxy.load(Ordering::Relaxed);
        snap.uptime = self.started_at.lock().ok().and_then(|g| *g).map(|t| t.elapsed().as_secs()).unwrap_or(0);

        let ver = self.ver.load(Ordering::Relaxed);
        if ver == snap.ver && (!need_logs || snap.logs_ready) {
            return;
        }
        // 限流：列表类内容最多 5Hz。计数类字段上面已经更新过了，不受影响。
        {
            let Ok(mut last) = self.last_snap.lock() else { return };
            match *last {
                Some(t) if t.elapsed() < SNAP_MIN_GAP => return,
                _ => *last = Some(Instant::now()),
            }
        }
        snap.ver = ver;
        snap.lat = self.lat.lock().map(|g| g.clone()).unwrap_or_default();
        snap.caps = self.caps.lock().map(|g| g.clone()).unwrap_or_default();
        snap.conns = self.conn_list.lock().map(|g| g.iter().cloned().collect()).unwrap_or_default();
        if need_logs {
            snap.logs = self.logs.lock().map(|g| g.iter().cloned().collect()).unwrap_or_default();
            snap.logs_ready = true;
        }
    }
}

#[derive(Clone, Default)]
pub struct Snap {
    pub running: bool,
    pub port: u16,
    pub conn_count: u64,
    pub reqs: u64,
    pub up: u64,
    pub down: u64,
    pub ca_installed: bool,
    pub sysproxy: bool,
    pub uptime: u64,
    pub lat: BTreeMap<String, u32>,
    pub caps: BTreeMap<String, bool>,
    pub conns: Vec<Conn>,
    pub logs: Vec<LogLine>,
    /// 上次取快照时的版本号（内部用）
    pub ver: u64,
    /// 日志已经取过至少一次（内部用）
    pub logs_ready: bool,
}

impl Snap {
    pub fn lat_of(&self, host: &str) -> Option<u32> {
        self.lat.get(host).copied()
    }

    pub fn cap_of(&self, host: &str) -> Option<bool> {
        self.caps.get(host).copied()
    }

    /// (探测过的域名数, 其中必须走代理的个数)
    pub fn cap_stats(&self) -> (usize, usize) {
        (self.caps.len(), self.caps.values().filter(|v| !**v).count())
    }
}

/// 把错误连它的 `source` 链一起打出来。
///
/// 为什么需要：hyper 的 `Kind::Io` 的 `Display` 是写死的 `"connection error"`，
/// 真正的成因（连接被重置 / 对端 EOF / rustls alert）全藏在 `source()` 里。
/// 只打 `{e}` 的话，日志里只剩一句「中继请求失败：connection error」——
/// 既不知道是谁掐的，也分不清是 IP 烂还是证书问题，等于没记。
pub fn err_chain<E>(e: &E) -> String
where
    E: std::error::Error + 'static,
{
    let mut out = e.to_string();
    let mut cur = e.source();
    let mut depth = 0;
    while let Some(s) = cur {
        let t = s.to_string();
        if !t.is_empty() && !out.contains(&t) {
            out.push_str(" <- ");
            out.push_str(&t);
        }
        cur = s.source();
        depth += 1;
        if depth >= 4 {
            break;
        }
    }
    out
}

pub fn fmt_bytes(n: u64) -> String {
    const U: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut v = n as f64;
    let mut i = 0;
    while v >= 1024.0 && i < U.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{n} B")
    } else {
        format!("{v:.1} {}", U[i])
    }
}

pub fn fmt_uptime(s: u64) -> String {
    let h = s / 3600;
    let m = (s % 3600) / 60;
    let sec = s % 60;
    if h > 0 {
        format!("{h}:{m:02}:{sec:02}")
    } else {
        format!("{m:02}:{sec:02}")
    }
}
