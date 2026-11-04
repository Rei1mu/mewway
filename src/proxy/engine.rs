//! 代理内核的驱动：一个后台 tokio 运行时，通过 channel 接收启停指令

use crate::config::{Mode, Settings};
use crate::proxy::resolver::Resolver;
use crate::proxy::rules;
use crate::proxy::{server, Ctx};
use crate::shared::{Command, Level, Shared};
use std::sync::Arc;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};
use tokio_util::sync::CancellationToken;

pub fn run(rx: UnboundedReceiver<Command>, shared: Arc<Shared>, tx: UnboundedSender<Command>) {
    let rt = match tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            shared.log(Level::Err, format!("创建异步运行时失败：{e}"));
            return;
        }
    };

    rt.block_on(async move {
        let mut rx = rx;
        let mut token: Option<CancellationToken> = None;
        let mut ctx: Option<Arc<Ctx>> = None;
        let mut cfg: Arc<Settings> = Arc::new(Settings::load());
        let mut tick: u32 = 0;

        loop {
            // 每 5 秒醒一次；连接记录每 30 秒才写一次盘 ——
            // 每次都是全量重写几十 KB 的 JSON，写得太勤纯属浪费 IO
            let cmd = match tokio::time::timeout(std::time::Duration::from_secs(5), rx.recv()).await {
                Ok(Some(c)) => c,
                Ok(None) => break,
                Err(_) => {
                    tick = tick.wrapping_add(1);
                    if tick % 6 == 0 {
                        shared.flush_conns();
                    }
                    if let Some(c) = &ctx {
                        c.probes.flush();
                    }
                    continue;
                }
            };
            match cmd {
                Command::Start(new_cfg) => {
                    cfg = new_cfg;
                    if let Some(t) = token.take() {
                        t.cancel();
                        tokio::time::sleep(std::time::Duration::from_millis(120)).await;
                    }
                    let up = if cfg.upstream.trim().is_empty() {
                        "直连（未配置上游）".to_string()
                    } else {
                        cfg.upstream.trim().to_string()
                    };
                    shared.log(Level::Info, format!("上游代理：{up}"));
                    match server::spawn(cfg.clone(), shared.clone(), tx.clone()).await {
                        Ok((c, t)) => {
                            // 预热：把「透传」规则先探一遍，浏览器来的时候就知道该透传还是中继，
                            // 免得第一次访问被 SNI 掐一次再重试
                            c.probes.warmup(&cfg.sites, c.resolver.clone());
                            ctx = Some(c);
                            token = Some(t);
                        }
                        Err(e) => {
                            shared.set_running(false);
                            shared.log(Level::Err, format!("启动失败：{e}"));
                        }
                    }
                }
                Command::Reload(new_cfg) => {
                    cfg = new_cfg;
                    if let Some(c) = &ctx {
                        c.replace(cfg.clone());
                        // 规则变了，新加进来的「加速」域名还没结论，补一轮预热（已知道的会跳过）
                        c.probes.warmup(&cfg.sites, c.resolver.clone());
                    }
                }
                Command::Stop => {
                    if let Some(t) = token.take() {
                        t.cancel();
                    }
                    shared.set_running(false);
                    shared.log(Level::Info, "已停止代理");
                }
                Command::Probe(items) => {
                    // 没启动时也能测速，用一个临时解析器
                    let resolver = match &ctx {
                        Some(c) => c.resolver.clone(),
                        None => Arc::new(Resolver::new(shared.clone(), cfg.doh.clone())),
                    };
                    let shared = shared.clone();
                    // 「直连」规则要按系统解析来测（Route::Direct 实际就是这么连的），
                    // 其余按 best() 择优。见 resolver::best_system 的注释。
                    let cfg = cfg.clone();
                    tokio::spawn(async move {
                        // 并发 8 路，几百条规则也能几秒跑完
                        let sem = Arc::new(tokio::sync::Semaphore::new(8));
                        let mut set = tokio::task::JoinSet::new();
                        for (key, host) in items {
                            let resolver = resolver.clone();
                            let shared = shared.clone();
                            let sem = sem.clone();
                            // 测速要「按这条规则实际怎么连」去量，否则数字是假的：
                            //   直连 -> 系统解析 + TCP（`best_system`）
                            //   中继 -> TCP + **无 SNI** 的 TLS 握手（`best_relay`）
                            //   其余 -> 三源合并 + TCP，且**跳过缓存**（`best_fresh`），
                            //           否则 180 秒内点第二次看到的还是上一次的数字
                            let mode = rules::find_rule(&cfg.sites, &key).map(|i| cfg.sites[i].mode);
                            set.spawn(async move {
                                let _permit = sem.acquire_owned().await.ok()?;
                                let r = match mode {
                                    Some(Mode::Direct) => resolver.best_system(&host, 443).await,
                                    Some(Mode::Relay) => resolver.best_relay(&host, 443).await,
                                    _ => resolver.best_fresh(&host, 443).await,
                                };
                                let (_, ms) = r?;
                                shared.set_lat(&key, ms);
                                Some(())
                            });
                        }
                        let mut ok = 0usize;
                        let mut fail = 0usize;
                        while let Some(r) = set.join_next().await {
                            match r {
                                Ok(Some(())) => ok += 1,
                                _ => fail += 1,
                            }
                        }
                        // 只在有失败时说话：全成功的话界面上的数字已经说明问题了，
                        // 每条都记一条日志只会把面板刷满
                        if fail > 0 {
                            shared.log(
                                Level::Info,
                                format!("测速完成：{ok} 条成功，{fail} 条没测出来（IP 全不通或超时）"),
                            );
                        }
                    });
                }
                Command::Escalate(host) => {
                    // 配置的唯一写入方是引擎。代理内核确认某域名被 SNI 阻断后，
                    // 把对应的「透传」规则改成「中继」并落盘，界面会感知 cfg_ver 变化后重读。
                    // auto_escalate 关掉的话只提示、不改动配置。
                    let idx = rules::find_rule(&cfg.sites, &host);
                    match idx {
                        Some(i) if cfg.sites[i].mode == Mode::Tunnel => {
                            if cfg.auto_escalate {
                                let mut new_cfg = (*cfg).clone();
                                new_cfg.sites[i].mode = Mode::Relay;
                                new_cfg.save();
                                if let Some(c) = &ctx {
                                    c.replace(Arc::new(new_cfg.clone()));
                                }
                                cfg = Arc::new(new_cfg);
                                shared.bump_cfg();
                                shared.log(
                                    Level::Ok,
                                    format!("[{host}] 确认被 SNI 阻断，已自动改为「中继」并保存"),
                                );
                            } else {
                                shared.log(
                                    Level::Warn,
                                    format!("[{host}] 确认被 SNI 阻断，可把规则改成「中继」（已关闭自动改写）"),
                                );
                            }
                        }
                        // 没命中「透传」规则：可能是未命中规则的兜底域名，或已经是中继。
                        // 不写配置，只让探针记一笔结论（mark_blocked 已经 set(false) 了）。
                        _ => {}
                    }
                }
                Command::Shutdown => {
                    if let Some(t) = token.take() {
                        t.cancel();
                    }
                    shared.flush_conns();
                    if let Some(c) = &ctx {
                        c.probes.flush();
                    }
                    break;
                }
            }
        }
        shared.flush_conns();
    });
}
