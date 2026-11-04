// 发布版不弹控制台窗口（--headless 模式建议用 debug 或另行重定向日志）
#![cfg_attr(all(windows, not(debug_assertions)), windows_subsystem = "windows")]

mod app;
mod config;
mod icon;
mod proxy;
mod shared;
mod sys;

use config::Settings;
use shared::{Command, Shared};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

fn main() {
    // rustls 需要显式指定加密后端
    let _ = rustls::crypto::ring::default_provider().install_default();

    let args: Vec<String> = std::env::args().skip(1).collect();
    let minimized = args.iter().any(|a| a == "--minimized" || a == "-m");
    let headless = args.iter().any(|a| a == "--headless" || a == "-H");
    let tab = parse_tab(&args);

    let cfg = Settings::load();

    // 单实例：同一个配置目录只允许一个进程。
    //
    // 这一步必须在 `heal` 之前 —— heal 会按「配置里说该开着」去改系统代理，
    // 第二个实例跑一遍就会把第一个实例正在用的 PAC 覆盖掉。
    // 拿不到锁说明已经有一个在跑：把它的窗口顶到前面，然后安静退出。
    #[cfg(windows)]
    let _single = match sys::single::acquire(&Settings::dir()) {
        Some(g) => g,
        None => {
            sys::win::activate_other_instance();
            return;
        }
    };

    let shared = Arc::new(Shared::new());
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
    // 引擎需要一份 tx：代理内核（预热 / 在线握手观察）确认某域名被 SNI 阻断时，
    // 会经这条 channel 把 Command::Escalate 回传给引擎，由它统一改写配置。
    // 这和界面用的 tx 是同一个通道，所以引擎能在自己的循环里收到。
    let engine_tx = tx.clone();

    // 上次若异常退出，系统代理可能还指着本地端口，这里自动还原
    let pac_url = sys::pac::url_for(&cfg.proxy_addr());
    sys::sysproxy::heal(&cfg.proxy_addr(), &pac_url);

    // 代理内核跑在独立线程的 tokio 运行时里，界面只通过 channel 下指令
    let engine_shared = shared.clone();
    std::thread::spawn(move || proxy::engine::run(rx, engine_shared, engine_tx));

    if headless {
        shared.console.store(true, Ordering::Relaxed);
        // 无界面模式也要检查一次证书，否则镜像规则永远被降级成隧道
        let installed = sys::cert::installed();
        shared.ca_installed.store(installed, Ordering::Relaxed);
        shared.ca_checked.store(true, Ordering::Relaxed);
        shared.log(shared::Level::Info, format!("本地 CA {}", if installed { "已安装" } else { "未安装" }));
        let _ = tx.send(Command::Start(Arc::new(cfg.clone())));
        if cfg.set_system_proxy {
            // PAC 由本机代理的 /pac 提供，等监听起来再接管
            app::wait_port(cfg.port);
            // 无界面模式同样按 PAC 分流，规则外的流量完全不受影响
            if let Err(e) = sys::pac::write(&cfg.sites, &cfg.proxy_addr()) {
                shared.log(shared::Level::Warn, format!("写入 PAC 失败：{e}"));
            }
            match sys::sysproxy::apply(true, cfg.proxy_mode, &cfg.proxy_addr(), &pac_url) {
                Ok(()) => shared.sysproxy.store(true, Ordering::Relaxed),
                Err(e) => shared.log(shared::Level::Err, format!("设置系统代理失败：{e}")),
            }
        }
        shared.log(shared::Level::Info, "无界面模式已启动，Ctrl+C 结束进程");
        loop {
            std::thread::sleep(Duration::from_secs(3600));
        }
    }

    let icon = icon::icon_data(64);
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1240.0, 780.0])
            .with_min_inner_size([1000.0, 620.0])
            .with_title("Mewway")
            .with_icon(icon)
            .with_visible(!minimized),
        ..Default::default()
    };

    let result = eframe::run_native(
        "Mewway",
        options,
        Box::new(move |cc| Ok(Box::new(app::App::new(cc, cfg, shared, tx, &tab, minimized)))),
    );
    if let Err(e) = result {
        eprintln!("界面启动失败：{e}");
    }
}

/// `--tab conns` / `--tab=settings`：启动时直接打开某一页
fn parse_tab(args: &[String]) -> String {
    let mut it = args.iter().peekable();
    while let Some(a) = it.next() {
        if let Some(v) = a.strip_prefix("--tab=") {
            return v.to_string();
        }
        if a == "--tab" {
            if let Some(v) = it.peek() {
                return (*v).clone();
            }
        }
    }
    String::new()
}
