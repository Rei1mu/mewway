//! 系统集成：系统代理、开机自启、根证书安装

pub mod autostart;
pub mod cert;
pub mod pac;
#[cfg(windows)]
pub mod single;
pub mod sysproxy;
#[cfg(windows)]
pub mod win;
