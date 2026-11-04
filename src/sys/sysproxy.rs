//! 系统代理开关（Windows: WinINet 注册表 + 立即刷新）
//!
//! 两种接管方式：
//! - **PAC**（默认）：只把规则表里的域名指向本程序，其余直连。影响面最小。
//! - **全局**：所有流量都指向本程序。
//!
//! 开启前会把用户原有的代理设置（含 `AutoConfigURL`）备份到 `proxy_backup.json`，
//! 关闭时原样还原，避免「程序退出后浏览器还指着一个不存在的代理」这种事故。

const BYPASS: &str = "localhost;127.*;10.*;172.16.*;172.17.*;172.18.*;172.19.*;172.2*;172.30.*;172.31.*;192.168.*;<local>";

#[cfg(windows)]
mod imp {
    use super::BYPASS;
    use crate::config::ProxyMode;
    use serde::{Deserialize, Serialize};
    use std::path::PathBuf;

    const KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings";

    #[derive(Serialize, Deserialize, Default)]
    struct Backup {
        /// 开启前用户自己的 ProxyEnable
        enable: u32,
        server: Option<String>,
        over: Option<String>,
        /// 开启前用户自己的 PAC 地址
        auto: Option<String>,
    }

    fn backup_path() -> PathBuf {
        crate::config::Settings::dir().join("proxy_backup.json")
    }

    fn notify() {
        use windows_sys::Win32::Networking::WinInet::InternetSetOptionW;
        // 39 = INTERNET_OPTION_SETTINGS_CHANGED, 37 = INTERNET_OPTION_REFRESH
        unsafe {
            InternetSetOptionW(std::ptr::null_mut(), 39, std::ptr::null(), 0);
            InternetSetOptionW(std::ptr::null_mut(), 37, std::ptr::null(), 0);
        }
    }

    fn read_str(key: &winreg::RegKey, name: &str) -> Option<String> {
        if let Ok(v) = key.get_value::<String, _>(name) {
            return Some(v);
        }
        key.get_value::<u32, _>(name).ok().map(|v| v.to_string())
    }

    /// 当前注册表是不是指向我们自己
    fn pointing_at(key: &winreg::RegKey, addr: &str, pac_url: &str) -> bool {
        read_str(key, "ProxyServer").as_deref() == Some(addr)
            || read_str(key, "AutoConfigURL").as_deref() == Some(pac_url)
    }

    /// 接管。`mode` 决定用 PAC 还是全局。
    pub fn apply(enabled: bool, mode: ProxyMode, addr: &str, pac_url: &str) -> Result<(), String> {
        use winreg::enums::*;
        use winreg::RegKey;

        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        let key = hkcu
            .open_subkey_with_flags(KEY, KEY_READ | KEY_WRITE)
            .map_err(|e| format!("打开注册表失败：{e}"))?;

        if !enabled {
            restore(&key);
            notify();
            return Ok(());
        }

        // 只在「当前不是我们自己」时备份一次，避免把自己的设置当成用户的备份
        if !pointing_at(&key, addr, pac_url) && !backup_path().exists() {
            let b = Backup {
                enable: key.get_value::<u32, _>("ProxyEnable").unwrap_or(0),
                server: read_str(&key, "ProxyServer"),
                over: read_str(&key, "ProxyOverride"),
                auto: read_str(&key, "AutoConfigURL"),
            };
            if let Ok(s) = serde_json::to_string(&b) {
                let _ = std::fs::write(backup_path(), s);
            }
        }

        match mode {
            ProxyMode::Pac => {
                // PAC 优先：ProxyEnable 关掉，只留 AutoConfigURL
                key.set_value("AutoConfigURL", &pac_url.to_string()).map_err(|e| e.to_string())?;
                key.set_value("ProxyEnable", &0u32).map_err(|e| e.to_string())?;
            }
            ProxyMode::Global => {
                // 全局模式下必须清掉 PAC，否则浏览器还是按 PAC 分流
                let _ = key.delete_value("AutoConfigURL");
                key.set_value("ProxyEnable", &1u32).map_err(|e| e.to_string())?;
                key.set_value("ProxyServer", &addr.to_string()).map_err(|e| e.to_string())?;
                key.set_value("ProxyOverride", &BYPASS.to_string()).map_err(|e| e.to_string())?;
            }
        }
        notify();
        Ok(())
    }

    fn restore(key: &winreg::RegKey) {
        let saved = std::fs::read_to_string(backup_path())
            .ok()
            .and_then(|s| serde_json::from_str::<Backup>(&s).ok());
        match saved {
            Some(b) => {
                let _ = key.set_value("ProxyEnable", &b.enable);
                match b.server {
                    Some(s) => {
                        let _ = key.set_value("ProxyServer", &s);
                    }
                    None => {
                        let _ = key.delete_value("ProxyServer");
                    }
                }
                match b.over {
                    Some(o) => {
                        let _ = key.set_value("ProxyOverride", &o);
                    }
                    None => {
                        let _ = key.delete_value("ProxyOverride");
                    }
                }
                match b.auto {
                    Some(a) => {
                        let _ = key.set_value("AutoConfigURL", &a);
                    }
                    None => {
                        let _ = key.delete_value("AutoConfigURL");
                    }
                }
                let _ = std::fs::remove_file(backup_path());
            }
            None => {
                let _ = key.set_value("ProxyEnable", &0u32);
                let _ = key.delete_value("AutoConfigURL");
            }
        }
    }

    /// 启动时自检：上次如果是崩溃退出，系统代理可能还指着我们，这里自动还原。
    /// 只有完全对得上（我们的端口 / 我们的 PAC）才动手，不会误伤用户自己的代理。
    pub fn heal(addr: &str, pac_url: &str) {
        use winreg::enums::*;
        use winreg::RegKey;
        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        let Ok(key) = hkcu.open_subkey_with_flags(KEY, KEY_READ | KEY_WRITE) else { return };
        let cur = pointing_at(&key, addr, pac_url);

        match std::fs::read_to_string(backup_path()).ok().and_then(|s| serde_json::from_str::<Backup>(&s).ok()) {
            Some(_) if cur => {
                restore(&key);
                notify();
            }
            Some(_) => {
                // 备份已失效（用户之后自己改过代理），丢弃
                let _ = std::fs::remove_file(backup_path());
            }
            None => {
                // 没有备份但注册表仍指着我们 -> 上次是硬崩溃
                if cur {
                    let _ = key.set_value("ProxyEnable", &0u32);
                    let _ = key.delete_value("AutoConfigURL");
                    notify();
                }
            }
        }
    }

    /// 系统代理当前是否指向我们（PAC 或全局都算）
    pub fn state(addr: &str, pac_url: &str) -> bool {
        use winreg::enums::*;
        use winreg::RegKey;
        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        let Ok(k) = hkcu.open_subkey(KEY) else { return false };
        if read_str(&k, "AutoConfigURL").as_deref() == Some(pac_url) {
            return true;
        }
        k.get_value::<u32, _>("ProxyEnable").map(|v| v == 1).unwrap_or(false)
            && read_str(&k, "ProxyServer").as_deref() == Some(addr)
    }
}

#[cfg(not(windows))]
mod imp {
    use crate::config::ProxyMode;
    pub fn apply(_enabled: bool, _mode: ProxyMode, _addr: &str, _pac_url: &str) -> Result<(), String> {
        Err("当前系统暂不支持自动设置代理，请手动配置".into())
    }
    pub fn heal(_addr: &str, _pac_url: &str) {}
    pub fn state(_addr: &str, _pac_url: &str) -> bool {
        false
    }
}

pub use imp::{apply, heal, state};
