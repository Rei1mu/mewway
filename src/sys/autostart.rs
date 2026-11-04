//! 开机自启（HKCU\...\Run）

#[cfg(windows)]
mod imp {
    const KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";
    const NAME: &str = "Mewway";

    pub fn set(enabled: bool) -> Result<(), String> {
        use winreg::enums::*;
        use winreg::RegKey;

        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        let key = hkcu
            .open_subkey_with_flags(KEY, KEY_READ | KEY_WRITE)
            .map_err(|e| format!("打开注册表失败：{e}"))?;

        if enabled {
            let exe = std::env::current_exe().map_err(|e| e.to_string())?;
            let cmd = format!("\"{}\" --minimized", exe.display());
            key.set_value(NAME, &cmd).map_err(|e| e.to_string())?;
        } else {
            let _ = key.delete_value(NAME);
        }
        Ok(())
    }

    pub fn enabled() -> bool {
        use winreg::enums::*;
        use winreg::RegKey;
        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        hkcu.open_subkey(KEY)
            .and_then(|k| k.get_value::<String, _>(NAME))
            .map(|v| !v.is_empty())
            .unwrap_or(false)
    }
}

#[cfg(not(windows))]
mod imp {
    pub fn set(_enabled: bool) -> Result<(), String> {
        Err("当前系统暂不支持".into())
    }
    pub fn enabled() -> bool {
        false
    }
}

pub use imp::{enabled, set};
