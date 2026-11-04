//! 本地 CA 的安装/卸载/检测（certutil，安装到「当前用户 - 受信任的根证书颁发机构」）

use std::path::Path;
use std::process::{Command, Stdio};

#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

fn run(args: &[&str]) -> (bool, String) {
    let mut cmd = Command::new("certutil");
    cmd.args(args).stdout(Stdio::piped()).stderr(Stdio::piped());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }
    match cmd.output() {
        Ok(o) => {
            let mut s = String::from_utf8_lossy(&o.stdout).to_string();
            s.push_str(&String::from_utf8_lossy(&o.stderr));
            (o.status.success(), s)
        }
        Err(e) => (false, format!("无法执行 certutil：{e}")),
    }
}

pub fn install(der: &Path) -> Result<(), String> {
    if !der.exists() {
        return Err(format!("证书文件不存在：{}", der.display()));
    }
    let p = der.to_string_lossy().to_string();
    let (ok, out) = run(&["-user", "-addstore", "-f", "Root", &p]);
    if ok {
        Ok(())
    } else {
        Err(format!("安装失败：{}", out.trim()))
    }
}

pub fn uninstall() -> Result<(), String> {
    let (ok, out) = run(&["-user", "-delstore", "Root", crate::proxy::ca::CN]);
    if ok {
        Ok(())
    } else {
        Err(format!("卸载失败：{}", out.trim()))
    }
}

/// 通过列出用户根证书区，检查我们的 CA 是否已在里面
pub fn installed() -> bool {
    let (_, out) = run(&["-user", "-store", "Root"]);
    out.contains(crate::proxy::ca::CN)
}
