//! 把 `logo.ico` 嵌进 exe 的资源段 —— 资源管理器、任务栏固定项、文件属性里
//! 看到的都是它，而不只是一个白底默认图标。
//!
//! 不引第三方 crate：这一步只需要「找到 rc.exe → 编一个 .res → 让链接器带上」，
//! 手写比加依赖短，也不会因为多一个 build-dependency 拖慢冷编译。
//!
//! 找不到 rc.exe（没装 Windows SDK / 不是 MSVC 工具链）就跳过，只打一条 warning，
//! 绝不让它变成编译错误 —— 图标是锦上添花，不该卡住构建。

use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=logo.ico");

    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }
    if std::env::var("CARGO_CFG_TARGET_ENV").as_deref() != Ok("msvc") {
        println!("cargo:warning=非 MSVC 工具链，跳过 exe 图标");
        return;
    }

    let manifest = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap_or_default());
    let ico = manifest.join("logo.ico");
    if !ico.exists() {
        println!("cargo:warning=找不到 logo.ico，跳过 exe 图标");
        return;
    }
    let out = PathBuf::from(std::env::var("OUT_DIR").unwrap_or_default());
    let rc_file = out.join("mewway.rc");
    let res_file = out.join("mewway.res");

    // .rc 里的路径要写成单反斜杠的绝对路径
    let ico_lit = ico.display().to_string().replace('\\', "\\\\");
    let script = format!("1 ICON \"{ico_lit}\"\n");
    if std::fs::write(&rc_file, script).is_err() {
        println!("cargo:warning=写 .rc 失败，跳过 exe 图标");
        return;
    }

    let Some(rc) = find_rc() else {
        println!("cargo:warning=没找到 rc.exe（Windows SDK），跳过 exe 图标");
        return;
    };

    let status = Command::new(&rc)
        .arg("/nologo")
        .arg("/fo")
        .arg(&res_file)
        .arg(&rc_file)
        .status();
    match status {
        Ok(s) if s.success() => {
            println!("cargo:rustc-link-arg-bins={}", res_file.display());
        }
        _ => println!("cargo:warning=rc.exe 执行失败，跳过 exe 图标"),
    }
}

/// 在 PATH 和 Windows Kits 目录里找 rc.exe，取版本号最高的那个
fn find_rc() -> Option<PathBuf> {
    if let Ok(out) = Command::new("where").arg("rc.exe").output() {
        if out.status.success() {
            let first = String::from_utf8_lossy(&out.stdout);
            let line = first.lines().next().unwrap_or("").trim();
            if !line.is_empty() {
                return Some(PathBuf::from(line));
            }
        }
    }

    let kits = std::env::var("ProgramFiles(x86)").ok().map(PathBuf::from)?.join("Windows Kits/10/bin");
    let mut versions: Vec<PathBuf> = std::fs::read_dir(&kits)
        .ok()?
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.is_dir())
        .collect();
    // 目录名就是版本号，字符串排序对 10.0.x 恰好也是版本序
    versions.sort();
    for v in versions.iter().rev() {
        for sub in ["x64", "x86"] {
            let p = v.join(sub).join("rc.exe");
            if p.is_file() {
                return Some(p);
            }
        }
    }
    let _ = Path::new(&kits);
    None
}
