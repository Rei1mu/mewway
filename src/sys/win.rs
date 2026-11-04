//! 把主窗口抢到前台（Windows）
//!
//! 托盘菜单点「显示主界面」时，只发 `ViewportCommand::Focus` 是不够的。
//! Windows 有「前台锁定」（foreground lock）：一个不在前台的进程调用
//! `SetForegroundWindow` 时，系统只会让任务栏图标闪一下，窗口并不会真的到前面来 ——
//! 这就是「点了显示，但窗口还在别的窗口后面」的原因。
//!
//! 绕过它需要两步：
//!   1. 把我们的线程 attach 到当前前台窗口所在的线程（`AttachThreadInput`），
//!      这样我们就「继承」了那个线程的前台权限；
//!   2. 此时再 `SetForegroundWindow` + `BringWindowToTop` 才会真的生效。
//!
//! 另外要注意时序：eframe 的 `Visible(true)` 是**下一帧**才真正调用 `ShowWindow`，
//! 在同一时刻抢前台时窗口还是隐藏的，Windows 会直接忽略。所以调用方要延后一点。

#![cfg(windows)]

use windows_sys::Win32::Foundation::{CloseHandle, HWND, LPARAM, RECT};
use windows_sys::Win32::System::Threading::{
    AttachThreadInput, GetCurrentThreadId, OpenProcess, QueryFullProcessImageNameW,
    PROCESS_QUERY_LIMITED_INFORMATION,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    BringWindowToTop, EnumWindows, GetClientRect, GetForegroundWindow, GetWindowTextW,
    GetWindowThreadProcessId, IsIconic, IsWindowVisible, SetForegroundWindow, ShowWindow, SW_RESTORE,
};
use windows_sys::core::BOOL;

/// 主窗口标题。eframe 里 `with_title("Mewway")` 设的就是它。
const TITLE: &str = "Mewway";

struct Finder {
    pid: u32,
    /// 标题对得上、而且可见 —— 最理想的目标
    exact: HWND,
    /// 同进程里可见窗口的最大者（标题对不上时的兜底）
    best_visible: (HWND, i32),
    /// 同进程里的任意顶层窗口（窗口还隐藏着时的最后兜底）
    any: HWND,
}

unsafe extern "system" fn enum_proc(hwnd: HWND, lparam: LPARAM) -> BOOL {
    // SAFETY: lparam 是我们自己传进来的 &mut Finder
    let f = unsafe { &mut *(lparam as *mut Finder) };
    let mut pid = 0u32;
    unsafe { GetWindowThreadProcessId(hwnd, &mut pid) };
    if pid != f.pid {
        return 1;
    }
    if f.any.is_null() {
        f.any = hwnd;
    }

    let mut buf = [0u16; 64];
    let n = unsafe { GetWindowTextW(hwnd, buf.as_mut_ptr(), buf.len() as i32) };
    let title = if n > 0 { String::from_utf16_lossy(&buf[..n as usize]) } else { String::new() };

    let visible = unsafe { IsWindowVisible(hwnd) } != 0;
    if visible {
        let mut rc: RECT = unsafe { std::mem::zeroed() };
        let area = if unsafe { GetClientRect(hwnd, &mut rc) } != 0 {
            (rc.right - rc.left).saturating_mul(rc.bottom - rc.top)
        } else {
            0
        };
        if area > f.best_visible.1 {
            f.best_visible = (hwnd, area);
        }
        if title == TITLE && f.exact.is_null() {
            f.exact = hwnd;
        }
    }
    1
}

/// 找到属于本进程的主窗口
fn find_main_window() -> HWND {
    let mut f = Finder { pid: std::process::id(), exact: std::ptr::null_mut(), best_visible: (std::ptr::null_mut(), -1), any: std::ptr::null_mut() };
    // SAFETY: 回调只在这个调用期间被使用，lparam 指向栈上的 f，生命周期足够
    unsafe { EnumWindows(Some(enum_proc), &mut f as *mut Finder as LPARAM) };

    if !f.exact.is_null() {
        return f.exact;
    }
    if !f.best_visible.0.is_null() {
        return f.best_visible.0;
    }
    f.any
}

/// 把主窗口显示出来并抢到最前面。找不到窗口就什么都不做（不要 panic）。
pub fn activate_main_window() {
    let hwnd = find_main_window();
    if !hwnd.is_null() {
        force_foreground(hwnd);
    }
}

/// 另一个实例的窗口：单实例模式下，第二个进程用它把已有窗口顶到前面。
///
/// 注意这里**不能**按标题找就算数 —— 资源管理器打开本项目目录时标题也叫
/// "mewway"，只差大小写。所以还要核对进程映像名确实是 mewway.exe。
pub fn activate_other_instance() {
    let me = std::process::id();
    let mut f = OtherFinder { me, best: (std::ptr::null_mut(), -1) };
    // SAFETY: 回调只在这个调用期间被使用，lparam 指向栈上的 f
    unsafe { EnumWindows(Some(enum_other), &mut f as *mut OtherFinder as LPARAM) };
    if !f.best.0.is_null() {
        force_foreground(f.best.0);
    }
}

struct OtherFinder {
    me: u32,
    best: (HWND, i32),
}

unsafe extern "system" fn enum_other(hwnd: HWND, lparam: LPARAM) -> BOOL {
    // SAFETY: lparam 是我们自己传进来的 &mut OtherFinder
    let f = unsafe { &mut *(lparam as *mut OtherFinder) };
    let mut pid = 0u32;
    unsafe { GetWindowThreadProcessId(hwnd, &mut pid) };
    if pid == 0 || pid == f.me {
        return 1;
    }
    if unsafe { IsWindowVisible(hwnd) } == 0 {
        return 1;
    }

    let mut buf = [0u16; 64];
    let n = unsafe { GetWindowTextW(hwnd, buf.as_mut_ptr(), buf.len() as i32) };
    if n <= 0 || String::from_utf16_lossy(&buf[..n as usize]) != TITLE {
        return 1;
    }

    // 标题对上了，再确认这个进程真的是 mewway.exe
    let exe = unsafe { exe_name(pid) };
    if exe != "mewway.exe" {
        return 1;
    }

    let mut rc: RECT = unsafe { std::mem::zeroed() };
    let area = if unsafe { GetClientRect(hwnd, &mut rc) } != 0 {
        (rc.right - rc.left).saturating_mul(rc.bottom - rc.top)
    } else {
        0
    };
    if area > f.best.1 {
        f.best = (hwnd, area);
    }
    1
}

/// 取进程映像的文件名（小写）。拿不到就返回空串 —— 调用方当作「不匹配」。
unsafe fn exe_name(pid: u32) -> String {
    // SAFETY: 句柄在使用后立即关闭
    let h = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if h.is_null() {
        return String::new();
    }
    let mut buf = [0u16; 512];
    let mut n = buf.len() as u32;
    let ok = unsafe { QueryFullProcessImageNameW(h, 0, buf.as_mut_ptr(), &mut n) };
    unsafe { CloseHandle(h) };
    if ok == 0 {
        return String::new();
    }
    let s = String::from_utf16_lossy(&buf[..n as usize]);
    s.rsplit(['\\', '/']).next().unwrap_or("").to_ascii_lowercase()
}

/// 还原（如果最小化了）+ 抢前台。两个入口共用。
fn force_foreground(hwnd: HWND) {
    // SAFETY: hwnd 来自 EnumWindows，是真实存在的顶层窗口
    unsafe {
        // 最小化过就先还原，否则 SetForegroundWindow 只会改任务栏状态
        if IsIconic(hwnd) != 0 {
            ShowWindow(hwnd, SW_RESTORE);
        }

        let fg = GetForegroundWindow();
        let fg_tid = if fg.is_null() { 0 } else { GetWindowThreadProcessId(fg, std::ptr::null_mut()) };
        let my_tid = GetCurrentThreadId();

        // 关键：attach 到当前前台线程，才被允许抢前台
        let attached = fg_tid != 0 && fg_tid != my_tid && AttachThreadInput(my_tid, fg_tid, 1) != 0;
        SetForegroundWindow(hwnd);
        BringWindowToTop(hwnd);
        if attached {
            AttachThreadInput(my_tid, fg_tid, 0);
        }
    }
}
