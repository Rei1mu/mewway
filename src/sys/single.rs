//! 单实例锁
//!
//! 双击 exe 时如果已经有一个在跑，第二个实例应该**激活已有窗口然后退出**，
//! 而不是再起一套引擎。多开的后果很实在：两个实例抢同一个端口、抢同一份
//! config.json、互相把对方的 PAC 覆盖掉。
//!
//! 实现用命名 mutex：`CreateMutexW` 在名字已存在时会把 `GetLastError` 设成
//! `ERROR_ALREADY_EXISTS`，但**仍然返回一个有效句柄**，所以拿到句柄后必须查
//! 错误码才能区分「我创建的」和「别人已经建好的」。
//!
//! 锁名按**配置目录**算，不是全局唯一 —— 这样 `MEWWAY_HOME` 指向不同目录时
//! 可以并存（隔离测试、便携版要用）。同一个目录仍然只允许一个。

#![cfg(windows)]

use std::path::Path;
use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, ERROR_ALREADY_EXISTS, HANDLE};
use windows_sys::Win32::System::Threading::CreateMutexW;

/// 持有它就代表「我是唯一实例」。进程退出时由 Drop 释放。
pub struct Guard(HANDLE);

impl Drop for Guard {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: 句柄是 CreateMutexW 给的，且只在这里释放一次
            unsafe { CloseHandle(self.0) };
        }
    }
}

/// 尝试成为唯一实例。返回 `None` 表示已经有一个实例在用同一个配置目录。
///
/// 拿不到锁（权限不足等）时**不拦**启动 —— 宁可多开，也不能让用户打不开程序。
pub fn acquire(dir: &Path) -> Option<Guard> {
    // 路径统一成小写再哈希，免得 `C:/a` 和 `c:\a` 被当成两个锁
    let key = dir.to_string_lossy().to_ascii_lowercase();
    let name = format!("Local\\Mewway-{:016x}", fnv1a(&key));

    let mut wide: Vec<u16> = name.encode_utf16().collect();
    wide.push(0);

    // SAFETY: 名字是合法的以 NUL 结尾的宽字符串，且在整个调用期间有效
    let handle = unsafe { CreateMutexW(std::ptr::null(), 0, wide.as_ptr()) };
    if handle.is_null() {
        return Some(Guard(handle));
    }
    // GetLastError 必须在 CreateMutexW 之后立刻读，中间不能夹别的 Win32 调用
    if unsafe { GetLastError() } == ERROR_ALREADY_EXISTS {
        // SAFETY: 这个句柄我们不再使用
        unsafe { CloseHandle(handle) };
        return None;
    }
    Some(Guard(handle))
}

/// FNV-1a。用固定实现而不是 `DefaultHasher`：后者不保证跨版本稳定，
/// 换编译器后同一个目录可能算出不同的锁名。
fn fnv1a(s: &str) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in s.as_bytes() {
        h ^= *b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}
