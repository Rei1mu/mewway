"""量一下 mewway.exe 在 N 秒里实际吃了多少 CPU。

用 GetProcessTimes 读内核+用户态时间差，比看任务管理器的瞬时百分比准。
用法：python tools/cpu.py [秒数]
"""

import ctypes
import ctypes.wintypes as wt
import sys
import time

k32 = ctypes.windll.kernel32
k32.OpenProcess.restype = wt.HANDLE
k32.OpenProcess.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]
k32.GetProcessTimes.argtypes = [
    wt.HANDLE,
    ctypes.POINTER(wt.FILETIME),
    ctypes.POINTER(wt.FILETIME),
    ctypes.POINTER(wt.FILETIME),
    ctypes.POINTER(wt.FILETIME),
]

PROC = "mewway.exe"


def find_pid():
    import subprocess

    out = subprocess.run(["tasklist", "/FI", f"IMAGENAME eq {PROC}", "/FO", "CSV", "/NH"],
                         capture_output=True, text=True, errors="ignore").stdout
    for line in out.splitlines():
        parts = [p.strip('"') for p in line.split('","')]
        if len(parts) > 1 and parts[0].lower() == PROC:
            return int(parts[1])
    return None


def cpu_seconds(h):
    c, e, k, u = (wt.FILETIME() for _ in range(4))
    if not k32.GetProcessTimes(h, ctypes.byref(c), ctypes.byref(e), ctypes.byref(k), ctypes.byref(u)):
        raise OSError("GetProcessTimes 失败")
    to_s = lambda ft: (ft.dwHighDateTime << 32 | ft.dwLowDateTime) / 1e7
    return to_s(k) + to_s(u)


pid = find_pid()
if pid is None:
    raise SystemExit(f"{PROC} 没在跑")
secs = float(sys.argv[1]) if len(sys.argv) > 1 else 10.0

h = k32.OpenProcess(0x1000, False, pid)
t0 = cpu_seconds(h)
time.sleep(secs)
t1 = cpu_seconds(h)
used = t1 - t0
print(f"PID {pid}  采样 {secs:.0f}s  占用 CPU {used:.3f}s  ≈ {used / secs * 100:.2f}% 单核")
