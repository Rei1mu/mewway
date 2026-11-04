"""截取 Mewway 窗口。

不模拟任何鼠标/键盘事件。只做两件事：把窗口提到最前（不抢焦点），然后拷位图。

找窗口按**进程名**找，不按标题 —— 标题是 "Mewway"，而资源管理器打开这个项目
目录时窗口标题也叫 "mewway"，按标题找会截到资源管理器。

用法：
    python tools/shot.py out.png          # 截面积最大的那个 mewway 窗口
    python tools/shot.py out.png 12345    # 只截指定 PID（同时开了多个实例时必须给）
"""

import ctypes
import ctypes.wintypes as wt
import os
import sys
import time

from PIL import Image

user32 = ctypes.windll.user32
gdi32 = ctypes.windll.gdi32
kernel32 = ctypes.windll.kernel32

PROC = "mewway.exe"
OUT = sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.environ["TEMP"], "ui.png")
ONLY_PID = int(sys.argv[2]) if len(sys.argv) > 2 else 0

SRCCOPY = 0x00CC0020
DIB_RGB_COLORS = 0
BI_RGB = 0
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000


class BITMAPINFOHEADER(ctypes.Structure):
    _fields_ = [
        ("biSize", wt.DWORD),
        ("biWidth", wt.LONG),
        ("biHeight", wt.LONG),
        ("biPlanes", wt.WORD),
        ("biBitCount", wt.WORD),
        ("biCompression", wt.DWORD),
        ("biSizeImage", wt.DWORD),
        ("biXPelsPerMeter", wt.LONG),
        ("biYPelsPerMeter", wt.LONG),
        ("biClrUsed", wt.DWORD),
        ("biClrImportant", wt.DWORD),
    ]


class BITMAPINFO(ctypes.Structure):
    _fields_ = [("bmiHeader", BITMAPINFOHEADER), ("bmiColors", wt.DWORD * 3)]


# 不声明 argtypes 的话 ctypes 会按 c_int 传 HWND/HDC，64 位下句柄值一超范围就报
# OverflowError（在回调里抛的还只会被静默打印），所以下面全部显式声明一遍。
WNDENUMPROC = ctypes.WINFUNCTYPE(wt.BOOL, wt.HWND, wt.LPARAM)
user32.EnumWindows.argtypes = [WNDENUMPROC, wt.LPARAM]
user32.EnumWindows.restype = wt.BOOL
user32.IsWindowVisible.argtypes = [wt.HWND]
user32.IsWindowVisible.restype = wt.BOOL
user32.GetWindowTextLengthW.argtypes = [wt.HWND]
user32.GetWindowTextLengthW.restype = ctypes.c_int
user32.GetWindowThreadProcessId.argtypes = [wt.HWND, ctypes.POINTER(wt.DWORD)]
user32.GetWindowThreadProcessId.restype = wt.DWORD
user32.SetWindowPos.argtypes = [wt.HWND, wt.HWND, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int, wt.UINT]
user32.GetWindowRect.argtypes = [wt.HWND, ctypes.POINTER(wt.RECT)]
user32.GetWindowDC.argtypes = [wt.HWND]
user32.GetWindowDC.restype = wt.HDC
user32.ReleaseDC.argtypes = [wt.HWND, wt.HDC]
user32.PrintWindow.argtypes = [wt.HWND, wt.HDC, wt.UINT]
gdi32.CreateCompatibleDC.argtypes = [wt.HDC]
gdi32.CreateCompatibleDC.restype = wt.HDC
gdi32.CreateCompatibleBitmap.argtypes = [wt.HDC, ctypes.c_int, ctypes.c_int]
gdi32.CreateCompatibleBitmap.restype = wt.HBITMAP
gdi32.SelectObject.argtypes = [wt.HDC, wt.HGDIOBJ]
gdi32.BitBlt.argtypes = [wt.HDC, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int, wt.HDC, ctypes.c_int, ctypes.c_int, wt.DWORD]
gdi32.GetDIBits.argtypes = [wt.HDC, wt.HBITMAP, wt.UINT, wt.UINT, ctypes.c_void_p, ctypes.POINTER(BITMAPINFO), wt.UINT]
gdi32.DeleteObject.argtypes = [wt.HGDIOBJ]
gdi32.DeleteDC.argtypes = [wt.HDC]


def exe_of(pid):
    h = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not h:
        return ""
    try:
        n = wt.DWORD(512)
        buf = ctypes.create_unicode_buffer(512)
        if kernel32.QueryFullProcessImageNameW(h, 0, buf, ctypes.byref(n)):
            return os.path.basename(buf.value).lower()
        return ""
    finally:
        kernel32.CloseHandle(h)


def find_windows():
    """枚举顶层窗口，挑出属于 mewway.exe 且可见、有标题的那些"""
    found = []

    def cb(hwnd, _):
        if not user32.IsWindowVisible(hwnd):
            return True
        if user32.GetWindowTextLengthW(hwnd) == 0:
            return True
        pid = wt.DWORD()
        user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
        if ONLY_PID and pid.value != ONLY_PID:
            return True
        if exe_of(pid.value) == PROC:
            found.append(hwnd)
        return True

    user32.EnumWindows(WNDENUMPROC(cb), 0)
    return found


def biggest(hwnds):
    """同一进程会有好几个顶层窗口（提示框、IME 候选窗之类），要面积最大的那个"""
    best, best_area = None, 0
    for h in hwnds:
        r = wt.RECT()
        if not user32.GetWindowRect(h, ctypes.byref(r)):
            continue
        area = (r.right - r.left) * (r.bottom - r.top)
        if area > best_area:
            best, best_area = h, area
    return best


hwnd = biggest(find_windows())
if not hwnd:
    raise SystemExit("没找到 %s 的窗口（程序在跑吗？）" % PROC)

# HWND_TOP(0) + SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE：提到最前，但不抢焦点、不动鼠标。
#
# 千万别写 -1：Win32 里 -1 是 HWND_TOPMOST，会把窗口设成**永久置顶**，
# 截完图它就一直压在别的窗口上面（踩过，用户以为程序自己在抢最前）。
HWND_TOP = 0
HWND_NOTOPMOST = -2
user32.SetWindowPos(hwnd, HWND_TOP, 0, 0, 0, 0, 0x0002 | 0x0001 | 0x0010)
# 顺手把可能被旧版脚本设上的置顶属性摘掉
user32.SetWindowPos(hwnd, HWND_NOTOPMOST, 0, 0, 0, 0, 0x0002 | 0x0001 | 0x0010)
time.sleep(0.35)

rect = wt.RECT()
user32.GetWindowRect(hwnd, ctypes.byref(rect))
w, h = rect.right - rect.left, rect.bottom - rect.top
if w <= 0 or h <= 0:
    raise SystemExit("窗口尺寸异常：%dx%d" % (w, h))

src = user32.GetWindowDC(hwnd)
mem = gdi32.CreateCompatibleDC(src)
bmp = gdi32.CreateCompatibleBitmap(src, w, h)
gdi32.SelectObject(mem, bmp)

# PW_RENDERFULLCONTENT(2)：让窗口自己把内容渲染到位图里，被压住也能截对。
# egui 走的是 GPU 合成，这个标志未必有效，所以失败（或整张全黑）就退回 BitBlt。
ok = user32.PrintWindow(hwnd, mem, 2)
if not ok:
    ok = gdi32.BitBlt(mem, 0, 0, w, h, src, 0, 0, SRCCOPY)

bi = BITMAPINFO()
bi.bmiHeader.biSize = ctypes.sizeof(BITMAPINFOHEADER)
bi.bmiHeader.biWidth = w
bi.bmiHeader.biHeight = -h  # 负数 = 自上而下
bi.bmiHeader.biPlanes = 1
bi.bmiHeader.biBitCount = 32
bi.bmiHeader.biCompression = BI_RGB

buf = ctypes.create_string_buffer(w * h * 4)
lines = gdi32.GetDIBits(mem, bmp, 0, h, buf, ctypes.byref(bi), DIB_RGB_COLORS)

gdi32.DeleteObject(bmp)
gdi32.DeleteDC(mem)
user32.ReleaseDC(hwnd, src)

if not ok or lines == 0:
    raise SystemExit("BitBlt/GetDIBits 失败：bitblt=%s lines=%s" % (ok, lines))

img = Image.frombuffer("RGBA", (w, h), buf, "raw", "BGRA", 0, 1).convert("RGB")

# PrintWindow 对 GPU 合成的窗口有时会返回全黑 —— 这时候没有更好的办法，
# 只能报错，让人把窗口露出来再用（不要静默存一张黑图）。
if not img.getbbox():
    raise SystemExit("截到的是空图：PrintWindow 对这个窗口无效，请把窗口露出来再截")

img.save(OUT)
print("saved %s (%dx%d)" % (OUT, w, h))
