"""Thin ctypes bindings. Import only on Windows."""
import ctypes
import sys
from ctypes import wintypes as wt

assert sys.platform == "win32", "win32 bindings are Windows-only"

user32 = ctypes.WinDLL("user32", use_last_error=True)
kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
shcore = ctypes.WinDLL("shcore", use_last_error=True)

LRESULT, WPARAM, LPARAM = ctypes.c_ssize_t, ctypes.c_size_t, ctypes.c_ssize_t
HOOKPROC = ctypes.WINFUNCTYPE(LRESULT, ctypes.c_int, WPARAM, LPARAM)
WNDPROC = ctypes.WINFUNCTYPE(LRESULT, ctypes.c_void_p, ctypes.c_uint, WPARAM, LPARAM)
MONITORENUMPROC = ctypes.WINFUNCTYPE(wt.BOOL, ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(wt.RECT), LPARAM)

WH_KEYBOARD_LL, WH_MOUSE_LL = 13, 14
MARKER = 0x4B564D53          # 'KVMS' in dwExtraInfo: "this event was injected by us"

WM_APP, WM_TIMER, WM_DISPLAYCHANGE, WM_POWERBROADCAST, WM_SETCURSOR = 0x8000, 0x113, 0x7E, 0x218, 0x20
WM_CLIPBOARDUPDATE, WM_QUIT = 0x31D, 0x12
PBT_APMSUSPEND, PBT_APMRESUMEAUTOMATIC = 4, 0x12

INPUT_MOUSE, INPUT_KEYBOARD = 0, 1
MOUSEEVENTF = dict(MOVE=1, LEFTDOWN=2, LEFTUP=4, RIGHTDOWN=8, RIGHTUP=0x10, MIDDLEDOWN=0x20, MIDDLEUP=0x40,
                   XDOWN=0x80, XUP=0x100, WHEEL=0x800, HWHEEL=0x1000, VIRTUALDESK=0x4000, ABSOLUTE=0x8000)
KEYEVENTF_EXTENDEDKEY, KEYEVENTF_KEYUP, KEYEVENTF_SCANCODE = 1, 2, 8

SM_XVIRTUALSCREEN, SM_YVIRTUALSCREEN, SM_CXVIRTUALSCREEN, SM_CYVIRTUALSCREEN = 76, 77, 78, 79


class POINT(ctypes.Structure):
    _fields_ = [("x", ctypes.c_long), ("y", ctypes.c_long)]


class MSLLHOOKSTRUCT(ctypes.Structure):
    _fields_ = [("pt", POINT), ("mouseData", wt.DWORD), ("flags", wt.DWORD), ("time", wt.DWORD),
                ("dwExtraInfo", ctypes.c_size_t)]


class KBDLLHOOKSTRUCT(ctypes.Structure):
    _fields_ = [("vkCode", wt.DWORD), ("scanCode", wt.DWORD), ("flags", wt.DWORD), ("time", wt.DWORD),
                ("dwExtraInfo", ctypes.c_size_t)]


class MOUSEINPUT(ctypes.Structure):
    _fields_ = [("dx", ctypes.c_long), ("dy", ctypes.c_long), ("mouseData", wt.DWORD), ("dwFlags", wt.DWORD),
                ("time", wt.DWORD), ("dwExtraInfo", ctypes.c_size_t)]


class KEYBDINPUT(ctypes.Structure):
    _fields_ = [("wVk", wt.WORD), ("wScan", wt.WORD), ("dwFlags", wt.DWORD), ("time", wt.DWORD),
                ("dwExtraInfo", ctypes.c_size_t)]


class HARDWAREINPUT(ctypes.Structure):
    _fields_ = [("uMsg", wt.DWORD), ("wParamL", wt.WORD), ("wParamH", wt.WORD)]


class _U(ctypes.Union):
    _fields_ = [("mi", MOUSEINPUT), ("ki", KEYBDINPUT), ("hi", HARDWAREINPUT)]


class INPUT(ctypes.Structure):
    _anonymous_ = ("u",)
    _fields_ = [("type", wt.DWORD), ("u", _U)]


class MONITORINFOEXW(ctypes.Structure):
    _fields_ = [("cbSize", wt.DWORD), ("rcMonitor", wt.RECT), ("rcWork", wt.RECT), ("dwFlags", wt.DWORD),
                ("szDevice", wt.WCHAR * 32)]


class WNDCLASSW(ctypes.Structure):
    _fields_ = [("style", wt.UINT), ("lpfnWndProc", WNDPROC), ("cbClsExtra", ctypes.c_int),
                ("cbWndExtra", ctypes.c_int), ("hInstance", ctypes.c_void_p), ("hIcon", ctypes.c_void_p),
                ("hCursor", ctypes.c_void_p), ("hbrBackground", ctypes.c_void_p),
                ("lpszMenuName", wt.LPCWSTR), ("lpszClassName", wt.LPCWSTR)]


def _sig(fn, res, *args):
    fn.restype, fn.argtypes = res, list(args)


_sig(user32.SetWindowsHookExW, ctypes.c_void_p, ctypes.c_int, HOOKPROC, ctypes.c_void_p, wt.DWORD)
_sig(user32.UnhookWindowsHookEx, wt.BOOL, ctypes.c_void_p)
_sig(user32.CallNextHookEx, LRESULT, ctypes.c_void_p, ctypes.c_int, WPARAM, LPARAM)
_sig(user32.GetMessageW, wt.BOOL, ctypes.POINTER(wt.MSG), ctypes.c_void_p, wt.UINT, wt.UINT)
_sig(user32.TranslateMessage, wt.BOOL, ctypes.POINTER(wt.MSG))
_sig(user32.DispatchMessageW, LRESULT, ctypes.POINTER(wt.MSG))
_sig(user32.PostMessageW, wt.BOOL, ctypes.c_void_p, wt.UINT, WPARAM, LPARAM)
_sig(user32.PostThreadMessageW, wt.BOOL, wt.DWORD, wt.UINT, WPARAM, LPARAM)
_sig(user32.RegisterClassW, wt.ATOM, ctypes.POINTER(WNDCLASSW))
_sig(user32.CreateWindowExW, ctypes.c_void_p, wt.DWORD, wt.LPCWSTR, wt.LPCWSTR, wt.DWORD, ctypes.c_int, ctypes.c_int,
     ctypes.c_int, ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p)
_sig(user32.DefWindowProcW, LRESULT, ctypes.c_void_p, wt.UINT, WPARAM, LPARAM)
_sig(user32.DestroyWindow, wt.BOOL, ctypes.c_void_p)
_sig(user32.SetLayeredWindowAttributes, wt.BOOL, ctypes.c_void_p, wt.DWORD, ctypes.c_ubyte, wt.DWORD)
_sig(user32.SetWindowPos, wt.BOOL, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_int, ctypes.c_int, ctypes.c_int,
     ctypes.c_int, wt.UINT)
_sig(user32.ShowWindow, wt.BOOL, ctypes.c_void_p, ctypes.c_int)
_sig(user32.SetCursor, ctypes.c_void_p, ctypes.c_void_p)
_sig(user32.SetCursorPos, wt.BOOL, ctypes.c_int, ctypes.c_int)
_sig(user32.GetCursorPos, wt.BOOL, ctypes.POINTER(POINT))
_sig(user32.SendInput, wt.UINT, wt.UINT, ctypes.POINTER(INPUT), ctypes.c_int)
_sig(user32.GetSystemMetrics, ctypes.c_int, ctypes.c_int)
_sig(user32.KillTimer, wt.BOOL, ctypes.c_void_p, ctypes.c_size_t)
_sig(user32.SetTimer, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_size_t, wt.UINT, ctypes.c_void_p)
_sig(user32.EnumDisplayMonitors, wt.BOOL, ctypes.c_void_p, ctypes.c_void_p, MONITORENUMPROC, LPARAM)
_sig(user32.GetMonitorInfoW, wt.BOOL, ctypes.c_void_p, ctypes.POINTER(MONITORINFOEXW))
_sig(user32.OpenInputDesktop, ctypes.c_void_p, wt.DWORD, wt.BOOL, wt.DWORD)
_sig(user32.CloseDesktop, wt.BOOL, ctypes.c_void_p)
_sig(user32.SetProcessDpiAwarenessContext, wt.BOOL, ctypes.c_void_p)
_sig(user32.OpenClipboard, wt.BOOL, ctypes.c_void_p)
_sig(user32.CloseClipboard, wt.BOOL)
_sig(user32.EmptyClipboard, wt.BOOL)
_sig(user32.GetClipboardData, ctypes.c_void_p, wt.UINT)
_sig(user32.SetClipboardData, ctypes.c_void_p, wt.UINT, ctypes.c_void_p)
_sig(user32.EnumClipboardFormats, wt.UINT, wt.UINT)
_sig(user32.GetClipboardFormatNameW, ctypes.c_int, wt.UINT, wt.LPWSTR, ctypes.c_int)
_sig(user32.RegisterClipboardFormatW, wt.UINT, wt.LPCWSTR)
_sig(user32.GetClipboardSequenceNumber, wt.DWORD)
_sig(user32.AddClipboardFormatListener, wt.BOOL, ctypes.c_void_p)
_sig(user32.RemoveClipboardFormatListener, wt.BOOL, ctypes.c_void_p)
_sig(kernel32.GlobalAlloc, ctypes.c_void_p, wt.UINT, ctypes.c_size_t)
_sig(kernel32.GlobalFree, ctypes.c_void_p, ctypes.c_void_p)
_sig(kernel32.GlobalLock, ctypes.c_void_p, ctypes.c_void_p)
_sig(kernel32.GlobalUnlock, wt.BOOL, ctypes.c_void_p)
_sig(kernel32.GlobalSize, ctypes.c_size_t, ctypes.c_void_p)
_sig(kernel32.GetModuleHandleW, ctypes.c_void_p, wt.LPCWSTR)
_sig(kernel32.GetCurrentThreadId, wt.DWORD)
_sig(shcore.GetDpiForMonitor, ctypes.c_long, ctypes.c_void_p, ctypes.c_int, ctypes.POINTER(wt.UINT), ctypes.POINTER(wt.UINT))


def set_dpi_aware():
    """Per-monitor v2: all coordinates are physical pixels (mixed-DPI correct)."""
    if not user32.SetProcessDpiAwarenessContext(ctypes.c_void_p(-4)):
        try:
            shcore.SetProcessDpiAwareness(2)
        except OSError:
            pass


def enum_monitors():
    from .topology import Monitor, Rect
    out = []

    def cb(hmon, hdc, rect, lparam):
        mi = MONITORINFOEXW()
        mi.cbSize = ctypes.sizeof(MONITORINFOEXW)
        user32.GetMonitorInfoW(hmon, ctypes.byref(mi))
        dx, dy = wt.UINT(96), wt.UINT(96)
        shcore.GetDpiForMonitor(hmon, 0, ctypes.byref(dx), ctypes.byref(dy))
        r = mi.rcMonitor
        out.append(Monitor(Rect(r.left, r.top, r.right - r.left, r.bottom - r.top), int(dx.value or 96),
                           bool(mi.dwFlags & 1), mi.szDevice))
        return True
    cbf = MONITORENUMPROC(cb)
    user32.EnumDisplayMonitors(None, None, cbf, 0)
    return out


def secure_desktop_active() -> bool:
    """True while UAC / lock screen / Ctrl+Alt+Del is showing (hooks and SendInput cannot reach it)."""
    h = user32.OpenInputDesktop(0, False, 0x0001)
    if not h:
        return True
    user32.CloseDesktop(h)
    return False
