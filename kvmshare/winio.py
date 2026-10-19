"""Windows input platform: low-level hooks, injection, cursor capture overlay.

Threading
  input thread  - owns the hooks, the overlay window and the message loop.
                  Hook callbacks only touch the Router (timed lock, no network).
  any thread    - injection (SendInput / SetCursorPos) is allowed from the
                  network thread. While injecting, `self.injecting` is raised so
                  our own hook ignores the resulting events (feedback-loop
                  prevention even for events without our dwExtraInfo marker,
                  and no deadlock: injected events are delivered to the hook
                  synchronously, the hook must not wait on a lock we hold).
"""
from __future__ import annotations

import ctypes
import logging
import threading
from typing import Callable, List, Optional, Tuple

from . import win32 as W
from .topology import Monitor

log = logging.getLogger("kvmshare.winio")
CMD_SHOW, CMD_HIDE, CMD_LAYOUT = 1, 2, 3
HC_ACTION = 0
WM_KEYDOWN_FAMILY = (0x100, 0x101, 0x104, 0x105)


class WinPlatform:
    def __init__(self, cfg: dict):
        self.cfg, self.icfg = cfg, cfg["input"]
        self.router = None
        self.injecting = 0
        self.tid = 0
        self.hwnd = self.overlay = None
        self.ready = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self.monitors_cb: Optional[Callable[[], None]] = None
        self.power_cb: Optional[Callable[[str], None]] = None
        self.secure_cb: Optional[Callable[[bool], None]] = None
        self._secure = False
        self._bench: Optional[Tuple[threading.Event, list]] = None
        # Enumerate now: the daemon reads monitors() BEFORE start(), an empty list means no topology
        self._mons: List[Monitor] = W.enum_monitors()

    # ------------------------------------------------------------ lifecycle
    def start(self, router):
        self.router = router
        self.refresh_monitors()
        self._thread = threading.Thread(target=self._main, name="input-hooks", daemon=True)
        self._thread.start()
        if not self.ready.wait(5):
            raise RuntimeError("input thread failed to start")

    def stop(self):
        if self.tid:
            W.user32.PostThreadMessageW(self.tid, W.WM_QUIT, 0, 0)

    def monitors(self) -> List[Monitor]:
        return list(self._mons)

    def refresh_monitors(self):
        self._mons = W.enum_monitors()

    def primary(self) -> Monitor:
        for m in self._mons:
            if m.primary:
                return m
        return self._mons[0]

    # --------------------------------------------------------- input thread
    def _main(self):
        self.tid = W.kernel32.GetCurrentThreadId()
        hinst = W.kernel32.GetModuleHandleW(None)
        self._wndproc = W.WNDPROC(self._on_wnd)
        wc = W.WNDCLASSW()
        wc.lpfnWndProc, wc.hInstance, wc.lpszClassName = self._wndproc, hinst, "KvmShareWnd"
        W.user32.RegisterClassW(ctypes.byref(wc))
        # hidden *top-level* window (message-only windows do not receive WM_POWERBROADCAST / WM_DISPLAYCHANGE)
        self.hwnd = W.user32.CreateWindowExW(0, "KvmShareWnd", "kvmshare", 0x80000000, 0, 0, 0, 0, None, None, hinst, None)
        # overlay: near-invisible, topmost, never activated; its only job is to show *no cursor*
        ex = 0x80000 | 0x8 | 0x80 | 0x08000000      # LAYERED | TOPMOST | TOOLWINDOW | NOACTIVATE
        self.overlay = W.user32.CreateWindowExW(ex, "KvmShareWnd", "kvmshare-overlay", 0x80000000, 0, 0, 1, 1,
                                                None, None, hinst, None)
        W.user32.SetLayeredWindowAttributes(self.overlay, 0, 1, 2)   # alpha 1/255, still hit-testable
        self._mouse_cb = W.HOOKPROC(self._mouse_proc)
        self._kbd_cb = W.HOOKPROC(self._kbd_proc)
        self._mh = W.user32.SetWindowsHookExW(W.WH_MOUSE_LL, self._mouse_cb, hinst, 0)
        self._kh = W.user32.SetWindowsHookExW(W.WH_KEYBOARD_LL, self._kbd_cb, hinst, 0)
        if not (self._mh and self._kh):
            log.error("could not install low-level hooks (error %d)", ctypes.get_last_error())
        W.user32.SetTimer(self.hwnd, 1, 250, None)
        self.ready.set()
        msg = W.wt.MSG()
        while W.user32.GetMessageW(ctypes.byref(msg), None, 0, 0) > 0:
            W.user32.TranslateMessage(ctypes.byref(msg))
            W.user32.DispatchMessageW(ctypes.byref(msg))
        for h in (self._mh, self._kh):
            if h:
                W.user32.UnhookWindowsHookEx(h)

    def _mouse_proc(self, n, wp, lp):
        if n == HC_ACTION:
            try:
                i = W.MSLLHOOKSTRUCT.from_address(lp)
                ours = self.injecting > 0 or i.dwExtraInfo == W.MARKER
                if self._bench and ours and wp == 0x200:
                    self._bench[1].append((i.pt.x, i.pt.y, __import__("time").perf_counter_ns()))
                    self._bench[0].set()
                if self.router.on_local_mouse(wp, i.pt.x, i.pt.y, i.mouseData, ours, bool(i.flags & 3)):
                    return 1
            except Exception:                                    # noqa: BLE001  never break the input chain
                log.exception("mouse hook")
        return W.user32.CallNextHookEx(None, n, wp, lp)

    def _kbd_proc(self, n, wp, lp):
        if n == HC_ACTION and wp in WM_KEYDOWN_FAMILY:
            try:
                i = W.KBDLLHOOKSTRUCT.from_address(lp)
                ours = self.injecting > 0 or i.dwExtraInfo == W.MARKER
                if self.router.on_local_key(i.vkCode, i.scanCode, i.flags, ours, bool(i.flags & 0x10)):
                    return 1
            except Exception:                                    # noqa: BLE001
                log.exception("keyboard hook")
        return W.user32.CallNextHookEx(None, n, wp, lp)

    def _on_wnd(self, hwnd, msg, wp, lp):
        try:
            if hwnd == self.overlay:
                if msg == W.WM_SETCURSOR:
                    W.user32.SetCursor(None)
                    return 1
            elif msg == W.WM_APP:
                self._cmd(int(wp))
                return 0
            elif msg == W.WM_TIMER:
                self.router.on_tick()
                sec = W.secure_desktop_active()
                if sec != self._secure:
                    self._secure = sec
                    if self.secure_cb:
                        self.secure_cb(sec)
                return 0
            elif msg == W.WM_DISPLAYCHANGE:
                self.refresh_monitors()
                if self.monitors_cb:
                    self.monitors_cb()
                return 0
            elif msg == W.WM_POWERBROADCAST:
                if wp == W.PBT_APMSUSPEND and self.power_cb:
                    self.power_cb("suspend")
                elif wp == W.PBT_APMRESUMEAUTOMATIC and self.power_cb:
                    self.power_cb("resume")
                return 1
        except Exception:                                        # noqa: BLE001
            log.exception("wndproc")
        return W.user32.DefWindowProcW(hwnd, msg, wp, lp)

    def _cmd(self, c: int):
        if c == CMD_SHOW:
            vx, vy = W.user32.GetSystemMetrics(W.SM_XVIRTUALSCREEN), W.user32.GetSystemMetrics(W.SM_YVIRTUALSCREEN)
            vw, vh = W.user32.GetSystemMetrics(W.SM_CXVIRTUALSCREEN), W.user32.GetSystemMetrics(W.SM_CYVIRTUALSCREEN)
            # HWND_TOPMOST=-1, SWP_NOACTIVATE|SWP_SHOWWINDOW
            W.user32.SetWindowPos(self.overlay, ctypes.c_void_p(-1), vx, vy, vw, vh, 0x10 | 0x40)
        elif c == CMD_HIDE:
            W.user32.ShowWindow(self.overlay, 0)

    # ------------------------------------------------- Platform interface
    def cursor_pos(self) -> Tuple[int, int]:
        p = W.POINT()
        W.user32.GetCursorPos(ctypes.byref(p))
        return p.x, p.y

    def move_abs(self, x: int, y: int):
        self.injecting += 1
        try:
            W.user32.SetCursorPos(int(x), int(y))
        finally:
            self.injecting -= 1

    def _send(self, inp: "W.INPUT"):
        self.injecting += 1
        try:
            W.user32.SendInput(1, ctypes.byref(inp), ctypes.sizeof(W.INPUT))
        finally:
            self.injecting -= 1

    def _mouse(self, flags: int, data: int = 0):
        i = W.INPUT(type=W.INPUT_MOUSE)
        i.mi = W.MOUSEINPUT(0, 0, data & 0xFFFFFFFF, flags, 0, W.MARKER)
        self._send(i)

    def button(self, btn: int, down: bool):
        E = W.MOUSEEVENTF
        table = {1: (E["LEFTDOWN"], E["LEFTUP"], 0), 2: (E["RIGHTDOWN"], E["RIGHTUP"], 0),
                 3: (E["MIDDLEDOWN"], E["MIDDLEUP"], 0), 4: (E["XDOWN"], E["XUP"], 1), 5: (E["XDOWN"], E["XUP"], 2)}
        d, u, data = table[btn]
        self._mouse(d if down else u, data)

    def wheel(self, dx: int, dy: int):
        if dy:
            self._mouse(W.MOUSEEVENTF["WHEEL"], dy)
        if dx:
            self._mouse(W.MOUSEEVENTF["HWHEEL"], dx)

    def key(self, vk: int, scan: int, up: bool, ext: bool):
        i = W.INPUT(type=W.INPUT_KEYBOARD)
        fl = (W.KEYEVENTF_KEYUP if up else 0) | (W.KEYEVENTF_EXTENDEDKEY if ext else 0)
        if self.icfg.get("key_mode") == "scancode":
            i.ki = W.KEYBDINPUT(0, scan, fl | W.KEYEVENTF_SCANCODE, 0, W.MARKER)
        else:
            i.ki = W.KEYBDINPUT(vk, scan, fl, 0, W.MARKER)
        self._send(i)

    def begin_capture(self) -> Tuple[int, int]:
        """Pointer left this machine: park it mid-screen and hide it."""
        m = self.primary().rect
        park = (m.x + m.w // 2, m.y + m.h // 2)
        self.move_abs(*park)
        if self.icfg.get("hide_cursor", True) and self.hwnd:
            W.user32.PostMessageW(self.hwnd, W.WM_APP, CMD_SHOW, 0)
        return park

    def end_capture(self):
        if self.hwnd:
            W.user32.PostMessageW(self.hwnd, W.WM_APP, CMD_HIDE, 0)

    def recenter(self, park: Tuple[int, int]):
        if self.cursor_pos() != park:
            self.move_abs(*park)

    # ----------------------------------------------------------- benchmark
    def bench_local(self, n: int = 500) -> dict:
        """Cost of the OS input path on this machine: injection call time and
        injection -> hook-callback latency (real kernel round trip)."""
        import time
        from .metrics import Histogram
        call, hook = Histogram(), Histogram()
        ev, rec = threading.Event(), []
        self._bench = (ev, rec)
        x0, y0 = self.cursor_pos()
        try:
            for k in range(n):
                ev.clear()
                rec.clear()
                t0 = time.perf_counter_ns()
                self.move_abs(x0 + (k % 40), y0)
                t1 = time.perf_counter_ns()
                call.add((t1 - t0) / 1000)
                if ev.wait(0.05) and rec:
                    hook.add((rec[0][2] - t0) / 1000)
                time.sleep(0.002)
        finally:
            self._bench = None
            self.move_abs(x0, y0)
        return {"inject_call_us": call.summary(), "inject_to_hook_us": hook.summary()}