"""Windows clipboard backend (own thread + own window for WM_CLIPBOARDUPDATE)."""
from __future__ import annotations

import ctypes
import logging
import struct
import threading
import time
from typing import Callable, Dict, List, Optional

from . import win32 as W
from .clipsync import Snapshot

log = logging.getLogger("kvmshare.winclip")
CF_UNICODETEXT, CF_DIB, CF_HDROP, CF_DIBV5 = 13, 8, 15, 17
GMEM_MOVEABLE = 2
_STD = {1: "CF_TEXT", 2: "CF_BITMAP", 3: "CF_METAFILEPICT", 7: "CF_OEMTEXT", 14: "CF_ENHMETAFILE",
        16: "CF_LOCALE", 0x82: "CF_DSPBITMAP", 0x83: "CF_DSPMETAFILEPICT"}
_IGNORED_NAMES = {"Preferred DropEffect", "Shell IDList Array", "DataObject", "OwnerLink", "Ole Private Data",
                  "Locale", "CF_LOCALE", "CF_OEMTEXT", "CF_TEXT", "CF_BITMAP", "CanIncludeInClipboardHistory",
                  "CanUploadToCloudClipboard", "ExcludeClipboardContentFromMonitorProcessing",
                  "Clipboard Viewer Ignore"}


class WinClipboard:
    def __init__(self):
        self.on_change: Optional[Callable[[], None]] = None
        self.f_html = W.user32.RegisterClipboardFormatW("HTML Format")
        self.f_rtf = W.user32.RegisterClipboardFormatW("Rich Text Format")
        self.f_drop_effect = W.user32.RegisterClipboardFormatW("Preferred DropEffect")
        self.f_png = W.user32.RegisterClipboardFormatW("PNG")
        self.f_exclude = W.user32.RegisterClipboardFormatW("ExcludeClipboardContentFromMonitorProcessing")
        self.hwnd = None
        self._ready = threading.Event()
        self._timer_pending = False
        self._self_seqs = []

    def is_self_write(self) -> bool:
        """True if the current clipboard state is the result of our own write."""
        return self.sequence() in self._self_seqs

    def _remember(self, seq: int) -> int:
        self._self_seqs = (self._self_seqs + [seq])[-8:]
        return seq

    def start(self, on_change: Callable[[], None]):
        self.on_change = on_change
        threading.Thread(target=self._main, name="clipboard", daemon=True).start()
        self._ready.wait(5)

    def _main(self):
        hinst = W.kernel32.GetModuleHandleW(None)
        self._proc = W.WNDPROC(self._wnd)
        wc = W.WNDCLASSW()
        wc.lpfnWndProc, wc.hInstance, wc.lpszClassName = self._proc, hinst, "KvmShareClip"
        W.user32.RegisterClassW(ctypes.byref(wc))
        self.hwnd = W.user32.CreateWindowExW(0, "KvmShareClip", "kvmshare-clip", 0, 0, 0, 0, 0,
                                             ctypes.c_void_p(-3), None, hinst, None)
        W.user32.AddClipboardFormatListener(self.hwnd)
        self._ready.set()
        msg = W.wt.MSG()
        while W.user32.GetMessageW(ctypes.byref(msg), None, 0, 0) > 0:
            W.user32.TranslateMessage(ctypes.byref(msg))
            W.user32.DispatchMessageW(ctypes.byref(msg))

    def _wnd(self, hwnd, msg, wp, lp):
        if msg == W.WM_CLIPBOARDUPDATE:
            if not self._timer_pending:              # debounce bursts (apps set several formats)
                self._timer_pending = True
                W.user32.SetTimer(hwnd, 77, 40, None)
            return 0
        if msg == W.WM_TIMER and wp == 77:
            self._timer_pending = False
            W.user32.KillTimer(hwnd, 77) if hasattr(W.user32, "KillTimer") else None
            try:
                if self.on_change:
                    self.on_change()
            except Exception:                        # noqa: BLE001
                log.exception("clipboard handler")
            return 0
        return W.user32.DefWindowProcW(hwnd, msg, wp, lp)

    # ------------------------------------------------------------ helpers
    def _open(self, owner=None) -> bool:
        for _ in range(20):                          # another app may hold it briefly
            if W.user32.OpenClipboard(owner):
                return True
            time.sleep(0.01)
        return False

    @staticmethod
    def _bytes(fmt: int) -> Optional[bytes]:
        h = W.user32.GetClipboardData(fmt)
        if not h:
            return None
        p = W.kernel32.GlobalLock(h)
        if not p:
            return None
        try:
            return ctypes.string_at(p, W.kernel32.GlobalSize(h))
        finally:
            W.kernel32.GlobalUnlock(h)

    def _name(self, fmt: int) -> str:
        if fmt in _STD:
            return _STD[fmt]
        buf = ctypes.create_unicode_buffer(128)
        if W.user32.GetClipboardFormatNameW(fmt, buf, 128):
            return buf.value
        return f"format-{fmt}"

    def sequence(self) -> int:
        return W.user32.GetClipboardSequenceNumber()

    # --------------------------------------------------------------- read
    def read(self) -> Optional[Snapshot]:
        if not self._open():
            return None
        snap = Snapshot()
        try:
            fmts, f = [], 0
            while True:
                f = W.user32.EnumClipboardFormats(f)
                if not f:
                    break
                fmts.append(f)
            if self.f_exclude in fmts:               # password managers ask not to be monitored: respect it
                return None
            if CF_HDROP in fmts:
                raw = self._bytes(CF_HDROP)
                if raw:
                    snap.files = self._parse_hdrop(raw)
                    return snap
            if CF_UNICODETEXT in fmts:
                raw = self._bytes(CF_UNICODETEXT)
                if raw is not None:
                    snap.formats["text"] = raw.decode("utf-16-le", "replace").split("\x00", 1)[0].encode("utf-8")
            if self.f_html in fmts:
                raw = self._bytes(self.f_html)
                if raw:
                    snap.formats["html"] = raw.split(b"\x00", 1)[0]
            if self.f_rtf in fmts:
                raw = self._bytes(self.f_rtf)
                if raw:
                    snap.formats["rtf"] = raw.split(b"\x00", 1)[0]
            for fmt in (CF_DIBV5, CF_DIB):
                if fmt in fmts:
                    raw = self._bytes(fmt)
                    if raw:
                        snap.formats["image"] = raw
                        break
            handled = {CF_UNICODETEXT, CF_DIB, CF_DIBV5, CF_HDROP, self.f_html, self.f_rtf, 1, 7, 16, 2}
            for fmt in fmts:
                if fmt not in handled:
                    n = self._name(fmt)
                    if n not in _IGNORED_NAMES:
                        snap.unsupported.append(n)
            return snap
        finally:
            W.user32.CloseClipboard()

    @staticmethod
    def _parse_hdrop(raw: bytes) -> List[str]:
        off, = struct.unpack_from("<I", raw, 0)
        wide, = struct.unpack_from("<I", raw, 16)
        data = raw[off:]
        txt = data.decode("utf-16-le" if wide else "mbcs", "replace")
        return [p for p in txt.split("\x00") if p]

    # -------------------------------------------------------------- write
    def _set(self, fmt: int, payload: bytes):
        h = W.kernel32.GlobalAlloc(GMEM_MOVEABLE, len(payload))
        p = W.kernel32.GlobalLock(h)
        ctypes.memmove(p, payload, len(payload))
        W.kernel32.GlobalUnlock(h)
        if not W.user32.SetClipboardData(fmt, h):
            W.kernel32.GlobalFree(h)

    def write(self, fm: Dict[str, bytes]) -> int:
        if not self._open():
            raise OSError("clipboard busy")
        try:
            W.user32.EmptyClipboard()
            if "text" in fm:
                self._set(CF_UNICODETEXT, fm["text"].decode("utf-8", "replace").encode("utf-16-le") + b"\x00\x00")
            if "html" in fm:
                self._set(self.f_html, fm["html"] + b"\x00")
            if "rtf" in fm:
                self._set(self.f_rtf, fm["rtf"] + b"\x00")
            if "image" in fm:
                hdr = struct.unpack_from("<I", fm["image"], 0)[0] if len(fm["image"]) >= 4 else 0
                self._set(CF_DIBV5 if hdr == 124 else CF_DIB, fm["image"])
        finally:
            W.user32.CloseClipboard()
        return self._remember(self.sequence())

    def write_files(self, paths: List[str]) -> int:
        """Put staged files on the clipboard as a normal 'copied files' list."""
        names = ("\x00".join(paths) + "\x00\x00").encode("utf-16-le")
        dropfiles = struct.pack("<IiiII", 20, 0, 0, 0, 1) + names
        if not self._open():
            raise OSError("clipboard busy")
        try:
            W.user32.EmptyClipboard()
            self._set(CF_HDROP, dropfiles)
            self._set(self.f_drop_effect, struct.pack("<I", 1))      # DROPEFFECT_COPY
        finally:
            W.user32.CloseClipboard()
        return self._remember(self.sequence())
