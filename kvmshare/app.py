"""Daemon wiring."""
from __future__ import annotations

import asyncio
import json
import logging
import logging.handlers
import os
import secrets
import socket
import struct
import sys
import time

from . import config as C
from .clipsync import ClipboardSync
from .discovery import Discovery
from .filetransfer import FileService
from .metrics import Metrics
from .notifier import notify
from .router import Router
from .security import Identity, PairedStore
from .session import Outbox, PeerLink
from .topology import Monitor, Rect

log = logging.getLogger("kvmshare")


class NullPlatform:
    """Headless stand-in (non-Windows dev/testing): no hooks, no injection."""
    def __init__(self, cfg): self._pos = (0, 0)
    def start(self, router): pass
    def stop(self): pass
    def monitors(self): return [Monitor(Rect(0, 0, 1920, 1080), 96, True, "null")]
    def refresh_monitors(self): pass
    def cursor_pos(self): return self._pos
    def move_abs(self, x, y): self._pos = (x, y)
    def button(self, *a): pass
    def wheel(self, *a): pass
    def key(self, *a): pass
    def begin_capture(self): return (960, 540)
    def end_capture(self): pass
    def recenter(self, p): pass
    monitors_cb = power_cb = secure_cb = None
    def bench_local(self, n=0): return {"error": "not on Windows"}


class NullClipboard:
    def start(self, cb): pass
    def read(self): return None
    def write(self, fm): pass
    def write_files(self, p): pass


def setup_logging(cfg):
    h = logging.handlers.RotatingFileHandler(C.data_dir() / "kvmshare.log", maxBytes=1_000_000, backupCount=3, encoding="utf-8")
    h.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
    root = logging.getLogger()
    root.setLevel(cfg["log_level"])
    root.addHandler(h)
    if sys.stderr and sys.stderr.isatty():
        root.addHandler(logging.StreamHandler())


class Daemon:
    def __init__(self, cfg):
        self.cfg = cfg
        if not cfg.get("role"):
            raise SystemExit("No role configured. Run `python -m kvmshare pair` first.")
        self.d = C.data_dir()
        self.ident = Identity.load_or_create(self.d)
        self.store = PairedStore(self.d)
        self.metrics = Metrics()
        self.token = self._token("control.token")
        self.ext_token = bytes.fromhex(self._token("external.token", 16))

    def _token(self, name, nbytes=32):
        p = self.d / name
        if not p.exists():
            fd = os.open(p, os.O_WRONLY | os.O_CREAT, 0o600)
            with os.fdopen(fd, "w") as f:
                f.write(secrets.token_hex(nbytes))
        return p.read_text().strip()

    async def run(self):
        loop = asyncio.get_running_loop()
        cfg = self.cfg
        if sys.platform == "win32":
            from . import win32
            from .winio import WinPlatform
            from .winclip import WinClipboard
            win32.set_dpi_aware()
            self.platform, self.clipbe = WinPlatform(cfg), WinClipboard()
        else:
            self.platform, self.clipbe = NullPlatform(cfg), NullClipboard()
        self.outbox = Outbox(loop, cfg["metrics"]["stamp_moves"])
        self.router = Router(cfg, self.platform, self.outbox, self.metrics, self.ident.device_id)
        self.router.machine = cfg["role"]
        self.router.set_layout(cfg["role"], self.platform.monitors())
        self.router.pos = self.platform.cursor_pos()
        self.link = PeerLink(cfg, self.ident, self.store, self.router, self.metrics, self.outbox, self.platform.monitors)
        self.files = FileService(cfg, self.link, notify, self.metrics, self.clipbe)
        self.clip = ClipboardSync(cfg, self.clipbe, self.link, self.files, notify, self.metrics, self.ident.device_id)
        self.router.on_clip_hotkey = lambda: loop.call_soon_threadsafe(self.clip.set_paused, not self.clip.paused)
        self.router.on_split_hotkey = lambda: loop.call_soon_threadsafe(self.toggle_split)
        self.link.handlers["split"] = self._on_split
        self.platform.monitors_cb = lambda: loop.call_soon_threadsafe(self._layout_changed)
        self.platform.power_cb = lambda ev: loop.call_soon_threadsafe(self._power, ev)
        self.platform.secure_cb = lambda s: loop.call_soon_threadsafe(self._secure, s)
        self.link.on_up = self._on_link_up
        await self.link.start()
        self.platform.start(self.router)
        from concurrent.futures import ThreadPoolExecutor
        self._pool = ThreadPoolExecutor(2, thread_name_prefix="clip")
        self.clipbe.start(lambda: self._pool.submit(self.clip.on_local_change))
        self.disc = Discovery(cfg, self.ident.device_id, self._beacon)
        try:
            await self.disc.start()
        except OSError as e:
            log.warning("discovery unavailable (%s); set peer_address in config.json", e)
        from .control import Control, ExternalInput
        self.control = Control(self)
        await self.control.start()
        await ExternalInput.start(self, loop)
        self.metrics.start_sampler()
        log.info("kvmshare %s up as %r (%s)", __import__("kvmshare").__version__, cfg["role"], self.ident.device_id)
        self._stop = asyncio.Event()
        await self._stop.wait()
        self.platform.stop()
        await self.link.stop()

    def _on_link_up(self):
        self.link.send_json({"t": "secure", "active": self.router.sec_local})
        if not self.router.input_enabled:                      # we are in split mode: tell the peer
            self.link.send_json({"t": "split", "on": True})

    # ---- split mode: both computers independent (no pointer/keyboard forwarding) ----
    def toggle_split(self):
        self.set_split(self.router.input_enabled)               # enabled -> go split; split -> rejoin

    def set_split(self, on: bool):
        r = self.router
        if on:
            r.set_input_enabled(False)
            self.link.send_json({"t": "split", "on": True})
            notify("KvmShare", "Split mode: each computer is independent")
        else:
            epoch = max(r.epoch, r.peer_epoch) + 1000           # larger than anything the peer has seen
            r.set_input_enabled(True, owner_local=True, epoch=epoch)   # this machine keeps the pointer
            self.link.send_json({"t": "split", "on": False, "epoch": epoch})
            notify("KvmShare", "Shared pointer restored")

    def _on_split(self, msg):
        r = self.router
        if msg.get("on"):
            r.set_input_enabled(False)
            notify("KvmShare", "Split mode: each computer is independent")
        else:
            ep = msg.get("epoch")
            if isinstance(ep, int) and 0 <= ep < 2 ** 32:
                r.set_input_enabled(True, owner_local=False, epoch=ep)
                notify("KvmShare", "Shared pointer restored")

    def _beacon(self, did, ip, port):
        if any(d["id"] == did for d in self.store.all()):
            self.link.addr_hint = (ip, port)
            if not self.link.connected:
                self.link.wake()

    def _layout_changed(self):
        mons = self.platform.monitors()
        self.router.set_layout(self.cfg["role"], mons)
        self.link.send_json({"t": "layout", "layout": [m.to_dict() for m in mons]})

    def _power(self, ev):
        log.info("power event: %s", ev)
        if ev == "suspend":
            self.link.drop()                       # peer releases keys / restores control immediately
        else:
            self.platform.refresh_monitors()
            self._layout_changed()
            self.link.wake()

    def _secure(self, active):
        self.router.set_secure_local(active)
        self.link.send_json({"t": "secure", "active": active})

    def reload(self):
        self.store.reload()
        self.link.reload_trust()
        if self.link.peer and not self.store.by_fp(self.link.peer["fp"]):
            self.link.drop()                       # revoked while connected