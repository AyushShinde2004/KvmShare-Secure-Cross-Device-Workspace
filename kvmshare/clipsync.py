"""Clipboard synchronisation core (OS access lives behind `backend`).

Loop / staleness protection
  * Every local change bumps a Lamport counter -> version (counter, device_id).
    A remote update older than what we already have is ignored, so slow links can
    never overwrite newer content with stale data.
  * Content hash of the last applied/sent payload suppresses echo notifications
    caused by our own clipboard writes (plus the OS sequence number).
Privacy
  * Content is never logged (only format names and sizes).
  * `paused` (hotkey / `kvmshare privacy on`) stops both sending and applying.
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import logging
import time
import zlib
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from . import protocol as P

log = logging.getLogger("kvmshare.clip")
FORMATS = ("text", "html", "rtf", "image")


@dataclass
class Snapshot:
    formats: Dict[str, bytes] = field(default_factory=dict)
    files: List[str] = field(default_factory=list)
    unsupported: List[str] = field(default_factory=list)


def _hash(fm: Dict[str, bytes]) -> str:
    h = hashlib.sha256()
    for k in sorted(fm):
        h.update(k.encode() + b"\0" + str(len(fm[k])).encode() + b"\0" + fm[k])
    return h.hexdigest()


def _inflate(b: bytes, limit: int) -> bytes:
    d = zlib.decompressobj()
    out = d.decompress(b, limit + 1)
    if len(out) > limit or d.unconsumed_tail:
        raise ValueError("clipboard payload exceeds limit")
    return out


class ClipboardSync:
    def __init__(self, cfg: dict, backend, link, files, notify, metrics, my_id: str):
        self.cfg, self.backend, self.link, self.files = cfg, backend, link, files
        self.notify, self.metrics, self.my_id = notify, metrics, my_id
        self.c = cfg["clipboard"]
        self.enabled = bool(cfg["features"]["clipboard"])
        self.paused = bool(self.c["paused"])
        self.counter = 0
        self.version = (0, "")
        self.last_hash: Optional[str] = None
        self.sent_at: Dict[tuple, float] = {}
        self._warned: set = set()
        self.lock = asyncio.Lock() if False else None
        link.handlers["clip"] = self._on_small
        link.handlers["clip_ack"] = self._on_ack
        link.aux_handlers["clip"] = self._on_stream

    # ------------------------------------------------------------ limits
    def _limit(self, name: str) -> int:
        return int((self.c["max_image_mb"] if name == "image" else self.c["max_text_mb"]) * 1048576)

    def set_paused(self, on: bool):
        self.paused = on
        self.notify("Clipboard sync", "paused (privacy mode)" if on else "resumed")

    # --------------------------------------------------- local -> remote
    def on_local_change(self):
        """Called by the backend thread when the OS clipboard changed."""
        if not self.enabled or self.paused:
            return
        if getattr(self.backend, "is_self_write", lambda: False)():
            return
        try:
            snap = self.backend.read()
        except Exception:                                   # noqa: BLE001
            log.exception("clipboard read failed")
            return
        if snap is None:
            return
        if snap.files:
            if self.files is not None and self.link.connected:
                self.files.offer_paths(snap.files)           # we are on a worker thread already
            return
        fm = {k: v for k, v in snap.formats.items()
              if k in self.c["formats"] and len(v) <= self._limit(k)}
        skipped = [k for k in snap.formats if k not in fm]
        if snap.unsupported or skipped:
            names = sorted(set(snap.unsupported) | set(f"{k} (too large/disabled)" for k in skipped))
            log.info("clipboard formats not synced: %s", ", ".join(names))
            key = tuple(names)
            if not fm and key not in self._warned:
                self._warned.add(key)
                self.notify("Clipboard", "Not synced: " + ", ".join(names[:5]))
        if not fm:
            return
        h = _hash(fm)
        if h == self.last_hash:
            return
        self.last_hash = h
        self.send(fm)

    def send(self, fm: Dict[str, bytes]) -> Optional[tuple]:
        if not self.link.connected:
            return None
        self.counter = max(self.counter, self.version[0]) + 1
        ver = (self.counter, self.my_id)
        self.version = ver
        blobs = []
        for name, raw in fm.items():
            z = zlib.compress(raw, 1) if len(raw) > 512 else raw
            if len(z) < len(raw):
                blobs.append((name, z, True, len(raw)))
            else:
                blobs.append((name, raw, False, len(raw)))
        self.sent_at[ver] = time.perf_counter()
        total = sum(len(b[1]) for b in blobs)
        if total <= self.c["inline_limit_kb"] * 1024:
            self.link.send_json({"t": "clip", "ver": list(ver), "f": [
                {"n": n, "z": z, "raw": rl, "d": base64.b64encode(d).decode()} for n, d, z, rl in blobs]})
        else:
            asyncio.run_coroutine_threadsafe(self._send_stream(ver, blobs), self.link.loop)
        self.metrics.count("clip_sent")
        log.info("clipboard sent: %s, %d bytes on wire", ",".join(fm), total)
        return ver

    async def _send_stream(self, ver, blobs):
        try:
            r, w = await self.link.open_aux("clip", {"ver": list(ver), "f": [
                {"n": n, "z": z, "raw": rl, "len": len(d)} for n, d, z, rl in blobs]})
            try:
                for _, d, _, _ in blobs:
                    for i in range(0, len(d), 1 << 20):
                        w.write(P.frame(P.T_DATA, d[i:i + (1 << 20)]))
                        await w.drain()
                await asyncio.wait_for(r.read(1), 60)          # peer closes when applied
            finally:
                w.close()
        except Exception as e:                                  # noqa: BLE001
            log.warning("large clipboard send failed: %s", type(e).__name__)

    # --------------------------------------------------- remote -> local
    def _on_small(self, msg: dict):
        try:
            fm = {}
            for f in msg["f"][:8]:
                n = f["n"]
                if n not in FORMATS or n not in self.c["formats"]:
                    continue
                d = base64.b64decode(f["d"], validate=True)
                fm[n] = _inflate(d, self._limit(n)) if f["z"] else d
                if len(fm[n]) > self._limit(n):
                    raise ValueError("too large")
            self.link.loop.run_in_executor(None, self._apply, tuple(msg["ver"]), fm)   # OS clipboard write may block
        except (KeyError, ValueError, TypeError):
            self.metrics.count("clip_rejected")

    async def _on_stream(self, reader, writer, hdr: dict):
        try:
            fm = {}
            specs = hdr["f"][:8]
            for f in specs:
                n, ln = f["n"], int(f["len"])
                lim = self._limit(n) if n in FORMATS else 0
                if n not in FORMATS or n not in self.c["formats"] or ln > lim or ln < 0 or int(f["raw"]) > lim:
                    raise ValueError("rejected")
                buf = bytearray()
                while len(buf) < ln:
                    t, body = await asyncio.wait_for(P.read_frame(reader, P.MAX_DATA_FRAME), 30)
                    if t != P.T_DATA or len(buf) + len(body) > ln:
                        raise ValueError("bad stream")
                    buf += body
                fm[n] = _inflate(bytes(buf), lim) if f["z"] else bytes(buf)
            loop = asyncio.get_running_loop()
            await loop.run_in_executor(None, self._apply, tuple(hdr["ver"]), fm)
        except (KeyError, ValueError, TypeError, asyncio.TimeoutError, asyncio.IncompleteReadError, P.ProtocolError):
            self.metrics.count("clip_rejected")
        finally:
            writer.close()

    def _apply(self, ver: tuple, fm: Dict[str, bytes]):
        if not self.enabled or self.paused or not fm:
            return
        ver = (int(ver[0]), str(ver[1]))
        if ver <= self.version:
            self.metrics.count("clip_stale_ignored")
            return
        t0 = time.perf_counter()
        self.version = ver
        self.counter = max(self.counter, ver[0])
        self.last_hash = _hash(fm)                              # our own write must not bounce back
        self.backend.write(fm)
        ms = (time.perf_counter() - t0) * 1000
        self.metrics.observe("clip_apply_ms", ms)
        self.link.send_json({"t": "clip_ack", "ver": list(ver), "ms": round(ms, 2)})

    def _on_ack(self, msg: dict):
        t0 = self.sent_at.pop(tuple(msg.get("ver", ())), None) if isinstance(msg.get("ver"), list) else None
        if t0 is not None:
            self.metrics.observe("clip_roundtrip_ms", (time.perf_counter() - t0) * 1000)

    async def bench(self, n: int, size: int) -> dict:
        """Propagation time: local send -> peer clipboard write -> ack."""
        import os
        for i in range(n):
            self.send({"text": base64.b64encode(os.urandom(size * 3 // 4)).decode().encode()})
            await asyncio.sleep(0.4)
        return self.metrics.snapshot()["hist"].get("clip_roundtrip_ms", {})
