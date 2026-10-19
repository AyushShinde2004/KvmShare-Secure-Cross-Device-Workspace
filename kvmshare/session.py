"""Peer link: persistent low-latency input channel + on-demand aux channels.

* One long-lived TLS 1.3 connection ("input") carries pointer/key events,
  heartbeats and small JSON messages. TCP_NODELAY is set.
* Aux connections ("clip", "xfer") are opened on demand so bulk data can never
  queue in front of a mouse move.
* The device with the lower id dials; both always listen. Either side may open
  aux channels.
"""
from __future__ import annotations

import asyncio
import ipaddress
import logging
import random
import socket
import ssl
import threading
import time
from collections import deque
from typing import Awaitable, Callable, Dict, Optional, Tuple

from . import protocol as P
from .security import Identity, PairedStore, fingerprint_der, session_context, trust_all
from .topology import Monitor

log = logging.getLogger("kvmshare.session")

HEARTBEAT_S = 1.0
DEAD_AFTER_S = 3.5


def _tune_socket(writer):
    """Best-effort socket tuning. Every option is optional: a failure here must never
    break a connection (the 1 s application heartbeat is the real liveness check)."""
    sock = writer.get_extra_info("socket")
    if sock is None:
        return

    def attempt(fn):
        try:
            fn()
        except (OSError, AttributeError, ValueError):
            pass
    attempt(lambda: sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1))
    attempt(lambda: sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1))
    # OS-level keepalive: first probe after 5 s, then every 1 s (Python 3.12+ on Windows exposes these)
    for name, val in (("TCP_KEEPIDLE", 5), ("TCP_KEEPINTVL", 1), ("TCP_KEEPCNT", 4)):
        if hasattr(socket, name):
            attempt(lambda n=name, v=val: sock.setsockopt(socket.IPPROTO_TCP, getattr(socket, n), v))
    # Older Windows Pythons: asyncio's TransportSocket hides ioctl, the wrapped socket still has it
    inner = getattr(sock, "_sock", None)
    if hasattr(socket, "SIO_KEEPALIVE_VALS") and inner is not None and hasattr(inner, "ioctl"):
        attempt(lambda: inner.ioctl(socket.SIO_KEEPALIVE_VALS, (1, 5000, 1000)))


def _private_ip(ip: str) -> bool:
    a = ipaddress.ip_address(ip.split("%")[0])
    if a.version == 6 and a.ipv4_mapped:
        a = a.ipv4_mapped
    return a.is_private or a.is_loopback or a.is_link_local


class Outbox:
    """Thread-safe producer side for the hook/network threads. Consecutive
    MOVE frames (and WHEEL frames) are merged, which is adaptive batching with
    zero added delay: the first event is flushed immediately, events that
    arrive while the loop is busy are folded into one frame."""

    MAX_BUFFER = 256 * 1024

    def __init__(self, loop: asyncio.AbstractEventLoop, stamp_moves: bool = False):
        self.loop, self.stamp = loop, stamp_moves
        self.dq: deque = deque()
        self.lock = threading.Lock()
        self.scheduled = False
        self.seq = 0
        self.writer: Optional[asyncio.StreamWriter] = None
        self.dropped = 0

    # ---- producers (any thread)
    def move(self, epoch, dx, dy):
        with self.lock:
            if self.dq and self.dq[-1][0] == "M" and self.dq[-1][1] == epoch:
                it = self.dq[-1]
                it[2] += dx
                it[3] += dy
            else:
                self.dq.append(["M", epoch, dx, dy, time.perf_counter_ns() if self.stamp else 0])
            self._kick()

    def wheel(self, epoch, dx, dy):
        with self.lock:
            if self.dq and self.dq[-1][0] == "W" and self.dq[-1][1] == epoch:
                it = self.dq[-1]
                it[2] += dx
                it[3] += dy
            else:
                self.dq.append(["W", epoch, dx, dy])
            self._kick()

    def button(self, epoch, btn, down):
        self._put(["B", epoch, btn, down])

    def key(self, epoch, vk, scan, flags):
        self._put(["K", epoch, vk, scan, flags])

    def enter(self, epoch, x, y):
        self._put(["E", epoch, x, y])

    def claim(self, epoch):
        self._put(["C", epoch])

    def send_json(self, obj: dict):
        self._put(["J", P.json_frame(obj)])

    def ping(self, pid: int):
        self._put(["P", pid, time.perf_counter_ns()])

    def _put(self, item):
        with self.lock:
            self.dq.append(item)
            self._kick()

    def _kick(self):                      # lock held
        if not self.scheduled:
            self.scheduled = True
            try:
                self.loop.call_soon_threadsafe(self._drain)
            except RuntimeError:          # loop closed during shutdown
                self.scheduled = False

    # ---- consumer (loop thread)
    def _encode(self, it) -> bytes:
        self.seq = (self.seq + 1) & 0xFFFFFFFF
        k = it[0]
        if k == "M":
            return P.pack(P.T_MOVE, it[1], self.seq, it[2], it[3], it[4])
        if k == "W":
            return P.pack(P.T_WHEEL, it[1], self.seq, it[2], it[3])
        if k == "B":
            return P.pack(P.T_BTN, it[1], self.seq, it[2], it[3])
        if k == "K":
            return P.pack(P.T_KEY, it[1], self.seq, it[2], it[3], it[4])
        if k == "E":
            return P.pack(P.T_ENTER, it[1], self.seq, it[2], it[3])
        if k == "C":
            return P.pack(P.T_CLAIM, it[1], self.seq)
        if k == "P":
            return P.pack(P.T_PING, it[1], it[2])
        return it[1]

    def _drain(self):
        w = self.writer
        with self.lock:
            items = list(self.dq)
            self.dq.clear()
            self.scheduled = False
        if w is None or w.is_closing():
            return
        if w.transport.get_write_buffer_size() > self.MAX_BUFFER:
            # Peer/Wi-Fi is congested: keep only the newest state instead of queueing stale motion.
            kept, dropped = [], 0
            for it in items:
                if it[0] == "M" and kept and kept[-1][0] == "M" and kept[-1][1] == it[1]:
                    kept[-1][2] += it[2]
                    kept[-1][3] += it[3]
                    dropped += 1
                else:
                    kept.append(it)
            self.dropped += dropped
            with self.lock:
                self.dq.extendleft(reversed(kept))
                if not self.scheduled:
                    self.scheduled = True
                    self.loop.call_later(0.004, self._drain)
            if w.transport.get_write_buffer_size() > 8 * self.MAX_BUFFER:
                w.close()
            return
        w.write(b"".join(self._encode(it) for it in items))


class _Bucket:
    def __init__(self, rate: float, burst: float):
        self.rate, self.burst, self.tokens, self.t = rate, burst, burst, time.monotonic()

    def take(self) -> bool:
        now = time.monotonic()
        self.tokens = min(self.burst, self.tokens + (now - self.t) * self.rate)
        self.t = now
        if self.tokens >= 1:
            self.tokens -= 1
            return True
        return False


class PeerLink:
    def __init__(self, cfg: dict, ident: Identity, store: PairedStore, router, metrics,
                 outbox: Outbox, layout_provider: Callable[[], list]):
        self.cfg, self.ident, self.store, self.router, self.metrics = cfg, ident, store, router, metrics
        self.outbox = outbox
        self.layout_provider = layout_provider
        self.loop = outbox.loop
        self.srv_ctx = self.cli_ctx = None
        self._server = None
        self.peer: Optional[dict] = None             # paired record of the connected peer
        self.peer_addr: Optional[Tuple[str, int]] = None
        self.addr_hint: Optional[Tuple[str, int]] = None
        self._writer: Optional[asyncio.StreamWriter] = None
        self._wake = asyncio.Event()
        self.handlers: Dict[str, Callable[[dict], None]] = {}
        self.aux_handlers: Dict[str, Callable[..., Awaitable]] = {}
        self.rtt_ms = 0.0
        self.offset_ns = 0
        self._best_rtt = 1 << 62
        self._pongs: Dict[int, asyncio.Future] = {}
        self._pid = 0
        self.down_at = time.monotonic()
        self.up_since: Optional[float] = None
        self._tasks = []
        self.stopping = False
        self.on_up: Optional[Callable[[], None]] = None
        self.on_down: Optional[Callable[[], None]] = None

    # ---------------------------------------------------------------- lifecycle
    async def start(self):
        self.srv_ctx = session_context(self.ident, self.store, server=True)
        self.cli_ctx = session_context(self.ident, self.store, server=False)
        self._server = await asyncio.start_server(
            self._on_conn, self.cfg["bind"], self.cfg["listen_port"], ssl=self.srv_ctx,
            ssl_handshake_timeout=5, reuse_address=True)
        self._tasks.append(asyncio.ensure_future(self._dial_loop()))

    async def stop(self):
        self.stopping = True
        for t in self._tasks:
            t.cancel()
        if self._writer:
            self._writer.close()
        if self._server:
            self._server.close()

    def reload_trust(self):
        """Pairing added a device: make the live contexts trust it. (Revocation
        is enforced by the post-handshake pin check, and by dropping the link.)"""
        trust_all(self.srv_ctx, self.store)
        trust_all(self.cli_ctx, self.store)
        self._wake.set()

    def drop(self):
        if self._writer:
            self._writer.close()

    def wake(self):
        self.loop.call_soon_threadsafe(self._wake.set)

    @property
    def connected(self) -> bool:
        return self.peer is not None and self._writer is not None and not self._writer.is_closing()

    # --------------------------------------------------------------- auth/dial
    def _authenticate(self, writer) -> Optional[dict]:
        peername = writer.get_extra_info("peername")
        if not peername or not _private_ip(peername[0]):
            log.warning("refusing non-private source address")
            return None
        sslobj = writer.get_extra_info("ssl_object")
        der = sslobj.getpeercert(binary_form=True) if sslobj else None
        if not der:
            return None
        dev = self.store.by_fp(fingerprint_der(der))
        if dev is None:
            log.warning("connection from unpaired/revoked certificate refused")
        return dev

    async def _on_conn(self, reader, writer):
        ch = None
        try:
            dev = self._authenticate(writer)
            if dev is None:
                writer.close()
                return
            _tune_socket(writer)
            t, body = await asyncio.wait_for(P.read_frame(reader, P.MAX_JSON_FRAME), 5)
            msg = P.decode(t, body) if t == P.T_JSON else {}
            ch = msg.get("channel")
            if ch == "input":
                await self._run_input(dev, reader, writer, writer.get_extra_info("peername"))
            elif ch in self.aux_handlers and self.connected and dev["id"] == self.peer["id"]:
                await self.aux_handlers[ch](reader, writer, msg)
            else:
                writer.close()
        except (asyncio.IncompleteReadError, ConnectionError, asyncio.TimeoutError, P.ProtocolError, ssl.SSLError, OSError):
            pass
        except Exception:                                     # noqa: BLE001
            log.exception("connection handler failed")
        finally:
            if ch != "input":
                writer.close()

    def _candidate_addrs(self):
        out = []
        if self.cfg.get("peer_address"):
            h, _, p = str(self.cfg["peer_address"]).partition(":")
            out.append((h, int(p or self.cfg["listen_port"])))
        if self.addr_hint:
            out.append(self.addr_hint)
        for d in self.store.all():
            la = d.get("last_addr")
            if la:
                out.append((la[0], la[1]))
        seen, uniq = set(), []
        for a in out:
            if a not in seen:
                seen.add(a)
                uniq.append(a)
        return uniq

    async def open_aux(self, channel: str, header: dict):
        """Open an authenticated aux channel to the connected peer."""
        if not self.connected or not self.peer_addr:
            raise ConnectionError("peer not connected")
        r, w = await asyncio.wait_for(asyncio.open_connection(
            *self.peer_addr, ssl=self.cli_ctx, server_hostname="kvmshare"), 5)
        dev = self._authenticate(w)
        if dev is None or dev["id"] != self.peer["id"]:
            w.close()
            raise ConnectionError("aux channel authenticated as a different device")
        _tune_socket(w)
        w.write(P.json_frame({"t": "open", "channel": channel, **header}))
        await w.drain()
        return r, w

    async def _sleep_or_wake(self, secs: float):
        try:
            await asyncio.wait_for(self._wake.wait(), secs)
        except asyncio.TimeoutError:
            pass
        self._wake.clear()

    async def _dial_loop(self):
        delay = 0.2
        while not self.stopping:
            try:
                peers = self.store.all()
                if self.connected or not peers:
                    await self._sleep_or_wake(0.5)
                    continue
                if not any(self.ident.device_id < d["id"] for d in peers):
                    await self._sleep_or_wake(1.0)           # the peer dials us
                    continue
                connected_once = False
                for addr in self._candidate_addrs():
                    try:
                        r, w = await asyncio.wait_for(asyncio.open_connection(
                            *addr, ssl=self.cli_ctx, server_hostname="kvmshare"), 3)
                    except (OSError, asyncio.TimeoutError, ssl.SSLError):
                        continue
                    dev = self._authenticate(w)
                    if dev is None:
                        w.close()
                        continue
                    _tune_socket(w)
                    w.write(P.json_frame({"t": "open", "channel": "input"}))
                    connected_once, delay = True, 0.2
                    try:
                        await self._run_input(dev, r, w, addr)
                    except (asyncio.IncompleteReadError, ConnectionError, asyncio.TimeoutError,
                            P.ProtocolError, ssl.SSLError, OSError):
                        pass
                    break
                if not connected_once:
                    await self._sleep_or_wake(delay)
                    delay = min(3.0, delay * 1.7) + random.random() * 0.1
            except asyncio.CancelledError:
                raise
            except Exception:                                  # noqa: BLE001
                log.exception("dial loop error")
                await asyncio.sleep(1)

    # ------------------------------------------------------------ input session
    def _hello(self) -> dict:
        return {"t": "hello", "v": 1, "id": self.ident.device_id, "name": self.cfg["device_name"],
                "role": self.cfg["role"], "port": self.cfg["listen_port"],
                "layout": [m.to_dict() for m in self.layout_provider()],
                "idle_ms": self.router.idle_ms(), "epoch": self.router.epoch}

    async def _run_input(self, dev: dict, reader, writer, addr):
        if self._writer is not None and not self._writer.is_closing():
            self._writer.close()                            # superseded (peer reconnected quickly)
            await asyncio.sleep(0.05)
        self._writer = writer
        self.outbox.writer = writer
        self.peer = dev
        host = addr[0]
        last_rx = time.monotonic()
        bucket = _Bucket(rate=8000, burst=4000)
        over = 0
        writer.write(P.json_frame(self._hello()))
        hello_ok = False
        hb = asyncio.ensure_future(self._heartbeat(writer))
        last_seq = None
        try:
            while True:
                t, body = await asyncio.wait_for(P.read_frame(reader, P.MAX_INPUT_FRAME), DEAD_AFTER_S)
                last_rx = time.monotonic()
                if t == P.T_JSON:
                    msg = P.decode(t, body)
                    k = msg.get("t")
                    if k == "hello" and not hello_ok:
                        if msg.get("id") != dev["id"] or not msg.get("role") or msg["role"] == self.cfg["role"]:
                            raise P.ProtocolError("hello does not match authenticated device")
                        hello_ok = True
                        port = int(msg.get("port", self.cfg["listen_port"]))
                        self.peer_addr = (host, port)
                        self.store.set_addr(dev["id"], [host, port])
                        mons = [Monitor.from_dict(d) for d in msg.get("layout", [])[:16]]
                        self.router.set_layout(msg["role"], mons)
                        self.router.on_link_up(dev["id"], msg["role"], int(msg.get("idle_ms", 1 << 30)),
                                               int(msg.get("epoch", 0)))
                        self.up_since = time.monotonic()
                        self.metrics.observe("reconnect_ms", (self.up_since - self.down_at) * 1000)
                        log.info("link up with %s (%s)", dev["name"], host)
                        if self.on_up:
                            self.on_up()
                    elif not hello_ok:
                        raise P.ProtocolError("expected hello")
                    elif k == "layout":
                        self.router.set_layout(self.peer["role"], [Monitor.from_dict(d) for d in msg.get("layout", [])[:16]])
                    elif k == "secure":
                        self.router.set_secure_peer(bool(msg.get("active")))
                    elif k in self.handlers:
                        self.handlers[k](msg)
                    continue
                if not hello_ok:
                    raise P.ProtocolError("input before hello")
                if not bucket.take():
                    over += 1
                    self.metrics.count("rate_limited")
                    if over > 2000:
                        raise P.ProtocolError("rate limit exceeded")
                    continue
                f = P.decode(t, body)
                if t == P.T_PING:
                    writer.write(P.pack(P.T_PONG, f[0], f[1], time.perf_counter_ns()))
                    continue
                if t == P.T_PONG:
                    self._on_pong(*f)
                    continue
                seq = f[1] if t in (P.T_MOVE, P.T_BTN, P.T_WHEEL, P.T_KEY, P.T_ENTER, P.T_CLAIM) else None
                if seq is not None:
                    if last_seq is not None and not P.seq_newer(seq, last_seq):
                        self.metrics.count("dup_or_old_dropped")
                        continue
                    last_seq = seq
                if t == P.T_MOVE:
                    self.router.on_peer_move(f[0], f[2], f[3], f[4], self.offset_ns)
                elif t == P.T_BTN:
                    self.router.on_peer_button(f[0], f[2], f[3])
                elif t == P.T_WHEEL:
                    self.router.on_peer_wheel(f[0], f[2], f[3])
                elif t == P.T_KEY:
                    self.router.on_peer_key(f[0], f[2], f[3], f[4])
                elif t == P.T_ENTER:
                    self.router.on_enter(f[0], f[2], f[3])
                elif t == P.T_CLAIM:
                    self.router.on_claim(f[0])
        finally:
            hb.cancel()
            if self._writer is writer:
                self._writer = None
                self.outbox.writer = None
                self.peer = None
                self.down_at = time.monotonic()
                self.up_since = None
                self.router.on_link_down()          # restores local control, releases injected keys
                if self.on_down:
                    self.on_down()
                log.info("link down")
            writer.close()

    async def _heartbeat(self, writer):
        try:
            while not writer.is_closing():
                self._pid = (self._pid + 1) & 0xFFFFFFFF
                self.outbox.ping(self._pid)
                await asyncio.sleep(HEARTBEAT_S)
        except asyncio.CancelledError:
            pass

    def _on_pong(self, pid: int, t_send: int, t_peer: int):
        now = time.perf_counter_ns()
        rtt = now - t_send
        fut = self._pongs.pop(pid, None)
        if fut and not fut.done():
            fut.set_result(rtt)
        self.rtt_ms = rtt / 1e6
        self.metrics.observe("rtt_ms", self.rtt_ms)
        if rtt <= self._best_rtt * 1.5 + 200_000:           # NTP-style: trust low-RTT samples
            self._best_rtt = min(self._best_rtt, rtt)
            self.offset_ns = t_peer - (t_send + rtt // 2)   # peer_clock - my_clock

    async def bench_ping(self, count: int, rate_hz: float) -> dict:
        """Measure round trip over the real input channel at a given event rate."""
        rtts, lost = [], 0
        for i in range(count):
            if not self.connected:
                break
            self._pid = (self._pid + 1) & 0xFFFFFFFF
            pid = self._pid
            fut = self.loop.create_future()
            self._pongs[pid] = fut
            self.outbox.ping(pid)
            try:
                rtts.append(await asyncio.wait_for(fut, 1.0) / 1e6)
            except asyncio.TimeoutError:
                lost += 1
                self._pongs.pop(pid, None)
            await asyncio.sleep(1.0 / rate_hz)
        s = sorted(rtts)

        def q(p):
            return s[min(len(s) - 1, int(p * len(s)))] if s else None
        mean = sum(s) / len(s) if s else None
        jitter = (sum(abs(a - b) for a, b in zip(rtts, rtts[1:])) / max(1, len(rtts) - 1)) if rtts else None
        return {"sent": count, "lost": lost, "rtt_ms": {"min": s[0] if s else None, "p50": q(.5), "p95": q(.95),
                                                         "p99": q(.99), "max": s[-1] if s else None, "mean": mean},
                "jitter_ms": jitter, "clock_offset_ms": self.offset_ns / 1e6}

    def send_json(self, obj: dict) -> bool:
        if not self.connected:
            return False
        self.outbox.send_json(obj)
        return True