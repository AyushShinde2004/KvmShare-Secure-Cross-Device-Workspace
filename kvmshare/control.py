"""Localhost control API (token-authenticated JSON lines) + external input socket."""
from __future__ import annotations

import asyncio
import hmac
import json
import logging
import struct

log = logging.getLogger("kvmshare.control")


class Control:
    def __init__(self, daemon):
        self.d = daemon

    async def start(self):
        self.srv = await asyncio.start_server(self._conn, "127.0.0.1", self.d.cfg["control_port"])

    async def _conn(self, r, w):
        try:
            line = await asyncio.wait_for(r.readline(), 5)
            req = json.loads(line)
            if not hmac.compare_digest(str(req.get("token", "")), self.d.token):
                w.write(b'{"ok":false,"error":"unauthorized"}\n')
            else:
                try:
                    res = await self.dispatch(req.get("cmd"), req.get("args") or {})
                    w.write((json.dumps({"ok": True, "result": res}, default=str) + "\n").encode())
                except Exception as e:                       # noqa: BLE001
                    w.write((json.dumps({"ok": False, "error": f"{type(e).__name__}: {e}"}) + "\n").encode())
            await w.drain()
        except (ValueError, asyncio.TimeoutError, ConnectionError):
            pass
        finally:
            w.close()

    async def dispatch(self, cmd, a):
        d = self.d
        if cmd == "status":
            return {"role": d.cfg["role"], "id": d.ident.device_id,
                    "link": {"connected": d.link.connected, "peer": (d.link.peer or {}).get("name"),
                             "rtt_ms": round(d.link.rtt_ms, 2), "addr": d.link.peer_addr},
                    "router": d.router.status(),
                    "features": {"input": d.router.input_enabled, "clipboard": d.clip.enabled and not d.clip.paused,
                                 "clipboard_paused": d.clip.paused, "files": d.files.enabled},
                    "metrics": d.metrics.snapshot()}
        if cmd == "reload":
            d.reload(); return "ok"
        if cmd == "reclaim":
            d.router.reclaim(); return "ok"
        if cmd == "privacy":
            d.clip.set_paused(bool(a.get("on"))); return d.clip.paused
        if cmd == "feature":
            name, on = a["name"], bool(a["on"])
            if name == "input": d.set_split(not on)          # "input off" == split mode, synchronised with the peer
            elif name == "clipboard": d.clip.enabled = on
            elif name == "files": d.files.enabled = on
            else: raise ValueError("unknown feature")
            return "ok"
        if cmd == "transfers":
            return d.files.list()
        if cmd == "accept":
            return d.files.start(a["id"])
        if cmd == "cancel":
            return d.files.cancel(a["id"])
        if cmd == "bench_net":
            return await d.link.bench_ping(int(a.get("count", 500)), float(a.get("rate", 500)))
        if cmd == "bench_local":
            return await asyncio.get_running_loop().run_in_executor(None, d.platform.bench_local, int(a.get("count", 500)))
        if cmd == "bench_clip":
            return await d.clip.bench(int(a.get("count", 10)), int(a.get("size", 1000)))
        if cmd == "shutdown":
            asyncio.get_running_loop().call_later(0.2, d._stop.set); return "bye"
        raise ValueError(f"unknown command {cmd!r}")


class ExternalInput(asyncio.DatagramProtocol):
    """Loopback UDP: lets other local programs (e.g. the air-mouse script) feed the
    router as if they were a mouse. Packet: b'KV1' + 16-byte token + '!hhBB' (dx, dy, button, down)."""
    FMT = struct.Struct("!hhBB")

    def __init__(self, d):
        self.d = d

    @classmethod
    async def start(cls, d, loop):
        await loop.create_datagram_endpoint(lambda: cls(d), local_addr=("127.0.0.1", d.cfg["external_input_port"]))

    def datagram_received(self, data, addr):
        if len(data) != 3 + 16 + self.FMT.size or data[:3] != b"KV1" or not hmac.compare_digest(data[3:19], self.d.ext_token):
            return
        dx, dy, btn, down = self.FMT.unpack(data[19:])
        if dx or dy:
            self.d.router.external_move(dx, dy)
        if 1 <= btn <= 5:
            self.d.router.external_button(btn, bool(down))