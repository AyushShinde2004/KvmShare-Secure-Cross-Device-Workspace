"""LAN discovery via small UDP broadcast beacons.

Beacons are *hints only* (device id, port). They are unauthenticated by design:
a spoofed beacon can at worst make us try a connection that fails the pinned
mutual-TLS check. No content or secrets are ever broadcast."""
from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import socket
import threading
import time
from typing import Callable, List, Optional

log = logging.getLogger("kvmshare.discovery")


def broadcast_addrs() -> List[str]:
    out = set()
    try:
        import psutil
        for addrs in psutil.net_if_addrs().values():
            for a in addrs:
                if a.family == socket.AF_INET and a.netmask and not a.address.startswith(("127.", "169.254.")):
                    ip = ipaddress.ip_address(a.address)
                    if ip.is_private:
                        net = ipaddress.ip_network(f"{a.address}/{a.netmask}", strict=False)
                        out.add(str(net.broadcast_address))
    except Exception:                                    # noqa: BLE001
        pass
    out.add("255.255.255.255")
    return sorted(out)


def _make_beacon(did: str, name: str, port: int, pair_port: Optional[int]) -> bytes:
    d = {"v": 1, "id": did, "name": name[:40], "port": port}
    if pair_port:
        d["pair"] = pair_port
    return json.dumps(d, separators=(",", ":")).encode()


class Discovery(asyncio.DatagramProtocol):
    def __init__(self, cfg: dict, device_id: str, on_peer: Callable[[str, str, int], None]):
        self.cfg, self.id, self.on_peer = cfg, device_id, on_peer
        self.transport: Optional[asyncio.DatagramTransport] = None
        self._task = None

    async def start(self):
        loop = asyncio.get_running_loop()
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.bind(("", self.cfg["beacon_port"]))
        sock.setblocking(False)
        self.transport, _ = await loop.create_datagram_endpoint(lambda: self, sock=sock)
        self._task = asyncio.ensure_future(self._announce())

    async def _announce(self):
        pkt = _make_beacon(self.id, self.cfg["device_name"], self.cfg["listen_port"], None)
        while True:
            for b in broadcast_addrs():
                try:
                    self.transport.sendto(pkt, (b, self.cfg["beacon_port"]))
                except OSError:
                    pass
            await asyncio.sleep(2.0)

    def datagram_received(self, data: bytes, addr):
        if len(data) > 512:
            return
        try:
            d = json.loads(data)
            if d.get("id") == self.id or not isinstance(d.get("port"), int):
                return
            if not ipaddress.ip_address(addr[0]).is_private:
                return
            self.on_peer(str(d["id"]), addr[0], int(d["port"]))
        except (ValueError, TypeError):
            pass

    def stop(self):
        if self._task:
            self._task.cancel()
        if self.transport:
            self.transport.close()


# ---- pairing helpers (blocking; used by the CLI) -----------------------------
class PairingAnnouncer:
    def __init__(self, cfg: dict, device_id: str):
        self.cfg, self.id, self._stop = cfg, device_id, threading.Event()

    def __enter__(self):
        def run():
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            pkt = _make_beacon(self.id, self.cfg["device_name"], self.cfg["listen_port"], self.cfg["pairing_port"])
            while not self._stop.is_set():
                for b in broadcast_addrs():
                    try:
                        s.sendto(pkt, (b, self.cfg["beacon_port"]))
                    except OSError:
                        pass
                self._stop.wait(1.0)
            s.close()
        threading.Thread(target=run, daemon=True).start()
        return self

    def __exit__(self, *a):
        self._stop.set()


def find_pairing_hosts(cfg: dict, timeout: float = 6.0) -> List[dict]:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("", cfg["beacon_port"]))
    s.settimeout(0.5)
    found, end = {}, time.time() + timeout
    while time.time() < end:
        try:
            data, addr = s.recvfrom(512)
            d = json.loads(data)
            if d.get("pair") and ipaddress.ip_address(addr[0]).is_private:
                found[addr[0]] = {"ip": addr[0], "port": int(d["pair"]), "name": str(d.get("name", "?"))}
        except (socket.timeout, ValueError, TypeError):
            pass
    s.close()
    return list(found.values())
