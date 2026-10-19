"""kvmshare command line."""
from __future__ import annotations

import argparse
import asyncio
import json
import socket
import sys

from . import config as C
from . import __version__


def _call(cmd: str, **args):
    cfg = C.load_config()
    tok = (C.data_dir() / "control.token")
    if not tok.exists():
        raise SystemExit("daemon has never run on this machine (no control token)")
    try:
        with socket.create_connection(("127.0.0.1", cfg["control_port"]), timeout=3) as s:
            s.sendall((json.dumps({"token": tok.read_text().strip(), "cmd": cmd, "args": args}) + "\n").encode())
            s.settimeout(120)
            data = b""
            while not data.endswith(b"\n"):
                chunk = s.recv(65536)
                if not chunk:
                    break
                data += chunk
    except OSError:
        raise SystemExit("daemon is not running (start it with: python -m kvmshare run)")
    r = json.loads(data)
    if not r.get("ok"):
        raise SystemExit(f"error: {r.get('error')}")
    return r["result"]


def _show(x):
    print(json.dumps(x, indent=2, default=str))


def _approve(kind):
    def f(name, role, fp):
        print(f"\n{kind}: device '{name}' (role {role}) with certificate fingerprint {fp}")
        return input("Accept this device? [y/N] ").strip().lower() == "y"
    return f


def cmd_pair(a):
    from . import discovery, pairing
    from .security import Identity, PairedStore
    cfg = C.load_config()
    d = C.data_dir()
    ident, store = Identity.load_or_create(d), PairedStore(d)
    name = cfg["device_name"]
    role = a.role or ("desktop" if a.host else "laptop")
    if a.host:
        code = pairing.new_code()
        print(f"This device will be '{role}'. On the OTHER computer run:\n    python -m kvmshare pair --join")
        print(f"\n    PAIRING CODE:  {pairing.fmt_code(code)}   (valid 2 minutes, one attempt)\n")
        with discovery.PairingAnnouncer(cfg, ident.device_id):
            dev = asyncio.run(pairing.host_pairing(ident, store, name, role, code, cfg["pairing_port"], cfg["bind"],
                                                   _approve("Pairing request")))
    else:
        if a.addr:
            host, _, port = a.addr.partition(":")
            port = int(port or cfg["pairing_port"])
        else:
            print("Looking for a pairing host on the LAN...")
            hosts = discovery.find_pairing_hosts(cfg)
            if not hosts:
                raise SystemExit("no host found; start `pair --host` on the other computer or pass --addr IP")
            h = hosts[0]
            host, port = h["ip"], h["port"]
            print(f"Found '{h['name']}' at {host}")
        code = input("Enter the pairing code shown on the other computer: ").replace("-", "").strip()
        dev = asyncio.run(pairing.join_pairing(ident, store, name, role, code, host, port, _approve("Host")))
    mine = role
    C.save_user_config({"role": mine})
    print(f"\nPaired with '{dev['name']}' ({dev['role']}). This computer is '{mine}'.")
    try:
        _call("reload")
    except SystemExit:
        pass


def cmd_run(a):
    from .app import Daemon, setup_logging
    cfg = C.load_config()
    setup_logging(cfg)
    try:
        asyncio.run(Daemon(cfg).run())
    except KeyboardInterrupt:
        pass


def cmd_devices(a):
    from .security import PairedStore, short_fp
    for d in PairedStore(C.data_dir()).all():
        print(f"{d['id']}  {d['name']:<20} role={d['role']:<8} fp={short_fp(d['fp'])}")


def cmd_revoke(a):
    from .security import PairedStore
    r = PairedStore(C.data_dir()).remove(a.device)
    print("revoked " + r["name"] if r else "no such device")
    try:
        _call("reload")
    except SystemExit:
        pass


def cmd_bench(a):
    if a.kind == "net":
        r = _call("bench_net", count=a.count, rate=a.rate)
    elif a.kind == "local":
        r = _call("bench_local", count=a.count)
    else:
        r = _call("bench_clip", count=min(a.count, 50), size=a.size)
    _show(r)


def main(argv=None):
    p = argparse.ArgumentParser("kvmshare", description="Seamless mouse/keyboard/clipboard/file sharing over the LAN")
    p.add_argument("--version", action="version", version=__version__)
    sp = p.add_subparsers(dest="cmd", required=True)
    sp.add_parser("run", help="start the background daemon").set_defaults(f=cmd_run)
    q = sp.add_parser("pair", help="pair two computers with a one-time code")
    g = q.add_mutually_exclusive_group(required=True)
    g.add_argument("--host", action="store_true")
    g.add_argument("--join", action="store_true")
    q.add_argument("--role", choices=["laptop", "desktop"])
    q.add_argument("--addr", help="host[:port] of the pairing host (skips discovery)")
    q.set_defaults(f=cmd_pair)
    sp.add_parser("devices").set_defaults(f=cmd_devices)
    q = sp.add_parser("revoke"); q.add_argument("device", help="id, name, role or fingerprint prefix"); q.set_defaults(f=cmd_revoke)
    sp.add_parser("status").set_defaults(f=lambda a: _show(_call("status")))
    sp.add_parser("reclaim", help="take the pointer back to this computer").set_defaults(f=lambda a: _call("reclaim"))
    q = sp.add_parser("privacy"); q.add_argument("state", choices=["on", "off"])
    q.set_defaults(f=lambda a: print("clipboard sync paused" if _call("privacy", on=a.state == "on") else "clipboard sync active"))
    q = sp.add_parser("feature", help="enable/disable input, clipboard or files at runtime")
    q.add_argument("name", choices=["input", "clipboard", "files"]); q.add_argument("state", choices=["on", "off"])
    q.set_defaults(f=lambda a: _call("feature", name=a.name, on=a.state == "on"))
    sp.add_parser("transfers").set_defaults(f=lambda a: _show(_call("transfers")))
    q = sp.add_parser("accept"); q.add_argument("id"); q.set_defaults(f=lambda a: print(_call("accept", id=a.id)))
    q = sp.add_parser("cancel"); q.add_argument("id"); q.set_defaults(f=lambda a: print(_call("cancel", id=a.id)))
    q = sp.add_parser("bench", help="measure latency / throughput")
    q.add_argument("kind", choices=["net", "local", "clip"])
    q.add_argument("--count", type=int, default=500); q.add_argument("--rate", type=float, default=500)
    q.add_argument("--size", type=int, default=1000)
    q.set_defaults(f=cmd_bench)
    sp.add_parser("selftest", help="check this machine (Windows)").set_defaults(f=lambda a: __import__("kvmshare.selftest", fromlist=["x"]).run())
    sp.add_parser("config", help="print config path and effective topology").set_defaults(
        f=lambda a: (print(C.config_path()), _show(C.load_config()["topology"])))
    sp.add_parser("stop").set_defaults(f=lambda a: _call("shutdown"))
    a = p.parse_args(argv)
    a.f(a)
    return 0
