"""Pairing with a one-time code (SPAKE2 PAKE) plus explicit approval.

Why a PAKE: a 6-digit code is brute-forceable offline if it is only used as an
HMAC key. SPAKE2 gives an attacker exactly one online guess per pairing
session; the host burns the code after the first failed confirmation.

Flow (JSON frames over an unauthenticated TLS channel):
  C->S p1 {name, role, spake}      S->C p2 {name, role, spake}
  C->S p3 {cert, mac_c}            (mac binds both certificates + TLS-observed cert)
  S approves -> S->C p4 {cert, mac_s}
  C approves -> C->S p5 {ok}       both persist the other's certificate
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import ipaddress
import secrets
import ssl
from typing import Callable, Optional

from spake2 import SPAKE2_A, SPAKE2_B

from .protocol import MAX_JSON_FRAME, ProtocolError, T_JSON, decode, json_frame, read_frame
from .security import (Identity, PairedStore, fingerprint_der, pairing_context,
                       pem_to_der, short_fp)

ID_A, ID_B = b"kvmshare-host", b"kvmshare-joiner"


class PairingError(Exception):
    pass


def new_code() -> str:
    return f"{secrets.randbelow(10 ** 6):06d}"


def fmt_code(code: str) -> str:
    return f"{code[:3]}-{code[3:]}"


def _mac(key: bytes, tag: bytes, *parts: str) -> str:
    k = hashlib.sha256(b"kvmshare-pair-v1" + key).digest()
    return hmac.new(k, tag + b"|" + b"|".join(p.encode() for p in parts), hashlib.sha256).hexdigest()


async def _send(w, obj):
    w.write(json_frame(obj))
    await w.drain()


async def _recv(r, expect: str) -> dict:
    t, body = await asyncio.wait_for(read_frame(r, MAX_JSON_FRAME), 30)
    if t != T_JSON:
        raise PairingError("unexpected frame")
    msg = decode(t, body)
    if msg.get("t") == "err":
        raise PairingError(str(msg.get("why", "peer aborted")))
    if msg.get("t") != expect:
        raise PairingError(f"protocol error (wanted {expect})")
    return msg


def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


async def host_pairing(ident: Identity, store: PairedStore, my_name: str, my_role: str,
                       code: str, port: int, bind: str, approve: Callable[[str, str, str], bool],
                       on_listening: Optional[Callable[[], None]] = None, timeout: float = 120.0) -> dict:
    """Wait for one joiner. Returns the stored device record."""
    result: asyncio.Future = asyncio.get_running_loop().create_future()
    used = False

    async def handle(r, w):
        nonlocal used
        peer = w.get_extra_info("peername")
        try:
            if used or not ipaddress.ip_address(peer[0]).is_private and not ipaddress.ip_address(peer[0]).is_loopback:
                return
            used = True                      # one attempt per code, success or not
            p1 = await _recv(r, "p1")
            spake = SPAKE2_A(code.encode(), idA=ID_A, idB=ID_B)
            out = spake.start()
            await _send(w, {"t": "p2", "name": my_name, "role": my_role, "spake": _b64(out)})
            key = spake.finish(base64.b64decode(p1["spake"]))
            p3 = await _recv(r, "p3")
            c_der = pem_to_der(p3["cert"])
            fp_c = fingerprint_der(c_der)
            want = _mac(key, b"C", fp_c, ident.fp, p1["role"], my_role)
            if not hmac.compare_digest(want, p3["mac"]):
                await _send(w, {"t": "err", "why": "wrong code"})
                raise PairingError("wrong pairing code (or man-in-the-middle); code burned")
            if p1["role"] == my_role:
                await _send(w, {"t": "err", "why": "both devices chose the same role"})
                raise PairingError("both devices chose the same role")
            ok = await asyncio.get_running_loop().run_in_executor(
                None, approve, str(p1.get("name", "?"))[:64], p1["role"], short_fp(fp_c))
            if not ok:
                await _send(w, {"t": "err", "why": "declined by host"})
                raise PairingError("declined")
            await _send(w, {"t": "p4", "cert": ident.cert_pem,
                            "mac": _mac(key, b"S", ident.fp, fp_c, p1["role"], my_role)})
            p5 = await _recv(r, "p5")
            if not p5.get("ok"):
                raise PairingError("joiner declined")
            dev = store.add(str(p1.get("name", "?"))[:64], p1["role"], p3["cert"])
            result.set_result(dev)
        except Exception as e:  # noqa: BLE001
            if not result.done():
                result.set_exception(e if isinstance(e, PairingError) else PairingError(repr(e)))
        finally:
            w.close()

    srv = await asyncio.start_server(handle, bind, port, ssl=pairing_context(ident, True),
                                     ssl_handshake_timeout=10)
    try:
        if on_listening:
            on_listening()
        return await asyncio.wait_for(result, timeout)
    except asyncio.TimeoutError:
        raise PairingError("pairing timed out")
    finally:
        srv.close()
        await srv.wait_closed()


async def join_pairing(ident: Identity, store: PairedStore, my_name: str, my_role: str,
                       code: str, host: str, port: int,
                       approve: Callable[[str, str, str], bool]) -> dict:
    r, w = await asyncio.wait_for(
        asyncio.open_connection(host, port, ssl=pairing_context(ident, False), server_hostname="kvmshare"), 10)
    try:
        sslobj = w.get_extra_info("ssl_object")
        fp_s_seen = fingerprint_der(sslobj.getpeercert(binary_form=True))
        spake = SPAKE2_B(code.encode(), idA=ID_A, idB=ID_B)
        await _send(w, {"t": "p1", "name": my_name, "role": my_role, "spake": _b64(spake.start())})
        p2 = await _recv(r, "p2")
        key = spake.finish(base64.b64decode(p2["spake"]))
        await _send(w, {"t": "p3", "cert": ident.cert_pem,
                        "mac": _mac(key, b"C", ident.fp, fp_s_seen, my_role, p2["role"])})
        p4 = await _recv(r, "p4")
        fp_s = fingerprint_der(pem_to_der(p4["cert"]))
        if fp_s != fp_s_seen:
            raise PairingError("certificate mismatch: possible man-in-the-middle")
        want = _mac(key, b"S", fp_s, ident.fp, my_role, p2["role"])
        if not hmac.compare_digest(want, p4["mac"]):
            raise PairingError("host failed to prove knowledge of the code")
        ok = await asyncio.get_running_loop().run_in_executor(
            None, approve, str(p2.get("name", "?"))[:64], p2["role"], short_fp(fp_s))
        await _send(w, {"t": "p5", "ok": bool(ok)})
        if not ok:
            raise PairingError("declined")
        return store.add(str(p2.get("name", "?"))[:64], p2["role"], p4["cert"])
    finally:
        w.close()
