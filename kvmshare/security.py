"""Device identity, pinned-certificate trust store and TLS contexts.

Every device owns a self-signed ECDSA P-256 certificate. After pairing, each
side stores the other's certificate and trusts *only* those exact certificates
(mutual TLS 1.3, pinning). There is no CA and no cloud."""
from __future__ import annotations

import datetime
import hashlib
import json
import os
import secrets
import ssl
import sys
import threading
import time
from pathlib import Path
from typing import Dict, List, Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


def fingerprint_der(der: bytes) -> str:
    return hashlib.sha256(der).hexdigest()


def pem_to_der(pem: str) -> bytes:
    return ssl.PEM_cert_to_DER_cert(pem)


def device_id_from_fp(fp: str) -> str:
    return fp[:20]


def short_fp(fp: str) -> str:
    return " ".join(fp[i:i + 4] for i in range(0, 20, 4)).upper()


# ---- DPAPI (Windows) protects the key passphrase at rest ----------------------
def _dpapi(data: bytes, protect: bool) -> bytes:
    import ctypes
    from ctypes import wintypes

    class BLOB(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]
    crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32")
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    buf = ctypes.create_string_buffer(data, len(data))
    inp = BLOB(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char)))
    out = BLOB()
    fn = crypt32.CryptProtectData if protect else crypt32.CryptUnprotectData
    ok = fn(ctypes.byref(inp), None, None, None, None, 0, ctypes.byref(out))
    if not ok:
        raise OSError("DPAPI failure")
    try:
        return ctypes.string_at(out.pbData, out.cbData)
    finally:
        kernel32.LocalFree(ctypes.cast(out.pbData, ctypes.c_void_p))


def _protect(b: bytes) -> bytes:
    return _dpapi(b, True) if sys.platform == "win32" else b


def _unprotect(b: bytes) -> bytes:
    return _dpapi(b, False) if sys.platform == "win32" else b


def _private_write(path: Path, data: bytes):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(data)


class Identity:
    def __init__(self, cert_path: Path, key_path: Path, passphrase: bytes):
        self.cert_path, self.key_path, self.passphrase = cert_path, key_path, passphrase
        self.cert_pem = cert_path.read_text()
        self.fp = fingerprint_der(pem_to_der(self.cert_pem))
        self.device_id = device_id_from_fp(self.fp)

    @classmethod
    def load_or_create(cls, d: Path, name: str = "kvmshare") -> "Identity":
        cp, kp, pp = d / "identity.cert.pem", d / "identity.key.pem", d / "identity.pass"
        if not (cp.exists() and kp.exists() and pp.exists()):
            key = ec.generate_private_key(ec.SECP256R1())
            passphrase = secrets.token_bytes(32).hex().encode()
            subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, f"kvmshare-{secrets.token_hex(4)}")])
            now = datetime.datetime.now(datetime.timezone.utc)
            cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
                    .public_key(key.public_key()).serial_number(x509.random_serial_number())
                    .not_valid_before(now - datetime.timedelta(days=1))
                    .not_valid_after(now + datetime.timedelta(days=3650))
                    .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
                    .add_extension(x509.KeyUsage(True, False, False, False, False, True, False, False, False), critical=True)
                    .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
                    .sign(key, hashes.SHA256()))
            _private_write(kp, key.private_bytes(
                serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                serialization.BestAvailableEncryption(passphrase)))
            _private_write(pp, _protect(passphrase))
            cp.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        return cls(cp, kp, _unprotect(pp.read_bytes()))


class PairedStore:
    """paired.json: {device_id: {name, role, cert, fp, added, last_addr}}"""

    def __init__(self, d: Path):
        self.path = d / "paired.json"
        self.lock = threading.Lock()
        self.devices: Dict[str, dict] = {}
        self.reload()

    def reload(self):
        with self.lock:
            self.devices = json.loads(self.path.read_text()) if self.path.exists() else {}

    def _save(self):
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self.devices, indent=2))
        os.replace(tmp, self.path)

    def add(self, name: str, role: str, cert_pem: str) -> dict:
        fp = fingerprint_der(pem_to_der(cert_pem))
        dev = {"id": device_id_from_fp(fp), "name": name, "role": role, "cert": cert_pem,
               "fp": fp, "added": int(time.time()), "last_addr": None}
        with self.lock:
            self.devices[dev["id"]] = dev
            self._save()
        return dev

    def remove(self, key: str) -> Optional[dict]:
        with self.lock:
            for did, d in list(self.devices.items()):
                if key in (did, d["name"], d["role"]) or d["fp"].startswith(key.lower()):
                    del self.devices[did]
                    self._save()
                    return d
        return None

    def by_fp(self, fp: str) -> Optional[dict]:
        with self.lock:
            for d in self.devices.values():
                if d["fp"] == fp:
                    return d
        return None

    def set_addr(self, did: str, addr):
        with self.lock:
            if did in self.devices and self.devices[did].get("last_addr") != addr:
                self.devices[did]["last_addr"] = addr
                self._save()

    def all(self) -> List[dict]:
        with self.lock:
            return list(self.devices.values())


def _base_ctx(server: bool) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER if server else ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    return ctx


def session_context(ident: Identity, store: PairedStore, server: bool) -> ssl.SSLContext:
    """Mutual TLS 1.3. Only certificates currently in the store verify."""
    ctx = _base_ctx(server)
    ctx.load_cert_chain(str(ident.cert_path), str(ident.key_path), password=lambda: ident.passphrase)
    ctx.verify_mode = ssl.CERT_REQUIRED
    if not server:
        ctx.check_hostname = False
    trust_all(ctx, store)
    return ctx


def trust_all(ctx: ssl.SSLContext, store: PairedStore):
    for d in store.all():
        ctx.load_verify_locations(cadata=d["cert"])


def pairing_context(ident: Identity, server: bool) -> ssl.SSLContext:
    """Pairing transport: encrypted but unauthenticated; authentication comes
    from the SPAKE2 confirmation that is bound to both certificates."""
    ctx = _base_ctx(server)
    if server:
        ctx.load_cert_chain(str(ident.cert_path), str(ident.key_path), password=lambda: ident.passphrase)
        ctx.verify_mode = ssl.CERT_NONE
    else:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx
