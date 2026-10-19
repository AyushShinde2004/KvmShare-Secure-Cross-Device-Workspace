"""Copy on one machine, paste on the other.

Sender: when the local clipboard holds files/folders, a manifest is built and an
*offer* (counts and sizes only) is sent. The receiver pulls over its own aux
TLS connection. The receiver never names paths: it asks for entry indexes of the
registered offer, so a peer can never read arbitrary files.

Receiver: validates every relative path, writes into a brand-new per-offer folder
(never overwrites), streams to `<name>.kvmpart`, verifies a SHA-256, then
renames. Interrupted transfers resume from the partial file. Nothing is ever
executed. After completion the staged files are put on the local clipboard as
CF_HDROP so a normal Ctrl+V in Explorer pastes them.
"""
from __future__ import annotations

import asyncio
import hashlib
import logging
import os
import re
import secrets
import stat
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple

from . import protocol as P

log = logging.getLogger("kvmshare.files")

CHUNK = 256 * 1024
_BAD_CHARS = re.compile(r'[<>:"|?*\\\x00-\x1f]')
_RESERVED = {"con", "prn", "aux", "nul", *(f"com{i}" for i in range(1, 10)), *(f"lpt{i}" for i in range(1, 10))}


class TransferError(Exception):
    pass


class Cancelled(Exception):
    pass


def safe_component(name: str) -> str:
    if not name or name in (".", "..") or len(name) > 255:
        raise TransferError("invalid path component")
    if _BAD_CHARS.search(name) or name != name.rstrip(" ."):
        raise TransferError("invalid characters in file name")
    if name.split(".")[0].lower() in _RESERVED:
        raise TransferError("reserved device name")
    return name


def safe_relpath(rel: str) -> str:
    """Validate a '/'-separated relative path from an untrusted peer."""
    if not isinstance(rel, str) or not rel or len(rel) > 400 or rel.startswith("/"):
        raise TransferError("invalid relative path")
    parts = rel.split("/")
    if len(parts) > 64:
        raise TransferError("path too deep")
    return "/".join(safe_component(p) for p in parts)


def _is_reparse(path: str, st: os.stat_result) -> bool:
    if stat.S_ISLNK(st.st_mode):
        return True
    return bool(getattr(st, "st_file_attributes", 0) & 0x400)   # junctions / mount points on Windows


def _unique(name: str, used: set) -> str:
    base, ext = os.path.splitext(name)
    cand, n = name, 2
    while cand.lower() in used:
        cand = f"{base} ({n}){ext}"
        n += 1
    used.add(cand.lower())
    return cand


def build_manifest(paths: List[str], max_entries: int, max_bytes: int) -> Tuple[List[dict], Dict[int, str], int, int]:
    """Returns (entries, index->absolute source path, total_bytes, skipped_links)."""
    entries: List[dict] = []
    src: Dict[int, str] = {}
    total = skipped = 0
    used_top: set = set()

    def add(rel, path, st, kind):
        nonlocal total
        if len(entries) >= max_entries:
            raise TransferError(f"more than {max_entries} entries")
        i = len(entries)
        size = st.st_size if kind == "file" else 0
        total += size
        if total > max_bytes:
            raise TransferError("transfer exceeds the configured size limit")
        entries.append({"i": i, "rel": rel, "kind": kind, "size": size, "mtime_ns": st.st_mtime_ns,
                        "ro": not (st.st_mode & stat.S_IWRITE)})
        src[i] = path

    for top in paths:
        try:
            st = os.lstat(top)
        except OSError:
            continue
        if _is_reparse(top, st):
            skipped += 1
            continue
        name = _unique(os.path.basename(os.path.normpath(top)), used_top)
        try:
            safe_component(name)
        except TransferError:
            skipped += 1
            continue
        if stat.S_ISDIR(st.st_mode):
            add(name, top, st, "dir")
            stack = [(top, name)]
            while stack:
                d, rel = stack.pop()
                try:
                    with os.scandir(d) as it:
                        for e in sorted(it, key=lambda e: e.name):
                            try:
                                est = e.stat(follow_symlinks=False)
                                child = f"{rel}/{e.name}"
                                safe_relpath(child)
                            except (OSError, TransferError):
                                skipped += 1
                                continue
                            if _is_reparse(e.path, est):
                                skipped += 1
                            elif stat.S_ISDIR(est.st_mode):
                                add(child, e.path, est, "dir")
                                stack.append((e.path, child))
                            elif stat.S_ISREG(est.st_mode):
                                add(child, e.path, est, "file")
                except OSError:
                    skipped += 1
        elif stat.S_ISREG(st.st_mode):
            add(name, top, st, "file")
    return entries, src, total, skipped


@dataclass
class Offer:
    id: str
    entries: List[dict]
    src: Dict[int, str]
    total: int
    created: float = field(default_factory=time.time)


@dataclass
class Job:
    id: str
    peer_name: str
    count: int
    total: int
    top: List[str]
    state: str = "pending"          # pending | running | done | failed | cancelled
    done_bytes: int = 0
    error: str = ""
    dest: str = ""
    attempts: int = 0
    started: float = 0.0
    cancel: bool = False
    entries: Optional[list] = None
    task: Optional[asyncio.Task] = None

    def view(self) -> dict:
        rate = self.done_bytes / max(1e-6, time.time() - self.started) if self.started else 0
        return {"id": self.id, "state": self.state, "from": self.peer_name, "files": self.count,
                "bytes": self.total, "done": self.done_bytes, "rate_mbps": round(rate * 8 / 1e6, 1),
                "dest": self.dest, "error": self.error, "attempts": self.attempts, "top": self.top}


class FileService:
    def __init__(self, cfg: dict, link, notify: Callable[[str, str], None], metrics, clip_backend=None):
        self.cfg, self.link, self.notify, self.metrics, self.clip = cfg, link, notify, metrics, clip_backend
        self.fcfg = cfg["files"]
        self.enabled = bool(cfg["features"]["files"])
        self.offers: Dict[str, Offer] = {}
        self.jobs: Dict[str, Job] = {}
        link.handlers["file_offer"] = self.on_offer
        link.handlers["file_cancel"] = self._on_remote_cancel
        link.aux_handlers["xfer"] = self.serve

    # ================================================================ sender
    def offer_paths(self, paths: List[str]) -> Optional[str]:
        """Blocking (run in an executor). Builds the manifest and tells the peer."""
        if not self.enabled or not self.link.connected:
            return None
        now = time.time()
        for k in [k for k, o in self.offers.items() if now - o.created > self.fcfg["offer_ttl_s"]]:
            del self.offers[k]
        try:
            entries, src, total, skipped = build_manifest(
                paths, self.fcfg["max_entries"], int(self.fcfg["max_total_gb"] * 1024 ** 3))
        except TransferError as e:
            self.notify("File sharing", f"Not offered: {e}")
            return None
        if not entries:
            return None
        oid = secrets.token_hex(8)
        self.offers[oid] = Offer(oid, entries, src, total)
        tops = [e["rel"] for e in entries if "/" not in e["rel"]][:3]
        self.link.send_json({"t": "file_offer", "id": oid, "count": sum(e["kind"] == "file" for e in entries),
                             "bytes": total, "top": tops, "skipped": skipped})
        log.info("offered %d entries (%d bytes)", len(entries), total)
        return oid

    async def serve(self, reader, writer, hdr: dict):
        """Aux channel handler on the machine that owns the files."""
        offer = self.offers.get(str(hdr.get("offer")))
        loop = asyncio.get_running_loop()
        try:
            if not self.enabled or offer is None:
                writer.write(P.json_frame({"t": "err", "why": "offer unavailable"}))
                return
            while True:
                t, body = await asyncio.wait_for(P.read_frame(reader, P.MAX_JSON_FRAME), 60)
                msg = P.decode(t, body) if t == P.T_JSON else {}
                k = msg.get("t")
                if k == "manifest":
                    writer.write(P.json_frame({"t": "manifest", "entries": offer.entries}))
                    await writer.drain()
                elif k == "get":
                    await self._serve_file(offer, int(msg["idx"]), int(msg.get("offset", 0)), writer, loop)
                else:
                    return
        finally:
            writer.close()

    async def _serve_file(self, offer: Offer, idx: int, offset: int, writer, loop):
        e = offer.entries[idx] if 0 <= idx < len(offer.entries) else None
        if e is None or e["kind"] != "file" or not 0 <= offset <= e["size"]:
            writer.write(P.json_frame({"t": "err", "why": "bad request"}))
            await writer.drain()
            return
        path = offer.src[idx]
        try:
            st = os.stat(path)
            if st.st_size != e["size"] or st.st_mtime_ns != e["mtime_ns"]:
                raise TransferError("source file changed since it was copied")
            h = hashlib.sha256()
            f = await loop.run_in_executor(None, open, path, "rb")
            try:
                writer.write(P.json_frame({"t": "file", "idx": idx, "size": e["size"], "offset": offset}))
                pos = 0
                while pos < e["size"]:
                    data = await loop.run_in_executor(None, f.read, min(CHUNK, e["size"] - pos))
                    if not data:
                        raise TransferError("source file shrank")
                    h.update(data)
                    if pos >= offset:
                        writer.write(P.frame(P.T_DATA, data))
                        await writer.drain()
                    elif pos + len(data) > offset:        # chunk straddles the resume point
                        writer.write(P.frame(P.T_DATA, data[offset - pos:]))
                        await writer.drain()
                    pos += len(data)
            finally:
                f.close()
            writer.write(P.json_frame({"t": "end", "sha256": h.hexdigest()}))
            await writer.drain()
        except (OSError, TransferError) as ex:
            writer.write(P.json_frame({"t": "err", "why": str(ex)[:200]}))
            await writer.drain()

    # ============================================================== receiver
    def on_offer(self, msg: dict):
        if not self.enabled:
            return
        try:
            oid = str(msg["id"])
            if not re.fullmatch(r"[0-9a-f]{16}", oid):
                return
            count, total = int(msg["count"]), int(msg["bytes"])
            top = [str(x)[:120] for x in list(msg.get("top", []))[:3]]
        except (KeyError, ValueError, TypeError):
            return
        peer = (self.link.peer or {}).get("name", "peer")
        job = Job(oid, peer, count, total, top)
        self.jobs[oid] = job
        mb = total / 1048576
        policy = self.fcfg["require_approval"]
        auto = policy == "never" or (policy == "large" and mb <= self.fcfg["auto_stage_max_mb"])
        label = f"{count} file(s), {mb:.1f} MB from {peer}"
        if auto:
            self.notify("Receiving files", label)
            self.start(oid)
        else:
            self.notify("Files waiting", f"{label}. Run: kvmshare accept {oid}")

    def _on_remote_cancel(self, msg: dict):
        self.offers.pop(str(msg.get("id")), None)

    def start(self, oid: str) -> bool:
        job = self.jobs.get(oid)
        if not job or job.state not in ("pending", "failed", "cancelled"):
            return False
        job.state, job.cancel, job.error = "pending", False, ""
        job.task = asyncio.run_coroutine_threadsafe(self._run(job), self.link.loop)
        return True

    def cancel(self, oid: str) -> bool:
        job = self.jobs.get(oid)
        if not job:
            return False
        job.cancel = True
        if job.state == "pending":
            job.state = "cancelled"
        self.link.send_json({"t": "file_cancel", "id": oid})
        return True

    def list(self) -> list:
        return [j.view() for j in self.jobs.values()]

    async def _run(self, job: Job):
        job.state, job.started = "running", time.time()
        delay = 1.0
        for attempt in range(1, int(self.fcfg["retries"]) + 2):
            job.attempts = attempt
            try:
                await self._attempt(job)
                job.state = "done"
                self.metrics.count("transfers_ok")
                self.notify("Files received", f"{job.count} file(s) saved to {job.dest}")
                return
            except Cancelled:
                job.state = "cancelled"
                return
            except TransferError as e:                         # permanent: bad data, refused, changed
                job.state, job.error = "failed", str(e)
                break
            except (OSError, asyncio.IncompleteReadError, asyncio.TimeoutError, P.ProtocolError) as e:
                job.error = f"{type(e).__name__}: {e}"
                log.warning("transfer %s interrupted (%s); will resume", job.id, job.error)
                await asyncio.sleep(delay)
                delay = min(15.0, delay * 2)
                while not self.link.connected and not job.cancel:   # wait for reconnect
                    await asyncio.sleep(0.5)
                if job.cancel:
                    job.state = "cancelled"
                    return
        else:
            job.state = "failed"
        if job.state == "failed":
            self.notify("Transfer failed", f"{job.error or 'unknown error'} (kvmshare accept {job.id} to retry)")

    async def _attempt(self, job: Job):
        loop = asyncio.get_running_loop()
        r, w = await self.link.open_aux("xfer", {"offer": job.id})
        try:
            if job.entries is None:
                w.write(P.json_frame({"t": "manifest"}))
                await w.drain()
                t, body = await asyncio.wait_for(P.read_frame(r, P.MAX_XFER_JSON), 30)
                msg = P.decode(t, body) if t == P.T_JSON else {}
                if msg.get("t") != "manifest":
                    raise TransferError(str(msg.get("why", "offer no longer available")))
                job.entries = self._validate_manifest(msg["entries"])
                job.count = sum(e["kind"] == "file" for e in job.entries)
                job.total = sum(e["size"] for e in job.entries)
                root = Path(self.fcfg["inbox"]) / f"{time.strftime('%Y%m%d-%H%M%S')}-{job.id[:6]}"
                root.mkdir(parents=True, exist_ok=False)
                job.dest = str(root)
            root = Path(job.dest)
            for e in job.entries:                              # create directories first (safe paths only)
                if e["kind"] == "dir":
                    (root / e["rel"]).mkdir(parents=True, exist_ok=True)
            job.done_bytes = 0
            bucket_t, bucket_n = time.monotonic(), 0
            rate = float(self.fcfg["max_rate_mbps"]) * 125000
            for e in job.entries:
                if e["kind"] != "file":
                    continue
                final = self._confine(root, e["rel"])
                if final.exists():                              # completed in an earlier attempt
                    job.done_bytes += e["size"]
                    continue
                part = final.with_name(final.name + ".kvmpart")
                offset = part.stat().st_size if part.exists() else 0
                if offset > e["size"]:
                    part.unlink()
                    offset = 0
                h = hashlib.sha256()
                if offset:
                    with open(part, "rb") as pf:
                        while True:
                            b = pf.read(CHUNK * 4)
                            if not b:
                                break
                            h.update(b)
                w.write(P.json_frame({"t": "get", "idx": e["i"], "offset": offset}))
                await w.drain()
                t, body = await asyncio.wait_for(P.read_frame(r, P.MAX_JSON_FRAME), 30)
                hdr = P.decode(t, body) if t == P.T_JSON else {}
                if hdr.get("t") != "file" or hdr.get("idx") != e["i"] or hdr.get("size") != e["size"]:
                    raise TransferError(str(hdr.get("why", "sender refused file")))
                got = offset
                job.done_bytes += offset
                f = open(part, "ab")
                try:
                    while got < e["size"]:
                        if job.cancel:
                            raise Cancelled()
                        t, body = await asyncio.wait_for(P.read_frame(r, P.MAX_DATA_FRAME), 30)
                        if t != P.T_DATA or got + len(body) > e["size"]:
                            raise TransferError("unexpected data from sender")
                        h.update(body)
                        await loop.run_in_executor(None, f.write, body)
                        got += len(body)
                        job.done_bytes += len(body)
                        if rate:
                            bucket_n += len(body)
                            ahead = bucket_n / rate - (time.monotonic() - bucket_t)
                            if ahead > 0:
                                await asyncio.sleep(ahead)
                finally:
                    f.close()
                t, body = await asyncio.wait_for(P.read_frame(r, P.MAX_JSON_FRAME), 60)
                end = P.decode(t, body) if t == P.T_JSON else {}
                if end.get("t") != "end":
                    raise TransferError(str(end.get("why", "transfer aborted by sender")))
                if end.get("sha256") != h.hexdigest():
                    part.unlink(missing_ok=True)
                    raise OSError("checksum mismatch; restarting file")
                os.replace(part, final) if not final.exists() else self._fail_exists()
                os.utime(final, ns=(e["mtime_ns"], e["mtime_ns"]))
                if e["ro"]:
                    os.chmod(final, stat.S_IREAD)
                job.done_bytes = job.done_bytes  # already counted incrementally
            for e in reversed(job.entries):                    # directory mtimes last
                if e["kind"] == "dir":
                    p = root / e["rel"]
                    os.utime(p, ns=(e["mtime_ns"], e["mtime_ns"]))
            w.write(P.json_frame({"t": "bye"}))
        finally:
            w.close()
        tops = [str(root / e["rel"]) for e in job.entries if "/" not in e["rel"]]
        if self.fcfg["put_on_clipboard"] and self.clip is not None and self.cfg["features"]["clipboard"]:
            await loop.run_in_executor(None, self.clip.write_files, tops)

    @staticmethod
    def _fail_exists():
        raise TransferError("destination appeared during transfer; refusing to overwrite")

    def _validate_manifest(self, entries) -> List[dict]:
        if not isinstance(entries, list) or len(entries) > self.fcfg["max_entries"]:
            raise TransferError("manifest too large")
        out, seen, total = [], set(), 0
        for i, e in enumerate(entries):
            try:
                rel = safe_relpath(e["rel"])
                kind, size = e["kind"], int(e["size"])
                mtime = int(e["mtime_ns"])
            except (KeyError, TypeError, ValueError, TransferError) as ex:
                raise TransferError(f"rejected manifest entry {i}: {ex}")
            if kind not in ("file", "dir") or size < 0 or (kind == "dir" and size):
                raise TransferError("bad manifest entry")
            if e.get("i") != i or rel.lower() in seen:
                raise TransferError("duplicate or misnumbered manifest entry")
            seen.add(rel.lower())
            parent = rel.rpartition("/")[0]
            if parent and parent.lower() not in seen:
                raise TransferError("manifest entry without parent directory")
            total += size
            out.append({"i": i, "rel": rel, "kind": kind, "size": size, "mtime_ns": max(0, mtime), "ro": bool(e.get("ro"))})
        if total > self.fcfg["max_total_gb"] * 1024 ** 3:
            raise TransferError("transfer exceeds the configured size limit")
        return out

    @staticmethod
    def _confine(root: Path, rel: str) -> Path:
        p = (root / rel).resolve()
        if os.path.commonpath([str(root.resolve()), str(p)]) != str(root.resolve()):
            raise TransferError("path escapes destination")
        return p
