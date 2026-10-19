"""Input router: the brain of the system. Platform independent and unit-tested.

Model
-----
There is ONE logical pointer. At any moment exactly one machine *owns* it
(`owner_local`). The owner's physical devices act natively (hook passes the
event through). The other machine is in *forward mode*: its hooks swallow every
local mouse/keyboard event and send it to the owner, which injects it. This is
symmetric: a trackpad/mouse/keyboard on either computer controls whichever
screen the pointer is on.

Ownership moves with ENTER(epoch+1) when the owner's pointer reaches a managed
edge. The epoch is a fencing token: any input frame carrying a stale epoch is
dropped, so a handoff can never cause double-injection or loops.

Injected events carry a marker (dwExtraInfo) so our own hooks never re-forward
them (feedback-loop prevention).
"""
from __future__ import annotations

import logging
import threading
import time
from typing import Dict, List, Optional, Set, Tuple

from . import topology as topo

log = logging.getLogger("kvmshare.router")

# Win32 message ids (portable constants so tests need no OS)
WM_MOUSEMOVE, WM_LBUTTONDOWN, WM_LBUTTONUP = 0x200, 0x201, 0x202
WM_RBUTTONDOWN, WM_RBUTTONUP, WM_MBUTTONDOWN, WM_MBUTTONUP = 0x204, 0x205, 0x207, 0x208
WM_MOUSEWHEEL, WM_XBUTTONDOWN, WM_XBUTTONUP, WM_MOUSEHWHEEL = 0x20A, 0x20B, 0x20C, 0x20E
BTN_L, BTN_R, BTN_M, BTN_X1, BTN_X2 = 1, 2, 3, 4, 5

_BUTTON_MSGS = {
    WM_LBUTTONDOWN: (BTN_L, True), WM_LBUTTONUP: (BTN_L, False),
    WM_RBUTTONDOWN: (BTN_R, True), WM_RBUTTONUP: (BTN_R, False),
    WM_MBUTTONDOWN: (BTN_M, True), WM_MBUTTONUP: (BTN_M, False),
}

KF_UP, KF_EXT = 1, 2

_VK_NAMES = {"esc": 0x1B, "pause": 0x13, "scroll": 0x91, "insert": 0x2D, "home": 0x24, "end": 0x23,
             "pageup": 0x21, "pagedown": 0x22, "space": 0x20, "tab": 0x09, "enter": 0x0D, "backspace": 0x08}
_MOD_VKS = {"ctrl": {0x11, 0xA2, 0xA3}, "alt": {0x12, 0xA4, 0xA5},
            "shift": {0x10, 0xA0, 0xA1}, "win": {0x5B, 0x5C}}


def parse_hotkey(spec: Optional[str]) -> Optional[Tuple[frozenset, int]]:
    if not spec or spec.lower() in ("none", "off"):
        return None
    parts = [p.strip().lower() for p in spec.split("+") if p.strip()]
    mods = frozenset(p for p in parts[:-1] if p in _MOD_VKS)
    k = parts[-1]
    if k in _VK_NAMES:
        vk = _VK_NAMES[k]
    elif k.startswith("f") and k[1:].isdigit() and 1 <= int(k[1:]) <= 24:
        vk = 0x6F + int(k[1:])
    elif len(k) == 1 and k.isalnum():
        vk = ord(k.upper())
    else:
        raise ValueError(f"unsupported hotkey {spec!r}")
    return mods, vk


class KeyTracker:
    """Per-key ownership so a key pressed on one side is always released on the
    same side, whatever happens to pointer ownership in between."""

    def __init__(self):
        self.state: Dict[tuple, str] = {}   # key -> 'local' | 'fwd' | 'drop'

    def on_event(self, key, up: bool, forwarding: bool) -> Tuple[bool, bool]:
        """Return (swallow, forward)."""
        st = self.state.get(key)
        if forwarding:
            if not up:
                if st in ("local", "drop"):
                    return True, False          # auto-repeat of a pre-handoff key
                self.state[key] = "fwd"
                return True, True
            if st == "local":
                del self.state[key]
                return False, False             # let the local OS see the release
            if st == "fwd":
                del self.state[key]
                return True, True
            if st == "drop":
                del self.state[key]
                return True, False
            return False, False
        if not up:
            if st in ("drop", "fwd"):
                return True, False
            self.state[key] = "local"
            return False, False
        if st == "drop":
            del self.state[key]
            return True, False
        self.state.pop(key, None)
        return False, False

    def drop_forwarded(self) -> None:
        for k, v in list(self.state.items()):
            if v == "fwd":
                self.state[k] = "drop"


class Router:
    def __init__(self, cfg: dict, platform, tx, metrics, my_id: str):
        self.cfg, self.platform, self.tx, self.metrics, self.my_id = cfg, platform, tx, metrics, my_id
        self.icfg = cfg["input"]
        self.lock = threading.RLock()
        self.machine: Optional[str] = cfg.get("role")
        self.peer_machine: Optional[str] = None
        self.layouts: Dict[str, List[topo.Monitor]] = {}
        self.resolved: Optional[topo.Resolved] = None
        self.topology_error: Optional[str] = None
        self.topology_warnings: List[str] = []

        self.session_up = False
        self.sec_local = False
        self.sec_peer = False
        self.input_enabled = bool(cfg["features"]["input"])
        self._was_active = False
        self.peer_id = ""
        self.peer_idle_ms = 0
        self.peer_epoch = 0

        self.owner_local = True
        self.epoch = 0
        self.pos: Tuple[int, int] = (0, 0)
        self.park: Tuple[int, int] = (0, 0)
        self.last_switch = 0.0
        self.last_input = time.monotonic()
        self._expect: Optional[Tuple[int, int]] = None
        self._expect_t = 0.0
        self._rem = [0.0, 0.0]
        self._last_d = (0, 0)
        self._force = None            # set by split-mode resume: explicit owner chosen by the user
        self._force_epoch = 0

        self.keys = KeyTracker()
        self.mods: Set[str] = set()
        self.local_buttons: Set[int] = set()
        self.fwd_buttons: Set[int] = set()
        self.injected_buttons: Set[int] = set()
        self.injected_keys: Dict[tuple, tuple] = {}
        self._hk_swallow: Set[int] = set()
        self.reclaim_hk = parse_hotkey(self.icfg.get("reclaim_hotkey"))
        self.clip_hk = parse_hotkey(self.icfg.get("clipboard_pause_hotkey"))
        self.split_hk = parse_hotkey(self.icfg.get("split_hotkey"))
        self.on_split_hotkey = None
        self.on_clip_hotkey = None
        self.on_state_change = None

    # ------------------------------------------------------------------ state
    def idle_ms(self) -> int:
        return int((time.monotonic() - self.last_input) * 1000)

    def _active(self) -> bool:
        return (self.session_up and self.input_enabled and not self.sec_local
                and not self.sec_peer and self.resolved is not None)

    def _forwarding(self) -> bool:
        return self._active() and not self.owner_local

    def status(self) -> dict:
        with self.lock:
            return {"active": self._active(), "owner": "local" if self.owner_local else "peer",
                    "epoch": self.epoch, "pos": self.pos, "topology_error": self.topology_error,
                    "warnings": self.topology_warnings, "secure_local": self.sec_local,
                    "secure_peer": self.sec_peer}

    # --------------------------------------------------------------- topology
    def set_layout(self, machine: str, monitors: List[topo.Monitor]):
        with self.lock:
            self.layouts[machine] = monitors
            self._resolve()

    def _resolve(self):
        try:
            self.resolved = topo.resolve(self.cfg["topology"], self.layouts, self.icfg["entry_inset_px"])
            self.topology_error = None
            self.topology_warnings = self.resolved.warnings()
            for w in self.topology_warnings:
                log.warning(w)
        except topo.TopologyError as e:
            self.resolved = None
            self.topology_error = str(e)
        self._update_routing()

    # ---------------------------------------------------------- session events
    def on_link_up(self, peer_id: str, peer_role: str, idle_ms: int, epoch: int):
        with self.lock:
            self.session_up, self.peer_id, self.peer_machine = True, peer_id, peer_role
            self.peer_idle_ms, self.peer_epoch = idle_ms, epoch
            self._update_routing()

    def on_link_down(self):
        with self.lock:
            self.session_up = False
            self.sec_peer = False
            self._force = None
            self._update_routing()

    def set_secure_local(self, active: bool):
        with self.lock:
            self.sec_local = active
            self._update_routing()

    def set_secure_peer(self, active: bool):
        with self.lock:
            self.sec_peer = active
            self._update_routing()

    def set_input_enabled(self, on: bool, owner_local=None, epoch=None):
        """Turn input sharing on/off ("split mode" = off: both computers fully independent).
        When turning it back on, `owner_local` says who gets the pointer and `epoch` is the shared
        fencing token, so both sides resume in exactly the same state (no guessing from stale idle times)."""
        with self.lock:
            self.input_enabled = on
            if on and owner_local is not None and epoch is not None and self.session_up:
                self._force, self._force_epoch = owner_local, int(epoch)
            self._update_routing()

    def _update_routing(self):
        now_active = self._active()
        if now_active and not self._was_active:
            self._activate()
        elif not now_active and self._was_active:
            self._deactivate()
        self._was_active = now_active
        if self.on_state_change:
            self.on_state_change()

    def _activate(self):
        """Link (re)established: decide who owns the pointer. Both sides run the
        same deterministic rule on the same inputs, so they always agree."""
        if self._force is not None:
            mine_wins, self.epoch, self._force = self._force, self._force_epoch, None
        else:
            mine_wins = (self.idle_ms(), self.my_id) < (self.peer_idle_ms, self.peer_id)
            self.epoch = max(self.epoch, self.peer_epoch) + 1
        if mine_wins:
            self.owner_local = True
            self.pos = self.platform.cursor_pos()
        else:
            self.owner_local = False
            self.park = self.platform.begin_capture()
        self.last_switch = time.monotonic()
        log.info("routing active, owner=%s epoch=%d", "local" if self.owner_local else "peer", self.epoch)

    def _deactivate(self):
        if not self.owner_local:
            self.owner_local = True
            self.platform.end_capture()
        self._release_injected()
        self.keys.drop_forwarded()
        self.fwd_buttons.clear()
        self._expect = None
        log.info("routing inactive; local control restored")

    def _release_injected(self):
        """Release everything we injected on behalf of the peer (no stuck keys)."""
        for key, (vk, scan, ext) in list(self.injected_keys.items()):
            self.platform.key(vk, scan, True, ext)
        self.injected_keys.clear()
        for b in list(self.injected_buttons):
            self.platform.button(b, False)
        self.injected_buttons.clear()

    # ----------------------------------------------------------- local events
    def on_local_mouse(self, msg: int, x: int, y: int, data: int, ours: bool, injected: bool) -> bool:
        """Called from the hook thread. Returns True to swallow the event."""
        if ours:
            if msg == WM_MOUSEMOVE:
                self.pos = (x, y)
            return False
        now = time.monotonic()
        # Hook callbacks must never wait long: SendInput() on another thread can
        # be blocked waiting for *this* hook, so we never block on the lock.
        if not self.lock.acquire(timeout=0.05):
            self.metrics.count("hook_lock_timeout")
            return False
        try:
            if msg == WM_MOUSEMOVE and self._expect is not None:
                if (x, y) == self._expect and now - self._expect_t < 0.25:
                    self._expect = None
                    self.pos = (x, y)
                    return False
            if not injected:
                self.last_input = now
            fwd = self._forwarding()
            if msg == WM_MOUSEMOVE:
                return self._fwd_move(x, y) if fwd else self._local_move(x, y, now)
            bd = _BUTTON_MSGS.get(msg)
            if bd is None and msg in (WM_XBUTTONDOWN, WM_XBUTTONUP):
                bd = (BTN_X1 if ((data >> 16) & 0xFFFF) == 1 else BTN_X2, msg == WM_XBUTTONDOWN)
            if bd is not None:
                return self._local_button(bd[0], bd[1], fwd)
            if msg in (WM_MOUSEWHEEL, WM_MOUSEHWHEEL):
                if not fwd:
                    return False
                d = (data >> 16) & 0xFFFF
                d = d - 0x10000 if d & 0x8000 else d
                if msg == WM_MOUSEWHEEL:
                    self.tx.wheel(self.epoch, 0, d)
                else:
                    self.tx.wheel(self.epoch, d, 0)
                return True
            return False
        finally:
            self.lock.release()

    def _local_move(self, x: int, y: int, now: float) -> bool:
        prev, self.pos = self.pos, (x, y)
        dx, dy = x - prev[0], y - prev[1]
        if dx or dy:
            self._last_d = (dx, dy)
        else:
            # Pointer is clamped at a screen edge and the hook repeats the position: the user is
            # still pushing, so keep the last direction of travel (otherwise an edge arrival that
            # was ignored once could never trigger again).
            dx, dy = self._last_d
        if not self._active() or self.resolved is None or (dx == 0 and dy == 0):
            return False
        if now - self.last_switch < self.icfg["switch_cooldown_ms"] / 1000.0:
            return False
        if self.icfg["block_cross_while_buttons"] and (self.local_buttons or self.injected_buttons):
            return False
        c = self.resolved.edge_touch(self.machine, (x, y), dx, dy)
        if c is None:
            return False
        self._handoff(c, now)
        return True

    def _handoff(self, c: topo.Crossing, now: float):
        self.epoch += 1
        self.tx.enter(self.epoch, c.x, c.y)       # tell the peer first: lowest latency
        self.owner_local = False
        self._release_injected()
        self.last_switch = now
        self.park = self.platform.begin_capture()
        self.metrics.count("handoff_out")

    def _scale(self, dx: int, dy: int) -> Tuple[int, int]:
        s = float(self.icfg.get("pointer_speed", 1.0))
        if s == 1.0:
            return dx, dy
        fx, fy = dx * s + self._rem[0], dy * s + self._rem[1]
        ix, iy = int(fx), int(fy)
        self._rem = [fx - ix, fy - iy]
        return ix, iy

    def _fwd_move(self, x: int, y: int) -> bool:
        dx, dy = x - self.park[0], y - self.park[1]
        if dx or dy:
            dx, dy = self._scale(dx, dy)
            if dx or dy:
                self.tx.move(self.epoch, dx, dy)
        return True

    def _local_button(self, btn: int, down: bool, fwd: bool) -> bool:
        if not fwd:
            (self.local_buttons.add if down else self.local_buttons.discard)(btn)
            return False
        if down:
            self.fwd_buttons.add(btn)
            self.tx.button(self.epoch, btn, 1)
            return True
        if btn in self.local_buttons:             # pressed before the handoff
            self.local_buttons.discard(btn)
            return False
        if btn in self.fwd_buttons:
            self.fwd_buttons.discard(btn)
            self.tx.button(self.epoch, btn, 0)
            return True
        return False

    def on_local_key(self, vk: int, scan: int, flags: int, ours: bool, injected: bool) -> bool:
        if ours:
            return False
        up, ext = bool(flags & 0x80), bool(flags & 0x01)
        if not self.lock.acquire(timeout=0.05):
            self.metrics.count("hook_lock_timeout")
            return False
        try:
            if not injected:
                self.last_input = time.monotonic()
            self._track_mods(vk, up)
            if self._hotkey(vk, up):
                return True
            if injected and not self.icfg.get("forward_injected_keys"):
                return False
            fwd = self._forwarding()
            swallow, send = self.keys.on_event((vk, scan, ext), up, fwd)
            if send:
                self.tx.key(self.epoch, vk, scan, (KF_UP if up else 0) | (KF_EXT if ext else 0))
            return swallow
        finally:
            self.lock.release()

    def _track_mods(self, vk: int, up: bool):
        for name, vks in _MOD_VKS.items():
            if vk in vks:
                (self.mods.discard if up else self.mods.add)(name)

    def _hotkey(self, vk: int, up: bool) -> bool:
        if up:
            if vk in self._hk_swallow:
                self._hk_swallow.discard(vk)
                return True
            return False
        for hk, action in ((self.reclaim_hk, self.reclaim), (self.clip_hk, self._clip_hotkey),
                           (self.split_hk, self._split_hotkey)):
            if hk and vk == hk[1] and hk[0] <= self.mods:
                self._hk_swallow.add(vk)
                action()
                return True
        return False

    def _split_hotkey(self):
        if self.on_split_hotkey:
            self.on_split_hotkey()

    def _clip_hotkey(self):
        if self.on_clip_hotkey:
            self.on_clip_hotkey()

    def reclaim(self):
        """Escape hatch: take the pointer back to this machine, unconditionally."""
        with self.lock:
            was_fwd = not self.owner_local
            self.epoch += 1
            self.owner_local = True
            if self.session_up:
                self.tx.claim(self.epoch)
            self._release_injected()
            self.keys.drop_forwarded()
            self.fwd_buttons.clear()
            self.last_switch = time.monotonic()
            if was_fwd:
                self.platform.end_capture()
                self.pos = self.platform.cursor_pos()
            self.metrics.count("reclaim")
            log.warning("pointer reclaimed locally (epoch %d)", self.epoch)

    def on_tick(self):
        """~4 Hz housekeeping from the input thread."""
        with self.lock:
            if self._forwarding():
                self.platform.recenter(self.park)

    # External sources (e.g. the air-mouse adapter): same path as a hardware device.
    def external_move(self, dx: int, dy: int):
        with self.lock:
            self.last_input = time.monotonic()
            if self._forwarding():
                self.tx.move(self.epoch, dx, dy)
            elif self._active() and self.owner_local:
                self._apply_move(dx, dy)
            else:                                   # not linked: behave like a plain local mouse
                x, y = self.platform.cursor_pos()
                q = (x + dx, y + dy)
                mons = self.layouts.get(self.machine) or []
                if mons:
                    q = topo.clamp_to_union(mons, q)
                self.platform.move_abs(*q)

    def external_button(self, btn: int, down: bool):
        with self.lock:
            self.last_input = time.monotonic()
            if self._forwarding():
                self.tx.button(self.epoch, btn, 1 if down else 0)
            else:
                self.platform.button(btn, down)

    # ------------------------------------------------------------ peer events
    def _limit(self, v: int) -> int:
        m = int(self.icfg["max_delta"])
        return max(-m, min(m, v))

    def _accept(self, epoch: int) -> bool:
        return self._active() and self.owner_local and epoch == self.epoch

    def on_peer_move(self, epoch: int, dx: int, dy: int, ts_ns: int = 0, offset_ns: int = 0):
        with self.lock:
            if not self._accept(epoch):
                self.metrics.count("stale_input_dropped")
                return
            t0 = time.perf_counter_ns()
            self._apply_move(self._limit(dx), self._limit(dy))
            t1 = time.perf_counter_ns()
            self.metrics.observe("inject_us", (t1 - t0) / 1000)
            if ts_ns:
                self.metrics.observe("move_oneway_ms", (t1 - (ts_ns - offset_ns)) / 1e6)

    def _apply_move(self, dx: int, dy: int):
        pos = self.pos
        res = self.resolved.advance(self.machine, pos, (pos[0] + dx, pos[1] + dy))
        now = time.monotonic()
        if res[0] == "cross":
            blocked = (now - self.last_switch < self.icfg["switch_cooldown_ms"] / 1000.0 or
                       (self.icfg["block_cross_while_buttons"] and (self.local_buttons or self.injected_buttons)))
            if not blocked:
                self._handoff(res[1], now)
                return
            new = self.resolved.clamp(self.machine, pos, (pos[0] + dx, pos[1] + dy))
        else:
            new = res[1]
        if new != pos:
            self._expect, self._expect_t, self.pos = new, now, new
            self.platform.move_abs(*new)

    def on_peer_button(self, epoch: int, btn: int, down: int):
        with self.lock:
            if not self._accept(epoch) or btn not in (1, 2, 3, 4, 5):
                return
            (self.injected_buttons.add if down else self.injected_buttons.discard)(btn)
            self.platform.button(btn, bool(down))

    def on_peer_wheel(self, epoch: int, dx: int, dy: int):
        with self.lock:
            if self._accept(epoch):
                self.platform.wheel(self._limit(dx), self._limit(dy))

    def on_peer_key(self, epoch: int, vk: int, scan: int, flags: int):
        with self.lock:
            if not self._accept(epoch) or not (1 <= vk <= 254):
                return
            up, ext = bool(flags & KF_UP), bool(flags & KF_EXT)
            key = (vk, scan, ext)
            if up:
                self.injected_keys.pop(key, None)
            else:
                self.injected_keys[key] = key
            self.platform.key(vk, scan, up, ext)

    def on_enter(self, epoch: int, x: int, y: int):
        """Peer hands the pointer to us."""
        with self.lock:
            if not self._active() or epoch <= self.epoch:
                return
            if self.owner_local:
                log.warning("ENTER while already owner; peer's epoch wins")
            self.epoch = epoch
            self.owner_local = True
            self._release_injected()
            self.keys.drop_forwarded()
            self.fwd_buttons.clear()
            self.platform.end_capture()
            if self.resolved and not self.resolved.inside(self.machine, x, y):
                x, y = self.resolved.clamp(self.machine, self.pos, (x, y))
            self.last_switch = time.monotonic()
            self._expect, self._expect_t, self.pos = (x, y), self.last_switch, (x, y)
            self.platform.move_abs(x, y)
            self.metrics.count("handoff_in")

    def on_claim(self, epoch: int):
        """Peer used its escape hatch: it owns the pointer now."""
        with self.lock:
            if not self._active() or epoch <= self.epoch:
                return
            self.epoch = epoch
            if self.owner_local:
                self.owner_local = False
                self._release_injected()
                self.park = self.platform.begin_capture()
            self.last_switch = time.monotonic()