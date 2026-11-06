"""Virtual desktop topology.

Pure logic, no OS calls, so it is fully unit-testable.

Terminology
-----------
* machine   - one computer ("laptop", "desktop"). Its monitors live in that
              machine's own virtual-desktop pixel space (physical pixels).
* screen    - a named monitor that takes part in the layout, e.g.
              "laptop", "desk-secondary", "desk-primary".
* link      - an adjacency between two screen edges. A link between screens of
              the *same* machine is "native": Windows already moves the pointer
              across it, we only validate it. A link between screens of
              *different* machines is "managed": we hand the pointer over.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

SIDES = ("left", "right", "top", "bottom")
OPPOSITE = {"left": "right", "right": "left", "top": "bottom", "bottom": "top"}
ALIGNS = ("proportional", "top", "center", "physical")


class TopologyError(Exception):
    pass


@dataclass(frozen=True)
class Rect:
    x: int
    y: int
    w: int
    h: int

    @property
    def left(self) -> int:
        return self.x

    @property
    def right(self) -> int:  # exclusive
        return self.x + self.w

    @property
    def top(self) -> int:
        return self.y

    @property
    def bottom(self) -> int:  # exclusive
        return self.y + self.h

    def contains(self, px: int, py: int) -> bool:
        return self.x <= px < self.right and self.y <= py < self.bottom


@dataclass(frozen=True)
class Monitor:
    rect: Rect
    dpi: int = 96
    primary: bool = False
    device: str = ""

    @property
    def scale(self) -> float:
        return max(self.dpi, 1) / 96.0

    def to_dict(self) -> dict:
        r = self.rect
        return {"x": r.x, "y": r.y, "w": r.w, "h": r.h, "dpi": self.dpi,
                "primary": self.primary, "device": self.device}

    @staticmethod
    def from_dict(d: dict) -> "Monitor":
        w, h = int(d["w"]), int(d["h"])
        if not (0 < w <= 65536 and 0 < h <= 65536):
            raise TopologyError("implausible monitor size")
        return Monitor(Rect(int(d["x"]), int(d["y"]), w, h),
                       int(d.get("dpi", 96)) or 96, bool(d.get("primary")),
                       str(d.get("device", ""))[:64])


@dataclass(frozen=True)
class Link:
    a: str
    a_side: str
    b: str
    b_side: str
    align: str = "proportional"
    offset: int = 0  # pixels, applied in the a->b direction (negated b->a)


@dataclass(frozen=True)
class Crossing:
    machine: str
    screen: str
    x: int
    y: int


def pick_monitor(monitors: List[Monitor], select: str) -> Monitor:
    """Resolve a selector such as 'primary', 'secondary', 'leftmost', 'index:1'."""
    if not monitors:
        raise TopologyError("machine reports no monitors")
    sel = (select or "primary").strip().lower()
    ordered = sorted(monitors, key=lambda m: (m.rect.x, m.rect.y))
    if sel == "primary":
        for m in monitors:
            if m.primary:
                return m
        return ordered[0]
    if sel in ("secondary", "non-primary"):
        others = [m for m in ordered if not m.primary]
        if len(others) != 1:
            raise TopologyError(
                f"selector 'secondary' is ambiguous ({len(others)} non-primary monitors); "
                "use 'index:N' or 'device:<name>'")
        return others[0]
    if sel in ("left", "leftmost"):
        return ordered[0]
    if sel in ("right", "rightmost"):
        return ordered[-1]
    if sel in ("only", "auto"):
        if len(monitors) != 1:
            raise TopologyError("selector 'only' needs exactly one monitor")
        return monitors[0]
    if sel.startswith("index:"):
        try:
            return ordered[int(sel[6:])]
        except (ValueError, IndexError):
            raise TopologyError(f"bad monitor selector {select!r}")
    if sel.startswith("device:"):
        want = sel[7:]
        for m in monitors:
            if m.device.lower().endswith(want):
                return m
        raise TopologyError(f"no monitor matching {select!r}")
    raise TopologyError(f"unknown monitor selector {select!r}")


class Resolved:
    """A topology bound to concrete monitor rectangles."""

    def __init__(self, screens: Dict[str, Tuple[str, Monitor]],
                 machine_monitors: Dict[str, List[Monitor]],
                 links: List[Link], inset: int = 1, corner_dead: int = 0):
        self.corner_dead = max(0, int(corner_dead))   # px at both ends of a managed edge that never switch
        self.screens = screens                    # id -> (machine, Monitor)
        self.machine_monitors = machine_monitors  # machine -> all monitors
        self.links = links
        self.inset = max(0, inset)
        self._by_side: Dict[Tuple[str, str], Tuple[Link, str, str]] = {}
        for ln in links:
            self._by_side[(ln.a, ln.a_side)] = (ln, ln.b, ln.b_side)
            self._by_side[(ln.b, ln.b_side)] = (ln, ln.a, ln.a_side)

    # -- queries ---------------------------------------------------------
    def is_managed(self, link: Link) -> bool:
        return self.screens[link.a][0] != self.screens[link.b][0]

    def inside(self, machine: str, x: int, y: int) -> bool:
        return any(m.rect.contains(x, y) for m in self.machine_monitors.get(machine, ()))

    def screen_at(self, machine: str, x: int, y: int) -> Optional[str]:
        for sid, (mach, mon) in self.screens.items():
            if mach == machine and mon.rect.contains(x, y):
                return sid
        return None

    def _nearest_screen(self, machine: str, x: int, y: int) -> Optional[str]:
        best, best_d = None, None
        for sid, (mach, mon) in self.screens.items():
            if mach != machine:
                continue
            r = mon.rect
            dx = max(r.left - x, 0, x - (r.right - 1))
            dy = max(r.top - y, 0, y - (r.bottom - 1))
            d = dx * dx + dy * dy
            if best_d is None or d < best_d:
                best, best_d = sid, d
        return best

    def clamp(self, machine: str, pos: Tuple[int, int], q: Tuple[int, int]) -> Tuple[int, int]:
        """Clamp an attempted position into the screen containing `pos`."""
        sid = self.screen_at(machine, *pos) or self._nearest_screen(machine, *pos)
        if sid is None:
            return pos
        r = self.screens[sid][1].rect
        return (min(max(q[0], r.left), r.right - 1), min(max(q[1], r.top), r.bottom - 1))

    # -- crossing --------------------------------------------------------
    def _managed_link(self, sid: str, side: str):
        hit = self._by_side.get((sid, side))
        if hit and self.is_managed(hit[0]):
            return hit
        return None

    def _map_along(self, link: Link, src: str, dst: str, along: int, vertical_edge: bool) -> int:
        s_mach, s_mon = self.screens[src]
        d_mach, d_mon = self.screens[dst]
        sr, dr = s_mon.rect, d_mon.rect
        s_lo, s_len = (sr.top, sr.h) if vertical_edge else (sr.left, sr.w)
        d_lo, d_len = (dr.top, dr.h) if vertical_edge else (dr.left, dr.w)
        t = min(max(along - s_lo, 0), s_len - 1)
        off = link.offset if src == link.a else -link.offset
        mode = link.align
        if mode == "top":
            v = d_lo + t + off
        elif mode == "center":
            v = d_lo + d_len // 2 + (t - s_len // 2) + off
        elif mode == "physical":
            v = d_lo + round(t * (d_mon.scale / s_mon.scale)) + off
        else:  # proportional
            f = t / (s_len - 1) if s_len > 1 else 0.5
            v = d_lo + round(f * (d_len - 1)) + off
        return min(max(v, d_lo), d_lo + d_len - 1)  # clamp: never a dead zone

    def _cross(self, src: str, side: str, along: int) -> Optional[Crossing]:
        hit = self._managed_link(src, side)
        if not hit:
            return None
        link, dst, dst_side = hit
        vertical = side in ("left", "right")
        if self.corner_dead:
            sr = self.screens[src][1].rect
            lo, length = (sr.top, sr.h) if vertical else (sr.left, sr.w)
            t = min(max(along - lo, 0), length - 1)
            if t < self.corner_dead or t > length - 1 - self.corner_dead:
                return None                       # corner: like plain Windows, the pointer just stops here
        v = self._map_along(link, src, dst, along, vertical)
        d_mach, d_mon = self.screens[dst]
        r, k = d_mon.rect, self.inset
        if dst_side == "left":
            x, y = r.left + k, v
        elif dst_side == "right":
            x, y = r.right - 1 - k, v
        elif dst_side == "top":
            x, y = v, r.top + k
        else:
            x, y = v, r.bottom - 1 - k
        return Crossing(d_mach, dst, min(max(x, r.left), r.right - 1), min(max(y, r.top), r.bottom - 1))

    def advance(self, machine: str, pos: Tuple[int, int], q: Tuple[int, int]):
        """Software-tracked pointer: move from pos to attempted q.

        Returns ('move', (x, y)) or ('cross', Crossing)."""
        if self.inside(machine, *q):
            return ("move", q)
        sid = self.screen_at(machine, *pos) or self._nearest_screen(machine, *pos)
        if sid is None:
            return ("move", pos)
        r = self.screens[sid][1].rect
        sides = []
        if q[0] >= r.right:
            sides.append("right")
        elif q[0] < r.left:
            sides.append("left")
        if q[1] >= r.bottom:
            sides.append("bottom")
        elif q[1] < r.top:
            sides.append("top")
        for side in sides:
            along = q[1] if side in ("left", "right") else q[0]
            c = self._cross(sid, side, along)
            if c:
                return ("cross", c)
        return ("move", self.clamp(machine, pos, q))

    def edge_touch(self, machine: str, p: Tuple[int, int], dx: int, dy: int) -> Optional[Crossing]:
        """OS-tracked pointer (clamped by Windows): did it touch a managed edge
        while moving towards it?"""
        # A fast flick (or a corner) can be reported *past* the edge by the LL hook, i.e. outside every
        # screen. Fall back to the nearest screen so an overshoot still counts as touching its edge.
        sid = self.screen_at(machine, *p) or self._nearest_screen(machine, *p)
        if sid is None:
            return None
        r = self.screens[sid][1].rect
        tests = (("right", dx > 0 and p[0] >= r.right - 1, p[1]),
                 ("left", dx < 0 and p[0] <= r.left, p[1]),
                 ("bottom", dy > 0 and p[1] >= r.bottom - 1, p[0]),
                 ("top", dy < 0 and p[1] <= r.top, p[0]))
        for side, hit, along in tests:
            if hit:
                c = self._cross(sid, side, along)
                if c:
                    return c
        return None

    # -- validation --------------------------------------------------------
    def warnings(self) -> List[str]:
        out = []
        for ln in self.links:
            ma, a = self.screens[ln.a]
            mb, b = self.screens[ln.b]
            ra, rb = a.rect, b.rect
            if ma == mb:
                ok = False
                if ln.a_side == "right" and ln.b_side == "left":
                    ok = ra.right == rb.left and min(ra.bottom, rb.bottom) > max(ra.top, rb.top)
                elif ln.a_side == "left" and ln.b_side == "right":
                    ok = rb.right == ra.left and min(ra.bottom, rb.bottom) > max(ra.top, rb.top)
                elif ln.a_side == "bottom" and ln.b_side == "top":
                    ok = ra.bottom == rb.top and min(ra.right, rb.right) > max(ra.left, rb.left)
                elif ln.a_side == "top" and ln.b_side == "bottom":
                    ok = rb.bottom == ra.top and min(ra.right, rb.right) > max(ra.left, rb.left)
                if not ok:
                    out.append(
                        f"Windows display arrangement on '{ma}' does not match the configured order "
                        f"({ln.a} {ln.a_side} of {ln.b}). Fix it in Settings > System > Display.")
            else:
                for sid, side in ((ln.a, ln.a_side), (ln.b, ln.b_side)):
                    mach, mon = self.screens[sid]
                    r = mon.rect
                    for other in self.machine_monitors[mach]:
                        o = other.rect
                        if o == r:
                            continue
                        if side == "left" and o.right == r.left and min(o.bottom, r.bottom) > max(o.top, r.top):
                            out.append(f"'{sid}' has another monitor on its {side} edge; "
                                       "the managed edge is not on the outside of the desktop.")
                        if side == "right" and o.left == r.right and min(o.bottom, r.bottom) > max(o.top, r.top):
                            out.append(f"'{sid}' has another monitor on its {side} edge; "
                                       "the managed edge is not on the outside of the desktop.")
        return out


def clamp_to_union(monitors: List[Monitor], q: Tuple[int, int]) -> Tuple[int, int]:
    """Nearest point to q inside the union of monitor rectangles."""
    best, best_d = q, None
    for m in monitors:
        r = m.rect
        c = (min(max(q[0], r.left), r.right - 1), min(max(q[1], r.top), r.bottom - 1))
        d = (c[0] - q[0]) ** 2 + (c[1] - q[1]) ** 2
        if best_d is None or d < best_d:
            best, best_d = c, d
    return best


def resolve(cfg: dict, machines: Dict[str, List[Monitor]], inset: int = 1, corner_dead: int = 0) -> Resolved:
    """Bind a topology config to detected monitors of every machine."""
    specs = cfg.get("screens") or []
    order = cfg.get("order") or [s["id"] for s in specs]
    by_id = {s["id"]: s for s in specs}
    if len(by_id) != len(specs):
        raise TopologyError("duplicate screen id")
    for sid in order:
        if sid not in by_id:
            raise TopologyError(f"order references unknown screen {sid!r}")
    screens: Dict[str, Tuple[str, Monitor]] = {}
    for s in specs:
        mach = s["machine"]
        if mach not in machines:
            raise TopologyError(f"machine {mach!r} is not connected yet")
        screens[s["id"]] = (mach, pick_monitor(machines[mach], s.get("select", "primary")))
    links: List[Link] = []
    explicit = cfg.get("links")
    if explicit:
        for e in explicit:
            if e["a_side"] not in SIDES or e["b_side"] not in SIDES:
                raise TopologyError("bad side in link")
            if e["a"] not in screens or e["b"] not in screens:
                raise TopologyError("link references unknown screen")
            align = e.get("align", "proportional")
            if align not in ALIGNS:
                raise TopologyError(f"bad align {align!r}")
            links.append(Link(e["a"], e["a_side"], e["b"], e["b_side"], align, int(e.get("offset", 0))))
    else:
        for a, b in zip(order, order[1:]):
            links.append(Link(a, "right", b, "left"))
    return Resolved(screens, {m: list(v) for m, v in machines.items()}, links, inset, corner_dead)


DEFAULT_TOPOLOGY = {
    "screens": [
        {"id": "laptop", "machine": "laptop", "select": "primary"},
        {"id": "desk-secondary", "machine": "desktop", "select": "secondary"},
        {"id": "desk-primary", "machine": "desktop", "select": "primary"},
    ],
    "order": ["laptop", "desk-secondary", "desk-primary"],
    "links": None,
}