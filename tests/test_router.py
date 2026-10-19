"""Two routers wired back-to-back through fake platforms = full handoff simulation."""
import time
from kvmshare import router as R, config
from kvmshare.metrics import Metrics
from kvmshare.topology import Monitor, Rect

def mon(x, y, w, h, dpi=96, primary=False): return Monitor(Rect(x, y, w, h), dpi, primary)
LAP = [mon(0, 0, 1920, 1080, 144, True)]
DESK = [mon(-1920, 0, 1920, 1080), mon(0, 0, 2560, 1440, 96, True)]

class FakePlat:
    def __init__(self, pos): self.log = []; self.pos = pos; self.captured = False
    def cursor_pos(self): return self.pos
    def move_abs(self, x, y): self.pos = (x, y); self.log.append(("move", x, y))
    def button(self, b, d): self.log.append(("btn", b, d))
    def wheel(self, dx, dy): self.log.append(("wheel", dx, dy))
    def key(self, vk, sc, up, ext): self.log.append(("key", vk, up))
    def begin_capture(self): self.captured = True; return (960, 540)
    def end_capture(self): self.captured = False
    def recenter(self, p): pass

class Wire:
    def __init__(self): self.peer = None; self.q = []
    def move(self, e, dx, dy): self.q.append(("m", e, dx, dy))
    def wheel(self, e, dx, dy): self.q.append(("w", e, dx, dy))
    def button(self, e, b, d): self.q.append(("b", e, b, d))
    def key(self, e, vk, sc, fl): self.q.append(("k", e, vk, sc, fl))
    def enter(self, e, x, y): self.q.append(("e", e, x, y))
    def claim(self, e): self.q.append(("c", e))
    def pump(self):
        r = self.peer
        while self.q:
            m = self.q.pop(0)
            {"m": lambda: r.on_peer_move(m[1], m[2], m[3]), "w": lambda: r.on_peer_wheel(m[1], m[2], m[3]),
             "b": lambda: r.on_peer_button(m[1], m[2], m[3]), "k": lambda: r.on_peer_key(m[1], m[2], m[3], m[4]),
             "e": lambda: r.on_enter(m[1], m[2], m[3]), "c": lambda: r.on_claim(m[1])}[m[0]]()

def make(role, pos, my_id):
    cfg = config.deep_merge(config.DEFAULTS, {"role": role, "input": {"switch_cooldown_ms": 0}})
    plat, wire = FakePlat(pos), Wire()
    r = R.Router(cfg, plat, wire, Metrics(), my_id)
    r.pos = pos
    return r, plat, wire

def linked():
    lap, lp, lw = make("laptop", (500, 500), "aaa")
    dsk, dp, dw = make("desktop", (500, 500), "bbb")
    lw.peer, dw.peer = dsk, lap
    for r in (lap, dsk):
        r.set_layout("laptop", LAP); r.set_layout("desktop", DESK)
    lap.last_input = time.monotonic(); dsk.last_input = time.monotonic() - 60
    li, di, le, de = lap.idle_ms(), dsk.idle_ms(), lap.epoch, dsk.epoch   # hellos cross on the wire
    lap.on_link_up("bbb", "desktop", di, de)
    dsk.on_link_up("aaa", "laptop", li, le)
    return (lap, lp, lw), (dsk, dp, dw)

def edge(lap):  # push the laptop pointer into its right edge
    return lap.on_local_mouse(R.WM_MOUSEMOVE, 1919, 540, 0, False, False)

def test_deterministic_owner_agreement():
    (lap, lp, lw), (dsk, dp, dw) = linked()
    assert lap.owner_local and not dsk.owner_local and dp.captured and not lp.captured
    assert lap.epoch == dsk.epoch

def test_full_crossing_laptop_to_desktop_and_back():
    (lap, lp, lw), (dsk, dp, dw) = linked()
    assert lap.on_local_mouse(R.WM_MOUSEMOVE, 1900, 540, 0, False, False) is False
    assert edge(lap) is True and not lap.owner_local and lp.captured
    lw.pump()
    assert dsk.owner_local and not dp.captured and dp.pos == (-1919, 540)
    assert lap.on_local_mouse(R.WM_MOUSEMOVE, 990, 540, 0, False, False) is True      # trackpad drives desktop
    lw.pump()
    assert dp.pos == (-1889, 540)
    assert dsk.on_local_mouse(R.WM_MOUSEMOVE, -2, 540, 0, False, False) is False       # desktop mouse native
    dsk.pos = (-3, 540)
    dsk.on_peer_move(dsk.epoch, 10, 0)
    assert dp.pos == (7, 540)                                                          # crossed native seam
    dsk.pos = (-1918, 540)
    for _ in range(3):
        lap.on_local_mouse(R.WM_MOUSEMOVE, 960 - 40, 540, 0, False, False); lw.pump(); dw.pump()
    assert not dsk.owner_local and lap.owner_local and not lp.captured and lp.pos[0] == 1918

def test_stale_epoch_dropped():
    (lap, lp, lw), (dsk, dp, dw) = linked()
    edge(lap); lw.pump()
    before = list(dp.log)
    dsk.on_peer_move(dsk.epoch - 1, 50, 0)
    assert dp.log == before and dsk.metrics.c.get("stale_input_dropped") == 1

def test_injected_events_never_reforwarded():
    (lap, lp, lw), (dsk, dp, dw) = linked()
    edge(lap); lw.pump()
    assert dsk.on_local_mouse(R.WM_MOUSEMOVE, -1919, 540, 0, True, True) is False
    assert dw.q == []

def test_keys_released_on_disconnect():
    (lap, lp, lw), (dsk, dp, dw) = linked()
    edge(lap); lw.pump()
    assert lap.on_local_key(0x11, 29, 0, False, False) and lap.on_local_key(0x43, 46, 0, False, False)
    lw.pump()
    assert ("key", 0x11, False) in dp.log and ("key", 0x43, False) in dp.log
    dsk.on_link_down()
    assert ("key", 0x11, True) in dp.log and ("key", 0x43, True) in dp.log and not dsk.injected_keys

def test_link_loss_restores_local_control():
    (lap, lp, lw), (dsk, dp, dw) = linked()
    edge(lap); assert lp.captured
    lap.on_link_down()
    assert lap.owner_local and not lp.captured
    assert lap.on_local_mouse(R.WM_MOUSEMOVE, 100, 100, 0, False, False) is False

def test_key_held_across_handoff_not_stuck():
    (lap, lp, lw), (dsk, dp, dw) = linked()
    assert lap.on_local_key(0x10, 42, 0, False, False) is False
    edge(lap)
    assert lap.on_local_key(0x10, 42, 0, False, False) is True
    assert lap.on_local_key(0x10, 42, 0x80, False, False) is False
    lw.pump()
    assert not any(e[0] == "key" for e in dp.log)

def test_reclaim_hotkey():
    (lap, lp, lw), (dsk, dp, dw) = linked()
    edge(lap); lw.pump()
    assert dsk.owner_local
    for vk in (0x11, 0x12, 0x10):
        lap.on_local_key(vk, 0, 0, False, False)
    assert lap.on_local_key(0x7B, 0, 0, False, False) is True
    assert lap.owner_local and not lp.captured
    lw.pump()
    assert not dsk.owner_local and dp.captured
    assert lap.on_local_key(0x7B, 0, 0x80, False, False) is True

def test_no_cross_while_button_held():
    (lap, lp, lw), (dsk, dp, dw) = linked()
    lap.on_local_mouse(R.WM_LBUTTONDOWN, 1900, 500, 0, False, False)
    assert edge(lap) is False and lap.owner_local

def test_wheel_and_buttons_route_to_owner():
    (lap, lp, lw), (dsk, dp, dw) = linked()
    edge(lap); lw.pump()
    assert lap.on_local_mouse(R.WM_MOUSEWHEEL, 0, 0, (-120 & 0xFFFF) << 16, False, False)
    assert lap.on_local_mouse(R.WM_RBUTTONDOWN, 0, 0, 0, False, False)
    assert lap.on_local_mouse(R.WM_RBUTTONUP, 0, 0, 0, False, False)
    lw.pump()
    assert ("wheel", 0, -120) in dp.log and ("btn", 2, True) in dp.log and ("btn", 2, False) in dp.log

def test_secure_desktop_suspends_routing():
    (lap, lp, lw), (dsk, dp, dw) = linked()
    edge(lap); lw.pump()
    dsk.set_secure_local(True); lap.set_secure_peer(True)
    assert lap.owner_local and not lp.captured

def test_hotkey_parser():
    assert R.parse_hotkey("ctrl+alt+shift+f12") == (frozenset({"ctrl", "alt", "shift"}), 0x7B)
    assert R.parse_hotkey("none") is None
