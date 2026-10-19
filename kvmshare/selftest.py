"""`kvmshare selftest` - verifies the OS-level assumptions on THIS machine."""
import ctypes
import sys
import time


def _ok(name, good, detail=""):
    print(f"[{'PASS' if good else 'FAIL'}] {name} {detail}")
    return good


def run():
    if sys.platform != "win32":
        raise SystemExit("selftest needs Windows")
    from . import config as C, win32 as W
    W.set_dpi_aware()
    ok = True
    mons = W.enum_monitors()
    ok &= _ok("monitor enumeration", bool(mons), "; ".join(f"{m.rect.w}x{m.rect.h}@({m.rect.x},{m.rect.y}) dpi={m.dpi}{' primary' if m.primary else ''}" for m in mons))
    cfg = C.load_config()
    if cfg.get("role"):
        from . import topology as T
        others = {"laptop": "desktop", "desktop": "laptop"}
        fake = {cfg["role"]: mons}
        print("      configured role:", cfg["role"], "(topology is validated when the peer connects: see `status` warnings)")
    # exact pointer placement: SetCursorPos must land on the requested pixel on every monitor, mixed DPI included
    p = W.POINT()
    W.user32.GetCursorPos(ctypes.byref(p))
    start = (p.x, p.y)
    bad = []
    for m in mons:
        r = m.rect
        for (x, y) in ((r.x, r.y), (r.x + r.w - 1, r.y + r.h - 1), (r.x + r.w // 2, r.y + r.h // 2)):
            W.user32.SetCursorPos(x, y)
            time.sleep(0.02)
            W.user32.GetCursorPos(ctypes.byref(p))
            if (p.x, p.y) != (x, y):
                bad.append(((x, y), (p.x, p.y)))
    W.user32.SetCursorPos(*start)
    ok &= _ok("SetCursorPos exact on all monitor corners/centers", not bad, str(bad[:3]))
    # hooks + injection round trip (also proves hooks see injected events and our marker logic)
    from .winio import WinPlatform
    from .router import Router
    from .metrics import Metrics

    class Tx:
        def __getattr__(self, n): return lambda *a, **k: None
    plat = WinPlatform(C.deep_merge(C.DEFAULTS, {}))
    r = Router(C.deep_merge(C.DEFAULTS, {"role": "x"}), plat, Tx(), Metrics(), "selftest")
    plat.start(r)
    res = plat.bench_local(200)
    h = res["inject_to_hook_us"]
    ok &= _ok("low-level hook receives injected moves", h.get("n", 0) > 150, f"({h.get('n', 0)}/200)")
    if h.get("n"):
        print(f"      inject call p50={res['inject_call_us']['p50']:.0f}us  inject->hook p50={h['p50']:.0f}us p99={h['p99']:.0f}us")
    plat.stop()
    ok &= _ok("secure desktop detector", not W.secure_desktop_active(), "(normal desktop expected)")
    print("\nAll good." if ok else "\nSome checks failed - see docs/LIMITATIONS.md")
