import pytest
from kvmshare import topology as T
from kvmshare.topology import Monitor, Rect

def mon(x, y, w, h, dpi=96, primary=False):
    return Monitor(Rect(x, y, w, h), dpi, primary)

def build(laptop=None, desk=None, topo=None):
    laptop = laptop or [mon(0, 0, 1920, 1080, 144, True)]
    desk = desk or [mon(-1920, 0, 1920, 1080), mon(0, 0, 2560, 1440, 96, True)]   # secondary left of primary
    return T.resolve(topo or T.DEFAULT_TOPOLOGY, {"laptop": laptop, "desktop": desk})

def test_default_order_and_links():
    r = build()
    assert [(l.a, l.b) for l in r.links] == [("laptop", "desk-secondary"), ("desk-secondary", "desk-primary")]
    assert r.is_managed(r.links[0]) and not r.is_managed(r.links[1])
    assert r.warnings() == []

def test_laptop_right_edge_enters_secondary_left_proportional():
    r = build()
    c = r.edge_touch("laptop", (1919, 540), 5, 0)
    assert c.machine == "desktop" and c.screen == "desk-secondary"
    assert c.x == -1920 + 1 and 535 <= c.y <= 545

def test_corners_never_dead():
    r = build(laptop=[mon(0, 0, 1366, 768, 96, True)])
    for y in (0, 767):
        c = r.edge_touch("laptop", (1365, y), 3, 0)
        assert c is not None and 0 <= c.y < 1080
    assert r.edge_touch("laptop", (1365, 0), 3, 0).y == 0
    assert r.edge_touch("laptop", (1365, 767), 3, 0).y == 1079

def test_reverse_crossing_from_secondary_left():
    r = build()
    c = r.edge_touch("desktop", (-1920, 1079), -2, 0)
    assert c.machine == "laptop" and c.x == 1918 and c.y == 1079

def test_no_crossing_on_native_link_or_wrong_direction():
    r = build()
    assert r.edge_touch("desktop", (-1, 500), 4, 0) is None           # secondary->primary is native
    assert r.edge_touch("laptop", (1919, 500), -3, 0) is None          # moving away from the edge
    assert r.edge_touch("laptop", (1000, 500), 3, 0) is None

def test_advance_inside_native_and_clamp():
    r = build()
    assert r.advance("desktop", (-5, 100), (10, 100)) == ("move", (10, 100))   # over the native seam
    assert r.advance("desktop", (100, 5), (100, -50)) == ("move", (100, 0))    # top wall, no link
    kind, c = r.advance("desktop", (-1900, 500), (-1930, 500))
    assert kind == "cross" and c.machine == "laptop"

def test_mixed_height_native_wall_slides():
    desk = [mon(-1920, 0, 1920, 1080), mon(0, 0, 2560, 700, 96, True)]
    r = build(desk=desk)
    k, p = r.advance("desktop", (-3, 900), (20, 900))
    assert k == "move" and p == (-1, 900)

def test_align_modes_and_offset():
    topo = dict(T.DEFAULT_TOPOLOGY)
    topo["links"] = [{"a": "laptop", "a_side": "right", "b": "desk-secondary", "b_side": "left", "align": "top", "offset": 100},
                     {"a": "desk-secondary", "a_side": "right", "b": "desk-primary", "b_side": "left"}]
    r = build(topo=topo)
    assert r.edge_touch("laptop", (1919, 200), 1, 0).y == 300
    back = r.edge_touch("desktop", (-1920, 300), -1, 0)
    assert back.y == 200

def test_bad_arrangement_warns():
    desk = [mon(0, 0, 1920, 1080, 96, True), mon(1920, 0, 1920, 1080)]   # secondary is to the RIGHT in Windows
    r = build(desk=desk)
    assert r.warnings()

def test_selector_errors():
    three = [mon(0, 0, 10, 10, 96, True), mon(10, 0, 10, 10), mon(20, 0, 10, 10)]
    with pytest.raises(T.TopologyError):
        T.pick_monitor(three, "secondary")
    assert T.pick_monitor(three, "index:2").rect.x == 20

def test_missing_machine():
    with pytest.raises(T.TopologyError):
        T.resolve(T.DEFAULT_TOPOLOGY, {"laptop": [mon(0, 0, 10, 10, 96, True)]})
