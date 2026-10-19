import asyncio, os, pathlib, tempfile, pytest
from kvmshare import config, pairing, security as S, session as SS
from kvmshare.metrics import Metrics

def mk(tmp, name):
    d = pathlib.Path(tmp) / name; d.mkdir()
    return d, S.Identity.load_or_create(d), S.PairedStore(d)

def test_pairing_ok_and_wrong_code():
    async def run():
        with tempfile.TemporaryDirectory() as t:
            _, ia, sa = mk(t, "a"); _, ib, sb = mk(t, "b")
            code = pairing.new_code()
            host = asyncio.ensure_future(pairing.host_pairing(ia, sa, "A", "desktop", code, 24902, "127.0.0.1", lambda *a: True))
            await asyncio.sleep(0.3)
            await pairing.join_pairing(ib, sb, "B", "laptop", code, "127.0.0.1", 24902, lambda *a: True)
            await host
            assert sa.by_fp(ib.fp)["role"] == "laptop" and sb.by_fp(ia.fp)["role"] == "desktop"
            # wrong code: nothing stored, host burns the code
            _, ic, sc = mk(t, "c"); _, ie, se = mk(t, "e")
            host = asyncio.ensure_future(pairing.host_pairing(ic, sc, "C", "desktop", "123456", 24903, "127.0.0.1", lambda *a: True))
            await asyncio.sleep(0.3)
            with pytest.raises(pairing.PairingError):
                await pairing.join_pairing(ie, se, "E", "laptop", "654321", "127.0.0.1", 24903, lambda *a: True)
            with pytest.raises(pairing.PairingError):
                await host
            assert not sc.all() and not se.all()
    asyncio.run(run())

def test_pairing_declined():
    async def run():
        with tempfile.TemporaryDirectory() as t:
            _, ia, sa = mk(t, "a"); _, ib, sb = mk(t, "b")
            host = asyncio.ensure_future(pairing.host_pairing(ia, sa, "A", "desktop", "111111", 24904, "127.0.0.1", lambda *a: False))
            await asyncio.sleep(0.3)
            with pytest.raises(pairing.PairingError):
                await pairing.join_pairing(ib, sb, "B", "laptop", "111111", "127.0.0.1", 24904, lambda *a: True)
            with pytest.raises(pairing.PairingError):
                await host
            assert not sa.all() and not sb.all()
    asyncio.run(run())

class FakeRouter:
    epoch = 0
    def __init__(self): self.ups = 0; self.downs = 0; self.moves = []
    def idle_ms(self): return 5
    def set_layout(self, *a): pass
    def on_link_up(self, *a): self.ups += 1
    def on_link_down(self): self.downs += 1
    def set_secure_peer(self, a): pass
    def on_peer_move(self, e, dx, dy, ts, off): self.moves.append((e, dx, dy))
    def on_enter(self, *a): pass
    def on_claim(self, *a): pass
    def on_peer_button(self, *a): pass
    def on_peer_wheel(self, *a): pass
    def on_peer_key(self, *a): pass

def test_session_connect_move_reconnect_revoke():
    async def run():
        with tempfile.TemporaryDirectory() as t:
            da, ia, sa = mk(t, "a"); db, ib, sb = mk(t, "b")
            sa.add("B", "laptop", ib.cert_pem); sb.add("A", "desktop", ia.cert_pem)
            loop = asyncio.get_running_loop()
            links = []
            for ident, store, role, port, peer_port in ((ia, sa, "desktop", 24910, 24911), (ib, sb, "laptop", 24911, 24910)):
                cfg = config.deep_merge(config.DEFAULTS, {"role": role, "listen_port": port, "bind": "127.0.0.1",
                                                          "peer_address": f"127.0.0.1:{peer_port}", "device_name": role})
                r, m = FakeRouter(), Metrics()
                ob = SS.Outbox(loop)
                links.append((SS.PeerLink(cfg, ident, store, r, m, ob, lambda: []), r, ob, m))
            for l, *_ in links: await l.start()
            for _ in range(60):
                if all(l.connected for l, *_ in links): break
                await asyncio.sleep(0.1)
            assert all(l.connected for l, *_ in links)
            (la, ra, oa, ma), (lb, rb, ob_, mb) = links
            # pointer moves from either side coalesce but total is preserved
            for _ in range(500): ob_.move(1, 1, 2)
            await asyncio.sleep(0.3)
            assert sum(m[1] for m in ra.moves) == 500 and sum(m[2] for m in ra.moves) == 1000
            assert len(ra.moves) < 500
            res = await lb.bench_ping(20, 200)
            assert res["lost"] == 0 and res["rtt_ms"]["p50"] < 50
            # network interruption -> both sides notice, reconnect, routers told
            la.drop()
            await asyncio.sleep(0.3)
            for _ in range(80):
                if all(l.connected for l, *_ in links) and ra.ups >= 2: break
                await asyncio.sleep(0.1)
            assert ra.ups >= 2 and ra.downs >= 1 and la.connected
            # revoke B on A: handshake still verifies (cert in live ctx) but pin check refuses
            sa.remove("laptop"); la.drop(); lb.drop()
            await asyncio.sleep(1.5)
            assert not la.connected
            for l, *_ in links: await l.stop()
    asyncio.run(run())
