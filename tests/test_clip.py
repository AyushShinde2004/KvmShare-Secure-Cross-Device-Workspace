import asyncio, tempfile, zlib, os
from kvmshare import config, clipsync as C, session as SS
from kvmshare.metrics import Metrics
from test_pairing_session import mk, FakeRouter

class MemBackend:
    def __init__(self): self.store = {}; self.writes = 0; self.snap = None
    def write(self, fm): self.store = dict(fm); self.writes += 1
    def read(self): return self.snap
    def write_files(self, p): pass

def setup(t, loop, extra=None):
    da, ia, sa = mk(t, "a"); db, ib, sb = mk(t, "b")
    sa.add("B", "laptop", ib.cert_pem); sb.add("A", "desktop", ia.cert_pem)
    out = []
    for ident, store, role, port, pp in ((ia, sa, "desktop", 24930, 24931), (ib, sb, "laptop", 24931, 24930)):
        cfg = config.deep_merge(config.DEFAULTS, {"role": role, "listen_port": port, "bind": "127.0.0.1",
                                "peer_address": f"127.0.0.1:{pp}", "device_name": role, **(extra or {})})
        link = SS.PeerLink(cfg, ident, store, FakeRouter(), Metrics(), SS.Outbox(loop), lambda: [])
        be = MemBackend()
        out.append((link, be, C.ClipboardSync(cfg, be, link, None, lambda a, b: None, link.metrics, ident.device_id)))
    return out

def test_text_sync_unicode_large_stale_and_privacy():
    async def run():
        loop = asyncio.get_running_loop()
        with tempfile.TemporaryDirectory() as t:
            (la, ba, ca), (lb, bb, cb) = setup(t, loop)
            await la.start(); await lb.start()
            for _ in range(60):
                if la.connected and lb.connected: break
                await asyncio.sleep(0.1)
            txt = "héllo 世界 😀\nline2\r\n" + "x" * 100
            ca.send({"text": txt.encode()}); await asyncio.sleep(0.3)
            assert bb.store["text"].decode() == txt
            big = os.urandom(3_000_000).hex().encode()            # ~6 MB: goes over the aux channel
            cb.send({"text": big}); await asyncio.sleep(1.5)
            assert ba.store["text"] == big
            # stale update (older version) must not overwrite newer content
            before = ba.writes
            ca._apply((1, "zzz"), {"text": b"stale"})
            assert ba.writes == before and ba.store["text"] == big
            # echo suppression: our own write reported back by the OS is a no-op
            ba.snap = C.Snapshot({"text": big}); sent = ca.metrics.c.get("clip_sent", 0)
            ca.on_local_change(); assert ca.metrics.c.get("clip_sent", 0) == sent
            # privacy mode: nothing leaves, nothing is applied
            ca.paused = True; ba.snap = C.Snapshot({"text": b"secret"}); ca.on_local_change()
            cb.paused = True; ca.paused = False
            ca.send({"text": b"fresh"}); await asyncio.sleep(0.3)
            assert bb.store["text"] != b"fresh"
            # ack gives propagation time
            cb.paused = False; ca.send({"text": b"timed"}); await asyncio.sleep(0.3)
            assert ca.metrics.snapshot()["hist"]["clip_roundtrip_ms"]["n"] >= 1
            # oversize rejected
            cb.c["max_text_mb"] = 1
            ca.send({"text": os.urandom(2_000_000).hex().encode()}); await asyncio.sleep(1)
            assert bb.store["text"] == b"timed"
            await la.stop(); await lb.stop()
    asyncio.run(run())
