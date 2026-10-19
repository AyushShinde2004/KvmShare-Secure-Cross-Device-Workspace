import asyncio, pytest
from kvmshare import protocol as P

def test_roundtrip_all_binary():
    for t, f in [(P.T_MOVE, (1, 2, -5, 7, 99)), (P.T_BTN, (1, 2, 3, 1)), (P.T_WHEEL, (1, 2, -120, 0)),
                 (P.T_KEY, (1, 2, 0x41, 30, 3)), (P.T_ENTER, (3, 4, -10, 20)), (P.T_CLAIM, (5, 6)),
                 (P.T_PING, (1, 2)), (P.T_PONG, (1, 2, 3))]:
        fr = P.pack(t, *f)
        assert int.from_bytes(fr[:4], "big") == len(fr) - 4
        assert P.decode(fr[4], fr[5:]) == f

def test_rejects_garbage():
    with pytest.raises(P.ProtocolError): P.decode(P.T_MOVE, b"\0\0")
    with pytest.raises(P.ProtocolError): P.decode(0x77, b"")
    with pytest.raises(P.ProtocolError): P.decode(P.T_JSON, b"[1]")
    with pytest.raises(P.ProtocolError): P.decode(P.T_JSON, b"\xff\xfe")

def test_read_frame_limits():
    async def run():
        r = asyncio.StreamReader(); r.feed_data((10**9).to_bytes(4, "big") + b"x"); r.feed_eof()
        with pytest.raises(P.ProtocolError): await P.read_frame(r, 1000)
        r = asyncio.StreamReader(); r.feed_data((0).to_bytes(4, "big")); r.feed_eof()
        with pytest.raises(P.ProtocolError): await P.read_frame(r, 1000)
    asyncio.run(run())

def test_seq_wraparound():
    assert P.seq_newer(1, 0) and not P.seq_newer(0, 1) and not P.seq_newer(5, 5)
    assert P.seq_newer(0, 0xFFFFFFFF) and not P.seq_newer(0xFFFFFFFF, 0)
