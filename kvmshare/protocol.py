"""Wire protocol. Frame = u32 length (type byte + body) | u8 type | body.

Input events are fixed-size binary structs (no JSON, no allocation-heavy
serialization on the hot path). Everything else is small JSON."""
from __future__ import annotations

import json
import struct

T_MOVE, T_BTN, T_WHEEL, T_KEY, T_ENTER, T_CLAIM, T_PING, T_PONG = 1, 2, 3, 4, 5, 6, 7, 8
T_JSON = 0x20
T_DATA = 0x31

MAX_INPUT_FRAME = 64 * 1024
MAX_JSON_FRAME = 1024 * 1024
MAX_XFER_JSON = 8 * 1024 * 1024
MAX_DATA_FRAME = 2 * 1024 * 1024

_STRUCTS = {
    T_MOVE: struct.Struct("!IIiiQ"),   # epoch seq dx dy t_capture_ns(0 = unstamped)
    T_BTN: struct.Struct("!IIBB"),     # epoch seq button down
    T_WHEEL: struct.Struct("!IIii"),   # epoch seq dx(h) dy(v)  (120 = one notch)
    T_KEY: struct.Struct("!IIHHB"),    # epoch seq vk scan flags(1=up 2=extended)
    T_ENTER: struct.Struct("!IIii"),   # epoch seq x y   (sender hands pointer to receiver)
    T_CLAIM: struct.Struct("!II"),     # epoch seq       (sender takes the pointer)
    T_PING: struct.Struct("!IQ"),      # id t_send_ns
    T_PONG: struct.Struct("!IQQ"),     # id t_send_ns(echo) t_recv_ns(peer clock)
}
_HDR = struct.Struct("!IB")


class ProtocolError(Exception):
    pass


def frame(t: int, body: bytes = b"") -> bytes:
    return _HDR.pack(len(body) + 1, t) + body


def pack(t: int, *fields) -> bytes:
    return frame(t, _STRUCTS[t].pack(*fields))


def json_frame(obj: dict) -> bytes:
    return frame(T_JSON, json.dumps(obj, separators=(",", ":")).encode("utf-8"))


def decode(t: int, body: bytes):
    """Return a tuple of fields for binary types, a dict for JSON."""
    if t == T_JSON:
        try:
            obj = json.loads(bytes(body).decode("utf-8"))
        except (ValueError, UnicodeDecodeError) as e:
            raise ProtocolError("bad json") from e
        if not isinstance(obj, dict):
            raise ProtocolError("json must be an object")
        return obj
    st = _STRUCTS.get(t)
    if st is None:
        raise ProtocolError(f"unknown frame type {t}")
    if len(body) != st.size:
        raise ProtocolError(f"bad length for type {t}")
    return st.unpack(body)


async def read_frame(reader, max_len: int):
    hdr = await reader.readexactly(4)
    n = int.from_bytes(hdr, "big")
    if n < 1 or n > max_len:
        raise ProtocolError(f"frame length {n} out of range")
    data = await reader.readexactly(n)
    return data[0], data[1:]


def seq_newer(seq: int, last: int) -> bool:
    """True if seq is ahead of last in u32 serial-number arithmetic."""
    d = (seq - last) & 0xFFFFFFFF
    return 0 < d < 0x80000000
