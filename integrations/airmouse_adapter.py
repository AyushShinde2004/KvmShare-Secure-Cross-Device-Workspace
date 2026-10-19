"""Air-mouse -> KvmShare bridge. Your ESP8266/MPU6050 firmware is untouched.

Your existing Python script turns gyro samples into pixel deltas and then calls
pyautogui. Replace only that last step:

    from airmouse_adapter import KvmSink
    sink = KvmSink()
    ...
    dx, dy = <your smoothed/clamped per-tick pixel deltas>   # ints
    if not sink.move(dx, dy):        # False -> KvmShare not running: keep the old behaviour
        pyautogui.moveRel(dx, dy)

KvmShare then treats the air mouse like any other pointer: it moves the cursor on whichever
computer owns the pointer and crosses screen edges. Packets go to 127.0.0.1 only and carry a
per-install secret, so other programs cannot inject input.
"""
import os
import socket
import struct
import time
from pathlib import Path


def _home() -> Path:
    if os.environ.get("KVMSHARE_HOME"):
        return Path(os.environ["KVMSHARE_HOME"])
    return Path(os.environ.get("LOCALAPPDATA", Path.home())) / "KvmShare"


class KvmSink:
    def __init__(self, port: int = 24806):
        self.addr = ("127.0.0.1", port)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            self.token = bytes.fromhex((_home() / "external.token").read_text().strip())
        except (OSError, ValueError):
            self.token = None

    def _alive(self) -> bool:
        """Is the KvmShare daemon listening? Cached for 2 s so the 100 Hz loop stays cheap."""
        now = time.monotonic()
        if now - getattr(self, "_t", 0) > 2.0:
            self._t = now
            try:
                socket.create_connection(("127.0.0.1", self.addr[1] - 1), timeout=0.05).close()   # control port = external port - 1
                self._up = True
            except OSError:
                self._up = False
        return self._up

    def _send(self, dx, dy, btn=0, down=0) -> bool:
        if not self.token or not self._alive():
            return False
        dx, dy = max(-32768, min(32767, int(dx))), max(-32768, min(32767, int(dy)))
        try:
            self.sock.sendto(b"KV1" + self.token + struct.pack("!hhBB", dx, dy, btn, down), self.addr)
            return True
        except OSError:
            return False

    def move(self, dx, dy):
        return self._send(dx, dy)

    def button(self, btn: int, down: bool):          # 1=left 2=right 3=middle
        return self._send(0, 0, btn, 1 if down else 0)
