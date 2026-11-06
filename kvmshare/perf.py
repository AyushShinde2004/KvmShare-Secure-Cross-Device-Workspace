"""Latency tuning for the Windows daemon. All best-effort; every call is optional.

Why: a background Python process on Windows is, by default, a low-priority citizen:
  * 15.6 ms timer granularity (affects every sleep/timeout/scheduler wake-up)
  * EcoQoS "power throttling" (Windows 11 may park it on efficiency cores at low clocks)
  * normal thread priority: the hook / network threads wait behind other apps' work
  * CPython's 5 ms GIL switch interval: a thread can wait that long to run Python code
"""
from __future__ import annotations

import ctypes
import logging
import sys

log = logging.getLogger("kvmshare.perf")


def boost() -> None:
    sys.setswitchinterval(0.0005)                      # 0.5 ms instead of 5 ms: all platforms
    if sys.platform != "win32":
        return
    try:
        k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        k32.GetCurrentProcess.restype = ctypes.c_void_p
        k32.SetPriorityClass.argtypes = [ctypes.c_void_p, ctypes.c_uint]
        k32.SetProcessInformation.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p, ctypes.c_uint]
        h = k32.GetCurrentProcess()
        # 1 ms system timer while we run (undone automatically when the process exits)
        ctypes.WinDLL("winmm").timeBeginPeriod(1)
        # ABOVE_NORMAL (not HIGH/REALTIME: we must never starve the rest of the system)
        k32.SetPriorityClass(h, 0x00008000)

        class THROTTLE(ctypes.Structure):
            _fields_ = [("Version", ctypes.c_uint), ("ControlMask", ctypes.c_uint), ("StateMask", ctypes.c_uint)]
        # Take control of EXECUTION_SPEED (1) and IGNORE_TIMER_RESOLUTION (4); StateMask 0 = "do not throttle"
        st = THROTTLE(1, 1 | 4, 0)
        k32.SetProcessInformation(h, 4, ctypes.byref(st), ctypes.sizeof(st))   # ProcessPowerThrottling
        log.info("latency boost applied (1 ms timer, above-normal priority, EcoQoS off)")
    except (OSError, AttributeError) as e:
        log.warning("latency boost partly unavailable: %s", e)


def boost_thread(level: int) -> None:
    """level: 2 = HIGHEST, 15 = TIME_CRITICAL (relative to the process class)."""
    if sys.platform != "win32":
        return
    try:
        k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        k32.GetCurrentThread.restype = ctypes.c_void_p
        k32.SetThreadPriority.argtypes = [ctypes.c_void_p, ctypes.c_int]
        k32.SetThreadPriority(k32.GetCurrentThread(), level)
    except (OSError, AttributeError):
        pass