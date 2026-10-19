"""Lightweight measurement: histograms, counters, process CPU/RSS sampler.
Never records input or clipboard content."""
from __future__ import annotations

import threading
import time
from collections import deque
from typing import Dict


class Histogram:
    def __init__(self, cap: int = 20000):
        self.v = deque(maxlen=cap)
        self.n = 0

    def add(self, x: float):
        self.v.append(x)
        self.n += 1

    def summary(self) -> dict:
        if not self.v:
            return {"n": 0}
        s = sorted(self.v)

        def q(p):
            return s[min(len(s) - 1, int(p * len(s)))]
        return {"n": self.n, "min": s[0], "p50": q(.5), "p95": q(.95), "p99": q(.99),
                "max": s[-1], "mean": sum(s) / len(s)}


class Metrics:
    def __init__(self):
        self.h: Dict[str, Histogram] = {}
        self.c: Dict[str, int] = {}
        self.g: Dict[str, float] = {}
        self._lock = threading.Lock()
        self._proc = None
        self._cpu_samples = Histogram(600)
        self._stop = False

    def observe(self, name: str, value: float):
        with self._lock:
            self.h.setdefault(name, Histogram()).add(value)

    def count(self, name: str, n: int = 1):
        with self._lock:
            self.c[name] = self.c.get(name, 0) + n

    def gauge(self, name: str, v: float):
        self.g[name] = v

    def start_sampler(self):
        try:
            import psutil
        except ImportError:
            return
        self._proc = psutil.Process()
        self._proc.cpu_percent(None)

        def run():
            while not self._stop:
                time.sleep(1.0)
                try:
                    self._cpu_samples.add(self._proc.cpu_percent(None))
                    self.g["rss_mb"] = self._proc.memory_info().rss / 1048576
                except Exception:
                    pass
        threading.Thread(target=run, daemon=True, name="metrics").start()

    def stop(self):
        self._stop = True

    def snapshot(self) -> dict:
        with self._lock:
            out = {"hist": {k: v.summary() for k, v in self.h.items()},
                   "counters": dict(self.c), "gauges": dict(self.g)}
        out["cpu_percent"] = self._cpu_samples.summary()
        return out
