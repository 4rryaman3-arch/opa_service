"""Bounded-memory in-process performance metrics (counters + fixed histograms)."""

from __future__ import annotations

import threading
import time
from collections import defaultdict
from typing import Any

BUCKETS = (0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0)


class Metrics:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._counters: dict[str, int] = defaultdict(int)
        self._hist: dict[str, list[int]] = {}
        self._sums: dict[str, float] = defaultdict(float)
        self._started = time.time()

    def inc(self, name: str, value: int = 1) -> None:
        with self._lock:
            self._counters[name] += value

    def observe(self, name: str, seconds: float) -> None:
        with self._lock:
            buckets = self._hist.setdefault(name, [0] * (len(BUCKETS) + 1))
            for i, b in enumerate(BUCKETS):
                if seconds <= b:
                    buckets[i] += 1
                    break
            else:
                buckets[-1] += 1
            self._sums[name] += seconds

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            hist = {}
            for name, counts in self._hist.items():
                total = sum(counts)
                hist[name] = {
                    "count": total,
                    "sum_seconds": round(self._sums[name], 6),
                    "buckets": {
                        **{f"le_{b}": c for b, c in zip(BUCKETS, counts)},
                        "le_inf": counts[-1],
                    },
                    "approx_p50_seconds": _quantile(counts, total, 0.50),
                    "approx_p95_seconds": _quantile(counts, total, 0.95),
                    "approx_p99_seconds": _quantile(counts, total, 0.99),
                }
            return {
                "uptime_seconds": round(time.time() - self._started, 1),
                "counters": dict(self._counters),
                "histograms": hist,
            }


def _quantile(counts: list[int], total: int, q: float) -> float | None:
    """Upper bucket bound containing quantile q (coarse, but bounded memory)."""
    if total == 0:
        return None
    target = q * total
    running = 0
    for b, c in zip(BUCKETS + (float("inf"),), counts):
        running += c
        if running >= target:
            return b if b != float("inf") else None
    return None
