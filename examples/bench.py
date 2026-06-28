#!/usr/bin/env python3
"""Micro-benchmark for the hybrid KEM — keygen / encap / decap, via ``timeit``.

Prints a plain-text table of per-operation timings (median + mean + ops/sec) so
the README "Benchmarks" numbers are reproducible on any machine. These measure
the WHOLE hybrid operation (X25519 leg + ML-KEM-768 leg + HKDF combiner), which
is what a caller actually pays.

Run:

    SK_PQC_LIBOQS=$HOME/.local/lib/liboqs.so \
    LD_LIBRARY_PATH=$HOME/.local/lib \
    python examples/bench.py            # default 200 iters
    python examples/bench.py 1000       # custom iteration count
"""

from __future__ import annotations

import platform
import statistics
import sys
import timeit

from sk_pqc import (
    hybrid_decap,
    hybrid_encap,
    hybrid_keypair,
    is_available,
)


def _time_op(fn, iters: int, repeats: int = 5) -> tuple[float, float]:
    """Return (median_per_call_us, mean_per_call_us) over ``repeats`` batches."""
    timer = timeit.Timer(fn)
    # Each batch runs ``iters`` calls; divide to get per-call seconds.
    per_call = [t / iters for t in timer.repeat(repeat=repeats, number=iters)]
    median_us = statistics.median(per_call) * 1e6
    mean_us = statistics.fmean(per_call) * 1e6
    return median_us, mean_us


def main() -> None:
    if not is_available():
        raise SystemExit(
            "PQ backend (liboqs via `oqs`) unavailable — install `sk-pqc[pq]`."
        )

    iters = int(sys.argv[1]) if len(sys.argv) > 1 else 200

    # Fixed inputs so encap/decap don't re-pay keygen each call.
    kp = hybrid_keypair()
    ciphertext, _ = hybrid_encap(kp.public_key)

    ops = {
        "keygen": lambda: hybrid_keypair(),
        "encap": lambda: hybrid_encap(kp.public_key),
        "decap": lambda: hybrid_decap(ciphertext, kp.private_key),
    }

    print(f"sk_pqc hybrid KEM bench  (suite x25519-mlkem768)")
    print(f"  python   {platform.python_version()} ({platform.machine()})")
    print(f"  platform {platform.platform()}")
    print(f"  iters    {iters} x 5 batches (median reported)")
    print()
    print(f"{'op':<8} {'median (us)':>14} {'mean (us)':>14} {'ops/sec':>12}")
    print("-" * 52)
    for name, fn in ops.items():
        median_us, mean_us = _time_op(fn, iters)
        ops_per_sec = 1e6 / median_us if median_us else float("inf")
        print(f"{name:<8} {median_us:>14.1f} {mean_us:>14.1f} {ops_per_sec:>12,.0f}")


if __name__ == "__main__":
    main()
