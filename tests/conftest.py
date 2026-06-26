"""Test fixtures for sk_pqc.

Points the cross-impl KEM vector at the copy bundled in ``tests/vectors/`` so the
Python<->Dart interop gate runs self-contained (no sibling-checkout dependency),
unless ``SK_PQC_VECTOR`` is already set by the caller.
"""

from __future__ import annotations

import os
from pathlib import Path

_BUNDLED_VECTOR = Path(__file__).parent / "vectors" / "hybrid_kem_x25519_mlkem768.json"

if not os.environ.get("SK_PQC_VECTOR") and _BUNDLED_VECTOR.exists():
    os.environ["SK_PQC_VECTOR"] = str(_BUNDLED_VECTOR)
