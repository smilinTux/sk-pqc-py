#!/usr/bin/env bash
# Build the sk_pqc HTML API reference with pdoc.
#
# Pure-Python, light: no compile. `pip install pdoc` is all you need (the ML-KEM
# leg's liboqs is only needed if you want the PQ-backed symbols to import cleanly;
# pdoc renders the docstrings either way). Output lands in docs/api/ and is what
# the README "API docs" link points at.
#
# Usage:
#   pip install pdoc            # one-time
#   scripts/build-api-docs.sh   # regenerate docs/api/
#
# Keep the experimental / unaudited banner: it is wired in as the pdoc footer and
# also lives in the package docstring, so it shows at the top of every page.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$here"

OUT="docs/api"

# Honest-claims / maturity banner rendered into every page footer.
FOOTER='⚠️ Experimental · pre-1.0 · NOT independently security-audited — clean-room reference implementation. Hybrid = confidential if EITHER the X25519 leg OR the ML-KEM-768 leg holds; never "quantum-proof". FIPS 203 (ML-KEM) · FIPS 204 (ML-DSA) · RFC 7748 · RFC 5869 · SP 800-38D. Review it yourself before production use.'

rm -rf "$OUT"
PYTHONPATH=src python3 -m pdoc \
  sk_pqc \
  sk_pqc.pqkem \
  sk_pqc.crypto_suites \
  sk_pqc.pqdm \
  sk_pqc.pqroute \
  sk_pqc.anon_queue \
  sk_pqc.group_ratchet \
  sk_pqc.dm_ratchet \
  --no-show-source \
  --footer-text "$FOOTER" \
  -o "$OUT"

echo "Built API docs -> $OUT/index.html"
