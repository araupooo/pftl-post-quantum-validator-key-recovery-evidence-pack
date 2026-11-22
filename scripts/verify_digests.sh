#!/bin/bash
# verify_digests.sh — verify every file listed in SHA256SUMS.
# Usage: bash scripts/verify_digests.sh
# Exits 0 only if every listed file matches its recorded digest.
set -u
PACK_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$PACK_ROOT" || exit 1
sha256sum -c SHA256SUMS
