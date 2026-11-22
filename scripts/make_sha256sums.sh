#!/bin/bash
# make_sha256sums.sh — (re)generate SHA256SUMS over every pack file except
# SHA256SUMS itself, PACK-READY.md, and the fresh-clone evidence set
# (outputs/fresh-clone-*), which is reproduction output, not pack content.
# Usage: bash scripts/make_sha256sums.sh
set -u
PACK_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$PACK_ROOT" || exit 1
find . -type f \
  ! -path "./.git/*" \
  ! -name "SHA256SUMS" \
  ! -name "PACK-READY.md" \
  ! -path "./outputs/fresh-clone-*" \
  | sort | xargs sha256sum > SHA256SUMS
echo "SHA256SUMS: $(wc -l < SHA256SUMS) files"
