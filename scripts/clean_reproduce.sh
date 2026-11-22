#!/bin/bash
# clean_reproduce.sh — full fresh-environment reproduction check.
#
# Copies the pack to a throwaway directory, drops all shipped probe/model/
# drill outputs, re-runs every generation step from scratch, and compares
# the fresh derived numbers with the shipped ones via compare_reproduce.py.
# Exits 0 only if every comparison check passes.
#
# The fresh probe set is copied back into outputs/fresh-clone-* so the
# reproduction itself is evidence. Only read-only public probes run; no
# transactions, no flood traffic, no live key material.
set -u
PACK_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="$(mktemp -d /tmp/pftl-keyrec-repro.XXXXXX)"
echo "clean_reproduce.sh workdir: $WORK"
cp -r "$PACK_ROOT" "$WORK/pack"
cd "$WORK/pack" || exit 1

# Drop everything the generation steps produce, so the run is from scratch.
rm -f outputs/*.json outputs/*.html outputs/*.log outputs/PROBE-MANIFEST.md
rm -rf outputs/derived
mkdir -p outputs/derived
rm -f findings.json run-manifest.json
rm -f docs/claim-index.md docs/gap-register.md docs/risk-register.md docs/evidence-index.md
rm -f fixtures/pq-sizes.csv fixtures/whitepaper-ml-dsa-section.txt

echo "--- step 1: probe (read-only) ---"
bash scripts/probe_all.sh || { echo "probe_all.sh FAILED"; exit 1; }
echo "--- step 2: key inventory ---"
python3 scripts/key_inventory.py > /dev/null || { echo "key_inventory.py FAILED"; exit 1; }
echo "--- step 3: shamir self-test ---"
python3 scripts/shamir.py --self-test || { echo "shamir self-test FAILED"; exit 1; }
echo "--- step 4: drill ---"
python3 scripts/drill.py --out outputs/derived/drill-results.json --log outputs/drill-run.log || { echo "drill.py FAILED"; exit 1; }
echo "--- step 5: models ---"
python3 src/key_model.py > /dev/null || { echo "key_model.py FAILED"; exit 1; }
python3 scripts/quorum_model.py > /dev/null || { echo "quorum_model.py FAILED"; exit 1; }
echo "--- step 6: analyze ---"
python3 scripts/analyze.py || { echo "analyze.py FAILED"; exit 1; }

echo "--- step 7: compare fresh vs shipped ---"
python3 scripts/compare_reproduce.py "$PACK_ROOT" "$WORK/pack"
COMPARE_EXIT=$?

# Keep the fresh probe set as evidence under outputs/fresh-clone-*.
for f in "$WORK"/pack/outputs/*; do
  base="$(basename "$f")"
  case "$base" in
    derived|fresh-clone-*) continue ;;
  esac
  cp "$f" "$PACK_ROOT/outputs/fresh-clone-$base" 2>/dev/null || true
done
for f in "$WORK"/pack/outputs/derived/*; do
  cp "$f" "$PACK_ROOT/outputs/fresh-clone-derived-$(basename "$f")" 2>/dev/null || true
done
cp "$WORK/pack/outputs/drill-run.log" "$PACK_ROOT/outputs/fresh-clone-drill-run.log" 2>/dev/null || true
# compare_reproduce.py's own log, for the record.
echo "fresh probe set copied to $PACK_ROOT/outputs/fresh-clone-*"

if [ "$COMPARE_EXIT" -ne 0 ]; then
  echo "clean_reproduce.sh: COMPARISON FAILED (exit $COMPARE_EXIT)"
  exit 1
fi
echo "clean_reproduce.sh: ALL CHECKS PASSED (exit 0)"
exit 0
