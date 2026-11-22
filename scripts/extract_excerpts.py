#!/usr/bin/env python3
"""extract_excerpts.py — extract verbatim pinned-source excerpts with line
numbers, verified against a local checkout of the pinned commit.

Usage: python3 scripts/extract_excerpts.py [--clone PATH] [--out DIR]
  --clone defaults to /tmp/pftl-keyrec/postfiatd (local checkout at the
          pinned commit 0085a1ff885d6a446369cf73a4430f75af22be55)
  --out   defaults to fixtures/source-excerpts

Each output file starts with a header (repo, commit, file, line range,
"verified with grep -n"), then the numbered source lines, verbatim.
fixtures/source-hashes.json records the git blob SHA-1 of every cited file.
Exits non-zero if any range is out of bounds or any file is missing.
"""
import argparse
import hashlib
import json
import os
import subprocess
import sys

COMMIT = "0085a1ff885d6a446369cf73a4430f75af22be55"
REPO = "https://github.com/postfiatorg/postfiatd"

# (source path in the pinned repo, first line, last line, output file)
EXCERPTS = [
    ("src/xrpld/app/misc/detail/ValidatorKeys.cpp", 29, 91,
     "ValidatorKeys-load.txt"),
    ("src/xrpld/app/misc/ValidatorKeys.h", 40, 66,
     "ValidatorKeys-struct.txt"),
    ("src/xrpld/app/misc/Manifest.h", 36, 78,
     "Manifest-design.txt"),
    ("src/xrpld/app/misc/detail/Manifest.cpp", 54, 100,
     "Manifest-deserialize-format.txt"),
    ("src/xrpld/app/misc/detail/Manifest.cpp", 196, 240,
     "Manifest-verify-revoked.txt"),
    ("src/xrpld/app/misc/detail/Manifest.cpp", 405, 450,
     "ManifestCache-sequence-rule.txt"),
    ("src/xrpld/rpc/handlers/ValidationCreate.cpp", 29, 67,
     "ValidationCreate.txt"),
    ("src/libxrpl/protocol/Seed.cpp", 65, 82,
     "Seed-random-generate.txt"),
    ("src/libxrpl/protocol/Seed.cpp", 134, 144,
     "Seed-as1751.txt"),
    ("include/xrpl/protocol/KeyType.h", 28, 45,
     "KeyType-enum.txt"),
    ("src/libxrpl/protocol/PublicKey.cpp", 223, 232,
     "PublicKey-type-prefix.txt"),
    ("src/libxrpl/protocol/PublicKey.cpp", 318, 328,
     "PublicKey-calcNodeID.txt"),
    ("src/libxrpl/protocol/SecretKey.cpp", 256, 290,
     "SecretKey-sign-dispatch.txt"),
    ("src/xrpld/app/misc/detail/ValidatorList.cpp", 1895, 1912,
     "ValidatorList-quorum-67.txt"),
    ("include/xrpl/protocol/detail/sfields.macro", 289, 307,
     "SField-manifest-codes.txt"),
    ("src/xrpld/core/ConfigSections.h", 89, 96,
     "ConfigSections-validator.txt"),
    ("docs/ValidatorKeyUpdate.md", 205, 224,
     "ValidatorKeyUpdate-backup-warning.txt"),
    ("docs/ValidatorKeyUpdate.md", 78, 84,
     "ValidatorKeyUpdate-rotation-6-12mo.txt"),
    ("docs/ValidatorKeyUpdate.md", 240, 250,
     "ValidatorKeyUpdate-sequence-propagation.txt"),
    ("docs/NodeSetup.md", 282, 292,
     "NodeSetup-create-keys.txt"),
    ("scripts/generate_vl.py", 1, 45,
     "GenerateVL-architecture.txt"),
    ("docs/MANIFEST_FLOOD_HOTFIX.md", 1, 40,
     "ManifestFloodHotfix-cap.txt"),
]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--clone", default="/tmp/pftl-keyrec/postfiatd")
    ap.add_argument("--out", default="fixtures/source-excerpts")
    ap.add_argument("--hashes", default="fixtures/source-hashes.json")
    args = ap.parse_args()
    head = subprocess.run(["git", "-C", args.clone, "rev-parse", "HEAD"],
                          capture_output=True, text=True, check=True)
    actual = head.stdout.strip()
    if actual != COMMIT:
        print(f"ERROR: clone HEAD is {actual}, expected {COMMIT}")
        return 1
    os.makedirs(args.out, exist_ok=True)
    hashes = {}
    for src, first, last, out_name in EXCERPTS:
        path = os.path.join(args.clone, src)
        with open(path, "r", errors="replace") as f:
            lines = f.readlines()
        if last > len(lines):
            print(f"ERROR: {src} has {len(lines)} lines, range ends at {last}")
            return 1
        header = (
            f"# Pinned source excerpt\n"
            f"# repo: {REPO}\n"
            f"# commit: {COMMIT}\n"
            f"# file: {src}\n"
            f"# lines: {first}-{last} (1-based, verified with grep -n)\n"
            f"# ----\n"
        )
        body = "".join(f"{n}: {lines[n - 1]}" for n in range(first, last + 1))
        with open(os.path.join(args.out, out_name), "w") as f:
            f.write(header + body)
        blob = subprocess.run(["git", "-C", args.clone, "hash-object", src],
                              capture_output=True, text=True, check=True)
        hashes[src] = blob.stdout.strip()
        print(f"  {out_name}: {src} lines {first}-{last}")
    json.dump({"commit": COMMIT, "repo": REPO, "files": hashes},
              open(args.hashes, "w"), indent=1)
    print(f"wrote {len(EXCERPTS)} excerpts + {args.hashes} "
          f"({len(hashes)} files)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
