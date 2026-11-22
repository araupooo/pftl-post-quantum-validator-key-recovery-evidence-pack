#!/usr/bin/env python3
"""manifest_parse.py — parse rippled/postfiatd validator manifests (STObject).

A manifest is a serialized STObject (see Manifest.cpp, pinned postfiatd).
Field codes are taken from include/xrpl/protocol/detail/sfields.macro:
  sfSequence        UINT32 field 4  -> header 0x24
  sfPublicKey       VLEN   field 1  -> header 0x71 (master key)
  sfSigningPubKey   VLEN   field 3  -> header 0x73 (ephemeral signing key)
  sfSignature       VLEN   field 6  -> header 0x76
  sfDomain          VLEN   field 7  -> header 0x77
  sfMasterSignature VLEN   field 18 -> header 0x70 0x12 (extended field code)
  sfVersion         UINT16 field 16 -> header 0x10 0x10 (extended field code)

Field headers use one byte when both the type code and the field code are
< 16, otherwise two bytes (first byte has a zero nibble, second byte is the
extended value). VLEN lengths < 193 use one byte. This parser handles both.

Public-key type is read from the first byte of the 33-byte key:
  0xED -> Ed25519, 0x02/0x03 -> secp256k1 compressed (see PublicKey.cpp
  publicKeyType: 0xED prefix is Ed25519, 0x02/0x03 prefix is secp256k1).

Usage: python3 scripts/manifest_parse.py <testnet_vl.json> [out.json]
Prints a summary; writes one row per validator (master key, signing key,
sequence, domain present, manifest length, VL key match) to out.json.
"""
import base64
import json
import sys


def parse_manifest(b: bytes) -> dict:
    i, out = 0, {}
    while i < len(b):
        h = b[i]
        i += 1
        t, f = h >> 4, h & 0x0F
        if f == 0:  # extended field code in the next byte
            f = b[i]
            i += 1
        if t == 1:  # UINT16
            out[("u16", f)] = int.from_bytes(b[i:i + 2], "big")
            i += 2
        elif t == 2:  # UINT32
            out[("u32", f)] = int.from_bytes(b[i:i + 4], "big")
            i += 4
        elif t == 7:  # VLEN-encoded
            ln = b[i]
            i += 1
            if ln >= 193:  # two-byte length
                ln = 193 + (ln - 193) * 256 + b[i]
                i += 1
            out[("vlen", f)] = b[i:i + ln]
            i += ln
        else:
            raise ValueError(f"unsupported STObject type {t} at offset {i - 1}")
    return out


def key_type(hexkey: str) -> str:
    if hexkey.startswith("ED"):
        return "ed25519"
    if hexkey[:2] in ("02", "03"):
        return "secp256k1"
    return "unknown"


def main() -> int:
    vl_path = sys.argv[1]
    out_path = sys.argv[2] if len(sys.argv) > 2 else None
    vl = json.load(open(vl_path))
    blob = vl["blobs_v2"][0]
    # The published VL stores the inner document as a base64 JSON string
    # under "blob"; accept an already-decoded document too.
    inner = json.loads(base64.b64decode(blob["blob"])) if "blob" in blob else blob
    validators = inner["validators"]
    rows = []
    for v in validators:
        raw = base64.b64decode(v["manifest"])
        p = parse_manifest(raw)
        master = p[("vlen", 1)].hex().upper()
        signing = p[("vlen", 3)].hex().upper()
        domain = p.get(("vlen", 7), b"").decode("utf-8", "replace")
        rows.append({
            "validation_public_key": v["validation_public_key"],
            "master_key": master,
            "master_key_type": key_type(master),
            "signing_key": signing,
            "signing_key_type": key_type(signing),
            "sequence": p[("u32", 4)],
            "domain": domain,
            "manifest_bytes": len(raw),
            "vl_key_is_master": v["validation_public_key"] == master,
            "vl_key_is_signing": v["validation_public_key"] == signing,
        })
    summary = {
        "validators": len(rows),
        "master_key_types": {t: sum(1 for r in rows if r["master_key_type"] == t)
                             for t in ("ed25519", "secp256k1", "unknown")},
        "signing_key_types": {t: sum(1 for r in rows if r["signing_key_type"] == t)
                              for t in ("ed25519", "secp256k1", "unknown")},
        "vl_key_is_master": sum(1 for r in rows if r["vl_key_is_master"]),
        "vl_key_is_signing": sum(1 for r in rows if r["vl_key_is_signing"]),
        "distinct_master_keys": len({r["master_key"] for r in rows}),
        "distinct_signing_keys": len({r["signing_key"] for r in rows}),
        "sequences": sorted({r["sequence"] for r in rows}),
        "sequence_counts": {str(s): sum(1 for r in rows if r["sequence"] == s)
                            for s in sorted({r["sequence"] for r in rows})},
        "domains_present": sum(1 for r in rows if r["domain"]),
        "manifest_bytes_min": min(r["manifest_bytes"] for r in rows),
        "manifest_bytes_max": max(r["manifest_bytes"] for r in rows),
        "rows": rows,
    }
    print(json.dumps({k: v for k, v in summary.items() if k != "rows"}, indent=1))
    if out_path:
        json.dump(summary, open(out_path, "w"), indent=1)
        print(f"wrote {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
