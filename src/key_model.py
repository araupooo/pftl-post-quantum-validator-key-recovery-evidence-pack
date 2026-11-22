#!/usr/bin/env python3
"""key_model.py — pure-computation model of validator key sizes, manifest
capacity, quorum arithmetic, and sequence budgets.

Sources (all cited in docs/citations.md):
- Ed25519 sizes: RFC 8032 (public key 32 bytes, signature 64 bytes).
- ML-DSA sizes: NIST FIPS 204, Table 2 (verified against the NIST PDF).
- SLH-DSA sizes: NIST FIPS 205, Table 2 (verified against the NIST PDF).
- secp256k1 sizes: pinned postfiatd (33-byte compressed public keys,
  DER signatures up to 72 bytes; PublicKey.cpp / SecretKey.cpp).
- Manifest cap: 512 bytes (docs/MANIFEST_FLOOD_HOTFIX.md, pinned postfiatd).
- Token sequence limit: 4,294,967,293 (docs/ValidatorKeyUpdate.md).
- Live UNL size and manifest sizes: outputs/derived/live-validator-set.json.

Usage: python3 src/key_model.py [--live-set PATH] [--out PATH]
Prints the model table as JSON; exits 0.
"""
import argparse
import json

# --- Algorithm sizes (bytes) -------------------------------------------
ALGORITHMS = {
    # name: {public_key, secret_key, signature, source}
    "ed25519": {
        "public_key": 32, "secret_key": 32, "signature": 64,
        "source": "RFC 8032 sections 5.1.5-5.1.6: public key 32 octets, "
                  "signature 64 octets; ~128-bit security (section 2).",
    },
    "secp256k1": {
        "public_key": 33, "secret_key": 32, "signature": 72,
        "source": "Pinned postfiatd: 33-byte compressed public keys "
                  "(PublicKey.cpp publicKeyType); DER ECDSA signatures "
                  "up to 72 bytes (SecretKey.cpp sign). 128-bit classical "
                  "security assumed; no standard sizes table cited.",
    },
    "ML-DSA-44": {
        "public_key": 1312, "secret_key": 2560, "signature": 2420,
        "source": "NIST FIPS 204 Table 2 (verified against the NIST PDF); "
                  "category 2.",
    },
    "ML-DSA-65": {
        "public_key": 1952, "secret_key": 4032, "signature": 3309,
        "source": "NIST FIPS 204 Table 2 (verified against the NIST PDF); "
                  "category 3. Named by the Post Fiat whitepaper section "
                  "1.11 as the genesis validator signature scheme.",
    },
    "ML-DSA-87": {
        "public_key": 2592, "secret_key": 4896, "signature": 4627,
        "source": "NIST FIPS 204 Table 2 (verified against the NIST PDF); "
                  "category 5.",
    },
    "SLH-DSA-128s": {
        "public_key": 32, "secret_key": 64, "signature": 7856,
        "source": "NIST FIPS 205 Table 2 (verified against the NIST PDF); "
                  "category 1, small-signature tuning.",
    },
    "SLH-DSA-128f": {
        "public_key": 32, "secret_key": 64, "signature": 17088,
        "source": "NIST FIPS 205 Table 2; category 1, fast-signing tuning.",
    },
    "SLH-DSA-192s": {
        "public_key": 48, "secret_key": 96, "signature": 16224,
        "source": "NIST FIPS 205 Table 2; category 3, small-signature tuning.",
    },
    "SLH-DSA-256s": {
        "public_key": 64, "secret_key": 128, "signature": 29792,
        "source": "NIST FIPS 205 Table 2; category 5, small-signature tuning.",
    },
    "SLH-DSA-256f": {
        "public_key": 64, "secret_key": 128, "signature": 49856,
        "source": "NIST FIPS 205 Table 2; category 5, fast-signing tuning.",
    },
}

MANIFEST_CAP_BYTES = 512
TOKEN_SEQUENCE_LIMIT = 4294967293  # docs/ValidatorKeyUpdate.md


def manifest_fit(live_manifest_max: int) -> list:
    """For each candidate signature scheme, can its signature fit in a
    manifest at all (cap 512 bytes, before any other field is counted)?"""
    rows = []
    for name, sizes in ALGORITHMS.items():
        sig = sizes["signature"]
        rows.append({
            "algorithm": name,
            "signature_bytes": sig,
            "fits_manifest_cap_512": sig <= MANIFEST_CAP_BYTES,
            "cap_overflow_bytes": max(0, sig - MANIFEST_CAP_BYTES),
            "cap_overflow_factor": round(sig / MANIFEST_CAP_BYTES, 2),
        })
    return rows


def quorum(unl_size: int, pct: float = 0.67) -> dict:
    """Validation quorum for a UNL of this size (ValidatorList.cpp
    calculateQuorum: 67% on this fork; original XRPL 80%)."""
    import math
    q67 = math.ceil(unl_size * 0.67)
    q80 = math.ceil(unl_size * 0.80)
    return {
        "unl_size": unl_size,
        "quorum_67pct": q67,
        "quorum_80pct": q80,
        "max_simultaneous_outages_at_67pct": unl_size - q67,
        "max_simultaneous_outages_at_80pct": unl_size - q80,
    }


def sequence_budget(rotations_per_year: float) -> dict:
    """Years of rotations the 32-bit token sequence space supports."""
    years = TOKEN_SEQUENCE_LIMIT / rotations_per_year if rotations_per_year else None
    return {
        "token_sequence_limit": TOKEN_SEQUENCE_LIMIT,
        "rotations_per_year": rotations_per_year,
        "years_of_rotations_supported": years,
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--live-set", default="outputs/derived/live-validator-set.json")
    ap.add_argument("--out", default="outputs/derived/pq-size-model.json")
    args = ap.parse_args()
    live = json.load(open(args.live_set))
    unl = live["validators"]
    manifest_max = live["manifest_bytes_max"]
    model = {
        "algorithms": ALGORITHMS,
        "live_inputs": {
            "unl_size": unl,
            "manifest_bytes_min": live["manifest_bytes_min"],
            "manifest_bytes_max": manifest_max,
            "manifest_cap_bytes": MANIFEST_CAP_BYTES,
            "manifest_headroom_bytes": MANIFEST_CAP_BYTES - manifest_max,
        },
        "manifest_fit": manifest_fit(manifest_max),
        "quorum": quorum(unl),
        "sequence_budget": {
            "one_rotation_per_6_months": sequence_budget(2),
            "one_rotation_per_year": sequence_budget(1),
            "one_rotation_per_month": sequence_budget(12),
        },
        "whitepaper_quorum_bytes": {
            # Whitepaper section 1.11: q=24 of 35 validators, ML-DSA-65
            # signatures 3,309 bytes each.
            "validators": 35,
            "quorum": 24,
            "signature_bytes_each": ALGORITHMS["ML-DSA-65"]["signature"],
            "quorum_signature_bytes": 24 * ALGORITHMS["ML-DSA-65"]["signature"],
            "note": "Whitepaper section 1.11 arithmetic, recomputed and "
                    "confirmed: 24 x 3309 = 79,416 signature bytes per "
                    "quorum set, before identifiers and framing.",
        },
    }
    json.dump(model, open(args.out, "w"), indent=1)
    print(json.dumps({k: v for k, v in model.items() if k != "algorithms"}, indent=1))
    print(f"wrote {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
