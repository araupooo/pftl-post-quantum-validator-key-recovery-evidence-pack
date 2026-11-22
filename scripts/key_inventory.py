#!/usr/bin/env python3
"""key_inventory.py — build the live validator key inventory from the
probed validator list and the live chain state.

Inputs (all produced by scripts/probe_all.sh):
  outputs/testnet_vl.json, outputs/server_info.json, outputs/fee.json,
  outputs/ledger_current.json
Outputs:
  outputs/derived/live-validator-set.json (VL decode + chain state)
  outputs/derived/key-inventory.json (key-type inventory + classification)

Ripple epoch for VL effective/expiration timestamps: 2000-01-01T00:00:00Z.
"""
import argparse
import base64
import datetime
import json
import subprocess
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from manifest_parse import parse_manifest, key_type  # noqa: E402

RIPPLE_EPOCH = datetime.datetime(2000, 1, 1, tzinfo=datetime.timezone.utc)


def ripple_to_iso(ts: int) -> str:
    return (RIPPLE_EPOCH + datetime.timedelta(seconds=ts)).isoformat()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out-dir", default="outputs/derived")
    ap.add_argument("--vl", default="outputs/testnet_vl.json")
    ap.add_argument("--server-info", default="outputs/server_info.json")
    args = ap.parse_args()
    out_dir = args.out_dir
    os.makedirs(out_dir, exist_ok=True)

    vl_raw = json.load(open(args.vl))
    blob = vl_raw["blobs_v2"][0]
    inner = json.loads(base64.b64decode(blob["blob"]))
    publisher_manifest = parse_manifest(base64.b64decode(vl_raw["manifest"]))
    pub_master = publisher_manifest[("vlen", 1)].hex().upper()
    pub_signing = publisher_manifest[("vlen", 3)].hex().upper()

    # Reuse manifest_parse's summary via subprocess for one code path.
    tmp = os.path.join(out_dir, "_manifest_tmp.json")
    subprocess.run([sys.executable, "scripts/manifest_parse.py",
                    args.vl, tmp], check=True,
                   capture_output=True)
    summary = json.load(open(tmp))
    os.unlink(tmp)

    si = json.load(open(args.server_info))
    info = si["result"]["info"]
    validated = info["validated_ledger"]

    live_set = {
        "probe": "testnet_vl.json + server_info.json (this pack's probe run)",
        "validator_list": {
            "publisher_public_key": vl_raw["public_key"],
            "publisher_public_key_type": key_type(vl_raw["public_key"]),
            "publisher_manifest_sequence": publisher_manifest[("u32", 4)],
            "publisher_manifest_master_key": pub_master,
            "publisher_manifest_master_key_type": key_type(pub_master),
            "publisher_manifest_signing_key": pub_signing,
            "publisher_manifest_signing_key_type": key_type(pub_signing),
            "blob_sequence": inner["sequence"],
            "effective_ripple": inner["effective"],
            "effective_iso": ripple_to_iso(inner["effective"]),
            "expiration_ripple": inner["expiration"],
            "expiration_iso": ripple_to_iso(inner["expiration"]),
        },
        "validators": summary["validators"],
        "master_key_types": summary["master_key_types"],
        "signing_key_types": summary["signing_key_types"],
        "vl_key_is_master": summary["vl_key_is_master"],
        "vl_key_is_signing": summary["vl_key_is_signing"],
        "distinct_master_keys": summary["distinct_master_keys"],
        "distinct_signing_keys": summary["distinct_signing_keys"],
        "sequences": summary["sequences"],
        "sequence_counts": summary["sequence_counts"],
        "domains_present": summary["domains_present"],
        "manifest_bytes_min": summary["manifest_bytes_min"],
        "manifest_bytes_max": summary["manifest_bytes_max"],
        "chain": {
            "network_id": info.get("network_id"),
            "build_version": info.get("build_version"),
            "validated_ledger_seq": validated["seq"],
            "validated_ledger_hash": validated.get("hash"),
            "validated_ledger_close_time_iso": validated.get("close_time_iso"),
            "peers": info.get("peers"),
            "quorum": info.get("quorum"),
            "validation_quorum": info.get("validation_quorum"),
            "server_state": info.get("server_state"),
        },
        "rows": summary["rows"],
    }
    json.dump(live_set, open(os.path.join(out_dir, "live-validator-set.json"), "w"), indent=1)

    inventory = {
        "key_classes": [
            {
                "class": "Validator master key",
                "role": "Permanent validator identity; signs manifests and "
                        "revocations; node ID is derived from it",
                "algorithm_live": "Ed25519 (25 of 25 live master keys)",
                "algorithm_code": "Ed25519 or secp256k1 (publicKeyType "
                                  "accepts both; Manifest.cpp)",
                "size_bytes": 33,
                "storage_live": "validator-keys.json (per ValidatorKeyUpdate.md)",
                "rotation": "Never rotated without losing the identity; a "
                            "new master key is a new validator",
                "loss_outcome": "UNRECOVERABLE (drill C)",
                "compromise_outcome": "Revocation manifest seq 0xFFFFFFFF "
                                      "(drill E), then new identity",
            },
            {
                "class": "Validator ephemeral signing key",
                "role": "Signs validations; bound to the master key by the "
                        "current manifest",
                "algorithm_live": "secp256k1 compressed (25 of 25 live "
                                  "signing keys)",
                "algorithm_code": "secp256k1 only, derived from the token's "
                                  "validation secret (ValidatorKeys.cpp)",
                "size_bytes": 33,
                "storage_live": "Inside the [validator_token] (base64) in "
                                "postfiatd.cfg, plus the key file",
                "rotation": "New manifest with sequence + 1, signed by the "
                            "master key; propagates in minutes",
                "loss_outcome": "RECOVERABLE by rotation (drill A)",
                "compromise_outcome": "RECOVERABLE by rotation; stale "
                                      "manifests rejected (drill B)",
            },
            {
                "class": "Validation seed (seed mode)",
                "role": "Alternative to a token: a 16-byte seed in "
                        "[validation_seed] generates the validator key",
                "algorithm_live": "Not observable on the live UNL (all 25 "
                                  "validators publish manifests, i.e. token mode)",
                "algorithm_code": "secp256k1 from the seed; master = signing "
                                  "= derived key; sequence 0 "
                                  "(ValidatorKeys.cpp)",
                "size_bytes": 16,
                "storage_live": "postfiatd.cfg [validation_seed]",
                "rotation": "No rotation path: a new seed is a new identity",
                "loss_outcome": "UNRECOVERABLE (same as master-key loss)",
                "compromise_outcome": "No revocation path without a manifest; "
                                      "the key must be removed from trust by "
                                      "the publisher",
            },
            {
                "class": "Validator-list publisher key",
                "role": "Signs the validator list itself; nodes verify the "
                        "VL signature against [validator_list_keys]",
                "algorithm_live": "Ed25519 (publisher key ED3F1E0D...)",
                "algorithm_code": "Ed25519 master + secp256k1 ephemeral "
                                  "(scripts/generate_vl.py)",
                "size_bytes": 33,
                "storage_live": "Publisher-held; single publisher for the testnet",
                "rotation": "VL sequence must increase; nodes reject "
                            "sequence <= current",
                "loss_outcome": "UNRECOVERABLE for the publisher identity; "
                                "nodes would need a new publisher key in config",
                "compromise_outcome": "Attacker can publish a malicious VL "
                                      "until operators change the publisher key",
            },
            {
                "class": "Node key (peer identity)",
                "role": "There is NO separate node key in the pinned code: "
                        "the node's peer identity is its validation key "
                        "(nodeID = hash of the master public key)",
                "algorithm_live": "Same as the validator master key",
                "algorithm_code": "calcNodeID(masterKey) "
                                  "(ValidatorKeys.cpp; PublicKey.cpp)",
                "size_bytes": 20,
                "storage_live": "Derived at startup; not stored separately",
                "rotation": "Follows the master key",
                "loss_outcome": "Follows the master key",
                "compromise_outcome": "Follows the master key",
            },
            {
                "class": "Account keys (for contrast)",
                "role": "Transaction signing keys; NOT validator keys, shown "
                        "only to bound the inventory",
                "algorithm_live": "Not measured in this pack (no account "
                                  "probes were made)",
                "algorithm_code": "Ed25519 or secp256k1 (KeyType enum has "
                                  "exactly these two values)",
                "size_bytes": 33,
                "storage_live": "Account holder's wallet",
                "rotation": "Regular-key / master-key rotation on ledger",
                "loss_outcome": "Account-level; out of scope for this pack",
                "compromise_outcome": "Account-level; out of scope for this pack",
            },
        ],
    }
    json.dump(inventory, open(os.path.join(out_dir, "key-inventory.json"), "w"), indent=1)
    print(json.dumps({k: v for k, v in live_set.items() if k != "rows"}, indent=1))
    print("wrote live-validator-set.json and key-inventory.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
