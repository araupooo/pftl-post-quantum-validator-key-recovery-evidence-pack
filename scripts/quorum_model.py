#!/usr/bin/env python3
"""quorum_model.py — quorum-preservation analysis for validator recovery.

Inputs: outputs/derived/live-validator-set.json (live UNL size),
outputs/derived/drill-results.json (measured drill timings).
Outputs: outputs/derived/quorum-model.json.

Quorum rule (ValidatorList.cpp calculateQuorum, pinned postfiatd): this
fork uses a 67% quorum; the comment in the code says the original XRPL
uses 80% and mainnet should revert to 80%. Quorum = ceil(pct * unl_size).

RTO/RPO targets in this file are SPECIFIED (design targets derived from
the documented propagation time — "within minutes", ValidatorKeyUpdate.md
— plus the measured lab crypto timings), not measured end-to-end, because
a full fleet rotation cannot be executed from this lab. They are labelled
as such wherever they appear.
"""
import argparse
import json
import math

# Documented propagation time for a new manifest (ValidatorKeyUpdate.md):
# "Other validators will detect and accept the new manifest within minutes".
PROPAGATION_MINUTES = 5  # upper end of "within minutes", conservative
OPERATOR_STEPS_MINUTES = 30  # generate token + edit config + restart (specified)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--live-set", default="outputs/derived/live-validator-set.json")
    ap.add_argument("--drill", default="outputs/derived/drill-results.json")
    ap.add_argument("--out", default="outputs/derived/quorum-model.json")
    args = ap.parse_args()
    live = json.load(open(args.live_set))
    drill = json.load(open(args.drill))
    n = live["validators"]
    q67 = math.ceil(n * 0.67)
    q80 = math.ceil(n * 0.80)

    # How many validators can be offline/rotating at once while the rest
    # can still form a quorum?
    model = {
        "unl_size": n,
        "quorum_67pct": q67,
        "quorum_80pct": q80,
        "max_simultaneous_outages_67pct": n - q67,
        "max_simultaneous_outages_80pct": n - q80,
        "rotation_windows": [],
        "rto_rpo": [],
    }
    for rotating in (1, 2, 4, 8, 9):
        model["rotation_windows"].append({
            "validators_rotating_simultaneously": rotating,
            "validators_remaining": n - rotating,
            "quorum_67pct_still_reachable": (n - rotating) >= q67,
            "quorum_80pct_still_reachable": (n - rotating) >= q80,
        })

    drill_seconds = {r["scenario"]: r["total_seconds"] for r in drill["scenarios"]}
    # RTO = operator steps + propagation; crypto time is measured and negligible.
    rto_ephemeral_min = OPERATOR_STEPS_MINUTES + PROPAGATION_MINUTES
    model["rto_rpo"] = [
        {
            "scenario": "A/B ephemeral-key loss or compromise",
            "rto_minutes": rto_ephemeral_min,
            "rto_basis": "SPECIFIED: 30 min operator steps (token, config, "
                         "restart) + 5 min manifest propagation "
                         "(ValidatorKeyUpdate.md: 'within minutes'); lab "
                         f"crypto time measured at "
                         f"{drill_seconds.get('A', 'n/a')} s (A) / "
                         f"{drill_seconds.get('B', 'n/a')} s (B)",
            "rpo": "0 — no ledger data is lost; the validator re-syncs from "
                   "peers after restart; only the key file is at risk",
        },
        {
            "scenario": "C master-key loss",
            "rto_minutes": None,
            "rto_basis": "NO RTO: the identity is unrecoverable; a new "
                         "identity requires a new VL publication (sequence "
                         "bump), publisher coordination, and trust "
                         "re-establishment. SPECIFIED as days, not minutes; "
                         "not measured — no fleet operation was performed.",
            "rpo": "N/A — the validator identity itself is lost",
        },
        {
            "scenario": "D node loss with 3-of-5 Shamir backup",
            "rto_minutes": rto_ephemeral_min,
            "rto_basis": "SPECIFIED: same operator steps as A/B plus share "
                         "gathering (3 custodians); lab restore measured at "
                         f"{drill_seconds.get('D', 'n/a')} s total, "
                         "reconstruction itself under 1 s",
            "rpo": "0 — the master secret is rebuilt exactly (fingerprint "
                   "verified in the drill)",
        },
        {
            "scenario": "E master-key compromise",
            "rto_minutes": rto_ephemeral_min,
            "rto_basis": "SPECIFIED: revocation manifest propagates like any "
                         "manifest (minutes); the validator is then OFFLINE "
                         "until re-onboarded as a new identity (days, as C)",
            "rpo": "N/A for the compromised identity; the network loses one "
                   "validator until re-onboarding completes",
        },
    ]
    model["quorum_during_recovery"] = {
        "one_validator_down": "quorum unaffected: 24 of 25 remain, quorum 17",
        "eight_validators_down": "quorum still reachable: 17 of 25 remain, "
                                 "exactly quorum 17 — zero margin",
        "nine_validators_down": "quorum LOST at 67%: 16 of 25 remain < 17; "
                                "the network cannot finalize until a "
                                "validator returns",
        "note": "At the 80% mainnet quorum (20 of 25), only 5 simultaneous "
                "outages are tolerable; a rolling rotation must be "
                "one-at-a-time with a quorum check between steps.",
    }
    json.dump(model, open(args.out, "w"), indent=1)
    print(json.dumps(model, indent=1))
    print(f"wrote {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
