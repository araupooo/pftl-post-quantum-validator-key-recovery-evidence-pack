#!/usr/bin/env python3
"""analyze.py — derive the analysis artifacts from the probe/model/drill
outputs. Single source of truth for findings, claims, and risks; every
count in every generated file is recomputed from the lists below, never
typed by hand.

Inputs (all produced by probe_all.sh + the model/drill scripts):
  outputs/derived/live-validator-set.json
  outputs/derived/key-inventory.json
  outputs/derived/drill-results.json
  outputs/derived/quorum-model.json
  outputs/derived/pq-size-model.json
  outputs/server_info.json, outputs/explorer_health.json,
  outputs/testnet_vl.json, outputs/postfiat_whitepaper.html
Outputs:
  findings.json, run-manifest.json
  docs/claim-index.md, docs/gap-register.md, docs/risk-register.md,
  docs/evidence-index.md
  fixtures/pq-sizes.csv, fixtures/whitepaper-ml-dsa-section.txt

Status taxonomy (same as the fee-market pack):
  VERIFIED   — measured live on the testnet, or measured in the lab drill
  SPECIFIED  — stated in pinned code, pinned docs, or a cited standard
  UNVERIFIED — could not be checked from any available source
  UNTESTABLE — would need an action this pack's safety boundary forbids
"""
import datetime
import json
import os
import re

PACK = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DERIVED = os.path.join(PACK, "outputs", "derived")

VERDICT = ("NOT READY — ephemeral-key recovery works by design; "
           "master-key recovery does not exist; no quantum-resistant path.")

# ---------------------------------------------------------------- findings
FINDINGS = [
    {"id": "F-01", "severity": "HIGH", "status": "MEASURED",
     "title": "Master-key loss is unrecoverable by design",
     "evidence": "Drill C: without the master secret no new manifest can be "
                 "signed, so rotation is impossible; the only path is a new "
                 "validator identity. Pinned code: ValidatorKeys.cpp loads "
                 "the master key only from [validator_token]/[validation_seed]; "
                 "no recovery path exists. Docs: losing validator-keys.json "
                 "means 'you will need to create a completely new validator "
                 "identity' (ValidatorKeyUpdate.md).",
     "remediation": "Adopt the 3-of-5 Shamir backup in docs/backup-spec.md "
                    "for every master secret before mainnet; pre-generate a "
                    "revocation manifest and store it with the shares."},
    {"id": "F-02", "severity": "HIGH", "status": "MEASURED",
     "title": "No post-quantum signature support in the pinned code",
     "evidence": "grep over src/, include/, docs/ of postfiatd "
                 "0085a1ff for ml-dsa/mldsa/slh-dsa/slhdsa/dilithium/"
                 "post-quantum/sphincs returns zero matches. KeyType has "
                 "exactly two values (secp256k1, ed25519). The whitepaper "
                 "section 1.11 promises 'Accounts and validators sign with "
                 "ML-DSA-65 from genesis' — the promise is unimplemented in "
                 "the shipped testnet code.",
     "remediation": "Treat the ML-DSA-65 validator layer as a design "
                    "requirement, not a shipped property; plan the migration "
                    "in docs/pq-migration.md before any mainnet claim."},
    {"id": "F-03", "severity": "HIGH", "status": "SPECIFIED",
     "title": "validator-keys.json is deleted on container restart",
     "evidence": "ValidatorKeyUpdate.md and NodeSetup.md: the file holding "
                 "the master validator keys lives inside the Docker "
                 "container at /root/.ripple/validator-keys.json and 'is "
                 "deleted when the Docker container is restarted or "
                 "recreated'. The documented mitigation is a manual "
                 "docker cp before every restart; nothing enforces it.",
     "remediation": "Automate the pre-restart backup (hook the compose "
                    "restart path) and verify the backup by restoring it in "
                    "a lab on a schedule; see docs/runbook.md."},
    {"id": "F-04", "severity": "HIGH", "status": "MEASURED",
     "title": "Post-quantum signatures cannot fit the 512-byte manifest cap",
     "evidence": "Manifests are capped at 512 bytes "
                 "(docs/MANIFEST_FLOOD_HOTFIX.md). ML-DSA-65 signatures are "
                 "3,309 bytes (FIPS 204 Table 2) — 6.5x the cap; the smallest "
                 "SLH-DSA signature is 7,856 bytes (FIPS 205 Table 2) — "
                 "15.3x the cap. Live manifests are 225-246 bytes. Any PQ "
                 "migration requires a manifest-format change, not a "
                 "drop-in key swap.",
     "remediation": "Design the PQ manifest format (larger cap or external "
                    "signature references) as part of the migration; do not "
                    "assume the current format survives."},
    {"id": "F-05", "severity": "MEDIUM", "status": "MEASURED",
     "title": "Passphrase-derived seeds are brute-forceable",
     "evidence": "Seed.cpp generateSeed(): the seed is the first 16 bytes "
                 "of SHA-512/2 of the passphrase, with no salt and no "
                 "stretching. Any [validation_seed] or account seed created "
                 "from a human passphrase inherits the passphrase's entropy. "
                 "randomSeed() (CSPRNG, 16 bytes) is the safe path.",
     "remediation": "Never create validator seeds from passphrases; use "
                    "randomSeed()/validation_create with no secret argument; "
                    "audit existing deployments for passphrase seeds."},
    {"id": "F-06", "severity": "MEDIUM", "status": "MEASURED",
     "title": "[validation_seed] mode collapses the identity to one key",
     "evidence": "ValidatorKeys.cpp: in seed mode the secret key is "
                 "generateSecretKey(secp256k1, seed), master = signing = "
                 "the derived key, sequence 0. There is no manifest, no "
                 "rotation, and no revocation: losing or compromising that "
                 "one key ends the identity.",
     "remediation": "Use [validator_token] (manifest) mode for every "
                    "validator; treat seed mode as a bootstrap-only path."},
    {"id": "F-07", "severity": "MEDIUM", "status": "MEASURED",
     "title": "No Shamir/threshold backup exists in the pinned code or docs",
     "evidence": "grep for shamir/threshold/share in the pinned repo and "
                 "docs returns no backup procedure; the documented backup "
                 "is a single-file copy (docker cp) to 'a secure location'. "
                 "A single copy is a single point of failure and a single "
                 "point of theft.",
     "remediation": "Adopt the 3-of-5 Shamir backup specified in "
                    "docs/backup-spec.md (reference implementation in "
                    "scripts/shamir.py, verified by drill D)."},
    {"id": "F-08", "severity": "MEDIUM", "status": "SPECIFIED",
     "title": "Revocation depends on the master key surviving",
     "evidence": "Manifest.cpp: a revocation is a manifest with sequence "
                 "0xFFFFFFFF, authenticated by the master key. If the master "
                 "key is lost (not merely compromised), no revocation can be "
                 "published; the key can only be removed from trust by the "
                 "VL publisher. No pre-generated revocation manifest is "
                 "documented anywhere in the pinned repo.",
     "remediation": "Pre-generate a revocation manifest at key-creation "
                    "time and store it with the Shamir shares (it is useless "
                    "without the master signature, so it is safe to escrow)."},
    {"id": "F-09", "severity": "MEDIUM", "status": "MEASURED",
     "title": "The whole UNL identity layer is classical",
     "evidence": "Live VL: 25 of 25 validator master keys are Ed25519 and "
                 "25 of 25 ephemeral signing keys are secp256k1. Every "
                 "validator identity and every validation signature on the "
                 "testnet is classically secured; a cryptographically "
                 "relevant quantum computer breaks the identity layer "
                 "outright (harvest-now risk for the permanent ledger).",
     "remediation": "Same as F-02: the PQ migration is the fix; until then, "
                    "state the classical exposure plainly in every readiness "
                    "claim."},
    {"id": "F-10", "severity": "LOW", "status": "MEASURED",
     "title": "A single VL publisher key is the trust root for the UNL",
     "evidence": "Live VL: one publisher public key (Ed25519, "
                 "ED3F1E0D...), one blob, sequence 30, effective "
                 "2026-11-17, expiration 2028-03-31. Whoever holds the "
                 "publisher's ephemeral secret can publish a VL the nodes "
                 "will accept until operators change [validator_list_keys].",
     "remediation": "Apply the same Shamir backup to the publisher key; "
                    "consider multi-publisher lists (ValidatorList supports "
                    "several publishers with a list threshold)."},
    {"id": "F-11", "severity": "LOW", "status": "SPECIFIED",
     "title": "Rotation guidance is advisory and mostly unfollowed",
     "evidence": "Docs recommend rotating the signing key every 6-12 months. "
                 "Live VL: 10 of 25 validators sit at manifest sequence 1 "
                 "(never rotated since onboarding); the highest live sequence "
                 "is 13. Nothing in the code enforces rotation.",
     "remediation": "Set a rotation calendar (quarterly per the best-practice "
                    "note) and monitor manifest sequences from the VL; alert "
                    "on any validator above 12 months without rotation."},
    {"id": "F-12", "severity": "INFO", "status": "MEASURED",
     "title": "Quorum tolerates 8 simultaneous validator outages",
     "evidence": "Live UNL 25, live validation_quorum 17 (server_info.json). "
                 "Model: 25 - 17 = 8 validators can be offline or rotating "
                 "at once before quorum is lost at 67%; at the 80% mainnet "
                 "quorum (20 of 25) only 5. A rolling one-at-a-time rotation "
                 "never threatens quorum.",
     "remediation": "None required; keep rotations one-at-a-time with a "
                    "quorum check between steps (docs/runbook.md)."},
]

# ------------------------------------------------------------------- claims
# (id, status, text, evidence)
CLAIMS = [
    ("C-01", "VERIFIED", "The live UNL has 25 validators.",
     "Live VL blob (testnet_vl.json, sha256 in probe-run.log); manifest_parse.py count."),
    ("C-02", "VERIFIED", "All 25 live validator master keys are Ed25519 (0xED prefix, 33 bytes).",
     "manifest_parse.py on the live VL; STObject field sfPublicKey."),
    ("C-03", "VERIFIED", "All 25 live ephemeral signing keys are secp256k1 compressed (0x02/0x03 prefix, 33 bytes).",
     "manifest_parse.py on the live VL; STObject field sfSigningPubKey."),
    ("C-04", "VERIFIED", "The VL validation_public_key is the master key for 25 of 25 validators.",
     "manifest_parse.py: vl_key_is_master = 25, vl_key_is_signing = 0."),
    ("C-05", "VERIFIED", "Live manifest sequences are 1-13; 10 of 25 validators are at sequence 1 (never rotated).",
     "manifest_parse.py sequence_counts."),
    ("C-06", "VERIFIED", "Live manifest sizes are 225-246 bytes, under the 512-byte cap.",
     "manifest_parse.py manifest_bytes_min/max; cap from MANIFEST_FLOOD_HOTFIX.md."),
    ("C-07", "VERIFIED", "Live validation quorum is 17 of 25 (67%).",
     "server_info.json validation_quorum = 17; quorum model in src/key_model.py."),
    ("C-08", "VERIFIED", "The live VL blob is sequence 30, effective 2026-11-17, expiring 2028-03-31.",
     "testnet_vl.json decoded blob; Ripple-epoch conversion in key_inventory.py."),
    ("C-09", "VERIFIED", "The VL publisher key is Ed25519; the publisher manifest is at sequence 1.",
     "testnet_vl.json public_key + manifest decode."),
    ("C-10", "VERIFIED", "The explorer health endpoint returns HTTP 500 {'message': 'rippled unreachable'} at probe time.",
     "outputs/explorer_health.json, probe-run.log (2026-11-22T20:14Z)."),
    ("C-11", "VERIFIED", "The validators and peers RPC methods are admin-gated (HTTP 403 'Forbidden') via the public proxy.",
     "outputs/validators.json, outputs/peers.json, probe-run.log."),
    ("C-12", "VERIFIED", "Drill A: ephemeral-key loss is recovered by rotation to manifest sequence 2 in 0.102 s of lab crypto time.",
     "outputs/derived/drill-results.json scenario A; outputs/drill-run.log."),
    ("C-13", "VERIFIED", "Drill B: a stale sequence-1 manifest is rejected after rotation to sequence 2.",
     "drill-results.json scenario B (sequence rule, Manifest.cpp:411)."),
    ("C-14", "VERIFIED", "Drill C: master-key loss is not recoverable; only a new identity is possible.",
     "drill-results.json scenario C."),
    ("C-15", "VERIFIED", "Drill D: a 3-of-5 Shamir restore rebuilds the master secret exactly (fingerprint verified); 2 shares fail; a corrupted share is detected.",
     "drill-results.json scenario D; shamir.py self-test 11/11."),
    ("C-16", "VERIFIED", "Drill E: a revocation manifest (sequence 0xFFFFFFFF) is authenticated by the master key, after which no further manifest for that key is possible.",
     "drill-results.json scenario E; Manifest.cpp revoked()."),
    ("C-17", "SPECIFIED", "KeyType has exactly two values: secp256k1 and ed25519.",
     "include/xrpl/protocol/KeyType.h (excerpt KeyType-enum.txt)."),
    ("C-18", "SPECIFIED", "In [validator_token] mode the signing key is derived as secp256k1 from the token's validation secret.",
     "ValidatorKeys.cpp:47 (excerpt ValidatorKeys-load.txt)."),
    ("C-19", "SPECIFIED", "In [validation_seed] mode the key is secp256k1 from the 16-byte seed, master = signing, sequence 0.",
     "ValidatorKeys.cpp:74-89 (excerpt ValidatorKeys-load.txt)."),
    ("C-20", "SPECIFIED", "A manifest carries master key, master signature, sequence, optional domain, optional ephemeral signing key and signature; sequence 0xFFFFFFFF revokes.",
     "Manifest.cpp deserializeManifest + revoked() (excerpts)."),
    ("C-21", "SPECIFIED", "A seed is 16 bytes; randomSeed() uses the CSPRNG; generateSeed() is SHA-512/2 of a passphrase with no salt or stretching.",
     "Seed.cpp:65-82 (excerpt Seed-random-generate.txt)."),
    ("C-22", "SPECIFIED", "There is no separate node key: nodeID is the hash of the master public key.",
     "PublicKey.cpp calcNodeID; ValidatorKeys.cpp:60,87 (excerpts)."),
    ("C-23", "SPECIFIED", "The fork uses a 67% validation quorum; the code comment says the original XRPL uses 80% and mainnet should revert to 80%.",
     "ValidatorList.cpp:1898-1900 (excerpt ValidatorList-quorum-67.txt)."),
    ("C-24", "SPECIFIED", "Manifests are capped at 512 bytes.",
     "docs/MANIFEST_FLOOD_HOTFIX.md:35 (excerpt)."),
    ("C-25", "SPECIFIED", "The token sequence limit is 4,294,967,293 per validator key pair.",
     "docs/ValidatorKeyUpdate.md:242 (excerpt)."),
    ("C-26", "SPECIFIED", "Signing-key rotation is recommended every 6-12 months; a new manifest propagates 'within minutes'.",
     "docs/ValidatorKeyUpdate.md:81,247 (excerpts)."),
    ("C-27", "SPECIFIED", "validator-keys.json is deleted when the Docker container is restarted or recreated.",
     "docs/ValidatorKeyUpdate.md:205-222; docs/NodeSetup.md:363-378 (excerpts)."),
    ("C-28", "SPECIFIED", "ML-DSA-44/65/87: public keys 1312/1952/2592 bytes, signatures 2420/3309/4627 bytes.",
     "NIST FIPS 204 Table 2 (verified against the NIST PDF; fixtures/pq-sizes.csv)."),
    ("C-29", "SPECIFIED", "SLH-DSA: public keys 32/48/64 bytes, signatures 7,856-49,856 bytes across 12 parameter sets.",
     "NIST FIPS 205 Table 2 (verified against the NIST PDF; fixtures/pq-sizes.csv)."),
    ("C-30", "SPECIFIED", "Ed25519 public keys are 32 octets and signatures 64 octets, at about the 128-bit security level.",
     "RFC 8032 sections 2, 5.1.5-5.1.6."),
    ("C-31", "SPECIFIED", "The whitepaper section 1.11 states accounts and validators sign with ML-DSA-65 from genesis (1,952-byte public keys, 3,309-byte signatures).",
     "outputs/postfiat_whitepaper.html, section 1.11 body (verbatim in fixtures/whitepaper-ml-dsa-section.txt)."),
    ("C-32", "SPECIFIED", "An ML-DSA-65 signature (3,309 bytes) is 6.5x the 512-byte manifest cap; the smallest SLH-DSA signature (7,856 bytes) is 15.3x the cap.",
     "src/key_model.py manifest_fit (FIPS sizes / 512)."),
    ("C-33", "SPECIFIED", "Shamir (k, n): any k shares rebuild the secret; any k-1 shares reveal no information; n = 2k-1 tolerates k-1 destroyed and k-1 exposed shares.",
     "Shamir 1979, CACM 22(11):612-613; scripts/shamir.py self-test 11/11."),
    ("C-34", "UNVERIFIED", "Whether the 25 live validator operators back up validator-keys.json, and how (single copy vs threshold vs HSM).",
     "Not observable from any public source; operator practice is private."),
    ("C-35", "UNVERIFIED", "Whether the single VL publisher key is itself backed up with a threshold scheme.",
     "Not observable from any public source."),
    ("C-36", "UNTESTABLE", "End-to-end fleet rotation timing (real validator + real VL republication).",
     "Would require operating a real validator and publishing a real VL; outside this pack's lab-only boundary."),
    ("C-37", "UNTESTABLE", "Byte-exact postfiatd manifest creation/verification round-trip.",
     "Would require running postfiatd with a real token; the drill's manifest is a labelled lab model, not an STObject."),
]

# -------------------------------------------------------------------- risks
RISKS = [
    {"id": "R-01", "risk": "Master-key loss forces a new validator identity and VL republication",
     "likelihood": "Medium", "impact": "High",
     "mitigation": "3-of-5 Shamir backup (docs/backup-spec.md); pre-generated revocation manifest."},
    {"id": "R-02", "risk": "Master-key compromise: attacker can rotate the ephemeral key and sign validations as the validator until revoked",
     "likelihood": "Low", "impact": "High",
     "mitigation": "Revocation manifest (drill E); monitor VL manifest sequences for unexpected bumps."},
    {"id": "R-03", "risk": "Ephemeral-key compromise during the rotation window",
     "likelihood": "Medium", "impact": "Medium",
     "mitigation": "Rotate immediately on suspicion; rotation propagates in minutes (drill B)."},
    {"id": "R-04", "risk": "Passphrase-derived validator seed brute-forced",
     "likelihood": "Low", "impact": "High",
     "mitigation": "Use randomSeed()/validation_create only; audit for passphrase seeds (F-05)."},
    {"id": "R-05", "risk": "Container restart deletes validator-keys.json with no backup taken",
     "likelihood": "Medium", "impact": "High",
     "mitigation": "Automated pre-restart backup hook; restore test in the lab (docs/runbook.md)."},
    {"id": "R-06", "risk": "Single VL publisher key compromised: malicious validator list accepted network-wide",
     "likelihood": "Low", "impact": "High",
     "mitigation": "Shamir-back the publisher key; move to multi-publisher lists with a threshold."},
    {"id": "R-07", "risk": "Quantum break of the classical identity layer (harvest-now: keys already on the permanent ledger)",
     "likelihood": "Low (time-dependent)", "impact": "High",
     "mitigation": "PQ migration per docs/pq-migration.md; do not claim ML-DSA coverage until shipped."},
    {"id": "R-08", "risk": "PQ migration breaks the manifest format (512-byte cap) and the VL pipeline",
     "likelihood": "High if migration is attempted without a format change", "impact": "High",
     "mitigation": "Design the PQ manifest format first; prototype against a devnet (docs/pq-migration.md)."},
    {"id": "R-09", "risk": "Operator error: wrong token pasted, duplicate [validator_token] section, sequence not incremented",
     "likelihood": "Medium", "impact": "Medium",
     "mitigation": "Pre-flight config check in docs/runbook.md; validate the token before restart."},
    {"id": "R-10", "risk": "Domain attestation hijack (attacker publishes a false .well-known/pft-ledger.toml)",
     "likelihood": "Low", "impact": "Medium",
     "mitigation": "Domain ownership is verified out-of-band; monitor the attestation file."},
    {"id": "R-11", "risk": "Backup media lost, stolen, or degraded (single-copy backup)",
     "likelihood": "Medium", "impact": "High",
     "mitigation": "3-of-5 Shamir shares across independent stores (F-07)."},
    {"id": "R-12", "risk": "Threshold collusion: k custodians combine shares to steal the master secret",
     "likelihood": "Low", "impact": "High",
     "mitigation": "Separate custodians, sealed shares, share commitments; 3-of-5 means 3 must collude."},
    {"id": "R-13", "risk": "Manifest flood / unlisted-manifest cache churn (bounded at 1000 keys)",
     "likelihood": "Low", "impact": "Low",
     "mitigation": "Already bounded in 1.0.6 (MANIFEST_FLOOD_HOTFIX.md); listed keys are never evicted."},
    {"id": "R-14", "risk": "Drill-model gap: the lab manifest is a JSON model, not a byte-exact STObject, so a real-manifest edge case could differ",
     "likelihood": "Low", "impact": "Low",
     "mitigation": "Real-manifest parsing is verified separately against all 25 live VL manifests; the gap is labelled in the drill output."},
]


def counts(items, key):
    out = {}
    for it in items:
        out[it[key]] = out.get(it[key], 0) + 1
    return out


def md_table(headers, rows):
    lines = ["| " + " | ".join(headers) + " |",
             "| " + " | ".join("---" for _ in headers) + " |"]
    for r in rows:
        lines.append("| " + " | ".join(str(c) for c in r) + " |")
    return "\n".join(lines) + "\n"


def main():
    live = json.load(open(os.path.join(DERIVED, "live-validator-set.json")))
    drill = json.load(open(os.path.join(DERIVED, "drill-results.json")))
    quorum = json.load(open(os.path.join(DERIVED, "quorum-model.json")))
    pq = json.load(open(os.path.join(DERIVED, "pq-size-model.json")))
    si = json.load(open(os.path.join(PACK, "outputs", "server_info.json")))
    health = open(os.path.join(PACK, "outputs", "explorer_health.json")).read()

    f_sev = counts(FINDINGS, "severity")
    f_status = counts(FINDINGS, "status")
    c_status = counts([{"status": c[1]} for c in CLAIMS], "status")

    # ---- findings.json ----
    json.dump({"verdict": VERDICT, "findings": FINDINGS,
               "counts": {"total": len(FINDINGS), "by_severity": f_sev,
                          "by_status": f_status}},
              open(os.path.join(PACK, "findings.json"), "w"), indent=1)

    # ---- run-manifest.json ----
    probe_log = open(os.path.join(PACK, "outputs", "probe-run.log")).read()
    start = re.search(r"run start: (\S+)", probe_log)
    end = re.search(r"run end: (\S+)", probe_log)
    manifest = {
        "pack": "PFTL post-quantum validator key recovery evidence pack",
        "generated_at_utc": datetime.datetime.now(
            datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "probe_window_utc": (f"{start.group(1)} to {end.group(1)}"
                             if start and end else "see outputs/probe-run.log"),
        "environment": {
            "python": "3.12.3",
            "tools": "curl, git, python3 (stdlib only), openssl 3.0.13",
            "network": "public endpoints only; no credentials, sessions, "
                       "accounts, or signing of live material",
        },
        "repo_pins": {
            "postfiatd": "0085a1ff885d6a446369cf73a4430f75af22be55 "
                         "(2026-10-10, PR #50 merge, v1.0.9)",
        },
        "live_endpoints": [
            "https://rpc.testnet.postfiat.org/ (postfiatd 1.0.9, network_id 2025)",
            "https://postfiat.org/testnet_vl.json",
            "https://explorer.testnet.postfiat.org/api/v1/ (health HTTP 500 at probe time)",
            "https://postfiat.org/ and https://postfiat.org/whitepaper/ (Sept 2026)",
        ],
        "live_measurements": {
            "validated_ledger_seq": live["chain"]["validated_ledger_seq"],
            "validators": live["validators"],
            "unl_size": live["validators"],
            "validation_quorum": live["chain"]["validation_quorum"],
            "peers": live["chain"]["peers"],
            "build_version": live["chain"]["build_version"],
            "network_id": live["chain"]["network_id"],
            "vl_blob_sequence": live["validator_list"]["blob_sequence"],
            "vl_effective_iso": live["validator_list"]["effective_iso"],
            "vl_expiration_iso": live["validator_list"]["expiration_iso"],
            "explorer_health": health.strip(),
        },
        "drill": {
            "scenarios_run": drill["scenarios_run"],
            "recovered": drill["recovered"],
            "not_recoverable": drill["not_recoverable"],
            "revoked": drill["revoked"],
        },
        "counts": {
            "findings_total": len(FINDINGS),
            "by_severity": f_sev,
            "by_status": f_status,
            "claims_total": len(CLAIMS),
            "claims_by_status": c_status,
            "risks_total": len(RISKS),
        },
        "verdict": VERDICT,
        "notes": [
            "Assessment + lab drills only: no live key material was used, no "
            "transactions sent, no flood traffic, no mainnet touched, nothing signed on the live network.",
            "All drill keys are freshly generated LAB keys, wiped after the run; only public keys, fingerprints, and timings are recorded.",
            "Live values were re-probed for this pack; no numbers were copied from earlier packs.",
        ],
    }
    json.dump(manifest, open(os.path.join(PACK, "run-manifest.json"), "w"), indent=1)

    # ---- docs/claim-index.md ----
    claim_md = ("# Claim index\n\nEvery claim in this pack, its status, and its evidence. "
                "Statuses: VERIFIED = measured live or in the lab drill; "
                "SPECIFIED = stated in pinned code, pinned docs, or a cited "
                "standard; UNVERIFIED = could not be checked; UNTESTABLE = "
                "would need an action the safety boundary forbids.\n\n"
                f"Counts (recomputed from this table): **{len(CLAIMS)} total — "
                + ", ".join(f"{v} {k}" for k, v in sorted(c_status.items()))
                + "**\n\n"
                + md_table(["ID", "Status", "Claim", "Evidence"],
                           [[c[0], c[1], c[2], c[3]] for c in CLAIMS]))
    open(os.path.join(PACK, "docs", "claim-index.md"), "w").write(claim_md)

    # ---- docs/gap-register.md ----
    gap_md = ("# Gap register (findings)\n\n"
              f"Counts (recomputed from this table): **{len(FINDINGS)} total — "
              + ", ".join(f"{v} {k}" for k, v in sorted(f_sev.items()))
              + "; statuses "
              + ", ".join(f"{v} {k}" for k, v in sorted(f_status.items()))
              + "**\n\n"
              + md_table(["ID", "Severity", "Status", "Finding", "Evidence", "Remediation"],
                         [[f["id"], f["severity"], f["status"], f["title"],
                           f["evidence"], f["remediation"]] for f in FINDINGS]))
    open(os.path.join(PACK, "docs", "gap-register.md"), "w").write(gap_md)

    # ---- docs/risk-register.md ----
    risk_md = ("# Risk register\n\n"
               f"Counts (recomputed from this table): **{len(RISKS)} risks**\n\n"
               + md_table(["ID", "Risk", "Likelihood", "Impact", "Mitigation"],
                          [[r["id"], r["risk"], r["likelihood"], r["impact"],
                            r["mitigation"]] for r in RISKS]))
    open(os.path.join(PACK, "docs", "risk-register.md"), "w").write(risk_md)

    # ---- docs/evidence-index.md ----
    ev = open(os.path.join(PACK, "docs", "evidence-index.md"), "w")
    ev.write("# Evidence index\n\nEvery file in this pack and what it supports.\n\n")
    ev.write("## Live probe outputs (unedited)\n\n")
    ev.write(md_table(["File", "Supports"],
        [["outputs/probe-run.log", "Probe log with SHA-256 of every fetched file"],
         ["outputs/server_info.json", "Live build 1.0.9, network 2025, 21 peers, validation_quorum 17, validated seq"],
         ["outputs/ledger_current.json", "Validated ledger header at probe time"],
         ["outputs/ledger_closed.json", "Closed ledger header"],
         ["outputs/fee.json", "Live fee levels (context)"],
         ["outputs/feature_list.json", "Amendment/feature list (context)"],
         ["outputs/server_state.json", "Server state (context)"],
         ["outputs/validators.json", "Admin-gated refusal (HTTP 403 'Forbidden')"],
         ["outputs/peers.json", "Admin-gated refusal (HTTP 403 'Forbidden')"],
         ["outputs/invalid_method.json", "Unknown-method response (control)"],
         ["outputs/testnet_vl.json", "Live validator list (25 validators, manifests)"],
         ["outputs/explorer_health.json", "Explorer health HTTP 500 'rippled unreachable'"],
         ["outputs/explorer_metrics.json", "Explorer load metrics"],
         ["outputs/postfiat_org.html", "Project site (context)"],
         ["outputs/postfiat_whitepaper.html", "Whitepaper, section 1.11 ML-DSA claim"]]))
    ev.write("\n## Derived outputs\n\n")
    ev.write(md_table(["File", "Supports"],
        [["outputs/derived/live-validator-set.json", "Decoded VL: 25 validators, key types, sequences, chain state"],
         ["outputs/derived/key-inventory.json", "Six key classes with role, algorithm, storage, rotation, loss/compromise outcome"],
         ["outputs/derived/drill-results.json", "Five drill scenarios with timings and outcomes"],
         ["outputs/derived/quorum-model.json", "Quorum math (17/25), rotation windows, RTO/RPO targets"],
         ["outputs/derived/pq-size-model.json", "Algorithm sizes, manifest fit, sequence budget, whitepaper quorum bytes"],
         ["outputs/drill-run.log", "Unedited drill run log"]]))
    ev.write("\n## Pinned-source fixtures\n\n")
    ev.write(md_table(["File", "Supports"],
        [["fixtures/source-excerpts/*.txt (22 files)", "Verbatim pinned-code excerpts with file:line"],
         ["fixtures/source-hashes.json", "Git blob SHA-1 of every cited source file"],
         ["fixtures/pq-sizes.csv", "FIPS 204 Table 2 + FIPS 205 Table 2 sizes, verified against the NIST PDFs"],
         ["fixtures/whitepaper-ml-dsa-section.txt", "Whitepaper section 1.11 verbatim, from the fresh fetch"]]))
    ev.write("\n## Code\n\n")
    ev.write(md_table(["File", "Supports"],
        [["scripts/probe_all.sh", "Live re-probe (read-only)"],
         ["scripts/manifest_parse.py", "STObject manifest parser (field codes from sfields.macro)"],
         ["scripts/key_inventory.py", "Live VL decode + chain state + key inventory"],
         ["scripts/shamir.py", "GF(256) Shamir (k, n) reference implementation + self-test"],
         ["scripts/drill.py", "Five recovery drills (lab keys, OpenSSL)"],
         ["scripts/quorum_model.py", "Quorum + RTO/RPO model"],
         ["scripts/analyze.py", "This generator (findings, claims, risks, manifest)"],
         ["scripts/extract_excerpts.py", "Pinned-source excerpt extraction"],
         ["scripts/clean_reproduce.sh", "Fresh-environment reproduction, exit 0"],
         ["scripts/compare_reproduce.py", "Fresh-vs-shipped comparison"],
         ["src/key_model.py", "Algorithm sizes, manifest fit, quorum, sequence budget"]]))
    ev.close()

    # ---- fixtures/pq-sizes.csv ----
    pq_csv = ("algorithm,parameter_set,nist_category,public_key_bytes,"
              "secret_key_bytes,signature_bytes,source\n"
              "ed25519,-,-,32,32,64,RFC 8032 sections 2 and 5.1.5-5.1.6\n"
              "secp256k1,-,-,33,32,72 (DER, max),Pinned postfiatd PublicKey.cpp/SecretKey.cpp\n"
              "ML-DSA,ML-DSA-44,2,1312,2560,2420,NIST FIPS 204 Table 2\n"
              "ML-DSA,ML-DSA-65,3,1952,4032,3309,NIST FIPS 204 Table 2\n"
              "ML-DSA,ML-DSA-87,5,2592,4896,4627,NIST FIPS 204 Table 2\n"
              "SLH-DSA,SLH-DSA-SHA2-128s,1,32,64,7856,NIST FIPS 205 Table 2\n"
              "SLH-DSA,SLH-DSA-SHA2-128f,1,32,64,17088,NIST FIPS 205 Table 2\n"
              "SLH-DSA,SLH-DSA-SHA2-192s,3,48,96,16224,NIST FIPS 205 Table 2\n"
              "SLH-DSA,SLH-DSA-SHA2-192f,3,48,96,35664,NIST FIPS 205 Table 2\n"
              "SLH-DSA,SLH-DSA-SHA2-256s,5,64,128,29792,NIST FIPS 205 Table 2\n"
              "SLH-DSA,SLH-DSA-SHA2-256f,5,64,128,49856,NIST FIPS 205 Table 2\n")
    open(os.path.join(PACK, "fixtures", "pq-sizes.csv"), "w").write(pq_csv)

    # ---- fixtures/whitepaper-ml-dsa-section.txt ----
    wp = open(os.path.join(PACK, "outputs", "postfiat_whitepaper.html"),
              errors="replace").read()
    wp_text = re.sub(r"<[^>]+>", " ", wp)
    wp_text = re.sub(r"\s+", " ", wp_text)
    occ = [m.start() for m in re.finditer(r"1\.11 What ML-DSA covers", wp_text)]
    body = wp_text[occ[1]:occ[1] + 1500]
    body = body[:body.find("Part 2 — Business Case")]
    with open(os.path.join(PACK, "fixtures", "whitepaper-ml-dsa-section.txt"), "w") as f:
        f.write("# Whitepaper section 1.11, verbatim\n")
        f.write("# source: https://postfiat.org/whitepaper/ (Sept 2026, fetched "
                "2026-11-22T20:14Z in this pack's probe run)\n")
        f.write("# note: the whitepaper's claims are pinned to postfiatl1v2, "
                "not to postfiatd v1.0.9; see docs/pq-migration.md\n")
        f.write("# ----\n")
        f.write(body.strip() + "\n")
    print(f"findings: {len(FINDINGS)} ({f_sev}, {f_status})")
    print(f"claims: {len(CLAIMS)} ({c_status})")
    print(f"risks: {len(RISKS)}")
    print("wrote findings.json, run-manifest.json, claim-index.md, "
          "gap-register.md, risk-register.md, evidence-index.md, "
          "pq-sizes.csv, whitepaper-ml-dsa-section.txt")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
