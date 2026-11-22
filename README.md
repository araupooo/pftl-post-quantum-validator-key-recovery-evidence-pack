# PFTL Post-Quantum Validator Key Recovery Evidence Pack

A public assessment of how PFTL validator keys are created, backed up,
rotated, and recovered — and where recovery is impossible — built from the
pinned protocol source, the live testnet validator list, and five recovery
drills executed in a lab with freshly generated keys. Assessment and lab
drills only: no live key material was used, no transactions were sent, no
flood traffic was generated, no mainnet was touched, nothing was signed on
the live network.

## Verdict

**Not ready — ephemeral-key recovery works by design; master-key recovery
does not exist; no quantum-resistant path.** Rotating a compromised or lost
ephemeral signing key is a solved problem in the pinned code (new manifest,
sequence + 1, propagates in minutes) and the drill recovers it in 0.1 s of
lab crypto time. Losing the master key is unrecoverable by design: no new
manifest can be signed, no revocation can be published, and the only path
is a brand-new validator identity. The documented backup is a single file
(`validator-keys.json`) that is deleted on container restart, with no
threshold scheme anywhere in the code or docs. And the whitepaper's promise
that "accounts and validators sign with ML-DSA-65 from genesis" is not
implemented in the pinned testnet code at all: every validator identity and
every validation signature on the live testnet is classical, and an
ML-DSA-65 signature (3,309 bytes) cannot fit the 512-byte manifest cap.
See `docs/decision-memo.md` for the full assessment.

## Headline measured numbers (live testnet, network 2025, 2026-11-22 20:14 UTC)

| Measurement | Value |
| --- | --- |
| Build / network / state | postfiatd 1.0.9, network_id 2025, `full`, 21 peers |
| Validated ledger | seq 8,279,102 at probe start |
| Validation quorum | 17 of 25 (67%) |
| Validators in the live list | 25 |
| Validator master keys | 25 of 25 Ed25519 (0xED prefix, 33 bytes) |
| Validator ephemeral signing keys | 25 of 25 secp256k1 compressed (0x02/0x03, 33 bytes) |
| VL validation_public_key is the master key | 25 of 25 |
| Manifest sequences | 1–13; 10 of 25 validators at sequence 1 (never rotated) |
| Manifest sizes | 225–246 bytes (cap 512 bytes) |
| VL blob | sequence 30, effective 2026-11-17, expiration 2028-03-31 |
| VL publisher | single Ed25519 key, manifest sequence 1 |
| Domains on manifests | 25 of 25 |
| Explorer health endpoint | HTTP 500 `{"message":"rippled unreachable"}` |
| validators / peers RPC | HTTP 403 `Forbidden` (admin-gated, as expected) |

## Headline drill results (lab, freshly generated keys, OpenSSL 3.0.13)

| Scenario | Outcome | Lab crypto time |
| --- | --- | --- |
| A. Ephemeral signing-key loss | RECOVERED — new ephemeral key, manifest seq 2, identity unchanged | 0.102 s |
| B. Ephemeral signing-key compromise | RECOVERED — rotation to seq 2; stale seq-1 manifest rejected | 0.078 s |
| C. Master-key loss | NOT RECOVERABLE — no new manifest can be signed; new identity only | 0.113 s |
| D. Node loss + 3-of-5 Shamir restore | RECOVERED — master secret rebuilt from shares 1, 3, 5, fingerprint verified | 0.001 s |
| E. Master-key compromise | REVOKED — revocation manifest seq 0xFFFFFFFF; no further manifest possible | 0.052 s |

Failure modes verified in drill D: 2 shares do not rebuild the secret;
one corrupted share is detected by its SHA-256 commitment.

## Headline modelled numbers (pinned constants, FIPS sizes)

| Quantity | Value |
| --- | --- |
| ML-DSA-65 signature | 3,309 bytes — 6.5x the 512-byte manifest cap |
| Smallest SLH-DSA signature (128s) | 7,856 bytes — 15.3x the manifest cap |
| Ed25519 signature (live) | 64 bytes |
| Simultaneous validator outages tolerated at 67% quorum | 8 of 25 (0 margin at 8; quorum lost at 9) |
| Simultaneous outages tolerated at 80% quorum | 5 of 25 |
| Token sequence budget | 4,294,967,293 rotations — effectively infinite at any sane cadence |

## Counts (recomputed from the lists they summarise)

- Findings: **12 total — 4 HIGH, 5 MEDIUM, 2 LOW, 1 INFO; statuses 9 MEASURED, 3 SPECIFIED**
- Claims: **37 total — 16 VERIFIED, 17 SPECIFIED, 2 UNVERIFIED, 2 UNTESTABLE**
- Risks: **14 total**
- Drill scenarios: **5 — 3 recovered, 1 not recoverable, 1 revoked**

The two UNTESTABLE claims (C-36, C-37) would need a real validator
operation or a running postfiatd with a real token, which this pack's
lab-only boundary forbids. They are marked explicitly in
`docs/claim-index.md`, not asserted.

## Safety boundary

**Lab drills + bounded observation only.** No live key material was used
or touched. All drill keys are freshly generated lab keys, wiped after the
run; only public keys, SHA-256 fingerprints, and timings are recorded. No
transactions were submitted to the testnet. No flood traffic was sent. All
probes are read-only queries against public endpoints (11 RPC calls in
`probe_all.sh`). The boundary is documented in `docs/methodology.md` and in
the header of every probe/drill script.

## Contents

- `docs/index.html` — results page: findings summary with links to evidence
- `docs/methodology.md` — safety boundary, methods, limitations
- `docs/key-inventory.md` — six key classes, live inventory, classification
- `docs/backup-spec.md` — Shamir 3-of-5 backup procedure, offline storage, access control
- `docs/recovery-drill.md` — the five drill scenarios, timings, failure modes
- `docs/runbook.md` — disaster-recovery runbook, RTO/RPO, incident-response playbook
- `docs/pq-migration.md` — ML-DSA/SLH-DSA candidate assessment, whitepaper gap
- `docs/decision-memo.md` — readiness assessment
- `docs/claim-index.md` — 37 claims with statuses and evidence (generated)
- `docs/gap-register.md` — 12 severity-scored findings with remediations (generated)
- `docs/risk-register.md` — 14 risks with likelihood, impact, mitigation (generated)
- `docs/citations.md` — every source with file:line or URL
- `docs/evidence-index.md` — every file and what it supports (generated)
- `src/key_model.py` — algorithm sizes, manifest fit, quorum, sequence budget
- `scripts/probe_all.sh`, `scripts/key_inventory.py` — the live probes (read-only)
- `scripts/manifest_parse.py` — STObject manifest parser (field codes from sfields.macro)
- `scripts/shamir.py` — GF(256) Shamir (k, n) reference implementation + self-test
- `scripts/drill.py` — the five recovery drills (lab keys, OpenSSL)
- `scripts/quorum_model.py` — quorum + RTO/RPO model
- `scripts/analyze.py` — regenerates derived files, findings, manifest
- `scripts/clean_reproduce.sh` — fresh-environment reproduction (exit 0)
- `configs/key-parameters.json` — every pinned key parameter with its file:line source
- `configs/recovery-parameters.json` — RTO/RPO targets and Shamir parameters
- `fixtures/source-excerpts/` — 22 verbatim code/doc excerpts with line numbers
- `fixtures/source-hashes.json` — git blob SHA-1 of every cited file
- `fixtures/pq-sizes.csv` — FIPS 204/205 size tables, verified against the NIST PDFs
- `fixtures/whitepaper-ml-dsa-section.txt` — whitepaper section 1.11, verbatim
- `outputs/` — unedited probe outputs, derived files, fresh-clone set
- `findings.json`, `run-manifest.json`, `SHA256SUMS`

## Pinned revision

postfiatd commit `0085a1ff885d6a446369cf73a4430f75af22be55` (2026-10-10,
PR #50 merge, tag v1.0.9). Every cited line number was verified with
`grep -n` against a local clone at that commit. See
`configs/pinned-revision.txt`.

## Reproduction

```bash
bash scripts/probe_all.sh        # re-probe every live endpoint (read-only)
python3 scripts/manifest_parse.py outputs/testnet_vl.json
python3 scripts/key_inventory.py # decode the live VL + chain state
python3 scripts/shamir.py --self-test   # 11 checks, exit 0
python3 scripts/drill.py         # five recovery drills, exit 0
python3 src/key_model.py         # recompute the size/quorum model
python3 scripts/quorum_model.py  # recompute quorum + RTO/RPO
python3 scripts/analyze.py       # regenerate derived files, findings, manifest
bash scripts/clean_reproduce.sh  # full fresh-environment check, exit 0
bash scripts/verify_digests.sh   # verify SHA256SUMS
```

`clean_reproduce.sh` copies the pack to a throwaway directory, drops all
shipped probe outputs, re-runs the probes, the inventory, the drills, and
the models, and compares the fresh derived numbers with the shipped ones.
It exits 0 only if every comparison check passes. The fresh probe set is
kept under `outputs/fresh-clone-*`.

## Raw log permalinks

Verification answers should lead with these raw-file permalinks so quoted
fields can be checked independently (replace `<repo>` with the published
repository URL):

- `<repo>/raw/main/outputs/probe-run.log`
- `<repo>/raw/main/outputs/drill-run.log`
- `<repo>/raw/main/outputs/derived/drill-results.json`
- `<repo>/raw/main/outputs/derived/live-validator-set.json`
- `<repo>/raw/main/fixtures/source-excerpts/ValidatorKeys-load.txt`
