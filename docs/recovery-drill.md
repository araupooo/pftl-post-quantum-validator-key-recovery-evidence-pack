# Recovery drill

Five scenarios, executed in the lab by `scripts/drill.py` (OpenSSL 3.0.13,
freshly generated lab keys, wiped after the run). The full unedited log is
`outputs/drill-run.log`; the machine-readable results are
`outputs/derived/drill-results.json`.

## Lab model — read this first

The drill's "manifest" is a LAB MODEL: a JSON record with the same fields
as a real manifest (master public key, ephemeral signing key, sequence,
domain, master signature, ephemeral signature). It is NOT a byte-exact
postfiatd STObject manifest, and its ephemeral signatures use ECDSA with
SHA-256 while the pinned VL uses SHA-512-Half + secp256k1 ECDSA. What the
drill proves is the lifecycle logic (rotation by sequence + 1, stale
rejection, revocation by sequence 0xFFFFFFFF, unrecoverability without the
master secret) with real cryptography — not the byte format. Real-manifest
parsing is verified separately against all 25 live VL manifests
(`scripts/manifest_parse.py`). The gap is risk R-14.

## Scenario A — Ephemeral signing-key loss [FACT]

- **Setup.** Lab master key Ed25519, lab ephemeral key secp256k1,
  manifest sequence 1, domain `lab.example` — mirroring the live UNL key
  split (25/25 Ed25519 masters, 25/25 secp256k1 ephemeral keys).
- **Fault injected.** The ephemeral secret is deleted; the master secret
  is kept.
- **Recovery.** Generate a replacement ephemeral keypair, build manifest
  sequence 2, verify both signatures.
- **Result.** RECOVERED. New ephemeral key, manifest sequence 2, validator
  identity (master key) unchanged. Total lab time 0.102 s.
- **What it proves.** Ephemeral loss is a routine rotation, not an
  incident. The identity survives because the master key never leaves the
  operator.

## Scenario B — Ephemeral signing-key compromise [FACT]

- **Setup.** Same as A, manifest sequence 1.
- **Fault injected.** The ephemeral secret is treated as known to an
  attacker.
- **Recovery.** Rotate to a new ephemeral key, manifest sequence 2.
- **Result.** RECOVERED. Total lab time 0.078 s. The stale sequence-1
  manifest is rejected by the sequence rule: a manifest whose sequence is
  not strictly greater than the stored one is ignored
  (`Manifest.cpp:411-413`).
- **What it proves.** The rotation mechanism is also the compromise
  response. The window of exposure is the time to generate a new token
  and restart — minutes in practice, not the crypto time.

## Scenario C — Master-key loss [FACT]

- **Setup.** Lab master + ephemeral keys, manifest sequence 1, verified.
- **Fault injected.** The master secret is deleted; no copy exists.
- **Recovery attempted.** Build a rotation manifest without the master
  secret — impossible by construction: there is no key to sign with.
- **Result.** NOT RECOVERABLE. Total lab time 0.113 s (the time to prove
  the negative and measure the alternative). The only path is a new
  validator identity: new master keypair (0.113 s of lab time for the key
  generation itself) plus, on the network side, a new VL entry, a VL
  sequence bump, publisher coordination, and trust re-establishment
  (days, SPECIFIED — no fleet operation was performed).
- **What it proves.** Master-key loss is a terminal event for the identity.
  There is no recovery procedure in the pinned code, and the docs confirm
  the consequence: "you will need to create a completely new validator
  identity."

## Scenario D — Node loss + Shamir restore (3-of-5) [FACT]

- **Setup.** A 32-byte lab master secret (the size of an Ed25519 seed),
  split 3-of-5 with `scripts/shamir.py`. Share commitments recorded.
- **Fault injected.** The "validator-keys.json" (the secret) is deleted,
  simulating a container restart wiping the key file.
- **Recovery.** Rebuild from shares 1, 3, 5; verify the SHA-256 fingerprint
  matches the original.
- **Result.** RECOVERED. Total lab time 0.001 s; the reconstruction itself
  is sub-millisecond for 32 bytes.
- **Failure modes verified.**
  - Only 2 shares: the rebuild produces a wrong value; the fingerprint
    check fails. Recovery is impossible — correctly.
  - One corrupted share: the rebuild produces a wrong value; the
    commitment check detects it before the secret is used.
  - Any other 3-share subset also rebuilds (verified in the Shamir
    self-test across all 10 subsets of a 3-of-5 split).
- **What it proves.** The backup specified in `docs/backup-spec.md` works
  as designed, and its failure modes fail closed (wrong secret, detected)
  rather than silently.

## Scenario E — Master-key compromise [FACT]

- **Setup.** Lab master + ephemeral keys, manifest sequence 3.
- **Fault injected.** The master secret is treated as known to an attacker.
- **Recovery.** Publish a revocation manifest: sequence 0xFFFFFFFF, no
  signing key, authenticated by the master signature
  (`Manifest.cpp:226-240`: revoked is sequence == max uint32).
- **Result.** REVOKED. Total lab time 0.052 s. The revocation signature
  verifies. No further manifest for this master key can ever be accepted,
  because no sequence number higher than 0xFFFFFFFF exists. The validator
  must re-onboard as a new identity.
- **What it proves.** Revocation works — but only while the operator still
  holds the master secret (or a pre-generated revocation manifest). If the
  master key is lost rather than compromised, revocation is impossible
  (finding F-08).

## Timing summary [FACT]

| Scenario | Outcome | Total lab time |
| --- | --- | --- |
| A. Ephemeral loss | RECOVERED | 0.102 s |
| B. Ephemeral compromise | RECOVERED | 0.078 s |
| C. Master loss | NOT RECOVERABLE | 0.113 s |
| D. Node loss + Shamir restore | RECOVERED | 0.001 s |
| E. Master compromise | REVOKED | 0.052 s |

These are lab crypto times only. Real-world recovery time is dominated by
operator steps and manifest propagation (see RTO in `docs/runbook.md`),
not by cryptography.
