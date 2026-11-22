# Backup-procedure specification

## Status

[SPECIFIED] This is a specification, not a description of current practice.
No threshold backup exists in the pinned code or docs today (finding F-07);
the documented backup is a single-file copy. This specification is
implementable with the reference code in this pack and is verified by
drill D.

## Design: Shamir 3-of-5 over the master secret

- **Scheme.** Shamir (k, n) = (3, 5) threshold sharing over GF(256)
  (Shamir 1979, Communications of the ACM 22(11):612-613). Any 3 of the 5
  shares rebuild the secret; any 2 shares reveal no information about it.
  With n = 2k - 1 the scheme recovers the secret even when k - 1 shares
  are destroyed, and stays secure even when k - 1 of the remaining shares
  are exposed.
- **Reference implementation.** `scripts/shamir.py` (GF(256), AES
  polynomial 0x11b, generator 3). Self-test: 11/11 checks, including
  round-trip reconstruction from every 3-share subset, k-1 failure,
  corruption detection, and parameter validation.
- **What is shared.** The 32-byte master secret (the Ed25519 seed, or the
  32-byte ML-DSA seed if the PQ migration lands — FIPS 204 notes the
  private key can be stored as just its 32-byte seed). The share format is
  `(index, 32 bytes)` plus a SHA-256 commitment per share. The commitment
  lets the restorer detect a corrupted share before trusting the rebuild
  (drill D verifies this).
- **What is NOT shared.** The ephemeral signing key (it is replaceable by
  rotation) and the validator token (it is re-derivable from the master
  key). Backing up only the master secret is sufficient and minimal.

## Procedure

1. **Generate** the master keypair in an offline, air-gapped environment
   (`validator-keys create_keys`). Never generate it on the validator host.
2. **Split** the 32-byte master secret into 5 shares, threshold 3, with
   `scripts/shamir.py`. Record each share's SHA-256 commitment in a
   separate, public-able inventory (commitments reveal nothing).
3. **Distribute** the 5 shares to 5 independent stores (see below).
   No single store holds 3 shares. No store holds the secret.
4. **Verify** the backup immediately: rebuild the secret from a different
   3-share subset in the lab and compare fingerprints. Log the
   verification (date, subset used, fingerprint match).
5. **Store the pre-generated revocation manifest** (sequence 0xFFFFFFFF,
   signed by the master key at creation time) with the shares. It is
   useless without the master signature, which it already carries, so it
   is safe to escrow — and it is the only way to revoke if the master key
   is later lost (finding F-08).
6. **Re-verify on a schedule**: rebuild from a rotating 3-share subset
   every 6 months (aligned with the rotation cadence). Replace any share
   whose store is degraded.

## Offline storage model

| Store | Medium | Access |
| --- | --- | --- |
| 1 | Encrypted USB, bank safe-deposit box | Operator A |
| 2 | Encrypted USB, second physical site | Operator B |
| 3 | Paper (share bytes as hex, sealed envelope), off-site | Operator C |
| 4 | Hardware security module / vault service | On-call lead |
| 5 | Encrypted USB, legal counsel / escrow | Counsel |

Rules: shares are never stored on the validator host; never stored in the
same place as another share; never transmitted over the same channel as
another share; never photographed or pasted into chat. A share is
transmitted only once, at creation, over an encrypted channel, and the
transmission is logged.

## Access-control model

- **Creation.** Requires 2 operators present (one generates, one
  witnesses and logs). The master secret exists in cleartext only in the
  air-gapped environment, only during creation, and is wiped afterwards.
- **Rotation.** Requires 1 operator (the master secret is not needed —
  rotation needs only the token path) — but the rotation itself is logged
  with the new sequence number.
- **Recovery.** Requires 3 of 5 custodians. No single custodian can
  recover the secret; any 3 can. Custodians are named individuals, not
  roles, and the roster is reviewed annually.
- **Revocation.** Requires either the master secret (to sign a fresh
  revocation) or the pre-generated revocation manifest (escrowed at
  creation). Publishing the revocation is a separate, logged step.
- **Audit.** Every access (creation, split, distribution, verification,
  recovery, revocation) is logged with date, operator, and purpose. The
  log contains no secret material — only fingerprints and commitments.

## Failure modes (verified in drill D)

| Case | Result |
| --- | --- |
| Any 3 of 5 shares | Secret rebuilt exactly, fingerprint verified |
| Only 2 shares | Rebuild produces a wrong value; the fingerprint check fails |
| One corrupted share | Rebuild produces a wrong value; the commitment check detects it before use |
| One store destroyed | 4 shares remain; any 3 rebuild — no loss |
| Two stores destroyed | 3 shares remain; rebuild still possible |
| Three stores destroyed | Unrecoverable — this is the residual risk (mitigated by store diversity) |

## Why 3-of-5 (not 2-of-3 or 4-of-7) [ANALYSIS]

2-of-3 is simpler but any 2 custodians can collude to steal the secret,
and losing 2 shares ends recovery. 4-of-7 tolerates more loss but needs 4
people to act in an emergency, which is slower. 3-of-5 is the standard
compromise: it tolerates 2 destroyed shares and requires 3 colluding
custodians to steal, while a recovery needs only 3 people. For a
single-operator validator, the 5 "custodians" can be 5 stores controlled
by 2-3 people under the same rule (no store holds 3 shares).
