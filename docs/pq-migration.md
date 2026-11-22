# Post-quantum migration assessment

## The gap [FACT]

The whitepaper (September 2026, section 1.11) states, verbatim:

> "Accounts and validators sign with ML-DSA-65 from genesis: 1,952-byte
> public keys, 3,309-byte signatures, deterministic verification, and
> domain-separated contexts for transactions, block certificates, bridge
> witnesses, and admission receipts."

The pinned testnet code (postfiatd 0085a1ff, v1.0.9) contains zero
references to ML-DSA, SLH-DSA, Dilithium, SPHINCS+, or post-quantum
cryptography anywhere in `src/`, `include/`, or `docs/`. Its `KeyType`
enum has exactly two values (secp256k1, ed25519). The live testnet
confirms it: 25/25 validator master keys are Ed25519 and 25/25 ephemeral
signing keys are secp256k1.

Two honest readings are possible, and the pack does not choose between
them: either the whitepaper describes a target chain (postfiatl1v2, which
the whitepaper's own references pin as its source) that the current
testnet code does not implement, or the testnet is a classical-key staging
network on the way to that target. What is [FACT] is the gap itself: the
ML-DSA-65 validator layer is a stated design requirement, not a shipped
property of the code running the testnet.

## Candidate assessment

### ML-DSA-65 (FIPS 204, category 3) — recommended candidate

- **Sizes.** Public key 1,952 bytes, secret key 4,032 bytes (storable as
  a 32-byte seed per FIPS 204 §3.1), signature 3,309 bytes.
- **Fit.** The signature is 6.5x the 512-byte manifest cap and 51.7x an
  Ed25519 signature. The manifest format must change.
- **Advantages.** Stateless, fast verification, the NIST primary
  recommendation for general-purpose signatures, and the scheme the
  whitepaper already names. A 32-byte seed keeps the Shamir backup design
  in `docs/backup-spec.md` unchanged (split the seed, not the expanded
  key).
- **Costs.** Whitepaper's own arithmetic: a quorum of 24 from 35
  validators carries 24 x 3,309 = 79,416 signature bytes per quorum set
  before identifiers and framing; prepare/precommit sets double that.
  Validation traffic grows ~50x in signature bytes versus Ed25519.

### ML-DSA-44 / ML-DSA-87

- ML-DSA-44 (category 2): 1,312-byte keys, 2,420-byte signatures — the
  smallest ML-DSA option, but category 2 is the weakest margin and the
  signature still exceeds the manifest cap 4.7x.
- ML-DSA-87 (category 5): 2,592-byte keys, 4,627-byte signatures — the
  strongest margin, 9.0x the cap. Preferable only if the threat model
  demands category 5; the whitepaper names ML-DSA-65.

### SLH-DSA (FIPS 205) — hedge, not default

- **Sizes.** Public keys tiny (32/48/64 bytes — the same size class as
  Ed25519); signatures huge (7,856–49,856 bytes; the smallest is 15.3x
  the manifest cap, the largest 97.4x).
- **Advantages.** Security rests only on hash functions — the conservative
  hedge if lattice schemes ever weaken. Tiny public keys fit the existing
  key fields.
- **Costs.** Signatures are far too large for validations at ledger
  cadence, and signing is slow. Suitable as a backup signature for rare
  operations (e.g. manifest signing, which happens on rotation, not per
  ledger), not for per-ledger validation signatures.

## What a migration must change [ANALYSIS]

1. **Manifest format.** The 512-byte cap must go (or signatures must move
   out of the manifest). ML-DSA-65 needs ~3.3 KB per signature; a manifest
   carries two signatures plus two public keys (~5.3 KB total).
2. **KeyType.** A third (and fourth) enum value, plus key parsing,
   derivation, and signing dispatch for the new types
   (`SecretKey.cpp`, `PublicKey.cpp`).
3. **Validator-list pipeline.** The VL carries manifests and validation
   public keys; larger keys bloat the VL blob (25 validators x ~2 KB keys
   = ~50 KB before manifests, vs ~2 KB today).
4. **Peer/validation traffic.** Validation messages grow from ~100 bytes
   of signature to ~3.3 KB; gossip and ledger-close bandwidth budgets
   must be re-derived.
5. **Backup design.** Unchanged in structure (32-byte seeds), but the
   Shamir shares now protect a PQ seed — the backup spec survives the
   migration intact, which is a reason to adopt it now.
6. **Dual-signature transition.** Validators will need a period where
   both a classical and a PQ signature are accepted (or a flag day).
   The manifest's single-signing-key field cannot express two keys; the
   format change in (1) must cover this.

## Recommendation [ANALYSIS]

Adopt ML-DSA-65 as the validator signature scheme, as the whitepaper
already states — but treat the current testnet as classical until the six
changes above land in a pinned commit and are demonstrated on a devnet.
Do not claim ML-DSA coverage in any readiness statement about the code
running today. In parallel, adopt the Shamir backup now: it protects the
classical keys today and the PQ seeds tomorrow, and it is the only
mitigation for the unrecoverable master-key loss (finding F-01).
