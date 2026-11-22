# Decision memo — validator key recovery readiness

## Question

Can PFTL validator keys be backed up, rotated, and recovered — including
against a quantum adversary — on the evidence in this pack?

## Answer

**Not ready.** Three of the five recovery scenarios work (ephemeral loss,
ephemeral compromise, Shamir restore), one is unrecoverable by design
(master-key loss), and one is a controlled demolition (master-key
compromise ends the identity). The quantum story is worse: the whitepaper
promises ML-DSA-65 validator signatures from genesis, and the shipped
code has none.

## Evidence chain

1. **Ephemeral recovery works.** The manifest design is the recovery
   mechanism: a master key signs a new manifest (sequence + 1) binding a
   new ephemeral key, and peers adopt it within minutes. Drills A and B
   prove it with real cryptography in ~0.1 s of lab time.
2. **Master recovery does not exist.** Drill C proves the negative: without
   the master secret, no manifest can be signed. The code has no recovery
   path, and the docs state the consequence plainly (new identity). The
   only mitigation is a backup that exists before the loss — and no
   threshold backup exists today (F-07).
3. **The documented backup is fragile.** A single file, deleted on
   container restart, copied by hand. Every operator who has ever typed
   `docker compose restart` without the `docker cp` first has rolled the
   dice on their validator identity (F-03).
4. **The quantum claim is unimplemented.** Zero PQ references in the pinned
   code; 25/25 live master keys Ed25519; 25/25 live signing keys
   secp256k1. The whitepaper's ML-DSA-65 promise names a scheme whose
   signatures (3,309 bytes) cannot fit the 512-byte manifest cap (F-02,
   F-04). A migration is a format change, not a key swap.
5. **The network tolerates recovery operations.** Quorum 17/25 survives 8
   simultaneous outages; one-at-a-time rotation never threatens finality
   (F-12).

## What must change before a mainnet readiness claim

1. Adopt the Shamir 3-of-5 backup (`docs/backup-spec.md`) for every
   validator master secret, and verify it by lab restore every 6 months.
2. Pre-generate a revocation manifest at key-creation time and escrow it
   with the shares (F-08).
3. Automate the pre-restart `validator-keys.json` backup so a container
   restart cannot silently destroy an identity (F-03).
4. Enforce signing-key rotation on a calendar (quarterly) and monitor VL
   manifest sequences; 10 of 25 testnet validators have never rotated
   (F-11).
5. Land the ML-DSA-65 validator layer in a pinned commit and demonstrate
   it on a devnet, including the manifest-format change the 512-byte cap
   forces (F-02, F-04). Until then, do not claim post-quantum validator
   authorization.

## What is already good

- The manifest design itself is sound: two-tier keys, sequence-ordered
  rotation, gossip propagation, revocation by maximum sequence. The
  recovery that exists is well designed.
- The live UNL is healthy on the measured dimensions: 25 distinct
  validators, all with manifests and domains, sequences sane (1–13),
  quorum 17/25, VL fresh (effective 2026-11-17, sequence 30).
- The drill evidence is strong: real keys, real signatures, timed
  measurements, verified failure modes.
