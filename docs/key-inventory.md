# Validator key inventory and classification

All live numbers in this document are from the probe run of 2026-11-22
20:14 UTC (validated ledger seq 8,279,102) unless stated otherwise. The
full machine-readable inventory is `outputs/derived/key-inventory.json`;
the decoded live validator set is
`outputs/derived/live-validator-set.json`.

## The six key classes

| # | Class | Algorithm (live) | Size | What it does |
| --- | --- | --- | --- | --- |
| 1 | Validator master key | Ed25519 (25/25) | 33 bytes | Permanent validator identity; signs manifests and revocations; node ID is derived from it |
| 2 | Validator ephemeral signing key | secp256k1 (25/25) | 33 bytes | Signs validations; bound to the master key by the current manifest |
| 3 | Validation seed (seed mode) | secp256k1 (code) | 16 bytes | Alternative to a token: a seed in `[validation_seed]` generates the validator key |
| 4 | Validator-list publisher key | Ed25519 (1 publisher) | 33 bytes | Signs the validator list itself |
| 5 | Node key (peer identity) | — (no separate key) | 20 bytes (node ID) | There is no separate node key: nodeID is the hash of the master public key |
| 6 | Account keys (for contrast) | Ed25519 or secp256k1 (code) | 33 bytes | Transaction signing; not validator keys |

## Class 1 — Validator master key [FACT]

- **Role.** The permanent validator identity. It signs manifests
  (binding an ephemeral signing key to the identity, with a sequence
  number) and revocations. The node's peer identity (nodeID) is the hash
  of this key (`calcNodeID`, `PublicKey.cpp:320-328`).
- **Algorithm.** Live: Ed25519 for all 25 validators (0xED prefix).
  Code: either type is accepted (`publicKeyType` accepts Ed25519 and
  secp256k1; `Manifest.cpp:95-100`).
- **Storage.** `validator-keys.json` at `/root/.ripple/validator-keys.json`
  (per `ValidatorKeyUpdate.md` / `NodeSetup.md`). [SPECIFIED] That file is
  deleted when the Docker container is restarted or recreated.
- **Rotation.** Never rotated without losing the identity. A new master key
  is a new validator (new VL entry, new trust).
- **Loss.** UNRECOVERABLE (drill C). **Compromise.** Revocation manifest,
  sequence 0xFFFFFFFF (drill E), then new identity.

## Class 2 — Validator ephemeral signing key [FACT]

- **Role.** Signs validations. It is the key peers actually verify
  validation signatures against; the manifest tells them which ephemeral
  key belongs to which master key.
- **Algorithm.** Live: secp256k1 compressed for all 25 validators (0x02/0x03
  prefix). Code: in `[validator_token]` mode the signing key is derived
  as secp256k1 from the token's validation secret
  (`ValidatorKeys.cpp:47`); there is no code path that derives an Ed25519
  ephemeral key from a token.
- **Storage.** Inside the `[validator_token]` (base64) in `postfiatd.cfg`,
  plus the key file.
- **Rotation.** New manifest with sequence + 1, signed by the master key;
  propagates "within minutes" (docs). Old manifests are rejected by the
  sequence rule (`Manifest.cpp:411`: sequence <= stored is ignored).
- **Loss / compromise.** RECOVERABLE by rotation (drills A, B).

## Class 3 — Validation seed (seed mode) [FACT]

- **Role.** Alternative configuration: `[validation_seed]` holds a 16-byte
  seed; the validator key is generated from it
  (`ValidatorKeys.cpp:74-89`).
- **Algorithm.** secp256k1 only. Master = signing = the derived key;
  sequence 0. No manifest exists in this mode.
- **Storage.** `postfiatd.cfg` `[validation_seed]`.
- **Rotation.** None: a new seed is a new identity.
- **Loss / compromise.** UNRECOVERABLE / no revocation path without a
  manifest; the key must be removed from trust by the VL publisher.
- **Live status.** Not in use on the UNL: all 25 validators publish
  manifests with distinct master and signing keys, i.e. token mode.

## Class 4 — Validator-list publisher key [FACT]

- **Role.** Signs the validator list. Nodes verify the VL signature
  against `[validator_list_keys]` before accepting the list
  (`scripts/generate_vl.py` docstring).
- **Algorithm.** Live: Ed25519 (`ED3F1E0D...`). The publisher's own
  manifest binds an Ed25519 master key to a secp256k1 ephemeral signing
  key, and the VL blob is signed SHA-512-Half + secp256k1 ECDSA.
- **Storage.** Publisher-held; a single publisher for the testnet.
- **Rotation.** The VL sequence must increase; nodes reject sequence <=
  current. Live blob sequence is 30.
- **Loss / compromise.** Loss is unrecoverable for the publisher identity
  (operators would need a new publisher key in config). Compromise lets an
  attacker publish a VL the nodes accept until operators change the key.

## Class 5 — Node key [FACT]

There is no separate node key in the pinned code. The node's peer identity
is its validation key: `nodeID = calcNodeID(masterKey)` in token mode,
`calcNodeID(pk)` in seed mode (`ValidatorKeys.cpp:60,87`). The node ID is
a 20-byte hash of the public key (`PublicKey.cpp:320-328`). Losing or
compromising the master key therefore also loses or compromises the peer
identity; there is nothing separate to rotate or back up.

## Class 6 — Account keys (for contrast) [FACT]

Account keys are not validator keys and are not measured in this pack. The
`KeyType` enum has exactly two values, secp256k1 and ed25519
(`KeyType.h`), and the signing dispatch in `SecretKey.cpp:258-290`
handles both. They are listed here only to bound the inventory: nothing
else in the pinned code creates keys.

## Live inventory summary [FACT]

| Quantity | Value |
| --- | --- |
| Validators in the live list | 25 |
| Master keys Ed25519 / secp256k1 / unknown | 25 / 0 / 0 |
| Signing keys Ed25519 / secp256k1 / unknown | 0 / 25 / 0 |
| VL key equals master key | 25 / 25 |
| VL key equals signing key | 0 / 25 |
| Distinct master keys | 25 |
| Distinct signing keys | 25 |
| Manifest sequences | 1 (x10), 2 (x3), 3 (x1), 4 (x2), 5 (x3), 6 (x2), 7 (x3), 13 (x1) |
| Manifests carrying a domain | 25 / 25 |
| Manifest sizes | 225–246 bytes |
| VL blob sequence / effective / expiration | 30 / 2026-11-17T20:10:08Z / 2028-03-31T16:14:53Z |
| Publisher master key | Ed25519, manifest sequence 1 |
| Validation quorum (live) | 17 of 25 |

## What the key split means [ANALYSIS]

The live network inverts the classic rippled arrangement. In classic
rippled deployments the master key is usually secp256k1 and the ephemeral
signing key Ed25519; here the master keys are Ed25519 and the ephemeral
keys secp256k1. The inversion is not a bug — the code accepts both types
for the master key, and the token path always derives a secp256k1 signing
key — but it matters for the quantum story: the long-lived identity keys
(the ones whose compromise is unrecoverable) are Ed25519, and the
short-lived keys are secp256k1. Both are classical; a quantum break takes
both. The rotation machinery only ever protects the short-lived half.
