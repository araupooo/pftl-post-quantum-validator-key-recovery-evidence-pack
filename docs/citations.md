# Citations

Every source cited in this pack, with the exact location. Pinned-source
line numbers were verified with `grep -n` against a local clone of
postfiatd at commit `0085a1ff885d6a446369cf73a4430f75af22be55`
(2026-10-10, PR #50 merge, v1.0.9). Verbatim excerpts: `fixtures/source-excerpts/`.

## Pinned postfiatd source (commit 0085a1ff)

- `src/xrpld/app/misc/detail/ValidatorKeys.cpp:29-91` — token vs seed
  loading; signing key derived as secp256k1 in both modes.
- `src/xrpld/app/misc/ValidatorKeys.h:40-66` — `Keys` struct (master,
  public, secret), nodeID, manifest, sequence.
- `src/xrpld/app/misc/Manifest.h:36-78` — manifest design comment
  (master key, ephemeral key, sequence, revocation at 0xFFFFFFFF, gossip).
- `src/xrpld/app/misc/detail/Manifest.cpp:54-100` — `deserializeManifest`,
  manifest format (master key, master signature, sequence, version,
  domain, signing key, signature).
- `src/xrpld/app/misc/detail/Manifest.cpp:196-240` — `verify()` and
  `revoked()` (sequence == max uint32).
- `src/xrpld/app/misc/detail/Manifest.cpp:405-450` — `ManifestCache`
  sequence rule (sequence <= stored is ignored).
- `src/xrpld/rpc/handlers/ValidationCreate.cpp:29-67` — `validation_create`
  (admin-only; `randomSeed()` if no secret; secp256k1 key generation).
- `src/libxrpl/protocol/Seed.cpp:65-82` — `randomSeed()` (CSPRNG, 16
  bytes) and `generateSeed()` (SHA-512/2 of passphrase, first 16 bytes).
- `src/libxrpl/protocol/Seed.cpp:134-144` — `seedAs1751()` (RFC 1751
  English-word encoding).
- `include/xrpl/protocol/KeyType.h:28-45` — `KeyType` enum: exactly
  secp256k1 and ed25519.
- `src/libxrpl/protocol/PublicKey.cpp:223-232` — `publicKeyType` (0xED =
  Ed25519, 0x02/0x03 = secp256k1).
- `src/libxrpl/protocol/PublicKey.cpp:318-328` — `calcNodeID` (hash of
  the public key).
- `src/libxrpl/protocol/SecretKey.cpp:256-290` — signing dispatch by key
  type (Ed25519 vs secp256k1).
- `src/xrpld/app/misc/detail/ValidatorList.cpp:1895-1912` — 67% quorum
  comment ("Original XRPL uses 80%, but this fork uses 67% for
  devnet/testnet. For mainnet, this should be reverted to 80%.").
- `include/xrpl/protocol/detail/sfields.macro:289-307` — manifest field
  codes (sfPublicKey VL/1, sfSigningPubKey VL/3, sfSignature VL/6,
  sfDomain VL/7, sfMasterSignature VL/18, sfSequence UINT32/4).
- `src/xrpld/core/ConfigSections.h:89-96` — `[validation_seed]`,
  `[validator_key_revocation]`, `[validators]`, `[validator_token]`.
- `scripts/generate_vl.py:1-45` — VL architecture (publisher master
  Ed25519, ephemeral secp256k1, SHA-512-Half + secp256k1 ECDSA signing).
- `docs/ValidatorKeyUpdate.md:78-84` — rotation every 6-12 months.
- `docs/ValidatorKeyUpdate.md:205-224` — "CRITICAL: Backup Master Keys
  Before Docker Restart!" (file deleted on restart).
- `docs/ValidatorKeyUpdate.md:240-250` — token sequence limit
  4,294,967,293; propagation "within minutes".
- `docs/NodeSetup.md:282-292` — `validator-keys create_keys`, key file
  location.
- `docs/MANIFEST_FLOOD_HOTFIX.md:1-40` — manifest cap 512 bytes; bounded
  unlisted-manifest set (default 1000 keys, `[overlay]
  max_untrusted_count`).

## Live sources (probed 2026-11-22 20:14 UTC)

- `https://rpc.testnet.postfiat.org/` — postfiatd 1.0.9, network_id 2025,
  21 peers, validation_quorum 17, validated seq 8,279,102
  (`outputs/server_info.json`).
- `https://postfiat.org/testnet_vl.json` — live validator list, 25
  validators, blob sequence 30, effective 2026-11-17, expiration
  2028-03-31 (`outputs/testnet_vl.json`).
- `https://explorer.testnet.postfiat.org/api/v1/health` — HTTP 500
  `{"message":"rippled unreachable"}` at probe time.
- `https://postfiat.org/whitepaper/` — September 2026 whitepaper, section
  1.11 "What ML-DSA covers" (verbatim in
  `fixtures/whitepaper-ml-dsa-section.txt`).

## Standards and papers

- NIST FIPS 204, Module-Lattice-Based Digital Signature Standard, August
  2024 — Table 2 (ML-DSA-44/65/87 sizes). Verified against the NIST PDF
  (nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf).
- NIST FIPS 205, Stateless Hash-Based Digital Signature Standard, August
  2024 — Table 2 (12 SLH-DSA parameter sets). Verified against the NIST
  PDF (nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.205.pdf).
- RFC 8032, Edwards-Curve Digital Signature Algorithm (EdDSA), January
  2017 — Ed25519: 32-octet keys, 64-octet signatures, ~128-bit security
  (sections 2, 5.1.5-5.1.6). Verified against the RFC Editor text.
- Adi Shamir, "How to Share a Secret", Communications of the ACM 22(11),
  612-613, November 1979 — (k, n) threshold schemes, polynomial
  interpolation, n = 2k - 1 robustness. Verified against the ACM paper text.
