# Claim index

Every claim in this pack, its status, and its evidence. Statuses: VERIFIED = measured live or in the lab drill; SPECIFIED = stated in pinned code, pinned docs, or a cited standard; UNVERIFIED = could not be checked; UNTESTABLE = would need an action the safety boundary forbids.

Counts (recomputed from this table): **37 total — 17 SPECIFIED, 2 UNTESTABLE, 2 UNVERIFIED, 16 VERIFIED**

| ID | Status | Claim | Evidence |
| --- | --- | --- | --- |
| C-01 | VERIFIED | The live UNL has 25 validators. | Live VL blob (testnet_vl.json, sha256 in probe-run.log); manifest_parse.py count. |
| C-02 | VERIFIED | All 25 live validator master keys are Ed25519 (0xED prefix, 33 bytes). | manifest_parse.py on the live VL; STObject field sfPublicKey. |
| C-03 | VERIFIED | All 25 live ephemeral signing keys are secp256k1 compressed (0x02/0x03 prefix, 33 bytes). | manifest_parse.py on the live VL; STObject field sfSigningPubKey. |
| C-04 | VERIFIED | The VL validation_public_key is the master key for 25 of 25 validators. | manifest_parse.py: vl_key_is_master = 25, vl_key_is_signing = 0. |
| C-05 | VERIFIED | Live manifest sequences are 1-13; 10 of 25 validators are at sequence 1 (never rotated). | manifest_parse.py sequence_counts. |
| C-06 | VERIFIED | Live manifest sizes are 225-246 bytes, under the 512-byte cap. | manifest_parse.py manifest_bytes_min/max; cap from MANIFEST_FLOOD_HOTFIX.md. |
| C-07 | VERIFIED | Live validation quorum is 17 of 25 (67%). | server_info.json validation_quorum = 17; quorum model in src/key_model.py. |
| C-08 | VERIFIED | The live VL blob is sequence 30, effective 2026-11-17, expiring 2028-03-31. | testnet_vl.json decoded blob; Ripple-epoch conversion in key_inventory.py. |
| C-09 | VERIFIED | The VL publisher key is Ed25519; the publisher manifest is at sequence 1. | testnet_vl.json public_key + manifest decode. |
| C-10 | VERIFIED | The explorer health endpoint returns HTTP 500 {'message': 'rippled unreachable'} at probe time. | outputs/explorer_health.json, probe-run.log (2026-11-22T20:14Z). |
| C-11 | VERIFIED | The validators and peers RPC methods are admin-gated (HTTP 403 'Forbidden') via the public proxy. | outputs/validators.json, outputs/peers.json, probe-run.log. |
| C-12 | VERIFIED | Drill A: ephemeral-key loss is recovered by rotation to manifest sequence 2 in 0.102 s of lab crypto time. | outputs/derived/drill-results.json scenario A; outputs/drill-run.log. |
| C-13 | VERIFIED | Drill B: a stale sequence-1 manifest is rejected after rotation to sequence 2. | drill-results.json scenario B (sequence rule, Manifest.cpp:411). |
| C-14 | VERIFIED | Drill C: master-key loss is not recoverable; only a new identity is possible. | drill-results.json scenario C. |
| C-15 | VERIFIED | Drill D: a 3-of-5 Shamir restore rebuilds the master secret exactly (fingerprint verified); 2 shares fail; a corrupted share is detected. | drill-results.json scenario D; shamir.py self-test 11/11. |
| C-16 | VERIFIED | Drill E: a revocation manifest (sequence 0xFFFFFFFF) is authenticated by the master key, after which no further manifest for that key is possible. | drill-results.json scenario E; Manifest.cpp revoked(). |
| C-17 | SPECIFIED | KeyType has exactly two values: secp256k1 and ed25519. | include/xrpl/protocol/KeyType.h (excerpt KeyType-enum.txt). |
| C-18 | SPECIFIED | In [validator_token] mode the signing key is derived as secp256k1 from the token's validation secret. | ValidatorKeys.cpp:47 (excerpt ValidatorKeys-load.txt). |
| C-19 | SPECIFIED | In [validation_seed] mode the key is secp256k1 from the 16-byte seed, master = signing, sequence 0. | ValidatorKeys.cpp:74-89 (excerpt ValidatorKeys-load.txt). |
| C-20 | SPECIFIED | A manifest carries master key, master signature, sequence, optional domain, optional ephemeral signing key and signature; sequence 0xFFFFFFFF revokes. | Manifest.cpp deserializeManifest + revoked() (excerpts). |
| C-21 | SPECIFIED | A seed is 16 bytes; randomSeed() uses the CSPRNG; generateSeed() is SHA-512/2 of a passphrase with no salt or stretching. | Seed.cpp:65-82 (excerpt Seed-random-generate.txt). |
| C-22 | SPECIFIED | There is no separate node key: nodeID is the hash of the master public key. | PublicKey.cpp calcNodeID; ValidatorKeys.cpp:60,87 (excerpts). |
| C-23 | SPECIFIED | The fork uses a 67% validation quorum; the code comment says the original XRPL uses 80% and mainnet should revert to 80%. | ValidatorList.cpp:1898-1900 (excerpt ValidatorList-quorum-67.txt). |
| C-24 | SPECIFIED | Manifests are capped at 512 bytes. | docs/MANIFEST_FLOOD_HOTFIX.md:35 (excerpt). |
| C-25 | SPECIFIED | The token sequence limit is 4,294,967,293 per validator key pair. | docs/ValidatorKeyUpdate.md:242 (excerpt). |
| C-26 | SPECIFIED | Signing-key rotation is recommended every 6-12 months; a new manifest propagates 'within minutes'. | docs/ValidatorKeyUpdate.md:81,247 (excerpts). |
| C-27 | SPECIFIED | validator-keys.json is deleted when the Docker container is restarted or recreated. | docs/ValidatorKeyUpdate.md:205-222; docs/NodeSetup.md:363-378 (excerpts). |
| C-28 | SPECIFIED | ML-DSA-44/65/87: public keys 1312/1952/2592 bytes, signatures 2420/3309/4627 bytes. | NIST FIPS 204 Table 2 (verified against the NIST PDF; fixtures/pq-sizes.csv). |
| C-29 | SPECIFIED | SLH-DSA: public keys 32/48/64 bytes, signatures 7,856-49,856 bytes across 12 parameter sets. | NIST FIPS 205 Table 2 (verified against the NIST PDF; fixtures/pq-sizes.csv). |
| C-30 | SPECIFIED | Ed25519 public keys are 32 octets and signatures 64 octets, at about the 128-bit security level. | RFC 8032 sections 2, 5.1.5-5.1.6. |
| C-31 | SPECIFIED | The whitepaper section 1.11 states accounts and validators sign with ML-DSA-65 from genesis (1,952-byte public keys, 3,309-byte signatures). | outputs/postfiat_whitepaper.html, section 1.11 body (verbatim in fixtures/whitepaper-ml-dsa-section.txt). |
| C-32 | SPECIFIED | An ML-DSA-65 signature (3,309 bytes) is 6.5x the 512-byte manifest cap; the smallest SLH-DSA signature (7,856 bytes) is 15.3x the cap. | src/key_model.py manifest_fit (FIPS sizes / 512). |
| C-33 | SPECIFIED | Shamir (k, n): any k shares rebuild the secret; any k-1 shares reveal no information; n = 2k-1 tolerates k-1 destroyed and k-1 exposed shares. | Shamir 1979, CACM 22(11):612-613; scripts/shamir.py self-test 11/11. |
| C-34 | UNVERIFIED | Whether the 25 live validator operators back up validator-keys.json, and how (single copy vs threshold vs HSM). | Not observable from any public source; operator practice is private. |
| C-35 | UNVERIFIED | Whether the single VL publisher key is itself backed up with a threshold scheme. | Not observable from any public source. |
| C-36 | UNTESTABLE | End-to-end fleet rotation timing (real validator + real VL republication). | Would require operating a real validator and publishing a real VL; outside this pack's lab-only boundary. |
| C-37 | UNTESTABLE | Byte-exact postfiatd manifest creation/verification round-trip. | Would require running postfiatd with a real token; the drill's manifest is a labelled lab model, not an STObject. |
