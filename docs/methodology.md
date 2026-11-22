# Methodology

## Safety boundary (non-negotiable)

**Lab drills + bounded observation only.**

- No live key material was used, touched, or requested. Every drill key is
  freshly generated inside the drill process (OpenSSL) and wiped afterwards
  (overwritten and deleted); only public keys, SHA-256 fingerprints, and
  timings are recorded in the outputs.
- No transactions were submitted to the testnet. No flood traffic was sent.
- All probes are read-only queries against public endpoints: 11 RPC calls
  in `scripts/probe_all.sh` (9 postfiatd methods + 2 explorer endpoints +
  the validator list, the site, and the whitepaper).
- The `validators` and `peers` RPC methods are admin-gated; the public
  proxy refuses them with HTTP 403 `Forbidden`. The refusal bodies are kept
  unedited as evidence of the gating.
- Nothing was signed on the live network. The only signatures in this pack
  are lab signatures over lab manifests, made by lab keys.

## Methods

1. **Pinned-source analysis.** postfiatd was cloned at commit
   `0085a1ff885d6a446369cf73a4430f75af22be55` (2026-10-10, PR #50 merge,
   v1.0.9). Every cited line number was verified with `grep -n` against
   that clone. 22 verbatim excerpts are kept in
   `fixtures/source-excerpts/`; `fixtures/source-hashes.json` records the
   git blob SHA-1 of every cited file.
2. **Live validator-list decode.** The published validator list
   (`https://postfiat.org/testnet_vl.json`) was fetched twice (identical
   SHA-256 both times) and decoded with `scripts/manifest_parse.py`, an
   STObject parser whose field codes come from the pinned
   `sfields.macro`. All 25 manifests were parsed: master key, ephemeral
   signing key, sequence, domain, length. The parser was cross-checked by
   an independent re-implementation during research (an early version
   mis-parsed one sequence number because of the two-byte extended field
   header for `sfMasterSignature`; the shipped parser handles extended
   field codes and the distribution was recomputed from its output).
3. **Live chain probe.** `scripts/probe_all.sh` fetched `server_info`
   (build 1.0.9, network 2025, 21 peers, validation_quorum 17, validated
   seq 8,279,102), the validated ledger, the closed ledger, `fee`,
   `feature`, `server_state`, and the admin-gated methods, plus the
   explorer health/metrics endpoints and the site/whitepaper.
4. **Recovery drills.** `scripts/drill.py` runs five scenarios with real
   OpenSSL key operations (Ed25519 master keys, secp256k1 ephemeral keys,
   mirroring the live UNL key split) and the GF(256) Shamir implementation
   in `scripts/shamir.py` (11/11 self-test checks). Timings are measured
   wall-clock times of the lab operations.
5. **Models.** `src/key_model.py` (algorithm sizes, manifest fit, quorum,
   sequence budget) and `scripts/quorum_model.py` (rotation windows,
   RTO/RPO). RTO values are SPECIFIED design targets (30 min operator
   steps + 5 min documented propagation), not measured end-to-end,
   because a full fleet rotation cannot be executed from this lab.
6. **Standards verification.** FIPS 204 Table 2 and FIPS 205 Table 2 were
   verified against the actual NIST PDFs (downloaded from nvlpubs.nist.gov
   and read with pdftotext), not only against secondary summaries. RFC 8032
   was verified against the RFC Editor text. Shamir 1979 was verified
   against the ACM paper text (Communications of the ACM 22(11):612-613).

## Claim labels

Every substantive claim carries one label: [FACT] for a verified fact with
source and date, [ESTIMATE] for a modelled or reported number, [ANALYSIS]
for interpretation. In the claim index the equivalent statuses are
VERIFIED / SPECIFIED / UNVERIFIED / UNTESTABLE (see `docs/claim-index.md`).

## Limitations

- **Lab model, not live execution.** The drill's "manifest" is a JSON lab
  model with the same fields as a real manifest (master key, signing key,
  sequence, domain, two signatures), not a byte-exact postfiatd STObject
  manifest, and its ephemeral signatures use ECDSA/SHA-256 while the
  pinned VL uses SHA-512-Half + secp256k1 ECDSA. Real-manifest parsing is
  verified separately against all 25 live VL manifests. The gap is
  labelled in the drill output and in risk R-14.
- **Operator practice is unobservable.** Whether the 25 live operators back
  up `validator-keys.json`, how often they rotate, and whether the VL
  publisher key is threshold-backed cannot be seen from any public source
  (claims C-34, C-35 UNVERIFIED).
- **Explorer degraded.** The explorer health endpoint returned HTTP 500
  `{"message":"rippled unreachable"}` at probe time, so no live validator
  liveness data (e.g. a stale-UNL-member check) could be taken from the
  explorer. The VL file is the authoritative live validator-set source
  used here.
- **RTO/RPO are targets, not measurements.** No fleet rotation was
  performed; the 35-minute RTO is 30 minutes of specified operator steps
  plus 5 minutes of documented propagation, with lab crypto time measured
  at ~0.1 s.
- **Whitepaper scope.** The whitepaper's claims are pinned to
  postfiatl1v2, not to postfiatd v1.0.9. The ML-DSA gap in this pack is a
  design-vs-implementation gap between the whitepaper's target chain and
  the shipped testnet code, not a claim that the whitepaper is wrong about
  its own chain.
- **Absence claims are grep-bounded.** "No post-quantum support" and "no
  Shamir backup" mean: no matches for the searched terms in the pinned
  repo at the pinned commit (source, headers, docs, scripts). A differently
  named implementation would not match; the search terms are listed in
  finding F-02/F-07.
