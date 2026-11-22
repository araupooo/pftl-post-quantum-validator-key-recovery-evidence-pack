# Evidence index

Every file in this pack and what it supports.

## Live probe outputs (unedited)

| File | Supports |
| --- | --- |
| outputs/probe-run.log | Probe log with SHA-256 of every fetched file |
| outputs/server_info.json | Live build 1.0.9, network 2025, 21 peers, validation_quorum 17, validated seq |
| outputs/ledger_current.json | Validated ledger header at probe time |
| outputs/ledger_closed.json | Closed ledger header |
| outputs/fee.json | Live fee levels (context) |
| outputs/feature_list.json | Amendment/feature list (context) |
| outputs/server_state.json | Server state (context) |
| outputs/validators.json | Admin-gated refusal (HTTP 403 'Forbidden') |
| outputs/peers.json | Admin-gated refusal (HTTP 403 'Forbidden') |
| outputs/invalid_method.json | Unknown-method response (control) |
| outputs/testnet_vl.json | Live validator list (25 validators, manifests) |
| outputs/explorer_health.json | Explorer health HTTP 500 'rippled unreachable' |
| outputs/explorer_metrics.json | Explorer load metrics |
| outputs/postfiat_org.html | Project site (context) |
| outputs/postfiat_whitepaper.html | Whitepaper, section 1.11 ML-DSA claim |

## Derived outputs

| File | Supports |
| --- | --- |
| outputs/derived/live-validator-set.json | Decoded VL: 25 validators, key types, sequences, chain state |
| outputs/derived/key-inventory.json | Six key classes with role, algorithm, storage, rotation, loss/compromise outcome |
| outputs/derived/drill-results.json | Five drill scenarios with timings and outcomes |
| outputs/derived/quorum-model.json | Quorum math (17/25), rotation windows, RTO/RPO targets |
| outputs/derived/pq-size-model.json | Algorithm sizes, manifest fit, sequence budget, whitepaper quorum bytes |
| outputs/drill-run.log | Unedited drill run log |

## Pinned-source fixtures

| File | Supports |
| --- | --- |
| fixtures/source-excerpts/*.txt (22 files) | Verbatim pinned-code excerpts with file:line |
| fixtures/source-hashes.json | Git blob SHA-1 of every cited source file |
| fixtures/pq-sizes.csv | FIPS 204 Table 2 + FIPS 205 Table 2 sizes, verified against the NIST PDFs |
| fixtures/whitepaper-ml-dsa-section.txt | Whitepaper section 1.11 verbatim, from the fresh fetch |

## Code

| File | Supports |
| --- | --- |
| scripts/probe_all.sh | Live re-probe (read-only) |
| scripts/manifest_parse.py | STObject manifest parser (field codes from sfields.macro) |
| scripts/key_inventory.py | Live VL decode + chain state + key inventory |
| scripts/shamir.py | GF(256) Shamir (k, n) reference implementation + self-test |
| scripts/drill.py | Five recovery drills (lab keys, OpenSSL) |
| scripts/quorum_model.py | Quorum + RTO/RPO model |
| scripts/analyze.py | This generator (findings, claims, risks, manifest) |
| scripts/extract_excerpts.py | Pinned-source excerpt extraction |
| scripts/clean_reproduce.sh | Fresh-environment reproduction, exit 0 |
| scripts/compare_reproduce.py | Fresh-vs-shipped comparison |
| src/key_model.py | Algorithm sizes, manifest fit, quorum, sequence budget |
