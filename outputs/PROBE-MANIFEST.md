# Probe manifest

Probes run by `scripts/probe_all.sh` on 2026-11-22 20:14:13–20:14:26 UTC
(see `outputs/probe-run.log` for per-file SHA-256 values). All probes are
read-only queries against public endpoints. No transactions were submitted,
no flood traffic was sent, no live key material was used.

| # | Endpoint / method | Output file | HTTP | Notes |
| --- | --- | --- | --- | --- |
| 1 | POST rpc.testnet.postfiat.org/ `server_info` | outputs/server_info.json | 200 | build 1.0.9, network 2025, 21 peers, quorum 17, validated seq 8,279,102 |
| 2 | POST `ledger` (validated seq, transactions) | outputs/ledger_current.json | 200 | Validated ledger header |
| 3 | POST `ledger_closed` | outputs/ledger_closed.json | 200 | Closed ledger header |
| 4 | POST `fee` | outputs/fee.json | 200 | Fee levels (context) |
| 5 | POST `feature` | outputs/feature_list.json | 200 | Amendment/feature list (context) |
| 6 | POST `server_state` | outputs/server_state.json | 200 | Server state (context) |
| 7 | POST `validators` | outputs/validators.json | 403 | Admin-gated refusal, body `Forbidden` |
| 8 | POST `peers` | outputs/peers.json | 403 | Admin-gated refusal, body `Forbidden` |
| 9 | POST `no_such_method` | outputs/invalid_method.json | 200 | Unknown-method control response |
| 10 | GET postfiat.org/testnet_vl.json | outputs/testnet_vl.json | 200 | Live validator list, 25 validators; SHA-256 identical across two independent fetches |
| 11 | GET explorer.testnet.postfiat.org/api/v1/health | outputs/explorer_health.json | 500 | `{"message":"rippled unreachable"}` |
| 12 | GET explorer.testnet.postfiat.org/api/v1/metrics | outputs/explorer_metrics.json | 200 | Load metrics (context) |
| 13 | GET postfiat.org/ | outputs/postfiat_org.html | 200 | Project site (context) |
| 14 | GET postfiat.org/whitepaper/ | outputs/postfiat_whitepaper.html | 200 | Whitepaper, section 1.11 ML-DSA claim |

Total RPC calls in `probe_all.sh`: 9 postfiatd method calls (plus 5 HTTP
GETs). The drill (`scripts/drill.py`) makes no network calls at all.
