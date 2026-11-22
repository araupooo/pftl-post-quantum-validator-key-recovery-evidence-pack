# Risk register

Counts (recomputed from this table): **14 risks**

| ID | Risk | Likelihood | Impact | Mitigation |
| --- | --- | --- | --- | --- |
| R-01 | Master-key loss forces a new validator identity and VL republication | Medium | High | 3-of-5 Shamir backup (docs/backup-spec.md); pre-generated revocation manifest. |
| R-02 | Master-key compromise: attacker can rotate the ephemeral key and sign validations as the validator until revoked | Low | High | Revocation manifest (drill E); monitor VL manifest sequences for unexpected bumps. |
| R-03 | Ephemeral-key compromise during the rotation window | Medium | Medium | Rotate immediately on suspicion; rotation propagates in minutes (drill B). |
| R-04 | Passphrase-derived validator seed brute-forced | Low | High | Use randomSeed()/validation_create only; audit for passphrase seeds (F-05). |
| R-05 | Container restart deletes validator-keys.json with no backup taken | Medium | High | Automated pre-restart backup hook; restore test in the lab (docs/runbook.md). |
| R-06 | Single VL publisher key compromised: malicious validator list accepted network-wide | Low | High | Shamir-back the publisher key; move to multi-publisher lists with a threshold. |
| R-07 | Quantum break of the classical identity layer (harvest-now: keys already on the permanent ledger) | Low (time-dependent) | High | PQ migration per docs/pq-migration.md; do not claim ML-DSA coverage until shipped. |
| R-08 | PQ migration breaks the manifest format (512-byte cap) and the VL pipeline | High if migration is attempted without a format change | High | Design the PQ manifest format first; prototype against a devnet (docs/pq-migration.md). |
| R-09 | Operator error: wrong token pasted, duplicate [validator_token] section, sequence not incremented | Medium | Medium | Pre-flight config check in docs/runbook.md; validate the token before restart. |
| R-10 | Domain attestation hijack (attacker publishes a false .well-known/pft-ledger.toml) | Low | Medium | Domain ownership is verified out-of-band; monitor the attestation file. |
| R-11 | Backup media lost, stolen, or degraded (single-copy backup) | Medium | High | 3-of-5 Shamir shares across independent stores (F-07). |
| R-12 | Threshold collusion: k custodians combine shares to steal the master secret | Low | High | Separate custodians, sealed shares, share commitments; 3-of-5 means 3 must collude. |
| R-13 | Manifest flood / unlisted-manifest cache churn (bounded at 1000 keys) | Low | Low | Already bounded in 1.0.6 (MANIFEST_FLOOD_HOTFIX.md); listed keys are never evicted. |
| R-14 | Drill-model gap: the lab manifest is a JSON model, not a byte-exact STObject, so a real-manifest edge case could differ | Low | Low | Real-manifest parsing is verified separately against all 25 live VL manifests; the gap is labelled in the drill output. |
