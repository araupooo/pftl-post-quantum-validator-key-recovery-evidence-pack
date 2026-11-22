# Disaster-recovery runbook

## RTO / RPO targets

[SPECIFIED] These are design targets, not measured end-to-end values. The
lab crypto time for every scenario is ~0.1 s; the targets below are
dominated by operator steps (30 min) and documented manifest propagation
("within minutes", 5 min used as the conservative end).

| Scenario | RTO | RPO | Basis |
| --- | --- | --- | --- |
| A/B. Ephemeral loss / compromise | 35 min | 0 | 30 min operator steps + 5 min propagation |
| D. Node loss with 3-of-5 Shamir backup | 35 min | 0 | Same, plus share gathering from 3 custodians |
| E. Master compromise (revocation) | 35 min to revoke; days to re-onboard | N/A for the compromised identity | Revocation propagates in minutes; the validator is offline until re-onboarded as a new identity |
| C. Master loss | No RTO (unrecoverable) | N/A — the identity itself is lost | New identity needs VL republication + trust re-establishment |

## Quorum preservation during recovery [FACT]

Live UNL 25, quorum 17 (67%). The model
(`outputs/derived/quorum-model.json`):

| Validators down at once | Remaining | Quorum 17 reachable? |
| --- | --- | --- |
| 1 | 24 | Yes |
| 2 | 23 | Yes |
| 4 | 21 | Yes |
| 8 | 17 | Yes — zero margin |
| 9 | 16 | No — finality stalls until one returns |

At the 80% mainnet quorum (20 of 25) only 5 simultaneous outages are
tolerable. Rule: **rotate one validator at a time, with a quorum check
between steps.** Never rotate 8 at once, and never rotate during another
validator's known outage.

## Incident-response playbook

### 1. Suspected ephemeral-key compromise

1. Confirm the indicator (unexpected manifest sequence bump in the VL,
   anomalous validation signatures, host intrusion evidence).
2. Generate a new ephemeral key and token (`validator-keys create_token`
   with the master key file present).
3. Replace the `[validator_token]` section in `postfiatd.cfg` (exactly one
   such section; no extra spaces or line breaks inside the token).
4. Restart the validator (`docker compose restart`).
5. **Before the restart, copy `validator-keys.json` out of the container**
   (`docker cp postfiatd:/root/.ripple/validator-keys.json ...`) — the
   file is deleted on restart.
6. Verify: the new manifest (sequence + 1) appears in the VL within
   minutes; the validator resumes signing with the new key; the old
   ephemeral key's validations stop.
7. Log the rotation (date, reason, old/new sequence, operator).

### 2. Ephemeral-key loss

Same as (1) without the compromise investigation: the key is gone, so
there is nothing to revoke — rotation is the whole response.

### 3. Master-key compromise

1. Publish the revocation manifest immediately (sequence 0xFFFFFFFF). If a
   pre-generated revocation was escrowed at creation time, publish that;
   otherwise sign one now — this requires the master secret, so do it
   before doing anything that might lose it.
2. Confirm the revocation propagates (the validator's master key stops
   appearing with a signing key; peers drop its validations).
3. Treat the validator as offline. Create a new identity
   (`validator-keys create_keys`), a new token, and a new VL entry.
4. Coordinate the VL republication with the publisher (sequence bump).
5. Re-onboard: new config, new token, restart, verify in the VL.
6. Post-incident review: how was the master key exposed, and which
   control failed.

### 4. Master-key loss (no backup)

1. Accept the identity is gone. There is no recovery procedure.
2. Create a new identity and VL entry (same as (3) steps 3-5).
3. Post-incident review: why was there no Shamir backup, and who owns
   fixing that for every other validator.

### 5. Node loss / container restart

1. Before any `docker compose down` or `restart`, copy
   `validator-keys.json` out of the container and verify the copy (compare
   fingerprints).
2. If the file is already lost: gather 3 of the 5 Shamir shares, rebuild
   the master secret (fingerprint check), restore the key file, and only
   then restart.
3. If fewer than 3 shares are available: the identity is lost — follow
   (4).
4. After restart, verify the validator reappears in the VL and resumes
   signing.

### 6. VL publisher-key compromise

1. The publisher revokes/rotates its own key the same way (its manifest
   sequence + 1, or revocation at 0xFFFFFFFF).
2. Operators update `[validator_list_keys]` in their configs to the new
   publisher key.
3. The old VL is distrusted once the new publisher key is configured.

## Pre-flight checklist (before any key operation)

- [ ] `validator-keys.json` copied out of the container and fingerprint-verified
- [ ] Shamir shares verified (rebuild from a rotating subset within the last 6 months)
- [ ] New token's sequence number is higher than the current one
- [ ] Exactly one `[validator_token]` section in the config
- [ ] No other validator is currently rotating (quorum check)
- [ ] Rollback plan ready: previous token retained until the new manifest is seen in the VL
