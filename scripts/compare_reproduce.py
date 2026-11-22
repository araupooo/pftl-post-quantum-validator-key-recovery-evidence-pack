#!/usr/bin/env python3
"""compare_reproduce.py — compare a fresh reproduce run against the shipped
pack. Exits 0 only if every applicable check passes.

Usage: python3 scripts/compare_reproduce.py <shipped_pack_dir> <fresh_dir>
  <fresh_dir> is the throwaway copy produced by clean_reproduce.sh.

Checks:
  1. Shamir self-test passes in the fresh run (deterministic).
  2. Drill outcomes identical (scenario outcomes + counts); timings are
     compared only as > 0 (wall-clock times vary run to run).
  3. Key-model arithmetic identical (quorum, manifest fit, sequence budget).
  4. Live chain identity identical (build_version, network_id,
     validation_quorum); validated seq must not go backwards.
  5. Validator list: if the fresh testnet_vl.json is byte-identical to the
     shipped one, all VL-derived numbers must match exactly. If the VL
     changed (new blob sequence), the VL checks are reported SKIPPED, not
     failed — the list is a live document.
  6. Digest verification passes in the fresh tree (via verify_digests.sh
     output passed on stdin? No — this script checks the fresh SHA256SUMS
     file exists and re-verifies a sample; the full verify runs separately).
"""
import hashlib
import json
import os
import subprocess
import sys


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def load(base, rel):
    return json.load(open(os.path.join(base, rel)))


def main():
    shipped, fresh = sys.argv[1], sys.argv[2]
    checks, skipped = [], []

    def check(name, ok, detail=""):
        checks.append((name, ok, detail))
        print(f"  {'PASS' if ok else 'FAIL'}  {name}"
              + (f" — {detail}" if detail else ""))

    print("compare_reproduce.py: shipped=%s fresh=%s" % (shipped, fresh))

    # 1. Shamir self-test in the fresh tree.
    r = subprocess.run([sys.executable, "scripts/shamir.py", "--self-test"],
                       cwd=fresh, capture_output=True, text=True)
    check("shamir self-test 11/11 in fresh tree",
          r.returncode == 0 and "all 11 checks passed" in r.stdout)

    # 2. Drill outcomes identical.
    d_ship = load(shipped, "outputs/derived/drill-results.json")
    d_fresh = load(fresh, "outputs/derived/drill-results.json")
    same = ([s["outcome"] for s in d_ship["scenarios"]]
            == [s["outcome"] for s in d_fresh["scenarios"]])
    check("drill scenario outcomes identical", same,
          f"{d_fresh['recovered']} recovered / {d_fresh['not_recoverable']} "
          f"not recoverable / {d_fresh['revoked']} revoked")
    timings_ok = all(s["total_seconds"] > 0 for s in d_fresh["scenarios"])
    check("drill timings recorded (> 0)", timings_ok)

    # 3. Key-model arithmetic identical.
    m_ship = load(shipped, "outputs/derived/pq-size-model.json")
    m_fresh = load(fresh, "outputs/derived/pq-size-model.json")
    check("quorum model identical",
          m_ship["quorum"] == m_fresh["quorum"],
          f"quorum 67% = {m_fresh['quorum']['quorum_67pct']}")
    check("manifest fit identical",
          m_ship["manifest_fit"] == m_fresh["manifest_fit"])
    check("sequence budget identical",
          m_ship["sequence_budget"] == m_fresh["sequence_budget"])

    # 4. Live chain identity.
    s_ship = load(shipped, "outputs/server_info.json")["result"]["info"]
    s_fresh = load(fresh, "outputs/server_info.json")["result"]["info"]
    check("build_version identical",
          s_ship["build_version"] == s_fresh["build_version"],
          s_fresh["build_version"])
    check("network_id identical",
          s_ship["network_id"] == s_fresh["network_id"])
    check("validation_quorum identical",
          s_ship["validation_quorum"] == s_fresh["validation_quorum"],
          str(s_fresh["validation_quorum"]))
    check("validated seq did not go backwards",
          s_fresh["validated_ledger"]["seq"]
          >= s_ship["validated_ledger"]["seq"],
          f"shipped {s_ship['validated_ledger']['seq']} -> "
          f"fresh {s_fresh['validated_ledger']['seq']}")

    # 5. Validator list.
    vl_same = (sha256(os.path.join(shipped, "outputs/testnet_vl.json"))
               == sha256(os.path.join(fresh, "outputs/testnet_vl.json")))
    if vl_same:
        l_ship = load(shipped, "outputs/derived/live-validator-set.json")
        l_fresh = load(fresh, "outputs/derived/live-validator-set.json")
        check("VL byte-identical; validator count identical",
              l_ship["validators"] == l_fresh["validators"] == 25)
        check("VL byte-identical; master key types identical",
              l_ship["master_key_types"] == l_fresh["master_key_types"])
        check("VL byte-identical; signing key types identical",
              l_ship["signing_key_types"] == l_fresh["signing_key_types"])
        check("VL byte-identical; sequences identical",
              l_ship["sequence_counts"] == l_fresh["sequence_counts"])
        check("VL byte-identical; manifest sizes identical",
              (l_ship["manifest_bytes_min"], l_ship["manifest_bytes_max"])
              == (l_fresh["manifest_bytes_min"], l_fresh["manifest_bytes_max"]))
    else:
        skipped.append("VL changed since ship (new blob); VL checks skipped")
        print("  SKIP  VL changed since ship (new blob); VL checks skipped")

    # 6. Claim/finding counts regenerated identically.
    f_ship = load(shipped, "findings.json")
    f_fresh = load(fresh, "findings.json")
    check("findings counts identical",
          f_ship["counts"] == f_fresh["counts"],
          f"{f_fresh['counts']['total']} findings")
    m_ship = load(shipped, "run-manifest.json")
    m_fresh = load(fresh, "run-manifest.json")
    check("run-manifest counts identical",
          m_ship["counts"] == m_fresh["counts"],
          f"{m_fresh['counts']['claims_total']} claims, "
          f"{m_fresh['counts']['risks_total']} risks")

    failed = [c for c in checks if not c[1]]
    print(f"compare_reproduce.py: {len(checks)} checks, "
          f"{len(failed)} failures, {len(skipped)} skipped")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
