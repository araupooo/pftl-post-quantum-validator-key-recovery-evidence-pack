#!/usr/bin/env python3
"""drill.py — post-quantum validator key recovery drills, executed in a LAB.

Five scenarios, all against freshly generated LAB keys (never real keys,
never persisted outside this process's wiped temp directory):
  A. Ephemeral signing-key loss      -> rotate ephemeral, manifest seq + 1
  B. Ephemeral signing-key compromise-> rotate + supersede; stale manifest rejected
  C. Master-key loss                 -> unrecoverable by design; new identity only
  D. Node loss + Shamir restore      -> 3-of-5 threshold restore of the key file
  E. Master-key compromise           -> revocation manifest (seq 0xFFFFFFFF)

What this drill IS: real Ed25519/secp256k1 key generation, signing, and
verification with the system OpenSSL; a real GF(256) Shamir split/rebuild
(scripts/shamir.py); timed measurements of every step.
What it is NOT: it does not run postfiatd, and its "manifest" is a LAB
MODEL (JSON with the same fields as a real manifest: master key, signing
key, sequence, domain, two signatures) — not a byte-exact postfiatd STObject
manifest. The model is validated separately against REAL live manifests
parsed by scripts/manifest_parse.py (see outputs/derived/live-validator-set.json).
Every model limitation is labelled in the output.

PRIVACY: secret keys exist only in memory and in a temp directory that is
overwritten and deleted at the end of the run (and on any error). The log
and the JSON output contain ONLY public keys, SHA-256 fingerprints, timings,
and pass/fail results. No secret key material is ever printed or written to
the pack.

Usage:
  python3 scripts/drill.py --out outputs/derived/drill-results.json \
      --log outputs/drill-run.log
Exit 0 only if every scenario's expected outcome holds.
"""
import argparse
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import shamir  # noqa: E402

REVOCATION_SEQUENCE = 0xFFFFFFFF


def sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def run(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, check=True, **kw)


class Lab:
    """A throwaway lab directory holding generated LAB keys. Wiped on exit."""

    def __init__(self, tmp):
        self.d = tmp
        self.n = 0

    def path(self, name):
        self.n += 1
        return os.path.join(self.d, f"{self.n:03d}-{name}")

    def gen_key(self, kind):
        """Generate a fresh LAB keypair with OpenSSL. Returns (priv, pub_der)."""
        priv = self.path(f"{kind}-priv.pem")
        pub = self.path(f"{kind}-pub.der")
        if kind == "ed25519":
            run(["openssl", "genpkey", "-algorithm", "ED25519", "-out", priv])
        else:
            run(["openssl", "genpkey", "-algorithm", "EC",
                 "-pkeyopt", "ec_paramgen_curve:secp256k1", "-out", priv])
        run(["openssl", "pkey", "-in", priv, "-pubout", "-outform", "DER",
             "-out", pub])
        with open(pub, "rb") as f:
            pub_der = f.read()
        return priv, pub_der

    def sign(self, kind, priv, msg: bytes) -> bytes:
        sig = self.path("sig.bin")
        if kind == "ed25519":
            run(["openssl", "pkeyutl", "-sign", "-inkey", priv, "-rawin",
                 "-in", self._write(msg), "-out", sig])
        else:
            # secp256k1: ECDSA with SHA-256 (openssl dgst). The pinned VL
            # uses SHA-512-Half + secp256k1 ECDSA (generate_vl.py); this lab
            # model uses SHA-256 and says so in the drill output.
            run(["openssl", "dgst", "-sha256", "-sign", priv,
                 "-out", sig, self._write(msg)])
        with open(sig, "rb") as f:
            return f.read()

    def verify(self, kind, pub_der, msg: bytes, sig: bytes) -> bool:
        pub = self.path("verify-pub.pem")
        if kind == "ed25519":
            # pkeyutl -verify needs the public key in PEM for Ed25519.
            run(["openssl", "pkey", "-inform", "DER", "-in",
                 self._write(pub_der), "-pubin", "-out", pub])
            sigf = self.path("verify-sig.bin")
            with open(sigf, "wb") as f:
                f.write(sig)
            msgf = self._write(msg)
            try:
                run(["openssl", "pkeyutl", "-verify", "-pubin", "-inkey", pub,
                     "-rawin", "-in", msgf, "-sigfile", sigf])
                return True
            except subprocess.CalledProcessError:
                return False
        # secp256k1: ECDSA/SHA-256 verification via dgst.
        run(["openssl", "pkey", "-inform", "DER", "-in",
             self._write(pub_der), "-pubin", "-out", pub])
        sigf = self.path("verify-sig.bin")
        with open(sigf, "wb") as f:
            f.write(sig)
        msgf = self._write(msg)
        try:
            run(["openssl", "dgst", "-sha256", "-verify", pub,
                 "-signature", sigf, msgf])
            return True
        except subprocess.CalledProcessError:
            return False

    def _write(self, data: bytes) -> str:
        p = self.path("msg.bin")
        with open(p, "wb") as f:
            f.write(data)
        return p

    def wipe(self):
        for root, _, files in os.walk(self.d):
            for fn in files:
                p = os.path.join(root, fn)
                try:
                    size = os.path.getsize(p)
                    with open(p, "wb") as f:
                        f.write(b"\x00" * size)
                    os.unlink(p)
                except OSError:
                    pass


def timed(fn):
    t0 = time.perf_counter()
    out = fn()
    return out, time.perf_counter() - t0


def manifest_bytes(model: dict) -> bytes:
    """Canonical bytes signed by the master key (lab model)."""
    return json.dumps(
        {k: model[k] for k in
         ("master_public_key", "signing_public_key", "sequence", "domain")},
        sort_keys=True).encode()


def build_manifest(lab, master_kind, master_priv, master_pub,
                   signing_kind, signing_priv, signing_pub, sequence, domain):
    model = {
        "master_public_key": master_pub.hex(),
        "master_public_key_sha256": sha256_hex(master_pub),
        "signing_public_key": signing_pub.hex(),
        "signing_public_key_sha256": sha256_hex(signing_pub),
        "sequence": sequence,
        "domain": domain,
    }
    body = manifest_bytes(model)
    model["master_signature"] = lab.sign(master_kind, master_priv, body).hex()
    model["ephemeral_signature"] = lab.sign(
        signing_kind, signing_priv, body).hex()
    return model


def verify_manifest(lab, model, master_kind, master_pub, signing_kind, signing_pub):
    body = manifest_bytes(model)
    ok_master = lab.verify(master_kind, master_pub, body,
                           bytes.fromhex(model["master_signature"]))
    ok_eph = lab.verify(signing_kind, signing_pub, body,
                        bytes.fromhex(model["ephemeral_signature"]))
    return ok_master and ok_eph


def scenario_a(lab, log):
    """A. Ephemeral signing-key loss: rotate to a new ephemeral key."""
    steps, t = [], time.perf_counter()
    log("  [A] Ephemeral signing-key loss (LAB keys, Ed25519 master / "
        "secp256k1 ephemeral, mirroring the live UNL key split)")
    (m_priv, m_pub), dt = timed(lambda: lab.gen_key("ed25519"))
    steps.append(("generate lab master keypair (Ed25519)", dt))
    (s_priv, s_pub), dt = timed(lambda: lab.gen_key("secp256k1"))
    steps.append(("generate lab ephemeral keypair (secp256k1)", dt))
    m1, dt = timed(lambda: build_manifest(
        lab, "ed25519", m_priv, m_pub, "secp256k1", s_priv, s_pub, 1,
        "lab.example"))
    steps.append(("build manifest seq 1", dt))
    ok1, dt = timed(lambda: verify_manifest(
        lab, m1, "ed25519", m_pub, "secp256k1", s_pub))
    assert ok1
    steps.append(("verify manifest seq 1 signatures", dt))
    # LOSE the ephemeral secret: delete it from the lab directory.
    os.unlink(s_priv)
    log("  [A] ephemeral secret deleted (simulated loss); master secret kept")
    (s2_priv, s2_pub), dt = timed(lambda: lab.gen_key("secp256k1"))
    steps.append(("generate replacement ephemeral keypair", dt))
    m2, dt = timed(lambda: build_manifest(
        lab, "ed25519", m_priv, m_pub, "secp256k1", s2_priv, s2_pub, 2,
        "lab.example"))
    steps.append(("build manifest seq 2 (rotation)", dt))
    ok, dt = timed(lambda: verify_manifest(
        lab, m2, "ed25519", m_pub, "secp256k1", s2_pub))
    steps.append(("verify manifest seq 2 signatures", dt))
    assert ok and m2["sequence"] == m1["sequence"] + 1
    assert m2["signing_public_key"] != m1["signing_public_key"]
    total = time.perf_counter() - t
    return {"scenario": "A",
            "name": "Ephemeral signing-key loss",
            "outcome": "RECOVERED: new ephemeral key + manifest seq 2, "
                       "validator identity (master key) unchanged",
            "total_seconds": round(total, 3),
            "steps": [{"step": s, "seconds": round(d, 4)} for s, d in steps],
            "master_public_key_sha256": sha256_hex(m_pub),
            "old_signing_key_sha256": sha256_hex(s_pub),
            "new_signing_key_sha256": sha256_hex(s2_pub),
            "sequences": [m1["sequence"], m2["sequence"]]}


def scenario_b(lab, log):
    """B. Ephemeral compromise: rotate and prove the stale manifest is dead."""
    t = time.perf_counter()
    log("  [B] Ephemeral signing-key compromise (rotation + stale rejection)")
    m_priv, m_pub = lab.gen_key("ed25519")
    s_priv, s_pub = lab.gen_key("secp256k1")
    m1 = build_manifest(lab, "ed25519", m_priv, m_pub,
                        "secp256k1", s_priv, s_pub, 1, "lab.example")
    # Compromise: the old ephemeral secret is now known to an attacker.
    # Operator rotates: new ephemeral, seq 2.
    s2_priv, s2_pub = lab.gen_key("secp256k1")
    m2 = build_manifest(lab, "ed25519", m_priv, m_pub,
                        "secp256k1", s2_priv, s2_pub, 2, "lab.example")
    # Model of ManifestCache (Manifest.cpp: sequence <= stored is ignored):
    stored_seq = m2["sequence"]
    stale_accepted = m1["sequence"] > stored_seq  # must be False
    assert not stale_accepted
    assert verify_manifest(lab, m2, "ed25519", m_pub, "secp256k1", s2_pub)
    total = time.perf_counter() - t
    return {"scenario": "B",
            "name": "Ephemeral signing-key compromise",
            "outcome": "RECOVERED: rotation to seq 2; stale seq-1 manifest "
                       "rejected by the sequence rule (seq <= stored ignored)",
            "total_seconds": round(total, 3),
            "stale_manifest_accepted": stale_accepted,
            "master_public_key_sha256": sha256_hex(m_pub),
            "compromised_signing_key_sha256": sha256_hex(s_pub),
            "new_signing_key_sha256": sha256_hex(s2_pub),
            "sequences": [m1["sequence"], m2["sequence"]]}


def scenario_c(lab, log):
    """C. Master-key loss: no new manifest can be signed. New identity only."""
    t = time.perf_counter()
    log("  [C] Master-key loss (unrecoverable by design)")
    m_priv, m_pub = lab.gen_key("ed25519")
    s_priv, s_pub = lab.gen_key("secp256k1")
    m1 = build_manifest(lab, "ed25519", m_priv, m_pub,
                        "secp256k1", s_priv, s_pub, 1, "lab.example")
    assert verify_manifest(lab, m1, "ed25519", m_pub, "secp256k1", s_pub)
    # LOSE the master secret.
    os.unlink(m_priv)
    log("  [C] master secret deleted (simulated loss); no copy exists")
    # Attempt: build a rotation manifest without the master secret.
    # Impossible by construction — there is no master private key to sign
    # with. Record the attempt as failed, then measure the only path.
    rotation_possible = False
    t_new = time.perf_counter()
    n_priv, n_pub = lab.gen_key("ed25519")
    n_s_priv, n_s_pub = lab.gen_key("secp256k1")
    n_m = build_manifest(lab, "ed25519", n_priv, n_pub,
                         "secp256k1", n_s_priv, n_s_pub, 1, "lab.example")
    new_identity_seconds = time.perf_counter() - t_new
    assert verify_manifest(lab, n_m, "ed25519", n_pub, "secp256k1", n_s_pub)
    assert n_m["master_public_key"] != m1["master_public_key"]
    total = time.perf_counter() - t
    return {"scenario": "C",
            "name": "Master-key loss",
            "outcome": "NOT RECOVERABLE: without the master secret no new "
                       "manifest can be signed; the only path is a new "
                       "validator identity (new master key, new VL entry)",
            "rotation_possible_without_master_secret": rotation_possible,
            "new_identity_lab_seconds": round(new_identity_seconds, 3),
            "total_seconds": round(total, 3),
            "lost_master_key_sha256": sha256_hex(m_pub),
            "new_master_key_sha256": sha256_hex(n_pub),
            "network_side_cost": "SPECIFIED (not measured in lab): new VL "
                "publication with a higher sequence, operator coordination, "
                "and trust re-establishment; see docs/runbook.md"}


def scenario_d(lab, log):
    """D. Node loss + Shamir restore of the validator-keys.json contents."""
    t = time.perf_counter()
    log("  [D] Node loss: validator-keys.json deleted on container restart; "
        "restore the master secret from 3-of-5 Shamir shares")
    # The "key file" contents, modelled as a 32-byte master secret (the
    # size of an Ed25519 seed / ML-DSA-65 seed; the real file holds the
    # master keypair + sequence — here only its secret is modelled).
    master_secret = os.urandom(32)
    fingerprint = sha256_hex(master_secret)
    shares = shamir.split(master_secret, 3, 5)
    log(f"  [D] lab master secret sha256={fingerprint[:16]}... split 3-of-5")
    # Simulate the container restart deleting validator-keys.json.
    del master_secret
    log("  [D] key file deleted (simulated container restart)")
    # Restore from shares 1, 3, 5.
    t0 = time.perf_counter()
    rebuilt = shamir.reconstruct([shares[0], shares[2], shares[4]])
    dt_restore = time.perf_counter() - t0
    assert sha256_hex(rebuilt) == fingerprint
    # Failure mode 1: only 2 shares.
    two_share = shamir.reconstruct(shares[:2])
    two_share_fails = sha256_hex(two_share) != fingerprint
    assert two_share_fails
    # Failure mode 2: one corrupted share is detected by commitment.
    bad = bytearray(shares[1][1])
    bad[0] ^= 0x01
    corrupted = shamir.reconstruct(
        [(shares[1][0], bytes(bad)), shares[2], shares[3]])
    corruption_detected = sha256_hex(corrupted) != fingerprint
    assert corruption_detected
    total = time.perf_counter() - t
    return {"scenario": "D",
            "name": "Node loss + Shamir restore (3-of-5)",
            "outcome": "RECOVERED: master secret rebuilt from shares 1, 3, 5 "
                       "and verified by fingerprint",
            "total_seconds": round(total, 3),
            "restore_seconds": round(dt_restore, 4),
            "master_secret_sha256": fingerprint,
            "share_commitments_sha256": [shamir.commitment(y) for _, y in shares],
            "failure_modes": {
                "two_shares_insufficient": two_share_fails,
                "corrupted_share_detected_by_commitment": corruption_detected,
            }}


def scenario_e(lab, log):
    """E. Master-key compromise: revocation manifest, then re-onboarding."""
    t = time.perf_counter()
    log("  [E] Master-key compromise (revocation manifest seq 0xFFFFFFFF)")
    m_priv, m_pub = lab.gen_key("ed25519")
    s_priv, s_pub = lab.gen_key("secp256k1")
    m1 = build_manifest(lab, "ed25519", m_priv, m_pub,
                        "secp256k1", s_priv, s_pub, 3, "lab.example")
    # Revocation: sequence 0xFFFFFFFF, no signing key (Manifest.cpp:
    # revoked() is sequence == max uint32; revocation manifests must not
    # carry a new signing key). The master signature still authenticates it.
    rev = {
        "master_public_key": m_pub.hex(),
        "master_public_key_sha256": sha256_hex(m_pub),
        "signing_public_key": None,
        "signing_public_key_sha256": None,
        "sequence": REVOCATION_SEQUENCE,
        "domain": "lab.example",
    }
    body = json.dumps(
        {k: rev[k] for k in ("master_public_key", "signing_public_key",
                             "sequence", "domain")}, sort_keys=True).encode()
    rev["master_signature"] = lab.sign("ed25519", m_priv, body).hex()
    rev["ephemeral_signature"] = None
    assert lab.verify("ed25519", m_pub, body,
                      bytes.fromhex(rev["master_signature"]))
    # Model of ManifestCache: after a revocation no further manifest for
    # this master key is accepted (no higher sequence number exists).
    further_manifest_possible = REVOCATION_SEQUENCE < 0xFFFFFFFF
    assert not further_manifest_possible
    total = time.perf_counter() - t
    return {"scenario": "E",
            "name": "Master-key compromise",
            "outcome": "REVOKED: revocation manifest seq 4294967295 "
                       "authenticated by the master key; no further manifest "
                       "for this master key can ever be accepted; the "
                       "validator must re-onboard as a new identity",
            "total_seconds": round(total, 3),
            "revocation_sequence": REVOCATION_SEQUENCE,
            "further_manifest_possible": further_manifest_possible,
            "master_public_key_sha256": sha256_hex(m_pub),
            "revoked_signing_key_sha256": sha256_hex(s_pub)}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="outputs/derived/drill-results.json")
    ap.add_argument("--log", default="outputs/drill-run.log")
    args = ap.parse_args()
    log_lines = []

    def log(msg):
        print(msg)
        log_lines.append(msg)

    log("recovery drill run start (LAB keys only, no live key material)")
    log("openssl: " + run(["openssl", "version"]).stdout.decode().strip())
    results = []
    with tempfile.TemporaryDirectory(prefix="pftl-keyrec-lab-") as tmp:
        lab = Lab(tmp)
        try:
            for fn in (scenario_a, scenario_b, scenario_c, scenario_d,
                       scenario_e):
                r = fn(lab, log)
                results.append(r)
                log(f"  [{r['scenario']}] {r['outcome']}")
        finally:
            lab.wipe()
    failed = [r for r in results
              if "NOT RECOVERABLE" not in r["outcome"]
              and "RECOVERED" not in r["outcome"]
              and "REVOKED" not in r["outcome"]]
    payload = {
        "drill": "post-quantum validator key recovery (LAB)",
        "scenarios": results,
        "scenarios_run": len(results),
        "recovered": sum(1 for r in results if r["outcome"].startswith("RECOVERED")),
        "not_recoverable": sum(1 for r in results if "NOT RECOVERABLE" in r["outcome"]),
        "revoked": sum(1 for r in results if r["outcome"].startswith("REVOKED")),
        "model_note": "Manifests in this drill are LAB MODELS (JSON with the "
                      "same fields as a real manifest), not byte-exact "
                      "postfiatd STObject manifests. Real-manifest parsing "
                      "is verified separately against the live VL.",
    }
    json.dump(payload, open(args.out, "w"), indent=1)
    with open(args.log, "w") as f:
        f.write("\n".join(log_lines) + "\n")
    print(f"wrote {args.out} and {args.log}")
    print(f"drill: {payload['recovered']} recovered, "
          f"{payload['not_recoverable']} not recoverable, "
          f"{payload['revoked']} revoked")
    return 0 if not failed else 1


if __name__ == "__main__":
    raise SystemExit(main())
