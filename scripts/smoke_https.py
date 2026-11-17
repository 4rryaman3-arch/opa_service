#!/usr/bin/env python3
"""Remote HTTPS verification - run this FROM THE SECURDEN SERVER (or any
separate machine holding the client certificate). Requires only httpx.

  python smoke_https.py --url https://opm.lan --ca ca.crt --cert client.crt \
      --key client.key --token-file api_token --tenant acme

Positive checks: TLS chain + hostname verified against the private CA, mTLS
accepted, /health, /ready, /api/v1/version, one synthetic evaluation.
Negative checks: connection without client certificate must fail; wrong
bearer token must get 401; CA mismatch must fail verification (if
--wrong-ca is given). Exit code 0 only if every check behaves as expected.
"""

from __future__ import annotations

import argparse
import socket
import ssl
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlparse

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "client"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from securden_opm_client import OpmClient, OpmError, OpmRequestError, RetryPolicy  # noqa: E402

RESULTS: list[tuple[str, bool, str]] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    RESULTS.append((name, ok, detail))
    print(f"[{'PASS' if ok else 'FAIL'}] {name}{(' - ' + detail) if detail else ''}", flush=True)


def tls_details(url: str, ca: str, cert: str, key: str) -> None:
    u = urlparse(url)
    host, port = u.hostname, u.port or 443
    ctx = ssl.create_default_context(cafile=ca)
    ctx.load_cert_chain(cert, key)
    with socket.create_connection((host, port), timeout=10) as raw:
        with ctx.wrap_socket(raw, server_hostname=host) as s:
            peer = s.getpeercert()
            subject = dict(x[0] for x in peer["subject"])
            sans = ", ".join(f"{t}:{v}" for t, v in peer.get("subjectAltName", ()))
            check("TLS handshake + hostname verification", True,
                  f"{s.version()} {s.cipher()[0]}; server CN={subject.get('commonName')}; SAN={sans}; "
                  f"notAfter={peer['notAfter']}")


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--url", required=True)
    p.add_argument("--ca", required=True)
    p.add_argument("--cert", required=True)
    p.add_argument("--key", required=True)
    p.add_argument("--token-file", required=True)
    p.add_argument("--tenant", required=True)
    p.add_argument("--wrong-ca", help="a CA bundle that did NOT issue the server cert (negative test)")
    a = p.parse_args()
    token = Path(a.token_file).read_text(encoding="utf-8").strip()
    print(f"OPM HTTPS verification against {a.url} from {socket.gethostname()} at "
          f"{datetime.now(timezone.utc).isoformat()}")

    try:
        tls_details(a.url, a.ca, a.cert, a.key)
    except Exception as exc:  # noqa: BLE001
        check("TLS handshake + hostname verification", False, f"{type(exc).__name__}: {exc}")
        return 1

    once = RetryPolicy(max_attempts=1)
    with OpmClient(base_url=a.url, token=token, ca_bundle=a.ca, client_cert=(a.cert, a.key), retry=once) as c:
        check("GET /health", c.health() == {"status": "ok"})
        ready = c.ready()
        check("GET /ready", ready.get("status") == "ready", str(ready.get("checks")))
        v = c.version()
        check("GET /api/v1/version", bool(v.get("policy_versions_consistent")),
              f"app={v['app_version']} opa={v['opa_version']} bundle={v['policy_bundle_version']}")
        end = datetime.now(timezone.utc).replace(minute=0, second=0, microsecond=0) - timedelta(hours=1)
        res = c.evaluate(a.tenant, {
            "rule_id": "PAM-ROTATION-001",
            "reporting_period": {"start": (end - timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%SZ"),
                                 "end": end.strftime("%Y-%m-%dT%H:%M:%SZ")},
            "evidence": {"evidence_type": "credential_rotation", "records": [{
                "record_id": "smoke-synthetic-1", "account_id": "smoke-synthetic-acct", "privileged": True,
                "last_rotated_at": (end - timedelta(days=95)).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "last_rotation_status": "SUCCESS"}],
                "completeness": {"expected_record_count": 1, "received_record_count": 1, "source_complete": True}},
        })
        check("POST /api/v1/evaluate (synthetic, expect FAIL)", res["status"] == "FAIL",
              f"evaluation_id={res['evaluation_id']} status={res['status']} "
              f"digest={res['decision_details']['input_digest'][:20]}...")

    # Negative: no client certificate
    try:
        with OpmClient(base_url=a.url, token=token, ca_bundle=a.ca, retry=once) as c:
            c.health()
        check("connection without client certificate is rejected", False, "request unexpectedly succeeded")
    except OpmError as exc:
        check("connection without client certificate is rejected", True, exc.code)

    # Negative: wrong bearer token (valid mTLS)
    try:
        with OpmClient(base_url=a.url, token="securden-prod.wrong", ca_bundle=a.ca,
                       client_cert=(a.cert, a.key), retry=once) as c:
            c.version()
        check("wrong API token is rejected", False, "request unexpectedly succeeded")
    except OpmRequestError as exc:
        check("wrong API token is rejected", exc.status_code == 401, f"HTTP {exc.status_code}")

    if a.wrong_ca:
        try:
            with OpmClient(base_url=a.url, token=token, ca_bundle=a.wrong_ca, client_cert=(a.cert, a.key),
                           retry=once) as c:
                c.health()
            check("untrusted CA is rejected", False, "request unexpectedly succeeded")
        except OpmError as exc:
            check("untrusted CA is rejected", exc.code == "TLS_VERIFICATION_FAILED", exc.code)

    failed = [r for r in RESULTS if not r[1]]
    print(f"\n{len(RESULTS) - len(failed)}/{len(RESULTS)} checks passed")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
