#!/usr/bin/env python3
"""Synthetic-workload benchmark. Reports only measured numbers.

Local (spawns OPA + the API on loopback, plain HTTP; measures app + OPA):
  python scripts/benchmark.py --local --opa /path/to/opa

Remote (through Caddy, HTTPS + mTLS; run from the Securden server):
  python scripts/benchmark.py --url https://opm.lan --ca ca.crt --cert client.crt \
      --key client.key --token-file api_token --tenant acme

Workloads (all synthetic PAM-ROTATION-001 credential_rotation evidence):
  single-N     sequential single evaluations with N records
  concurrent   C parallel clients, 100 records per evaluation
  batch        /evaluate/batch with 100 items x 100 records
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import secrets
import socket
import ssl
import statistics
import subprocess
import sys
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parents[1]


def z(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


END = datetime.now(timezone.utc).replace(minute=0, second=0, microsecond=0) - timedelta(hours=1)
START = END - timedelta(days=30)


def evaluation(n: int, seed: int = 0) -> dict:
    records = [{
        "record_id": f"rot-{seed}-{i}",
        "account_id": f"acct-{seed}-{i}",
        "privileged": True,
        "last_rotated_at": z(END - timedelta(days=(i * 7) % 120)),
        "last_rotation_status": "SUCCESS",
    } for i in range(n)]
    return {
        "rule_id": "PAM-ROTATION-001",
        "reporting_period": {"start": z(START), "end": z(END)},
        "evidence": {"evidence_type": "credential_rotation", "records": records,
                     "completeness": {"expected_record_count": n, "received_record_count": n,
                                      "source_complete": True, "collection_errors": 0}},
    }


def pct(values, q):
    values = sorted(values)
    k = max(0, min(len(values) - 1, int(round(q * (len(values) - 1)))))
    return values[k]


def summarize(name, latencies, wall=None, items=None, payload_bytes=None):
    out = {
        "workload": name,
        "requests": len(latencies),
        "p50_ms": round(statistics.median(latencies) * 1000, 2),
        "p95_ms": round(pct(latencies, 0.95) * 1000, 2),
        "max_ms": round(max(latencies) * 1000, 2),
    }
    if wall:
        out["wall_s"] = round(wall, 2)
        out["throughput_rps"] = round(len(latencies) / wall, 1)
        if items:
            out["records_per_s"] = round(items / wall)
    if payload_bytes:
        out["request_body_kib"] = round(payload_bytes / 1024, 1)
    return out


def run(client: httpx.Client, tenant: str, reps: int, concurrency: int) -> list[dict]:
    results = []
    for n in (10, 100, 1000, 10000):
        body = {"tenant_id": tenant, **evaluation(n)}
        size = len(json.dumps(body))
        r = client.post("/api/v1/evaluate", json=body)
        r.raise_for_status()  # warm-up + sanity
        lat = []
        count = reps if n < 10000 else max(5, reps // 4)
        for _ in range(count):
            t = time.perf_counter()
            r = client.post("/api/v1/evaluate", json=body)
            lat.append(time.perf_counter() - t)
            assert r.status_code == 200, r.text[:300]
        results.append(summarize(f"single-{n}", lat, payload_bytes=size))
        print(results[-1], flush=True)

    body = {"tenant_id": tenant, **evaluation(100)}
    total = reps * 4
    lat: list[float] = []
    lock = threading.Lock()

    def one(_):
        t = time.perf_counter()
        r = client.post("/api/v1/evaluate", json=body)
        d = time.perf_counter() - t
        assert r.status_code == 200, r.text[:300]
        with lock:
            lat.append(d)

    t0 = time.perf_counter()
    with ThreadPoolExecutor(concurrency) as pool:
        list(pool.map(one, range(total)))
    results.append(summarize(f"concurrent-{concurrency}x100rec", lat, time.perf_counter() - t0, items=total * 100))
    print(results[-1], flush=True)

    batch = {"tenant_id": tenant, "items": [evaluation(100, seed=i) for i in range(100)]}
    size = len(json.dumps(batch))
    lat = []
    for _ in range(max(3, reps // 6)):
        t = time.perf_counter()
        r = client.post("/api/v1/evaluate/batch", json=batch, timeout=120)
        lat.append(time.perf_counter() - t)
        assert r.status_code == 200 and r.json()["summary"]["succeeded"] == 100, r.text[:300]
    res = summarize("batch-100x100rec", lat, payload_bytes=size)
    res["records_per_s"] = round(10_000 / statistics.median(lat))
    results.append(res)
    print(results[-1], flush=True)
    return results


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def local(args):
    tmp = Path(tempfile.mkdtemp(prefix="opm-bench-"))
    token = secrets.token_urlsafe(48)
    secret = secrets.token_urlsafe(32)
    (tmp / "clients.json").write_text(json.dumps({"clients": [{
        "key_id": "bench", "secret_sha256": hashlib.sha256(secret.encode()).hexdigest(),
        "tenants": ["bench"], "scopes": ["evaluate", "metrics:read"]}]}))
    opa_port, api_port = free_port(), free_port()
    opa = subprocess.Popen([args.opa, "run", "--server", f"--addr=127.0.0.1:{opa_port}", "--authentication=token",
                            "--authorization=basic", "--disable-telemetry", "--log-level=error", "policy-bundle"],
                           cwd=ROOT, env={**os.environ, "OPA_AUTH_TOKEN": token},
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    env = {**os.environ, "OPM_OPA_URL": f"http://127.0.0.1:{opa_port}", "OPM_OPA_TOKEN": token,
           "OPM_POLICY_BUNDLE_DIR": str(ROOT / "policy-bundle"), "OPM_DB_PATH": str(tmp / "opm.db"),
           "OPM_API_CLIENTS_FILE": str(tmp / "clients.json"), "OPM_LOG_LEVEL": "WARNING",
           "OPM_RATE_LIMIT_PER_MINUTE": "1000000", "OPM_RATE_LIMIT_BURST": "100000",
           "OPM_BATCH_CONCURRENCY": str(args.batch_concurrency)}
    api = subprocess.Popen([sys.executable, "-m", "uvicorn", "app.main:app_factory", "--factory", "--host", "127.0.0.1",
                            "--port", str(api_port), "--no-access-log", "--log-level", "warning"],
                           cwd=ROOT, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        client = httpx.Client(base_url=f"http://127.0.0.1:{api_port}", timeout=60,
                              headers={"Authorization": f"Bearer bench.{secret}"},
                              limits=httpx.Limits(max_connections=args.concurrency * 2))
        deadline = time.time() + 30
        while time.time() < deadline:
            try:
                if client.get("/ready").status_code == 200:
                    break
            except httpx.HTTPError:
                pass
            time.sleep(0.3)
        else:
            raise SystemExit("service did not become ready")
        results = run(client, "bench", args.reps, args.concurrency)
        metrics = client.get("/api/v1/metrics").json()
        return results, {"mode": "local-loopback-http", "opa_request_seconds": metrics["histograms"].get("opa_request_seconds")}
    finally:
        api.terminate()
        opa.terminate()


def remote(args):
    ctx = ssl.create_default_context(cafile=args.ca)
    if args.cert:
        ctx.load_cert_chain(args.cert, args.key)
    token = Path(args.token_file).read_text().strip()
    client = httpx.Client(base_url=args.url, verify=ctx, timeout=120, headers={"Authorization": f"Bearer {token}"},
                          limits=httpx.Limits(max_connections=args.concurrency * 2))
    return run(client, args.tenant, args.reps, args.concurrency), {"mode": "remote-https", "url": args.url}


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--local", action="store_true")
    p.add_argument("--opa", default=os.environ.get("OPM_TEST_OPA_BINARY", "opa"))
    p.add_argument("--url")
    p.add_argument("--ca")
    p.add_argument("--cert")
    p.add_argument("--key")
    p.add_argument("--token-file")
    p.add_argument("--tenant", default="bench")
    p.add_argument("--reps", type=int, default=30)
    p.add_argument("--concurrency", type=int, default=8)
    p.add_argument("--batch-concurrency", type=int, default=8)
    p.add_argument("--out", default="benchmark-results.json")
    args = p.parse_args()
    results, meta = local(args) if args.local else remote(args)
    meta.update({
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "platform": platform.platform(),
        "python": platform.python_version(),
        "cpu_count": os.cpu_count(),
        "processor": platform.processor(),
        "reps": args.reps, "concurrency": args.concurrency, "batch_concurrency": args.batch_concurrency,
    })
    Path(args.out).write_text(json.dumps({"meta": meta, "results": results}, indent=2))
    print(f"wrote {args.out}")


if __name__ == "__main__":
    main()
