#!/usr/bin/env python3
"""Run the stack natively (no Docker): OPA + FastAPI on loopback, Caddy on HTTPS.

  python scripts/run_native.py --with-ollama [--port 443]

Intended for testing on a host without Docker. Same Caddyfile, policies and
app as the Compose deployment; OPA and the API listen on 127.0.0.1 only, so
Caddy (TLS + mTLS) is the only thing reachable from the LAN.
Requires .env, deploy/certs/ and secrets/api_clients.json (scripts/bootstrap.py).
Logs: logs/opa.log, logs/api.log, logs/caddy.log. Ctrl+C stops everything.
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path
from urllib.parse import urlsplit

import httpx
from dotenv import dotenv_values

ROOT = Path(__file__).resolve().parents[1]


def read_env(path: Path) -> dict[str, str]:
    return {k: v for k, v in dotenv_values(path).items() if v is not None}


def ollama_binary(explicit: str | None = None) -> str:
    candidates = [explicit, shutil.which("ollama")]
    if os.name == "nt":
        candidates.append(str(Path(os.environ.get("LOCALAPPDATA", "")) / "Programs" / "Ollama" / "ollama.exe"))
    for candidate in candidates:
        if candidate and Path(candidate).is_file():
            return candidate
    raise RuntimeError("Ollama binary not found; install Ollama or pass --ollama /path/to/ollama")


def wait_http(url: str, procs: list[tuple[str, subprocess.Popen]], *, timeout: float = 30) -> None:
    deadline = time.monotonic() + timeout
    with httpx.Client(timeout=1, trust_env=False) as client:
        while time.monotonic() < deadline:
            for name, proc in procs:
                if proc.poll() is not None:
                    raise RuntimeError(f"{name} exited; see logs/{name}.log")
            try:
                if client.get(url).status_code == 200:
                    return
            except httpx.HTTPError:
                pass
            time.sleep(0.25)
    raise RuntimeError(f"service did not become ready: {url}; see logs/")


def main() -> int:
    exe = ".exe" if os.name == "nt" else ""
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--port", type=int, help="HTTPS port (default OPM_HTTPS_PORT from .env, or 443)")
    p.add_argument("--opa", default=str(ROOT / ".tools" / f"opa{exe}"))
    p.add_argument("--caddy", default=str(ROOT / ".tools" / f"caddy{exe}"))
    p.add_argument("--opa-port", type=int, default=8181)
    p.add_argument("--api-port", type=int, default=8000)
    p.add_argument("--with-ollama", action="store_true", help="start/reuse local Ollama and verify model inference + GPU")
    p.add_argument("--with-catalog-admin", action="store_true", help="enable separate host-side catalog review/upload/job API")
    p.add_argument("--catalog-admin-port", type=int, default=8001)
    p.add_argument("--ollama", help="Ollama executable (also checks PATH and the Windows install directory)")
    args = p.parse_args()

    cfg = {**read_env(ROOT / ".env"), **os.environ}
    args.port = args.port if args.port is not None else int(cfg.get("OPM_HTTPS_PORT") or "443")
    token = cfg.get("OPA_AUTH_TOKEN", "")
    if len(token) < 32:
        sys.exit("OPA_AUTH_TOKEN missing in .env (run scripts/bootstrap.py)")
    if args.with_ollama and not cfg.get("OPM_REGINTEL_LLM_MODEL"):
        sys.exit("set OPM_REGINTEL_LLM_MODEL in .env to an installed model (see .env.example)")
    for required in ("deploy/certs/server.crt", "deploy/certs/client-ca.crt", "secrets/api_clients.json"):
        if not (ROOT / required).exists():
            sys.exit(f"missing {required} (run scripts/bootstrap.py)")

    logs = ROOT / "logs"
    logs.mkdir(exist_ok=True)
    (ROOT / "data").mkdir(exist_ok=True)
    base = dict(os.environ)
    # OPM_* settings plus the rule-generation flags (REGINTEL_AUTO_*, DJANGO_CONTRACT.md §5.4)
    passthrough = {k: v for k, v in cfg.items() if k.startswith(("OPM_", "REGINTEL_AUTO_")) and v}

    # Active policy bundle: bundle-store/ACTIVE (written by `python -m regintel bundle-activate`)
    # names an immutable, tested bundle version; without it the base bundle is used.
    # OPA and the API must load the same directory or the API fails closed.
    pointer = ROOT / "bundle-store" / "ACTIVE"
    active = pointer.read_text(encoding="utf-8").strip() if pointer.exists() else ""
    bundle_rel = f"bundle-store/versions/{active}" if active else "policy-bundle"
    if not (ROOT / bundle_rel).is_dir():
        sys.exit(f"active policy bundle directory is missing: {bundle_rel}")
    print(f"policy bundle: {bundle_rel}", flush=True)

    specs = [
        ("opa", [args.opa, "run", "--server", f"--addr=127.0.0.1:{args.opa_port}", "--authentication=token",
                 "--authorization=basic", "--disable-telemetry", "--log-level=info", "--log-format=json",
                 bundle_rel],  # relative on purpose: OPA parses "D:\..." as "<prefix>:<path>"
         {"OPA_AUTH_TOKEN": token}),
        ("api", [sys.executable, "-m", "uvicorn", "app.main:app_factory", "--factory", "--host", "127.0.0.1",
                 "--port", str(args.api_port), "--proxy-headers", "--forwarded-allow-ips", "127.0.0.1",
                 "--no-server-header", "--no-access-log"],
         {**passthrough,
          "OPM_OPA_URL": f"http://127.0.0.1:{args.opa_port}", "OPM_OPA_TOKEN": token,
          "OPM_POLICY_BUNDLE_DIR": str(ROOT / bundle_rel), "OPM_DB_PATH": str(ROOT / "data" / "opm.db"),
          "OPM_CATALOG_DB_PATH": str(ROOT / "data" / "regintel" / "catalog.db"),
          "OPM_API_CLIENTS_FILE": str(ROOT / "secrets" / "api_clients.json")}),
        ("caddy", [args.caddy, "run", "--config", str(ROOT / "deploy" / "Caddyfile"), "--adapter", "caddyfile"],
         {"OPM_CERT_DIR": (ROOT / "deploy" / "certs").as_posix(), "OPM_UPSTREAM": f"127.0.0.1:{args.api_port}",
          "OPM_LISTEN_PORT": str(args.port), "OPM_TLS_SERVER_NAME": cfg.get("OPM_TLS_SERVER_NAME") or "opm.lan",
          "OPM_MAX_BODY_SIZE": cfg.get("OPM_MAX_BODY_SIZE") or "5MB",
          "OPM_CATALOG_ADMIN_UPSTREAM": f"127.0.0.1:{args.catalog_admin_port}"}),
    ]
    if args.with_catalog_admin:
        specs.insert(-1, ("catalog-admin", [sys.executable, "-m", "uvicorn", "regintel.admin_api:app_factory",
            "--factory", "--host", "127.0.0.1", "--port", str(args.catalog_admin_port),
            "--no-server-header", "--no-access-log"],
            {**passthrough, "OPM_CATALOG_DB_PATH": str(ROOT / "data/regintel/catalog.db"),
             "OPM_POLICY_BUNDLE_DIR": str(ROOT / bundle_rel),
             # the evaluator's tenant rule store: activated generated rules (PAM-GEN-*) are written here
             "OPM_DB_PATH": str(ROOT / "data" / "opm.db"),
             "OPM_API_CLIENTS_FILE": str(ROOT / "secrets/api_clients.json")}))
    procs: list[tuple[str, subprocess.Popen]] = []

    def start(name: str, cmd: list[str], env: dict[str, str]) -> None:
        with open(logs / f"{name}.log", "ab") as log:
            proc = subprocess.Popen(cmd, cwd=ROOT, env={**base, **env}, stdout=log, stderr=log,
                                    creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0)
        procs.append((name, proc))
        print(f"started {name} (pid {proc.pid})", flush=True)

    try:
        if args.with_ollama:
            sys.path.insert(0, str(ROOT))
            from regintel.llm import assert_local_endpoint

            url = cfg.get("OPM_REGINTEL_LLM_URL") or "http://127.0.0.1:11434"
            assert_local_endpoint(url)
            try:
                with httpx.Client(timeout=2, trust_env=False) as client:
                    client.get(url.rstrip("/") + "/api/version").raise_for_status()
                print(f"reusing Ollama at {url}", flush=True)
            except httpx.HTTPError:
                parts = urlsplit(url)
                if parts.scheme != "http" or parts.hostname not in ("127.0.0.1", "localhost", "::1"):
                    raise RuntimeError("automatic Ollama startup requires a loopback HTTP endpoint")
                start("ollama", [ollama_binary(args.ollama), "serve"],
                      {"OLLAMA_HOST": parts.netloc, "OLLAMA_NO_CLOUD": "1", "OLLAMA_NUM_PARALLEL": "1"})
                wait_http(url.rstrip("/") + "/api/version", procs)
            print("checking Ollama model and GPU (logs/llm-check.log)...", flush=True)
            with open(logs / "llm-check.log", "ab") as log:
                subprocess.run([sys.executable, "-m", "regintel", "llm-check"], cwd=ROOT,
                               env={**base, **passthrough}, stdout=log, stderr=log, check=True,
                               timeout=float(cfg.get("OPM_REGINTEL_LLM_TIMEOUT") or "600") + 30)
            print("Ollama structured inference and GPU check passed", flush=True)
        for name, cmd, env in specs:
            start(name, cmd, env)
            if name == "api":
                wait_http(f"http://127.0.0.1:{args.api_port}/ready", procs)
            if name == "catalog-admin":
                wait_http(f"http://127.0.0.1:{args.catalog_admin_port}/health", procs)
        # The API is ready; wait until the edge has bound its HTTPS port.
        deadline = time.monotonic() + 10
        import socket
        while True:
            try:
                with socket.create_connection(("127.0.0.1", args.port), timeout=1):
                    break
            except OSError:
                if time.monotonic() >= deadline or procs[-1][1].poll() is not None:
                    raise RuntimeError("Caddy failed to listen; see logs/caddy.log")
                time.sleep(0.25)
        print(f"listening on https://<this-host>:{args.port}  (logs in {logs})", flush=True)
        while True:
            for name, proc in procs:
                code = proc.poll()
                if code is not None:
                    print(f"{name} exited with code {code}; stopping the stack (see logs/{name}.log)", flush=True)
                    return 1
            time.sleep(2)
    except KeyboardInterrupt:
        return 0
    except (RuntimeError, OSError, subprocess.SubprocessError) as exc:
        print(f"startup failed: {exc}; see logs/", file=sys.stderr, flush=True)
        return 1
    finally:
        for _, proc in reversed(procs):
            if proc.poll() is None:
                proc.terminate()
        for _, proc in procs:
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()


if __name__ == "__main__":
    raise SystemExit(main())
