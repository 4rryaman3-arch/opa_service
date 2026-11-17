#!/usr/bin/env python3
"""First-time setup on the OMEN host (idempotent; never overwrites secrets).

  python scripts/bootstrap.py --dns opm.lan --ip 192.168.7.7 \
      --tenant acme --client-cn securden-prod

1. .env from .env.example with a fresh OPA_AUTH_TOKEN (if .env is missing)
2. deploy/certs/: private CA, server cert (SANs), Securden mTLS client cert
3. secrets/api_clients.json with one Securden client (token printed once)
"""

from __future__ import annotations

import argparse
import re
import secrets
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--dns", action="append", default=[])
    p.add_argument("--ip", action="append", default=[])
    p.add_argument("--tenant", action="append", required=True)
    p.add_argument("--client-cn", default="securden-prod")
    p.add_argument("--key-id", default="securden-prod")
    p.add_argument("--scopes", default="evaluate,rules:read,rules:write,rules:admin,metrics:read")
    args = p.parse_args()
    if not args.dns and not args.ip:
        sys.exit("give at least one --dns or --ip for the server certificate")

    env = ROOT / ".env"
    if env.exists():
        print(".env exists - leaving it unchanged")
    else:
        text = (ROOT / ".env.example").read_text(encoding="utf-8")
        text = re.sub(r"^OPA_AUTH_TOKEN=.*$", f"OPA_AUTH_TOKEN={secrets.token_urlsafe(48)}", text, flags=re.M)
        if args.ip:
            text = re.sub(r"^OPM_BIND_ADDRESS=.*$", f"OPM_BIND_ADDRESS={args.ip[0]}", text, flags=re.M)
        if args.dns:
            text = re.sub(r"^OPM_TLS_SERVER_NAME=.*$", f"OPM_TLS_SERVER_NAME={args.dns[0]}", text, flags=re.M)
        env.write_text(text, encoding="utf-8")
        print("wrote .env (OPA token generated)")

    certs = ROOT / "deploy" / "certs"
    if (certs / "server.crt").exists():
        print("deploy/certs/server.crt exists - leaving certificates unchanged")
    else:
        cmd = [sys.executable, str(ROOT / "scripts" / "gen_certs.py"), "--out", str(certs), "--client-cn", args.client_cn]
        for d in args.dns:
            cmd += ["--dns", d]
        for i in args.ip:
            cmd += ["--ip", i]
        subprocess.run(cmd, check=True)

    clients = ROOT / "secrets" / "api_clients.json"
    if clients.exists():
        print("secrets/api_clients.json exists - use scripts/manage_keys.py to add clients")
    else:
        subprocess.run([sys.executable, str(ROOT / "scripts" / "manage_keys.py"), "add", args.key_id,
                        "--tenants", ",".join(args.tenant), "--scopes", args.scopes, "--file", str(clients)],
                       check=True)
    print("\nNext: copy deploy/certs/{ca.crt,client.crt,client.key} and the token to the Securden server,"
          "\nthen move deploy/certs/ca.key OFFLINE and run: docker compose up -d --build")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
