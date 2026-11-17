#!/usr/bin/env python3
"""Manage API client credentials for the OPM service.

The secrets file stores only SHA-256 digests. The full token is printed once
at creation time; store it in the Securden server's secret store.

  python scripts/manage_keys.py add securden-prod --tenants acme,globex \
      --scopes evaluate,rules:read --file secrets/api_clients.json
  python scripts/manage_keys.py list --file secrets/api_clients.json
  python scripts/manage_keys.py disable securden-prod --file secrets/api_clients.json
  python scripts/manage_keys.py opa-token --out secrets/opa_token
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import secrets
import sys
import tempfile
from pathlib import Path

SCOPES = {"evaluate", "rules:read", "rules:write", "rules:admin", "metrics:read", "catalog:read",
          "catalog:operate", "catalog:review", "catalog:publish"}
KEY_ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{2,63}$")
TENANT_RE = re.compile(r"^[a-z0-9][a-z0-9-]{1,62}$")


def _load(path: Path) -> dict:
    if path.exists():
        return json.loads(path.read_text(encoding="utf-8"))
    return {"clients": []}


def _atomic_write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".tmp-")
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(content)
    os.chmod(tmp, 0o640)
    os.replace(tmp, path)


def cmd_add(args) -> int:
    if not KEY_ID_RE.match(args.key_id):
        sys.exit("key_id must match ^[a-z0-9][a-z0-9-]{2,63}$")
    scopes = [s for s in args.scopes.split(",") if s]
    tenants = [t for t in args.tenants.split(",") if t]
    if set(scopes) - SCOPES:
        sys.exit(f"unknown scopes: {sorted(set(scopes) - SCOPES)}")
    if not tenants or any(not TENANT_RE.match(t) for t in tenants):
        sys.exit("tenants must be a comma-separated list matching ^[a-z0-9][a-z0-9-]{1,62}$")
    path = Path(args.file)
    data = _load(path)
    if any(c["key_id"] == args.key_id for c in data["clients"]):
        sys.exit(f"key_id {args.key_id} already exists (use rotate)")
    secret = secrets.token_urlsafe(32)
    data["clients"].append({
        "key_id": args.key_id,
        "secret_sha256": hashlib.sha256(secret.encode()).hexdigest(),
        "tenants": sorted(tenants),
        "scopes": sorted(scopes),
        "enabled": True,
    })
    _atomic_write(path, json.dumps(data, indent=2) + "\n")
    print("Store this token in the Securden server secret store. It is shown only once:")
    print(f"{args.key_id}.{secret}")
    return 0


def cmd_rotate(args) -> int:
    path = Path(args.file)
    data = _load(path)
    for c in data["clients"]:
        if c["key_id"] == args.key_id:
            secret = secrets.token_urlsafe(32)
            c["secret_sha256"] = hashlib.sha256(secret.encode()).hexdigest()
            _atomic_write(path, json.dumps(data, indent=2) + "\n")
            print("New token (restart the api container to load it):")
            print(f"{args.key_id}.{secret}")
            return 0
    sys.exit("key_id not found")


def cmd_set_enabled(args, enabled: bool) -> int:
    path = Path(args.file)
    data = _load(path)
    for c in data["clients"]:
        if c["key_id"] == args.key_id:
            c["enabled"] = enabled
            _atomic_write(path, json.dumps(data, indent=2) + "\n")
            print(f"{args.key_id} enabled={enabled} (restart the api container to apply)")
            return 0
    sys.exit("key_id not found")


def cmd_list(args) -> int:
    for c in _load(Path(args.file))["clients"]:
        print(f"{c['key_id']:30} enabled={c.get('enabled', True)!s:5} tenants={','.join(c['tenants'])} "
              f"scopes={','.join(c['scopes'])}")
    return 0


def cmd_grant_scope(args) -> int:
    scopes = {s for s in args.scopes.split(",") if s}
    if not scopes or scopes - SCOPES:
        sys.exit("provide valid scopes: " + ",".join(sorted(SCOPES)))
    path = Path(args.file)
    data = _load(path)
    for client in data["clients"]:
        if client["key_id"] == args.key_id:
            client["scopes"] = sorted(set(client.get("scopes", [])) | scopes)
            _atomic_write(path, json.dumps(data, indent=2) + "\n")
            print(f"Updated scopes for {args.key_id}; token unchanged. Restart the API to apply.")
            return 0
    sys.exit("key_id not found")


def cmd_opa_token(args) -> int:
    token = secrets.token_urlsafe(48)
    _atomic_write(Path(args.out), token + "\n")
    print(f"wrote {args.out}")
    return 0


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("add")
    a.add_argument("key_id")
    a.add_argument("--tenants", required=True)
    a.add_argument("--scopes", default="evaluate,rules:read")
    a.add_argument("--file", default="secrets/api_clients.json")
    grant = sub.add_parser("grant-scope", help="add permissions without changing the existing token")
    grant.add_argument("key_id")
    grant.add_argument("--scopes", required=True)
    grant.add_argument("--file", default="secrets/api_clients.json")
    for name in ("rotate", "disable", "enable"):
        s = sub.add_parser(name)
        s.add_argument("key_id")
        s.add_argument("--file", default="secrets/api_clients.json")
    ls = sub.add_parser("list")
    ls.add_argument("--file", default="secrets/api_clients.json")
    o = sub.add_parser("opa-token")
    o.add_argument("--out", default="secrets/opa_token")
    args = p.parse_args()
    return {
        "add": cmd_add,
        "grant-scope": cmd_grant_scope,
        "rotate": cmd_rotate,
        "disable": lambda a: cmd_set_enabled(a, False),
        "enable": lambda a: cmd_set_enabled(a, True),
        "list": cmd_list,
        "opa-token": cmd_opa_token,
    }[args.cmd](args)


if __name__ == "__main__":
    raise SystemExit(main())
