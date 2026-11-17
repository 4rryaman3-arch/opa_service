#!/usr/bin/env python3
"""Generate a private PKI for LAN deployment (requires `cryptography`).

Creates, in --out (default deploy/certs):
  ca.crt / ca.key          private root CA (keep ca.key OFFLINE after use)
  server.crt / server.key  Caddy TLS certificate with the given DNS/IP SANs
  client-ca.crt            CA that Caddy trusts for client certs (same root here)
  client.crt / client.key  mTLS client certificate for the Securden server

  python scripts/gen_certs.py --dns opm.lan --ip 192.168.7.7 --client-cn securden-prod

Re-running with an existing ca.key reuses the CA (so issued certs stay
trusted) unless --new-ca is given.
"""

from __future__ import annotations

import argparse
import datetime as dt
import ipaddress
import os
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


def _write_key(path: Path, key) -> None:
    path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def _write_cert(path: Path, cert) -> None:
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))


def _name(cn: str, org: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, org), x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def make_ca(out: Path, org: str, days: int):
    key = ec.generate_private_key(ec.SECP384R1())
    now = dt.datetime.now(dt.timezone.utc)
    name = _name(f"{org} OPM Internal Root CA", org)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5)).not_valid_after(now + dt.timedelta(days=days))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .sign(key, hashes.SHA384())
    )
    _write_key(out / "ca.key", key)
    _write_cert(out / "ca.crt", cert)
    return cert, key


def load_ca(out: Path):
    cert = x509.load_pem_x509_certificate((out / "ca.crt").read_bytes())
    key = serialization.load_pem_private_key((out / "ca.key").read_bytes(), password=None)
    return cert, key


def issue(ca_cert, ca_key, cn: str, org: str, days: int, *, server: bool, dns=(), ips=()):
    key = ec.generate_private_key(ec.SECP256R1())
    now = dt.datetime.now(dt.timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(_name(cn, org)).issuer_name(ca_cert.subject).public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5)).not_valid_after(now + dt.timedelta(days=days))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(True, False, False, False, False, False, False, False, False), critical=True)
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH if server else ExtendedKeyUsageOID.CLIENT_AUTH]),
            critical=False,
        )
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
    )
    sans = [x509.DNSName(d) for d in dns] + [x509.IPAddress(ipaddress.ip_address(i)) for i in ips]
    if server:
        if not sans:
            raise SystemExit("server certificate needs at least one --dns or --ip")
        builder = builder.add_extension(x509.SubjectAlternativeName(sans), critical=False)
    return builder.sign(ca_key, hashes.SHA256()), key


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--out", default="deploy/certs")
    p.add_argument("--org", default="Securden OPM")
    p.add_argument("--dns", action="append", default=[], help="server DNS SAN (repeatable)")
    p.add_argument("--ip", action="append", default=[], help="server IP SAN (repeatable)")
    p.add_argument("--client-cn", action="append", default=[], help="client cert CN (repeatable)")
    p.add_argument("--ca-days", type=int, default=3650)
    p.add_argument("--leaf-days", type=int, default=397)
    p.add_argument("--new-ca", action="store_true")
    args = p.parse_args(argv)

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    if (out / "ca.key").exists() and not args.new_ca:
        ca_cert, ca_key = load_ca(out)
        print("reusing existing CA")
    else:
        ca_cert, ca_key = make_ca(out, args.org, args.ca_days)
        print("created new CA")
    _write_cert(out / "client-ca.crt", ca_cert)

    if args.dns or args.ip:
        cn = (args.dns or args.ip)[0]
        cert, key = issue(ca_cert, ca_key, cn, args.org, args.leaf_days, server=True, dns=args.dns, ips=args.ip)
        _write_cert(out / "server.crt", cert)
        _write_key(out / "server.key", key)
        print(f"server cert: SANs dns={args.dns} ip={args.ip}")
    for cn in args.client_cn:
        cert, key = issue(ca_cert, ca_key, cn, args.org, args.leaf_days, server=False)
        stem = "client" if len(args.client_cn) == 1 else f"client-{cn}"
        _write_cert(out / f"{stem}.crt", cert)
        _write_key(out / f"{stem}.key", key)
        print(f"client cert: CN={cn} -> {stem}.crt")
    print(f"done: {out.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
