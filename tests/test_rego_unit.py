"""Runs the Rego unit tests (policy-tests/) and a strict compile check."""

from __future__ import annotations

import subprocess

import pytest

from .conftest import ROOT, opa_binary

pytestmark = pytest.mark.opa


@pytest.fixture(scope="module")
def opa():
    binary = opa_binary()
    if not binary:
        pytest.skip("OPA binary not available")
    return binary


def test_rego_unit_tests(opa):
    proc = subprocess.run([opa, "test", "-v", "policy-bundle", "policy-tests"], cwd=ROOT,
                          capture_output=True, text=True, timeout=120)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "FAIL" not in proc.stdout


def test_bundle_compiles_strict(opa):
    proc = subprocess.run([opa, "check", "--strict", "policy-bundle"], cwd=ROOT, capture_output=True, text=True)
    assert proc.returncode == 0, proc.stdout + proc.stderr
