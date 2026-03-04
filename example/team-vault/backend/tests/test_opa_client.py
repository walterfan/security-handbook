"""Tests for OPA client wrapper (ch15, ch16).

Tests the mock OPA client and OPA input/decision models.
"""

import pytest
import pytest_asyncio

from authz.opa_client import OPAClient, OPAInput, OPADecision

pytestmark = pytest.mark.asyncio


class TestOPAInput:
    """Test OPA input construction."""

    def test_basic_input(self):
        inp = OPAInput(path="/notes", method="GET", source_ip="127.0.0.1")
        assert inp.path == "/notes"
        assert inp.method == "GET"

    def test_input_with_user(self):
        inp = OPAInput(
            path="/admin/users",
            method="DELETE",
            source_ip="10.0.0.5",
            user={"id": "alice", "role": "admin"},
        )
        assert inp.user["role"] == "admin"


class TestOPADecision:
    """Test OPA decision model."""

    def test_allow_decision(self):
        d = OPADecision(allow=True, rate_limit_tier="elevated", reasons=["admin_user"])
        assert d.allow is True
        assert d.rate_limit_tier == "elevated"

    def test_deny_decision(self):
        d = OPADecision(allow=False, reasons=["blocked_ip", "opa_unavailable"])
        assert d.allow is False
        assert "blocked_ip" in d.reasons


class TestMockOPAClient:
    """Test the mock OPA client used in tests."""

    async def test_mock_always_allows(self, mock_authz_clients):
        _, opa = mock_authz_clients
        inp = OPAInput(path="/anything", method="GET")
        decision = await opa.evaluate(inp)
        assert decision.allow is True

    async def test_mock_health(self, mock_authz_clients):
        _, opa = mock_authz_clients
        assert await opa.check_health() is True
