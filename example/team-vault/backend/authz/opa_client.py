"""OPA (Open Policy Agent) client for coarse-grained API authorization.

Demonstrates ch15 (OPA) and ch16 (Policy as Code):
  - REST API integration with OPA
  - Policy evaluation with input context
  - Decision logging for audit

OPA evaluates Rego policies (see opa/policies/api_policy.rego).
It handles Layer 1 authorization:
  - IP allowlist for admin endpoints
  - Rate limiting tier assignment
  - Business hours enforcement
"""

import logging
from dataclasses import dataclass, field

import httpx

from config import settings

logger = logging.getLogger(__name__)


@dataclass
class OPAInput:
    """Input context sent to OPA for policy evaluation."""
    path: str
    method: str
    source_ip: str = "127.0.0.1"
    user: dict | None = None  # {"id": "...", "role": "member", ...}
    headers: dict = field(default_factory=dict)
    timestamp: str = ""


@dataclass
class OPADecision:
    """Decision returned by OPA."""
    allow: bool
    rate_limit_tier: str = "standard"
    reasons: list[str] = field(default_factory=list)
    raw: dict = field(default_factory=dict)


class OPAClient:
    """Async client for OPA REST API.

    Sends authorization queries to OPA and interprets decisions.
    OPA runs as a sidecar or standalone service.
    """

    def __init__(self, opa_url: str | None = None, policy_path: str | None = None):
        self.opa_url = (opa_url or settings.opa_url).rstrip("/")
        self.policy_path = policy_path or settings.opa_policy_path

    async def evaluate(self, input_data: OPAInput) -> OPADecision:
        """Evaluate a policy with the given input.

        Sends a POST to OPA's Data API:
            POST /v1/data/teamvault/authz/decision
            {"input": {...}}

        Returns:
            OPADecision with allow/deny and metadata
        """
        url = f"{self.opa_url}{self.policy_path}"
        payload = {
            "input": {
                "path": input_data.path,
                "method": input_data.method,
                "source_ip": input_data.source_ip,
                "user": input_data.user,
                "headers": input_data.headers,
                "timestamp": input_data.timestamp,
            }
        }

        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.post(url, json=payload)
                resp.raise_for_status()
                result = resp.json().get("result", {})

                decision = OPADecision(
                    allow=result.get("allow", False),
                    rate_limit_tier=result.get("rate_limit_tier", "standard"),
                    reasons=result.get("reasons", []),
                    raw=result,
                )

                logger.info(
                    f"OPA decision: {input_data.method} {input_data.path} "
                    f"→ {'ALLOW' if decision.allow else 'DENY'} "
                    f"(reasons: {decision.reasons})"
                )
                return decision

        except httpx.HTTPError as e:
            logger.error(f"OPA evaluation failed: {e}")
            # Fail-closed: deny on OPA error
            return OPADecision(
                allow=False,
                reasons=["opa_unavailable"],
                raw={"error": str(e)},
            )

    async def check_health(self) -> bool:
        """Check if OPA is healthy."""
        try:
            async with httpx.AsyncClient(timeout=3.0) as client:
                resp = await client.get(f"{self.opa_url}/health")
                return resp.status_code == 200
        except httpx.HTTPError:
            return False


# ── Singleton ───────────────────────────────────────────

_opa_client: OPAClient | None = None


def get_opa_client() -> OPAClient:
    """Get or create the OPA client singleton."""
    global _opa_client
    if _opa_client is None:
        _opa_client = OPAClient()
    return _opa_client
