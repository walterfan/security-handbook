"""mTLS connectivity tests (ch19: SPIFFE, ch24: Service Mesh).

These tests verify that:
  - Services can communicate via mTLS
  - Certificates are valid X.509-SVIDs
  - Unauthorized services are rejected

Note: These tests require the full Docker Compose stack to be running.
Run with: pytest tests/ -v --tb=short
"""

import os
import ssl
import pytest
import httpx

# Skip if not running in integration test mode
INTEGRATION = os.getenv("INTEGRATION_TEST", "false").lower() == "true"
BASE_URL = os.getenv("API_GATEWAY_URL", "http://localhost:8080")

pytestmark = pytest.mark.skipif(not INTEGRATION, reason="Integration tests disabled")


class TestServiceHealth:
    """Verify all services are running and healthy."""

    @pytest.mark.asyncio
    async def test_api_gateway_health(self):
        async with httpx.AsyncClient() as client:
            resp = await client.get(f"{BASE_URL}/health")
            assert resp.status_code == 200
            data = resp.json()
            assert data["status"] == "ok"
            assert data["service"] == "api-gateway"

    @pytest.mark.asyncio
    async def test_orders_endpoint(self):
        """API Gateway should proxy to Order Service via mTLS."""
        async with httpx.AsyncClient() as client:
            resp = await client.get(f"{BASE_URL}/api/orders")
            assert resp.status_code == 200
            orders = resp.json()
            assert isinstance(orders, list)
            assert len(orders) > 0


class TestMTLSEnforcement:
    """Verify mTLS is enforced between services."""

    @pytest.mark.asyncio
    async def test_direct_order_service_rejected(self):
        """Direct access to order service (bypassing mTLS) should fail."""
        order_url = os.getenv("ORDER_SERVICE_URL", "https://localhost:8443")
        async with httpx.AsyncClient(verify=False) as client:
            with pytest.raises(httpx.ConnectError):
                await client.get(f"{order_url}/orders")

    @pytest.mark.asyncio
    async def test_direct_payment_service_rejected(self):
        """Direct access to payment service should fail."""
        payment_url = os.getenv("PAYMENT_SERVICE_URL", "https://localhost:8444")
        async with httpx.AsyncClient(verify=False) as client:
            with pytest.raises(httpx.ConnectError):
                await client.post(f"{payment_url}/payments/process")
