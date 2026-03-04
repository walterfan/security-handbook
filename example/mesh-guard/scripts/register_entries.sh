#!/bin/bash
# Register SPIRE workload entries (ch20: SPIRE)
#
# Each entry maps a workload selector to a SPIFFE ID.
# When a workload connects to the SPIRE Agent's Workload API,
# the agent uses these selectors to determine which SVID to issue.
#
# Usage: ./register_entries.sh

set -euo pipefail

SPIRE_SERVER="docker-compose exec spire-server /opt/spire/bin/spire-server"

echo "=== Registering SPIRE workload entries ==="

# 1. Create a join token for the agent
echo "[1/4] Creating agent join token..."
JOIN_TOKEN=$($SPIRE_SERVER token generate -spiffeID spiffe://mesh-guard/agent -ttl 3600 | awk '{print $2}')
echo "  Token: ${JOIN_TOKEN:0:8}..."

# 2. Register API Gateway
echo "[2/4] Registering API Gateway..."
$SPIRE_SERVER entry create \
    -spiffeID spiffe://mesh-guard/api-gateway \
    -parentID spiffe://mesh-guard/agent \
    -selector docker:label:app:api-gateway \
    -ttl 3600

# 3. Register Order Service
echo "[3/4] Registering Order Service..."
$SPIRE_SERVER entry create \
    -spiffeID spiffe://mesh-guard/order-service \
    -parentID spiffe://mesh-guard/agent \
    -selector docker:label:app:order-service \
    -ttl 3600

# 4. Register Payment Service
echo "[4/4] Registering Payment Service..."
$SPIRE_SERVER entry create \
    -spiffeID spiffe://mesh-guard/payment-service \
    -parentID spiffe://mesh-guard/agent \
    -selector docker:label:app:payment-service \
    -ttl 3600

echo ""
echo "=== All entries registered ==="
echo ""
echo "Verify with:"
echo "  $SPIRE_SERVER entry show"
echo ""
echo "SPIFFE IDs:"
echo "  spiffe://mesh-guard/api-gateway"
echo "  spiffe://mesh-guard/order-service"
echo "  spiffe://mesh-guard/payment-service"
