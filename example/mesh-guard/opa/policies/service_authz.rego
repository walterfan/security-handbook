# Service-to-service authorization policy (ch15: OPA, ch23: Zero Trust)
#
# This policy enforces the principle of least privilege:
# each service can only call the downstream services it needs.
#
# Input:
#   - source_spiffe_id: SPIFFE ID of the calling service
#   - destination_service: name of the target service
#   - method: HTTP method
#   - path: request path
#
# Decision:
#   - allow: boolean
#   - reasons: list of strings explaining the decision

package meshguard.authz

import rego.v1

default decision := {
    "allow": false,
    "reasons": ["no matching policy"]
}

# ── Service Call Graph ──────────────────────────────────
# Defines which services can call which other services.
# This is the "authorization graph" — the core of zero trust.

allowed_calls := {
    # API Gateway → Order Service (read orders)
    {
        "source": "spiffe://mesh-guard/api-gateway",
        "destination": "order-service",
        "methods": ["GET"],
        "paths": ["/orders", "/orders/*"],
    },
    # Order Service → Payment Service (process payments)
    {
        "source": "spiffe://mesh-guard/order-service",
        "destination": "payment-service",
        "methods": ["POST"],
        "paths": ["/payments/process"],
    },
    # Order Service → Payment Service (check status)
    {
        "source": "spiffe://mesh-guard/order-service",
        "destination": "payment-service",
        "methods": ["GET"],
        "paths": ["/payments/*"],
    },
}

# ── Decision Logic ──────────────────────────────────────

decision := result if {
    some call in allowed_calls
    call.source == input.source_spiffe_id
    call.destination == input.destination_service
    input.method in call.methods
    path_matches(input.path, call.paths)
    result := {
        "allow": true,
        "reasons": [sprintf("allowed: %s → %s %s %s", [
            input.source_spiffe_id,
            input.method,
            input.destination_service,
            input.path,
        ])],
    }
}

# ── Health endpoints are always allowed ─────────────────

decision := result if {
    input.path == "/health"
    result := {
        "allow": true,
        "reasons": ["health endpoint always allowed"],
    }
}

# ── Path Matching Helper ────────────────────────────────

path_matches(path, patterns) if {
    some pattern in patterns
    glob.match(pattern, ["/"], path)
}

# ── Audit: log denied requests ──────────────────────────

audit_log := sprintf(
    "AUDIT: %s → %s %s %s | decision: %v",
    [
        input.source_spiffe_id,
        input.method,
        input.destination_service,
        input.path,
        decision.allow,
    ],
)
