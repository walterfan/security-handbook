# TeamVault API Policy — OPA Rego (ch15, ch16)
#
# Layer 1 authorization: coarse-grained API-level checks
# These run BEFORE the fine-grained OpenFGA checks.
#
# Policies:
#   1. IP allowlist for admin endpoints
#   2. Rate limiting metadata
#   3. Business hours restriction for sensitive operations
#   4. API version enforcement

package teamvault.authz

import rego.v1

# ── Default deny ────────────────────────────────────────

default allow := false

# ── Public endpoints (no auth required) ─────────────────

allow if {
    input.path == "/health"
}

allow if {
    input.path == "/auth/login"
    input.method == "POST"
}

allow if {
    input.path == "/auth/register"
    input.method == "POST"
}

# ── Authenticated API access ────────────────────────────

allow if {
    input.user != null
    not is_admin_endpoint
    not is_blocked_ip
}

# ── Admin endpoints require admin role + IP allowlist ───

allow if {
    is_admin_endpoint
    input.user.role in {"owner", "admin"}
    is_allowed_ip
}

# ── Helper rules ────────────────────────────────────────

is_admin_endpoint if {
    startswith(input.path, "/admin/")
}

is_admin_endpoint if {
    input.path == "/organizations"
    input.method in {"DELETE"}
}

# IP allowlist for admin operations
is_allowed_ip if {
    net.cidr_contains("10.0.0.0/8", input.source_ip)
}

is_allowed_ip if {
    net.cidr_contains("172.16.0.0/12", input.source_ip)
}

is_allowed_ip if {
    input.source_ip == "127.0.0.1"
}

is_allowed_ip if {
    input.source_ip == "::1"
}

is_blocked_ip if {
    input.source_ip in data.blocked_ips
}

# ── Business hours check (for sensitive operations) ─────

is_business_hours if {
    hour := time.clock(time.now_ns())[0]
    hour >= 8
    hour < 22
}

# Sensitive operations (delete, bulk export) only during business hours
allow_sensitive if {
    allow
    is_business_hours
}

# ── Rate limit metadata (informational) ─────────────────
# OPA doesn't enforce rate limits directly, but provides metadata
# for the PEP middleware to enforce.

rate_limit_tier := "standard" if {
    input.user.role == "member"
}

rate_limit_tier := "elevated" if {
    input.user.role in {"admin", "owner"}
}

rate_limit_tier := "unlimited" if {
    input.user.role == "service_account"
}

# ── Audit decision ──────────────────────────────────────

decision := {
    "allow": allow,
    "rate_limit_tier": rate_limit_tier,
    "reasons": reasons,
}

reasons contains "public_endpoint" if {
    input.path in {"/health", "/auth/login", "/auth/register"}
}

reasons contains "authenticated_user" if {
    input.user != null
}

reasons contains "admin_ip_check" if {
    is_admin_endpoint
}

reasons contains "blocked_ip" if {
    is_blocked_ip
}
