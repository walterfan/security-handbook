# Vault Configuration (ch27: Secrets Management)
#
# Vault manages sensitive data:
#   - Payment gateway API keys
#   - Database credentials
#   - TLS certificates (as backup to SPIRE)
#   - Encryption keys for data at rest
#
# In production, use auto-unseal with AWS KMS or GCP Cloud KMS.

# Storage backend — file for demo, use Consul/Raft in production
storage "file" {
  path = "/vault/data"
}

# Listener — API endpoint
listener "tcp" {
  address     = "0.0.0.0:8200"
  tls_disable = true  # Demo only! Enable TLS in production.
}

# API address
api_addr = "http://vault:8200"

# Disable mlock for Docker
disable_mlock = true

# UI
ui = true

# Audit logging — essential for compliance (ch27)
# Enable after initialization:
#   vault audit enable file file_path=/vault/logs/audit.log
