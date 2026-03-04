#!/usr/bin/env bash
# ============================================================================
# Certificate Generation Script for SecureNote
#
# Demonstrates ch03 (PKI & X.509) and ch06 (TLS):
#   - Self-signed Root CA
#   - Server certificate (for HTTPS)
#   - Client certificate (for mTLS)
#   - RSA key pair for JWT RS256 signing
#
# Usage:
#   cd backend/certs && ./generate_certs.sh
#
# Output:
#   ca.key / ca.crt           — Root CA key pair
#   server.key / server.crt   — Server TLS certificate
#   client.key / client.crt   — Client mTLS certificate
#   jwt_private.pem / jwt_public.pem — JWT RS256 key pair
# ============================================================================

set -euo pipefail

DAYS=365
COUNTRY="CN"
STATE="Anhui"
CITY="Hefei"
ORG="SecureNote Demo"
CA_CN="SecureNote Root CA"
SERVER_CN="localhost"
CLIENT_CN="securenote-client"

echo "=== Step 1: Generate Root CA (ch03: Certificate Authority) ==="
openssl genrsa -out ca.key 4096
openssl req -new -x509 -days $DAYS -key ca.key -out ca.crt \
    -subj "/C=$COUNTRY/ST=$STATE/L=$CITY/O=$ORG/CN=$CA_CN"
echo "✓ Root CA created: ca.key, ca.crt"

echo ""
echo "=== Step 2: Generate Server Certificate (ch06: TLS) ==="
# Create server key and CSR
openssl genrsa -out server.key 2048
openssl req -new -key server.key -out server.csr \
    -subj "/C=$COUNTRY/ST=$STATE/L=$CITY/O=$ORG/CN=$SERVER_CN"

# Create SAN extension config (required for modern browsers)
cat > server_ext.cnf <<EOF
[v3_req]
subjectAltName = @alt_names
[alt_names]
DNS.1 = localhost
DNS.2 = *.localhost
IP.1 = 127.0.0.1
IP.2 = ::1
EOF

# Sign with CA
openssl x509 -req -days $DAYS -in server.csr -CA ca.crt -CAkey ca.key \
    -CAcreateserial -out server.crt -extfile server_ext.cnf -extensions v3_req
echo "✓ Server certificate created: server.key, server.crt"

echo ""
echo "=== Step 3: Generate Client Certificate (ch06: mTLS) ==="
openssl genrsa -out client.key 2048
openssl req -new -key client.key -out client.csr \
    -subj "/C=$COUNTRY/ST=$STATE/L=$CITY/O=$ORG/CN=$CLIENT_CN"
openssl x509 -req -days $DAYS -in client.csr -CA ca.crt -CAkey ca.key \
    -CAcreateserial -out client.crt
echo "✓ Client certificate created: client.key, client.crt"

echo ""
echo "=== Step 4: Generate JWT RS256 Key Pair (ch09: JWT) ==="
openssl genrsa -out jwt_private.pem 2048
openssl rsa -in jwt_private.pem -pubout -out jwt_public.pem
echo "✓ JWT key pair created: jwt_private.pem, jwt_public.pem"

echo ""
echo "=== Step 5: Verify Certificate Chain ==="
openssl verify -CAfile ca.crt server.crt
openssl verify -CAfile ca.crt client.crt

echo ""
echo "=== Step 6: Display Certificate Info ==="
echo "--- CA Certificate ---"
openssl x509 -in ca.crt -noout -subject -issuer -dates
echo ""
echo "--- Server Certificate ---"
openssl x509 -in server.crt -noout -subject -issuer -dates -ext subjectAltName
echo ""
echo "--- Client Certificate ---"
openssl x509 -in client.crt -noout -subject -issuer -dates

# Cleanup CSR and temp files
rm -f server.csr client.csr server_ext.cnf ca.srl

echo ""
echo "=== All certificates generated successfully! ==="
echo ""
echo "To test mTLS with curl:"
echo "  curl --cacert ca.crt --cert client.crt --key client.key https://localhost:8000/health"
