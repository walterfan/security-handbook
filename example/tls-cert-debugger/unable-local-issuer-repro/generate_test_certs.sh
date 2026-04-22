#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CERT_DIR="${SCRIPT_DIR}/certs"

rm -rf "${CERT_DIR}"
mkdir -p "${CERT_DIR}"

cat > "${CERT_DIR}/root_ca_ext.cnf" <<'EOF'
[v3_ca]
basicConstraints = critical, CA:true, pathlen:1
keyUsage = critical, digitalSignature, cRLSign, keyCertSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
EOF

cat > "${CERT_DIR}/intermediate_ca_ext.cnf" <<'EOF'
[v3_intermediate_ca]
basicConstraints = critical, CA:true, pathlen:0
keyUsage = critical, digitalSignature, cRLSign, keyCertSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
EOF

cat > "${CERT_DIR}/server_ext.cnf" <<'EOF'
[v3_server]
basicConstraints = critical, CA:false
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer

[alt_names]
DNS.1 = localhost
IP.1 = 127.0.0.1
EOF

openssl req -x509 -newkey rsa:2048 -sha256 -nodes \
  -days 3650 \
  -subj "/C=US/ST=CA/L=San Jose/O=Demo Root CA/CN=Demo Root CA" \
  -keyout "${CERT_DIR}/root-ca.key" \
  -out "${CERT_DIR}/root-ca.pem" \
  -extensions v3_ca \
  -config "${CERT_DIR}/root_ca_ext.cnf"

openssl req -new -newkey rsa:2048 -sha256 -nodes \
  -subj "/C=US/ST=CA/L=San Jose/O=Demo Intermediate CA/CN=Demo Intermediate CA" \
  -keyout "${CERT_DIR}/intermediate-ca.key" \
  -out "${CERT_DIR}/intermediate-ca.csr"

openssl x509 -req -sha256 -days 1825 \
  -in "${CERT_DIR}/intermediate-ca.csr" \
  -CA "${CERT_DIR}/root-ca.pem" \
  -CAkey "${CERT_DIR}/root-ca.key" \
  -CAcreateserial \
  -out "${CERT_DIR}/intermediate-ca.pem" \
  -extensions v3_intermediate_ca \
  -extfile "${CERT_DIR}/intermediate_ca_ext.cnf"

openssl req -new -newkey rsa:2048 -sha256 -nodes \
  -subj "/C=US/ST=CA/L=San Jose/O=Demo Server/CN=localhost" \
  -keyout "${CERT_DIR}/server.key" \
  -out "${CERT_DIR}/server.csr"

openssl x509 -req -sha256 -days 825 \
  -in "${CERT_DIR}/server.csr" \
  -CA "${CERT_DIR}/intermediate-ca.pem" \
  -CAkey "${CERT_DIR}/intermediate-ca.key" \
  -CAcreateserial \
  -out "${CERT_DIR}/server.pem" \
  -extensions v3_server \
  -extfile "${CERT_DIR}/server_ext.cnf"

cat "${CERT_DIR}/server.pem" "${CERT_DIR}/intermediate-ca.pem" > "${CERT_DIR}/server-fullchain.pem"

echo "Generated test certificates in ${CERT_DIR}"
echo "Root CA: ${CERT_DIR}/root-ca.pem"
echo "Intermediate CA: ${CERT_DIR}/intermediate-ca.pem"
echo "Leaf server cert: ${CERT_DIR}/server.pem"
echo "Full chain: ${CERT_DIR}/server-fullchain.pem"
