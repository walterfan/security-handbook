#!/usr/bin/env bash
set -euo pipefail

BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CERTS_DIR="${BASE_DIR}/certs"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/mitm-proxy-certs.XXXXXX")"

cleanup() {
  rm -rf "${TMP_DIR}"
}
trap cleanup EXIT

if ! command -v openssl >/dev/null 2>&1; then
  echo "openssl not found" >&2
  exit 1
fi

rm -rf "${CERTS_DIR}"
mkdir -p "${CERTS_DIR}"

write_intermediate_ext() {
  local path="$1"
  cat >"${path}" <<'EOF'
basicConstraints=critical,CA:TRUE,pathlen:0
keyUsage=critical,keyCertSign,cRLSign
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
EOF
}

write_server_ext() {
  local path="$1"
  cat >"${path}" <<'EOF'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=IP:127.0.0.1,DNS:localhost
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
EOF
}

generate_root_ca() {
  local prefix="$1"
  local subject="$2"
  openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout "${CERTS_DIR}/${prefix}.key" \
    -out "${CERTS_DIR}/${prefix}.pem" \
    -days 3650 \
    -sha256 \
    -subj "${subject}" \
    -addext "basicConstraints=critical,CA:TRUE,pathlen:1" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -addext "subjectKeyIdentifier=hash" >/dev/null 2>&1
}

generate_intermediate_ca() {
  local prefix="$1"
  local subject="$2"
  local parent_prefix="$3"
  local csr_path="${TMP_DIR}/${prefix}.csr"
  local ext_path="${TMP_DIR}/${prefix}.ext"

  write_intermediate_ext "${ext_path}"
  openssl req -newkey rsa:2048 -nodes \
    -keyout "${CERTS_DIR}/${prefix}.key" \
    -out "${csr_path}" \
    -sha256 \
    -subj "${subject}" >/dev/null 2>&1

  openssl x509 -req \
    -in "${csr_path}" \
    -CA "${CERTS_DIR}/${parent_prefix}.pem" \
    -CAkey "${CERTS_DIR}/${parent_prefix}.key" \
    -CAcreateserial \
    -out "${CERTS_DIR}/${prefix}.pem" \
    -days 1825 \
    -sha256 \
    -extfile "${ext_path}" >/dev/null 2>&1
}

generate_server_cert() {
  local prefix="$1"
  local subject="$2"
  local parent_prefix="$3"
  local csr_path="${TMP_DIR}/${prefix}.csr"
  local ext_path="${TMP_DIR}/${prefix}.ext"

  write_server_ext "${ext_path}"
  openssl req -newkey rsa:2048 -nodes \
    -keyout "${CERTS_DIR}/${prefix}.key" \
    -out "${csr_path}" \
    -sha256 \
    -subj "${subject}" >/dev/null 2>&1

  openssl x509 -req \
    -in "${csr_path}" \
    -CA "${CERTS_DIR}/${parent_prefix}.pem" \
    -CAkey "${CERTS_DIR}/${parent_prefix}.key" \
    -CAcreateserial \
    -out "${CERTS_DIR}/${prefix}.pem" \
    -days 825 \
    -sha256 \
    -extfile "${ext_path}" >/dev/null 2>&1
}

generate_root_ca "origin-root-ca" "/CN=Local Origin Root CA"
generate_intermediate_ca "origin-intermediate-ca" "/CN=Local Origin Intermediate CA" "origin-root-ca"
generate_server_cert "origin-server" "/CN=127.0.0.1" "origin-intermediate-ca"

generate_root_ca "proxy-root-ca" "/CN=Local Proxy Root CA"
generate_intermediate_ca "proxy-intermediate-ca" "/CN=Local Proxy Intermediate CA" "proxy-root-ca"
generate_server_cert "proxy-leaf" "/CN=127.0.0.1" "proxy-intermediate-ca"

cat "${CERTS_DIR}/origin-server.pem" "${CERTS_DIR}/origin-intermediate-ca.pem" > "${CERTS_DIR}/origin-server-fullchain.pem"
cat "${CERTS_DIR}/proxy-leaf.pem" "${CERTS_DIR}/proxy-intermediate-ca.pem" > "${CERTS_DIR}/proxy-leaf-fullchain.pem"

echo "Generated certificate artifacts in ${CERTS_DIR}:"
printf '%s\n' \
  "origin-root-ca.pem" \
  "origin-intermediate-ca.pem" \
  "origin-server.pem" \
  "origin-server-fullchain.pem" \
  "origin-server.key" \
  "proxy-root-ca.pem" \
  "proxy-intermediate-ca.pem" \
  "proxy-leaf.pem" \
  "proxy-leaf-fullchain.pem" \
  "proxy-leaf.key"
