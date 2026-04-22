#!/usr/bin/env bash
set -euo pipefail

HOST="${1:?usage: inspect_cert_chain.sh <host> [port] [out_dir]}"
PORT="${2:-443}"
OUT_DIR="${3:-/tmp/${HOST}_cert_inspect}"

if ! command -v openssl >/dev/null 2>&1; then
  echo "openssl not found" >&2
  exit 1
fi

if ! command -v python3 >/dev/null 2>&1; then
  echo "python3 not found" >&2
  exit 1
fi

mkdir -p "${OUT_DIR}"
LOG_FILE="${OUT_DIR}/s_client.log"

echo "[1/4] Fetch certificate chain from ${HOST}:${PORT}"
openssl s_client \
  -connect "${HOST}:${PORT}" \
  -servername "${HOST}" \
  -showcerts \
  -verify_return_error < /dev/null | tee "${LOG_FILE}"

echo
echo "[2/4] Split PEM certificates"
python3 - "${HOST}" "${LOG_FILE}" "${OUT_DIR}" <<'PY'
from pathlib import Path
import re
import sys

host = sys.argv[1]
log_file = Path(sys.argv[2])
out_dir = Path(sys.argv[3])
text = log_file.read_text()
matches = re.findall(
    r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
    text,
    re.S,
)
if not matches:
    print("No certificates found in s_client output.", file=sys.stderr)
    raise SystemExit(1)

for i, cert in enumerate(matches, 1):
    out = out_dir / f"{host}-cert-{i}.pem"
    out.write_text(cert + "\n")
    print(out)
PY

echo
echo "[3/4] Print certificate details"
for f in "${OUT_DIR}"/"${HOST}"-cert-*.pem; do
  echo "=================================================="
  echo "FILE: $f"
  openssl x509 -in "$f" -noout \
    -subject \
    -issuer \
    -serial \
    -dates \
    -fingerprint -sha256
  echo
  for ext in \
    subjectAltName \
    authorityKeyIdentifier \
    subjectKeyIdentifier \
    basicConstraints \
    keyUsage \
    extendedKeyUsage \
    authorityInfoAccess; do
    echo "-- extension: ${ext} --"
    openssl x509 -in "$f" -noout -ext "$ext" 2>/dev/null || echo "(not present)"
    echo
  done
done

echo "[4/4] Quick chain hints"
echo "- cert-1 is usually the leaf certificate"
echo "- check whether issuer(cert-1) == subject(cert-2)"
echo "- if intermediate is missing, chain often breaks here"
echo "- servers often do NOT send the root CA; the client is expected to trust it locally"
echo "- inspect ${LOG_FILE} for 'Verify return code'"
