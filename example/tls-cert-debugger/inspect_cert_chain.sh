#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
usage: inspect_cert_chain.sh <host> [port] [out_dir] [options]

options:
  --proxy <host:port>       Connect through an explicit HTTP CONNECT proxy
  --proxy-user <username>   Optional proxy username
  --proxy-pass <password>   Optional proxy password
  --dry-run                 Print the openssl command without executing it
  --help                    Show this help message
EOF
}

if [[ $# -eq 0 ]]; then
  usage >&2
  exit 1
fi

if [[ "${1}" == "--help" ]]; then
  usage
  exit 0
fi

HOST=""
PORT="443"
OUT_DIR=""
POSITIONAL_INDEX=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --*)
      break
      ;;
    *)
      case "${POSITIONAL_INDEX}" in
        0) HOST="$1" ;;
        1) PORT="$1" ;;
        2) OUT_DIR="$1" ;;
        *)
          echo "unexpected positional argument: $1" >&2
          usage >&2
          exit 1
          ;;
      esac
      POSITIONAL_INDEX=$((POSITIONAL_INDEX + 1))
      shift
      ;;
  esac
done

if [[ -z "${HOST}" ]]; then
  usage >&2
  exit 1
fi

OUT_DIR="${OUT_DIR:-/tmp/${HOST}_cert_inspect}"
PROXY_ADDR=""
PROXY_USER=""
PROXY_PASS=""
DRY_RUN="false"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --proxy)
      PROXY_ADDR="${2:?missing value for --proxy}"
      shift 2
      ;;
    --proxy-user)
      PROXY_USER="${2:?missing value for --proxy-user}"
      shift 2
      ;;
    --proxy-pass)
      PROXY_PASS="${2:?missing value for --proxy-pass}"
      shift 2
      ;;
    --dry-run)
      DRY_RUN="true"
      shift
      ;;
    --help)
      usage
      exit 0
      ;;
    *)
      echo "unknown option: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

if [[ -n "${PROXY_PASS}" && -z "${PROXY_USER}" ]]; then
  echo "--proxy-pass requires --proxy-user" >&2
  exit 1
fi

if [[ (-n "${PROXY_USER}" || -n "${PROXY_PASS}") && -z "${PROXY_ADDR}" ]]; then
  echo "--proxy-user/--proxy-pass require --proxy" >&2
  exit 1
fi

OPENSSL_CMD=(
  openssl s_client
  -connect "${HOST}:${PORT}"
  -servername "${HOST}"
  -showcerts
  -verify_return_error
)

NETWORK_PATH="direct"
if [[ -n "${PROXY_ADDR}" ]]; then
  NETWORK_PATH="proxy-connect"
  OPENSSL_CMD+=(-proxy "${PROXY_ADDR}")
  if [[ -n "${PROXY_USER}" ]]; then
    OPENSSL_CMD+=(-proxy_user "${PROXY_USER}")
    OPENSSL_CMD+=(-proxy_pass "${PROXY_PASS}")
  fi
fi

if [[ "${DRY_RUN}" == "true" ]]; then
  echo "network_path=${NETWORK_PATH}"
  echo "proxy=${PROXY_ADDR:-none}"
  printf 'command='
  printf '%q ' "${OPENSSL_CMD[@]}"
  printf '\n'
  exit 0
fi

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
echo "network_path=${NETWORK_PATH}"
echo "proxy=${PROXY_ADDR:-none}"
"${OPENSSL_CMD[@]}" < /dev/null | tee "${LOG_FILE}"

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
if [[ -n "${PROXY_ADDR}" ]]; then
  echo "- when a proxy is configured, this is the chain presented on the proxy path"
fi
echo "- inspect ${LOG_FILE} for 'Verify return code'"
