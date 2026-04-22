#!/usr/bin/env python3
"""
Diagnose HTTPS certificate chain and CA trust issues from Python's point of view.
"""

from __future__ import annotations

import argparse
import os
import pprint
import socket
import ssl
import sys

try:
    import requests
except Exception:
    requests = None

try:
    import certifi
except Exception:
    certifi = None


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Diagnose HTTPS certificate chain and CA trust issues."
    )
    parser.add_argument("--host", required=True, help="Target HTTPS hostname")
    parser.add_argument("--port", type=int, default=443, help="TCP port, default 443")
    parser.add_argument("--path", default="/", help="HTTP path, default /")
    parser.add_argument(
        "--cafile",
        help="Optional custom PEM CA bundle. If omitted, Python's default trust store is used.",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=5.0,
        help="Socket timeout in seconds, default 5",
    )
    parser.add_argument(
        "--requests-check",
        action="store_true",
        help="Also issue an HTTPS request with requests if available.",
    )
    return parser.parse_args()


def print_env() -> None:
    print("== Python / CA environment ==")
    print("ssl.get_default_verify_paths():")
    print(ssl.get_default_verify_paths())
    print()

    for name in ["SSL_CERT_FILE", "SSL_CERT_DIR", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE"]:
        print(f"{name}={os.environ.get(name)}")
    print()

    if certifi:
        print(f"certifi.where()={certifi.where()}")
    else:
        print("certifi.where()=N/A")
    print()


def tls_probe(host: str, port: int, path: str, cafile: str | None, timeout: float) -> None:
    print("== TLS probe with ssl module ==")
    context = ssl.create_default_context(cafile=cafile)
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED

    with socket.create_connection((host, port), timeout=timeout) as tcp_sock:
        with context.wrap_socket(tcp_sock, server_hostname=host) as tls_sock:
            peer_cert = tls_sock.getpeercert()
            request = (
                f"GET {path} HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                "User-Agent: tls-probe/1.0\r\n"
                "Connection: close\r\n"
                "\r\n"
            )
            tls_sock.sendall(request.encode("ascii"))
            first_line = tls_sock.recv(4096).splitlines()[0].decode(
                "iso-8859-1", errors="replace"
            )

            print("verified=yes")
            print(f"host={host}:{port}")
            print(f"tls_version={tls_sock.version()}")
            print(f"cipher={tls_sock.cipher()}")
            print(f"http_response={first_line}")
            print("peer_certificate:")
            pprint.pprint(peer_cert)
            print()


def requests_probe(host: str, port: int, path: str, cafile: str | None, timeout: float) -> None:
    print("== requests probe ==")
    if not requests:
        print("requests not installed, skipped")
        print()
        return

    if port == 443:
        url = f"https://{host}{path}"
    else:
        url = f"https://{host}:{port}{path}"

    verify = cafile if cafile else True
    print(f"url={url}")
    print(f"verify={verify}")
    response = requests.get(url, timeout=timeout, verify=verify)
    print(f"status_code={response.status_code}")
    print(f"response_head={response.text[:200]!r}")
    print()


def main() -> int:
    args = parse_args()
    print_env()

    try:
        tls_probe(args.host, args.port, args.path, args.cafile, args.timeout)
    except ssl.SSLCertVerificationError as exc:
        print("== TLS verification failed ==")
        print(f"reason={exc.verify_message}")
        print(f"host={args.host}:{args.port}")
        print(f"cafile={args.cafile}")
        return 1
    except ssl.SSLError as exc:
        print("== TLS error ==")
        print(exc)
        return 2
    except OSError as exc:
        print("== Network error ==")
        print(exc)
        return 3

    if args.requests_check:
        try:
            requests_probe(args.host, args.port, args.path, args.cafile, args.timeout)
        except Exception as exc:
            print("== requests error ==")
            print(exc)
            return 4

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
