#!/usr/bin/env python3
"""
Start two local HTTPS servers in sequence and compare:

1. failure case: server sends only the leaf certificate
2. success case: server sends the full certificate chain
"""

import ssl
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

try:
    import requests
except Exception:
    requests = None

from https_server import build_https_server


def run_server(host: str, port: int, certfile: str, keyfile: str):
    httpd = build_https_server(host=host, port=port, certfile=certfile, keyfile=keyfile)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    return httpd, thread


def stop_server(httpd, thread) -> None:
    httpd.shutdown()
    httpd.server_close()
    thread.join(timeout=2)


def https_get(url: str, verify: str, timeout: float):
    if requests:
        response = requests.get(url, timeout=timeout, verify=verify)
        return response.status_code, response.text

    context = ssl.create_default_context(cafile=verify)
    request = urllib.request.Request(url, headers={"User-Agent": "compare-success-vs-failure/1.0"})
    with urllib.request.urlopen(request, context=context, timeout=timeout) as response:
        body = response.read().decode("utf-8", errors="replace")
        return response.status, body


def is_expected_ssl_failure(exc: Exception) -> bool:
    message = str(exc).lower()
    return "unable to get local issuer certificate" in message


def main() -> int:
    base_dir = Path(__file__).resolve().parent / "certs"
    host = "127.0.0.1"
    port = 4443
    url = f"https://{host}:{port}/api/v1/demo-secret"
    root_ca = str(base_dir / "root-ca.pem")
    leaf_cert = str(base_dir / "server.pem")
    fullchain_cert = str(base_dir / "server-fullchain.pem")
    keyfile = str(base_dir / "server.key")

    if not Path(root_ca).exists():
        print("Certificates not found. Run 'bash generate_test_certs.sh' first.")
        return 2

    print("=== Failure case: server presents only the leaf certificate ===")
    httpd, thread = run_server(host, port, leaf_cert, keyfile)
    time.sleep(0.3)
    try:
        https_get(url, root_ca, 5)
        print("Unexpected success: the leaf-only server should have failed verification.")
        return 1
    except ssl.SSLCertVerificationError as exc:
        print(f"Expected SSL error: {exc}")
        if not is_expected_ssl_failure(exc):
            print("The request failed, but not for the expected reason.")
            return 1
    except urllib.error.URLError as exc:
        if not isinstance(exc.reason, ssl.SSLCertVerificationError):
            raise
        print(f"Expected SSL error: {exc.reason}")
        if not is_expected_ssl_failure(exc.reason):
            print("The request failed, but not for the expected reason.")
            return 1
    except Exception as exc:
        if requests and isinstance(exc, requests.exceptions.SSLError):
            print(f"Expected SSL error: {exc}")
            if not is_expected_ssl_failure(exc):
                print("The request failed, but not for the expected reason.")
                return 1
        else:
            raise
    finally:
        stop_server(httpd, thread)

    print()
    print("=== Success case: server presents the full certificate chain ===")
    httpd, thread = run_server(host, port, fullchain_cert, keyfile)
    time.sleep(0.3)
    try:
        status_code, text = https_get(url, root_ca, 5)
        print(f"HTTP {status_code}")
        print(text)
        if status_code != 200:
            print("Unexpected status code in success case.")
            return 1
    except (ssl.SSLError, urllib.error.URLError) as exc:
        print(f"Unexpected TLS failure in success case: {exc}")
        return 1
    finally:
        stop_server(httpd, thread)

    print()
    print("Comparison finished successfully.")
    print("Conclusion:")
    print("- trusting the root CA is not enough when the server omits the intermediate certificate")
    print("- once the server presents the full chain, the same client succeeds")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
