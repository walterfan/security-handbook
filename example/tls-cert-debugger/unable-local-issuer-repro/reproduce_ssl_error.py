#!/usr/bin/env python3
"""
Reproduce requests/urllib3 SSL verification failure caused by a missing
intermediate certificate in the server-presented chain.
"""

import argparse
import ssl
import sys
import traceback
import urllib.error
import urllib.request
from pathlib import Path

try:
    import requests
except Exception:
    requests = None


def parse_args() -> argparse.Namespace:
    base_dir = Path(__file__).resolve().parent / "certs"
    parser = argparse.ArgumentParser(
        description="Reproduce certificate verify failed: unable to get local issuer certificate."
    )
    parser.add_argument(
        "--url",
        default="https://127.0.0.1:4443/api/v1/demo-secret",
        help="Target URL. Defaults to the local demo HTTPS server.",
    )
    parser.add_argument(
        "--verify",
        default=str(base_dir / "root-ca.pem"),
        help="CA bundle passed to requests.verify. Defaults to the generated root CA.",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=5.0,
    )
    parser.add_argument(
        "--expect-success",
        action="store_true",
        help="Expect the HTTPS request to succeed instead of fail.",
    )
    return parser.parse_args()


def https_get(url: str, verify: str, timeout: float):
    if requests:
        response = requests.get(url, verify=verify, timeout=timeout)
        return response.status_code, response.text

    context = ssl.create_default_context(cafile=verify)
    request = urllib.request.Request(url, headers={"User-Agent": "reproduce-ssl-error/1.0"})
    with urllib.request.urlopen(request, context=context, timeout=timeout) as response:
        body = response.read().decode("utf-8", errors="replace")
        return response.status, body


def main() -> int:
    args = parse_args()

    print(f"Connecting to: {args.url}", flush=True)
    print(f"Using CA bundle: {args.verify}", flush=True)

    if args.expect_success:
        print("Expected result: HTTP 200 because the server presents the full chain.", flush=True)
    else:
        print(
            "Expected result: SSLCertVerificationError with 'unable to get local issuer certificate'",
            flush=True,
        )

    try:
        status_code, text = https_get(args.url, args.verify, args.timeout)
        print(f"HTTP {status_code}")
        print(text)
        return 0 if args.expect_success else 1
    except ssl.SSLCertVerificationError as exc:
        print(f"TLS verification failed: {exc}")
        print()
        print("Full traceback:")
        traceback.print_exc(file=sys.stdout)
        return 0 if not args.expect_success else 2
    except urllib.error.URLError as exc:
        if isinstance(exc.reason, ssl.SSLCertVerificationError):
            print(f"TLS verification failed: {exc.reason}")
            print()
            print("Full traceback:")
            traceback.print_exc(file=sys.stdout)
            return 0 if not args.expect_success else 2
        raise
    except Exception as exc:
        print(f"TLS verification failed: {exc}")
        print()
        print("Full traceback:")
        traceback.print_exc(file=sys.stdout)
        return 0 if not args.expect_success else 2


if __name__ == "__main__":
    raise SystemExit(main())
