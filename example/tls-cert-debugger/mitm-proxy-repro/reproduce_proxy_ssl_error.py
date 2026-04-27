#!/usr/bin/env python3
"""Reproduce TLS verification failures caused by an explicit MITM proxy."""

from __future__ import annotations

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


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    certs_dir = Path(__file__).resolve().parent / "certs"
    parser = argparse.ArgumentParser(
        description="Reproduce proxy-caused TLS verification failures."
    )
    parser.add_argument(
        "--url",
        default="https://127.0.0.1:4443/api/v1/demo-secret",
        help="Target origin URL reached through the explicit proxy.",
    )
    parser.add_argument(
        "--proxy",
        default="http://127.0.0.1:8081",
        help="Explicit HTTP proxy URL.",
    )
    parser.add_argument(
        "--verify",
        default=str(certs_dir / "proxy-root-ca.pem"),
        help="CA bundle used to verify the proxy-presented chain.",
    )
    parser.add_argument("--timeout", type=float, default=5.0)
    parser.add_argument(
        "--expect-success",
        action="store_true",
        help="Expect the request to succeed instead of fail TLS verification.",
    )
    parser.add_argument(
        "--expect-error-substring",
        help="Optional substring that must appear in the TLS failure message.",
    )
    return parser.parse_args(argv)


def https_get_via_proxy(url: str, proxy: str, verify: str, timeout: float):
    if requests:
        session = requests.Session()
        session.trust_env = False
        response = session.get(
            url,
            proxies={"http": proxy, "https": proxy},
            verify=verify,
            timeout=timeout,
        )
        return response.status_code, response.text

    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({"http": proxy, "https": proxy}),
        urllib.request.HTTPSHandler(context=ssl.create_default_context(cafile=verify)),
    )
    request = urllib.request.Request(url, headers={"User-Agent": "mitm-proxy-repro/1.0"})
    with opener.open(request, timeout=timeout) as response:
        body = response.read().decode("utf-8", errors="replace")
        return response.status, body


def error_matches(exc: Exception, expected_error_substring: str | None) -> bool:
    if not expected_error_substring:
        return True
    return expected_error_substring.lower() in str(exc).lower()


def reproduce(
    url: str,
    proxy: str,
    verify: str,
    expect_success: bool,
    timeout: float,
    expected_error_substring: str | None = None,
) -> int:
    print(f"Connecting to: {url}", flush=True)
    print(f"Using explicit proxy: {proxy}", flush=True)
    print(f"Using CA bundle: {verify}", flush=True)

    if expect_success:
        print("Expected result: HTTP 200 because the proxy chain is trusted and complete.", flush=True)
    else:
        print("Expected result: TLS verification failure on the proxy-presented chain.", flush=True)

    try:
        status_code, text = https_get_via_proxy(url, proxy, verify, timeout)
        print(f"HTTP {status_code}")
        print(text)
        return 0 if expect_success else 1
    except ssl.SSLCertVerificationError as exc:
        print(f"TLS verification failed: {exc}")
        print()
        print("Full traceback:")
        traceback.print_exc(file=sys.stdout)
        return 0 if (not expect_success and error_matches(exc, expected_error_substring)) else 2
    except urllib.error.URLError as exc:
        if isinstance(exc.reason, ssl.SSLCertVerificationError):
            print(f"TLS verification failed: {exc.reason}")
            print()
            print("Full traceback:")
            traceback.print_exc(file=sys.stdout)
            return 0 if (not expect_success and error_matches(exc.reason, expected_error_substring)) else 2
        raise
    except Exception as exc:
        if requests and isinstance(exc, requests.exceptions.SSLError):
            print(f"TLS verification failed: {exc}")
            print()
            print("Full traceback:")
            traceback.print_exc(file=sys.stdout)
            return 0 if (not expect_success and error_matches(exc, expected_error_substring)) else 2
        print(f"Request failed unexpectedly: {exc}")
        print()
        print("Full traceback:")
        traceback.print_exc(file=sys.stdout)
        return 3


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    return reproduce(
        url=args.url,
        proxy=args.proxy,
        verify=args.verify,
        expect_success=args.expect_success,
        timeout=args.timeout,
        expected_error_substring=args.expect_error_substring,
    )


if __name__ == "__main__":
    raise SystemExit(main())
