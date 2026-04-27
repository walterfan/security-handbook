#!/usr/bin/env python3
"""Compare three local MITM proxy TLS outcomes in one run."""

from __future__ import annotations

import threading
import time
from pathlib import Path

from mitm_https_proxy import build_proxy_server
from origin_https_server import build_origin_server
from reproduce_proxy_ssl_error import reproduce


def run_server(server):
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    time.sleep(0.1)
    return thread


def stop_server(server, thread) -> None:
    server.shutdown()
    server.server_close()
    thread.join(timeout=2)


def run_case(
    label: str,
    certs_dir: Path,
    origin_port: int,
    proxy_mode: str,
    verify_bundle: Path,
    expect_success: bool,
    expected_error_substring: str | None = None,
) -> None:
    print(f"=== {label} ===")
    certfile_name = "proxy-leaf-fullchain.pem" if proxy_mode == "fullchain" else "proxy-leaf.pem"
    proxy = build_proxy_server(
        host="127.0.0.1",
        port=0,
        target_host="127.0.0.1",
        target_port=origin_port,
        certfile=str(certs_dir / certfile_name),
        keyfile=str(certs_dir / "proxy-leaf.key"),
        upstream_cafile=str(certs_dir / "origin-root-ca.pem"),
        mode=proxy_mode,
    )
    proxy_thread = run_server(proxy)
    try:
        proxy_port = proxy.server_address[1]
        exit_code = reproduce(
            url=f"https://127.0.0.1:{origin_port}/api/v1/demo-secret",
            proxy=f"http://127.0.0.1:{proxy_port}",
            verify=str(verify_bundle),
            expect_success=expect_success,
            timeout=5.0,
            expected_error_substring=expected_error_substring,
        )
        if exit_code != 0:
            raise SystemExit(1)
    finally:
        stop_server(proxy, proxy_thread)
    print()


def main() -> int:
    certs_dir = Path(__file__).resolve().parent / "certs"
    required_files = [
        certs_dir / "origin-root-ca.pem",
        certs_dir / "origin-server-fullchain.pem",
        certs_dir / "origin-server.key",
        certs_dir / "proxy-root-ca.pem",
        certs_dir / "proxy-leaf.pem",
        certs_dir / "proxy-leaf-fullchain.pem",
        certs_dir / "proxy-leaf.key",
    ]
    if not all(path.exists() for path in required_files):
        print("Certificates not found. Run 'bash generate_proxy_certs.sh' first.")
        return 2

    origin = build_origin_server(
        host="127.0.0.1",
        port=0,
        certfile=str(certs_dir / "origin-server-fullchain.pem"),
        keyfile=str(certs_dir / "origin-server.key"),
    )
    origin_thread = run_server(origin)
    try:
        origin_port = origin.server_address[1]
        run_case(
            label="Failure case: proxy CA not trusted",
            certs_dir=certs_dir,
            origin_port=origin_port,
            proxy_mode="fullchain",
            verify_bundle=certs_dir / "origin-root-ca.pem",
            expect_success=False,
        )
        run_case(
            label="Failure case: proxy leaf only",
            certs_dir=certs_dir,
            origin_port=origin_port,
            proxy_mode="leaf-only",
            verify_bundle=certs_dir / "proxy-root-ca.pem",
            expect_success=False,
            expected_error_substring="unable to get local issuer certificate",
        )
        run_case(
            label="Success case: proxy full chain",
            certs_dir=certs_dir,
            origin_port=origin_port,
            proxy_mode="fullchain",
            verify_bundle=certs_dir / "proxy-root-ca.pem",
            expect_success=True,
        )
    finally:
        stop_server(origin, origin_thread)

    print("Comparison finished successfully.")
    print("Conclusion:")
    print("- the client can fail before validating the origin when the proxy CA is not trusted")
    print("- even after trusting the proxy root, a proxy that serves only the leaf can still break the chain")
    print("- once the proxy serves the full chain and the client trusts the proxy root, the same request succeeds")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
