#!/usr/bin/env python3
"""
Run a local HTTPS server for reproducing certificate chain validation failures.

Default behavior:
- present only the leaf certificate
- client trusts the root CA
- validation fails because the intermediate CA is missing from the served chain
"""

from __future__ import annotations

import argparse
import json
import ssl
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path


class ReusableHTTPServer(HTTPServer):
    allow_reuse_address = True


class DemoHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        if self.path.startswith("/api/v1/demo-secret"):
            payload = {
                "success": True,
                "message": "demo response",
                "items": [],
            }
            body = json.dumps(payload).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        if self.path.startswith("/healthz"):
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")
            return

        self.send_response(404)
        self.end_headers()

    def log_message(self, format: str, *args) -> None:
        print(f"{self.address_string()} - {format % args}")


def parse_args() -> argparse.Namespace:
    base_dir = Path(__file__).resolve().parent / "certs"
    parser = argparse.ArgumentParser(description="Run the local repro HTTPS server.")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=4443)
    parser.add_argument(
        "--certfile",
        default=str(base_dir / "server.pem"),
        help="TLS cert to present. Defaults to the leaf cert only.",
    )
    parser.add_argument(
        "--keyfile",
        default=str(base_dir / "server.key"),
        help="Private key for the TLS certificate.",
    )
    return parser.parse_args()


def build_https_server(host: str, port: int, certfile: str, keyfile: str) -> HTTPServer:
    httpd = ReusableHTTPServer((host, port), DemoHandler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=certfile, keyfile=keyfile)
    httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
    return httpd


def main() -> None:
    args = parse_args()

    httpd = build_https_server(
        host=args.host,
        port=args.port,
        certfile=args.certfile,
        keyfile=args.keyfile,
    )

    print(f"Serving HTTPS on https://{args.host}:{args.port}")
    print(f"Presented cert file: {args.certfile}")
    httpd.serve_forever()


if __name__ == "__main__":
    main()
