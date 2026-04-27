#!/usr/bin/env python3
"""Run the local explicit CONNECT proxy used by the MITM proxy repro."""

from __future__ import annotations

import argparse
import socket
import socketserver
import ssl
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class ProxyConfig:
    target_host: str
    target_port: int
    certfile: str
    keyfile: str
    upstream_cafile: str
    mode: str = "fullchain"


class ReusableTCPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


class MitmProxyHandler(socketserver.StreamRequestHandler):
    def send_proxy_response(self, status_line: str, body: str = "") -> None:
        payload = body.encode("utf-8")
        headers = [
            status_line,
            f"Content-Length: {len(payload)}",
            "Connection: close",
            "",
            "",
        ]
        self.wfile.write("\r\n".join(headers).encode("ascii"))
        if payload:
            self.wfile.write(payload)

    def send_connect_established(self) -> None:
        self.connection.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")

    def discard_headers(self) -> None:
        while True:
            line = self.rfile.readline()
            if line in (b"", b"\r\n", b"\n"):
                return

    def handle(self) -> None:
        request_line = self.rfile.readline().decode("iso-8859-1", errors="replace").strip()
        if not request_line:
            return

        self.discard_headers()

        try:
            host, port = parse_connect_target(request_line)
        except ValueError as exc:
            self.send_proxy_response("HTTP/1.1 405 Method Not Allowed", str(exc))
            return

        if not is_allowed_target(host, port, self.server.proxy_config):
            self.send_proxy_response("HTTP/1.1 403 Forbidden", "Unsupported CONNECT target")
            return

        config = self.server.proxy_config
        self.send_connect_established()

        try:
            with build_server_context(config.certfile, config.keyfile).wrap_socket(
                self.connection, server_side=True
            ) as client_tls:
                with socket.create_connection((config.target_host, config.target_port), timeout=5) as upstream_tcp:
                    with build_client_context(config.upstream_cafile).wrap_socket(
                        upstream_tcp,
                        server_hostname=config.target_host,
                    ) as upstream_tls:
                        relay_single_http_exchange(client_tls, upstream_tls)
        except ssl.SSLError:
            return
        except OSError:
            return


def parse_connect_target(request_line: str) -> tuple[str, int]:
    parts = request_line.split(" ", 2)
    if len(parts) != 3:
        raise ValueError("malformed CONNECT request")

    method, authority, _ = parts
    if method != "CONNECT":
        raise ValueError("only CONNECT is supported")

    if ":" not in authority:
        raise ValueError("CONNECT target must be host:port")

    host, port_text = authority.rsplit(":", 1)
    return host, int(port_text)


def is_allowed_target(host: str, port: int, config: ProxyConfig) -> bool:
    loopback_aliases = {"127.0.0.1", "localhost"}
    host_matches = host == config.target_host or (
        host in loopback_aliases and config.target_host in loopback_aliases
    )
    return host_matches and port == config.target_port


def build_server_context(certfile: str, keyfile: str) -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=certfile, keyfile=keyfile)
    return context


def build_client_context(cafile: str) -> ssl.SSLContext:
    return ssl.create_default_context(cafile=cafile)


def read_http_message(sock: ssl.SSLSocket) -> bytes:
    data = bytearray()
    while b"\r\n\r\n" not in data:
        chunk = sock.recv(4096)
        if not chunk:
            raise OSError("connection closed before HTTP headers completed")
        data.extend(chunk)

    header_end = data.index(b"\r\n\r\n")
    headers = bytes(data[:header_end])
    body = bytearray(data[header_end + 4 :])
    content_length = 0

    for line in headers.split(b"\r\n")[1:]:
        if line.lower().startswith(b"content-length:"):
            content_length = int(line.split(b":", 1)[1].strip())
            break

    while len(body) < content_length:
        chunk = sock.recv(4096)
        if not chunk:
            raise OSError("connection closed before HTTP body completed")
        body.extend(chunk)

    return headers + b"\r\n\r\n" + body


def relay_single_http_exchange(client_tls: ssl.SSLSocket, upstream_tls: ssl.SSLSocket) -> None:
    request_bytes = read_http_message(client_tls)
    upstream_tls.sendall(request_bytes)
    response_bytes = read_http_message(upstream_tls)
    client_tls.sendall(response_bytes)


def build_proxy_server(
    host: str,
    port: int,
    target_host: str,
    target_port: int,
    certfile: str,
    keyfile: str,
    upstream_cafile: str,
    mode: str = "fullchain",
) -> ReusableTCPServer:
    server = ReusableTCPServer((host, port), MitmProxyHandler)
    server.proxy_config = ProxyConfig(
        target_host=target_host,
        target_port=target_port,
        certfile=certfile,
        keyfile=keyfile,
        upstream_cafile=upstream_cafile,
        mode=mode,
    )
    return server


def parse_args() -> argparse.Namespace:
    certs_dir = Path(__file__).resolve().parent / "certs"
    parser = argparse.ArgumentParser(description="Run the local MITM demo proxy.")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8081)
    parser.add_argument("--target-host", default="127.0.0.1")
    parser.add_argument("--target-port", type=int, default=4443)
    parser.add_argument("--certfile", default=str(certs_dir / "proxy-leaf-fullchain.pem"))
    parser.add_argument("--keyfile", default=str(certs_dir / "proxy-leaf.key"))
    parser.add_argument("--upstream-cafile", default=str(certs_dir / "origin-root-ca.pem"))
    parser.add_argument(
        "--mode",
        choices=["leaf-only", "fullchain"],
        default="fullchain",
        help="Certificate presentation mode for downstream clients.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    server = build_proxy_server(
        host=args.host,
        port=args.port,
        target_host=args.target_host,
        target_port=args.target_port,
        certfile=args.certfile,
        keyfile=args.keyfile,
        upstream_cafile=args.upstream_cafile,
        mode=args.mode,
    )
    print(f"Serving MITM proxy on {args.host}:{args.port}")
    print(f"Allowed CONNECT target: {args.target_host}:{args.target_port}")
    print(f"Presentation mode: {args.mode}")
    server.serve_forever()


if __name__ == "__main__":
    main()
