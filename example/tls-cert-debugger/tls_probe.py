#!/usr/bin/env python3
"""Diagnose HTTPS certificate chain and CA trust issues from Python's point of view."""

from __future__ import annotations

import argparse
import base64
import os
import pprint
import socket
import ssl
from dataclasses import dataclass
from urllib.parse import quote, urlsplit, urlunsplit

try:
    import requests
except Exception:
    requests = None

try:
    import certifi
except Exception:
    certifi = None


@dataclass(frozen=True)
class ProxyConfig:
    scheme: str
    host: str
    port: int
    username: str | None = None
    password: str | None = None


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
    parser.add_argument(
        "--proxy",
        help="Optional proxy URL, for example http://127.0.0.1:8080 or https://127.0.0.1:8443",
    )
    parser.add_argument("--proxy-user", help="Optional proxy username")
    parser.add_argument("--proxy-pass", help="Optional proxy password")
    return parser.parse_args()


def print_env() -> None:
    print("== Python / CA environment ==")
    print("ssl.get_default_verify_paths():")
    print(ssl.get_default_verify_paths())
    print()

    for name in [
        "SSL_CERT_FILE",
        "SSL_CERT_DIR",
        "REQUESTS_CA_BUNDLE",
        "CURL_CA_BUNDLE",
        "HTTPS_PROXY",
        "https_proxy",
        "HTTP_PROXY",
        "http_proxy",
        "NO_PROXY",
        "no_proxy",
    ]:
        print(f"{name}={os.environ.get(name)}")
    print()

    if certifi:
        print(f"certifi.where()={certifi.where()}")
    else:
        print("certifi.where()=N/A")
    print()


def parse_proxy_url(proxy: str | None) -> ProxyConfig | None:
    if not proxy:
        return None

    normalized = proxy if "://" in proxy else f"http://{proxy}"
    parsed = urlsplit(normalized)
    if parsed.scheme not in {"http", "https"}:
        raise ValueError(f"unsupported proxy scheme: {parsed.scheme}")
    if not parsed.hostname:
        raise ValueError("proxy URL must include a hostname")

    default_port = 443 if parsed.scheme == "https" else 80
    return ProxyConfig(
        scheme=parsed.scheme,
        host=parsed.hostname,
        port=parsed.port or default_port,
        username=parsed.username,
        password=parsed.password,
    )


def resolve_proxy_auth(
    proxy_config: ProxyConfig | None, proxy_user: str | None, proxy_pass: str | None
) -> tuple[str, str] | None:
    if proxy_user is None and proxy_pass is not None:
        raise ValueError("--proxy-pass requires --proxy-user")
    if proxy_config is None:
        if proxy_user or proxy_pass:
            raise ValueError("--proxy-user/--proxy-pass require --proxy")
        return None

    if proxy_user is not None:
        return (proxy_user, proxy_pass or "")
    if proxy_config.username is not None:
        return (proxy_config.username, proxy_config.password or "")
    return None


def format_proxy_url(
    proxy_config: ProxyConfig | None, proxy_auth: tuple[str, str] | None = None
) -> str:
    if proxy_config is None:
        return "none"

    netloc = f"{proxy_config.host}:{proxy_config.port}"
    if proxy_auth is not None:
        user = quote(proxy_auth[0], safe="")
        password = quote(proxy_auth[1], safe="")
        netloc = f"{user}:{password}@{netloc}"

    return urlunsplit((proxy_config.scheme, netloc, "", "", ""))


def read_http_headers(sock: socket.socket) -> bytes:
    data = bytearray()
    while b"\r\n\r\n" not in data:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data.extend(chunk)
        if len(data) > 65536:
            raise OSError("proxy response headers too large")

    if b"\r\n\r\n" not in data:
        raise OSError("proxy response ended before headers completed")
    return bytes(data)


def build_connect_request(
    host: str, port: int, proxy_auth: tuple[str, str] | None
) -> bytes:
    lines = [
        f"CONNECT {host}:{port} HTTP/1.1",
        f"Host: {host}:{port}",
        "Proxy-Connection: Keep-Alive",
    ]
    if proxy_auth is not None:
        token = base64.b64encode(
            f"{proxy_auth[0]}:{proxy_auth[1]}".encode("utf-8")
        ).decode("ascii")
        lines.append(f"Proxy-Authorization: Basic {token}")
    lines.extend(["", ""])
    return "\r\n".join(lines).encode("ascii")


def open_tunnel(
    host: str,
    port: int,
    proxy: str | None,
    timeout: float,
    proxy_auth: tuple[str, str] | None,
) -> socket.socket:
    proxy_config = parse_proxy_url(proxy)
    if proxy_config is None:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.settimeout(timeout)
        return sock

    sock = socket.create_connection((proxy_config.host, proxy_config.port), timeout=timeout)
    sock.settimeout(timeout)
    if proxy_config.scheme == "https":
        proxy_context = ssl.create_default_context()
        sock = proxy_context.wrap_socket(sock, server_hostname=proxy_config.host)
        sock.settimeout(timeout)

    sock.sendall(build_connect_request(host, port, proxy_auth))
    response = read_http_headers(sock)
    status_line = response.split(b"\r\n", 1)[0].decode("iso-8859-1", errors="replace")
    if " 200 " not in f" {status_line} ":
        raise OSError(f"proxy CONNECT failed: {status_line}")
    return sock


def tls_probe(
    host: str,
    port: int,
    path: str,
    cafile: str | None,
    timeout: float,
    proxy_config: ProxyConfig | None,
    proxy_auth: tuple[str, str] | None,
) -> None:
    print("== TLS probe with ssl module ==")
    context = ssl.create_default_context(cafile=cafile)
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED

    with open_tunnel(
        host,
        port,
        format_proxy_url(proxy_config, proxy_auth) if proxy_config else None,
        timeout,
        proxy_auth,
    ) as tcp_sock:
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
            print(f"network_path={'proxy' if proxy_config else 'direct'}")
            print(f"proxy={format_proxy_url(proxy_config)}")
            print(f"tls_version={tls_sock.version()}")
            print(f"cipher={tls_sock.cipher()}")
            print(f"http_response={first_line}")
            print("peer_certificate:")
            pprint.pprint(peer_cert)
            print()


def requests_probe(
    host: str,
    port: int,
    path: str,
    cafile: str | None,
    timeout: float,
    proxy_config: ProxyConfig | None,
    proxy_auth: tuple[str, str] | None,
) -> None:
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
    if proxy_config:
        request_proxy = format_proxy_url(proxy_config, proxy_auth)
        proxies = {"http": request_proxy, "https": request_proxy}
        print("network_path=proxy")
        print(f"proxy={format_proxy_url(proxy_config)}")
        response = requests.get(
            url,
            timeout=timeout,
            verify=verify,
            proxies=proxies,
        )
    else:
        print("network_path=direct")
        print("proxy=none")
        response = requests.get(url, timeout=timeout, verify=verify)
    print(f"status_code={response.status_code}")
    print(f"response_head={response.text[:200]!r}")
    print()


def main() -> int:
    args = parse_args()
    print_env()
    try:
        proxy_config = parse_proxy_url(args.proxy)
        proxy_auth = resolve_proxy_auth(proxy_config, args.proxy_user, args.proxy_pass)
    except ValueError as exc:
        print("== Invalid proxy configuration ==")
        print(exc)
        return 5

    try:
        tls_probe(
            args.host,
            args.port,
            args.path,
            args.cafile,
            args.timeout,
            proxy_config,
            proxy_auth,
        )
    except ssl.SSLCertVerificationError as exc:
        print("== TLS verification failed ==")
        print(f"reason={exc.verify_message}")
        print(f"host={args.host}:{args.port}")
        print(f"cafile={args.cafile}")
        print(f"network_path={'proxy' if proxy_config else 'direct'}")
        print(f"proxy={format_proxy_url(proxy_config)}")
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
            requests_probe(
                args.host,
                args.port,
                args.path,
                args.cafile,
                args.timeout,
                proxy_config,
                proxy_auth,
            )
        except Exception as exc:
            print("== requests error ==")
            print(exc)
            return 4

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
