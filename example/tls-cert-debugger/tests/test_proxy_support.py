import importlib.util
import socket
import socketserver
import subprocess
import sys
import threading
import unittest
from pathlib import Path


PROJECT_DIR = Path(__file__).resolve().parents[1]
TLS_PROBE_PATH = PROJECT_DIR / "tls_probe.py"
INSPECT_SCRIPT_PATH = PROJECT_DIR / "inspect_cert_chain.sh"


def load_tls_probe_module():
    spec = importlib.util.spec_from_file_location("tls_probe_module", TLS_PROBE_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class EchoHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data = self.request.recv(4096)
        self.request.sendall(b"echo:" + data)


class ConnectProxyHandler(socketserver.StreamRequestHandler):
    def handle(self):
        request_line = self.rfile.readline().decode("iso-8859-1").strip()
        if not request_line.startswith("CONNECT "):
            self.wfile.write(b"HTTP/1.1 405 Method Not Allowed\r\n\r\n")
            return

        target = request_line.split()[1]
        while True:
            header_line = self.rfile.readline()
            if header_line in (b"\r\n", b"\n", b""):
                break

        host, port_text = target.rsplit(":", 1)
        upstream = socket.create_connection((host, int(port_text)))
        self.wfile.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")

        downstream = self.connection

        def pipe(source, dest):
            try:
                while True:
                    chunk = source.recv(4096)
                    if not chunk:
                        break
                    dest.sendall(chunk)
            finally:
                try:
                    dest.shutdown(socket.SHUT_WR)
                except OSError:
                    pass

        thread = threading.Thread(target=pipe, args=(upstream, downstream), daemon=True)
        thread.start()
        pipe(downstream, upstream)
        upstream.close()


class ProxySupportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tls_probe = load_tls_probe_module()

    def test_parse_proxy_url_requires_supported_scheme(self):
        with self.assertRaises(ValueError):
            self.tls_probe.parse_proxy_url("socks5://127.0.0.1:1080")

    def test_open_tunnel_via_connect_proxy_reaches_target(self):
        echo_server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), EchoHandler)
        proxy_server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), ConnectProxyHandler)
        echo_thread = threading.Thread(target=echo_server.serve_forever, daemon=True)
        proxy_thread = threading.Thread(target=proxy_server.serve_forever, daemon=True)
        echo_thread.start()
        proxy_thread.start()

        host, port = echo_server.server_address
        proxy_host, proxy_port = proxy_server.server_address

        try:
            sock = self.tls_probe.open_tunnel(
                host,
                port,
                f"http://{proxy_host}:{proxy_port}",
                3.0,
                None,
            )
            with sock:
                sock.sendall(b"ping")
                self.assertEqual(sock.recv(4096), b"echo:ping")
        finally:
            proxy_server.shutdown()
            echo_server.shutdown()
            proxy_server.server_close()
            echo_server.server_close()

    def test_inspect_cert_chain_help_mentions_proxy_flags(self):
        result = subprocess.run(
            ["bash", str(INSPECT_SCRIPT_PATH), "--help"],
            cwd=PROJECT_DIR,
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0)
        self.assertIn("--proxy", result.stdout)
        self.assertIn("--dry-run", result.stdout)

    def test_inspect_cert_chain_dry_run_prints_proxy_command(self):
        result = subprocess.run(
            [
                "bash",
                str(INSPECT_SCRIPT_PATH),
                "example.com",
                "443",
                "/tmp/out",
                "--proxy",
                "127.0.0.1:8080",
                "--proxy-user",
                "alice",
                "--proxy-pass",
                "secret",
                "--dry-run",
            ],
            cwd=PROJECT_DIR,
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0)
        self.assertIn("-proxy 127.0.0.1:8080", result.stdout)
        self.assertIn("-proxy_user alice", result.stdout)
        self.assertIn("-proxy_pass secret", result.stdout)


if __name__ == "__main__":
    unittest.main()
