import contextlib
import io
import importlib.util
import shutil
import socket
import subprocess
import sys
import threading
import unittest
import urllib.request
import ssl
from pathlib import Path


class MitmProxyReproTests(unittest.TestCase):
    def setUp(self) -> None:
        self.project_dir = Path(__file__).resolve().parents[1]
        self.repro_dir = self.project_dir / "mitm-proxy-repro"
        self.certs_dir = self.repro_dir / "certs"

    def load_module(self, filename: str, module_name: str):
        module_path = self.repro_dir / filename
        spec = importlib.util.spec_from_file_location(module_name, module_path)
        module = importlib.util.module_from_spec(spec)
        assert spec.loader is not None
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        return module

    def start_server(self, server):
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        return thread

    def stop_server(self, server, thread) -> None:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)

    def test_generate_proxy_certs_creates_expected_files(self):
        if self.certs_dir.exists():
            shutil.rmtree(self.certs_dir)

        result = subprocess.run(
            ["bash", str(self.repro_dir / "generate_proxy_certs.sh")],
            cwd=self.repro_dir,
            check=False,
            capture_output=True,
            text=True,
        )

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        expected = {
            "origin-root-ca.pem",
            "origin-intermediate-ca.pem",
            "origin-server.pem",
            "origin-server-fullchain.pem",
            "origin-server.key",
            "proxy-root-ca.pem",
            "proxy-intermediate-ca.pem",
            "proxy-leaf.pem",
            "proxy-leaf-fullchain.pem",
            "proxy-leaf.key",
        }
        actual = {path.name for path in self.certs_dir.iterdir()}
        self.assertTrue(expected.issubset(actual))

    def test_origin_server_serves_demo_json(self):
        if not self.certs_dir.exists():
            subprocess.run(
                ["bash", str(self.repro_dir / "generate_proxy_certs.sh")],
                cwd=self.repro_dir,
                check=True,
                capture_output=True,
                text=True,
            )

        origin_module = self.load_module("origin_https_server.py", "mitm_origin_https_server")
        origin = origin_module.build_origin_server(
            host="127.0.0.1",
            port=0,
            certfile=str(self.certs_dir / "origin-server-fullchain.pem"),
            keyfile=str(self.certs_dir / "origin-server.key"),
        )
        thread = self.start_server(origin)
        try:
            port = origin.server_address[1]
            context = ssl.create_default_context(cafile=str(self.certs_dir / "origin-root-ca.pem"))
            request = urllib.request.Request(f"https://127.0.0.1:{port}/api/v1/demo-secret")
            with urllib.request.urlopen(request, context=context, timeout=5) as response:
                body = response.read().decode("utf-8", errors="replace")
            self.assertIn('"success": true', body.lower())
        finally:
            self.stop_server(origin, thread)

    def test_proxy_rejects_unsupported_connect_target(self):
        if not self.certs_dir.exists():
            subprocess.run(
                ["bash", str(self.repro_dir / "generate_proxy_certs.sh")],
                cwd=self.repro_dir,
                check=True,
                capture_output=True,
                text=True,
            )

        proxy_module = self.load_module("mitm_https_proxy.py", "mitm_https_proxy")
        proxy = proxy_module.build_proxy_server(
            host="127.0.0.1",
            port=0,
            target_host="127.0.0.1",
            target_port=4443,
            certfile=str(self.certs_dir / "proxy-leaf-fullchain.pem"),
            keyfile=str(self.certs_dir / "proxy-leaf.key"),
            upstream_cafile=str(self.certs_dir / "origin-root-ca.pem"),
        )
        thread = self.start_server(proxy)
        try:
            with socket.create_connection(proxy.server_address, timeout=5) as sock:
                sock.sendall(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
                response = sock.recv(4096).decode("iso-8859-1", errors="replace")
            self.assertIn("403", response)
        finally:
            self.stop_server(proxy, thread)

    def test_reproducer_client_accepts_explicit_proxy_and_ca_bundle(self):
        reproducer_module = self.load_module(
            "reproduce_proxy_ssl_error.py",
            "mitm_reproduce_proxy_ssl_error",
        )
        args = reproducer_module.parse_args(
            [
                "--url",
                "https://127.0.0.1:4443/api/v1/demo-secret",
                "--proxy",
                "http://127.0.0.1:8081",
                "--verify",
                str(self.certs_dir / "proxy-root-ca.pem"),
                "--expect-success",
            ]
        )
        self.assertEqual(args.proxy, "http://127.0.0.1:8081")
        self.assertEqual(args.verify, str(self.certs_dir / "proxy-root-ca.pem"))
        self.assertTrue(args.expect_success)

    def test_proxy_leaf_only_mode_causes_missing_issuer_error(self):
        if not self.certs_dir.exists():
            subprocess.run(
                ["bash", str(self.repro_dir / "generate_proxy_certs.sh")],
                cwd=self.repro_dir,
                check=True,
                capture_output=True,
                text=True,
            )

        origin_module = self.load_module("origin_https_server.py", "mitm_origin_https_server_for_leaf_case")
        proxy_module = self.load_module("mitm_https_proxy.py", "mitm_https_proxy_for_leaf_case")
        reproducer_module = self.load_module(
            "reproduce_proxy_ssl_error.py",
            "mitm_reproduce_proxy_ssl_error_for_leaf_case",
        )

        origin = origin_module.build_origin_server(
            host="127.0.0.1",
            port=0,
            certfile=str(self.certs_dir / "origin-server-fullchain.pem"),
            keyfile=str(self.certs_dir / "origin-server.key"),
        )
        origin_thread = self.start_server(origin)
        origin_port = origin.server_address[1]

        proxy = proxy_module.build_proxy_server(
            host="127.0.0.1",
            port=0,
            target_host="127.0.0.1",
            target_port=origin_port,
            certfile=str(self.certs_dir / "proxy-leaf.pem"),
            keyfile=str(self.certs_dir / "proxy-leaf.key"),
            upstream_cafile=str(self.certs_dir / "origin-root-ca.pem"),
            mode="leaf-only",
        )
        proxy_thread = self.start_server(proxy)
        proxy_port = proxy.server_address[1]

        stdout = io.StringIO()
        try:
            with contextlib.redirect_stdout(stdout):
                exit_code = reproducer_module.main(
                    [
                        "--url",
                        f"https://127.0.0.1:{origin_port}/api/v1/demo-secret",
                        "--proxy",
                        f"http://127.0.0.1:{proxy_port}",
                        "--verify",
                        str(self.certs_dir / "proxy-root-ca.pem"),
                    ]
                )
        finally:
            self.stop_server(proxy, proxy_thread)
            self.stop_server(origin, origin_thread)

        self.assertEqual(exit_code, 0)
        self.assertIn("unable to get local issuer certificate", stdout.getvalue().lower())

    def test_compare_proxy_cases_reports_all_three_expected_outcomes(self):
        if not self.certs_dir.exists():
            subprocess.run(
                ["bash", str(self.repro_dir / "generate_proxy_certs.sh")],
                cwd=self.repro_dir,
                check=True,
                capture_output=True,
                text=True,
            )

        result = subprocess.run(
            [sys.executable, str(self.repro_dir / "compare_proxy_cases.py")],
            cwd=self.repro_dir,
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("Failure case: proxy CA not trusted", result.stdout)
        self.assertIn("Failure case: proxy leaf only", result.stdout)
        self.assertIn("Success case: proxy full chain", result.stdout)
        self.assertIn("Comparison finished successfully.", result.stdout)


if __name__ == "__main__":
    unittest.main()
