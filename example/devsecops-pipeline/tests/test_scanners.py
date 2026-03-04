"""Tests for built-in scanners (ch29: DevSecOps).

Tests the pipeline's built-in scanning capabilities
(no external tools required).
"""

import os
import tempfile
from pathlib import Path

import pytest

from pipeline.report_aggregator import Finding, Severity


class TestBuiltinSAST:
    """Test the built-in SAST scanner (no Bandit required)."""

    def test_detects_eval(self):
        from pipeline.runner import PipelineRunner

        with tempfile.TemporaryDirectory() as tmpdir:
            # Create a file with eval()
            src = Path(tmpdir) / "bad.py"
            src.write_text('result = eval(user_input)\n')

            runner = PipelineRunner(target=tmpdir)
            findings = runner._builtin_sast()

            assert len(findings) >= 1
            assert any(f.rule_id == "B307" for f in findings)

    def test_detects_exec(self):
        from pipeline.runner import PipelineRunner

        with tempfile.TemporaryDirectory() as tmpdir:
            src = Path(tmpdir) / "bad.py"
            src.write_text('exec(code_string)\n')

            runner = PipelineRunner(target=tmpdir)
            findings = runner._builtin_sast()

            assert len(findings) >= 1
            assert any(f.rule_id == "B102" for f in findings)

    def test_detects_pickle(self):
        from pipeline.runner import PipelineRunner

        with tempfile.TemporaryDirectory() as tmpdir:
            src = Path(tmpdir) / "bad.py"
            src.write_text('data = pickle.loads(untrusted)\n')

            runner = PipelineRunner(target=tmpdir)
            findings = runner._builtin_sast()

            assert len(findings) >= 1
            assert any(f.rule_id == "B301" for f in findings)

    def test_clean_code_no_findings(self):
        from pipeline.runner import PipelineRunner

        with tempfile.TemporaryDirectory() as tmpdir:
            src = Path(tmpdir) / "good.py"
            src.write_text('def hello():\n    return "world"\n')

            runner = PipelineRunner(target=tmpdir)
            findings = runner._builtin_sast()

            assert len(findings) == 0


class TestSecretDetection:
    """Test the built-in secret detection scanner."""

    def test_detects_api_key(self):
        from pipeline.runner import PipelineRunner

        with tempfile.TemporaryDirectory() as tmpdir:
            src = Path(tmpdir) / "config.py"
            src.write_text('API_KEY = "sk-1234567890abcdef1234567890abcdef"\n')

            runner = PipelineRunner(target=tmpdir)
            result = runner._run_secret_detection()

            assert len(result.findings) >= 1
            assert any("API key" in f.message or "secret" in f.message.lower() for f in result.findings)

    def test_detects_password(self):
        from pipeline.runner import PipelineRunner

        with tempfile.TemporaryDirectory() as tmpdir:
            src = Path(tmpdir) / "config.py"
            src.write_text('password = "super_secret_password_123"\n')

            runner = PipelineRunner(target=tmpdir)
            result = runner._run_secret_detection()

            assert len(result.findings) >= 1

    def test_clean_code_no_secrets(self):
        from pipeline.runner import PipelineRunner

        with tempfile.TemporaryDirectory() as tmpdir:
            src = Path(tmpdir) / "clean.py"
            src.write_text('import os\nname = os.getenv("NAME", "default")\n')

            runner = PipelineRunner(target=tmpdir)
            result = runner._run_secret_detection()

            assert len(result.findings) == 0


class TestDockerfileLint:
    """Test the built-in Dockerfile security checks."""

    def test_detects_latest_tag(self):
        from scanners.container.trivy_scanner import TrivyScanner

        with tempfile.NamedTemporaryFile(mode="w", suffix="Dockerfile", delete=False) as f:
            f.write("FROM python:latest\nCMD ['python']\n")
            f.flush()

            scanner = TrivyScanner()
            findings = scanner._builtin_dockerfile_check(f.name)

            assert any(f.rule_id == "DS001" for f in findings)
            os.unlink(f.name)

    def test_detects_root_user(self):
        from scanners.container.trivy_scanner import TrivyScanner

        with tempfile.NamedTemporaryFile(mode="w", suffix="Dockerfile", delete=False) as f:
            f.write("FROM python:3.12\nUSER root\nCMD ['python']\n")
            f.flush()

            scanner = TrivyScanner()
            findings = scanner._builtin_dockerfile_check(f.name)

            assert any(f.rule_id == "DS002" for f in findings)
            os.unlink(f.name)

    def test_detects_add_instead_of_copy(self):
        from scanners.container.trivy_scanner import TrivyScanner

        with tempfile.NamedTemporaryFile(mode="w", suffix="Dockerfile", delete=False) as f:
            f.write("FROM python:3.12\nADD . /app\nCMD ['python']\n")
            f.flush()

            scanner = TrivyScanner()
            findings = scanner._builtin_dockerfile_check(f.name)

            assert any(f.rule_id == "DS005" for f in findings)
            os.unlink(f.name)

    def test_detects_missing_healthcheck(self):
        from scanners.container.trivy_scanner import TrivyScanner

        with tempfile.NamedTemporaryFile(mode="w", suffix="Dockerfile", delete=False) as f:
            f.write("FROM python:3.12\nCOPY . /app\nCMD ['python']\n")
            f.flush()

            scanner = TrivyScanner()
            findings = scanner._builtin_dockerfile_check(f.name)

            assert any(f.rule_id == "DS004" for f in findings)
            os.unlink(f.name)

    def test_good_dockerfile(self):
        from scanners.container.trivy_scanner import TrivyScanner

        with tempfile.NamedTemporaryFile(mode="w", suffix="Dockerfile", delete=False) as f:
            f.write(
                "FROM python:3.12-slim\n"
                "COPY . /app\n"
                "USER appuser\n"
                "HEALTHCHECK CMD curl -f http://localhost/ || exit 1\n"
                "CMD ['python']\n"
            )
            f.flush()

            scanner = TrivyScanner()
            findings = scanner._builtin_dockerfile_check(f.name)

            # Should only have informational or no findings
            assert not any(f.severity in (Severity.HIGH, Severity.CRITICAL) for f in findings)
            os.unlink(f.name)
