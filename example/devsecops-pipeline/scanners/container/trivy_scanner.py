"""Trivy Container Scanner wrapper (ch28: Cloud-Native Security, ch29: DevSecOps).

Trivy scans container images for:
  - OS package vulnerabilities (Alpine, Debian, Ubuntu, etc.)
  - Application dependency vulnerabilities
  - Misconfigurations (Dockerfile best practices)
  - Secrets accidentally baked into images

This implements the "Container" layer of the 4C security model (ch28):
  Cloud → Cluster → Container → Code

Usage:
    scanner = TrivyScanner()
    findings = scanner.scan_image("myapp:latest")
    findings = scanner.scan_dockerfile("./Dockerfile")
"""

import json
import logging
import subprocess

from pipeline.report_aggregator import Finding, Severity

logger = logging.getLogger(__name__)


class TrivyScanner:
    """Wraps the Trivy CLI for container security scanning."""

    SEVERITY_MAP = {
        "CRITICAL": Severity.CRITICAL,
        "HIGH": Severity.HIGH,
        "MEDIUM": Severity.MEDIUM,
        "LOW": Severity.LOW,
        "UNKNOWN": Severity.INFO,
    }

    def scan_image(self, image: str) -> list[Finding]:
        """Scan a container image for vulnerabilities.

        Args:
            image: Docker image name (e.g., "myapp:latest")
        """
        try:
            result = subprocess.run(
                [
                    "trivy", "image",
                    "--format", "json",
                    "--severity", "CRITICAL,HIGH,MEDIUM",
                    "--quiet",
                    image,
                ],
                capture_output=True,
                text=True,
                timeout=180,
            )

            if result.stdout:
                return self._parse_output(result.stdout)
            return []

        except FileNotFoundError:
            logger.warning("Trivy not installed. Install from: https://trivy.dev")
            return []
        except subprocess.TimeoutExpired:
            logger.error("Trivy scan timed out")
            return []

    def scan_dockerfile(self, dockerfile_path: str) -> list[Finding]:
        """Scan a Dockerfile for misconfigurations.

        Checks for:
          - Running as root
          - Using latest tag
          - Missing HEALTHCHECK
          - Exposing unnecessary ports
          - ADD instead of COPY
        """
        try:
            result = subprocess.run(
                [
                    "trivy", "config",
                    "--format", "json",
                    "--quiet",
                    dockerfile_path,
                ],
                capture_output=True,
                text=True,
                timeout=60,
            )

            if result.stdout:
                return self._parse_config_output(result.stdout)
            return []

        except FileNotFoundError:
            logger.warning("Trivy not installed, using built-in Dockerfile checks")
            return self._builtin_dockerfile_check(dockerfile_path)
        except subprocess.TimeoutExpired:
            logger.error("Trivy config scan timed out")
            return []

    def _parse_output(self, output: str) -> list[Finding]:
        """Parse Trivy JSON output for image scans."""
        findings = []
        try:
            data = json.loads(output)
            for result in data.get("Results", []):
                target = result.get("Target", "")
                for vuln in result.get("Vulnerabilities", []):
                    severity = self.SEVERITY_MAP.get(
                        vuln.get("Severity", "UNKNOWN"),
                        Severity.INFO,
                    )
                    findings.append(Finding(
                        rule_id=vuln.get("VulnerabilityID", "UNKNOWN"),
                        severity=severity,
                        message=f"{vuln.get('PkgName', '')}@{vuln.get('InstalledVersion', '')}: {vuln.get('Title', '')}",
                        file=target,
                        scanner="trivy",
                        fix=f"Upgrade to {vuln.get('FixedVersion', 'N/A')}",
                    ))
        except json.JSONDecodeError:
            logger.error("Failed to parse Trivy output")
        return findings

    def _parse_config_output(self, output: str) -> list[Finding]:
        """Parse Trivy config scan output."""
        findings = []
        try:
            data = json.loads(output)
            for result in data.get("Results", []):
                for misconfig in result.get("Misconfigurations", []):
                    severity = self.SEVERITY_MAP.get(
                        misconfig.get("Severity", "LOW"),
                        Severity.LOW,
                    )
                    findings.append(Finding(
                        rule_id=misconfig.get("ID", "UNKNOWN"),
                        severity=severity,
                        message=misconfig.get("Title", ""),
                        file=result.get("Target", ""),
                        scanner="trivy-config",
                        fix=misconfig.get("Resolution", ""),
                    ))
        except json.JSONDecodeError:
            logger.error("Failed to parse Trivy config output")
        return findings

    def _builtin_dockerfile_check(self, dockerfile_path: str) -> list[Finding]:
        """Built-in Dockerfile security checks (no Trivy needed)."""
        findings = []
        try:
            with open(dockerfile_path) as f:
                content = f.read()
                lines = content.splitlines()

            for i, line in enumerate(lines, 1):
                stripped = line.strip()

                # Check: using latest tag
                if stripped.startswith("FROM") and ":latest" in stripped:
                    findings.append(Finding(
                        rule_id="DS001",
                        severity=Severity.MEDIUM,
                        message="Avoid using 'latest' tag — pin to specific version",
                        file=dockerfile_path,
                        line=i,
                        scanner="dockerfile-lint",
                    ))

                # Check: running as root
                if stripped == "USER root":
                    findings.append(Finding(
                        rule_id="DS002",
                        severity=Severity.HIGH,
                        message="Container should not run as root",
                        file=dockerfile_path,
                        line=i,
                        scanner="dockerfile-lint",
                    ))

                # Check: ADD instead of COPY
                if stripped.startswith("ADD") and "http" not in stripped:
                    findings.append(Finding(
                        rule_id="DS005",
                        severity=Severity.LOW,
                        message="Use COPY instead of ADD for local files",
                        file=dockerfile_path,
                        line=i,
                        scanner="dockerfile-lint",
                    ))

            # Check: no HEALTHCHECK
            if "HEALTHCHECK" not in content:
                findings.append(Finding(
                    rule_id="DS004",
                    severity=Severity.LOW,
                    message="Missing HEALTHCHECK instruction",
                    file=dockerfile_path,
                    scanner="dockerfile-lint",
                ))

        except FileNotFoundError:
            logger.error(f"Dockerfile not found: {dockerfile_path}")

        return findings
