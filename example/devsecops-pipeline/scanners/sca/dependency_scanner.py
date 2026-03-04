"""Dependency Scanner — SCA (Software Composition Analysis) (ch29).

Checks project dependencies for known vulnerabilities (CVEs).
Uses pip-audit as the primary tool, with Safety as fallback.

SCA is critical because:
  - 80%+ of modern code comes from open-source dependencies
  - Known vulnerabilities (CVEs) are the #1 attack vector
  - Supply chain attacks are increasing (e.g., event-stream, ua-parser-js)

Usage:
    scanner = DependencyScanner()
    findings = scanner.scan("./project")
"""

import json
import logging
import subprocess
from pathlib import Path

from pipeline.report_aggregator import Finding, Severity

logger = logging.getLogger(__name__)


class DependencyScanner:
    """Scans Python dependencies for known vulnerabilities."""

    def scan(self, target: str) -> list[Finding]:
        """Scan dependencies using pip-audit.

        Looks for requirements.txt or pyproject.toml in the target directory.
        """
        target_path = Path(target)
        req_file = target_path / "requirements.txt"

        if not req_file.exists():
            logger.info(f"No requirements.txt found in {target}")
            return []

        # Try pip-audit first
        findings = self._run_pip_audit(req_file)
        if findings is not None:
            return findings

        # Fallback to Safety
        findings = self._run_safety(req_file)
        if findings is not None:
            return findings

        logger.warning("No SCA tool available. Install pip-audit or safety.")
        return []

    def _run_pip_audit(self, req_file: Path) -> list[Finding] | None:
        """Run pip-audit on requirements file."""
        try:
            result = subprocess.run(
                [
                    "pip-audit",
                    "-r", str(req_file),
                    "-f", "json",
                    "--progress-spinner=off",
                ],
                capture_output=True,
                text=True,
                timeout=120,
            )

            if result.stdout:
                return self._parse_pip_audit(result.stdout, str(req_file))
            return []

        except FileNotFoundError:
            return None
        except subprocess.TimeoutExpired:
            logger.error("pip-audit timed out")
            return []

    def _run_safety(self, req_file: Path) -> list[Finding] | None:
        """Run Safety check on requirements file."""
        try:
            result = subprocess.run(
                [
                    "safety", "check",
                    "-r", str(req_file),
                    "--json",
                ],
                capture_output=True,
                text=True,
                timeout=120,
            )

            if result.stdout:
                return self._parse_safety(result.stdout, str(req_file))
            return []

        except FileNotFoundError:
            return None
        except subprocess.TimeoutExpired:
            logger.error("Safety check timed out")
            return []

    def _parse_pip_audit(self, output: str, req_file: str) -> list[Finding]:
        """Parse pip-audit JSON output."""
        findings = []
        try:
            data = json.loads(output)
            for dep in data.get("dependencies", []):
                for vuln in dep.get("vulns", []):
                    severity = self._cvss_to_severity(vuln.get("fix_versions", []))
                    findings.append(Finding(
                        rule_id=vuln.get("id", "UNKNOWN"),
                        severity=severity,
                        message=f"{dep['name']}=={dep['version']}: {vuln.get('description', 'Known vulnerability')}",
                        file=req_file,
                        scanner="pip-audit",
                        fix=f"Upgrade to {', '.join(vuln.get('fix_versions', []))}",
                    ))
        except json.JSONDecodeError:
            logger.error("Failed to parse pip-audit output")
        return findings

    def _parse_safety(self, output: str, req_file: str) -> list[Finding]:
        """Parse Safety JSON output."""
        findings = []
        try:
            data = json.loads(output)
            for vuln in data.get("vulnerabilities", []):
                findings.append(Finding(
                    rule_id=vuln.get("vulnerability_id", "UNKNOWN"),
                    severity=Severity.HIGH,
                    message=f"{vuln.get('package_name')}=={vuln.get('analyzed_version')}: {vuln.get('advisory', '')}",
                    file=req_file,
                    scanner="safety",
                ))
        except json.JSONDecodeError:
            logger.error("Failed to parse Safety output")
        return findings

    @staticmethod
    def _cvss_to_severity(fix_versions: list) -> Severity:
        """Estimate severity (simplified — real implementation uses CVSS score)."""
        return Severity.HIGH if fix_versions else Severity.CRITICAL
