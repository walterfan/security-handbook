"""Bandit SAST Scanner wrapper (ch29: DevSecOps — SAST).

Bandit is a Python-specific SAST tool that finds common security
issues in Python code:
  - SQL injection (B608)
  - Use of eval/exec (B307, B102)
  - Hardcoded passwords (B105, B106)
  - Insecure hash functions (B303)
  - Pickle deserialization (B301)
  - Subprocess with shell=True (B602, B603)

Usage:
    scanner = BanditScanner()
    findings = scanner.scan("./src")
"""

import json
import logging
import subprocess
from pathlib import Path

from pipeline.report_aggregator import Finding, Severity

logger = logging.getLogger(__name__)


class BanditScanner:
    """Wraps the Bandit CLI tool for Python SAST scanning."""

    SEVERITY_MAP = {
        "HIGH": Severity.HIGH,
        "MEDIUM": Severity.MEDIUM,
        "LOW": Severity.LOW,
    }

    def scan(self, target: str) -> list[Finding]:
        """Run Bandit on the target directory.

        Args:
            target: Path to Python source directory

        Returns:
            List of security findings
        """
        target_path = Path(target)
        if not target_path.exists():
            logger.error(f"Target not found: {target}")
            return []

        try:
            result = subprocess.run(
                [
                    "bandit",
                    "-r", str(target_path),
                    "-f", "json",
                    "-ll",  # Only medium and above
                    "--quiet",
                ],
                capture_output=True,
                text=True,
                timeout=120,
            )

            # Bandit returns exit code 1 if findings exist
            if result.stdout:
                return self._parse_output(result.stdout)
            return []

        except FileNotFoundError:
            logger.warning("Bandit not installed. Install with: pip install bandit")
            return []
        except subprocess.TimeoutExpired:
            logger.error("Bandit scan timed out")
            return []

    def _parse_output(self, output: str) -> list[Finding]:
        """Parse Bandit JSON output into Finding objects."""
        findings = []
        try:
            data = json.loads(output)
            for result in data.get("results", []):
                severity = self.SEVERITY_MAP.get(
                    result.get("issue_severity", "LOW"),
                    Severity.LOW,
                )
                findings.append(Finding(
                    rule_id=result.get("test_id", "UNKNOWN"),
                    severity=severity,
                    message=result.get("issue_text", ""),
                    file=result.get("filename", ""),
                    line=result.get("line_number", 0),
                    column=result.get("col_offset", 0),
                    scanner="bandit",
                    cwe=result.get("issue_cwe", {}).get("id", ""),
                    confidence=result.get("issue_confidence", "").lower(),
                ))
        except json.JSONDecodeError:
            logger.error("Failed to parse Bandit output")

        return findings
