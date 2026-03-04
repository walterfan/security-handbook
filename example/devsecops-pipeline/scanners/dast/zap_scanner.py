"""OWASP ZAP DAST Scanner wrapper (ch29: DevSecOps — DAST).

DAST (Dynamic Application Security Testing) tests a running application
for vulnerabilities by sending crafted HTTP requests:
  - XSS (Cross-Site Scripting)
  - SQL Injection
  - CSRF (Cross-Site Request Forgery)
  - Authentication bypass
  - Security header misconfigurations

ZAP (Zed Attack Proxy) is the most popular open-source DAST tool.

Usage:
    scanner = ZAPScanner(target_url="http://localhost:8000")
    findings = scanner.scan()
"""

import json
import logging
import subprocess

from pipeline.report_aggregator import Finding, Severity

logger = logging.getLogger(__name__)


class ZAPScanner:
    """Wraps OWASP ZAP for dynamic application security testing."""

    RISK_MAP = {
        "0": Severity.INFO,     # Informational
        "1": Severity.LOW,      # Low
        "2": Severity.MEDIUM,   # Medium
        "3": Severity.HIGH,     # High
    }

    def __init__(self, target_url: str, zap_path: str = "zap-cli"):
        self.target_url = target_url
        self.zap_path = zap_path

    def scan(self) -> list[Finding]:
        """Run ZAP baseline scan against the target URL.

        Uses ZAP's baseline scan which:
          1. Spiders the target to discover endpoints
          2. Runs passive scan rules
          3. Runs selected active scan rules
          4. Reports findings
        """
        try:
            # ZAP Docker baseline scan
            result = subprocess.run(
                [
                    "docker", "run", "--rm",
                    "-v", "/tmp/zap:/zap/wrk",
                    "ghcr.io/zaproxy/zaproxy:stable",
                    "zap-baseline.py",
                    "-t", self.target_url,
                    "-J", "zap-report.json",
                    "-I",  # Don't fail on warnings
                ],
                capture_output=True,
                text=True,
                timeout=300,
            )

            # Parse the JSON report
            report_path = "/tmp/zap/zap-report.json"
            try:
                with open(report_path) as f:
                    return self._parse_report(json.load(f))
            except FileNotFoundError:
                logger.warning("ZAP report not found")
                return []

        except FileNotFoundError:
            logger.warning("Docker not available for ZAP scan")
            return []
        except subprocess.TimeoutExpired:
            logger.error("ZAP scan timed out (5 min limit)")
            return []

    def _parse_report(self, report: dict) -> list[Finding]:
        """Parse ZAP JSON report into Finding objects."""
        findings = []
        for site in report.get("site", []):
            for alert in site.get("alerts", []):
                severity = self.RISK_MAP.get(
                    str(alert.get("riskcode", "1")),
                    Severity.LOW,
                )
                for instance in alert.get("instances", [{}]):
                    findings.append(Finding(
                        rule_id=f"ZAP-{alert.get('pluginid', '0')}",
                        severity=severity,
                        message=alert.get("name", "Unknown vulnerability"),
                        file=instance.get("uri", self.target_url),
                        scanner="owasp-zap",
                        cwe=alert.get("cweid", ""),
                        fix=alert.get("solution", ""),
                    ))
        return findings
