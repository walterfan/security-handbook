"""Report Aggregator — unified security findings in SARIF format.

Demonstrates ch29 — DevSecOps:
  - Standardized security report format (SARIF v2.1.0)
  - Severity classification (CRITICAL/HIGH/MEDIUM/LOW/INFO)
  - Multi-scanner result aggregation
  - Deduplication of findings

SARIF (Static Analysis Results Interchange Format) is the industry
standard for security tool output, supported by GitHub, Azure DevOps,
and most CI/CD platforms.
"""

from dataclasses import dataclass, field
from enum import Enum


class Severity(str, Enum):
    """Finding severity levels (aligned with CVSS)."""
    CRITICAL = "critical"  # CVSS 9.0-10.0
    HIGH = "high"          # CVSS 7.0-8.9
    MEDIUM = "medium"      # CVSS 4.0-6.9
    LOW = "low"            # CVSS 0.1-3.9
    INFO = "info"          # Informational


@dataclass
class Finding:
    """A single security finding from any scanner."""
    rule_id: str           # e.g., "B307", "CVE-2024-1234"
    severity: Severity
    message: str           # Human-readable description
    file: str = ""         # File path (relative)
    line: int = 0          # Line number
    column: int = 0        # Column number
    scanner: str = ""      # Which scanner found this
    cwe: str = ""          # CWE ID (e.g., "CWE-89")
    fix: str = ""          # Suggested fix
    confidence: str = ""   # "high", "medium", "low"


class ReportAggregator:
    """Aggregates findings from multiple scanners into SARIF format."""

    def to_sarif(self, findings: list[Finding]) -> dict:
        """Convert findings to SARIF v2.1.0 format.

        SARIF structure:
          - $schema: SARIF schema URL
          - version: "2.1.0"
          - runs[]: one per scanner tool
            - tool: scanner metadata
            - results[]: findings
              - ruleId, level, message, locations
        """
        # Group findings by scanner
        by_scanner: dict[str, list[Finding]] = {}
        for f in findings:
            scanner = f.scanner or "unknown"
            by_scanner.setdefault(scanner, []).append(f)

        runs = []
        for scanner_name, scanner_findings in by_scanner.items():
            # Collect unique rules
            rules = {}
            for f in scanner_findings:
                if f.rule_id not in rules:
                    rules[f.rule_id] = {
                        "id": f.rule_id,
                        "shortDescription": {"text": f.message},
                        "defaultConfiguration": {
                            "level": self._severity_to_sarif_level(f.severity),
                        },
                    }
                    if f.cwe:
                        rules[f.rule_id]["properties"] = {"cwe": f.cwe}

            # Build results
            results = []
            for f in scanner_findings:
                result = {
                    "ruleId": f.rule_id,
                    "level": self._severity_to_sarif_level(f.severity),
                    "message": {"text": f.message},
                }
                if f.file:
                    result["locations"] = [{
                        "physicalLocation": {
                            "artifactLocation": {"uri": f.file},
                            "region": {
                                "startLine": f.line or 1,
                                "startColumn": f.column or 1,
                            },
                        },
                    }]
                if f.fix:
                    result["fixes"] = [{"description": {"text": f.fix}}]
                results.append(result)

            runs.append({
                "tool": {
                    "driver": {
                        "name": scanner_name,
                        "rules": list(rules.values()),
                    },
                },
                "results": results,
            })

        return {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": runs,
        }

    def deduplicate(self, findings: list[Finding]) -> list[Finding]:
        """Remove duplicate findings (same rule + file + line)."""
        seen = set()
        unique = []
        for f in findings:
            key = (f.rule_id, f.file, f.line)
            if key not in seen:
                seen.add(key)
                unique.append(f)
        return unique

    @staticmethod
    def _severity_to_sarif_level(severity: Severity) -> str:
        """Map severity to SARIF level."""
        mapping = {
            Severity.CRITICAL: "error",
            Severity.HIGH: "error",
            Severity.MEDIUM: "warning",
            Severity.LOW: "note",
            Severity.INFO: "none",
        }
        return mapping.get(severity, "warning")
