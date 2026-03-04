"""Tests for Report Aggregator (ch29: DevSecOps).

Verifies SARIF report generation and finding deduplication.
"""

import pytest

from pipeline.report_aggregator import ReportAggregator, Finding, Severity


class TestSARIFGeneration:
    """Test SARIF v2.1.0 report format."""

    def test_empty_findings(self):
        agg = ReportAggregator()
        sarif = agg.to_sarif([])
        assert sarif["version"] == "2.1.0"
        assert sarif["runs"] == []

    def test_single_finding(self):
        agg = ReportAggregator()
        findings = [
            Finding(
                rule_id="B307",
                severity=Severity.HIGH,
                message="Use of eval()",
                file="app.py",
                line=10,
                scanner="bandit",
            )
        ]
        sarif = agg.to_sarif(findings)
        assert len(sarif["runs"]) == 1
        run = sarif["runs"][0]
        assert run["tool"]["driver"]["name"] == "bandit"
        assert len(run["results"]) == 1
        assert run["results"][0]["ruleId"] == "B307"
        assert run["results"][0]["level"] == "error"  # HIGH → error

    def test_multiple_scanners(self):
        agg = ReportAggregator()
        findings = [
            Finding(rule_id="B307", severity=Severity.HIGH, message="eval", scanner="bandit"),
            Finding(rule_id="CVE-2024-001", severity=Severity.CRITICAL, message="vuln", scanner="pip-audit"),
        ]
        sarif = agg.to_sarif(findings)
        assert len(sarif["runs"]) == 2
        scanner_names = {r["tool"]["driver"]["name"] for r in sarif["runs"]}
        assert scanner_names == {"bandit", "pip-audit"}

    def test_severity_mapping(self):
        agg = ReportAggregator()
        test_cases = [
            (Severity.CRITICAL, "error"),
            (Severity.HIGH, "error"),
            (Severity.MEDIUM, "warning"),
            (Severity.LOW, "note"),
            (Severity.INFO, "none"),
        ]
        for severity, expected_level in test_cases:
            findings = [Finding(rule_id="TEST", severity=severity, message="test", scanner="test")]
            sarif = agg.to_sarif(findings)
            assert sarif["runs"][0]["results"][0]["level"] == expected_level

    def test_location_included(self):
        agg = ReportAggregator()
        findings = [
            Finding(
                rule_id="B307",
                severity=Severity.HIGH,
                message="eval",
                file="src/app.py",
                line=42,
                column=5,
                scanner="bandit",
            )
        ]
        sarif = agg.to_sarif(findings)
        location = sarif["runs"][0]["results"][0]["locations"][0]
        assert location["physicalLocation"]["artifactLocation"]["uri"] == "src/app.py"
        assert location["physicalLocation"]["region"]["startLine"] == 42
        assert location["physicalLocation"]["region"]["startColumn"] == 5

    def test_fix_suggestion_included(self):
        agg = ReportAggregator()
        findings = [
            Finding(
                rule_id="CVE-001",
                severity=Severity.HIGH,
                message="vuln",
                scanner="pip-audit",
                fix="Upgrade to 2.0.0",
            )
        ]
        sarif = agg.to_sarif(findings)
        result = sarif["runs"][0]["results"][0]
        assert result["fixes"][0]["description"]["text"] == "Upgrade to 2.0.0"

    def test_cwe_in_rules(self):
        agg = ReportAggregator()
        findings = [
            Finding(
                rule_id="B608",
                severity=Severity.HIGH,
                message="SQL injection",
                scanner="bandit",
                cwe="CWE-89",
            )
        ]
        sarif = agg.to_sarif(findings)
        rule = sarif["runs"][0]["tool"]["driver"]["rules"][0]
        assert rule["properties"]["cwe"] == "CWE-89"


class TestDeduplication:
    """Test finding deduplication."""

    def test_no_duplicates(self):
        agg = ReportAggregator()
        findings = [
            Finding(rule_id="B307", severity=Severity.HIGH, message="eval", file="a.py", line=1),
            Finding(rule_id="B608", severity=Severity.HIGH, message="sql", file="b.py", line=2),
        ]
        result = agg.deduplicate(findings)
        assert len(result) == 2

    def test_removes_exact_duplicates(self):
        agg = ReportAggregator()
        findings = [
            Finding(rule_id="B307", severity=Severity.HIGH, message="eval", file="a.py", line=10),
            Finding(rule_id="B307", severity=Severity.HIGH, message="eval", file="a.py", line=10),
        ]
        result = agg.deduplicate(findings)
        assert len(result) == 1

    def test_keeps_same_rule_different_location(self):
        agg = ReportAggregator()
        findings = [
            Finding(rule_id="B307", severity=Severity.HIGH, message="eval", file="a.py", line=10),
            Finding(rule_id="B307", severity=Severity.HIGH, message="eval", file="a.py", line=20),
        ]
        result = agg.deduplicate(findings)
        assert len(result) == 2

    def test_keeps_same_rule_different_file(self):
        agg = ReportAggregator()
        findings = [
            Finding(rule_id="B307", severity=Severity.HIGH, message="eval", file="a.py", line=10),
            Finding(rule_id="B307", severity=Severity.HIGH, message="eval", file="b.py", line=10),
        ]
        result = agg.deduplicate(findings)
        assert len(result) == 2
