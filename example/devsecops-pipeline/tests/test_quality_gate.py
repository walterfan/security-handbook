"""Tests for Quality Gate (ch29: DevSecOps).

Verifies that the quality gate correctly evaluates findings
against configurable thresholds.
"""

import pytest

from pipeline.quality_gate import QualityGate, QualityGateConfig
from pipeline.report_aggregator import Finding, Severity


def _make_findings(critical=0, high=0, medium=0, low=0) -> list[Finding]:
    """Helper to create findings with specific severity counts."""
    findings = []
    for i in range(critical):
        findings.append(Finding(rule_id=f"CRIT-{i}", severity=Severity.CRITICAL, message="Critical issue"))
    for i in range(high):
        findings.append(Finding(rule_id=f"HIGH-{i}", severity=Severity.HIGH, message="High issue"))
    for i in range(medium):
        findings.append(Finding(rule_id=f"MED-{i}", severity=Severity.MEDIUM, message="Medium issue"))
    for i in range(low):
        findings.append(Finding(rule_id=f"LOW-{i}", severity=Severity.LOW, message="Low issue"))
    return findings


class TestQualityGateDefaults:
    """Test with default thresholds (0 critical, 5 high, 20 medium)."""

    def test_no_findings_passes(self):
        gate = QualityGate()
        result = gate.evaluate([])
        assert result.passed is True

    def test_low_findings_only_passes(self):
        gate = QualityGate()
        result = gate.evaluate(_make_findings(low=100))
        assert result.passed is True  # Low has no limit by default

    def test_one_critical_fails(self):
        gate = QualityGate()
        result = gate.evaluate(_make_findings(critical=1))
        assert result.passed is False
        assert "Critical" in result.reasons[0]

    def test_five_high_passes(self):
        gate = QualityGate()
        result = gate.evaluate(_make_findings(high=5))
        assert result.passed is True

    def test_six_high_fails(self):
        gate = QualityGate()
        result = gate.evaluate(_make_findings(high=6))
        assert result.passed is False

    def test_twenty_medium_passes(self):
        gate = QualityGate()
        result = gate.evaluate(_make_findings(medium=20))
        assert result.passed is True

    def test_twentyone_medium_fails(self):
        gate = QualityGate()
        result = gate.evaluate(_make_findings(medium=21))
        assert result.passed is False


class TestQualityGateCustomConfig:
    """Test with custom thresholds."""

    def test_strict_config(self):
        """Zero tolerance for everything."""
        config = QualityGateConfig(max_critical=0, max_high=0, max_medium=0, max_low=0)
        gate = QualityGate(config)
        result = gate.evaluate(_make_findings(low=1))
        assert result.passed is False

    def test_relaxed_config(self):
        """Allow many findings."""
        config = QualityGateConfig(max_critical=5, max_high=50, max_medium=100, max_low=-1)
        gate = QualityGate(config)
        result = gate.evaluate(_make_findings(critical=3, high=30, medium=80, low=500))
        assert result.passed is True

    def test_counts_are_correct(self):
        gate = QualityGate()
        result = gate.evaluate(_make_findings(critical=2, high=3, medium=4, low=5))
        assert result.critical_count == 2
        assert result.high_count == 3
        assert result.medium_count == 4
        assert result.low_count == 5


class TestQualityGateReasons:
    """Test that failure reasons are informative."""

    def test_multiple_failures(self):
        config = QualityGateConfig(max_critical=0, max_high=0)
        gate = QualityGate(config)
        result = gate.evaluate(_make_findings(critical=1, high=1))
        assert result.passed is False
        assert len(result.reasons) == 2

    def test_pass_reason(self):
        gate = QualityGate()
        result = gate.evaluate([])
        assert "All thresholds met" in result.reasons
