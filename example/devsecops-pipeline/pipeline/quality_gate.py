"""Quality Gate — pass/fail decision for the security pipeline.

Demonstrates ch29 — DevSecOps:
  - Automated security gates in CI/CD
  - Configurable thresholds per severity
  - Block merge on critical/high findings
  - Allow override for accepted risks

The quality gate is the "shift-left" enforcement mechanism:
  - PR checks: block merge if critical findings exist
  - Release gate: block deployment if high+ findings exceed threshold
  - Nightly scan: alert on new findings
"""

from dataclasses import dataclass, field

from pipeline.report_aggregator import Finding, Severity


@dataclass
class QualityGateConfig:
    """Configuration for quality gate thresholds.

    Default: zero tolerance for critical, max 5 high, max 20 medium.
    """
    max_critical: int = 0    # Block on any critical finding
    max_high: int = 5        # Allow up to 5 high findings
    max_medium: int = 20     # Allow up to 20 medium findings
    max_low: int = -1        # -1 = unlimited
    fail_on_error: bool = True  # Fail if any scanner errors


@dataclass
class QualityGateResult:
    """Result of quality gate evaluation."""
    passed: bool
    reasons: list[str] = field(default_factory=list)
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0


class QualityGate:
    """Evaluates security findings against configurable thresholds."""

    def __init__(self, config: QualityGateConfig | None = None):
        self.config = config or QualityGateConfig()

    def evaluate(self, findings: list[Finding]) -> QualityGateResult:
        """Evaluate findings against quality gate thresholds.

        Returns:
            QualityGateResult with pass/fail and reasons
        """
        result = QualityGateResult(passed=True)

        # Count by severity
        for f in findings:
            match f.severity:
                case Severity.CRITICAL:
                    result.critical_count += 1
                case Severity.HIGH:
                    result.high_count += 1
                case Severity.MEDIUM:
                    result.medium_count += 1
                case Severity.LOW:
                    result.low_count += 1

        # Check thresholds
        if self.config.max_critical >= 0 and result.critical_count > self.config.max_critical:
            result.passed = False
            result.reasons.append(
                f"Critical findings ({result.critical_count}) exceed threshold ({self.config.max_critical})"
            )

        if self.config.max_high >= 0 and result.high_count > self.config.max_high:
            result.passed = False
            result.reasons.append(
                f"High findings ({result.high_count}) exceed threshold ({self.config.max_high})"
            )

        if self.config.max_medium >= 0 and result.medium_count > self.config.max_medium:
            result.passed = False
            result.reasons.append(
                f"Medium findings ({result.medium_count}) exceed threshold ({self.config.max_medium})"
            )

        if self.config.max_low >= 0 and result.low_count > self.config.max_low:
            result.passed = False
            result.reasons.append(
                f"Low findings ({result.low_count}) exceed threshold ({self.config.max_low})"
            )

        if result.passed:
            result.reasons.append("All thresholds met")

        return result
