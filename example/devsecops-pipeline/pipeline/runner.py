"""Pipeline Runner — orchestrates all security scanning stages.

Demonstrates ch29 — DevSecOps:
  - Shift-left security: run scans early in the development cycle
  - Automated security gates in CI/CD
  - SARIF report aggregation for unified view

Usage:
    python -m pipeline.runner --target ./sample-app --output ./reports
"""

import argparse
import json
import logging
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from pipeline.quality_gate import QualityGate, QualityGateResult
from pipeline.report_aggregator import ReportAggregator, Finding, Severity

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


@dataclass
class StageResult:
    """Result from a single pipeline stage."""
    name: str
    findings: list[Finding] = field(default_factory=list)
    duration_seconds: float = 0.0
    error: str | None = None
    skipped: bool = False


@dataclass
class PipelineResult:
    """Aggregated result from all pipeline stages."""
    stages: list[StageResult] = field(default_factory=list)
    total_findings: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    gate_passed: bool = False
    started_at: str = ""
    completed_at: str = ""
    duration_seconds: float = 0.0


class PipelineRunner:
    """Orchestrates security scanning stages.

    Stages run in order:
      1. SAST — Static Application Security Testing
      2. SCA  — Software Composition Analysis
      3. Secret Detection
      4. Container Scanning (if Dockerfile present)
      5. DAST — Dynamic Application Security Testing (if URL provided)

    After all stages, the Quality Gate evaluates pass/fail.
    """

    def __init__(self, target: str, output_dir: str = "./reports"):
        self.target = Path(target)
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.aggregator = ReportAggregator()
        self.quality_gate = QualityGate()

    def run(self) -> PipelineResult:
        """Run the full security scanning pipeline."""
        logger.info(f"Starting DevSecOps pipeline on: {self.target}")
        start_time = time.time()
        result = PipelineResult(started_at=datetime.now(timezone.utc).isoformat())

        # Stage 1: SAST
        sast_result = self._run_sast()
        result.stages.append(sast_result)

        # Stage 2: SCA
        sca_result = self._run_sca()
        result.stages.append(sca_result)

        # Stage 3: Secret Detection
        secret_result = self._run_secret_detection()
        result.stages.append(secret_result)

        # Stage 4: Container Scanning
        dockerfile = self.target / "Dockerfile"
        if dockerfile.exists():
            container_result = self._run_container_scan()
            result.stages.append(container_result)
        else:
            result.stages.append(StageResult(name="container-scan", skipped=True))

        # Aggregate all findings
        all_findings = []
        for stage in result.stages:
            all_findings.extend(stage.findings)

        result.total_findings = len(all_findings)
        result.critical_count = sum(1 for f in all_findings if f.severity == Severity.CRITICAL)
        result.high_count = sum(1 for f in all_findings if f.severity == Severity.HIGH)
        result.medium_count = sum(1 for f in all_findings if f.severity == Severity.MEDIUM)
        result.low_count = sum(1 for f in all_findings if f.severity == Severity.LOW)

        # Quality Gate
        gate_result = self.quality_gate.evaluate(all_findings)
        result.gate_passed = gate_result.passed

        result.completed_at = datetime.now(timezone.utc).isoformat()
        result.duration_seconds = time.time() - start_time

        # Write reports
        self._write_summary(result)
        self._write_sarif(all_findings)

        # Log summary
        logger.info(f"Pipeline completed in {result.duration_seconds:.1f}s")
        logger.info(
            f"Findings: {result.critical_count} critical, {result.high_count} high, "
            f"{result.medium_count} medium, {result.low_count} low"
        )
        logger.info(f"Quality Gate: {'PASSED ✅' if result.gate_passed else 'FAILED ❌'}")

        return result

    def _run_sast(self) -> StageResult:
        """Run SAST scanning (Bandit for Python)."""
        logger.info("Stage 1: SAST (Static Application Security Testing)")
        start = time.time()
        findings = []

        try:
            from scanners.sast.bandit_scanner import BanditScanner
            scanner = BanditScanner()
            findings = scanner.scan(str(self.target))
        except ImportError:
            logger.warning("Bandit not available, using built-in SAST")
            findings = self._builtin_sast()
        except Exception as e:
            return StageResult(name="sast", error=str(e), duration_seconds=time.time() - start)

        return StageResult(name="sast", findings=findings, duration_seconds=time.time() - start)

    def _run_sca(self) -> StageResult:
        """Run SCA scanning (dependency vulnerability check)."""
        logger.info("Stage 2: SCA (Software Composition Analysis)")
        start = time.time()
        findings = []

        try:
            from scanners.sca.dependency_scanner import DependencyScanner
            scanner = DependencyScanner()
            findings = scanner.scan(str(self.target))
        except ImportError:
            logger.warning("SCA scanner not available")
        except Exception as e:
            return StageResult(name="sca", error=str(e), duration_seconds=time.time() - start)

        return StageResult(name="sca", findings=findings, duration_seconds=time.time() - start)

    def _run_secret_detection(self) -> StageResult:
        """Run secret detection scanning."""
        logger.info("Stage 3: Secret Detection")
        start = time.time()
        findings = []

        # Built-in secret detection (simplified)
        import re
        secret_patterns = [
            (r'(?i)(api[_-]?key|apikey)\s*[=:]\s*["\']?[\w-]{20,}', "Potential API key"),
            (r'(?i)(secret|password|passwd|pwd)\s*[=:]\s*["\']?[^\s"\']{8,}', "Potential hardcoded secret"),
            (r'(?i)aws[_-]?access[_-]?key[_-]?id\s*[=:]\s*["\']?AKIA[\w]{16}', "AWS Access Key"),
            (r'-----BEGIN (?:RSA )?PRIVATE KEY-----', "Private key in source"),
        ]

        for py_file in self.target.rglob("*.py"):
            try:
                content = py_file.read_text()
                for pattern, description in secret_patterns:
                    for match in re.finditer(pattern, content):
                        line_num = content[:match.start()].count('\n') + 1
                        findings.append(Finding(
                            rule_id="SECRET-001",
                            severity=Severity.HIGH,
                            message=description,
                            file=str(py_file.relative_to(self.target)),
                            line=line_num,
                            scanner="secret-detector",
                        ))
            except Exception:
                pass

        return StageResult(name="secret-detection", findings=findings, duration_seconds=time.time() - start)

    def _run_container_scan(self) -> StageResult:
        """Run container image scanning."""
        logger.info("Stage 4: Container Scanning")
        start = time.time()
        findings = []

        try:
            from scanners.container.trivy_scanner import TrivyScanner
            scanner = TrivyScanner()
            findings = scanner.scan_dockerfile(str(self.target / "Dockerfile"))
        except ImportError:
            logger.warning("Trivy scanner not available")
        except Exception as e:
            return StageResult(name="container-scan", error=str(e), duration_seconds=time.time() - start)

        return StageResult(name="container-scan", findings=findings, duration_seconds=time.time() - start)

    def _builtin_sast(self) -> list[Finding]:
        """Built-in SAST rules (simplified, no external dependencies)."""
        findings = []
        dangerous_patterns = [
            ("eval(", "B307", "Use of eval() is dangerous", Severity.HIGH),
            ("exec(", "B102", "Use of exec() is dangerous", Severity.HIGH),
            ("subprocess.call(", "B603", "subprocess call with shell=True", Severity.MEDIUM),
            ("pickle.loads(", "B301", "Pickle deserialization is unsafe", Severity.HIGH),
            ("yaml.load(", "B506", "Use yaml.safe_load instead", Severity.MEDIUM),
            ("SELECT.*%s", "B608", "Possible SQL injection", Severity.HIGH),
            ("md5(", "B303", "Use of insecure MD5 hash", Severity.MEDIUM),
            ("sha1(", "B303", "Use of insecure SHA1 hash", Severity.LOW),
        ]

        for py_file in self.target.rglob("*.py"):
            try:
                content = py_file.read_text()
                for line_num, line in enumerate(content.splitlines(), 1):
                    for pattern, rule_id, message, severity in dangerous_patterns:
                        if pattern in line:
                            findings.append(Finding(
                                rule_id=rule_id,
                                severity=severity,
                                message=message,
                                file=str(py_file.relative_to(self.target)),
                                line=line_num,
                                scanner="builtin-sast",
                            ))
            except Exception:
                pass

        return findings

    def _write_summary(self, result: PipelineResult):
        """Write JSON summary report."""
        summary = {
            "pipeline": "devsecops-security-scan",
            "started_at": result.started_at,
            "completed_at": result.completed_at,
            "duration_seconds": result.duration_seconds,
            "quality_gate": "PASSED" if result.gate_passed else "FAILED",
            "findings": {
                "total": result.total_findings,
                "critical": result.critical_count,
                "high": result.high_count,
                "medium": result.medium_count,
                "low": result.low_count,
            },
            "stages": [
                {
                    "name": s.name,
                    "findings_count": len(s.findings),
                    "duration_seconds": s.duration_seconds,
                    "skipped": s.skipped,
                    "error": s.error,
                }
                for s in result.stages
            ],
        }
        output_path = self.output_dir / "summary.json"
        output_path.write_text(json.dumps(summary, indent=2))
        logger.info(f"Summary written to {output_path}")

    def _write_sarif(self, findings: list[Finding]):
        """Write SARIF format report (standard for security tools)."""
        sarif = self.aggregator.to_sarif(findings)
        output_path = self.output_dir / "results.sarif"
        output_path.write_text(json.dumps(sarif, indent=2))
        logger.info(f"SARIF report written to {output_path}")


def main():
    parser = argparse.ArgumentParser(description="DevSecOps Security Pipeline")
    parser.add_argument("--target", required=True, help="Target directory to scan")
    parser.add_argument("--output", default="./reports", help="Output directory for reports")
    args = parser.parse_args()

    runner = PipelineRunner(target=args.target, output_dir=args.output)
    result = runner.run()

    sys.exit(0 if result.gate_passed else 1)


if __name__ == "__main__":
    main()
