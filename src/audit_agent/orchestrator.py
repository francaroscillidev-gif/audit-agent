"""Orchestrates the entire AuditAgent pipeline: Static Parsing -> Semantic Reasoning -> Test Verification -> Remediation."""
from pathlib import Path
from typing import List, Optional
from audit_agent.models import (
    TargetType,
    AuditSummary,
    VerifiedFinding,
    VerificationStatus,
)
from audit_agent.reasoner.engine import SemanticReasoner
from audit_agent.verifiers.solidity_verifier import SolidityVerifier
from audit_agent.verifiers.webapp_verifier import WebAPIVerifier
from audit_agent.remediation.patcher import RemediationPatcher


class AuditOrchestrator:
    """End-to-end security auditing pipeline with empirical proof-of-concept verification."""

    def __init__(self, api_key: Optional[str] = None, max_repair_retries: int = 2):
        self.reasoner = SemanticReasoner(api_key=api_key)
        self.solidity_verifier = SolidityVerifier()
        self.webapp_verifier = WebAPIVerifier()
        self.max_repair_retries = max_repair_retries

    def run_audit(self, target_path: str) -> AuditSummary:
        path = Path(target_path)
        if not path.exists():
            raise FileNotFoundError(f"Target path not found: {target_path}")

        if path.is_dir():
            return self.run_project_audit(str(path))

        source_code = path.read_text(encoding="utf-8")
        target_type = self._detect_target_type(path)

        # 1. Generate vulnerability hypotheses via semantic reasoning
        hypotheses = self.reasoner.analyze(source_code, str(path.name), target_type)

        findings: List[VerifiedFinding] = []
        confirmed_count = 0
        pruned_count = 0
        unverifiable_count = 0

        # 2. For each hypothesis, synthesize harness and verify empirically
        for hyp in hypotheses:
            harness = self.reasoner.synthesize_test_harness(hyp, source_code, target_type)

            # Verification execution with self-repair loop
            res = self._execute_verification_with_repair(hyp, harness, source_code, target_type)

            is_false_positive = (res.status == VerificationStatus.REFUTED)
            finding = VerifiedFinding(
                hypothesis=hyp,
                verification=res,
                is_false_positive=is_false_positive,
            )

            if res.status == VerificationStatus.CONFIRMED:
                confirmed_count += 1
                # Generate automated patch
                finding.remediation_patch = RemediationPatcher.generate_patch(finding, source_code)
            elif res.status == VerificationStatus.REFUTED:
                pruned_count += 1
            else:
                unverifiable_count += 1

            findings.append(finding)

        total = len(hypotheses)
        pruning_rate = (pruned_count / total * 100.0) if total > 0 else 0.0

        return AuditSummary(
            target_path=str(path),
            target_type=target_type,
            total_hypotheses=total,
            confirmed_bugs=confirmed_count,
            false_positives_pruned=pruned_count,
            unverifiable=unverifiable_count,
            pruning_efficiency_pct=round(pruning_rate, 1),
            findings=findings,
        )

    def run_project_audit(self, project_dir: str) -> AuditSummary:
        """Scan and verify all contracts and endpoints in a directory project."""
        p = Path(project_dir)
        sol_files = list(p.rglob("*.sol"))
        py_files = [f for f in p.rglob("*.py") if "test" not in f.name and ".venv" not in str(f)]

        # Filter out common build/test folders
        ignored_patterns = [".git", "node_modules", "lib", "test", "tests", "cache", "out", "artifacts"]
        target_files = []
        for f in sol_files + py_files:
            if not any(ign in f.parts for ign in ignored_patterns):
                target_files.append(f)

        if not target_files:
            # Fallback to any files found
            target_files = sol_files if sol_files else py_files

        all_findings: List[VerifiedFinding] = []
        primary_type = TargetType.SMART_CONTRACT if sol_files else TargetType.WEB_APP_API

        for f in target_files:
            sub_summary = self.run_audit(str(f))
            all_findings.extend(sub_summary.findings)

        total = len(all_findings)
        confirmed = sum(1 for f in all_findings if f.verification.status == VerificationStatus.CONFIRMED)
        pruned = sum(1 for f in all_findings if f.verification.status == VerificationStatus.REFUTED)
        unverifiable = total - confirmed - pruned
        pruning_rate = (pruned / total * 100.0) if total > 0 else 0.0

        return AuditSummary(
            target_path=str(p),
            target_type=primary_type,
            total_hypotheses=total,
            confirmed_bugs=confirmed,
            false_positives_pruned=pruned,
            unverifiable=unverifiable,
            pruning_efficiency_pct=round(pruning_rate, 1),
            findings=all_findings,
        )

    def _execute_verification_with_repair(
        self, hyp, harness, source_code, target_type
    ):
        """Executes verification and invokes self-repair if harness produces compilation error."""
        active_harness = harness
        res = None

        for attempt in range(self.max_repair_retries + 1):
            if target_type == TargetType.SMART_CONTRACT:
                res = self.solidity_verifier.verify(hyp, active_harness, source_code)
            else:
                res = self.webapp_verifier.verify(hyp, active_harness, source_code)

            if res.status != VerificationStatus.HARNESS_ERROR or attempt == self.max_repair_retries:
                break

            # Attempt self-repair
            active_harness = self.reasoner.repair_test_harness(
                active_harness, res.output_log, source_code
            )

        return res

    def _detect_target_type(self, path: Path) -> TargetType:
        if path.suffix in [".sol"]:
            return TargetType.SMART_CONTRACT
        return TargetType.WEB_APP_API
