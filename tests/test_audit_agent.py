"""Unit and integration test suite for AuditAgent."""
import tempfile
from pathlib import Path
from audit_agent.models import TargetType, VerificationStatus, VerificationTestHarness
from audit_agent.parsers.solidity import SolidityASTParser
from audit_agent.parsers.webapp import WebAPIASTParser
from audit_agent.orchestrator import AuditOrchestrator
from audit_agent.reporting.html_report import HTMLReportGenerator
from audit_agent.reasoner.engine import SemanticReasoner


def test_solidity_parser_heuristics():
    code = """
    contract TestContract {
        mapping(address => uint256) public balances;
        function withdraw() external {
            msg.sender.call{value: 10}("");
            balances[msg.sender] = 0;
        }
    }
    """
    parser = SolidityASTParser(code)
    heuristics = parser.detect_static_heuristics()
    assert any(h["heuristic"] == "POTENTIAL_REENTRANCY" for h in heuristics)


def test_webapp_parser_heuristics():
    code = """
    from fastapi import FastAPI
    app = FastAPI()
    @app.get("/items/{item_id}")
    def get_item(item_id: int):
        return {"id": item_id}
    """
    parser = WebAPIASTParser(code)
    heuristics = parser.detect_static_heuristics()
    assert any(h["heuristic"] == "POTENTIAL_IDOR_OR_UNAUTHENTICATED_ACCESS" for h in heuristics)


def test_orchestrator_smart_contract_audit():
    orchestrator = AuditOrchestrator()
    summary = orchestrator.run_audit("examples/VulnerableVault.sol")
    assert summary.total_hypotheses >= 3
    assert summary.confirmed_bugs >= 1
    assert summary.false_positives_pruned >= 1

    # Check that Reentrancy was verified and confirmed
    reentrancy_finding = next(
        f for f in summary.findings if "reentrancy" in f.hypothesis.category.value
    )
    assert reentrancy_finding.verification.status == VerificationStatus.CONFIRMED
    assert reentrancy_finding.remediation_patch is not None


def test_orchestrator_webapp_audit():
    orchestrator = AuditOrchestrator()
    summary = orchestrator.run_audit("examples/vulnerable_api.py")
    assert summary.confirmed_bugs >= 1
    idor_finding = next(f for f in summary.findings if "IDOR" in f.hypothesis.title)
    assert idor_finding.verification.status == VerificationStatus.CONFIRMED


def test_html_report_generator():
    orchestrator = AuditOrchestrator()
    summary = orchestrator.run_audit("examples/VulnerableVault.sol")
    with tempfile.TemporaryDirectory() as tmpdir:
        report_file = Path(tmpdir) / "report.html"
        HTMLReportGenerator.generate(summary, str(report_file))
        assert report_file.exists()
        content = report_file.read_text()
        assert "<!DOCTYPE html>" in content
        assert "Confirmed Vulnerabilities" in content
        assert "HYP-001" in content


def test_project_wide_audit():
    orchestrator = AuditOrchestrator()
    summary = orchestrator.run_project_audit("examples")
    assert summary.total_hypotheses >= 4
    assert summary.confirmed_bugs >= 2
    assert summary.false_positives_pruned >= 2


def test_harness_self_repair():
    reasoner = SemanticReasoner()
    faulty_harness = VerificationTestHarness(
        hypothesis_id="HYP-999",
        framework="foundry",
        test_code="contract BrokenTest { function test() public {} }",
        test_filename="test_broken.sol",
        execution_command="forge test",
    )
    error_log = "Error: Function not found or pragma missing"
    repaired = reasoner.repair_test_harness(faulty_harness, error_log, "")
    assert "pragma solidity" in repaired.test_code
