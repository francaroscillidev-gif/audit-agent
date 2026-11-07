"""Unit and integration test suite for AuditAgent."""
import json
import shutil
import tempfile
from pathlib import Path
from audit_agent.models import TargetType, VerificationStatus, VerificationTestHarness, VulnerabilityCategory
from audit_agent.parsers.solidity import SolidityASTParser
from audit_agent.parsers.webapp import WebAPIASTParser
from audit_agent.orchestrator import AuditOrchestrator
from audit_agent.reporting.html_report import HTMLReportGenerator
from audit_agent.reporting.sarif_report import SARIFReportGenerator
from audit_agent.reporting.test_exporter import TestExporter
from audit_agent.reasoner.engine import SemanticReasoner
from audit_agent.reasoner.providers import LLMProviderAdapter
from audit_agent.compliance.registry import ComplianceRegistry
from audit_agent.compliance.cvss import CVSSScorer
from audit_agent.fuzzing.invariants import StatefulInvariantFuzzer
from audit_agent.remediation.applier import PatchApplier
from audit_agent.analysis.cfg import CFGBuilder
from audit_agent.analysis.taint import TaintAnalyzer
from audit_agent.analysis.callgraph import CallGraphResolver


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


def test_sarif_report_generator():
    orchestrator = AuditOrchestrator()
    summary = orchestrator.run_audit("examples/VulnerableVault.sol")
    with tempfile.TemporaryDirectory() as tmpdir:
        sarif_file = Path(tmpdir) / "report.sarif"
        SARIFReportGenerator.generate(summary, str(sarif_file))
        assert sarif_file.exists()
        data = json.loads(sarif_file.read_text())
        assert data["version"] == "2.1.0"
        assert len(data["runs"]) > 0
        assert len(data["runs"][0]["results"]) >= 1


def test_compliance_registry():
    reentrancy_info = ComplianceRegistry.get_compliance_info(VulnerabilityCategory.REENTRANCY)
    assert reentrancy_info["swc_id"] == "SWC-107"
    assert reentrancy_info["cwe_id"] == "CWE-841"

    idor_info = ComplianceRegistry.get_compliance_info(VulnerabilityCategory.IDOR)
    assert idor_info["cwe_id"] == "CWE-639"


def test_stateful_invariant_fuzzing():
    vault_code = Path("examples/VulnerableVault.sol").read_text()
    fuzzer = StatefulInvariantFuzzer(vault_code, iterations=50)
    results = fuzzer.run_fuzzing()
    assert len(results) >= 2
    # Check that solvency invariant caught the reentrancy counterexample
    solvency_res = next(r for r in results if r.invariant_name == "invariant_vaultSolvency")
    assert solvency_res.passed is False
    assert len(solvency_res.failure_counterexample) > 0


def test_test_exporter():
    orchestrator = AuditOrchestrator()
    summary = orchestrator.run_audit("examples/VulnerableVault.sol")
    with tempfile.TemporaryDirectory() as tmpdir:
        files = TestExporter.export(summary, tmpdir)
        assert len(files) >= 1
        assert any(f.suffix == ".sol" for f in files)


def test_patch_applier_and_reverification():
    orchestrator = AuditOrchestrator()
    summary = orchestrator.run_audit("examples/VulnerableVault.sol")
    reentrancy_finding = next(f for f in summary.findings if f.hypothesis.category == VulnerabilityCategory.REENTRANCY)

    with tempfile.TemporaryDirectory() as tmpdir:
        copy_sol = Path(tmpdir) / "VulnerableVault.sol"
        copy_sol.write_text(Path("examples/VulnerableVault.sol").read_text())

        # Update finding target file to temporary copy
        reentrancy_finding.hypothesis.target_file = str(copy_sol)
        success, msg = PatchApplier.apply_and_verify(
            reentrancy_finding,
            orchestrator.solidity_verifier,
            orchestrator.reasoner
        )
        assert success is True
        assert "neutralized" in msg


def test_llm_provider_adapter():
    adapter = LLMProviderAdapter(provider="offline_expert")
    assert adapter.complete("test prompt") is None
    gemini_adapter = LLMProviderAdapter(provider="gemini", api_key="dummy_key")
    assert gemini_adapter.model == "gemini-2.5-flash"


def test_cfg_builder():
    fn_lines = [
        "function withdraw() external {",
        "    msg.sender.call{value: 10}('');",
        "    balances[msg.sender] = 0;",
        "}"
    ]
    cfg = CFGBuilder.build("withdraw", fn_lines)
    assert len(cfg.blocks) >= 2
    assert cfg.entry_block == "B0"


def test_taint_analyzer():
    fn_lines = [
        "function setOwner(address newOwner) external {",
        "    owner = newOwner;",
        "}"
    ]
    flows = TaintAnalyzer.analyze_solidity_function("setOwner", fn_lines)
    assert len(flows) >= 1
    assert any(f.sink_type == "OWNER_MUTATION" for f in flows)


def test_callgraph_resolver():
    code = """
    contract BaseContract { }
    contract MyVault is BaseContract {
        function foo() external {
            otherContract.callMe();
        }
    }
    """
    cg = CallGraphResolver.resolve_contracts(code)
    assert "MyVault" in cg.contracts
    assert "BaseContract" in cg.get_inheritance_tree("MyVault")


def test_cvss_scorer():
    score, vector, tier = CVSSScorer.calculate_score(VulnerabilityCategory.REENTRANCY)
    assert score == 9.8
    assert "CVSS:3.1" in vector
    assert "EXTREME" in tier


def test_gas_mev_analyzer():
    from audit_agent.analysis.gas_mev import GasMEVAnalyzer
    defi_code = Path("examples/DeFiSwapVault.sol").read_text()
    items = GasMEVAnalyzer.analyze(defi_code)
    assert len(items) >= 4
    assert any(i.category == "MEV_VULNERABILITY" for i in items)
    assert any(i.category == "GAS_OPTIMIZATION" for i in items)


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


def test_cli_version_flag():
    from typer.testing import CliRunner
    from audit_agent.cli import app
    runner = CliRunner()
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert "AuditAgent version 1.0.0" in result.output
