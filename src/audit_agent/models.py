"""Data models and schemas for AuditAgent."""
from enum import Enum
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field


class TargetType(str, Enum):
    SMART_CONTRACT = "smart_contract"
    WEB_APP_API = "web_app_api"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class VulnerabilityCategory(str, Enum):
    REENTRANCY = "reentrancy"
    AUTHORIZATION_BYPASS = "authorization_bypass"
    IDOR = "idor"
    RACE_CONDITION = "race_condition"
    INPUT_VALIDATION = "input_validation"
    INTEGER_ARITHMETIC = "integer_arithmetic"
    LOGIC_FLAW = "business_logic_flaw"
    UNCHECKED_CALL = "unchecked_external_call"


class VerificationStatus(str, Enum):
    CONFIRMED = "confirmed"              # Bug proven: test reproduced the invariant breach
    REFUTED = "refuted"                  # False positive: test proved invariant holds / exploit failed
    HARNESS_ERROR = "harness_error"      # Test harness failed to compile/run properly
    SKIPPED = "skipped"                  # Could not safely verify


class VulnerabilityHypothesis(BaseModel):
    id: str = Field(..., description="Unique ID, e.g. HYP-001")
    title: str
    severity: Severity
    category: VulnerabilityCategory
    target_file: str
    affected_lines: List[int] = Field(default_factory=list)
    description: str
    preconditions: str
    exploit_hypothesis: str
    expected_invariant_breach: str
    proposed_fix: Optional[str] = None


class VerificationTestHarness(BaseModel):
    hypothesis_id: str
    framework: str = Field(..., description="e.g. 'foundry', 'hardhat', 'pytest', 'simulated_evm'")
    test_code: str
    test_filename: str
    execution_command: str


class VerificationResult(BaseModel):
    hypothesis_id: str
    status: VerificationStatus
    output_log: str
    duration_ms: float = 0.0
    invariant_breach_detected: bool = False
    details: Optional[str] = None


class VerifiedFinding(BaseModel):
    hypothesis: VulnerabilityHypothesis
    verification: VerificationResult
    is_false_positive: bool
    remediation_patch: Optional[str] = None


class AuditSummary(BaseModel):
    target_path: str
    target_type: TargetType
    total_hypotheses: int
    confirmed_bugs: int
    false_positives_pruned: int
    unverifiable: int
    pruning_efficiency_pct: float
    findings: List[VerifiedFinding]
