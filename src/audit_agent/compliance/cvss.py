"""CVSS v3.1 Scoring Engine and Web3 Financial Risk Exposure Calculator."""
from typing import Dict, Any, Tuple
from audit_agent.models import VulnerabilityCategory, Severity


class CVSSScorer:
    """Computes CVSS v3.1 Vector Strings and Base Scores for vulnerabilities."""

    @classmethod
    def calculate_score(cls, category: VulnerabilityCategory) -> Tuple[float, str, str]:
        """Returns (base_score, vector_string, financial_exposure_tier)."""
        if category == VulnerabilityCategory.REENTRANCY:
            # Network / Low Complexity / None Privileges / None User Interaction / Unchanged / High Impact
            vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
            return 9.8, vector, "EXTREME (100% Total Value at Risk - Protocol Insolvency)"

        elif category == VulnerabilityCategory.AUTHORIZATION_BYPASS:
            # Network / Low Complexity / None Privileges / None User Interaction / Unchanged / High Impact
            vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
            return 9.1, vector, "CRITICAL (Full Administrative Takeover / Privilege Escalation)"

        elif category == VulnerabilityCategory.IDOR:
            # Network / Low Complexity / Low Privileges / None User Interaction / Unchanged / High Confidentiality
            vector = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N"
            return 7.1, vector, "HIGH (Cross-Tenant Data Exfiltration)"

        elif category == VulnerabilityCategory.UNCHECKED_CALL:
            vector = "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:M/A:M"
            return 5.3, vector, "MEDIUM (Silent Execution Failure / State Inconsistency)"

        return 5.0, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N", "LOW (Minor Operational Risk)"
