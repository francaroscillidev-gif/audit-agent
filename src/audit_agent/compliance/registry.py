"""Taxonomy and registry mapping vulnerabilities to SWC (Smart Contract Weakness) and CWE."""
from typing import Dict, Any, Optional
from audit_agent.models import VulnerabilityCategory


class ComplianceRegistry:
    """Security standard mapping for SWC Registry, CWE, and OWASP Top 10."""

    REGISTRY: Dict[VulnerabilityCategory, Dict[str, Any]] = {
        VulnerabilityCategory.REENTRANCY: {
            "swc_id": "SWC-107",
            "swc_title": "Reentrancy",
            "cwe_id": "CWE-841",
            "cwe_title": "Improper Enforcement of Behavioral Workflow",
            "owasp_category": "A04:2021-Insecure Design",
            "remediation_guideline": "Adhere strictly to the Checks-Effects-Interactions pattern or implement OpenZeppelin ReentrancyGuard.",
            "references": [
                "https://swcregistry.io/docs/SWC-107",
                "https://cwe.mitre.org/data/definitions/841.html"
            ]
        },
        VulnerabilityCategory.AUTHORIZATION_BYPASS: {
            "swc_id": "SWC-105",
            "swc_title": "Unprotected Ether Withdrawal / State Mutation",
            "cwe_id": "CWE-285",
            "cwe_title": "Improper Authorization",
            "owasp_category": "A01:2021-Broken Access Control",
            "remediation_guideline": "Ensure all administrative functions have strict access control modifiers (e.g. onlyOwner, AccessControl).",
            "references": [
                "https://swcregistry.io/docs/SWC-105",
                "https://cwe.mitre.org/data/definitions/285.html"
            ]
        },
        VulnerabilityCategory.IDOR: {
            "swc_id": "N/A",
            "swc_title": "N/A (Web Application Flaw)",
            "cwe_id": "CWE-639",
            "cwe_title": "Authorization Bypass Through User-Controlled Key",
            "owasp_category": "A01:2021-Broken Access Control",
            "remediation_guideline": "Validate that the authenticated session owns or is authorized to read/modify the requested resource identifier.",
            "references": [
                "https://cwe.mitre.org/data/definitions/639.html",
                "https://owasp.org/Top10/A01_2021-Broken_Access_Control/"
            ]
        },
        VulnerabilityCategory.UNCHECKED_CALL: {
            "swc_id": "SWC-104",
            "swc_title": "Unchecked Call Return Value",
            "cwe_id": "CWE-252",
            "cwe_title": "Unchecked Return Value",
            "owasp_category": "A04:2021-Insecure Design",
            "remediation_guideline": "Always verify return values of low-level calls with require(success, ...).",
            "references": [
                "https://swcregistry.io/docs/SWC-104"
            ]
        }
    }

    @classmethod
    def get_compliance_info(cls, category: VulnerabilityCategory) -> Dict[str, Any]:
        return cls.REGISTRY.get(category, {
            "swc_id": "SWC-UNKNOWN",
            "swc_title": category.value,
            "cwe_id": "CWE-699",
            "cwe_title": "Software Development Security Flaw",
            "owasp_category": "A04:2021-Insecure Design",
            "remediation_guideline": "Review business logic invariants and enforce defensive state transitions.",
            "references": []
        })
