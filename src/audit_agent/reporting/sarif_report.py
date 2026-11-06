"""OASIS SARIF v2.1.0 Exporter for native GitHub Code Scanning integration."""
import json
from pathlib import Path
from typing import Dict, Any, List
from audit_agent.models import AuditSummary, VerificationStatus, Severity
from audit_agent.compliance.registry import ComplianceRegistry


class SARIFReportGenerator:
    """Generates standard SARIF v2.1.0 reports compatible with GitHub Security Alerts and SonarQube."""

    @staticmethod
    def generate(summary: AuditSummary, output_path: str) -> None:
        rules: List[Dict[str, Any]] = []
        results: List[Dict[str, Any]] = []
        rule_ids_seen = set()

        confirmed_findings = [f for f in summary.findings if f.verification.status == VerificationStatus.CONFIRMED]

        for finding in confirmed_findings:
            hyp = finding.hypothesis
            comp = ComplianceRegistry.get_compliance_info(hyp.category)
            rule_id = comp["swc_id"] if comp["swc_id"] != "N/A" else comp["cwe_id"]

            if rule_id not in rule_ids_seen:
                rule_ids_seen.add(rule_id)
                rules.append({
                    "id": rule_id,
                    "name": hyp.category.value.replace("_", " ").title().replace(" ", ""),
                    "shortDescription": {"text": hyp.title},
                    "fullDescription": {"text": hyp.description},
                    "help": {
                        "text": f"Remediation: {comp['remediation_guideline']}\n\nStandard: {comp['cwe_title']}",
                        "markdown": f"**Remediation:** {comp['remediation_guideline']}\n\n**CWE:** [{comp['cwe_id']} - {comp['cwe_title']}](https://cwe.mitre.org/data/definitions/{comp['cwe_id'].replace('CWE-', '')}.html)"
                    },
                    "properties": {
                        "category": comp["owasp_category"],
                        "precision": "very-high"  # High precision because empirical PoC proved it!
                    }
                })

            level = "error" if hyp.severity in [Severity.CRITICAL, Severity.HIGH] else "warning"
            start_line = hyp.affected_lines[0] if hyp.affected_lines else 1

            result_entry = {
                "ruleId": rule_id,
                "level": level,
                "message": {
                    "text": f"[Empirical PoC Verified] {hyp.title}. Invariant breach: {hyp.expected_invariant_breach}"
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": hyp.target_file,
                                "uriBaseId": "%SRCROOT%"
                            },
                            "region": {
                                "startLine": start_line,
                                "startColumn": 1
                            }
                        }
                    }
                ]
            }

            if finding.remediation_patch:
                result_entry["fixes"] = [
                    {
                        "description": {"text": "Apply automated Checks-Effects / access control fix"},
                        "fileChanges": [
                            {
                                "artifactLocation": {"uri": hyp.target_file},
                                "replacements": [
                                    {
                                        "deletedRegion": {"startLine": start_line},
                                        "insertedContent": {"text": finding.remediation_patch}
                                    }
                                ]
                            }
                        ]
                    }
                ]

            results.append(result_entry)

        sarif_document = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "AuditAgent",
                            "semanticVersion": "0.2.0",
                            "informationUri": "https://github.com/francaroscillidev-gif/audit-agent",
                            "rules": rules
                        }
                    },
                    "results": results
                }
            ]
        }

        Path(output_path).write_text(json.dumps(sarif_document, indent=2), encoding="utf-8")
