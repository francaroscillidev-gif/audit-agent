"""Automated patch generation and remediation for verified vulnerabilities."""
import difflib
import re
from typing import Optional
from audit_agent.models import VulnerabilityCategory, VerifiedFinding


class RemediationPatcher:
    """Generates unified diff patches for verified security vulnerabilities."""

    @staticmethod
    def generate_patch(finding: VerifiedFinding, source_code: str) -> Optional[str]:
        hyp = finding.hypothesis
        modified_lines = source_code.splitlines(keepends=True)

        if hyp.category == VulnerabilityCategory.REENTRANCY:
            # Reorder Checks-Effects: Move balance update before external call
            new_source = RemediationPatcher._fix_reentrancy(source_code)
            if new_source != source_code:
                return RemediationPatcher._compute_diff(source_code, new_source, hyp.target_file)

        elif hyp.category == VulnerabilityCategory.AUTHORIZATION_BYPASS:
            # Add onlyOwner modifier to vulnerable function
            new_source = RemediationPatcher._fix_authorization(source_code, hyp.title)
            if new_source != source_code:
                return RemediationPatcher._compute_diff(source_code, new_source, hyp.target_file)

        elif hyp.category == VulnerabilityCategory.IDOR:
            # Add ownership check
            new_source = RemediationPatcher._fix_idor(source_code)
            if new_source != source_code:
                return RemediationPatcher._compute_diff(source_code, new_source, hyp.target_file)

        return None

    @staticmethod
    def _fix_reentrancy(source: str) -> str:
        lines = source.splitlines()
        withdraw_start = -1
        call_idx = -1
        write_idx = -1

        for idx, line in enumerate(lines):
            if "function withdraw(" in line or "function withdraw" in line:
                withdraw_start = idx
            if withdraw_start != -1 and ".call{value:" in line:
                call_idx = idx
            if withdraw_start != -1 and call_idx != -1 and ("balances[msg.sender] = 0" in line or "balances[msg.sender] -=" in line):
                write_idx = idx
                break

        if call_idx != -1 and write_idx != -1 and write_idx > call_idx:
            # Swap lines: place write line before call line
            updated = list(lines)
            write_line = updated.pop(write_idx)
            updated.insert(call_idx, "        // FIX: Checks-Effects-Interactions (state update moved before external call)")
            updated.insert(call_idx + 1, write_line)
            return "\n".join(updated) + "\n"

        return source

    @staticmethod
    def _fix_authorization(source: str, title: str) -> str:
        # Extract function name from title if possible
        match = re.search(r"function '([A-Za-z0-9_]+)'", title)
        if match:
            fn_name = match.group(1)
            pattern = re.compile(rf"(function\s+{fn_name}\s*\([^)]*\)\s*(?:public|external))(\s*)")
            if pattern.search(source):
                return pattern.sub(r"\1 onlyOwner\2", source)
        return source

    @staticmethod
    def _fix_idor(source: str) -> str:
        # Inject authorization verification
        pattern = re.compile(r"(def\s+[A-Za-z0-9_]+\s*\([^)]*current_user[^)]*\):)")
        if pattern.search(source):
            return pattern.sub(r"\1\n    # FIX: Verify resource ownership\n    if item.owner_id != current_user.id:\n        raise HTTPException(status_code=403, detail='Unauthorized access')", source)
        return source

    @staticmethod
    def _compute_diff(original: str, modified: str, filename: str) -> str:
        orig_lines = original.splitlines(keepends=True)
        mod_lines = modified.splitlines(keepends=True)
        diff = difflib.unified_diff(
            orig_lines,
            mod_lines,
            fromfile=f"a/{filename}",
            tofile=f"b/{filename}",
            lineterm=""
        )
        return "".join(diff)
