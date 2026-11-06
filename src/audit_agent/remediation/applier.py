"""Automated and validated patch applier with backup and post-fix invariant re-verification."""
import shutil
from pathlib import Path
from typing import Tuple, Optional
from audit_agent.models import VerifiedFinding, VerificationStatus
from audit_agent.remediation.patcher import RemediationPatcher


class PatchApplier:
    """Applies verified security patches to source files and confirms resolution."""

    @staticmethod
    def apply_and_verify(
        finding: VerifiedFinding,
        verifier,
        reasoner,
    ) -> Tuple[bool, str]:
        """Apply patch to target file and re-verify invariant to confirm remediation."""
        hyp = finding.hypothesis
        target_path = Path(hyp.target_file)
        if not target_path.exists():
            return False, f"Target file {target_path} not found"

        original_code = target_path.read_text(encoding="utf-8")

        # Compute new content based on vulnerability category
        if finding.hypothesis.category.value == "reentrancy":
            new_code = RemediationPatcher._fix_reentrancy(original_code)
        elif finding.hypothesis.category.value == "authorization_bypass":
            new_code = RemediationPatcher._fix_authorization(original_code, hyp.title)
        elif finding.hypothesis.category.value == "idor":
            new_code = RemediationPatcher._fix_idor(original_code)
        else:
            return False, "Automated patch not supported for this category"

        if new_code == original_code:
            return False, "Patch could not be applied or code is already patched"

        # Create backup
        backup_path = target_path.with_suffix(target_path.suffix + ".bak")
        shutil.copyfile(target_path, backup_path)

        # Write patched code
        target_path.write_text(new_code, encoding="utf-8")

        # Post-fix verification: Re-run test harness to ensure exploit now FAILS (invariant holds!)
        harness = reasoner.synthesize_test_harness(hyp, new_code, verifier.__class__.__name__)
        re_result = verifier.verify(hyp, harness, new_code)

        if re_result.status == VerificationStatus.REFUTED or not re_result.invariant_breach_detected:
            # Exploit neutralized!
            if backup_path.exists():
                backup_path.unlink()  # Clean up backup on success
            return True, f"Patch successfully applied to {target_path.name} and re-verified: exploit neutralized!"
        else:
            # Revert to original if test still breaches invariant
            shutil.copyfile(backup_path, target_path)
            return False, "Patch failed post-verification: exploit was not fully neutralized. File rolled back."
