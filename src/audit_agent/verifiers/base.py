"""Base interface for Verification Engines."""
from abc import ABC, abstractmethod
from audit_agent.models import VulnerabilityHypothesis, VerificationTestHarness, VerificationResult


class BaseVerifier(ABC):
    """Abstract base class for running verification harnesses and checking invariant breaches."""

    @abstractmethod
    def verify(
        self,
        hypothesis: VulnerabilityHypothesis,
        harness: VerificationTestHarness,
        source_code: str,
    ) -> VerificationResult:
        """Execute the test harness and return the verification result."""
        pass
