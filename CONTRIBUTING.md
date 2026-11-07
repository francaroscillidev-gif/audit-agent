# Contributing to AuditAgent

Thank you for your interest in contributing to **AuditAgent**! We welcome contributions from developers, security researchers, and Web3 auditors.

---

## 🛠️ Development Setup

1. **Clone the repository:**
   ```bash
   git clone https://github.com/francaroscillidev-gif/audit-agent.git
   cd audit-agent
   ```

2. **Install dependencies with `uv`:**
   ```bash
   uv sync
   ```

3. **Run the test suite:**
   ```bash
   uv run pytest
   ```

---

## 🧩 Adding a New Vulnerability Detector

AuditAgent relies on a 3-step verification architecture:
1. **Static AST Pattern:** Add structural heuristics in [`src/audit_agent/parsers/`](src/audit_agent/parsers/).
2. **Semantic Hypothesis:** Update the reasoning engine in [`src/audit_agent/reasoner/`](src/audit_agent/reasoner/) to formulate the invariant breach scenario.
3. **Empirical Verifier:** Ensure the test harness simulator in [`src/audit_agent/verifiers/`](src/audit_agent/verifiers/) tests the invariant and eliminates false positives.
4. **Remediation Patch:** Add an automated unified diff fix in [`src/audit_agent/remediation/`](src/audit_agent/remediation/).
5. **Unit Tests:** Add corresponding test cases in [`tests/test_audit_agent.py`](tests/test_audit_agent.py).

---

## 📋 Git Commit Guidelines

We follow Conventional Commits:
- `feat:` New features or security detectors
- `fix:` Bug fixes or false-positive tuning
- `docs:` Documentation and guides
- `test:` Unit or integration test suites
- `refactor:` Code improvements without behavioral changes

---

## 👥 Code Review Process

1. Open a Pull Request against the `main` branch.
2. Ensure all `pytest` checks pass.
3. Maintainers will review the PR for security, test coverage, and code quality.
