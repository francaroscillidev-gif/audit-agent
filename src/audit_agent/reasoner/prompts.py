"""Prompts and templates for LLM Semantic Reasoning and Test Harness Synthesis."""

SYSTEM_PROMPT_SECURITY_EXPERT = """You are an elite Smart Contract and Application Security Auditor.
Your objective is to identify REAL, high-impact business logic and security vulnerabilities, avoiding false positives.

For every suspicious pattern you find:
1. Clearly articulate the PRECONDITIONS required.
2. Define the exact SEQUENCE OF ACTIONS an attacker would take.
3. Define the INVARIANT BREACH that proves the bug (e.g. "Contract balance drops to 0 while attacker balance multiplies", or "Attacker alters state of user B").
4. Provide a concrete, executable TEST HARNESS (Foundry .t.sol or pytest) that demonstrates the bug.
"""

HYPOTHESIS_GENERATION_PROMPT = """Analyze the following source code and the initial static heuristics detected.

Source File: {filename}
```
{source_code}
```

Static Heuristics Detected:
{heuristics_json}

For each candidate vulnerability:
1. Formulate a hypothesis with:
   - id: "HYP-001"
   - title
   - severity (critical, high, medium, low)
   - category (reentrancy, authorization_bypass, idor, race_condition, etc.)
   - target_file
   - affected_lines
   - description
   - preconditions
   - exploit_hypothesis
   - expected_invariant_breach
   - proposed_fix

Return your response as structured JSON.
"""

TEST_SYNTHESIS_PROMPT = """Given this vulnerability hypothesis:
Title: {title}
Category: {category}
Expected Invariant Breach: {expected_invariant_breach}

Source Code:
```
{source_code}
```

Generate a self-contained, reproducible test harness (Foundry Solidity test or Python test) that executes the exploit scenario.
The test must:
1. Setup the initial legitimate state.
2. Execute the exploit steps.
3. Assert the invariant breach. If the bug exists, the test should PASS the invariant breach check (proving vulnerability).
"""
