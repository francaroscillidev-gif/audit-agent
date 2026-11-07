"""Gas Optimization and MEV / Front-Running Analysis Engine for Solidity Smart Contracts."""
import re
from typing import List, Dict, Any
from pydantic import BaseModel, Field


class GasOptimizationItem(BaseModel):
    category: str  # "GAS_OPTIMIZATION" or "MEV_VULNERABILITY"
    title: str
    line_number: int
    estimated_gas_savings: str
    severity: str  # "HIGH", "MEDIUM", "LOW", "INFO"
    description: str
    recommendation: str


class GasMEVAnalyzer:
    """Detects MEV / Sandwich attack vectors and actionable Gas optimizations in Solidity."""

    @classmethod
    def analyze(cls, source_code: str) -> List[GasOptimizationItem]:
        items: List[GasOptimizationItem] = []
        lines = source_code.splitlines()

        # Check single-line and multi-line DEX calls
        full_code = re.sub(r"/\*.*?\*/", "", source_code, flags=re.DOTALL)
        
        # 1. MEV: Slippage Protection Missing (amountOutMin == 0) in multi-line call
        dex_swap_pattern = re.compile(
            r"(swapExactTokensForTokens|swapExactETHForTokens|swapExactTokensForETH)\s*\(([^)]+)\)",
            re.DOTALL
        )
        for match in dex_swap_pattern.finditer(full_code):
            args_str = match.group(2)
            args = [a.strip() for a in args_str.split(",") if a.strip()]
            start_pos = match.start()
            call_line = full_code[:start_pos].count("\n") + 1

            # Second parameter is amountOutMin
            if len(args) >= 2 and args[1] == "0":
                items.append(GasOptimizationItem(
                    category="MEV_VULNERABILITY",
                    title="DEX Swap with 0 Minimum Output (Zero Slippage Protection)",
                    line_number=call_line,
                    estimated_gas_savings="N/A (Prevents 100% loss from Sandwich Attacks)",
                    severity="HIGH",
                    description="DEX swap specifies amountOutMin = 0, exposing the transaction to front-running sandwich attacks by MEV bots.",
                    recommendation="Compute and enforce a non-zero amountOutMin based on acceptable slippage tolerance."
                ))

            # Last parameter is deadline
            if len(args) >= 5 and "block.timestamp" in args[-1]:
                items.append(GasOptimizationItem(
                    category="MEV_VULNERABILITY",
                    title="DEX Deadline using current block.timestamp",
                    line_number=call_line,
                    estimated_gas_savings="N/A (Prevents Miner/Validator front-running)",
                    severity="MEDIUM",
                    description="Passing block.timestamp as deadline disables expiration protection; validators can hold transaction indefinitely until profitable.",
                    recommendation="Pass a caller-defined deadline timestamp from function parameters."
                ))

        for idx, line in enumerate(lines):
            line_no = idx + 1
            stripped = line.strip()

            if stripped.startswith("//") or stripped.startswith("/*"):
                continue

            # 3. Gas: memory instead of calldata for external function parameters
            if "external" in stripped and "function " in stripped:
                if "string memory" in stripped or "bytes memory" in stripped or "[] memory" in stripped:
                    items.append(GasOptimizationItem(
                        category="GAS_OPTIMIZATION",
                        title="Use 'calldata' instead of 'memory' for external function parameters",
                        line_number=line_no,
                        estimated_gas_savings="~300 - 1,200 gas per parameter",
                        severity="LOW",
                        description="For external functions, parameters marked 'memory' are copied into memory from calldata. Marking them 'calldata' avoids the memory allocation and copying cost.",
                        recommendation="Change parameter location from 'memory' to 'calldata'."
                    ))

            # 4. Gas: for-loop increment not wrapped in unchecked
            if re.search(r"for\s*\([^;]+;[^;]+;\s*(\+\+i|i\+\+|\+\+j|j\+\+)\s*\)", stripped):
                items.append(GasOptimizationItem(
                    category="GAS_OPTIMIZATION",
                    title="Loop counter increment can be unchecked",
                    line_number=line_no,
                    estimated_gas_savings="~30 - 40 gas per loop iteration",
                    severity="INFO",
                    description="In Solidity >= 0.8.0, arithmetic operations have default overflow checks. Since the loop counter cannot exceed array bounds, wrapping ++i in 'unchecked' saves gas.",
                    recommendation="Refactor loop increment: unchecked { ++i; }"
                ))

            # 5. Gas: State variable could be constant or immutable
            if re.search(r"^\s*(address|uint256|uint)\s+(public|private|internal)?\s*[a-zA-Z0-9_]+\s*=\s*[0-9a-zA-Z_]+;", line):
                if "constant" not in stripped and "immutable" not in stripped:
                    items.append(GasOptimizationItem(
                        category="GAS_OPTIMIZATION",
                        title="State variable initialized at declaration could be 'constant'",
                        line_number=line_no,
                        estimated_gas_savings="~2,100 gas per read (avoids SLOAD)",
                        severity="LOW",
                        description="State variables that never change after declaration should be marked 'constant' to replace storage reads (SLOAD) with bytecode constants.",
                        recommendation="Add 'constant' keyword to variable declaration."
                    ))

        return items
