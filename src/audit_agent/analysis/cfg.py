"""Control Flow Graph (CFG) Construction and Analysis for Smart Contracts and Code."""
import re
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field


class BasicBlock(BaseModel):
    block_id: str
    function_name: str
    start_line: int
    end_line: int
    statements: List[str] = Field(default_factory=list)
    has_external_call: bool = False
    has_state_write: bool = False
    is_conditional_branch: bool = False
    condition: Optional[str] = None
    successors: List[str] = Field(default_factory=list)


class ControlFlowGraph(BaseModel):
    function_name: str
    entry_block: str
    blocks: Dict[str, BasicBlock] = Field(default_factory=dict)

    def find_checks_effects_inversion_paths(self) -> List[List[str]]:
        """Identify execution paths where an external call block leads directly to a state write block."""
        violating_paths = []

        def dfs(current_id: str, visited: List[str], saw_call: bool):
            block = self.blocks.get(current_id)
            if not block or current_id in visited:
                return

            new_visited = visited + [current_id]
            currently_saw_call = saw_call or block.has_external_call

            if currently_saw_call and block.has_state_write and not block.has_external_call:
                violating_paths.append(new_visited)

            for succ in block.successors:
                dfs(succ, new_visited, currently_saw_call)

        dfs(self.entry_block, [], False)
        return violating_paths


class CFGBuilder:
    """Constructs function-level Control Flow Graphs from source code."""

    @staticmethod
    def build(function_name: str, fn_lines: List[str], base_line_offset: int = 1) -> ControlFlowGraph:
        cfg = ControlFlowGraph(function_name=function_name, entry_block="B0")
        current_block_id = "B0"
        block_counter = 0

        current_stmts = []
        block_start = base_line_offset
        has_call = False
        has_write = False

        for idx, line in enumerate(fn_lines):
            line_no = base_line_offset + idx
            stripped = line.strip()

            if not stripped or stripped.startswith("//"):
                continue

            # Detect external calls
            if re.search(r"(\.call\{|\.transfer\(|\.send\(|\.delegatecall\()", stripped):
                has_call = True

            # Detect state variable writes
            if re.search(r"([A-Za-z0-9_\[\]]+)\s*(=|\+=|-=|\*=)\s*", stripped) and not stripped.startswith("emit ") and not stripped.startswith("require"):
                has_write = True

            # Detect branching (if / else / require)
            is_branch = stripped.startswith("if ") or stripped.startswith("if(")
            current_stmts.append(stripped)

            if is_branch or has_call:
                # Close current block and branch
                next_block_id = f"B{block_counter + 1}"
                cfg.blocks[current_block_id] = BasicBlock(
                    block_id=current_block_id,
                    function_name=function_name,
                    start_line=block_start,
                    end_line=line_no,
                    statements=current_stmts,
                    has_external_call=has_call,
                    has_state_write=has_write,
                    is_conditional_branch=is_branch,
                    condition=stripped if is_branch else None,
                    successors=[next_block_id]
                )
                block_counter += 1
                current_block_id = next_block_id
                current_stmts = []
                block_start = line_no + 1
                has_call = False
                has_write = False

        # Close final block
        if current_stmts or not cfg.blocks:
            cfg.blocks[current_block_id] = BasicBlock(
                block_id=current_block_id,
                function_name=function_name,
                start_line=block_start,
                end_line=base_line_offset + len(fn_lines) - 1,
                statements=current_stmts,
                has_external_call=has_call,
                has_state_write=has_write,
                is_conditional_branch=False,
                successors=[]
            )

        return cfg
