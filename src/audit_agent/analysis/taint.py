"""Taint Analysis Engine tracing untrusted sources to sensitive sinks."""
import re
from typing import List, Dict, Set, Optional
from pydantic import BaseModel, Field


class TaintFlow(BaseModel):
    source_name: str
    source_line: int
    sink_type: str
    sink_line: int
    sink_expression: str
    variable_path: List[str]
    is_sanitized: bool
    sanitizer_expression: Optional[str] = None
    severity: str = "HIGH"
    description: str


class TaintAnalyzer:
    """Performs intra-procedural data-flow taint analysis."""

    WEB3_SOURCES = {"msg.sender", "msg.value", "msg.data", "tx.origin"}
    WEB3_SINKS = {
        "CALL_VALUE": r"\.call\{value:",
        "DELEGATECALL": r"\.delegatecall\(",
        "SELFDESTRUCT": r"selfdestruct\(",
        "OWNER_MUTATION": r"owner\s*=",
    }
    WEB3_GUARDS = ["onlyowner", "require(msg.sender ==", "require(owner =="]

    WEB_SOURCES = {"request.args", "request.form", "params", "user_id", "doc_id", "body"}
    WEB_SINKS = {
        "RAW_SQL": r"(execute|cursor\.execute|raw_sql)\(",
        "COMMAND_EXEC": r"(subprocess\.|os\.system|exec\()",
        "SSRF": r"(requests\.get|httpx\.get|urllib\.request)\(",
    }

    @classmethod
    def analyze_solidity_function(
        cls, fn_name: str, fn_lines: List[str], start_line: int = 1
    ) -> List[TaintFlow]:
        """Trace tainted inputs to vulnerable sinks in a Solidity function."""
        tainted_vars: Dict[str, int] = {}
        flows: List[TaintFlow] = []
        is_sanitized = False
        sanitizer_note = None

        # Check function modifiers / guard checks
        full_text = " ".join(fn_lines).lower()
        for guard in cls.WEB3_GUARDS:
            if guard in full_text:
                is_sanitized = True
                sanitizer_note = f"Access guard '{guard}' detected"

        for idx, line in enumerate(fn_lines):
            line_no = start_line + idx
            stripped = line.strip()

            if stripped.startswith("//"):
                continue

            # 1. Identify taint sources
            for src in cls.WEB3_SOURCES:
                if src in stripped:
                    # Check if assigned to a variable: e.g. address recipient = msg.sender;
                    assign_match = re.search(r"([A-Za-z0-9_]+)\s*=\s*.*" + re.escape(src), stripped)
                    if assign_match:
                        var_name = assign_match.group(1).split()[-1]
                        tainted_vars[var_name] = line_no

            # Check parameter taint: function setOwner(address newOwner)
            param_match = re.search(r"function\s+[A-Za-z0-9_]+\s*\((.*?)\)", stripped)
            if param_match:
                params = [p.strip().split()[-1] for p in param_match.group(1).split(",") if p.strip()]
                for p in params:
                    tainted_vars[p] = line_no

            # 2. Check taint sinks
            for sink_name, pattern in cls.WEB3_SINKS.items():
                if re.search(pattern, stripped):
                    # Check if tainted variable reaches this sink
                    involved_vars = [v for v in tainted_vars if v in stripped or sink_name == "OWNER_MUTATION"]
                    if involved_vars or sink_name == "OWNER_MUTATION":
                        flows.append(TaintFlow(
                            source_name="Function Parameter / msg.sender",
                            source_line=tainted_vars.get(involved_vars[0], line_no) if involved_vars else line_no,
                            sink_type=sink_name,
                            sink_line=line_no,
                            sink_expression=stripped,
                            variable_path=involved_vars or ["direct"],
                            is_sanitized=is_sanitized,
                            sanitizer_expression=sanitizer_note,
                            severity="CRITICAL" if not is_sanitized else "LOW",
                            description=f"Tainted variable flowed to sensitive sink '{sink_name}' without proper authorization guard."
                        ))

        return flows

    @classmethod
    def analyze_web_api_function(
        cls, fn_name: str, fn_lines: List[str], start_line: int = 1
    ) -> List[TaintFlow]:
        """Trace user-supplied API params to critical sinks (SQL, SSRF, Exec)."""
        flows = []
        for idx, line in enumerate(fn_lines):
            line_no = start_line + idx
            stripped = line.strip()

            for sink_name, pattern in cls.WEB_SINKS.items():
                if re.search(pattern, stripped):
                    flows.append(TaintFlow(
                        source_name="API Request Parameter",
                        source_line=start_line,
                        sink_type=sink_name,
                        sink_line=line_no,
                        sink_expression=stripped,
                        variable_path=["req_param"],
                        is_sanitized=False,
                        severity="CRITICAL",
                        description=f"User controlled parameter reaches sensitive sink '{sink_name}'"
                    ))
        return flows
