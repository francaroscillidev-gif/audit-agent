"""Static code parsers and AST heuristics."""
import re
from typing import List, Dict, Any, Optional
from pathlib import Path


class SolidityASTParser:
    """Lightweight Solidity static and AST analysis parser."""

    def __init__(self, source_code: str, file_path: str = "contract.sol"):
        self.source = source_code
        self.file_path = file_path
        self.lines = source_code.splitlines()

    def extract_contracts(self) -> List[Dict[str, Any]]:
        """Extract contract names and their line spans."""
        contracts = []
        pattern = r"(contract|library|interface)\s+([A-Za-z0-9_]+)(?:\s+is\s+([^{]+))?\s*\{"
        matches = list(re.finditer(pattern, self.source))

        for idx, match in enumerate(matches):
            kind = match.group(1)
            name = match.group(2)
            inheritance = [x.strip() for x in match.group(3).split(",")] if match.group(3) else []
            start_pos = match.start()
            start_line = self.source[:start_pos].count("\n") + 1
            
            contracts.append({
                "kind": kind,
                "name": name,
                "inheritance": inheritance,
                "start_line": start_line,
                "raw_match": match.group(0),
            })
        return contracts

    def extract_functions(self) -> List[Dict[str, Any]]:
        """Extract functions, their visibility, modifiers, and line numbers."""
        functions = []
        pattern = r"function\s+([A-Za-z0-9_]+)\s*\((.*?)\)\s*([^{;]*)(?:\{|;)"
        matches = list(re.finditer(pattern, self.source))

        for match in matches:
            fn_name = match.group(1)
            params = match.group(2).strip()
            attributes = match.group(3).strip()
            start_pos = match.start()
            start_line = self.source[:start_pos].count("\n") + 1

            is_public = "public" in attributes or "external" in attributes
            is_payable = "payable" in attributes
            is_view_or_pure = "view" in attributes or "pure" in attributes

            modifiers = []
            for token in attributes.split():
                if token not in ["public", "external", "internal", "private", "payable", "view", "pure", "virtual", "override", "returns"]:
                    if not token.startswith("returns("):
                        modifiers.append(token)

            functions.append({
                "name": fn_name,
                "params": params,
                "attributes": attributes,
                "start_line": start_line,
                "is_public_or_external": is_public,
                "is_payable": is_payable,
                "is_state_changing": not is_view_or_pure,
                "modifiers": modifiers,
            })
        return functions

    def detect_static_heuristics(self) -> List[Dict[str, Any]]:
        """Scan for common high-risk structural patterns (Checks-Effects, tx.origin, delegatecall, missing modifier)."""
        heuristics = []

        # 1. External call before state update (Checks-Effects-Interactions violation)
        call_pattern = re.compile(r"(\.call\{value:|\.transfer\(|\.send\()")
        state_write_pattern = re.compile(r"([A-Za-z0-9_\[\]]+)\s*(=|\+=|-=|\*=)\s*")

        lines = self.lines
        in_function = None
        call_line = None

        for idx, line in enumerate(lines):
            line_num = idx + 1
            stripped = line.strip()

            if stripped.startswith("function "):
                in_function = stripped.split()[1].split("(")[0]
                call_line = None

            if in_function and call_pattern.search(stripped):
                call_line = line_num

            # Check if state update happens after external call in same function
            if in_function and call_line and line_num > call_line:
                if state_write_pattern.search(stripped) and not stripped.startswith("//") and not stripped.startswith("emit "):
                    heuristics.append({
                        "heuristic": "POTENTIAL_REENTRANCY",
                        "function": in_function,
                        "call_line": call_line,
                        "write_line": line_num,
                        "detail": f"State variable mutation at line {line_num} occurs after external call at line {call_line}."
                    })
                    call_line = None  # Report once per function

        # 2. Sensitive admin/drain functions without access control modifiers
        sensitive_names = ["withdraw", "drain", "setowner", "transferownership", "setfee", "emergencywithdraw", "upgrade"]
        for fn in self.extract_functions():
            lower_name = fn["name"].lower()
            if any(sens in lower_name for sens in sensitive_names):
                has_auth = any(m.lower() in ["onlyowner", "onlyadmin", "auth", "onlyrole"] for m in fn["modifiers"])
                if fn["is_public_or_external"] and not has_auth and fn["is_state_changing"]:
                    heuristics.append({
                        "heuristic": "POTENTIAL_UNPROTECTED_SENSITIVE_FUNCTION",
                        "function": fn["name"],
                        "start_line": fn["start_line"],
                        "detail": f"Sensitive function '{fn['name']}' is public/external but lacks obvious access control modifiers."
                    })

        # 3. tx.origin authentication check
        for idx, line in enumerate(lines):
            if "tx.origin" in line and not line.strip().startswith("//"):
                heuristics.append({
                    "heuristic": "TX_ORIGIN_AUTHENTICATION",
                    "line": idx + 1,
                    "detail": "Usage of tx.origin detected, which can lead to phishing-based authorization bypass."
                })

        return heuristics
