"""Cross-Contract Call Graph and Inheritance Hierarchy Resolver."""
import re
from typing import Dict, List, Set, Any
from pydantic import BaseModel, Field


class ContractNode(BaseModel):
    name: str
    kind: str  # contract, interface, library
    inherits_from: List[str] = Field(default_factory=list)
    functions: List[str] = Field(default_factory=list)
    state_variables: List[str] = Field(default_factory=list)
    external_calls_to: List[str] = Field(default_factory=list)


class ProjectCallGraph(BaseModel):
    contracts: Dict[str, ContractNode] = Field(default_factory=dict)

    def get_inheritance_tree(self, contract_name: str) -> List[str]:
        """Resolve full inheritance chain for a contract."""
        chain = []
        visited = set()

        def recurse(name: str):
            if name in visited:
                return
            visited.add(name)
            node = self.contracts.get(name)
            if node:
                for parent in node.inherits_from:
                    chain.append(parent)
                    recurse(parent)

        recurse(contract_name)
        return chain


class CallGraphResolver:
    """Builds project-wide dependency and call graphs across multiple contracts."""

    @classmethod
    def resolve_contracts(cls, source_code: str) -> ProjectCallGraph:
        graph = ProjectCallGraph()

        # Contract definition pattern
        contract_pattern = re.compile(r"(contract|interface|library)\s+([A-Za-z0-9_]+)(?:\s+is\s+([^{]+))?\s*\{")
        matches = list(contract_pattern.finditer(source_code))

        for idx, match in enumerate(matches):
            kind = match.group(1)
            name = match.group(2)
            parents = [p.strip() for p in match.group(3).split(",")] if match.group(3) else []

            # Extract contract body
            start = match.end()
            end = matches[idx + 1].start() if idx + 1 < len(matches) else len(source_code)
            body = source_code[start:end]

            # Extract functions
            fns = re.findall(r"function\s+([A-Za-z0-9_]+)\s*\(", body)

            # Extract external calls
            ext_calls = re.findall(r"([A-Za-z0-9_]+)\.([A-Za-z0-9_]+)\s*\(", body)
            called_targets = list(set(target for target, _ in ext_calls if target not in ["msg", "tx", "block", "abi"]))

            graph.contracts[name] = ContractNode(
                name=name,
                kind=kind,
                inherits_from=parents,
                functions=fns,
                external_calls_to=called_targets
            )

        return graph
