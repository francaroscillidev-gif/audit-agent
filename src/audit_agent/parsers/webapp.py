"""Static analysis heuristics for Web Application APIs (Python / FastAPI / Flask / Express)."""
import re
from typing import List, Dict, Any


class WebAPIASTParser:
    """Lightweight web application API endpoint parser and security pattern scanner."""

    def __init__(self, source_code: str, file_path: str = "api.py"):
        self.source = source_code
        self.file_path = file_path
        self.lines = source_code.splitlines()

    def extract_endpoints(self) -> List[Dict[str, Any]]:
        """Extract web endpoints, methods, and parameters."""
        endpoints = []
        # Pattern for FastAPI / Flask routes
        route_pattern = re.compile(r"@(app|router)\.(get|post|put|delete|patch)\(\s*['\"]([^'\"]+)['\"]", re.IGNORECASE)

        for idx, line in enumerate(self.lines):
            match = route_pattern.search(line)
            if match:
                method = match.group(2).upper()
                path = match.group(3)
                start_line = idx + 1

                # Look forward for function definition
                fn_name = "unknown"
                params = ""
                for j in range(idx + 1, min(idx + 6, len(self.lines))):
                    fn_match = re.search(r"def\s+([A-Za-z0-9_]+)\s*\((.*?)\)", self.lines[j])
                    if fn_match:
                        fn_name = fn_match.group(1)
                        params = fn_match.group(2)
                        break

                endpoints.append({
                    "method": method,
                    "path": path,
                    "function_name": fn_name,
                    "params": params,
                    "start_line": start_line
                })
        return endpoints

    def detect_static_heuristics(self) -> List[Dict[str, Any]]:
        """Detect potential authorization issues, such as missing auth guards on parameter lookups."""
        heuristics = []
        endpoints = self.extract_endpoints()

        for ep in endpoints:
            path = ep["path"]
            params = ep["params"]
            fn_name = ep["function_name"]

            # Heuristic: Path parameter like {user_id} or {order_id} without auth dependency (e.g., Depends(get_current_user))
            has_id_param = re.search(r"\{(id|[a-zA-Z0-9_]+_id)\}", path) or "user_id" in params
            has_auth_guard = "current_user" in params or "Depends" in params or "auth" in params.lower()

            if has_id_param and not has_auth_guard:
                heuristics.append({
                    "heuristic": "POTENTIAL_IDOR_OR_UNAUTHENTICATED_ACCESS",
                    "endpoint": f"{ep['method']} {path}",
                    "function": fn_name,
                    "line": ep["start_line"],
                    "detail": f"Endpoint receives an ID parameter without visible authentication/authorization dependency."
                })

        return heuristics
