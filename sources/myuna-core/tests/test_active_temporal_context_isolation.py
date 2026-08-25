from __future__ import annotations

import ast
from pathlib import Path
import unittest


PACKAGE = Path(__file__).parents[1] / "src" / "myuna_core" / "active_temporal_context"


class TemporalIsolationTest(unittest.TestCase):
    def test_package_has_no_p07_session_memory_p10_or_wall_clock_coupling(self) -> None:
        forbidden_imports = {
            "myuna_core.owner_profile",
            "myuna_core.context_window",
            "myuna_core.memory",
            "myuna_core.capability_runtime",
        }
        forbidden_calls = {"datetime.now", "datetime.utcnow", "time.time"}
        for path in PACKAGE.glob("*.py"):
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for node in ast.walk(tree):
                if isinstance(node, ast.ImportFrom) and node.module:
                    self.assertFalse(
                        any(node.module.startswith(prefix) for prefix in forbidden_imports),
                        f"forbidden cross-layer import in {path.name}: {node.module}",
                    )
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        self.assertFalse(
                            any(alias.name.startswith(prefix) for prefix in forbidden_imports),
                            f"forbidden cross-layer import in {path.name}: {alias.name}",
                        )
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                    if isinstance(node.func.value, ast.Name):
                        rendered = f"{node.func.value.id}.{node.func.attr}"
                        self.assertNotIn(rendered, forbidden_calls)


if __name__ == "__main__":
    unittest.main()
