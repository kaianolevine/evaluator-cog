"""Python-package-structure rule checks (pyproject, src-layout, naming, etc)."""

from __future__ import annotations

import ast
import re
from pathlib import Path

from evaluator_cog.engine.deterministic._shared import (
    Finding,
    _finding,
)


def check_pre_commit(repo_path: Path) -> list[Finding]:
    """PY-008: pre-commit configured."""
    CHECK_ID = "PY-008"
    findings = []
    if not (repo_path / ".pre-commit-config.yaml").exists():
        findings.append(
            _finding(
                "PY-008",
                "WARN",
                "structural_conformance",
                ".pre-commit-config.yaml is absent.",
                "Add .pre-commit-config.yaml with ruff hooks.",
            )
        )
    return findings


def check_src_layout(repo_path: Path) -> list[Finding]:
    """PY-005: src layout required."""
    CHECK_ID = "PY-005"
    findings = []
    if not (repo_path / "src").is_dir():
        findings.append(
            _finding(
                "PY-005",
                "ERROR",
                "structural_conformance",
                "src/ directory is absent — flat layout detected.",
                "Move package files under src/<package_name>/.",
            )
        )
    return findings


def check_no_setup_py(repo_path: Path) -> list[Finding]:
    """PY-007: pyproject.toml as single source of truth."""
    CHECK_ID = "PY-007"
    findings = []
    for bad in ("setup.py", "requirements.txt"):
        if (repo_path / bad).exists():
            findings.append(
                _finding(
                    "PY-007",
                    "WARN",
                    "structural_conformance",
                    f"{bad} found — pyproject.toml should be the single source of truth.",
                    f"Remove {bad} and consolidate into pyproject.toml.",
                )
            )
    return findings


def check_common_python_utils_dep(repo_path: Path) -> list[Finding]:
    """PY-006: common-python-utils declared as dependency."""
    CHECK_ID = "PY-006"
    findings = []
    pyproject = repo_path / "pyproject.toml"
    if not pyproject.exists():
        return findings
    if "common-python-utils" not in pyproject.read_text():
        findings.append(
            _finding(
                "PY-006",
                "ERROR",
                "structural_conformance",
                "common-python-utils not declared as a dependency.",
                "Add common-python-utils to [project].dependencies.",
            )
        )
    return findings


def check_pyproject(
    repo_path: Path,
    exceptions: frozenset[str] | None = None,
) -> list[Finding]:
    """
    Runs all pyproject.toml checks in one pass.
    Covers: PY-001, PY-002, PY-003, PY-009, PY-010, CD-002.
    """
    CHECK_ID = "PY-001"
    findings = []
    _exc = exceptions or frozenset()
    pyproject = repo_path / "pyproject.toml"
    if not pyproject.exists():
        findings.append(
            _finding(
                "PY-007",
                "ERROR",
                "structural_conformance",
                "pyproject.toml is absent.",
                "Add pyproject.toml as the single source of truth.",
            )
        )
        return findings

    content = pyproject.read_text()

    if "PY-001" not in _exc and (
        "uv.lock" not in [p.name for p in repo_path.iterdir()]
        and "[tool.uv]" not in content
    ):
        findings.append(
            _finding(
                "PY-001",
                "WARN",
                "structural_conformance",
                "No uv.lock or [tool.uv] found — uv may not be in use.",
                "Use uv for dependency management.",
            )
        )

    if "PY-002" not in _exc and "[tool.ruff]" not in content:
        findings.append(
            _finding(
                "PY-002",
                "WARN",
                "structural_conformance",
                "[tool.ruff] section absent from pyproject.toml.",
                "Add ruff configuration to pyproject.toml.",
            )
        )

    if (
        "PY-003" not in _exc
        and 'requires-python = ">=3.11"' not in content
        and ">=3.12" not in content
    ):
        findings.append(
            _finding(
                "PY-003",
                "WARN",
                "structural_conformance",
                "Python minimum version may be below 3.11.",
                'Set requires-python = ">=3.11" in pyproject.toml.',
            )
        )

    if "PY-009" not in _exc and "hatchling" not in content:
        findings.append(
            _finding(
                "PY-009",
                "INFO",
                "structural_conformance",
                "hatchling not found as build backend.",
                'Set build-backend = "hatchling.build" in [build-system].',
            )
        )

    if "PY-010" not in _exc and "line-length = 88" not in content:
        findings.append(
            _finding(
                "PY-010",
                "INFO",
                "structural_conformance",
                "ruff line-length is not explicitly set to 88.",
                "Add line-length = 88 under [tool.ruff].",
            )
        )

    if "CD-002" not in _exc and "sentry-sdk" not in content:
        findings.append(
            _finding(
                "CD-002",
                "WARN",
                "cd_readiness",
                "sentry-sdk not found in pyproject.toml.",
                "Add sentry-sdk to dependencies and initialise at service entry point.",
            )
        )

    return findings


def check_naming_conventions(repo_path: Path) -> list[Finding]:
    """PY-011: Naming conventions — Python."""
    CHECK_ID = "PY-011"

    findings = []
    pyproject = repo_path / "pyproject.toml"
    src = repo_path / "src"
    repo_expected = repo_path.name.replace("-", "_")

    project_name = ""
    if pyproject.exists():
        m = re.search(r'^\s*name\s*=\s*"([^"]+)"', pyproject.read_text(), re.MULTILINE)
        if m:
            project_name = m.group(1).replace("-", "_")

    src_pkg = ""
    if src.is_dir():
        for child in src.iterdir():
            if child.is_dir() and child.name != "__pycache__":
                src_pkg = child.name
                break

    if project_name and project_name != repo_expected:
        findings.append(
            _finding(
                "PY-011",
                "WARN",
                "structural_conformance",
                f"Project name '{project_name}' does not match repo naming '{repo_expected}'.",
                "Align [project].name with repository name (hyphens -> underscores).",
            )
        )

    if src_pkg and project_name and src_pkg != project_name:
        findings.append(
            _finding(
                "PY-011",
                "WARN",
                "structural_conformance",
                f"src package '{src_pkg}' does not match project name '{project_name}'.",
                "Rename the src package folder to match the project package identity.",
            )
        )

    snake_re = re.compile(r"^[a-z0-9_]+$")
    if src.is_dir():
        for py_file in src.rglob("*.py"):
            stem = py_file.stem
            if not snake_re.match(stem):
                findings.append(
                    _finding(
                        "PY-011",
                        "WARN",
                        "structural_conformance",
                        f"Non-snake_case Python module filename: {py_file.relative_to(repo_path)}.",
                        "Rename Python modules to snake_case.",
                    )
                )
    return findings


def check_failed_prefix(repo_path: Path) -> list[Finding]:
    """PY-012: FAILED_ prefix for failed inputs."""
    CHECK_ID = "PY-012"
    findings = []
    src = repo_path / "src"
    if not src.is_dir():
        return findings

    content = "\n".join(f.read_text() for f in src.rglob("*.py"))
    has_file_processing = (
        ("shutil" in content or "pathlib" in content)
        and "except" in content
        and ("move(" in content or "rename(" in content)
    )
    if has_file_processing and "FAILED_" not in content:
        findings.append(
            _finding(
                "PY-012",
                "WARN",
                "structural_conformance",
                "File-processing exception paths do not use FAILED_ prefixing.",
                "Rename failed input files with FAILED_ to make failures visible and auditable.",
            )
        )
    return findings


def check_duplicate_prefix(repo_path: Path) -> list[Finding]:
    """PY-013: possible_duplicate_ prefix for duplicates."""
    CHECK_ID = "PY-013"
    findings = []
    src = repo_path / "src"
    if not src.is_dir():
        return findings

    content = "\n".join(f.read_text().lower() for f in src.rglob("*.py"))
    dedup_signals = ("dedup", "duplicate", "already exists")
    if (
        any(s in content for s in dedup_signals)
        and "possible_duplicate_" not in content
    ):
        findings.append(
            _finding(
                "PY-013",
                "WARN",
                "structural_conformance",
                "Deduplication logic present but possible_duplicate_ prefixing is missing.",
                "Prefix duplicate files with possible_duplicate_ to preserve recoverability.",
            )
        )
    return findings


def check_finally_cleanup(repo_path: Path) -> list[Finding]:
    """PY-014: finally for temp file cleanup."""
    CHECK_ID = "PY-014"
    import ast

    findings = []
    src = repo_path / "src"
    if not src.is_dir():
        return findings

    temp_calls = {"NamedTemporaryFile", "mkstemp", "mkdtemp", "TemporaryDirectory"}

    for py_file in src.rglob("*.py"):
        try:
            tree = ast.parse(py_file.read_text())
        except Exception:
            continue

        parents: dict[ast.AST, ast.AST] = {}
        for node in ast.walk(tree):
            for child in ast.iter_child_nodes(node):
                parents[child] = node

        def _has_cleanup_context(
            node: ast.AST,
            parent_map: dict[ast.AST, ast.AST],
        ) -> bool:
            cur = node
            while cur in parent_map:
                cur = parent_map[cur]
                if isinstance(cur, ast.With):
                    return True
                if isinstance(cur, ast.Try) and cur.finalbody:
                    return True
            return False

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            name = ""
            if isinstance(node.func, ast.Name):
                name = node.func.id
            elif isinstance(node.func, ast.Attribute):
                name = node.func.attr
            if name in temp_calls and not _has_cleanup_context(node, parents):
                findings.append(
                    _finding(
                        "PY-014",
                        "WARN",
                        "structural_conformance",
                        f"Temporary resource created without with/finally cleanup: {py_file.relative_to(repo_path)}.",
                        "Wrap temp resource usage in a context manager or try/finally cleanup.",
                    )
                )
                break
    return findings


def check_mypy_in_ci(repo_path: Path) -> list[Finding]:
    """TEST-012: mypy must run in CI if [tool.mypy] is declared."""
    CHECK_ID = "TEST-012"
    findings = []
    pyproject = repo_path / "pyproject.toml"
    if not pyproject.exists():
        return findings
    content = pyproject.read_text()
    if "[tool.mypy]" not in content:
        return findings

    workflows = repo_path / ".github" / "workflows"
    combined = ""
    if workflows.is_dir():
        for yml in list(workflows.rglob("*.yml")) + list(workflows.rglob("*.yaml")):
            combined += "\n" + yml.read_text().lower()
    if "mypy" not in combined:
        findings.append(
            _finding(
                "TEST-012",
                "WARN",
                "testing_coverage",
                "[tool.mypy] is configured but mypy is not run in CI workflows.",
                "Add a mypy step to CI when [tool.mypy] is present.",
            )
        )
    return findings
