"""Deterministic rule checks for the conformance flow.

Each check function takes a repo_path (Path) and returns a list of finding
dicts with keys: rule_id, severity, dimension, finding, suggestion.

Checks are grouped by what they inspect:
  - file_checks     — presence/absence of required files
  - pyproject_checks — pyproject.toml content
  - ci_checks       — .github/workflows/ci.yml content
  - ast_checks      — Python source AST scanning
  - test_checks     — tests/ directory structure
"""

from __future__ import annotations

import ast
import re
import re as _re_eval003
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from evaluator_cog.engine.evaluator_config import EvaluatorConfig

Finding = dict[str, Any]


@dataclass
class CheckResult:
    """TODO: describe this class."""

    findings: list[Finding]
    checked_rule_ids: set[str]


def _finding(
    rule_id: str,
    severity: str,
    dimension: str,
    finding: str,
    suggestion: str = "",
) -> Finding:
    return {
        "rule_id": rule_id,
        "violation_id": rule_id or None,
        "severity": severity,
        "dimension": dimension,
        "finding": finding,
        "suggestion": suggestion,
    }


# Pairs where the first rule supersedes the second — if both fire,
# drop the superseded rule's finding.
_SUPERSEDED_BY: dict[str, str] = {
    "CD-002": "CD-010",
    "CD-009": "CD-010",
}


def _deduplicate_same_repo_findings(findings: list[Finding]) -> list[Finding]:
    """
    Remove findings for rules that are superseded by a higher-level rule
    that also fired in the same check run.

    Example: if CD-010 fires, drop any CD-002 and CD-009 findings — they
    are sub-components of CD-010 and generating all three is redundant.
    """
    fired_rule_ids = {str(f.get("rule_id", "")) for f in findings}
    return [
        f
        for f in findings
        if not (
            str(f.get("rule_id", "")) in _SUPERSEDED_BY
            and _SUPERSEDED_BY[str(f.get("rule_id", ""))] in fired_rule_ids
        )
    ]


def _ast_constant_is_dict_key(const: ast.Constant, tree: ast.AST) -> bool:
    """True if this Constant is the key expression of a dict display."""
    for node in ast.walk(tree):
        if isinstance(node, ast.Dict) and const in node.keys:
            return True
    return False


def _is_inside_string_literal(source: str, match_substring: str) -> bool:
    """Return True if every occurrence of match_substring in source sits
    inside a Python string literal.

    Used by checkers that scan Python files with substring containment
    (e.g. ``if "X-Internal-API-Key" in text``). When the scanned file is
    the checker itself — or a test fixture containing source snippets
    built as string literals — every match is a self-scan artifact, not
    a real occurrence.

    Implementation: parse ``source`` with ast.parse(). If parsing fails,
    return False (conservative — let the caller flag). Walk the AST for
    ast.Constant nodes whose .value is a str containing match_substring.
    Dict literal keys are excluded — ``{{"X-Internal-API-Key": "x"}}`` is
    real usage, not a quoted pattern string.

    Count how many times match_substring appears in total (plain
    source.count(match_substring)) vs. how many times it appears inside
    counted string-literal Constant nodes. If every occurrence is inside
    a string literal, return True; otherwise return False.

    Caveat: this handles the common case of bare string literals. It
    does NOT try to reason about f-strings, concatenated literals, or
    triple-quoted docstrings beyond what ast represents — ast.Constant
    already covers those correctly for our purposes.
    """
    if match_substring not in source:
        return False
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return False
    literal_hits = 0
    for node in ast.walk(tree):
        if not isinstance(node, ast.Constant) or not isinstance(node.value, str):
            continue
        if _ast_constant_is_dict_key(node, tree):
            continue
        literal_hits += node.value.count(match_substring)
    total_hits = source.count(match_substring)
    return literal_hits >= total_hits


# -- File presence checks -----------------------------------------------------


def check_readme(repo_path: Path, monorepo_root: Path | None = None) -> list[Finding]:
    """DOC-001: README.md is mandatory."""
    CHECK_ID = "DOC-001"
    findings = []
    exists = (repo_path / "README.md").exists()
    if not exists and monorepo_root:
        exists = (monorepo_root / "README.md").exists()
    if not exists:
        findings.append(
            _finding(
                "DOC-001",
                "ERROR",
                "documentation_coverage",
                "README.md is absent.",
                "Create README.md documenting purpose, inputs, outputs, and how to run locally.",
            )
        )
    return findings


def check_changelog(
    repo_path: Path, monorepo_root: Path | None = None
) -> list[Finding]:
    """DOC-003: CHANGELOG.md required."""
    CHECK_ID = "DOC-003"
    findings = []
    exists = (repo_path / "CHANGELOG.md").exists()
    if not exists and monorepo_root:
        exists = (monorepo_root / "CHANGELOG.md").exists()
    if not exists:
        findings.append(
            _finding(
                "DOC-003",
                "WARN",
                "documentation_coverage",
                "CHANGELOG.md is absent.",
                "Create CHANGELOG.md — managed by semantic-release.",
            )
        )
    return findings


def check_env_example(
    repo_path: Path, monorepo_root: Path | None = None
) -> list[Finding]:
    """DOC-004: .env.example is required."""
    CHECK_ID = "DOC-004"
    findings = []
    # Check root first, then common monorepo locations
    candidates = [
        repo_path / ".env.example",
        repo_path / "apps" / "api" / ".env.example",
        repo_path / "apps" / "app" / ".env.example",
        repo_path / "app" / ".env.example",
        repo_path / "backend" / ".env.example",
        repo_path / "server" / ".env.example",
    ]
    if monorepo_root:
        candidates.append(monorepo_root / ".env.example")
    if not any(p.exists() for p in candidates):
        findings.append(
            _finding(
                "DOC-004",
                "WARN",
                "documentation_coverage",
                ".env.example is absent.",
                "Create .env.example documenting all required environment variables.",
            )
        )
    return findings


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


def check_releaserc(
    repo_path: Path, monorepo_root: Path | None = None
) -> list[Finding]:
    """VER-003: semantic-release on all repos."""
    CHECK_ID = "VER-003"
    findings = []
    exists = (repo_path / ".releaserc.json").exists()
    if not exists and monorepo_root:
        exists = (monorepo_root / ".releaserc.json").exists()
    if not exists:
        findings.append(
            _finding(
                "VER-003",
                "ERROR",
                "cd_readiness",
                ".releaserc.json is absent.",
                "Add .releaserc.json and a release job to ci.yml.",
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


# -- pyproject.toml checks ----------------------------------------------------


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


# -- CI checks ----------------------------------------------------------------


def check_pytest_coverage_in_ci(repo_path: Path) -> list[Finding]:
    """TEST-006: pytest coverage measured in CI."""
    CHECK_ID = "TEST-006"
    findings = []
    ci = repo_path / ".github" / "workflows" / "ci.yml"
    if not ci.exists():
        return findings
    content = ci.read_text()
    if "pytest --cov" not in content and "pytest-cov" not in content:
        findings.append(
            _finding(
                "TEST-006",
                "WARN",
                "testing_coverage",
                "Coverage not measured in CI — pytest --cov not found in ci.yml.",
                "Add --cov flag to pytest invocation in CI.",
            )
        )
    return findings


def check_ci(
    repo_path: Path,
    exceptions: frozenset[str] | None = None,
    monorepo_root: Path | None = None,
) -> list[Finding]:
    """
    Runs all CI checks in one pass.
    Covers: VER-003, VER-005, VER-006.
    """
    CHECK_ID = "VER-003"
    findings = []
    _exc = exceptions or frozenset()
    ci_root = monorepo_root or repo_path
    ci = ci_root / ".github" / "workflows" / "ci.yml"
    if not ci.exists():
        findings.append(
            _finding(
                "VER-003",
                "ERROR",
                "cd_readiness",
                "ci.yml not found at .github/workflows/ci.yml.",
                "Add a CI workflow with test and release jobs.",
            )
        )
        return findings

    content = ci.read_text()

    if "VER-003" not in _exc and "semantic-release" not in content:
        findings.append(
            _finding(
                "VER-003",
                "ERROR",
                "cd_readiness",
                "semantic-release not found in ci.yml.",
                "Add a release job running npx semantic-release.",
            )
        )

    if "VER-005" not in _exc and "fetch-depth: 0" not in content:
        findings.append(
            _finding(
                "VER-005",
                "ERROR",
                "cd_readiness",
                "fetch-depth: 0 absent from ci.yml checkout step.",
                "Add fetch-depth: 0 to the actions/checkout step in the release job.",
            )
        )

    if "VER-006" not in _exc and (
        "npm install --no-save" not in content
        and "pnpm exec semantic-release" not in content
        and "pnpm run semantic-release" not in content
        and "pnpm add" not in content
    ):
        findings.append(
            _finding(
                "VER-006",
                "ERROR",
                "cd_readiness",
                "npm install --no-save step absent from release job.",
                "Add explicit npm install --no-save before npx semantic-release, "
                "or use pnpm exec semantic-release with plugins in devDependencies.",
            )
        )

    return findings


# -- AST checks ---------------------------------------------------------------


def check_no_print_statements(repo_path: Path) -> list[Finding]:
    """CD-003: No print() statements in production code paths."""
    CHECK_ID = "CD-003"
    import ast

    findings = []
    src = repo_path / "src"
    if not src.is_dir():
        return findings

    for py_file in src.rglob("*.py"):
        try:
            tree = ast.parse(py_file.read_text())
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id == "print"
            ):
                findings.append(
                    _finding(
                        "CD-003",
                        "WARN",
                        "cd_readiness",
                        f"print() statement found in {py_file.relative_to(repo_path)}.",
                        "Replace with structured logger from common-python-utils.",
                    )
                )
                break  # one finding per file is enough
    return findings


def check_no_hardcoded_urls(repo_path: Path) -> list[Finding]:
    """FE-007: No hardcoded API URLs in source."""
    CHECK_ID = "FE-007"
    import re

    findings = []
    pattern = re.compile(r"https?://(localhost|.*railway\.app|.*up\.railway\.app)")
    src = repo_path / "src"
    if not src.is_dir():
        return findings

    for py_file in src.rglob("*.py"):
        content = py_file.read_text()
        if pattern.search(content):
            findings.append(
                _finding(
                    "FE-007",
                    "ERROR",
                    "structural_conformance",
                    f"Hardcoded API URL found in {py_file.relative_to(repo_path)}.",
                    "Move URL to environment variable.",
                )
            )
    return findings


# -- Additional deterministic checks ------------------------------------------


def check_naming_conventions(repo_path: Path) -> list[Finding]:
    """PY-011: Naming conventions — Python."""
    CHECK_ID = "PY-011"
    import re

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


def check_split_package_identity(repo_path: Path) -> list[Finding]:
    """DOC-009: Split package identity documented at entry point."""
    CHECK_ID = "DOC-009"
    import re

    findings = []
    pyproject = repo_path / "pyproject.toml"
    src = repo_path / "src"
    readme = repo_path / "README.md"
    if not pyproject.exists() or not src.is_dir():
        return findings

    m = re.search(r'^\s*name\s*=\s*"([^"]+)"', pyproject.read_text(), re.MULTILINE)
    if not m:
        return findings
    project_name = m.group(1)
    pkg_dirs = [d for d in src.iterdir() if d.is_dir() and d.name != "__pycache__"]
    if not pkg_dirs:
        return findings
    pkg_name = pkg_dirs[0].name
    if project_name.replace("-", "_") == pkg_name:
        return findings

    init_file = pkg_dirs[0] / "__init__.py"
    init_text = init_file.read_text().lower() if init_file.exists() else ""
    readme_text = readme.read_text().lower() if readme.exists() else ""

    if (
        project_name.lower() not in init_text
        or pkg_name.lower() not in init_text
        or project_name.lower() not in readme_text
        or pkg_name.lower() not in readme_text
    ):
        findings.append(
            _finding(
                "DOC-009",
                "WARN",
                "documentation_coverage",
                "Split package identity is not documented across __init__.py and README.",
                "Document both distribution name and import package name at the service entry points.",
            )
        )
    return findings


def check_readme_running_locally(
    repo_path: Path,
    dod_type: str | None = None,
) -> list[Finding]:
    """DOC-013: README Running locally section is complete."""
    CHECK_ID = "DOC-013"
    findings = []
    readme = repo_path / "README.md"
    if not readme.exists():
        return findings
    text = readme.read_text().lower()

    missing: list[str] = []
    if dod_type in ("new_cog", "new_fastapi_service"):
        required = ["uv sync", "pre-commit install", "pre-commit run", "uv run pytest"]
        missing.extend([r for r in required if r not in text])
        if "prereq" not in text and "python" not in text and "uv" not in text:
            missing.append("python/uv prerequisites")
    elif dod_type == "new_hono_service":
        required = ["pnpm install", "pnpm dev", "pnpm test", "node"]
        missing.extend([r for r in required if r not in text])
    elif dod_type in ("new_frontend_site", "new_react_app"):
        if "pnpm install" not in text and "npm install" not in text:
            missing.append("pnpm install or npm install")
        if "pnpm build" not in text and "npm run build" not in text:
            missing.append("pnpm build or npm run build")
        if (
            "pnpm dev" not in text
            and "npm run dev" not in text
            and "astro dev" not in text
        ):
            missing.append("pnpm dev or npm run dev or astro dev")
        if ".env.example" not in text:
            missing.append(".env.example")

    for item in missing:
        findings.append(
            _finding(
                "DOC-013",
                "WARN",
                "documentation_coverage",
                f"README Running locally is missing: {item}.",
                "Add the missing command/prerequisite to the Running locally section.",
            )
        )
    return findings


def check_healthchecks_integration(
    repo_path: Path,
    cog_subtype: str | None = None,
) -> list[Finding]:
    """CD-007: Healthchecks.io for trigger cogs."""
    CHECK_ID = "CD-007"
    findings = []
    if cog_subtype != "trigger":
        return findings
    env_example = repo_path / ".env.example"
    env_text = env_example.read_text() if env_example.exists() else ""
    src_text = (
        "\n".join(f.read_text() for f in (repo_path / "src").rglob("*.py"))
        if (repo_path / "src").is_dir()
        else ""
    )
    if "HEALTHCHECKS_URL_" not in env_text or (
        "HEALTHCHECKS_URL_" not in src_text and "healthchecks" not in src_text.lower()
    ):
        findings.append(
            _finding(
                "CD-007",
                "WARN",
                "cd_readiness",
                "Trigger cog is missing Healthchecks.io integration signals.",
                "Declare HEALTHCHECKS_URL_<SERVICE> in .env.example and ping it in trigger loop code.",
            )
        )
    return findings


def check_structured_logging(repo_path: Path) -> list[Finding]:
    """CD-009: Structured logging via shared library."""
    CHECK_ID = "CD-009"
    findings = []
    src = repo_path / "src"
    if not src.is_dir():
        return findings

    for py_file in src.rglob("*.py"):
        text = py_file.read_text()
        if (
            "import logging" in text
            or "logging.basicConfig" in text
            or "logging.getLogger" in text
        ):
            findings.append(
                _finding(
                    "CD-009",
                    "WARN",
                    "cd_readiness",
                    f"Hand-rolled logging detected in {py_file.relative_to(repo_path)}.",
                    "Use shared structured logger from the shared utility library.",
                )
            )
            break
    for ts_file in list(src.rglob("*.ts")) + list(src.rglob("*.tsx")):
        text = ts_file.read_text()
        if "console.log(" in text:
            findings.append(
                _finding(
                    "CD-009",
                    "WARN",
                    "cd_readiness",
                    f"console.log used as primary logger in {ts_file.relative_to(repo_path)}.",
                    "Use shared structured logger helpers instead of console.log.",
                )
            )
            break
    return findings


def check_no_hardcoded_secrets(repo_path: Path) -> list[Finding]:
    """CD-011: Doppler as canonical secret store."""
    CHECK_ID = "CD-011"
    import re

    findings = []

    for env_file in repo_path.rglob(".env*"):
        if env_file.name == ".env.example":
            continue
        findings.append(
            _finding(
                "CD-011",
                "ERROR",
                "cd_readiness",
                f"Committed env file detected: {env_file.relative_to(repo_path)}.",
                "Remove committed env files and use Doppler-managed runtime secrets.",
            )
        )
        break

    secret_patterns = [
        re.compile(r"sk-[A-Za-z0-9]{16,}"),
        re.compile(r"Bearer\s+[A-Za-z0-9]{20,}"),
        re.compile(r"password\s*=\s*['\"][^'\"]+['\"]", re.IGNORECASE),
        re.compile(r"api[_-]?key\s*=\s*['\"][^'\"]+['\"]", re.IGNORECASE),
    ]
    src = repo_path / "src"
    if not src.is_dir():
        return findings
    for path in (
        list(src.rglob("*.py")) + list(src.rglob("*.ts")) + list(src.rglob("*.tsx"))
    ):
        text = path.read_text()
        lowered = text.lower()
        if "os.getenv(" in lowered or "process.env" in lowered:
            pass
        for pat in secret_patterns:
            if pat.search(text):
                findings.append(
                    _finding(
                        "CD-011",
                        "ERROR",
                        "cd_readiness",
                        f"Potential hardcoded secret in {path.relative_to(repo_path)}.",
                        "Move secrets to Doppler/runtime env vars and remove literal values.",
                    )
                )
                break
        if any(
            f["rule_id"] == "CD-011" and "hardcoded secret" in f["finding"]
            for f in findings
        ):
            break
    return findings


def check_no_manual_changelog(repo_path: Path) -> list[Finding]:
    """VER-004: Never manually edit version files or CHANGELOG."""
    CHECK_ID = "VER-004"
    import re

    findings = []
    changelog = repo_path / "CHANGELOG.md"
    if not changelog.exists():
        return findings
    lines = changelog.read_text().splitlines()
    sr_header = re.compile(r"^## \[\d+\.\d+\.\d+\]\(.+\) \(\d{4}-\d{2}-\d{2}\)$")
    bad_header = re.compile(r"^##\s+\d+\.\d+\.\d+")
    for line in lines:
        if bad_header.match(line) and not sr_header.match(line):
            findings.append(
                _finding(
                    "VER-004",
                    "ERROR",
                    "cd_readiness",
                    "CHANGELOG.md appears manually edited with non-semantic-release headers.",
                    "Let semantic-release manage version and changelog sections.",
                )
            )
            break
    return findings


def check_astro_framework(repo_path: Path) -> list[Finding]:
    """FE-001: Astro for all static sites."""
    CHECK_ID = "FE-001"
    findings = []
    pkg = repo_path / "package.json"
    pkg_text = pkg.read_text().lower() if pkg.exists() else ""
    has_config = (repo_path / "astro.config.mjs").exists() or (
        repo_path / "astro.config.ts"
    ).exists()
    if '"astro"' not in pkg_text or not has_config:
        findings.append(
            _finding(
                "FE-001",
                "WARN",
                "structural_conformance",
                "Astro framework signals are missing for frontend site.",
                "Use Astro with package dependency and astro.config.* file.",
            )
        )
    return findings


def check_vite_react_ts(repo_path: Path) -> list[Finding]:
    """FE-002: Vite + React + TypeScript for web apps."""
    CHECK_ID = "FE-002"
    findings = []
    pkg = repo_path / "package.json"
    pkg_text = pkg.read_text().lower() if pkg.exists() else ""
    tsconfig_exists = (repo_path / "tsconfig.json").exists()
    if '"typescript"' not in pkg_text or not tsconfig_exists:
        findings.append(
            _finding(
                "FE-002",
                "ERROR",
                "structural_conformance",
                "TypeScript setup missing for React web app.",
                "Add TypeScript dependency and tsconfig.json to satisfy FE-002.",
            )
        )
    for forbidden in ("webpack", "create-react-app", '"next"'):
        if forbidden in pkg_text:
            findings.append(
                _finding(
                    "FE-002",
                    "ERROR",
                    "structural_conformance",
                    f"Forbidden frontend stack signal found: {forbidden}.",
                    "Use Vite + React + TypeScript baseline for web apps.",
                )
            )
            break
    return findings


def check_tailwind(repo_path: Path) -> list[Finding]:
    """FE-003: Tailwind CSS for styling."""
    CHECK_ID = "FE-003"
    findings = []
    pkg = repo_path / "package.json"
    pkg_text = pkg.read_text().lower() if pkg.exists() else ""
    astro_mjs = repo_path / "astro.config.mjs"
    astro_ts = repo_path / "astro.config.ts"
    astro_cfg_text = ""
    if astro_mjs.exists():
        astro_cfg_text += "\n" + astro_mjs.read_text().lower()
    if astro_ts.exists():
        astro_cfg_text += "\n" + astro_ts.read_text().lower()

    has_astro_tailwind = "@astrojs/tailwind" in astro_cfg_text
    has_cfg = (
        (repo_path / "tailwind.config.js").exists()
        or (repo_path / "tailwind.config.ts").exists()
        or (repo_path / "tailwind.config.mjs").exists()
        or has_astro_tailwind
    )
    has_tailwind_signal = '"tailwindcss"' in pkg_text or has_astro_tailwind
    if not has_tailwind_signal or not has_cfg:
        findings.append(
            _finding(
                "FE-003",
                "WARN",
                "structural_conformance",
                "Tailwind CSS setup is incomplete or absent.",
                "Add tailwindcss dependency and tailwind.config.*.",
            )
        )
    if "styled-components" in pkg_text or "emotion" in pkg_text:
        findings.append(
            _finding(
                "FE-003",
                "WARN",
                "structural_conformance",
                "Alternative CSS-in-JS stack detected alongside/instead of Tailwind.",
                "Prefer Tailwind CSS as the primary styling approach.",
            )
        )
    return findings


def check_shadcn(repo_path: Path) -> list[Finding]:
    """FE-004: shadcn/ui for components."""
    CHECK_ID = "FE-004"
    findings = []
    pkg = repo_path / "package.json"
    pkg_text = pkg.read_text().lower() if pkg.exists() else ""
    has_radix = "@radix-ui/" in pkg_text
    has_ui_dir = (repo_path / "src" / "components" / "ui").is_dir()
    if not has_radix and not has_ui_dir:
        findings.append(
            _finding(
                "FE-004",
                "WARN",
                "structural_conformance",
                "shadcn/ui signals not detected (no Radix deps and no src/components/ui).",
                "Adopt shadcn/ui component structure for frontend consistency.",
            )
        )
    return findings


def check_react_hook_form_zod(repo_path: Path) -> list[Finding]:
    """FE-005: React Hook Form + Zod for forms and validation."""
    CHECK_ID = "FE-005"
    findings = []
    pkg = repo_path / "package.json"
    pkg_text = pkg.read_text().lower() if pkg.exists() else ""
    src = repo_path / "src"
    if not src.is_dir():
        return findings
    form_exists = False
    for tsx in src.rglob("*.tsx"):
        text = tsx.read_text()
        if "<form" in text or "<Form" in text:
            form_exists = True
            break
    if form_exists and ('"react-hook-form"' not in pkg_text or '"zod"' not in pkg_text):
        findings.append(
            _finding(
                "FE-005",
                "WARN",
                "structural_conformance",
                "Form components exist but react-hook-form and/or zod is missing.",
                "Use React Hook Form + Zod for form handling and validation.",
            )
        )
    return findings


def check_railway_hosted_api(
    repo_path: Path, *, language: str = "python"
) -> list[Finding]:
    """API-001: API services are hosted on Railway (deterministic slice).

    Implements Railway deployment artifact presence (condition 1) and
    framework dependency presence (condition 3). Workflow-based checks for
    competing hosts belong to other rules.

    TODO(API-001-condition-2): ecosystem.yaml per-service ``host: railway`` is
    deferred — requires threading service context through deterministic checks.
    """
    CHECK_ID = "API-001"
    findings: list[Finding] = []
    has_railway = (
        (repo_path / "railway.toml").exists()
        or (repo_path / "railway.json").exists()
        or (repo_path / "nixpacks.toml").exists()
    )
    if not has_railway:
        findings.append(
            _finding(
                "API-001",
                "WARN",
                "structural_conformance",
                "Railway deployment configuration is missing (expected railway.toml, railway.json, or nixpacks.toml at repo root).",
                "Add Railway configuration so deployments are explicit and reviewable.",
            )
        )

    if language == "python":
        pyproject = repo_path / "pyproject.toml"
        py_text = pyproject.read_text().lower() if pyproject.exists() else ""
        req = repo_path / "requirements.txt"
        req_text = req.read_text().lower() if req.exists() else ""
        if "fastapi" not in py_text + "\n" + req_text:
            findings.append(
                _finding(
                    "API-001",
                    "WARN",
                    "structural_conformance",
                    "FastAPI is not declared for this Python API service.",
                    "Declare fastapi in pyproject.toml or requirements.txt dependencies.",
                )
            )
    else:
        pkg = repo_path / "package.json"
        pkg_text = pkg.read_text().lower() if pkg.exists() else ""
        if "hono" not in pkg_text:
            findings.append(
                _finding(
                    "API-001",
                    "WARN",
                    "structural_conformance",
                    "Hono is not declared for this TypeScript API service.",
                    "Add hono to package.json dependencies.",
                )
            )
    return findings


_NON_POSTGRES_STORE_MARKERS_PY = (
    "mysql",
    "mysqlclient",
    "pymysql",
    "aiosqlite",
    "sqlite3",
    "sqlalchemy[sqlite]",
    "mongodb",
    "motor",
    "pymongo",
    "dynamodb",
    "boto3",
)


def check_postgres_only_data_store(
    repo_path: Path, *, language: str = "python"
) -> list[Finding]:
    """API-002: PostgreSQL as the only primary relational data store.

    Scans declared Python and Node dependencies for obvious non-Postgres
    primary-store clients. Redis as a cache alongside Postgres is a judgment
    call — a bare ``redis`` dependency still flags here; narrow exemptions
    belong in evaluator.yaml when justified.
    """
    CHECK_ID = "API-002"
    findings: list[Finding] = []
    if language == "python":
        combined = ""
        for rel in (
            "pyproject.toml",
            "requirements.txt",
            "requirements/base.txt",
            "requirements/prod.txt",
        ):
            p = repo_path / rel
            if p.exists():
                combined += "\n" + p.read_text().lower()
        for marker in _NON_POSTGRES_STORE_MARKERS_PY:
            if marker in combined:
                findings.append(
                    _finding(
                        "API-002",
                        "ERROR",
                        "structural_conformance",
                        f"Non-Postgres data-store client or driver signal detected ({marker!r}).",
                        "Standardize on PostgreSQL as the primary relational store; remove alternate DB drivers unless formally excepted.",
                    )
                )
                break
    else:
        pkg = repo_path / "package.json"
        if not pkg.exists():
            return findings
        text = pkg.read_text().lower()
        node_markers = (
            '"mysql"',
            '"mysql2"',
            '"sqlite3"',
            '"better-sqlite3"',
            '"mongodb"',
            '"mongoose"',
            '"redis"',
            '"ioredis"',
            '"dynamodb"',
        )
        for marker in node_markers:
            if marker in text:
                findings.append(
                    _finding(
                        "API-002",
                        "ERROR",
                        "structural_conformance",
                        f"Non-Postgres data-store dependency present ({marker}).",
                        "Use PostgreSQL with an approved client (e.g. drizzle + postgres).",
                    )
                )
                break
    return findings


def _pyproject_and_requirements_text(repo_path: Path) -> str:
    parts: list[str] = []
    py = repo_path / "pyproject.toml"
    if py.exists():
        parts.append(py.read_text().lower())
    for rel in ("requirements.txt", "requirements/base.txt"):
        p = repo_path / rel
        if p.exists():
            parts.append(p.read_text().lower())
    return "\n".join(parts)


def check_prefect_present(
    repo_path: Path,
    cog_subtype: str = "pipeline",
) -> list[Finding]:
    """PIPE-001: Prefect dependency and usage signals.

    Pipeline cogs must declare ``prefect`` and use ``@flow`` in Python sources.
    Trigger cogs must declare ``prefect`` and call into deployment APIs such as
    ``run_deployment``.

    If ``prefect`` is not declared, emit only the dependency finding — do not
    also flag missing usage (the dependency gap is the root cause).
    """
    CHECK_ID = "PIPE-001"
    findings: list[Finding] = []
    blob = _pyproject_and_requirements_text(repo_path)
    if "prefect" not in blob:
        findings.append(
            _finding(
                "PIPE-001",
                "WARN",
                "pipeline_consistency",
                "Prefect is not declared as a dependency.",
                "Add prefect to pyproject.toml (or requirements.txt) for orchestrated flows.",
            )
        )
        return findings

    src = repo_path / "src"
    if not src.is_dir():
        findings.append(
            _finding(
                "PIPE-001",
                "WARN",
                "pipeline_consistency",
                "src/ tree missing — cannot verify Prefect usage in application code.",
                "Add a src/ package with flow entrypoints.",
            )
        )
        return findings

    py_src = "\n".join(f.read_text() for f in src.rglob("*.py"))
    if cog_subtype == "trigger":
        if "run_deployment" not in py_src:
            findings.append(
                _finding(
                    "PIPE-001",
                    "WARN",
                    "pipeline_consistency",
                    "Trigger cog source does not reference run_deployment (Prefect deployment API).",
                    "Use Prefect's Python client to trigger downstream deployments from the watcher/trigger cog.",
                )
            )
    elif "@flow" not in py_src:
        findings.append(
            _finding(
                "PIPE-001",
                "WARN",
                "pipeline_consistency",
                "Pipeline cog source has no @flow-decorated Prefect flow.",
                "Define orchestration entrypoints with @flow and register them from the cog main module.",
            )
        )
    return findings


def check_prefect_cloud_observability(
    repo_path: Path,
    cog_subtype: str = "pipeline",
) -> list[Finding]:
    """CD-005: Prefect Cloud wiring is documented for orchestrated cogs.

    When ``prefect`` is declared as a dependency, ``.env.example`` should
    document how the process reaches Prefect Cloud (``PREFECT_API_URL`` or
    equivalent). If Prefect is not a declared dependency, return no findings —
    PIPE-001 already covers the missing-dependency case.

    Competing schedulers referenced from application source (for example
    APScheduler) are surfaced at INFO with a manual review prompt — a
    deterministic scan cannot tell dev-only fallback from primary scheduling.

    GitHub Actions workflow scanning for competing orchestrators is owned by
    CD-006 (future wave) to avoid double-reporting once that check lands.
    """
    CHECK_ID = "CD-005"
    findings: list[Finding] = []
    blob = _pyproject_and_requirements_text(repo_path)
    if "prefect" not in blob:
        return findings

    env_example = repo_path / ".env.example"
    env_text = env_example.read_text() if env_example.exists() else ""
    lowered = env_text.lower()
    if not any(
        token in lowered
        for token in (
            "prefect_api_url",
            "prefect_api_key",
            "api.prefect.cloud",
            "prefect_cloud",
        )
    ):
        findings.append(
            _finding(
                "CD-005",
                "WARN",
                "cd_readiness",
                "Prefect Cloud connection is not documented in .env.example (expected PREFECT_API_URL or equivalent).",
                "Document Prefect Cloud API URL / workspace auth vars for operators.",
            )
        )

    src = repo_path / "src"
    if src.is_dir():
        py_src = "\n".join(f.read_text() for f in src.rglob("*.py"))
        if (
            "apscheduler" in py_src.lower()
            and not _is_inside_string_literal(py_src, "APScheduler")
            and not _is_inside_string_literal(py_src, "apscheduler")
        ):
            findings.append(
                _finding(
                    "CD-005",
                    "INFO",
                    "cd_readiness",
                    "APScheduler is referenced — confirm it is only a local dev fallback, not the primary scheduler.",
                    "Primary orchestration should remain Prefect Cloud; document intentional APScheduler use if applicable.",
                )
            )
    return findings


def _fe008_version_is_pinned_exact(version: str) -> bool:
    v = str(version).strip().strip('"').strip("'")
    if not v or v in ("*", "latest"):
        return False
    if v.startswith(("^", "~", ">", "<")):
        return False
    return not re.search(r"\d+\.[xX](?:\D|$)", v)


def check_astro_pinned_versions(repo_path: Path) -> list[Finding]:
    """FE-008: Astro-related npm dependencies use exact semver pins.

    Flags range markers (^, ~, >=, …), ``latest``, wildcards, and ``1.x``-style
    placeholders in dependency strings for packages whose names contain
    ``astro``.
    """
    CHECK_ID = "FE-008"
    findings: list[Finding] = []
    pkg = repo_path / "package.json"
    if not pkg.exists():
        return findings
    try:
        import json as _json

        data = _json.loads(pkg.read_text())
    except Exception:
        findings.append(
            _finding(
                "FE-008",
                "WARN",
                "structural_conformance",
                "package.json is not valid JSON — cannot validate Astro pin policy.",
                "Repair package.json syntax.",
            )
        )
        return findings

    for section in ("dependencies", "devDependencies"):
        block = data.get(section)
        if not isinstance(block, dict):
            continue
        for name, raw_ver in block.items():
            if "astro" not in str(name).lower():
                continue
            if not isinstance(raw_ver, str):
                findings.append(
                    _finding(
                        "FE-008",
                        "WARN",
                        "structural_conformance",
                        f"{section}: {name} version must be a string semver for FE-008 scanning.",
                        "Use explicit string versions for Astro-related packages.",
                    )
                )
                continue
            if not _fe008_version_is_pinned_exact(raw_ver):
                findings.append(
                    _finding(
                        "FE-008",
                        "WARN",
                        "structural_conformance",
                        f"{section}: {name} is not pinned to an exact version ({raw_ver!r}).",
                        "Pin Astro-related packages to exact versions (no ^, ~, >=, *, latest, or x-range placeholders).",
                    )
                )
    return findings


def check_gha_not_trigger_relay(repo_path: Path) -> list[Finding]:
    """CD-006: GitHub Actions must not relay repository triggers into app code.

    Scans ``.github/workflows`` for ``repository_dispatch`` paired with
    Prefect/deployment invocations, scheduled jobs calling Prefect Cloud, and
    internal trigger HTTP paths. Handles malformed YAML and the YAML 1.1
    ``on:`` → ``true`` quirk via ``suppress`` around ``yaml.safe_load``.
    """
    CHECK_ID = "CD-006"
    findings: list[Finding] = []
    import yaml as _yaml

    wf_dir = repo_path / ".github" / "workflows"
    if wf_dir.is_dir():
        for wf in sorted(wf_dir.rglob("*.yml")) + sorted(wf_dir.rglob("*.yaml")):
            try:
                text = wf.read_text()
            except OSError:
                continue
            low = text.lower()
            rel = str(wf.relative_to(repo_path))
            with suppress(Exception):
                _yaml.safe_load(text)

            if "repository_dispatch" in low:
                relay = any(
                    k in low
                    for k in (
                        "prefect deployment run",
                        "prefect deploy",
                        "run_deployment(",
                        "npx prefect",
                    )
                ) or (
                    "/dispatches" in text
                    and any(k in low for k in ("curl ", "httpx.", "requests."))
                )
                pure_ci = ("pytest" in low or "ruff" in low) and not relay
                if relay and not pure_ci:
                    findings.append(
                        _finding(
                            "CD-006",
                            "WARN",
                            "structural_conformance",
                            f"repository_dispatch workflow appears to relay into automation ({rel}).",
                            "Prefer watcher-cog + Prefect; do not chain GitHub Actions into app invocations.",
                        )
                    )

            if ("schedule" in low or "cron:" in low) and "api.prefect.cloud" in low:
                findings.append(
                    _finding(
                        "CD-006",
                        "WARN",
                        "structural_conformance",
                        f"Scheduled workflow references Prefect Cloud API ({rel}).",
                        "Avoid cron-driven Prefect Cloud calls from GitHub Actions; use Prefect-native scheduling.",
                    )
                )

            if re.search(r"['\"]/v1/(trigger|runs)", text):
                findings.append(
                    _finding(
                        "CD-006",
                        "WARN",
                        "structural_conformance",
                        f"Workflow references internal trigger HTTP path ({rel}).",
                        "Do not POST to internal trigger endpoints from GitHub Actions.",
                    )
                )

    src = repo_path / "src"
    if src.is_dir():
        for py in src.rglob("*.py"):
            if "tests/" in str(py).replace("\\", "/"):
                continue
            try:
                t = py.read_text()
            except OSError:
                continue
            if re.search(
                r"(httpx|requests)\.(post|put)\([^\)]*api\.github\.com/[^\"'\)]+/dispatches",
                t,
                re.I,
            ):
                findings.append(
                    _finding(
                        "CD-006",
                        "WARN",
                        "structural_conformance",
                        f"Python source posts to GitHub dispatches API ({py.relative_to(repo_path)}).",
                        "Use watcher-cog + Prefect instead of repository_dispatch relays.",
                    )
                )
    return findings


def check_adrs_present(repo_path: Path) -> list[Finding]:
    """DOC-005: ADR trail for non-trivial repos (LOC heuristic under src/)."""
    findings: list[Finding] = []
    src = repo_path / "src"
    loc = 0
    if src.is_dir():
        for p in src.rglob("*"):
            if not p.is_file():
                continue
            if p.suffix.lower() not in {".py", ".ts", ".tsx", ".js", ".mjs"}:
                continue
            with suppress(OSError, UnicodeDecodeError):
                loc += len(p.read_text().splitlines())
    if loc < 50:
        return findings

    dec = repo_path / "docs" / "decisions"
    if not dec.is_dir():
        findings.append(
            _finding(
                "DOC-005",
                "WARN",
                "documentation_coverage",
                "docs/decisions/ directory is missing for a non-trivial codebase.",
                "Add architecture decision records under docs/decisions/.",
            )
        )
        return findings

    if not any(dec.glob("ADR-*.md")):
        findings.append(
            _finding(
                "DOC-005",
                "WARN",
                "documentation_coverage",
                "docs/decisions/ exists but no ADR-NNN-*.md files were found.",
                "Author numbered ADR markdown files for significant decisions.",
            )
        )
    return findings


def check_response_shape_parity(
    repo_path: Path, *, language: str = "python"
) -> list[Finding]:
    """XSTACK-002: HTTP handlers expose typed response models / helpers."""
    CHECK_ID = "XSTACK-002"
    findings: list[Finding] = []
    src = repo_path / "src"
    if not src.is_dir():
        return findings

    if language == "python":
        for py in src.rglob("*.py"):
            if "tests/" in str(py).replace("\\", "/"):
                continue
            try:
                text = py.read_text()
            except OSError:
                continue
            if not re.search(
                r"@(?:router|app)\.(get|post|put|delete|patch)\s*\(", text
            ):
                continue
            if "response_model=" not in text:
                findings.append(
                    _finding(
                        "XSTACK-002",
                        "WARN",
                        "structural_conformance",
                        f"FastAPI route missing response_model= in {py.relative_to(repo_path)}.",
                        "Declare response_model (or return type) for every public route.",
                    )
                )
                break
    else:
        for ts in list(src.rglob("*.ts")) + list(src.rglob("*.tsx")):
            ts_path_str = str(ts).replace("\\", "/")
            # Skip test code regardless of layout:
            #   - any file under a tests/ or test/ directory
            #   - any *.test.ts or *.test.tsx file (Vitest/Jest convention)
            if (
                "/tests/" in ts_path_str
                or "/test/" in ts_path_str
                or ts.name.endswith(".test.ts")
                or ts.name.endswith(".test.tsx")
            ):
                continue
            try:
                text = ts.read_text()
            except OSError:
                continue
            if not re.search(r"\bc\.json\s*\(", text):
                continue
            if "success(" in text or re.search(
                r"from\s+['\"][^'\"]*success", text, re.I
            ):
                continue
            findings.append(
                _finding(
                    "XSTACK-002",
                    "WARN",
                    "structural_conformance",
                    f"Hono handler uses raw c.json without success()/error() helper ({ts.relative_to(repo_path)}).",
                    "Wrap JSON responses with the shared success()/error() helpers.",
                )
            )
            break
    return findings


def _parse_astro_file(path: Path) -> dict[str, Any]:
    """Split an Astro file into frontmatter, <script> bodies, and client flags."""
    try:
        text = path.read_text()
    except OSError:
        return {"frontmatter": "", "scripts": [], "has_client": False, "body": ""}
    frontmatter = ""
    body = text
    if text.startswith("---"):
        parts = text.split("---", 2)
        if len(parts) >= 3:
            frontmatter = parts[1]
            body = parts[2]
    scripts = re.findall(r"<script[^>]*>([\s\S]*?)</script>", body, flags=re.IGNORECASE)
    has_client = bool(re.search(r"\bclient:[^\s=]+", body))
    return {
        "frontmatter": frontmatter,
        "scripts": scripts,
        "has_client": has_client,
        "body": body,
    }


def _extract_fetch_urls(chunk: str) -> list[str]:
    return re.findall(r"""fetch\s*\(\s*['"]([^'"]+)['"]""", chunk)


def check_astro_build_time_data(repo_path: Path) -> list[Finding]:
    """FE-009: Runtime fetch URLs must not duplicate build-time fetches."""
    CHECK_ID = "FE-009"
    findings: list[Finding] = []
    build_urls: set[str] = set()
    astro_files = list(repo_path.rglob("*.astro"))
    if not astro_files:
        return findings

    for path in astro_files:
        parsed = _parse_astro_file(path)
        for url in _extract_fetch_urls(parsed["frontmatter"]):
            build_urls.add(url)

    for path in astro_files:
        parsed = _parse_astro_file(path)
        if parsed["has_client"]:
            continue
        combined = "\n".join(parsed["scripts"])
        for url in _extract_fetch_urls(combined):
            if url in build_urls:
                findings.append(
                    _finding(
                        "FE-009",
                        "WARN",
                        "structural_conformance",
                        f"Astro component performs runtime fetch of URL also used in frontmatter ({path.relative_to(repo_path)}).",
                        "Move data to build-time fetch or isolate client-only access with client:* directives.",
                    )
                )
                break
    return findings


def check_astro_runtime_queries(repo_path: Path) -> list[Finding]:
    """FE-010: Undocumented runtime fetches in Astro islands."""
    CHECK_ID = "FE-010"
    findings: list[Finding] = []
    docs_blob = ""
    readme = repo_path / "README.md"
    if readme.exists():
        with suppress(OSError):
            docs_blob += readme.read_text().lower()
    for md in (
        (repo_path / "docs").rglob("*.md") if (repo_path / "docs").is_dir() else []
    ):
        with suppress(OSError):
            docs_blob += md.read_text().lower()

    for path in repo_path.rglob("*.astro"):
        parsed = _parse_astro_file(path)
        if parsed["has_client"]:
            continue
        combined = "\n".join(parsed["scripts"])
        if "fetch(" not in combined:
            continue
        for url in _extract_fetch_urls(combined):
            if url not in docs_blob:
                findings.append(
                    _finding(
                        "FE-010",
                        "WARN",
                        "structural_conformance",
                        f"Runtime fetch URL not documented in README/docs ({path.relative_to(repo_path)}: {url}).",
                        "Document external endpoints or mark the island as client:* when intentional.",
                    )
                )
                break
    return findings


def check_clerk_m2m_auth(repo_path: Path, *, language: str = "python") -> list[Finding]:
    """CD-012: Internal calls should use Clerk M2M JWTs, not static API keys."""
    CHECK_ID = "CD-012"
    findings: list[Finding] = []
    if language != "python":
        return findings
    src = repo_path / "src"
    if not src.is_dir():
        return findings
    for py in src.rglob("*.py"):
        if "tests/" in str(py).replace("\\", "/"):
            continue
        try:
            text = py.read_text()
        except OSError:
            continue
        if "X-Internal-API-Key" in text and not _is_inside_string_literal(
            text, "X-Internal-API-Key"
        ):
            findings.append(
                _finding(
                    "CD-012",
                    "WARN",
                    "cd_readiness",
                    f"X-Internal-API-Key header referenced in {py.relative_to(repo_path)}.",
                    "Replace static internal API keys with Clerk machine-to-machine JWT acquisition.",
                )
            )
        elif (
            ("api.kaianolevine" in text or '"/v1/' in text)
            and "httpx" in text
            and not any(
                token in text.lower()
                for token in ("clerk", "jwt", "get_token", "authenticate")
            )
        ):
            findings.append(
                _finding(
                    "CD-012",
                    "WARN",
                    "cd_readiness",
                    f"Internal HTTP client without Clerk/JWT acquisition pattern ({py.relative_to(repo_path)}).",
                    "Acquire Clerk M2M JWTs before calling internal APIs.",
                )
            )
    return findings


def check_db_writes_use_upserts(repo_path: Path) -> list[Finding]:
    """PIPE-002: Database writes should use upsert / ON CONFLICT patterns."""
    CHECK_ID = "PIPE-002"
    findings: list[Finding] = []
    src = repo_path / "src"
    if not src.is_dir():
        return findings
    for py in src.rglob("*.py"):
        if "tests/" in str(py).replace("\\", "/"):
            continue
        try:
            text = py.read_text()
        except OSError:
            continue
        if (
            "session.add(" in text
            and "on_conflict" not in text.lower()
            and "merge(" not in text
        ):
            findings.append(
                _finding(
                    "PIPE-002",
                    "WARN",
                    "pipeline_consistency",
                    f"session.add() without merge()/on_conflict in {py.relative_to(repo_path)}.",
                    "Prefer upsert patterns (merge or ON CONFLICT) for idempotent writes.",
                )
            )
        if (
            re.search(r"\bINSERT\s+INTO\b", text, re.I)
            and "ON CONFLICT" not in text.upper()
        ):
            findings.append(
                _finding(
                    "PIPE-002",
                    "WARN",
                    "pipeline_consistency",
                    f"Raw INSERT without ON CONFLICT in {py.relative_to(repo_path)}.",
                    "Use INSERT ... ON CONFLICT for idempotent persistence.",
                )
            )
    return findings


def check_inputs_not_deleted(repo_path: Path) -> list[Finding]:
    """PIPE-005: Input files must not be deleted or moved to trash."""
    CHECK_ID = "PIPE-005"
    findings: list[Finding] = []
    src = repo_path / "src"
    if not src.is_dir():
        return findings
    for path in list(src.rglob("*.py")) + list(src.rglob("*.ts")):
        if "tests/" in str(path).replace("\\", "/"):
            continue
        try:
            text = path.read_text()
        except OSError:
            continue
        has_delete = ".files().delete(" in text or "files().delete(" in text
        if has_delete and not (
            _is_inside_string_literal(text, ".files().delete(")
            and _is_inside_string_literal(text, "files().delete(")
        ):
            findings.append(
                _finding(
                    "PIPE-005",
                    "WARN",
                    "pipeline_consistency",
                    f"Drive files().delete() referenced in {path.relative_to(repo_path)}.",
                    "Never delete raw input artifacts from Drive — move to derived outputs only.",
                )
            )
        if (
            "trashed" in text.lower()
            and "update" in text.lower()
            and "files()" in text
            and not _is_inside_string_literal(text, "trashed")
        ):
            findings.append(
                _finding(
                    "PIPE-005",
                    "WARN",
                    "pipeline_consistency",
                    f"Potential Drive trash update on input file in {path.relative_to(repo_path)}.",
                    "Avoid trashing upstream inputs; operate on copies.",
                )
            )
        if re.search(r"os\.(remove|unlink)\(|shutil\.rmtree\(", text) and re.search(
            r"\b(input_path|input_file|source_path|src_path|local_path)\b", text
        ):
            findings.append(
                _finding(
                    "PIPE-005",
                    "WARN",
                    "pipeline_consistency",
                    f"os.remove/unlink/rmtree may target input paths ({path.relative_to(repo_path)}).",
                    "Only remove scratch/temp paths — never input variables.",
                )
            )
    return findings


# Wave 9 — Coverage sweep. Implementations for 37 rules missing from
# engine but present in the catalog. Deliberately conservative on
# false-positive rate: where the rule has LLM-judgment components,
# only the mechanical part is implemented here.
# ==========================================================================


def check_orm_usage(repo_path: Path, language: str = "python") -> list[Finding]:
    """API-003: ORM usage required; no raw SQL outside ORM."""
    CHECK_ID = "API-003"
    findings: list[Finding] = []
    if language == "python":
        pyproject = repo_path / "pyproject.toml"
        py_text = pyproject.read_text().lower() if pyproject.exists() else ""
        if "sqlalchemy" not in py_text:
            findings.append(
                _finding(
                    "API-003",
                    "WARN",
                    "structural_conformance",
                    "api-service (Python) does not declare sqlalchemy in pyproject.toml.",
                    "Add sqlalchemy to dependencies and declare models via ORM.",
                )
            )
    else:
        pkg = repo_path / "package.json"
        pkg_text = pkg.read_text().lower() if pkg.exists() else ""
        if "drizzle-orm" not in pkg_text and "prisma" not in pkg_text:
            findings.append(
                _finding(
                    "API-003",
                    "WARN",
                    "structural_conformance",
                    "api-service (TypeScript) does not declare drizzle-orm or prisma.",
                    "Depend on an ORM (drizzle-orm preferred) instead of raw SQL.",
                )
            )
    return findings


def check_v1_route_prefix(repo_path: Path, language: str = "python") -> list[Finding]:
    """API-004: /v1/ prefix required on public routes."""
    findings: list[Finding] = []
    src = repo_path / "src"
    if not src.is_dir():
        return findings

    exempt_paths = (
        "/health",
        "/docs",
        "/openapi.json",
        "/metrics",
        "/redoc",
        "/version",
    )

    if language == "python":
        import ast

        route_attrs = {"get", "post", "put", "delete", "patch", "head", "options"}

        def _const_str(node: ast.AST | None) -> str | None:
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                return node.value
            return None

        def _router_var_name(node: ast.AST | None) -> str | None:
            if isinstance(node, ast.Name):
                return node.id
            if isinstance(node, ast.Attribute):
                return node.attr
            return None

        def _norm_path(segment: str) -> str:
            seg = (segment or "").strip()
            if not seg:
                return ""
            if not seg.startswith("/"):
                seg = "/" + seg
            if seg != "/":
                seg = seg.rstrip("/")
            return seg

        def _join_paths(left: str, right: str) -> str:
            left_norm = _norm_path(left)
            right_norm = _norm_path(right)
            if not left_norm:
                return right_norm or "/"
            if not right_norm:
                return left_norm
            if left_norm == "/":
                return right_norm
            if right_norm == "/":
                return left_norm
            return f"{left_norm}/{right_norm.lstrip('/')}"

        py_files = list(src.rglob("*.py"))
        local_prefixes: dict[str, str] = {}
        include_prefixes: dict[str, str] = {}

        # Pass 1: collect APIRouter local prefixes and include_router mount prefixes.
        for py_file in py_files:
            try:
                text = py_file.read_text()
                tree = ast.parse(text)
            except Exception:
                continue
            for node in ast.walk(tree):
                if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
                    call = node.value
                    if not (
                        isinstance(call.func, ast.Name) and call.func.id == "APIRouter"
                    ) and not (
                        isinstance(call.func, ast.Attribute)
                        and call.func.attr == "APIRouter"
                    ):
                        continue
                    prefix_val: str | None = None
                    for kw in call.keywords:
                        if kw.arg == "prefix":
                            prefix_val = _const_str(kw.value)
                            break
                    if not prefix_val:
                        continue
                    for target in node.targets:
                        if isinstance(target, ast.Name):
                            local_prefixes[target.id] = prefix_val

                if isinstance(node, ast.Call):
                    if not (
                        isinstance(node.func, ast.Attribute)
                        and node.func.attr == "include_router"
                    ):
                        continue
                    if not node.args:
                        continue
                    router_name = _router_var_name(node.args[0])
                    if not router_name:
                        continue
                    include_prefix: str | None = None
                    for kw in node.keywords:
                        if kw.arg == "prefix":
                            include_prefix = _const_str(kw.value)
                            break
                    if not include_prefix:
                        continue
                    existing = include_prefixes.get(router_name)
                    # Prefer a v1-bearing mount if multiple include_router calls exist.
                    if existing is None or (
                        "/v1" in include_prefix and "/v1" not in existing
                    ):
                        include_prefixes[router_name] = include_prefix

        # Pass 2: evaluate effective route path from include + local + decorator path.
        for py_file in py_files:
            try:
                text = py_file.read_text()
                tree = ast.parse(text)
            except Exception:
                continue
            rel = py_file.relative_to(repo_path)
            for node in ast.walk(tree):
                if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    continue
                for dec in node.decorator_list:
                    if not isinstance(dec, ast.Call):
                        continue
                    if not isinstance(dec.func, ast.Attribute):
                        continue
                    if dec.func.attr not in route_attrs:
                        continue
                    if not dec.args:
                        continue
                    path_arg = dec.args[0]
                    route = _const_str(path_arg)
                    if route is None:
                        continue
                    router_var = _router_var_name(dec.func.value)
                    include_prefix = include_prefixes.get(router_var or "", "")
                    local_prefix = local_prefixes.get(router_var or "", "")
                    effective_route = _join_paths(
                        _join_paths(include_prefix, local_prefix), route
                    )

                    if any(effective_route.startswith(p) for p in exempt_paths):
                        continue
                    if not effective_route.startswith("/v1/"):
                        findings.append(
                            _finding(
                                "API-004",
                                "ERROR",
                                "structural_conformance",
                                f"{rel}::{node.name}: effective route {effective_route!r} missing /v1/ prefix.",
                                "Mount routes under /v1/ to support versioning.",
                            )
                        )
    else:
        route_re = re.compile(
            r"""(?:app|router)\.(?:get|post|put|delete|patch)\s*\(\s*['"]([^'"]+)['"]"""
        )
        for ts_file in list(src.rglob("*.ts")) + list(src.rglob("*.tsx")):
            try:
                text = ts_file.read_text()
            except Exception:
                continue
            rel = ts_file.relative_to(repo_path)
            for m in route_re.finditer(text):
                route = m.group(1)
                if any(route.startswith(p) for p in exempt_paths):
                    continue
                if not route.startswith("/v1/"):
                    findings.append(
                        _finding(
                            "API-004",
                            "ERROR",
                            "structural_conformance",
                            f"{rel}: route {route!r} missing /v1/ prefix.",
                            "Mount routes under /v1/ to support versioning.",
                        )
                    )
    return findings


def check_response_envelope_presence(repo_path: Path) -> list[Finding]:
    """API-005: Response envelope — endpoints declare response_model.

    Partial overlap with XSTACK-002, but this one specifically looks at
    shape consistency. Our deterministic pass just asserts response_model=
    exists on each endpoint (delegating shape inspection to the LLM).
    """
    CHECK_ID = "API-005"
    import ast

    findings: list[Finding] = []
    src = repo_path / "src"
    if not src.is_dir():
        return findings

    route_attrs = {"get", "post", "put", "delete", "patch"}
    flagged: set[tuple[str, str]] = set()
    for py_file in src.rglob("*.py"):
        try:
            text = py_file.read_text()
            tree = ast.parse(text)
        except Exception:
            continue
        rel = py_file.relative_to(repo_path)
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for dec in node.decorator_list:
                if not isinstance(dec, ast.Call):
                    continue
                if not isinstance(dec.func, ast.Attribute):
                    continue
                if dec.func.attr not in route_attrs:
                    continue
                has_rm = any(kw.arg == "response_model" for kw in dec.keywords)
                if not has_rm:
                    key = (str(rel), node.name)
                    if key in flagged:
                        continue
                    flagged.add(key)
                    findings.append(
                        _finding(
                            "API-005",
                            "ERROR",
                            "structural_conformance",
                            f"{rel}::{node.name}: endpoint missing response_model=.",
                            "Declare a response_model Pydantic class so the envelope "
                            "shape is explicit.",
                        )
                    )
    return findings


def check_owner_id_column(repo_path: Path) -> list[Finding]:
    """API-006: Every table is authorization-scoped to a Clerk user.

    Three patterns satisfy this:

    1. Direct ownership — the table has an ``owner_id`` column holding the
       Clerk user ID of the row's owner. Majority case.

    2. Identity table — the table IS the user; its primary key IS the user
       identifier. Detected by: primary-key column named ``user_id`` (or
       class ends in ``Profile``/``Identity``/``User``).

    3. Relationship table — the row represents a relationship to a user,
       using a ``user_id`` column that carries a ``ForeignKey`` to an
       identity table. Detected by: ``user_id`` column with a ``ForeignKey``
       argument in its ``mapped_column(...)`` / ``Column(...)`` call.

    Existing exemptions by class-name suffix (``_lookup``, ``_config``,
    ``_enum``) continue to apply. The SQLAlchemy declarative root
    (``Base``, ``DeclarativeBase``, ``Model``) is skipped.
    """
    import ast

    findings: list[Finding] = []
    src = repo_path / "src"
    if not src.is_dir():
        return findings

    # Variable names that hint a model is internal/lookup and exempt.
    exempt_suffixes = ("_lookup", "_config", "_enum", "Lookup", "Config", "Enum")

    # Class names suggesting the model is the user identity itself.
    identity_class_suffixes = ("Profile", "Identity", "User")

    # Class names that are the SQLAlchemy declarative root itself, not a
    # table. These inherit from DeclarativeBase or declarative_base() and
    # exist to serve as the base for every real model — they have no
    # columns of their own.
    abstract_root_names = {"Base", "DeclarativeBase", "Model"}

    def _column_call_kwargs(value: ast.AST) -> list[ast.keyword]:
        """For a `mapped_column(...)` / `Column(...)` call, return its kwargs."""
        if isinstance(value, ast.Call):
            func = value.func
            func_name = None
            if isinstance(func, ast.Name):
                func_name = func.id
            elif isinstance(func, ast.Attribute):
                func_name = func.attr
            if func_name in ("mapped_column", "Column"):
                return list(value.keywords)
        return []

    def _column_call_positional_args(value: ast.AST) -> list[ast.AST]:
        """For a column call, return its positional args (where FK can live)."""
        if isinstance(value, ast.Call):
            func = value.func
            func_name = None
            if isinstance(func, ast.Name):
                func_name = func.id
            elif isinstance(func, ast.Attribute):
                func_name = func.attr
            if func_name in ("mapped_column", "Column"):
                return list(value.args)
        return []

    def _has_foreign_key(value: ast.AST) -> bool:
        """True if a column call contains a ForeignKey(...) argument."""
        # ForeignKey can appear as a positional arg or as kwarg `foreign_keys=...`
        for arg in _column_call_positional_args(value):
            if isinstance(arg, ast.Call):
                fn = arg.func
                name = None
                if isinstance(fn, ast.Name):
                    name = fn.id
                elif isinstance(fn, ast.Attribute):
                    name = fn.attr
                if name == "ForeignKey":
                    return True
        return False

    def _is_primary_key(value: ast.AST) -> bool:
        """True if a column call has primary_key=True."""
        for kw in _column_call_kwargs(value):
            if (
                kw.arg == "primary_key"
                and isinstance(kw.value, ast.Constant)
                and kw.value.value is True
            ):
                return True
        return False

    for py_file in src.rglob("*.py"):
        try:
            text = py_file.read_text()
            tree = ast.parse(text)
        except Exception:
            continue
        rel = py_file.relative_to(repo_path)
        for node in ast.walk(tree):
            if not isinstance(node, ast.ClassDef):
                continue
            # Skip the SQLAlchemy declarative root itself.
            if node.name in abstract_root_names:
                continue
            # Heuristic: class is a SQLAlchemy model if it inherits from a
            # class ending in Base or DeclarativeBase.
            base_names = []
            for b in node.bases:
                if isinstance(b, ast.Name):
                    base_names.append(b.id)
                elif isinstance(b, ast.Attribute):
                    base_names.append(b.attr)
            if not any(bn.endswith("Base") or "Declarative" in bn for bn in base_names):
                continue
            if any(node.name.endswith(s) for s in exempt_suffixes):
                continue

            has_owner_id = False
            user_id_is_pk = False
            user_id_has_fk = False

            for stmt in node.body:
                if isinstance(stmt, ast.AnnAssign):
                    targets = [stmt.target]
                    value = stmt.value
                elif isinstance(stmt, ast.Assign):
                    targets = stmt.targets
                    value = stmt.value
                else:
                    continue
                for t in targets:
                    if not isinstance(t, ast.Name):
                        continue
                    if t.id == "owner_id":
                        has_owner_id = True
                    elif t.id == "user_id" and value is not None:
                        if _is_primary_key(value):
                            user_id_is_pk = True
                        if _has_foreign_key(value):
                            user_id_has_fk = True

            if has_owner_id:
                continue
            # Pattern 2: identity table — user_id is PK, OR class-name suffix
            # indicates identity.
            if user_id_is_pk or any(
                node.name.endswith(s) for s in identity_class_suffixes
            ):
                continue
            # Pattern 3: relationship table — user_id carries a ForeignKey.
            if user_id_has_fk:
                continue

            findings.append(
                _finding(
                    "API-006",
                    "WARN",
                    "structural_conformance",
                    f"{rel}::{node.name}: SQLAlchemy model is not "
                    "authorization-scoped — no owner_id column, not an identity "
                    "table (user_id primary key), and no user_id ForeignKey to "
                    "an identity table.",
                    "Add owner_id for ordinary tables; make user_id the primary "
                    "key for identity tables; or add a ForeignKey on user_id for "
                    "tables representing a relationship to a user. Suffix with "
                    "_lookup/_config/_enum for internal tables, or document in "
                    "evaluator.yaml.",
                )
            )
    return findings


def check_clerk_auth_dep(repo_path: Path, language: str = "python") -> list[Finding]:
    """API-007: Clerk verification helper referenced."""
    CHECK_ID = "API-007"
    findings: list[Finding] = []

    if language == "python":
        src = repo_path / "src"
        if not src.is_dir():
            return findings
        has_verify_token_usage = False
        for py_file in src.rglob("*.py"):
            try:
                text = py_file.read_text()
            except Exception:
                continue
            if "verify_token" in text or "clerk" in text.lower():
                has_verify_token_usage = True
                break
        if not has_verify_token_usage:
            findings.append(
                _finding(
                    "API-007",
                    "WARN",
                    "structural_conformance",
                    "api-service (Python) has no visible Clerk or verify_token usage.",
                    "Import verify_token from common-python-utils and add "
                    "Depends(verify_token) to protected routes.",
                )
            )
    else:
        pkg = repo_path / "package.json"
        pkg_text = pkg.read_text() if pkg.exists() else ""
        if "@clerk" not in pkg_text and "common-typescript-utils" not in pkg_text:
            findings.append(
                _finding(
                    "API-007",
                    "WARN",
                    "structural_conformance",
                    "api-service (TypeScript) has no Clerk SDK or common-typescript-utils dep.",
                    "Add @clerk/clerk-sdk-node or use verifyClerkToken from "
                    "common-typescript-utils.",
                )
            )
    return findings


def check_unauthenticated_routes(
    repo_path: Path, language: str = "python"
) -> list[Finding]:
    """API-008: Unauthenticated routes must be intentional.

    A FastAPI route clears the check if any of the following hold:

      1. The function signature has a Depends(...) default (authed).
      2. The route path is on the built-in exempt list (/health,
         /metrics, /docs, /openapi.json, /redoc).
      3. The decorator's description= or summary= kwarg contains the
         phrase "intentionally public" (case-insensitive) — the route
         explicitly documents its unauthenticated intent.
      4. The handler's docstring contains "intentionally public".

    Routes that lack auth and none of the above intent markers are
    flagged.
    """
    findings: list[Finding] = []
    if language != "python":
        return findings
    import ast

    src = repo_path / "src"
    if not src.is_dir():
        return findings

    route_attrs = {"get", "post", "put", "delete", "patch"}
    exempt_paths = ("/health", "/metrics", "/docs", "/openapi.json", "/redoc")
    intent_marker = "intentionally public"

    def _kwarg_contains(dec: ast.Call, kwarg_name: str, needle: str) -> bool:
        """Return True if decorator's kwarg (string or concatenated) contains needle."""
        for kw in dec.keywords:
            if kw.arg != kwarg_name:
                continue
            # Simple string constant
            if (
                isinstance(kw.value, ast.Constant)
                and isinstance(kw.value.value, str)
                and needle in kw.value.value.lower()
            ):
                return True
            # Implicit-string-concatenation or parenthesized multi-line string:
            # FastAPI often has description=( "..." "..." ) which AST represents
            # as a single Constant in Python 3.12+, but may be a BinOp or
            # JoinedStr in other forms. Fall back to unparsing the node.
            try:
                unparsed = ast.unparse(kw.value)
                if needle in unparsed.lower():
                    return True
            except Exception:
                pass
        return False

    for py_file in src.rglob("*.py"):
        try:
            text = py_file.read_text()
            tree = ast.parse(text)
        except Exception:
            continue
        rel = py_file.relative_to(repo_path)
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            # Is this a route handler?
            route_path: str | None = None
            route_dec: ast.Call | None = None
            for dec in node.decorator_list:
                if not isinstance(dec, ast.Call):
                    continue
                if not isinstance(dec.func, ast.Attribute):
                    continue
                if dec.func.attr not in route_attrs:
                    continue
                if (
                    dec.args
                    and isinstance(dec.args[0], ast.Constant)
                    and isinstance(dec.args[0].value, str)
                ):
                    route_path = dec.args[0].value
                    route_dec = dec
                    break
            if route_path is None or route_dec is None:
                continue
            if any(route_path.startswith(p) for p in exempt_paths):
                continue
            # Depends(...) default?
            has_depends = False
            for arg_default in node.args.defaults + node.args.kw_defaults:
                if arg_default is None:
                    continue
                if (
                    isinstance(arg_default, ast.Call)
                    and isinstance(arg_default.func, ast.Name)
                    and arg_default.func.id == "Depends"
                ):
                    has_depends = True
                    break
            if has_depends:
                continue
            # "intentionally public" marker in decorator description/summary?
            if _kwarg_contains(
                route_dec, "description", intent_marker
            ) or _kwarg_contains(route_dec, "summary", intent_marker):
                continue
            # "intentionally public" marker in function docstring?
            doc = ast.get_docstring(node) or ""
            if intent_marker in doc.lower():
                continue
            findings.append(
                _finding(
                    "API-008",
                    "ERROR",
                    "structural_conformance",
                    f"{rel}::{node.name}: route {route_path!r} has no Depends(...) auth.",
                    "Add Depends(verify_token) for protected routes, or document the "
                    "intentional public access in the route's decorator "
                    "description=/summary= or docstring with the phrase "
                    "'intentionally public'.",
                )
            )
    return findings


def check_cors_config(repo_path: Path, language: str = "python") -> list[Finding]:
    """API-009: CORS middleware configured; no hardcoded origins."""
    CHECK_ID = "API-009"
    findings: list[Finding] = []
    src = repo_path / "src"

    if language == "python":
        has_cors = False
        has_cors_origins_env = False
        if src.is_dir():
            for py_file in src.rglob("*.py"):
                try:
                    text = py_file.read_text()
                except Exception:
                    continue
                if "CORSMiddleware" in text:
                    has_cors = True
                if (
                    "CORS_ORIGINS" in text
                    or 'getenv("CORS_ORIGINS"' in text
                    or "getenv('CORS_ORIGINS'" in text
                ):
                    has_cors_origins_env = True
        if not has_cors:
            findings.append(
                _finding(
                    "API-009",
                    "ERROR",
                    "structural_conformance",
                    "api-service (Python) has no CORSMiddleware configuration.",
                    "Register CORSMiddleware from fastapi.middleware.cors with origins "
                    "sourced from CORS_ORIGINS env var.",
                )
            )
        elif not has_cors_origins_env:
            findings.append(
                _finding(
                    "API-009",
                    "WARN",
                    "structural_conformance",
                    "api-service (Python) uses CORSMiddleware but CORS_ORIGINS env var is not referenced.",
                    "Source allowed origins from CORS_ORIGINS rather than hardcoded values.",
                )
            )
    else:
        has_cors_import = False
        if src.is_dir():
            for ts_file in list(src.rglob("*.ts")) + list(src.rglob("*.tsx")):
                try:
                    text = ts_file.read_text()
                except Exception:
                    continue
                if (
                    "cors(" in text
                    or "from 'hono/cors'" in text
                    or 'from "hono/cors"' in text
                ):
                    has_cors_import = True
                    break
        if not has_cors_import:
            findings.append(
                _finding(
                    "API-009",
                    "ERROR",
                    "structural_conformance",
                    "api-service (TypeScript) has no cors() middleware import.",
                    "Import and register cors() from hono/cors with origins from process.env.CORS_ORIGINS.",
                )
            )
    return findings


def check_health_endpoint(repo_path: Path, language: str = "python") -> list[Finding]:
    """API-010: GET /health endpoint present."""
    findings: list[Finding] = []
    src = repo_path / "src"
    if not src.is_dir():
        return findings

    exts = ("*.py",) if language == "python" else ("*.ts", "*.tsx")
    has_health = False
    for ext in exts:
        for f in src.rglob(ext):
            try:
                text = f.read_text()
            except Exception:
                continue
            if "/health" in text and (
                "def health" in text or '"/health"' in text or "'/health'" in text
            ):
                has_health = True
                break
        if has_health:
            break
    if not has_health:
        findings.append(
            _finding(
                "API-010",
                "WARN",
                "structural_conformance",
                "api-service has no visible GET /health endpoint.",
                "Add a GET /health route that returns {'status': 'ok'} with no auth "
                "and no DB queries.",
            )
        )
    return findings


def check_migration_in_ci(
    repo_path: Path,
    language: str = "python",
    monorepo_root: Path | None = None,
) -> list[Finding]:
    """API-011: CI runs database migrations on deploy.

    Python (Alembic): ci.yml contains 'alembic upgrade head' in a deploy job.
    TypeScript (Drizzle): ci.yml contains 'drizzle-kit push' or 'drizzle-kit migrate'.
    For monorepo services, also checks the workspace root ci.yml.
    """
    findings: list[Finding] = []

    ci_texts = []
    ci = repo_path / ".github" / "workflows" / "ci.yml"
    if ci.exists():
        with suppress(Exception):
            ci_texts.append(ci.read_text())
    if monorepo_root is not None:
        root_ci = monorepo_root / ".github" / "workflows" / "ci.yml"
        if root_ci.exists():
            with suppress(Exception):
                ci_texts.append(root_ci.read_text())

    if not ci_texts:
        findings.append(
            _finding(
                "API-011",
                "ERROR",
                "structural_conformance",
                "api-service has no .github/workflows/ci.yml — migration steps cannot be verified.",
                "Add a ci.yml with deploy job including migration step.",
            )
        )
        return findings

    combined = "\n".join(ci_texts)

    if language == "python":
        if "alembic upgrade head" not in combined and "alembic upgrade" not in combined:
            findings.append(
                _finding(
                    "API-011",
                    "ERROR",
                    "structural_conformance",
                    "ci.yml has no 'alembic upgrade head' step.",
                    "Add 'alembic upgrade head' to the deploy job so migrations run "
                    "automatically on release.",
                )
            )
    else:
        if "drizzle-kit push" not in combined and "drizzle-kit migrate" not in combined:
            findings.append(
                _finding(
                    "API-011",
                    "ERROR",
                    "structural_conformance",
                    "ci.yml has no 'drizzle-kit push' or 'drizzle-kit migrate' step.",
                    "Add a Drizzle migration step to the deploy job.",
                )
            )
    return findings


def check_auth_header_parity(repo_path: Path) -> list[Finding]:
    """AUTH-002: Auth header parity — shared library vs api.

    Evaluator-cog can't compare two repos at once. We check a lighter
    property: auth.py (if present) has a cross-reference comment to
    common-python-utils.
    """
    CHECK_ID = "AUTH-002"
    findings: list[Finding] = []
    src = repo_path / "src"
    if not src.is_dir():
        return findings
    # Find auth.py files
    auth_files = list(src.rglob("auth.py"))
    if not auth_files:
        return findings
    for auth_file in auth_files:
        try:
            text = auth_file.read_text()
        except Exception:
            continue
        if "common-python-utils" not in text and "common_python_utils" not in text:
            rel = auth_file.relative_to(repo_path)
            findings.append(
                _finding(
                    "AUTH-002",
                    "WARN",
                    "cross_repo_coherence",
                    f"{rel}: auth.py has no reference to common-python-utils.",
                    "Add a cross-reference comment noting the auth header parity with "
                    "CommonPythonApiClient.",
                )
            )
    return findings


def check_env_var_prefix(repo_path: Path) -> list[Finding]:
    """XSTACK-004: Client-exposed env vars use PUBLIC_ or VITE_ prefix."""
    CHECK_ID = "XSTACK-004"
    import re

    findings: list[Finding] = []
    src = repo_path / "src"
    if not src.is_dir():
        return findings

    # Detect repo flavor from presence of astro vs vite config
    has_astro = (repo_path / "astro.config.mjs").exists() or (
        repo_path / "astro.config.ts"
    ).exists()
    has_vite = (
        (repo_path / "vite.config.ts").exists()
        or (repo_path / "vite.config.js").exists()
        or (repo_path / "vite.config.mjs").exists()
    )

    expected_prefix = None
    wrong_prefix = None
    if has_astro:
        expected_prefix = "PUBLIC_"
        wrong_prefix = "VITE_"
    elif has_vite:
        expected_prefix = "VITE_"
        wrong_prefix = "PUBLIC_"
    else:
        return findings  # Not a frontend repo with client-side env vars

    env_re = re.compile(r"""import\.meta\.env\.(\w+)""")
    for f in (
        list(src.rglob("*.ts"))
        + list(src.rglob("*.tsx"))
        + list(src.rglob("*.astro"))
        + list(src.rglob("*.js"))
        + list(src.rglob("*.jsx"))
    ):
        try:
            text = f.read_text()
        except Exception:
            continue
        rel = f.relative_to(repo_path)
        for m in env_re.finditer(text):
            var = m.group(1)
            if var.startswith(wrong_prefix):
                findings.append(
                    _finding(
                        "XSTACK-004",
                        "WARN",
                        "structural_conformance",
                        f"{rel}: env var {var} uses {wrong_prefix} prefix in a repo expecting {expected_prefix}.",
                        f"Rename to {expected_prefix}{var[len(wrong_prefix) :]}.",
                    )
                )
    return findings


def check_logger_misuse(repo_path: Path) -> list[Finding]:
    """CD-008: logger.error not used for expected outcomes."""
    CHECK_ID = "CD-008"
    import re

    findings: list[Finding] = []
    src = repo_path / "src"
    if not src.is_dir():
        return findings

    noise_patterns = (
        r"not found",
        r"no files",
        r"skipping",
        r"already exists",
        r"no new items",
    )
    noise_re = re.compile("|".join(noise_patterns), re.IGNORECASE)
    error_call_re = re.compile(r"""logger\.error\s*\(\s*['"]([^'"]+)['"]""")
    for py_file in src.rglob("*.py"):
        try:
            text = py_file.read_text()
        except Exception:
            continue
        rel = py_file.relative_to(repo_path)
        for m in error_call_re.finditer(text):
            msg = m.group(1)
            if noise_re.search(msg):
                findings.append(
                    _finding(
                        "CD-008",
                        "WARN",
                        "structural_conformance",
                        f"{rel}: logger.error used for expected outcome: {msg!r}.",
                        "Downgrade to logger.warning or logger.info — errors should "
                        "indicate unexpected failures.",
                    )
                )
    return findings


def check_three_layer_observability(
    repo_path: Path,
    cog_subtype: str | None = None,
    language: str = "python",
) -> list[Finding]:
    """CD-010: Three-layer observability — Healthchecks + logger + Sentry.

    Language-aware: Python services must use sentry_sdk + common-python-utils;
    TypeScript services must use @sentry/node (or @sentry/react/@sentry/astro)
    + common-typescript-utils. The stack is equivalent; only the package
    names differ.
    """
    findings: list[Finding] = []
    src = repo_path / "src"
    env_example = repo_path / ".env.example"

    env_text = env_example.read_text() if env_example.exists() else ""
    src_text = ""
    if src.is_dir():
        exts = ("*.py",) if language == "python" else ("*.ts", "*.tsx", "*.astro")
        for ext in exts:
            for f in src.rglob(ext):
                try:
                    src_text += "\n" + f.read_text(errors="replace")
                except Exception:
                    continue

    package_json_text = ""
    package_json = repo_path / "package.json"
    if package_json.exists():
        with suppress(Exception):
            package_json_text = package_json.read_text()

    # Layer 1: Healthchecks — only required for worker-style services.
    if cog_subtype in ("pipeline", "trigger"):
        env_has_healthchecks = (
            "HEALTHCHECKS_URL" in env_text or "HEALTHCHECKS_URL_" in env_text
        )
        src_has_ping_signal = "healthchecks.io" in src_text.lower() or (
            "HEALTHCHECKS_URL" in src_text
        )
        if not (env_has_healthchecks and src_has_ping_signal):
            findings.append(
                _finding(
                    "CD-010",
                    "ERROR",
                    "structural_conformance",
                    "Layer 1 missing: no HEALTHCHECKS_URL env var or healthchecks.io ping in source.",
                    "Add HEALTHCHECKS_URL (or a per-service HEALTHCHECKS_URL_<NAME>) "
                    "to .env.example and reference it from the main loop to ping "
                    "healthchecks.io.",
                )
            )

    # Layer 2: structured logging via shared library.
    if language == "python":
        layer2_present = (
            "common_python_utils" in src_text or "mini_app_polis" in src_text
        )
        layer2_hint = (
            "Import the shared logger from common_python_utils "
            "(import package name: mini_app_polis) and use it throughout."
        )
    else:
        layer2_present = "common-typescript-utils" in src_text or (
            "common-typescript-utils" in package_json_text
        )
        layer2_hint = (
            "Import the shared logger from common-typescript-utils "
            "(createLogger) and use it throughout."
        )
    if not layer2_present:
        findings.append(
            _finding(
                "CD-010",
                "ERROR",
                "structural_conformance",
                "Layer 2 missing: no shared-library logger usage.",
                layer2_hint,
            )
        )

    # Layer 3: Sentry.
    if language == "python":
        layer3_present = "sentry_sdk" in src_text and (
            "SENTRY_DSN" in env_text or "SENTRY_DSN" in src_text
        )
        layer3_hint = (
            "Initialise sentry_sdk at entry point and add SENTRY_DSN "
            "(or a service-specific variant) to .env.example."
        )
    else:
        layer3_present = (
            "@sentry/node" in package_json_text
            or "@sentry/react" in package_json_text
            or "@sentry/astro" in package_json_text
        ) and ("SENTRY_DSN" in env_text or "SENTRY_DSN" in src_text)
        layer3_hint = (
            "Install @sentry/node (api) or @sentry/react/@sentry/astro (web), "
            "initialise it at entry point, and add SENTRY_DSN to .env.example."
        )
    if not layer3_present:
        findings.append(
            _finding(
                "CD-010",
                "ERROR",
                "structural_conformance",
                "Layer 3 missing: Sentry integration not detected.",
                layer3_hint,
            )
        )
    return findings


def check_cloudflare_pages_deploy(repo_path: Path) -> list[Finding]:
    """CD-014: Static site deployed via Cloudflare Pages."""
    CHECK_ID = "CD-014"
    findings: list[Finding] = []
    ci = repo_path / ".github" / "workflows" / "ci.yml"
    readme = repo_path / "README.md"

    ci_text = ci.read_text() if ci.exists() else ""
    readme_text = readme.read_text() if readme.exists() else ""

    has_cf_pages = (
        "cloudflare/pages-action" in ci_text
        or "wrangler pages" in ci_text
        or "pages.dev" in readme_text
        or "Cloudflare Pages" in readme_text
    )

    # Check for competing deploy targets
    has_netlify = (repo_path / "netlify.toml").exists()
    has_vercel = (repo_path / "vercel.json").exists()
    has_gh_pages = "gh-pages" in ci_text or "peaceiris/actions-gh-pages" in ci_text

    if has_netlify:
        findings.append(
            _finding(
                "CD-014",
                "WARN",
                "structural_conformance",
                "Static site has netlify.toml — expected Cloudflare Pages deployment.",
                "Remove netlify.toml and configure Cloudflare Pages deploy instead.",
            )
        )
    if has_vercel:
        findings.append(
            _finding(
                "CD-014",
                "WARN",
                "structural_conformance",
                "Static site has vercel.json — expected Cloudflare Pages deployment.",
                "Remove vercel.json and configure Cloudflare Pages deploy instead.",
            )
        )
    if has_gh_pages:
        findings.append(
            _finding(
                "CD-014",
                "WARN",
                "structural_conformance",
                "Static site uses GitHub Pages deploy — expected Cloudflare Pages.",
                "Switch to Cloudflare Pages deploy.",
            )
        )

    if not has_cf_pages and not (has_netlify or has_vercel or has_gh_pages):
        findings.append(
            _finding(
                "CD-014",
                "WARN",
                "structural_conformance",
                "No deployment target detected (no Cloudflare Pages markers in ci.yml or README).",
                "Document the Cloudflare Pages deploy in ci.yml or README.",
            )
        )
    return findings


def check_public_docstrings(repo_path: Path) -> list[Finding]:
    """DOC-006: Public functions/classes have docstrings."""
    CHECK_ID = "DOC-006"
    import ast

    findings: list[Finding] = []
    src = repo_path / "src"
    if not src.is_dir():
        return findings

    for py_file in src.rglob("*.py"):
        try:
            text = py_file.read_text()
            tree = ast.parse(text)
        except Exception:
            continue
        rel = py_file.relative_to(repo_path)
        for node in ast.walk(tree):
            if not isinstance(
                node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
            ):
                continue
            if node.name.startswith("_"):
                continue
            # Skip dunder methods
            if node.name.startswith("__") and node.name.endswith("__"):
                continue
            if ast.get_docstring(node):
                continue
            findings.append(
                _finding(
                    "DOC-006",
                    "WARN",
                    "documentation_coverage",
                    f"{rel}::{node.name}: public {type(node).__name__.replace('Def', '').lower()} missing docstring.",
                    "Add a docstring explaining the purpose and usage.",
                )
            )
    return findings


def check_pydantic_field_descriptions(repo_path: Path) -> list[Finding]:
    """DOC-007: Pydantic fields use Field(description=...)."""
    CHECK_ID = "DOC-007"
    import ast

    findings: list[Finding] = []
    src = repo_path / "src"
    if not src.is_dir():
        return findings

    for py_file in src.rglob("*.py"):
        try:
            text = py_file.read_text()
            tree = ast.parse(text)
        except Exception:
            continue
        rel = py_file.relative_to(repo_path)
        for node in ast.walk(tree):
            if not isinstance(node, ast.ClassDef):
                continue
            base_names = []
            for b in node.bases:
                if isinstance(b, ast.Name):
                    base_names.append(b.id)
                elif isinstance(b, ast.Attribute):
                    base_names.append(b.attr)
            if "BaseModel" not in base_names:
                continue
            for stmt in node.body:
                if not isinstance(stmt, ast.AnnAssign):
                    continue
                if not isinstance(stmt.target, ast.Name):
                    continue
                fname = stmt.target.id
                if fname.startswith("_"):
                    continue
                # Check if value is Field(... description=...)
                has_description = False
                if (
                    stmt.value
                    and isinstance(stmt.value, ast.Call)
                    and (
                        isinstance(stmt.value.func, ast.Name)
                        and stmt.value.func.id == "Field"
                    )
                ):
                    has_description = any(
                        kw.arg == "description" for kw in stmt.value.keywords
                    )
                if not has_description:
                    findings.append(
                        _finding(
                            "DOC-007",
                            "WARN",
                            "documentation_coverage",
                            f"{rel}::{node.name}.{fname}: Pydantic field missing Field(description=...).",
                            "Wrap the field with Field(description='...') for OpenAPI docs.",
                        )
                    )
    return findings


def check_fastapi_route_docs(repo_path: Path) -> list[Finding]:
    """DOC-010: FastAPI route decorators have summary=, description=, response_model=."""
    CHECK_ID = "DOC-010"
    import ast

    findings: list[Finding] = []
    src = repo_path / "src"
    if not src.is_dir():
        return findings

    route_attrs = {"get", "post", "put", "delete", "patch"}
    required = ("summary", "description", "response_model")

    for py_file in src.rglob("*.py"):
        try:
            text = py_file.read_text()
            tree = ast.parse(text)
        except Exception:
            continue
        rel = py_file.relative_to(repo_path)
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for dec in node.decorator_list:
                if not isinstance(dec, ast.Call):
                    continue
                if not isinstance(dec.func, ast.Attribute):
                    continue
                if dec.func.attr not in route_attrs:
                    continue
                kwargs = {kw.arg for kw in dec.keywords}
                missing = [r for r in required if r not in kwargs]
                if missing:
                    findings.append(
                        _finding(
                            "DOC-010",
                            "ERROR",
                            "documentation_coverage",
                            f"{rel}::{node.name}: route decorator missing: {', '.join(missing)}.",
                            "Add all three (summary, description, response_model) to the "
                            "route decorator for complete OpenAPI docs.",
                        )
                    )
    return findings


def check_unauthenticated_routes_documented(repo_path: Path) -> list[Finding]:
    """DOC-011: Unauthenticated routes document their intent."""
    CHECK_ID = "DOC-011"
    import ast

    findings: list[Finding] = []
    src = repo_path / "src"
    if not src.is_dir():
        return findings

    route_attrs = {"get", "post", "put", "delete", "patch"}
    exempt_paths = ("/health", "/metrics", "/docs", "/openapi.json", "/redoc")
    public_markers = (
        "intentionally public",
        "no auth required",
        "read-only public",
        "public endpoint",
    )

    for py_file in src.rglob("*.py"):
        try:
            text = py_file.read_text()
            tree = ast.parse(text)
        except Exception:
            continue
        rel = py_file.relative_to(repo_path)
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            route_path: str | None = None
            description: str | None = None
            for dec in node.decorator_list:
                if not isinstance(dec, ast.Call):
                    continue
                if not isinstance(dec.func, ast.Attribute):
                    continue
                if dec.func.attr not in route_attrs:
                    continue
                if (
                    dec.args
                    and isinstance(dec.args[0], ast.Constant)
                    and isinstance(dec.args[0].value, str)
                ):
                    route_path = dec.args[0].value
                for kw in dec.keywords:
                    if (
                        kw.arg == "description"
                        and isinstance(kw.value, ast.Constant)
                        and isinstance(kw.value.value, str)
                    ):
                        description = kw.value.value
            if route_path is None:
                continue
            if any(route_path.startswith(p) for p in exempt_paths):
                continue
            # Has auth?
            has_depends = False
            for arg_default in node.args.defaults + node.args.kw_defaults:
                if arg_default is None:
                    continue
                if (
                    isinstance(arg_default, ast.Call)
                    and isinstance(arg_default.func, ast.Name)
                    and arg_default.func.id == "Depends"
                ):
                    has_depends = True
                    break
            if has_depends:
                continue
            # No auth — must have public-intent marker in description or docstring
            ds = ast.get_docstring(node) or ""
            combined = (description or "") + " " + ds
            if not any(marker in combined.lower() for marker in public_markers):
                findings.append(
                    _finding(
                        "DOC-011",
                        "WARN",
                        "documentation_coverage",
                        f"{rel}::{node.name}: unauthenticated route {route_path!r} lacks public-intent marker.",
                        "Add 'intentionally public' or 'no auth required' to the route "
                        "description or docstring.",
                    )
                )
    return findings


def check_fetch_error_handling(repo_path: Path) -> list[Finding]:
    """FE-006: Astro fetch calls wrapped in try/catch with fallback."""
    CHECK_ID = "FE-006"
    import re

    findings: list[Finding] = []
    src = repo_path / "src"
    if not src.is_dir():
        return findings

    for astro_file in src.rglob("*.astro"):
        try:
            text = astro_file.read_text()
        except Exception:
            continue
        # Extract frontmatter
        m = re.match(r"^---\s*\n(.*?)\n---", text, re.DOTALL)
        if not m:
            continue
        fm = m.group(1)
        if "fetch(" not in fm:
            continue
        # Crude heuristic: the frontmatter should contain `try` and `catch`
        # somewhere around the fetch call.
        if "try" not in fm or "catch" not in fm:
            rel = astro_file.relative_to(repo_path)
            findings.append(
                _finding(
                    "FE-006",
                    "ERROR",
                    "structural_conformance",
                    f"{rel}: frontmatter fetch() without try/catch error handling.",
                    "Wrap fetch calls in try/catch with a fallback value so build "
                    "succeeds when the API is unavailable.",
                )
            )
    return findings


def check_shared_resource_concurrency(repo_path: Path) -> list[Finding]:
    """PIPE-004: Flows writing shared resources use concurrency guards."""
    CHECK_ID = "PIPE-004"
    import ast

    findings: list[Finding] = []
    src = repo_path / "src"
    if not src.is_dir():
        return findings

    for py_file in src.rglob("*.py"):
        try:
            text = py_file.read_text()
            tree = ast.parse(text)
        except Exception:
            continue
        rel = py_file.relative_to(repo_path)
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            is_flow = any(
                (isinstance(d, ast.Name) and d.id == "flow")
                or (
                    isinstance(d, ast.Call)
                    and isinstance(d.func, ast.Name)
                    and d.func.id == "flow"
                )
                or (isinstance(d, ast.Attribute) and d.attr == "flow")
                for d in node.decorator_list
            )
            if not is_flow:
                continue
            body_src = ast.unparse(node)
            writes_shared_resource = any(
                m in body_src
                for m in [
                    "session.commit()",
                    "session.add(",
                    "drive_service.files().move",
                    "drive_service.files().update",
                    ".post(",
                    ".patch(",
                ]
            )
            if not writes_shared_resource:
                continue
            has_concurrency_param = False
            for d in node.decorator_list:
                if isinstance(d, ast.Call):
                    for kw in d.keywords:
                        if kw.arg == "concurrency_limit":
                            has_concurrency_param = True
            has_concurrency_block = (
                "with concurrency(" in body_src or "concurrency.sync" in body_src
            )
            if not (has_concurrency_param or has_concurrency_block):
                findings.append(
                    _finding(
                        "PIPE-004",
                        "ERROR",
                        "pipeline_consistency",
                        f"{rel}::{node.name}: flow writes to shared resource without concurrency guard.",
                        "Add concurrency_limit= on the @flow decorator, or wrap the write "
                        "block with a 'with concurrency(...)' slot from prefect.concurrency.sync.",
                    )
                )
    return findings


def check_prefect_run_logger(repo_path: Path) -> list[Finding]:
    """PIPE-006: Prefect flows use get_run_logger() with fallback.

    Accepts two equivalent patterns:

      1. Direct: the flow body calls get_run_logger() itself.
      2. Wrapper: the flow body calls a function whose name contains
         'logger' and whose body (defined in this repo) calls
         get_run_logger().

    The wrapper pattern is common — it centralizes the
    fallback-to-stdlib behavior in one place.
    """
    import ast

    findings: list[Finding] = []
    src = repo_path / "src"
    if not src.is_dir():
        return findings

    # First pass: collect repo-local logger-wrapper functions —
    # functions whose name contains "logger" and whose body calls
    # get_run_logger.
    wrapper_names: set[str] = set()
    for py_file in src.rglob("*.py"):
        try:
            text = py_file.read_text()
            tree = ast.parse(text)
        except Exception:
            continue
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            if "logger" not in node.name.lower():
                continue
            try:
                body_src = ast.unparse(node)
            except Exception:
                continue
            if "get_run_logger" in body_src:
                wrapper_names.add(node.name)

    # Second pass: check each @flow-decorated function.
    for py_file in src.rglob("*.py"):
        try:
            text = py_file.read_text()
            tree = ast.parse(text)
        except Exception:
            continue
        rel = py_file.relative_to(repo_path)
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            is_flow = any(
                (isinstance(d, ast.Name) and d.id == "flow")
                or (
                    isinstance(d, ast.Call)
                    and isinstance(d.func, ast.Name)
                    and d.func.id == "flow"
                )
                or (isinstance(d, ast.Attribute) and d.attr == "flow")
                for d in node.decorator_list
            )
            if not is_flow:
                continue
            try:
                body_src = ast.unparse(node)
            except Exception:
                continue
            if "get_run_logger" in body_src:
                continue
            if any(name in body_src for name in wrapper_names):
                continue
            findings.append(
                _finding(
                    "PIPE-006",
                    "WARN",
                    "pipeline_consistency",
                    f"{rel}::{node.name}: flow does not call get_run_logger() "
                    f"(directly or via a logger-wrapper defined in this repo).",
                    "Use get_run_logger() inside flows for Prefect-integrated logging; "
                    "fall back to stdlib logging outside Prefect context. A wrapper "
                    "whose name contains 'logger' and which internally calls "
                    "get_run_logger() is also accepted.",
                )
            )
    return findings


def check_final_evaluation_task(
    repo_path: Path, cog_subtype: str | None = None
) -> list[Finding]:
    """PIPE-011: Pipeline cogs end with an AI evaluation task.

    Exempt: trigger-cogs (they fire flow runs, don't run pipelines),
    and evaluator-cog itself.
    """
    CHECK_ID = "PIPE-011"
    findings: list[Finding] = []
    if cog_subtype == "trigger":
        return findings
    # Check if this is evaluator-cog itself
    if (repo_path / "src" / "evaluator_cog").is_dir():
        return findings
    src = repo_path / "src"
    if not src.is_dir():
        return findings

    evaluation_markers = (
        "pipeline_eval",
        "evaluation_client",
        "/v1/evaluations",
        "/v1/pipeline_evaluations",
        "PipelineEvaluator",
    )
    found_marker = False
    for py_file in src.rglob("*.py"):
        try:
            text = py_file.read_text()
        except Exception:
            continue
        if any(m in text for m in evaluation_markers):
            found_marker = True
            break
    if not found_marker:
        findings.append(
            _finding(
                "PIPE-011",
                "WARN",
                "pipeline_consistency",
                "No AI evaluation task found in pipeline-cog source.",
                "Add a final task that writes to pipeline_evaluations (via the evaluation "
                "client from common-python-utils) so quality can be tracked.",
            )
        )
    return findings


def check_hardcoded_retry_delay(repo_path: Path) -> list[Finding]:
    """PIPE-012: retry_delay_seconds not hardcoded to non-zero."""
    CHECK_ID = "PIPE-012"
    import ast

    findings: list[Finding] = []
    src = repo_path / "src"
    if not src.is_dir():
        return findings

    for py_file in src.rglob("*.py"):
        try:
            text = py_file.read_text()
            tree = ast.parse(text)
        except Exception:
            continue
        rel = py_file.relative_to(repo_path)
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            for kw in node.keywords:
                if kw.arg != "retry_delay_seconds":
                    continue
                # Must be a hardcoded non-zero numeric literal
                if (
                    isinstance(kw.value, ast.Constant)
                    and isinstance(kw.value.value, (int, float))
                    and kw.value.value != 0
                ):
                    # Check for PYTEST_CURRENT_TEST guard nearby
                    py_text = py_file.read_text()
                    if "PYTEST_CURRENT_TEST" not in py_text:
                        findings.append(
                            _finding(
                                "PIPE-012",
                                "WARN",
                                "pipeline_consistency",
                                f"{rel}: retry_delay_seconds={kw.value.value} hardcoded without PYTEST_CURRENT_TEST guard.",
                                "Source from Settings field or wrap with os.getenv('PYTEST_CURRENT_TEST') "
                                "conditional so tests don't sleep.",
                            )
                        )
    return findings


def check_pydantic_for_external_data(repo_path: Path) -> list[Finding]:
    """PY-004: External data goes through Pydantic.

    Heuristic: flag files that access response.json() or csv.DictReader
    results directly without defining a BaseModel subclass.
    """
    CHECK_ID = "PY-004"
    import re

    findings: list[Finding] = []
    src = repo_path / "src"
    if not src.is_dir():
        return findings

    suspect_patterns = (
        r"\.json\(\)\[",  # response.json()["..."]
        r"csv\.DictReader",
        r"csv\.reader",
    )
    suspect_re = re.compile("|".join(suspect_patterns))
    for py_file in src.rglob("*.py"):
        try:
            text = py_file.read_text()
        except Exception:
            continue
        rel = py_file.relative_to(repo_path)
        if suspect_re.search(text) and "BaseModel" not in text:
            findings.append(
                _finding(
                    "PY-004",
                    "WARN",
                    "structural_conformance",
                    f"{rel}: accesses external data (JSON/CSV) without a Pydantic BaseModel.",
                    "Define a Pydantic model and validate external payloads through it.",
                )
            )
    return findings


def check_async_sqlalchemy(repo_path: Path) -> list[Finding]:
    """PY-015: SQLAlchemy uses async API."""
    CHECK_ID = "PY-015"
    findings: list[Finding] = []
    pyproject = repo_path / "pyproject.toml"
    pyp_text = pyproject.read_text() if pyproject.exists() else ""

    src = repo_path / "src"
    if not src.is_dir():
        return findings

    src_text = ""
    for py_file in src.rglob("*.py"):
        try:
            src_text += "\n" + py_file.read_text()
        except Exception:
            continue

    if "sqlalchemy" not in src_text.lower() and "sqlalchemy" not in pyp_text.lower():
        return findings  # Not a SQLAlchemy repo

    # Flag sync imports
    if (
        (
            "from sqlalchemy.orm import Session" in src_text
            or "from sqlalchemy.orm import sessionmaker" in src_text
        )
        and "AsyncSession" not in src_text
        and "async_sessionmaker" not in src_text
    ):
        findings.append(
            _finding(
                "PY-015",
                "ERROR",
                "structural_conformance",
                "Sync Session/sessionmaker imported without AsyncSession/async_sessionmaker counterpart.",
                "Use AsyncSession and async_sessionmaker from sqlalchemy.ext.asyncio.",
            )
        )
    # Flag sync create_engine
    if "create_engine(" in src_text and "create_async_engine(" not in src_text:
        findings.append(
            _finding(
                "PY-015",
                "ERROR",
                "structural_conformance",
                "Sync create_engine() used without create_async_engine() counterpart.",
                "Use create_async_engine from sqlalchemy.ext.asyncio.",
            )
        )
    # asyncpg required when sqlalchemy is present
    if "sqlalchemy" in pyp_text.lower() and "asyncpg" not in pyp_text.lower():
        findings.append(
            _finding(
                "PY-015",
                "ERROR",
                "structural_conformance",
                "sqlalchemy declared without asyncpg in pyproject.toml.",
                "Add asyncpg to dependencies for async PostgreSQL.",
            )
        )
    return findings


def check_settings_field_consistency(repo_path: Path) -> list[Finding]:
    """CFG-001: getattr(settings, X) / settings.X keys declared on Settings."""
    CHECK_ID = "CFG-001"
    import ast

    findings: list[Finding] = []
    src = repo_path / "src"
    if not src.is_dir():
        return findings

    declared_fields: set[str] = set()
    # First pass: collect fields on any Settings class
    for py_file in src.rglob("*.py"):
        try:
            text = py_file.read_text()
            tree = ast.parse(text)
        except Exception:
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.ClassDef):
                continue
            if not (node.name == "Settings" or node.name.endswith("Settings")):
                continue
            for stmt in node.body:
                if isinstance(stmt, ast.AnnAssign) and isinstance(
                    stmt.target, ast.Name
                ):
                    declared_fields.add(stmt.target.id)
                elif isinstance(stmt, ast.Assign):
                    for t in stmt.targets:
                        if isinstance(t, ast.Name):
                            declared_fields.add(t.id)

    if not declared_fields:
        return findings  # No Settings class; rule doesn't apply here

    # Second pass: find getattr(settings, "X") calls and settings.X access
    for py_file in src.rglob("*.py"):
        try:
            text = py_file.read_text()
            tree = ast.parse(text)
        except Exception:
            continue
        rel = py_file.relative_to(repo_path)
        for node in ast.walk(tree):
            # getattr(settings, "X")
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id == "getattr"
                and len(node.args) >= 2
                and isinstance(node.args[0], ast.Name)
                and node.args[0].id == "settings"
                and isinstance(node.args[1], ast.Constant)
                and isinstance(node.args[1].value, str)
            ):
                key = node.args[1].value
                if key not in declared_fields:
                    findings.append(
                        _finding(
                            "CFG-001",
                            "WARN",
                            "configuration_consistency",
                            f"{rel}: getattr(settings, {key!r}) but {key} not declared on Settings.",
                            "Declare the field on Settings or remove the access.",
                        )
                    )
            # settings.KEY
            if (
                isinstance(node, ast.Attribute)
                and isinstance(node.value, ast.Name)
                and node.value.id == "settings"
                and node.attr not in declared_fields
                and not node.attr.startswith("_")
            ):
                findings.append(
                    _finding(
                        "CFG-001",
                        "WARN",
                        "configuration_consistency",
                        f"{rel}: settings.{node.attr} access but not declared on Settings.",
                        "Declare the field on Settings or remove the access.",
                    )
                )
    return findings


def check_env_example_settings_parity(repo_path: Path) -> list[Finding]:
    """CFG-002: .env.example keys match Settings declared fields."""
    CHECK_ID = "CFG-002"
    import ast

    findings: list[Finding] = []
    env_example = repo_path / ".env.example"
    if not env_example.exists():
        return findings
    src = repo_path / "src"
    if not src.is_dir():
        return findings

    declared_fields: set[str] = set()
    for py_file in src.rglob("*.py"):
        try:
            text = py_file.read_text()
            tree = ast.parse(text)
        except Exception:
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.ClassDef):
                continue
            if not (node.name == "Settings" or node.name.endswith("Settings")):
                continue
            for stmt in node.body:
                if isinstance(stmt, ast.AnnAssign) and isinstance(
                    stmt.target, ast.Name
                ):
                    declared_fields.add(stmt.target.id)

    if not declared_fields:
        return findings

    env_text = env_example.read_text()
    lines = env_text.splitlines()
    prev_is_external_marker = False
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("#"):
            # Check if this comment marks the next key as external tooling
            if "external" in stripped.lower() or "tooling" in stripped.lower():
                prev_is_external_marker = True
            continue
        if not stripped or "=" not in stripped:
            prev_is_external_marker = False
            continue
        key = stripped.split("=", 1)[0].strip()
        # Uppercase env vars correspond to Settings fields case-insensitively
        if key in declared_fields or key.upper() in (
            f.upper() for f in declared_fields
        ):
            prev_is_external_marker = False
            continue
        if prev_is_external_marker:
            prev_is_external_marker = False
            continue
        findings.append(
            _finding(
                "CFG-002",
                "WARN",
                "configuration_consistency",
                f".env.example key {key!r} not declared on Settings.",
                "Declare the field on Settings or mark the key with a comment noting "
                "'external tooling'.",
            )
        )
    return findings


def check_hardcoded_time_values(
    repo_path: Path, language: str = "python"
) -> list[Finding]:
    """TEST-013: No hardcoded numeric sleeps/timeouts/delays."""
    CHECK_ID = "TEST-013"
    import re

    findings: list[Finding] = []
    src = repo_path / "src"
    if not src.is_dir():
        return findings

    if language == "python":
        patterns = [
            re.compile(r"time\.sleep\(\s*(\d+(?:\.\d+)?)\s*\)"),
            re.compile(r"retry_delay_seconds\s*=\s*(\d+)"),
            re.compile(r"\btimeout\s*=\s*(\d+)"),
        ]
        exts = ("*.py",)
    else:
        patterns = [
            re.compile(r"setTimeout\(\s*\w+\s*,\s*(\d+)"),
            re.compile(r"setInterval\(\s*\w+\s*,\s*(\d+)"),
        ]
        exts = ("*.ts", "*.tsx")

    # UI contexts where setTimeout/setInterval values are visual design
    # choices (animation delays, toast timing, progress-bar completion
    # effects), not production retry/timeout values.
    _ui_path_markers = ("/pages/", "/components/", "/layouts/", "/views/")

    for ext in exts:
        for f in src.rglob(ext):
            if language != "python":
                path_str = str(f).replace("\\", "/")
                if f.suffix == ".tsx" or any(m in path_str for m in _ui_path_markers):
                    continue
            try:
                text = f.read_text()
            except Exception:
                continue
            rel = f.relative_to(repo_path)
            for pat in patterns:
                for m in pat.finditer(text):
                    val = m.group(1)
                    if val == "0":
                        continue
                    # Skip if guarded by env/settings — we check if the line
                    # has "os.getenv", "settings.", or "process.env" nearby.
                    start = max(0, m.start() - 200)
                    context = text[start : m.end()]
                    if (
                        "os.getenv" in context
                        or "settings." in context
                        or "process.env" in context
                        or "PYTEST_CURRENT_TEST" in text
                    ):
                        continue
                    findings.append(
                        _finding(
                            "TEST-013",
                            "INFO",
                            "principles",
                            f"{rel}: hardcoded numeric value {val} in time/retry/timeout call.",
                            "Source from Settings or env var so tests can override with 0.",
                        )
                    )
                    break  # One finding per file is enough
    return findings


def check_testclient_for_v1_routes(repo_path: Path) -> list[Finding]:
    """TEST-008: /v1/ route tests use TestClient or AsyncClient."""
    CHECK_ID = "TEST-008"
    import re

    findings: list[Finding] = []
    tests_dir = repo_path / "tests"
    if not tests_dir.is_dir():
        return findings

    for test_file in tests_dir.rglob("test_*.py"):
        try:
            text = test_file.read_text()
        except Exception:
            continue
        # Skip if file uses TestClient/AsyncClient
        if "TestClient" in text or "AsyncClient" in text:
            continue
        # Look for test functions referencing /v1/
        for m in re.finditer(r"def (test_\w+)\([^)]*\):([\s\S]*?)(?=\ndef |\Z)", text):
            fn_name, body = m.group(1), m.group(2)
            if "/v1/" in body:
                rel = test_file.relative_to(repo_path)
                findings.append(
                    _finding(
                        "TEST-008",
                        "WARN",
                        "test_coverage",
                        f"{rel}::{fn_name}: references /v1/ without TestClient/AsyncClient.",
                        "Use fastapi.testclient.TestClient or httpx.AsyncClient for route tests.",
                    )
                )
    return findings


def check_db_test_fixtures(repo_path: Path) -> list[Finding]:
    """TEST-009: conftest has DB test fixtures."""
    CHECK_ID = "TEST-009"
    findings: list[Finding] = []
    src = repo_path / "src"
    tests = repo_path / "tests"
    if not src.is_dir() or not tests.is_dir():
        return findings

    # Is this a SQLAlchemy repo?
    has_sqlalchemy = False
    for py_file in src.rglob("*.py"):
        try:
            if "sqlalchemy" in py_file.read_text().lower():
                has_sqlalchemy = True
                break
        except Exception:
            continue
    if not has_sqlalchemy:
        return findings

    conftest_files = list(tests.rglob("conftest.py"))
    if not conftest_files:
        findings.append(
            _finding(
                "TEST-009",
                "ERROR",
                "test_coverage",
                "SQLAlchemy repo has no conftest.py with DB test fixtures.",
                "Add a conftest.py with DATABASE_URL override, in-memory engine, or "
                "transaction rollback fixture.",
            )
        )
        return findings

    combined = "\n".join(f.read_text() for f in conftest_files if f.exists())
    has_fixture_pattern = (
        "DATABASE_URL" in combined
        or "sqlite:///:memory:" in combined
        or ("rollback" in combined.lower() and "fixture" in combined.lower())
    )
    if not has_fixture_pattern:
        findings.append(
            _finding(
                "TEST-009",
                "ERROR",
                "test_coverage",
                "conftest.py has no DB test fixture pattern (DATABASE_URL override, in-memory SQLite, or rollback fixture).",
                "Add one of: DATABASE_URL override, in-memory SQLite engine, or rollback fixture.",
            )
        )
    return findings


def check_route_contract_tests(repo_path: Path) -> list[Finding]:
    """TEST-010: Each FastAPI route has a contract test."""
    CHECK_ID = "TEST-010"
    import ast

    findings: list[Finding] = []
    src = repo_path / "src"
    tests = repo_path / "tests"
    if not src.is_dir() or not tests.is_dir():
        return findings

    route_paths: set[str] = set()
    route_attrs = {"get", "post", "put", "delete", "patch"}
    for py_file in src.rglob("*.py"):
        try:
            text = py_file.read_text()
            tree = ast.parse(text)
        except Exception:
            continue
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for dec in node.decorator_list:
                if not isinstance(dec, ast.Call):
                    continue
                if not isinstance(dec.func, ast.Attribute):
                    continue
                if dec.func.attr not in route_attrs:
                    continue
                if (
                    dec.args
                    and isinstance(dec.args[0], ast.Constant)
                    and isinstance(dec.args[0].value, str)
                ):
                    route_paths.add(dec.args[0].value)

    if not route_paths:
        return findings

    test_text = ""
    for test_file in tests.rglob("test_*.py"):
        try:
            test_text += "\n" + test_file.read_text()
        except Exception:
            continue

    untested = [r for r in route_paths if r not in test_text]
    if untested:
        sample = ", ".join(sorted(untested)[:5])
        suffix = " (and others)" if len(untested) > 5 else ""
        findings.append(
            _finding(
                "TEST-010",
                "ERROR",
                "test_coverage",
                f"{len(untested)} route(s) have no contract test referencing them: {sample}{suffix}.",
                "Add tests that exercise each /v1/ route and assert the response shape.",
            )
        )
    return findings


def check_mock_assertions(repo_path: Path) -> list[Finding]:
    """TEST-011: Mocks have corresponding assertions.

    Accepts multiple valid verification patterns:

    1. Direct mock-API verification — ``assert_called`` / ``assert_any_call`` /
       ``assert_not_called`` / ``assert_called_with`` / ``assert_called_once`` /
       ``assert_called_once_with``, plus reads of ``.call_count`` / ``.call_args`` /
       ``.call_args_list`` / ``.called``.

    2. Capture-list verification — a local ``name: list = []`` (or ``name = []``)
       bound inside the test body, then referenced in any ``assert`` statement.
       This covers the common pytest idiom where the mock hands off to a closure
       that appends to the list, and the test asserts on the list afterward.

    3. Behavior-injection verification — ``patch(..., return_value=X)`` or
       ``patch(..., side_effect=X)`` configures the mock as plumbing for the
       real thing under test. The test verifies the real thing's output with
       any ``assert`` statement, not the mock itself.

    A test that creates a mock but has zero assertions in its body is still
    flagged.

    Excludes tests that call ``check_mock_assertions`` in their body — those
    tests exercise this check by feeding it fixture source, so flagging them
    is circular.

    Uses AST parsing so that ``def test_X():`` text appearing inside string
    literals is not mistaken for a real test function. Function bodies are
    extracted by line slicing rather than ast.get_source_segment — the latter
    is ~5x slower because it re-computes source positions per call.
    """
    findings: list[Finding] = []
    tests = repo_path / "tests"
    if not tests.is_dir():
        return findings

    _assert_prefix = chr(97) + "ssert_"
    _mock_verify_patterns = (
        rf"\.{_assert_prefix}called\b",
        rf"\.{_assert_prefix}any_call\b",
        rf"\.{_assert_prefix}not_called\b",
        rf"\.{_assert_prefix}called_with\b",
        rf"\.{_assert_prefix}called_once\b",
        rf"\.{_assert_prefix}called_once_with\b",
        r"\.call_count\b",
        r"\.call_args\b",
        r"\.call_args_list\b",
        r"\.called\b",
    )
    _mock_verify_re = re.compile("|".join(_mock_verify_patterns))
    _mock_create_re = re.compile(r"\b(MagicMock|AsyncMock|patch|mock_\w+)\b")

    # A local list binding: `name = []`, `name: Type = []`, or `name = list()`.
    _empty_list_bind_re = re.compile(
        r"^\s*(\w+)\s*(?::\s*[^=]+)?=\s*(?:\[\s*\]|list\(\s*\))\s*$",
        re.MULTILINE,
    )

    # `patch(..., return_value=X)` or `patch(..., side_effect=X)` — behavior
    # injection. These mocks are plumbing; we don't require verifying them.
    _patch_behavior_injection_re = re.compile(
        r"\bpatch[.\w]*\([^)]*\b(return_value|side_effect)\s*=",
        re.DOTALL,
    )

    # Catch MagicMock(..., side_effect=...) / MagicMock(..., return_value=...)
    # which is the same behavior-injection idiom outside of `patch()`.
    _mock_ctor_behavior_injection_re = re.compile(
        r"\b(?:MagicMock|AsyncMock)\([^)]*\b(?:return_value|side_effect)\s*=",
        re.DOTALL,
    )

    # Any explicit `assert ...` statement (not assertRaises / not assert_xxx).
    _has_assert_re = re.compile(r"^\s*assert\b", re.MULTILINE)

    # Self-reference: test body invokes the function under test.
    _self_reference_re = re.compile(r"\bcheck_mock_assertions\b")

    def _has_capture_list_assertion(body_src: str) -> bool:
        names = {m.group(1) for m in _empty_list_bind_re.finditer(body_src)}
        if not names:
            return False
        for name in names:
            # Any `assert ...` statement that references the captured
            # list name counts as verification, whether via len(), indexing,
            # membership, comparison, or iteration in a comprehension.
            pat = rf"\bassert\b[^\n]*\b{re.escape(name)}\b"
            if re.search(pat, body_src):
                return True
        return False

    def _is_behavior_injection_with_assertion(body_src: str) -> bool:
        """Patches with return_value/side_effect are plumbing; any assert counts."""
        injects = _patch_behavior_injection_re.search(
            body_src
        ) or _mock_ctor_behavior_injection_re.search(body_src)
        if not injects:
            return False
        return bool(_has_assert_re.search(body_src))

    for test_file in tests.rglob("test_*.py"):
        try:
            text = test_file.read_text()
        except Exception:
            continue
        try:
            tree = ast.parse(text)
        except SyntaxError:
            continue
        lines = text.splitlines()
        rel = test_file.relative_to(repo_path)

        test_fns: list[ast.FunctionDef | ast.AsyncFunctionDef] = []
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if node.name.startswith("test_"):
                    test_fns.append(node)
            elif isinstance(node, ast.ClassDef):
                for inner in node.body:
                    if isinstance(inner, (ast.FunctionDef, ast.AsyncFunctionDef)) and (
                        inner.name.startswith("test_")
                    ):
                        test_fns.append(inner)

        for fn in test_fns:
            start = (fn.lineno or 1) - 1
            for dec in fn.decorator_list:
                ln = getattr(dec, "lineno", None)
                if isinstance(ln, int) and ln > 0:
                    start = min(start, ln - 1)
            end = fn.end_lineno or len(lines)
            body_src = "\n".join(lines[start:end])
            if not body_src:
                continue
            if not _mock_create_re.search(body_src):
                continue
            if _self_reference_re.search(body_src):
                continue
            if _mock_verify_re.search(body_src):
                continue
            if _has_capture_list_assertion(body_src):
                continue
            if _is_behavior_injection_with_assertion(body_src):
                continue
            findings.append(
                _finding(
                    "TEST-011",
                    "ERROR",
                    "test_coverage",
                    f"{rel}::{fn.name}: creates mocks but has no verification "
                    f"(mock-API helpers like called / call_args, capture-list "
                    f"assertion, or behavior-injection with at least one "
                    f"assert statement).",
                    "Verify the mock was exercised using unittest.mock's standard "
                    "verification APIs, assert against a capture list populated "
                    "by the mocked callable, or include at least one assert on "
                    "the code under test when the mock is used only for "
                    "return_value / side_effect behavior injection.",
                )
            )
    return findings


def check_test_gap_critical_paths(repo_path: Path) -> list[Finding]:
    """TEST-GAP-001: Track presence of TEST-001..004 critical-path tests."""
    CHECK_ID = "TEST-GAP-001"
    findings: list[Finding] = []
    tests = repo_path / "tests"
    if not tests.is_dir():
        return findings

    test_text = ""
    for test_file in tests.rglob("test_*.py"):
        try:
            test_text += "\n" + test_file.read_text()
        except Exception:
            continue

    # Heuristic markers for each critical-path category
    critical_markers = {
        "TEST-001 (normalization)": ("normalize", "normalise", "normalization"),
        "TEST-002 (deduplication)": ("dedup", "deduplication"),
        "TEST-003 (persistence)": ("persist", "upsert", "session.commit"),
        "TEST-004 (archival)": ("archive", "archival", "move"),
    }
    missing = []
    for label, markers in critical_markers.items():
        if not any(m in test_text.lower() for m in markers):
            missing.append(label)

    if missing:
        findings.append(
            _finding(
                "TEST-GAP-001",
                "INFO",
                "test_coverage",
                f"Missing critical-path tests: {', '.join(missing)}.",
                "Add tests for the missing categories so each pipeline stage has coverage.",
            )
        )
    return findings


def check_retry_logic(repo_path: Path) -> list[Finding]:
    """PIPE-007: Retry logic on external API calls."""
    CHECK_ID = "PIPE-007"
    import ast

    findings = []
    src = repo_path / "src"
    if not src.is_dir():
        return findings

    for py_file in src.rglob("*.py"):
        text = py_file.read_text()
        if "DriveFacade" in text or "LLMClient" in text:
            continue
        try:
            tree = ast.parse(text)
        except Exception:
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.FunctionDef):
                continue
            task_decorator = None
            for dec in node.decorator_list:
                if (isinstance(dec, ast.Name) and dec.id == "task") or (
                    isinstance(dec, ast.Call)
                    and (
                        (isinstance(dec.func, ast.Name) and dec.func.id == "task")
                        or (
                            isinstance(dec.func, ast.Attribute)
                            and dec.func.attr == "task"
                        )
                    )
                ):
                    task_decorator = dec
            if task_decorator is None:
                continue

            body_text = ast.get_source_segment(text, node) or ""
            external_signal = any(
                s in body_text for s in ("httpx.", "anthropic", "drive", "sheets")
            )
            if not external_signal:
                continue

            has_retries = isinstance(task_decorator, ast.Call) and any(
                kw.arg == "retries" for kw in task_decorator.keywords
            )
            if not has_retries:
                findings.append(
                    _finding(
                        "PIPE-007",
                        "WARN",
                        "pipeline_consistency",
                        f"External-calling task missing retries= in {py_file.relative_to(repo_path)}::{node.name}.",
                        "Add retries= to @task decorators that call external APIs.",
                    )
                )
    return findings


def check_no_retired_trigger_patterns(repo_path: Path) -> list[Finding]:
    """PIPE-008: Narrowed retired GitHub / GAS / gh CLI trigger patterns (2026-04).

    Fires only when: (1) a workflow uses ``repository_dispatch`` together with
    app-invoking steps, (2) Python/JS source actively POSTs to GitHub
    ``/dispatches``, (3) the retired ``google-app-script-trigger`` string appears,
    or (4) ``gh workflow run`` is invoked (shell or argv list form). Bare URL
    literals are intentionally ignored — see LLM rule PIPE-014 for consistency
    reasoning across input types.
    """
    CHECK_ID = "PIPE-008"
    findings: list[Finding] = []
    wf_dir = repo_path / ".github" / "workflows"
    if wf_dir.is_dir():
        for wf in sorted(wf_dir.rglob("*.yml")) + sorted(wf_dir.rglob("*.yaml")):
            try:
                text = wf.read_text()
            except OSError:
                continue
            low = text.lower()
            if "repository_dispatch" not in low:
                continue
            relay = any(
                k in low
                for k in (
                    "prefect deployment run",
                    "prefect deploy",
                    "run_deployment(",
                    "npx prefect",
                )
            ) or (
                "/dispatches" in text
                and any(k in low for k in ("curl ", "httpx.", "requests."))
            )
            pure_ci = ("pytest" in low or "ruff" in low) and not relay
            if relay and not pure_ci:
                findings.append(
                    _finding(
                        "PIPE-008",
                        "WARN",
                        "structural_conformance",
                        f"repository_dispatch in GitHub workflow with app-triggering steps ({wf.relative_to(repo_path)}).",
                        "Use watcher-cog + Prefect instead of GHA repository_dispatch relays.",
                    )
                )

    code_exts = {".py", ".ts", ".tsx", ".js"}
    for path in repo_path.rglob("*"):
        if not path.is_file():
            continue
        if "tests/" in str(path).replace("\\", "/"):
            continue
        if path.suffix.lower() not in code_exts:
            continue
        if ".github/workflows/" in str(path).replace("\\", "/"):
            continue
        try:
            body = path.read_text()
        except OSError:
            continue
        low = body.lower()
        if re.search(
            r"(httpx|requests)\.(post|put)\([^\)]*api\.github\.com/[^\"'\)]+/dispatches",
            body,
            re.I,
        ):
            findings.append(
                _finding(
                    "PIPE-008",
                    "WARN",
                    "structural_conformance",
                    f"Active HTTP client call to GitHub dispatches API ({path.relative_to(repo_path)}).",
                    "Use watcher-cog + Prefect instead of repository_dispatch HTTP relays.",
                )
            )
        if "google-app-script-trigger" in body:
            findings.append(
                _finding(
                    "PIPE-008",
                    "WARN",
                    "structural_conformance",
                    f"Retired google-app-script-trigger reference in {path.relative_to(repo_path)}.",
                    "Use watcher-cog + Prefect; remove legacy Apps Script trigger hooks.",
                )
            )
        if re.search(r"\bgh\s+workflow\s+run\b", low):
            findings.append(
                _finding(
                    "PIPE-008",
                    "WARN",
                    "structural_conformance",
                    f"gh workflow run invocation in {path.relative_to(repo_path)}.",
                    "Use watcher-cog + Prefect instead of driving workflows via gh CLI.",
                )
            )
        if re.search(
            r"\[\s*['\"]gh['\"]\s*,\s*['\"]workflow['\"]\s*,\s*['\"]run['\"]",
            body,
        ):
            findings.append(
                _finding(
                    "PIPE-008",
                    "WARN",
                    "structural_conformance",
                    f"gh workflow run argv-style invocation in {path.relative_to(repo_path)}.",
                    "Use watcher-cog + Prefect instead of subprocess gh workflow relays.",
                )
            )
    return findings


def check_evaluation_step(repo_path: Path) -> list[Finding]:
    """PIPE-009: AI evaluation step as final pipeline task."""
    CHECK_ID = "PIPE-009"
    findings = []
    if repo_path.name == "evaluator-cog":
        return findings
    src = repo_path / "src"
    if not src.is_dir():
        return findings
    text = "\n".join(f.read_text() for f in src.rglob("*.py"))
    signals = (
        "pipeline_eval",
        "post_evaluation",
        "/v1/evaluations",
        "evaluate_pipeline_run",
    )
    if not any(s in text for s in signals):
        findings.append(
            _finding(
                "PIPE-009",
                "WARN",
                "pipeline_consistency",
                "Pipeline cog source has no clear evaluation-step signal.",
                "Add or document an evaluation step that posts findings to /v1/evaluations.",
            )
        )
    return findings


def check_respx_for_http_mocking(repo_path: Path) -> list[Finding]:
    """TEST-007: respx/httpx for HTTP mocking — no real external calls."""
    CHECK_ID = "TEST-007"
    findings = []
    pyproject = repo_path / "pyproject.toml"
    py_text = pyproject.read_text().lower() if pyproject.exists() else ""
    if "respx" not in py_text:
        findings.append(
            _finding(
                "TEST-007",
                "ERROR",
                "testing_coverage",
                "respx is absent from development dependencies.",
                "Add respx to dev dependencies for HTTP mocking in tests.",
            )
        )

    tests_dir = repo_path / "tests"
    if not tests_dir.is_dir():
        return findings
    for test_file in tests_dir.rglob("test_*.py"):
        try:
            text = test_file.read_text()
        except OSError:
            continue

        http_tokens = (
            "httpx.get(",
            "httpx.post(",
            "requests.get(",
            "requests.post(",
        )
        real_http_tokens = [
            tok
            for tok in http_tokens
            if tok in text and not _is_inside_string_literal(text, tok)
        ]
        if real_http_tokens and "respx.mock" not in text:
            findings.append(
                _finding(
                    "TEST-007",
                    "ERROR",
                    "testing_coverage",
                    f"Raw HTTP calls found without respx.mock in {test_file.relative_to(repo_path)}.",
                    "Wrap HTTP interactions in respx.mock() and avoid real external network calls.",
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


def check_shared_library_used(
    repo_path: Path,
    language: str = "python",
    workspace_package_json_text: str | None = None,
) -> list[Finding]:
    """XSTACK-001: Shared library dependency must be declared (2026-04 narrow).

    Hand-rolled logger/auth/response reimplementation heuristics moved to LLM
    rule XSTACK-005; this check only verifies the dependency is present in
    ``pyproject.toml`` / workspace ``package.json`` (MONO-001).
    """
    CHECK_ID = "XSTACK-001"
    findings: list[Finding] = []
    if language == "python":
        pyproject = repo_path / "pyproject.toml"
        py_text = pyproject.read_text().lower() if pyproject.exists() else ""
        if "common-python-utils" not in py_text:
            findings.append(
                _finding(
                    "XSTACK-001",
                    "ERROR",
                    "cross_repo_coherence",
                    "common-python-utils is not declared for this Python service.",
                    "Depend on common-python-utils and consume shared behaviors from it.",
                )
            )
    else:
        pkg = repo_path / "package.json"
        per_app_text = pkg.read_text().lower() if pkg.exists() else ""
        pkg_text = per_app_text + (workspace_package_json_text or "").lower()
        if "common-typescript-utils" not in pkg_text:
            findings.append(
                _finding(
                    "XSTACK-001",
                    "ERROR",
                    "cross_repo_coherence",
                    "common-typescript-utils is not declared for this TypeScript service.",
                    "Depend on common-typescript-utils to avoid re-implementing shared utilities.",
                )
            )
    return findings


def check_standards_freshness(repo_path: Path) -> list[Finding]:
    """PRIN-009: Standards are a living document.

    Checks the timestamp of the most recent commit on main in the
    ecosystem-standards repo via the GitHub API. Flags if more than
    90 days have elapsed. Degrades gracefully on fetch failure
    (rate limit, network, etc.) — returns empty rather than a false
    positive, matching the pre-existing behavior of this check.
    """
    CHECK_ID = "PRIN-009"
    import datetime

    findings: list[Finding] = []
    try:
        import httpx

        url = "https://api.github.com/repos/mini-app-polis/ecosystem-standards/commits/main"
        r = httpx.get(
            url,
            timeout=20.0,
            headers={"Accept": "application/vnd.github+json"},
        )
        r.raise_for_status()
        data = r.json() or {}
        committer = (data.get("commit") or {}).get("committer") or {}
        date_str = str(committer.get("date") or "").strip()
        if not date_str:
            return findings

        # GitHub returns ISO-8601 with trailing 'Z' (e.g. "2026-04-18T14:23:01Z").
        # Python's fromisoformat handles 'Z' natively as of 3.11.
        try:
            commit_dt = datetime.datetime.fromisoformat(date_str.replace("Z", "+00:00"))
        except ValueError:
            return findings

        now = datetime.datetime.now(datetime.UTC)
        age_days = (now - commit_dt).days
        if age_days > 90:
            findings.append(
                _finding(
                    "PRIN-009",
                    "WARN",
                    "standards_currency",
                    f"Standards repo appears stale ({age_days} days since last commit).",
                    "Review ecosystem-standards — if no recent changes are warranted, commit an explicit review-attestation entry.",
                )
            )
    except Exception:
        return findings
    return findings


# -- META checks (standards-repo type only) -----------------------------------


def check_meta_release_pipeline_wired(repo_path: Path) -> list[Finding]:
    """META-001: Release automation for the standards repo is wired end-to-end."""
    CHECK_ID = "META-001"
    findings: list[Finding] = []
    workflows_dir = repo_path / ".github" / "workflows"
    workflow_blob = ""
    if workflows_dir.is_dir():
        for wf in list(workflows_dir.rglob("*.yml")) + list(
            workflows_dir.rglob("*.yaml")
        ):
            try:
                workflow_blob += "\n" + wf.read_text().lower()
            except OSError:
                continue

    has_sem_rel_wf = any(
        s in workflow_blob
        for s in (
            "semantic-release",
            "npx semantic-release",
            "semantic_release",
        )
    )
    has_rel_hook = (
        (repo_path / ".releaserc.json").exists()
        or (repo_path / ".releaserc.cjs").exists()
        or (repo_path / ".releaserc.yaml").exists()
    )
    pkg = repo_path / "package.json"
    pkg_ok = False
    if pkg.exists():
        try:
            import json as _json

            pdata = _json.loads(pkg.read_text())
            scripts = pdata.get("scripts") or {}
            dev = pdata.get("devDependencies") or {}
            deps = pdata.get("dependencies") or {}
            scripts_blob = str(scripts).lower()
            pkg_ok = "semantic-release" in scripts_blob or any(
                "semantic-release" in str(k).lower() for k in {**dev, **deps}
            )
        except Exception:
            pkg_ok = False

    push_to_main = "push:" in workflow_blob and "main" in workflow_blob

    if not has_sem_rel_wf:
        findings.append(
            _finding(
                "META-001",
                "WARN",
                "structural_conformance",
                "No GitHub Actions workflow references semantic-release.",
                "Add a workflow that executes semantic-release on the mainline branch.",
            )
        )
    if not has_rel_hook:
        findings.append(
            _finding(
                "META-001",
                "WARN",
                "structural_conformance",
                "Missing .releaserc.* configuration alongside semantic-release.",
                "Add .releaserc.json (or .releaserc.cjs / .yaml) describing branches and plugins.",
            )
        )
    if not pkg_ok:
        findings.append(
            _finding(
                "META-001",
                "WARN",
                "structural_conformance",
                "package.json lacks semantic-release wiring (script or dependency).",
                "Declare semantic-release in devDependencies and expose an npm script if required by the catalog.",
            )
        )
    if not push_to_main:
        findings.append(
            _finding(
                "META-001",
                "WARN",
                "structural_conformance",
                "No workflow appears to trigger on push to main.",
                "Ensure release automation runs when main updates (push trigger with main branch).",
            )
        )
    return findings


def check_meta_no_scattered_metadata(repo_path: Path) -> list[Finding]:
    """META-002: Version metadata is not scattered outside canonical files."""
    CHECK_ID = "META-002"
    findings: list[Finding] = []
    index_path = repo_path / "index.yaml"
    if index_path.exists():
        try:
            text = index_path.read_text()
            if re.search(r"(?m)^version\s*:", text):
                findings.append(
                    _finding(
                        "META-002",
                        "WARN",
                        "structural_conformance",
                        "index.yaml still declares a top-level version: field.",
                        "Remove version from index.yaml — package.json is the single version of record.",
                    )
                )
            if re.search(r"(?m)^updated\s*:", text):
                findings.append(
                    _finding(
                        "META-002",
                        "WARN",
                        "structural_conformance",
                        "index.yaml still declares a top-level updated: field.",
                        "Remove updated metadata from index.yaml; rely on git history and package.json.",
                    )
                )
        except OSError as exc:
            findings.append(
                _finding(
                    "META-002",
                    "WARN",
                    "structural_conformance",
                    f"index.yaml could not be read: {exc}",
                    "Fix permissions/encoding so META-002 can scan for scattered metadata.",
                )
            )

    for stray in ("VERSION.txt", "VERSION", "version.txt"):
        candidate = repo_path / stray
        if candidate.is_file():
            findings.append(
                _finding(
                    "META-002",
                    "WARN",
                    "structural_conformance",
                    f"Stray plaintext version file exists at repo root ({stray}).",
                    "Delete ad-hoc version files — package.json must remain canonical.",
                )
            )
            break
    return findings


_CANONICAL_ENUM_KEYS = (
    "repo_types",
    "traits",
    "dod_types",
    "service_statuses",
    "rule_severities",
)


def check_meta_canonical_enums_are_dicts(repo_path: Path) -> list[Finding]:
    """META-003: Schema enumerations are dict maps, not YAML lists."""
    CHECK_ID = "META-003"
    findings: list[Finding] = []
    index_path = repo_path / "index.yaml"
    if not index_path.exists():
        return findings
    try:
        import yaml as _yaml

        data = _yaml.safe_load(index_path.read_text()) or {}
    except Exception:
        findings.append(
            _finding(
                "META-003",
                "WARN",
                "structural_conformance",
                "index.yaml is not parseable YAML — cannot validate canonical enum dict shapes.",
                "Fix YAML syntax errors reported by the standards CI job.",
            )
        )
        return findings

    schema = data.get("schema") or {}
    for key in _CANONICAL_ENUM_KEYS:
        val = schema.get(key)
        if val is None:
            continue
        if isinstance(val, list):
            findings.append(
                _finding(
                    "META-003",
                    "WARN",
                    "structural_conformance",
                    f"schema.{key} is a YAML list — canonical enums must be dict maps.",
                    "Convert the enumeration to a mapping keyed by stable identifiers.",
                )
            )
    return findings


# -- Test checks --------------------------------------------------------------


def check_pytest_config(repo_path: Path) -> list[Finding]:
    """TEST-005: pytest configuration present in pyproject.toml.

    The wider test-structure checks that previously lived here (TEST-003
    failure-path detection) were retired in favor of LLM routing per
    the ecosystem-standards v3.8.0 classification. TEST-005 remains a
    deterministic structural check and is preserved here with a proper
    CHECK_ID.
    """
    CHECK_ID = "TEST-005"
    findings: list[Finding] = []
    pyproject = repo_path / "pyproject.toml"
    if not pyproject.exists():
        return findings
    if "[tool.pytest.ini_options]" not in pyproject.read_text():
        findings.append(
            _finding(
                "TEST-005",
                "WARN",
                "testing_coverage",
                "[tool.pytest.ini_options] absent from pyproject.toml.",
                "Add pytest configuration to pyproject.toml.",
            )
        )
    return findings


def check_prefect_serve_pattern(repo_path: Path) -> list[Finding]:
    """CD-015: Prefect serve() — no work pool.

    Detects three equivalent serve() call shapes:

      1. prefect.serve(...)
      2. flow.serve(...)
      3. ``from prefect import serve`` followed by ``serve(...)``

    Also flags incompatible patterns: flow.deploy(), work_pool_name
    references, and work_pool: in prefect.yaml.
    """
    findings = []
    src = repo_path / "src"
    if not src.is_dir():
        return findings

    content = "\n".join(f.read_text(errors="replace") for f in src.rglob("*.py"))

    # Incompatible patterns.
    if "flow.deploy(" in content or "work_pool_name" in content:
        findings.append(
            _finding(
                "CD-015",
                "ERROR",
                "cd_readiness",
                "work pool pattern detected — flow.deploy() or work_pool_name found.",
                "Use prefect.serve() running in-process on Railway instead of work pool deployments.",
            )
        )
    prefect_yaml = repo_path / "prefect.yaml"
    if prefect_yaml.exists() and "work_pool" in prefect_yaml.read_text():
        findings.append(
            _finding(
                "CD-015",
                "ERROR",
                "cd_readiness",
                "work_pool configuration found in prefect.yaml.",
                "Remove work pool config and use prefect.serve() instead.",
            )
        )

    # Accepted serve patterns.
    has_qualified_serve = "prefect.serve(" in content or "flow.serve(" in content
    # ``from prefect import serve`` (optionally with other names) followed
    # anywhere by a bare ``serve(`` call.
    imports_serve = bool(
        re.search(
            r"from\s+prefect\s+import\s+[^\n]*\bserve\b",
            content,
        )
    )
    has_bare_serve_call = bool(re.search(r"(?:^|[\s(=,])serve\s*\(", content))
    has_imported_serve = imports_serve and has_bare_serve_call

    if not (has_qualified_serve or has_imported_serve):
        findings.append(
            _finding(
                "CD-015",
                "WARN",
                "cd_readiness",
                "No prefect.serve() call found in source — flow registration "
                "pattern missing or unverifiable.",
                "Ensure flows are registered via prefect.serve() (or "
                "`from prefect import serve; serve(...)`) at the cog entry point.",
            )
        )
    return findings


def check_releaserc_assets(
    repo_path: Path, monorepo_root: Path | None = None
) -> list[Finding]:
    """VER-008: .releaserc.json assets must include all version-managed files."""
    CHECK_ID = "VER-008"
    import json as _json

    findings = []
    releaserc = repo_path / ".releaserc.json"
    if not releaserc.exists() and monorepo_root:
        releaserc = monorepo_root / ".releaserc.json"
    if not releaserc.exists():
        return findings
    try:
        data = _json.loads(releaserc.read_text())
    except Exception:
        return findings

    plugins = data.get("plugins", [])
    prepare_cmd = ""
    git_assets: list[str] = []

    for plugin in plugins:
        if isinstance(plugin, list) and len(plugin) >= 2:
            name, config = plugin[0], plugin[1]
            if "@semantic-release/exec" in str(name):
                prepare_cmd = config.get("prepareCmd", "")
            if "@semantic-release/git" in str(name):
                git_assets = config.get("assets", [])

    # Detect files written by prepareCmd
    managed_files = []
    for candidate in ("pyproject.toml", "package.json", "index.yaml"):
        if candidate in prepare_cmd:
            managed_files.append(candidate)

    if "CHANGELOG.md" not in git_assets:
        findings.append(
            _finding(
                "VER-008",
                "ERROR",
                "cd_readiness",
                "CHANGELOG.md is absent from @semantic-release/git assets.",
                "Add CHANGELOG.md to the assets array in the @semantic-release/git plugin config.",
            )
        )

    for f in managed_files:
        if f not in git_assets:
            findings.append(
                _finding(
                    "VER-008",
                    "ERROR",
                    "cd_readiness",
                    f"{f} is written by prepareCmd but absent from @semantic-release/git assets.",
                    f"Add {f} to the assets array in the @semantic-release/git plugin config.",
                )
            )
    return findings


def check_pnpm_lockfile(
    repo_path: Path,
    monorepo_root: Path | None = None,
) -> list[Finding]:
    """XSTACK-003: pnpm for all TypeScript projects."""
    CHECK_ID = "XSTACK-003"
    findings = []
    check_root = monorepo_root or repo_path
    if (check_root / "package-lock.json").exists():
        findings.append(
            _finding(
                "XSTACK-003",
                "ERROR",
                "structural_conformance",
                "package-lock.json found — npm is not the approved package manager for TypeScript projects.",
                "Migrate to pnpm: remove package-lock.json, run pnpm install, commit pnpm-lock.yaml.",
            )
        )
    if (check_root / "yarn.lock").exists():
        findings.append(
            _finding(
                "XSTACK-003",
                "ERROR",
                "structural_conformance",
                "yarn.lock found — yarn is not the approved package manager for TypeScript projects.",
                "Migrate to pnpm: remove yarn.lock, run pnpm install, commit pnpm-lock.yaml.",
            )
        )
    if not (check_root / "pnpm-lock.yaml").exists():
        findings.append(
            _finding(
                "XSTACK-003",
                "WARN",
                "structural_conformance",
                "pnpm-lock.yaml not found — pnpm may not be in use.",
                "Use pnpm as the package manager and commit pnpm-lock.yaml.",
            )
        )
    return findings


def _type_to_dod(repo_type: str, language: str = "python") -> str | None:
    """Map new repo type taxonomy back to dod_type string for check_readme_running_locally."""
    mapping = {
        "pipeline-cog": "new_cog",
        "trigger-cog": "new_cog",
        "api-service": "new_fastapi_service"
        if language == "python"
        else "new_hono_service",
        # Libraries have no standardized "running locally" section like cogs — avoid
        # routing through the Python cog README path (uv sync, pytest, etc.).
        "shared-library": None,
        "static-site": "new_frontend_site",
        "react-app": "new_react_app",
        "standards-repo": None,
    }
    return mapping.get(repo_type)


def check_eval_003(
    *,
    lookback_days: int = 30,
) -> list[Finding]:
    """EVAL-003: Findings emitted by evaluator-cog must be specific and actionable.

    Reads pipeline_evaluations for findings with
    source='conformance_check' or source='standards_drift' in the last
    `lookback_days`.
    """
    CHECK_ID = "EVAL-003"
    from mini_app_polis.api import KaianoApiClient

    try:
        api = KaianoApiClient.from_env()
        response = api.get(
            f"/v1/evaluations?source=conformance_check,standards_drift"
            f"&lookback_days={lookback_days}&limit=1000"
        )
    except Exception as exc:
        return [
            _finding(
                "CHECKER",
                "WARN",
                "pipeline_consistency",
                f"EVAL-003: could not fetch pipeline_evaluations: {exc}",
                "Investigate api-kaianolevine-com connectivity.",
            )
        ]

    if isinstance(response, dict):
        rows = response.get("data") or response.get("items") or []
    elif isinstance(response, list):
        rows = response
    else:
        rows = []

    findings: list[Finding] = []
    rule_id_pattern = _re_eval003.compile(r"[A-Z]+-\d+")

    for row in rows:
        if not isinstance(row, dict):
            continue
        text = str(row.get("finding") or "").strip()
        remediation = str(row.get("suggestion") or row.get("remediation") or "").strip()
        row_id = row.get("id") or row.get("run_id")

        problems: list[str] = []
        if not rule_id_pattern.search(text):
            problems.append("no rule ID reference in finding_text")
        if len(text) <= 60:
            problems.append(f"finding_text too short ({len(text)} chars)")
        if not remediation:
            problems.append("empty remediation")
        elif len(remediation) < max(len(text) * 0.5, 40):
            problems.append(
                f"remediation too short ({len(remediation)} chars) "
                f"vs finding ({len(text)} chars)"
            )

        if problems:
            findings.append(
                _finding(
                    CHECK_ID,
                    "WARN",
                    "pipeline_consistency",
                    f"Finding {row_id} violates EVAL-003: "
                    + "; ".join(problems)
                    + f". finding={text[:80]!r}",
                    "Rewrite the finding to reference a rule ID, "
                    "expand past 60 chars, and include concrete remediation guidance.",
                )
            )

    return findings


def check_mono_003(
    *,
    ecosystem: dict | None = None,
    lookback_days: int = 30,
) -> list[Finding]:
    """MONO-003: Sibling findings with same root cause must be deduplicated."""
    CHECK_ID = "MONO-003"
    from collections import defaultdict

    from mini_app_polis.api import KaianoApiClient

    if ecosystem is None:
        return []
    monorepo_services: dict[str, str] = {}
    for svc in ecosystem.get("services", []) or []:
        if not isinstance(svc, dict):
            continue
        mono = svc.get("monorepo")
        sid = svc.get("id")
        if mono and sid:
            monorepo_services[str(sid)] = str(mono)

    if not monorepo_services:
        return []

    _PER_APP_EXPECTED = frozenset({"XSTACK-002"})

    try:
        api = KaianoApiClient.from_env()
        service_ids = ",".join(monorepo_services.keys())
        response = api.get(
            f"/v1/evaluations?repos={service_ids}&lookback_days={lookback_days}&limit=2000"
        )
    except Exception as exc:
        return [
            _finding(
                "CHECKER",
                "WARN",
                "monorepo_coherence",
                f"MONO-003: could not fetch pipeline_evaluations: {exc}",
                "Investigate api-kaianolevine-com connectivity.",
            )
        ]

    if isinstance(response, dict):
        rows = response.get("data") or response.get("items") or []
    elif isinstance(response, list):
        rows = response
    else:
        rows = []

    buckets: dict[str, dict[tuple, list[dict]]] = defaultdict(lambda: defaultdict(list))
    for row in rows:
        if not isinstance(row, dict):
            continue
        repo = str(row.get("repo") or "")
        mono = monorepo_services.get(repo)
        if not mono:
            continue
        rule_id = str(row.get("rule_id") or row.get("violation_id") or "")
        if rule_id in _PER_APP_EXPECTED:
            continue
        key = (
            rule_id,
            str(row.get("finding") or ""),
            str(row.get("standards_version") or ""),
            str(row.get("run_id") or ""),
        )
        buckets[mono][key].append(row)

    findings: list[Finding] = []
    for mono_id, groups in buckets.items():
        for key, group in groups.items():
            if len(group) <= 1:
                continue
            rule_id, _text, _version, _run_id = key
            affected = sorted({str(r.get("repo") or "") for r in group})
            findings.append(
                _finding(
                    CHECK_ID,
                    "WARN",
                    "monorepo_coherence",
                    f"Monorepo '{mono_id}' emitted {len(group)} duplicate "
                    f"findings for rule {rule_id} across sibling apps "
                    f"({', '.join(affected)}). Expected one collapsed "
                    f"finding tagged with all affected service IDs.",
                    f"Verify MONO-001 / MONO-002 dedup logic is invoked "
                    f"for rule {rule_id} on this monorepo.",
                )
            )

    return findings


def check_eval_007(
    *,
    rule_catalog: dict[str, dict] | None = None,
    current_standards_version: str = "",
    evaluator_standards_version: str = "",
) -> list[Finding]:
    """EVAL-007: Standards/evaluator check coverage must be tracked and in sync."""
    CHECK_ID = "EVAL-007"
    if not rule_catalog:
        return []

    findings: list[Finding] = []

    import inspect

    this_module_src = inspect.getsource(inspect.getmodule(check_eval_007))
    impl_ids: set[str] = set(
        re.findall(r'CHECK_ID\s*=\s*"([A-Z]+-(?:GAP-)?[0-9A-Z]+)"', this_module_src)
    )

    checkable_ids = set(rule_catalog.keys())

    unimplemented = sorted(checkable_ids - impl_ids)
    orphaned = sorted(impl_ids - checkable_ids)

    for rid in unimplemented:
        findings.append(
            _finding(
                CHECK_ID,
                "WARN",
                "standards_currency",
                f"Rule {rid} is checkable in the catalog but has no "
                f"CHECK_ID constant in evaluator-cog's deterministic.py.",
                f"Add a check function for {rid} and register its CHECK_ID.",
            )
        )

    for rid in orphaned:
        findings.append(
            _finding(
                CHECK_ID,
                "ERROR",
                "standards_currency",
                f"CHECK_ID {rid} is implemented in evaluator-cog but has "
                f"no matching rule in the catalog (orphaned check).",
                "Remove the implementation or restore the rule in ecosystem-standards.",
            )
        )

    if current_standards_version and evaluator_standards_version:
        try:
            cur_parts = [int(p) for p in current_standards_version.split(".")[:2]]
            ev_parts = [int(p) for p in evaluator_standards_version.split(".")[:2]]
            if cur_parts[0] > ev_parts[0]:
                findings.append(
                    _finding(
                        CHECK_ID,
                        "WARN",
                        "standards_currency",
                        f"Evaluator pinned to standards v{evaluator_standards_version}, "
                        f"catalog is at v{current_standards_version} — major version skew.",
                        "Rebuild/redeploy evaluator-cog against the current catalog.",
                    )
                )
            elif cur_parts[0] == ev_parts[0] and (cur_parts[1] - ev_parts[1]) > 1:
                findings.append(
                    _finding(
                        CHECK_ID,
                        "WARN",
                        "standards_currency",
                        f"Evaluator pinned to standards v{evaluator_standards_version}, "
                        f"catalog is at v{current_standards_version} — "
                        f">1 minor version behind.",
                        "Rebuild/redeploy evaluator-cog against the current catalog.",
                    )
                )
        except (ValueError, IndexError):
            pass

    return findings


# -- Runner -------------------------------------------------------------------


def run_all_checks(
    repo_path: Path,
    language: str = "python",
    service_type: str = "worker",
    cog_subtype: str | None = None,
    dod_type: str | None = None,
    check_exceptions: list[str] | None = None,
    exception_reasons: dict[str, str] | None = None,
    monorepo_root: Path | None = None,
    workspace_package_json_text: str | None = None,
    evaluator_config: EvaluatorConfig | None = None,
    rule_catalog: dict[str, dict] | None = None,
    catalog_schema: dict | None = None,
) -> CheckResult:
    """Run deterministic checks against a repo and return combined findings.

    When evaluator_config is provided (from the repo's evaluator.yaml), it
    takes precedence over the legacy dod_type/service_type/check_exceptions
    parameters for type-based branching and exception scoping.
    """
    # ── Resolve type-based flags ─────────────────────────────────────────────
    # Prefer evaluator_config (from evaluator.yaml) over legacy dod_type fields.
    if evaluator_config is not None:
        if rule_catalog is not None:
            evaluator_config.rule_catalog = rule_catalog
        if catalog_schema is not None:
            evaluator_config.catalog_schema = catalog_schema
        cfg = evaluator_config
        # Type says "could be Python" (e.g. shared-library); ecosystem language is authoritative.
        is_python = (language == "python") and cfg.is_python_service
        is_library = cfg.is_shared_library
        is_pipeline_cog = cfg.is_pipeline_cog
        is_fastapi = cfg.is_api_service and language == "python"
        # Language-agnostic api-service flag — for rules that apply to both
        # FastAPI (Python) and Hono (TypeScript) API services.
        is_api_service = cfg.is_api_service
        is_frontend = cfg.is_frontend
    else:
        # Legacy path — used during migration when evaluator.yaml is absent
        is_python = language == "python" or dod_type in (
            "new_cog",
            "new_fastapi_service",
        )
        is_library = service_type == "library" or dod_type is None
        is_pipeline_cog = (dod_type == "new_cog" and cog_subtype != "trigger") or (
            is_python and service_type == "worker" and cog_subtype == "pipeline"
        )
        is_fastapi = dod_type == "new_fastapi_service"
        is_api_service = dod_type in ("new_fastapi_service", "new_hono_service")
        is_frontend = dod_type in ("new_frontend_site", "new_react_app")

    # Legacy skip list is still used by a handful of checker functions that
    # accept "exceptions" lists directly.
    _exceptions = (
        evaluator_config.all_skipped_ids
        if evaluator_config is not None
        else frozenset(check_exceptions or [])
    )

    # Also handle cog_subtype trigger for trigger-cog type
    is_trigger_cog = (
        evaluator_config is not None and evaluator_config.is_trigger_cog
    ) or cog_subtype == "trigger"

    checked_rule_ids: set[str] = set()

    def _mark_checked(*rule_ids: str) -> None:
        checked_rule_ids.update(rule_ids)

    def _run(check_fn, rule_id: str | None = None) -> None:
        if rule_id:
            checked_rule_ids.add(rule_id)
        if not rule_id:
            # Legacy call without a rule_id: just run and collect.
            try:
                findings.extend(check_fn(repo_path))
            except Exception as exc:
                findings.append(
                    _finding(
                        "CHECKER",
                        "WARN",
                        "structural_conformance",
                        f"Check {check_fn.__name__} raised an unexpected error: {exc}",
                        "Investigate the checker itself.",
                    )
                )
            return

        if evaluator_config is None:
            # No catalog available → honor explicit legacy exceptions only.
            if rule_id in _exceptions:
                reason = (exception_reasons or {}).get(rule_id, "")
                if reason:
                    findings.append(
                        _finding(
                            rule_id,
                            "INFO",
                            "structural_conformance",
                            f"Skipped: {reason}",
                            "",
                        )
                    )
                return
            disposition_info_reason = ""
            severity_override: str | None = None
            is_deferred = False
            rule_status = ""
        else:
            result = evaluator_config.resolve_dispatch(rule_id)
            rule_meta = (evaluator_config.rule_catalog or {}).get(rule_id, {})
            rule_status = rule_meta.get("status", "")
            if not result.should_run:
                if result.emits_skip_finding and result.reason:
                    f = _finding(
                        rule_id,
                        "INFO",
                        "structural_conformance",
                        f"Skipped: {result.reason}",
                        "",
                    )
                    f["status"] = rule_status
                    findings.append(f)
                return
            disposition_info_reason = result.reason
            severity_override = (
                result.downgraded_severity
                if result.disposition.value == "run_downgraded"
                else None
            )
            is_deferred = result.disposition.value == "run_deferred"

        try:
            new_findings = check_fn(repo_path)
            for f in new_findings:
                if is_deferred:
                    f["severity"] = "INFO"
                    f["deferred"] = True
                    if disposition_info_reason and "deferred_reason" not in f:
                        f["deferred_reason"] = disposition_info_reason
                elif severity_override:
                    f["severity"] = severity_override
                    f["downgraded"] = True
                    if disposition_info_reason and "downgrade_reason" not in f:
                        f["downgrade_reason"] = disposition_info_reason
                if rule_status and "status" not in f:
                    f["status"] = rule_status
            findings.extend(new_findings)
        except Exception as exc:
            findings.append(
                _finding(
                    "CHECKER",
                    "WARN",
                    "structural_conformance",
                    f"Check {check_fn.__name__} raised an unexpected error: {exc}",
                    "Investigate the checker itself.",
                )
            )

    findings: list[Finding] = []

    _run(lambda p: check_readme(p, monorepo_root=monorepo_root), "DOC-001")
    _run(lambda p: check_changelog(p, monorepo_root=monorepo_root), "DOC-003")
    _run(lambda p: check_releaserc(p, monorepo_root=monorepo_root), "VER-003")
    _run(check_split_package_identity, "DOC-009")

    if not is_library:
        _run(lambda p: check_env_example(p, monorepo_root=monorepo_root), "DOC-004")

    if is_python and not is_frontend:
        _run(check_pre_commit, "PY-008")
        _run(check_src_layout, "PY-005")
        _run(check_no_setup_py, "PY-007")
        _mark_checked("PY-001", "PY-002", "PY-003", "PY-009", "PY-010", "CD-002")
        try:
            findings.extend(check_pyproject(repo_path, exceptions=_exceptions))
        except Exception as exc:
            findings.append(
                _finding(
                    "CHECKER",
                    "WARN",
                    "structural_conformance",
                    f"check_pyproject raised an unexpected error: {exc}",
                    "",
                )
            )
        _run(check_no_print_statements, "CD-003")
        _run(check_naming_conventions, "PY-011")
        _run(check_failed_prefix, "PY-012")
        _run(check_duplicate_prefix, "PY-013")
        _run(check_finally_cleanup, "PY-014")

    if (is_python or is_fastapi) and not is_library and not is_frontend:
        _run(check_common_python_utils_dep, "PY-006")

    # Healthchecks only applies to trigger cogs
    _mark_checked("CD-007")
    if is_trigger_cog:
        findings.extend(
            check_healthchecks_integration(repo_path, cog_subtype="trigger")
        )

    _run(check_structured_logging, "CD-009")
    _run(check_no_hardcoded_secrets, "CD-011")
    _run(check_no_manual_changelog, "VER-004")

    _mark_checked("XSTACK-001")
    if (evaluator_config is None and "XSTACK-001" not in _exceptions) or (
        evaluator_config is not None
        and evaluator_config.resolve_dispatch("XSTACK-001").should_run
    ):
        # Static sites are excluded from XSTACK-001 by type scoping
        if not is_frontend or (
            evaluator_config is not None and not evaluator_config.is_static_site
        ):
            findings.extend(
                check_shared_library_used(
                    repo_path,
                    language=language,
                    workspace_package_json_text=workspace_package_json_text,
                )
            )
    else:
        if evaluator_config is None:
            reason = (exception_reasons or {}).get("XSTACK-001", "")
            if reason:
                findings.append(
                    _finding(
                        "XSTACK-001",
                        "INFO",
                        "structural_conformance",
                        f"Skipped: {reason}",
                        "",
                    )
                )
        else:
            dispatch = evaluator_config.resolve_dispatch("XSTACK-001")
            if dispatch.emits_skip_finding and dispatch.reason:
                rule_status = (
                    (evaluator_config.rule_catalog or {})
                    .get("XSTACK-001", {})
                    .get("status", "")
                )
                skip_finding = _finding(
                    "XSTACK-001",
                    "INFO",
                    "structural_conformance",
                    f"Skipped: {dispatch.reason}",
                    "",
                )
                if rule_status:
                    skip_finding["status"] = rule_status
                findings.append(skip_finding)

    # Standards freshness check only applies to standards-repo type
    if evaluator_config is not None:
        if evaluator_config.is_standards_repo:
            _run(check_standards_freshness, "PRIN-009")
            _run(check_meta_release_pipeline_wired, "META-001")
            _run(check_meta_no_scattered_metadata, "META-002")
            _run(check_meta_canonical_enums_are_dicts, "META-003")
    elif dod_type is None:
        _run(check_standards_freshness, "PRIN-009")

    _run(check_no_hardcoded_urls, "FE-007")

    _mark_checked("VER-003", "VER-005", "VER-006")
    try:
        findings.extend(
            check_ci(
                repo_path,
                exceptions=_exceptions,
                monorepo_root=monorepo_root,
            )
        )
    except Exception as exc:
        findings.append(
            _finding(
                "CHECKER",
                "WARN",
                "structural_conformance",
                f"check_ci raised an unexpected error: {exc}",
                "",
            )
        )

    if is_python:
        _run(check_pytest_coverage_in_ci, "TEST-006")
        _run(check_respx_for_http_mocking, "TEST-007")
        _run(check_mypy_in_ci, "TEST-012")

    if is_python:
        _run(check_pytest_config, "TEST-005")

    # DOC-013 README running locally — use new type for dod_type hint
    if (
        evaluator_config is None
        or evaluator_config.resolve_dispatch("DOC-013").should_run
    ):
        _mark_checked("DOC-013")
        # Map type to dod_type string for check_readme_running_locally
        if evaluator_config is not None:
            _readme_dod = _type_to_dod(evaluator_config.repo_type, language)
        else:
            _readme_dod = dod_type
        findings.extend(check_readme_running_locally(repo_path, dod_type=_readme_dod))

    if is_frontend:
        _run(check_tailwind, "FE-003")
    # Static site specific
    if evaluator_config is not None:
        if evaluator_config.is_static_site:
            _run(check_astro_framework, "FE-001")
            _run(check_astro_pinned_versions, "FE-008")
            _run(check_astro_build_time_data, "FE-009")
            _run(check_astro_runtime_queries, "FE-010")
        elif evaluator_config.is_react_app:
            _run(check_vite_react_ts, "FE-002")
            _run(check_shadcn, "FE-004")
            _run(check_react_hook_form_zod, "FE-005")
    else:
        if dod_type == "new_frontend_site":
            _run(check_astro_framework, "FE-001")
            _run(check_astro_pinned_versions, "FE-008")
            _run(check_astro_build_time_data, "FE-009")
            _run(check_astro_runtime_queries, "FE-010")
        if dod_type == "new_react_app":
            _run(check_vite_react_ts, "FE-002")
            _run(check_shadcn, "FE-004")
            _run(check_react_hook_form_zod, "FE-005")

    if is_pipeline_cog:
        _run(check_retry_logic, "PIPE-007")
        _run(check_no_retired_trigger_patterns, "PIPE-008")
        _run(check_evaluation_step, "PIPE-009")
        _run(check_prefect_serve_pattern, "CD-015")
        _run(check_db_writes_use_upserts, "PIPE-002")
        _run(check_inputs_not_deleted, "PIPE-005")

    # PIPE-001 applies to both pipeline-cogs and trigger-cogs — Prefect is
    # required on both, with slightly different usage patterns (see the
    # check function for the pipeline-vs-trigger branch).
    if is_pipeline_cog or is_trigger_cog:
        _cog_subtype = "trigger" if is_trigger_cog else "pipeline"

        def _pipe_001_check(p: Path) -> list[Finding]:
            return check_prefect_present(p, cog_subtype=_cog_subtype)

        _run(_pipe_001_check, "PIPE-001")

        # CD-005 also covers pipeline-cogs and trigger-cogs. It overlaps with
        # PIPE-001's condition 1 by design (see the rule body) — a repo missing
        # prefect entirely will produce two findings, which is correct.
        def _cd_005_check(p: Path) -> list[Finding]:
            return check_prefect_cloud_observability(p, cog_subtype=_cog_subtype)

        _run(_cd_005_check, "CD-005")

    # API-001 / API-002 apply to api-service repos regardless of language.
    if is_api_service:

        def _api_001_check(p: Path) -> list[Finding]:
            return check_railway_hosted_api(p, language=language)

        def _api_002_check(p: Path) -> list[Finding]:
            return check_postgres_only_data_store(p, language=language)

        _run(_api_001_check, "API-001")
        _run(_api_002_check, "API-002")

    # CD-006 applies to pipeline-cogs, trigger-cogs, and api-services —
    # any repo type where GHA relaying would be a genuine anti-pattern.
    if is_pipeline_cog or is_trigger_cog or is_api_service:
        _run(check_gha_not_trigger_relay, "CD-006")

    # CD-012 (Clerk M2M JWT) applies to the same set — services that
    # make or receive internal calls should use JWT, not API keys.
    if is_pipeline_cog or is_trigger_cog or is_api_service:

        def _cd_012_check(p: Path) -> list[Finding]:
            return check_clerk_m2m_auth(p, language=language)

        _run(_cd_012_check, "CD-012")

    # XSTACK-002 (response shape parity) applies to api-service only per
    # the narrowed applies_to in the audit.
    if is_api_service:

        def _xstack_002_check(p: Path) -> list[Finding]:
            return check_response_shape_parity(p, language=language)

        _run(_xstack_002_check, "XSTACK-002")

    # DOC-005 (ADRs present) applies to pipeline-cogs, trigger-cogs,
    # api-services, shared-libraries, and standards-repo per the catalog.
    if (
        is_pipeline_cog
        or is_trigger_cog
        or is_api_service
        or is_library
        or (evaluator_config is not None and evaluator_config.is_standards_repo)
    ):
        _run(check_adrs_present, "DOC-005")

    _is_static = (
        evaluator_config is not None and evaluator_config.is_static_site
    ) or dod_type == "new_frontend_site"
    # Wave 9 — coverage sweep for 35 rules previously only in catalog
    # ==================================================================

    # API domain — api-service only
    if is_api_service:

        def _api_003(p: Path) -> list[Finding]:
            return check_orm_usage(p, language=language)

        def _api_004(p: Path) -> list[Finding]:
            return check_v1_route_prefix(p, language=language)

        def _api_007(p: Path) -> list[Finding]:
            return check_clerk_auth_dep(p, language=language)

        def _api_008(p: Path) -> list[Finding]:
            return check_unauthenticated_routes(p, language=language)

        def _api_009(p: Path) -> list[Finding]:
            return check_cors_config(p, language=language)

        def _api_010(p: Path) -> list[Finding]:
            return check_health_endpoint(p, language=language)

        _run(_api_003, "API-003")
        _run(_api_004, "API-004")
        _run(check_response_envelope_presence, "API-005")
        _run(_api_007, "API-007")
        _run(_api_008, "API-008")
        _run(_api_009, "API-009")
        _run(_api_010, "API-010")

        def _api_011(p: Path) -> list[Finding]:
            return check_migration_in_ci(
                p, language=language, monorepo_root=monorepo_root
            )

        _run(_api_011, "API-011")

        # API-006 and AUTH-002 — Python-only shape checks
        if language == "python":
            _run(check_owner_id_column, "API-006")
            _run(check_auth_header_parity, "AUTH-002")

    # CD-008 logger misuse — applies broadly; language-gated to Python.
    if language == "python":
        _run(check_logger_misuse, "CD-008")

    # CD-010 three-layer observability — applies to all runtime services.
    if is_pipeline_cog or is_trigger_cog or is_api_service:
        _cog_st_010 = (
            "trigger" if is_trigger_cog else ("pipeline" if is_pipeline_cog else None)
        )

        def _cd_010_check(p: Path) -> list[Finding]:
            return check_three_layer_observability(
                p, cog_subtype=_cog_st_010, language=language
            )

        _run(_cd_010_check, "CD-010")

    # CD-014 — static-site deploy target
    if _is_static:
        _run(check_cloudflare_pages_deploy, "CD-014")

    # DOC-006 / DOC-007 — Python docstring / Pydantic descriptions.
    if language == "python":
        _run(check_public_docstrings, "DOC-006")
    if language == "python" and (is_pipeline_cog or is_api_service):
        _run(check_pydantic_field_descriptions, "DOC-007")

    # DOC-010 / DOC-011 — FastAPI route docs + unauthenticated-route intent.
    if is_api_service and language == "python":
        _run(check_fastapi_route_docs, "DOC-010")
        _run(check_unauthenticated_routes_documented, "DOC-011")

    # FE-006 — fetch error handling on static sites + react apps.
    if (
        _is_static
        or (evaluator_config is not None and evaluator_config.is_react_app)
        or dod_type == "new_react_app"
    ):
        _run(check_fetch_error_handling, "FE-006")

    # Pipeline rules — PIPE-004, PIPE-006, PIPE-011, PIPE-012.
    # PIPE-003 is LLM-routed per ecosystem-standards v3.8.0.
    if is_pipeline_cog or is_trigger_cog:
        _cog_st_pipe = "trigger" if is_trigger_cog else "pipeline"

        def _pipe_011_check(p: Path) -> list[Finding]:
            return check_final_evaluation_task(p, cog_subtype=_cog_st_pipe)

        _run(check_shared_resource_concurrency, "PIPE-004")
        _run(check_prefect_run_logger, "PIPE-006")
        _run(_pipe_011_check, "PIPE-011")
        _run(check_hardcoded_retry_delay, "PIPE-012")

    # Python — PY-004, PY-015
    if language == "python" and (is_pipeline_cog or is_api_service or is_library):
        _run(check_pydantic_for_external_data, "PY-004")
    if is_api_service and language == "python":
        _run(check_async_sqlalchemy, "PY-015")

    # Configuration — CFG-001, CFG-002
    if language == "python" and (is_pipeline_cog or is_api_service or is_library):
        _run(check_settings_field_consistency, "CFG-001")
        _run(check_env_example_settings_parity, "CFG-002")

    # Testing — TEST-008, TEST-009, TEST-010, TEST-011, TEST-013, TEST-GAP-001
    if is_api_service:
        _run(check_testclient_for_v1_routes, "TEST-008")
        if language == "python":
            _run(check_db_test_fixtures, "TEST-009")
            _run(check_route_contract_tests, "TEST-010")
    if is_pipeline_cog or is_api_service:
        _run(check_mock_assertions, "TEST-011")
        _run(check_test_gap_critical_paths, "TEST-GAP-001")

    def _test_013(p: Path) -> list[Finding]:
        return check_hardcoded_time_values(p, language=language)

    if (
        is_pipeline_cog
        or is_api_service
        or (evaluator_config is not None and evaluator_config.is_react_app)
        or dod_type == "new_react_app"
    ):
        _run(_test_013, "TEST-013")

    # XSTACK-004 — env var prefix. Frontend + api-service.
    if (
        _is_static
        or (evaluator_config is not None and evaluator_config.is_react_app)
        or dod_type == "new_react_app"
        or is_api_service
    ):
        _run(check_env_var_prefix, "XSTACK-004")

    _run(
        lambda p: check_releaserc_assets(p, monorepo_root=monorepo_root),
        "VER-008",
    )

    # XSTACK-003 pnpm — applies to api-service (TS) and react-app
    if evaluator_config is not None:
        _needs_pnpm = evaluator_config.is_react_app or (
            evaluator_config.is_api_service and language == "typescript"
        )
    else:
        _needs_pnpm = dod_type in ("new_hono_service", "new_react_app")

    if _needs_pnpm:

        def _pnpm_lock_check(p: Path) -> list[Finding]:
            return check_pnpm_lockfile(p, monorepo_root=monorepo_root)

        _run(_pnpm_lock_check, "XSTACK-003")

    # EVAL-008: check for evaluator.yaml presence
    _mark_checked("EVAL-008")
    if not (repo_path / "evaluator.yaml").exists():
        findings.append(
            _finding(
                "EVAL-008",
                "WARN",
                "structural_conformance",
                "evaluator.yaml is absent from repo root.",
                "Add evaluator.yaml declaring type, traits, exemptions, and deferrals.",
            )
        )

    if evaluator_config is not None:
        catalog = evaluator_config.rule_catalog or {}
        for finding in findings:
            if "status" in finding:
                continue
            rid = str(finding.get("rule_id") or "")
            if not rid:
                continue
            rule_status = str((catalog.get(rid) or {}).get("status") or "").strip()
            if rule_status:
                finding["status"] = rule_status

    findings = _deduplicate_same_repo_findings(findings)
    return CheckResult(findings=findings, checked_rule_ids=checked_rule_ids)
