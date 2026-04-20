"""Deterministic checks: DOC-005, XSTACK-002, FE-009/010, CD-012, PIPE-002/005, narrowed PIPE-008 / XSTACK-001."""

from __future__ import annotations

import json
from pathlib import Path

from evaluator_cog.engine.deterministic import (
    check_adrs_present,
    check_astro_build_time_data,
    check_astro_runtime_queries,
    check_clerk_m2m_auth,
    check_db_writes_use_upserts,
    check_inputs_not_deleted,
    check_no_retired_trigger_patterns,
    check_response_shape_parity,
    check_shared_library_used,
)


def _write(repo: Path, rel: str, body: str) -> None:
    path = repo / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, encoding="utf-8")


def _nontrivial_src_py() -> str:
    return "".join(f"x_{i} = {i}\n" for i in range(55))


# --- DOC-005 -----------------------------------------------------------------


def test_doc005_skips_when_loc_under_threshold(tmp_path: Path) -> None:
    _write(tmp_path, "src/tiny.py", "a = 1\n")
    assert check_adrs_present(tmp_path) == []


def test_doc005_flags_missing_decisions_dir(tmp_path: Path) -> None:
    _write(tmp_path, "src/big.py", _nontrivial_src_py())
    f = check_adrs_present(tmp_path)
    assert any(x["rule_id"] == "DOC-005" for x in f)


def test_doc005_flags_empty_decisions_dir(tmp_path: Path) -> None:
    _write(tmp_path, "src/big.py", _nontrivial_src_py())
    (tmp_path / "docs" / "decisions").mkdir(parents=True, exist_ok=True)
    f = check_adrs_present(tmp_path)
    assert any(x["rule_id"] == "DOC-005" for x in f)


def test_doc005_passes_when_adr_present(tmp_path: Path) -> None:
    _write(tmp_path, "src/big.py", _nontrivial_src_py())
    _write(tmp_path, "docs/decisions/ADR-001-init.md", "# ADR\n")
    assert check_adrs_present(tmp_path) == []


# --- XSTACK-002 --------------------------------------------------------------


def test_xstack002_python_flags_missing_response_model(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "src/pkg/routes.py",
        "from fastapi import APIRouter\n"
        "router = APIRouter()\n"
        '@router.get("/items")\n'
        "def list_items():\n"
        "    return {}\n",
    )
    f = check_response_shape_parity(tmp_path, language="python")
    assert any(x["rule_id"] == "XSTACK-002" for x in f)


def test_xstack002_python_passes_with_response_model(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "src/pkg/routes.py",
        "from fastapi import APIRouter\n"
        "router = APIRouter()\n"
        '@router.get("/items", response_model=dict)\n'
        "def list_items():\n"
        "    return {}\n",
    )
    assert check_response_shape_parity(tmp_path, language="python") == []


def test_xstack002_typescript_flags_raw_c_json(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "src/api.ts",
        "import { Hono } from 'hono'\n"
        "const app = new Hono()\n"
        "app.get('/x', (c) => c.json({ ok: true }))\n",
    )
    f = check_response_shape_parity(tmp_path, language="typescript")
    assert any(x["rule_id"] == "XSTACK-002" for x in f)


def test_xstack002_typescript_passes_with_success_helper(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "src/api.ts",
        "import { Hono } from 'hono'\n"
        "import { success } from './http'\n"
        "const app = new Hono()\n"
        "app.get('/x', (c) => success(c, { ok: true }))\n",
    )
    assert check_response_shape_parity(tmp_path, language="typescript") == []


# --- FE-009 / FE-010 ---------------------------------------------------------


def test_fe009_no_astro_returns_empty(tmp_path: Path) -> None:
    _write(tmp_path, "src/x.py", "x = 1\n")
    assert check_astro_build_time_data(tmp_path) == []


def test_fe009_flags_runtime_fetch_matching_frontmatter_elsewhere(
    tmp_path: Path,
) -> None:
    url = "https://api.example.com/data"
    _write(
        tmp_path,
        "src/pages/a.astro",
        f"---\nconst _ = await fetch('{url}')\n---\n<div />\n",
    )
    _write(
        tmp_path,
        "src/pages/b.astro",
        f"<script>\nconst r = await fetch('{url}')\n</script>\n",
    )
    f = check_astro_build_time_data(tmp_path)
    assert any(x["rule_id"] == "FE-009" for x in f)


def test_fe009_skips_when_client_directive_present(tmp_path: Path) -> None:
    url = "https://api.example.com/data"
    _write(
        tmp_path,
        "src/pages/a.astro",
        f"---\nconst _ = await fetch('{url}')\n---\n<div />\n",
    )
    _write(
        tmp_path,
        "src/pages/b.astro",
        "<script>\n"
        f"const r = await fetch('{url}')\n"
        "</script>\n"
        "<Counter client:load />\n",
    )
    assert check_astro_build_time_data(tmp_path) == []


def test_fe010_flags_undocumented_runtime_fetch(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "src/x.astro",
        "<script>\nconst r = await fetch('https://api.secret.example/v1')\n</script>\n",
    )
    f = check_astro_runtime_queries(tmp_path)
    assert any(x["rule_id"] == "FE-010" for x in f)


def test_fe010_passes_when_url_in_readme(tmp_path: Path) -> None:
    u = "https://api.secret.example/v1"
    _write(tmp_path, "README.md", f"Calls `{u}` from the browser.\n")
    _write(
        tmp_path, "src/x.astro", f"<script>\nconst r = await fetch('{u}')\n</script>\n"
    )
    assert check_astro_runtime_queries(tmp_path) == []


def test_fe010_skips_client_island_even_if_undocumented(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "src/x.astro",
        "<script>\n"
        "const r = await fetch('https://api.secret.example/v1')\n"
        "</script>\n"
        "<Island client:visible />\n",
    )
    assert check_astro_runtime_queries(tmp_path) == []


# --- CD-012 ------------------------------------------------------------------


def test_cd012_flags_x_internal_api_key(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "src/c.py",
        'HEADERS = {"X-Internal-API-Key": "x"}\n'
        "import httpx\n"
        "httpx.get('https://example.com', headers=HEADERS)\n",
    )
    f = check_clerk_m2m_auth(tmp_path, language="python")
    assert any(x["rule_id"] == "CD-012" for x in f)


def test_cd012_skips_tests_tree_under_src(tmp_path: Path) -> None:
    _write(tmp_path, "src/tests/bad.py", 'HEADERS = {"X-Internal-API-Key": "x"}\n')
    assert check_clerk_m2m_auth(tmp_path, language="python") == []


def test_cd012_passes_when_jwt_pattern_present(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "src/c.py",
        "import httpx\n"
        "def call():\n"
        "    token = get_token()  # clerk jwt\n"
        "    return httpx.get('https://api.kaianolevine.com/x', headers={'Authorization': token})\n",
    )
    assert check_clerk_m2m_auth(tmp_path, language="python") == []


def test_cd012_flags_internal_httpx_without_jwt_signals(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "src/c.py",
        "import httpx\n"
        "def call():\n"
        "    return httpx.get('https://api.kaianolevine.com/v1/foo')\n",
    )
    f = check_clerk_m2m_auth(tmp_path, language="python")
    assert any(x["rule_id"] == "CD-012" for x in f)


# --- PIPE-002 / PIPE-005 ------------------------------------------------------


def test_pipe002_flags_session_add_without_upsert_helpers(tmp_path: Path) -> None:
    _write(tmp_path, "src/db.py", "def save(session, row):\n    session.add(row)\n")
    f = check_db_writes_use_upserts(tmp_path)
    assert any(x["rule_id"] == "PIPE-002" for x in f)


def test_pipe002_passes_when_on_conflict_present(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "src/db.py",
        "def save(session, row):\n"
        "    session.add(row)\n"
        "    stmt = insert(Table).values(x=1).on_conflict_do_nothing()\n",
    )
    assert check_db_writes_use_upserts(tmp_path) == []


def test_pipe002_flags_raw_insert_without_on_conflict(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "src/db.py",
        'def q():\n    return "INSERT INTO t (a) VALUES (1)"\n',
    )
    f = check_db_writes_use_upserts(tmp_path)
    assert any(x["rule_id"] == "PIPE-002" for x in f)


def test_pipe005_flags_drive_files_delete(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "src/drive.py",
        "def rm(drive, fid):\n    drive.files().delete(fileId=fid).execute()\n",
    )
    f = check_inputs_not_deleted(tmp_path)
    assert any(x["rule_id"] == "PIPE-005" for x in f)


def test_pipe005_flags_trashed_update(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "src/drive.py",
        "def trash(service, fid):\n"
        "    return service.files().update(fileId=fid, body={'trashed': True})\n",
    )
    f = check_inputs_not_deleted(tmp_path)
    assert any(x["rule_id"] == "PIPE-005" for x in f)


def test_pipe005_flags_os_remove_on_input_path(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "src/io.py",
        "import os\ndef clean(input_path):\n    os.remove(input_path)\n",
    )
    f = check_inputs_not_deleted(tmp_path)
    assert any(x["rule_id"] == "PIPE-005" for x in f)


def test_pipe005_ignores_remove_on_static_paths(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "src/io.py",
        "import os\ndef clean():\n    os.remove('/tmp/scratch.dat')\n",
    )
    assert check_inputs_not_deleted(tmp_path) == []


def test_pipe005_skips_under_src_tests(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "src/tests/t.py",
        "import os\ndef x(input_path):\n    os.remove(input_path)\n",
    )
    assert check_inputs_not_deleted(tmp_path) == []


# --- PIPE-008 (narrowed) -----------------------------------------------------


def test_pipe008_bare_dispatches_url_not_flagged(tmp_path: Path) -> None:
    _write(
        tmp_path, "src/t.py", 'url = "https://api.github.com/repos/o/r/dispatches"\n'
    )
    assert check_no_retired_trigger_patterns(tmp_path) == []


def test_pipe008_flags_active_httpx_post_to_dispatches(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "src/t.py",
        "import httpx\n"
        "httpx.post('https://api.github.com/repos/o/r/dispatches', json={})\n",
    )
    f = check_no_retired_trigger_patterns(tmp_path)
    assert any(x["rule_id"] == "PIPE-008" for x in f)


def test_pipe008_flags_google_app_script_trigger_string(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "src/legacy.ts",
        "export const hook = 'google-app-script-trigger'\n",
    )
    f = check_no_retired_trigger_patterns(tmp_path)
    assert any(x["rule_id"] == "PIPE-008" for x in f)


def test_pipe008_flags_gh_workflow_run_argv_list(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "src/cli.py",
        "import subprocess\nsubprocess.run(['gh', 'workflow', 'run', 'ci.yml'])\n",
    )
    f = check_no_retired_trigger_patterns(tmp_path)
    assert any(x["rule_id"] == "PIPE-008" for x in f)


# --- XSTACK-001 (narrowed) ----------------------------------------------------


def test_xstack001_python_flags_missing_dep(tmp_path: Path) -> None:
    _write(tmp_path, "pyproject.toml", "[project]\nname=x\n")
    f = check_shared_library_used(tmp_path, language="python")
    assert any(x["rule_id"] == "XSTACK-001" for x in f)


def test_xstack001_python_passes_when_dep_declared(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "pyproject.toml",
        "[project]\nname=x\ndependencies=['common-python-utils']\n",
    )
    assert check_shared_library_used(tmp_path, language="python") == []


def test_xstack001_ts_hand_rolled_ok_when_dep_declared(tmp_path: Path) -> None:
    pkg = {"name": "x", "dependencies": {"common-typescript-utils": "1.0.0"}}
    _write(tmp_path, "package.json", json.dumps(pkg))
    _write(tmp_path, "src/index.ts", "function createLogger() { return console }\n")
    assert check_shared_library_used(tmp_path, language="typescript") == []


def test_xstack001_ts_workspace_root_dep_satisfies(tmp_path: Path) -> None:
    _write(tmp_path, "package.json", '{"name":"x","dependencies":{}}\n')
    ws = '{"dependencies":{"common-typescript-utils":"1.0.0"}}'
    assert (
        check_shared_library_used(
            tmp_path, language="typescript", workspace_package_json_text=ws
        )
        == []
    )


# --- TEST-011 -----------------------------------------------------------------


def test_test_011_accepts_assert_not_called(tmp_path: Path) -> None:
    """TEST-011: assert_not_called() is a valid assertion."""
    from evaluator_cog.engine.deterministic import check_mock_assertions

    tests_dir = tmp_path / "tests"
    tests_dir.mkdir()
    (tests_dir / "test_x.py").write_text(
        "from unittest.mock import MagicMock\n"
        "\n"
        "def test_a():\n"
        "    m = MagicMock()\n"
        "    m.do.assert_not_called()\n"
    )
    assert check_mock_assertions(tmp_path) == []


def test_test_011_accepts_call_count(tmp_path: Path) -> None:
    """TEST-011: .call_count comparisons count as assertions."""
    from evaluator_cog.engine.deterministic import check_mock_assertions

    tests_dir = tmp_path / "tests"
    tests_dir.mkdir()
    (tests_dir / "test_x.py").write_text(
        "from unittest.mock import MagicMock\n"
        "\n"
        "def test_a():\n"
        "    m = MagicMock()\n"
        "    m.do()\n"
        "    m.do()\n"
        "    assert m.do.call_count == 2\n"
    )
    assert check_mock_assertions(tmp_path) == []


def test_test_011_still_flags_unverified_mock(tmp_path: Path) -> None:
    """TEST-011: mocks without any interrogation still get flagged."""
    from evaluator_cog.engine.deterministic import check_mock_assertions

    tests_dir = tmp_path / "tests"
    tests_dir.mkdir()
    (tests_dir / "test_x.py").write_text(
        "from unittest.mock import MagicMock\n"
        "\n"
        "def test_a():\n"
        "    m = MagicMock()\n"
        "    m.do()\n"
        "    assert True\n"
    )
    findings = check_mock_assertions(tmp_path)
    assert len(findings) == 1


# --- PIPE-006 -----------------------------------------------------------------


def test_pipe_006_accepts_repo_local_wrapper(tmp_path: Path) -> None:
    """PIPE-006: flows calling a repo-local logger wrapper are accepted."""
    from evaluator_cog.engine.deterministic import check_prefect_run_logger

    src = tmp_path / "src" / "mycog"
    src.mkdir(parents=True)
    (src / "helpers.py").write_text(
        "import logging\n"
        "from prefect import get_run_logger\n"
        "\n"
        "_log = logging.getLogger(__name__)\n"
        "\n"
        "def get_prefect_logger():\n"
        "    try:\n"
        "        return get_run_logger()\n"
        "    except Exception:\n"
        "        return _log\n"
    )
    (src / "flow_mod.py").write_text(
        "from prefect import flow\n"
        "from .helpers import get_prefect_logger\n"
        "\n"
        "@flow\n"
        "def my_flow():\n"
        "    logger = get_prefect_logger()\n"
        "    logger.info('hello')\n"
    )
    assert check_prefect_run_logger(tmp_path) == []


def test_pipe_006_flags_flow_with_no_logger(tmp_path: Path) -> None:
    """PIPE-006: flows with no logger acquisition still flagged."""
    from evaluator_cog.engine.deterministic import check_prefect_run_logger

    src = tmp_path / "src" / "mycog"
    src.mkdir(parents=True)
    (src / "flow_mod.py").write_text(
        "from prefect import flow\n\n@flow\ndef my_flow():\n    print('hello')\n"
    )
    assert len(check_prefect_run_logger(tmp_path)) == 1


def test_pipe_006_does_not_accept_logger_function_without_run_logger(
    tmp_path: Path,
) -> None:
    """PIPE-006: get_logger without get_run_logger is not a wrapper."""
    from evaluator_cog.engine.deterministic import check_prefect_run_logger

    src = tmp_path / "src" / "mycog"
    src.mkdir(parents=True)
    (src / "helpers.py").write_text(
        "import logging\n\ndef get_logger():\n    return logging.getLogger(__name__)\n"
    )
    (src / "flow_mod.py").write_text(
        "from prefect import flow\n"
        "from .helpers import get_logger\n"
        "\n"
        "@flow\n"
        "def my_flow():\n"
        "    logger = get_logger()\n"
        "    logger.info('hello')\n"
    )
    assert len(check_prefect_run_logger(tmp_path)) == 1


# --- CD-015 -------------------------------------------------------------------


def test_cd_015_accepts_from_prefect_import_serve(tmp_path: Path) -> None:
    """CD-015: `from prefect import serve` then `serve(...)` is accepted."""
    from evaluator_cog.engine.deterministic import check_prefect_serve_pattern

    src = tmp_path / "src" / "mycog"
    src.mkdir(parents=True)
    (src / "main.py").write_text(
        "from prefect import serve\n"
        "from .flow_mod import my_flow\n"
        "\n"
        "def main():\n"
        "    serve(my_flow.to_deployment(name='x'))\n"
    )
    warn_findings = [
        f for f in check_prefect_serve_pattern(tmp_path) if f.get("severity") == "WARN"
    ]
    assert warn_findings == []


def test_cd_015_still_warns_when_no_serve(tmp_path: Path) -> None:
    """CD-015: repo with no serve() call at all is still flagged."""
    from evaluator_cog.engine.deterministic import check_prefect_serve_pattern

    src = tmp_path / "src" / "mycog"
    src.mkdir(parents=True)
    (src / "main.py").write_text("def main(): pass\n")
    warn_findings = [
        f for f in check_prefect_serve_pattern(tmp_path) if f.get("severity") == "WARN"
    ]
    assert len(warn_findings) == 1


def test_cd_015_still_catches_work_pool(tmp_path: Path) -> None:
    """CD-015: flow.deploy() and work_pool_name still flagged as incompatible."""
    from evaluator_cog.engine.deterministic import check_prefect_serve_pattern

    src = tmp_path / "src" / "mycog"
    src.mkdir(parents=True)
    (src / "main.py").write_text(
        "def main():\n    flow.deploy(work_pool_name='default')\n"
    )
    errors = [
        f for f in check_prefect_serve_pattern(tmp_path) if f.get("severity") == "ERROR"
    ]
    assert len(errors) >= 1


# --- API-008 ------------------------------------------------------------------


def test_api_008_accepts_intentionally_public_in_description(tmp_path: Path) -> None:
    """API-008: routes with 'intentionally public' in description= are exempt."""
    from evaluator_cog.engine.deterministic import check_unauthenticated_routes

    src = tmp_path / "src"
    src.mkdir()
    (src / "main.py").write_text(
        "from fastapi import FastAPI\n"
        "app = FastAPI()\n"
        "\n"
        "@app.get('/version', description='Reports version. Intentionally public.')\n"
        "async def version() -> dict:\n"
        "    return {'version': '1'}\n"
    )
    assert check_unauthenticated_routes(tmp_path, language="python") == []


def test_api_008_accepts_intentionally_public_in_docstring(tmp_path: Path) -> None:
    """API-008: routes with 'intentionally public' in docstring are exempt."""
    from evaluator_cog.engine.deterministic import check_unauthenticated_routes

    src = tmp_path / "src"
    src.mkdir()
    (src / "main.py").write_text(
        "from fastapi import FastAPI\n"
        "app = FastAPI()\n"
        "\n"
        "@app.get('/')\n"
        "async def root() -> dict:\n"
        "    '''Redirect. Intentionally public.'''\n"
        "    return {}\n"
    )
    assert check_unauthenticated_routes(tmp_path, language="python") == []


def test_api_008_still_flags_unmarked_public_route(tmp_path: Path) -> None:
    """API-008: routes with no auth and no intent marker still flagged."""
    from evaluator_cog.engine.deterministic import check_unauthenticated_routes

    src = tmp_path / "src"
    src.mkdir()
    (src / "main.py").write_text(
        "from fastapi import FastAPI\n"
        "app = FastAPI()\n"
        "\n"
        "@app.get('/secret')\n"
        "async def secret() -> dict:\n"
        "    return {'data': 'leak'}\n"
    )
    findings = check_unauthenticated_routes(tmp_path, language="python")
    assert len(findings) == 1


def test_api_008_accepts_depends(tmp_path: Path) -> None:
    """API-008: routes with Depends() unchanged."""
    from evaluator_cog.engine.deterministic import check_unauthenticated_routes

    src = tmp_path / "src"
    src.mkdir()
    (src / "main.py").write_text(
        "from fastapi import FastAPI, Depends\n"
        "app = FastAPI()\n"
        "\n"
        "def verify(): pass\n"
        "\n"
        "@app.get('/protected')\n"
        "async def protected(user=Depends(verify)) -> dict:\n"
        "    return {}\n"
    )
    assert check_unauthenticated_routes(tmp_path, language="python") == []


# --- CD-010 --------------------------------------------------------------------


def test_cd_010_typescript_accepts_sentry_node(tmp_path: Path) -> None:
    """CD-010: TS service with @sentry/node + common-typescript-utils passes."""
    from evaluator_cog.engine.deterministic import check_three_layer_observability

    src = tmp_path / "src"
    src.mkdir()
    (src / "app.ts").write_text(
        'import * as Sentry from "@sentry/node";\n'
        'import { createLogger } from "common-typescript-utils";\n'
        "Sentry.init({ dsn: process.env.SENTRY_DSN });\n"
        'const logger = createLogger("app");\n'
    )
    (tmp_path / ".env.example").write_text("SENTRY_DSN=\n")
    (tmp_path / "package.json").write_text(
        '{"dependencies": {"@sentry/node": "^10.0.0", "common-typescript-utils": "^1.0.0"}}'
    )
    findings = check_three_layer_observability(
        tmp_path, cog_subtype=None, language="typescript"
    )
    layer_errors = [f for f in findings if "Layer" in f["finding"]]
    assert layer_errors == []


def test_cd_010_typescript_flags_missing_sentry(tmp_path: Path) -> None:
    """CD-010: TS service without @sentry/* is flagged at Layer 3."""
    from evaluator_cog.engine.deterministic import check_three_layer_observability

    src = tmp_path / "src"
    src.mkdir()
    (src / "app.ts").write_text(
        'import { createLogger } from "common-typescript-utils";\n'
    )
    (tmp_path / ".env.example").write_text("")
    (tmp_path / "package.json").write_text(
        '{"dependencies": {"common-typescript-utils": "^1.0.0"}}'
    )
    findings = check_three_layer_observability(
        tmp_path, cog_subtype=None, language="typescript"
    )
    assert any("Layer 3" in f["finding"] for f in findings)


def test_cd_010_python_unchanged(tmp_path: Path) -> None:
    """CD-010: Python path still works as before."""
    from evaluator_cog.engine.deterministic import check_three_layer_observability

    src = tmp_path / "src"
    src.mkdir()
    (src / "main.py").write_text(
        "import sentry_sdk\n"
        "from mini_app_polis.logger import get_logger\n"
        "sentry_sdk.init()\n"
    )
    (tmp_path / ".env.example").write_text("SENTRY_DSN=\n")
    findings = check_three_layer_observability(
        tmp_path, cog_subtype=None, language="python"
    )
    assert findings == []


# --- XSTACK-002 (TS exclusions) ------------------------------------------------


def test_xstack_002_skips_src_test_directory(tmp_path: Path) -> None:
    """XSTACK-002: files under src/test/ are not flagged."""
    src = tmp_path / "src" / "test"
    src.mkdir(parents=True)
    (src / "mocks.ts").write_text(
        "export function mockHandler(c) {\n  return c.json({ ok: true });\n}\n"
    )
    assert check_response_shape_parity(tmp_path, language="typescript") == []


def test_xstack_002_skips_dot_test_files(tmp_path: Path) -> None:
    """XSTACK-002: *.test.ts files are not flagged."""
    src = tmp_path / "src" / "routes"
    src.mkdir(parents=True)
    (src / "songs.test.ts").write_text(
        'test("x", () => {\n  c.json({ data: [] });\n});\n'
    )
    assert check_response_shape_parity(tmp_path, language="typescript") == []


def test_xstack_002_still_flags_production_handler(tmp_path: Path) -> None:
    """XSTACK-002: real production handlers using raw c.json still flagged."""
    src = tmp_path / "src" / "routes"
    src.mkdir(parents=True)
    (src / "songs.ts").write_text(
        "export function handler(c) {\n  return c.json({ ok: true });\n}\n"
    )
    findings = check_response_shape_parity(tmp_path, language="typescript")
    assert len(findings) == 1
