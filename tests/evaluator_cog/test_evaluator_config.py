"""Tests for evaluator.yaml loading and EvaluatorConfig (ADR-001 / ADR-002)."""

from __future__ import annotations

from pathlib import Path

import pytest

from evaluator_cog.engine.evaluator_config import (
    EvaluatorConfig,
    _map_legacy_type,
    _parse_evaluator_yaml,
    load_evaluator_config,
)


def test_load_evaluator_config_valid_yaml(tmp_path: Path) -> None:
    """Valid evaluator.yaml yields correct type, traits, exemptions, deferrals."""
    (tmp_path / "evaluator.yaml").write_text(
        """
type: pipeline-cog
traits:
  - logger-primitive
exemptions:
  - rule: DOC-999
    reason: genuinely N/A for this repo
deferrals:
  - rule: DOC-888
    reason: backlog
""".strip()
    )
    cfg = load_evaluator_config(tmp_path)
    assert cfg.repo_type == "pipeline-cog"
    assert cfg.traits == ["logger-primitive"]
    assert cfg.exemption_ids == ["DOC-999"]
    assert cfg.exemption_reasons["DOC-999"] == "genuinely N/A for this repo"
    assert cfg.deferral_ids == ["DOC-888"]
    assert cfg.deferral_reasons["DOC-888"] == "backlog"
    assert cfg.source == "evaluator.yaml"


def test_load_evaluator_config_absent_uses_fallback(tmp_path: Path) -> None:
    """Missing evaluator.yaml uses fallback_type and fallback_exceptions."""
    cfg = load_evaluator_config(
        tmp_path,
        fallback_type="library",
        fallback_exceptions=["FE-001"],
        fallback_exception_reasons={"FE-001": "legacy reason"},
    )
    assert cfg.repo_type == "shared-library"
    assert cfg.traits == []
    assert "FE-001" in cfg.exemption_ids
    assert cfg.exemption_reasons.get("FE-001") == "legacy reason"
    assert cfg.source == "ecosystem.yaml (fallback)"


def test_load_evaluator_config_malformed_yaml_falls_back(tmp_path: Path) -> None:
    """Broken YAML logs and falls back like an absent file."""
    (tmp_path / "evaluator.yaml").write_text("{{not valid yaml::: [[[\n")
    cfg = load_evaluator_config(
        tmp_path,
        fallback_type="api",
        fallback_exceptions=["X-1"],
    )
    assert cfg.repo_type == "api-service"
    assert "X-1" in cfg.exemption_ids
    assert cfg.source == "ecosystem.yaml (fallback)"


def test_parse_evaluator_yaml_invalid_type_raises() -> None:
    with pytest.raises(ValueError, match="invalid type"):
        _parse_evaluator_yaml({"type": "not-a-valid-type"})


def test_parse_evaluator_yaml_unknown_trait_warns(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Unknown traits are ignored with a warning (no exception)."""
    with caplog.at_level("WARNING"):
        cfg = _parse_evaluator_yaml(
            {"type": "pipeline-cog", "traits": ["not-a-real-trait"]}
        )
    assert cfg.traits == []
    assert any("unknown trait" in r.message for r in caplog.records)


def test_all_skipped_ids_shared_library_with_catalog() -> None:
    """With a catalog, type-based skips come from applies_to."""
    catalog = {
        # applies_to excludes shared-library -> skipped
        "CD-002": ["pipeline-cog", "trigger-cog", "api-service", "react-app"],
        "TEST-001": ["pipeline-cog", "api-service"],
        "TEST-007": ["pipeline-cog", "api-service"],
        # applies_to includes shared-library -> NOT skipped
        "PY-006": ["pipeline-cog", "api-service", "shared-library"],
        "XSTACK-001": [
            "pipeline-cog",
            "trigger-cog",
            "api-service",
            "react-app",
            "shared-library",
        ],
        # applies_to='all' -> NEVER skipped
        "DOC-001": ["all"],
    }
    cfg = EvaluatorConfig(repo_type="shared-library", rule_applies_to=catalog)
    skipped = cfg.all_skipped_ids
    assert {"CD-002", "TEST-001", "TEST-007"} <= skipped
    assert "PY-006" not in skipped
    assert "XSTACK-001" not in skipped
    assert "DOC-001" not in skipped


def test_all_skipped_ids_static_site_cloudflare_trait() -> None:
    cfg = EvaluatorConfig(repo_type="static-site", traits=["cloudflare-pages"])
    skipped = cfg.all_skipped_ids
    assert {"VER-003", "VER-005", "VER-006"} <= skipped


def test_all_skipped_ids_pipeline_cog_no_catalog_empty() -> None:
    """Without a catalog, a pipeline-cog has no type auto-exceptions."""
    cfg = EvaluatorConfig(repo_type="pipeline-cog")
    assert cfg.all_skipped_ids == frozenset()


def test_all_skipped_ids_pipeline_cog_with_catalog_skips_non_applicable() -> None:
    """With a catalog, pipeline-cog skips rules whose applies_to excludes it."""
    catalog = {
        "FE-001": ["static-site"],  # skipped
        "API-001": ["api-service"],  # skipped
        "PIPE-001": ["pipeline-cog", "trigger-cog"],  # NOT skipped
        "DOC-001": ["all"],  # NOT skipped
    }
    cfg = EvaluatorConfig(repo_type="pipeline-cog", rule_applies_to=catalog)
    skipped = cfg.all_skipped_ids
    assert "FE-001" in skipped
    assert "API-001" in skipped
    assert "PIPE-001" not in skipped
    assert "DOC-001" not in skipped


def test_all_skipped_ids_api_service_with_catalog() -> None:
    catalog = {
        "CD-015": ["pipeline-cog", "trigger-cog"],  # applies_to excludes api-service
    }
    cfg = EvaluatorConfig(repo_type="api-service", rule_applies_to=catalog)
    assert "CD-015" in cfg.all_skipped_ids


def test_is_deferred() -> None:
    cfg = EvaluatorConfig(
        repo_type="pipeline-cog",
        deferral_ids=["CD-003"],
        deferral_reasons={"CD-003": "later"},
    )
    assert cfg.is_deferred("CD-003") is True
    assert cfg.is_deferred("DOC-001") is False


def test_is_skipped_auto_and_explicit() -> None:
    catalog = {
        "CD-002": ["pipeline-cog", "trigger-cog", "api-service", "react-app"],
        "DOC-001": ["all"],
    }
    cfg = EvaluatorConfig(
        repo_type="shared-library",
        exemption_ids=["FE-777"],
        exemption_reasons={"FE-777": "custom"},
        rule_applies_to=catalog,
    )
    assert cfg.is_skipped("CD-002") is True  # catalog says not for shared-library
    assert cfg.is_skipped("FE-777") is True  # explicit exemption
    assert cfg.is_skipped("DOC-001") is False  # applies to all


@pytest.mark.parametrize(
    ("legacy", "expected"),
    [
        ("new_cog", "pipeline-cog"),
        ("new_fastapi_service", "api-service"),
        ("new_hono_service", "api-service"),
        ("new_frontend_site", "static-site"),
        ("new_react_app", "react-app"),
        ("worker", "pipeline-cog"),
        ("api", "api-service"),
        ("library", "shared-library"),
        ("site", "static-site"),
        ("standards", "standards-repo"),
        ("pipeline-cog", "pipeline-cog"),
        ("trigger-cog", "trigger-cog"),
        ("api-service", "api-service"),
        ("shared-library", "shared-library"),
        ("static-site", "static-site"),
        ("react-app", "react-app"),
        ("standards-repo", "standards-repo"),
        ("evaluator-service", "evaluator-service"),
        (None, "shared-library"),
        ("unknown-legacy-value", "pipeline-cog"),
    ],
)
def test_map_legacy_type(legacy: str | None, expected: str) -> None:
    assert _map_legacy_type(legacy) == expected


@pytest.mark.parametrize(
    (
        "repo_type",
        "pipeline",
        "trigger",
        "api",
        "shared",
        "static",
        "react",
        "std",
        "front",
    ),
    [
        ("pipeline-cog", True, False, False, False, False, False, False, False),
        ("trigger-cog", False, True, False, False, False, False, False, False),
        ("api-service", False, False, True, False, False, False, False, False),
        ("shared-library", False, False, False, True, False, False, False, False),
        ("static-site", False, False, False, False, True, False, False, True),
        ("react-app", False, False, False, False, False, True, False, True),
        ("standards-repo", False, False, False, False, False, False, True, False),
        # evaluator-service shares no narrow boolean with any of the others — it
        # is its own category. is_pipeline_style coverage lives in a dedicated
        # test below.
        ("evaluator-service", False, False, False, False, False, False, False, False),
    ],
)
def test_evaluator_config_boolean_properties(
    repo_type: str,
    pipeline: bool,
    trigger: bool,
    api: bool,
    shared: bool,
    static: bool,
    react: bool,
    std: bool,
    front: bool,
) -> None:
    cfg = EvaluatorConfig(repo_type=repo_type)
    assert cfg.is_pipeline_cog is pipeline
    assert cfg.is_trigger_cog is trigger
    assert cfg.is_api_service is api
    assert cfg.is_shared_library is shared
    assert cfg.is_static_site is static
    assert cfg.is_react_app is react
    assert cfg.is_standards_repo is std
    assert cfg.is_frontend is front


def test_language_property_returns_typescript_for_non_python_types() -> None:
    """Repo types that are not Python services return 'typescript' from .language."""
    for repo_type in ("react-app", "static-site", "frontend"):
        cfg = EvaluatorConfig(repo_type=repo_type)
        assert cfg.language == "typescript", (
            f"Expected 'typescript' for repo_type={repo_type!r}, got {cfg.language!r}"
        )


def test_is_evaluator_service_is_strict() -> None:
    """is_evaluator_service is True only for the evaluator-service type."""
    assert EvaluatorConfig(repo_type="evaluator-service").is_evaluator_service is True
    for other in (
        "pipeline-cog",
        "trigger-cog",
        "api-service",
        "shared-library",
        "static-site",
        "react-app",
        "standards-repo",
    ):
        assert EvaluatorConfig(repo_type=other).is_evaluator_service is False


def test_is_pipeline_style_covers_pipeline_cog_and_evaluator_service() -> None:
    """
    is_pipeline_style is the engine-level predicate meaning "runs Prefect
    flows and carries pipeline-cog-shaped rule applicability." It must
    return True for both pipeline-cog and evaluator-service, and False
    for every other type — otherwise pipeline rules leak to non-pipeline
    repos or miss evaluator-service.
    """
    assert EvaluatorConfig(repo_type="pipeline-cog").is_pipeline_style is True
    assert EvaluatorConfig(repo_type="evaluator-service").is_pipeline_style is True
    for other in (
        "trigger-cog",
        "api-service",
        "shared-library",
        "static-site",
        "react-app",
        "standards-repo",
    ):
        assert EvaluatorConfig(repo_type=other).is_pipeline_style is False


def test_evaluator_service_is_python_service_and_language() -> None:
    """evaluator-service is a Python service and reports language='python'."""
    cfg = EvaluatorConfig(repo_type="evaluator-service")
    assert cfg.is_python_service is True
    assert cfg.language == "python"


def test_evaluator_service_no_catalog_trait_only() -> None:
    """Without a catalog, evaluator-service has only trait/explicit skips."""
    cfg = EvaluatorConfig(repo_type="evaluator-service")
    assert cfg.all_skipped_ids == frozenset()


def test_evaluator_service_with_catalog_derives_from_applies_to() -> None:
    """With a catalog, evaluator-service skips rules whose applies_to
    does not list it — consistent with the repo owner's standing ruling
    that ecosystem-standards is always authoritative."""
    catalog = {
        # applies_to lists evaluator-service -> NOT skipped
        "EVAL-003": ["evaluator-service"],
        "MONO-003": ["evaluator-service"],
        # applies_to excludes evaluator-service -> skipped
        "API-001": ["api-service"],
        "FE-001": ["static-site"],
        "PIPE-001": ["pipeline-cog", "trigger-cog"],
        # applies_to='all' -> NOT skipped
        "DOC-001": ["all"],
    }
    cfg = EvaluatorConfig(repo_type="evaluator-service", rule_applies_to=catalog)
    skipped = cfg.all_skipped_ids
    assert "EVAL-003" not in skipped
    assert "MONO-003" not in skipped
    assert "API-001" in skipped
    assert "FE-001" in skipped
    assert "PIPE-001" in skipped
    assert "DOC-001" not in skipped


def test_load_evaluator_yaml_accepts_evaluator_service_type(tmp_path: Path) -> None:
    """A fresh evaluator.yaml declaring type: evaluator-service parses cleanly."""
    (tmp_path / "evaluator.yaml").write_text("type: evaluator-service\n")
    cfg = load_evaluator_config(tmp_path)
    assert cfg.repo_type == "evaluator-service"
    assert cfg.is_evaluator_service is True
    assert cfg.is_pipeline_style is True
