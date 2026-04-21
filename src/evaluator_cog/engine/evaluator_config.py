"""evaluator_config.py

Loads and validates a repo's evaluator.yaml file (ADR-001, ADR-002).

The evaluator.yaml lives at the root of each repo and declares:
  - type: repo type (pipeline-cog, trigger-cog, api-service, etc.)
  - traits: optional list of composable flags (logger-primitive, cloudflare-pages, etc.)
  - exemptions: rules that genuinely do not apply, with required reason strings
  - deferrals: rules that apply but are not currently prioritized

This module is the single point of truth for reading that config.
It falls back gracefully when evaluator.yaml is absent (migration period).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path

import yaml

log = logging.getLogger(__name__)

# Valid repo types per index.yaml schema.repo_types (v3.0.0)
VALID_REPO_TYPES = {
    "pipeline-cog",
    "trigger-cog",
    "api-service",
    "shared-library",
    "static-site",
    "react-app",
    "standards-repo",
    "evaluator-service",
}

# Valid traits per index.yaml schema.traits (v3.0.0)
VALID_TRAITS = {
    "logger-primitive",
    "cloudflare-pages",
    "multi-flow",
    "pipeline-cog-evaluator",
    "pre-rule",
}

# Rules automatically excepted by trait
_TRAIT_AUTO_EXCEPTIONS: dict[str, set[str]] = {
    "logger-primitive": {"CD-009", "XSTACK-001"},
    "cloudflare-pages": {"VER-003", "VER-005", "VER-006"},
    "multi-flow": {"CD-015"},
    "pipeline-cog-evaluator": {"PIPE-011"},
    "pre-rule": set(),
}


# One-shot warning latch — when an EvaluatorConfig is constructed without
# a catalog (rule_applies_to unset), type-based auto-exceptions cannot be
# derived and only trait exceptions + explicit exemptions apply. We warn
# once per process so tests and migration-period callers don't spam logs.
_WARNED_NO_CATALOG = False


def _warn_once_no_catalog() -> None:
    global _WARNED_NO_CATALOG
    if _WARNED_NO_CATALOG:
        return
    _WARNED_NO_CATALOG = True
    log.warning(
        "evaluator_config: EvaluatorConfig constructed without a catalog "
        "(rule_applies_to unset) — type-based auto-exceptions disabled, "
        "only trait exceptions and explicit exemptions apply. This is "
        "expected in unit tests; a warning in production indicates the "
        "catalog fetch failed."
    )


@dataclass
class EvaluatorConfig:
    """Parsed and validated contents of a repo's evaluator.yaml.

    When `rule_applies_to` is provided (a dict mapping rule_id -> the rule's
    applies_to list from the standards catalog), `all_skipped_ids` derives
    type-based auto-exceptions at runtime: any checkable rule whose
    applies_to list does not include this repo type (and does not include
    'all') is skipped. When the catalog is absent, only trait exceptions
    and explicit exemptions apply, and a one-time warning is logged.
    """

    repo_type: str
    traits: list[str] = field(default_factory=list)
    exemption_ids: list[str] = field(default_factory=list)
    exemption_reasons: dict[str, str] = field(default_factory=dict)
    deferral_ids: list[str] = field(default_factory=list)
    deferral_reasons: dict[str, str] = field(default_factory=dict)
    source: str = "evaluator.yaml"
    rule_applies_to: dict[str, list[str]] | None = None

    @property
    def all_skipped_ids(self) -> frozenset[str]:
        """Return the full set of rule IDs the evaluator will skip for this
        repo: type-based (derived from applies_to), trait-based, and
        explicit exemptions declared in evaluator.yaml."""
        skipped: set[str] = set()
        if self.rule_applies_to is not None:
            for rule_id, applies in self.rule_applies_to.items():
                if "all" in applies:
                    continue
                if self.repo_type not in applies:
                    skipped.add(rule_id)
        else:
            _warn_once_no_catalog()
        for trait in self.traits:
            skipped.update(_TRAIT_AUTO_EXCEPTIONS.get(trait, set()))
        skipped.update(self.exemption_ids)
        return frozenset(skipped)

    def is_deferred(self, rule_id: str) -> bool:
        """TODO: describe this function."""
        return rule_id in self.deferral_ids

    def is_skipped(self, rule_id: str) -> bool:
        """TODO: describe this function."""
        return rule_id in self.all_skipped_ids

    @property
    def language(self) -> str:
        """TODO: describe this function."""
        if self.repo_type in (
            "pipeline-cog",
            "trigger-cog",
            "api-service",
            "shared-library",
            "standards-repo",
            "evaluator-service",
        ):
            return "python"
        return "typescript"

    @property
    def is_python_service(self) -> bool:
        """TODO: describe this function."""
        return self.repo_type in (
            "pipeline-cog",
            "trigger-cog",
            "api-service",
            "shared-library",
            "evaluator-service",
        )

    @property
    def is_pipeline_cog(self) -> bool:
        """TODO: describe this function."""
        return self.repo_type == "pipeline-cog"

    @property
    def is_evaluator_service(self) -> bool:
        """TODO: describe this function."""
        return self.repo_type == "evaluator-service"

    @property
    def is_pipeline_style(self) -> bool:
        """
        True for types that run Prefect flows and carry pipeline-shaped
        rule applicability (tests for normalization/dedup, retry logic,
        prefect.serve pattern, etc.). Distinct from `is_pipeline_cog`,
        which answers the narrower "is this specifically the pipeline-cog
        type?" question. Engine branches that ask the broader question
        should prefer this property so that new pipeline-style types
        (currently just `evaluator-service`) inherit the same checks
        without broadening the semantics of `is_pipeline_cog`.
        """
        return self.repo_type in ("pipeline-cog", "evaluator-service")

    @property
    def is_trigger_cog(self) -> bool:
        """TODO: describe this function."""
        return self.repo_type == "trigger-cog"

    @property
    def is_api_service(self) -> bool:
        """TODO: describe this function."""
        return self.repo_type == "api-service"

    @property
    def is_shared_library(self) -> bool:
        """TODO: describe this function."""
        return self.repo_type == "shared-library"

    @property
    def is_static_site(self) -> bool:
        """TODO: describe this function."""
        return self.repo_type == "static-site"

    @property
    def is_react_app(self) -> bool:
        """TODO: describe this function."""
        return self.repo_type == "react-app"

    @property
    def is_standards_repo(self) -> bool:
        """TODO: describe this function."""
        return self.repo_type == "standards-repo"

    @property
    def is_frontend(self) -> bool:
        """TODO: describe this function."""
        return self.repo_type in ("static-site", "react-app")


def load_evaluator_config(
    repo_path: Path,
    *,
    fallback_type: str | None = None,
    fallback_exceptions: list[str] | None = None,
    fallback_exception_reasons: dict[str, str] | None = None,
    rule_applies_to: dict[str, list[str]] | None = None,
) -> EvaluatorConfig:
    """Load and return the EvaluatorConfig for a repo.

    Reads evaluator.yaml from repo_path if present; falls back to a config
    derived from the provided fallback_type and exception lists if absent or
    unparseable. Never raises.

    `rule_applies_to`, when provided, is attached to the returned
    EvaluatorConfig so `all_skipped_ids` can derive type-based skips from
    the live catalog. When absent, only trait and explicit exemptions apply.
    """
    evaluator_yaml = repo_path / "evaluator.yaml"

    if evaluator_yaml.exists():
        try:
            raw = yaml.safe_load(evaluator_yaml.read_text()) or {}
            cfg = _parse_evaluator_yaml(raw, source="evaluator.yaml")
            cfg.rule_applies_to = rule_applies_to
            return cfg
        except Exception as exc:
            log.warning(
                "evaluator_config: failed to parse evaluator.yaml at %s: %s — falling back",
                repo_path,
                exc,
            )

    cfg = _build_fallback_config(
        fallback_type=fallback_type,
        fallback_exceptions=fallback_exceptions or [],
        fallback_exception_reasons=fallback_exception_reasons or {},
    )
    cfg.rule_applies_to = rule_applies_to
    return cfg


def _parse_evaluator_yaml(raw: dict, source: str = "evaluator.yaml") -> EvaluatorConfig:
    repo_type = str(raw.get("type", "")).strip()
    if repo_type not in VALID_REPO_TYPES:
        raise ValueError(
            f"evaluator.yaml: invalid type '{repo_type}'. "
            f"Must be one of: {sorted(VALID_REPO_TYPES)}"
        )

    traits = []
    for t in raw.get("traits", []) or []:
        t = str(t).strip()
        if t in VALID_TRAITS:
            traits.append(t)
        else:
            log.warning("evaluator_config: unknown trait '%s' — ignored", t)

    exemption_ids = []
    exemption_reasons = {}
    for item in raw.get("exemptions", []) or []:
        if not isinstance(item, dict):
            continue
        rule_id = str(item.get("rule", "")).strip()
        reason = str(item.get("reason", "")).strip()
        if rule_id:
            exemption_ids.append(rule_id)
            if reason:
                exemption_reasons[rule_id] = reason

    deferral_ids = []
    deferral_reasons = {}
    for item in raw.get("deferrals", []) or []:
        if not isinstance(item, dict):
            continue
        rule_id = str(item.get("rule", "")).strip()
        reason = str(item.get("reason", "")).strip()
        if rule_id:
            deferral_ids.append(rule_id)
            if reason:
                deferral_reasons[rule_id] = reason

    return EvaluatorConfig(
        repo_type=repo_type,
        traits=traits,
        exemption_ids=exemption_ids,
        exemption_reasons=exemption_reasons,
        deferral_ids=deferral_ids,
        deferral_reasons=deferral_reasons,
        source=source,
    )


def _build_fallback_config(
    fallback_type: str | None,
    fallback_exceptions: list[str],
    fallback_exception_reasons: dict[str, str],
) -> EvaluatorConfig:
    repo_type = _map_legacy_type(fallback_type)
    log.info(
        "evaluator_config: evaluator.yaml absent — using fallback type '%s' (from '%s')",
        repo_type,
        fallback_type,
    )
    return EvaluatorConfig(
        repo_type=repo_type,
        traits=[],
        exemption_ids=fallback_exceptions,
        exemption_reasons=fallback_exception_reasons,
        deferral_ids=[],
        deferral_reasons={},
        source="ecosystem.yaml (fallback)",
    )


def _map_legacy_type(legacy: str | None) -> str:
    mapping = {
        "worker": "pipeline-cog",
        "api": "api-service",
        "library": "shared-library",
        "site": "static-site",
        "standards": "standards-repo",
        "new_cog": "pipeline-cog",
        "new_fastapi_service": "api-service",
        "new_hono_service": "api-service",
        "new_frontend_site": "static-site",
        "new_react_app": "react-app",
        "pipeline-cog": "pipeline-cog",
        "trigger-cog": "trigger-cog",
        "api-service": "api-service",
        "shared-library": "shared-library",
        "static-site": "static-site",
        "react-app": "react-app",
        "standards-repo": "standards-repo",
        "evaluator-service": "evaluator-service",
    }
    if legacy is None:
        return "shared-library"
    return mapping.get(str(legacy).strip(), "pipeline-cog")
