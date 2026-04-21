"""Introspection rule checks (EVAL-003, MONO-003, EVAL-007 — drift & data quality)."""

from __future__ import annotations

import re
import re as _re_eval003

from evaluator_cog.engine.deterministic._shared import (
    Finding,
    _finding,
)


def check_eval_003(
    *,
    lookback_days: int = 30,
) -> list[Finding]:
    """EVAL-003: Findings emitted by evaluator-cog must be specific and actionable.

    Reads pipeline_evaluations for findings emitted by evaluator-cog
    internal sources in the last `lookback_days`. The historical source
    name 'conformance_check' is also included so findings stored before
    the conformance_llm / conformance_deterministic / data_quality split
    are still covered by the quality check.
    """
    CHECK_ID = "EVAL-003"
    from mini_app_polis.api import KaianoApiClient

    _eval_003_sources = ",".join(
        [
            "conformance_llm",
            "conformance_deterministic",
            "standards_drift",
            "data_quality",
            # Legacy — pre-rename stored rows still present in the DB.
            "conformance_check",
        ]
    )

    try:
        api = KaianoApiClient.from_env()
        response = api.get(
            f"/v1/evaluations?source={_eval_003_sources}"
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
    """EVAL-007: Standards/evaluator check coverage must be tracked and in sync.

    LLM-routed rules (those with `check_notes` starting with
    `LLM CHECK.`) are excluded from the unimplemented set — they are
    correctly handled on the LLM path and do not require a
    deterministic CHECK_ID constant. Rules whose catalog entry carries
    ``check_mode == "llm"`` are filtered before comparing against
    implemented CHECK_IDs. Catalog entries missing a `check_mode`
    field default to the pre-filter behaviour (treated as
    deterministic), preserving behaviour for tests and legacy
    callers that build rule_catalog dicts by hand.

    A deterministic rule counts as "implemented" if any of the
    following appear in deterministic.py:
      - ``CHECK_ID = "<rule-id>"`` — the canonical constant convention.
      - ``_run(fn, "<rule-id>")`` — dispatch wrapper registration.
      - ``_mark_checked("<rule-id>", ...)`` — manual registration for
        rules whose check logic is inlined rather than wrapped.
    The three are equivalent from EVAL-007's perspective — each
    demonstrates that the evaluator has accepted responsibility for
    the rule. Matching on all three avoids false "unimplemented"
    findings for checks that are wired but don't follow the constant
    convention.
    """
    CHECK_ID = "EVAL-007"
    if not rule_catalog:
        return []

    findings: list[Finding] = []

    import inspect

    this_module_src = inspect.getsource(inspect.getmodule(check_eval_007))

    # CHECK_ID constants (canonical rule registration).
    impl_ids: set[str] = set(
        re.findall(r'CHECK_ID\s*=\s*"([A-Z]+-(?:GAP-)?[0-9A-Z]+)"', this_module_src)
    )
    # _run() dispatch registrations.
    impl_ids.update(
        re.findall(r'_run\([^,]+,\s*"([A-Z]+-(?:GAP-)?[0-9A-Z]+)"', this_module_src)
    )
    # _mark_checked registrations.
    for call_args in re.findall(r"_mark_checked\(([^)]*)\)", this_module_src):
        impl_ids.update(re.findall(r'"([A-Z]+-(?:GAP-)?[0-9A-Z]+)"', call_args))

    # Only deterministic rules require a CHECK_ID constant. LLM rules
    # are dispatched through engine/llm.py and should not be flagged
    # as missing.
    deterministic_ids = {
        rid
        for rid, meta in rule_catalog.items()
        if (meta or {}).get("check_mode", "deterministic") != "llm"
    }

    unimplemented = sorted(deterministic_ids - impl_ids)
    orphaned = sorted(impl_ids - set(rule_catalog.keys()))

    for rid in unimplemented:
        findings.append(
            _finding(
                CHECK_ID,
                "WARN",
                "standards_currency",
                f"Rule {rid} is a deterministic checkable rule in the catalog "
                f"but is not registered in evaluator-cog's deterministic.py "
                f"(no CHECK_ID constant, _run() call, or _mark_checked() "
                f"reference found).",
                f"Add a check function for {rid} and register it via "
                f'_run(check_fn, "{rid}") or declare CHECK_ID = "{rid}".',
            )
        )

    for rid in orphaned:
        findings.append(
            _finding(
                CHECK_ID,
                "ERROR",
                "standards_currency",
                f"Rule {rid} is registered in evaluator-cog's deterministic.py "
                f"but has no matching rule in the catalog (orphaned check).",
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
