"""Pipeline evaluation flow — post-run AI assessment and Prefect webhook handling.

Note: this module is NOT registered as a Prefect deployment in main.py.
`evaluate_pipeline_run` is called directly (in-process) by other cogs at the
end of their flows, and `handle_prefect_flow_run_event` is invoked via the
Prefect Cloud automation webhook. There is no scheduled or queued execution of
this module — it is a library called by other services and by the webhook
handler embedded in conformance_check_flow.

TODO (May 2026): deprecate this entire module.
---------------------------------------------
Cogs now self-report pipeline_consistency findings directly via
``mini_app_polis.pipeline_status.post_run_finding`` /
``post_findings`` (single library, Clerk M2M auth, best-effort
semantics, severity preserved verbatim, no LLM round-trip). The two
remaining responsibilities of this module — `evaluate_pipeline_run`'s
LLM scoring of CSV/collection runs and `handle_prefect_flow_run_event`'s
webhook fallback — are both redundant once every cog reports through
the library:

  - The LLM-scoring path predates the self-report API. With cogs now
    posting their own SUCCESS/WARN/ERROR with concrete counter context,
    the LLM's job here is duplicate work that adds latency, cost, and
    one more thing that can drift.
  - The webhook fallback was useful when a cog could die before
    reaching its own end-of-run report. With the failure hooks
    (`make_failure_hook` in mini_app_polis.pipeline_status) wired into
    every production flow's on_failure / on_crashed, the webhook path
    is also redundant for any cog using the library.

Plan, in order:

  1. Confirm every production flow in the fleet (deejay-cog,
     transcription-cog) is wired through the library shim with a
     failure hook. Done.
  2. Stand the webhook automation in Prefect Cloud down (or repoint it
     at a no-op endpoint) so `handle_prefect_flow_run_event` stops
     receiving traffic.
  3. Delete `evaluate_pipeline_run`, `handle_prefect_flow_run_event`,
     `_FLOW_REPO_MAP`, `_flow_name_to_repo`, and the rest of this file.
     Drop the unused dependency on `evaluator_cog.engine.llm._build_prompt_*`.
  4. Strip evaluator-cog tests for this module (test_webhook.py and
     the `_flow_name_to_repo` block of test_llm.py).
  5. Remove evaluator-cog as a runtime dependency of any cog that no
     longer needs it — only conformance-checking remains.

See ecosystem-standards/BACKLOG.md (#pipeline-eval-deprecation) for
the tracked work item.
"""

from __future__ import annotations

import functools
import json
import os
from collections.abc import Iterable
from typing import Any
from urllib.request import urlopen

from mini_app_polis import logger as logger_mod

from evaluator_cog.engine import llm as llm_engine
from evaluator_cog.engine.api_client import post_findings

log = logger_mod.get_logger()

_STANDARDS_VERSION_URL = os.environ.get(
    "ECOSYSTEM_STANDARDS_VERSION_URL",
    "https://raw.githubusercontent.com/mini-app-polis/ecosystem-standards/main/package.json",
)


@functools.lru_cache(maxsize=1)
def _fetch_current_standards_version() -> str:
    """
    Fetch the current standards version from ecosystem-standards/package.json.
    Cached for process lifetime. Returns 'unknown' on any fetch or parse
    failure — findings will land with standards_version='unknown' rather
    than a stale hardcoded value.
    """
    try:
        _timeout = int(os.environ.get("EVALUATOR_HTTP_TIMEOUT_SECONDS", "10"))
        with urlopen(_STANDARDS_VERSION_URL, timeout=_timeout) as resp:
            data = json.loads(resp.read())
        version = data.get("version") if isinstance(data, dict) else None
        if isinstance(version, str) and version.strip():
            return version.strip()
        return "unknown"
    except Exception:
        log.warning("Could not fetch standards version from %s", _STANDARDS_VERSION_URL)
        return "unknown"


def _resolve_standards_version() -> str:
    """
    Prefer STANDARDS_VERSION env var (explicit override), then fall back
    to fetching from package.json, then to 'unknown'.
    """
    override = os.environ.get("STANDARDS_VERSION", "").strip()
    if override:
        return override
    return _fetch_current_standards_version()


# Maps Prefect flow names (from @flow(name=...) decorators) to ecosystem
# repo IDs. Used by the prefect_webhook handler to attribute findings
# to the correct repo in pipeline_evaluations. The inline helper path
# (deejay-cog/_pipeline_eval.post_run_finding) stamps repo directly and
# does not consult this map — this map exists for the webhook-only path,
# where the repo is not carried in the Prefect event payload.
#
# Include every flow that MIGHT produce a webhook event, including
# local-only or WIP flows. Missing entries fall through to "unknown"
# and produce findings with repo="unknown" in Pipeline Health.
_FLOW_REPO_MAP: dict[str, str] = {
    # evaluator-cog flows
    "conformance-check": "evaluator-cog",
    "pipeline-eval": "evaluator-cog",
    # transcription-cog flows (May 2026: merged from the standalone
    # notes-ingest-cog and voicenotes-cog repos; see ADR-004 in
    # transcription-cog). All three production flow names below ship in
    # one Railway service under the unified transcription-cog repo
    # identifier; the router flow's own name is also included so a
    # webhook event for the router itself doesn't fall through to
    # "unknown".
    "transcription-cog": "transcription-cog",
    "process-transcript": "transcription-cog",
    "voicenotes-ingest": "transcription-cog",
    "voicenotes-cleanup": "transcription-cog",
    # deejay-cog flows (production)
    "process-new-csv-files": "deejay-cog",
    "ingest-live-history": "deejay-cog",
    # deejay-cog flows (local-only; kept in map for correct attribution if ever seen)
    "generate-summaries": "deejay-cog",
    "update-dj-set-collection": "deejay-cog",
    # deejay-cog flows (WIP, not served in production)
    "retag-music": "deejay-cog",
}

_UNKNOWN_REPO = "unknown"


def _flow_name_to_repo(flow_name: str) -> str:
    """Map a Prefect flow name to its ecosystem repo id.

    Returns 'unknown' for flow names not in the map so that findings are
    attributed visibly rather than silently misattributed to a known repo.
    Add new entries to _FLOW_REPO_MAP when new cogs are deployed.
    """
    return _FLOW_REPO_MAP.get(flow_name, _UNKNOWN_REPO)


def evaluate_pipeline_run(
    *,
    run_id: str,
    repo: str,
    sets_imported: int,
    sets_failed: int,
    sets_skipped: int,
    total_tracks: int,
    failed_set_labels: list[str],
    api_ingest_success: bool,
    sets_attempted: int = 0,
    collection_update: bool = False,
    unrecognized_filename_skips: int = 0,
    duplicate_csv_count: int = 0,
    direct_finding_text: str | None = None,
    direct_severity: str | None = None,
    folders_processed: int = 0,
    tabs_written: int = 0,
    total_sets: int = 0,
    json_snapshot_written: bool = False,
    folder_names: list[str] | None = None,
    flow_name: str | None = None,
    source: str = "flow_inline",
) -> None:
    """Call Claude, then POST each finding to KAIANO_API_BASE_URL /v1/evaluations.

    Never raises — logs and returns on any failure.
    """
    if not os.environ.get("KAIANO_API_BASE_URL"):
        return

    standards_version = _resolve_standards_version()
    model = os.environ.get("ANTHROPIC_MODEL", "claude-sonnet-4-20250514")
    findings: list[dict[str, Any]] = []

    if direct_finding_text:
        sev = str(direct_severity or "WARN").upper()
        if sev == "WARNING":
            sev = "WARN"
        if sev not in {"CRITICAL", "ERROR", "WARN", "INFO", "SUCCESS"}:
            sev = "WARN"
        findings = [
            {
                "dimension": "pipeline_consistency",
                "severity": sev,
                "finding": direct_finding_text.strip(),
                "suggestion": None,
            }
        ]
    else:
        if not os.environ.get("ANTHROPIC_API_KEY"):
            return
        try:
            if collection_update:
                user_prompt = llm_engine._build_prompt_collection(
                    run_id=run_id,
                    standards_version=standards_version,
                    folders_processed=folders_processed,
                    tabs_written=tabs_written,
                    total_sets=total_sets,
                    json_snapshot_written=json_snapshot_written,
                    folder_names=folder_names or [],
                )
            else:
                user_prompt = llm_engine._build_prompt_csv(
                    run_id=run_id,
                    standards_version=standards_version,
                    sets_imported=sets_imported,
                    sets_failed=sets_failed,
                    sets_skipped=sets_skipped,
                    total_tracks=total_tracks,
                    failed_set_labels=failed_set_labels,
                    api_ingest_success=api_ingest_success,
                    sets_attempted=sets_attempted,
                    unrecognized_filename_skips=unrecognized_filename_skips,
                    duplicate_csv_count=duplicate_csv_count,
                )

            claude_text = llm_engine._anthropic_messages_create(
                api_key=os.environ["ANTHROPIC_API_KEY"],
                model=model,
                max_tokens=4096,
                user_prompt=user_prompt,
            )
            log.debug("Claude raw response: %s", claude_text[:500])
            findings, _ = llm_engine._parse_findings_from_claude(claude_text)
        except Exception:
            log.exception("pipeline evaluation: Claude request or parse failed")
            return

    post_findings(
        findings=findings,
        run_id=run_id,
        repo=repo,
        flow_name=flow_name,
        source=source,
        standards_version=standards_version,
        direct_finding_text=direct_finding_text,
    )


def build_csv_evaluation_prompt(
    *,
    run_id: str,
    standards_version: str,
    sets_imported: int,
    sets_failed: int,
    sets_skipped: int,
    total_tracks: int,
    failed_set_labels: list[str],
    api_ingest_success: bool,
    sets_attempted: int,
    unrecognized_filename_skips: int = 0,
    duplicate_csv_count: int = 0,
) -> str:
    """Public wrapper around llm_engine._build_prompt_csv for external use."""
    return llm_engine._build_prompt_csv(
        run_id=run_id,
        standards_version=standards_version,
        sets_imported=sets_imported,
        sets_failed=sets_failed,
        sets_skipped=sets_skipped,
        total_tracks=total_tracks,
        failed_set_labels=failed_set_labels,
        api_ingest_success=api_ingest_success,
        sets_attempted=sets_attempted,
        unrecognized_filename_skips=unrecognized_filename_skips,
        duplicate_csv_count=duplicate_csv_count,
    )


def build_collection_evaluation_prompt(
    *,
    run_id: str,
    standards_version: str,
    folders_processed: int,
    tabs_written: int,
    total_sets: int,
    json_snapshot_written: bool,
    folder_names: list[str],
) -> str:
    """Public wrapper around llm_engine._build_prompt_collection for external use."""
    return llm_engine._build_prompt_collection(
        run_id=run_id,
        standards_version=standards_version,
        folders_processed=folders_processed,
        tabs_written=tabs_written,
        total_sets=total_sets,
        json_snapshot_written=json_snapshot_written,
        folder_names=folder_names,
    )


def _extract_flow_run_event_fields(payload: dict[str, Any]) -> dict[str, str]:
    """Handle flat webhook payloads and nested event payloads."""
    resource = payload.get("resource")
    if isinstance(resource, dict):
        payload = {**resource, **payload}

    return {
        "flow_run_id": str(
            payload.get("flow_run_id") or payload.get("id") or ""
        ).strip(),
        "flow_name": str(payload.get("flow_name") or "").strip(),
        "state_name": str(payload.get("state_name") or "").strip(),
        "state_type": str(payload.get("state_type") or "").strip().upper(),
        "start_time": str(payload.get("start_time") or "").strip(),
        "end_time": str(payload.get("end_time") or "").strip(),
    }


def _state_to_severity(state_type: str) -> str:
    """Map a Prefect flow run state type string to an evaluation severity level.

    CRASHED -> CRITICAL (process-level failure, likely unrecoverable),
    FAILED -> ERROR (flow logic failed, needs attention),
    CANCELLED -> WARN (intentional but worth noting),
    anything else -> INFO.
    """
    normalized = (state_type or "").upper()
    if normalized == "CRASHED":
        return "CRITICAL"
    if normalized == "FAILED":
        return "ERROR"
    if normalized == "CANCELLED":
        return "WARN"
    return "INFO"


def _apply_prefect_flow_run_event(payload: dict[str, Any]) -> None:
    """Map a single webhook payload to evaluate_pipeline_run. May raise."""
    fields = _extract_flow_run_event_fields(payload)
    flow_run_id = fields["flow_run_id"] or "prefect-unknown-run"
    flow_name = fields["flow_name"] or "unknown-flow"
    state_name = fields["state_name"] or "UNKNOWN"
    state_type = fields["state_type"] or "UNKNOWN"
    collection_update = flow_name == "update-dj-set-collection"

    repo = _flow_name_to_repo(flow_name)
    if repo == _UNKNOWN_REPO:
        log.warning(
            "evaluation_webhook: unknown flow name %r — finding will be posted "
            "under repo='unknown'. Add this flow to _FLOW_REPO_MAP.",
            flow_name,
        )

    if state_type in {"FAILED", "CRASHED", "CANCELLED"}:
        evaluate_pipeline_run(
            run_id=flow_run_id,
            repo=repo,
            flow_name=flow_name,
            sets_imported=0,
            sets_failed=0,
            sets_skipped=0,
            total_tracks=0,
            failed_set_labels=[],
            api_ingest_success=True,
            sets_attempted=0,
            collection_update=collection_update,
            direct_finding_text=f"Flow {flow_name} entered {state_name} state",
            direct_severity=_state_to_severity(state_type),
            source="prefect_webhook",
        )
        return

    evaluate_pipeline_run(
        run_id=flow_run_id,
        repo=repo,
        flow_name=flow_name,
        sets_imported=0,
        sets_failed=0,
        sets_skipped=0,
        total_tracks=0,
        failed_set_labels=[],
        api_ingest_success=True,
        sets_attempted=0,
        collection_update=collection_update,
        source="prefect_webhook",
    )


def handle_prefect_flow_run_event(payload: dict[str, Any]) -> None:
    """Best-effort handler for Prefect flow run state events.

    Never raises; logs and returns on failure.
    """
    try:
        _apply_prefect_flow_run_event(payload)
    except Exception:
        log.exception("evaluation_webhook: failed to handle flow run event")


def handle_prefect_flow_run_events(payloads: Iterable[dict[str, Any]]) -> None:
    """Handle multiple Prefect flow run state event payloads."""
    for payload in payloads:
        handle_prefect_flow_run_event(payload)
