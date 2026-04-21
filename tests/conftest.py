"""Shared pytest configuration for evaluator-cog.

Isolates every test from the real Prefect Cloud account and local
~/.prefect/storage by routing all flow/task execution through an
ephemeral SQLite-backed test harness. Also disables task retries and
quiets Prefect's logger so expected exceptions in flow-level handlers
do not dump tracebacks on every run.

Pins STANDARDS_VERSION so pipeline evaluation tests do not fetch
standards metadata over the network.
"""

from __future__ import annotations

import logging

import pytest
from prefect.testing.utilities import prefect_test_harness


@pytest.fixture(autouse=True, scope="session")
def prefect_test_fixture():
    """Route all Prefect orchestration through an ephemeral test backend.

    Without this, importing any @flow or @task and calling it triggers
    real Prefect Cloud API calls and writes to ~/.prefect/storage. The
    harness sets PREFECT_API_URL to an in-process ephemeral server and
    uses a temp SQLite database that's torn down at session end.
    """
    with prefect_test_harness():
        yield


@pytest.fixture(autouse=True)
def _disable_task_retries(monkeypatch: pytest.MonkeyPatch) -> None:
    """Disable task retries in tests.

    Production flows may declare @task(retries=...). In tests that means
    a mocked side_effect exception fires multiple times per call,
    generating noise and slowing the suite.
    """
    monkeypatch.setenv("PREFECT_TASK_DEFAULT_RETRIES", "0")
    monkeypatch.setenv("PREFECT_TASK_DEFAULT_RETRY_DELAY_SECONDS", "0")


@pytest.fixture(autouse=True)
def _quiet_prefect_logs() -> None:
    """Suppress Prefect's task-engine tracebacks for expected exceptions.

    When a task raises and the flow catches it, Prefect's default logging
    can dump the full traceback at ERROR before the flow handler runs,
    which clutters test output.
    """
    logging.getLogger("prefect").setLevel(logging.CRITICAL)
    logging.getLogger("prefect.task_runs").setLevel(logging.CRITICAL)
    logging.getLogger("prefect.flow_runs").setLevel(logging.CRITICAL)


@pytest.fixture(autouse=True)
def _default_standards_version_for_pipeline_eval(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Pin STANDARDS_VERSION so evaluate_pipeline_run does not hit the network in tests."""
    monkeypatch.setenv("STANDARDS_VERSION", "8.8.8-test")
