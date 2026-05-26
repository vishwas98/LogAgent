"""
Shared pytest fixtures for all LogAgent test suites.
All external I/O (Splunk, Anthropic, SMTP, GitHub) is mocked here.
"""

from __future__ import annotations

import time
from unittest.mock import MagicMock, patch

import pytest

from event_driven_agent import IncidentEvent, IncidentWindow


# ── Log line fixtures ──────────────────────────────────────────────────────────


@pytest.fixture
def java_stacktrace() -> str:
    return (
        "java.sql.SQLException: Connection pool exhausted\n"
        "\tat com.app.db.Pool.acquire(Pool.java:87)\n"
        "\tat com.app.service.UserService.getUser(UserService.java:45)\n"
        "\tat com.app.api.UserController.handle(UserController.java:23)\n"
        "\tat com.app.api.UserController.dispatch(UserController.java:10)\n"
        "Caused by: java.io.IOException: timeout after 30000ms"
    )


@pytest.fixture
def python_stacktrace() -> str:
    return (
        'File "app/db.py", line 34, in get_connection\n'
        '  raise ConnectionError("pool exhausted")\n'
        'File "app/service.py", line 12, in get_user\n'
        "  conn = get_connection()\n"
        'File "app/api.py", line 8, in handle\n'
        "  result = get_user(uid)\n"
        "ConnectionError: pool exhausted"
    )


@pytest.fixture
def plain_error() -> str:
    return "2026-05-25 05:05:00 ERROR DatabaseConnectionPool exhausted after 30000ms"


@pytest.fixture
def plain_error_with_ip() -> str:
    return "ERROR connecting to 10.0.0.1 port 5432 after 30000ms timeout"


@pytest.fixture
def context_window(plain_error) -> list[str]:
    return [
        "2026-05-25 05:04:55 INFO  DB pool at 19/20 capacity",
        "2026-05-25 05:04:56 INFO  DB pool at 19/20 capacity",
        "2026-05-25 05:04:57 INFO  DB pool at 19/20 capacity",
        plain_error,
        "2026-05-25 05:05:01 WARN  HTTP 503 returned to upstream",
        "2026-05-25 05:05:02 WARN  HTTP 503 returned to upstream",
    ]


# ── Webhook payload fixtures ───────────────────────────────────────────────────


@pytest.fixture
def splunk_webhook_payload() -> dict:
    return {
        "result": {
            "_time": "1748150700.000",
            "host": "web-prod-01",
            "source": "/var/log/app.log",
            "_raw": "2026-05-25 05:05:00 ERROR DatabaseConnectionPool exhausted",
        },
        "sid": "scheduler_123",
        "search_name": "LogAgent Error Alert",
        "owner": "admin",
    }


# ── IncidentEvent / IncidentWindow factories ────────────────────────────────────


@pytest.fixture
def make_event():
    def _make(
        host: str = "web-01",
        source: str = "/var/log/app.log",
        raw: str = "ERROR something failed",
        ts: float | None = None,
        severity: str = "ERROR",
    ) -> IncidentEvent:
        return IncidentEvent(
            host=host,
            source=source,
            raw=raw,
            timestamp=ts if ts is not None else time.time(),
            severity=severity,
        )

    return _make


@pytest.fixture
def make_window(make_event):
    def _make(
        host: str = "web-01", source: str = "/var/log/app.log", ts: float | None = None
    ) -> IncidentWindow:
        t = ts if ts is not None else time.time()
        w = IncidentWindow(
            stream_key=f"{host}||{source}",
            host=host,
            source=source,
            first_event_time=t,
        )
        w.add_event(make_event(host=host, source=source, ts=t))
        return w

    return _make


# ── Mock patches ──────────────────────────────────────────────────────────────


@pytest.fixture
def mock_anthropic():
    """Mock the Anthropic client so no real API calls are made."""
    mock_resp = MagicMock()
    mock_resp.content = [
        MagicMock(
            text='{"summary":"DB pool exhausted","technical_context":"All connections in use","root_cause":"Pool size too small","action_items":["Increase pool size"]}'
        )
    ]
    with patch("splunk_rca_agent.anthropic.Anthropic") as mock_cls:
        mock_cls.return_value.messages.create.return_value = mock_resp
        yield mock_cls


@pytest.fixture
def mock_smtp():
    """Mock SMTP so no real emails are sent."""
    with patch("splunk_rca_agent.smtplib.SMTP") as mock_cls:
        mock_smtp_instance = MagicMock()
        mock_cls.return_value.__enter__ = MagicMock(return_value=mock_smtp_instance)
        mock_cls.return_value.__exit__ = MagicMock(return_value=False)
        yield mock_cls


@pytest.fixture
def mock_splunk_session():
    """Mock requests.Session so no real Splunk calls are made."""
    with patch("splunk_rca_agent.requests.Session") as mock_cls:
        yield mock_cls
