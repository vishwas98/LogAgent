"""
Tests for event_driven_agent.py.

Coverage targets:
  IncidentEvent             — stream_key property
  IncidentWindow            — add_event, is_ready (silence + max cap), post_init
  IncidentBuffer            — new stream, extend existing, fire on silence,
                              force-fire at max cap, multiple streams independent,
                              get_open_count, concurrent add_event, stop()
  _parse_webhook_payload    — valid, missing fields, non-anomaly, bad _time
  _validate_secret          — match, mismatch
  _WebhookHandler           — valid POST, wrong path, no auth, bad auth,
                              empty body, invalid JSON, non-anomaly payload
  _fetch_with_retry         — success first try, retry on failure, all retries fail
  EventDrivenLogAgent       — process_window happy path, no context, all suppressed,
                              dedup prune, _split_new_known, _submit_window
  Integration               — webhook → buffer → process_window end-to-end
"""

from __future__ import annotations

import http.client
import json
import threading
import time
from unittest.mock import MagicMock, call, patch

import pytest

from event_driven_agent import (
    MAX_WINDOW_SECS,
    EventDrivenLogAgent,
    IncidentBuffer,
    IncidentEvent,
    IncidentWindow,
    _WebhookServer,
    _fetch_with_retry,
    _parse_webhook_payload,
    _validate_secret,
)
from splunk_rca_agent import LogCluster


# ── IncidentEvent ──────────────────────────────────────────────────────────────


class TestIncidentEvent:
    def test_stream_key_combines_host_and_source(self):
        ev = IncidentEvent(host="web-01", source="/var/log/app.log", raw="ERROR x", timestamp=1.0)
        assert ev.stream_key == "web-01||/var/log/app.log"

    def test_stream_key_separates_different_hosts(self):
        ev1 = IncidentEvent(host="web-01", source="/app.log", raw="ERROR", timestamp=1.0)
        ev2 = IncidentEvent(host="web-02", source="/app.log", raw="ERROR", timestamp=1.0)
        assert ev1.stream_key != ev2.stream_key

    def test_default_severity(self):
        ev = IncidentEvent(host="h", source="s", raw="ERROR x", timestamp=1.0)
        assert ev.severity == "ERROR"


# ── IncidentWindow ─────────────────────────────────────────────────────────────


class TestIncidentWindow:
    def test_last_event_time_initialises_to_first_event_time(self):
        t = 1000.0
        w = IncidentWindow(stream_key="h||s", host="h", source="s", first_event_time=t)
        assert w.last_event_time == t

    def test_add_event_updates_last_event_time(self, make_event):
        w = IncidentWindow(stream_key="h||s", host="h", source="s", first_event_time=1000.0)
        ev = make_event(ts=1005.0)
        w.add_event(ev)
        assert w.last_event_time == 1005.0

    def test_add_event_does_not_decrease_last_event_time(self, make_event):
        w = IncidentWindow(stream_key="h||s", host="h", source="s", first_event_time=1000.0)
        w.add_event(make_event(ts=1010.0))
        w.add_event(make_event(ts=999.0))  # older event — should not decrease
        assert w.last_event_time == 1010.0

    def test_add_event_appended_to_list(self, make_event):
        w = IncidentWindow(stream_key="h||s", host="h", source="s", first_event_time=1000.0)
        ev = make_event(ts=1001.0)
        w.add_event(ev)
        assert ev in w.events

    def test_is_ready_after_post_window_silence(self):
        t0 = time.time() - 150  # 150s ago
        w = IncidentWindow(stream_key="h||s", host="h", source="s", first_event_time=t0)
        w.last_event_time = t0  # silence for 150s
        assert w.is_ready(time.time(), post_window_secs=120, max_window_secs=600)

    def test_not_ready_within_post_window(self):
        t0 = time.time() - 30  # only 30s ago
        w = IncidentWindow(stream_key="h||s", host="h", source="s", first_event_time=t0)
        w.last_event_time = t0
        assert not w.is_ready(time.time(), post_window_secs=120, max_window_secs=600)

    def test_ready_at_max_window_cap(self):
        t0 = time.time() - 700  # 700s ago — past max_window_secs=600
        w = IncidentWindow(stream_key="h||s", host="h", source="s", first_event_time=t0)
        w.last_event_time = time.time()  # event just now (no silence yet)
        assert w.is_ready(time.time(), post_window_secs=120, max_window_secs=600)

    def test_firing_status_blocks_is_ready(self):
        t0 = time.time() - 200
        w = IncidentWindow(stream_key="h||s", host="h", source="s", first_event_time=t0)
        w.status = "firing"
        assert not w.is_ready(time.time(), post_window_secs=10, max_window_secs=60)


# ── IncidentBuffer ─────────────────────────────────────────────────────────────


class TestIncidentBuffer:
    def test_new_stream_creates_window(self, make_event):
        fired = []
        buf = IncidentBuffer(
            on_window_ready=fired.append,
            post_window_secs=60,
            max_window_secs=300,
            check_interval=0.05,
        )
        try:
            ev = make_event(host="h1", source="s1")
            buf.add_event(ev)
            assert buf.get_open_count() == 1
        finally:
            buf.stop()

    def test_same_stream_extends_window(self, make_event):
        fired = []
        buf = IncidentBuffer(
            on_window_ready=fired.append,
            post_window_secs=60,
            max_window_secs=300,
            check_interval=0.05,
        )
        try:
            buf.add_event(make_event(ts=1000.0))
            buf.add_event(make_event(ts=1005.0))
            assert buf.get_open_count() == 1  # still one window, not two
        finally:
            buf.stop()

    def test_multiple_streams_independent(self, make_event):
        fired = []
        buf = IncidentBuffer(
            on_window_ready=fired.append,
            post_window_secs=60,
            max_window_secs=300,
            check_interval=0.05,
        )
        try:
            buf.add_event(make_event(host="h1", source="s1"))
            buf.add_event(make_event(host="h2", source="s2"))
            assert buf.get_open_count() == 2
        finally:
            buf.stop()

    def test_window_fires_after_post_window_silence(self, make_event):
        fired = []
        buf = IncidentBuffer(
            on_window_ready=fired.append,
            post_window_secs=0,  # fire immediately
            max_window_secs=300,
            check_interval=0.05,
        )
        try:
            buf.add_event(make_event())
            time.sleep(0.3)  # allow timer to run
            assert len(fired) == 1
            assert buf.get_open_count() == 0
        finally:
            buf.stop()

    def test_window_force_fires_at_max_cap(self, make_event):
        fired = []
        buf = IncidentBuffer(
            on_window_ready=fired.append,
            post_window_secs=9999,  # silence-based firing disabled
            max_window_secs=0,  # force-fire immediately
            check_interval=0.05,
        )
        try:
            buf.add_event(make_event())
            time.sleep(0.3)
            assert len(fired) == 1
        finally:
            buf.stop()

    def test_window_not_fired_twice(self, make_event):
        fired = []
        buf = IncidentBuffer(
            on_window_ready=fired.append,
            post_window_secs=0,
            max_window_secs=300,
            check_interval=0.05,
        )
        try:
            buf.add_event(make_event())
            time.sleep(0.4)
            assert len(fired) == 1  # exactly once
        finally:
            buf.stop()

    def test_stop_joins_timer_thread(self, make_event):
        buf = IncidentBuffer(on_window_ready=lambda w: None, check_interval=0.05)
        buf.stop(timeout=2.0)
        assert not buf._timer.is_alive()

    def test_concurrent_add_events_thread_safe(self, make_event):
        """Multiple threads adding events to different streams should not corrupt state."""
        fired = []
        buf = IncidentBuffer(on_window_ready=fired.append, post_window_secs=60, check_interval=0.05)
        threads = []
        for i in range(10):
            t = threading.Thread(
                target=buf.add_event,
                args=(make_event(host=f"host-{i}", source="s"),),
            )
            threads.append(t)
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        try:
            assert buf.get_open_count() == 10
        finally:
            buf.stop()

    def test_callback_exception_does_not_crash_timer(self, make_event):
        """If on_window_ready raises, the timer thread must survive."""

        def bad_callback(w):
            raise RuntimeError("deliberate test error")

        buf = IncidentBuffer(
            on_window_ready=bad_callback,
            post_window_secs=0,
            max_window_secs=300,
            check_interval=0.05,
        )
        try:
            buf.add_event(make_event())
            time.sleep(0.3)
            assert buf._timer.is_alive()  # timer thread still running
        finally:
            buf.stop()


# ── _parse_webhook_payload ─────────────────────────────────────────────────────


class TestParseWebhookPayload:
    def test_valid_payload_returns_event(self, splunk_webhook_payload):
        event = _parse_webhook_payload(splunk_webhook_payload)
        assert event is not None
        assert event.host == "web-prod-01"
        assert event.source == "/var/log/app.log"
        assert "ERROR" in event.raw
        assert event.severity == "ERROR"

    def test_timestamp_parsed_from_time_field(self, splunk_webhook_payload):
        event = _parse_webhook_payload(splunk_webhook_payload)
        assert event.timestamp == pytest.approx(1748150700.0)

    def test_bad_time_falls_back_to_now(self, splunk_webhook_payload):
        splunk_webhook_payload["result"]["_time"] = "not-a-number"
        t_before = time.time()
        event = _parse_webhook_payload(splunk_webhook_payload)
        assert event is not None
        assert event.timestamp >= t_before

    def test_missing_raw_returns_none(self, splunk_webhook_payload):
        del splunk_webhook_payload["result"]["_raw"]
        assert _parse_webhook_payload(splunk_webhook_payload) is None

    def test_missing_host_returns_none(self, splunk_webhook_payload):
        del splunk_webhook_payload["result"]["host"]
        assert _parse_webhook_payload(splunk_webhook_payload) is None

    def test_missing_source_returns_none(self, splunk_webhook_payload):
        del splunk_webhook_payload["result"]["source"]
        assert _parse_webhook_payload(splunk_webhook_payload) is None

    def test_non_anomaly_raw_returns_none(self, splunk_webhook_payload):
        splunk_webhook_payload["result"]["_raw"] = "INFO all systems nominal"
        assert _parse_webhook_payload(splunk_webhook_payload) is None

    def test_missing_result_key_returns_none(self):
        assert _parse_webhook_payload({"sid": "123"}) is None

    def test_non_dict_payload_returns_none(self):
        assert _parse_webhook_payload("not a dict") is None  # type: ignore[arg-type]

    @pytest.mark.parametrize("sev", ["ERROR", "EXCEPTION", "CRITICAL", "FATAL", "FAILED"])
    def test_all_severity_levels_accepted(self, splunk_webhook_payload, sev):
        splunk_webhook_payload["result"]["_raw"] = f"{sev} something bad happened"
        event = _parse_webhook_payload(splunk_webhook_payload)
        assert event is not None
        assert event.severity == sev


# ── _validate_secret ──────────────────────────────────────────────────────────


class TestValidateSecret:
    def test_matching_secret_returns_true(self):
        assert _validate_secret("mysecret", "mysecret") is True

    def test_wrong_secret_returns_false(self):
        assert _validate_secret("wrongsecret", "mysecret") is False

    def test_empty_strings_match(self):
        assert _validate_secret("", "") is True

    def test_whitespace_stripped(self):
        assert _validate_secret("  mysecret  ", "mysecret") is True


# ── _WebhookServer (HTTP integration) ─────────────────────────────────────────


def _start_test_server(buffer: IncidentBuffer, secret: str = "") -> tuple[_WebhookServer, int]:
    """Spin up a webhook server on a free port, return (server, port)."""
    import socketserver

    server = _WebhookServer("127.0.0.1", 0, buffer, secret)
    port = server.server_address[1]
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    return server, port


def _post(
    port: int,
    body: bytes,
    path: str = "/webhook",
    content_type: str = "application/json",
    headers: dict | None = None,
) -> tuple[int, dict]:
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    all_headers = {"Content-Type": content_type, "Content-Length": str(len(body))}
    if headers:
        all_headers.update(headers)
    conn.request("POST", path, body, all_headers)
    resp = conn.getresponse()
    return resp.status, json.loads(resp.read())


class TestWebhookServer:
    def test_valid_payload_returns_200(self, splunk_webhook_payload):
        events = []
        buf = IncidentBuffer(
            on_window_ready=lambda w: None, post_window_secs=999, check_interval=0.05
        )
        server, port = _start_test_server(buf)
        try:
            status, body = _post(port, json.dumps(splunk_webhook_payload).encode())
            assert status == 200
            assert body["status"] == "queued"
        finally:
            server.shutdown()
            buf.stop()

    def test_valid_payload_queues_event(self, splunk_webhook_payload):
        # Use current time so the window doesn't immediately expire via max_window_secs
        splunk_webhook_payload["result"]["_time"] = str(time.time())
        buf = IncidentBuffer(
            on_window_ready=lambda w: None,
            post_window_secs=9999,
            max_window_secs=9999,
            check_interval=0.05,
        )
        server, port = _start_test_server(buf)
        try:
            _post(port, json.dumps(splunk_webhook_payload).encode())
            time.sleep(0.05)
            assert buf.get_open_count() == 1
        finally:
            server.shutdown()
            buf.stop()

    def test_wrong_path_returns_404(self, splunk_webhook_payload):
        buf = IncidentBuffer(
            on_window_ready=lambda w: None, post_window_secs=999, check_interval=0.05
        )
        server, port = _start_test_server(buf)
        try:
            status, _ = _post(port, json.dumps(splunk_webhook_payload).encode(), path="/wrong")
            assert status == 404
        finally:
            server.shutdown()
            buf.stop()

    def test_empty_body_returns_400(self):
        buf = IncidentBuffer(
            on_window_ready=lambda w: None, post_window_secs=999, check_interval=0.05
        )
        server, port = _start_test_server(buf)
        try:
            status, _ = _post(port, b"", headers={"Content-Length": "0"})
            assert status == 400
        finally:
            server.shutdown()
            buf.stop()

    def test_invalid_json_returns_400(self):
        buf = IncidentBuffer(
            on_window_ready=lambda w: None, post_window_secs=999, check_interval=0.05
        )
        server, port = _start_test_server(buf)
        try:
            status, _ = _post(port, b"not json at all {{{")
            assert status == 400
        finally:
            server.shutdown()
            buf.stop()

    def test_non_anomaly_event_returns_422(self):
        buf = IncidentBuffer(
            on_window_ready=lambda w: None, post_window_secs=999, check_interval=0.05
        )
        server, port = _start_test_server(buf)
        try:
            payload = {
                "result": {"_time": "1.0", "host": "h", "source": "s", "_raw": "INFO all good"}
            }
            status, _ = _post(port, json.dumps(payload).encode())
            assert status == 422
        finally:
            server.shutdown()
            buf.stop()

    def test_valid_secret_accepted(self, splunk_webhook_payload):
        buf = IncidentBuffer(
            on_window_ready=lambda w: None, post_window_secs=999, check_interval=0.05
        )
        server, port = _start_test_server(buf, secret="correct-secret")
        try:
            status, _ = _post(
                port,
                json.dumps(splunk_webhook_payload).encode(),
                headers={"Authorization": "correct-secret"},
            )
            assert status == 200
        finally:
            server.shutdown()
            buf.stop()

    def test_wrong_secret_returns_401(self, splunk_webhook_payload):
        buf = IncidentBuffer(
            on_window_ready=lambda w: None, post_window_secs=999, check_interval=0.05
        )
        server, port = _start_test_server(buf, secret="correct-secret")
        try:
            status, _ = _post(
                port,
                json.dumps(splunk_webhook_payload).encode(),
                headers={"Authorization": "wrong-secret"},
            )
            assert status == 401
        finally:
            server.shutdown()
            buf.stop()

    def test_missing_auth_header_returns_401(self, splunk_webhook_payload):
        buf = IncidentBuffer(
            on_window_ready=lambda w: None, post_window_secs=999, check_interval=0.05
        )
        server, port = _start_test_server(buf, secret="required-secret")
        try:
            status, _ = _post(port, json.dumps(splunk_webhook_payload).encode())
            assert status == 401
        finally:
            server.shutdown()
            buf.stop()

    def test_no_secret_config_skips_auth_check(self, splunk_webhook_payload):
        """When WEBHOOK_SECRET is empty, ANY request (no auth header) is accepted."""
        buf = IncidentBuffer(
            on_window_ready=lambda w: None, post_window_secs=999, check_interval=0.05
        )
        server, port = _start_test_server(buf, secret="")  # no secret
        try:
            status, _ = _post(port, json.dumps(splunk_webhook_payload).encode())
            assert status == 200
        finally:
            server.shutdown()
            buf.stop()


# ── _fetch_with_retry ─────────────────────────────────────────────────────────


class TestFetchWithRetry:
    def test_success_on_first_attempt(self, make_window):
        mock_splunk = MagicMock()
        mock_splunk.fetch_context_for_stream.return_value = [("ERROR x", ["ERROR x"])]
        w = make_window()
        result = _fetch_with_retry(
            mock_splunk, w.host, w.source, w.first_event_time, retries=3, base_delay=0.0
        )
        assert len(result) == 1
        mock_splunk.fetch_context_for_stream.assert_called_once()

    def test_retries_on_transient_failure(self, make_window):
        mock_splunk = MagicMock()
        mock_splunk.fetch_context_for_stream.side_effect = [
            ConnectionError("timeout"),
            [("ERROR x", ["ERROR x"])],  # succeeds on 2nd attempt
        ]
        w = make_window()
        result = _fetch_with_retry(
            mock_splunk, w.host, w.source, w.first_event_time, retries=3, base_delay=0.0
        )
        assert len(result) == 1
        assert mock_splunk.fetch_context_for_stream.call_count == 2

    def test_returns_empty_after_all_retries_exhausted(self, make_window):
        mock_splunk = MagicMock()
        mock_splunk.fetch_context_for_stream.side_effect = ConnectionError("always fails")
        w = make_window()
        result = _fetch_with_retry(
            mock_splunk, w.host, w.source, w.first_event_time, retries=3, base_delay=0.0
        )
        assert result == []
        assert mock_splunk.fetch_context_for_stream.call_count == 3

    def test_no_retry_on_zero_retries(self, make_window):
        mock_splunk = MagicMock()
        mock_splunk.fetch_context_for_stream.side_effect = RuntimeError("fail")
        w = make_window()
        result = _fetch_with_retry(
            mock_splunk, w.host, w.source, w.first_event_time, retries=1, base_delay=0.0
        )
        assert result == []
        assert mock_splunk.fetch_context_for_stream.call_count == 1


# ── EventDrivenLogAgent.process_window ────────────────────────────────────────


class TestProcessWindow:
    def _make_agent(self, mock_anthropic, mock_smtp):
        """Build an agent with all I/O mocked out."""
        with (
            patch("event_driven_agent.SplunkClient"),
            patch("event_driven_agent.CodebaseIndexer.from_env", return_value=None),
            patch("event_driven_agent.RCAAnalyzer") as mock_rca_cls,
        ):
            agent = EventDrivenLogAgent()
        # Set mocks AFTER construction so they survive outside the with block
        mock_rca = MagicMock()
        mock_rca._indexer = None
        mock_rca.analyze.return_value = {
            "summary": "DB pool exhausted",
            "technical_context": "Pool full",
            "root_cause": "Max connections reached",
            "action_items": ["Increase pool size"],
        }
        agent.rca = mock_rca
        agent.reporter = MagicMock()  # prevents real SMTP calls
        agent.splunk = MagicMock()
        return agent

    def test_no_context_returns_false(self, make_window, mock_anthropic, mock_smtp):
        agent = self._make_agent(mock_anthropic, mock_smtp)
        agent.splunk = MagicMock()
        agent.splunk.fetch_context_for_stream.return_value = []
        w = make_window()
        assert agent.process_window(w) is False

    def test_no_clusters_returns_false(self, make_window, mock_anthropic, mock_smtp):
        agent = self._make_agent(mock_anthropic, mock_smtp)
        agent.splunk = MagicMock()
        # Return INFO-only lines — no anomaly events → compress_events returns []
        agent.splunk.fetch_context_for_stream.return_value = [
            ("INFO all good", ["INFO all good"]),
        ]
        # Patch compress_events to return nothing
        with patch("event_driven_agent.compress_events", return_value=([], MagicMock())):
            w = make_window()
            assert agent.process_window(w) is False

    def test_new_cluster_triggers_alert(self, make_window, mock_anthropic, mock_smtp):
        agent = self._make_agent(mock_anthropic, mock_smtp)
        agent.splunk = MagicMock()

        fake_cluster = LogCluster(template=["ERROR", "db", "down"], count=10)
        fake_stats = MagicMock()
        fake_stats.llm_sent = 1
        fake_stats.summary.return_value = "1 cluster"

        with (
            patch("event_driven_agent.compress_events", return_value=([fake_cluster], fake_stats)),
            patch(
                "event_driven_agent._fetch_with_retry",
                return_value=[("ERROR db down", ["ERROR db down"])],
            ),
        ):
            w = make_window()
            result = agent.process_window(w)

        assert result is True
        agent.rca.analyze.assert_called_once_with(fake_cluster)

    def test_known_cluster_suppressed(self, make_window, mock_anthropic, mock_smtp):
        agent = self._make_agent(mock_anthropic, mock_smtp)

        fake_cluster = LogCluster(template=["ERROR", "db", "down"], count=10)
        # Pre-mark as reported
        agent._reported[fake_cluster.cluster_id] = time.time()

        with (
            patch("event_driven_agent.compress_events", return_value=([fake_cluster], MagicMock())),
            patch(
                "event_driven_agent._fetch_with_retry",
                return_value=[("ERROR db down", ["ERROR db down"])],
            ),
        ):
            w = make_window()
            result = agent.process_window(w)

        assert result is False
        agent.rca.analyze.assert_not_called()

    def test_dedup_marks_cluster_as_reported(self, make_window, mock_anthropic, mock_smtp):
        agent = self._make_agent(mock_anthropic, mock_smtp)
        agent.splunk = MagicMock()
        agent.reporter = MagicMock()

        fake_cluster = LogCluster(template=["ERROR", "db", "down"], count=10)
        fake_stats = MagicMock()
        fake_stats.summary.return_value = ""

        with (
            patch("event_driven_agent.compress_events", return_value=([fake_cluster], fake_stats)),
            patch("event_driven_agent._fetch_with_retry", return_value=[("ERROR db down", [])]),
        ):
            w = make_window()
            agent.process_window(w)

        assert fake_cluster.cluster_id in agent._reported

    def test_dedup_pruning_removes_expired_entries(self, mock_anthropic, mock_smtp):
        agent = self._make_agent(mock_anthropic, mock_smtp)
        old_time = time.time() - (30 * 60 * 60)  # 30 hours ago — beyond 2h window
        agent._reported["old-cluster"] = old_time
        agent._prune_dedup()
        assert "old-cluster" not in agent._reported

    def test_dedup_keeps_recent_entries(self, mock_anthropic, mock_smtp):
        agent = self._make_agent(mock_anthropic, mock_smtp)
        recent = time.time() - 30  # 30 seconds ago
        agent._reported["recent-cluster"] = recent
        agent._prune_dedup()
        assert "recent-cluster" in agent._reported

    def test_split_new_known_separates_correctly(self, mock_anthropic, mock_smtp):
        agent = self._make_agent(mock_anthropic, mock_smtp)
        c_new = LogCluster(template=["ERROR", "new", "thing"], count=5)
        c_known = LogCluster(template=["ERROR", "known", "thing"], count=3)
        agent._reported[c_known.cluster_id] = time.time()

        new, known = agent._split_new_known([c_new, c_known])
        assert c_new in new
        assert c_known in known


# ── Integration: webhook → buffer → process_window ────────────────────────────


class TestIntegration:
    def test_webhook_triggers_process_window(self, splunk_webhook_payload):
        """
        Full path: POST /webhook → IncidentBuffer fires → process_window called.
        """
        processed = threading.Event()

        def fake_process(window: IncidentWindow) -> None:
            processed.set()

        with (
            patch("event_driven_agent.SplunkClient"),
            patch("event_driven_agent.CodebaseIndexer.from_env", return_value=None),
            patch("event_driven_agent.RCAAnalyzer"),
        ):
            agent = EventDrivenLogAgent()

        # Replace buffer with fast-firing version
        agent.buffer.stop()
        agent.buffer = IncidentBuffer(
            on_window_ready=lambda w: agent._executor.submit(fake_process, w),
            post_window_secs=0,
            max_window_secs=300,
            check_interval=0.05,
        )

        server, port = _start_test_server(agent.buffer)
        try:
            _post(port, json.dumps(splunk_webhook_payload).encode())
            fired = processed.wait(timeout=3.0)
            assert fired, "process_window was never called within 3 seconds"
        finally:
            server.shutdown()
            agent.buffer.stop()
            agent._executor.shutdown(wait=False)

    def test_two_streams_fire_independently(self, splunk_webhook_payload):
        """Two different source streams produce two independent incident windows."""
        fired_streams: list[str] = []

        def capture(window: IncidentWindow) -> None:
            fired_streams.append(window.stream_key)

        buf = IncidentBuffer(
            on_window_ready=capture,
            post_window_secs=0,
            max_window_secs=300,
            check_interval=0.05,
        )
        server, port = _start_test_server(buf)
        try:
            payload1 = dict(splunk_webhook_payload)
            payload1["result"] = {**splunk_webhook_payload["result"], "source": "/log/stream1.log"}
            payload2 = dict(splunk_webhook_payload)
            payload2["result"] = {**splunk_webhook_payload["result"], "source": "/log/stream2.log"}

            _post(port, json.dumps(payload1).encode())
            _post(port, json.dumps(payload2).encode())

            time.sleep(0.4)
            assert len(fired_streams) == 2
            assert len(set(fired_streams)) == 2  # distinct streams
        finally:
            server.shutdown()
            buf.stop()
