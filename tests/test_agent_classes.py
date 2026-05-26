"""
Tests for RCAAnalyzer, EmailReporter, and LogMonitorAgent in splunk_rca_agent.py.

These classes touch external services (Anthropic, SMTP, Splunk).
All external I/O is mocked — no real API keys or network connections needed.

Coverage targets:
  RCAAnalyzer._system_blocks   — 2 blocks (no indexer) vs 3 blocks (with arch)
  RCAAnalyzer.analyze          — happy path, JSON parse failure fallback
  RCAAnalyzer.refresh_codebase — no indexer, before refresh hour, already done today,
                                  scheduled refresh (new arch), empty arch fallback
  EmailReporter.send           — builds HTML, sends via SMTP, multiple recipients
  LogMonitorAgent.__init__     — without GitHub, with GitHub
  LogMonitorAgent._prune_dedup — removes expired, keeps recent
  LogMonitorAgent._split_new_known — correctly partitions new vs known
  LogMonitorAgent.run_once     — quiet (no events), no new clusters, sends alert
"""

from __future__ import annotations

import email as _email_module
import time
from datetime import date, datetime, timezone
from unittest.mock import MagicMock, patch

import pytest

import splunk_rca_agent as sra
from splunk_rca_agent import (
    DEDUP_WINDOW_MINS,
    CompressionStats,
    EmailReporter,
    LogCluster,
    LogMonitorAgent,
    RCAAnalyzer,
)


# ── RCAAnalyzer ───────────────────────────────────────────────────────────────


class TestRCAAnalyzer:
    def _make_rca(self, mock_anthropic, indexer=None):
        """Build RCAAnalyzer with mocked Anthropic client."""
        return RCAAnalyzer(indexer=indexer)

    def test_system_blocks_without_indexer_returns_two(self, mock_anthropic):
        rca = self._make_rca(mock_anthropic)
        blocks = rca._system_blocks()
        assert len(blocks) == 2
        # Both should be cached
        assert all(b.get("cache_control") for b in blocks)

    def test_system_blocks_with_arch_returns_three(self, mock_anthropic):
        rca = self._make_rca(mock_anthropic)
        rca._arch_block = {
            "type": "text",
            "text": "## App Architecture\n...",
            "cache_control": {"type": "ephemeral"},
        }
        blocks = rca._system_blocks()
        assert len(blocks) == 3

    def test_analyze_returns_parsed_json(self, mock_anthropic):
        rca = self._make_rca(mock_anthropic)
        c = LogCluster(template=["ERROR", "db", "connection", "failed"], count=10)
        result = rca.analyze(c)
        assert isinstance(result, dict)
        assert "summary" in result
        assert "action_items" in result

    def test_analyze_json_parse_failure_returns_fallback(self, mock_anthropic):
        # Make the API return non-JSON
        mock_anthropic.return_value.messages.create.return_value.content = [
            MagicMock(text="not valid json {{{{")
        ]
        rca = self._make_rca(mock_anthropic)
        c = LogCluster(template=["ERROR", "boom"], count=1)
        result = rca.analyze(c)
        assert result["summary"] == "RCA parse failed."
        assert result["root_cause"] == "Unknown"

    def test_analyze_empty_response_returns_fallback(self, mock_anthropic):
        mock_anthropic.return_value.messages.create.return_value.content = []
        rca = self._make_rca(mock_anthropic)
        c = LogCluster(template=["ERROR", "empty"], count=1)
        result = rca.analyze(c)
        assert result["summary"] == "RCA parse failed."

    def test_analyze_includes_var_slots_in_prompt(self, mock_anthropic):
        rca = self._make_rca(mock_anthropic)
        c = LogCluster(
            template=["ERROR", "connecting", "to", "<IP>"],
            count=5,
            var_slots={3: ["10.0.0.1", "192.168.1.5"]},
        )
        rca.analyze(c)
        call_args = mock_anthropic.return_value.messages.create.call_args
        user_content = call_args[1]["messages"][0]["content"]
        assert "10.0.0.1" in user_content or "Slots" in user_content

    def test_analyze_with_indexer_fetches_code_context(self, mock_anthropic):
        """Lines 1000-1004: indexer path inside analyze()."""
        mock_indexer = MagicMock()
        mock_indexer.extract_keywords.return_value = ["ConnectionPool", "exhausted"]
        mock_indexer.find_snippets.return_value = "def get_connection():\n    pass"
        rca = self._make_rca(mock_anthropic, indexer=mock_indexer)
        c = LogCluster(template=["ERROR", "ConnectionPool", "exhausted"], count=7)
        result = rca.analyze(c)
        mock_indexer.extract_keywords.assert_called_once()
        mock_indexer.find_snippets.assert_called_once()
        assert isinstance(result, dict)

    def test_analyze_includes_raw_samples_in_prompt(self, mock_anthropic):
        """Line 856: _build_context takes the raw_samples branch."""
        rca = self._make_rca(mock_anthropic)
        c = LogCluster(
            template=["ERROR", "db", "down"],
            count=3,
            raw_samples=["→ ERROR db down\n  10:00:01 INFO heartbeat"],
        )
        rca.analyze(c)
        call_args = mock_anthropic.return_value.messages.create.call_args
        user_content = call_args[1]["messages"][0]["content"]
        assert "Incident context" in user_content

    def test_analyze_truncates_oversized_prompt(self, mock_anthropic):
        """Line 1015: prompt longer than LLM_BUDGET_CHARS is trimmed."""
        rca = self._make_rca(mock_anthropic)
        # Build a cluster whose raw_sample alone exceeds the budget
        huge_sample = "x" * (sra.LLM_BUDGET_CHARS + 500)
        c = LogCluster(
            template=["ERROR", "overflow"],
            count=1,
            raw_samples=[huge_sample],
        )
        rca.analyze(c)
        call_args = mock_anthropic.return_value.messages.create.call_args
        user_content = call_args[1]["messages"][0]["content"]
        assert "…[truncated]" in user_content

    def test_refresh_codebase_no_indexer_returns_false(self, mock_anthropic):
        rca = self._make_rca(mock_anthropic)
        assert rca._indexer is None
        assert rca.refresh_codebase() is False

    def test_refresh_codebase_before_refresh_hour_returns_false(self, mock_anthropic):
        mock_indexer = MagicMock()
        rca = self._make_rca(mock_anthropic, indexer=mock_indexer)
        rca._last_refresh_date = None

        # Patch datetime to return an hour before the refresh window
        with (
            patch.object(
                sra,
                "_EASTERN",
                timezone.utc,  # use UTC to avoid DST complexity
            ),
            patch("splunk_rca_agent.datetime") as mock_dt,
        ):
            mock_now = MagicMock()
            mock_now.hour = 3  # before CODEBASE_REFRESH_HOUR (7)
            mock_now.date.return_value = date.today()
            mock_dt.now.return_value = mock_now
            result = rca.refresh_codebase()
        assert result is False

    def test_refresh_codebase_already_done_today_returns_false(self, mock_anthropic):
        mock_indexer = MagicMock()
        rca = self._make_rca(mock_anthropic, indexer=mock_indexer)
        today = date.today()
        rca._last_refresh_date = today

        with patch("splunk_rca_agent.datetime") as mock_dt:
            mock_now = MagicMock()
            mock_now.hour = 9
            mock_now.date.return_value = today
            mock_dt.now.return_value = mock_now
            result = rca.refresh_codebase()
        assert result is False

    def test_refresh_codebase_triggers_full_reindex(self, mock_anthropic):
        mock_indexer = MagicMock()
        mock_indexer.build_arch_summary.return_value = "# Arch summary"
        rca = self._make_rca(mock_anthropic, indexer=mock_indexer)
        rca._last_refresh_date = None

        with patch("splunk_rca_agent.datetime") as mock_dt:
            mock_now = MagicMock()
            mock_now.hour = 9  # past CODEBASE_REFRESH_HOUR=7
            today = date.today()
            mock_now.date.return_value = today
            mock_dt.now.return_value = mock_now
            result = rca.refresh_codebase()

        assert result is True
        mock_indexer.force_reindex.assert_called_once()
        mock_indexer.build_arch_summary.assert_called()
        assert rca._last_refresh_date == today
        assert rca._arch_block is not None

    def test_refresh_codebase_empty_arch_clears_block(self, mock_anthropic):
        mock_indexer = MagicMock()
        mock_indexer.build_arch_summary.return_value = ""  # empty
        rca = self._make_rca(mock_anthropic, indexer=mock_indexer)
        rca._arch_block = {"type": "text", "text": "old arch"}
        rca._last_refresh_date = None

        with patch("splunk_rca_agent.datetime") as mock_dt:
            mock_now = MagicMock()
            mock_now.hour = 9
            mock_now.date.return_value = date.today()
            mock_dt.now.return_value = mock_now
            rca.refresh_codebase()

        assert rca._arch_block is None


# ── EmailReporter ─────────────────────────────────────────────────────────────


class TestEmailReporter:
    def _make_clusters_and_analyses(self):
        c = LogCluster(
            template=["ERROR", "database", "connection", "failed"],
            count=42,
            severity="ERROR",
        )
        analyses = {
            c.cluster_id: {
                "summary": "DB connection pool exhausted",
                "technical_context": "All 20 connections in use",
                "root_cause": "Pool size too small for load",
                "action_items": ["Increase pool size", "Add read replica"],
            }
        }
        stats = CompressionStats(
            raw=1000,
            context_lines=5000,
            unique=100,
            compressed=80,
            clusters=5,
            merged=4,
            llm_sent=1,
        )
        return [c], analyses, stats

    @staticmethod
    def _decode_html(mime_string: str) -> str:
        """Parse the multipart MIME message and return the decoded HTML body.

        EmailReporter uses Content-Transfer-Encoding: base64 for the HTML part,
        so raw MIME string comparisons fail.  This helper walks the message parts
        and base64-decodes the text/html payload so tests can assert on real HTML.
        """
        msg = _email_module.message_from_string(mime_string)
        for part in msg.walk():
            if part.get_content_type() == "text/html":
                return part.get_payload(decode=True).decode("utf-8")
        # Fallback: message has no multipart structure — return as-is
        return mime_string

    def test_send_calls_smtp(self, mock_smtp):
        reporter = EmailReporter()
        clusters, analyses, stats = self._make_clusters_and_analyses()
        reporter.send(clusters, analyses, stats)
        mock_smtp.assert_called_once()

    def test_send_uses_starttls(self, mock_smtp):
        reporter = EmailReporter()
        clusters, analyses, stats = self._make_clusters_and_analyses()
        reporter.send(clusters, analyses, stats)
        smtp_instance = mock_smtp.return_value.__enter__.return_value
        smtp_instance.starttls.assert_called_once()

    def test_send_multiple_recipients(self, mock_smtp):
        original = sra.EMAIL_TO
        sra.EMAIL_TO = "alice@example.com,bob@example.com"
        try:
            reporter = EmailReporter()
            clusters, analyses, stats = self._make_clusters_and_analyses()
            reporter.send(clusters, analyses, stats)
            smtp_instance = mock_smtp.return_value.__enter__.return_value
            sendmail_call = smtp_instance.sendmail.call_args
            recipients = sendmail_call[0][1]
            assert len(recipients) == 2
        finally:
            sra.EMAIL_TO = original

    def test_send_subject_includes_cluster_count(self, mock_smtp):
        reporter = EmailReporter()
        clusters, analyses, stats = self._make_clusters_and_analyses()
        reporter.send(clusters, analyses, stats)
        smtp_instance = mock_smtp.return_value.__enter__.return_value
        # sendmail is called with the email as string — check it contains cluster count
        email_body = smtp_instance.sendmail.call_args[0][2]
        assert "1 cluster" in email_body

    def test_send_html_contains_rca_fields(self, mock_smtp):
        reporter = EmailReporter()
        clusters, analyses, stats = self._make_clusters_and_analyses()
        reporter.send(clusters, analyses, stats)
        smtp_instance = mock_smtp.return_value.__enter__.return_value
        html = self._decode_html(smtp_instance.sendmail.call_args[0][2])
        assert "DB connection pool exhausted" in html
        assert "Pool size too small" in html
        assert "Increase pool size" in html

    def test_send_sorts_clusters_by_count_descending(self, mock_smtp):
        c1 = LogCluster(template=["ERROR", "low", "count"], count=5, severity="ERROR")
        c2 = LogCluster(template=["ERROR", "high", "count"], count=100, severity="CRITICAL")
        analyses = {
            c1.cluster_id: {
                "summary": "low",
                "technical_context": "",
                "root_cause": "",
                "action_items": [],
            },
            c2.cluster_id: {
                "summary": "high",
                "technical_context": "",
                "root_cause": "",
                "action_items": [],
            },
        }
        stats = CompressionStats(llm_sent=2)
        reporter = EmailReporter()
        reporter.send([c1, c2], analyses, stats)
        html = self._decode_html(
            mock_smtp.return_value.__enter__.return_value.sendmail.call_args[0][2]
        )
        # "high" cluster card should appear before "low" cluster card
        assert html.index("high") < html.index("low")

    def test_send_unknown_rca_shows_na(self, mock_smtp):
        c = LogCluster(template=["ERROR", "unknown"], count=3, severity="ERROR")
        reporter = EmailReporter()
        reporter.send([c], {}, CompressionStats(llm_sent=1))
        html = self._decode_html(
            mock_smtp.return_value.__enter__.return_value.sendmail.call_args[0][2]
        )
        assert "N/A" in html


# ── SplunkClient utilities ────────────────────────────────────────────────────


class TestSplunkClientUtils:
    """Tests for pure-utility methods that don't require a live Splunk instance."""

    def test_esc_leaves_plain_string_unchanged(self):
        assert sra.SplunkClient._esc("hello world") == "hello world"

    def test_esc_escapes_double_quotes(self):
        """Line 648: backslash-escape embedded double-quotes for SPL safety."""
        assert sra.SplunkClient._esc('host="web-01"') == 'host=\\"web-01\\"'

    def test_esc_escapes_multiple_quotes(self):
        assert sra.SplunkClient._esc('"a" and "b"') == '\\"a\\" and \\"b\\"'


# ── LogMonitorAgent ───────────────────────────────────────────────────────────


class TestLogMonitorAgent:
    def _make_agent(self, mock_anthropic, mock_smtp, mock_splunk_session):
        with patch("splunk_rca_agent.CodebaseIndexer.from_env", return_value=None):
            agent = LogMonitorAgent()
        return agent

    def test_init_without_github(self, mock_anthropic, mock_smtp, mock_splunk_session):
        with patch("splunk_rca_agent.CodebaseIndexer.from_env", return_value=None):
            agent = LogMonitorAgent()
        assert agent.splunk is not None
        assert agent.rca is not None
        assert agent._reported == {}

    def test_prune_dedup_removes_expired(self, mock_anthropic, mock_smtp, mock_splunk_session):
        agent = self._make_agent(mock_anthropic, mock_smtp, mock_splunk_session)
        old_ts = time.time() - (DEDUP_WINDOW_MINS + 10) * 60
        agent._reported["expired"] = old_ts
        agent._reported["fresh"] = time.time()
        agent._prune_dedup()
        assert "expired" not in agent._reported
        assert "fresh" in agent._reported

    def test_split_new_known_correctly_partitions(
        self, mock_anthropic, mock_smtp, mock_splunk_session
    ):
        agent = self._make_agent(mock_anthropic, mock_smtp, mock_splunk_session)
        c_new = LogCluster(template=["ERROR", "brand", "new"], count=5)
        c_known = LogCluster(template=["WARN", "already", "seen"], count=3)
        agent._reported[c_known.cluster_id] = time.time()

        new, known = agent._split_new_known([c_new, c_known])
        assert c_new in new
        assert c_known in known

    def test_run_once_quiet_returns_false(self, mock_anthropic, mock_smtp, mock_splunk_session):
        agent = self._make_agent(mock_anthropic, mock_smtp, mock_splunk_session)
        agent.splunk = MagicMock()
        agent.splunk.fetch_anomalies.return_value = []

        result = agent.run_once()
        assert result is False

    def test_run_once_no_clusters_returns_false(
        self, mock_anthropic, mock_smtp, mock_splunk_session
    ):
        agent = self._make_agent(mock_anthropic, mock_smtp, mock_splunk_session)
        agent.splunk = MagicMock()
        agent.splunk.fetch_anomalies.return_value = [("ERROR db down", ["ERROR db down"])]

        with patch("splunk_rca_agent.compress_events", return_value=([], MagicMock())):
            result = agent.run_once()
        assert result is False

    def test_run_once_all_known_returns_false(self, mock_anthropic, mock_smtp, mock_splunk_session):
        agent = self._make_agent(mock_anthropic, mock_smtp, mock_splunk_session)
        agent.splunk = MagicMock()
        agent.splunk.fetch_anomalies.return_value = [("ERROR db down", ["ERROR db down"])]

        cluster = LogCluster(template=["ERROR", "db", "down"], count=10)
        agent._reported[cluster.cluster_id] = time.time()

        mock_stats = MagicMock()
        mock_stats.llm_sent = 0
        with patch("splunk_rca_agent.compress_events", return_value=([cluster], mock_stats)):
            result = agent.run_once()
        assert result is False

    def test_run_once_new_cluster_sends_alert(self, mock_anthropic, mock_smtp, mock_splunk_session):
        agent = self._make_agent(mock_anthropic, mock_smtp, mock_splunk_session)
        agent.splunk = MagicMock()
        agent.splunk.fetch_anomalies.return_value = [("ERROR db down", ["ERROR db down"])]
        agent.reporter = MagicMock()

        cluster = LogCluster(template=["ERROR", "db", "down"], count=10)
        mock_stats = MagicMock()
        mock_stats.summary.return_value = "1 cluster"

        with patch("splunk_rca_agent.compress_events", return_value=([cluster], mock_stats)):
            result = agent.run_once()

        assert result is True
        agent.reporter.send.assert_called_once()
        assert cluster.cluster_id in agent._reported

    def test_run_once_marks_reported_before_send(
        self, mock_anthropic, mock_smtp, mock_splunk_session
    ):
        """Cluster should be marked as reported even if send() raises."""
        agent = self._make_agent(mock_anthropic, mock_smtp, mock_splunk_session)
        agent.splunk = MagicMock()
        agent.splunk.fetch_anomalies.return_value = [("ERROR db down", [])]
        agent.reporter = MagicMock()
        agent.reporter.send.side_effect = Exception("SMTP failure")

        cluster = LogCluster(template=["ERROR", "db", "down"], count=10)
        mock_stats = MagicMock()
        mock_stats.summary.return_value = ""

        with patch("splunk_rca_agent.compress_events", return_value=([cluster], mock_stats)):
            with pytest.raises(Exception, match="SMTP failure"):
                agent.run_once()

        # Despite send() crashing, the cluster must already be in _reported
        assert cluster.cluster_id in agent._reported

    def test_run_once_codebase_refresh_called(self, mock_anthropic, mock_smtp, mock_splunk_session):
        agent = self._make_agent(mock_anthropic, mock_smtp, mock_splunk_session)
        agent.splunk = MagicMock()
        agent.splunk.fetch_anomalies.return_value = []
        agent.rca = MagicMock()
        agent.rca._indexer = None

        agent.run_once()
        agent.rca.refresh_codebase.assert_called_once()
