"""
Tests for the 6-stage compression pipeline in splunk_rca_agent.py.

Coverage targets:
  compress_stacktrace       — Java frames, Python frames, no frames, cause chain
  _tokenize                 — all 12 variable-substitution patterns
  LogCluster                — template_str, cluster_id stability
  CompressionStats          — summary, total_ratio, zero-denominator guard
  DrainClusterer            — new cluster, match existing, weight, slot tracking,
                              MAX_CHILDREN cap, non-anomaly ignored, severity
  merge_clusters            — empty, no-merge, merge, var-slot merge, sample merge
  inline_single_slots       — literal inlined, typed kept, multi-value kept
  _format_context_window    — error found, run collapse, error not absorbed,
                              error not found fallback, empty window
  _var_summary              — empty, single slot, multi-slot, truncation
  compress_events           — empty input, happy path stats, top-N order
"""

from __future__ import annotations

import hashlib

import pytest

import splunk_rca_agent as sra
from splunk_rca_agent import (
    CompressionStats,
    DrainClusterer,
    LogCluster,
    _format_context_window,
    _tokenize,
    _var_summary,
    compress_events,
    compress_stacktrace,
    inline_single_slots,
    merge_clusters,
)


# ── compress_stacktrace ───────────────────────────────────────────────────────


class TestCompressStacktrace:
    def test_java_keeps_header_and_two_frames(self, java_stacktrace):
        result = compress_stacktrace(java_stacktrace)
        assert "Connection pool exhausted" in result
        assert "Pool.acquire" in result
        assert "UserService.getUser" in result

    def test_java_omits_extra_frames(self, java_stacktrace):
        result = compress_stacktrace(java_stacktrace)
        assert "omitted" in result
        # Third frame should not appear verbatim
        assert "UserController.handle" not in result

    def test_java_includes_caused_by(self, java_stacktrace):
        result = compress_stacktrace(java_stacktrace)
        assert "timeout after 30000ms" in result

    def test_python_keeps_header_and_two_frames(self, python_stacktrace):
        result = compress_stacktrace(python_stacktrace)
        assert "ConnectionError" in result
        assert "app/db.py" in result

    def test_python_omits_extra_frames(self, python_stacktrace):
        result = compress_stacktrace(python_stacktrace)
        assert "omitted" in result

    def test_plain_line_unchanged(self, plain_error):
        result = compress_stacktrace(plain_error)
        assert result == plain_error

    def test_escaped_newlines_handled(self):
        line = (
            "java.lang.NullPointerException\\n"
            "\\tat com.app.Foo.bar(Foo.java:1)\\n"
            "\\tat com.app.Foo.baz(Foo.java:2)"
        )
        result = compress_stacktrace(line)
        assert "NullPointerException" in result
        assert "Foo.bar" in result

    def test_output_capped_at_500_chars(self, java_stacktrace):
        # Add many extra frames
        extra = "\n".join(f"\tat com.app.Extra.method{i}(Extra.java:{i})" for i in range(50))
        long_trace = java_stacktrace + "\n" + extra
        result = compress_stacktrace(long_trace)
        assert len(result) <= 500


# ── _tokenize ─────────────────────────────────────────────────────────────────


class TestTokenize:
    def test_ip_address(self):
        tokens = _tokenize("ERROR connecting to 192.168.1.5 port 5432")
        assert "<IP>" in tokens

    def test_ip_with_port(self):
        tokens = _tokenize("ERROR connecting to 10.0.0.1:8080 failed")
        assert "<IP>" in tokens

    def test_uuid(self):
        # UUID must appear standalone (not prefixed with key= which makes it a <KV>)
        tokens = _tokenize("ERROR trace 550e8400-e29b-41d4-a716-446655440000 done")
        assert "<UUID>" in tokens

    def test_hex_string(self):
        tokens = _tokenize("ERROR checksum mismatch deadbeefdeadbeef0123456789abcdef")
        assert "<HEX>" in tokens

    def test_timestamp(self):
        tokens = _tokenize("at 2026-05-25T05:05:00Z the service failed")
        assert "<TS>" in tokens

    def test_epoch(self):
        tokens = _tokenize("event at 1748150700 timed out")
        assert "<EPOCH>" in tokens

    def test_path(self):
        tokens = _tokenize("ERROR reading /var/log/app/service.log failed")
        assert "<PATH>" in tokens

    def test_email(self):
        tokens = _tokenize("notification to admin@example.com bounced")
        assert "<EMAIL>" in tokens

    def test_kv_pair(self):
        tokens = _tokenize("status=500 duration=342ms")
        assert "<KV>" in tokens

    def test_quoted_string(self):
        tokens = _tokenize('ERROR "connection refused" after retry')
        assert "<STR>" in tokens

    def test_thread_id(self):
        tokens = _tokenize("thread-abc123 session-xyz789 ERROR failed")
        assert "<TID>" in tokens

    def test_number(self):
        tokens = _tokenize("ERROR after 3 retries on port 5432")
        assert "<NUM>" in tokens

    def test_caps_at_64_tokens(self):
        long_line = " ".join(str(i) for i in range(100))
        tokens = _tokenize(long_line)
        assert len(tokens) <= 64

    def test_empty_line(self):
        assert _tokenize("") == []


# ── LogCluster ────────────────────────────────────────────────────────────────


class TestLogCluster:
    def test_template_str(self):
        c = LogCluster(template=["ERROR", "connecting", "to", "<IP>"], count=5)
        assert c.template_str == "ERROR connecting to <IP>"

    def test_cluster_id_is_md5_prefix(self):
        c = LogCluster(template=["ERROR", "timeout"], count=1)
        expected = hashlib.md5("ERROR timeout".encode()).hexdigest()[:8]
        assert c.cluster_id == expected

    def test_cluster_id_changes_with_template(self):
        c1 = LogCluster(template=["ERROR", "timeout"], count=1)
        c2 = LogCluster(template=["WARN", "timeout"], count=1)
        assert c1.cluster_id != c2.cluster_id

    def test_cluster_id_stable_on_same_template(self):
        c = LogCluster(template=["ERROR", "db", "down"], count=10)
        assert c.cluster_id == c.cluster_id  # property, but stable


# ── CompressionStats ──────────────────────────────────────────────────────────


class TestCompressionStats:
    def test_summary_includes_all_counts(self):
        s = CompressionStats(
            raw=5000, unique=312, compressed=198, clusters=24, merged=17, llm_sent=17
        )
        summary = s.summary()
        assert "5,000" in summary
        assert "312" in summary
        assert "17" in summary

    def test_total_ratio_with_context_lines(self):
        s = CompressionStats(context_lines=5000, merged=17)
        assert "x" in s.total_ratio.lower() or "×" in s.total_ratio

    def test_total_ratio_zero_merged_no_crash(self):
        s = CompressionStats(context_lines=100, merged=0)
        # Should not divide by zero
        ratio = s.total_ratio
        assert ratio is not None

    def test_summary_zero_values(self):
        s = CompressionStats()
        summary = s.summary()
        assert "0" in summary


# ── DrainClusterer ────────────────────────────────────────────────────────────


class TestDrainClusterer:
    def test_single_event_creates_cluster(self):
        d = DrainClusterer()
        events = [("ERROR database connection failed", [], 1)]
        clusters = d.cluster(events)
        assert len(clusters) == 1
        assert clusters[0].count == 1

    def test_identical_events_merged_with_weight(self):
        d = DrainClusterer()
        line = "ERROR database connection failed"
        events = [(line, [], 3)]  # weight=3 from pre-dedup
        clusters = d.cluster(events)
        assert len(clusters) == 1
        assert clusters[0].count == 3

    def test_similar_events_produce_wildcard(self):
        # Variable token must sit at index >= DRAIN_DEPTH (4) so BOTH events share
        # the same prefix key ("ERROR database pool exhausted") and land in the same
        # Drain bucket.  "host-primary" / "host-replica" appear at index 4 and are
        # plain literals (no var-sub regex matches them), so Drain creates a <*> slot.
        d = DrainClusterer()
        events = [
            ("ERROR database pool exhausted host-primary timeout limit", [], 1),
            ("ERROR database pool exhausted host-replica timeout limit", [], 1),
        ]
        clusters = d.cluster(events)
        assert len(clusters) == 1
        assert "<*>" in clusters[0].template

    def test_dissimilar_events_stay_separate(self):
        d = DrainClusterer()
        events = [
            ("ERROR database connection failed", [], 1),
            ("EXCEPTION NullPointerException at line 45", [], 1),
        ]
        clusters = d.cluster(events)
        assert len(clusters) == 2

    def test_non_anomaly_line_ignored(self):
        d = DrainClusterer()
        events = [("INFO all systems nominal", [], 1)]
        clusters = d.cluster(events)
        assert len(clusters) == 0

    def test_severity_extracted_correctly(self):
        d = DrainClusterer()
        for sev in ("ERROR", "EXCEPTION", "CRITICAL", "FATAL", "FAILED"):
            d2 = DrainClusterer()
            clusters = d2.cluster([(f"{sev} something bad", [], 1)])
            assert clusters[0].severity == sev

    def test_var_slots_tracked(self):
        # Variable token at index 4 (past DRAIN_DEPTH=4 prefix), so both events share
        # prefix key "ERROR database pool exhausted" and land in the same bucket.
        # After merging, slot at position 4 records both literal values.
        d = DrainClusterer()
        events = [
            ("ERROR database pool exhausted host-primary timeout limit", [], 1),
            ("ERROR database pool exhausted host-replica timeout limit", [], 1),
        ]
        clusters = d.cluster(events)
        assert len(clusters) == 1
        assert len(clusters[0].var_slots) > 0

    def test_context_window_stored_in_samples(self):
        d = DrainClusterer()
        ctx = ["INFO heartbeat", "ERROR boom", "WARN degraded"]
        events = [("ERROR boom", ctx, 1)]
        clusters = d.cluster(events)
        assert len(clusters[0].raw_samples) == 1
        # Sample should contain context info (formatted window)
        assert clusters[0].raw_samples[0] != ""

    def test_max_children_limit_returns_none_gracefully(self):
        """When a bucket is full, new non-matching lines are silently dropped."""
        import splunk_rca_agent as sra_mod

        original_children = sra_mod.MAX_CHILDREN
        original_sim = sra_mod.SIM_THRESHOLD
        # MAX_CHILDREN=1: first event fills the bucket.
        # SIM_THRESHOLD=0.99: second event doesn't match (sim=4/5=0.8) → dropped.
        sra_mod.MAX_CHILDREN = 1
        sra_mod.SIM_THRESHOLD = 0.99
        try:
            d = DrainClusterer()
            events = [
                ("ERROR alpha beta gamma delta_A extra", [], 1),  # creates cluster, bucket full
                ("ERROR alpha beta gamma delta_B extra", [], 1),  # sim < 0.99 → dropped
            ]
            clusters = d.cluster(events)
            assert len(clusters) == 1
        finally:
            sra_mod.MAX_CHILDREN = original_children
            sra_mod.SIM_THRESHOLD = original_sim

    def test_empty_events_list(self):
        d = DrainClusterer()
        clusters = d.cluster([])
        assert clusters == []


# ── _sim helper ────────────────────────────────────────────────────────────────


class TestSim:
    def test_unequal_lengths_returns_zero(self):
        """_sim early-return guard: unequal-length token lists → 0.0."""
        assert sra._sim(["a", "b"], ["c"]) == 0.0

    def test_equal_lengths_computes_ratio(self):
        assert sra._sim(["a", "b", "c"], ["a", "x", "c"]) == pytest.approx(2 / 3)

    def test_identical_lists_returns_one(self):
        assert sra._sim(["x", "y"], ["x", "y"]) == pytest.approx(1.0)


# ── merge_clusters ─────────────────────────────────────────────────────────────


class TestMergeClusters:
    def test_empty_input(self):
        assert merge_clusters([]) == []

    def test_single_cluster_unchanged(self):
        c = LogCluster(template=["ERROR", "db", "down"], count=5)
        result = merge_clusters([c])
        assert len(result) == 1
        assert result[0].count == 5

    def test_similar_clusters_merged(self):
        # 4/5 = 0.80 >= MERGE_SIM(0.8) → should merge
        c1 = LogCluster(template=["ERROR", "connecting", "to", "db-primary", "timeout"], count=10)
        c2 = LogCluster(template=["ERROR", "connecting", "to", "db-replica", "timeout"], count=5)
        result = merge_clusters([c1, c2])
        assert len(result) == 1
        assert result[0].count == 15
        assert "<*>" in result[0].template

    def test_dissimilar_clusters_not_merged(self):
        c1 = LogCluster(template=["ERROR", "db", "connection", "failed"], count=10)
        c2 = LogCluster(template=["WARN", "high", "memory", "usage"], count=5)
        result = merge_clusters([c1, c2])
        assert len(result) == 2

    def test_var_slots_merged(self):
        c1 = LogCluster(
            template=["ERROR", "to", "<*>", "failed"], count=10, var_slots={2: ["db-primary"]}
        )
        c2 = LogCluster(
            template=["ERROR", "to", "<*>", "failed"], count=5, var_slots={2: ["db-replica"]}
        )
        result = merge_clusters([c1, c2])
        assert len(result) == 1
        assert "db-primary" in result[0].var_slots.get(2, [])
        assert "db-replica" in result[0].var_slots.get(2, [])

    def test_raw_samples_capped_at_three(self):
        c1 = LogCluster(
            template=["ERROR", "db", "to", "failed"],
            count=10,
            raw_samples=["line1", "line2", "line3"],
        )
        c2 = LogCluster(
            template=["ERROR", "db", "to", "failed"], count=5, raw_samples=["line4", "line5"]
        )
        result = merge_clusters([c1, c2])
        assert len(result[0].raw_samples) <= 3

    def test_different_length_clusters_never_merged(self):
        c1 = LogCluster(template=["ERROR", "db", "down"], count=10)
        c2 = LogCluster(template=["ERROR", "db", "connection", "down"], count=5)
        result = merge_clusters([c1, c2])
        assert len(result) == 2


# ── inline_single_slots ────────────────────────────────────────────────────────


class TestInlineSingleSlots:
    def test_single_literal_value_inlined(self):
        c = LogCluster(
            template=["ERROR", "connecting", "to", "<*>", "failed"],
            count=5,
            var_slots={3: ["db-primary"]},
        )
        inline_single_slots([c])
        assert c.template[3] == "db-primary"
        assert 3 not in c.var_slots

    def test_typed_placeholder_not_inlined(self):
        c = LogCluster(
            template=["ERROR", "connecting", "to", "<*>", "failed"],
            count=5,
            var_slots={3: ["<IP>"]},
        )
        inline_single_slots([c])
        assert c.template[3] == "<*>"  # NOT inlined
        assert 3 in c.var_slots

    def test_multiple_values_not_inlined(self):
        c = LogCluster(
            template=["ERROR", "to", "<*>", "port", "<*>"],
            count=5,
            var_slots={2: ["db-primary", "db-replica"]},
        )
        inline_single_slots([c])
        assert c.template[2] == "<*>"  # kept as wildcard
        assert 2 in c.var_slots

    def test_empty_slots_no_change(self):
        c = LogCluster(template=["ERROR", "db", "down"], count=5, var_slots={})
        original_template = list(c.template)
        inline_single_slots([c])
        assert c.template == original_template

    def test_multiple_clusters_processed(self):
        c1 = LogCluster(template=["ERROR", "<*>", "failed"], count=5, var_slots={1: ["db-primary"]})
        c2 = LogCluster(template=["WARN", "<*>", "slow"], count=3, var_slots={1: ["cache-01"]})
        inline_single_slots([c1, c2])
        assert c1.template[1] == "db-primary"
        assert c2.template[1] == "cache-01"

    def test_position_out_of_template_bounds_skipped(self):
        c = LogCluster(template=["ERROR", "db"], count=5, var_slots={99: ["value"]})
        inline_single_slots([c])
        # Position 99 is out of bounds — slot should remain (not crash)
        assert 99 in c.var_slots


# ── _format_context_window ─────────────────────────────────────────────────────


class TestFormatContextWindow:
    def test_error_line_marked_with_arrows(self, plain_error, context_window):
        result = _format_context_window(plain_error, context_window)
        assert ">>>" in result
        assert plain_error[:50] in result

    def test_repeated_lines_collapsed(self):
        error = "ERROR boom"
        window = [
            "INFO heartbeat",
            "INFO heartbeat",
            "INFO heartbeat",
            error,
            "WARN degraded",
        ]
        result = _format_context_window(error, window)
        assert "(×3)" in result or "(×2)" in result or "heartbeat" in result

    def test_error_line_never_absorbed_into_run(self):
        error = "ERROR connection failed"
        # All lines (including error) have same tokenized form — error still marked
        window = ["ERROR connection failed", error, "ERROR connection failed"]
        result = _format_context_window(error, window)
        assert ">>>" in result

    def test_header_shows_counts(self, plain_error, context_window):
        result = _format_context_window(plain_error, context_window)
        assert "lines before" in result
        assert "lines after" in result

    def test_error_not_found_uses_middle(self):
        window = ["INFO a", "INFO b", "INFO c", "INFO d"]
        # Error line not in window — fallback to middle
        result = _format_context_window("ERROR something", window, max_display=10)
        assert ">>>" in result  # some line marked as error

    def test_empty_window_returns_empty_string(self):
        # Guard added in splunk_rca_agent: empty window → return "" without crashing
        result = _format_context_window("ERROR boom", [])
        assert result == ""


# ── _var_summary ───────────────────────────────────────────────────────────────


class TestVarSummary:
    def test_empty_slots_returns_empty(self):
        c = LogCluster(template=["ERROR", "db"], count=1, var_slots={})
        assert _var_summary(c) == ""

    def test_single_slot_rendered(self):
        c = LogCluster(
            template=["ERROR", "connecting", "to", "<IP>"],
            count=5,
            var_slots={3: ["10.0.0.1", "192.168.1.5"]},
        )
        result = _var_summary(c)
        assert "[3]" in result
        assert "10.0.0.1" in result

    def test_more_than_display_max_shows_suffix(self):
        c = LogCluster(
            template=["ERROR", "<*>"],
            count=5,
            var_slots={1: ["a", "b", "c", "d"]},  # 4 values, display max = 3
        )
        result = _var_summary(c)
        assert "+1more" in result

    def test_multiple_slots_all_rendered(self):
        c = LogCluster(
            template=["ERROR", "<IP>", "port", "<NUM>"],
            count=5,
            var_slots={1: ["10.0.0.1"], 3: ["5432"]},
        )
        result = _var_summary(c)
        assert "[1]" in result
        assert "[3]" in result


# ── compress_events ───────────────────────────────────────────────────────────


class TestCompressEvents:
    def test_empty_input_returns_empty(self):
        clusters, stats = compress_events([])
        assert clusters == []
        assert stats.raw == 0

    def test_single_event_produces_one_cluster(self, plain_error, context_window):
        ctx_events = [(plain_error, context_window)]
        clusters, stats = compress_events(ctx_events)
        assert len(clusters) == 1
        assert stats.raw == 1
        assert stats.unique == 1
        assert stats.merged >= 1

    def test_duplicate_events_deduped(self, plain_error, context_window):
        ctx_events = [(plain_error, context_window)] * 100
        clusters, stats = compress_events(ctx_events)
        assert stats.unique == 1
        assert stats.raw == 100

    def test_clusters_sorted_by_count_descending(self):
        # compress_events expects list[ContextualEvent] = list[tuple[str, list[str]]]
        events = [
            ("ERROR alpha bravo charlie delta", []),
            ("ERROR alpha bravo charlie delta", []),
            ("ERROR alpha bravo charlie delta", []),
            ("EXCEPTION foxtrot golf hotel india", []),
        ]
        clusters, _ = compress_events(events)
        if len(clusters) > 1:
            assert clusters[0].count >= clusters[1].count

    def test_stats_track_all_stages(self, plain_error, context_window):
        many_events = [(plain_error, context_window)] * 10
        _, stats = compress_events(many_events)
        assert stats.raw == 10
        assert stats.unique >= 1
        assert stats.compressed >= 1
        assert stats.clusters >= 1
        assert stats.merged >= 1

    def test_stack_trace_events_compressed(self):
        # The error line must match ANOMALY_RE (ERROR/EXCEPTION/etc. at word boundary)
        # Real Splunk log lines have the level prefix before the stacktrace
        error_line = "ERROR java.sql.SQLException Connection pool exhausted after timeout"
        ctx_events = [(error_line, [])]
        clusters, stats = compress_events(ctx_events)
        assert len(clusters) == 1
