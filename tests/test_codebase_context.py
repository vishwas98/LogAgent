"""
Tests for codebase_context.py.

Coverage targets:
  CodebaseIndexer.extract_keywords  — exception names, FQN, static tokens, slots, filtering
  CodebaseIndexer.find_snippets     — no keywords, keyword match, no match, snippet cap
  CodebaseIndexer.build_arch_summary — content sections, char cap, missing files
  CodebaseIndexer.from_env          — no token, bad repo format, success
  CodebaseIndexer.get_head_sha      — success, failure returns None
  CodebaseIndexer.refresh_if_stale  — same sha, new sha, github failure
  CodebaseIndexer.force_reindex     — clears caches
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from codebase_context import CodebaseIndexer


# ── Fixtures ───────────────────────────────────────────────────────────────────


def _make_indexer(tree=None, files=None):
    """Build a CodebaseIndexer with mocked HTTP session and pre-loaded cache."""
    idx = CodebaseIndexer(token="ghp_test", owner="acme", repo="backend", branch="main")
    # Pre-load tree cache so no HTTP calls needed
    if tree is not None:
        idx._tree = tree
    if files is not None:
        idx._files = files
    return idx


SAMPLE_TREE = [
    {"path": "README.md", "type": "blob", "sha": "aaa", "size": 100},
    {"path": "src/db/ConnectionPool.py", "type": "blob", "sha": "bbb", "size": 500},
    {"path": "src/exception_handler.py", "type": "blob", "sha": "ccc", "size": 300},
    {"path": "tests/test_db.py", "type": "blob", "sha": "ddd", "size": 200},
    {"path": "requirements.txt", "type": "blob", "sha": "eee", "size": 50},
]

SAMPLE_FILES = {
    "README.md": "# Backend Service\nHandles user auth and DB connections.\n",
    "src/db/ConnectionPool.py": (
        "class ConnectionPool:\n"
        "    def acquire(self):\n"
        "        if self.pool.isEmpty():\n"
        "            raise PoolExhaustedException('No connections available')\n"
        "        return self.pool.pop()\n"
    ),
    "src/exception_handler.py": (
        "def handle_db_error(exc):\n    log.error('DB error: %s', exc)\n    return 503\n"
    ),
    "requirements.txt": "requests==2.31.0\nanthropics==0.20.0\n",
}


# ── extract_keywords ────────────────────────────────────────────────────────────


class TestExtractKeywords:
    def test_camel_case_exception_extracted(self):
        idx = _make_indexer()
        kws = idx.extract_keywords("PoolExhaustedException occurred at startup", {})
        assert "PoolExhaustedException" in kws

    def test_service_class_extracted(self):
        idx = _make_indexer()
        kws = idx.extract_keywords("UserService failed to connect", {})
        assert "UserService" in kws

    def test_fqn_last_segment_extracted(self):
        idx = _make_indexer()
        kws = idx.extract_keywords("com.app.db.ConnectionPool timeout", {})
        assert "ConnectionPool" in kws

    def test_static_tokens_long_enough(self):
        idx = _make_indexer()
        kws = idx.extract_keywords("ERROR connecting timeout", {})
        # "connecting" and "timeout" are ≥4 chars
        assert "connecting" in kws or "timeout" in kws

    def test_short_tokens_filtered_out(self):
        idx = _make_indexer()
        kws = idx.extract_keywords("at to is db", {})
        # All tokens < 4 chars — no static keywords
        for kw in kws:
            assert len(kw) >= 4

    def test_wildcards_excluded(self):
        idx = _make_indexer()
        kws = idx.extract_keywords("<IP> <NUM> <UUID>", {})
        assert "<IP>" not in kws
        assert "<NUM>" not in kws

    def test_slot_identifier_values_included(self):
        idx = _make_indexer()
        kws = idx.extract_keywords("ERROR connecting to <*>", {2: ["db-primary"]})
        assert "db-primary" in kws

    def test_slot_ip_values_excluded(self):
        idx = _make_indexer()
        kws = idx.extract_keywords("ERROR to <*>", {2: ["10.0.0.1"]})
        # IP addresses should not be included (don't match identifier pattern)
        assert "10.0.0.1" not in kws

    def test_returns_at_most_15(self):
        idx = _make_indexer()
        # Very long template with many tokens
        template = " ".join(f"ExceptionClass{i}" for i in range(30))
        kws = idx.extract_keywords(template, {})
        assert len(kws) <= 15


# ── find_snippets ──────────────────────────────────────────────────────────────


class TestFindSnippets:
    def test_empty_keywords_returns_empty(self):
        idx = _make_indexer(tree=SAMPLE_TREE, files=SAMPLE_FILES)
        assert idx.find_snippets([]) == ""

    def test_keyword_match_returns_snippet(self):
        idx = _make_indexer(tree=SAMPLE_TREE, files=SAMPLE_FILES)
        result = idx.find_snippets(["ConnectionPool"])
        assert "ConnectionPool" in result

    def test_no_matching_keyword_returns_empty(self):
        idx = _make_indexer(tree=SAMPLE_TREE, files=SAMPLE_FILES)
        result = idx.find_snippets(["XYZNonExistentSymbol99999"])
        assert result == ""

    def test_error_handler_files_prioritized(self):
        idx = _make_indexer(tree=SAMPLE_TREE, files=SAMPLE_FILES)
        result = idx.find_snippets(["handle_db_error"])
        assert "exception_handler" in result

    def test_snippet_capped_at_max_chars(self):
        idx = _make_indexer(tree=SAMPLE_TREE, files=SAMPLE_FILES)
        with patch("codebase_context.MAX_SNIPPET_CHARS", 50):
            result = idx.find_snippets(["ConnectionPool"])
        assert len(result) <= 50 + len("\n…[snippets truncated]")

    def test_returns_at_most_max_snippets(self):
        idx = _make_indexer(tree=SAMPLE_TREE, files=SAMPLE_FILES)
        # Each source file has a match — should return at most max_snippets=2
        result = idx.find_snippets(["def", "class"], max_snippets=2)
        separator = "─" * 60
        count = result.count(separator)
        assert count <= 1  # N snippets → N-1 separators

    def test_unreadable_file_skipped(self):
        idx = _make_indexer(
            tree=SAMPLE_TREE, files={**SAMPLE_FILES, "src/db/ConnectionPool.py": ""}
        )
        # Empty file → no snippet for that file, but should not crash
        result = idx.find_snippets(["ConnectionPool"])
        # May or may not find a match in other files — just no crash
        assert isinstance(result, str)


# ── build_arch_summary ──────────────────────────────────────────────────────────


class TestBuildArchSummary:
    def test_includes_repo_identity(self):
        idx = _make_indexer(tree=SAMPLE_TREE, files=SAMPLE_FILES)
        idx._indexed_sha = "abc12345"
        summary = idx.build_arch_summary()
        assert "acme/backend" in summary
        assert "main" in summary

    def test_includes_readme(self):
        idx = _make_indexer(tree=SAMPLE_TREE, files=SAMPLE_FILES)
        summary = idx.build_arch_summary()
        assert "Backend Service" in summary

    def test_includes_requirements(self):
        idx = _make_indexer(tree=SAMPLE_TREE, files=SAMPLE_FILES)
        summary = idx.build_arch_summary()
        assert "requirements.txt" in summary

    def test_includes_error_handler(self):
        idx = _make_indexer(tree=SAMPLE_TREE, files=SAMPLE_FILES)
        summary = idx.build_arch_summary()
        assert "exception_handler" in summary

    def test_capped_at_max_arch_chars(self):
        idx = _make_indexer(tree=SAMPLE_TREE, files=SAMPLE_FILES)
        with patch("codebase_context.MAX_ARCH_CHARS", 100):
            summary = idx.build_arch_summary()
        assert len(summary) <= 100 + len("\n…[architecture summary truncated]")

    def test_captures_indexed_sha(self):
        idx = _make_indexer(tree=SAMPLE_TREE, files=SAMPLE_FILES)
        idx._indexed_sha = None

        mock_resp = MagicMock()
        mock_resp.ok = True
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json.return_value = {"commit": {"sha": "deadbeef1234"}}
        idx._sess = MagicMock()
        idx._sess.get.return_value = mock_resp

        idx.build_arch_summary()
        assert idx._indexed_sha == "deadbeef1234"


# ── get_head_sha ──────────────────────────────────────────────────────────────


class TestGetHeadSha:
    def test_returns_sha_on_success(self):
        idx = _make_indexer()
        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json.return_value = {"commit": {"sha": "abc123"}}
        idx._sess = MagicMock()
        idx._sess.get.return_value = mock_resp

        sha = idx.get_head_sha()
        assert sha == "abc123"

    def test_returns_none_on_network_error(self):
        idx = _make_indexer()
        idx._sess = MagicMock()
        idx._sess.get.side_effect = ConnectionError("unreachable")
        assert idx.get_head_sha() is None


# ── refresh_if_stale ──────────────────────────────────────────────────────────


class TestRefreshIfStale:
    def test_same_sha_returns_false(self):
        idx = _make_indexer(tree=SAMPLE_TREE)
        idx._indexed_sha = "abc123"
        idx.get_head_sha = MagicMock(return_value="abc123")
        assert idx.refresh_if_stale() is False

    def test_new_sha_clears_caches_and_returns_true(self):
        idx = _make_indexer(tree=SAMPLE_TREE, files=SAMPLE_FILES)
        idx._indexed_sha = "old-sha"
        idx.get_head_sha = MagicMock(return_value="new-sha")

        result = idx.refresh_if_stale()
        assert result is True
        assert idx._tree is None
        assert idx._files == {}
        assert idx._indexed_sha == "new-sha"

    def test_github_failure_returns_false_keeps_cache(self):
        idx = _make_indexer(tree=SAMPLE_TREE, files=SAMPLE_FILES)
        idx._indexed_sha = "current-sha"
        idx.get_head_sha = MagicMock(return_value=None)

        result = idx.refresh_if_stale()
        assert result is False
        assert idx._tree is not None  # cache preserved


# ── force_reindex ──────────────────────────────────────────────────────────────


class TestForceReindex:
    def test_clears_tree_and_files(self):
        idx = _make_indexer(tree=SAMPLE_TREE, files=SAMPLE_FILES)
        idx._indexed_sha = "some-sha"
        idx.force_reindex()
        assert idx._tree is None
        assert idx._files == {}
        assert idx._indexed_sha is None


# ── from_env ───────────────────────────────────────────────────────────────────


class TestFromEnv:
    def test_no_token_returns_none(self, monkeypatch):
        monkeypatch.delenv("GITHUB_TOKEN", raising=False)
        monkeypatch.delenv("GITHUB_REPO", raising=False)
        assert CodebaseIndexer.from_env() is None

    def test_no_repo_returns_none(self, monkeypatch):
        monkeypatch.setenv("GITHUB_TOKEN", "ghp_test")
        monkeypatch.delenv("GITHUB_REPO", raising=False)
        assert CodebaseIndexer.from_env() is None

    def test_bad_repo_format_returns_none(self, monkeypatch):
        monkeypatch.setenv("GITHUB_TOKEN", "ghp_test")
        monkeypatch.setenv("GITHUB_REPO", "no-slash-in-name")
        assert CodebaseIndexer.from_env() is None

    def test_valid_env_creates_indexer(self, monkeypatch):
        monkeypatch.setenv("GITHUB_TOKEN", "ghp_test")
        monkeypatch.setenv("GITHUB_REPO", "acme/backend")
        monkeypatch.setenv("GITHUB_BRANCH", "develop")
        idx = CodebaseIndexer.from_env()
        assert idx is not None
        assert idx.owner == "acme"
        assert idx.repo == "backend"
        assert idx.branch == "develop"
