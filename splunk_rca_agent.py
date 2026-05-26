#!/usr/bin/env python3
"""
splunk_rca_agent.py
Splunk anomaly monitor → enhanced Drain clustering → LLM RCA → HTML email

Runs as a 24/7 daemon (LogMonitorAgent.start()) or single-shot (run_once()).
Only fires the LLM + email when NEW error patterns appear — quiet cycles are silent.

Compression pipeline (6 stages + 3 prompt-level optimizations):
  [1] Pre-dedup         exact-hash lines → count weights (O(1)/line)
  [2] Stack compressor  collapse Java/Python frames → 2 kept + N omitted
  [3] Extended tokenize key=value, quoted strings, thread IDs → typed tokens
  [4] Drain clustering  prefix-tree similarity grouping with weight + var slots
  [5] Cluster merger    second-pass similarity merge of near-identical templates
  [6] Token budget      variable-slot differential encoding + hard char cap

Prompt-level optimizations applied at LLM call time (lossless w.r.t. RCA accuracy):
  [6a] Single-value slot inlining   inline_single_slots() — slots with exactly one
       literal value are inlined into the template (drops the slot table row).
  [6b] Context window dedup         _format_context_window() collapses consecutive
       tokenized-equivalent lines into "first original + (×N)" notation.
  [6c] Cached output schema         JSON schema lives in a cached system block,
       not repeated in every per-cluster user prompt (~8 KB saved per run).

Codebase-aware RCA (via codebase_context.py):
  - Reads GitHub main branch once at startup
  - Architecture summary → cached LLM system block (shared across all clusters)
  - Per-cluster: keyword extraction → relevant code snippet injection into prompt
  - Falls back gracefully when GITHUB_TOKEN / GITHUB_REPO are not set

Dependencies:  pip install requests anthropic urllib3
Python:        3.10+

Required env vars:
  SPLUNK_HOST  SPLUNK_USER  SPLUNK_PASS  ANTHROPIC_API_KEY  SMTP_USER  SMTP_PASS  EMAIL_TO

Optional env vars (defaults shown):
  SPLUNK_INDEX=main  LOOKBACK_MINS=60  MAX_LOG_RESULTS=5000  MAX_LLM_CLUSTERS=20
  DRAIN_SIM=0.5  DRAIN_DEPTH=4  DRAIN_MAX_CHILD=100  MERGE_SIM=0.8
  LLM_BUDGET_CHARS=3500  MAX_SLOT_VALS=5
  SMTP_HOST=smtp.gmail.com  SMTP_PORT=587  EMAIL_FROM=<SMTP_USER>
  GITHUB_TOKEN=ghp_...  GITHUB_REPO=owner/repo  GITHUB_BRANCH=main
  MAX_ARCH_CHARS=6000  MAX_SNIPPET_CHARS=2000
  POLL_INTERVAL_SECS=3600  DEDUP_WINDOW_MINS=120
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import signal
import smtplib
import threading
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

# Eastern Time zone — used to schedule the daily 7 AM codebase refresh.
# zoneinfo (stdlib 3.9+) handles DST automatically; falls back to a fixed UTC-5
# offset if timezone data is unavailable (Windows without the tzdata package).
try:
    from zoneinfo import ZoneInfo

    _EASTERN = ZoneInfo("America/New_York")
except Exception:
    # Install the 'tzdata' PyPI package for full DST support on Windows.
    _EASTERN = timezone(timedelta(hours=-5))  # type: ignore[assignment]

import anthropic
import requests
import urllib3

from codebase_context import CodebaseIndexer

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger(__name__)

# ── CONFIG ───────────────────────────────────────────────────────────────────
SPLUNK_HOST = os.environ.get("SPLUNK_HOST", "https://localhost:8089")
SPLUNK_USER = os.environ.get("SPLUNK_USER", "admin")
SPLUNK_PASS = os.environ.get("SPLUNK_PASS", "")
SPLUNK_INDEX = os.environ.get("SPLUNK_INDEX", "main")
LOOKBACK_MINS = int(os.environ.get("LOOKBACK_MINS", "60"))
MAX_LOG_RESULTS = int(os.environ.get("MAX_LOG_RESULTS", "5000"))
MAX_LLM_CLUSTERS = int(os.environ.get("MAX_LLM_CLUSTERS", "20"))

LLM_MODEL = "claude-opus-4-7"
ANTHROPIC_KEY = os.environ.get("ANTHROPIC_API_KEY", "")

SMTP_HOST = os.environ.get("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USER = os.environ.get("SMTP_USER", "")
SMTP_PASS = os.environ.get("SMTP_PASS", "")
EMAIL_FROM = os.environ.get("EMAIL_FROM", SMTP_USER)
EMAIL_TO = os.environ.get("EMAIL_TO", "devteam@example.com")

# Drain params
SIM_THRESHOLD = float(os.environ.get("DRAIN_SIM", "0.5"))
DRAIN_DEPTH = int(os.environ.get("DRAIN_DEPTH", "4"))
MAX_CHILDREN = int(os.environ.get("DRAIN_MAX_CHILD", "100"))
MERGE_SIM = float(os.environ.get("MERGE_SIM", "0.8"))  # [4] second-pass merger

# Token budget params
LLM_BUDGET_CHARS = int(os.environ.get("LLM_BUDGET_CHARS", "3500"))  # [6] total user prompt cap
MAX_SLOT_VALS = int(os.environ.get("MAX_SLOT_VALS", "5"))  # [5] values per slot

# Time-based context window  (anchored on FIRST error occurrence per source stream)
# Window = [first_error_time - PRE_WINDOW_SECS, first_error_time + POST_WINDOW_SECS]
#
# 3 minutes before: captures the lead-up — connection retries, pool pressure, slow queries
# 2 minutes after:  captures the immediate consequence — 503s, cascading failures, recovery
# Total: 5-minute incident slice, the same window an engineer would pull in Splunk manually.
PRE_WINDOW_SECS = int(os.environ.get("PRE_WINDOW_SECS", "180"))  # 3 min before first error
POST_WINDOW_SECS = int(os.environ.get("POST_WINDOW_SECS", "120"))  # 2 min after first error
MAX_CONTEXT_SOURCES = int(os.environ.get("MAX_CONTEXT_SOURCES", "30"))  # OR-clause cap

# Continuous-daemon params
# POLL_INTERVAL_SECS: how often to query Splunk (should match or be a multiple of LOOKBACK_MINS)
# DEDUP_WINDOW_MINS: suppress re-alerting on the same cluster pattern within this many minutes
#   (prevents hourly repeat emails for a persistent error that hasn't been fixed yet)
POLL_INTERVAL_SECS = int(os.environ.get("POLL_INTERVAL_SECS", "3600"))  # poll every 1 hour
DEDUP_WINDOW_MINS = int(os.environ.get("DEDUP_WINDOW_MINS", "120"))  # suppress repeats for 2h

# Hour (0-23) in Eastern Time at which the codebase index is refreshed once per day.
# Default 7 AM ET: picks up any overnight / early-morning deploys before business hours.
# Deploys during business hours (7 AM – 6 PM ET) are excluded by team convention,
# so one refresh at the start of the day is sufficient — no need to check GitHub on
# every poll cycle.
CODEBASE_REFRESH_HOUR = int(os.environ.get("CODEBASE_REFRESH_HOUR", "7"))

ANOMALY_RE = re.compile(r"\b(ERROR|EXCEPTION|FAILED|CRITICAL|FATAL)\b", re.I)

# Type alias: (error_line, context_window_lines)
ContextualEvent = tuple[str, list[str]]


# ── COMPRESSION STATS ─────────────────────────────────────────────────────────
@dataclass
class CompressionStats:
    raw: int = 0  # error events from Splunk pass-1
    context_lines: int = 0  # total lines fetched in pass-2 context windows
    unique: int = 0  # unique error lines after dedup
    compressed: int = 0  # after stack compactor
    clusters: int = 0  # after Drain
    merged: int = 0  # after second-pass merge
    llm_sent: int = 0  # clusters actually analyzed

    @property
    def total_ratio(self) -> str:
        r = self.context_lines / max(self.merged, 1)
        return f"{r:,.0f}x"

    def summary(self) -> str:
        return (
            f"errors={self.raw:,} ctx_lines={self.context_lines:,} "
            f"→ dedup={self.unique:,} → stackcomp={self.compressed:,} "
            f"→ drain={self.clusters} → merged={self.merged} → llm={self.llm_sent}  "
            f"[total {self.total_ratio} compression]"
        )


# ── [2] STACK TRACE COMPRESSOR ────────────────────────────────────────────────
_JAVA_FRAME = re.compile(r"\n?\s*at [\w.$<>]+\([\w.]+(?::\d+)?\)")
_PY_FRAME = re.compile(r'\n?\s*File "[^"]+", line \d+(?:, in \w+)?')
_CAUSED_BY = re.compile(r"(?:Caused by|caused by): ?[^\n]+")
_EXC_CLASS = re.compile(r"[\w.$]+(?:Exception|Error|Fault|Failure|Warning)[^\n]{0,120}")


def compress_stacktrace(line: str) -> str:
    """
    Collapse Java / Python stack frames.
    Handles both real newlines and \\n-escaped single-line blobs.
    Keeps: exception header + first 2 frames + omission marker + cause chain.
    """
    norm = line.replace("\\n", "\n").replace("\\t", "\t")

    # ── Java
    java_frames = _JAVA_FRAME.findall(norm)
    if java_frames:
        first = norm.find("\tat ")
        header = norm[:first].strip() if first > 0 else norm[:200]
        causes = _CAUSED_BY.findall(norm)
        kept = [f.strip() for f in java_frames[:2]]
        omit = max(0, len(java_frames) - 2)
        parts = [header] + kept
        if omit:
            parts.append(f"…[{omit} frames omitted]")
        parts.extend(causes[:2])
        return " | ".join(p for p in parts if p)[:500]

    # ── Python
    py_frames = _PY_FRAME.findall(norm)
    if py_frames:
        exc = _EXC_CLASS.search(norm)
        kept = [f.strip() for f in py_frames[:2]]
        omit = max(0, len(py_frames) - 2)
        parts = ([exc.group(0)[:150]] if exc else []) + kept
        if omit:
            parts.append(f"…[{omit} frames omitted]")
        return " | ".join(p for p in parts if p)[:500]

    return line  # not a stack trace


# ── [3] TOKENIZER (base + extended patterns) ─────────────────────────────────
_VAR_SUBS: list[tuple[re.Pattern, str]] = [
    # --- Base patterns (high specificity first) ---
    (re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?\b"), "<IP>"),
    (re.compile(r"\b[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}\b", re.I), "<UUID>"),
    (re.compile(r"\b[0-9a-fA-F]{16,}\b"), "<HEX>"),
    (re.compile(r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?\b"), "<TS>"),
    (re.compile(r"\b\d{10,13}\b"), "<EPOCH>"),
    (re.compile(r"/[\w./\-]{4,}"), "<PATH>"),
    (re.compile(r"\b[\w.+-]+@[\w.-]+\.\w+\b"), "<EMAIL>"),
    # --- [3] Extended patterns ---
    # key=value pairs: user_id=abc123, status=500, duration=342ms
    (re.compile(r'(?<!\w)[\w.\-]{2,24}=(?:[^\s,;{}\[\]"\']{1,40})'), "<KV>"),
    # double / single quoted strings (3–80 chars)
    (re.compile(r'"[^"\\]{3,80}"'), "<STR>"),
    (re.compile(r"'[^'\\]{3,80}'"), "<STR>"),
    # thread / connection / session / transaction identifiers
    (
        re.compile(r"\b(?:thread|conn|session|txn|req|task|job)[-_]?[A-Za-z0-9]{4,}\b", re.I),
        "<TID>",
    ),
    # generic large numbers last
    (re.compile(r"\b\d+\b"), "<NUM>"),
]


def _tokenize(line: str) -> list[str]:
    """Apply all substitutions, split, cap at 64 tokens."""
    for pat, tok in _VAR_SUBS:
        line = pat.sub(tok, line)
    return line.split()[:64]


# ── DATA MODEL ───────────────────────────────────────────────────────────────
@dataclass
class LogCluster:
    template: list[str]
    raw_samples: list[str] = field(default_factory=list)
    # [5] variable slot tracker: {token_position → [distinct_values_seen]}
    var_slots: dict[int, list[str]] = field(default_factory=dict)
    count: int = 0
    severity: str = "ERROR"

    @property
    def template_str(self) -> str:
        return " ".join(self.template)

    @property
    def cluster_id(self) -> str:
        return hashlib.md5(self.template_str.encode()).hexdigest()[:8]


# ── [4] DRAIN CLUSTERER ───────────────────────────────────────────────────────
def _sim(a: list[str], b: list[str]) -> float:
    if len(a) != len(b):
        return 0.0
    return sum(x == y for x, y in zip(a, b, strict=False)) / len(a)


def _merge_tpl(a: list[str], b: list[str]) -> list[str]:
    return [x if x == y else "<*>" for x, y in zip(a, b, strict=False)]


class DrainClusterer:
    """
    Prefix-tree Drain clusterer.
    Tree: { token_len → { prefix_key → [LogCluster] } }
    Accepts per-line weights (from pre-dedup counts).
    Tracks variable slot values for differential LLM encoding.
    """

    def __init__(self) -> None:
        self._tree: dict[int, dict[str, list[LogCluster]]] = defaultdict(lambda: defaultdict(list))

    def _prefix_key(self, tokens: list[str]) -> str:
        return " ".join(t if not t.startswith("<") else "<*>" for t in tokens[:DRAIN_DEPTH])

    def _severity(self, line: str) -> str:
        m = ANOMALY_RE.search(line)
        return m.group(1).upper() if m else "ERROR"

    def _track_slots(self, cluster: LogCluster, tokens: list[str]) -> None:
        """Record dynamic values at positions where template diverges."""
        for i, (tmpl_tok, new_tok) in enumerate(zip(cluster.template, tokens, strict=False)):
            if tmpl_tok != new_tok:
                slot = cluster.var_slots.setdefault(i, [])
                # Capture original value on first divergence
                if tmpl_tok != "<*>" and tmpl_tok not in slot and len(slot) < MAX_SLOT_VALS:
                    slot.append(tmpl_tok[:30])
                if new_tok not in slot and len(slot) < MAX_SLOT_VALS:
                    slot.append(new_tok[:30])

    def _add(
        self,
        raw: str,
        weight: int = 1,
        context_window: list[str] | None = None,
    ) -> LogCluster | None:
        tokens = _tokenize(raw)
        if not tokens:
            return None

        bucket = self._tree[len(tokens)][self._prefix_key(tokens)]
        best, best_sim = None, -1.0
        for c in bucket:
            s = _sim(c.template, tokens)
            if s > best_sim:
                best_sim, best = s, c

        # Store the formatted 5-minute context window instead of the bare error line
        sample = _format_context_window(raw, context_window) if context_window else raw[:300]

        if best_sim >= SIM_THRESHOLD and best:
            self._track_slots(best, tokens)
            best.template = _merge_tpl(best.template, tokens)
            best.count += weight
            if len(best.raw_samples) < 3:
                best.raw_samples.append(sample)
        else:
            if len(bucket) >= MAX_CHILDREN:
                return None
            best = LogCluster(
                template=list(tokens),
                raw_samples=[sample],
                count=weight,
                severity=self._severity(raw),
            )
            bucket.append(best)
        return best

    def cluster(self, events: list[tuple[str, list[str], int]]) -> list[LogCluster]:
        """
        Cluster error lines from contextual events.
        events: list of (error_line, context_window_lines, weight)

        Context windows (the 5-min incident slice around each error) are stored
        in raw_samples so the LLM receives rich sequential context for RCA.
        """
        for error_line, context_window, weight in events:
            if ANOMALY_RE.search(error_line):
                self._add(error_line, weight=weight, context_window=context_window)
        return [c for by_len in self._tree.values() for cs in by_len.values() for c in cs]


# ── [5] POST-DRAIN CLUSTER MERGER ─────────────────────────────────────────────
def merge_clusters(clusters: list[LogCluster]) -> list[LogCluster]:
    """
    Second-pass similarity merge. Groups by template length (prerequisite for
    sim comparison), then absorbs near-identical clusters into the highest-count one.
    """
    by_len: dict[int, list[LogCluster]] = defaultdict(list)
    for c in clusters:
        by_len[len(c.template)].append(c)

    merged: list[LogCluster] = []
    for group in by_len.values():
        group.sort(key=lambda c: -c.count)
        absorbed: set[int] = set()
        for i, base in enumerate(group):
            if id(base) in absorbed:
                continue
            for cand in group[i + 1 :]:
                if id(cand) in absorbed:
                    continue
                if _sim(base.template, cand.template) >= MERGE_SIM:
                    base.template = _merge_tpl(base.template, cand.template)
                    base.count += cand.count
                    base.raw_samples = (base.raw_samples + cand.raw_samples)[:3]
                    # Merge var slots
                    for pos, vals in cand.var_slots.items():
                        slot = base.var_slots.setdefault(pos, [])
                        for v in vals:
                            if v not in slot and len(slot) < MAX_SLOT_VALS:
                                slot.append(v)
                    absorbed.add(id(cand))
            merged.append(base)
    return merged


# ── [6a] SINGLE-VALUE SLOT INLINING ──────────────────────────────────────────
def inline_single_slots(clusters: list[LogCluster]) -> None:
    """
    Mutate clusters in place: slots with exactly one literal observed value are
    inlined back into the template (replacing the wildcard at that position) and
    removed from the slot table.

    Example before:
      template:   ["connection", "to", "<*>", "failed"]
      var_slots:  {2: ["db-primary"]}        ← only one value ever seen
      → display:  "connection to <*> failed" + slot row for [2]

    Example after:
      template:   ["connection", "to", "db-primary", "failed"]
      var_slots:  {}                          ← slot row eliminated
      → display:  "connection to db-primary failed"

    Typed placeholders (values starting with '<' like '<IP>' or '<NUM>') are
    NOT inlined — they represent a CLASS of values, not a single literal, so
    keeping them as wildcards in the template preserves the abstraction.

    Lossless: the literal value is fully preserved (moved from slot to template).
    Saves ~50 chars per affected cluster (slot-row header + value formatting).
    Also makes the email report's template line more readable for the on-call.
    """
    for c in clusters:
        new_template = list(c.template)
        new_slots: dict[int, list[str]] = {}
        for pos, vals in c.var_slots.items():
            if (
                len(vals) == 1
                and not vals[0].startswith("<")  # keep typed placeholders abstract
                and pos < len(new_template)
            ):
                new_template[pos] = vals[0]
            else:
                new_slots[pos] = vals
        c.template = new_template
        c.var_slots = new_slots


# ── CONTEXT WINDOW FORMATTER ([6b] internal dedup) ────────────────────────────
def _tokenize_for_match(s: str) -> str:
    """Apply the same variable substitutions used for clustering, return the
    normalized string (used ONLY for adjacent-line equality matching — display
    still shows the original line so no information is lost)."""
    for pat, tok in _VAR_SUBS:
        s = pat.sub(tok, s)
    return s.strip()


def _format_context_window(error_line: str, window: list[str], max_display: int = 40) -> str:
    """
    Format a context window for the LLM with [6b] internal dedup.

    Pipeline:
      1. Locate the triggering error line (marked with '>>>' in output)
      2. Tokenize every line (for matching only) using _VAR_SUBS
      3. Collapse runs of consecutive tokenized-equivalent lines, keeping the
         FIRST original line as display + "(×N)" suffix when N>1
      4. The error line is never absorbed into a neighbouring run
      5. Trim symmetrically around the error to max_display collapsed runs

    Lossless guarantee:
      - First original of each run is shown verbatim → actual values preserved
      - Cluster-level var_slots already capture cross-occurrence variance
      - Error line shown unchanged (no tokenization, larger char cap)

    Example output (raw 50-line window → 4 displayed lines):
      [2 lines before | ERROR | 1 lines after]
          INFO  DB pool at 95% capacity (19/20)  (×30)
          INFO  Queuing request — waiting for free connection  (×3)
      >>> ERROR DatabaseConnectionPool exhausted after 30000ms timeout
          WARN  Returning HTTP 503 to upstream caller  (×12)
    """
    if not window:
        return ""

    # ── Locate the error line in the window (first match by content) ─────────
    err_idx = next(
        (
            i
            for i, ln in enumerate(window)
            if error_line.strip() in ln or ln.strip() == error_line.strip()
        ),
        len(window) // 2,  # fallback: assume middle
    )

    # ── Build collapsed runs of adjacent tokenized-equivalent lines ──────────
    # Each entry: (tokenized_key, first_original_idx, run_count, is_error_line)
    # The error line is NEVER absorbed into a neighbouring run.
    tokenized = [_tokenize_for_match(ln) for ln in window]
    runs: list[tuple[str, int, int, bool]] = []
    for i, tok in enumerate(tokenized):
        is_err = i == err_idx
        # Extend previous run iff: both non-error AND same tokenized form
        if runs and not is_err and not runs[-1][3] and runs[-1][0] == tok:
            prev_tok, prev_idx, prev_count, _ = runs[-1]
            runs[-1] = (prev_tok, prev_idx, prev_count + 1, False)
        else:
            runs.append((tok, i, 1, is_err))

    # ── Locate the error run in the collapsed sequence ───────────────────────
    new_err_idx = next(j for j, r in enumerate(runs) if r[3])

    # ── Trim symmetrically around the error ──────────────────────────────────
    half = max_display // 2
    start = max(0, new_err_idx - half)
    end = min(len(runs), new_err_idx + half + 1)
    before_count = new_err_idx - start
    after_count = end - new_err_idx - 1

    # ── Render ───────────────────────────────────────────────────────────────
    lines_out = [f"[{before_count} lines before | ERROR | {after_count} lines after]"]
    for j in range(start, end):
        _, orig_idx, count, is_err = runs[j]
        prefix = ">>> " if is_err else "    "
        # Error line gets larger cap (200) to preserve full diagnostic detail;
        # context lines capped at 150 (tokenized-equivalent siblings collapsed already).
        cap = 200 if is_err else 150
        suffix = f"  (×{count})" if count > 1 else ""
        lines_out.append(f"{prefix}{window[orig_idx][:cap]}{suffix}")
    return "\n".join(lines_out)


# ── REUSABLE COMPRESSION PIPELINE ─────────────────────────────────────────────
def compress_events(ctx_events: list[ContextualEvent]) -> tuple[list[LogCluster], CompressionStats]:
    """
    Run compression stages [1]–[5] + [6a] on a list of contextual events.

    Shared by both LogMonitorAgent (polling) and EventDrivenLogAgent (webhook).
    Accepts (error_line, context_window_lines) pairs from any source.

    Stages:
      [1] Pre-dedup          exact-hash, keep first context window per unique line
      [2] Stack compressor   Java/Python frame collapse
      [3] Drain clustering   prefix-tree similarity grouping with var slots
      [4] Cluster merger     second-pass 0.8-similarity merge
      [6a] Slot inlining     single-literal slots inlined into template (lossless)

    Returns (clusters sorted by count DESC, CompressionStats).
    cluster_id values are stable after this call — callers must not mutate
    cluster.template afterward (cluster_id is md5 of template_str).
    """
    stats = CompressionStats()
    if not ctx_events:
        return [], stats

    stats.raw = len(ctx_events)
    stats.context_lines = sum(len(ctx) for _, ctx in ctx_events)

    # [1] Pre-dedup — keep first context window seen per unique error line
    seen: dict[str, list[str]] = {}
    for error_line, ctx in ctx_events:
        if error_line not in seen:
            seen[error_line] = ctx
    stats.unique = len(seen)
    log.info(
        "[1] dedup: %d → %d unique (%.1fx)",
        stats.raw,
        stats.unique,
        stats.raw / max(stats.unique, 1),
    )

    # [2] Stack trace compression
    compressed: dict[str, tuple[list[str], int]] = {}
    for error_line, ctx in seen.items():
        c = compress_stacktrace(error_line)
        if c in compressed:
            _, w = compressed[c]
            compressed[c] = (ctx, w + 1)
        else:
            compressed[c] = (ctx, 1)
    stats.compressed = len(compressed)
    log.info("[2] stack-compress: %d → %d", stats.unique, stats.compressed)

    # [3] Drain clustering
    drain = DrainClusterer()
    drain_input: list[tuple[str, list[str], int]] = [
        (line, ctx, weight) for line, (ctx, weight) in compressed.items()
    ]
    clusters = drain.cluster(drain_input)
    stats.clusters = len(clusters)
    log.info("[3] drain: %d clusters", stats.clusters)

    # [4] Post-drain merge
    clusters = merge_clusters(clusters)
    stats.merged = len(clusters)
    log.info(
        "[4] merge: %d → %d (%.1fx)",
        stats.clusters,
        stats.merged,
        stats.clusters / max(stats.merged, 1),
    )

    if not clusters:
        return [], stats

    # [6a] Single-value slot inlining — MUST run before any cluster_id dedup lookups
    inline_single_slots(clusters)

    return sorted(clusters, key=lambda c: -c.count), stats


# ── SPLUNK CLIENT ─────────────────────────────────────────────────────────────
class SplunkClient:
    """
    Two-pass context-aware Splunk REST client.

    Pass 1 — error discovery (fast, filtered):
        SPL with (ERROR OR EXCEPTION …) → error events + timestamps per source stream.

    Pass 2 — context batch fetch (one SPL, all streams):
        For each source stream: window = [first_error - PRE_WINDOW_SECS,
                                           first_error + POST_WINDOW_SECS]
        All streams OR-ed into a single blocking job → full incident context.

    Returns list[ContextualEvent] = list[(error_line, context_window_lines)]
    """

    def __init__(self) -> None:
        self._sess = requests.Session()
        self._sess.verify = False  # replace with cert path in prod
        self._token: str | None = None

    @property
    def _auth_token(self) -> str:
        if not self._token:
            import xml.etree.ElementTree as ET

            r = self._sess.post(
                f"{SPLUNK_HOST}/services/auth/login",
                data={"username": SPLUNK_USER, "password": SPLUNK_PASS},
                timeout=15,
            )
            r.raise_for_status()
            self._token = ET.fromstring(r.text).findtext(".//sessionKey")
        return self._token  # type: ignore[return-value]

    def _hdrs(self) -> dict:
        return {"Authorization": f"Splunk {self._auth_token}"}

    def _run_spl(self, spl: str, max_count: int = MAX_LOG_RESULTS) -> list[dict]:
        """Submit a blocking Splunk search job and return result rows."""
        r = self._sess.post(
            f"{SPLUNK_HOST}/services/search/jobs",
            headers=self._hdrs(),
            data={
                "search": spl,
                "output_mode": "json",
                "exec_mode": "blocking",
                "max_count": max_count,
            },
            timeout=300,
        )
        r.raise_for_status()
        r2 = self._sess.get(
            f"{SPLUNK_HOST}/services/search/jobs/{r.json()['sid']}/results",
            headers=self._hdrs(),
            params={"output_mode": "json", "count": max_count},
            timeout=30,
        )
        r2.raise_for_status()
        return r2.json().get("results", [])

    @staticmethod
    def _esc(s: str) -> str:
        return s.replace('"', '\\"')

    def fetch_anomalies(self) -> list[ContextualEvent]:
        """
        Two-pass fetch:  error discovery → time-windowed context batch.
        Returns (error_line, context_window) pairs.
        """
        # ── Pass 1: error discovery ───────────────────────────────────────────
        error_rows = self._run_spl(
            f'search index="{SPLUNK_INDEX}" earliest=-{LOOKBACK_MINS}m '
            f"(ERROR OR EXCEPTION OR FAILED OR CRITICAL OR FATAL) "
            f"| sort host source _time "
            f"| head {MAX_LOG_RESULTS} "
            f"| fields _time host source _raw",
        )
        if not error_rows:
            return []
        log.info("Pass 1: %d error events", len(error_rows))

        # Group by stream; track FIRST error timestamp per stream
        # stream_key → {first_time, host, source, errors:[raw,...]}
        streams: dict[str, dict] = {}
        for e in error_rows:
            host, src, raw = e.get("host", ""), e.get("source", ""), e.get("_raw", "")
            t = float(e.get("_time", 0))
            if not raw:
                continue
            key = f"{host}||{src}"
            if key not in streams:
                streams[key] = {"host": host, "source": src, "first_time": t, "errors": []}
            # Keep track of first occurrence (rows are time-sorted)
            streams[key]["errors"].append(raw)

        # ── Pass 2: batch context fetch (one SPL, all streams) ────────────────
        top = list(streams.values())[:MAX_CONTEXT_SOURCES]

        src_clause = " OR ".join(
            f'(host="{self._esc(s["host"])}" source="{self._esc(s["source"])}")' for s in top
        )
        # Window anchored on first_error per stream — use global extremes for the batch query
        t_first_all = min(s["first_time"] for s in top)
        t_last_all = max(s["first_time"] for s in top)
        batch_earliest = int(t_first_all - PRE_WINDOW_SECS)
        batch_latest = int(t_last_all + POST_WINDOW_SECS)

        ctx_rows = self._run_spl(
            f'search index="{SPLUNK_INDEX}" '
            f"earliest={batch_earliest} latest={batch_latest} "
            f"({src_clause}) "
            f"| sort host source _time "
            f"| head {MAX_LOG_RESULTS * 5} "
            f"| fields _time host source _raw",
            max_count=MAX_LOG_RESULTS * 5,
        )
        log.info(
            "Pass 2: %d context lines (window: -%ds before / +%ds after first error per stream)",
            len(ctx_rows),
            PRE_WINDOW_SECS,
            POST_WINDOW_SECS,
        )

        # Group context rows by stream key
        ctx_by_stream: dict[str, list[str]] = defaultdict(list)
        for e in ctx_rows:
            key = f"{e.get('host', '')}||{e.get('source', '')}"
            if e.get("_raw"):
                ctx_by_stream[key].append(e["_raw"])

        # Build (error_line, context_window) pairs
        results: list[ContextualEvent] = []
        for key, stream in streams.items():
            ctx_lines = ctx_by_stream.get(key, stream["errors"])  # fallback to error-only
            for error_raw in stream["errors"]:
                results.append((error_raw, ctx_lines))
        return results

    def fetch_context_for_stream(
        self,
        host: str,
        source: str,
        first_error_time: float,
        pre_secs: int = PRE_WINDOW_SECS,
        post_secs: int = POST_WINDOW_SECS,
    ) -> list[ContextualEvent]:
        """
        Fetch the incident context window for a single known stream.

        Used by EventDrivenLogAgent after an IncidentWindow fires. Unlike
        fetch_anomalies() which runs a two-pass discovery, this method already
        knows *where* (host + source) and *when* (first_error_time) the error
        occurred — supplied by the Splunk webhook trigger — so it goes straight
        to a single targeted SPL.

        Window: [first_error_time - pre_secs, first_error_time + post_secs]
        Returns [(error_line, all_context_lines)] for every error in the window.
        Empty list if Splunk finds no results or no anomaly lines are present.
        """
        batch_earliest = int(first_error_time - pre_secs)
        batch_latest = int(first_error_time + post_secs)

        log.info(
            "Context fetch for %s/%s  window=[%s → %s]",
            host,
            source,
            datetime.fromtimestamp(batch_earliest, tz=timezone.utc).strftime("%H:%M:%S"),
            datetime.fromtimestamp(batch_latest, tz=timezone.utc).strftime("%H:%M:%S"),
        )

        rows = self._run_spl(
            f'search index="{SPLUNK_INDEX}" '
            f"earliest={batch_earliest} latest={batch_latest} "
            f'host="{self._esc(host)}" source="{self._esc(source)}" '
            f"| sort _time "
            f"| head {MAX_LOG_RESULTS} "
            f"| fields _time _raw",
        )
        if not rows:
            return []

        all_lines = [r.get("_raw", "") for r in rows if r.get("_raw")]
        results: list[ContextualEvent] = [
            (line, all_lines) for line in all_lines if ANOMALY_RE.search(line)
        ]
        log.info(
            "Context fetch: %d total lines, %d error lines for %s/%s",
            len(all_lines),
            len(results),
            host,
            source,
        )
        return results


# ── LLM RCA ANALYZER ─────────────────────────────────────────────────────────
_SYS_PERSONA = (
    "You are a senior SRE with deep expertise in distributed systems, "
    "cloud infrastructure, and application debugging. "
    "When source code is provided, use it to pinpoint exact lines, "
    "methods, or configs responsible for the error. Be concise and precise."
)

# [6c] Output schema lives in a CACHED system block — not repeated per-cluster.
# Saves ~400 chars × N clusters of user-prompt tokens every run; cached after
# first request so the schema itself costs effectively zero tokens thereafter.
_SYS_OUTPUT_SCHEMA = """\
For each log error cluster the user submits, respond with ONLY valid JSON \
(no markdown, no code fences) matching this exact schema:

{
  "summary":           "<one sentence: what happened and its impact>",
  "technical_context": "<technical explanation of why this error occurs>",
  "root_cause":        "<the underlying trigger or failure point — cite file:line if code provided>",
  "action_items":      ["<actionable step 1>", "<step 2>", ...]
}

Ground every analysis in the application's architecture context (next system \
block) and any source-code snippets included in the user message. Keep responses \
concise — the consumer is an on-call engineer skimming an email at 2 AM."""

# Compact per-cluster user message — schema description moved to cached system block.
# {code_section} is empty string when no indexer is configured.
_USER_TMPL = """\
Template : {template}
Frequency: {count} occurrences
{context}{code_section}"""

# Slot display cap: show up to N values per slot in the prompt; if more were
# captured (up to MAX_SLOT_VALS) indicate the count with "+Nmore" suffix.
# 3 examples is enough to convey variance; the count signals "this varies a lot"
# without spending tokens on additional samples.
_SLOT_DISPLAY_MAX = 3


def _var_summary(cluster: LogCluster) -> str:
    """
    Compact slot table: token position → sampled dynamic values.

    Format (one slot per line):  [pos]<token>='v1','v2','v3'+Nmore
    - Compact single-line representation (no spaces around '=' or ',')
    - Up to _SLOT_DISPLAY_MAX values shown; '+Nmore' indicates additional
      unique values were captured beyond what's displayed.
    """
    if not cluster.var_slots:
        return ""
    rows = []
    for pos in sorted(cluster.var_slots):
        vals = cluster.var_slots[pos]
        token = cluster.template[pos] if pos < len(cluster.template) else "<*>"
        shown = ",".join(repr(v) for v in vals[:_SLOT_DISPLAY_MAX])
        extra = len(vals) - _SLOT_DISPLAY_MAX
        more = f"+{extra}more" if extra > 0 else ""
        rows.append(f"  [{pos}]{token}={shown}{more}")
    return "Slots:\n" + "\n".join(rows)


def _build_context(cluster: LogCluster) -> str:
    """
    Build LLM context from two sources:
    1. Variable slot table  — compact differential encoding of what changed per occurrence
    2. Context window       — the 5-minute incident slice (before/error/after) from raw_samples
    Both are included when available; together they give the LLM both the pattern variance
    and the sequential log narrative around the error.
    """
    parts: list[str] = []
    if cluster.var_slots:
        parts.append(_var_summary(cluster))
    if cluster.raw_samples:
        # raw_samples now stores formatted context windows (not bare error lines)
        parts.append(
            f"Incident context window (sample 1/{len(cluster.raw_samples)}):\n{cluster.raw_samples[0]}"
        )
    if not parts:
        return "No context available."
    return "\n\n".join(parts)


class RCAAnalyzer:
    """
    LLM-powered root cause analyzer.

    Context hierarchy (token-efficient, cached where possible):
      System block 1 — SRE persona                    (ephemeral cache)
      System block 2 — Codebase architecture summary  (ephemeral cache, if indexer set)
      User message   — Template + var slots + per-cluster code snippets
    """

    def __init__(self, indexer: CodebaseIndexer | None = None) -> None:
        self._client = anthropic.Anthropic(api_key=ANTHROPIC_KEY)
        self._indexer = indexer
        self._arch_block: dict | None = None

        if indexer:
            log.info("Building codebase architecture summary from GitHub…")
            arch = indexer.build_arch_summary()
            if arch:
                self._arch_block = {
                    "type": "text",
                    "text": f"## Application Codebase Context\n\n{arch}",
                    "cache_control": {"type": "ephemeral"},  # cached across all clusters
                }
                log.info(
                    "Architecture summary ready (%d chars, will be cached by LLM)",
                    len(arch),
                )

        # Track the Eastern-time date on which the codebase was last refreshed.
        # Prevents the daily 7 AM trigger from re-indexing immediately if the daemon
        # starts after 7 AM (startup already built a fresh index).
        # None = not yet set; the 7 AM window fires as soon as it passes for the first time.
        now_et = datetime.now(_EASTERN)
        if now_et.hour >= CODEBASE_REFRESH_HOUR and indexer:
            # Daemon started at or after today's scheduled refresh time.
            # Mark today as done — daily refresh will next fire at 7 AM tomorrow.
            self._last_refresh_date: date | None = now_et.date()
            log.info(
                "Daemon started after %02d:00 ET — daily codebase refresh will next fire tomorrow.",
                CODEBASE_REFRESH_HOUR,
            )
        else:
            # Daemon started before 7 AM or GitHub not configured.
            # Daily refresh will fire naturally when the clock crosses 7 AM ET today.
            self._last_refresh_date = None

    def refresh_codebase(self) -> bool:
        """
        Refresh the codebase index once per day at CODEBASE_REFRESH_HOUR Eastern Time.

        Decision logic (checked at the top of every daemon poll cycle):
          • Not configured (no GitHub token) → skip, return False.
          • Already refreshed today (Eastern date) → skip, return False.
          • Current Eastern hour < CODEBASE_REFRESH_HOUR → not yet time, return False.
          • Past CODEBASE_REFRESH_HOUR and not yet refreshed today → full re-index.

        Why time-gated rather than per-cycle SHA check:
          Deploys only happen outside business hours (before 7 AM or after 6 PM ET by
          convention).  A single 7 AM re-index captures overnight / early-morning commits
          before the first business-hours alert of the day, with zero GitHub API calls
          during the remaining 23 hours of each cycle.

        Returns True if a refresh was performed, False if skipped.
        """
        if not self._indexer:
            return False

        now_et = datetime.now(_EASTERN)
        today_et = now_et.date()

        if self._last_refresh_date == today_et:
            return False  # already refreshed today — skip

        if now_et.hour < CODEBASE_REFRESH_HOUR:
            return False  # daily window hasn't opened yet

        # ── Scheduled daily refresh ───────────────────────────────────────────
        log.info(
            "⏰  Daily %02d:00 ET codebase refresh — re-indexing %s/%s@%s",
            CODEBASE_REFRESH_HOUR,
            self._indexer.owner,
            self._indexer.repo,
            self._indexer.branch,
        )
        self._indexer.force_reindex()  # clear file-tree + content caches
        arch = self._indexer.build_arch_summary()  # fetch fresh from GitHub
        self._last_refresh_date = today_et  # mark done for today

        if arch:
            self._arch_block = {
                "type": "text",
                "text": f"## Application Codebase Context\n\n{arch}",
                "cache_control": {"type": "ephemeral"},
            }
            log.info(
                "Architecture context refreshed (%d chars) — valid until 07:00 ET tomorrow.",
                len(arch),
            )
        else:
            self._arch_block = None
            log.warning(
                "build_arch_summary() returned empty — falling back to generic RCA context."
            )
        return True

    def _system_blocks(self) -> list[dict]:
        """
        Three cached system blocks (all ephemeral-cached, TTL=5 min):
          [0] persona — tiny, always present (SRE role definition)
          [1] schema  — output JSON schema  ← [6c] moved here from user prompt
                        saves ~400 chars per cluster call × N clusters per run
          [2] arch    — large codebase architecture summary
                        present only when GITHUB_TOKEN/REPO are configured

        All three are reused across every per-cluster call this run, so cost is
        paid once and amortized across all 20 cluster analyses.
        """
        blocks: list[dict] = [
            {
                "type": "text",
                "text": _SYS_PERSONA,
                "cache_control": {"type": "ephemeral"},
            },
            {
                "type": "text",
                "text": _SYS_OUTPUT_SCHEMA,
                "cache_control": {"type": "ephemeral"},
            },
        ]
        if self._arch_block:
            blocks.append(self._arch_block)
        return blocks

    def analyze(self, cluster: LogCluster) -> dict:
        # Per-cluster: find source code relevant to this error template
        code_section = ""
        if self._indexer:
            kws = self._indexer.extract_keywords(cluster.template_str, cluster.var_slots)
            if kws:
                snippets = self._indexer.find_snippets(kws)
                if snippets:
                    code_section = f"\n\nRelevant source code:\n{snippets}"

        prompt = _USER_TMPL.format(
            template=cluster.template_str[:300],
            count=cluster.count,
            context=_build_context(cluster),
            code_section=code_section,
        )

        # [6] Hard token budget on the user message
        if len(prompt) > LLM_BUDGET_CHARS:
            prompt = prompt[:LLM_BUDGET_CHARS] + "\n…[truncated]"

        resp = self._client.messages.create(
            model=LLM_MODEL,
            max_tokens=800,
            system=self._system_blocks(),
            messages=[{"role": "user", "content": prompt}],
        )
        raw = resp.content[0].text if resp.content else ""
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return {
                "summary": "RCA parse failed.",
                "technical_context": raw[:300],
                "root_cause": "Unknown",
                "action_items": ["Review logs manually."],
            }


# ── EMAIL REPORTER ────────────────────────────────────────────────────────────
_SEV_COLOR = {
    "CRITICAL": "#f38ba8",
    "FATAL": "#f38ba8",
    "ERROR": "#fab387",
    "EXCEPTION": "#f9e2af",
    "FAILED": "#89b4fa",
}

_CARD = """\
<div style="border-left:4px solid {color};background:#1e1e2e;padding:16px 20px;
            margin-bottom:20px;border-radius:6px;">
  <div style="color:#cba6f7;font-size:13px;font-weight:bold;margin-bottom:8px;font-family:monospace;">
    [{severity}]&nbsp;#{cluster_id}
    &nbsp;&middot;&nbsp;<span style="color:#f38ba8;">&times;{count} occurrences</span>
  </div>
  <div style="color:#89dceb;font-size:12px;font-family:monospace;word-break:break-all;margin-bottom:14px;">
    <strong>Template:</strong> {template}
  </div>
  <table style="width:100%;border-collapse:collapse;font-size:13px;color:#cdd6f4;font-family:sans-serif;">
    <tr>
      <td style="padding:7px 0;vertical-align:top;width:175px;color:#a6e3a1;"><strong>📋 Error Summary</strong></td>
      <td style="padding:7px 0;">{summary}</td>
    </tr>
    <tr>
      <td style="padding:7px 0;vertical-align:top;color:#89b4fa;"><strong>⚙️ Technical Context</strong></td>
      <td style="padding:7px 0;">{technical_context}</td>
    </tr>
    <tr>
      <td style="padding:7px 0;vertical-align:top;color:#f38ba8;"><strong>🔍 Root Cause</strong></td>
      <td style="padding:7px 0;">{root_cause}</td>
    </tr>
    <tr>
      <td style="padding:7px 0;vertical-align:top;color:#fab387;"><strong>🛠 Action Items</strong></td>
      <td style="padding:7px 0;"><ol style="margin:0;padding-left:20px;">{action_items}</ol></td>
    </tr>
  </table>
</div>"""

_WRAPPER = """\
<!DOCTYPE html><html><head><meta charset="utf-8">
<style>
  body  {{ background:#11111b; color:#cdd6f4; font-family:sans-serif; padding:28px; margin:0; }}
  h1    {{ color:#89dceb; font-size:20px; margin:0 0 6px; }}
  .meta {{ color:#6c7086; font-size:12px; margin-bottom:8px; }}
  .meta span {{ margin-right:16px; }}
  .comp {{ color:#a6e3a1; font-size:11px; font-family:monospace; margin-bottom:28px; }}
</style>
</head><body>
<h1>🔴 Splunk Anomaly Report</h1>
<div class="meta">
  <span>🕐 {dt}</span>
  <span>📂 index: <strong>{index}</strong></span>
  <span>⏱ window: last <strong>{mins} min</strong></span>
  <span>🧩 clusters: <strong>{llm_sent}</strong></span>
  <span>📊 total events: <strong>{events:,}</strong></span>
</div>
<div class="comp">📉 compression: {comp_summary}</div>
{cards}
</body></html>"""


class EmailReporter:
    def send(
        self,
        clusters: list[LogCluster],
        analyses: dict[str, dict],
        stats: CompressionStats,
    ) -> None:
        cards = ""
        for c in sorted(clusters, key=lambda x: -x.count):
            rca = analyses.get(c.cluster_id, {})
            color = _SEV_COLOR.get(c.severity, "#89dceb")
            items = "".join(f"<li>{a}</li>" for a in rca.get("action_items", []))
            cards += _CARD.format(
                color=color,
                severity=c.severity,
                cluster_id=c.cluster_id,
                count=c.count,
                template=c.template_str[:250],
                summary=rca.get("summary", "N/A"),
                technical_context=rca.get("technical_context", "N/A"),
                root_cause=rca.get("root_cause", "N/A"),
                action_items=items,
            )

        now = datetime.now(timezone.utc)
        body = _WRAPPER.format(
            dt=now.strftime("%Y-%m-%d %H:%M UTC"),
            index=SPLUNK_INDEX,
            mins=LOOKBACK_MINS,
            llm_sent=stats.llm_sent,
            events=stats.raw,
            comp_summary=stats.summary(),
            cards=cards,
        )

        msg = MIMEMultipart("alternative")
        msg["Subject"] = (
            f"[SPLUNK ALERT] {stats.llm_sent} cluster(s) | "
            f"{stats.total_ratio} compression | {now:%Y-%m-%d %H:%M} UTC"
        )
        msg["From"] = EMAIL_FROM
        msg["To"] = EMAIL_TO
        msg.attach(MIMEText(body, "html"))

        recipients = [e.strip() for e in EMAIL_TO.split(",")]
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=20) as srv:
            srv.ehlo()
            srv.starttls()
            srv.login(SMTP_USER, SMTP_PASS)
            srv.sendmail(EMAIL_FROM, recipients, msg.as_string())
        log.info("Report sent → %s", EMAIL_TO)


# ── ORCHESTRATOR ─────────────────────────────────────────────────────────────
class LogMonitorAgent:
    """
    Full 24/7 monitoring agent.

    Pipeline per cycle:
      Splunk (2-pass) → [1]dedup → [2]stackcomp → [3]tokenize+Drain → [4]merge
      → cluster dedup (suppress known patterns) → [5][6]LLM → email

    LLM and email are only triggered when NEW error patterns appear.
    Quiet cycles (no errors, or all patterns already reported recently) are silent.
    """

    def __init__(self) -> None:
        self.splunk = SplunkClient()
        self.reporter = EmailReporter()

        # Codebase indexer: optional but strongly recommended for accurate RCA.
        # Loaded once at startup; architecture summary cached across all cluster calls.
        indexer = CodebaseIndexer.from_env()
        if not indexer:
            log.info(
                "No GITHUB_TOKEN/GITHUB_REPO set — RCA will use generic SRE context only. "
                "Set both env vars to enable codebase-aware root cause analysis."
            )
        self.rca = RCAAnalyzer(indexer)

        # Cross-cycle dedup: cluster_id → epoch time when last reported.
        # Prevents re-alerting on the same persistent error every poll cycle.
        self._reported: dict[str, float] = {}

    # ── Dedup helpers ─────────────────────────────────────────────────────────

    def _prune_dedup(self) -> None:
        """Drop cluster IDs that have aged past the dedup window."""
        cutoff = time.time() - DEDUP_WINDOW_MINS * 60
        self._reported = {cid: t for cid, t in self._reported.items() if t > cutoff}

    def _split_new_known(
        self, clusters: list[LogCluster]
    ) -> tuple[list[LogCluster], list[LogCluster]]:
        """Return (new_clusters, suppressed_clusters) based on dedup window."""
        self._prune_dedup()
        new: list[LogCluster] = []
        known: list[LogCluster] = []
        for c in clusters:
            (known if c.cluster_id in self._reported else new).append(c)
        return new, known

    # ── Single poll cycle ─────────────────────────────────────────────────────

    def run_once(self) -> bool:
        """
        Execute one complete poll cycle.

        Returns True  if an alert email was sent (new error patterns found).
        Returns False if the cycle was quiet (no errors, or all patterns already known).

        The LLM is never called on a quiet cycle — zero API cost when nothing is wrong.
        """
        # ── Daily codebase sync (once at CODEBASE_REFRESH_HOUR Eastern Time) ───
        # No-op on every cycle except the first one after 7 AM ET each day.
        # Zero GitHub API calls until the scheduled window opens.
        refreshed = self.rca.refresh_codebase()
        if refreshed:
            log.info("✅  Codebase re-indexed — RCA context updated with today's code.")

        # ── Pass 1 + 2: error discovery → time-windowed context batch fetch ──
        log.info(
            "Polling — last %d min | index=%s | window: -%ds/+%ds around first error",
            LOOKBACK_MINS,
            SPLUNK_INDEX,
            PRE_WINDOW_SECS,
            POST_WINDOW_SECS,
        )
        ctx_events: list[ContextualEvent] = self.splunk.fetch_anomalies()
        if not ctx_events:
            log.info(
                "✅  All quiet — no ERROR/EXCEPTION/FAILED/CRITICAL/FATAL in last %d min.",
                LOOKBACK_MINS,
            )
            return False

        log.info(
            "⚠️  %d error event(s) — running compression pipeline",
            len(ctx_events),
        )

        # ── [1]–[4] + [6a]: shared compression pipeline ───────────────────────
        all_clusters, stats = compress_events(ctx_events)
        if not all_clusters:
            log.info("Zero clusters after compression — nothing to report.")
            return False

        # ── Top-N selection ───────────────────────────────────────────────────
        top = all_clusters[:MAX_LLM_CLUSTERS]

        # ── Cross-cycle dedup: skip patterns seen in the last DEDUP_WINDOW_MINS ──
        new_clusters, suppressed = self._split_new_known(top)
        if suppressed:
            log.info(
                "🔕  Suppressed %d cluster(s) already reported within the last %d-min dedup window: %s",
                len(suppressed),
                DEDUP_WINDOW_MINS,
                ", ".join(f"#{c.cluster_id}" for c in suppressed),
            )
        if not new_clusters:
            log.info(
                "✅  All %d cluster(s) are known patterns — no new anomalies to report.",
                len(top),
            )
            return False

        stats.llm_sent = len(new_clusters)
        log.info("Compression: %s", stats.summary())

        # ── [5][6] LLM RCA — only for NEW clusters (conditional on error presence) ──
        analyses: dict[str, dict] = {}
        code_ctx = "on" if self.rca._indexer else "off"
        for i, c in enumerate(new_clusters, 1):
            log.info(
                "[%d/%d] RCA %s sev=%s ×%d slots=%d code-ctx=%s",
                i,
                len(new_clusters),
                c.cluster_id,
                c.severity,
                c.count,
                len(c.var_slots),
                code_ctx,
            )
            analyses[c.cluster_id] = self.rca.analyze(c)

        # Mark as reported before sending (so a crash during send still avoids spam)
        now_ts = time.time()
        for c in new_clusters:
            self._reported[c.cluster_id] = now_ts

        self.reporter.send(new_clusters, analyses, stats)
        log.info("🚨  Alert sent — %d new cluster(s) reported.", len(new_clusters))
        return True

    # ── 24/7 daemon loop ──────────────────────────────────────────────────────

    def start(self) -> None:
        """
        Run as a 24/7 daemon.

        - Polls Splunk every POLL_INTERVAL_SECS seconds (default: 3600 = 1 h).
        - Only calls the LLM and sends email when NEW error patterns appear.
        - Suppresses repeat alerts for the same cluster within DEDUP_WINDOW_MINS minutes.
        - Recovers from transient errors (Splunk down, network blip) without crashing.
        - Graceful shutdown on SIGTERM or Ctrl+C — finishes the current cycle first.
        """
        _shutdown = threading.Event()

        def _handle_signal(sig: int, frame: object) -> None:
            log.info(
                "🛑  Shutdown signal received (sig=%d) — finishing current cycle then stopping.",
                sig,
            )
            _shutdown.set()

        signal.signal(signal.SIGTERM, _handle_signal)
        signal.signal(signal.SIGINT, _handle_signal)

        log.info(
            "🚀  LogAgent daemon started | poll every %ds (%dm) | dedup window: %dm | index: %s",
            POLL_INTERVAL_SECS,
            POLL_INTERVAL_SECS // 60,
            DEDUP_WINDOW_MINS,
            SPLUNK_INDEX,
        )

        cycle = 0
        while not _shutdown.is_set():
            cycle += 1
            cycle_start = time.time()
            log.info("── Cycle #%d ────────────────────────────────────────────────", cycle)

            try:
                self.run_once()
            except Exception as exc:
                log.error(
                    "Cycle #%d encountered an error: %s — sleeping and retrying next cycle.",
                    cycle,
                    exc,
                    exc_info=True,
                )

            elapsed = time.time() - cycle_start
            sleep_secs = max(0.0, POLL_INTERVAL_SECS - elapsed)

            if not _shutdown.is_set():
                log.info(
                    "── Cycle #%d done in %.1fs — next poll in %dm %02ds ───────────────",
                    cycle,
                    elapsed,
                    int(sleep_secs) // 60,
                    int(sleep_secs) % 60,
                )
                # Block until next cycle or shutdown — wakes immediately on Ctrl+C / SIGTERM
                _shutdown.wait(timeout=sleep_secs)

        log.info("👋  LogAgent stopped cleanly after %d cycle(s).", cycle)


# ── ENTRY POINT ──────────────────────────────────────────────────────────────
if __name__ == "__main__":
    missing = [
        v
        for v in ("SPLUNK_PASS", "ANTHROPIC_API_KEY", "SMTP_USER", "SMTP_PASS")
        if not os.environ.get(v)
    ]
    if missing:
        raise SystemExit(f"Missing required env vars: {', '.join(missing)}")
    LogMonitorAgent().start()
