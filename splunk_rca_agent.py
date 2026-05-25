#!/usr/bin/env python3
"""
splunk_rca_agent.py
Splunk anomaly monitor → enhanced Drain clustering → LLM RCA → HTML email

Compression pipeline (6 stages):
  [1] Pre-dedup         exact-hash lines → count weights (O(1)/line)
  [2] Stack compressor  collapse Java/Python frames → 2 kept + N omitted
  [3] Extended tokenize key=value, quoted strings, thread IDs → typed tokens
  [4] Drain clustering  prefix-tree similarity grouping with weight + var slots
  [5] Cluster merger    second-pass similarity merge of near-identical templates
  [6] Token budget      variable-slot differential encoding + hard char cap

Dependencies:  pip install requests anthropic urllib3
Python:        3.10+

Required env vars:
  SPLUNK_HOST  SPLUNK_USER  SPLUNK_PASS  ANTHROPIC_API_KEY  SMTP_USER  SMTP_PASS  EMAIL_TO

Optional env vars (defaults shown):
  SPLUNK_INDEX=main  LOOKBACK_MINS=60  MAX_LOG_RESULTS=5000  MAX_LLM_CLUSTERS=20
  DRAIN_SIM=0.5  DRAIN_DEPTH=4  DRAIN_MAX_CHILD=100  MERGE_SIM=0.8
  LLM_BUDGET_CHARS=2000  MAX_SLOT_VALS=5
  SMTP_HOST=smtp.gmail.com  SMTP_PORT=587  EMAIL_FROM=<SMTP_USER>
"""

from __future__ import annotations
import os, re, json, smtplib, logging, hashlib
from datetime import datetime, timezone
from dataclasses import dataclass, field
from collections import defaultdict, Counter
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Optional

import urllib3
import requests
import anthropic

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger(__name__)

# ── CONFIG ───────────────────────────────────────────────────────────────────
SPLUNK_HOST      = os.environ.get("SPLUNK_HOST",       "https://localhost:8089")
SPLUNK_USER      = os.environ.get("SPLUNK_USER",       "admin")
SPLUNK_PASS      = os.environ.get("SPLUNK_PASS",       "")
SPLUNK_INDEX     = os.environ.get("SPLUNK_INDEX",      "main")
LOOKBACK_MINS    = int(os.environ.get("LOOKBACK_MINS",    "60"))
MAX_LOG_RESULTS  = int(os.environ.get("MAX_LOG_RESULTS",  "5000"))
MAX_LLM_CLUSTERS = int(os.environ.get("MAX_LLM_CLUSTERS", "20"))

LLM_MODEL        = "claude-opus-4-7"
ANTHROPIC_KEY    = os.environ.get("ANTHROPIC_API_KEY", "")

SMTP_HOST        = os.environ.get("SMTP_HOST",  "smtp.gmail.com")
SMTP_PORT        = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USER        = os.environ.get("SMTP_USER",  "")
SMTP_PASS        = os.environ.get("SMTP_PASS",  "")
EMAIL_FROM       = os.environ.get("EMAIL_FROM", SMTP_USER)
EMAIL_TO         = os.environ.get("EMAIL_TO",   "devteam@example.com")

# Drain params
SIM_THRESHOLD    = float(os.environ.get("DRAIN_SIM",       "0.5"))
DRAIN_DEPTH      = int(os.environ.get("DRAIN_DEPTH",       "4"))
MAX_CHILDREN     = int(os.environ.get("DRAIN_MAX_CHILD",   "100"))
MERGE_SIM        = float(os.environ.get("MERGE_SIM",       "0.8"))   # [4] second-pass merger

# Token budget params
LLM_BUDGET_CHARS = int(os.environ.get("LLM_BUDGET_CHARS", "2000"))   # [6] ~500 tokens
MAX_SLOT_VALS    = int(os.environ.get("MAX_SLOT_VALS",     "5"))      # [5] values per slot

ANOMALY_RE       = re.compile(r"\b(ERROR|EXCEPTION|FAILED|CRITICAL|FATAL)\b", re.I)

# ── COMPRESSION STATS ─────────────────────────────────────────────────────────
@dataclass
class CompressionStats:
    raw:          int = 0   # lines from Splunk
    unique:       int = 0   # after exact dedup  [1]
    compressed:   int = 0   # after stack compactor [2]
    clusters:     int = 0   # after Drain  [3/4]
    merged:       int = 0   # after second-pass merge [5]
    llm_sent:     int = 0   # clusters actually analyzed

    @property
    def total_ratio(self) -> str:
        r = self.raw / max(self.merged, 1)
        return f"{r:,.0f}x"

    def summary(self) -> str:
        return (
            f"raw={self.raw:,} → dedup={self.unique:,} "
            f"→ stackcomp={self.compressed:,} → drain={self.clusters} "
            f"→ merged={self.merged} → llm={self.llm_sent}  "
            f"[total {self.total_ratio} compression]"
        )

# ── [2] STACK TRACE COMPRESSOR ────────────────────────────────────────────────
_JAVA_FRAME  = re.compile(r'\n?\s*at [\w.$<>]+\([\w.]+(?::\d+)?\)')
_PY_FRAME    = re.compile(r'\n?\s*File "[^"]+", line \d+(?:, in \w+)?')
_CAUSED_BY   = re.compile(r'(?:Caused by|caused by): ?[^\n]+')
_EXC_CLASS   = re.compile(r'[\w.$]+(?:Exception|Error|Fault|Failure|Warning)[^\n]{0,120}')

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
        kept   = [f.strip() for f in java_frames[:2]]
        omit   = max(0, len(java_frames) - 2)
        parts  = [header] + kept
        if omit:
            parts.append(f"…[{omit} frames omitted]")
        parts.extend(causes[:2])
        return " | ".join(p for p in parts if p)[:500]

    # ── Python
    py_frames = _PY_FRAME.findall(norm)
    if py_frames:
        exc   = _EXC_CLASS.search(norm)
        kept  = [f.strip() for f in py_frames[:2]]
        omit  = max(0, len(py_frames) - 2)
        parts = ([exc.group(0)[:150]] if exc else []) + kept
        if omit:
            parts.append(f"…[{omit} frames omitted]")
        return " | ".join(p for p in parts if p)[:500]

    return line  # not a stack trace

# ── [3] TOKENIZER (base + extended patterns) ─────────────────────────────────
_VAR_SUBS: list[tuple[re.Pattern, str]] = [
    # --- Base patterns (high specificity first) ---
    (re.compile(r'\b\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?\b'),                      "<IP>"),
    (re.compile(r'\b[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}\b', re.I),     "<UUID>"),
    (re.compile(r'\b[0-9a-fA-F]{16,}\b'),                                        "<HEX>"),
    (re.compile(r'\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?\b'),   "<TS>"),
    (re.compile(r'\b\d{10,13}\b'),                                                "<EPOCH>"),
    (re.compile(r'/[\w./\-]{4,}'),                                                "<PATH>"),
    (re.compile(r'\b[\w.+-]+@[\w.-]+\.\w+\b'),                                   "<EMAIL>"),
    # --- [3] Extended patterns ---
    # key=value pairs: user_id=abc123, status=500, duration=342ms
    (re.compile(r'(?<!\w)[\w.\-]{2,24}=(?:[^\s,;{}\[\]"\']{1,40})'),            "<KV>"),
    # double / single quoted strings (3–80 chars)
    (re.compile(r'"[^"\\]{3,80}"'),                                               "<STR>"),
    (re.compile(r"'[^'\\]{3,80}'"),                                               "<STR>"),
    # thread / connection / session / transaction identifiers
    (re.compile(r'\b(?:thread|conn|session|txn|req|task|job)[-_]?[A-Za-z0-9]{4,}\b', re.I), "<TID>"),
    # generic large numbers last
    (re.compile(r'\b\d+\b'),                                                      "<NUM>"),
]

def _tokenize(line: str) -> list[str]:
    """Apply all substitutions, split, cap at 64 tokens."""
    for pat, tok in _VAR_SUBS:
        line = pat.sub(tok, line)
    return line.split()[:64]

# ── DATA MODEL ───────────────────────────────────────────────────────────────
@dataclass
class LogCluster:
    template:    list[str]
    raw_samples: list[str]             = field(default_factory=list)
    # [5] variable slot tracker: {token_position → [distinct_values_seen]}
    var_slots:   dict[int, list[str]]  = field(default_factory=dict)
    count:       int                   = 0
    severity:    str                   = "ERROR"

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
    return sum(x == y for x, y in zip(a, b)) / len(a)

def _merge_tpl(a: list[str], b: list[str]) -> list[str]:
    return [x if x == y else "<*>" for x, y in zip(a, b)]

class DrainClusterer:
    """
    Prefix-tree Drain clusterer.
    Tree: { token_len → { prefix_key → [LogCluster] } }
    Accepts per-line weights (from pre-dedup counts).
    Tracks variable slot values for differential LLM encoding.
    """

    def __init__(self) -> None:
        self._tree: dict[int, dict[str, list[LogCluster]]] = \
            defaultdict(lambda: defaultdict(list))

    def _prefix_key(self, tokens: list[str]) -> str:
        return " ".join(
            t if not t.startswith("<") else "<*>"
            for t in tokens[:DRAIN_DEPTH]
        )

    def _severity(self, line: str) -> str:
        m = ANOMALY_RE.search(line)
        return m.group(1).upper() if m else "ERROR"

    def _track_slots(self, cluster: LogCluster, tokens: list[str]) -> None:
        """Record dynamic values at positions where template diverges."""
        for i, (tmpl_tok, new_tok) in enumerate(zip(cluster.template, tokens)):
            if tmpl_tok != new_tok:
                slot = cluster.var_slots.setdefault(i, [])
                # Capture original value on first divergence
                if tmpl_tok != "<*>" and tmpl_tok not in slot and len(slot) < MAX_SLOT_VALS:
                    slot.append(tmpl_tok[:30])
                if new_tok not in slot and len(slot) < MAX_SLOT_VALS:
                    slot.append(new_tok[:30])

    def add(self, raw: str, weight: int = 1) -> Optional[LogCluster]:
        tokens = _tokenize(raw)
        if not tokens:
            return None

        bucket   = self._tree[len(tokens)][self._prefix_key(tokens)]
        best, best_sim = None, -1.0
        for c in bucket:
            s = _sim(c.template, tokens)
            if s > best_sim:
                best_sim, best = s, c

        if best_sim >= SIM_THRESHOLD and best:
            self._track_slots(best, tokens)          # [5] track before merge
            best.template = _merge_tpl(best.template, tokens)
            best.count   += weight
            if len(best.raw_samples) < 3:
                best.raw_samples.append(raw[:300])
        else:
            if len(bucket) >= MAX_CHILDREN:
                return None
            best = LogCluster(
                template=list(tokens),
                raw_samples=[raw[:300]],
                count=weight,
                severity=self._severity(raw),
            )
            bucket.append(best)
        return best

    def cluster(self, weighted: dict[str, int]) -> list[LogCluster]:
        """Cluster unique lines, respecting pre-dedup weights."""
        for line, weight in weighted.items():
            if ANOMALY_RE.search(line):
                self.add(line, weight)
        return [c for by_len in self._tree.values()
                  for cs in by_len.values()
                  for c in cs]

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
            for cand in group[i + 1:]:
                if id(cand) in absorbed:
                    continue
                if _sim(base.template, cand.template) >= MERGE_SIM:
                    base.template = _merge_tpl(base.template, cand.template)
                    base.count   += cand.count
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

# ── SPLUNK CLIENT ─────────────────────────────────────────────────────────────
class SplunkClient:
    """REST-only Splunk client. No splunk-sdk dependency."""

    def __init__(self) -> None:
        self._sess  = requests.Session()
        self._sess.verify = False       # replace with cert path in prod
        self._token: Optional[str] = None

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

    def fetch_anomalies(self) -> list[str]:
        spl = (
            f'search index="{SPLUNK_INDEX}" earliest=-{LOOKBACK_MINS}m '
            f'(ERROR OR EXCEPTION OR FAILED OR CRITICAL OR FATAL) '
            f'| head {MAX_LOG_RESULTS} | fields _raw'
        )
        r = self._sess.post(
            f"{SPLUNK_HOST}/services/search/jobs",
            headers=self._hdrs(),
            data={"search": spl, "output_mode": "json",
                  "exec_mode": "blocking", "max_count": MAX_LOG_RESULTS},
            timeout=180,
        )
        r.raise_for_status()
        sid = r.json()["sid"]
        r2  = self._sess.get(
            f"{SPLUNK_HOST}/services/search/jobs/{sid}/results",
            headers=self._hdrs(),
            params={"output_mode": "json", "count": MAX_LOG_RESULTS},
            timeout=30,
        )
        r2.raise_for_status()
        return [row["_raw"] for row in r2.json().get("results", []) if row.get("_raw")]

# ── LLM RCA ANALYZER ─────────────────────────────────────────────────────────
_SYS = (
    "You are a senior SRE with deep expertise in distributed systems, "
    "cloud infrastructure, and application debugging. Be concise and precise."
)

# [5] Differential encoding template — variable slots replace raw samples
_USER_TMPL = """\
Analyze the log error cluster. Return ONLY valid JSON — no markdown, no fences.

Template : {template}
Frequency: {count} occurrences
{context}

Required JSON (exact keys):
{{
  "summary":           "<one sentence: what happened and its impact>",
  "technical_context": "<technical explanation of why this error occurs>",
  "root_cause":        "<the underlying trigger or failure point>",
  "action_items":      ["<actionable step 1>", "<step 2>", ...]
}}"""

def _var_summary(cluster: LogCluster) -> str:
    """Compact slot table: position index, token type, sampled values."""
    if not cluster.var_slots:
        return ""
    rows = []
    for pos in sorted(cluster.var_slots):
        tok  = cluster.template[pos] if pos < len(cluster.template) else "<*>"
        vals = ", ".join(repr(v) for v in cluster.var_slots[pos])
        rows.append(f"  [{pos}] {tok}: {vals}")
    return "Variable slots (position → observed values):\n" + "\n".join(rows)

def _build_context(cluster: LogCluster) -> str:
    """Use slot table when available, fall back to raw samples."""
    if cluster.var_slots:
        return _var_summary(cluster)
    samples = "\n".join(f"  {s}" for s in cluster.raw_samples[:3])
    return f"Sample logs:\n{samples}"

class RCAAnalyzer:
    def __init__(self) -> None:
        self._client = anthropic.Anthropic(api_key=ANTHROPIC_KEY)

    def analyze(self, cluster: LogCluster) -> dict:
        context = _build_context(cluster)
        prompt  = _USER_TMPL.format(
            template=cluster.template_str[:300],
            count=cluster.count,
            context=context,
        )
        # [6] Token budget: hard cap before sending
        if len(prompt) > LLM_BUDGET_CHARS:
            prompt = prompt[:LLM_BUDGET_CHARS] + "\n…[truncated]"

        resp = self._client.messages.create(
            model=LLM_MODEL,
            max_tokens=700,
            # System block cached across all cluster calls — ephemeral TTL 5 min
            system=[{"type": "text", "text": _SYS,
                     "cache_control": {"type": "ephemeral"}}],
            messages=[{"role": "user", "content": prompt}],
        )
        raw = resp.content[0].text if resp.content else ""
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return {
                "summary":           "RCA parse failed.",
                "technical_context": raw[:300],
                "root_cause":        "Unknown",
                "action_items":      ["Review logs manually."],
            }

# ── EMAIL REPORTER ────────────────────────────────────────────────────────────
_SEV_COLOR = {
    "CRITICAL": "#f38ba8", "FATAL": "#f38ba8",
    "ERROR":    "#fab387", "EXCEPTION": "#f9e2af", "FAILED": "#89b4fa",
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
            rca   = analyses.get(c.cluster_id, {})
            color = _SEV_COLOR.get(c.severity, "#89dceb")
            items = "".join(f"<li>{a}</li>" for a in rca.get("action_items", []))
            cards += _CARD.format(
                color=color,
                severity=c.severity,
                cluster_id=c.cluster_id,
                count=c.count,
                template=c.template_str[:250],
                summary=rca.get("summary",           "N/A"),
                technical_context=rca.get("technical_context", "N/A"),
                root_cause=rca.get("root_cause",     "N/A"),
                action_items=items,
            )

        now  = datetime.now(timezone.utc)
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
        msg["To"]   = EMAIL_TO
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
    Full compression pipeline:
      Splunk → [1]dedup → [2]stackcomp → [3]tokenize+Drain → [4]merge → [5][6]LLM → email
    """

    def __init__(self) -> None:
        self.splunk   = SplunkClient()
        self.drain    = DrainClusterer()
        self.rca      = RCAAnalyzer()
        self.reporter = EmailReporter()

    def run(self) -> None:
        stats = CompressionStats()

        # ── Fetch
        log.info("Fetching — last %d min | index=%s", LOOKBACK_MINS, SPLUNK_INDEX)
        raw_lines = self.splunk.fetch_anomalies()
        if not raw_lines:
            log.info("No anomaly events. Exiting.")
            return
        stats.raw = len(raw_lines)

        # ── [1] Pre-deduplication: collapse identical lines, keep weights
        dedup: dict[str, int] = dict(Counter(raw_lines))
        stats.unique = len(dedup)
        log.info("[1] dedup: %d → %d unique lines (%.1fx)",
                 stats.raw, stats.unique, stats.raw / max(stats.unique, 1))

        # ── [2] Stack trace compression on unique lines
        compressed: dict[str, int] = {}
        for line, weight in dedup.items():
            c = compress_stacktrace(line)
            compressed[c] = compressed.get(c, 0) + weight
        stats.compressed = len(compressed)
        log.info("[2] stack-compress: %d → %d lines", stats.unique, stats.compressed)

        # ── [3] Drain clustering (weighted)
        clusters = self.drain.cluster(compressed)
        stats.clusters = len(clusters)
        log.info("[3] drain: %d clusters", stats.clusters)

        # ── [4] Post-drain merge
        clusters = merge_clusters(clusters)
        stats.merged = len(clusters)
        log.info("[4] merge: %d → %d clusters (%.1fx further)",
                 stats.clusters, stats.merged, stats.clusters / max(stats.merged, 1))

        if not clusters:
            log.info("Zero clusters after merge. Exiting.")
            return

        # ── Top-N selection
        top = sorted(clusters, key=lambda c: -c.count)[:MAX_LLM_CLUSTERS]
        stats.llm_sent = len(top)
        log.info("Compression: %s", stats.summary())

        # ── [5][6] LLM RCA (differential encoding + budget cap)
        analyses: dict[str, dict] = {}
        for i, c in enumerate(top, 1):
            log.info("[%d/%d] RCA %s sev=%s ×%d slots=%d",
                     i, len(top), c.cluster_id, c.severity,
                     c.count, len(c.var_slots))
            analyses[c.cluster_id] = self.rca.analyze(c)

        self.reporter.send(top, analyses, stats)
        log.info("Done.")

# ── ENTRY POINT ──────────────────────────────────────────────────────────────
if __name__ == "__main__":
    missing = [v for v in ("SPLUNK_PASS", "ANTHROPIC_API_KEY", "SMTP_USER", "SMTP_PASS")
               if not os.environ.get(v)]
    if missing:
        raise SystemExit(f"Missing required env vars: {', '.join(missing)}")
    LogMonitorAgent().run()
