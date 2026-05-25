#!/usr/bin/env python3
"""
splunk_rca_agent.py
Splunk anomaly monitor → Drain clustering → LLM RCA → HTML email report

Dependencies:  pip install requests anthropic urllib3
Python:        3.10+

Env vars (required):
  SPLUNK_HOST       https://your-splunk:8089
  SPLUNK_USER       admin
  SPLUNK_PASS       ***
  ANTHROPIC_API_KEY sk-ant-***
  SMTP_USER         sender@gmail.com
  SMTP_PASS         app-password
  EMAIL_TO          team@company.com,oncall@company.com

Env vars (optional / have defaults):
  SPLUNK_INDEX      main
  LOOKBACK_MINS     60
  MAX_LOG_RESULTS   5000
  MAX_LLM_CLUSTERS  20      top-N clusters by freq sent to LLM
  DRAIN_SIM         0.5     similarity threshold [0-1]
  DRAIN_DEPTH       4       prefix length for tree buckets
  DRAIN_MAX_CHILD   100     max clusters per bucket
  SMTP_HOST         smtp.gmail.com
  SMTP_PORT         587
  EMAIL_FROM        <SMTP_USER>
"""

from __future__ import annotations
import os, re, json, smtplib, logging, hashlib
from datetime import datetime, timezone
from dataclasses import dataclass, field
from collections import defaultdict
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
EMAIL_TO         = os.environ.get("EMAIL_TO",   "devteam@example.com")  # comma-sep

SIM_THRESHOLD    = float(os.environ.get("DRAIN_SIM",        "0.5"))
DRAIN_DEPTH      = int(os.environ.get("DRAIN_DEPTH",        "4"))
MAX_CHILDREN     = int(os.environ.get("DRAIN_MAX_CHILD",    "100"))

ANOMALY_RE       = re.compile(r"\b(ERROR|EXCEPTION|FAILED|CRITICAL|FATAL)\b", re.I)

# ── DYNAMIC TOKEN PATTERNS (applied before clustering) ───────────────────────
_VAR_SUBS: list[tuple[re.Pattern, str]] = [
    (re.compile(r'\b\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?\b'),                     "<IP>"),
    (re.compile(r'\b[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}\b', re.I),    "<UUID>"),
    (re.compile(r'\b[0-9a-fA-F]{16,}\b'),                                       "<HEX>"),
    (re.compile(r'\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?\b'),  "<TS>"),
    (re.compile(r'\b\d{10,13}\b'),                                               "<EPOCH>"),
    (re.compile(r'/[\w./\-]{4,}'),                                               "<PATH>"),
    (re.compile(r'\b[\w.+-]+@[\w.-]+\.\w+\b'),                                  "<EMAIL>"),
    (re.compile(r'\b\d+\b'),                                                     "<NUM>"),
]

# ── DATA MODEL ───────────────────────────────────────────────────────────────
@dataclass
class LogCluster:
    template:    list[str]
    raw_samples: list[str] = field(default_factory=list)
    count:       int       = 0
    severity:    str       = "ERROR"

    @property
    def template_str(self) -> str:
        return " ".join(self.template)

    @property
    def cluster_id(self) -> str:
        return hashlib.md5(self.template_str.encode()).hexdigest()[:8]

# ── DRAIN CLUSTERER ──────────────────────────────────────────────────────────
def _tokenize(line: str) -> list[str]:
    """Normalize dynamic fields → typed tokens, then split (max 64 tokens)."""
    for pat, tok in _VAR_SUBS:
        line = pat.sub(tok, line)
    return line.split()[:64]

def _sim(a: list[str], b: list[str]) -> float:
    """Sequential token match ratio; 0 if lengths differ."""
    if len(a) != len(b):
        return 0.0
    return sum(x == y for x, y in zip(a, b)) / len(a)

def _merge(a: list[str], b: list[str]) -> list[str]:
    """Build merged template: keep equal tokens, wildcard divergent ones."""
    return [x if x == y else "<*>" for x, y in zip(a, b)]

class DrainClusterer:
    """
    Drain-style prefix-tree log clusterer.
    Tree structure: { token_count → { prefix_key → [LogCluster, …] } }
    O(1) bucket lookup; O(k) similarity scan per bucket.
    """

    def __init__(self) -> None:
        self._tree: dict[int, dict[str, list[LogCluster]]] = \
            defaultdict(lambda: defaultdict(list))

    def _prefix_key(self, tokens: list[str]) -> str:
        """First DRAIN_DEPTH tokens (dynamic tokens collapsed to <*>)."""
        return " ".join(
            t if not t.startswith("<") else "<*>"
            for t in tokens[:DRAIN_DEPTH]
        )

    def _severity(self, line: str) -> str:
        m = ANOMALY_RE.search(line)
        return m.group(1).upper() if m else "ERROR"

    def _add(self, raw: str) -> Optional[LogCluster]:
        tokens = _tokenize(raw)
        if not tokens:
            return None

        bucket = self._tree[len(tokens)][self._prefix_key(tokens)]
        best, best_sim = None, -1.0

        for c in bucket:
            s = _sim(c.template, tokens)
            if s > best_sim:
                best_sim, best = s, c

        if best_sim >= SIM_THRESHOLD and best:
            best.template = _merge(best.template, tokens)
            best.count   += 1
            if len(best.raw_samples) < 3:
                best.raw_samples.append(raw[:400])
        else:
            if len(bucket) >= MAX_CHILDREN:
                return None                     # overflow guard
            best = LogCluster(
                template=list(tokens),
                raw_samples=[raw[:400]],
                count=1,
                severity=self._severity(raw),
            )
            bucket.append(best)
        return best

    def cluster(self, lines: list[str]) -> list[LogCluster]:
        """Filter anomaly lines, cluster them, return all LogCluster objects."""
        for line in lines:
            if ANOMALY_RE.search(line):
                self._add(line)
        return [c for by_len in self._tree.values()
                  for cs in by_len.values()
                  for c in cs]

# ── SPLUNK CLIENT ────────────────────────────────────────────────────────────
class SplunkClient:
    """Thin wrapper around Splunk REST API (no splunk-sdk dependency)."""

    def __init__(self) -> None:
        self._sess  = requests.Session()
        self._sess.verify = False           # set True with proper cert bundle in prod
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
        return self._token                  # type: ignore[return-value]

    def _hdrs(self) -> dict:
        return {"Authorization": f"Splunk {self._auth_token}"}

    def fetch_anomalies(self) -> list[str]:
        """Run a blocking SPL search, return raw log strings."""
        spl = (
            f'search index="{SPLUNK_INDEX}" earliest=-{LOOKBACK_MINS}m '
            f'(ERROR OR EXCEPTION OR FAILED OR CRITICAL OR FATAL) '
            f'| head {MAX_LOG_RESULTS} | fields _raw'
        )
        # Create blocking job
        r = self._sess.post(
            f"{SPLUNK_HOST}/services/search/jobs",
            headers=self._hdrs(),
            data={
                "search":      spl,
                "output_mode": "json",
                "exec_mode":   "blocking",
                "max_count":   MAX_LOG_RESULTS,
            },
            timeout=180,
        )
        r.raise_for_status()
        sid = r.json()["sid"]

        # Fetch results page
        r2 = self._sess.get(
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

_USER_TMPL = """\
Analyze the log error cluster below. Return ONLY valid JSON — no markdown, no fences.

Template : {template}
Frequency: {count} occurrences
Samples  :
{samples}

Required JSON (exact keys):
{{
  "summary":           "<one sentence: what happened and its impact>",
  "technical_context": "<technical explanation of why this error occurs>",
  "root_cause":        "<the underlying trigger or failure point>",
  "action_items":      ["<actionable step 1>", "<step 2>", ...]
}}"""

class RCAAnalyzer:
    """Calls Claude to generate structured RCA for each error cluster."""

    def __init__(self) -> None:
        self._client = anthropic.Anthropic(api_key=ANTHROPIC_KEY)

    def analyze(self, cluster: LogCluster) -> dict:
        samples = "\n".join(f"  {s}" for s in cluster.raw_samples[:3])
        resp = self._client.messages.create(
            model=LLM_MODEL,
            max_tokens=700,
            # System block is prompt-cached across all cluster calls — saves tokens
            system=[{
                "type":          "text",
                "text":          _SYS,
                "cache_control": {"type": "ephemeral"},
            }],
            messages=[{"role": "user", "content": _USER_TMPL.format(
                template=cluster.template_str[:300],
                count=cluster.count,
                samples=samples,
            )}],
        )
        raw = resp.content[0].text if resp.content else ""
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return {
                "summary":           "RCA parse failed — see raw.",
                "technical_context": raw[:300],
                "root_cause":        "Unknown",
                "action_items":      ["Review logs manually."],
            }

# ── EMAIL REPORTER ────────────────────────────────────────────────────────────
_SEV_COLOR = {
    "CRITICAL": "#f38ba8", "FATAL": "#f38ba8",
    "ERROR":    "#fab387", "EXCEPTION": "#f9e2af",
    "FAILED":   "#89b4fa",
}

_CARD = """\
<div style="border-left:4px solid {color};background:#1e1e2e;padding:16px 20px;
            margin-bottom:20px;border-radius:6px;font-family:monospace;">
  <div style="color:#cba6f7;font-size:13px;font-weight:bold;margin-bottom:8px;">
    [{severity}]&nbsp;#{cluster_id}
    &nbsp;&middot;&nbsp;<span style="color:#f38ba8;">&times;{count} occurrences</span>
  </div>
  <div style="color:#89dceb;font-size:12px;word-break:break-all;margin-bottom:14px;">
    <strong>Template:</strong> {template}
  </div>
  <table style="width:100%;border-collapse:collapse;font-size:13px;
                color:#cdd6f4;font-family:sans-serif;">
    <tr>
      <td style="padding:7px 0;vertical-align:top;width:175px;color:#a6e3a1;">
        <strong>📋 Error Summary</strong></td>
      <td style="padding:7px 0;">{summary}</td>
    </tr>
    <tr>
      <td style="padding:7px 0;vertical-align:top;color:#89b4fa;">
        <strong>⚙️ Technical Context</strong></td>
      <td style="padding:7px 0;">{technical_context}</td>
    </tr>
    <tr>
      <td style="padding:7px 0;vertical-align:top;color:#f38ba8;">
        <strong>🔍 Root Cause</strong></td>
      <td style="padding:7px 0;">{root_cause}</td>
    </tr>
    <tr>
      <td style="padding:7px 0;vertical-align:top;color:#fab387;">
        <strong>🛠 Action Items</strong></td>
      <td style="padding:7px 0;">
        <ol style="margin:0;padding-left:20px;">{action_items}</ol>
      </td>
    </tr>
  </table>
</div>"""

_WRAPPER = """\
<!DOCTYPE html><html><head><meta charset="utf-8">
<style>
  body {{ background:#11111b; color:#cdd6f4; font-family:sans-serif;
          padding:28px; margin:0; }}
  h1   {{ color:#89dceb; font-size:20px; margin:0 0 6px; }}
  .meta {{ color:#6c7086; font-size:12px; margin-bottom:28px; }}
  .meta span {{ margin-right:16px; }}
</style>
</head><body>
<h1>🔴 Splunk Anomaly Report</h1>
<div class="meta">
  <span>🕐 {dt}</span>
  <span>📂 index: <strong>{index}</strong></span>
  <span>⏱ window: last <strong>{mins} min</strong></span>
  <span>🧩 clusters: <strong>{clusters}</strong></span>
  <span>📊 total events: <strong>{events}</strong></span>
</div>
{cards}
</body></html>"""


class EmailReporter:
    """Builds dark-themed HTML report and dispatches via SMTP STARTTLS."""

    def send(self, clusters: list[LogCluster], analyses: dict[str, dict]) -> None:
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
            clusters=len(clusters),
            events=sum(c.count for c in clusters),
            cards=cards,
        )

        msg = MIMEMultipart("alternative")
        msg["Subject"] = (
            f"[SPLUNK ALERT] {len(clusters)} cluster(s) detected "
            f"| {now:%Y-%m-%d %H:%M} UTC"
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
        log.info("Report sent → %s (%d cluster(s))", EMAIL_TO, len(clusters))

# ── ORCHESTRATOR ─────────────────────────────────────────────────────────────
class LogMonitorAgent:
    """Pipeline: Splunk fetch → Drain cluster → LLM RCA → Email."""

    def __init__(self) -> None:
        self.splunk   = SplunkClient()
        self.drain    = DrainClusterer()
        self.rca      = RCAAnalyzer()
        self.reporter = EmailReporter()

    def run(self) -> None:
        log.info("Fetching anomalies — last %d min | index: %s", LOOKBACK_MINS, SPLUNK_INDEX)
        lines = self.splunk.fetch_anomalies()
        if not lines:
            log.info("No anomaly events found. Exiting.")
            return

        log.info("Clustering %d raw log lines…", len(lines))
        clusters = self.drain.cluster(lines)
        log.info("%d unique clusters formed.", len(clusters))
        if not clusters:
            log.info("Zero clusters after filtering. Exiting.")
            return

        # Analyze only top-N by frequency to control LLM cost
        top = sorted(clusters, key=lambda c: -c.count)[:MAX_LLM_CLUSTERS]
        analyses: dict[str, dict] = {}
        for i, c in enumerate(top, 1):
            log.info(
                "[%d/%d] RCA cluster=%s sev=%s count=%d → %s…",
                i, len(top), c.cluster_id, c.severity, c.count,
                c.template_str[:70],
            )
            analyses[c.cluster_id] = self.rca.analyze(c)

        self.reporter.send(top, analyses)
        log.info("Done.")

# ── ENTRY POINT ──────────────────────────────────────────────────────────────
if __name__ == "__main__":
    missing = [v for v in ("SPLUNK_PASS", "ANTHROPIC_API_KEY", "SMTP_USER", "SMTP_PASS")
               if not os.environ.get(v)]
    if missing:
        raise SystemExit(f"Missing required env vars: {', '.join(missing)}")

    LogMonitorAgent().run()
