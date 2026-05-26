#!/usr/bin/env python3
"""
event_driven_agent.py
Event-driven Splunk anomaly monitor.

Replaces the 1-hour polling loop with a real-time webhook trigger:

  Splunk saved-search alert (fires every 1 min)
    → POST /webhook  (this HTTP server, default :8765)
       → IncidentBuffer  (per-stream debounce window)
          → POST_WINDOW_SECS silence  →  fire
             → SplunkClient.fetch_context_for_stream()
                → compress_events()  (6-stage shared pipeline)
                   → RCAAnalyzer (Claude)
                      → EmailReporter

Latency comparison vs polling agent:
  Polling:       up to POLL_INTERVAL_SECS (default 60 min) before first alert.
  Event-driven:  POST_WINDOW_SECS (default 2 min) after the LAST error in a burst.

Splunk one-time setup — create a Saved Search:
  SPL:
    search index="<INDEX>" earliest=-1m
      (ERROR OR EXCEPTION OR FAILED OR CRITICAL OR FATAL)
    | head 1 | fields _time host source _raw
  Alert: trigger when "Number of Results > 0", check every 1 minute.
  Alert action → Webhook:
    URL: http://<logagent-host>:8765/webhook
    (Optional) add header  Authorization: <WEBHOOK_SECRET>

Additional env vars (beyond base agent):
  WEBHOOK_HOST        bind address (default: 0.0.0.0)
  WEBHOOK_PORT        listen port  (default: 8765)
  WEBHOOK_SECRET      optional shared secret; if set, validates
                      the Authorization header on every request
  MAX_WINDOW_SECS     force-fire cap per stream (default: 600 = 10 min)
                      prevents a noisy stream from deferring RCA forever
  WORKER_THREADS      concurrent incident processors (default: 3)
  SPLUNK_FETCH_RETRIES retries on transient Splunk errors (default: 3)
  SPLUNK_RETRY_BASE   exponential back-off base in seconds (default: 2.0)
"""

from __future__ import annotations

import http.server
import socketserver
import json
import logging
import os
import signal
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Callable

from splunk_rca_agent import (
    ANOMALY_RE,
    DEDUP_WINDOW_MINS,
    MAX_LLM_CLUSTERS,
    POST_WINDOW_SECS,
    PRE_WINDOW_SECS,
    CompressionStats,
    ContextualEvent,
    EmailReporter,
    LogCluster,
    RCAAnalyzer,
    SplunkClient,
    compress_events,
)
from codebase_context import CodebaseIndexer

log = logging.getLogger(__name__)

# ── CONFIG ────────────────────────────────────────────────────────────────────
WEBHOOK_HOST = os.environ.get("WEBHOOK_HOST", "0.0.0.0")
WEBHOOK_PORT = int(os.environ.get("WEBHOOK_PORT", "8765"))
WEBHOOK_SECRET = os.environ.get("WEBHOOK_SECRET", "")
MAX_WINDOW_SECS = int(os.environ.get("MAX_WINDOW_SECS", "600"))
WORKER_THREADS = int(os.environ.get("WORKER_THREADS", "3"))
SPLUNK_FETCH_RETRIES = int(os.environ.get("SPLUNK_FETCH_RETRIES", "3"))
SPLUNK_RETRY_BASE = float(os.environ.get("SPLUNK_RETRY_BASE", "2.0"))


# ── DATA MODEL ────────────────────────────────────────────────────────────────


@dataclass
class IncidentEvent:
    """
    A single error event received from Splunk via webhook.
    Maps 1:1 to a Splunk result row in the alert payload.
    """

    host: str
    source: str
    raw: str
    timestamp: float  # Unix epoch from Splunk _time field
    severity: str = "ERROR"

    @property
    def stream_key(self) -> str:
        """Unique identifier for the (host, source) stream."""
        return f"{self.host}||{self.source}"


@dataclass
class IncidentWindow:
    """
    Tracks an open incident for one stream (host + source pair).

    Lifecycle:
      open    — receiving events; timer not yet fired
      firing  — timer fired; being handed to a worker
      processed — worker completed (window removed from buffer)

    The window fires when either:
      (a) POST_WINDOW_SECS have elapsed since the LAST event  → silence-based
      (b) MAX_WINDOW_SECS have elapsed since the FIRST event  → hard cap

    Condition (a) is the normal case: wait for the burst to settle.
    Condition (b) prevents a continuously noisy stream from never being analysed.
    """

    stream_key: str
    host: str
    source: str
    first_event_time: float
    status: str = "open"  # "open" | "firing" | "processed"
    events: list[IncidentEvent] = field(default_factory=list)
    last_event_time: float = field(init=False)

    def __post_init__(self) -> None:
        self.last_event_time = self.first_event_time

    def add_event(self, event: IncidentEvent) -> None:
        self.events.append(event)
        if event.timestamp > self.last_event_time:
            self.last_event_time = event.timestamp

    def is_ready(self, now: float, post_window_secs: int, max_window_secs: int) -> bool:
        """
        True when the window should fire.
        Either the stream has gone silent for post_window_secs,
        or the window has been open for max_window_secs (hard cap).
        """
        return self.status == "open" and (
            now - self.last_event_time >= post_window_secs
            or now - self.first_event_time >= max_window_secs
        )


# ── INCIDENT BUFFER ───────────────────────────────────────────────────────────


class IncidentBuffer:
    """
    Thread-safe per-stream incident window manager.

    Receives IncidentEvents from the webhook server thread and groups them
    by stream_key into IncidentWindows.  A background timer thread checks
    every check_interval seconds for windows that are ready to fire, and
    calls on_window_ready(window) for each one.

    Concurrency model:
      - Webhook handler threads call add_event() concurrently.
      - Timer thread calls _check_windows() on its own interval.
      - All access to _windows is protected by a single lock.
      - on_window_ready() is called WITHOUT the lock held — it may be slow.
    """

    def __init__(
        self,
        on_window_ready: Callable[[IncidentWindow], None],
        post_window_secs: int = POST_WINDOW_SECS,
        max_window_secs: int = MAX_WINDOW_SECS,
        check_interval: float = 1.0,
    ) -> None:
        self._windows: dict[str, IncidentWindow] = {}
        self._lock = threading.Lock()
        self._on_ready = on_window_ready
        self._post_window_secs = post_window_secs
        self._max_window_secs = max_window_secs
        self._check_interval = check_interval
        self._shutdown = threading.Event()
        self._timer = threading.Thread(
            target=self._timer_loop,
            name="incident-timer",
            daemon=True,
        )
        self._timer.start()

    # ── public API ─────────────────────────────────────────────────────────────

    def add_event(self, event: IncidentEvent) -> None:
        """
        Add an event to its stream's window (creating the window if needed).
        Thread-safe — called from multiple webhook handler threads.
        """
        with self._lock:
            key = event.stream_key
            if key not in self._windows or self._windows[key].status != "open":
                self._windows[key] = IncidentWindow(
                    stream_key=key,
                    host=event.host,
                    source=event.source,
                    first_event_time=event.timestamp,
                )
                log.info("⚡  New incident window opened for %s", key)
            self._windows[key].add_event(event)

    def get_open_count(self) -> int:
        """Return the number of currently open (not yet fired) windows."""
        with self._lock:
            return sum(1 for w in self._windows.values() if w.status == "open")

    def stop(self, timeout: float = 5.0) -> None:
        """Gracefully stop the timer thread."""
        self._shutdown.set()
        self._timer.join(timeout=timeout)

    # ── internal ───────────────────────────────────────────────────────────────

    def _check_windows(self) -> list[IncidentWindow]:
        """
        Atomically collect all windows that are ready to fire and mark them
        as 'firing' so they cannot be fired again.
        """
        now = time.time()
        ready: list[IncidentWindow] = []
        with self._lock:
            for window in list(self._windows.values()):
                if window.is_ready(now, self._post_window_secs, self._max_window_secs):
                    window.status = "firing"
                    ready.append(window)
        return ready

    def _fire_window(self, window: IncidentWindow) -> None:
        """
        Invoke the callback for a ready window, then remove it from the buffer.
        Called from the timer thread — callback is invoked outside the lock.
        """
        age = time.time() - window.first_event_time
        log.info(
            "🔔  Incident window firing: %s | %d event(s) | age=%.1fs",
            window.stream_key,
            len(window.events),
            age,
        )
        try:
            self._on_ready(window)
        except Exception:
            log.exception("on_window_ready raised for %s", window.stream_key)
        finally:
            with self._lock:
                self._windows.pop(window.stream_key, None)

    def _timer_loop(self) -> None:
        """Background thread: check for ready windows every check_interval seconds."""
        while not self._shutdown.is_set():
            for window in self._check_windows():
                self._fire_window(window)
            self._shutdown.wait(timeout=self._check_interval)


# ── WEBHOOK SERVER ────────────────────────────────────────────────────────────


def _parse_webhook_payload(payload: dict) -> IncidentEvent | None:
    """
    Parse a Splunk alert webhook payload into an IncidentEvent.

    Splunk webhook format (alert action → Webhook):
      {
        "result": {
          "_time": "1748150700.000",
          "host":  "web-prod-01",
          "source": "/var/log/app.log",
          "_raw":  "<log line>"
        },
        "sid":         "scheduler__admin__...",
        "search_name": "LogAgent Error Alert",
        ...
      }

    Returns None if the payload is missing required fields or if the _raw
    line is not an anomaly (ERROR / EXCEPTION / FAILED / CRITICAL / FATAL).
    """
    result = payload.get("result") if isinstance(payload, dict) else None
    if not isinstance(result, dict):
        return None

    raw = result.get("_raw", "").strip()
    host = result.get("host", "").strip()
    source = result.get("source", "").strip()

    if not raw or not host or not source:
        return None
    if not ANOMALY_RE.search(raw):
        return None

    try:
        ts = float(result.get("_time") or time.time())
    except (ValueError, TypeError):
        ts = time.time()

    m = ANOMALY_RE.search(raw)
    severity = m.group(1).upper() if m else "ERROR"

    return IncidentEvent(host=host, source=source, raw=raw, timestamp=ts, severity=severity)


def _validate_secret(authorization_header: str, expected_secret: str) -> bool:
    """
    Validate a plain shared-secret Authorization header.
    Uses hmac.compare_digest to prevent timing attacks.
    """
    import hmac as _hmac

    return _hmac.compare_digest(authorization_header.strip(), expected_secret.strip())


class _WebhookHandler(http.server.BaseHTTPRequestHandler):
    """
    Handle incoming Splunk webhook POSTs.

    Attributes injected by the owning HTTPServer:
      server.buffer  — IncidentBuffer to receive parsed events
      server.secret  — optional shared secret (empty string = no auth)
    """

    def do_POST(self) -> None:  # noqa: N802
        if self.path.rstrip("/") != "/webhook":
            self._respond(404, {"error": "Not found"})
            return

        # Optional shared-secret auth (plain Authorization header)
        if self.server.secret:
            auth = self.headers.get("Authorization", "")
            if not _validate_secret(auth, self.server.secret):
                log.warning("Webhook: rejected request — invalid Authorization header")
                self._respond(401, {"error": "Unauthorized"})
                return

        length = int(self.headers.get("Content-Length", 0))
        if length <= 0:
            self._respond(400, {"error": "Empty body"})
            return

        body = self.rfile.read(length)

        try:
            payload = json.loads(body)
        except json.JSONDecodeError as exc:
            log.warning("Webhook: invalid JSON: %s", exc)
            self._respond(400, {"error": "Invalid JSON"})
            return

        event = _parse_webhook_payload(payload)
        if event is None:
            log.debug("Webhook: payload is not an anomaly event — ignored")
            self._respond(422, {"error": "Not an anomaly event or missing fields"})
            return

        self.server.buffer.add_event(event)
        log.info("Webhook: queued event stream=%s sev=%s", event.stream_key, event.severity)
        self._respond(200, {"status": "queued", "stream": event.stream_key})

    def _respond(self, code: int, body: dict) -> None:
        data = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, fmt: str, *args: object) -> None:  # silence access log
        log.debug("HTTP %s", fmt % args)


class _WebhookServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    """
    HTTPServer that carries the shared buffer + secret for the handler.

    ThreadingMixIn gives each request its own thread so that concurrent
    Splunk alert POSTs (e.g. from multiple saved searches) never queue
    behind each other.  daemon_threads=True ensures worker threads exit
    cleanly when the main thread shuts down.
    """

    daemon_threads = True  # worker threads exit when main thread exits

    def __init__(
        self,
        host: str,
        port: int,
        buffer: IncidentBuffer,
        secret: str,
    ) -> None:
        super().__init__((host, port), _WebhookHandler)
        self.buffer = buffer
        self.secret = secret


# ── RETRY WRAPPER ─────────────────────────────────────────────────────────────


def _fetch_with_retry(
    splunk: SplunkClient,
    host: str,
    source: str,
    first_error_time: float,
    retries: int = SPLUNK_FETCH_RETRIES,
    base_delay: float = SPLUNK_RETRY_BASE,
) -> list[ContextualEvent]:
    """
    Call SplunkClient.fetch_context_for_stream() with exponential back-off.

    Retries on any exception (network timeout, HTTP 500, transient Splunk error).
    Returns an empty list if all retries are exhausted.

    Back-off schedule (base_delay=2.0):
      attempt 1 → immediate
      attempt 2 → sleep 2s
      attempt 3 → sleep 4s
    """
    last_exc: Exception | None = None
    for attempt in range(1, retries + 1):
        try:
            return splunk.fetch_context_for_stream(host, source, first_error_time)
        except Exception as exc:
            last_exc = exc
            if attempt < retries:
                delay = base_delay ** (attempt - 1)
                log.warning(
                    "Splunk fetch attempt %d/%d failed for %s/%s: %s — retrying in %.1fs",
                    attempt,
                    retries,
                    host,
                    source,
                    exc,
                    delay,
                )
                time.sleep(delay)
            else:
                log.error(
                    "Splunk fetch failed after %d attempts for %s/%s: %s",
                    retries,
                    host,
                    source,
                    exc,
                )
    return []


# ── ORCHESTRATOR ──────────────────────────────────────────────────────────────


class EventDrivenLogAgent:
    """
    Full event-driven monitoring agent.

    Pipeline per incident:
      webhook trigger → IncidentBuffer (debounce) → fetch_context_for_stream
      → compress_events [1–5, 6a] → dedup → LLM RCA → email

    The LLM and email are only triggered when NEW error patterns appear
    in the incident window — same guarantee as the polling agent.
    """

    def __init__(self) -> None:
        self.splunk = SplunkClient()
        self.reporter = EmailReporter()

        indexer = CodebaseIndexer.from_env()
        if not indexer:
            log.info(
                "No GITHUB_TOKEN/GITHUB_REPO — RCA will use generic SRE context. "
                "Set both env vars for codebase-aware root cause analysis."
            )
        self.rca = RCAAnalyzer(indexer)

        # Cross-incident dedup: cluster_id → epoch time last reported.
        self._reported: dict[str, float] = {}
        self._reported_lock = threading.Lock()

        # Worker pool for concurrent incident processing
        self._executor = ThreadPoolExecutor(
            max_workers=WORKER_THREADS,
            thread_name_prefix="incident-worker",
        )
        self._shutdown = threading.Event()

        # IncidentBuffer fires _submit_window from the timer thread
        self.buffer = IncidentBuffer(
            on_window_ready=self._submit_window,
            post_window_secs=POST_WINDOW_SECS,
            max_window_secs=MAX_WINDOW_SECS,
        )

    # ── Dedup helpers ──────────────────────────────────────────────────────────

    def _prune_dedup(self) -> None:
        cutoff = time.time() - DEDUP_WINDOW_MINS * 60
        with self._reported_lock:
            self._reported = {cid: t for cid, t in self._reported.items() if t > cutoff}

    def _split_new_known(
        self, clusters: list[LogCluster]
    ) -> tuple[list[LogCluster], list[LogCluster]]:
        self._prune_dedup()
        new: list[LogCluster] = []
        known: list[LogCluster] = []
        with self._reported_lock:
            for c in clusters:
                (known if c.cluster_id in self._reported else new).append(c)
        return new, known

    # ── Window processing ──────────────────────────────────────────────────────

    def _submit_window(self, window: IncidentWindow) -> None:
        """Called by IncidentBuffer timer — submit to worker pool (non-blocking)."""
        if not self._shutdown.is_set():
            self._executor.submit(self._process_window_safe, window)

    def _process_window_safe(self, window: IncidentWindow) -> None:
        """Wrapper that logs and swallows exceptions so workers never die silently."""
        try:
            self.process_window(window)
        except Exception:
            log.exception("process_window raised for %s", window.stream_key)

    def process_window(self, window: IncidentWindow) -> bool:
        """
        Process one fired incident window end-to-end.

        Steps:
          1. Fetch context from Splunk with retry
          2. Run 6-stage compression pipeline
          3. Suppress clusters seen within the dedup window
          4. Call LLM RCA for new clusters
          5. Send email report
          6. Return True if an alert email was sent

        LLM and email are NOT invoked if:
          - Splunk returns no context lines
          - All clusters were already reported within DEDUP_WINDOW_MINS
        """
        log.info(
            "🔍  Processing window %s | %d event(s) | first_error=%s",
            window.stream_key,
            len(window.events),
            window.events[0].raw[:80] if window.events else "(none)",
        )

        # Step 1: fetch context with retry
        ctx_events = _fetch_with_retry(
            self.splunk,
            window.host,
            window.source,
            window.first_event_time,
        )
        if not ctx_events:
            log.info("No context events from Splunk for %s — skipping.", window.stream_key)
            return False

        # Step 2: compression pipeline [1]–[5] + [6a]
        log.info("⚙️  %d error lines — compressing for %s", len(ctx_events), window.stream_key)
        all_clusters, stats = compress_events(ctx_events)
        if not all_clusters:
            log.info("Zero clusters after compression for %s — skipping.", window.stream_key)
            return False

        # Top-N
        top = all_clusters[:MAX_LLM_CLUSTERS]

        # Step 3: dedup against recently reported
        new_clusters, suppressed = self._split_new_known(top)
        if suppressed:
            log.info(
                "🔕  Suppressed %d known cluster(s) for %s: %s",
                len(suppressed),
                window.stream_key,
                ", ".join(f"#{c.cluster_id}" for c in suppressed),
            )
        if not new_clusters:
            log.info("✅  All clusters are known patterns for %s — no alert.", window.stream_key)
            return False

        stats.llm_sent = len(new_clusters)
        log.info("Compression: %s", stats.summary())

        # Step 4: LLM RCA
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

        # Mark reported BEFORE send — avoids spam if the email transport crashes
        now_ts = time.time()
        with self._reported_lock:
            for c in new_clusters:
                self._reported[c.cluster_id] = now_ts

        # Step 5: email
        self.reporter.send(new_clusters, analyses, stats)
        log.info("🚨  Alert sent for %s — %d new cluster(s).", window.stream_key, len(new_clusters))
        return True

    # ── Lifecycle ──────────────────────────────────────────────────────────────

    def start(self, host: str = WEBHOOK_HOST, port: int = WEBHOOK_PORT) -> None:
        """
        Start the HTTP webhook server and block until SIGTERM / Ctrl+C.

        Shutdown sequence:
          1. Signal handler sets _shutdown event.
          2. HTTP server stops accepting new requests.
          3. IncidentBuffer timer is stopped.
          4. Worker thread pool drains in-flight incidents.
        """
        server = _WebhookServer(host, port, self.buffer, WEBHOOK_SECRET)
        server_thread = threading.Thread(
            target=server.serve_forever, name="webhook-server", daemon=True
        )
        server_thread.start()

        log.info(
            "⚡  EventDrivenLogAgent listening on %s:%d | post_window=%ds | max_window=%ds",
            host,
            port,
            POST_WINDOW_SECS,
            MAX_WINDOW_SECS,
        )

        def _handle_signal(sig: int, _frame: object) -> None:
            log.info("🛑  Shutdown signal (sig=%d) — draining in-flight incidents…", sig)
            self._shutdown.set()

        signal.signal(signal.SIGTERM, _handle_signal)
        signal.signal(signal.SIGINT, _handle_signal)

        self._shutdown.wait()

        log.info("Stopping webhook server…")
        server.shutdown()
        log.info("Stopping incident buffer…")
        self.buffer.stop(timeout=10.0)
        log.info("Waiting for worker pool to drain…")
        self._executor.shutdown(wait=True)
        log.info("👋  EventDrivenLogAgent stopped.")


# ── ENTRY POINT ───────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import sys

    missing = [
        v
        for v in ("SPLUNK_PASS", "ANTHROPIC_API_KEY", "SMTP_USER", "SMTP_PASS")
        if not os.environ.get(v)
    ]
    if missing:
        raise SystemExit(f"Missing required env vars: {', '.join(missing)}")

    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
    EventDrivenLogAgent().start()
