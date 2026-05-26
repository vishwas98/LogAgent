# LogAgent — System Architecture

## High-level overview

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                              LOGAGENT PIPELINE                                  │
│                                                                                 │
│  ┌─────────────────────┐                                                        │
│  │   Trigger source    │                                                        │
│  │                     │                                                        │
│  │  Polling:           │                                                        │
│  │   Splunk REST API   │  ──── fetch_anomalies()                               │
│  │   (two-pass fetch)  │      (two-pass SPL)                                   │
│  │                     │                                                        │
│  │  Event-driven:      │                                                        │
│  │   Splunk webhook    │  ──── _WebhookServer → IncidentBuffer                 │
│  │   POST /webhook     │      → fetch_context_for_stream()                     │
│  └─────────────────────┘                                                        │
│               │                                                                 │
│               │  list[ContextualEvent]  (error_line, context_window_lines)      │
│               ▼                                                                 │
│  ┌──────────────────────────────────────────────────────────────────────────┐   │
│  │               compress_events()   ← shared by both modes                 │   │
│  │  [1]dedup → [2]stackcomp → [3]tokenize                                   │   │
│  │  → [4]Drain → [5]merge → [6a]slot-inline                                 │   │
│  └─────────────────────────┬────────────────────────────────────────────────┘   │
│                             │  list[LogCluster]                                 │
│  ┌──────────────┐           ▼                                                   │
│  │   GitHub     │  ┌──────────────────────────────────────────────────────┐    │
│  │  REST API    │─▶│              RCA Analyzer (Claude)                    │    │
│  │  (optional)  │  │  system[persona + schema + arch_summary (cached)]    │    │
│  └──────────────┘  │  user  [template + var_slots + ctx_sample + snippet] │    │
│                    └─────────────────────┬────────────────────────────────┘    │
│                                          │  dict[cluster_id → rca]             │
│                                          ▼                                      │
│                    ┌──────────────────────────────────────────────────────┐    │
│                    │              Email Reporter                           │    │
│                    │  dark-theme HTML, one card per cluster                │    │
│                    └─────────────────────┬────────────────────────────────┘    │
│                                          │                                      │
└──────────────────────────────────────────┼──────────────────────────────────────┘
                                           ▼
                                 Dev team inbox
```

---

## Component breakdown

### 1. SplunkClient

```
SplunkClient
  ├── _auth_token            POST /services/auth/login → session key (lazy, cached)
  ├── _hdrs()                Authorization: Splunk <token>
  ├── _esc(s)                backslash-escape double-quotes for safe SPL embedding
  ├── _run_spl(spl, n)       POST /services/search/jobs  (exec_mode=blocking)
  │                          GET  /services/search/jobs/{sid}/results
  │                          returns list[dict]
  │
  ├── fetch_anomalies()      Two-pass context-aware fetch (polling mode)
  │     Pass 1 — error discovery
  │       SPL: search index="{INDEX}" earliest=-{MINS}m
  │              (ERROR OR EXCEPTION OR FAILED OR CRITICAL OR FATAL)
  │            | sort host source _time | head {MAX}
  │            | fields _time host source _raw
  │       → groups results by (host, source) stream
  │       → records first_error_time per stream
  │
  │     Pass 2 — batch context fetch (one SPL for ALL streams)
  │       Window per stream: [first_error - PRE_WINDOW_SECS, first_error + POST_WINDOW_SECS]
  │       Global batch uses extremes across all streams
  │       SPL: search … earliest={min_t} latest={max_t}
  │              (host="h1" source="s1") OR (host="h2" source="s2") …
  │            | sort host source _time | head {MAX×5}
  │       → returns list[ContextualEvent]  (error_line, context_window_lines)
  │
  └── fetch_context_for_stream(host, source, first_error_time)
        Single-stream targeted fetch (event-driven mode)
        Already knows where + when — no discovery pass needed.
        Window: [first_error - PRE_WINDOW_SECS, first_error + POST_WINDOW_SECS]
        SPL: search … earliest={t0} latest={t1}
               host="{host}" source="{source}"
             | sort _time | head {MAX} | fields _time _raw
        → returns list[ContextualEvent]  (anomaly lines only, context = all lines)
```

---

### 2. compress_events() — shared compression pipeline

```python
def compress_events(ctx_events: list[ContextualEvent]) \
        -> tuple[list[LogCluster], CompressionStats]:
```

**Shared by both `LogMonitorAgent` (polling) and `EventDrivenLogAgent` (event-driven).**  
Accepts `(error_line, context_window_lines)` pairs from any source.

```
ctx_events: list[ContextualEvent]   (error_line, context_window_lines)
     │
     │  [1] PRE-DEDUP
     │      dict[error_line → first_ctx_window]
     │      Effect: 5,000 events → ~300 unique  (typical 10–50x reduction)
     │
     │  [2] STACK TRACE COMPRESSOR
     │      Detect Java (\tat ) / Python (File "...") frames
     │      Keep: exception header + first 2 frames + "...[N omitted]" + cause chain
     │      Cross-line dedup: if compress(A) == compress(B), weight += 1 (same skeleton)
     │      Effect: 200-line traces → ~5 tokens; repeated variants counted, not re-stored
     │
     │  [3] EXTENDED TOKENIZER  (_VAR_SUBS patterns applied in order)
     │      <IP>    \d{1,3}(\.\d{1,3}){3}(:\d+)?
     │      <UUID>  8-4-4-4-12 hex
     │      <HEX>   16+ hex chars
     │      <TS>    ISO-8601 timestamps
     │      <EPOCH> 10-13 digit numbers
     │      <PATH>  /word/word/...
     │      <EMAIL> addr@domain
     │      <KV>    key=value pairs          ← extended
     │      <STR>   "quoted strings"         ← extended
     │      <TID>   thread-/conn-/session-ID ← extended
     │      <NUM>   remaining bare integers
     │
     │  [4] DRAIN CLUSTERING
     │      Tree: { token_length → { prefix_key → [LogCluster] } }
     │      prefix_key = first DRAIN_DEPTH (4) tokens, typed placeholders → <*>
     │      ┌─ bucket lookup    O(1)
     │      ├─ similarity scan  O(k)  where k = clusters in bucket (typically <10)
     │      ├─ sim(a,b)         matched_tokens / len  (0.0 if lengths differ)
     │      ├─ merge template   token_a if token_a==token_b else "<*>"
     │      └─ var slot track   position → [distinct values seen]  (max 5)
     │         weight = pre-dedup count; count += weight on match
     │         raw_samples: stores formatted 5-min context windows (not bare error lines)
     │
     │  [5] CLUSTER MERGER  (second pass)
     │      Group by template length
     │      For each pair: if sim ≥ MERGE_SIM(0.8) → absorb smaller into larger
     │      Merge var slots from both clusters
     │      Effect: catches near-identical templates split by prefix-key differences
     │
     │  [6a] SINGLE-VALUE SLOT INLINING  (always applied before dedup checks)
     │       Slots with 1 literal value → inlined into template (drops slot row)
     │       "ERROR connecting to <*> port <*>" + slots[2]='db-primary',[4]='5432'
     │         → "ERROR connecting to db-primary port 5432"   (slot table empty)
     │       Typed placeholders (<IP>, <NUM>) NOT inlined — kept abstract.
     │       Affects cluster_id; runs BEFORE cross-cycle dedup lookup.
     │
     ▼
list[LogCluster]  sorted by count DESC
  .template_str   "ERROR connecting to <IP> port <NUM> after <NUM>ms"
  .count          4,231
  .severity       "ERROR"
  .var_slots      {3: ['10.0.0.1','192.168.1.5'], 5: ['5432','3306']}
  .raw_samples    [≤3 formatted context windows, each ≤300 chars]
  .cluster_id     md5(template_str)[:8]
```

**Prompt-level optimizations applied at LLM call time (lossless):**

```
[6b] Context window adjacent-line dedup  (_format_context_window)
     Tokenize each context line; collapse consecutive equivalents into
     "first original + (×N)" notation. Error line is a hard boundary
     (never absorbed into a run). Typical 60–80% char savings on noisy logs:
       50 lines of "INFO Heartbeat tick" → 1 display line "(×50)"
     raw_samples already stores the pre-formatted window (dedup applied once,
     at cluster-add time — not repeated per LLM call).

[6c] Output schema in cached system block
     JSON schema description moved from per-cluster user prompt to a
     cached system block. ~400 chars × N clusters saved per run.
     Schema costs effectively zero tokens after first cluster (cache hit).
```

---

### 3. Event-Driven Mode (event_driven_agent.py)

```
IncidentEvent
  .host, .source, .raw, .timestamp, .severity
  .stream_key   →   "{host}||{source}"

IncidentWindow
  .stream_key, .host, .source
  .first_event_time     unix epoch of first event in the burst
  .last_event_time      updated on every add_event()
  .events               list[IncidentEvent]
  .status               "open" | "firing" | "processed"

  is_ready(now, post_window_secs, max_window_secs) → bool
    True when:
      (a) now - last_event_time >= post_window_secs   [silence-based, normal]
      (b) now - first_event_time >= max_window_secs   [hard cap for noisy streams]

IncidentBuffer
  Thread-safe per-stream window manager.
  ┌─ Webhook threads    add_event(event)      → creates/updates IncidentWindow
  └─ Timer thread       _check_windows() every check_interval (1s)
       → for each window: if is_ready() → fire it
       → _fire_window() marks status="firing", removes from _windows
       → calls on_window_ready(window)  OUTSIDE lock (may be slow)

  Concurrency:
    _windows dict protected by threading.Lock
    on_window_ready called without lock → no deadlock risk

_WebhookServer  (socketserver.ThreadingMixIn + http.server.HTTPServer on WEBHOOK_HOST:WEBHOOK_PORT)
  Each incoming POST is handled in its own thread (daemon_threads=True) so
  concurrent Splunk saved-search alerts never queue behind each other.
  POST /webhook
    1. Validate Authorization header (WEBHOOK_SECRET, hmac.compare_digest)
    2. Parse JSON body → _parse_webhook_payload()
    3. If not anomaly → 422
    4. buffer.add_event(incident_event) → 200

_parse_webhook_payload(payload)
  Expects Splunk alert webhook JSON: {"result": {"_raw": …, "host": …, "source": …, "_time": …}}
  Returns IncidentEvent or None if required fields are missing / no anomaly match.

EventDrivenLogAgent
  ┌── splunk: SplunkClient
  ├── rca: RCAAnalyzer
  ├── reporter: EmailReporter
  ├── buffer: IncidentBuffer  (on_window_ready = _submit_window)
  ├── _executor: ThreadPoolExecutor (WORKER_THREADS=3)
  └── _reported: dict[cluster_id → epoch]   (cross-incident dedup, lock-protected)

  _submit_window(window)          → executor.submit(_process_window_safe)
  _process_window_safe(window)    → wraps process_window(), logs + swallows exceptions
  process_window(window) → bool
    1. _fetch_with_retry()         Splunk context fetch with exponential back-off
    2. compress_events()           shared 6-stage pipeline
    3. _split_new_known(clusters)  prune expired dedup, partition new vs known
    4. if no new clusters → return False
    5. for each new cluster: rca.analyze(cluster)
    6. mark _reported BEFORE send() → crash-safe (no double-alert on retry)
    7. reporter.send(new_clusters, analyses, stats)
    8. return True

_fetch_with_retry(splunk, host, source, first_error_time)
  Retries SPLUNK_FETCH_RETRIES times with delay = SPLUNK_RETRY_BASE^(attempt-1)
  Returns [] after all retries exhausted (processing continues gracefully).
```

---

### 4. CodebaseIndexer (codebase_context.py)

```
GitHub REST API  (one session, all responses in-memory cached)
     │
     │  get_head_sha()       GET /repos/{owner}/{repo}/branches/{branch}
     │                       returns commit SHA (1 lightweight call, NOT cached)
     │                       Used by refresh_if_stale() every poll cycle.
     │
     │  refresh_if_stale()   called at the TOP of every agent cycle
     │     ├── get_head_sha() → compare with self._indexed_sha
     │     ├── [same SHA]   → return False  (no-op — index still valid)
     │     └── [new SHA]    → clear _tree cache + clear _files cache
     │                         update _indexed_sha → return True
     │
     │  _get_tree()          GET /repos/{owner}/{repo}/git/trees/{branch}?recursive=1
     │                       returns list[{path, type, sha, size}]  (1 API call, cached)
     │
     │  _read(path)          GET /repos/{owner}/{repo}/contents/{path}?ref={branch}
     │                       base64-decode → str  (per-file, cached)
     │
     ├── build_arch_summary()       called at startup AND after each deploy detection
     │     ├── snapshot HEAD SHA    establishes _indexed_sha baseline
     │     ├── language distribution             ext_counts from tree
     │     ├── top-level module list             unique dir[0] segments
     │     ├── priority files       README, configs, build files (≤2500 chars each)
     │     └── error handler sources             *exception*/*handler*/*middleware* (≤1500 chars each)
     │     → str (capped at MAX_ARCH_CHARS=6000)  includes commit SHA in header
     │     → stored as ephemeral-cached LLM system block
     │
     └── find_snippets(keywords)                 called PER CLUSTER
           ├── extract_keywords(template, slots)
           │     ├── CamelCase exception/class names
           │     ├── Java FQN last segments
           │     ├── static meaningful tokens (≥4 chars)
           │     └── identifier-shaped slot values
           ├── score source files by path-keyword overlap
           ├── read top-10 scored files
           ├── grep each file → first keyword-hit line → ±20 line window
           └── return ≤5 snippets  (capped at MAX_SNIPPET_CHARS=2000)
```

**Daily refresh flow (time-gated, once per day at 7 AM ET):**
```
run_once() / process_window() called each cycle
  │
  └─ rca.refresh_codebase()
       │
       ├─ no indexer?                          →  return False
       ├─ now_et.hour < CODEBASE_REFRESH_HOUR? →  return False  (no GitHub calls at all)
       ├─ _last_refresh_date == today_et?       →  return False  (already done today)
       │
       └─ [first cycle at or after 7 AM ET]
            ⏰  Daily refresh triggered
            indexer.force_reindex()
              _tree = None          (tree re-fetched on next _get_tree())
              _files.clear()        (all content re-fetched on next _read())
              _indexed_sha = None   (re-captured in next build_arch_summary())
            indexer.build_arch_summary()  →  fresh arch block
              empty result → self._arch_block = None  (generic RCA context used)
            _last_refresh_date = today_et
            return True
```

GitHub API calls per day:
  - 23 hours of quiet cycles: **0 GitHub calls**
  - 1 daily refresh window:   **~5–15 calls** (tree + priority files)
  Total: ~15 calls/day regardless of how frequently Splunk is polled.

---

### 5. RCAAnalyzer

```
Per-run init:
  build_arch_summary() → self._arch_block  (sent in system once, TTL=5min cache)

Per-cluster call:
  ┌─ System blocks (all ephemeral-cached) ─────────────────────────────────────┐
  │  [0] SRE persona  ("You are a senior SRE…")                                │
  │  [1] Output schema (JSON field definitions)  ← moved from user prompt [6c] │
  │  [2] Arch summary ("# owner/repo @ main\n…")  ← only present when indexer  │
  └────────────────────────────────────────────────────────────────────────────┘
  ┌─ User message (per cluster) ────────────────────────────────────────────────┐
  │  Template : ERROR connecting to <IP> port <NUM> after <NUM>ms              │
  │  Frequency: 4,231 occurrences                                              │
  │  Variable slots:                                                           │
  │    [3] <IP>:  '10.0.0.1', '192.168.1.5'                                   │
  │    [5] <NUM>: '5432', '3306'                                               │
  │                                                                            │
  │  Incident context window (sample 1/3):                                     │
  │  ── 5 min window · 42 lines · 3 anomalies ────────────────────────────    │
  │    10:00:01 INFO  heartbeat                                                │
  │  → ERROR connecting to 10.0.0.1 port 5432 after 30000ms                   │
  │    10:00:02 WARN  retry attempt 1                                          │
  │                                                                            │
  │  Relevant source code:                                                     │
  │  # src/db/ConnectionPool.java  (line 87)                                  │
  │    public Connection acquire(String host, int port, int timeoutMs) { …    │
  └────────────────────────────────────────────────────────────────────────────┘
  → JSON: summary / technical_context / root_cause (file:line) / action_items

  Prompt truncation: if len(prompt) > LLM_BUDGET_CHARS → trim + "…[truncated]"
  Parse failure fallback: {"summary": "RCA parse failed.", "root_cause": "Unknown", …}
```

**Token cost per run** (with caching + prompt-level optimizations):

| Block | Tokens | Cached? |
|---|---|---|
| Persona (system) | ~40 | ✅ after first cluster |
| Schema (system) | ~120 | ✅ after first cluster  ← moved from user prompt [6c] |
| Arch summary (system) | ~1,500 | ✅ after first cluster |
| User prompt per cluster | ~200–400 | ❌ unique per cluster |
| Max output per cluster | ~200 | — |
| **20 clusters total** | **~1,660 cached + 20×300 unique** | ~7.6k input tokens/run |

Pre-optimization (no [6a]/[6b]/[6c]): ~1,540 cached + 20×700 unique = ~15.5k input tokens/run.
After [6a]/[6b]/[6c]: roughly **2× cheaper** with zero RCA-accuracy compromise.

---

### 6. EmailReporter

```
HTML structure:
  <html>
    <head> dark-theme CSS (Catppuccin palette) </head>
    <body>
      <h1> 🔴 Splunk Anomaly Report </h1>
      <div class="meta">  timestamp · index · window · clusters · events · compression ratio  </div>
      <div class="comp">  📉 raw=5000 → dedup=312 → drain=18 → merged=14 [357x compression]  </div>

      for each cluster (sorted by count desc):
        <div class="card" style="border-left: 4px solid {severity_color}">
          [{SEVERITY}] #{cluster_id}  ×{count} occurrences
          Template: ...
          📋 Error Summary      | {rca.summary}
          ⚙️ Technical Context  | {rca.technical_context}
          🔍 Root Cause         | {rca.root_cause}  ← cites file:line when code matched
          🛠 Action Items        | 1. … 2. … 3. …
        </div>
    </body>
  </html>

Transport: SMTP STARTTLS  (Gmail App Password / any SMTP relay)
HTML body: base64-encoded Content-Transfer-Encoding (standard MIME multipart/alternative)
Missing RCA (cluster not in analyses dict): all four fields shown as "N/A"
```

---

### 7. Polling Daemon (LogMonitorAgent)

```
LogMonitorAgent.run_once() → bool
  │
  ├─ rca.refresh_codebase()          daily GitHub re-index (no-op most cycles)
  ├─ splunk.fetch_anomalies()        two-pass context-aware SPL
  ├─ compress_events(ctx_events)     shared 6-stage pipeline
  ├─ _split_new_known(clusters)      prune expired dedup, partition new vs known
  ├─ if no new clusters → return False
  ├─ for each new cluster: rca.analyze(cluster)
  ├─ mark _reported BEFORE reporter.send()  ← crash-safe, prevents double-alert
  ├─ reporter.send(new_clusters, analyses, stats)
  └─ return True

LogMonitorAgent.start()
  │  Register SIGTERM / SIGINT → threading.Event (_shutdown)
  │
  └─ while not _shutdown.is_set():
       │
       ├─ run_once()
       │    ├─ [no errors]          → log "All quiet", return False
       │    ├─ [all clusters known] → log "No new patterns", return False
       │    └─ [new clusters]       → LLM RCA → email → mark reported, return True
       │
       ├─ sleep = max(0, POLL_INTERVAL_SECS - cycle_elapsed)
       └─ _shutdown.wait(timeout=sleep)  ← wakes immediately on Ctrl+C / SIGTERM

  Dedup state: dict[cluster_id → epoch_reported] in memory, across cycles.
  Clusters age out after DEDUP_WINDOW_MINS (default 120 min).
  Zero LLM API calls on quiet cycles.
```

---

### 8. logagent CLI

```
logagent init
  │  Wizard sections (in order, each tested live before proceeding):
  ├── Splunk     → POST /services/auth/login
  │    also prompts: POLL_INTERVAL_SECS, DEDUP_WINDOW_MINS
  ├── Anthropic  → messages.create (claude-haiku-4-5, 5 tokens)
  ├── SMTP       → STARTTLS login
  └── GitHub     → GET /repos/{owner}/{repo}
  Saves: ~/.logagent/config.env  (chmod 600)

logagent run          → LogMonitorAgent().start()   (continuous daemon, blocks)
logagent run --once   → LogMonitorAgent().run_once() (single cycle, for cron)
  Both write: ~/.logagent/last_run.json  {status, timestamp, elapsed_s}

logagent test   →  re-runs all 4 connection checks
logagent status →  reads last_run.json (status: running | alerted | quiet | stopped | failed)
logagent config →  prints config.env (secrets masked to ****last4)
```

---

## Data flow diagram

```
  ┌─────────────────────────────────────────────────────────────────────────────┐
  │  TRIGGER                                                                    │
  │                                                                             │
  │  Polling:  Splunk REST ──────────────────────────────┐                     │
  │  (hourly)  fetch_anomalies()                         │                     │
  │            two-pass SPL                              │                     │
  │                                                      │                     │
  │  Event:    Splunk webhook ─▶ _WebhookServer          │ list[ContextualEvent]│
  │  (< 2min)  POST /webhook      ─▶ IncidentBuffer      │                     │
  │                                  ─▶ worker thread    │                     │
  │                                  fetch_context_for_  │                     │
  │                                  stream()            │                     │
  └──────────────────────────────────────────────────────┘                     │
                                                          │                     │
                                                          ▼                     │
          ┌──────────────────────────────────────────────────────────────────┐  │
          │  compress_events()   ← shared by both modes                      │  │
          │  [1] Counter dedup        5,000 → 312 unique (+weights)          │  │
          │  [2] Stack compressor     312   → 198 compressed                 │  │
          │  [3] Tokenize             <IP> <UUID> <KV> <STR> <TID> <NUM>…    │  │
          │  [4] Drain cluster        198   → 24 LogClusters                 │  │
          │  [5] Cluster merge        24    → 17 LogClusters                 │  │
          │  [6a] Slot inlining       single-literal slots → inlined         │  │
          └────┬─────────────────────────────────────────────────────────────┘  │
               │  17 clusters  (357x compression of original 5,000 lines)       │
               │                                                                 │
          ┌────▼──────────────┐     ┌────────────────────┐                      │
          │  GitHub Indexer   │     │   Claude Opus 4.7  │                      │
          │  (once per run)   │────▶│                    │                      │
          │  arch_summary     │     │  system (cached):  │                      │
          │  find_snippets()  │     │    persona         │                      │
          │  per cluster      │     │    schema          │                      │
          └───────────────────┘     │    arch_summary    │                      │
                                    │                    │                      │
                                    │  user (per cluster)│                      │
                                    │    template        │                      │
                                    │    var_slots       │                      │
                                    │    ctx_window      │                      │
                                    │    code_snippet    │                      │
                                    └────────┬───────────┘                      │
                                             │  JSON RCA × 17                   │
                                        ┌────▼────────────┐                     │
                                        │  EmailReporter  │                     │
                                        │  HTML dark card │                     │
                                        └────────┬────────┘                     │
                                                 │                              │
                                        Dev team inbox 📧                       │
```

---

## File structure

```
LogAgent/
├── splunk_rca_agent.py     Core pipeline
│                           compress_events()    ← shared standalone function
│                           SplunkClient         (fetch_anomalies + fetch_context_for_stream)
│                           DrainClusterer, merge_clusters, inline_single_slots
│                           RCAAnalyzer, EmailReporter
│                           LogMonitorAgent      (polling daemon)
│                           CompressionStats, LogCluster
│
├── event_driven_agent.py   Event-driven agent
│                           IncidentEvent, IncidentWindow, IncidentBuffer
│                           _parse_webhook_payload, _validate_secret
│                           _WebhookServer, _WebhookHandler
│                           _fetch_with_retry
│                           EventDrivenLogAgent
│
├── codebase_context.py     GitHub indexer (CodebaseIndexer, standalone CLI)
├── logagent_cli.py         CLI entry point (init wizard, run, test, status, config)
├── pyproject.toml          PyPI packaging + ruff config
├── Dockerfile              One-shot container entrypoint
├── requirements.txt        requests, anthropic, urllib3
├── requirements-dev.txt    pytest, pytest-cov
├── pytest.ini              testpaths = tests, addopts = -v --tb=short
├── .env.example            All env vars documented with defaults
│
├── tests/
│   ├── conftest.py         Shared fixtures (mock_anthropic, mock_smtp,
│   │                       mock_splunk_session, java_stacktrace, …)
│   ├── test_pipeline.py    compress_stacktrace, _tokenize, DrainClusterer,
│   │                       merge_clusters, inline_single_slots,
│   │                       _format_context_window, compress_events
│   ├── test_agent_classes.py  RCAAnalyzer, EmailReporter, LogMonitorAgent,
│   │                          SplunkClient._esc  (all external I/O mocked)
│   ├── test_event_driven.py   IncidentEvent, IncidentWindow, IncidentBuffer,
│   │                          _WebhookServer (real HTTP), _fetch_with_retry,
│   │                          EventDrivenLogAgent.process_window, integration
│   └── test_codebase_context.py  CodebaseIndexer (GitHub API mocked)
│
├── ARCHITECTURE.md         This file
└── README.md               User-facing docs + install guide

Test suite: 199 tests, 85% coverage (splunk_rca_agent 84%, event_driven_agent 89%,
                                      codebase_context 84%)
```
