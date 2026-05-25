# LogAgent — System Architecture

## High-level overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              LOGAGENT PIPELINE                              │
│                                                                             │
│  ┌──────────────┐     ┌──────────────────────────────────────────────────┐  │
│  │   Splunk     │     │               Compression Engine                 │  │
│  │  REST API    │────▶│  [1]dedup → [2]stackcomp → [3]tokenize          │  │
│  │  port 8089   │     │  → [4]Drain → [5]merge → [6]budget              │  │
│  └──────────────┘     └─────────────────────┬────────────────────────────┘  │
│                                             │  list[LogCluster]             │
│  ┌──────────────┐                           ▼                               │
│  │   GitHub     │     ┌──────────────────────────────────────────────────┐  │
│  │  REST API    │────▶│              RCA Analyzer (Claude)               │  │
│  │  (optional)  │     │  system[persona + arch_summary (cached)]         │  │
│  └──────────────┘     │  user  [template + var_slots + code_snippets]    │  │
│                        └─────────────────────┬────────────────────────────┘  │
│                                             │  dict[cluster_id → rca]       │
│                                             ▼                               │
│                        ┌──────────────────────────────────────────────────┐  │
│                        │              Email Reporter                      │  │
│                        │  dark-theme HTML, one card per cluster           │  │
│                        └─────────────────────┬────────────────────────────┘  │
│                                             │                               │
└─────────────────────────────────────────────┼───────────────────────────────┘
                                              ▼
                                    Dev team inbox
```

---

## Component breakdown

### 1. SplunkClient

```
SplunkClient
  ├── _auth_token        POST /services/auth/login → session key (lazy, cached)
  ├── _hdrs()            Authorization: Splunk <token>
  └── fetch_anomalies()  POST /services/search/jobs  (exec_mode=blocking)
                         GET  /services/search/jobs/{sid}/results
                         returns list[str]  (_raw log lines)

SPL query:
  search index="{INDEX}" earliest=-{MINS}m
  (ERROR OR EXCEPTION OR FAILED OR CRITICAL OR FATAL)
  | head {MAX} | fields _raw
```

---

### 2. Compression Engine (6 stages)

```
raw_lines: list[str]  (up to 5,000 from Splunk)
     │
     │  [1] PRE-DEDUP
     │      Counter(lines) → dict[unique_line, weight]
     │      Effect: 5,000 lines → ~300 unique  (typical 10–50x reduction)
     │
     │  [2] STACK TRACE COMPRESSOR
     │      Detect Java (\tat ) / Python (File "...") frames
     │      Keep: exception header + first 2 frames + "...[N omitted]" + cause chain
     │      Effect: 200-line traces → ~5 tokens
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
     │      ┌─ bucket lookup    O(1)
     │      ├─ similarity scan  O(k)  where k = clusters in bucket (typically <10)
     │      ├─ sim(a,b)         matched_tokens / len  (0 if lengths differ)
     │      ├─ merge template   token_a if token_a==token_b else "<*>"
     │      └─ var slot track   position → [distinct values seen]  (max 5)
     │         weight = pre-dedup count; count += weight on match
     │
     │  [5] CLUSTER MERGER  (second pass)
     │      Group by template length
     │      For each pair: if sim ≥ MERGE_SIM(0.8) → absorb smaller into larger
     │      Merge var slots from both clusters
     │      Effect: catches near-identical templates split by prefix-key differences
     │
     │  [6] TOKEN BUDGET
     │      Select top-N clusters by count  (MAX_LLM_CLUSTERS=20)
     │      LLM user prompt capped at LLM_BUDGET_CHARS=3500 chars
     │
     ▼
clusters: list[LogCluster]
  .template_str   "ERROR connecting to <IP> port <NUM> after <NUM>ms"
  .count          4,231
  .severity       "ERROR"
  .var_slots      {3: ['10.0.0.1','192.168.1.5'], 5: ['5432','3306']}
  .raw_samples    [first 3 raw lines, ≤300 chars each]
  .cluster_id     md5(template_str)[:8]
```

---

### 3. CodebaseIndexer (codebase_context.py)

```
GitHub REST API  (one session, all responses in-memory cached)
     │
     │  get_head_sha()       GET /repos/{owner}/{repo}/branches/{branch}
     │                       returns commit SHA (1 lightweight call, NOT cached)
     │                       Used by refresh_if_stale() every poll cycle to detect deploys.
     │
     │  refresh_if_stale()   called at the TOP of every daemon poll cycle
     │     ├── get_head_sha() → compare with self._indexed_sha
     │     ├── [same SHA]   → return False  (no-op — index still valid)
     │     └── [new SHA]    → clear _tree cache + clear _files cache
     │                         update _indexed_sha → return True
     │                         (caller rebuilds arch summary with fresh data)
     │
     │  _get_tree()          GET /repos/{owner}/{repo}/git/trees/{branch}?recursive=1
     │                       returns list[{path, type, sha, size}]  (1 API call, cached)
     │                       cache cleared automatically on deploy detection
     │
     │  _read(path)          GET /repos/{owner}/{repo}/contents/{path}?ref={branch}
     │                       base64-decode → str  (per-file, cached)
     │                       cache cleared automatically on deploy detection
     │
     ├── build_arch_summary()       called at startup AND after each deploy detection
     │     ├── snapshot HEAD SHA    establishes _indexed_sha baseline for refresh checks
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
           ├── read top-10 scored files (from refreshed cache after deploy)
           ├── grep each file → first keyword-hit line → ±20 line window
           └── return ≤5 snippets  (capped at MAX_SNIPPET_CHARS=2000)
```

**Daily refresh flow (time-gated, once per day at 7 AM ET):**
```
run_once() called (every poll cycle)
  │
  └─ rca.refresh_codebase()
       │
       ├─ now_et.hour < CODEBASE_REFRESH_HOUR?  →  return False  (no GitHub calls at all)
       ├─ _last_refresh_date == today_et?        →  return False  (already done today)
       │
       └─ [first cycle at or after 7 AM ET]
            ⏰  Daily refresh triggered
            indexer.force_reindex()
              _tree = None          (tree re-fetched on next _get_tree())
              _files.clear()        (all content re-fetched on next _read())
              _indexed_sha = None   (re-captured in next build_arch_summary())
            indexer.build_arch_summary()  →  fresh tree + fresh files
            _last_refresh_date = today_et
            self._arch_block = new LLM system block
            return True

Startup behaviour:
  Hour >= 7 AM ET  → mark _last_refresh_date = today (startup IS the refresh)
                     next refresh: 7 AM tomorrow
  Hour <  7 AM ET  → _last_refresh_date = None
                     daily refresh fires naturally when clock crosses 7 AM
```

GitHub API calls per day:
  - 23 hours of quiet cycles: **0 GitHub calls**
  - 1 daily refresh window:   **~5–15 calls** (tree + priority files)
  Total: ~15 calls/day regardless of how frequently Splunk is polled.

---

### 4. RCAAnalyzer

```
Per-run init:
  build_arch_summary() → self._arch_block  (sent in system once, TTL=5min cache)

Per-cluster call:
  ┌─ System blocks (both ephemeral-cached) ────────────────────────────────────┐
  │  [0] SRE persona  ("You are a senior SRE…")                               │
  │  [1] Arch summary ("# owner/repo @ main\nLanguages…README…error_handler") │
  └────────────────────────────────────────────────────────────────────────────┘
  ┌─ User message (per cluster) ────────────────────────────────────────────────┐
  │  Template : ERROR connecting to <IP> port <NUM> after <NUM>ms              │
  │  Frequency: 4,231 occurrences                                              │
  │  Variable slots:                                                           │
  │    [3] <IP>:  '10.0.0.1', '192.168.1.5'                                   │
  │    [5] <NUM>: '5432', '3306'                                               │
  │                                                                            │
  │  Relevant source code:                                                     │
  │  # src/db/ConnectionPool.java  (line 87)                                  │
  │    public Connection acquire(String host, int port, int timeoutMs) {      │
  │      if (pool.isEmpty()) {                                                 │
  │        log.error("ERROR connecting to {} port {}…", host, port, ms);      │
  │        throw new PoolExhaustedException(…);                               │
  └────────────────────────────────────────────────────────────────────────────┘
  → JSON: summary / technical_context / root_cause (file:line) / action_items
```

**Token cost per run** (with caching):

| Block | Tokens | Cached? |
|---|---|---|
| Persona (system) | ~40 | ✅ after first cluster |
| Arch summary (system) | ~1,500 | ✅ after first cluster |
| User prompt per cluster | ~400–800 | ❌ unique per cluster |
| Max output per cluster | ~200 | — |
| **20 clusters total** | **~1,580 cached + 20×700 unique** | |

---

### 5. EmailReporter

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
```

---

### 6. 24/7 Daemon Loop (LogMonitorAgent.start)

```
LogMonitorAgent.start()
  │
  │  Register SIGTERM / SIGINT → threading.Event (_shutdown)
  │
  └─ while not _shutdown.is_set():
       │
       ├─ run_once()
       │    ├─ [no errors]         → log "All quiet", return False
       │    ├─ [all clusters known] → log "No new patterns", return False
       │    └─ [new clusters]      → LLM RCA → email → mark reported, return True
       │
       ├─ sleep = max(0, POLL_INTERVAL_SECS - cycle_elapsed)
       └─ _shutdown.wait(timeout=sleep)  ← wakes immediately on Ctrl+C / SIGTERM

  Dedup state: dict[cluster_id → epoch_reported] persists across cycles in memory.
  Clusters age out after DEDUP_WINDOW_MINS (default 120 min).
  Zero LLM API calls on quiet cycles.
```

### 7. logagent CLI

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
          ┌──────────┐
          │  Splunk  │  5,000 raw log lines
          └────┬─────┘
               │
          ┌────▼─────────────────────────────────────────────────────────────┐
          │  [1] Counter dedup        5,000 → 312 unique (+weights)          │
          │  [2] Stack compressor     312   → 198 compressed                 │
          │  [3] Tokenize             <IP> <UUID> <KV> <STR> <TID> <NUM>…    │
          │  [4] Drain cluster        198   → 24 LogClusters                 │
          │  [5] Cluster merge        24    → 17 LogClusters                 │
          │  [6] Top-N select         17    → 17 (≤20 cap)                   │
          └────┬─────────────────────────────────────────────────────────────┘
               │  17 clusters  (357x compression of original 5,000 lines)
               │
          ┌────▼──────────────┐     ┌────────────────────┐
          │  GitHub Indexer   │     │   Claude Opus 4.7  │
          │  (once per run)   │────▶│                    │
          │  arch_summary     │     │  system (cached):  │
          │  find_snippets()  │     │    persona         │
          │  per cluster      │     │    arch_summary    │
          └───────────────────┘     │                    │
                                    │  user (per cluster)│
                                    │    template        │
                                    │    var_slots       │
                                    │    code_snippet    │
                                    └────────┬───────────┘
                                             │  JSON RCA × 17
                                        ┌────▼────────────┐
                                        │  EmailReporter  │
                                        │  HTML dark card │
                                        └────────┬────────┘
                                                 │
                                        Dev team inbox 📧
```

---

## File structure

```
LogAgent/
├── splunk_rca_agent.py     Core pipeline  (SplunkClient, DrainClusterer,
│                           merge_clusters, RCAAnalyzer, EmailReporter,
│                           LogMonitorAgent, CompressionStats)
├── codebase_context.py     GitHub indexer (CodebaseIndexer, standalone CLI)
├── logagent_cli.py         CLI entry point (init wizard, run, test, status, config)
├── pyproject.toml          PyPI packaging + ruff config
├── Dockerfile              One-shot container entrypoint
├── requirements.txt        requests, anthropic, urllib3
├── .env.example            All env vars documented with defaults
├── ARCHITECTURE.md         This file
└── README.md               User-facing docs + install guide
```
