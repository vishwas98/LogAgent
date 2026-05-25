# LogAgent

Splunk anomaly monitor with **codebase-aware LLM root cause analysis**.

Fetches error logs → compresses with 6-stage Drain pipeline → reads your GitHub repo → generates code-specific RCA with Claude → emails a structured HTML report.

---

## Why LogAgent?

### The problem it solves

Production systems generate thousands of log lines per hour. When something breaks at 2 AM:

- A Splunk alert fires with **5,000 raw log lines** — too much to read
- On-call engineers spend **30–60 minutes** manually triaging before they even know what broke
- Generic monitoring tools say "there are errors" but not **why**, **where in the code**, or **what to do**

### Benefits

| | Without LogAgent | With LogAgent |
|---|---|---|
| **Triage time** | 30–60 min manual log reading | < 2 min — report in inbox |
| **Signal quality** | Raw noisy log dump | Clustered, deduplicated, ranked by frequency |
| **Root cause** | Engineer must trace through code | LLM cites exact `file:line` from your repo |
| **Action clarity** | "something is wrong with the DB" | Step-by-step fix instructions per error cluster |
| **Token cost** | N/A | Up to 357× compressed before LLM sees any data |
| **Setup** | Custom scripts per team | `pip install` + 2-minute wizard |

### Key advantages over raw Splunk alerting

**1. Codebase-aware RCA** — not generic advice  
The agent reads your actual GitHub repo before analyzing logs. Instead of "check your database connection pool", it says:  
> Root cause: `src/db/ConnectionPool.java:87` — `pool.isEmpty()` throws `PoolExhaustedException` when all 20 connections are in use. The pool size is hardcoded in `application.yml: db.pool.max=20`.

**2. Extreme compression before the LLM sees anything**  
Six-stage pipeline reduces 5,000 raw log lines to ~17 representative cluster templates before a single token reaches Claude. This makes analysis fast and cheap.

```
5,000 raw lines
  → 312 unique (dedup)
  → 198 compressed (stack traces collapsed)
  → 17 clusters (Drain + merge)
  → ~17 × 700 tokens sent to LLM   vs   5,000 × 30 tokens without compression
  = 357× cheaper
```

**3. Zero noise — only unique error patterns reach the LLM**  
If `ERROR: connection refused` fires 4,000 times, the LLM sees it exactly once with `×4000` context. No duplicate analysis, no wasted tokens.

**4. Variable slot differential encoding**  
Instead of sending raw log lines, the agent sends a structured diff of what changed:
```
Template : ERROR connecting to <IP> port <NUM> after <NUM>ms
Variable slots:
  [2] <IP>:  '10.0.0.1', '192.168.1.5', 'db-replica-3'
  [4] <NUM>: '5432', '3306'
  [6] <NUM>: '30000', '45000', '60000'
```
The LLM gets maximum diagnostic information in minimum tokens.

**5. One command install — works for any team**  
```bash
pip install splunk-logagent && logagent init
```
No YAML to hand-edit. The wizard tests every connection live and saves credentials securely (`~/.logagent/config.env`, chmod 600).

**6. Prompt caching across all cluster calls**  
The architecture summary (your repo's README, configs, error handlers — ~6,000 chars) is sent as a cached LLM system block. It's uploaded once and reused across all 20 cluster analyses, keeping costs low even on large repos.

---

## Install & run  (2 minutes)

```bash
pip install splunk-logagent

logagent init   # interactive wizard — tests every connection live
logagent run    # start the 24/7 continuous daemon (Ctrl+C to stop)
```

That's it. No config files to hand-edit.

LogAgent runs **continuously** — it polls Splunk every hour, only calls the LLM and sends email when **new** error patterns appear. Quiet periods generate zero API calls and zero emails.

---

## What `logagent init` asks for

```
── Splunk ────────────────────────────────────────────
  REST URL      [https://localhost:8089]:
  Username      [admin]:
  Password:
  Index         [main]:
  Lookback (min)[60]:
  ✅  authenticated

── Anthropic API ─────────────────────────────────────
  API key (sk-ant-...):
  ✅  reachable

── Email (SMTP) ──────────────────────────────────────
  SMTP host     [smtp.gmail.com]:
  Sender email:
  App password:
  Recipients (comma-separated):
  ✅  login OK

── GitHub (optional — enables code-aware RCA) ─────────
  GitHub PAT (leave blank to skip):
  App repo (owner/repo):
  Branch        [main]:
  ✅  repo accessible

✅  Config saved → /home/you/.logagent/config.env
```

Credentials are stored at `~/.logagent/config.env` (chmod 600 — owner-readable only).

---

## How the continuous daemon works

```
logagent run
     │
     └─ every POLL_INTERVAL_SECS (default: 1 hour)
          │
          ├─ fetch Splunk — any ERROR/EXCEPTION/FAILED/CRITICAL/FATAL?
          │
          ├─ [NO]  → "All quiet" log line. Zero API calls. Waits for next cycle.
          │
          └─ [YES] → 6-stage compression pipeline
                      → cluster deduplication (already reported within DEDUP_WINDOW_MINS?)
                           │
                           ├─ [all known] → "No new patterns" log. Zero API calls.
                           │
                           └─ [new patterns] → LLM RCA → email alert → back to sleep
```

Key behaviour:
- **Zero cost when healthy** — LLM is never called if there are no errors.
- **No alert storms** — same error pattern reported at most once per `DEDUP_WINDOW_MINS` (default: 2 h). You won't get 24 emails about the same DB timeout.
- **Resilient** — if Splunk is unreachable, the cycle logs the error and retries next interval. The daemon never crashes.
- **Graceful shutdown** — `Ctrl+C` or `SIGTERM` completes the current cycle, then exits cleanly.

---

## Other commands

```bash
logagent test             # re-test all saved connections
logagent status           # show last run / daemon state
logagent config           # print current config (secrets masked)
logagent run --once       # single poll cycle then exit (for cron scheduling)
```

---

## Docker (alternative install)

```bash
docker build -t logagent .
docker run --rm \
  -e SPLUNK_HOST=https://splunk:8089 \
  -e SPLUNK_USER=admin \
  -e SPLUNK_PASS=*** \
  -e ANTHROPIC_API_KEY=sk-ant-*** \
  -e SMTP_USER=alerts@company.com \
  -e SMTP_PASS=*** \
  -e EMAIL_TO=team@company.com \
  -e GITHUB_TOKEN=ghp_*** \
  -e GITHUB_REPO=owner/app \
  logagent
```

---

## Running as a 24/7 daemon (recommended)

```bash
logagent run        # blocks — stays alive until Ctrl+C or SIGTERM
```

**Systemd service (Linux):**
```ini
[Unit]
Description=LogAgent Splunk Monitor
After=network.target

[Service]
ExecStart=logagent run
Restart=always
RestartSec=30

[Install]
WantedBy=multi-user.target
```
```bash
sudo systemctl enable --now logagent
```

---

## Alternative: cron / one-shot mode

If you prefer scheduled one-shot runs (e.g., cron or Task Scheduler), use `--once`:

**Linux/Mac (cron):**
```bash
echo "0 * * * * $(which logagent) run --once >> ~/.logagent/agent.log 2>&1" | crontab -
```

**Windows (Task Scheduler):**
```powershell
schtasks /create /tn "LogAgent" /tr "logagent run --once" /sc hourly /mo 1
```

**Kubernetes CronJob:**
```yaml
apiVersion: batch/v1
kind: CronJob
metadata:
  name: logagent
spec:
  schedule: "0 * * * *"
  jobTemplate:
    spec:
      template:
        spec:
          containers:
          - name: logagent
            image: logagent:latest
            args: ["run", "--once"]
            envFrom:
            - secretRef:
                name: logagent-secrets
          restartPolicy: OnFailure
```

> **Note:** In cron mode, the cross-cycle deduplication (`DEDUP_WINDOW_MINS`) resets on each run because the process is ephemeral. Use the daemon mode to preserve dedup state in memory.

---

## Email report structure

Each error cluster card in the report:

| Section | Content |
|---|---|
| **Error Summary** | What happened and its impact (1 sentence) |
| **Technical Context** | Why the error occurs — references actual code paths when GitHub is configured |
| **Root Cause** | The underlying trigger — cites `file:line` when source code matched |
| **Action Items** | Step-by-step resolution targeted to your actual codebase |

Subject line includes compression ratio:
`[SPLUNK ALERT] 12 cluster(s) | 342x compression | 2026-05-25 14:32 UTC`

---

## How it works

```
Splunk REST API
  │  fetch (ERROR / EXCEPTION / FAILED / CRITICAL / FATAL)
  │
  ├─[1] Pre-dedup        Counter-hash exact duplicates → weighted lines
  ├─[2] Stack compressor Java/Python frame collapse → 2 kept + N omitted
  ├─[3] Extended tokenize key=value, quoted strings, thread IDs → <typed>
  ├─[4] Drain clustering  prefix-tree weighted grouping + variable slot tracking
  ├─[5] Cluster merger    second-pass MERGE_SIM=0.8 template consolidation
  └─[6] Token budget      hard char cap with graceful truncation
  │
  ├─ GitHub API (once per run, cached in memory)
  │    build_arch_summary() → LLM system block (ephemeral-cached across clusters)
  │    find_snippets(kws)   → per-cluster code snippet → injected into user prompt
  │
  └─ Claude claude-opus-4-7
       system: [persona] + [arch summary]   ← both ephemeral-cached
       user:   template + var slots + code snippet
       → JSON: summary / technical_context / root_cause / action_items
  │
  └─ HTML email → dev team inbox
```

---

## Configuration reference

All settings via `~/.logagent/config.env` (created by `logagent init`).

| Variable | Default | Description |
|---|---|---|
| `SPLUNK_HOST` | — | `https://host:8089` |
| `SPLUNK_INDEX` | `main` | Index to search |
| `LOOKBACK_MINS` | `60` | How far back to scan |
| `MAX_LLM_CLUSTERS` | `20` | Top-N clusters sent to Claude |
| `GITHUB_REPO` | — | `owner/repo` of the app producing the logs |
| `GITHUB_BRANCH` | `main` | Branch to read |
| `MAX_ARCH_CHARS` | `6000` | Architecture summary size (system block) |
| `MAX_SNIPPET_CHARS` | `2000` | Per-cluster code snippet size |
| `DRAIN_SIM` | `0.5` | Cluster similarity threshold (0–1) |
| `MERGE_SIM` | `0.8` | Second-pass merge threshold |
| `LLM_BUDGET_CHARS` | `3500` | Hard cap on user-message chars per LLM call |
| `POLL_INTERVAL_SECS` | `3600` | Daemon poll interval in seconds (default: 1 hour) |
| `DEDUP_WINDOW_MINS` | `120` | Suppress repeat alerts for same cluster within N minutes |
| `CODEBASE_REFRESH_HOUR` | `7` | Hour (0-23) in Eastern Time to re-index GitHub codebase daily |

---

## Requirements

- Python 3.10+
- Splunk with REST API on port 8089
- Anthropic API key
- Gmail App Password (or any SMTP)
- GitHub PAT with `read:contents` scope *(optional)*

---

## Files

| File | Purpose |
|---|---|
| `logagent_cli.py` | CLI entry point + setup wizard |
| `splunk_rca_agent.py` | Core agent pipeline |
| `codebase_context.py` | GitHub codebase indexer (also runs standalone) |
| `pyproject.toml` | PyPI packaging + ruff config |
| `Dockerfile` | Docker alternative |
| `ARCHITECTURE.md` | Full system architecture, data flow diagrams, token cost breakdown |

→ For a deep-dive into how the pipeline works internally, see [ARCHITECTURE.md](ARCHITECTURE.md).
