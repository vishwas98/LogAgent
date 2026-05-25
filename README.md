# LogAgent

Splunk anomaly monitor with **codebase-aware LLM root cause analysis**.

Fetches error logs → compresses with 6-stage Drain pipeline → reads your GitHub repo → generates code-specific RCA with Claude → emails a structured HTML report.

---

## Install & run  (2 minutes)

```bash
pip install splunk-logagent

logagent init   # interactive wizard — tests every connection live
logagent run    # send your first report
```

That's it. No config files to hand-edit.

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

## Other commands

```bash
logagent test     # re-test all saved connections
logagent status   # show last run timestamp + result
logagent config   # print current config (secrets masked)
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

## Schedule it (run every hour)

**Linux/Mac (cron):**
```bash
echo "0 * * * * $(which logagent) run >> ~/.logagent/agent.log 2>&1" | crontab -
```

**Windows (Task Scheduler):**
```powershell
schtasks /create /tn "LogAgent" /tr "logagent run" /sc hourly /mo 1
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
            envFrom:
            - secretRef:
                name: logagent-secrets
          restartPolicy: OnFailure
```

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
| `pyproject.toml` | PyPI packaging |
| `Dockerfile` | Docker alternative |
