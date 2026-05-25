# LogAgent

Splunk log monitor with **codebase-aware root cause analysis**.

Fetches anomalous logs → compresses them with a 6-stage pipeline → reads your GitHub repo to understand the application → uses Claude to generate targeted, code-specific RCA → emails a structured HTML report.

---

## Pipeline

```
Splunk REST API
      │  fetch (ERROR/EXCEPTION/FAILED/CRITICAL/FATAL)
      │
      ▼ ─── 6-stage compression ───────────────────────────────────────────────
      │
      │  [1] Pre-dedup        Counter-hash exact duplicates → weighted lines
      │  [2] Stack compressor Java/Python frame collapse → 2 kept + N omitted
      │  [3] Extended tokenizer key=value, quoted strings, thread IDs → <typed>
      │  [4] Drain clustering  prefix-tree weighted grouping + var slot tracking
      │  [5] Cluster merger    second-pass MERGE_SIM=0.8 template consolidation
      │  [6] Token budget      hard char cap with graceful truncation
      │
      ▼ ─── codebase context (codebase_context.py) ────────────────────────────
      │
      │  GitHub API (once per run, results cached)
      │    ├── build_arch_summary()   → LLM system block (ephemeral-cached)
      │    │     README, configs, error handlers, module structure
      │    └── find_snippets(kws)     → injected into each cluster's user prompt
      │          keywords from log template + variable slot values
      │          score source files by path overlap → read top-N → ±20-line windows
      │
      ▼ ─── RCA (claude-opus-4-7) ─────────────────────────────────────────────
      │
      │  System: [persona block] + [arch block]   ← both ephemeral-cached
      │  User:   template + var slots + code snippet
      │  → JSON: summary / technical_context / root_cause / action_items
      │
      ▼ ─── HTML email ────────────────────────────────────────────────────────

Dev team inbox  (dark-theme, one card per cluster, ordered by frequency)
```

---

## Quick start

```bash
pip install -r requirements.txt

cp .env.example .env
# fill in credentials

python splunk_rca_agent.py
```

**Test codebase indexer standalone:**
```bash
export GITHUB_TOKEN=ghp_...
export GITHUB_REPO=owner/your-app
python codebase_context.py
```

---

## Email report structure

Each error cluster card:

| Section | Content |
|---|---|
| **Error Summary** | What happened and its impact (1 sentence) |
| **Technical Context** | Why the error occurs — references actual code paths when available |
| **Root Cause** | Specific trigger — cites `file:line` when source code matched |
| **Action Items** | Step-by-step resolution targeted to your actual codebase |

Email subject includes compression ratio: `[SPLUNK ALERT] 12 cluster(s) | 342x compression | 2026-05-25 14:32 UTC`

---

## Configuration

All settings via environment variables. See [`.env.example`](.env.example).

### Key tuning knobs

| Variable | Default | Purpose |
|---|---|---|
| `GITHUB_REPO` | — | `owner/repo` of the app producing the logs. Enables codebase-aware RCA. |
| `GITHUB_TOKEN` | — | PAT with `read:contents` scope |
| `GITHUB_BRANCH` | `main` | Branch to read (use your stable/release branch) |
| `MAX_ARCH_CHARS` | `6000` | Architecture summary size (system block, cached) |
| `MAX_SNIPPET_CHARS` | `2000` | Per-cluster code snippet injected into user prompt |
| `LOOKBACK_MINS` | `60` | Splunk search window |
| `MAX_LLM_CLUSTERS` | `20` | Cap LLM API calls to top-N clusters by frequency |
| `DRAIN_SIM` | `0.5` | Cluster similarity threshold (0–1) |
| `MERGE_SIM` | `0.8` | Second-pass merge threshold |
| `LLM_BUDGET_CHARS` | `3500` | Hard cap on user-message chars per LLM call |

### Without GitHub (generic mode)

Omit `GITHUB_TOKEN` / `GITHUB_REPO`. The agent still works — RCA uses generic SRE knowledge without code-specific context.

---

## Files

| File | Purpose |
|---|---|
| `splunk_rca_agent.py` | Main agent — all pipeline stages + email dispatch |
| `codebase_context.py` | Standalone GitHub codebase indexer (importable or CLI) |
| `requirements.txt` | Dependencies |
| `.env.example` | All env vars with descriptions |

---

## Requirements

- Python 3.10+
- Splunk with REST API enabled (port 8089)
- Anthropic API key
- GitHub PAT (optional, `read:contents` scope)
- SMTP credentials (Gmail app password recommended)
