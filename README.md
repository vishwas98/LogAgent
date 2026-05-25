# LogAgent

Splunk log monitor agent with Drain-style clustering, LLM-powered Root Cause Analysis, and HTML email reporting.

## Pipeline

```
Splunk REST API
      │  fetch anomaly events (ERROR / EXCEPTION / FAILED / CRITICAL / FATAL)
      ▼
DrainClusterer
      │  tokenize → normalize dynamic fields → prefix-tree similarity grouping
      ▼
RCAAnalyzer  (claude-opus-4-7 via Anthropic API)
      │  prompt-cached system block, per-cluster JSON RCA
      ▼
EmailReporter
      │  dark-theme HTML report, one card per cluster ordered by frequency
      ▼
Dev team inbox
```

## Setup

```bash
pip install -r requirements.txt

cp .env.example .env
# fill in your credentials

python splunk_rca_agent.py
```

## Email Report Structure

Each error cluster card contains:

| Section | Content |
|---|---|
| **Error Summary** | What happened and its impact |
| **Technical Context** | Why the error occurs technically |
| **Root Cause** | The underlying trigger or failure point |
| **Action Items** | Step-by-step resolution for developers |

## Configuration

All settings are driven by environment variables — see [`.env.example`](.env.example).

Key tuning knobs:

| Variable | Default | Purpose |
|---|---|---|
| `LOOKBACK_MINS` | `60` | Splunk search window |
| `MAX_LLM_CLUSTERS` | `20` | Cap LLM API calls to top-N clusters |
| `DRAIN_SIM` | `0.5` | Cluster similarity threshold (0–1) |
| `DRAIN_DEPTH` | `4` | Prefix tokens used for tree bucketing |

## Requirements

- Python 3.10+
- Splunk with REST API enabled (port 8089)
- Anthropic API key
- SMTP credentials (Gmail app password recommended)
