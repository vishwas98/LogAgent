#!/usr/bin/env python3
"""
logagent_cli.py  —  CLI entry point for the LogAgent PyPI package

After `pip install splunk-logagent`:
  logagent init       Interactive setup wizard (tests each connection live)
  logagent run        Run the agent once
  logagent test       Re-test all saved connections
  logagent status     Show last run summary
  logagent config     Print current config file path + contents (masked)
"""

from __future__ import annotations

import argparse
import getpass
import json
import os
import smtplib
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

# ── Config storage ────────────────────────────────────────────────────────────
CONFIG_DIR = Path.home() / ".logagent"
CONFIG_FILE = CONFIG_DIR / "config.env"
STATUS_FILE = CONFIG_DIR / "last_run.json"

_SECRET_KEYS = {"SPLUNK_PASS", "ANTHROPIC_API_KEY", "SMTP_PASS", "GITHUB_TOKEN"}


# ── Helpers ───────────────────────────────────────────────────────────────────
def _load() -> dict[str, str]:
    if not CONFIG_FILE.exists():
        return {}
    cfg: dict[str, str] = {}
    for line in CONFIG_FILE.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            cfg[k.strip()] = v.strip()
    return cfg


def _save(cfg: dict[str, str]) -> None:
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    CONFIG_FILE.write_text("\n".join(f"{k}={v}" for k, v in cfg.items()) + "\n")
    CONFIG_FILE.chmod(0o600)  # owner-readable only


def _apply(cfg: dict[str, str]) -> None:
    """Inject saved config into the current process env."""
    for k, v in cfg.items():
        os.environ.setdefault(k, v)


def _prompt(
    label: str,
    default: str = "",
    secret: bool = False,
    required: bool = True,
) -> str:
    hint = f" [{default}]" if default and not secret else ""
    fn = getpass.getpass if secret else input
    while True:
        val = fn(f"  {label}{hint}: ").strip()
        if not val:
            val = default
        if val or not required:
            return val
        print("    ⚠  Required — please enter a value.")


def _ok(msg: str = "") -> None:
    print(f"  ✅  {msg}")


def _fail(msg: str = "") -> None:
    print(f"  ❌  {msg}")


def _section(title: str) -> None:
    print(f"\n── {title} {'─' * max(0, 50 - len(title))}")


# ── Connection tests ──────────────────────────────────────────────────────────
def _test_splunk(cfg: dict) -> bool:
    print("  Splunk REST API … ", end="", flush=True)
    try:
        import xml.etree.ElementTree as ET

        import requests
        import urllib3

        urllib3.disable_warnings()
        r = requests.post(
            f"{cfg['SPLUNK_HOST']}/services/auth/login",
            data={"username": cfg["SPLUNK_USER"], "password": cfg["SPLUNK_PASS"]},
            verify=False,
            timeout=12,
        )
        if r.ok and ET.fromstring(r.text).findtext(".//sessionKey"):
            _ok("authenticated")
            return True
        _fail(f"HTTP {r.status_code}")
    except Exception as e:
        _fail(str(e))
    return False


def _test_anthropic(cfg: dict) -> bool:
    print("  Anthropic API … ", end="", flush=True)
    try:
        import anthropic

        anthropic.Anthropic(api_key=cfg["ANTHROPIC_API_KEY"]).messages.create(
            model="claude-haiku-4-5-20251001",
            max_tokens=5,
            messages=[{"role": "user", "content": "ping"}],
        )
        _ok("reachable")
        return True
    except Exception as e:
        _fail(str(e))
    return False


def _test_smtp(cfg: dict) -> bool:
    print("  SMTP … ", end="", flush=True)
    try:
        with smtplib.SMTP(
            cfg.get("SMTP_HOST", "smtp.gmail.com"),
            int(cfg.get("SMTP_PORT", "587")),
            timeout=12,
        ) as s:
            s.ehlo()
            s.starttls()
            s.login(cfg["SMTP_USER"], cfg["SMTP_PASS"])
        _ok("login OK")
        return True
    except Exception as e:
        _fail(str(e))
    return False


def _test_github(cfg: dict) -> bool:
    if "GITHUB_TOKEN" not in cfg or "GITHUB_REPO" not in cfg:
        return True  # optional — skip silently
    print("  GitHub … ", end="", flush=True)
    try:
        import requests

        r = requests.get(
            f"https://api.github.com/repos/{cfg['GITHUB_REPO']}",
            headers={
                "Authorization": f"Bearer {cfg['GITHUB_TOKEN']}",
                "Accept": "application/vnd.github+json",
            },
            timeout=10,
        )
        if r.ok:
            _ok(f"repo '{cfg['GITHUB_REPO']}' accessible")
            return True
        _fail(f"HTTP {r.status_code} — check token/repo name")
    except Exception as e:
        _fail(str(e))
    return False


def _run_all_tests(cfg: dict) -> bool:
    results = [
        _test_splunk(cfg),
        _test_anthropic(cfg),
        _test_smtp(cfg),
        _test_github(cfg),
    ]
    return all(results)


# ── Commands ──────────────────────────────────────────────────────────────────
def cmd_init() -> None:
    """Interactive setup wizard. Tests each connection before moving on."""
    print("\n╔══════════════════════════════════════════════╗")
    print("║         LogAgent  —  Setup Wizard            ║")
    print("║  Ctrl+C at any time to cancel                ║")
    print("╚══════════════════════════════════════════════╝")

    existing = _load()
    cfg: dict[str, str] = {}

    # ── Splunk ────────────────────────────────────────────────────────────────
    _section("Splunk  (REST API, default port 8089)")
    print("  Need: host URL, admin credentials, index name.")
    cfg["SPLUNK_HOST"] = _prompt("REST URL", existing.get("SPLUNK_HOST", "https://localhost:8089"))
    cfg["SPLUNK_USER"] = _prompt("Username", existing.get("SPLUNK_USER", "admin"))
    cfg["SPLUNK_PASS"] = _prompt("Password", secret=True)
    cfg["SPLUNK_INDEX"] = _prompt("Index", existing.get("SPLUNK_INDEX", "main"))
    cfg["LOOKBACK_MINS"] = _prompt("Lookback (min)", existing.get("LOOKBACK_MINS", "60"))

    print()
    if not _test_splunk(cfg):
        print("  ⚠  Connection failed — check URL / credentials and try again.")
        print("     Continuing anyway; you can fix and re-run `logagent init`.\n")

    # ── Anthropic ─────────────────────────────────────────────────────────────
    _section("Anthropic API  (console.anthropic.com → API Keys)")
    cfg["ANTHROPIC_API_KEY"] = _prompt("API key (sk-ant-...)", secret=True)

    print()
    if not _test_anthropic(cfg):
        print("  ⚠  API key invalid or unreachable. Continuing.\n")

    # ── Email ─────────────────────────────────────────────────────────────────
    _section("Email  (SMTP — who sends the report)")
    print("  For Gmail: enable 2-Step Verification → create an App Password.")
    print("  App Password path: myaccount.google.com → Security → App Passwords\n")

    cfg["SMTP_HOST"] = _prompt("SMTP host", existing.get("SMTP_HOST", "smtp.gmail.com"))
    cfg["SMTP_PORT"] = _prompt("SMTP port", existing.get("SMTP_PORT", "587"))
    cfg["SMTP_USER"] = _prompt("Sender email", existing.get("SMTP_USER", ""))
    cfg["SMTP_PASS"] = _prompt("App password", secret=True)
    cfg["EMAIL_FROM"] = cfg["SMTP_USER"]
    cfg["EMAIL_TO"] = _prompt(
        "Recipients (comma-separated)",
        existing.get("EMAIL_TO", ""),
    )

    print()
    if not _test_smtp(cfg):
        print("  ⚠  SMTP login failed. Check app password (not your Gmail login).\n")

    # ── GitHub (optional) ─────────────────────────────────────────────────────
    _section("GitHub  (optional — enables code-aware RCA)")
    print("  Without this: generic SRE root cause analysis.")
    print("  With this:    LLM reads your repo to cite specific file:line causes.")
    print("  Need: PAT with read:contents scope on the app repo.\n")
    print("  PAT path: github.com → Settings → Developer Settings → Fine-grained tokens\n")

    github_token = _prompt("GitHub PAT (leave blank to skip)", secret=True, required=False)
    if github_token:
        cfg["GITHUB_TOKEN"] = github_token
        cfg["GITHUB_REPO"] = _prompt("App repo (owner/repo)", existing.get("GITHUB_REPO", ""))
        cfg["GITHUB_BRANCH"] = _prompt("Branch", existing.get("GITHUB_BRANCH", "main"))
        print()
        _test_github(cfg)
    else:
        print("  Skipped — running without code context.")

    # ── Save ──────────────────────────────────────────────────────────────────
    _save(cfg)
    print(f"\n{'─' * 54}")
    print(f"✅  Config saved → {CONFIG_FILE}")
    print("\nNext steps:")
    print("  logagent test    — re-run all connection checks")
    print("  logagent run     — run the agent now")
    print()


def cmd_test() -> None:
    """Re-test all saved connections."""
    cfg = _load()
    if not cfg:
        print("Not configured. Run:  logagent init")
        sys.exit(1)
    print(f"\nTesting connections (config: {CONFIG_FILE})\n")
    ok = _run_all_tests(cfg)
    print()
    if ok:
        print("✅  All checks passed. Ready to run.\n")
    else:
        print("❌  Some checks failed. Fix config and retry:  logagent init\n")
        sys.exit(1)


def cmd_run() -> None:
    """Load config and run the agent once."""
    cfg = _load()
    if not cfg:
        print("Not configured. Run:  logagent init")
        sys.exit(1)
    _apply(cfg)

    # Add package directory so sibling modules can be imported
    sys.path.insert(0, str(Path(__file__).parent))

    start = time.time()
    try:
        from splunk_rca_agent import LogMonitorAgent

        LogMonitorAgent().run()
        elapsed = time.time() - start
        _write_status("success", elapsed)
    except Exception as exc:
        elapsed = time.time() - start
        _write_status("failed", elapsed, str(exc))
        print(f"\n❌  Agent failed: {exc}", file=sys.stderr)
        sys.exit(1)


def cmd_status() -> None:
    """Show last run summary."""
    if not STATUS_FILE.exists():
        print("No runs recorded yet. Run:  logagent run")
        return
    data = json.loads(STATUS_FILE.read_text())
    ts = data.get("timestamp", "unknown")
    st = data.get("status", "unknown")
    secs = data.get("elapsed_s", 0)
    icon = "✅" if st == "success" else "❌"
    print(f"\n{icon}  Last run: {ts}  ({secs:.1f}s)  status={st}")
    if data.get("error"):
        print(f"   Error: {data['error']}")
    print(f"   Config: {CONFIG_FILE}\n")


def cmd_config() -> None:
    """Print current config with secrets masked."""
    cfg = _load()
    if not cfg:
        print("No config found. Run:  logagent init")
        return
    print(f"\nConfig file: {CONFIG_FILE}\n")
    for k, v in cfg.items():
        display = ("*" * 8 + v[-4:]) if k in _SECRET_KEYS and len(v) > 4 else v
        print(f"  {k:25s} = {display}")
    print()


def _write_status(status: str, elapsed: float, error: str = "") -> None:
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    STATUS_FILE.write_text(
        json.dumps(
            {
                "status": status,
                "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
                "elapsed_s": round(elapsed, 1),
                "error": error,
            },
            indent=2,
        )
    )


# ── Entry point ───────────────────────────────────────────────────────────────
def main() -> None:
    p = argparse.ArgumentParser(
        prog="logagent",
        description="Splunk anomaly monitor with LLM-powered root cause analysis.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
commands:
  init      Interactive setup wizard — configure Splunk, Anthropic, email, GitHub
  run       Run the agent once and send the report
  test      Re-test all saved connections without running the agent
  status    Show last run timestamp and result
  config    Print current config (secrets masked)

quick start:
  pip install splunk-logagent
  logagent init
  logagent run
        """,
    )
    p.add_argument("command", choices=["init", "run", "test", "status", "config"])
    args = p.parse_args()

    dispatch = {
        "init": cmd_init,
        "run": cmd_run,
        "test": cmd_test,
        "status": cmd_status,
        "config": cmd_config,
    }
    try:
        dispatch[args.command]()
    except KeyboardInterrupt:
        print("\n\nAborted.")
        sys.exit(0)


if __name__ == "__main__":
    main()
