#!/usr/bin/env python3
"""
codebase_context.py
GitHub codebase indexer for LLM-aware log analysis.

Builds two tiers of context:
  (A) Architecture summary  — project structure, README, config, error handlers.
      Sent once as a cached LLM system block; reused across all cluster RCA calls.

  (B) Per-cluster snippets  — keywords extracted from each log template are used
      to score and grep source files, returning ±20-line windows of relevant code.

Standalone usage:
  from codebase_context import CodebaseIndexer
  idx = CodebaseIndexer(token="ghp_...", owner="acme", repo="backend", branch="main")
  print(idx.build_arch_summary())
  kws     = idx.extract_keywords("ERROR connecting to <IP> port <NUM>", {})
  snippet = idx.find_snippets(kws)

Env vars (when used inside the agent):
  GITHUB_TOKEN    Personal access token (read:contents scope)
  GITHUB_REPO     owner/repo  (e.g. acme/backend)
  GITHUB_BRANCH   default: main
  MAX_ARCH_CHARS  default: 6000   system-block size cap
  MAX_SNIPPET_CHARS default: 2000 per-cluster snippet cap
"""

from __future__ import annotations

import base64
import logging
import os
import re
from collections import Counter

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
log = logging.getLogger(__name__)

# ── CONFIG ────────────────────────────────────────────────────────────────────
MAX_ARCH_CHARS = int(os.environ.get("MAX_ARCH_CHARS", "6000"))
MAX_SNIPPET_CHARS = int(os.environ.get("MAX_SNIPPET_CHARS", "2000"))

# ── CONSTANTS ────────────────────────────────────────────────────────────────
# Source extensions to index for snippet search
_SRC_EXTS = {
    ".py",
    ".java",
    ".js",
    ".ts",
    ".go",
    ".rb",
    ".cs",
    ".scala",
    ".kt",
    ".rs",
    ".cpp",
    ".c",
    ".php",
    ".swift",
}

# Priority files for architecture summary (checked in order)
_ARCH_FILES = [
    "README.md",
    "README.rst",
    "README.txt",
    "ARCHITECTURE.md",
    "docker-compose.yml",
    "docker-compose.yaml",
    "pyproject.toml",
    "setup.py",
    "requirements.txt",
    "pom.xml",
    "build.gradle",
    "build.gradle.kts",
    "package.json",
    "go.mod",
    "Cargo.toml",
    "application.yml",
    "application.yaml",
    "application.properties",
    "config.py",
    "settings.py",
    "config.yaml",
    "config.yml",
    ".env.example",
    "Makefile",
]

# Files whose name suggests error/exception handling
_ERROR_FILE_RE = re.compile(
    r"(?:exception|error|fault|handler|middleware|interceptor|filter|advice)",
    re.I,
)

# Regex to find exception / service class names in log templates
_CAMEL_CLASS_RE = re.compile(
    r"\b[A-Z][a-zA-Z]+(?:Exception|Error|Failure|Service|Handler|"
    r"Controller|Manager|Repository|Client|Gateway|Dao|Filter|Interceptor)\b"
)
_FQN_CLASS_RE = re.compile(r"(?:[\w]+\.)+([A-Z]\w+)")  # com.app.UserService → UserService


# ── CODEBASE INDEXER ─────────────────────────────────────────────────────────
class CodebaseIndexer:
    """
    Fetches and indexes a GitHub repository to supply the LLM with
    application-specific context for accurate root cause analysis.

    All API responses are cached in-memory for the lifetime of the object.
    Typical call pattern per agent run:
      1 × build_arch_summary()     → ~5–15 GitHub API calls
      N × find_snippets(keywords)  → 0–10 cached reads per cluster
    """

    def __init__(
        self,
        token: str,
        owner: str,
        repo: str,
        branch: str = "main",
    ) -> None:
        self.owner = owner
        self.repo = repo
        self.branch = branch

        self._sess = requests.Session()
        self._sess.headers.update(
            {
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
            }
        )
        self._api = "https://api.github.com"

        self._tree: list[dict] | None = None  # full file tree (cached)
        self._files: dict[str, str] = {}  # file contents (cached)
        # HEAD SHA at the time the index was last built.
        # Used by refresh_if_stale() to detect new commits without re-fetching everything.
        self._indexed_sha: str | None = None

    # ── private helpers ───────────────────────────────────────────────────────

    def _get_tree(self) -> list[dict]:
        """Fetch the full recursive file tree (one API call, cached)."""
        if self._tree is not None:
            return self._tree
        r = self._sess.get(
            f"{self._api}/repos/{self.owner}/{self.repo}/git/trees/{self.branch}",
            params={"recursive": "1"},
            timeout=30,
        )
        r.raise_for_status()
        self._tree = [n for n in r.json().get("tree", []) if n["type"] == "blob"]
        log.info(
            "Indexed %d files from %s/%s@%s",
            len(self._tree),
            self.owner,
            self.repo,
            self.branch,
        )
        return self._tree

    def _read(self, path: str) -> str:
        """
        Read a file via GitHub Contents API.
        Returns empty string on any failure (404, too-large, binary).
        """
        if path in self._files:
            return self._files[path]
        try:
            r = self._sess.get(
                f"{self._api}/repos/{self.owner}/{self.repo}/contents/{path}",
                params={"ref": self.branch},
                timeout=15,
            )
            if r.status_code == 200:
                data = r.json()
                # GitHub returns base64-encoded content for files < 1 MB
                if data.get("encoding") == "base64":
                    raw = base64.b64decode(data["content"]).decode("utf-8", errors="replace")
                    self._files[path] = raw
                    return raw
        except Exception as exc:
            log.debug("Could not read %s: %s", path, exc)
        self._files[path] = ""
        return ""

    def _all_paths(self) -> list[str]:
        return [n["path"] for n in self._get_tree()]

    def _source_files(self) -> list[str]:
        return [p for p in self._all_paths() if os.path.splitext(p)[1].lower() in _SRC_EXTS]

    # ── public API ────────────────────────────────────────────────────────────

    def get_head_sha(self) -> str | None:
        """
        Return the current HEAD commit SHA for the configured branch.

        One lightweight GitHub API call — used to detect deploys without
        re-fetching the entire file tree.  Returns None on any failure so
        callers can degrade gracefully (keep using the existing index).
        """
        try:
            r = self._sess.get(
                f"{self._api}/repos/{self.owner}/{self.repo}/branches/{self.branch}",
                timeout=10,
            )
            r.raise_for_status()
            return r.json().get("commit", {}).get("sha")
        except Exception as exc:
            log.debug(
                "Could not fetch HEAD SHA for %s/%s@%s: %s",
                self.owner,
                self.repo,
                self.branch,
                exc,
            )
            return None

    def refresh_if_stale(self) -> bool:
        """
        Detect new commits on the branch and invalidate the cache if found.

        Called once per daemon poll cycle.  If the branch HEAD SHA has changed
        since the last index build (i.e., a deploy landed):

          • Clears _tree  (file-tree cache)    → next _get_tree() fetches fresh list
          • Clears _files (content cache)      → next _read() fetches updated files
          • Updates _indexed_sha to new SHA    → avoids repeated refreshes

        Returns True  → new commits detected; caller must call build_arch_summary()
                        to regenerate the LLM architecture context block.
        Returns False → index is current (same SHA) OR the SHA check failed
                        (network issue); existing cache is kept as-is.
        """
        current_sha = self.get_head_sha()
        if not current_sha:
            return False  # can't reach GitHub — keep using existing index

        if current_sha == self._indexed_sha:
            return False  # branch unchanged since last index — nothing to do

        log.info(
            "🔄  New commit on %s/%s@%s: %s → %s — invalidating codebase cache",
            self.owner,
            self.repo,
            self.branch,
            (self._indexed_sha or "none")[:8],
            current_sha[:8],
        )
        # Invalidate both cache layers
        self._tree = None
        self._files.clear()
        self._indexed_sha = current_sha
        return True

    def build_arch_summary(self) -> str:
        """
        Build (or rebuild) the architecture summary for use as an LLM system block.

        Captures the HEAD SHA before fetching anything, establishing the baseline
        for future refresh_if_stale() calls (first-time indexing or post-deploy rebuild).

        Sections:
          1. Repo identity + language breakdown + indexed commit SHA
          2. Top-level module/package structure
          3. README & build files (capped per file)
          4. Error / exception handler source files (up to 3)

        Returns a single string, capped at MAX_ARCH_CHARS.
        """
        # Snapshot HEAD SHA before reading any files — this is the commit we're indexing.
        # If _indexed_sha is already set (called after refresh_if_stale), keep it.
        if self._indexed_sha is None:
            sha = self.get_head_sha()
            if sha:
                self._indexed_sha = sha
                log.info("Indexing %s/%s@%s  commit %s", self.owner, self.repo, self.branch, sha[:8])

        all_paths = self._all_paths()
        path_set = set(all_paths)

        # Language distribution
        ext_counts = Counter(
            os.path.splitext(p)[1].lower()
            for p in all_paths
            if os.path.splitext(p)[1].lower() in _SRC_EXTS
        )
        lang_str = ", ".join(f"{e}({c})" for e, c in ext_counts.most_common(6)) or "unknown"

        # Top-level directory/package names
        top_dirs = sorted({p.split("/")[0] for p in all_paths if "/" in p})

        sha_label = f"  commit:{self._indexed_sha[:8]}" if self._indexed_sha else ""
        sections: list[str] = [
            f"# {self.owner}/{self.repo}  branch:{self.branch}{sha_label}",
            f"Languages : {lang_str}",
            f"Total files: {len(all_paths)}",
            "Top-level modules:\n" + "\n".join(f"  {d}/" for d in top_dirs[:25]),
        ]

        # Priority architecture / config files
        for fname in _ARCH_FILES:
            if fname in path_set:
                content = self._read(fname)
                if content.strip():
                    # Cap long files — keep the most informative head
                    sections.append(f"\n## {fname}\n{content[:2500]}")

        # Error handler source files — crucial for RCA pattern matching
        err_files = [
            p
            for p in all_paths
            if _ERROR_FILE_RE.search(os.path.basename(p))
            and os.path.splitext(p)[1].lower() in _SRC_EXTS
        ][:3]

        for ef in err_files:
            content = self._read(ef)
            if content.strip():
                sections.append(f"\n## {ef}  (error handler)\n{content[:1500]}")

        summary = "\n".join(sections)
        if len(summary) > MAX_ARCH_CHARS:
            summary = summary[:MAX_ARCH_CHARS] + "\n…[architecture summary truncated]"
        return summary

    def extract_keywords(
        self,
        template_str: str,
        var_slots: dict[int, list[str]],
    ) -> list[str]:
        """
        Derive searchable identifiers from a log template + its variable slot values.

        Priority (high → low):
          1. Exception / class names  (NullPointerException, UserService…)
          2. Java FQN last segment    (com.app.db.ConnectionPool → ConnectionPool)
          3. Meaningful static tokens (≥4 chars, not a wildcard or pure digit)
          4. Identifier-shaped slot values (not IPs / epoch timestamps)

        Returns up to 15 keywords.
        """
        kws: set[str] = set()

        # 1 & 2 — class-name patterns
        kws.update(_CAMEL_CLASS_RE.findall(template_str))
        kws.update(_FQN_CLASS_RE.findall(template_str))

        # 3 — static template tokens
        for tok in template_str.split():
            if tok.startswith("<") or len(tok) < 4:
                continue
            cleaned = re.sub(r"[^\w.$\-]", "", tok)
            if cleaned and not cleaned.isdigit() and len(cleaned) >= 4:
                kws.add(cleaned)

        # 4 — identifier-shaped variable slot values
        for vals in var_slots.values():
            for v in vals:
                if re.match(r"^[a-zA-Z][\w\-]{2,30}$", v):
                    kws.add(v)

        return [k for k in kws if len(k) >= 4][:15]

    def find_snippets(
        self,
        keywords: list[str],
        max_snippets: int = 5,
        context_lines: int = 20,
    ) -> str:
        """
        Locate code relevant to the given keywords and return formatted snippets.

        Algorithm:
          1. Score all source files by keyword overlap with their path
             (error-handler files get a +1 bonus).
          2. Read top-10 path-scored files (from cache if already fetched).
          3. For each file, find the first line matching any keyword;
             extract a ±context_lines window.
          4. Return up to max_snippets snippets joined by a separator,
             capped at MAX_SNIPPET_CHARS.
        """
        if not keywords:
            return ""

        src = self._source_files()
        kw_low = [k.lower() for k in keywords]

        def _score(path: str) -> int:
            pl = path.lower()
            s = sum(1 for k in kw_low if k in pl)
            if _ERROR_FILE_RE.search(os.path.basename(path)):
                s += 1
            return s

        candidates = sorted(src, key=_score, reverse=True)[:10]

        snippets: list[str] = []
        for path in candidates:
            if len(snippets) >= max_snippets:
                break
            content = self._read(path)
            if not content:
                continue
            lines = content.splitlines()
            for i, line in enumerate(lines):
                ll = line.lower()
                if any(k in ll for k in kw_low):
                    start = max(0, i - 5)
                    end = min(len(lines), i + context_lines)
                    block = "\n".join(lines[start:end])
                    header = f"# {path}  (line {i + 1})"
                    snippets.append(f"{header}\n{block}")
                    break  # one window per file

        if not snippets:
            return ""

        sep = "\n\n" + "─" * 60 + "\n\n"
        joined = sep.join(snippets)
        if len(joined) > MAX_SNIPPET_CHARS:
            joined = joined[:MAX_SNIPPET_CHARS] + "\n…[snippets truncated]"
        return joined

    # ── convenience ──────────────────────────────────────────────────────────

    @classmethod
    def from_env(cls) -> CodebaseIndexer | None:
        """
        Construct from standard env vars. Returns None if not configured.
        Expected:  GITHUB_TOKEN, GITHUB_REPO=owner/repo, GITHUB_BRANCH=main
        """
        token = os.environ.get("GITHUB_TOKEN", "")
        repo = os.environ.get("GITHUB_REPO", "")
        if not (token and repo):
            return None
        try:
            owner, name = repo.split("/", 1)
        except ValueError:
            log.error("GITHUB_REPO must be 'owner/repo', got: %s", repo)
            return None
        branch = os.environ.get("GITHUB_BRANCH", "main")
        log.info("CodebaseIndexer: %s/%s @ %s", owner, name, branch)
        return cls(token=token, owner=owner, repo=name, branch=branch)


# ── CLI / standalone test ─────────────────────────────────────────────────────
if __name__ == "__main__":
    import sys

    idx = CodebaseIndexer.from_env()
    if not idx:
        print("Set GITHUB_TOKEN and GITHUB_REPO=owner/repo to run standalone test.")
        sys.exit(1)

    print("=" * 70)
    print("ARCHITECTURE SUMMARY")
    print("=" * 70)
    arch = idx.build_arch_summary()
    print(arch)

    # Demo keyword extraction + snippet search
    demo_template = "ERROR connecting to <IP> port <NUM> after <NUM>ms timeout"
    kws = idx.extract_keywords(demo_template, {})
    print(f"\n{'=' * 70}")
    print(f"KEYWORDS for: {demo_template!r}")
    print(kws)
    print(f"\n{'=' * 70}")
    print("SNIPPETS")
    print("=" * 70)
    print(idx.find_snippets(kws) or "(no matches found)")
