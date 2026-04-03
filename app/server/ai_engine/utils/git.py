"""
ARGOS — Git Utilities
Adapted from Claude Code utils/git.ts (Anthropic Inc.)

Symlink-safe git root discovery with LRU cache.
Minimal async git state queries (branch, head, remote URL).

Security: resolveCanonicalRoot validates the .git file → commondir chain
to prevent malicious repos from borrowing a trusted repo's identity via
crafted worktree symlinks.

ARGOS use cases:
  - Auto-memory: scope memory to canonical repo root (not worktree)
  - Audit trail: record git branch/commit with each scan session
  - Scheduled scans: detect repo changes since last scan
"""
from __future__ import annotations

import asyncio
import hashlib
import logging
import os
import re
from functools import lru_cache
from pathlib import Path
from typing import Optional

log = logging.getLogger("argos.git")

_GIT_ROOT_NOT_FOUND = object()  # sentinel


# ─── FIND GIT ROOT ────────────────────────────────────────────────────────────

@lru_cache(maxsize=50)
def _find_git_root_impl(start_path: str) -> Optional[str]:
    """
    Walk up the directory tree looking for a .git entry.
    .git can be a directory (regular repo) or a file (worktree/submodule).
    Returns NFC-normalised path or None.
    Memoized per start_path with LRU(50).
    """
    current = os.path.realpath(start_path)

    while True:
        git_path = os.path.join(current, ".git")
        try:
            st = os.stat(git_path)
            if st.st_mode:   # exists (dir or file)
                return os.path.normpath(current)
        except OSError:
            pass

        parent = os.path.dirname(current)
        if parent == current:
            break
        current = parent

    return None


def find_git_root(start_path: str) -> Optional[str]:
    """
    Find the git root by walking up the directory tree.
    Returns the directory containing .git, or None if not in a repo.
    Result is cached with LRU(50).
    """
    return _find_git_root_impl(os.path.realpath(start_path))


@lru_cache(maxsize=50)
def _resolve_canonical_root(git_root: str) -> str:
    """
    For a regular repo: returns git_root unchanged.
    For a worktree: follows .git file → gitdir → commondir chain to the
    main repo's working directory.

    SECURITY: validates the worktree chain to prevent malicious repos from
    borrowing a trusted repo's identity via crafted .git files.
    Same logic as Claude Code's resolveCanonicalRoot().
    """
    try:
        git_file = os.path.join(git_root, ".git")
        with open(git_file, encoding="utf-8") as fh:
            content = fh.read().strip()

        if not content.startswith("gitdir:"):
            return git_root  # regular repo, .git is a directory (would raise EISDIR)

        worktree_git_dir = os.path.realpath(
            os.path.join(git_root, content[len("gitdir:"):].strip())
        )

        # Read commondir (submodules have no commondir → fall through)
        commondir_file = os.path.join(worktree_git_dir, "commondir")
        with open(commondir_file, encoding="utf-8") as fh:
            common_dir = os.path.realpath(
                os.path.join(worktree_git_dir, fh.read().strip())
            )

        # SECURITY CHECK 1: worktreeGitDir must be a direct child of <commonDir>/worktrees/
        expected_parent = os.path.join(common_dir, "worktrees")
        if os.path.dirname(worktree_git_dir) != expected_parent:
            return git_root

        # SECURITY CHECK 2: gitdir back-link must point to <git_root>/.git
        gitdir_backlink_file = os.path.join(worktree_git_dir, "gitdir")
        with open(gitdir_backlink_file, encoding="utf-8") as fh:
            backlink = os.path.realpath(fh.read().strip())
        if backlink != os.path.join(os.path.realpath(git_root), ".git"):
            return git_root

        # Bare-repo worktrees: commondir isn't inside a working directory
        if os.path.basename(common_dir) != ".git":
            return common_dir

        return os.path.dirname(common_dir)

    except (OSError, IsADirectoryError):
        # .git is a directory (not a worktree) or file unreadable
        return git_root


def find_canonical_git_root(start_path: str) -> Optional[str]:
    """
    Like find_git_root but returns the main repo root for worktrees.
    All worktrees of the same repo map to the same canonical root.
    Use this for project-scoped state (memory, config, session storage).
    """
    root = find_git_root(start_path)
    if root is None:
        return None
    return _resolve_canonical_root(root)


# ─── ASYNC GIT QUERIES ────────────────────────────────────────────────────────

async def _run_git(*args: str, cwd: Optional[str] = None) -> tuple[int, str]:
    """Run a git command. Returns (returncode, stdout.strip())."""
    try:
        proc = await asyncio.create_subprocess_exec(
            "git", *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
            cwd=cwd,
        )
        stdout, _ = await proc.communicate()
        return proc.returncode or 0, stdout.decode(errors="replace").strip()
    except FileNotFoundError:
        return 1, ""
    except Exception as exc:
        log.debug("[git] Command failed: git %s — %s", " ".join(args), exc)
        return 1, ""


async def get_branch(cwd: Optional[str] = None) -> str:
    """Return current branch name, or 'HEAD' if detached."""
    code, out = await _run_git("rev-parse", "--abbrev-ref", "HEAD", cwd=cwd)
    return out if code == 0 and out else "HEAD"


async def get_head(cwd: Optional[str] = None) -> str:
    """Return current HEAD commit hash (short)."""
    code, out = await _run_git("rev-parse", "--short", "HEAD", cwd=cwd)
    return out if code == 0 else ""


async def get_remote_url(cwd: Optional[str] = None) -> Optional[str]:
    """Return origin remote URL, or None if not set."""
    code, out = await _run_git("remote", "get-url", "origin", cwd=cwd)
    return out if code == 0 and out else None


async def is_git_repo(path: str) -> bool:
    """Return True if `path` is inside a git repository."""
    return find_git_root(path) is not None


async def get_is_clean(cwd: Optional[str] = None) -> bool:
    """Return True if the working tree has no uncommitted changes."""
    code, out = await _run_git("status", "--porcelain", cwd=cwd)
    return code == 0 and out == ""


async def has_unpushed_commits(cwd: Optional[str] = None) -> bool:
    """Return True if there are local commits not yet pushed to origin."""
    code, out = await _run_git("log", "@{u}..", "--oneline", cwd=cwd)
    return code == 0 and bool(out)


async def is_bare_repo(cwd: Optional[str] = None) -> bool:
    """Return True if the current directory is a bare git repo (attack vector)."""
    code, out = await _run_git("rev-parse", "--is-bare-repository", cwd=cwd)
    return code == 0 and out == "true"


# ─── REMOTE URL NORMALISATION ─────────────────────────────────────────────────

_SSH_RE   = re.compile(r"^git@([^:]+):(.+?)(?:\.git)?$")
_HTTPS_RE = re.compile(r"^(?:https?|ssh)://(?:[^@]+@)?([^/]+)/(.+?)(?:\.git)?$")


def normalize_git_remote_url(url: str) -> Optional[str]:
    """
    Normalise a git remote URL to `host/owner/repo` (lowercase, no .git).
    Handles SSH (git@host:owner/repo.git) and HTTPS/SSH-URL formats.
    Returns None for unrecognised formats.
    """
    trimmed = url.strip()
    if not trimmed:
        return None

    m = _SSH_RE.match(trimmed)
    if m:
        return f"{m.group(1)}/{m.group(2)}".lower()

    m = _HTTPS_RE.match(trimmed)
    if m:
        return f"{m.group(1)}/{m.group(2)}".lower()

    return None


async def get_repo_remote_hash(cwd: Optional[str] = None) -> Optional[str]:
    """
    Return first 16 chars of SHA-256 of the normalised remote URL.
    Stable across SSH/HTTPS; doesn't expose repo name in logs.
    """
    remote = await get_remote_url(cwd)
    if not remote:
        return None
    normalized = normalize_git_remote_url(remote)
    if not normalized:
        return None
    digest = hashlib.sha256(normalized.encode()).hexdigest()
    return digest[:16]
