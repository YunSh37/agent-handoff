#!/usr/bin/env python3
"""Zero-dependency cross-agent session handoff CLI (Claude Code, Codex, Antigravity, Cursor).

Solves session continuity across AI coding agents while automatically redacting
secrets/tokens before context leaves a session.
"""

from __future__ import annotations

import argparse
import dataclasses
import datetime as dt
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, Sequence

__version__ = "0.1.0"
SCHEMA_VERSION = "1.0"
SUPPORTED_TARGETS: tuple[str, ...] = ("claude", "codex", "antigravity", "cursor")
MAX_SCAN_FILE_BYTES = 512 * 1024
DEFAULT_FILE_LIMIT = 80
DEFAULT_TODO_LIMIT = 40

TODO_PATTERN = re.compile(r"\b(TODO|FIXME|XXX|HACK)\b(?:\s*[:\-]\s*|\s+)?(.*)")

# Order matters: longer / multi-line / assignment patterns first, then standalone prefixes.
_PRIVATE_KEY_BLOCK_RE = re.compile(
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----"
)
_PRIVATE_KEY_HEADER_RE = re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----")
_GITHUB_PAT_RE = re.compile(r"\bgithub_pat_[A-Za-z0-9_]{16,}\b")
_GITHUB_CLASSIC_RE = re.compile(r"\bgh[pousr]_[A-Za-z0-9]{12,}\b")
_KAGGLE_TOKEN_RE = re.compile(r"\bKGAT_[A-Za-z0-9]{12,}\b")
_GOOGLE_KEY_RE = re.compile(r"\bAIza[0-9A-Za-z\-_]{16,}\b")
_SK_KEY_RE = re.compile(r"\bsk-(?:proj-|ant-[a-z0-9]+-)?[A-Za-z0-9\-_]{16,}\b")
_AWS_KEY_RE = re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")
_BEARER_RE = re.compile(
    r"(?i)\b(Authorization\s*:\s*Bearer)\s+([A-Za-z0-9\-._~+/=]{8,})"
)

_SENSITIVE_KEY_NAMES = (
    r"(?:PASSWORD|PASSWD|SECRET|SECRET_KEY|API_KEY|ACCESS_KEY|AUTH_TOKEN|"
    r"GITHUB_TOKEN|GH_TOKEN|KAGGLE_KEY|GMAIL_APP_PASSWORD|PRIVATE_KEY)"
)
_QUOTED_ASSIGN_RE = re.compile(
    rf"(?i)\b([A-Za-z0-9_]*{_SENSITIVE_KEY_NAMES}[A-Za-z0-9_]*)\s*([:=])\s*(['\"])([^'\"\r\n]{{4,}})\3"
)
_JSON_QUOTED_ASSIGN_RE = re.compile(
    rf"""(?i)(["'](?:[a-z0-9_]*{_SENSITIVE_KEY_NAMES.lower()}[a-z0-9_]*)["']\s*:\s*)(['"])([^'"\r\n]{{4,}})\2"""
)
_UNQUOTED_ENV_ASSIGN_RE = re.compile(
    rf"(?im)^(\s*(?:export\s+)?[A-Z0-9_]*{_SENSITIVE_KEY_NAMES}[A-Z0-9_]*\b\s*=\s*)([^\s#'\"\r\n]{{4,}})"
)
_REDACTED_MARKER_RE = re.compile(r"^\[REDACTED:[A-Z0-9_]+\]$")

_SCAN_RULES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("Private Key Block", _PRIVATE_KEY_HEADER_RE),
    ("GitHub Fine-Grained Token", _GITHUB_PAT_RE),
    ("GitHub Token", _GITHUB_CLASSIC_RE),
    ("Kaggle API Token", _KAGGLE_TOKEN_RE),
    ("Google API Key", _GOOGLE_KEY_RE),
    ("sk- Secret Key", _SK_KEY_RE),
    ("AWS Access Key", _AWS_KEY_RE),
    ("Bearer Token", _BEARER_RE),
    ("Secret Assignment", _QUOTED_ASSIGN_RE),
    ("JSON Secret Assignment", _JSON_QUOTED_ASSIGN_RE),
    ("Env Secret Assignment", _UNQUOTED_ENV_ASSIGN_RE),
)


class HandoffError(Exception):
    """Domain error raised for invalid repositories, missing artifacts, or git failures."""


@dataclasses.dataclass(frozen=True)
class SecretFinding:
    """Single unredacted secret finding detected during handoff validation."""

    file_path: str
    rule_name: str
    line_number: int


@dataclasses.dataclass
class RedactionReport:
    """Tracks redaction counts and categories applied during snapshot generation."""

    redacted_count: int = 0
    categories: list[str] = dataclasses.field(default_factory=list)

    def record(self, category: str, count: int = 1) -> None:
        if count <= 0:
            return
        self.redacted_count += count
        if category not in self.categories:
            self.categories.append(category)


def redact_secrets(text: str, tracker: RedactionReport | None = None) -> str:
    """Scrub sensitive tokens and secret assignments while remaining idempotent."""
    if not text:
        return text

    result = text

    def _sub_simple(pattern: re.Pattern[str], label: str, replacement: str) -> None:
        nonlocal result
        result, count = pattern.subn(replacement, result)
        if tracker and count:
            tracker.record(label, count)

    def _replace_quoted_assign(match: re.Match[str]) -> str:
        key, sep, _quote, val = match.group(1), match.group(2), match.group(3), match.group(4)
        if _REDACTED_MARKER_RE.match(val.strip()):
            return f"{key} {sep} {val.strip()}"
        if tracker:
            tracker.record("SECRET_ASSIGNMENT", 1)
        return f"{key} {sep} [REDACTED:SECRET_ASSIGNMENT]"

    def _replace_json_assign(match: re.Match[str]) -> str:
        prefix, _quote, val = match.group(1), match.group(2), match.group(3)
        if _REDACTED_MARKER_RE.match(val.strip()):
            return match.group(0)
        if tracker:
            tracker.record("SECRET_ASSIGNMENT", 1)
        return f"{prefix}[REDACTED:SECRET_ASSIGNMENT]"

    def _replace_env_assign(match: re.Match[str]) -> str:
        prefix, val = match.group(1), match.group(2)
        if _REDACTED_MARKER_RE.match(val.strip()):
            return match.group(0)
        if tracker:
            tracker.record("ENV_SECRET", 1)
        return f"{prefix}[REDACTED:ENV_SECRET]"

    def _replace_bearer(match: re.Match[str]) -> str:
        header, token = match.group(1), match.group(2)
        if _REDACTED_MARKER_RE.match(token.strip()):
            return match.group(0)
        if tracker:
            tracker.record("BEARER_TOKEN", 1)
        return f"{header} [REDACTED:BEARER_TOKEN]"

    _sub_simple(_PRIVATE_KEY_BLOCK_RE, "PRIVATE_KEY", "[REDACTED:PRIVATE_KEY]")
    _sub_simple(_PRIVATE_KEY_HEADER_RE, "PRIVATE_KEY", "[REDACTED:PRIVATE_KEY_HEADER]")
    # Scrub assignments first so embedded tokens become unquoted [REDACTED:...] placeholders.
    result = _QUOTED_ASSIGN_RE.sub(_replace_quoted_assign, result)
    result = _JSON_QUOTED_ASSIGN_RE.sub(_replace_json_assign, result)
    result = _UNQUOTED_ENV_ASSIGN_RE.sub(_replace_env_assign, result)
    result = _BEARER_RE.sub(_replace_bearer, result)
    _sub_simple(_GITHUB_PAT_RE, "GITHUB_PAT", "[REDACTED:GITHUB_PAT]")
    _sub_simple(_GITHUB_CLASSIC_RE, "GITHUB_TOKEN", "[REDACTED:GITHUB_TOKEN]")
    _sub_simple(_KAGGLE_TOKEN_RE, "KAGGLE_TOKEN", "[REDACTED:KAGGLE_TOKEN]")
    _sub_simple(_GOOGLE_KEY_RE, "GOOGLE_API_KEY", "[REDACTED:GOOGLE_API_KEY]")
    _sub_simple(_SK_KEY_RE, "SK_SECRET_KEY", "[REDACTED:SK_SECRET_KEY]")
    _sub_simple(_AWS_KEY_RE, "AWS_ACCESS_KEY", "[REDACTED:AWS_ACCESS_KEY]")
    return result


def scan_text_for_secrets(text: str, label: str = "<memory>") -> list[SecretFinding]:
    """Scan text line-by-line for unredacted secret patterns."""
    findings: list[SecretFinding] = []
    for line_no, line in enumerate(text.splitlines(), start=1):
        for rule_name, pattern in _SCAN_RULES:
            match = pattern.search(line)
            if not match:
                continue
            if rule_name in ("Secret Assignment", "JSON Secret Assignment") and _REDACTED_MARKER_RE.match(
                match.group(match.lastindex or 0).strip()
            ):
                continue
            if rule_name == "Env Secret Assignment" and _REDACTED_MARKER_RE.match(match.group(2).strip()):
                continue
            if rule_name == "Bearer Token" and _REDACTED_MARKER_RE.match(match.group(2).strip()):
                continue
            findings.append(SecretFinding(file_path=label, rule_name=rule_name, line_number=line_no))
    return findings


def _run_git(repo: Path, args: Sequence[str], check: bool = True) -> subprocess.CompletedProcess[str]:
    cmd = ["git", "-c", "core.quotePath=false", *args]
    try:
        proc = subprocess.run(
            cmd,
            cwd=str(repo),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=15,
        )
    except FileNotFoundError as exc:
        raise HandoffError("`git` executable not found on PATH.") from exc
    except subprocess.TimeoutExpired as exc:
        raise HandoffError(f"git command timed out: {' '.join(args)}") from exc

    if check and proc.returncode != 0:
        err = (proc.stderr or proc.stdout).strip()
        raise HandoffError(f"git {' '.join(args)} failed: {err}")
    return proc


def _resolve_repo_root(repo: Path) -> Path:
    if not repo.exists():
        raise HandoffError(f"Repository path does not exist: {repo}")
    proc = _run_git(repo, ["rev-parse", "--is-inside-work-tree"], check=False)
    if proc.returncode != 0 or proc.stdout.strip().lower() != "true":
        raise HandoffError(f"Not a git repository: {repo}")
    top = _run_git(repo, ["rev-parse", "--show-toplevel"])
    return Path(top.stdout.strip()).resolve()


def _detect_branch_and_head(repo_root: Path, tracker: RedactionReport) -> tuple[str, dict[str, str]]:
    head_proc = _run_git(repo_root, ["log", "-1", "--format=%H%n%h%n%s%n%cI"], check=False)
    has_head = head_proc.returncode == 0 and bool(head_proc.stdout.strip())

    branch_proc = _run_git(repo_root, ["rev-parse", "--abbrev-ref", "HEAD"], check=False)
    branch = branch_proc.stdout.strip() if branch_proc.returncode == 0 else ""
    if not branch or branch == "HEAD":
        sym_proc = _run_git(repo_root, ["symbolic-ref", "--short", "HEAD"], check=False)
        if sym_proc.returncode == 0 and sym_proc.stdout.strip():
            branch = sym_proc.stdout.strip()
        elif has_head:
            short = head_proc.stdout.splitlines()[1].strip()
            branch = f"HEAD (detached at {short})"
        else:
            branch = "HEAD (unborn)"

    branch = redact_secrets(branch, tracker)

    if not has_head:
        return branch, {
            "sha": "UNBORN",
            "short_sha": "UNBORN",
            "subject": "(no commits yet)",
            "committed_at": "",
        }

    lines = head_proc.stdout.splitlines()
    sha = lines[0].strip() if len(lines) > 0 else "UNKNOWN"
    short_sha = lines[1].strip() if len(lines) > 1 else sha[:7]
    subject = redact_secrets(lines[2].strip() if len(lines) > 2 else "", tracker)
    committed_at = lines[3].strip() if len(lines) > 3 else ""
    return branch, {
        "sha": sha,
        "short_sha": short_sha,
        "subject": subject,
        "committed_at": committed_at,
    }


def _parse_porcelain_status(
    repo_root: Path,
    tracker: RedactionReport,
) -> tuple[dict[str, list[str]], list[dict[str, str]], list[str]]:
    proc = _run_git(repo_root, ["status", "--porcelain=v1"])
    buckets: dict[str, list[str]] = {
        "staged": [],
        "unstaged": [],
        "untracked": [],
        "conflicted": [],
    }
    modified_files: list[dict[str, str]] = []
    scan_paths: list[str] = []
    seen_paths: set[str] = set()

    for raw_line in proc.stdout.splitlines():
        if len(raw_line) < 4:
            continue
        xy = raw_line[:2]
        payload = raw_line[3:]
        if " -> " in payload:
            _old_path, new_path = payload.split(" -> ", 1)
            rel_path = new_path.strip()
        else:
            rel_path = payload.strip()

        clean_path = redact_secrets(rel_path, tracker)
        x, y = xy[0], xy[1]

        if xy == "??":
            buckets["untracked"].append(clean_path)
        elif "U" in xy or xy in ("AA", "DD"):
            buckets["conflicted"].append(clean_path)
        else:
            if x != " ":
                buckets["staged"].append(clean_path)
            if y != " ":
                buckets["unstaged"].append(clean_path)

        status_label = xy.strip() or "?"
        modified_files.append({"status": status_label, "path": clean_path})

        if "D" not in xy and rel_path not in seen_paths:
            seen_paths.add(rel_path)
            scan_paths.append(rel_path)

    return buckets, modified_files, scan_paths


def _collect_diff_stat(repo_root: Path, has_head: bool, tracker: RedactionReport) -> str:
    if has_head:
        proc = _run_git(repo_root, ["diff", "HEAD", "--stat"], check=False)
        stat = proc.stdout.strip() if proc.returncode == 0 else ""
    else:
        staged = _run_git(repo_root, ["diff", "--cached", "--stat"], check=False).stdout.strip()
        unstaged = _run_git(repo_root, ["diff", "--stat"], check=False).stdout.strip()
        parts = [p for p in (staged, unstaged) if p]
        stat = "\n".join(parts)

    if not stat:
        return "(no tracked diff)"
    return redact_secrets(stat, tracker)


def _scan_todos_in_files(
    repo_root: Path,
    rel_paths: Sequence[str],
    tracker: RedactionReport,
) -> list[dict[str, Any]]:
    todos: list[dict[str, Any]] = []
    for rel_path in rel_paths:
        full_path = repo_root / rel_path
        if not full_path.is_file() or full_path.is_symlink():
            continue
        try:
            if full_path.stat().st_size > MAX_SCAN_FILE_BYTES:
                continue
            raw_bytes = full_path.read_bytes()
        except OSError:
            continue

        if b"\x00" in raw_bytes[:4096]:
            continue

        text = raw_bytes.decode("utf-8", errors="replace")
        clean_file = redact_secrets(rel_path, tracker)
        for line_no, line in enumerate(text.splitlines(), start=1):
            match = TODO_PATTERN.search(line)
            if not match:
                continue
            tag = match.group(1).upper()
            snippet = match.group(2).strip() or line.strip()
            snippet = redact_secrets(snippet, tracker)
            if len(snippet) > 180:
                snippet = snippet[:177] + "..."
            todos.append(
                {
                    "file": clean_file,
                    "line": line_no,
                    "tag": tag,
                    "text": snippet,
                }
            )
    return todos


def _render_markdown_from_dict(data: dict[str, Any], max_todos: int | None = None, max_files: int | None = None, max_diff_lines: int | None = None, snippet_limit: int = 180, minimal: bool = False) -> str:
    head = data["head_commit"]
    status = data["status_summary"]
    mod_files = data["modified_files"]
    todos = data["todos"]
    next_steps = data["next_steps"]
    decisions = data.get("decisions", [])
    blockers = data.get("blockers", [])
    redaction = data.get("redaction", {"redacted_count": 0, "categories": []})

    lines: list[str] = [
        f"# Session Handoff — {data['repo_name']}",
        "",
        f"- **Generated**: {data['generated_at']}",
        f"- **Branch**: `{data['branch']}`",
        f"- **HEAD Commit**: `{head['short_sha']}` — {head['subject']}",
    ]
    if data.get("goal"):
        lines.append(f"- **Goal**: {data['goal']}")
    lines.append(
        f"- **Secret Scrubbing**: {redaction['redacted_count']} redaction(s)"
        + (f" ({', '.join(redaction['categories'])})" if redaction.get("categories") else "")
    )
    lines.append("")

    if minimal:
        lines.extend(
            [
                "## Workspace Summary",
                (
                    f"- Staged: {len(status['staged'])}, Unstaged: {len(status['unstaged'])}, "
                    f"Untracked: {len(status['untracked'])}, Conflicted: {len(status['conflicted'])}, "
                    f"TODOs: {len(todos)}"
                ),
            ]
        )
        if mod_files:
            file_cap = 5 if max_files is None else max_files
            shown = mod_files[:file_cap]
            if shown:
                lines.append("- Key Files: " + ", ".join(f"`{f['path']}`" for f in shown))
            if len(mod_files) > len(shown):
                lines.append(f"  (+{len(mod_files) - len(shown)} more file(s))")
        lines.extend(["", "## Next Steps"])
        if next_steps:
            for idx, step in enumerate(next_steps, start=1):
                lines.append(f"{idx}. {step}")
        else:
            lines.append("1. Review workspace status and continue remaining tasks.")
        return "\n".join(lines) + "\n"

    lines.extend(
        [
            "## Workspace Status",
            (
                f"- Staged: {len(status['staged'])} | "
                f"Unstaged: {len(status['unstaged'])} | "
                f"Untracked: {len(status['untracked'])} | "
                f"Conflicted: {len(status['conflicted'])}"
            ),
        ]
    )

    if mod_files:
        shown_files = mod_files[:max_files] if max_files is not None else mod_files
        lines.append("- Modified Files:")
        for item in shown_files:
            lines.append(f"  - `{item['status']}` `{item['path']}`")
        if len(mod_files) > len(shown_files):
            lines.append(f"  - ... (+{len(mod_files) - len(shown_files)} more file(s))")
    else:
        lines.append("- Modified Files: (clean working tree)")

    diff_text = data.get("diff_stat", "(no tracked diff)")
    diff_lines = diff_text.splitlines()
    if max_diff_lines is not None and len(diff_lines) > max_diff_lines:
        if max_diff_lines <= 1:
            diff_lines = [diff_lines[-1]]
        else:
            kept = diff_lines[: max_diff_lines - 1]
            omitted = len(diff_lines) - max_diff_lines
            summary_line = diff_lines[-1]
            diff_lines = [*kept, f"... ({omitted} more diff line(s) omitted)", summary_line]

    lines.extend(["", "## Diff Stat", "```text", *diff_lines, "```", ""])

    lines.append("## TODO / FIXME in Changed Files")
    if todos:
        shown_todos = todos[:max_todos] if max_todos is not None else todos
        for item in shown_todos:
            text = item["text"]
            if len(text) > snippet_limit:
                text = text[: max(0, snippet_limit - 3)] + "..."
            lines.append(f"- `{item['file']}:{item['line']}` **[{item['tag']}]** {text}")
        if len(todos) > len(shown_todos):
            lines.append(f"- ... (+{len(todos) - len(shown_todos)} more TODO/FIXME item(s))")
    else:
        lines.append("- (none found in changed files)")

    if decisions:
        lines.extend(["", "## Key Decisions"])
        for dec in decisions:
            lines.append(f"- {dec}")

    if blockers:
        lines.extend(["", "## Blockers"])
        for blk in blockers:
            lines.append(f"- {blk}")

    lines.extend(["", "## Next Steps"])
    if next_steps:
        for idx, step in enumerate(next_steps, start=1):
            lines.append(f"{idx}. {step}")
    else:
        lines.append("1. Inspect modified files and verify pending changes with tests.")

    return "\n".join(lines) + "\n"


def _compact_markdown_to_budget(data: dict[str, Any], max_chars: int) -> tuple[str, bool]:
    full_md = _render_markdown_from_dict(data)
    if max_chars <= 0 or len(full_md) <= max_chars:
        return full_md, False

    tiers: tuple[dict[str, Any], ...] = (
        {"max_todos": 10, "max_files": 20, "max_diff_lines": 15, "snippet_limit": 100, "minimal": False},
        {"max_todos": 5, "max_files": 10, "max_diff_lines": 8, "snippet_limit": 70, "minimal": False},
        {"max_todos": 2, "max_files": 6, "max_diff_lines": 1, "snippet_limit": 50, "minimal": False},
        {"max_todos": 0, "max_files": 5, "max_diff_lines": 1, "snippet_limit": 40, "minimal": True},
        {"max_todos": 0, "max_files": 0, "max_diff_lines": 0, "snippet_limit": 30, "minimal": True},
    )
    candidate = full_md
    for opts in tiers:
        candidate = _render_markdown_from_dict(data, **opts)
        if len(candidate) <= max_chars:
            return candidate, True

    marker = "\n...[compacted]\n"
    if max_chars <= len(marker):
        return candidate[:max_chars], True
    return candidate[: max_chars - len(marker)].rstrip() + marker, True


def create_snapshot(
    repo: Path,
    out_dir: Path | None = None,
    next_steps: Sequence[str] = (),
    goal: str = "",
    decisions: Sequence[str] = (),
    blockers: Sequence[str] = (),
    max_chars: int | None = None,
) -> tuple[Path, Path, dict[str, Any]]:
    """Inspect a git repo, scrub secrets, and write HANDOFF.md + handoff.json."""
    repo_root = _resolve_repo_root(repo)
    target_dir = out_dir.resolve() if out_dir else repo_root
    target_dir.mkdir(parents=True, exist_ok=True)

    tracker = RedactionReport()
    branch, head_commit = _detect_branch_and_head(repo_root, tracker)
    has_head = head_commit["sha"] != "UNBORN"
    status_summary, modified_files, scan_paths = _parse_porcelain_status(repo_root, tracker)
    diff_stat = _collect_diff_stat(repo_root, has_head=has_head, tracker=tracker)
    todos = _scan_todos_in_files(repo_root, scan_paths, tracker)

    clean_goal = redact_secrets(goal.strip(), tracker) if goal else ""
    clean_next_steps = [redact_secrets(s.strip(), tracker) for s in next_steps if s.strip()]
    clean_decisions = [redact_secrets(d.strip(), tracker) for d in decisions if d.strip()]
    clean_blockers = [redact_secrets(b.strip(), tracker) for b in blockers if b.strip()]

    generated_at = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    bundle: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "tool": "agent-handoff",
        "generated_at": generated_at,
        "repo_name": redact_secrets(repo_root.name, tracker),
        "branch": branch,
        "head_commit": head_commit,
        "goal": clean_goal,
        "status_summary": status_summary,
        "modified_files": modified_files[:DEFAULT_FILE_LIMIT],
        "modified_files_total": len(modified_files),
        "diff_stat": diff_stat,
        "todos": todos[:DEFAULT_TODO_LIMIT],
        "todos_total": len(todos),
        "decisions": clean_decisions,
        "blockers": clean_blockers,
        "next_steps": clean_next_steps,
        "redaction": {
            "redacted_count": tracker.redacted_count,
            "categories": tracker.categories,
        },
        "compaction": {
            "compacted": False,
            "max_chars": max_chars,
            "original_chars": 0,
            "final_chars": 0,
        },
    }

    full_md = _render_markdown_from_dict(bundle)
    original_chars = len(full_md)
    if max_chars is not None:
        handoff_md, compacted = _compact_markdown_to_budget(bundle, max_chars)
        if compacted:
            diff_lines = bundle["diff_stat"].splitlines()
            if len(diff_lines) > 10:
                bundle["diff_stat"] = "\n".join([*diff_lines[:8], "... (compacted)", diff_lines[-1]])
            bundle["todos"] = bundle["todos"][:10]
    else:
        handoff_md = full_md
        compacted = False

    bundle["compaction"] = {
        "compacted": compacted,
        "max_chars": max_chars,
        "original_chars": original_chars,
        "final_chars": len(handoff_md),
    }

    # Final defense-in-depth scrub before writing to disk.
    handoff_md = redact_secrets(handoff_md)
    json_text = redact_secrets(json.dumps(bundle, indent=2, ensure_ascii=False) + "\n")

    md_path = target_dir / "HANDOFF.md"
    json_path = target_dir / "handoff.json"
    md_path.write_text(handoff_md, encoding="utf-8")
    json_path.write_text(json_text, encoding="utf-8")
    return md_path, json_path, bundle


def _load_handoff_input(input_path: Path) -> tuple[dict[str, Any] | None, str]:
    resolved = input_path.resolve()
    if resolved.is_dir():
        json_file = resolved / "handoff.json"
        md_file = resolved / "HANDOFF.md"
        if json_file.is_file():
            data = json.loads(json_file.read_text(encoding="utf-8"))
            md_text = md_file.read_text(encoding="utf-8") if md_file.is_file() else _render_markdown_from_dict(data)
            return data, md_text
        if md_file.is_file():
            return None, md_file.read_text(encoding="utf-8")
        raise HandoffError(f"No handoff.json or HANDOFF.md found in directory: {resolved}")

    if not resolved.is_file():
        raise HandoffError(f"Handoff input does not exist: {resolved}")

    if resolved.suffix.lower() == ".json":
        data = json.loads(resolved.read_text(encoding="utf-8"))
        return data, _render_markdown_from_dict(data)
    return None, resolved.read_text(encoding="utf-8")


def render_resume_prompt(
    target: str,
    input_path: Path,
    max_chars: int | None = None,
) -> str:
    """Render a ready-to-paste session resumption prompt for a target AI coding agent."""
    target_norm = target.strip().lower()
    if target_norm not in SUPPORTED_TARGETS:
        raise HandoffError(
            f"Unsupported target '{target}'. Choose from: {', '.join(SUPPORTED_TARGETS)}"
        )

    data, md_text = _load_handoff_input(input_path)

    if data is None:
        context_block = redact_secrets(md_text.strip())
        files_hint = "(see handoff context above)"
        steps_block = "Follow the Next Steps listed in the handoff above."
    else:
        context_block = redact_secrets(_render_markdown_from_dict(data).strip())
        mod_files = data.get("modified_files", [])
        if target_norm == "cursor":
            files_hint = " ".join(f"@{item['path']}" for item in mod_files[:15]) or "(clean working tree)"
        else:
            files_hint = ", ".join(item["path"] for item in mod_files[:15]) or "(clean working tree)"
        steps = data.get("next_steps") or ["Inspect workspace state and continue pending work."]
        steps_block = "\n".join(f"{idx}. {step}" for idx, step in enumerate(steps, start=1))

    templates: dict[str, tuple[str, str]] = {
        "claude": (
            "You are resuming an active engineering session in Claude Code CLI.",
            (
                "Instructions for Claude Code:\n"
                "- Read CLAUDE.md (if present) and verify `git status` before making edits.\n"
                "- Focus on the Next Steps below and run relevant tests after changes.\n"
                "- Before exiting, refresh the handoff with `agent-handoff snapshot`."
            ),
        ),
        "codex": (
            "You are resuming an engineering task in OpenAI Codex CLI.",
            (
                "Execution Directive for Codex:\n"
                "- Check AGENTS.md conventions if present in the repo.\n"
                "- Operate strictly on the relevant files, execute tests to verify, and summarize diffs cleanly."
            ),
        ),
        "antigravity": (
            "You are resuming an engineering workflow in Antigravity.",
            (
                "Antigravity Continuity Protocol:\n"
                "- Review the captured git state, blockers, and TODOs before modifying code.\n"
                "- Validate changes via isolated unit tests and secret checks before final delivery."
            ),
        ),
        "cursor": (
            "You are resuming an active workspace session in Cursor.",
            (
                f"Cursor Context Hints: @HANDOFF.md {files_hint}\n"
                "- Inspect the referenced files first, complete the Next Steps checklist, and verify locally."
            ),
        ),
    }

    preamble, footer = templates[target_norm]
    prompt = "\n\n".join(
        [
            f"# Resume Context ({target_norm})",
            preamble,
            "## Captured Session Snapshot",
            context_block,
            "## Priority Next Steps",
            steps_block,
            footer,
        ]
    ) + "\n"

    prompt = redact_secrets(prompt)
    if max_chars is not None and max_chars > 0 and len(prompt) > max_chars:
        if data is not None:
            compact_ctx, _ = _compact_markdown_to_budget(data, max(120, max_chars // 2))
            prompt = redact_secrets(
                "\n\n".join(
                    [
                        f"# Resume Context ({target_norm})",
                        preamble,
                        compact_ctx.strip(),
                        "## Priority Next Steps",
                        steps_block,
                        footer,
                    ]
                )
                + "\n"
            )
        if len(prompt) > max_chars:
            marker = "\n...[compacted]\n"
            prompt = (
                prompt[:max_chars]
                if max_chars <= len(marker)
                else prompt[: max_chars - len(marker)].rstrip() + marker
            )
    return prompt


def _iter_json_strings(obj: Any) -> list[str]:
    """Extract all string values recursively from parsed JSON for unescaped secret scanning."""
    values: list[str] = []
    if isinstance(obj, str):
        values.append(obj)
    elif isinstance(obj, list):
        for item in obj:
            values.extend(_iter_json_strings(item))
    elif isinstance(obj, dict):
        for val in obj.values():
            values.extend(_iter_json_strings(val))
    return values


def check_handoff(path: Path, strict: bool = False) -> dict[str, Any]:
    """Validate handoff completeness and guarantee zero unredacted secret leaks."""
    resolved = path.resolve()
    errors: list[str] = []
    warnings: list[str] = []
    findings: list[SecretFinding] = []
    checked_files: list[str] = []

    if not resolved.exists():
        return {
            "passed": False,
            "errors": [f"Target path does not exist: {resolved}"],
            "warnings": [],
            "secret_findings": [],
            "checked_files": [],
        }

    json_path: Path | None = None
    md_path: Path | None = None
    if resolved.is_dir():
        json_path = resolved / "handoff.json"
        md_path = resolved / "HANDOFF.md"
        if not json_path.is_file():
            errors.append(f"Missing required bundle file: {json_path}")
        if not md_path.is_file():
            errors.append(f"Missing required bundle file: {md_path}")
    elif resolved.suffix.lower() == ".json":
        json_path = resolved
    else:
        md_path = resolved

    if json_path and json_path.is_file():
        checked_files.append(str(json_path))
        json_text = json_path.read_text(encoding="utf-8", errors="replace")
        if not json_text.strip():
            errors.append("handoff.json is empty.")
        else:
            findings.extend(scan_text_for_secrets(json_text, str(json_path)))
            try:
                data = json.loads(json_text)
            except json.JSONDecodeError as exc:
                errors.append(f"Invalid JSON in handoff.json: {exc}")
                data = None

            if isinstance(data, dict):
                raw_rules = {(f.file_path, f.rule_name) for f in findings}
                for json_str in _iter_json_strings(data):
                    for jf in scan_text_for_secrets(json_str, str(json_path)):
                        if (jf.file_path, jf.rule_name) not in raw_rules:
                            findings.append(jf)
                            raw_rules.add((jf.file_path, jf.rule_name))
                required_keys = (
                    "schema_version",
                    "generated_at",
                    "repo_name",
                    "branch",
                    "head_commit",
                    "modified_files",
                    "diff_stat",
                    "todos",
                    "next_steps",
                )
                for key in required_keys:
                    if key not in data:
                        errors.append(f"handoff.json missing required key: '{key}'")
                for non_empty_key in ("generated_at", "repo_name", "branch"):
                    if not str(data.get(non_empty_key, "")).strip():
                        errors.append(f"handoff.json field '{non_empty_key}' must be non-empty.")
                head = data.get("head_commit")
                if not isinstance(head, dict) or not head.get("sha") or not head.get("short_sha"):
                    errors.append("handoff.json 'head_commit' must include 'sha' and 'short_sha'.")
                for list_key in ("modified_files", "todos", "next_steps"):
                    if list_key in data and not isinstance(data[list_key], list):
                        errors.append(f"handoff.json '{list_key}' must be a JSON array.")
                if isinstance(data.get("next_steps"), list) and len(data["next_steps"]) == 0:
                    msg = "handoff.json has empty 'next_steps' (recommended for continuity)."
                    if strict:
                        errors.append(msg)
                    else:
                        warnings.append(msg)
            elif data is not None:
                errors.append("handoff.json root must be a JSON object.")

    if md_path and md_path.is_file():
        checked_files.append(str(md_path))
        md_text = md_path.read_text(encoding="utf-8", errors="replace")
        if not md_text.strip():
            errors.append("HANDOFF.md is empty.")
        else:
            findings.extend(scan_text_for_secrets(md_text, str(md_path)))
            markers = (
                ("# Session Handoff", "Branch")
                if "...[compacted]" in md_text
                else ("# Session Handoff", "Branch", "HEAD Commit", "Next Steps")
            )
            for expected_marker in markers:
                if expected_marker not in md_text:
                    errors.append(f"HANDOFF.md missing expected section/marker: '{expected_marker}'")

    for f in findings:
        errors.append(
            f"Secret leak detected in {f.file_path}:{f.line_number} ({f.rule_name})"
        )

    return {
        "passed": len(errors) == 0,
        "errors": errors,
        "warnings": warnings,
        "secret_findings": [dataclasses.asdict(f) for f in findings],
        "checked_files": checked_files,
    }


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="agent-handoff",
        description=(
            "Cross-agent session handoff CLI for Claude Code, Codex, Antigravity, and Cursor."
        ),
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    snap = subparsers.add_parser(
        "snapshot",
        help="Inspect a git repo and write redacted HANDOFF.md + handoff.json.",
    )
    snap.add_argument("--repo", type=Path, default=Path("."), help="Path inside target git repo (default: .)")
    snap.add_argument(
        "--out-dir",
        type=Path,
        default=None,
        help="Output directory for HANDOFF.md and handoff.json (default: repo root)",
    )
    snap.add_argument(
        "--next-steps",
        nargs="+",
        action="extend",
        default=[],
        help="Explicit next steps for the receiving agent (repeatable or space-separated)",
    )
    snap.add_argument("--goal", default="", help="Optional session goal or ticket summary")
    snap.add_argument(
        "--decisions",
        nargs="+",
        action="extend",
        default=[],
        help="Key architectural decisions made in this session",
    )
    snap.add_argument(
        "--blockers",
        nargs="+",
        action="extend",
        default=[],
        help="Known blockers or open risks",
    )
    snap.add_argument(
        "--max-chars",
        type=int,
        default=None,
        help="Compact HANDOFF.md within this character/token budget",
    )

    res = subparsers.add_parser(
        "resume",
        help="Render a ready-to-paste prompt for a target AI coding agent.",
    )
    res.add_argument(
        "--target",
        required=True,
        choices=SUPPORTED_TARGETS,
        help="Target agent format",
    )
    res.add_argument(
        "--input",
        type=Path,
        default=Path("."),
        help="Directory with handoff.json/HANDOFF.md, or direct path to a handoff file",
    )
    res.add_argument(
        "--max-chars",
        type=int,
        default=None,
        help="Compact rendered prompt within this character limit",
    )
    res.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Optional output file path instead of stdout",
    )

    chk = subparsers.add_parser(
        "check",
        help="Validate a handoff bundle for completeness and zero secret leaks.",
    )
    chk.add_argument(
        "path",
        nargs="?",
        type=Path,
        default=Path("."),
        help="Handoff directory or file to validate (default: .)",
    )
    chk.add_argument(
        "--strict",
        action="store_true",
        help="Fail if recommended fields such as next_steps are empty",
    )
    chk.add_argument(
        "--json",
        action="store_true",
        dest="as_json",
        help="Print validation report as JSON",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    try:
        if args.command == "snapshot":
            if args.max_chars is not None and args.max_chars <= 0:
                raise HandoffError("--max-chars must be a positive integer.")
            md_path, json_path, bundle = create_snapshot(
                repo=args.repo,
                out_dir=args.out_dir,
                next_steps=args.next_steps,
                goal=args.goal,
                decisions=args.decisions,
                blockers=args.blockers,
                max_chars=args.max_chars,
            )
            redacted = bundle["redaction"]["redacted_count"]
            print(f"[agent-handoff] Wrote {md_path}")
            print(f"[agent-handoff] Wrote {json_path}")
            print(
                f"[agent-handoff] Branch={bundle['branch']} HEAD={bundle['head_commit']['short_sha']} "
                f"Files={bundle['modified_files_total']} TODOs={bundle['todos_total']} "
                f"Redactions={redacted} Compacted={bundle['compaction']['compacted']}"
            )
            return 0

        if args.command == "resume":
            if args.max_chars is not None and args.max_chars <= 0:
                raise HandoffError("--max-chars must be a positive integer.")
            prompt = render_resume_prompt(
                target=args.target,
                input_path=args.input,
                max_chars=args.max_chars,
            )
            if args.output:
                args.output.write_text(prompt, encoding="utf-8")
                print(f"[agent-handoff] Wrote {args.target} prompt to {args.output}")
            else:
                sys.stdout.write(prompt)
            return 0

        if args.command == "check":
            report = check_handoff(path=args.path, strict=args.strict)
            if args.as_json:
                print(json.dumps(report, indent=2, ensure_ascii=False))
            else:
                status = "PASS" if report["passed"] else "FAIL"
                print(f"[agent-handoff check] {status} ({len(report['checked_files'])} file(s) checked)")
                for warn in report["warnings"]:
                    print(f"  WARN: {warn}")
                for err in report["errors"]:
                    print(f"  ERROR: {err}")
            return 0 if report["passed"] else 1

    except HandoffError as exc:
        print(f"[agent-handoff] Error: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
