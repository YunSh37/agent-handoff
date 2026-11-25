# agent-handoff

A single-file Python 3.11+ CLI for writing sanitized git session handoffs (`HANDOFF.md` + `handoff.json`) and formatting resume prompts for Claude Code, Codex, Antigravity, and Cursor.

Built around the workflow described in [anthropics/claude-code#11455](https://github.com/anthropics/claude-code/issues/11455): keeping branch state, changed files, open `TODO` items, and next steps outside any single agent's volatile session memory.

## Design

- **Zero runtime dependencies**: Python 3.11+ standard library and `git` only. Runs either installed via `pip` or directly as `python3 agent_handoff.py`.
- **Deterministic git inspection (`snapshot`)**: Captures branch (normal, detached `HEAD`, or unborn repo), `HEAD` commit metadata, `git status --porcelain=v1` buckets (`staged`, `unstaged`, `untracked`, `conflicted`), `git diff HEAD --stat`, modified file list, and `TODO`/`FIXME`/`XXX`/`HACK` lines in changed files.
- **Pre-write secret scrubbing**: Strips common token prefixes (`ghp_*`, `github_pat_*`, `KGAT_*`, `AIza*`, `sk-*`, `AKIA*`/`ASIA*`), `Authorization: Bearer` headers, private key blocks, and password/secret assignments before writing `HANDOFF.md`, `handoff.json`, or `resume` output.
- **Budget compaction (`--max-chars`)**: Reduces `HANDOFF.md` in fixed tiers (trimming TODO snippets, diff lines, and file lists before touching core header fields or `next_steps`).
- **Cross-agent prompt rendering (`resume`)**: Formats `HANDOFF.md` / `handoff.json` for `claude`, `codex`, `antigravity`, or `cursor` (adding `@file` hints for Cursor).
- **Bundle validation (`check`)**: Checks required files, `handoff.json` keys, Markdown section markers, and scans both raw text and unescaped JSON string values for unredacted secrets.

## Installation

Install locally with `pip`:

```bash
pip install .
agent-handoff --help
```

Or run the standalone module directly without installation:

```bash
python3 agent_handoff.py --help
```

## Usage

### 1. Capture a handoff snapshot (`snapshot`)

Run inside a git repository before ending a session or switching tools:

```bash
agent-handoff snapshot \
  --goal "Finish OAuth callback validation" \
  --decisions "Keep JWT verification stateless in auth_middleware.py" \
  --blockers "Waiting on sandbox callback URL" \
  --next-steps "Run pytest tests/test_auth.py" "Update error codes in routes.py"
```

Optional output directory and character budget:

```bash
agent-handoff snapshot --out-dir . --max-chars 1500 --next-steps "Fix failing unit test"
```

Generated files:
- `HANDOFF.md`: Markdown summary for humans and coding agents.
- `handoff.json`: Structured bundle (`schema_version: "1.0"`) containing `generated_at`, `repo_name`, `branch`, `head_commit`, `goal`, `status_summary`, `modified_files`, `diff_stat`, `todos`, `decisions`, `blockers`, `next_steps`, `redaction`, and `compaction`.

### 2. Render a resume prompt (`resume`)

```bash
agent-handoff resume --target claude
agent-handoff resume --target codex
agent-handoff resume --target antigravity
agent-handoff resume --target cursor
```

Optional character cap, alternate input file/directory, and file output:

```bash
agent-handoff resume --target cursor --input ./HANDOFF.md --max-chars 2000 --output .cursor_resume.md
```

### 3. Validate a handoff bundle (`check`)

```bash
agent-handoff check .
```

Strict mode (fails if `next_steps` is empty) and JSON output:

```bash
agent-handoff check . --strict --json
```

Exit codes:
- `0`: Validation passed with zero secret findings.
- `1`: Validation failed (missing files, invalid schema/sections, empty `next_steps` under `--strict`, or unredacted secret found).
- `2`: Invalid CLI arguments, missing input path, or target is not a git repository.

## Secret Scrubbing Details

Matched values are replaced with unquoted `[REDACTED:<CATEGORY>]` markers, and the count/categories are recorded under `redaction` in `handoff.json`. Benign shell variables such as `PWD=/workspace/app` are left untouched.

Covered patterns:
- GitHub tokens (`ghp_*`, `gho_*`, `ghu_*`, `ghs_*`, `ghr_*`, `github_pat_*`)
- Kaggle tokens (`KGAT_*`)
- Google API keys (`AIza*`)
- OpenAI / Anthropic / generic `sk-*` keys
- AWS access key IDs (`AKIA*`, `ASIA*`)
- Private key blocks (`-----BEGIN ... PRIVATE KEY-----`)
- `Authorization: Bearer ...` headers
- Quoted/unquoted assignments (`PASSWORD`, `PASSWD`, `SECRET`, `SECRET_KEY`, `API_KEY`, `ACCESS_KEY`, `AUTH_TOKEN`, `GITHUB_TOKEN`, `GH_TOKEN`, `KAGGLE_KEY`, `GMAIL_APP_PASSWORD`, `PRIVATE_KEY`)

## Scope and Limitations

- Secret scrubbing uses regex rules. It prevents accidental copy-paste leaks of common token formats, but it is not a substitute for dedicated secret scanners (`gitleaks`, `trufflehog`).
- `TODO`/`FIXME`/`XXX`/`HACK` extraction only scans changed or untracked non-binary files up to 512 KB, and `handoff.json` caps `modified_files` at 80 entries and `todos` at 40 entries by default.
- `--max-chars` performs deterministic structural pruning rather than LLM/semantic summarization. If set below the minimal header size, trailing text is sliced with `...[compacted]`.
- Requires `git` on `PATH` and Python 3.11 or newer.

## Tests

Run the full test suite (`test_agent_handoff.py` with 7 CLI/core tests, plus `test_presets.py` with 4 preset/workflow checks when the optional `presets/` directory is present):

```bash
python3 -m unittest discover -s . -v
```

## Release Bundles

- `dist/agent-handoff-v0.1.0.zip`: MIT core CLI release (`agent_handoff.py`, `pyproject.toml`, `README.md`, `LICENSE`, `test_agent_handoff.py`).
- `dist/agent-handoff-presets-v0.1.0.zip`: Full bundle adding `presets/` (`presets/claude/settings.json`, `presets/claude/CLAUDE_HANDOFF.md`, `presets/codex/AGENTS_HANDOFF.md`, `presets/antigravity/RULES_HANDOFF.md`, `presets/cursor/handoff.mdc`, `presets/github-workflows/handoff-check.yml`, `presets/prompts/*.md`, `presets/TEAM_PLAYBOOK.md`) and `test_presets.py`.

## License

MIT (`LICENSE`).

## Support & Preset Packs

Maintained by YunSh37 on Afdian: https://afdian.com/a/yunsh37
