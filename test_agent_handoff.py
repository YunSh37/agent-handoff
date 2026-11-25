#!/usr/bin/env python3
"""Unit tests for agent_handoff CLI (snapshot, redaction, compaction, resume, check)."""

from __future__ import annotations

import contextlib
import io
import json
import subprocess
import tempfile
import unittest
from pathlib import Path

import agent_handoff


def _git(repo: Path, *args: str) -> str:
    proc = subprocess.run(
        ["git", *args],
        cwd=str(repo),
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=True,
    )
    return proc.stdout.strip()


def _init_repo(repo: Path, initial_commit: bool = True) -> None:
    _git(repo, "init")
    _git(repo, "config", "user.name", "Test Engineer")
    _git(repo, "config", "user.email", "tester@example.com")
    if initial_commit:
        readme = repo / "README.md"
        readme.write_text("# Sample Project\n", encoding="utf-8")
        _git(repo, "add", "README.md")
        _git(repo, "commit", "-m", "chore: initial commit")


def _build_synthetic_secrets() -> dict[str, str]:
    """Construct test credentials dynamically so static repo scanners never flag tests."""
    return {
        "ghp": "ghp_" + "AbCd1234EfGh5678IjKl9012",
        "gh_pat": "github_pat_" + "11AABBCCDD_" + "0123456789abcdefABCDEF",
        "kgat": "KGAT_" + "9876ZyXw5432VuTs1098",
        "aiza": "AIza" + "SyDummyKeyForUnitTest1234567",
        "sk": "sk-" + "proj-" + "TestApiKey9876543210abcd",
        "aws": "AKIA" + "IOSFODNN7EXAMPLE",
        "bearer": "Authorization: Bearer " + "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
        "pwd_assign": "PASSWORD" + ' = "my_super_secret_pw_99"',
        "gh_assign": "GITHUB_TOKEN" + '="ghp_' + '1234567890abcdefghijkl"',
        "json_secret": '"api_key"' + ': "secret_value_abc_12345"',
        "env_secret": "SECRET_KEY" + "=unquoted_top_secret_42",
        "priv_key": "-----BEGIN " + "RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA\n-----END " + "RSA PRIVATE KEY-----",
    }


class TestAgentHandoff(unittest.TestCase):
    def test_snapshot_generates_markdown_and_json(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp) / "demo_repo"
            repo.mkdir()
            _init_repo(repo, initial_commit=True)
            _git(repo, "checkout", "-b", "feat/session-handoff")

            app_py = repo / "app.py"
            app_py.write_text(
                "def run():\n"
                "    # TODO: validate token expiry before refresh\n"
                "    return True\n",
                encoding="utf-8",
            )
            _git(repo, "add", "app.py")
            _git(repo, "commit", "-m", "feat: add runner")

            # Staged edit, unstaged edit, and untracked file
            helper_py = repo / "helper.py"
            helper_py.write_text("# FIXME: handle empty payload cleanly\n", encoding="utf-8")
            _git(repo, "add", "helper.py")

            app_py.write_text(
                "def run():\n"
                "    # TODO: validate token expiry before refresh\n"
                "    # HACK: temporary retry fallback\n"
                "    return False\n",
                encoding="utf-8",
            )
            notes_md = repo / "notes.md"
            notes_md.write_text("Pending TODO: document CLI flags\n", encoding="utf-8")

            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                rc = agent_handoff.main(
                    [
                        "snapshot",
                        "--repo",
                        str(repo),
                        "--goal",
                        "Stabilize runner retries",
                        "--decisions",
                        "Keep zero external dependencies",
                        "--blockers",
                        "Waiting on rate-limit spec",
                        "--next-steps",
                        "Add unit tests for helper.py",
                        "Run check before commit",
                    ]
                )

            self.assertEqual(rc, 0)
            md_path = repo / "HANDOFF.md"
            json_path = repo / "handoff.json"
            self.assertTrue(md_path.is_file())
            self.assertTrue(json_path.is_file())

            bundle = json.loads(json_path.read_text(encoding="utf-8"))
            self.assertEqual(bundle["branch"], "feat/session-handoff")
            self.assertEqual(bundle["head_commit"]["subject"], "feat: add runner")
            self.assertEqual(bundle["goal"], "Stabilize runner retries")
            self.assertEqual(
                bundle["next_steps"],
                ["Add unit tests for helper.py", "Run check before commit"],
            )
            self.assertEqual(bundle["decisions"], ["Keep zero external dependencies"])
            self.assertEqual(bundle["blockers"], ["Waiting on rate-limit spec"])
            self.assertIn("helper.py", bundle["status_summary"]["staged"])
            self.assertIn("app.py", bundle["status_summary"]["unstaged"])
            self.assertIn("notes.md", bundle["status_summary"]["untracked"])
            self.assertIn("app.py", bundle["diff_stat"])
            tags_found = {(t["file"], t["tag"]) for t in bundle["todos"]}
            self.assertIn(("app.py", "TODO"), tags_found)
            self.assertIn(("app.py", "HACK"), tags_found)
            self.assertIn(("helper.py", "FIXME"), tags_found)
            self.assertIn(("notes.md", "TODO"), tags_found)

            md_text = md_path.read_text(encoding="utf-8")
            self.assertIn("# Session Handoff — demo_repo", md_text)
            self.assertIn("feat/session-handoff", md_text)
            self.assertIn("Add unit tests for helper.py", md_text)

            report = agent_handoff.check_handoff(repo, strict=True)
            self.assertTrue(report["passed"], report)

    def test_snapshot_unborn_repo_and_detached_head(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            unborn = Path(tmp) / "unborn_repo"
            unborn.mkdir()
            _init_repo(unborn, initial_commit=False)
            (unborn / "main.py").write_text("# TODO: initial setup\n", encoding="utf-8")
            _git(unborn, "add", "main.py")

            _, _, bundle = agent_handoff.create_snapshot(
                repo=unborn,
                next_steps=["Make first commit"],
            )
            self.assertEqual(bundle["head_commit"]["sha"], "UNBORN")
            self.assertTrue(agent_handoff.check_handoff(unborn, strict=True)["passed"])

            detached = Path(tmp) / "detached_repo"
            detached.mkdir()
            _init_repo(detached, initial_commit=True)
            _git(detached, "checkout", "--detach", "HEAD")

            _, _, d_bundle = agent_handoff.create_snapshot(
                repo=detached,
                next_steps=["Create branch from detached HEAD"],
            )
            self.assertIn("detached at", d_bundle["branch"])
            self.assertTrue(agent_handoff.check_handoff(detached, strict=True)["passed"])

    def test_secret_redaction_across_all_patterns(self) -> None:
        secrets = _build_synthetic_secrets()
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp) / "secret_repo"
            repo.mkdir()
            _init_repo(repo, initial_commit=True)

            leaky_file = repo / "config_notes.py"
            leaky_file.write_text(
                "\n".join(
                    [
                        "PWD=/workspace/app",
                        f"# TODO: rotate {secrets['ghp']}",
                        f"# TODO: fine {secrets['gh_pat']}",
                        f"# FIXME: kaggle {secrets['kgat']}",
                        f"# TODO: gcp {secrets['aiza']}",
                        f"# TODO: llm {secrets['sk']}",
                        f"# TODO: aws {secrets['aws']}",
                        f"# TODO: {secrets['bearer']}",
                        f"# FIXME: {secrets['pwd_assign']}",
                        f"# TODO: {secrets['gh_assign']}",
                        f"# TODO: {secrets['json_secret']}",
                        f"# TODO: {secrets['env_secret']}",
                        f"# TODO: {secrets['priv_key'].replace(chr(10), ' ')}",
                    ]
                )
                + "\n",
                encoding="utf-8",
            )

            out_dir = Path(tmp) / "handoff_out"
            md_path, json_path, bundle = agent_handoff.create_snapshot(
                repo=repo,
                out_dir=out_dir,
                goal=f"Fix auth leak {secrets['ghp']}",
                next_steps=[f"Replace {secrets['sk']} and {secrets['pwd_assign']}"],
            )

            md_text = md_path.read_text(encoding="utf-8")
            json_text = json_path.read_text(encoding="utf-8")
            combined = md_text + "\n" + json_text

            self.assertGreater(bundle["redaction"]["redacted_count"], 5)
            # Ensure benign POSIX PWD path is preserved while real secrets are scrubbed.
            for secret_val in (
                secrets["ghp"],
                secrets["gh_pat"],
                secrets["kgat"],
                secrets["aiza"],
                secrets["sk"],
                secrets["aws"],
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
                "my_super_secret_pw_99",
                "secret_value_abc_12345",
                "unquoted_top_secret_42",
                "BEGIN RSA PRIVATE KEY",
            ):
                self.assertNotIn(secret_val, combined)

            self.assertIn("[REDACTED:", combined)
            # Verify idempotency and benign PWD preservation.
            sample_pwd = "PWD=/workspace/app"
            self.assertEqual(agent_handoff.redact_secrets(sample_pwd), sample_pwd)
            self.assertEqual(agent_handoff.redact_secrets(md_text), md_text)

            report = agent_handoff.check_handoff(out_dir, strict=True)
            self.assertTrue(report["passed"], report)
            self.assertEqual(report["secret_findings"], [])

    def test_budget_compaction_max_chars(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp) / "big_repo"
            repo.mkdir()
            _init_repo(repo, initial_commit=True)

            for i in range(25):
                f = repo / f"module_{i:02d}.py"
                f.write_text(
                    f"# TODO: refactor module {i} with detailed validation logic and telemetry\n"
                    f"VALUE_{i} = {i}\n",
                    encoding="utf-8",
                )
            _git(repo, "add", ".")

            out_750 = Path(tmp) / "out_750"
            md_750, json_750, bundle_750 = agent_handoff.create_snapshot(
                repo=repo,
                out_dir=out_750,
                next_steps=["Verify compacted handoff stays readable"],
                max_chars=750,
            )
            md_text_750 = md_750.read_text(encoding="utf-8")
            self.assertLessEqual(len(md_text_750), 750)
            self.assertTrue(bundle_750["compaction"]["compacted"])
            self.assertGreater(bundle_750["compaction"]["original_chars"], 750)
            self.assertIn("Verify compacted handoff stays readable", md_text_750)
            self.assertTrue(agent_handoff.check_handoff(out_750, strict=True)["passed"])
            # JSON remains intact and valid.
            parsed_750 = json.loads(json_750.read_text(encoding="utf-8"))
            self.assertEqual(parsed_750["modified_files_total"], 25)

            out_250 = Path(tmp) / "out_250"
            md_250, _, bundle_250 = agent_handoff.create_snapshot(
                repo=repo,
                out_dir=out_250,
                next_steps=["Run final test"],
                max_chars=250,
            )
            self.assertLessEqual(len(md_250.read_text(encoding="utf-8")), 250)
            self.assertTrue(bundle_250["compaction"]["compacted"])
            self.assertTrue(agent_handoff.check_handoff(out_250)["passed"])

    def test_resume_renders_all_four_targets(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp) / "resume_repo"
            repo.mkdir()
            _init_repo(repo, initial_commit=True)
            (repo / "service.py").write_text("# TODO: add caching\n", encoding="utf-8")

            agent_handoff.create_snapshot(
                repo=repo,
                goal="Implement response cache",
                next_steps=["Add TTL eviction", "Run unittest suite"],
            )

            expected_markers = {
                "claude": "CLAUDE.md",
                "codex": "AGENTS.md",
                "antigravity": "Antigravity Continuity Protocol",
                "cursor": "@service.py",
            }
            for target, marker in expected_markers.items():
                prompt = agent_handoff.render_resume_prompt(target=target, input_path=repo)
                self.assertIn(f"# Resume Context ({target})", prompt)
                self.assertIn(marker, prompt)
                self.assertIn("Add TTL eviction", prompt)

            # Fallback rendering from HANDOFF.md only + budget cap + CLI --output
            out_file = Path(tmp) / "cursor_prompt.md"
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                rc = agent_handoff.main(
                    [
                        "resume",
                        "--target",
                        "cursor",
                        "--input",
                        str(repo / "HANDOFF.md"),
                        "--max-chars",
                        "420",
                        "--output",
                        str(out_file),
                    ]
                )
            self.assertEqual(rc, 0)
            written = out_file.read_text(encoding="utf-8")
            self.assertLessEqual(len(written), 420)
            self.assertIn("# Resume Context (cursor)", written)

    def test_check_detects_missing_fields_and_secret_leaks(self) -> None:
        secrets = _build_synthetic_secrets()
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)

            # Missing directory -> check fails
            self.assertFalse(agent_handoff.check_handoff(base / "missing")["passed"])

            # Empty next_steps -> warns normally, fails with --strict
            repo = base / "check_repo"
            repo.mkdir()
            _init_repo(repo, initial_commit=True)
            agent_handoff.create_snapshot(repo=repo)

            normal_rep = agent_handoff.check_handoff(repo, strict=False)
            self.assertTrue(normal_rep["passed"])
            self.assertTrue(normal_rep["warnings"])

            strict_rep = agent_handoff.check_handoff(repo, strict=True)
            self.assertFalse(strict_rep["passed"])

            # Inject escaped JSON secret assignment -> check must catch and fail exit code 1
            json_file = repo / "handoff.json"
            data = json.loads(json_file.read_text(encoding="utf-8"))
            data["next_steps"] = [f"Fix {secrets['pwd_assign']} and {secrets['ghp']}"]
            json_file.write_text(json.dumps(data, indent=2), encoding="utf-8")

            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                rc = agent_handoff.main(["check", str(repo), "--json"])
            self.assertEqual(rc, 1)
            out_report = json.loads(stdout.getvalue())
            self.assertFalse(out_report["passed"])
            self.assertGreaterEqual(len(out_report["secret_findings"]), 2)
            # Raw secret must never be echoed in check output!
            self.assertNotIn(secrets["ghp"], stdout.getvalue())
            self.assertNotIn("my_super_secret_pw_99", stdout.getvalue())

            # Missing required key
            del data["branch"]
            json_file.write_text(json.dumps(data), encoding="utf-8")
            bad_schema = agent_handoff.check_handoff(repo)
            self.assertFalse(bad_schema["passed"])
            self.assertTrue(any("branch" in err for err in bad_schema["errors"]))

    def test_cli_invalid_repo_returns_exit_2(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                rc = agent_handoff.main(["snapshot", "--repo", tmp])
            self.assertEqual(rc, 2)
            self.assertIn("Not a git repository", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
