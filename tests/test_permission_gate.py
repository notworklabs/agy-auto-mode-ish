"""Regression tests for policy loading and shell authorization (no shell execution)."""

import contextlib
import io
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from scripts import permission_gate as gate


class PermissionGateTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.config = self.root / ".agents" / "guardrails.json"
        self.config.parent.mkdir()

    def configure(self, policy):
        self.config.write_text(json.dumps(policy), encoding="utf-8")

    def payload(self, cmd, cwd=None):
        return {
            "workspacePaths": [str(self.root)],
            "toolCall": {
                "name": "run_command",
                "args": {"Cwd": str(cwd or self.root), "CommandLine": cmd},
            },
        }

    def assert_decision(self, cmd, expected, cwd=None):
        result = gate.evaluate_tool_call(self.payload(cmd, cwd))
        self.assertEqual(result["decision"], expected, (cmd, result))

    def test_invalid_project_policy_requires_confirmation_and_names_file(self):
        policies = [
            "{", "[]", "null", '"policy"',
            {"allow_commands": ["["]},
            {"deny_commands": [{"pattern": "[", "reason": "invalid"}]},
            {"ask_commands": [{"pattern": "[", "reason": "invalid"}]},
            {"deny_commands": ["not a rule"]},
            {"ask_commands": [{"reason": "missing pattern"}]},
            {"deny_commands": [{"pattern": "foo", "reason": 1}]},
            {"allow_commands": "^git"},
            {"ask_write_paths": [None]},
            {"deny_paths": {}},
            {"ask_commands": None},
        ]
        for policy in policies:
            with self.subTest(policy=policy):
                self.config.write_text(policy if isinstance(policy, str) else json.dumps(policy))
                result = gate.evaluate_tool_call(self.payload("git status"))
                self.assertEqual(result["decision"], "force_ask")
                self.assertIn(str(self.config), result["reason"])

    def test_unreadable_project_policy_requires_confirmation(self):
        self.configure({})
        read_text = Path.read_text

        def read(path, *args, **kwargs):
            if path == self.config:
                raise PermissionError("unreadable policy")
            return read_text(path, *args, **kwargs)

        with patch.object(Path, "read_text", read):
            result = gate.evaluate_tool_call(self.payload("git status"))
        self.assertEqual(result["decision"], "force_ask")
        self.assertIn(str(self.config), result["reason"])

    def test_directory_in_place_of_policy_requires_confirmation(self):
        self.config.mkdir()
        result = gate.evaluate_tool_call(self.payload("git status"))
        self.assertEqual(result["decision"], "force_ask")
        self.assertIn(str(self.config), result["reason"])

    def test_missing_optional_policy_allows_baseline(self):
        self.assert_decision("git status", "auto_approve")

    def test_valid_project_rules_are_merged(self):
        self.configure({
            "deny_commands": [{"pattern": "custom-deny", "reason": "blocked"}],
            "ask_commands": [{"pattern": "custom-ask", "reason": "confirm"}],
            "allow_commands": ["^custom-allow$"],
        })
        for cmd, expected in (("custom-deny", "deny"), ("custom-ask", "force_ask"),
                              ("custom-allow", "auto_approve"), ("git status", "auto_approve")):
            with self.subTest(cmd=cmd):
                self.assert_decision(cmd, expected)

    def test_baseline_env_regex_and_shell_reads(self):
        pattern = json.loads(gate.DEFAULT_POLICY_PATH.read_text())["deny_commands"][0]["pattern"]
        for name in (".env", "./.env", "nested/.env", ".env.local"):
            with self.subTest(name=name):
                self.assertIsNotNone(re.search(pattern, f"cat {name}"))
                self.assert_decision(f"cat {name}", "deny")
        for name in (".env.example", ".env.sample", ".env.template"):
            with self.subTest(name=name):
                self.assertIsNone(re.search(pattern, f"cat {name}"))
                self.assert_decision(f"cat {name}", "auto_approve")

    def test_shell_paths_use_workspace_policy(self):
        self.configure({"deny_paths": ["secrets/", "private.txt"]})
        for cmd in (
            "cat secrets/token", "git diff -- private.txt", "cat .git/config",
            "echo x >private.txt", "echo x >>secrets/token", "cat <secrets/token",
            "cat --file=private.txt", "cat 'secrets/token'", "echo x >.env",
            "echo x 2>.env.local", "cat <.env", "git diff -- .env.local",
            f"cat {self.root}/private.txt", "cat ../private.txt",
        ):
            with self.subTest(cmd=cmd):
                cwd = self.root / "nested" if cmd == "cat ../private.txt" else None
                self.assert_decision(cmd, "deny", cwd)

    def test_symlink_to_protected_path_is_denied(self):
        self.configure({"deny_paths": ["secrets/"]})
        (self.root / "alias").symlink_to(self.root / "secrets", target_is_directory=True)
        self.assert_decision("cat alias/token", "deny")

    def test_shell_glob_matches_use_workspace_policy(self):
        self.configure({"deny_paths": ["secrets/", "private.txt", "literal[1].txt"]})
        for name in (".env.local", ".git/config", ".git/hooks/pre-commit",
                     "secrets/token", "private.txt", "public.txt", "literal1.txt", "literal[1].txt"):
            target = self.root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.touch()
        for cmd in (
            "cat .e*", "cat .en?.local", "cat .[e]nv.local", "cat .git/con*",
            "cat .git/hook?/pre-commit", "cat sec*/token", "cat priv?te.txt",
            "git diff -- priva[t]e.txt", "cat --file=priv*.txt", "echo x >priva*",
            "cat *.txt", "sudo cat priv*", "echo x >.agents/file; cat priv*",
            f"cat {self.root}/priv*", "cat 'literal[1].txt'",
        ):
            with self.subTest(cmd=cmd):
                self.assert_decision(cmd, "deny")

    def test_shell_glob_matches_resolve_symlinks(self):
        self.configure({"deny_paths": ["private.txt"]})
        (self.root / "private.txt").touch()
        (self.root / "alias.txt").symlink_to(self.root / "private.txt")
        self.assert_decision("cat ali*", "deny")

    def test_shell_globs_use_current_directory_after_cd(self):
        self.configure({"deny_paths": ["backend/private.txt"]})
        backend = self.root / "backend"
        backend.mkdir()
        (backend / "private.txt").touch()
        self.assert_decision("cat priv*", "deny", backend)
        self.assert_decision("cd backend && cat priv*", "deny")
        self.assert_decision("cd back* && cat priv*", "deny")

    def test_shell_globs_are_never_auto_approved(self):
        self.configure({"allow_commands": [".*"]})
        (self.root / "public.txt").touch()
        for cmd in (
            "cat pub*", "cat publi?.txt", "cat [p]ublic.txt", "cat missing*",
            "cat missing?", "cat [m]issing", "git status && cat *.txt",
        ):
            with self.subTest(cmd=cmd):
                self.assert_decision(cmd, "ask")
        self.assert_decision("echo x >.ag*/guardrails.json", "force_ask")

    def test_redirections_to_guardrail_files_require_confirmation(self):
        for cmd in ("echo x >.agents/guardrails.json", "echo x >> .agents/guardrails.json",
                    "echo x 2>.agents/log", "cat < .agents/guardrails.json"):
            with self.subTest(cmd=cmd):
                self.assert_decision(cmd, "force_ask")
        self.assert_decision("cat .agents/guardrails.json", "auto_approve")

    def test_project_write_paths_apply_to_redirections(self):
        self.configure({"ask_write_paths": ["generated/"]})
        self.assert_decision("echo x >generated/file", "force_ask")
        self.assert_decision("cat generated/file", "auto_approve")

    def test_deny_takes_priority_over_ask(self):
        self.assert_decision("echo x >.agents/file; cat .env.local", "deny")
        self.assert_decision("sudo cat .git/config", "deny")

    def test_every_chain_segment_must_be_allowed(self):
        for separator in (" && ", " || ", "; ", " | "):
            with self.subTest(separator=separator):
                self.assert_decision(f"git status{separator}unknown-command", "ask")
                self.assert_decision(f"unknown-command{separator}git status", "ask")
                self.assert_decision(f"git status{separator}git diff", "auto_approve")

    def test_complex_shell_syntax_is_never_auto_approved(self):
        # Even an unrestricted project allow rule cannot bypass syntax checks.
        self.configure({"allow_commands": [".*"]})
        for cmd in (
            "echo $(unknown-command)", "echo `unknown-command`", "echo ${COMMAND}",
            "echo $COMMAND", "echo x >file", "echo x >>file", "cat <file",
            "cat <(unknown-command)", "git status\nunknown-command", "git status\n",
            "git status\r\n", "(git status)",
        ):
            with self.subTest(cmd=cmd):
                self.assert_decision(cmd, "ask")

    def test_allow_patterns_are_matched_at_segment_start(self):
        self.configure({"allow_commands": ["custom-allow"]})
        self.assert_decision("unknown-command custom-allow", "ask")
        self.assert_decision("custom-allow", "auto_approve")

    def test_example_allows_cd_and_test_segments_independently(self):
        example = gate.PLUGIN_ROOT / "examples" / "guardrails.example.json"
        self.configure(json.loads(example.read_text()))
        for cmd in ("cd backend && pytest", "cd frontend && npm test", "cd backend && ruff check ."):
            with self.subTest(cmd=cmd):
                self.assert_decision(cmd, "auto_approve")
        self.assert_decision("cd backend && unknown-command", "ask")
        self.assert_decision("cd backend || pytest", "ask")
        self.assert_decision("cd backend; pytest", "ask")

    def test_paths_after_cd_are_checked_from_new_directory(self):
        self.configure({"deny_paths": ["backend/private/"], "allow_commands": [r"^cd\s+backend$"]})
        self.assert_decision("cd backend && cat private/token", "deny")

    def test_cd_symlink_outside_workspace_requires_confirmation(self):
        self.configure({"allow_commands": [r"^cd\s+backend$"]})
        (self.root / "backend").symlink_to(self.root.parent, target_is_directory=True)
        self.assert_decision("cd backend && git status", "force_ask")

    def test_outside_paths_and_dangerous_commands_keep_restrictions(self):
        for cmd in ("cat /etc/passwd", "cat ../outside", "cat $HOME/file",
                    "rm project.txt", "sudo true"):
            with self.subTest(cmd=cmd):
                self.assert_decision(cmd, "force_ask")

    def test_main_prints_decision_on_unexpected_evaluation_error(self):
        output = io.StringIO()
        with patch.object(sys, "argv", ["permission_gate.py"]), \
                patch.object(sys, "stdin", io.StringIO(json.dumps(self.payload("git status")))), \
                patch.object(gate, "evaluate_tool_call", side_effect=RuntimeError("test failure")), \
                contextlib.redirect_stdout(output):
            gate.main()
        self.assertEqual(json.loads(output.getvalue())["decision"], "force_ask")

    def test_hook_exits_zero_on_invalid_payload_or_policy(self):
        self.config.write_text('{"allow_commands": ["["]}')
        for payload in ("[]", json.dumps(self.payload("git status"))):
            with self.subTest(payload=payload):
                result = subprocess.run(
                    [sys.executable, str(gate.PLUGIN_ROOT / "scripts" / "permission_gate.py")],
                    input=payload, text=True, capture_output=True, check=False,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                decision = json.loads(result.stdout)
                self.assertEqual(decision["decision"], "force_ask")
                if payload != "[]":
                    self.assertIn(str(self.config), decision["reason"])


if __name__ == "__main__":
    unittest.main()
