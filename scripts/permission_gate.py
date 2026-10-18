#!/usr/bin/env python3
"""Generic, config-driven PreToolUse permission gate for the `agy-auto-mode-ish` plugin.

How it works:
1. Dynamically reads `workspacePaths` and `artifactDirectoryPath` from the Antigravity
   `PreToolUse` JSON payload on `stdin` (never hardcoded to a single machine or repo).
2. Loads universal baseline rules from `../defaults/default_policy.json`.
3. Automatically discovers and merges `<workspace>/.agents/guardrails.json` (if present)
   so each project can add its own protected paths, denied commands, ask rules, and
   auto-approved test/build commands without modifying plugin code.
4. Evaluates every file operation and shell command in strict precedence order:
   `deny` > `force_ask` > `auto_approve` > `ask`.

CLI usage:
- Run as a hook (reads JSON from stdin, writes JSON decision to stdout):
    python3 permission_gate.py
- Run built-in self-test suite against current workspace policy:
    python3 permission_gate.py --self-test [workspace_path]
"""

from __future__ import annotations

import json
import os
import re
import shlex
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

PLUGIN_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_POLICY_PATH = PLUGIN_ROOT / "defaults" / "default_policy.json"

ALLOWED_GLOBAL_READ_SUFFIXES = (
    ".gemini/antigravity-cli/builtin/skills",
    ".gemini/config/skills",
    ".gemini/config/plugins",
)


@dataclass
class CompiledRule:
    pattern: re.Pattern[str]
    reason: str


@dataclass
class Policy:
    deny_paths: list[str] = field(default_factory=list)
    ask_write_paths: list[str] = field(default_factory=list)
    deny_commands: list[CompiledRule] = field(default_factory=list)
    ask_commands: list[CompiledRule] = field(default_factory=list)
    allow_commands: list[re.Pattern[str]] = field(default_factory=list)


def _compile_rule_list(items: list[dict[str, str]]) -> list[CompiledRule]:
    compiled: list[CompiledRule] = []
    for item in items:
        pat = item.get("pattern")
        reason = item.get("reason", "Action requires review per guardrails policy.")
        if pat:
            compiled.append(CompiledRule(pattern=re.compile(pat), reason=reason))
    return compiled


def load_merged_policy(workspace_roots: list[Path]) -> Policy:
    """Loads `default_policy.json` and merges `<workspace>/.agents/guardrails.json`."""
    policy = Policy()

    if DEFAULT_POLICY_PATH.is_file():
        raw_default = json.loads(DEFAULT_POLICY_PATH.read_text(encoding="utf-8"))
        policy.deny_paths.extend(raw_default.get("deny_paths", []))
        policy.ask_write_paths.extend(raw_default.get("ask_write_paths", []))
        policy.deny_commands.extend(_compile_rule_list(raw_default.get("deny_commands", [])))
        policy.ask_commands.extend(
            _compile_rule_list(raw_default.get("delete_or_destructive_commands", []))
        )
        policy.ask_commands.extend(_compile_rule_list(raw_default.get("host_system_commands", [])))
        policy.ask_commands.extend(_compile_rule_list(raw_default.get("ask_commands", [])))
        for pat in raw_default.get("allow_commands", []):
            policy.allow_commands.append(re.compile(pat))

    for root in workspace_roots:
        project_cfg_path = root / ".agents" / "guardrails.json"
        if project_cfg_path.is_file():
            try:
                raw_proj = json.loads(project_cfg_path.read_text(encoding="utf-8"))
            except Exception:
                continue
            for p in raw_proj.get("deny_paths", []):
                if p not in policy.deny_paths:
                    policy.deny_paths.append(p)
            for p in raw_proj.get("ask_write_paths", []):
                if p not in policy.ask_write_paths:
                    policy.ask_write_paths.append(p)
            policy.deny_commands.extend(_compile_rule_list(raw_proj.get("deny_commands", [])))
            policy.ask_commands.extend(_compile_rule_list(raw_proj.get("ask_commands", [])))
            for pat in raw_proj.get("allow_commands", []):
                policy.allow_commands.append(re.compile(pat))

    return policy


def is_subpath(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False


def resolve_candidate_path(raw_path: str, base_dir: Path) -> Path:
    expanded = os.path.expanduser(raw_path)
    p = Path(expanded)
    if not p.is_absolute():
        p = base_dir / p
    return p.resolve(strict=False)


def is_allowed_global_skill_read(resolved: Path) -> bool:
    posix = resolved.as_posix()
    return any(suffix in posix for suffix in ALLOWED_GLOBAL_READ_SUFFIXES)


def match_rel_path_entry(rel_posix: str, entry: str) -> bool:
    norm = entry.strip("/")
    if not norm:
        return False
    if entry.endswith("/"):
        return rel_posix == norm or rel_posix.startswith(norm + "/")
    return rel_posix == norm or rel_posix.startswith(norm + "/")


def check_workspace_rel_policy(
    resolved: Path,
    workspace_root: Path,
    policy: Policy,
    is_write: bool,
) -> tuple[str, str] | None:
    rel = resolved.relative_to(workspace_root).as_posix()
    name = resolved.name

    # Protect any `.env*` file except `.env.example` / `.env.sample` / `.env.template`
    if name.startswith(".env") and name not in {
        ".env.example",
        ".env.sample",
        ".env.template",
    }:
        return (
            "deny",
            f"Access to private environment file `{rel}` is blocked by agy-auto-mode-ish.",
        )

    for entry in policy.deny_paths:
        if match_rel_path_entry(rel, entry):
            return (
                "deny",
                f"Access to protected path `{rel}` is blocked by agy-auto-mode-ish.",
            )

    if is_write:
        for entry in policy.ask_write_paths:
            if match_rel_path_entry(rel, entry):
                return (
                    "force_ask",
                    f"Modifying agent customization/guardrail file `{rel}` requires confirmation.",
                )

    return None


def references_outside_workspace(
    cmd: str,
    cwd: Path,
    workspace_roots: list[Path],
    artifact_dir: Path | None,
) -> str | None:
    """Detects shell arguments or redirections that point outside the project workspace."""
    if re.search(r"(?:^|[\s><=|])~(?:/|$|\s)", cmd) or "$HOME" in cmd or "${HOME}" in cmd:
        return "Command references the host home directory (`~` or `$HOME`) outside the project folder."

    try:
        tokens = shlex.split(cmd, posix=True)
    except ValueError:
        tokens = cmd.split()

    allowed_system_binary_prefixes = (
        "/dev/null",
        "/usr/bin/",
        "/bin/",
        "/usr/local/bin/",
    )

    for tok in tokens:
        cleaned = re.sub(r"^(?:[0-9]*>>?|[0-9]*<|--[a-zA-Z0-9_-]+=)", "", tok)
        if not cleaned:
            continue

        if ".." in cleaned.split("/"):
            candidate = resolve_candidate_path(cleaned, cwd)
            in_ws = any(is_subpath(candidate, root) for root in workspace_roots)
            in_art = artifact_dir is not None and is_subpath(candidate, artifact_dir)
            if not in_ws and not in_art:
                return f"Command path `{cleaned}` resolves outside the project folder (`{candidate}`)."

        if cleaned.startswith("/"):
            if any(
                cleaned == p or cleaned.startswith(p.rstrip("/") + "/")
                for p in allowed_system_binary_prefixes
            ):
                continue
            if any(
                cleaned == str(root) or cleaned.startswith(str(root) + "/")
                for root in workspace_roots
            ):
                continue
            if artifact_dir is not None and (
                cleaned == str(artifact_dir) or cleaned.startswith(str(artifact_dir) + "/")
            ):
                continue
            return f"Command references host path `{cleaned}` outside the project folder."

    return None


def evaluate_tool_call(data: dict[str, Any]) -> dict[str, Any]:
    raw_workspaces = data.get("workspacePaths") or []
    workspace_roots = [
        Path(p).resolve(strict=False)
        for p in raw_workspaces
        if isinstance(p, str) and p.strip()
    ]
    if not workspace_roots:
        # Fallback: walk up from PLUGIN_ROOT to find the enclosing repo root if vendor-installed
        if PLUGIN_ROOT.parent.name in {".agents", ".agent", "_agents", "_agent"}:
            workspace_roots = [PLUGIN_ROOT.parent.parent.resolve()]
        else:
            workspace_roots = [Path.cwd().resolve()]

    primary_root = workspace_roots[0]
    policy = load_merged_policy(workspace_roots)

    raw_artifact_dir = data.get("artifactDirectoryPath")
    artifact_dir = (
        Path(raw_artifact_dir).resolve(strict=False)
        if isinstance(raw_artifact_dir, str) and raw_artifact_dir.strip()
        else None
    )

    tool_call = data.get("toolCall") or {}
    tool_name = str(tool_call.get("name") or "").lower()
    args = tool_call.get("args") or {}

    # 1. Terminal commands
    if tool_name == "run_command" or "CommandLine" in args:
        cmd = str(args.get("CommandLine") or "").strip()
        raw_cwd = str(args.get("Cwd") or str(primary_root)).strip()
        cwd = resolve_candidate_path(raw_cwd, primary_root)

        in_ws = any(is_subpath(cwd, root) for root in workspace_roots)
        in_art = artifact_dir is not None and is_subpath(cwd, artifact_dir)
        if not in_ws and not in_art:
            return {
                "decision": "deny",
                "reason": f"Command working directory `{cwd}` is outside the project folder `{primary_root}`.",
            }

        for rule in policy.deny_commands:
            if rule.pattern.search(cmd):
                return {"decision": "deny", "reason": rule.reason}

        for rule in policy.ask_commands:
            if rule.pattern.search(cmd):
                return {"decision": "force_ask", "reason": rule.reason}

        outside_reason = references_outside_workspace(cmd, cwd, workspace_roots, artifact_dir)
        if outside_reason is not None:
            return {"decision": "force_ask", "reason": outside_reason}

        for allow_pat in policy.allow_commands:
            if allow_pat.search(cmd):
                return {"decision": "auto_approve"}

        return {
            "decision": "ask",
            "reason": "Unrecognized shell command; please review before execution.",
        }

    # 2. File read/write/search tools
    write_keys = ("TargetFile",)
    read_keys = ("AbsolutePath", "DirectoryPath", "SearchPath", "File")
    if (
        tool_name
        in {
            "view_file",
            "write_to_file",
            "replace_file_content",
            "multi_replace_file_content",
            "grep_search",
            "find_by_name",
            "list_dir",
            "view_file_outline",
            "view_code_item",
            "code_action",
        }
        or any(k in args for k in (*write_keys, *read_keys))
    ):
        is_write = tool_name in {
            "write_to_file",
            "replace_file_content",
            "multi_replace_file_content",
            "code_action",
        } or any(k in args for k in write_keys)

        raw_target = None
        for k in (*write_keys, *read_keys):
            if isinstance(args.get(k), str) and args[k].strip():
                raw_target = args[k].strip()
                break

        if not raw_target:
            return {"decision": "allow"}

        resolved = resolve_candidate_path(raw_target, primary_root)

        for root in workspace_roots:
            if is_subpath(resolved, root):
                rel_decision = check_workspace_rel_policy(
                    resolved, root, policy, is_write=is_write
                )
                if rel_decision is not None:
                    return {"decision": rel_decision[0], "reason": rel_decision[1]}
                return {"decision": "auto_approve"}

        if artifact_dir is not None and is_subpath(resolved, artifact_dir):
            return {"decision": "auto_approve"}

        if not is_write and is_allowed_global_skill_read(resolved):
            return {"decision": "auto_approve"}

        if is_write:
            return {
                "decision": "deny",
                "reason": f"Writing or editing files outside `{primary_root}` is blocked (`{resolved}`).",
            }
        return {
            "decision": "force_ask",
            "reason": f"Reading file outside `{primary_root}` requires confirmation (`{resolved}`).",
        }

    return {"decision": "allow"}


def run_self_test(ws_path: Path) -> int:
    ws = str(ws_path.resolve())
    cases = [
        (
            "read project file",
            {"workspacePaths": [ws], "toolCall": {"name": "view_file", "args": {"AbsolutePath": f"{ws}/README.md"}}},
            "auto_approve",
        ),
        (
            "write project file",
            {"workspacePaths": [ws], "toolCall": {"name": "write_to_file", "args": {"TargetFile": f"{ws}/src/example.ts"}}},
            "auto_approve",
        ),
        (
            "read .env blocked",
            {"workspacePaths": [ws], "toolCall": {"name": "view_file", "args": {"AbsolutePath": f"{ws}/.env"}}},
            "deny",
        ),
        (
            "read .env.example allowed",
            {"workspacePaths": [ws], "toolCall": {"name": "view_file", "args": {"AbsolutePath": f"{ws}/.env.example"}}},
            "auto_approve",
        ),
        (
            "write outside workspace blocked",
            {"workspacePaths": [ws], "toolCall": {"name": "write_to_file", "args": {"TargetFile": "/tmp/outside.txt"}}},
            "deny",
        ),
        (
            "edit .agents config asks",
            {"workspacePaths": [ws], "toolCall": {"name": "write_to_file", "args": {"TargetFile": f"{ws}/.agents/guardrails.json"}}},
            "force_ask",
        ),
        (
            "rm file asks",
            {"workspacePaths": [ws], "toolCall": {"name": "run_command", "args": {"Cwd": ws, "CommandLine": "rm some_file.txt"}}},
            "force_ask",
        ),
        (
            "sudo command asks",
            {"workspacePaths": [ws], "toolCall": {"name": "run_command", "args": {"Cwd": ws, "CommandLine": "sudo systemctl restart docker"}}},
            "force_ask",
        ),
        (
            "git status auto-approved",
            {"workspacePaths": [ws], "toolCall": {"name": "run_command", "args": {"Cwd": ws, "CommandLine": "git status -s"}}},
            "auto_approve",
        ),
    ]

    for label, payload, expected in cases:
        out = evaluate_tool_call(payload)
        if out.get("decision") != expected:
            print(f"FAIL: {label}: expected {expected}, got {out}", file=sys.stderr)
            return 1
        print(f"PASS: {label} -> {out['decision']}")
    return 0


def main() -> None:
    if len(sys.argv) > 1 and sys.argv[1] == "--self-test":
        target_ws = Path(sys.argv[2]) if len(sys.argv) > 2 else Path.cwd()
        sys.exit(run_self_test(target_ws))

    try:
        raw_input = sys.stdin.read()
        if not raw_input.strip():
            sys.stdout.write(json.dumps({"decision": "allow"}) + "\n")
            return
        data = json.loads(raw_input)
    except Exception:
        sys.stdout.write(
            json.dumps(
                {
                    "decision": "ask",
                    "reason": "Could not parse PreToolUse payload; prompting for safety.",
                }
            )
            + "\n"
        )
        return

    result = evaluate_tool_call(data)
    sys.stdout.write(json.dumps(result) + "\n")


if __name__ == "__main__":
    main()
