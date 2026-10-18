# `agy-auto-mode-ish` — Safe Project-Scoped Auto Mode for Google Antigravity

`agy-auto-mode-ish` is a zero-dependency Google Antigravity plugin that gives you a **Claude-style safe auto-mode** strictly confined to your active project folder.

It lets the agent **read, add, edit, and replace project files and run standard test/build tools automatically**, while **always prompting before file deletions or host system changes** and **hard-blocking any file writes or `Cwd` outside the project folder**.

---

## 1. Three-Tier Separation: Universal Defaults vs. Project Config vs. Private Data

`agy-auto-mode-ish` is designed so the plugin repository never contains project-specific paths or secrets:

| Tier | Where It Lives | What Belongs Here | Version Control |
| :--- | :--- | :--- | :--- |
| **1. Universal Plugin Defaults** | This plugin repo (`defaults/default_policy.json` & `scripts/permission_gate.py`) | Generic rules that apply to every repo: workspace boundary checks, `.env` protection, `rm`/`git clean` delete prompts, `sudo`/`apt`/`systemctl`/`chmod` host prompts, and common test runners (`pytest`, `ruff`, `npm test`, `cargo test`, `go test`). | Tracked in `notworklabs/agy-auto-mode-ish` (Public/Shared). |
| **2. Project-Specific Policy** | `<your-project>/.agents/guardrails.json` | Project-specific protected folders, custom denied commands (e.g., `docker compose down -v`), custom ask commands (e.g., deploy scripts), and custom monorepo test/build commands. | Tracked in your project repository (or `.gitignore`d if preferred). |
| **3. Private Secrets & Data** | `.env`, local data volumes, credentials, host paths | API keys, JWT secrets, database files, backups, private URLs/IPs. | **Never committed anywhere** (blocked from agent access by Tier 1 & Tier 2). |

---

## 2. How Every Tool Call Is Evaluated (`Deny > Force Ask > Auto Approve > Default Ask`)

When Antigravity triggers `PreToolUse`, `scripts/permission_gate.py` reads `workspacePaths` and `toolCall` from `stdin` and evaluates the action in strict priority order:

### 1. Hard Deny (`deny`) — Blocked Immediately
- Writing, editing, or replacing any file outside `workspacePaths` (except Antigravity's per-conversation artifact/scratch directory).
- Running any shell command whose working directory (`Cwd`) resolves outside `workspacePaths`.
- Reading or writing `.env` / `.env.*` secret files (while allowing `.env.example`, `.env.sample`, `.env.template`), `.git/config`, `.git/hooks`, or any path in `deny_paths`.
- Running any command matching `deny_commands`.

### 2. Explicit Confirmation (`force_ask`) — Always Prompts You
- **File or directory deletion / destructive Git commands:** `rm`, `rmdir`, `unlink`, `shred`, `find ... -delete`, `git clean`, `git reset --hard`, `git checkout --`, `git restore`, `git branch -D`, `git push --force`.
- **Host system, package, permission, or service changes outside containers:** `sudo`, `su`, `doas`, `pkexec`, `apt`, `apt-get`, `dpkg`, `snap`, `flatpak`, `dnf`, `yum`, `pacman`, `brew`, `systemctl`, `service`, `crontab`, `mount`, `umount`, `chown`, `chgrp`, `chmod`, `ufw`, `iptables`, `nft`, `reboot`, `shutdown`, `killall`, `pkill`, global `npm -g`, or direct `pip install`.
- **Commands referencing paths outside the project folder:** Commands using `~`, `$HOME`, `..` escaping the workspace root, or absolute host paths outside the workspace (other than `/dev/null` and `/usr/bin`, `/bin`, `/usr/local/bin` binaries).
- **Modifying `.agents/` guardrail files:** Prevents the agent from silently weakening its own guardrails without your confirmation.
- **Project-specific `ask_commands`** defined in `<workspace>/.agents/guardrails.json`.

### 3. Project Autonomy (`auto_approve`) — Runs Without Prompting
- Reading, creating (`write_to_file`), editing, and replacing (`replace_file_content`, `multi_replace_file_content`) any non-denied project file inside `workspacePaths`.
- Searching and listing files inside `workspacePaths` (`grep_search`, `find_by_name`, `list_dir`, `view_file_outline`, `view_code_item`).
- Running safe workspace-confined commands matching universal `allow_commands` or project-specific `allow_commands`.

### 4. Fallback (`ask`)
- Any unrecognized shell command inside the workspace prompts for review.

---

## 3. Installation & Usage

Requires Python 3.10+ (uses only the Python standard library; zero third-party dependencies).

### Option A: Install for a Single Project
Clone into your project's `.agents/plugins/` directory (or add as a Git submodule):

```bash
mkdir -p .agents/plugins
git clone https://github.com/notworklabs/agy-auto-mode-ish.git .agents/plugins/agy-auto-mode-ish
```

### Option B: Install Globally Across All Your Projects
Clone into your global Antigravity config directory:

```bash
mkdir -p ~/.gemini/config/plugins
git clone https://github.com/notworklabs/agy-auto-mode-ish.git ~/.gemini/config/plugins/agy-auto-mode-ish
```

### Option C: Share a Single Local Clone Across Selected Projects via `plugins.json`
Clone the repository once (for example, to `~/workspace/agy-auto-mode-ish`) and reference its parent directory in `<project>/.agents/plugins.json`:

```json
{
  "entries": [
    {
      "path": "~/workspace",
      "include_only": ["agy-auto-mode-ish"]
    }
  ]
}
```

---

## 4. Per-Project Customization (`.agents/guardrails.json`)

To add project-specific rules without modifying the plugin, create `.agents/guardrails.json` in your project root (or ask the agent: *"Use the `guardrails-init` skill to set up `.agents/guardrails.json` for this repo"*).

See [`examples/guardrails.example.json`](examples/guardrails.example.json) and [`defaults/guardrails.schema.json`](defaults/guardrails.schema.json) for the full schema:

```json
{
  "$schema": "./plugins/agy-auto-mode-ish/defaults/guardrails.schema.json",
  "description": "Project-specific guardrails layered on top of agy-auto-mode-ish defaults.",
  "deny_paths": [
    "secrets/",
    "backups/"
  ],
  "ask_write_paths": [
    ".agents/"
  ],
  "deny_commands": [
    {
      "pattern": "\bdocker(?:\s+compose|-compose)\b[^\n;|&]*\bdown\b[^\n;|&]*(?:-v\b|--volumes\b)",
      "reason": "Destroying named Docker volumes with `down -v` is blocked."
    }
  ],
  "ask_commands": [
    {
      "pattern": "\bdocker(?:\s+compose|-compose)\s+(?:up|down|stop|restart|rm|kill)\b",
      "reason": "Starting, stopping, or recreating Docker Compose services requires confirmation."
    }
  ],
  "allow_commands": [
    "^(?:cd\s+backend\s*&&\s*)?(?:\.venv/bin/|uv\s+run\s+)?(?:pytest|ruff)\b",
    "^(?:cd\s+frontend\s*&&\s*)?npm\s+(?:test|run\s+build|run\s+lint|ci)\b"
  ]
}
```

---

## 5. Verification & Self-Test

Run the built-in verification suite at any time:

```bash
python3 .agents/plugins/agy-auto-mode-ish/scripts/permission_gate.py --self-test
```

Or test a custom `PreToolUse` payload from the terminal:

```bash
echo '{
  "workspacePaths": ["'"$(pwd)"'"],
  "toolCall": {
    "name": "run_command",
    "args": {
      "Cwd": "'"$(pwd)"'",
      "CommandLine": "rm -rf dist/"
    }
  }
}' | python3 .agents/plugins/agy-auto-mode-ish/scripts/permission_gate.py
```
